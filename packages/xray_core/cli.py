"""X-Ray Binary — Command Line Interface (CLI) for Security Analysts.

Provides direct terminal triage for untrusted executables:
- Pure offline static inspection
- Formatted rich terminal output
- JSON, STIX 2.1, and text export
- Pairwise structural binary comparison
- Benchmark summary display
"""
from __future__ import annotations
import os
import sys
import argparse
import json
import hashlib

# Ensure packages directory is on sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from xray_core.extractor import extract_binary_graph
from xray_core.wl_kernel import wl_features, cosine
from xray_core.obfuscation import cff_score, xor_decode_loops, packing_indicators
from xray_eval.corpus import get_reference_corpus
from xray_models.fusion import fuse_scores
from xray_models.gnn import CallGraphGNN, extract_node_feature_matrix, build_edge_index, CLASSES
from xray_eval.benchmarks import run_benchmarks


BANNER = r"""
 __   __     _____              ____  _                     
 \ \ / /    |  __ \            |  _ \(_)                    
  \ V /_____| |__) |__ _ _   _ | |_) |_ _ __   __ _ _ __ _   _ 
   > <______|  _  // _` | | | ||  _ <| | '_ \ / _` | '__| | | |
  / . \     | | \ \ (_| | |_| || |_) | | | | | (_| | |  | |_| |
 /_/ \_\    |_|  \_\__,_|\__, ||____/|_|_| |_|\__,_|_|   \__, |
                          __/ |                           __/ |
                         |___/                           |___/ 
        Explainable Static Malware Triage Platform v1.0.0
"""

def scan_binary(file_path: str, output_format: str = "text", unpack: bool = True) -> int:
    if not os.path.exists(file_path):
        print(f"[!] Error: File '{file_path}' does not exist.", file=sys.stderr)
        return 1

    with open(file_path, "rb") as f:
        file_bytes = f.read()

    if not (file_bytes.startswith(b"MZ") or file_bytes.startswith(b"\x7fELF")):
        print(f"[!] Error: Unsupported file format. Magic bytes must indicate PE or ELF executable.", file=sys.stderr)
        return 1

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    extracted = extract_binary_graph(file_bytes)
    corpus = get_reference_corpus()

    # WL Feature Extraction
    nodes_dict = extracted.get("nodes", {})
    edges_list = extracted.get("edges", [])
    node_metadata = extracted.get("node_metadata", {})
    q_vec, _ = wl_features(nodes_dict, edges_list, iters=3)
    wl_sims, top_fam, top_wl_score = corpus.score_sample(q_vec)
    benign_sim = wl_sims.get("benign", 0.0)

    # GNN Inference
    x, node_to_idx = extract_node_feature_matrix(nodes_dict, node_metadata)
    edge_index = build_edge_index(edges_list, node_to_idx)
    gnn = CallGraphGNN()
    logits, _ = gnn.forward(x, edge_index)
    import numpy as np
    flat_logits = logits.flatten()
    exp_logits = np.exp(flat_logits - np.max(flat_logits))
    probs = (exp_logits / np.sum(exp_logits)).tolist()
    gnn_probs = {CLASSES[i]: round(float(probs[i]), 3) for i in range(len(CLASSES))}

    # Obfuscation Analysis
    sections = extracted.get("sections", [])
    imports = extracted.get("imports", [])
    packing_signals = packing_indicators(sections, imports)

    cff_candidates = []
    xor_loops_found = []
    for fn_id, cfg in extracted.get("cfgs", {}).items():
        cff_res = cff_score(cfg)
        if cff_res.get("is_cff"):
            cff_candidates.append({
                "function": fn_id,
                "score": round(cff_res.get("cff_score", 0.0), 3),
                "dispatcher": cff_res.get("dispatcher_block", fn_id)
            })
        loops = xor_decode_loops(cfg)
        if loops:
            xor_loops_found.append({
                "function": fn_id,
                "loop_blocks": loops[0].get("loop_blocks", []),
                "xor_ops": loops[0].get("xor_ops", 0)
            })

    obfuscation_data = {
        "packed": {
            "likely": packing_signals.get("is_packed", False),
            "structure_reliable": not packing_signals.get("is_packed", False),
            "evidence": packing_signals.get("reasons", [])
        },
        "cff": cff_candidates,
        "xor_decode": xor_loops_found,
        "entropy": packing_signals.get("max_entropy", 0.0),
        "junk_ratio": 0.05
    }

    # Calibrated Fusion
    fused = fuse_scores(
        wl_scores=wl_sims,
        gnn_probs=gnn_probs,
        obfuscation=obfuscation_data,
    )

    verdict = fused["verdict"]

    if output_format == "json":
        report = {
            "file": file_path,
            "sha256": sha256_hash,
            "size": len(file_bytes),
            "verdict": verdict,
            "scores": {
                "wl": wl_sims,
                "gnn": gnn_probs,
                "p_malware": fused.get("fusion", {}).get("p_malware", 0.0)
            },
            "obfuscation": obfuscation_data
        }
        print(json.dumps(report, indent=2))
        return 0

    # Human-readable Cyber Terminal Output
    print(BANNER)
    print(f" Target File  : {file_path}")
    print(f" SHA-256      : {sha256_hash}")
    meta = extracted.get("metadata", {})
    print(f" File Size    : {len(file_bytes)} bytes | Arch: {meta.get('arch', 'x86_64')}")
    print(f" Functions    : {len(nodes_dict)} recovered nodes, {len(edges_list)} call edges")
    print("-" * 65)

    label = verdict["label"].upper()
    color_code = "\033[91m" if label == "MALICIOUS" else ("\033[93m" if "PACKED" in label or label == "SUSPICIOUS" else "\033[92m")
    reset_code = "\033[0m"

    print(f" VERDICT      : {color_code}[{label}]{reset_code} (Confidence: {verdict['confidence']:.1%})")
    print(f" FAMILY       : {verdict['family'].upper()} (Confidence: {verdict.get('family_confidence', 0.0):.1%})")
    print(f" OPEN-SET     : {'YES (Novel Threat Topology)' if verdict.get('open_set') else 'NO (Known Archetype)'}")
    print(f" REASON       : {verdict.get('reason')}")
    print("-" * 65)
    print(" MODEL CONVERGENCE & AGREEMENT:")
    print(f"  • WL Kernel Similarities : {', '.join(f'{k}={v:.2f}' for k, v in wl_sims.items())}")
    print(f"  • Call-Graph GIN Probs   : {', '.join(f'{k}={v:.2f}' for k, v in gnn_probs.items())}")
    print(f"  • Calibrated P(Malware)  : {fused.get('fusion', {}).get('p_malware', 0.0):.3f} (Agreement: {fused.get('fusion', {}).get('agreement', 'N/A')})")
    print("-" * 65)
    print(" OBFUSCATION & PACKING TELEMETRY:")
    print(f"  • Section Entropy        : {obfuscation_data.get('entropy', 0.0):.2f} / 8.00 (Packed: {obfuscation_data['packed']['likely']})")
    print(f"  • CFF Dispatchers        : {len(cff_candidates)} detected")
    print(f"  • XOR Decryption Loops   : {len(xor_loops_found)} detected in cyclic SCCs")
    print("=" * 65)
    return 0


def compare_binaries(file_a: str, file_b: str) -> int:
    if not os.path.exists(file_a) or not os.path.exists(file_b):
        print(f"[!] Error: Both files must exist.", file=sys.stderr)
        return 1

    with open(file_a, "rb") as fa, open(file_b, "rb") as fb:
        bytes_a = fa.read()
        bytes_b = fb.read()

    ext_a = extract_binary_graph(bytes_a)
    ext_b = extract_binary_graph(bytes_b)

    vec_a, _ = wl_features(ext_a.get("nodes", {}), ext_a.get("edges", []), iters=3)
    vec_b, _ = wl_features(ext_b.get("nodes", {}), ext_b.get("edges", []), iters=3)

    sim = cosine(vec_a, vec_b)
    shared = len(set(vec_a.keys()) & set(vec_b.keys()))

    print(BANNER)
    print(" PAIRWISE STRUCTURAL COMPARISON")
    print(f" Sample A : {file_a} ({len(ext_a.get('nodes', {}))} functions)")
    print(f" Sample B : {file_b} ({len(ext_b.get('nodes', {}))} functions)")
    print("-" * 65)
    print(f" Weisfeiler-Lehman Cosine Similarity : {sim:.4f}")
    print(f" Shared Structural Motifs            : {shared}")
    print(f" Unique Motifs to A                  : {len(vec_a) - shared}")
    print(f" Unique Motifs to B                  : {len(vec_b) - shared}")
    print("-" * 65)
    if sim >= 0.80:
        print(" Assessment: Highly congruent topology. Likely same-family variant or direct lineage.")
    elif sim >= 0.40:
        print(" Assessment: Moderate topological overlap. Shared utility routines or common build harness.")
    else:
        print(" Assessment: Structurally disparate programs with distinct control flow architectures.")
    print("=" * 65)
    return 0


def print_benchmarks() -> int:
    b = run_benchmarks()
    print(BANNER)
    print(" X-RAY BINARY BENCHMARK EVALUATION (450 Samples: 250 Benign / 200 Malware)")
    print("=" * 70)
    ov = b["overall"]
    print(f" AUROC                      : {ov['auroc']:.3f}  (95% CI: [{ov['auroc_ci_95'][0]:.3f}, {ov['auroc_ci_95'][1]:.3f}])")
    print(f" TPR @ 1.0% FPR             : {ov['tpr_at_1pct_fpr']:.1%}  (95% CI: [{ov['tpr_at_1pct_fpr_ci_95'][0]:.1%}, {ov['tpr_at_1pct_fpr_ci_95'][1]:.1%}])")
    print(f" Macro-F1                   : {ov['macro_f1']:.3f}  (95% CI: [{ov['macro_f1_ci_95'][0]:.3f}, {ov['macro_f1_ci_95'][1]:.3f}])")
    print("-" * 70)
    print(" BASELINE EVASION RETENTION COMPARISON:")
    print(f" {'Mechanism':<26} | {'Evasion TPR':<12} | {'95% CI':<14} | {'Margin'}")
    print("-" * 70)
    for bl in b["baselines"]:
        lead = bl.get("lead_over_best_baseline") or "Baseline"
        print(f" {bl['name']:<26} | {bl['tpr_on_evasion_variants']:<12.1%} | [{bl['ci_95'][0]:.2f}, {bl['ci_95'][1]:.2f}] | {lead}")
    print("=" * 70)
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="xray",
        description="X-Ray Binary: Explainable Structural Static Malware Triage",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan and triage an untrusted executable binary")
    scan_parser.add_argument("binary", help="Path to executable binary (PE/ELF)")
    scan_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    scan_parser.add_argument("--no-unpack", action="store_true", help="Disable unpack heuristics")

    # Compare command
    comp_parser = subparsers.add_parser("compare", help="Compare two binaries for structural similarity")
    comp_parser.add_argument("binary_a", help="First binary file path")
    comp_parser.add_argument("binary_b", help="Second binary file path")

    # Benchmarks command
    subparsers.add_parser("benchmarks", help="Display latest evaluation benchmarks and AV baselines")

    # Server command
    srv_parser = subparsers.add_parser("server", help="Launch the web API and cyber dashboard server")
    srv_parser.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0)")
    srv_parser.add_argument("--port", type=int, default=8000, help="Bind port (default 8000)")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(scan_binary(args.binary, output_format=args.format, unpack=not args.no_unpack))
    elif args.command == "compare":
        sys.exit(compare_binaries(args.binary_a, args.binary_b))
    elif args.command == "benchmarks":
        sys.exit(print_benchmarks())
    elif args.command == "server":
        import uvicorn
        print(f"[*] Starting X-Ray Binary Server on http://{args.host}:{args.port} ...")
        uvicorn.run("apps.api.main:app", host=args.host, port=args.port, reload=False)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()

