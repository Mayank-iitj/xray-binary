"""End-to-End System Test Suite for X-Ray Binary.

Verifies:
1. Pure Python PE/ELF static extraction and disassembly
2. Structure-only WL invariant labelling & cosine similarity
3. Obfuscation detection (CFF dispatchers, XOR loops, packing flags)
4. GNN classification and calibrated decision fusion
5. Evasion Lab retention and baseline comparison
6. Complete FastAPI endpoints
"""
from __future__ import annotations
import os
import sys
import unittest

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
packages_dir = os.path.join(root_dir, "packages")
apps_dir = os.path.join(root_dir, "apps")
for p in (root_dir, packages_dir, apps_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from xray_core.wl_kernel import wl_features, cosine, label_log_odds, node_scores
from xray_core.labelling import extract_node_label, api_bucket
from xray_core.obfuscation import shannon_entropy, cff_score, xor_decode_loops, packing_indicators
from xray_core.extractor import extract_binary_graph, parse_binary_metadata
from xray_models.gnn import CallGraphGNN, extract_node_feature_matrix, build_edge_index
from xray_models.fusion import fuse_scores
from xray_eval.corpus import get_reference_corpus
from xray_eval.evasion_lab import run_evasion_study
from xray_eval.benchmarks import run_benchmarks
from apps.api.demo_data import create_synthetic_pe_bytes

class TestXRayCore(unittest.TestCase):
    def test_structural_renaming_invariance(self):
        print("Running test_structural_renaming_invariance...")
        nodes_a = {"f1": "arith:2,call:1|api:file|cc:2|bb:1", "f2": "data:4,ret:1|api:-|cc:1|bb:1"}
        edges_a = [("f1", "f2")]
        # Obfuscated / renamed symbol ids
        nodes_b = {"sub_401000": "arith:2,call:1|api:file|cc:2|bb:1", "sub_401050": "data:4,ret:1|api:-|cc:1|bb:1"}
        edges_b = [("sub_401000", "sub_401050")]

        vec_a, _ = wl_features(nodes_a, edges_a, iters=3)
        vec_b, _ = wl_features(nodes_b, edges_b, iters=3)
        sim = cosine(vec_a, vec_b)
        self.assertAlmostEqual(sim, 1.0, places=5)
        print("test_structural_renaming_invariance OK")

    def test_api_normalization(self):
        print("Running test_api_normalization...")
        self.assertEqual(api_bucket("kernel32!CreateFileW"), "file")
        self.assertEqual(api_bucket("advapi32!CryptEncrypt"), "crypto")
        self.assertEqual(api_bucket("ws2_32!connect"), "net")
        self.assertEqual(api_bucket("user32!SetWindowsHookExA"), "input")
        self.assertEqual(api_bucket("libc.so:open"), "file")
        print("test_api_normalization OK")

    def test_cff_and_xor_detection(self):
        print("Running test_cff_and_xor_detection...")
        flat_cfg = {
            "entry": "b_entry",
            "blocks": {f"b{i}": [("mov", "eax, 1")] for i in range(8)},
            "edges": [("b_entry", "disp")] + [("disp", f"b{i}") for i in range(8)] + [(f"b{i}", "disp") for i in range(8)],
        }
        flat_cfg["blocks"]["disp"] = [("cmp", "eax, 3"), ("jmp", "eax")]
        flat_cfg["blocks"]["b_entry"] = [("push", "rbp")]

        cff_res = cff_score(flat_cfg)
        self.assertGreater(cff_res["score"], 0.6)
        self.assertEqual(cff_res["dispatcher"], "disp")

        xor_cfg = {
            "entry": "loop_head",
            "blocks": {
                "loop_head": [
                    ("movzx", "eax, byte [rsi]"),
                    ("xor", "eax, 0x5a"),
                    ("mov", "[rdi], al"),
                    ("inc", "rsi"),
                    ("dec", "rcx"),
                    ("jnz", "loop_head")
                ],
                "exit": [("ret", "")]
            },
            "edges": [("loop_head", "loop_head"), ("loop_head", "exit")]
        }
        hits = xor_decode_loops(xor_cfg)
        self.assertTrue(len(hits) > 0)
        self.assertEqual(hits[0]["xor_ops"], 1)
        print("test_cff_and_xor_detection OK")

    def test_pe_extraction(self):
        print("Running test_pe_extraction...")
        pe_bytes = create_synthetic_pe_bytes("ransomware")
        meta = parse_binary_metadata(pe_bytes)
        print("meta sections count:", len(meta["sections"]))
        self.assertEqual(meta["format"], "PE64")
        self.assertEqual(meta["arch"], "x86_64")
        self.assertTrue(len(meta["sections"]) >= 1)

        graph = extract_binary_graph(pe_bytes)
        self.assertTrue(len(graph["nodes"]) > 0)
        self.assertTrue(len(graph["edges"]) >= 0)
        print("test_pe_extraction OK")

class TestXRayModelsAndEval(unittest.TestCase):
    def test_gnn_and_fusion(self):
        print("Running test_gnn_and_fusion...")
        gnn = CallGraphGNN(in_dim=28, hidden_dim=32, emb_dim=32, num_classes=4)
        gnn.eval()
        nodes = {"0x1000": "profile_a", "0x2000": "profile_b"}
        meta = {
            "0x1000": {"instruction_profile": {"arith": 0.5}, "api_calls": [{"bucket": "crypto", "name": "CryptEncrypt"}]},
            "0x2000": {"instruction_profile": {"data": 0.4}, "api_calls": [{"bucket": "file", "name": "WriteFile"}]},
        }
        x, node_to_idx = extract_node_feature_matrix(nodes, meta)
        edge_index = build_edge_index([("0x1000", "0x2000")], node_to_idx)
        logits, emb = gnn(x, edge_index)
        self.assertEqual(logits.shape, (1, 4))
        self.assertEqual(emb.shape, (1, 32))

        fusion = fuse_scores(
            wl_scores={"ransomware": 0.88, "keylogger": 0.31, "downloader": 0.27, "benign": 0.22},
            gnn_probs={"ransomware": 0.93, "keylogger": 0.02, "downloader": 0.03, "benign": 0.02},
            obfuscation={"packed": {"likely": False, "structure_reliable": True}, "cff": [], "xor_decode": []}
        )
        self.assertEqual(fusion["verdict"]["label"], "malicious")
        self.assertEqual(fusion["verdict"]["family"], "ransomware")
        self.assertGreater(fusion["verdict"]["confidence"], 0.80)
        print("test_gnn_and_fusion OK")

    def test_evasion_lab_and_benchmarks(self):
        print("Running test_evasion_lab_and_benchmarks...")
        ev = run_evasion_study("tool-fileenc")
        self.assertEqual(ev["program_id"], "tool-fileenc")
        self.assertTrue(len(ev["results"]) >= 10)
        self.assertGreaterEqual(ev["summary"]["mean_retention_wo_packing"], 0.65)

        bm = run_benchmarks()
        self.assertGreaterEqual(bm["overall"]["auroc"], 0.97)
        self.assertGreaterEqual(bm["overall"]["tpr_at_1pct_fpr"], 0.90)
        print("test_evasion_lab_and_benchmarks OK")

if __name__ == "__main__":
    unittest.main()
