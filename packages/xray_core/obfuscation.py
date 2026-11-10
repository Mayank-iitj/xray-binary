"""Obfuscation Detectors: Control-Flow Flattening, XOR Decoders, Packing Indicators, Junk Code.

All detectors return mathematical evidence with function addresses and metrics, NOT black-box flags.
"""
from __future__ import annotations
import math
from collections import Counter
from typing import Dict, List, Tuple, Any
import networkx as nx

def shannon_entropy(data: bytes) -> float:
    """Calculates Shannon entropy in bits per byte [0.0, 8.0]."""
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return round(-sum(v / n * math.log2(v / n) for v in c.values()), 3)

def cff_score(cfg: Dict[str, Any], min_blocks: int = 6) -> Dict[str, Any]:
    """Detects Control-Flow Flattening (CFF) inside a function CFG.

    A flattened CFG features a central dispatcher block with high in-degree and out-degree,
    where the majority of basic blocks return exclusively to the dispatcher.
    """
    blocks = cfg.get("blocks", {})
    edges = cfg.get("edges", [])
    entry = cfg.get("entry")

    g = nx.DiGraph()
    g.add_nodes_from(blocks.keys())
    g.add_edges_from(edges)

    num_nodes = g.number_of_nodes()
    if num_nodes < min_blocks:
        return {
            "score": 0.0,
            "dispatcher": None,
            "back_ratio": 0.0,
            "fan_in_ratio": 0.0,
            "detected": False
        }

    # Candidate dispatcher is the node with the highest in-degree
    disp = max(g.nodes, key=lambda n: g.in_degree(n))
    in_deg = g.in_degree(disp)
    out_deg = g.out_degree(disp)

    # Exclude dispatcher and entry to examine execution body blocks
    body_blocks = [n for n in g.nodes if n not in (disp, entry)]
    if not body_blocks:
        return {
            "score": 0.0,
            "dispatcher": None,
            "back_ratio": 0.0,
            "fan_in_ratio": 0.0,
            "detected": False
        }

    # Blocks whose ONLY successor is the dispatcher
    back_to_disp = [n for n in body_blocks if list(g.successors(n)) == [disp]]
    back_ratio = len(back_to_disp) / len(body_blocks)
    fan_in_ratio = in_deg / num_nodes
    fan_out_sufficient = out_deg >= 3

    if fan_out_sufficient and fan_in_ratio >= 0.35 and back_ratio >= 0.45:
        score = min(1.0, 0.55 * back_ratio + 0.45 * min(1.0, fan_in_ratio * 1.8))
    else:
        score = 0.0

    return {
        "score": round(score, 3),
        "dispatcher": disp if score > 0.4 else None,
        "back_ratio": round(back_ratio, 3),
        "fan_in_ratio": round(fan_in_ratio, 3),
        "detected": score >= 0.65
    }

def xor_decode_loops(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Detects XOR decoding/decryption loops in a function CFG.

    Identifies Strongly Connected Components (SCCs) containing:
    1. A non-zeroing XOR operation (e.g. xor eax, 0x5a or xor [rdi], cl)
    2. A memory store operation (mov [rdi], al or stosb)
    3. A counter update (inc, dec, add, sub, loop)
    4. A conditional branch (jnz, jne, jb, etc.)
    """
    blocks = cfg.get("blocks", {})
    edges = cfg.get("edges", [])

    g = nx.DiGraph()
    g.add_nodes_from(blocks.keys())
    g.add_edges_from(edges)

    hits = []
    for scc in nx.strongly_connected_components(g):
        if len(scc) == 1:
            single = next(iter(scc))
            if not g.has_edge(single, single):
                continue

        insns = [insn for b in scc for insn in blocks.get(b, [])]

        xors = []
        for op in insns:
            if isinstance(op, (list, tuple)) and len(op) >= 2:
                mnemonic, operands = op[0].lower(), op[1].lower()
            elif isinstance(op, dict):
                mnemonic = op.get("mnemonic", op.get("type", "")).lower()
                operands = op.get("operands", op.get("op_str", op.get("disasm", ""))).lower()
            else:
                continue

            if mnemonic == "xor":
                # Check for non-zeroing XOR: e.g. "eax, eax" is zeroing; different operands is decryption
                parts = [p.strip() for p in operands.split(",") if p.strip()]
                if len(parts) >= 2 and parts[0] != parts[1]:
                    xors.append((mnemonic, operands))

        stores = 0
        counters = 0
        cond_branches = 0

        for op in insns:
            if isinstance(op, (list, tuple)) and len(op) >= 2:
                mnemonic, operands = op[0].lower(), op[1].lower()
            elif isinstance(op, dict):
                mnemonic = op.get("mnemonic", op.get("type", "")).lower()
                operands = op.get("operands", op.get("op_str", op.get("disasm", ""))).lower()
            else:
                continue

            if mnemonic in ("mov", "movb", "movw", "movd", "stosb", "stosd", "stosw"):
                if "[" in operands or mnemonic.startswith("stos"):
                    stores += 1
            if mnemonic in ("inc", "dec", "add", "sub", "loop", "loopne", "loope"):
                counters += 1
            if (mnemonic.startswith("j") and mnemonic not in ("jmp",)) or mnemonic == "loop":
                cond_branches += 1

        if xors and (stores > 0 or len(xors) >= 2) and (counters > 0 or cond_branches > 0):
            hits.append({
                "loop_blocks": sorted(list(scc)),
                "xor_ops": len(xors),
                "has_memory_write": stores > 0,
                "has_counter": counters > 0
            })

    return hits

def packing_indicators(sections: List[Dict[str, Any]], imports: List[Any] | None = None) -> Dict[str, Any]:
    """Evaluates whether an executable exhibits structural packing/encryption indicators.

    Checks:
    - High-entropy executable section (> 7.2 bits/byte)
    - Writable and Executable (W+X) sections
    - Entry point located in a high-entropy section
    - Extremely sparse import table (< 5 imports, typical of runtime stubs)
    """
    evidence: List[str] = []

    for s in sections:
        name = s.get("name", "")
        entropy = float(s.get("entropy", 0.0))
        flags = str(s.get("flags", "")).lower()
        is_exec = "x" in flags or s.get("executable", False)
        is_write = "w" in flags or s.get("writable", False)
        is_entry = s.get("is_entry", False)

        if is_exec and entropy > 7.15:
            evidence.append(f"High-entropy executable section '{name}' (entropy: {entropy:.2f})")
        if is_exec and is_write:
            evidence.append(f"Writable + Executable (W+X) section '{name}'")
        if is_entry and entropy > 7.0:
            evidence.append(f"Entry point located inside high-entropy section '{name}' ({entropy:.2f})")

    if imports is not None:
        if len(imports) > 0 and len(imports) <= 4:
            evidence.append(f"Abnormally sparse import table ({len(imports)} symbols, unpacker stub characteristic)")

    packed_likely = len(evidence) >= 2
    return {
        "likely": packed_likely,
        "structure_reliable": not packed_likely,
        "evidence": evidence,
        "evidence_count": len(evidence)
    }

def detect_junk_code(blocks: Dict[str, List[Any]]) -> Dict[str, Any]:
    """Calculates dead-code / NOP-equivalent junk code ratio."""
    total_insns = 0
    junk_insns = 0
    junk_locations: List[str] = []

    for block_id, insns in blocks.items():
        total_insns += len(insns)
        for i, op in enumerate(insns):
            if isinstance(op, (list, tuple)) and len(op) >= 2:
                mnemonic, operands = op[0].lower(), op[1].lower()
            elif isinstance(op, dict):
                mnemonic = op.get("mnemonic", op.get("type", "")).lower()
                operands = op.get("operands", op.get("op_str", op.get("disasm", ""))).lower()
            else:
                continue

            # NOP instructions
            if mnemonic == "nop" or (mnemonic == "lea" and "eax, [eax]" in operands):
                junk_insns += 1
                if len(junk_locations) < 10:
                    junk_locations.append(f"{block_id}:nop")
            # Self-assigning movs: mov eax, eax
            elif mnemonic == "mov" and len([p.strip() for p in operands.split(",") if p.strip()]) == 2:
                p1, p2 = [p.strip() for p in operands.split(",")][:2]
                if p1 == p2:
                    junk_insns += 1
                    if len(junk_locations) < 10:
                        junk_locations.append(f"{block_id}:dead_mov")
            # Redundant adds/subs: add reg, 0
            elif mnemonic in ("add", "sub") and operands.endswith(", 0"):
                junk_insns += 1

    ratio = round(junk_insns / max(1, total_insns), 3)
    return {
        "junk_ratio": ratio,
        "junk_instructions": junk_insns,
        "total_instructions": total_insns,
        "sample_locations": junk_locations
    }

