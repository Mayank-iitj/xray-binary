"""Heuristic obfuscation indicators on per-function CFGs (reference implementation).

Each CFG: {"blocks": {bid: [(mnemonic, op_str), ...]}, "edges": [(src, dst), ...], "entry": bid}
These are heuristics that report evidence + a 0..1 score; they are NOT proofs.
"""
from __future__ import annotations
import math
import networkx as nx
from collections import Counter
from typing import List

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    c = Counter(data)
    n = len(data)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def cff_score(cfg: dict, min_blocks: int = 8) -> dict:
    """Control-flow flattening: one dispatcher block with very high fan-in/out; most body blocks
    have the dispatcher as their ONLY successor."""
    g = nx.DiGraph()
    g.add_nodes_from(cfg["blocks"])
    g.add_edges_from(cfg["edges"])
    if g.number_of_nodes() < min_blocks:
        return {"score": 0.0, "dispatcher": None}
    disp = max(g.nodes, key=lambda n: g.in_degree(n))
    body = [n for n in g.nodes if n not in (disp, cfg.get("entry"))]
    back = [n for n in body if list(g.successors(n)) == [disp]]
    back_ratio = len(back) / max(1, len(body))
    fan_ratio = g.in_degree(disp) / g.number_of_nodes()
    fan_out_ok = g.out_degree(disp) >= 3
    score = (0.6 * back_ratio + 0.4 * min(1.0, fan_ratio * 2)) if fan_out_ok else 0.0
    return {"score": round(score, 3), "dispatcher": disp, "back_ratio": round(back_ratio, 3),
            "fan_in_ratio": round(fan_ratio, 3)}

def xor_decode_loops(cfg: dict) -> List[dict]:
    """Loop (SCC) containing a non-zeroing XOR, a memory store, and a counter update + conditional branch."""
    g = nx.DiGraph()
    g.add_nodes_from(cfg["blocks"])
    g.add_edges_from(cfg["edges"])
    hits = []
    for scc in nx.strongly_connected_components(g):
        insns = [i for b in scc for i in cfg["blocks"][b]]
        if len(scc) == 1 and not g.has_edge(next(iter(scc)), next(iter(scc))):
            continue
        xors = [(m, o) for m, o in insns if m == "xor" and len({p.strip() for p in o.split(",")}) > 1]
        stores = [1 for m, o in insns if m in ("mov", "movb", "stosb") and o.split(",")[0].strip().endswith("]")]
        counters = [1 for m, _ in insns if m in ("inc", "dec", "add", "sub", "loop")]
        cond = [1 for m, _ in insns if m.startswith("j") and m != "jmp"]
        if xors and stores and counters and cond:
            hits.append({"blocks": sorted(scc), "xor_ops": len(xors)})
    return hits

def packing_indicators(sections: List[dict]) -> dict:
    """sections: [{name, entropy, flags:'rwx', is_entry:bool}]. Flags likely-packed binaries."""
    ev = []
    if any(s["entropy"] > 7.2 and "x" in s["flags"] for s in sections):
        ev.append("high-entropy executable section")
    if any("w" in s["flags"] and "x" in s["flags"] for s in sections):
        ev.append("writable+executable section")
    ent = [s for s in sections if s.get("is_entry")]
    if ent and ent[0]["entropy"] > 7.0:
        ev.append("entry point in high-entropy section")
    return {"packed_likely": len(ev) >= 2, "structure_reliable": len(ev) < 2, "evidence": ev}
