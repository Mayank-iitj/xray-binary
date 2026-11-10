"""Weisfeiler-Lehman fingerprints + discriminative node scoring (reference implementation).

Directed WL: a node's next label hashes its own label with the sorted multisets of
out-neighbour and in-neighbour labels. Feature vector = histogram of (depth, label).
Labels are structure-only (instruction-class profile + API bucket), never raw bytes/names.
"""
from __future__ import annotations
import hashlib, math
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple

def _h(s: str) -> str:
    return hashlib.blake2b(s.encode(), digest_size=8).hexdigest()

def wl_features(nodes: Dict[str, str], edges: Iterable[Tuple[str, str]], iters: int = 3):
    """nodes: {node_id: label_string}; edges: (src, dst). Returns (Counter, provenance)."""
    out_n, in_n = defaultdict(list), defaultdict(list)
    for s, d in edges:
        out_n[s].append(d); in_n[d].append(s)
    labels = {n: _h(l) for n, l in nodes.items()}
    feats: Counter = Counter(f"0:{l}" for l in labels.values())
    prov: Dict[str, List[str]] = {n: [f"0:{labels[n]}"] for n in nodes}
    for t in range(1, iters + 1):
        new = {}
        for n in nodes:
            o = ",".join(sorted(labels[m] for m in out_n[n]))
            i = ",".join(sorted(labels[m] for m in in_n[n]))
            new[n] = _h(f"{labels[n]}|o:{o}|i:{i}")
        labels = new
        feats.update(f"{t}:{l}" for l in labels.values())
        for n in nodes:
            prov[n].append(f"{t}:{labels[n]}")
    return feats, prov

def cosine(a: Counter, b: Counter, idf: Dict[str, float] | None = None) -> float:
    """Sublinear-TF (optionally IDF-weighted) cosine similarity in [0,1]."""
    def w(k, v): return (1 + math.log(v)) * (idf.get(k, 1.0) if idf else 1.0)
    if not a or not b: return 0.0
    dot = sum(w(k, v) * w(k, b[k]) for k, v in a.items() if k in b)
    na = math.sqrt(sum(w(k, v) ** 2 for k, v in a.items()))
    nb = math.sqrt(sum(w(k, v) ** 2 for k, v in b.items()))
    return dot / (na * nb) if na and nb else 0.0

def build_idf(corpus: List[Counter]) -> Dict[str, float]:
    df = Counter(k for c in corpus for k in c)
    n = len(corpus)
    return {k: math.log((1 + n) / (1 + v)) + 1.0 for k, v in df.items()}

def label_log_odds(family_docs: List[Counter], benign_docs: List[Counter], alpha: float = 1.0,
                   min_depth: int = 1) -> Dict[str, float]:
    """Smoothed log-odds that a WL label belongs to the family vs benign (document frequency).
    Depth-0 labels are skipped by default: they are generic instruction profiles."""
    fam_df = Counter(k for c in family_docs for k in c)
    ben_df = Counter(k for c in benign_docs for k in c)
    nf, nb = len(family_docs), len(benign_docs)
    out = {}
    for k in set(fam_df) | set(ben_df):
        if int(k.split(":", 1)[0]) < min_depth: continue
        pf = (fam_df[k] + alpha) / (nf + 2 * alpha)
        pb = (ben_df[k] + alpha) / (nb + 2 * alpha)
        out[k] = math.log(pf / (1 - pf)) - math.log(pb / (1 - pb))
    return out

def node_scores(prov: Dict[str, List[str]], log_odds: Dict[str, float], top_k: int = 2) -> Dict[str, float]:
    """Per-node suspicion = mean of the top_k positive log-odds among the node's WL labels (depths>=1)."""
    res = {}
    for n, labs in prov.items():
        vals = sorted((max(log_odds.get(l, 0.0), 0.0) for l in labs[1:]), reverse=True)[:top_k]
        res[n] = sum(vals) / top_k if vals else 0.0
    return res
