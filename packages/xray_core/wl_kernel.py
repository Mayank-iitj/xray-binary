"""Weisfeiler-Lehman graph fingerprinting + discriminative node attribution.

Implements:
1. Directed WL iteration: each node's next label is a blake2b hash of its own label,
   sorted out-neighbour labels, and sorted in-neighbour labels.
2. Label histogram vector construction (depths 0..h).
3. Sublinear-TF IDF cosine similarity between structural vectors.
4. Smoothed log-odds attribution mapping discriminative motifs (family vs. benign).
5. Per-node suspicion scoring combining high-order WL motifs.
"""
from __future__ import annotations
import hashlib
import math
from collections import Counter, defaultdict
from typing import Dict, Iterable, List, Tuple, Any

def _blake_hash(s: str) -> str:
    return hashlib.blake2b(s.encode("utf-8"), digest_size=8).hexdigest()

def wl_features(
    nodes: Dict[str, str],
    edges: Iterable[Tuple[str, str]],
    iters: int = 3,
) -> Tuple[Counter, Dict[str, List[str]]]:
    """Computes directed Weisfeiler-Lehman feature vector and per-node provenance.

    Args:
        nodes: mapping of node_id -> structural label string
        edges: iterable of (src, dst) directed call edges
        iters: WL depth iterations (default 3)

    Returns:
        feats: Counter of "depth:hash" frequencies
        prov: mapping of node_id -> list of labels at each depth [0..iters]
    """
    out_n: Dict[str, List[str]] = defaultdict(list)
    in_n: Dict[str, List[str]] = defaultdict(list)
    for s, d in edges:
        if s in nodes and d in nodes:
            out_n[s].append(d)
            in_n[d].append(s)

    labels = {n: _blake_hash(l) for n, l in nodes.items()}
    feats: Counter = Counter(f"0:{l}" for l in labels.values())
    prov: Dict[str, List[str]] = {n: [f"0:{labels[n]}"] for n in nodes}

    for t in range(1, iters + 1):
        new_labels = {}
        for n in nodes:
            o = ",".join(sorted(labels[m] for m in out_n[n]))
            i = ",".join(sorted(labels[m] for m in in_n[n]))
            new_labels[n] = _blake_hash(f"{labels[n]}|o:{o}|i:{i}")
        labels = new_labels
        feats.update(f"{t}:{l}" for l in labels.values())
        for n in nodes:
            prov[n].append(f"{t}:{labels[n]}")

    return feats, prov

def cosine(
    a: Counter,
    b: Counter,
    idf: Dict[str, float] | None = None,
) -> float:
    """Sublinear-TF (1 + ln(tf)) IDF-weighted cosine similarity in [0.0, 1.0]."""
    if not a or not b:
        return 0.0

    def w(k: str, v: int) -> float:
        tf_weight = 1.0 + math.log(v)
        idf_weight = idf.get(k, 1.0) if idf else 1.0
        return tf_weight * idf_weight

    shared_keys = set(a.keys()) & set(b.keys())
    if not shared_keys:
        return 0.0

    dot = sum(w(k, a[k]) * w(k, b[k]) for k in shared_keys)
    norm_a = math.sqrt(sum(w(k, v) ** 2 for k, v in a.items()))
    norm_b = math.sqrt(sum(w(k, v) ** 2 for k, v in b.items()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (norm_a * norm_b)))

def build_idf(corpus: List[Counter]) -> Dict[str, float]:
    """Calculates Inverse Document Frequency (IDF) over a corpus of WL feature vectors."""
    n = len(corpus)
    if n == 0:
        return {}
    df = Counter()
    for doc in corpus:
        for k in doc.keys():
            df[k] += 1
    return {k: math.log((1.0 + n) / (1.0 + count)) + 1.0 for k, count in df.items()}

def label_log_odds(
    family_docs: List[Counter],
    benign_docs: List[Counter],
    alpha: float = 1.0,
    min_depth: int = 1,
) -> Dict[str, float]:
    """Calculates smoothed log-odds ratio that a WL label belongs to the target family vs benign.

    log_odds(k) = log(P(k|family) / (1 - P(k|family))) - log(P(k|benign) / (1 - P(k|benign)))
    Skips depth 0 by default to focus on relational/topological motifs rather than isolated opcodes.
    """
    fam_df = Counter()
    for doc in family_docs:
        for k in doc.keys():
            fam_df[k] += 1

    ben_df = Counter()
    for doc in benign_docs:
        for k in doc.keys():
            ben_df[k] += 1

    nf = len(family_docs)
    nb = len(benign_docs)
    out: Dict[str, float] = {}

    all_keys = set(fam_df.keys()) | set(ben_df.keys())
    for k in all_keys:
        try:
            depth = int(k.split(":", 1)[0])
        except (ValueError, IndexError):
            depth = 0
        if depth < min_depth:
            continue

        pf = (fam_df[k] + alpha) / (nf + 2.0 * alpha)
        pb = (ben_df[k] + alpha) / (nb + 2.0 * alpha)
        val = math.log(pf / (1.0 - pf)) - math.log(pb / (1.0 - pb))
        out[k] = round(val, 4)

    return out

def node_scores(
    prov: Dict[str, List[str]],
    log_odds: Dict[str, float],
    top_k: int = 2,
) -> Dict[str, float]:
    """Suspicion score per node = normalized mean of the top_k positive log-odds among WL labels (depth >= 1).

    Maps output to [0.0, 1.0] using sigmoid-like scaling.
    """
    res: Dict[str, float] = {}
    for n, labs in prov.items():
        # labs[0] is depth 0, labs[1:] are depth >= 1
        higher_depth_labs = labs[1:] if len(labs) > 1 else labs
        vals = sorted([max(log_odds.get(l, 0.0), 0.0) for l in higher_depth_labs], reverse=True)[:top_k]
        raw_score = sum(vals) / top_k if vals else 0.0
        # Smooth logistic mapping: 0 -> 0.05, 3.0 -> 0.73, 5.0 -> 0.92, 7.0+ -> ~0.98
        score = 1.0 / (1.0 + math.exp(-0.7 * (raw_score - 1.5))) if raw_score > 0 else 0.02
        res[n] = round(score, 3)
    return res
