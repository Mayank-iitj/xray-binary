import random
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from wl_kernel import wl_features, cosine, label_log_odds, node_scores
from obfuscation import cff_score, xor_decode_loops, packing_indicators, shannon_entropy

def make_graph(seed):
    r = random.Random(seed); nodes, edges = {}, []
    for i in range(30): nodes[f"f{i}"] = r.choice(["arith", "mem", "branch", "api:file", "api:net", "api:crypto"])
    for i in range(1, 30): edges.append((f"f{r.randrange(i)}", f"f{i}"))
    return nodes, edges

def rename(nodes, edges):
    m = {n: f"x_{i}_{(i * 7919) % 1000}" for i, n in enumerate(nodes)}
    return {m[n]: l for n, l in nodes.items()}, [(m[a], m[b]) for a, b in edges]

def test_rename_invariance():
    n, e = make_graph(1); n2, e2 = rename(n, e)
    assert abs(cosine(wl_features(n, e)[0], wl_features(n2, e2)[0]) - 1.0) < 1e-9

def test_different_graphs_less_similar():
    assert cosine(wl_features(*make_graph(1))[0], wl_features(*make_graph(2))[0]) < 0.9

def test_small_perturbation_retains_similarity():
    n, e = make_graph(3); a = wl_features(n, e)[0]
    n2 = dict(n); n2["j1"] = "junk"; n2["j2"] = "junk"; e2 = e + [("f10", "j1"), ("j1", "j2")]
    assert 0.5 < cosine(a, wl_features(n2, e2)[0]) < 1.0

def fam_graph(s):
    n, e = make_graph(s)
    n = {**n, "m0": "api:crypto", "m1": "api:file", "m2": "api:file"}
    return n, e + [("f0", "m0"), ("m0", "m1"), ("m1", "m2")]

def test_discriminative_nodes_highlighted():
    fam = [wl_features(*fam_graph(s))[0] for s in range(10, 20)]
    ben = [wl_features(*make_graph(s))[0] for s in range(30, 40)]
    lo = label_log_odds(fam, ben)
    f, prov = wl_features(*fam_graph(10)); sc = node_scores(prov, lo)
    top = sorted(sc, key=lambda k: sc[k], reverse=True)[:8]
    assert any(t in top for t in ("m0", "m1", "m2", "f0"))

def flat_cfg(k=12):
    blocks = {f"b{i}": [("mov", "eax, 1")] for i in range(k)}
    blocks["disp"] = [("cmp", "eax, 3")]; blocks["entry"] = [("push", "rbp")]
    edges = [("entry", "disp")] + [("disp", f"b{i}") for i in range(k)] + [(f"b{i}", "disp") for i in range(k)]
    return {"blocks": blocks, "edges": edges, "entry": "entry"}

def normal_cfg():
    blocks = {f"b{i}": [("mov", "eax, 1")] for i in range(10)}
    edges = [(f"b{i}", f"b{i+1}") for i in range(9)] + [("b2", "b5"), ("b3", "b7")]
    return {"blocks": blocks, "edges": edges, "entry": "b0"}

def test_cff_detected():
    assert cff_score(flat_cfg())["score"] > 0.7 and cff_score(normal_cfg())["score"] < 0.4

def test_xor_loop():
    cfg = {"blocks": {"h": [("movzx", "eax, byte [rsi]"), ("xor", "eax, 0x5a"), ("mov", "[rdi], al"),
                            ("inc", "rsi"), ("dec", "rcx"), ("jnz", "h")], "x": [("ret", "")]},
           "edges": [("h", "h"), ("h", "x")], "entry": "h"}
    assert xor_decode_loops(cfg)
    zero = {"blocks": {"h": [("xor", "eax, eax"), ("inc", "rsi"), ("jnz", "h")]}, "edges": [("h", "h")], "entry": "h"}
    assert not xor_decode_loops(zero)

def test_entropy_and_packing():
    assert shannon_entropy(bytes(range(256)) * 10) > 7.9 and shannon_entropy(b"A" * 100) == 0
    p = packing_indicators([{"name": ".text", "entropy": 7.6, "flags": "rwx", "is_entry": True}])
    assert p["packed_likely"] and not p["structure_reliable"]
