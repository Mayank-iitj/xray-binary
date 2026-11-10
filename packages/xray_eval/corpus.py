"""Reference Corpus Generation and Knowledge Base for Malware Triage.

Generates reproducible reference call graphs, WL feature vectors, label log-odds, and IDF stats
for four primary classes:
- Ransomware (directory traversal -> crypto key generation -> encryption -> write-back -> shadow copy removal)
- Keylogger (SetWindowsHookEx / GetAsyncKeyState -> keystroke buffer -> exfiltration network dispatcher)
- Downloader (HTTP handshake -> payload fetch -> temp file drop -> CreateProcess execution)
- Benign (file manipulation, arithmetic math routines, sorting, JSON parsing, clean UI event loop)
"""
from __future__ import annotations
import random
from collections import Counter
from typing import Dict, List, Tuple, Any

from xray_core.wl_kernel import wl_features, build_idf, label_log_odds
from xray_core.labelling import extract_node_label

def build_ransomware_graph(seed: int = 42) -> Tuple[Dict[str, str], List[Tuple[str, str]], Dict[str, Any]]:
    """Synthesizes a realistic ransomware structural call graph."""
    rng = random.Random(seed)
    nodes: Dict[str, str] = {}
    edges: List[Tuple[str, str]] = []
    meta: Dict[str, Any] = {}

    # Entry point & setup
    nodes["0x140001000"] = extract_node_label(["push", "mov", "sub", "call"], ["IsDebuggerPresent"], 2, 3)
    nodes["0x140001200"] = extract_node_label(["mov", "call", "test", "jnz"], ["GetFileSize"], 3, 4)

    # Core malicious pipeline (The ransomware triad: Enumerate -> Encrypt -> WriteBack)
    nodes["0x140002100"] = extract_node_label(["push", "mov", "call", "test", "jnz"], ["FindFirstFile", "FindNextFile"], 5, 8)
    nodes["0x140002400"] = extract_node_label(["push", "mov", "call"], ["CryptAcquireContext", "CryptGenKey"], 4, 6)
    nodes["0x140002800"] = extract_node_label(["mov", "xor", "add", "call", "loop"], ["CryptEncrypt"], 8, 12)
    nodes["0x140002b00"] = extract_node_label(["push", "mov", "call", "cmp", "jz"], ["CreateFile", "WriteFile"], 4, 5)
    nodes["0x140003000"] = extract_node_label(["push", "mov", "call"], ["ShellExecute"], 2, 3) # VSSadmin delete shadows

    # Connect triad
    edges.extend([
        ("0x140001000", "0x140001200"),
        ("0x140001200", "0x140002100"),
        ("0x140002100", "0x140002400"),
        ("0x140002400", "0x140002800"),
        ("0x140002800", "0x140002b00"),
        ("0x140002100", "0x140002b00"), # Recursive traversal
        ("0x140001200", "0x140003000"),
    ])

    # Add auxiliary utility functions
    for i in range(15):
        fid = f"0x140004{i:03x}"
        nodes[fid] = extract_node_label(["mov", "add", "cmp", "ret"], [], 2, 2)
        caller = rng.choice(list(nodes.keys())[:-1])
        edges.append((caller, fid))

    return nodes, edges, meta

def build_keylogger_graph(seed: int = 101) -> Tuple[Dict[str, str], List[Tuple[str, str]], Dict[str, Any]]:
    """Synthesizes a realistic keylogger structural call graph."""
    nodes: Dict[str, str] = {}
    edges: List[Tuple[str, str]] = []
    meta: Dict[str, Any] = {}

    nodes["0x140010000"] = extract_node_label(["push", "mov", "call"], ["IsDebuggerPresent"], 2, 2)
    nodes["0x140010500"] = extract_node_label(["push", "mov", "call", "test"], ["SetWindowsHookEx"], 4, 5)
    nodes["0x140010800"] = extract_node_label(["mov", "call", "cmp", "jnz"], ["GetAsyncKeyState", "GetForegroundWindow"], 6, 9)
    nodes["0x140011000"] = extract_node_label(["mov", "xor", "call"], ["WriteFile"], 3, 4)
    nodes["0x140011400"] = extract_node_label(["push", "call", "test"], ["InternetOpen", "HttpSendRequest"], 4, 6)

    edges.extend([
        ("0x140010000", "0x140010500"),
        ("0x140010500", "0x140010800"),
        ("0x140010800", "0x140011000"),
        ("0x140010800", "0x140011400"),
    ])

    for i in range(12):
        fid = f"0x140012{i:03x}"
        nodes[fid] = extract_node_label(["mov", "arith", "stack"], [], 1, 2)
        edges.append(("0x140010800", fid))

    return nodes, edges, meta

def build_downloader_graph(seed: int = 202) -> Tuple[Dict[str, str], List[Tuple[str, str]], Dict[str, Any]]:
    """Synthesizes a realistic downloader / dropper structural call graph."""
    nodes: Dict[str, str] = {}
    edges: List[Tuple[str, str]] = []
    meta: Dict[str, Any] = {}

    nodes["0x140020000"] = extract_node_label(["push", "mov", "call"], [], 2, 2)
    nodes["0x140020400"] = extract_node_label(["push", "call", "test"], ["URLDownloadToFile", "InternetOpenUrl"], 4, 6)
    nodes["0x140020800"] = extract_node_label(["mov", "call", "cmp"], ["CreateFile", "WriteFile"], 3, 4)
    nodes["0x140021000"] = extract_node_label(["push", "call"], ["CreateProcess", "ShellExecute"], 3, 4)

    edges.extend([
        ("0x140020000", "0x140020400"),
        ("0x140020400", "0x140020800"),
        ("0x140020800", "0x140021000"),
    ])

    for i in range(10):
        fid = f"0x140022{i:03x}"
        nodes[fid] = extract_node_label(["mov", "arith", "ret"], [], 1, 2)
        edges.append(("0x140020000", fid))

    return nodes, edges, meta

def build_benign_graph(seed: int = 303) -> Tuple[Dict[str, str], List[Tuple[str, str]], Dict[str, Any]]:
    """Synthesizes a clean utility program call graph (math/sort/string/file reader)."""
    rng = random.Random(seed)
    nodes: Dict[str, str] = {}
    edges: List[Tuple[str, str]] = []
    meta: Dict[str, Any] = {}

    nodes["0x140030000"] = extract_node_label(["push", "mov", "call"], [], 2, 3) # main
    nodes["0x140030300"] = extract_node_label(["mov", "call", "cmp"], ["ReadFile"], 3, 4) # parse_args
    nodes["0x140030600"] = extract_node_label(["mov", "add", "cmp", "loop"], [], 4, 6) # sort/math algorithm
    nodes["0x140030900"] = extract_node_label(["mov", "arith", "cjmp"], [], 3, 4) # compute_hash
    nodes["0x140031000"] = extract_node_label(["mov", "call"], ["WriteFile"], 2, 3) # print output

    edges.extend([
        ("0x140030000", "0x140030300"),
        ("0x140030000", "0x140030600"),
        ("0x140030600", "0x140030900"),
        ("0x140030000", "0x140031000"),
    ])

    for i in range(20):
        fid = f"0x140032{i:03x}"
        nodes[fid] = extract_node_label(["mov", "arith", "ret"], [], 1, 2)
        caller = rng.choice(list(nodes.keys())[:5])
        edges.append((caller, fid))

    return nodes, edges, meta

class ReferenceCorpus:
    """Manages the reference malware family corpus, IDF vectors, and discriminative motif tables."""
    def __init__(self) -> None:
        self.families = ["ransomware", "keylogger", "downloader", "benign"]
        self.corpus_graphs: Dict[str, List[Tuple[Dict[str, str], List[Tuple[str, str]]]]] = {}
        self.wl_vectors: Dict[str, List[Counter]] = {}
        self.all_vectors: List[Counter] = []
        self.idf: Dict[str, float] = {}
        self.log_odds: Dict[str, Dict[str, float]] = {}
        self._build_corpus()

    def _build_corpus(self) -> None:
        # Generate representative variations of each family with structural variations
        for fam in self.families:
            self.corpus_graphs[fam] = []
            self.wl_vectors[fam] = []

            for i in range(8):
                seed = i * 37 + hash(fam) % 1000
                if fam == "ransomware":
                    n, e, _ = build_ransomware_graph(seed)
                elif fam == "keylogger":
                    n, e, _ = build_keylogger_graph(seed)
                elif fam == "downloader":
                    n, e, _ = build_downloader_graph(seed)
                else:
                    n, e, _ = build_benign_graph(seed)

                vec, _ = wl_features(n, e, iters=3)
                self.corpus_graphs[fam].append((n, e))
                self.wl_vectors[fam].append(vec)
                self.all_vectors.append(vec)

        # Compute corpus-wide IDF
        self.idf = build_idf(self.all_vectors)

        # Compute discriminative log-odds for each malware family vs benign
        benign_vecs = self.wl_vectors["benign"]
        for fam in ["ransomware", "keylogger", "downloader"]:
            fam_vecs = self.wl_vectors[fam]
            self.log_odds[fam] = label_log_odds(fam_vecs, benign_vecs, alpha=1.0, min_depth=1)

    def score_sample(self, sample_vec: Counter) -> Tuple[Dict[str, float], str, float]:
        """Calculates nearest-neighbor and mean-top-3 WL similarity against each reference family."""
        from xray_core.wl_kernel import cosine

        scores: Dict[str, float] = {}
        for fam, vecs in self.wl_vectors.items():
            sims = [cosine(sample_vec, ref_vec, self.idf) for ref_vec in vecs]
            sims.sort(reverse=True)
            # Top-1 nearest neighbor and mean of top-3
            top1 = sims[0] if sims else 0.0
            mean_top3 = sum(sims[:3]) / min(3, len(sims)) if sims else 0.0
            scores[fam] = round(0.7 * top1 + 0.3 * mean_top3, 3)

        top_fam = max(["ransomware", "keylogger", "downloader"], key=lambda f: scores.get(f, 0.0))
        return scores, top_fam, scores.get(top_fam, 0.0)

# Singleton global reference corpus
_GLOBAL_CORPUS: ReferenceCorpus | None = None

def get_reference_corpus() -> ReferenceCorpus:
    global _GLOBAL_CORPUS
    if _GLOBAL_CORPUS is None:
        _GLOBAL_CORPUS = ReferenceCorpus()
    return _GLOBAL_CORPUS
