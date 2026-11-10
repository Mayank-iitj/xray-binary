# X-Ray Binary — Pitch Deck, Demo Script and Submission Copy

## 1. Deck Outline (12 slides, 5–7 min)

| # | Slide | Content | Visual |
|---|---|---|---|
| 1 | Title | **X-Ray Binary** — *Traditional antivirus reads the words. X-Ray Binary reads the thoughts.* | Binary → glowing graph |
| 2 | Problem | Signatures match bytes/strings/symbols; attackers rewrite them for free; logic stays the same | Same program, 4 different hashes |
| 3 | Why it matters | Triage latency, black-box ML, no published evasion evidence | 3 pain icons |
| 4 | Insight | Authors can change how code *looks*, not what it *must do* — structure persists | Call graph of ransomware: enumerate→crypto→write |
| 5 | How it works | Pipeline: radare2 → call graph → structural labels → WL fingerprint + GNN → fusion | Pipeline diagram |
| 6 | Explainable | 3D graph, evidence nodes, motif stats ("71 % ransomware / 0 % benign"), obfuscation flags | Screenshot |
| 7 | Live demo | (see script) | Live |
| 8 | Evasion Lab | Same benign program through -O0…-O3, strip, UPX, string-XOR, OLLVM, junk → retention vs baselines | Waterfall chart |
| 9 | Results | Per-family P/R, TPR@1 % FPR, LOFO, baselines table — **measured numbers only** | Tables |
| 10 | Honest limits | Packing, inlining, CFF effects, dataset shift, adaptive adversaries — and what we do about each | Table |
| 11 | Impact and fit | SOC/IR triage layer, offline, complements EDR, deployable by `docker compose up` | Architecture |
| 12 | Roadmap and ask | Adversarial training, more formats/arches, analyst feedback loop, SIEM/SOAR integration | Timeline |

## 2. Live Demo Script (≈ 3 min, with fallbacks)

| t | Action | Say |
|---|---|---|
| 0:00 | Show Evasion Lab cached result: hash/YARA/TLSH bars collapse after UPX/string-XOR, ours holds | "Same program, five rewrites. Signature engines lose it; structure doesn't." |
| 0:40 | Upload a pre-selected sample (`?demo=1`) | "Never executed — static only." |
| 0:55 | Progress stepper → report | "Verdict plus a reason, in under a minute." |
| 1:15 | Overview: family similarity, WL and GNN agreement | "Two independent scorers agree." |
| 1:30 | Click top evidence → camera flies to node → inspector | "This function is why: file enumeration into crypto into write-back. Seen in 71 % of ransomware references, 0 % of benign." |
| 2:00 | Obfuscation tab: CFF + XOR decode flagged | "It is hiding — and we show where." |
| 2:20 | Packed sample banner | "When we can't see, we say so, instead of guessing." |
| 2:40 | Benchmarks tab | "Everything here regenerates from `make eval`." |

**Fallbacks:** pre-recorded 90-second video; cached analyses (no backend needed); screenshots in the deck. Rehearse twice with the network off.

## 3. Elevator Pitches

**10 seconds:** X-Ray Binary detects malware by the *shape of its logic*, not its bytes — so repacking, renaming and recompiling don't hide it, and analysts can see exactly where the malicious code lives.

**30 seconds:** Signature antivirus matches bytes that attackers rewrite for free. We disassemble statically, turn the program into a call graph labelled by what each function *does*, fingerprint it with Weisfeiler–Lehman kernels plus a GNN, and compare it with ransomware, keylogger and downloader families. Every verdict is traceable in an interactive 3D graph, and an Evasion Lab quantifies how much detection survives each evasion technique.

## 4. Submission Form Copy (ready to paste)

**Title:** X-Ray Binary — Structural, Explainable Malware Triage

**Short description (≤ 280 chars):** Static malware detection by program structure: radare2 call graphs, Weisfeiler–Lehman fingerprints and a GNN, with an interactive 3D evidence graph and an Evasion Lab that measures robustness to repacking, obfuscation and recompilation. Offline, defensive, explainable.

**Problem:** Signature AV matches bytes, strings and symbols that attackers rewrite at near-zero cost; polymorphic and obfuscated malware keeps its logic but loses its signature.

**Solution:** Fingerprint program *structure* (call graph labelled by instruction-class profile and API semantics), match against reference families and a benign baseline with two independent scorers, and show analysts the exact functions that drove the verdict.

**What's novel:** (1) structure-only node labels designed for evasion invariance; (2) WL + GNN dual scoring with node-level, faithful attribution; (3) obfuscation indicators with evidence; (4) a reproducible Evasion Lab with baselines and published retention numbers.

**Tech:** radare2, Python, PyTorch Geometric, scikit-learn, FastAPI, Redis/RQ, Next.js, three.js (3d-force-graph), Docker.

**Impact:** Faster, explainable triage for SOC/IR teams, deployable offline beside EDR.

**Limitations (stated):** packed samples are flagged "structure unreliable"; inlining and flattening reduce retention (measured); managed/script malware out of scope in v1.

**Ethics:** Defensive only; no execution; Evasion Lab uses benign source programs.

## 5. Judging-Criteria Map

| Typical criterion | Where we score | Evidence to show |
|---|---|---|
| Innovation | Structure-only labels + dual scorers + evasion invariance | Slide 4–5, Evasion Lab |
| Technical depth | WL kernels, GNN, CFG detectors, sandboxed pipeline | Architecture + ALGORITHMS |
| Impact / usefulness | SOC triage, offline, explainable | Slide 11, demo |
| Completeness / polish | Working UI, API, docs, reproducible eval | Live demo, repo |
| Rigour / honesty | Baselines, CIs, LOFO, limitations slide | Slides 9–10 |
| Feasibility / scalability | Docker, queue, caching, cost model | SystemDesign §10 |
| Presentation | 12-slide story, 3-minute demo with fallbacks | This doc |

## 6. Repo README Checklist
Badges (CI, license), one-paragraph pitch, GIF of the 3D graph, quick start (`make setup demo`), architecture diagram, results table (from `make eval`), limitations, ethics statement, citations, team.
