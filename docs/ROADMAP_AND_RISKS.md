# Build Plan, Roadmap and Risk Register

## 1. 5-Day Build Plan (solo-friendly; adjust to the hackathon window)

| Day | Goal | Tasks (ID) | Exit check |
|---|---|---|---|
| **D1** | Extraction + fingerprint | D1-01 sandbox image with pinned radare2; D1-02 **verify r2 JSON field names** (`aflj`, `afbj`, `pdfj`, `iij`, `iSj`) and finish `extract_r2.py`; D1-03 label function; D1-04 WL on 50 benign + 50 malware; D1-05 corpus download scripts, dedup | Graph + WL vector for 100 files; rename-invariance test passes on real binaries |
| **D2** | Index, scoring, API | D2-01 reference index + IDF + log-odds; D2-02 family scoring + open-set; D2-03 FastAPI endpoints (`/samples`, `/report`, `/graph`); D2-04 job queue + SSE | Upload → JSON verdict end-to-end |
| **D3** | GNN + UI | D3-01 GIN training + calibration; D3-02 fusion; D3-03 Next.js upload/report; D3-04 3D force graph + inspector; D3-05 obfuscation detectors wired | Demo path works with real data |
| **D4** | Evasion lab + benchmarks | D4-01 benign programs + build matrix (gcc/clang, UPX, OLLVM, junk pass); D4-02 baselines (hash/YARA/TLSH/n-gram LGBM); D4-03 `make eval` tables/figures; D4-04 benchmarks page; D4-05 UPX static unpack | Retention table + baseline comparison generated |
| **D5** | Polish + pitch | D5-01 caching & demo mode; D5-02 failure analysis; D5-03 deck, video fallback; D5-04 README/docs; D5-05 rehearse ×3, offline test | Submission package complete |

**Cut lines:** see PRD §11. Never cut Evasion Lab, baselines or the limitations slide.

## 2. Task Breakdown by Workstream

| Workstream | Deliverables |
|---|---|
| Core | `xray_core`: extractor, labeller, WL, obfuscation, attribution (+ tests) |
| Models | GNN training script, fusion/calibration, model bundle |
| Data | Corpus scripts, dedup, splits, manifests |
| Backend | API, workers, DB, exports |
| Frontend | Upload, report, graph, inspector, lab, benchmarks |
| Eval | Metrics, baselines, evasion runner, report generator |
| Ops | Docker images, sandbox hardening, CI |
| Story | Deck, demo script, video, README |

## 3. Risk Register

| # | Risk | Likelihood | Impact | Mitigation | Owner/Trigger |
|---|---|---|---|---|---|
| R1 | Can't obtain enough labelled samples quickly | M | H | Start downloads D1; use fewer families; supplement with benign-heavy evaluation and natural-variant tests; state scale honestly | D1 |
| R2 | radare2 JSON fields differ from assumptions | M | M | D1-02 verification task; adapter layer; fallback to Capstone + custom CFG | D1 |
| R3 | `aaa` too slow on big samples | M | M | Timeouts, shallow fallback, function cap, size filter for corpus | D2 |
| R4 | GNN underperforms / overfits | M | M | WL is primary explainable scorer; GNN as secondary; augmentation; smaller model | D3 |
| R5 | 3D graph janky on large graphs | M | M | Prune/cluster, LOD, 2D fallback, pre-cached demo | D3 |
| R6 | Evasion lab toolchain (OLLVM, mingw) setup pain | H | M | Prebuilt Docker image; Linux ELF lab first; PE cross-build later; fewer transforms if needed | D4 |
| R7 | Retention under CFF/inlining low | M | M | Report honestly; show call-graph-only vs CFG-aware ablation | D4 |
| R8 | Judges challenge novelty | M | M | Related-work slide; emphasise combination, explainability, and measured evasion study | D5 |
| R9 | Live demo failure | M | H | Cached `?demo=1`, recorded video, offline rehearsal | D5 |
| R10 | Sandbox escape / unsafe handling | L | H | Isolation controls; never execute; isolated VM for samples | always |
| R11 | Time overrun | H | H | Cut lines; daily exit checks; freeze scope at D4 end | daily |
| R12 | Label noise in families | M | M | Consensus tags + manual spot-check; report noise | D1–D2 |

## 4. Post-Hackathon Roadmap

| Horizon | Items |
|---|---|
| 1–2 months | Adversarial training; more families; ARM/MIPS ELF (IoT botnets); active-learning loop; STIX/MISP export |
| 3–6 months | Managed-code (.NET/Java) front-ends; safe automated unpacking research; SIEM/SOAR integration; analyst feedback UI; model cards |
| 6–12 months | Federated reference updates; similarity search over large corpora; continuous drift monitoring; independent third-party evaluation |

## 5. Definition of Done (Submission Package)

- [ ] Repo with `docker compose up` working on a clean machine
- [ ] `make eval` reproduces tables/figures; artefacts committed
- [ ] Docs complete (this folder), README with GIF + results
- [ ] Deck (12 slides) + 90 s fallback video
- [ ] Demo rehearsed offline ×3
- [ ] Limitations and ethics visible in deck and UI
- [ ] All numbers in deck traceable to `artifacts/eval_*`
