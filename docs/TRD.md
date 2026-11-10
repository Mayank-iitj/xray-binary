# X-Ray Binary — Technical Requirements Document (TRD)

Companion docs: `SystemDesign.md` (architecture), `ALGORITHMS.md` (math), `API.md` (contract), `techstack.md` (tools), `EVALUATION_PLAN.md` (validation).

## 1. Scope

A defensive, offline, static-analysis service that ingests an executable, builds a structural graph representation, scores it against reference malware families and a benign baseline using two independent scorers, and returns an explainable verdict. The sample is **never executed**.

Supported inputs (v1): PE32/PE32+ and ELF32/ELF64, x86/x86-64. Max upload 50 MB (configurable). Other formats are rejected with `415`.

## 2. Pipeline Stages

```
upload → validate → (unpack?) → disassemble → extract graph → label → fingerprint (WL)
       → embed (GNN) → score + calibrate → attribute (nodes) → obfuscation detectors → report
```

| # | Stage | Input → Output | Time budget (5 MB) | Failure behaviour |
|---|---|---|---|---|
| S1 | Intake | bytes → SHA-256, size, magic, format | < 0.2 s | `415/413`, no job created |
| S2 | Static triage | file → section table, entropy, imports, packer hints | < 1 s | continue with warnings |
| S3 | Static unpack (P1) | packed UPX → unpacked file | < 5 s | flag `packed_unreliable`, continue on original |
| S4 | Disassembly | file → functions, call refs, basic blocks | ≤ 40 s hard timeout | fall back `aa` (shallow) then partial; flag `partial_analysis` |
| S5 | Graph build | r2 JSON → `G_call`, per-function `G_cfg` | < 2 s | — |
| S6 | Node labelling | graph → labelled graph | < 2 s | — |
| S7 | WL fingerprint | labelled graph → sparse vector | < 1 s | — |
| S8 | GNN embedding | labelled graph → vector + class probs | < 3 s CPU | scorer disabled, reported |
| S9 | Fusion | scores → calibrated verdict | < 0.1 s | — |
| S10 | Attribution | vector + log-odds → node scores | < 1 s | — |
| S11 | Obfuscation | CFGs + sections → indicators | < 3 s | — |
| S12 | Report | all → JSON + cached graph | < 1 s | — |

Total target p50 ≤ 30 s, p95 ≤ 90 s on a 4-core CPU laptop.

## 3. Data Model

### 3.1 Call graph `G_call = (V, E)`
- `V`: recovered functions (cap `MAX_FUNCS = 20 000`; if exceeded keep largest by size, flag `truncated`).
- `E`: directed `caller → callee` edges for direct calls. Calls to imports are **not** nodes; they become API-bucket attributes of the caller (keeps graphs small and robust to import-table order).
- Thunks/trampolines (single `jmp`) are collapsed into their target.

### 3.2 Node feature vector `x_v` (used by GNN) and label `ℓ_v` (used by WL)

| Group | Features | Notes |
|---|---|---|
| Instruction-class profile | Fraction of each class: data-move, stack, arith, logic, xor, shift/rotate, cmp, jmp, cjmp, call, ret, nop, mem-load/store, other (≈ 14 dims) | Bucketed to deciles for the WL label |
| API semantic buckets | Multi-hot over: file, crypto, net, process-inject, input-capture, registry, memory-protect, dynamic-loader, anti-debug (+ `none`) | Derived from normalised import names (strip lib prefix, `A/W/Ex` suffix) |
| CFG statistics | #basic blocks, #edges, cyclomatic complexity, loop count, max block fan-in, dispatcher score, XOR-loop flag | Log-scaled, capped |
| Graph position | in-degree, out-degree, depth from entry, is-leaf, is-recursive | |
| Size | log(#instructions) | |

**Hard rules for labels:** no raw bytes, no function names, no string contents, no absolute addresses. This is the property that makes renaming, string encryption and relocation leave the representation intact.

### 3.3 WL label (string fed to the hash)
`"<insn profile deciles>|api:<sorted buckets>|cc:<min(cc,20)>|bb:<min(nbbs/4,10)>"`

### 3.4 Persisted entities (SQLite → PostgreSQL)

```
samples(id, sha256 UNIQUE, size, format, arch, uploaded_at, status, packed_flag, partial_flag)
analyses(id, sample_id FK, model_version, started_at, finished_at, stage_timings JSON,
         verdict, confidence, family, report_path)
graphs(analysis_id FK, nodes_parquet, edges_parquet)            -- or JSON.gz on disk
reference_sets(id, name, family, n_samples, wl_depth, built_at)
reference_vectors(set_id FK, sample_hash, wl_vector BLOB)       -- sparse, int-hashed
label_stats(set_id FK, label, df_family, df_benign, log_odds)   -- for attribution
evasion_runs(id, program, transforms JSON, created_at, status)
evasion_results(run_id FK, stage, binary_sha256, similarity, verdict, family_score, notes)
eval_runs(id, split, metrics JSON, created_at)
```

## 4. Algorithms (summary; details in ALGORITHMS.md)

1. **WL fingerprint** — directed 1-WL, `h = 3` (default; ablate 1–4), BLAKE2b-64 label hashing; vector = histogram of `(depth, label)`.
2. **Similarity** — sublinear-TF, IDF-weighted cosine. Per family: `s_f = max` over reference samples of that family (nearest-neighbour) and `mean of top-3` (robust variant).
3. **GNN** — 3-layer GIN (or GraphSAGE) on the call graph with node features `x_v`; sum+max readout; heads: family softmax (incl. `benign`) and an embedding for kNN. Trained with class-balanced loss and dropout; fixed seeds.
4. **Fusion** — logistic regression over `[s_f for f in families, s_benign, gnn_probs, packed_flag, obf_scores]` → Platt/isotonic calibration on a held-out calibration split.
5. **Open set** — if `max_f s_f < τ_sim` **and** `max gnn prob < τ_p` → `unknown` (reported as "no close family; structurally unusual" with obfuscation flags).
6. **Attribution** — smoothed log-odds per `(depth,label)`; node score = mean of top-2 positive log-odds among the node's labels at depth ≥ 1; GNN occlusion (mask node, measure Δ family logit) as a secondary, cross-checked view.
7. **Obfuscation detectors** — heuristic, evidence-bearing (see §6).

## 5. Verdict Logic

```
if file invalid → error
if packed_unreliable and no unpack success → verdict = "inconclusive_packed" (+ best-effort scores, clearly labelled)
p_mal = calibrated P(malware)
if p_mal ≥ T_high: verdict = "malicious", family = argmax
elif p_mal ≥ T_low: verdict = "suspicious"
else verdict = "benign"
if open-set condition: family = "unknown"
```
Thresholds `T_high, T_low` chosen on validation to hit target FPR (default 0.5 % and 5 %), versioned with the model.

## 6. Obfuscation Detectors

| Detector | Signal | Evidence returned |
|---|---|---|
| Control-flow flattening | One block with very high CFG fan-in/out whose neighbours return to it as sole successor; ratio of such blocks; switch-like compare chain | function addr, dispatcher block, back-edge ratio, score 0–1 |
| XOR decode routine | Loop (SCC) containing non-zeroing `xor`, memory store, counter update, conditional branch | function addr, loop blocks, #xor ops |
| Packing | High-entropy executable section, W+X section, entry point in high-entropy section, tiny import table (loader-only imports) | section table, entropy values |
| Junk code | Ratio of NOP-equivalent / dead-store / self-cancelling sequences per function | ratio, sample addresses |
| Opaque predicates (P2) | Constant-outcome conditional branches via simple symbolic folding | addr list |

Reference implementation: `reference/obfuscation.py` (unit-tested on synthetic CFGs).

## 7. Reference Corpus Requirements

| Item | Requirement |
|---|---|
| Families (v1) | ransomware, keylogger/infostealer, downloader/loader |
| Samples per family | target 300–1000 after de-duplication (minimum viable: 100) |
| Benign | ≥ 2× malware count: system binaries, installers, open-source builds across compilers |
| Labels | family label from AV-consensus tags (e.g., AVClass-style normalisation) + manual spot-check |
| Splits | time-based train/val/test + leave-one-family-out for generalisation (EVALUATION_PLAN) |
| De-dup | drop near-duplicates by TLSH distance and by function-set Jaccard before splitting |

## 8. Determinism and Versioning

- Pin radare2 version, Python deps (lockfile), PyTorch/PyG versions; record in every report (`toolchain` block).
- Seeds fixed for GNN init, dropout, data order. Inference in `eval()` mode, deterministic ops enabled.
- WL labels are content-addressed hashes → same graph ⇒ same vector.
- `model_version = semver + data_hash`; reports record it; reference index is rebuilt only by explicit command.

## 9. Security Requirements (detail in SECURITY_AND_ETHICS.md)

- Disassembler runs in an ephemeral container: `--network none`, read-only root FS, `tmpfs` workdir, `--cap-drop ALL`, `no-new-privileges`, seccomp default, non-root UID, CPU/mem/pids/time limits.
- Parsers of untrusted binaries (radare2, LIEF/pefile) are assumed attackable → isolate, timeout, kill on breach.
- Sample bytes never leave the worker except as derived graphs; API never serves raw samples back.
- Uploads magic-validated; size capped; stored under SHA-256; deletable.

## 10. Performance and Scalability

| Concern | Approach |
|---|---|
| Large binaries | Function cap, shallow-analysis fallback, hard wall-clock timeout |
| WL cost | O(h · \|E\|) with hashing — negligible vs disassembly |
| Reference search | Sparse vectors; inverted index on `(depth,label)` → candidate shortlist → exact cosine |
| GNN | CPU inference; graphs truncated to ≤ 5 000 nodes for the model (largest by size + all API-bearing) |
| Throughput | N workers = N cores; job queue; results cached by `(sha256, model_version)` |

## 11. Testing Strategy

| Level | What | Tooling |
|---|---|---|
| Unit | WL invariance (rename), perturbation retention, obfuscation heuristics, API bucketing | `pytest` (`reference/tests` — 7 passing) |
| Property | Relabelling nodes never changes the vector; adding disconnected nodes only adds features | `hypothesis` |
| Integration | Known test binaries → expected graph stats; golden JSON reports | pytest + fixtures |
| Robustness | Malformed/truncated/zip-bomb-like inputs, huge function counts | fuzz corpus, timeout asserts |
| Evaluation | Full metrics + evasion lab | `make eval` produces `artifacts/eval_*.json` |
| UI | Component tests, Playwright smoke: upload → report → click node | Playwright |
| Security | Container-escape checklist, resource-limit tests | scripted |

## 12. Acceptance Criteria (Definition of Done for v1)

1. `docker compose up` → upload sample → verdict, evidence, 3D graph, obfuscation panel in the UI.
2. `make eval` regenerates all benchmark tables and evasion charts from scratch with fixed seeds.
3. Evasion Lab produces a retention table for ≥ 8 transformation stages on ≥ 3 benign test programs.
4. Benchmark compares ≥ 3 baselines (hash/YARA, fuzzy hash, n-gram ML) on identical variants.
5. Reports contain model version, toolchain versions, stage timings, and limitations flags.
6. Limitation behaviours (packed, partial, truncated) are visible in the UI, never silent.
