# X-Ray Binary — Product Requirements Document (PRD)

| Field | Value |
|---|---|
| Product | X-Ray Binary — structural, explainable static malware triage |
| Version | 1.0 (hackathon build + roadmap) |
| Owner | Mayank Sharma |
| Tagline | *Traditional antivirus reads the words. X-Ray Binary reads the thoughts.* |
| Status | Ready for build |

---

## 1. Problem

Signature antivirus matches **bytes, strings and symbols**. Attackers rewrite all three at near-zero cost: repacking, string encryption, recompiling with another optimisation level, renaming, junk-code insertion. The result is *polymorphic* and *obfuscated* malware whose **underlying logic is unchanged** but whose hash and signature are new.

Consequences for defenders:
- **Triage latency.** SOC/IR analysts receive "unknown" samples that no signature covers and must reverse them by hand.
- **Black-box ML.** Existing ML detectors return a score with no evidence, so analysts cannot trust or act on it.
- **No evasion evidence.** Vendors claim robustness but rarely publish *how much* detection survives each evasion technique.

## 2. Insight / Product Thesis

Malware authors can cheaply change *how a program looks*; they cannot cheaply change *what it must do*. A ransomware sample must enumerate files, call crypto, and write files back, in a particular call-graph shape. X-Ray Binary fingerprints that **structure** (call graph labelled by instruction-class profile and API semantics) and shows analysts *where* the malicious logic lives.

## 3. Target Users and Personas

| Persona | Needs | How X-Ray Binary helps |
|---|---|---|
| **Priya, SOC Tier-1/2 analyst** | Fast verdict + reason on an unknown file | Verdict, family similarity, top evidence nodes in < 60 s |
| **Arjun, Incident responder** | Understand a sample, find the payload function | 3D graph, node inspector with disassembly, obfuscation flags |
| **Meera, Detection engineer** | Know whether a detector survives evasion | Evasion Lab retention curves, per-family P/R, baseline comparison |
| **Dr. Rao, Researcher/educator** | Reproducible results | Open pipeline, fixed seeds, exported evaluation artefacts |

## 4. Goals and Non-Goals

### Goals
- G1. Classify an uploaded executable as *benign / malware family X / unknown-suspicious* **without executing it**.
- G2. Make every verdict **traceable** to specific functions (nodes) and obfuscation evidence.
- G3. **Quantify robustness** to evasion with a reproducible lab, instead of asserting it.
- G4. Run **fully offline**, and be deployable as a triage layer beside EDR.
- G5. Beat signature/byte-level baselines on evasion variants (measured, with confidence intervals).

### Non-Goals (explicit)
- NG1. Replacing EDR/AV or providing real-time endpoint protection.
- NG2. Dynamic analysis, sandbox detonation, or any execution of the sample.
- NG3. Generating, modifying or obfuscating **malware**. The Evasion Lab transforms *benign programs built from source*.
- NG4. Guaranteeing detection of heavily packed samples (we detect and *report* that structure is unreliable; see §9).
- NG5. Attribution or threat-actor naming.

## 5. User Stories and Acceptance Criteria

| ID | Story | Acceptance criteria |
|---|---|---|
| US-1 | As Priya, I upload a Windows PE/Linux ELF and get a verdict. | Upload ≤ 50 MB; verdict + confidence returned; progress shown; sample is never executed. |
| US-2 | As Arjun, I see which functions drove the verdict. | Top-N evidence nodes listed with score; clicking a node in the 3D graph shows disassembly excerpt, API buckets, callers/callees. |
| US-3 | As Arjun, I learn whether the sample is obfuscated/packed. | Panel lists CFF dispatchers, XOR decode loops, packing indicators with function addresses and evidence; packed ⇒ banner "structure unreliable". |
| US-4 | As Meera, I run an evasion study on a test program. | Select program + transformations; get similarity-retention table/chart per stage within 5 min (cached builds). |
| US-5 | As Meera, I compare against baselines. | Benchmark page shows our system vs YARA/hash/fuzzy-hash/n-gram-ML on the same evasion variants. |
| US-6 | As Priya, I compare two samples. | `compare` returns structural similarity and a graph diff highlighting shared/unique nodes. |
| US-7 | As an analyst, I export the report. | JSON (complete) and PDF (summary) exports; STIX 2.1 as stretch. |
| US-8 | As an admin, I run it air-gapped. | `docker compose up` works with no internet after image build; no telemetry. |

## 6. Functional Requirements

**P0 = must ship in demo, P1 = should, P2 = stretch.**

| ID | Requirement | Pri |
|---|---|---|
| FR-01 | Accept PE (x86/x64) and ELF (x86/x64) uploads; validate by magic bytes, not extension. | P0 |
| FR-02 | Disassemble with radare2 inside a no-network sandbox; extract functions, call graph, per-function CFG. | P0 |
| FR-03 | Node labelling by instruction-class profile + API semantic buckets + CFG stats (never raw bytes/names). | P0 |
| FR-04 | WL-kernel fingerprint (h = 3 default) and similarity to family and benign reference sets. | P0 |
| FR-05 | GNN embedding + family/benign classifier as an independent second scorer. | P0 |
| FR-06 | Calibrated score fusion; open-set "unknown/suspicious" outcome. | P0 |
| FR-07 | Node-level attribution from WL label log-odds (family vs benign); top-N evidence list. | P0 |
| FR-08 | Interactive 3D force graph with suspicion colouring, node inspector, filtering, 2D fallback. | P0 |
| FR-09 | Obfuscation detectors: CFF dispatcher, XOR decode loop, packing/entropy, junk-code ratio, sparse-import. | P0 |
| FR-10 | Evasion Lab: transformation pipeline on benign sources, retention report per stage. | P0 |
| FR-11 | Benchmark page: per-family P/R/F1, leave-one-family-out, baselines, CIs. | P0 |
| FR-12 | Static unpacking for UPX (`upx -d`) with before/after comparison. | P1 |
| FR-13 | Sample-to-sample compare + graph diff. | P1 |
| FR-14 | Job queue with progress events (SSE). | P1 |
| FR-15 | JSON/PDF export; STIX 2.1 export. | P1 / P2 |
| FR-16 | Active-learning loop: analyst feedback (confirm/deny node) stored for retraining. | P2 |
| FR-17 | Similarity search across previously analysed samples (index of WL vectors). | P2 |

## 7. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-1 | End-to-end latency, ≤ 5 MB binary, ≤ 5 k functions | p50 ≤ 30 s, p95 ≤ 90 s (CPU only) |
| NFR-2 | Reproducibility | Same sample + same model version ⇒ byte-identical report (fixed seeds, pinned toolchain) |
| NFR-3 | Safety | Sample never executed; analysis in container with `--network none`, read-only FS, CPU/mem/time limits |
| NFR-4 | Offline | Zero outbound calls at runtime |
| NFR-5 | Explainability | 100 % of non-benign verdicts carry ≥ 1 evidence node and a reason string |
| NFR-6 | Privacy | Uploads stored only by SHA-256 in local volume; delete endpoint; no third-party calls |
| NFR-7 | Accessibility | Keyboard navigation, colour-blind-safe palette plus shape/labels, 2D alternative to 3D |
| NFR-8 | Observability | Structured logs, per-stage timings, Prometheus metrics |

## 8. Success Metrics

Targets are goals to be **verified by the evaluation run**; no result is claimed until measured (see EVALUATION_PLAN.md).

| Metric | Target |
|---|---|
| Malware-vs-benign AUROC (time-split test) | ≥ 0.97 |
| TPR at 1 % FPR | ≥ 0.90 |
| Family macro-F1 (3 families, held-out time split) | ≥ 0.85 |
| Similarity retention to original under -O0…-O3, strip, string-encryption | ≥ 0.80 |
| Retention under flattening/bogus-CF (reported honestly, may drop) | report as measured; target ≥ 0.60 |
| Detection survival of our system vs best baseline on evasion variants | ≥ +30 pp absolute |
| Evidence faithfulness: removing top-k evidence nodes drops family score | ≥ 30 % relative drop at k = 10 % of nodes |
| Analyst-time proxy: nodes an analyst must inspect to reach payload | ≤ 5 (user-study / scripted proxy) |

## 9. Constraints and Known Limits (stated up-front — judges will ask)

1. **Packing.** A packed binary's static call graph is the unpacker stub. We detect this (entropy, RWX sections, sparse imports), attempt static unpack for known packers (UPX), and otherwise *refuse to over-claim*: verdict carries "structure unreliable".
2. **Compiler optimisation** (inlining, DCE) changes the call graph. Retention is reported per level, not assumed flat.
3. **Function recovery is imperfect** (indirect calls, stripped binaries). Mitigated with import-driven API labels and CFG-level features.
4. **Dataset shift.** Families evolve; we use time-aware splits and open-set rejection.
5. **Adversarial ML.** An adaptive attacker aware of the model could perturb structure. Out of scope for v1; discussed in SECURITY_AND_ETHICS.md and roadmap.

## 10. Competitive and Related Landscape

| Approach | Strength | Weakness vs X-Ray Binary |
|---|---|---|
| Hash / signature AV, YARA | Precise on known samples, fast | Breaks on trivial byte changes; needs constant rule upkeep |
| Fuzzy hashes (ssdeep, TLSH), imphash | Tolerates small edits | Byte/import-order based; fails under repack/recompile |
| Byte/opcode n-gram ML (e.g., MalConv, EMBER-style GBDT) | Strong accuracy, no disassembly | Opaque; byte-level features shift with packing/compilers |
| Binary diffing (BinDiff, Diaphora) | Precise function matching | Pairwise, analyst-driven; not a classifier or triage layer |
| Graph-based research (call-graph kernels/GNNs, e.g., Kinable & Kostakis 2011; Hu et al. 2009; Gemini, Xu et al. 2017) | Structural robustness | Mostly academic prototypes, rarely explainable end-to-end or evasion-quantified |

**Our differentiation** is the *combination*, not any single idea: instruction-class + API-semantic node labels, WL fingerprint **and** GNN as independent scorers, node-level evidence in a 3D analyst UI, and a reproducible **Evasion Lab** with published retention numbers and baselines.

## 11. Scope Cut Lines

- **Must (demo-critical):** FR-01…FR-11 on PE+ELF x86/x64, 3 families + benign.
- **Cut order if time runs out:** STIX → similarity search → active learning → compare/diff → UPX unpack → GNN explainer (keep WL attribution) → ELF (keep PE).
- **Never cut:** Evasion Lab, baselines table, honest-limitations slide.

## 12. Release Plan

| Milestone | Content |
|---|---|
| M0 (Day 1) | r2 extraction + graph labels + WL on small corpus |
| M1 (Day 2) | Reference index, scoring, API, minimal UI |
| M2 (Day 3) | GNN, attribution, 3D UI, obfuscation panel |
| M3 (Day 4) | Evasion Lab + baselines + benchmark page |
| M4 (Day 5) | Polish, caching, demo rehearsal, deck |

## 13. Open Questions / Decisions

| # | Question | Default decision |
|---|---|---|
| 1 | Windows-only or also Linux? | PE first, ELF if corpus permits (radare2 handles both) |
| 2 | Families | Ransomware, keylogger/infostealer, downloader/loader (+ botnet stretch) |
| 3 | Fusion method | Logistic regression over [WL max-sim per family, GNN probs, obfuscation flags], Platt-calibrated |
| 4 | Hosting for demo | Local docker compose on laptop + recorded fallback demo |
