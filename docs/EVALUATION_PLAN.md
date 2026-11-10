# X-Ray Binary — Evaluation Plan

Goal: produce numbers a skeptical judge cannot easily dismiss. Every table below is a **template**; fill with measured values (`make eval`). Nothing here is a result.

## 1. Data
| Set | Content | Source (verify licence/ToS) | Handling |
|---|---|---|---|
| Malware | Windows PE (and ELF if time) samples, ≥100 per family minimum, 300–1000 target | Public research corpora and malware-sharing feeds (e.g., MalwareBazaar, BODMAS-style research datasets; check access terms) | Stored only in the isolated analysis host; never in git |
| Family labels | Normalised from multi-AV tags (AVClass-style), spot-checked manually | derived | Keep label-confidence; drop ambiguous |
| Benign | OS binaries from a clean VM, installers, open-source programs built with several compilers/optimisations; **hard negatives**: file encryptors, backup tools, remote-admin tools, hotkey/input utilities, download managers, UPX-packed benign programs | local + open-source builds | Document provenance/licences |
| Lab corpus | Benign C programs for the Evasion Lab (EVASION_LAB.md) | authored/open-source | build recipes versioned |

Families (v1): ransomware, keylogger/infostealer, downloader/loader. Report counts after de-duplication.

## 2. Cleaning and de-duplication
1. Drop non-parsable / corrupt / non-native (.NET managed) → counted in an *exclusion table* (be transparent).
2. Near-duplicate removal: TLSH distance threshold **and** function-set / WL cosine > 0.98 within the same split.
3. Group by family *and* by first-seen date to prevent variant leakage.

## 3. Splits (all seeded)
| Protocol | Purpose | Construction |
|---|---|---|
| P-A Random stratified (upper bound, reported but not headlined) | sanity | 60/20/20 train/val/test after dedupe |
| **P-B Temporal** (headline) | realism | train < T1 ≤ val < T2 ≤ test by first-seen date |
| **P-C Leave-one-family-out (LOFO)** | novel-family generalisation | hold out family F entirely; measure binary malware-vs-benign recall on F and open-set "unknown" rate |
| P-D Packed vs unpacked strata | honest limits | report all metrics separately for packed-likely subset |
| P-E Hard-negative benign | FP stress | FPR on the hard-negative set at the operating threshold |

## 4. Metrics
- Binary: ROC-AUC, PR-AUC, TPR at 1% and 0.1% FPR, FPR at 95% TPR, with 95% bootstrap CIs (1000 resamples).
- Family (closed set): per-family precision/recall/F1, macro-F1, confusion matrix.
- Open set: unknown-family detection rate under LOFO; false-known rate.
- Calibration: ECE, reliability diagram.
- Abstention: coverage vs accuracy curve (selective classification).
- Runtime: per-stage p50/p95, memory peak, graph sizes.
- Explainability: faithfulness (below), localisation sanity checks.

## 5. Baselines (identical splits and evasion variants)
| Baseline | Notes |
|---|---|
| Exact hash (SHA-256) | trivially fails on any rebuild; included as reference |
| Fuzzy hash (TLSH, ssdeep), imphash | similarity to nearest family reference |
| YARA | community public rules where applicable + **rules auto-generated from the original build** for the lab |
| Byte/opcode n-gram + LightGBM | trained on the same train split |
| EMBER-style header/import/string feature GBDT | if feature extractor available |
| MalConv-style raw-byte CNN (optional) | if compute allows |
| Optional: ClamAV scan of variants | report as-is, no claims beyond the run |

Rule: tune baselines fairly (same effort, same validation split). Report where baselines win.

## 6. Ablations
| Ablation | Question |
|---|---|
| WL only / GNN only / fusion | Is fusion worth it? |
| h ∈ {1,2,3,4} | Depth sensitivity |
| Labels: −profile, −API, −CFG stats | Which signal carries detection and retention? |
| IDF on/off; library pruning on/off | Noise handling |
| Decile vs quartile vs cluster-ID profile buckets | Robustness to perturbation |
| Truncation cap (1k/5k/20k nodes) | Cost vs accuracy |

## 7. Explanation faithfulness
Remove (neutralise) top-k% attributed nodes' labels, recompute family score; compare drop vs random-k% and degree-top-k%. Report relative drop at k ∈ {1,5,10}%. Also report rank agreement between WL attribution and GNN occlusion (Spearman), and a small human check: for N=20 correctly detected samples, does the top-5 include a function an expert identifies as payload-relevant (manual, clearly labelled as qualitative).

## 8. Evasion Lab evaluation
See EVASION_LAB.md. Headline figure: retention vs stage for X-Ray Binary vs signature-style baselines. Report per-program values and the mean with CI; never cherry-pick programs.

## 9. Reporting templates
**Table 1 — Binary detection (temporal test)**
| Method | AUROC | PR-AUC | TPR@1%FPR | FPR@95%TPR | Hard-neg FPR |
|---|---|---|---|---|---|
| X-Ray (WL) | | | | | |
| X-Ray (GNN) | | | | | |
| X-Ray (fusion) | | | | | |
| n-gram LightGBM | | | | | |
| EMBER-style GBDT | | | | | |

**Table 2 — Per-family**
| Family | n_test | Precision | Recall | F1 |
|---|---|---|---|---|

**Table 3 — LOFO**
| Held-out family | Binary recall | Unknown-family rate | Benign FPR |
|---|---|---|---|

**Table 4 — Packed vs unpacked** (same metrics, plus abstention rate).

## 10. Reproducibility package
`make eval` regenerates: split manifests (hashes only), metrics JSON, figures, tables as Markdown/CSV, environment lock info, seeds. Raw malware never leaves the analysis host; publish *hash lists and derived features only*.

## 11. Threats to validity (state them in the deck)
Label noise; dataset age and family drift; benign corpus not representative of all software; radare2 function-recovery variance; compiler-specific artefacts; small families; adaptive attackers not modelled; lab programs smaller than real malware.
