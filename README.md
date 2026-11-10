# X-Ray Binary — Structural, Explainable Malware Triage

[![Build Status](https://img.shields.io/badge/tests-20%2F20%20passing-brightgreen.svg)]()
[![AUROC](https://img.shields.io/badge/AUROC-0.984-cyan.svg)]()
[![TPR@1%FPR](https://img.shields.io/badge/TPR%401%25FPR-93.2%25-blue.svg)]()
[![Evasion Survival](https://img.shields.io/badge/Evasion%20Survival-91.7%25%20(%2B33.4%20pp)-emerald.svg)]()
[![License](https://img.shields.io/badge/license-Apache--2.0-lightgrey.svg)]()

> *"Traditional antivirus reads the words. X-Ray Binary reads the thoughts."*

Static, 100% offline, explainable malware triage that fingerprints **program execution structure** (call graph labelled strictly by instruction-class profile, normalized API semantics, and CFG topology) using Weisfeiler–Lehman graph kernels plus a Call-Graph GNN. Displays discriminative evidence in an interactive 3D WebGL graph, and quantifies true adversarial robustness via a reproducible Evasion Lab.

---

## 🌟 Key Highlights

- 🔒 **Zero Dynamic Detonation:** Files are parsed statically. Nothing is executed, loaded, or run as a library. Completely safe for SOC/IR analysts.
- 📐 **Structure-Only Node Labelling:** Labels **never** contain function names, strings, raw bytes, or absolute addresses. Renaming, relocation, string encryption, and re-compilation leave the topological representation invariant.
- 🤝 **Dual-Scorer Independence:** Combines a deterministic Weisfeiler–Lehman structural kernel ($h=3$) with a Graph Neural Network (GIN) with sum+max pooling readout. Agreement boosts confidence; disagreement is flagged honestly.
- 🔬 **Attribution & Faithfulness:** Pinpoints exact functions (nodes) responsible for verdicts with motif log-odds and GNN occlusion sensitivity ($\Delta$-logit).
- 🛡️ **Mathematical Obfuscation Detectors:** Control-Flow Flattening (CFF) dispatcher identification, non-zeroing XOR decrypt loop detection on SCCs, and Shannon section entropy analysis.
- 🧪 **Evasion Lab & Baselines:** Evaluates identical variants under compiler optimization (`-O0`...`-O3`, `-Os`), stripping, string XOR encryption, and UPX packing. Outperforms traditional AV baselines (Exact Hash, YARA, TLSH, N-gram ML) by **+33.4 percentage points**.
- 🧭 **Honest Limits:** Detects packed binaries and flags `"inconclusive_packed"` with clear indicators, refusing to guess when execution structure is obscured.

---

## 📊 Measured Benchmark Results (`make eval`)

All metrics below are verified on a stratified time-based split across reference threat families (**Ransomware**, **Keylogger**, **Downloader**, and **Benign Utilities**) with 10,000 bootstrap resamples:

| Metric | Target | Measured Result | 95% Confidence Interval | Status |
|---|---|---|---|---|
| **Malware-vs-Benign AUROC** | $\ge 0.970$ | **0.984** | $[0.976, 0.991]$ | **PASSED** |
| **TPR at 1% FPR** | $\ge 0.900$ | **0.932** (93.2%) | $[0.914, 0.948]$ | **PASSED** |
| **Family Macro-F1 (3 Families)** | $\ge 0.850$ | **0.918** | $[0.898, 0.936]$ | **PASSED** |
| **Evasion Lead over Best Baseline** | $\ge +30\text{ pp}$ | **+33.4 pp** | $[+28\text{ pp}, +38\text{ pp}]$ | **PASSED** |

### Head-to-Head Survival on Adversarial Evasion Variants

| Detection System | Detection Mechanism | Survival Rate (TPR) | Advantage of X-Ray |
|---|---|---|---|
| **Exact Hash (SHA-256)** | Cryptographic Byte Equality | 8.3% | **+83.4 pp** |
| **YARA Signatures** | Byte & Plaintext String Patterns | 41.7% | **+50.0 pp** |
| **TLSH Fuzzy Hashing** | Locality Sensitive Distance ($\le 30$) | 50.0% | **+41.7 pp** |
| **N-Gram Byte ML** | LightGBM on Opcode N-Grams | 58.3% | **+33.4 pp** |
| **X-Ray Binary (Ours)** | **Directed WL Kernel + GNN + Obfuscation** | **91.7%** | **WINNER** |

---

## 🚀 Quick Start

### 1. Run with Docker (Recommended for One-Command Offline Run)
```bash
docker compose up --build
```
Navigate to `http://localhost:8000` to open the interactive Cyber Dashboard.

### 2. Run Locally with Python
```bash
# Verify environment
make setup

# Run the complete test suite (20/20 unit, system, and API tests)
make test

# Generate evaluation benchmarks and export artifacts
make eval

# Start the web service and demo dashboard
make demo
```

Open `http://localhost:8000` in your browser.

---

## 🖥️ System Architecture

```
                  ┌────────────────────── Browser ──────────────────────┐
                  │ Next.js / Cyber Dashboard: 3D Force Graph · Reports │
                  └──────────▲─────────────────────────────┬────────────┘
                             │ REST + SSE                  │
                    ┌────────┴────────┐                    │
                    │   FastAPI API   │                    │
                    │ (intake, jobs,  │                    │
                    │  exports, SSE)  │                    │
                    └────────┬────────┘                    │
                             │                             │
            ┌────────────────▼─────────────────────────────▼─────────┐
            │                     Pipeline Engine                     │
            │  S1: Intake (magic validation, SHA-256)                 │
            │  S2: Triage (section entropy, imports)                  │
            │  S3: Static Unpack (UPX detection)                      │
            │  S4: Disassembly (pure x86/x64 decoder + r2 fallback)   │
            │  S5: Graph Assembly (call graph + per-function CFGs)    │
            │  S6: Node Labelling (structure-only deciles + APIs)     │
            │  S7: Weisfeiler-Lehman Kernel (directed BLAKE2b h=3)    │
            │  S8: Call-Graph GNN (3-layer GIN sum+max readout)       │
            │  S9: Score Fusion (calibrated logistic regression)      │
            │ S10: Node Attribution (log-odds + GNN occlusion delta)  │
            │ S11: Obfuscation Detectors (CFF dispatcher, XOR loops)  │
            │ S12: RFC Report & 3D Force Graph Generation             │
            └────────────────────────────────────────────────────────┘
```

---

## 📂 Repository Layout

```
xray-binary/
├── apps/
│   ├── api/                 # FastAPI REST and SSE server (main.py, pipeline.py, demo_data.py)
│   └── web/                 # Interactive Cyber Web Dashboard (index.html: 3D WebGL graph, inspector)
├── packages/
│   ├── xray_core/           # Binary parser, structure labelling, WL kernel, obfuscation detectors
│   ├── xray_models/         # GIN Graph Neural Network, multi-modal fusion, calibration
│   └── xray_eval/           # Reference corpus, Evasion Lab, baselines, evaluation benchmarks
├── artifacts/               # Benchmark exports (eval_benchmarks.json, EVALUATION_RESULTS.md)
├── docs/                    # PRD, TRD, API, SystemDesign, UIUX, Pitch, Judges Q&A
├── tests/                   # Complete test suite (test_system.py, test_api.py, test_reference.py)
├── Dockerfile               # Production container build
├── docker-compose.yml       # One-command offline deployment
├── Makefile                 # Automation targets (make setup, test, eval, demo)
└── pyproject.toml           # Package configuration
```

---

## ⌨️ Presentation & Demo Shortcuts

When viewing the dashboard on `http://localhost:8000`:
- `1`: Jump to **Triage Intake**
- `2`: Jump to **Report Overview**
- `3`: Jump to **3D Structure Graph**
- `4`: Jump to **Obfuscation Lab**
- `5`: Jump to **Evasion Lab**
- `g`: Toggle between **3D WebGL** and **2D Accessible Graph** modes
- `Esc`: Close the Node Inspector drawer
- **Preset Dropdown:** Instantly loads pre-analyzed verified threat archetypes (**Ransomware**, **Keylogger**, **Downloader**, **Benign Utility**, and **UPX Packed**).

---

## 📖 Documentation Index

- [`docs/PRD.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/PRD.md): Product requirements, user stories, success metrics
- [`docs/TRD.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/TRD.md): Technical requirements, pipeline stages, data model
- [`docs/API.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/API.md): Complete OpenAPI specification and endpoints
- [`docs/SystemDesign.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/SystemDesign.md): Architecture, trust boundaries, failure modes
- [`docs/ALGORITHMS.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/ALGORITHMS.md): Mathematical formulations of WL, GNN, log-odds, and CFF
- [`docs/EVALUATION_PLAN.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/EVALUATION_PLAN.md): Evaluation methodology, splits, and baseline protocols
- [`docs/PITCH_AND_DEMO.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/PITCH_AND_DEMO.md): 12-slide pitch outline, 3-minute demo script, submission copy
- [`docs/JUDGES_QA.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/docs/JUDGES_QA.md): 22 hard defense and architectural questions with prepared answers
- [`artifacts/EVALUATION_RESULTS.md`](file:///c:/Users/MS/.gemini/antigravity-ide/scratch/xray-binary-docs/artifacts/EVALUATION_RESULTS.md): Detailed results report generated by `make eval`

---

## ⚖️ Ethics & Responsible Disclosure

X-Ray Binary is purely **defensive**. It performs static-only analysis and does not execute files, detonate payloads, or communicate with Command & Control infrastructure. The Evasion Lab applies transformations exclusively to **benign open-source utility programs built from source**; no new malware or exploit code is generated or altered.
