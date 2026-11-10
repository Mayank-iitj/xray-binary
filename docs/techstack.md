# X-Ray Binary — Tech Stack

Versions: pin exact versions in lockfiles / Dockerfiles on Day 1. Ranges below are the compatibility targets, not claims about "latest".

## 1. Summary

| Layer | Choice | Why | Alternatives considered |
|---|---|---|---|
| Disassembly / analysis | **radare2** (+ `r2pipe`) | Free, scriptable, JSON output (`aflj`, `afbj`, `pdfj`, `iij`, `iSj`), PE+ELF+multi-arch, runs headless | Ghidra headless (better decompiler, heavier/slower start), angr (powerful CFG, slow), IDA (licence), Capstone (disassembly only, no function recovery) |
| Binary parsing | **LIEF**, `pefile`, `pyelftools` | Sections, entropy, imports, header sanity independent of r2 | — |
| Unpacking (P1) | **UPX** (`upx -d`) | Most common static-unpackable packer | Emulation-based unpackers (out of scope: would execute code paths) |
| Graph algorithms | **NetworkX**, **NumPy**, **SciPy sparse** | Simple, testable; WL implemented in-house (≈60 LOC, `reference/wl_kernel.py`) | GraKeL (WL kernel library; optional cross-check) |
| ML — GNN | **PyTorch** + **PyTorch Geometric** (GIN/GraphSAGE) | Standard, CPU inference fine | DGL |
| ML — classical | **scikit-learn** (logistic fusion, calibration), **LightGBM** (baseline) | Calibrated, interpretable fusion | XGBoost |
| Similarity index | Sparse vectors + inverted index on `(depth,label)`; optional **FAISS** for GNN embeddings | Exact and fast at corpus scale ≤ 10⁵ | HNSW libs |
| API | **FastAPI** + **Pydantic v2** + **Uvicorn** | Typed contracts, auto OpenAPI, SSE support | Flask |
| Jobs | **Redis** + **RQ** (or Celery) | Simple worker pool, retries, timeouts | Dramatiq, Kafka (overkill) |
| Persistence | **SQLite** (demo) → **PostgreSQL 16** (prod) via **SQLAlchemy** + Alembic | Zero-setup demo, clean upgrade path | — |
| Artefact storage | Local volume (content-addressed by SHA-256); **MinIO** optional | Offline-friendly | S3 |
| Frontend | **Next.js** (React, TypeScript), **Tailwind CSS**, **shadcn/ui** | Fast UI, strong DX | Vite+React |
| 3D graph | **3d-force-graph** (three.js / WebGL) with `d3-force-3d` | Interactive force layout, node picking, custom materials | Cytoscape.js (2D fallback), sigma.js |
| Charts | **Recharts** or **Plotly.js** | Retention curves, waterfall, ROC | — |
| Reports | **WeasyPrint** (HTML→PDF), JSON | Offline PDF | ReportLab |
| Packaging | **Docker**, **docker compose** | One-command offline deploy | Podman |
| Sandbox hardening | Docker flags + seccomp default; optional **gVisor** (`runsc`) | Defence in depth for hostile inputs | Firecracker |
| Observability | **structlog**, **Prometheus** client, optional Grafana | Stage timings, queue depth | OpenTelemetry |
| Testing | **pytest**, **hypothesis**, **Playwright** | Unit/property/UI | — |
| Quality | **ruff**, **mypy**, **pre-commit**, **GitHub Actions** | CI gate | — |
| Evasion lab toolchain | **gcc/clang** (-O0…-O3, -Os), **mingw-w64** (PE cross-build), **Obfuscator-LLVM / Hikari-style passes** (`-mllvm -sub -bcf -fla`), **UPX**, custom junk-insertion pass | Standard, reproducible transformations on **benign source** | — |
| Baselines | **YARA** (+ `yara-python`), **TLSH**, **ssdeep**, **imphash**, **LightGBM on byte/opcode n-grams**, optional **MalConv** | Fair comparison on identical variants | — |

## 2. Version Targets

| Component | Target |
|---|---|
| Python | 3.11 – 3.12 |
| Node.js | current LTS |
| PyTorch / PyG | 2.x / 2.x (CPU wheels) |
| radare2 | recent stable (≥ 5.8); **pin exact build in Dockerfile and verify r2 JSON field names** |
| PostgreSQL | 16 |
| Redis | 7 |

## 3. Repository Layout

```
xray-binary/
├─ apps/
│  ├─ api/               # FastAPI app (routers, schemas, deps)
│  ├─ worker/            # RQ worker entrypoints (analysis, evasion)
│  └─ web/               # Next.js UI
├─ packages/
│  ├─ xray_core/         # extraction, labelling, WL, obfuscation, scoring
│  ├─ xray_models/       # GNN, fusion, calibration, training scripts
│  └─ xray_eval/         # splits, metrics, baselines, evasion lab
├─ sandbox/              # Dockerfile.analysis (r2 + deps), seccomp profile
├─ data/                 # (gitignored) corpora, indexes, models
├─ artifacts/            # eval outputs, figures, tables
├─ docs/                 # these documents
├─ docker-compose.yml
├─ Makefile              # make setup | index | train | eval | demo | test
└─ pyproject.toml / package.json / lockfiles
```

## 4. Environment Variables

| Var | Default | Meaning |
|---|---|---|
| `XRAY_MAX_UPLOAD_MB` | 50 | Upload cap |
| `XRAY_R2_TIMEOUT_S` | 60 | Disassembly wall-clock |
| `XRAY_MAX_FUNCS` | 20000 | Function cap |
| `XRAY_WL_DEPTH` | 3 | WL iterations |
| `XRAY_WORKERS` | cores | Worker count |
| `XRAY_MODEL_DIR` | `/data/models` | Model/index location |
| `XRAY_DB_URL` | `sqlite:///data/xray.db` | DB |
| `XRAY_API_KEYS` | empty | Comma list; empty = demo mode |
| `XRAY_SEED` | 1337 | Global seed |

## 5. Dependency Policy

- Lockfiles committed; hashes verified in Docker build.
- Runtime containers have **no outbound network**; model and reference data baked into volumes at build/index time.
- Third-party licences tracked (radare2 LGPL, UPX GPL-with-exception, YARA BSD, PyTorch BSD, three.js MIT).

## 6. Hardware Targets

| Use | Spec |
|---|---|
| Demo laptop | 4+ cores, 16 GB RAM, no GPU required |
| Training GNN | CPU feasible for ≤ 5 k graphs; GPU optional (single consumer GPU) |
| Corpus indexing | Embarrassingly parallel over files (≈ N cores × throughput) |
