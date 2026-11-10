# X-Ray Binary — System Design

## 1. Architecture Overview

```
                ┌────────────────────────────── Browser ──────────────────────────────┐
                │ Next.js UI: Upload · Report · 3D Graph · Obfuscation · Evasion Lab    │
                └──────────────▲───────────────────────────────┬──────────────────────┘
                               │ REST + SSE                     │ graph JSON / reports
                      ┌────────┴────────┐                      │
                      │   FastAPI API   │──────── SQL ────────▶ SQLite/Postgres
                      │ (validation,    │──────── files ──────▶ Artefact store (by SHA-256)
                      │  auth, export)  │
                      └────────┬────────┘
                               │ enqueue (Redis/RQ)
              ┌────────────────▼─────────────────┐
              │          Worker pool              │
              │ ┌───────────────────────────────┐ │
              │ │ Analysis sandbox (ephemeral   │ │   no network · read-only FS · cgroup limits
              │ │ container per job)            │ │
              │ │  radare2 → graph extraction   │ │
              │ └──────────────┬────────────────┘ │
              │      graph (JSON only) ▼          │
              │  Label → WL → GNN → Fusion →      │
              │  Attribution → Obfuscation → Report│
              └────────────────┬─────────────────┘
                               │ loads
                 ┌─────────────▼──────────────┐
                 │ Model & Reference Store     │  WL reference index · label log-odds ·
                 │ (versioned, read-only)      │  GNN weights · calibrator · thresholds
                 └─────────────────────────────┘

   Offline: Corpus Builder → Extractor → Index/Train → Evaluate → Publish model bundle
   Lab:     Benign source → Transform Matrix (opt, strip, pack, obf) → same pipeline → Retention report
```

## 2. Components

| Component | Responsibility | Notes |
|---|---|---|
| **Web UI** | Upload, progress, report, 3D graph, inspector, Evasion Lab, Benchmarks | WebGL; 2D fallback |
| **API service** | Validation (magic/size), job creation, status, report/graph serving, export | Stateless; horizontal scaling by replicas |
| **Queue** | Decouples request from heavy analysis; retries, timeouts | Redis + RQ |
| **Analysis sandbox** | Runs radare2 on untrusted bytes, emits **graph JSON only** | One container per job, destroyed after |
| **Core pipeline (`xray_core`)** | Labelling, WL, obfuscation, attribution | Pure Python, deterministic |
| **Model service (`xray_models`)** | GNN inference, fusion, calibration | Loaded once per worker |
| **Reference store** | WL vectors per family/benign, label statistics, weights | Versioned bundle; read-only at runtime |
| **Evasion Lab runner** | Builds transformed binaries of benign programs, runs pipeline + baselines | Cached by `(program, transform, toolchain)` |
| **Corpus builder / evaluator** | Offline: extract, dedup, split, index, train, evaluate | `make index train eval` |

## 3. Trust Boundaries

```
 [Untrusted]  uploaded bytes ─▶ [Sandbox: parse + disassemble] ─▶ graph JSON (data only) ─▶ [Trusted pipeline]
```
- Only **derived data** crosses the boundary: JSON with bounded size, schema-validated (no free-form blobs, strings truncated/escaped).
- Disassembly text excerpts are treated as untrusted text: HTML-escaped in the UI, length-capped.
- The trusted pipeline never opens the original binary again (except for the entropy/section parse done inside the sandbox).

## 4. Primary Flow — Analyse a Sample

```
Client            API             Redis/RQ        Worker/Sandbox           Store
  │ POST /samples  │                  │                 │                    │
  │───────────────▶│ validate magic   │                 │                    │
  │                │ sha256, dedupe ──┼─────────────────┼──── lookup ───────▶│ hit? return cached analysis
  │                │ enqueue job ────▶│                 │                    │
  │◀── 202 ids ────│                  │ dequeue ───────▶│ run r2 (timeout)   │
  │ SSE /events    │                  │                 │ emit graph JSON    │
  │◀─ stage: ... ──│◀── progress ─────│◀────────────────│ label/WL/GNN/fuse  │
  │                │                  │                 │ attribute/obfusc.  │
  │                │                  │                 │ write report ─────▶│
  │◀─ done ────────│◀──────────────────────────────────│                    │
  │ GET /report, /graph                                                      │
```

## 5. Evasion Lab Flow

```
Benign source (3+ programs)
   └─▶ Build matrix:  O0 O1 O2(ref) O3 Os | strip | UPX | string-XOR | OLLVM sub / bcf / fla | junk-insert | combined
        └─▶ for each variant: pipeline → WL vector, GNN probs, verdict, obfuscation flags
        └─▶ baselines on same variant: hash/YARA, TLSH, imphash, n-gram ML
   └─▶ Retention = cosine(WL(variant), WL(O2 reference));  detection survival = P(verdict ≥ suspicious)
   └─▶ Outputs: per-stage table, waterfall chart, graph-diff (reference vs variant)
```
Because the lab transforms **benign programs from source**, it needs no malware and is fully reproducible. Detection survival on real malware uses naturally occurring variants in the dataset (same family, different builds/packers) rather than manufactured evasions.

## 6. Scoring Design

```
 labelled graph ─┬─▶ WL vector ──▶ sim to {family refs, benign refs} ──┐
                 │                                                      ├─▶ Fusion (LogReg + Platt) ─▶ verdict
                 └─▶ GNN ───────▶ class probs + embedding ──────────────┤
 obfuscation flags / packed flag ───────────────────────────────────────┘
```
Independence argument: WL is a deterministic, data-free structural kernel; the GNN is learned. Agreement raises confidence, disagreement is surfaced to the analyst ("scorers disagree") and lowers `confidence`.

## 7. Explainability Design

| Layer | Method | UI element |
|---|---|---|
| Node evidence | WL label log-odds family vs benign; node score = mean top-2 positive log-odds | Node colour ramp, top-N list |
| Cross-check | GNN occlusion Δ-logit on top-K nodes | Inspector "model agrees: yes/no" |
| Motif rationale | `df_family`, `df_benign` for the node's strongest label | "Seen in 71 % ransomware refs, 0 % benign" |
| Obfuscation | CFF/XOR/packing evidence with addresses | Panel + badges on nodes |
| Faithfulness test | Remove top-k evidence nodes → recompute score | Reported in Benchmarks (metric) |

## 8. Data Storage

| Data | Where | Retention |
|---|---|---|
| Uploaded binary | `/data/samples/<sha256>` (0600) | Until deleted (`DELETE`), TTL configurable |
| Graph | `/data/graphs/<analysis>.json.gz` | With analysis |
| Report | `/data/reports/<analysis>.json` | With analysis |
| Reference bundle | `/data/models/<version>/` | Immutable |
| DB | SQLite file / Postgres | Persistent |

## 9. Failure Modes and Handling

| Failure | Detection | Handling |
|---|---|---|
| Disassembly timeout | worker wall-clock | retry with shallow analysis; partial report with `partial_analysis` |
| Corrupt/malicious header crashes r2 | non-zero exit / signal | job `failed`; container destroyed; error problem+json |
| Packed sample | entropy/RWX/imports | banner + `inconclusive_packed` unless unpack succeeds |
| Huge graph | node count > cap | truncate by size; `truncated` flag; viewer prunes |
| Model missing/corrupt | startup check | readiness fails; API returns 503 |
| Scorer disagreement | |p_wl − p_gnn| > δ | lower confidence; show both |
| Worker crash | RQ heartbeat | job requeued once, then failed |
| Disk full | health check | uploads rejected `507`/`503` |

## 10. Scalability Path

| Stage | Setup | Throughput intuition |
|---|---|---|
| Demo | 1 host, 4 workers | tens of samples/min (disassembly-bound) |
| Team | N workers across hosts, Postgres, MinIO | linear in workers |
| Org | Kubernetes Jobs for sandboxes (gVisor/Kata), Redis cluster, reference index sharded by family | horizontal; WL/GNN cost negligible relative to disassembly |

Cache key `(sha256, model_version)` makes re-analysis free; reference index is immutable per version so replicas stay consistent.

## 11. Security Architecture (summary)

Defence in depth: (1) magic/size validation, (2) per-job ephemeral sandbox with `--network none`, read-only FS, dropped caps, seccomp, cgroup limits, non-root, (3) JSON-only boundary, (4) no execution of samples anywhere, (5) HTML-escaping of all untrusted text in UI, (6) audit logs with request IDs. Details in `SECURITY_AND_ETHICS.md`.

## 12. Deployment (docker compose)

```yaml
services:
  api:     { build: ./apps/api,    ports: ["8000:8000"], depends_on: [redis, db], volumes: ["data:/data"] }
  worker:  { build: ./apps/worker, deploy: { replicas: 4 }, volumes: ["data:/data:rw", "models:/models:ro"],
             # spawns/uses the sandbox image for the r2 step
           }
  sandbox: { build: ./sandbox, network_mode: none, read_only: true, cap_drop: [ALL],
             security_opt: ["no-new-privileges:true"], pids_limit: 256, mem_limit: 2g, tmpfs: ["/work:size=512m"] }
  web:     { build: ./apps/web, ports: ["3000:3000"] }
  redis:   { image: redis:7 }
  db:      { image: postgres:16 }   # or SQLite in demo profile
volumes: { data: {}, models: {} }
```
Worker invokes the sandbox per job (`docker run --rm --network none …` or an in-container `bwrap`/`nsjail` equivalent where Docker-in-Docker is undesirable).

## 13. Observability

Prometheus: `xray_jobs_total{status}`, `xray_stage_seconds{stage}`, `xray_queue_depth`, `xray_r2_timeouts_total`, `xray_verdicts_total{label}`. Structured logs include `request_id`, `sha256`, `analysis_id`, stage, duration.

## 14. Key Design Decisions (ADR summary)

| ADR | Decision | Rationale | Trade-off |
|---|---|---|---|
| 1 | Call graph + per-function CFG stats, not whole-program CFG | Small, robust, fast | Loses some intra-function detail (compensated by CFG features in labels) |
| 2 | API calls as node attributes, not nodes | Robust to import-table reordering; smaller graphs | Indirect/dynamic resolution (`GetProcAddress`) under-captured → loader bucket flagged |
| 3 | WL + GNN dual scorers | Independent evidence; WL is training-free and explainable | Two components to maintain |
| 4 | Log-odds attribution over GNN-only explainers | Faithful to the fingerprint actually used; cheap | GNN occlusion kept as cross-check |
| 5 | Report limits instead of hiding them | Packed/partial states are first-class | Some demo samples return "inconclusive" |
| 6 | Evasion Lab on benign source | Safe, reproducible, no malware generation | Real-world evasions may differ; mitigated with natural-variant evaluation |
| 7 | Offline-first | SOC/air-gapped adoption | No cloud reputation features |
