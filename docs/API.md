# X-Ray Binary — API Specification (v1)

Base URL: `http://localhost:8000/api/v1` · Format: JSON (`application/json`) unless noted · Implementation: FastAPI (OpenAPI auto-published at `/openapi.json`, UI at `/docs`).

## 1. Conventions

| Topic | Rule |
|---|---|
| Auth | Demo mode: none. Hosted mode: `X-API-Key: <key>` header. |
| IDs | `sample_id` = SHA-256 hex (64 chars). `analysis_id` = UUIDv4. |
| Async | Analysis is a job: `POST` returns `202`; poll `GET` or subscribe to SSE. |
| Idempotency | Re-uploading identical bytes returns the existing sample; add `?force=true` to re-run. |
| Errors | RFC 7807 `application/problem+json` (see §9). |
| Rate limits | 30 uploads/min/key (configurable); `429` with `Retry-After`. |
| Versioning | URI prefix `/api/v1`; report schema carries `schema_version`. |
| Safety | The API never returns raw sample bytes. |

## 2. Endpoint Summary

| Method | Path | Purpose | Pri |
|---|---|---|---|
| POST | `/samples` | Upload a binary and start analysis | P0 |
| GET | `/samples/{sample_id}` | Sample metadata and latest analysis status | P0 |
| DELETE | `/samples/{sample_id}` | Delete sample and derived data | P0 |
| GET | `/analyses/{analysis_id}` | Analysis status and progress | P0 |
| GET | `/analyses/{analysis_id}/events` | SSE progress stream | P1 |
| GET | `/analyses/{analysis_id}/report` | Full report (verdict, scores, evidence) | P0 |
| GET | `/analyses/{analysis_id}/graph` | Graph for the 3D viewer | P0 |
| GET | `/analyses/{analysis_id}/nodes/{node_id}` | Node inspector (disassembly excerpt, neighbours) | P0 |
| GET | `/analyses/{analysis_id}/obfuscation` | Obfuscation/packing indicators | P0 |
| GET | `/analyses/{analysis_id}/export?format=json\|pdf\|stix` | Export | P1 |
| POST | `/compare` | Structural comparison of two analyses | P1 |
| GET | `/families` | Reference families and corpus stats | P0 |
| GET | `/families/{family}/signature` | Top discriminative structural motifs | P1 |
| GET | `/evasion/programs` | Benign test programs available to the lab | P0 |
| POST | `/evasion/runs` | Start an evasion study | P0 |
| GET | `/evasion/runs/{run_id}` | Status and results | P0 |
| GET | `/benchmarks/latest` | Latest evaluation metrics and baselines | P0 |
| GET | `/health` | Liveness/readiness | P0 |
| GET | `/metrics` | Prometheus metrics | P1 |

## 3. Samples

### `POST /samples`
`multipart/form-data`

| Field | Type | Req | Notes |
|---|---|---|---|
| `file` | binary | yes | ≤ `MAX_UPLOAD_MB` (default 50). Validated by magic bytes. |
| `tags` | string | no | Free-text comma list |
| `unpack` | bool | no | Default `true` (static UPX unpack attempt) |

**202 Accepted**
```json
{
  "sample_id": "9f2c…e1",
  "analysis_id": "5b0c9e6e-6d52-4a8e-9d5f-0d5a2f4a7c11",
  "status": "queued",
  "format": "PE64",
  "arch": "x86_64",
  "size": 1843200,
  "links": {
    "self": "/api/v1/analyses/5b0c9e6e-…",
    "events": "/api/v1/analyses/5b0c9e6e-…/events"
  }
}
```
**Errors:** `413` too large · `415` unsupported format · `422` invalid multipart · `429` rate limit.

### `GET /samples/{sample_id}`
```json
{
  "sample_id": "9f2c…e1", "format": "PE64", "arch": "x86_64", "size": 1843200,
  "uploaded_at": "2026-11-10T09:14:03Z", "tags": ["demo"],
  "latest_analysis": {"analysis_id": "5b0c…", "status": "done", "verdict": "malicious", "family": "ransomware"}
}
```

### `DELETE /samples/{sample_id}` → `204`. Removes upload, graphs, reports.

## 4. Analyses

### `GET /analyses/{analysis_id}`
```json
{
  "analysis_id": "5b0c…", "sample_id": "9f2c…", "status": "running",
  "stage": "disassembly", "progress": 0.35,
  "stages": [
    {"name": "intake", "state": "done", "ms": 112},
    {"name": "triage", "state": "done", "ms": 640},
    {"name": "disassembly", "state": "running", "ms": null},
    {"name": "graph", "state": "pending"}
  ]
}
```
`status` ∈ `queued | running | done | failed | timeout`.

### `GET /analyses/{analysis_id}/events` (SSE)
```
event: stage
data: {"name":"disassembly","state":"done","ms":18420}

event: done
data: {"analysis_id":"5b0c…","verdict":"malicious"}
```

### `GET /analyses/{analysis_id}/report`
```json
{
  "schema_version": "1.0",
  "analysis_id": "5b0c…",
  "sample": {"sha256": "9f2c…", "format": "PE64", "arch": "x86_64", "size": 1843200},
  "verdict": {
    "label": "malicious",              
    "confidence": 0.962,               
    "family": "ransomware",
    "family_confidence": 0.91,
    "open_set": false,
    "reason": "14 functions share ransomware-specific structure: enumerate-files → crypto → write-back loop."
  },
  "scores": {
    "wl": {"depth": 3, "families": {"ransomware": 0.88, "keylogger": 0.31, "downloader": 0.27}, "benign": 0.22,
           "nearest": [{"ref_id": "rw-0142", "family": "ransomware", "similarity": 0.88}]},
    "gnn": {"probs": {"ransomware": 0.93, "keylogger": 0.02, "downloader": 0.03, "benign": 0.02}},
    "fusion": {"p_malware": 0.962, "calibrated": true, "thresholds": {"suspicious": 0.20, "malicious": 0.80}}
  },
  "evidence": [
    {"node_id": "0x140012a40", "score": 0.97, "rank": 1,
     "why": "WL motif seen in 71% of ransomware refs, 0% of benign refs",
     "api_buckets": ["file", "crypto"], "callers": 2, "callees": 5}
  ],
  "obfuscation": {
    "packed": {"likely": false, "structure_reliable": true, "evidence": []},
    "cff": [{"function": "0x140031000", "score": 0.84, "dispatcher": "0x140031040"}],
    "xor_decode": [{"function": "0x14002c900", "loop_blocks": ["0x14002c910", "0x14002c93a"]}],
    "junk_ratio": 0.07
  },
  "flags": {"partial_analysis": false, "truncated": false, "unpack_attempted": false},
  "timings_ms": {"intake": 112, "triage": 640, "disassembly": 18420, "graph": 1210, "wl": 340, "gnn": 2010, "fusion": 12, "attribution": 420, "obfuscation": 1650},
  "toolchain": {"model_version": "1.0.0+d41c9a", "radare2": "<pinned>", "torch": "<pinned>"},
  "limitations": []
}
```
`verdict.label` ∈ `benign | suspicious | malicious | inconclusive_packed | error`. Reports for packed samples without successful unpack include `"limitations": ["packed: static call graph reflects unpacker stub"]`.

## 5. Graph and Node Inspection

### `GET /analyses/{analysis_id}/graph`
Query: `max_nodes` (default 2000), `min_score` (0–1), `include=cfg` (optional).
```json
{
  "meta": {"total_nodes": 4312, "returned_nodes": 2000, "truncated": true, "wl_depth": 3},
  "nodes": [
    {"id": "0x140012a40", "label_hash": "a41f…", "score": 0.97, "size": 812, "in": 2, "out": 5,
     "api": ["file", "crypto"], "obf": ["xor_decode"], "cluster": 7}
  ],
  "edges": [{"source": "0x140011000", "target": "0x140012a40"}],
  "clusters": [{"id": 7, "label": "file-enumeration + crypto", "mean_score": 0.88}]
}
```
Large graphs are pruned: keep all nodes with `score ≥ min_score`, their 1-hop neighbours, and top-degree nodes; collapse low-score benign-like regions into cluster super-nodes.

### `GET /analyses/{analysis_id}/nodes/{node_id}`
```json
{
  "id": "0x140012a40", "score": 0.97,
  "instruction_profile": {"data": 0.31, "arith": 0.12, "xor": 0.09, "cjmp": 0.11, "call": 0.14},
  "api_calls": [{"bucket": "file", "name": "FindFirstFileW"}, {"bucket": "crypto", "name": "CryptEncrypt"}],
  "cfg": {"blocks": 27, "edges": 38, "cyclomatic": 13, "loops": 2},
  "disasm_excerpt": ["0x140012a40  push rbp", "0x140012a41  mov rbp, rsp", "…"],
  "callers": ["0x140011000"], "callees": ["0x14000f200", "0x140010800"],
  "motifs": [{"depth": 2, "df_family": 0.71, "df_benign": 0.0, "log_odds": 5.8}],
  "gnn_occlusion": {"delta_family_logit": -2.4}
}
```
`disasm_excerpt` is capped (default 40 lines) and is text only.

## 6. Obfuscation
### `GET /analyses/{analysis_id}/obfuscation` → the `obfuscation` object from the report plus `sections` table (`name, entropy, flags, virtual_size, raw_size`) and import statistics.

## 7. Compare
### `POST /compare`
```json
{ "analysis_a": "5b0c…", "analysis_b": "77aa…" }
```
**200**
```json
{
  "wl_cosine": 0.83,
  "shared_motifs": 214, "unique_a": 96, "unique_b": 131,
  "matched_nodes": [{"a": "0x140012a40", "b": "0x401a20", "similarity": 0.94}],
  "interpretation": "Likely same family; B appears recompiled at a different optimisation level."
}
```

## 8. Families, Evasion Lab, Benchmarks

### `GET /families`
```json
{"families": [
  {"name": "ransomware", "n_samples": 412, "wl_depth": 3, "top_motifs": 25},
  {"name": "keylogger", "n_samples": 305}, {"name": "downloader", "n_samples": 366}, {"name": "benign", "n_samples": 1800}
], "model_version": "1.0.0+d41c9a"}
```

### `GET /evasion/programs` — benign test programs built from source
```json
{"programs": [{"id": "tool-fileenc", "description": "Open-source file-encryption utility (benign)"},
              {"id": "tool-httpget", "description": "Open-source HTTP fetch utility (benign)"},
              {"id": "tool-hotkey", "description": "Open-source keyboard-shortcut utility (benign)"}]}
```

### `POST /evasion/runs`
```json
{
  "program_id": "tool-fileenc",
  "transforms": ["opt_O0", "opt_O1", "opt_O3", "strip", "upx", "string_xor", "ollvm_sub", "ollvm_bcf", "ollvm_fla", "junk_insert", "combined"],
  "compare_baselines": true
}
```
**202** → `{"run_id": "ev-7c1…", "status": "queued"}`

### `GET /evasion/runs/{run_id}`
```json
{
  "run_id": "ev-7c1…", "program_id": "tool-fileenc", "status": "done",
  "reference_stage": "opt_O2",
  "results": [
    {"stage": "opt_O2", "sha256": "…", "wl_similarity_to_ref": 1.00, "family_score": 0.74,
     "baselines": {"hash_match": true, "yara": true, "tlsh_distance": 0, "ngram_ml_p": 0.71}},
    {"stage": "upx", "sha256": "…", "wl_similarity_to_ref": 0.31, "flag": "packed_unreliable",
     "after_static_unpack": {"wl_similarity_to_ref": 0.97},
     "baselines": {"hash_match": false, "yara": false, "tlsh_distance": 288, "ngram_ml_p": 0.18}}
  ],
  "summary": {"mean_retention_wo_packing": 0.0, "note": "values above are illustrative schema examples, not measured results"}
}
```
> Example numbers in this document illustrate the **schema only**; real values come from `make eval`.

### `GET /benchmarks/latest`
```json
{
  "eval_id": "ev-2026-11-10", "split": "time_based",
  "overall": {"auroc": null, "tpr_at_1pct_fpr": null, "macro_f1": null},
  "per_family": [{"family": "ransomware", "precision": null, "recall": null, "f1": null, "n_test": null}],
  "leave_one_family_out": [{"held_out": "keylogger", "flagged_suspicious_rate": null}],
  "baselines": [{"name": "yara_hash", "tpr_on_evasion_variants": null}, {"name": "tlsh", "tpr_on_evasion_variants": null},
                {"name": "ngram_lgbm", "tpr_on_evasion_variants": null}],
  "confidence_intervals": "bootstrap_95"
}
```
`null` = not yet measured; the API never fabricates numbers.

## 9. Errors (RFC 7807)
```json
{
  "type": "https://xray-binary.local/problems/unsupported-format",
  "title": "Unsupported file format",
  "status": 415,
  "detail": "Magic bytes 50 4B 03 04 (ZIP). Supported: PE, ELF.",
  "instance": "/api/v1/samples"
}
```
| Code | Meaning |
|---|---|
| 400 | Bad request |
| 401/403 | Missing/invalid API key |
| 404 | Unknown id |
| 409 | Analysis already running for this sample |
| 413 | Upload too large |
| 415 | Unsupported format |
| 422 | Validation error |
| 429 | Rate limited |
| 500 | Internal error (request id in `X-Request-ID`) |
| 504 | Analysis timeout (partial report may exist: `GET …/report` returns `flags.partial_analysis=true`) |

## 10. Health
`GET /health` → `{"status":"ok","queue":{"depth":0},"workers":{"alive":4},"model":{"version":"1.0.0+d41c9a","loaded":true}}`

## 11. Example Session
```bash
curl -s -F file=@sample.bin http://localhost:8000/api/v1/samples          # → analysis_id
curl -N  http://localhost:8000/api/v1/analyses/$AID/events                 # stream progress
curl -s  http://localhost:8000/api/v1/analyses/$AID/report | jq '.verdict, .evidence[:3]'
curl -s  "http://localhost:8000/api/v1/analyses/$AID/graph?max_nodes=1500" > graph.json
```

## 12. Pydantic Models (excerpt)
```python
class Verdict(BaseModel):
    label: Literal["benign","suspicious","malicious","inconclusive_packed","error"]
    confidence: confloat(ge=0, le=1)
    family: str | None
    family_confidence: confloat(ge=0, le=1) | None
    open_set: bool
    reason: str

class Evidence(BaseModel):
    node_id: str; score: float; rank: int; why: str
    api_buckets: list[str]; callers: int; callees: int
```
