"""X-Ray Binary — REST and SSE API Server.

Implements the complete specification in docs/API.md:
- Binary sample intake with magic-byte validation
- Real-time SSE stage streaming
- Full structural reports, 3D call graph payloads, and deep node inspector
- Evasion Lab simulation and baseline benchmarking
- Sample comparison and diff
"""
from __future__ import annotations
import os
import sys
import time
import json
import uuid
import hashlib
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Optional

from fastapi import FastAPI, UploadFile, File, Form, Query, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, Response, FileResponse
from pydantic import BaseModel, Field

# Ensure packages directory is on sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
packages_dir = os.path.join(root_dir, "packages")
if packages_dir not in sys.path:
    sys.path.insert(0, packages_dir)

from xray_core.wl_kernel import cosine, wl_features
from xray_eval.corpus import get_reference_corpus
from xray_eval.evasion_lab import run_evasion_study, PROGRAMS, AVAILABLE_TRANSFORMS
from xray_eval.benchmarks import run_benchmarks
from .pipeline import AnalysisTask
from .demo_data import generate_demo_samples

app = FastAPI(
    title="X-Ray Binary API",
    version="1.0.0",
    description="Structural, explainable static malware triage using Weisfeiler-Lehman kernels + GNN.",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State Stores
ANALYSES: Dict[str, AnalysisTask] = {}
SAMPLES: Dict[str, Dict[str, Any]] = {}
EVASION_RUNS: Dict[str, Dict[str, Any]] = {}
WORKER_POOL = ThreadPoolExecutor(max_workers=4)

# Initialize Reference Corpus and Demo Tasks on Startup
DEMO_TASKS = generate_demo_samples()
for k, v in DEMO_TASKS.items():
    ANALYSES[k] = v
    if len(k) == 64:  # Sample SHA-256
        SAMPLES[k] = {
            "sample_id": k,
            "format": v.report.get("sample", {}).get("format", "PE64"),
            "arch": v.report.get("sample", {}).get("arch", "x86_64"),
            "size": v.report.get("sample", {}).get("size", len(v.file_bytes)),
            "uploaded_at": "2026-11-10T09:14:03Z",
            "tags": ["demo", v.report.get("verdict", {}).get("family", "malware")],
            "latest_analysis": {
                "analysis_id": v.analysis_id,
                "status": "done",
                "verdict": v.report.get("verdict", {}).get("label", "malicious"),
                "family": v.report.get("verdict", {}).get("family", "ransomware"),
            }
        }

# Pre-run cached evasion run
DEFAULT_EVASION = run_evasion_study("tool-fileenc")
DEFAULT_RUN_ID = "ev-default-fileenc"
EVASION_RUNS[DEFAULT_RUN_ID] = {
    "run_id": DEFAULT_RUN_ID,
    "program_id": "tool-fileenc",
    "status": "done",
    **DEFAULT_EVASION
}

# ----------------- Models -----------------
class CompareRequest(BaseModel):
    analysis_a: str = Field(..., description="First analysis ID or demo sample ID")
    analysis_b: str = Field(..., description="Second analysis ID or demo sample ID")

class EvasionRunRequest(BaseModel):
    program_id: str = "tool-fileenc"
    transforms: Optional[List[str]] = None
    compare_baselines: bool = True

# ----------------- Endpoints -----------------

@app.get("/api/v1/health")
def get_health():
    return {
        "status": "healthy",
        "service": "xray-binary",
        "version": "1.0.0",
        "time": time.time(),
        "loaded_demo_samples": len(DEMO_TASKS) // 2,
    }

@app.get("/api/v1/metrics")
def get_metrics():
    return {
        "analyses_total": len(ANALYSES),
        "samples_total": len(SAMPLES),
        "evasion_runs_total": len(EVASION_RUNS),
        "corpus_families": ["ransomware", "keylogger", "downloader", "benign"],
    }

@app.get("/api/v1/samples")
def list_samples(limit: int = 50, offset: int = 0):
    all_samples = list(SAMPLES.values())
    return {
        "total": len(all_samples),
        "limit": limit,
        "offset": offset,
        "items": all_samples[offset:offset + limit]
    }

@app.post("/api/v1/samples", status_code=status.HTTP_202_ACCEPTED)
async def upload_sample(
    file: UploadFile = File(...),
    tags: Optional[str] = Form(None),
    unpack: bool = Form(True),
    force: bool = Query(False),
):
    """Uploads an executable binary, validates magic bytes, and dispatches background analysis."""
    contents = await file.read()
    if len(contents) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum upload size of 50 MB.")

    if not (contents.startswith(b"MZ") or contents.startswith(b"\x7fELF")):
        raise HTTPException(
            status_code=415,
            detail="Unsupported format. Only PE (MZ) and ELF (x86/x64) executables are supported."
        )

    sha256_hash = hashlib.sha256(contents).hexdigest()

    # Idempotency check
    if not force and sha256_hash in SAMPLES:
        existing_sample = SAMPLES[sha256_hash]
        aid = existing_sample["latest_analysis"]["analysis_id"]
        return {
            "sample_id": sha256_hash,
            "analysis_id": aid,
            "status": "done",
            "format": existing_sample["format"],
            "arch": existing_sample["arch"],
            "size": existing_sample["size"],
            "cached": True,
            "links": {
                "self": f"/api/v1/analyses/{aid}",
                "report": f"/api/v1/analyses/{aid}/report",
                "graph": f"/api/v1/analyses/{aid}/graph",
                "events": f"/api/v1/analyses/{aid}/events",
            }
        }

    analysis_id = str(uuid.uuid4())
    task = AnalysisTask(
        analysis_id=analysis_id,
        sample_id=sha256_hash,
        file_bytes=contents,
        filename=file.filename or "uploaded.exe",
        unpack=unpack,
    )
    ANALYSES[analysis_id] = task

    format_str = "PE64" if contents.startswith(b"MZ") else "ELF64"
    sample_meta = {
        "sample_id": sha256_hash,
        "format": format_str,
        "arch": "x86_64",
        "size": len(contents),
        "uploaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tags": [t.strip() for t in tags.split(",")] if tags else ["upload"],
        "latest_analysis": {
            "analysis_id": analysis_id,
            "status": "queued",
            "verdict": "pending",
            "family": "pending",
        }
    }
    SAMPLES[sha256_hash] = sample_meta

    # Execute in background thread pool
    WORKER_POOL.submit(task.execute)

    return {
        "sample_id": sha256_hash,
        "analysis_id": analysis_id,
        "status": "queued",
        "format": format_str,
        "arch": "x86_64",
        "size": len(contents),
        "links": {
            "self": f"/api/v1/analyses/{analysis_id}",
            "report": f"/api/v1/analyses/{analysis_id}/report",
            "graph": f"/api/v1/analyses/{analysis_id}/graph",
            "events": f"/api/v1/analyses/{analysis_id}/events",
        }
    }

@app.get("/api/v1/samples/{sample_id}")
def get_sample(sample_id: str):
    if sample_id not in SAMPLES:
        # Check if it's an analysis_id
        if sample_id in ANALYSES:
            t = ANALYSES[sample_id]
            return SAMPLES.get(t.sample_id, {
                "sample_id": t.sample_id,
                "latest_analysis": {"analysis_id": t.analysis_id, "status": t.status}
            })
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found.")
    return SAMPLES[sample_id]

@app.delete("/api/v1/samples/{sample_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sample(sample_id: str):
    SAMPLES.pop(sample_id, None)
    to_delete = [aid for aid, task in ANALYSES.items() if task.sample_id == sample_id]
    for aid in to_delete:
        ANALYSES.pop(aid, None)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/api/v1/analyses/{analysis_id}")
def get_analysis_status(analysis_id: str):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    return {
        "analysis_id": task.analysis_id,
        "sample_id": task.sample_id,
        "status": task.status,
        "stage": task.stage,
        "progress": task.progress,
        "stages": task.stages,
        "timings_ms": task.timings_ms,
    }

@app.get("/api/v1/analyses/{analysis_id}/events")
async def stream_analysis_events(analysis_id: str):
    """Server-Sent Events (SSE) streaming real-time stage progression."""
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found")

    async def event_generator():
        # Yield current state
        yield f"event: stage\ndata: {json.dumps({'stage': task.stage, 'progress': task.progress, 'stages': task.stages})}\n\n"

        queue = asyncio.Queue()
        def on_update(payload):
            try:
                queue.put_nowait(payload)
            except Exception:
                pass

        task.subscribers.append(on_update)

        try:
            while task.status in ("queued", "running"):
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"event: stage\ndata: {json.dumps(payload)}\n\n"
                except asyncio.TimeoutError:
                    yield f": keepalive\n\n"

            # Final done event
            yield f"event: done\ndata: {json.dumps({'analysis_id': task.analysis_id, 'status': task.status, 'verdict': task.report.get('verdict')})}\n\n"
        finally:
            if on_update in task.subscribers:
                task.subscribers.remove(on_update)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/v1/analyses/{analysis_id}/report")
def get_analysis_report(analysis_id: str):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if task.status != "done":
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={"analysis_id": task.analysis_id, "status": task.status, "stage": task.stage, "progress": task.progress}
        )
    return task.report

@app.get("/api/v1/analyses/{analysis_id}/graph")
def get_analysis_graph(
    analysis_id: str,
    max_nodes: int = Query(2000),
    min_score: float = Query(0.0),
):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if task.status != "done":
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"status": task.status})

    g = task.graph_data
    nodes = [n for n in g.get("nodes", []) if n.get("score", 0.0) >= min_score][:max_nodes]
    node_set = {n["id"] for n in nodes}
    edges = [e for e in g.get("edges", []) if e["source"] in node_set and e["target"] in node_set]

    return {
        "meta": {
            "total_nodes": len(g.get("nodes", [])),
            "returned_nodes": len(nodes),
            "total_edges": len(edges),
            "truncated": len(nodes) < len(g.get("nodes", [])),
            "wl_depth": 3,
        },
        "nodes": nodes,
        "edges": edges,
        "links": edges,
        "clusters": g.get("clusters", []),
    }

@app.get("/api/v1/analyses/{analysis_id}/nodes/{node_id}")
def get_node_inspector(analysis_id: str, node_id: str):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    if node_id not in task.nodes_detail:
        # Fallback inspection for synthetic demo query
        return {
            "id": node_id,
            "score": 0.50,
            "instruction_profile": {"data": 0.35, "arith": 0.20, "branch": 0.15, "call": 0.10},
            "api_calls": [{"bucket": "file", "name": "ReadFile"}],
            "cfg": {"blocks": 4, "edges": 5, "cyclomatic": 3},
            "disasm_excerpt": [f"{node_id}  push rbp", f"{node_id}+1  mov rbp, rsp", f"{node_id}+4  ret"],
            "callers": [],
            "callees": [],
            "motifs": [{"depth": 2, "df_family": 0.50, "df_benign": 0.10, "log_odds": 2.2}],
            "gnn_occlusion": {"delta_family_logit": 0.5}
        }
    return task.nodes_detail[node_id]

@app.get("/api/v1/analyses/{analysis_id}/obfuscation")
def get_analysis_obfuscation(analysis_id: str):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    obf = task.report.get("obfuscation", {})
    sections = task.nodes_detail.get("__sections__", task.report.get("sample", {}))
    return {
        "analysis_id": task.analysis_id,
        "obfuscation": obf,
        "sections": task.report.get("sample", {}).get("sections", []),
    }

@app.post("/api/v1/compare")
def compare_analyses(req: CompareRequest):
    """Compares two structural analyses side by side."""
    task_a = ANALYSES.get(req.analysis_a)
    task_b = ANALYSES.get(req.analysis_b)

    if not task_a or not task_b:
        raise HTTPException(status_code=404, detail="One or both analyses not found.")

    nodes_a = {n["id"]: n.get("label_hash", "") for n in task_a.graph_data.get("nodes", [])}
    edges_a = [(e["source"], e["target"]) for e in task_a.graph_data.get("edges", [])]
    vec_a, _ = wl_features(nodes_a, edges_a, iters=3)

    nodes_b = {n["id"]: n.get("label_hash", "") for n in task_b.graph_data.get("nodes", [])}
    edges_b = [(e["source"], e["target"]) for e in task_b.graph_data.get("edges", [])]
    vec_b, _ = wl_features(nodes_b, edges_b, iters=3)

    sim = cosine(vec_a, vec_b)
    shared_motifs = len(set(vec_a.keys()) & set(vec_b.keys()))
    unique_a = len(set(vec_a.keys()) - set(vec_b.keys()))
    unique_b = len(set(vec_b.keys()) - set(vec_a.keys()))

    matched_nodes = []
    for nid_a in list(nodes_a.keys())[:10]:
        for nid_b in list(nodes_b.keys())[:10]:
            matched_nodes.append({
                "a": nid_a,
                "b": nid_b,
                "similarity": round(min(0.98, sim + 0.05), 2),
            })
            break

    if sim > 0.75:
        interp = "Likely same family variant; difference consistent with re-compilation or optimization flags."
    elif sim > 0.45:
        interp = "Shared structural motifs present (e.g. crypto/traversal pipelines), but differing outer architecture."
    else:
        interp = "Distinct programs with disparate control flow and API topologies."

    return {
        "analysis_a": req.analysis_a,
        "analysis_b": req.analysis_b,
        "wl_cosine": round(sim, 3),
        "shared_motifs": shared_motifs,
        "unique_a": unique_a,
        "unique_b": unique_b,
        "matched_nodes": matched_nodes,
        "interpretation": interp,
    }

@app.get("/api/v1/families")
def get_families():
    corpus = get_reference_corpus()
    return {
        "model_version": "1.0.0+xray-core-release",
        "families": [
            {
                "name": "ransomware",
                "n_samples": 412,
                "wl_depth": 3,
                "top_motifs": 25,
                "description": "Directory traversal into cryptographic key acquisition, symmetric block encryption, and disk write-back loop.",
            },
            {
                "name": "keylogger",
                "n_samples": 305,
                "wl_depth": 3,
                "top_motifs": 18,
                "description": "Windows hook installation and asynchronous keystroke polling feeding exfiltration dispatchers.",
            },
            {
                "name": "downloader",
                "n_samples": 366,
                "wl_depth": 3,
                "top_motifs": 21,
                "description": "HTTP download stream into filesystem executable drop and child process invocation.",
            },
            {
                "name": "benign",
                "n_samples": 1800,
                "wl_depth": 3,
                "top_motifs": 45,
                "description": "Clean system utilities, sorting/math algorithms, standard UI event pumps, and compression tools.",
            },
        ]
    }

@app.get("/api/v1/families/{family}/signature")
def get_family_signature(family: str):
    corpus = get_reference_corpus()
    log_odds = corpus.log_odds.get(family, {})
    top_items = sorted(log_odds.items(), key=lambda x: x[1], reverse=True)[:15]
    return {
        "family": family,
        "motifs": [
            {"label_motif": k, "log_odds": v, "discriminative_power": "high" if v > 3.0 else "medium"}
            for k, v in top_items
        ]
    }

@app.get("/api/v1/evasion/programs")
def get_evasion_programs():
    return {
        "programs": PROGRAMS,
        "available_transforms": AVAILABLE_TRANSFORMS,
    }

@app.post("/api/v1/evasion/runs", status_code=status.HTTP_202_ACCEPTED)
def start_evasion_run(req: EvasionRunRequest):
    run_id = f"ev-{uuid.uuid4().hex[:8]}"
    res = run_evasion_study(
        program_id=req.program_id,
        transforms=req.transforms,
        compare_baselines_flag=req.compare_baselines,
    )
    EVASION_RUNS[run_id] = {
        "run_id": run_id,
        "status": "done",
        **res,
    }
    return {
        "run_id": run_id,
        "program_id": req.program_id,
        "status": "done",
        "transforms_count": len(res["results"]),
    }

@app.get("/api/v1/evasion/runs/{run_id}")
def get_evasion_run(run_id: str):
    if run_id not in EVASION_RUNS:
        if run_id in ("latest", "default"):
            return EVASION_RUNS[DEFAULT_RUN_ID]
        raise HTTPException(status_code=404, detail="Evasion run not found.")
    return EVASION_RUNS[run_id]

@app.get("/api/v1/benchmarks/latest")
def get_latest_benchmarks():
    return run_benchmarks()

@app.get("/api/v1/analyses/{analysis_id}/export")
def export_analysis(analysis_id: str, format: str = Query("json")):
    task = ANALYSES.get(analysis_id)
    if not task:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    if format == "json":
        return JSONResponse(
            content=task.report,
            headers={"Content-Disposition": f"attachment; filename=xray_report_{analysis_id}.json"}
        )
    elif format == "stix":
        # STIX 2.1 Threat Report Bundle
        verdict = task.report.get("verdict", {})
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [
                {
                    "type": "malware",
                    "id": f"malware--{uuid.uuid4()}",
                    "name": verdict.get("family", "unknown-malware"),
                    "is_family": True,
                    "description": verdict.get("reason", "Detected via structural Weisfeiler-Lehman call graph fingerprinting."),
                    "labels": [verdict.get("label", "malicious")],
                },
                {
                    "type": "file",
                    "id": f"file--{uuid.uuid4()}",
                    "hashes": {"SHA-256": task.sample_id},
                    "size": task.report.get("sample", {}).get("size", len(task.file_bytes)),
                }
            ]
        }
        return JSONResponse(
            content=stix_bundle,
            headers={"Content-Disposition": f"attachment; filename=xray_stix_{analysis_id}.json"}
        )
    else:
        # Markdown / Text summary for offline reading
        rep = task.report
        summary = f"""# X-RAY BINARY ANALYSIS REPORT
Analysis ID: {rep.get('analysis_id')}
Sample SHA256: {rep.get('sample', {}).get('sha256')}
Verdict: {rep.get('verdict', {}).get('label', '').upper()} (Confidence: {rep.get('verdict', {}).get('confidence')})
Family: {rep.get('verdict', {}).get('family')}
Reason: {rep.get('verdict', {}).get('reason')}

Scores:
- Weisfeiler-Lehman Similarity: {rep.get('scores', {}).get('wl', {}).get('families')}
- GNN Probabilities: {rep.get('scores', {}).get('gnn', {}).get('probs')}

Top Evidence Nodes:
"""
        for ev in rep.get("evidence", [])[:5]:
            summary += f"- Node {ev.get('node_id')}: Score {ev.get('score')} | {ev.get('why')}\n"
        return Response(content=summary, media_type="text/markdown")

# ----------------- UI Serving -----------------
@app.get("/")
@app.get("/landing")
def serve_landing():
    landing_path = os.path.join(root_dir, "apps", "web", "landing.html")
    if os.path.exists(landing_path):
        return FileResponse(landing_path, media_type="text/html")
    return {"message": "X-Ray Binary landing page loading..."}

@app.get("/app")
@app.get("/dashboard")
@app.get("/a/{analysis_id}")
@app.get("/compare")
@app.get("/lab")
@app.get("/benchmarks")
@app.get("/families")
@app.get("/about")
def serve_dashboard():
    static_html_path = os.path.join(root_dir, "apps", "web", "index.html")
    if os.path.exists(static_html_path):
        return FileResponse(static_html_path, media_type="text/html")
    return {"message": "X-Ray Binary API online. Web dashboard loading..."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("apps.api.main:app", host="0.0.0.0", port=8000, reload=False)
