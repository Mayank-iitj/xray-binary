"""API Integration Test Suite.

Tests all REST endpoints specified in docs/API.md:
- Health check & Metrics
- Sample upload & SSE event subscription
- Report fetching & schema validation
- 3D Graph endpoint & Node inspector
- Obfuscation details & Section entropy
- Comparison diff endpoint
- Evasion Lab runs & Benchmark results
"""
from __future__ import annotations
import os
import sys
import unittest
from fastapi.testclient import TestClient

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (root_dir, os.path.join(root_dir, "packages"), os.path.join(root_dir, "apps")):
    if p not in sys.path:
        sys.path.insert(0, p)

from apps.api.main import app
from apps.api.demo_data import create_synthetic_pe_bytes

class TestAPIEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_health_and_metrics(self):
        res = self.client.get("/api/v1/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "xray-binary")

        res_m = self.client.get("/api/v1/metrics")
        self.assertEqual(res_m.status_code, 200)

    def test_demo_sample_report(self):
        res = self.client.get("/api/v1/analyses/demo-ransomware/report")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["schema_version"], "1.0")
        self.assertEqual(data["verdict"]["label"], "malicious")
        self.assertEqual(data["verdict"]["family"], "ransomware")
        self.assertGreater(data["verdict"]["confidence"], 0.80)
        self.assertTrue(len(data["evidence"]) > 0)

    def test_demo_sample_graph_and_node(self):
        res_g = self.client.get("/api/v1/analyses/demo-ransomware/graph")
        self.assertEqual(res_g.status_code, 200)
        g = res_g.json()
        self.assertTrue(len(g["nodes"]) > 0)
        top_node = g["nodes"][0]["id"]

        res_n = self.client.get(f"/api/v1/analyses/demo-ransomware/nodes/{top_node}")
        self.assertEqual(res_n.status_code, 200)
        n_detail = res_n.json()
        self.assertEqual(n_detail["id"], top_node)
        self.assertIn("instruction_profile", n_detail)

    def test_packed_demo_sample(self):
        res = self.client.get("/api/v1/analyses/demo-packed/report")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["verdict"]["label"], "inconclusive_packed")
        self.assertTrue(data["obfuscation"]["packed"]["likely"])

    def test_compare_endpoint(self):
        res = self.client.post("/api/v1/compare", json={
            "analysis_a": "demo-ransomware",
            "analysis_b": "demo-keylogger"
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("wl_cosine", data)
        self.assertIn("interpretation", data)

    def test_evasion_and_benchmarks(self):
        res_p = self.client.get("/api/v1/evasion/programs")
        self.assertEqual(res_p.status_code, 200)

        res_ev = self.client.get("/api/v1/evasion/runs/latest")
        self.assertEqual(res_ev.status_code, 200)
        ev_data = res_ev.json()
        self.assertTrue(len(ev_data["results"]) >= 10)

        res_bm = self.client.get("/api/v1/benchmarks/latest")
        self.assertEqual(res_bm.status_code, 200)
        bm_data = res_bm.json()
        self.assertGreater(bm_data["overall"]["auroc"], 0.97)

    def test_live_upload(self):
        pe_bytes = create_synthetic_pe_bytes("downloader")
        files = {"file": ("test_sample.exe", pe_bytes, "application/octet-stream")}
        res = self.client.post("/api/v1/samples", files=files, data={"unpack": "true"})
        self.assertEqual(res.status_code, 202)
        data = res.json()
        self.assertIn("analysis_id", data)
        self.assertIn("sample_id", data)

if __name__ == "__main__":
    unittest.main()
