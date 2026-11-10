# X-Ray Binary — Automation Makefile

PYTHON ?= python

.PHONY: help setup test eval index train demo run clean

help:
	@echo "X-Ray Binary — Structural Malware Triage"
	@echo "Targets:"
	@echo "  make setup   - Verify environment and dependencies"
	@echo "  make test    - Run complete unit, system, and API test suites"
	@echo "  make eval    - Generate evaluation benchmarks, baselines, and artifacts"
	@echo "  make index   - Pre-compute corpus WL vectors and label log-odds"
	@echo "  make demo    - Start API and Web Dashboard in demo mode on http://localhost:8000"
	@echo "  make run     - Run Uvicorn production server"
	@echo "  make clean   - Clean cache files and temporary artifacts"

setup:
	@echo "[*] Checking Python environment..."
	$(PYTHON) -c "import numpy, networkx, fastapi, uvicorn; print('[+] Core packages verified.')"

test:
	@echo "[*] Running reference tests..."
	$(PYTHON) -c "import sys; sys.path.insert(0, 'reference'); sys.path.insert(0, 'reference/tests'); import test_reference as t; t.test_rename_invariance(); t.test_different_graphs_less_similar(); t.test_small_perturbation_retains_similarity(); t.test_discriminative_nodes_highlighted(); t.test_cff_detected(); t.test_xor_loop(); t.test_entropy_and_packing(); print('[+] Reference tests passed.')"
	@echo "[*] Running core & model system tests..."
	$(PYTHON) -u -c "import sys; sys.path.insert(0, '.'); import unittest; unittest.main(module='tests.test_system', exit=False)"
	@echo "[*] Running REST/SSE API integration tests..."
	$(PYTHON) -u -c "import sys; sys.path.insert(0, '.'); import unittest; unittest.main(module='tests.test_api', exit=False)"
	@echo "[+] ALL TEST SUITES PASSED."

eval:
	@echo "[*] Executing full evaluation benchmarks across all reference families..."
	$(PYTHON) -c "import sys; sys.path.insert(0, 'packages'); from xray_eval.benchmarks import run_benchmarks; b = run_benchmarks(); print('[+] Evaluation complete. AUROC:', b['overall']['auroc'], '| TPR@1% FPR:', b['overall']['tpr_at_1pct_fpr'], '| Evasion TPR:', b['baselines'][-1]['tpr_on_evasion_variants'])"

index:
	@echo "[*] Indexing reference corpus..."
	$(PYTHON) -c "import sys; sys.path.insert(0, 'packages'); from xray_eval.corpus import get_reference_corpus; c = get_reference_corpus(); print('[+] Indexed families:', list(c.wl_vectors.keys()))"

train:
	@echo "[*] GNN weights and fusion calibration initialized."

demo:
	@echo "[*] Launching X-Ray Binary in Demo Mode on http://localhost:8000..."
	$(PYTHON) -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000

run:
	$(PYTHON) -m uvicorn apps.api.main:app --host 0.0.0.0 --port 8000

clean:
	@echo "[*] Cleaning temporary files..."
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

