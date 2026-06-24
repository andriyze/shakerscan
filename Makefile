# ShakerScan developer targets.
PY ?= python3

.PHONY: e2e e2e-model-intake e2e-ai-gate e2e-dast test

## Full end-to-end suite against the live stack + honey targets (hard gate).
e2e:
	$(PY) tests/e2e/run_e2e.py --area all

e2e-model-intake:
	$(PY) tests/e2e/run_e2e.py --area model_intake

e2e-ai-gate:
	$(PY) tests/e2e/run_e2e.py --area ai_gate

e2e-dast:
	$(PY) tests/e2e/run_e2e.py --area dast
