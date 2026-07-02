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

## Fast unit tests (pure logic) — run inside the api container, which has the runtime
## deps (asyncpg/fastapi/...). pytest ships in the image; we install it on the fly only
## when running against an older image that predates it. The host can't run these (no
## asyncpg), so they intentionally run in-container.
UNIT_TESTS = tests/test_deployment_gate.py tests/test_canonical_dedupe.py \
	tests/test_api_id_validation.py \
	tests/test_evidence_objects.py tests/test_worker_freshness.py \
	tests/test_agent_receipt_verification.py tests/test_application_graph.py
test:
	@docker compose exec -T api rm -rf /tmp/tests >/dev/null
	@docker compose cp tests api:/tmp/tests >/dev/null
	@docker compose exec -T api sh -lc '\
		command -v pytest >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1; \
		rm -rf /tmp/api /tmp/scanner; cd /tmp; \
		PYTHONPATH=/app/_src/api:/app/_src python -m pytest -q -p no:cacheprovider $(UNIT_TESTS)'
