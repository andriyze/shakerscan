# ShakerScan developer targets.
PY ?= python3
UV ?= uv
UVX ?= uvx

.PHONY: e2e e2e-model-intake e2e-model-intake-fixture e2e-ai-gate e2e-dast test \
	release-gates dependency-lock dependency-audit upgrade-smoke

## Regenerate the cross-platform Python 3.12 runtime lock consumed by scanner/Dockerfile.
dependency-lock:
	$(UV) pip compile scanner/requirements.txt --python-version 3.12 --universal \
		--generate-hashes --output-file scanner/requirements.lock

## Networked release check: fail on known UI or locked Python dependency vulnerabilities.
## Uses the same --audit-level=high threshold as the release workflow so local == CI.
dependency-audit:
	npm --prefix ui audit --omit=dev --audit-level=high
	$(UVX) pip-audit --no-deps --disable-pip -r scanner/requirements.lock

## Exercise current migrations twice over clean and duplicate-dirty published schemas.
upgrade-smoke:
	docker build -f scanner/Dockerfile -t shakerscan-scanner:upgrade-smoke .
	SCANNER_IMAGE=shakerscan-scanner:upgrade-smoke scripts/upgrade_smoke.sh

## Full manual/release end-to-end suite against the live stack + honey targets.
e2e:
	$(PY) tests/e2e/run_e2e.py --area all

e2e-model-intake:
	SHAKERSCAN_E2E_HF=1 $(PY) tests/e2e/run_e2e.py --area model_intake

## Offline/deterministic Model Intake subset for environments without external network access.
e2e-model-intake-fixture:
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
	@docker compose exec -T api sh -lc 'rm -rf /tmp/tests /tmp/db /tmp/api; mkdir -p /tmp/api' >/dev/null
	@docker compose cp tests api:/tmp/tests >/dev/null
	@docker compose cp db api:/tmp/db >/dev/null
	@docker compose cp api/retest_contract.py api:/tmp/api/retest_contract.py >/dev/null
	@docker compose exec -T api sh -lc '\
		command -v pytest >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1; \
		rm -rf /tmp/scanner; cd /tmp; \
		PYTHONPATH=/app/_src/api:/app/_src python -m pytest -q -p no:cacheprovider $(UNIT_TESTS)'

## Run the named roadmap release gates. Use GATES='test:planner-no-shell ...'
## to run a subset.
release-gates:
	$(PY) scripts/release_gates.py $(GATES)
