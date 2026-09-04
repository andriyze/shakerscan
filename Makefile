# ShakerScan developer targets.
PY ?= python3
UV ?= uv
UVX ?= uvx

.PHONY: e2e e2e-model-intake e2e-model-intake-fixture e2e-ai-gate e2e-dast e2e-hunt e2e-platform e2e-scan-parity e2e-wire e2e-api-overlay test \
	release-gates dependency-lock dependency-audit installer-smoke installed-stack-smoke upgrade-smoke fleet-acceptance

## Regenerate the cross-platform Python 3.12 runtime lock consumed by scanner/Dockerfile.
dependency-lock:
	$(UV) pip compile scanner/requirements.txt --python-version 3.12 --universal \
		--generate-hashes --output-file scanner/requirements.lock

## Networked release check: fail on known UI or locked Python dependency vulnerabilities.
## Uses the same --audit-level=high threshold as the release workflow so local == CI.
dependency-audit:
	npm --prefix ui audit --omit=dev --audit-level=high
	$(UVX) pip-audit==2.10.1 --no-deps --disable-pip -r scanner/requirements.lock

## Install from this exact checkout into an empty temporary home without starting services.
installer-smoke:
	scripts/installer_smoke.sh
	scripts/installer_channel_smoke.sh

## Start the exact curl-installed release stack and verify user-visible contracts.
installed-stack-smoke:
	scripts/installed_stack_smoke.sh

## Exercise current migrations twice over clean and duplicate-dirty published schemas.
upgrade-smoke:
	docker build -f scanner/Dockerfile -t shakerscan-scanner:upgrade-smoke .
	docker build --build-arg SCANNER_RUNTIME_IMAGE=shakerscan-scanner:upgrade-smoke \
		-f scanner/Dockerfile.api -t shakerscan-api:upgrade-smoke .
	docker build --build-arg SCANNER_RUNTIME_IMAGE=shakerscan-scanner:upgrade-smoke \
		-f scanner/Dockerfile.model-intake -t shakerscan-model-intake:upgrade-smoke .
	docker build -f ui/Dockerfile -t shakerscan-ui:upgrade-smoke ui
	SCANNER_IMAGE=shakerscan-scanner:upgrade-smoke \
		CANDIDATE_API_IMAGE=shakerscan-api:upgrade-smoke \
		CANDIDATE_UI_IMAGE=shakerscan-ui:upgrade-smoke \
		CANDIDATE_MODEL_INTAKE_IMAGE=shakerscan-model-intake:upgrade-smoke \
		scripts/upgrade_smoke.sh

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

e2e-hunt:
	$(PY) tests/e2e/run_e2e.py --area hunt

e2e-platform:
	$(PY) tests/e2e/run_e2e.py --area platform

## Real local/outbound-broker/parallel semantic parity. Requires a ready Linux broker node.
e2e-scan-parity:
	$(PY) tests/e2e/run_scan_parity.py $(SCAN_PARITY_ARGS)

## Run every external adapter from the exact worker image against a counting target.
e2e-wire:
	$(PY) tests/e2e/run_external_wire_acceptance.py $(WIRE_ACCEPT_ARGS)

## Prove the API is a thin derivative of the exact scanner runtime image.
e2e-api-overlay:
	bash scripts/docker_api_overlay_smoke.sh

## Physical fleet gate. Example:
## make fleet-acceptance FLEET_ACCEPT_ARGS='--api-url https://scanner.example --public-host scanner.example --target https://lab.example --authorized'
fleet-acceptance:
	$(PY) scripts/fleet_acceptance.py $(FLEET_ACCEPT_ARGS)

## Fast unit tests (pure logic) — run inside the api container, which has the runtime
## deps (asyncpg/fastapi/...). pytest ships in the image; we install it on the fly only
## when running against an older image that predates it. The host can't run these (no
## asyncpg), so they intentionally run in-container.
UNIT_TESTS = tests/test_deployment_gate.py tests/test_canonical_dedupe.py \
	tests/test_api_id_validation.py \
	tests/test_evidence_objects.py tests/test_worker_freshness.py \
	tests/test_agent_receipt_verification.py tests/test_application_graph.py \
	tests/test_runtime_hardening.py
FOUNDATION_PACKAGE_TESTS = tests/test_http_archive.py \
	tests/test_hunt_authority_integrity.py tests/test_hunt_direct_origin.py \
	tests/test_hunt_http_capability.py tests/test_hunt_run_router.py \
	tests/test_hunt_skills.py tests/test_runtime_credentials.py \
	tests/test_scan_credentials.py tests/test_scan_finalizer.py \
	tests/test_scan_risk_and_assurance.py
test:
	@docker compose exec -T api sh -lc '\
		command -v pytest >/dev/null 2>&1 || pip install -q pytest >/dev/null 2>&1; \
		cd /workspace; \
		PYTHONPATH=/workspace/api:/workspace/scanner:/workspace python -m pytest -q -p no:cacheprovider $(UNIT_TESTS); \
		PYTHONPATH=/workspace:/workspace/api:/workspace/scanner python -m pytest -q -p no:cacheprovider $(FOUNDATION_PACKAGE_TESTS)'

## Run the named roadmap release gates. Use GATES='test:planner-no-shell ...'
## to run a subset.
release-gates:
	$(PY) scripts/release_gates.py $(GATES)
