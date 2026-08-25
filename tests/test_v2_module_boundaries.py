"""Static gates for the V2 product/module ownership boundaries."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _source(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _reject_monolith_imports(relative: str) -> None:
    source = _source(relative)
    assert "from api import" not in source
    assert "import api\n" not in source
    assert "from worker import" not in source
    assert "import worker\n" not in source


def test_api_routers_own_real_endpoint_behavior_without_monolith_imports():
    credential = _source("api/credential_api.py")
    collection = _source("api/request_collection_api.py")
    scan = _source("api/scan/read_router.py")
    primary = _source("api/api.py")

    for relative in (
        "api/credential_api.py",
        "api/request_collection_api.py",
        "api/scan/read_router.py",
    ):
        _reject_monolith_imports(relative)

    assert "PostgresCredentialProfileStore" in credential
    assert "INSERT INTO request_collections" in collection
    assert "PostgresScanActionStore" in scan
    assert "app.include_router(credential_router)" in primary
    assert "app.include_router(request_collection_router)" in primary
    assert "app.include_router(scan_read_router)" in primary
    assert '@app.post("/request-collections")' not in primary
    assert '@app.get("/scans/{scan_id}/actions")' not in primary


def test_product_services_are_concrete_and_independent_of_api_monolith():
    contracts = {
        "api/scan/worker_action_executor.py": (
            "class ReceiptScanActionExecutor",
            "async def execute",
        ),
        "api/hunt/action_dispatcher.py": (
            "class HuntActionDispatcher",
            "async def execute",
        ),
        "api/model_intake_control_plane.py": (
            "def freeze_evidence_manifest",
            "def issue_admission_v2",
        ),
        "api/fleet.py": (
            "async def enroll_node",
            "async def record_heartbeat",
        ),
    }
    for relative, required in contracts.items():
        source = _source(relative)
        _reject_monolith_imports(relative)
        for symbol in required:
            assert symbol in source


def test_worker_product_handlers_own_behavior_without_worker_wrappers():
    non_dast = _source("api/worker_handlers/non_dast.py")
    worker = _source("api/worker.py")

    _reject_monolith_imports("api/worker_handlers/non_dast.py")
    assert "run_device_posture_scan" in non_dast
    assert "run_model_intake_scan" in non_dast
    assert "run_ai_target_scan" in non_dast
    assert "async def run_scan(" not in worker
    assert "run_scan = _NON_DAST_WORKER_HANDLER.run" in worker


def test_parallel_parent_uses_canonical_compiler_service():
    parallel = _source("api/parallel_scan.py")
    compiler = _source("api/scan/parallel_compiler.py")
    worker = _source("api/worker.py")

    assert "class ParallelActionPartition" in compiler
    assert "ParallelActionPlanCompiler().compile(" in worker
    assert "validate_parallel_partition_record(" in worker
    assert "scan_type" not in parallel
    assert "ACTIVE_SCAN_TYPES" not in parallel
