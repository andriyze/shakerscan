"""Every entry point of the 2.8.3 fixes goes through the fixed code (2.8.2 acceptance).

The behaviour is tested where it lives (tests/test_target_asset_startup_postgres.py,
tests/test_hunt_withheld_values_separators.py, tests/test_scan_running_authority_postgres.py).
These source guards keep every other way in routed through it:

* schema: the API process and every worker run the same unified startup, so a migration placed
  in its always-run section reaches each of them;
* device runs: a connected-device posture scan or service probe is queued only by
  ``POST /devices/{id}/scan`` and ``POST /devices/{id}/verify-service``, which bind the device's
  standing authorization. The /devices list, the device page, the device Hunt tools (agent scan,
  service verification, candidate verification) and the Hunt SSH shell dispatch all call those
  two routes rather than queueing a run of their own.
"""
from __future__ import annotations

import ast
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"


def _calls(path: Path, name: str) -> int:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id == name)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == name)
        )
    )


def test_the_api_and_the_workers_run_the_unified_startup():
    assert _calls(API / "api.py", "run_schema_migrations") >= 1
    assert _calls(API / "worker.py", "run_schema_migrations") >= 1
    source = (API / "retest_contract.py").read_text(encoding="utf-8")
    assert "run_unified_startup(pool, _run_schema_migrations_once" in source


def test_the_2_8_2_migrations_live_in_the_always_run_startup():
    source = (API / "targets" / "asset_migration.py").read_text(encoding="utf-8")
    always = source[source.index("async def run_unified_startup"):]
    always = always[always.index("if not await migration_applied(conn):"):]
    for step in (
        "ADD COLUMN IF NOT EXISTS requested_by",
        "await recompute_spanning_target_roots(conn)",
        "await repair_target_host_spellings(conn)",
    ):
        assert step in always, step


def _functions_inserting(run_kind: str) -> list[str]:
    """The functions under api/ whose SQL inserts a scan of ``run_kind``."""
    found = []
    pattern = re.compile(r"INSERT INTO scans\b.{0,1200}?'" + run_kind + r"'", re.DOTALL)
    for path in sorted(API.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "INSERT INTO scans" not in text:
            continue
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = ast.get_source_segment(text, node) or ""
                inner = [child for child in ast.walk(node)
                         if child is not node and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))]
                if inner:
                    continue  # judged at the innermost function
                if pattern.search(body):
                    found.append(f"{path.relative_to(ROOT)}:{node.name}")
    return found


def test_device_runs_are_queued_only_by_the_two_device_routes():
    assert _functions_inserting("device_posture") == ["api/devices/router.py:scan_device"]
    assert _functions_inserting("device_probe") == ["api/devices/router.py:verify_device_service"]


def test_every_device_request_is_handed_to_the_device_routes():
    """Each ``DeviceScanRequest(...)``/``DeviceServiceVerifyRequest(...)`` built in api/ is the
    argument of ``scan_device``/``verify_device_service``."""
    pairs = {"DeviceScanRequest": "scan_device", "DeviceServiceVerifyRequest": "verify_device_service"}
    seen = {name: 0 for name in pairs}
    for path in sorted(API.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "DeviceScanRequest" not in text and "DeviceServiceVerifyRequest" not in text:
            continue
        tree = ast.parse(text, filename=str(path))
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
            if name not in pairs:
                continue
            seen[name] += 1
            parent = parents.get(node)
            called = parent.func if isinstance(parent, ast.Call) else None
            route = called.id if isinstance(called, ast.Name) else called.attr if isinstance(called, ast.Attribute) else ""
            assert route == pairs[name], f"{path.relative_to(ROOT)}:{node.lineno} builds {name} for {route!r}"
    # The /devices agent scan, Hunt SSH dispatch, service verification and candidate verification.
    assert seen["DeviceScanRequest"] >= 3 and seen["DeviceServiceVerifyRequest"] >= 2


def test_both_device_routes_bind_the_standing_authorization_whatever_the_confirmation():
    source = (API / "devices" / "router.py").read_text(encoding="utf-8")
    for route in ("async def scan_device(", "async def verify_device_service("):
        body = source[source.index(route):]
        body = body[:body.index("\n@router.")]
        assert "standing = await network_authorization_snapshot(conn, device_uuid)\n" in body, route
        assert "\"asset_authorization_receipt_id\": standing['approval_receipt_id'] if standing else None" in body
