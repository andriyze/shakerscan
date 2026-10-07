"""The worker records a Scan's subdomain discovery on every path that ingests a finished report.

A local Scan records it while loading the finalized report; a fleet node finalizes the same
report but has no database, so the control plane records it when it claims the broker result.
Both bind the recording to the root domains the control plane derived for the job, never to the
report's own claim. Removing a wiring call fails a test here.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace

from api.scan import subdomain_targets
from api.runtime.models import ScanBudget, ScanPolicy, TargetBinding
from api.scan.execution import ScanExecutionPlan

ROOT = Path(__file__).resolve().parents[1]
SCAN_ID = "22222222-2222-4222-8222-222222222222"


def _report():
    return {
        "target": "https://shakerscan.com",
        "findings": [],
        "discovery": {"subdomains": {
            "root_domain": "shakerscan.com",
            "hosts": ["api.shakerscan.com"],
            "count": 1, "total": 1, "truncated": False, "source": "subfinder",
        }},
    }


class _Pool:
    def acquire(self):
        return self

    async def __aenter__(self):
        return object()

    async def __aexit__(self, *_exc):
        return False


def _spy(calls):
    async def record(pool, report, *, scan_id, allowed_root_domains=None, plan_targets=None):
        calls.append({"report": report, "scan_id": scan_id, "roots": allowed_root_domains})
        report["discovery"]["subdomains"]["targets"] = {"status": "recorded", "added": 1}
        return report["discovery"]["subdomains"]["targets"]

    return record


def test_the_finalized_report_is_recorded_before_it_is_returned(monkeypatch):
    calls = []

    class _Store:
        async def load(self, conn, *, reference, scan_id, action_id):
            assert action_id == "finalize.report" and reference == "manifest-ref"
            return [{"kind": "scan_report", "report": _report()}]

    monkeypatch.setattr(subdomain_targets, "record_scan_subdomain_discovery", _spy(calls))
    report = asyncio.run(subdomain_targets.load_recorded_scan_report(
        _Pool(), _Store(), SimpleNamespace(observation_manifest_ref="manifest-ref"),
        scan_id=SCAN_ID, root_domains=("shakerscan.com",),
    ))

    assert len(calls) == 1
    assert calls[0]["scan_id"] == SCAN_ID and calls[0]["roots"] == ("shakerscan.com",)
    # The outcome is in the report the caller persists.
    assert report["discovery"]["subdomains"]["targets"]["status"] == "recorded"


def test_an_invalid_final_report_raises_the_callers_error():
    class _Store:
        async def load(self, conn, **_kwargs):
            return [{"kind": "something_else"}]

    class ContractError(Exception):
        pass

    try:
        asyncio.run(subdomain_targets.load_recorded_scan_report(
            _Pool(), _Store(), SimpleNamespace(observation_manifest_ref="r"),
            scan_id=SCAN_ID, root_domains=(), invalid_error=ContractError,
        ))
    except ContractError as exc:
        assert "report observation is invalid" in str(exc)
    else:
        raise AssertionError("an invalid report must raise")


def test_a_broker_report_is_recorded_under_the_control_planes_binding(monkeypatch):
    calls = []
    monkeypatch.setattr(subdomain_targets, "record_scan_subdomain_discovery", _spy(calls))
    monkeypatch.setattr(subdomain_targets, "bound_root_domains", lambda options: ("shakerscan.com",))
    report = _report()
    asyncio.run(subdomain_targets.record_ingested_report_subdomains(
        _Pool(), report, scan_id=SCAN_ID, options={"scan_type": "smart"},
    ))
    assert len(calls) == 1 and calls[0]["roots"] == ("shakerscan.com",)
    assert report["discovery"]["subdomains"]["targets"]["status"] == "recorded"

    calls.clear()
    asyncio.run(subdomain_targets.record_ingested_report_subdomains(
        _Pool(), {"findings": []}, scan_id=SCAN_ID, options={},
    ))
    assert calls == []


def test_the_binding_is_derived_from_the_job_and_absent_for_an_unbindable_one():
    plan = ScanExecutionPlan(
        policy=ScanPolicy(active_testing=False, subdomain_discovery=True),
        budget_profile="balanced",
        budget=ScanBudget(1200, 5000, 2000, 200, 5000, 900, 4, 0, 100),
    )
    options = plan.option_metadata()
    options["subfinder"] = True
    options["_canonical_target_binding"] = TargetBinding(
        target_id="t1", target_kind="web", canonical_host="app.shakerscan.com",
        allowed_origins=("https://app.shakerscan.com",), allowed_addresses=("203.0.113.10",),
        allowed_root_domains=("shakerscan.com",), environment="production",
        scope_receipt_id=None,
    ).canonical_dict()
    assert subdomain_targets.bound_root_domains(options) == ("shakerscan.com",)
    # A legacy or malformed job binds nothing, which the recorder treats as "record nothing".
    assert subdomain_targets.bound_root_domains({"scan_type": "smart"}) is None
    assert subdomain_targets.bound_root_domains({}) is None


def _calls_in(function_name: str) -> list[ast.Call]:
    tree = ast.parse((ROOT / "api" / "worker.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == function_name:
            return [
                call for call in ast.walk(node)
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
            ]
    raise AssertionError(f"{function_name} not found in api/worker.py")


def test_the_local_scan_returns_the_recorded_report_under_its_own_binding():
    calls = [
        call for call in _calls_in("_execute_reserved_deterministic_scan")
        if call.func.id == "load_recorded_scan_report"
    ]
    assert len(calls) == 1
    roots = {kw.arg: ast.unparse(kw.value) for kw in calls[0].keywords}["root_domains"]
    assert roots == "execution.target_binding.allowed_root_domains"


def test_both_broker_ingest_paths_record_the_reports_subdomains():
    for function_name in ("process_scan_job", "process_scan_shard_job"):
        names = [call.func.id for call in _calls_in(function_name)]
        assert "_load_broker_result" in names, function_name
        assert "record_ingested_report_subdomains" in names, function_name
