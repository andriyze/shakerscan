from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

from api.scan.continuation import (
    ScanContinuationAllocation,
    ScanPlanRevision,
    root_scan_plan_revision,
)
from api.scan.capability_result import (
    CapabilityResultReference,
    CapabilityResultStatus,
)
from api.scan.finalizer import finalize_scan_report
from api.runtime.observation_manifests import ObservationManifest
from api.scan.report_rebuild import (
    ScanReportRebuildError,
    build_scan_report_rebuild_bundle,
    canonical_report_json,
    rebuild_scan_report,
)
from tests.test_scan_orchestrator import _plan, _result


def _bundle():
    plan = _plan()
    results = {
        action.action_id: _result(action, status=CapabilityResultStatus.SUCCESS)
        for action in plan.actions
        if action.action_id != "finalize.report"
    }
    observations = {action_id: () for action_id in results}
    report = finalize_scan_report(
        plan=plan,
        plan_revision=root_scan_plan_revision(plan),
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )
    return build_scan_report_rebuild_bundle(
        plan=plan,
        plan_revision=root_scan_plan_revision(plan),
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
        expected_report_digest=report["report_digest"],
    ), report


def test_offline_bundle_rebuilds_the_byte_stable_report():
    bundle, expected = _bundle()

    rebuilt = rebuild_scan_report(json.loads(json.dumps(bundle)))

    assert rebuilt == expected
    assert canonical_report_json(rebuilt) == canonical_report_json(expected)


def test_offline_rebuild_rejects_tampered_result_authority():
    bundle, _expected = _bundle()
    tampered = copy.deepcopy(bundle)
    first = next(iter(tampered["action_results"].values()))
    first["budget_consumed"]["http_requests"] = 99

    with pytest.raises(ScanReportRebuildError, match="evidence is invalid"):
        rebuild_scan_report(tampered)


def test_offline_rebuild_verifies_observation_content_digest():
    plan = _plan()
    action = plan.actions[0]
    base = _result(action, status=CapabilityResultStatus.SUCCESS)
    rows = ({"kind": "http_observation", "status_code": 200},)
    content = json.dumps(
        list(rows), sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")
    manifest = ObservationManifest(
        manifest_id=str(uuid.uuid4()),
        owner_id=plan.scan_id,
        action_id=action.action_id,
        capability_name=action.capability_name,
        output_schema=action.output_schema,
        observation_count=1,
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
        object_key=f"scan-observations/{uuid.uuid4()}.json",
    ).reference()
    result = CapabilityResultReference(**{
        **base.digest_material(),
        "receipt_ref": base.receipt_ref,
        "observation_manifest_ref": manifest,
    })
    other_results = {
        item.action_id: _result(item, status=CapabilityResultStatus.SUCCESS)
        for item in plan.actions[1:]
        if item.action_id != "finalize.report"
    }
    results = {action.action_id: result, **other_results}
    observations = {
        action.action_id: rows,
        **{action_id: () for action_id in other_results},
    }
    bundle = build_scan_report_rebuild_bundle(
        plan=plan,
        plan_revision=root_scan_plan_revision(plan),
        target_url="https://app.example.test",
        action_results=results,
        observations=observations,
    )
    bundle["observations"][action.action_id][0]["status_code"] = 500

    with pytest.raises(ScanReportRebuildError, match="content digest"):
        rebuild_scan_report(bundle)


def test_offline_rebuild_binds_amended_revision_to_exact_allocation():
    bundle, _expected = _bundle()
    plan = _plan()
    allocation = ScanContinuationAllocation(
        scan_id=plan.scan_id,
        parent_plan_digest="a" * 64,
        execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest,
        parent_action_ids=(plan.actions[0].action_id,),
        budget_ceiling={
            "http_requests": 1,
            "state_changing_requests": 0,
            "browser_actions": 0,
            "tcp_ports_attempted": 0,
            "hosts_attempted": 0,
            "tool_wall_seconds": 1,
        },
        max_endpoint_entries=1,
        max_candidate_entries=1,
        allowed_capabilities=(),
    )
    revision = ScanPlanRevision(
        scan_id=plan.scan_id,
        revision=1,
        plan_digest=plan.plan_digest,
        parent_plan_digest=allocation.parent_plan_digest,
        continuation_allocation_digest=allocation.allocation_digest,
        discovery_result_digest="b" * 64,
        work_manifest_references=({
            "schema_version": "scan-work-manifest-reference/v1",
            "manifest_id": "55555555-5555-4555-8555-555555555555",
            "kind": "candidate",
            "content_schema": "candidate-manifest/v1",
            "manifest_digest": "d" * 64,
            "entry_count": 1,
            "status": "complete",
        },),
        continuation_plan_digest="e" * 64,
    )
    bundle["plan_revision"] = revision.canonical_dict()
    bundle["continuation_allocation"] = allocation.canonical_dict()
    bundle["expected_report_digest"] = None

    rebuilt = rebuild_scan_report(bundle)
    assert rebuilt["canonical_action_execution"]["plan_revision"] == (
        revision.canonical_dict()
    )

    tampered = copy.deepcopy(bundle)
    tampered["continuation_allocation"]["budget_ceiling"][
        "tool_wall_seconds"
    ] = 2
    with pytest.raises(ScanReportRebuildError, match="allocation"):
        rebuild_scan_report(tampered)

    missing = copy.deepcopy(bundle)
    missing["continuation_allocation"] = None
    with pytest.raises(ScanReportRebuildError, match="requires"):
        rebuild_scan_report(missing)


def test_offline_rebuild_modules_import_no_network_clients():
    root = Path(__file__).resolve().parents[1]
    forbidden = {"aiohttp", "httpx", "requests", "socket", "urllib.request"}
    for relative in ("api/scan/finalizer.py", "api/scan/report_rebuild.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            str(node.module or "")
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            imported == item or imported.startswith(item + ".")
            for imported in imports for item in forbidden
        )


def test_offline_rebuild_command_writes_verified_report(tmp_path):
    bundle, expected = _bundle()
    bundle_path = tmp_path / "bundle.json"
    report_path = tmp_path / "report.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/rebuild_scan_report.py",
            str(bundle_path),
            "--output",
            str(report_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(report_path.read_text(encoding="utf-8")) == expected

    repeated = subprocess.run(
        [
            sys.executable,
            "scripts/rebuild_scan_report.py",
            str(bundle_path),
            "--output",
            str(report_path),
        ],
        cwd=Path(__file__).resolve().parents[1],
        check=False,
        capture_output=True,
        text=True,
    )
    assert repeated.returncode == 2
    assert "use --force" in repeated.stderr
    assert json.loads(report_path.read_text(encoding="utf-8")) == expected
