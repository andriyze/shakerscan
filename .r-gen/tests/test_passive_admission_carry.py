"""A passive Scan's continuation does not re-run the pack its admission action ran.

The required admission `passive.templates` action runs the reviewed pack over the admitted
surface (the frozen origin and admitted seeds); continuation slices run the same pack over
the discovered surface, which contains those routes again. They re-sent the pack to them,
and the finalizer counted the admission slice's scheduled entry against the discovered
manifest, so it could cancel out an unscheduled discovered route.
"""

from __future__ import annotations

import asyncio
import dataclasses
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.models import ScanPolicy
import scan.action_adapter as action_adapter_module
from scan.action_plan import ScanActionPlan
from scan.work_manifests import (
    build_canonical_passive_nuclei_template_manifest,
    build_endpoint_manifest,
)
from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop


def _surface(scan_id, paths, source):
    return build_endpoint_manifest(
        scan_id=scan_id,
        target_binding_digest=TARGET.digest,
        surface_manifest={
            "schema_version": "endpoint-manifest/v2", "status": "complete", "reason": None,
            "endpoints": [
                {
                    "method": "GET", "scheme": "https", "host": "app.example.test", "port": 443,
                    "normalized_path": path, "concrete_path": path, "query_keys": [],
                    "source": source,
                }
                for path in paths
            ],
        },
        source_action_ids=(source,),
    )


def _matched(path, granted):
    return CapabilityAdapterResult(
        status="success",
        observations=({
            "kind": "template_match", "template_id": "http-missing-security-headers",
            "severity": "info", "matched_at": f"https://app.example.test{path}",
        },),
        actual_budget={"http_requests": 1, "tool_wall_seconds": min(2, granted["tool_wall_seconds"])},
        execution_started=True, parser_version="nuclei-jsonl/v1",
    )


def _run_admission_then_continuation(monkeypatch, *, admission_status="success"):
    scan_id = str(uuid.uuid4())
    templates = build_canonical_passive_nuclei_template_manifest(
        scan_id=scan_id, target_binding_digest=TARGET.digest,
    )
    admitted = _surface(scan_id, ("/", "/seed"), "admission.surface")
    discovered = _surface(scan_id, ("/", "/seed", "/docs/a", "/docs/b"), "discover.web_crawl")
    template_ref = templates.reference().canonical_dict()
    admission = dataclasses.replace(
        _action(
            "passive.templates", "templates.passive_batch", 0,
            capability_args={
                "target_ref": "canonical_origin",
                "target_manifest_ref": admitted.reference().canonical_dict(),
                "template_manifest_ref": template_ref,
                "slice": {"start": 0, "count": 2},
            },
        ),
        requested_budget={"http_requests": 14, "tool_wall_seconds": 60},
        action_digest=None,
    )
    continuation = dataclasses.replace(
        _action(
            "passive.templates.r01", "templates.passive_batch", 1,
            capability_args={
                "target_ref": "canonical_origin",
                "target_manifest_ref": discovered.reference().canonical_dict(),
                "template_manifest_ref": template_ref,
                "slice": {"start": 0, "count": 4},
                "continuation_work_key": "passive.templates",
            },
        ),
        requested_budget={"http_requests": 21, "tool_wall_seconds": 90},
        action_digest=None,
    )
    plan = ScanActionPlan(
        scan_id=scan_id, execution_plan_digest="a" * 64,
        target_binding_digest=TARGET.digest, actions=(admission, continuation),
    )
    backend = Backend(manifests={
        admitted.manifest_id: admitted, discovered.manifest_id: discovered,
        templates.manifest_id: templates,
    })
    calls: list[str] = []

    async def execute(_self, context, adapter, **_kwargs):
        path = adapter._process_payload["execution_target"].split("app.example.test", 1)[1]
        calls.append(path)
        granted = dict(context.requested_budget)
        if admission_status != "success" and (path or "/") == "/" and calls.count(path) == 1:
            # Wall-killed after partial output: not retried, and never a verdict to carry.
            return dataclasses.replace(
                _matched(path, granted), status="partial", partial=True, timed_out=True,
                errors=("timeout",),
                actual_budget={"http_requests": 1, "tool_wall_seconds": granted["tool_wall_seconds"]},
            )
        return _matched(path, granted)

    monkeypatch.setattr(action_adapter_module.CapabilityExecutor, "execute", execute)
    dispatcher = _dispatcher(plan, backend, policy=ScanPolicy())
    first = asyncio.run(dispatcher(admission, _lease(plan, admission), _noop))
    admission_calls = list(calls)
    calls.clear()
    second = asyncio.run(dispatcher(continuation, _lease(plan, continuation), _noop))
    return first, admission_calls, second, calls


def _normalized(paths):
    return sorted(path or "/" for path in paths)


def test_a_continuation_slice_carries_the_origin_the_admission_pack_examined(monkeypatch):
    first, admission_calls, second, calls = _run_admission_then_continuation(monkeypatch)

    assert first.status == "success" and _normalized(admission_calls) == ["/", "/seed"]
    assert _normalized(calls) == ["/docs/a", "/docs/b"], "origin and seed must not be re-sent"
    assert second.status == "success"
    execution = second.redacted_execution
    assert execution["carried_from_admission"] == "passive.templates"
    assert execution["carried_count"] == 2
    assert execution["attempted_count"] == 4 and execution["unattempted_count"] == 0
    carried = [
        item for item in second.observations
        if item.get("kind") == "candidate_attempt" and item.get("carried_from")
    ]
    assert [item["carried_from"] for item in carried] == ["passive.templates"] * 2
    # The admission action keeps the finding; the carried record is bookkeeping only.
    assert not any(
        item.get("kind") == "template_match" and item.get("matched_at", "").endswith("test/")
        for item in second.observations
    )


def test_an_admission_attempt_that_never_finished_is_rerun(monkeypatch):
    _first, _admission_calls, second, calls = _run_admission_then_continuation(
        monkeypatch, admission_status="timed_out",
    )

    assert _normalized(calls) == ["/", "/docs/a", "/docs/b"], "only the unfinished origin re-runs"
    # The seed the admission pack finished is still carried.
    assert second.redacted_execution["carried_count"] == 1


# --- each worklist is measured against its own manifest -----------------------------------


def test_the_admission_slice_cannot_hide_an_unscheduled_discovered_route():
    from api.scan.capability_result import CapabilityResultStatus
    from api.scan.finalizer import finalize_scan_report
    from tests.test_scan_orchestrator import SCAN_ID, _action as _plan_action, _result

    def ref(digest, entries):
        return {
            "kind": "endpoint", "manifest_digest": digest * 64, "entry_count": entries,
            "manifest_id": str(uuid.uuid4()), "schema_version": "x", "status": "complete",
            "content_schema": "x",
        }

    baseline = _plan_action("baseline.http", 0)
    admission = dataclasses.replace(
        _plan_action("passive.templates", 1, capability_name="templates.passive_batch"),
        capability_args={
            "slice": {"start": 0, "count": 1}, "manifest_entries": 1,
            "target_manifest_ref": ref("a", 1),
        },
        action_digest=None,
    )
    # The discovered worklist holds three routes; the round scheduled only two of them.
    continuation = dataclasses.replace(
        _plan_action("passive.templates.r01", 2, capability_name="templates.passive_batch"),
        capability_args={
            "slice": {"start": 0, "count": 2}, "manifest_entries": 3,
            "target_manifest_ref": ref("b", 3), "continuation_work_key": "passive.templates",
        },
        action_digest=None,
    )
    final = _plan_action(
        "finalize.report", 3,
        dependencies=(baseline.action_id, admission.action_id, continuation.action_id),
    )
    plan = ScanActionPlan(
        scan_id=SCAN_ID, execution_plan_digest="b" * 64, target_binding_digest="a" * 64,
        actions=(baseline, admission, continuation, final),
    )
    results = {
        action.action_id: _result(action, status=CapabilityResultStatus.SUCCESS)
        for action in (baseline, admission, continuation)
    }
    report = finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results=results, observations={},
    )
    family = next(
        row for row in report["coverage"]["family_coverage"]
        if row["family"] == "nuclei_passive"
    )

    assert family["unscheduled_candidates"] == 1
    assert family["coverage_status"] == "partial"
