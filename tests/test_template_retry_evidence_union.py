"""A retried passive-pack endpoint keeps every match either attempt reported (audit S001).

A passive attempt the wall cut off is retried with the whole pack (soak N32). The batch then
dropped every record of the cut-off first attempt except its bookkeeping, on the assumption
that the retry reproduced them -- which nothing checked. A first attempt that matched A followed
by a retry that matched B lost A; a retry that finished with no match lost everything. The
filtered list is what the action receipt, the observation manifest and the finalizer read.

These tests run the real batch adapter and feed its receipt to the real finalizer. Unit fixture:
the nuclei process is replaced by scripted CapabilityAdapterResults.
"""

from __future__ import annotations

import hashlib
import uuid

from hunt.capability_executor import CapabilityAdapterResult
from runtime.observation_manifests import ObservationManifest
from scan.action_plan import ScanActionPlan
from scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReason,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.finalizer import finalize_scan_report
from tests.test_scan_action_adapter import _action
from tests.test_template_batch_empty_timeout_retry import _run

HOST = "https://app.example.test"


def _match(path, template, *, matcher=None, sha=None):
    return {
        "kind": "template_match", "template_id": template, "severity": "low",
        "name": template, "matched_at": f"{HOST}{path}",
        **({"matcher_name": matcher} if matcher else {}),
        **({"response_sha256": sha} if sha else {}),
    }


def _attempt(granted, matches, *, cut_off):
    wall = int(granted["tool_wall_seconds"])
    return CapabilityAdapterResult(
        status="partial" if cut_off else "success",
        timed_out=cut_off, partial=cut_off, errors=("timeout",) if cut_off else (),
        observations=tuple(matches),
        actual_budget={"http_requests": 1, "tool_wall_seconds": wall if cut_off else min(2, wall)},
        execution_started=True, parser_version="nuclei-jsonl/v1",
    )


def _batch(monkeypatch, first, retry):
    """``/slow`` is cut off on its first attempt with ``first`` and retried with ``retry``."""
    def outcome(path, call, granted):
        if path == "/slow":
            return _attempt(granted, first if call == 1 else retry, cut_off=call == 1)
        return _attempt(granted, (), cut_off=False)

    receipt, calls, _backend, (plan, action, _dispatcher) = _run(monkeypatch, outcome)
    assert [path for path, _ in calls].count("/slow") == 2, "the cut-off endpoint is retried"
    return receipt, plan, action


def _findings(receipt, plan, action):
    """The finalizer's findings for the batch, exactly as a Scan report would carry them."""
    final = _action("finalize.report", "scan.finalize", 1, dependencies=(action.action_id,))
    report_plan = ScanActionPlan(
        scan_id=plan.scan_id, execution_plan_digest=plan.execution_plan_digest,
        target_binding_digest=plan.target_binding_digest, actions=(action, final),
    )
    batch = report_plan.actions[0]
    rows = tuple(dict(item) for item in receipt.observations)
    status = CapabilityResultStatus(receipt.status)
    result = CapabilityResultReference(
        action_id=batch.action_id, action_digest=batch.action_digest,
        capability_name=batch.capability_name,
        adapter_name=str(batch.placement["adapter_name"]),
        adapter_version=str(batch.placement["adapter_version"]),
        output_schema=batch.output_schema, status=status,
        partial=status is not CapabilityResultStatus.SUCCESS,
        timed_out=status is CapabilityResultStatus.TIMED_OUT,
        reason_code=(
            None if status is CapabilityResultStatus.SUCCESS
            else CapabilityResultReason(receipt.errors[0])
        ),
        receipt_ref=CapabilityReceiptReference(
            receipt_id=str(uuid.uuid4()), receipt_hash=hashlib.sha256(b"receipt").hexdigest(),
        ),
        observation_manifest_ref=ObservationManifest(
            manifest_id=str(uuid.uuid4()), owner_id=plan.scan_id, action_id=batch.action_id,
            capability_name=batch.capability_name, output_schema=batch.output_schema,
            observation_count=len(rows), content_sha256="0" * 64, size_bytes=512,
            object_key="scans/x.jsonl",
        ).reference(),
        budget_reserved=dict(batch.requested_budget),
        budget_consumed={},
    )
    report = finalize_scan_report(
        plan=report_plan, target_url=HOST,
        action_results={batch.action_id: result}, observations={batch.action_id: rows},
    )
    return [item for item in report["findings"] if item.get("tool") == "nuclei"]


def _template_matches(receipt):
    return [item for item in receipt.observations if item.get("kind") == "template_match"]


def test_a_retry_with_a_different_match_keeps_both_matches(monkeypatch):
    first = [_match("/slow", "exposed-panel", sha="a" * 64)]
    retry = [_match("/slow", "tech-detect", matcher="nginx")]

    receipt, plan, action = _batch(monkeypatch, first, retry)

    matches = {item["template_id"]: item for item in _template_matches(receipt)}
    assert set(matches) == {"exposed-panel", "tech-detect"}
    # The first attempt's match keeps its attempt, its evidence hash and its proof level, and
    # says the retry did not reproduce it.
    kept = matches["exposed-panel"]
    assert kept["retry_reproduced"] is False
    assert kept["response_sha256"] == "a" * 64
    assert kept["attempt_id"] != matches["tech-detect"]["attempt_id"]
    assert kept["retry_attempt_id"] == matches["tech-detect"]["attempt_id"]
    assert "proof_state" not in kept or kept["proof_state"] == "candidate"
    # Both attempts stay on the receipt.
    assert sum(1 for item in receipt.observations if item.get("kind") == "candidate_attempt") == 4

    findings = _findings(receipt, plan, action)
    assert sorted(item["evidence"]["template_id"] for item in findings) == [
        "exposed-panel", "tech-detect",
    ]
    assert all(item["proof_state"] == "candidate" and not item["verified"] for item in findings)


def test_an_empty_successful_retry_does_not_erase_the_first_attempts_match(monkeypatch):
    first = [_match("/slow", "exposed-panel", sha="b" * 64)]

    receipt, plan, action = _batch(monkeypatch, first, [])

    matches = _template_matches(receipt)
    assert [item["template_id"] for item in matches] == ["exposed-panel"]
    assert matches[0]["retry_reproduced"] is False
    findings = _findings(receipt, plan, action)
    assert [item["evidence"]["template_id"] for item in findings] == ["exposed-panel"]
    assert findings[0]["proof_state"] == "candidate"


def test_an_identical_retry_keeps_one_record_and_one_finding(monkeypatch):
    # The same match, printed by the retry with a trailing slash and an upper-case host.
    first = [
        _match("/slow", "exposed-panel", matcher="login", sha="c" * 64),
        _match("/slow", "http-missing-security-headers", matcher="x-frame-options"),
    ]
    retry = [
        {**_match("/slow/", "exposed-panel", matcher="login"),
         "matched_at": "https://APP.example.test/slow/"},
        _match("/slow", "http-missing-security-headers", matcher="x-frame-options"),
    ]

    receipt, plan, action = _batch(monkeypatch, first, retry)

    matches = _template_matches(receipt)
    assert sorted(item["template_id"] for item in matches) == [
        "exposed-panel", "http-missing-security-headers",
    ]
    by_template = {item["template_id"]: item for item in matches}
    retry_attempt = by_template["exposed-panel"]["attempt_id"]
    first_attempt = by_template["exposed-panel"]["reproduced_from_attempt_ids"][0]
    assert first_attempt != retry_attempt
    assert by_template["exposed-panel"]["reproduced_from_evidence_sha256"] == ["c" * 64]
    assert "retry_reproduced" not in by_template["exposed-panel"]

    findings = _findings(receipt, plan, action)
    assert len(findings) == 2
    header = next(item for item in findings if item["evidence"].get("header_name"))
    # One match per response, so the origin-level header finding counts the URL once.
    assert header["evidence"]["matched_url_count"] == 1


def test_a_resumed_batch_replays_the_same_union(monkeypatch):
    first = [_match("/slow", "exposed-panel")]
    retry = [_match("/slow", "tech-detect")]

    def outcome(path, call, granted):
        if path == "/slow":
            return _attempt(granted, first if call == 1 else retry, cut_off=call == 1)
        return _attempt(granted, (), cut_off=False)

    import asyncio

    from tests.test_scan_action_adapter import _lease, _noop

    receipt, calls, _backend, (plan, action, dispatcher) = _run(monkeypatch, outcome)
    executed = len(calls)
    resumed = asyncio.run(dispatcher(action, _lease(plan, action), _noop))

    assert len(calls) == executed
    assert sorted(item["template_id"] for item in _template_matches(resumed)) == [
        "exposed-panel", "tech-detect",
    ]
    assert [dict(item) for item in resumed.observations] == [
        dict(item) for item in receipt.observations
    ]


def test_records_of_other_endpoints_are_untouched():
    from scan.action_adapter import merge_retried_template_records

    rows = [
        {"kind": "candidate_attempt", "attempt_id": "f", "candidate_id": "slow"},
        _match("/slow", "a") | {"attempt_id": "f", "candidate_id": "slow"},
        {"kind": "candidate_attempt", "attempt_id": "o", "candidate_id": "other"},
        _match("/other", "a") | {"attempt_id": "o", "candidate_id": "other"},
        {"kind": "candidate_attempt", "attempt_id": "r", "candidate_id": "slow", "retry_round": 1},
        _match("/slow", "a") | {"attempt_id": "r", "candidate_id": "slow"},
    ]
    merged = merge_retried_template_records(rows, {"slow": "f"})
    assert [(item["kind"], item["attempt_id"]) for item in merged] == [
        ("candidate_attempt", "f"), ("candidate_attempt", "o"), ("template_match", "o"),
        ("candidate_attempt", "r"), ("template_match", "r"),
    ]
    assert merged[-1]["reproduced_from_attempt_ids"] == ["f"]
    # The input rows are not mutated.
    assert "reproduced_from_attempt_ids" not in rows[-1]
    assert merge_retried_template_records(rows, {}) == rows
