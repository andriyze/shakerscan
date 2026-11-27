"""Scan fixtures in the installed-runtime import layout (``scan.*``, ``runtime.*``).

Tests in that layout import these instead of the ``api.*``-layout helpers, so a single pytest
session can run both layouts in any order.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import uuid

from runtime.models import ScanPolicy, TargetBinding
from runtime.observation_manifests import ObservationManifest
from runtime.receipts import CapabilityReceipt
from scan.action_plan import ScanActionPlan
from scan.capability_result import (
    CapabilityReceiptReference,
    CapabilityResultReference,
    CapabilityResultStatus,
)
from scan.contracts import BUDGET_PROFILES
from scan.execution import ScanExecutionPlan

from tests.test_scan_action_adapter import TARGET, _action

SCAN_ID = "30000000-0000-4000-8000-000000000001"
WORKER_ID = "broker:worker-1"  # the worker of tests.test_scan_action_adapter._lease


def plan(*actions) -> ScanActionPlan:
    return ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                          target_binding_digest=TARGET.digest, actions=tuple(actions))


def baseline_plan() -> ScanActionPlan:
    first = _action("baseline.http", "http.request", 0)
    return plan(first, _action("finalize.report", "scan.finalize", 1, dependencies=(first.action_id,)))


def receipt(action, *, status="success", errors=(), observations=None, timed_out=False,
            scan_id=SCAN_ID) -> CapabilityReceipt:
    now = datetime.now(timezone.utc).isoformat()
    return CapabilityReceipt(
        capability_name=action.capability_name,
        adapter_name=str(action.placement["adapter_name"]),
        adapter_version=str(action.placement["adapter_version"]),
        target_id=TARGET.target_id, scan_id=scan_id, worker_id=WORKER_ID,
        status=status, input_digest=action.action_digest, parser_version="1",
        started_at=now, finished_at=now, budget_reserved=action.requested_budget,
        budget_consumed={name: min(1, int(amount)) for name, amount in action.requested_budget.items()},
        partial=status in {"partial", "timed_out"} or timed_out, timed_out=timed_out,
        errors=tuple(errors),
        observations=tuple(observations or ({"kind": "http_response", "status_code": 200},)),
    )


def result_with_observations(action, count: int) -> CapabilityResultReference:
    content = b"{}\n" * count
    manifest = ObservationManifest(
        manifest_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"toplevel:{action.action_id}:{count}")),
        owner_id=SCAN_ID, action_id=action.action_id, capability_name=action.capability_name,
        output_schema=action.output_schema, observation_count=count,
        content_sha256=hashlib.sha256(content).hexdigest(), size_bytes=len(content),
        object_key=f"scans/{SCAN_ID}/{action.action_id}.jsonl",
    ).reference()
    return CapabilityResultReference(
        action_id=action.action_id, action_digest=action.action_digest,
        capability_name=action.capability_name,
        adapter_name=str(action.placement["adapter_name"]),
        adapter_version=str(action.placement["adapter_version"]),
        output_schema=action.output_schema, status=CapabilityResultStatus.SUCCESS,
        partial=False, timed_out=False, reason_code=None,
        receipt_ref=CapabilityReceiptReference(
            receipt_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"receipt:{action.action_id}")),
            receipt_hash=hashlib.sha256(action.action_id.encode()).hexdigest(),
        ),
        observation_manifest_ref=manifest, budget_reserved=action.requested_budget,
        budget_consumed={name: 0 for name in action.requested_budget},
    )


def compiler_target() -> TargetBinding:
    return TargetBinding(
        target_id="10000000-0000-0000-0000-000000000002", target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test", "http://app.example.test"),
        allowed_addresses=("192.0.2.10",), allowed_root_domains=("example.test",),
        scope_receipt_id="10000000-0000-0000-0000-000000000003",
    )


def execution(*, include=(), active=True) -> ScanExecutionPlan:
    return ScanExecutionPlan(
        policy=ScanPolicy(
            active_testing=active, include_families=tuple(include),
            scope_receipt_id=compiler_target().scope_receipt_id,
            approval_receipt_id="10000000-0000-0000-0000-000000000004" if active else None,
        ),
        budget_profile="balanced", budget=BUDGET_PROFILES["balanced"],
    )
