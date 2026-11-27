from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json

from api.scan.authorization import (
    ActionAuthorityDecision,
    revalidate_action_authority,
)


class _DatabaseRecord:
    """Minimal asyncpg.Record-shaped authority row (not a Mapping)."""

    def __init__(self, values):
        self._values = dict(values)

    def __getitem__(self, name):
        return self._values[name]


def test_privileged_action_dispatch_requires_fresh_scope_and_approval_authority():
    decision = revalidate_action_authority(
        action={"capability_name": "web.active.xss"},
        approval_receipt={"status": "revoked"},
        target_binding={"status": "active"},
    )
    assert decision is ActionAuthorityDecision.REJECTED_REVOKED


def _authority(*, expiry_delta: timedelta = timedelta(minutes=5)):
    now = datetime(2026, 8, 23, tzinfo=timezone.utc)
    scope = {
        "id": "scope-1",
        "target_id": "target-1",
        "verdict": "needs_approval",
        "allowed_hosts": ["app.example.test"],
        "allowed_root_domains": ["example.test"],
    }
    approval = {
        "id": "10000000-0000-4000-8000-000000000001",
        "scope_receipt_id": "scope-1",
        "status": "approved",
        "approved_by": "operator",
        "confirmations": ["confirm_authorized", "confirm_scope_reviewed"],
        "expires_at": now + expiry_delta,
    }
    target = {
        "status": "active",
        "target_id": "target-1",
        "canonical_host": "app.example.test",
        "scope_receipt_id": "scope-1",
    }
    return now, scope, approval, target


def test_fresh_target_bound_approval_allows_active_canonical_action():
    now, scope, approval, target = _authority()
    assert revalidate_action_authority(
        action={"capability_name": "xss.verify"},
        target_binding=target,
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.ALLOWED


def test_database_record_authority_rows_are_read_at_runtime():
    now, scope, approval, target = _authority()

    assert revalidate_action_authority(
        action={"capability_name": "xss.verify"},
        target_binding=target,
        scope_receipt=_DatabaseRecord(scope),
        approval_receipt=_DatabaseRecord(approval),
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.ALLOWED


def test_database_json_columns_are_decoded_before_runtime_scope_checks():
    now, scope, approval, target = _authority()
    scope["allowed_hosts"] = json.dumps(scope["allowed_hosts"])
    scope["allowed_root_domains"] = json.dumps(
        scope["allowed_root_domains"]
    )
    approval["confirmations"] = json.dumps(approval["confirmations"])

    assert revalidate_action_authority(
        action={"capability_name": "xss.verify"},
        target_binding=target,
        scope_receipt=_DatabaseRecord(scope),
        approval_receipt=_DatabaseRecord(approval),
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.ALLOWED


def test_expired_approval_is_rejected_at_action_boundary():
    now, scope, approval, target = _authority(expiry_delta=timedelta(seconds=-1))
    assert revalidate_action_authority(
        action={"capability_name": "xss.verify"},
        target_binding=target,
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.REJECTED_EXPIRED


def test_scope_host_and_target_cannot_drift_after_admission():
    now, scope, approval, target = _authority()
    target["canonical_host"] = "outside.example.net"
    assert revalidate_action_authority(
        action={"capability_name": "http.request"},
        target_binding=target,
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.REJECTED_SCOPE


def test_empty_canonical_host_is_never_treated_as_in_scope():
    now, scope, approval, target = _authority()
    target["canonical_host"] = ""
    assert revalidate_action_authority(
        action={"capability_name": "http.request"},
        target_binding=target,
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.REJECTED_SCOPE


def test_unknown_capability_is_rejected_instead_of_using_name_heuristics():
    now, scope, approval, target = _authority()
    assert revalidate_action_authority(
        action={"capability_name": "future.passive-looking-capability"},
        target_binding=target,
        scope_receipt=scope,
        approval_receipt=approval,
        scope_receipt_id="scope-1",
        approval_receipt_id=approval["id"],
        now=now,
    ) is ActionAuthorityDecision.REJECTED_CAPABILITY
