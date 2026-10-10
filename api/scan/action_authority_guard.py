"""Re-check a running Scan's authorization before and during every local action.

Hunt re-checks each dispatch (``_revalidate_hunt_action_authority``) and the broker each
action lease (``_revalidate_broker_action_authority``). The local canonical path ran its whole
action graph on the authority it was admitted with, so revoking a target's authorization did
not stop an anonymous scan already running on the single host. This guard gives the local path
the same decision, from the same function:

* before an action is dispatched, a full re-check (``scan_action_authority_reason``), which is
  fail-closed: an error is retried briefly and then blocks the action as
  ``authorization_unverified``;
* while it runs, a cheap poll every ``poll_seconds``: one round trip that reads the rows the
  decision depends on, by primary key. When any of them changed, the approval reached its
  expiry, or ``full_recheck_seconds`` passed, the full check runs again. A poll that fails is
  reported to the caller, which interrupts the action as ``authorization_unverified`` (never as
  a revoke) once ``unverified_after_seconds`` pass without a successful confirmation. The
  caller bounds each check as a whole (acquisition, queries, full check) by that deadline and
  cancels one that is still pending, so a hung database cannot hold the interruption back;
* once authority is withdrawn the guard stays withdrawn for the rest of the Scan: every later
  action is blocked without traffic and the report says why (``annotate``).

Reasons are enum values only; no database text reaches a receipt or a log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Callable, Mapping
import uuid

from .authorization import ActionAuthorityDecision, revalidate_scan_action_authority
from .capability_result import CapabilityResultReason


AUTHORIZATION_WITHDRAWN = "authorization_withdrawn"
EXEMPT_ACTIONS = frozenset({"finalize.report"})

_REASONS: Mapping[ActionAuthorityDecision, CapabilityResultReason] = {
    ActionAuthorityDecision.REJECTED_EXPIRED: CapabilityResultReason.AUTHORIZATION_EXPIRED,
    ActionAuthorityDecision.REJECTED_REVOKED: CapabilityResultReason.AUTHORIZATION_REVOKED,
    ActionAuthorityDecision.REJECTED_MISSING: CapabilityResultReason.AUTHORIZATION_REVOKED,
    ActionAuthorityDecision.REJECTED_MISMATCH: CapabilityResultReason.AUTHORIZATION_REVOKED,
    ActionAuthorityDecision.REJECTED_SCOPE: CapabilityResultReason.SCOPE_INVALID,
    ActionAuthorityDecision.REJECTED_CAPABILITY: CapabilityResultReason.SCOPE_INVALID,
}
_EVENTS: Mapping[ActionAuthorityDecision, str] = {
    ActionAuthorityDecision.REJECTED_REVOKED: "approval_revocation",
    ActionAuthorityDecision.REJECTED_SCOPE: "target_transport_block",
}

# Everything the decision reads that a person can change while a Scan runs, in one statement
# of primary-key lookups. Scope receipts are immutable and are not polled.
_FINGERPRINT_SQL = """
SELECT (SELECT row(a.status, a.revoked_at, a.expires_at, a.approved_by, a.denial_reason,
                   a.action_context->>'derived_from_approval_receipt_id')::text
          FROM approval_receipts a WHERE a.id = $1) AS approval,
       (SELECT a.expires_at FROM approval_receipts a WHERE a.id = $1) AS expires_at,
       (SELECT row(s.status)::text FROM approval_receipts s
          WHERE s.id = (SELECT CASE WHEN (a.action_context->>'derived_from_approval_receipt_id')
                                         ~* '^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$'
                                    THEN (a.action_context->>'derived_from_approval_receipt_id')::uuid
                               END
                          FROM approval_receipts a WHERE a.id = $1)) AS alias_source,
       (SELECT row(t.is_active, t.url, t.authorization_inheritance, t.asset_owner_id)::text
          FROM targets t WHERE t.id = $2) AS target,
       (SELECT row(d.is_active, d.primary_locator)::text
          FROM device_targets d WHERE d.id = $2) AS device,
       (SELECT row(i.is_active, i.endpoint_url)::text
          FROM ai_targets i WHERE i.id = $2) AS ai_target,
       (SELECT row(o.is_active, o.url)::text FROM targets o WHERE o.id = $3) AS authority_owner
"""


async def scan_action_authority_reason(
    conn: Any,
    *,
    action: Any,
    target_binding: Any,
    scope_receipt_id: str | None,
    approval_receipt_id: str | None,
) -> tuple[str | None, ActionAuthorityDecision | None]:
    """``(None, None)`` when allowed, else ``(CapabilityResultReason value, decision)``.

    The target (a web target, a connected device or an AI target) must still be active, as the
    broker requires at ``fleet_routes/router.py`` (``_revalidate_broker_action_authority``), and
    the receipts must pass
    ``revalidate_scan_action_authority`` exactly as they do for Hunt and broker actions.
    """
    target_id = _uuid(getattr(target_binding, "target_id", None))
    active = None
    if target_id is not None:
        active = await conn.fetchval("SELECT is_active FROM targets WHERE id=$1", target_id)
        if active is None:
            active = await conn.fetchval("SELECT is_active FROM device_targets WHERE id=$1", target_id)
        if active is None:
            active = await conn.fetchval("SELECT is_active FROM ai_targets WHERE id=$1", target_id)
    if active is not True:
        return CapabilityResultReason.SCOPE_INVALID.value, ActionAuthorityDecision.REJECTED_SCOPE
    decision = await revalidate_scan_action_authority(
        conn,
        action=action,
        target_binding=target_binding,
        scope_receipt_id=scope_receipt_id,
        approval_receipt_id=approval_receipt_id,
    )
    if decision is ActionAuthorityDecision.ALLOWED:
        return None, None
    return _REASONS[decision].value, decision


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ScanAuthorityGuard:
    """Per-Scan authority state shared by every round's executor."""

    pool: Any
    target_binding: Any
    scope_receipt_id: str | None
    approval_receipt_id: str | None
    record_event: Callable[[str], Any] | None = None
    poll_seconds: float = 2.0
    full_recheck_seconds: float = 30.0
    # How long a running action may go without a successful confirmation (database
    # unreachable or not answering) before it is interrupted as authorization_unverified; also
    # the bound on a pre-dispatch check and its retries before it fails closed. Read by
    # ReceiptScanActionExecutor.
    unverified_after_seconds: float = 10.0
    check_retry_delays: tuple[float, ...] = (0.5, 1.0, 2.0)
    reason: str | None = None
    withdrawn_at: str | None = None
    interrupted_actions: list[str] = field(default_factory=list)
    blocked_actions: list[str] = field(default_factory=list)
    full_checks: int = 0
    polls: int = 0
    _fingerprint: tuple[Any, ...] | None = None
    _last_full: float = 0.0
    _scope_owner: uuid.UUID | None = None

    @classmethod
    def for_scan(cls, pool: Any, *, target_binding: Any, policy: Any, **kwargs: Any) -> "ScanAuthorityGuard":
        return cls(
            pool=pool,
            target_binding=target_binding,
            scope_receipt_id=(
                getattr(target_binding, "scope_receipt_id", None)
                or getattr(policy, "scope_receipt_id", None)
            ),
            approval_receipt_id=getattr(policy, "approval_receipt_id", None),
            **kwargs,
        )

    @property
    def withdrawn(self) -> bool:
        return self.reason is not None

    async def check(self, action: Any) -> str | None:
        """Full fail-closed check immediately before dispatch; raises on a database error."""
        if action.action_id in EXEMPT_ACTIONS:
            return None
        if self.reason is None:
            async with self.pool.acquire() as conn:
                await self._full(conn, action)
        if self.reason is not None:
            self.blocked_actions.append(action.action_id)
        return self.reason

    async def poll(self, action: Any) -> str | None:
        """Cheap in-flight check; raises on a database error so the caller can count failures."""
        if self.reason is not None:
            return self.reason
        self.polls += 1
        async with self.pool.acquire() as conn:
            fingerprint, expires_at = await self._read_fingerprint(conn)
            due = (
                time.monotonic() - self._last_full >= self.full_recheck_seconds
                or (expires_at is not None and expires_at <= _now())
            )
            if due or fingerprint != self._fingerprint:
                await self._full(conn, action)
        if self.reason is not None:
            self.interrupted_actions.append(action.action_id)
        return self.reason

    async def _read_fingerprint(self, conn: Any) -> tuple[tuple[Any, ...], datetime | None]:
        row = await conn.fetchrow(
            _FINGERPRINT_SQL,
            _uuid(self.approval_receipt_id),
            _uuid(getattr(self.target_binding, "target_id", None)),
            self._scope_owner,
        )
        values = dict(row) if row is not None else {}
        expires_at = values.pop("expires_at", None)
        if isinstance(expires_at, datetime) and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return tuple(sorted(values.items())), expires_at

    async def _full(self, conn: Any, action: Any) -> None:
        if self._scope_owner is None and self.scope_receipt_id:
            self._scope_owner = _uuid(await conn.fetchval(
                "SELECT target_id FROM scope_receipts WHERE id=$1", str(self.scope_receipt_id),
            ))
        fingerprint, _expires_at = await self._read_fingerprint(conn)
        reason, decision = await scan_action_authority_reason(
            conn,
            action=action,
            target_binding=self.target_binding,
            scope_receipt_id=self.scope_receipt_id,
            approval_receipt_id=self.approval_receipt_id,
        )
        self.full_checks += 1
        self._last_full = time.monotonic()
        if reason is None:
            self._fingerprint = fingerprint
            return
        self.reason, self.withdrawn_at = reason, _now().isoformat()
        event = _EVENTS.get(decision) if decision is not None else None
        if event and self.record_event is not None:
            try:
                self.record_event(event)
            except Exception:  # an observability sink never changes the decision
                pass

    async def annotate(self, report: dict[str, Any], *, scan_id: str, interrupted: str | None = None,
                       interrupted_action: str | None = None) -> dict[str, Any]:
        """Record on the Scan report that it stopped because authorization was withdrawn.

        ``not_run_actions`` is every action the Scan did not run after the stop: those this
        guard refused and those blocked because a refused action was their prerequisite.
        Findings recorded before the stop are kept; the report is partial, never complete.

        A Scan that runs as one piece of work (``running_scan_authority``) also passes the
        reason it was stopped for as ``interrupted``: when the guard is not withdrawn that is
        ``authorization_unverified``, and the report names that stop instead, never a revoke.
        """
        reason = self.reason or interrupted
        if reason is None:
            return report
        stop_reason = AUTHORIZATION_WITHDRAWN if self.reason is not None else reason
        rows: list[Any] = []
        if self.reason is not None:
            # An unverified stop is reported without another query: the database has just
            # failed to answer, and only a withdrawal blocks later actions.
            async with self.pool.acquire() as conn:
                rows = await conn.fetch(
                    """SELECT action_id FROM scan_capability_actions
                        WHERE scan_id=$1 AND status='blocked' AND reason_code = ANY($2::text[])
                        ORDER BY ordinal, action_id""",
                    uuid.UUID(str(scan_id)),
                    [*sorted({item.value for item in _REASONS.values()}),
                     CapabilityResultReason.DEPENDENCY_FAILED.value],
                )
        not_run = list(dict.fromkeys([*self.blocked_actions, *(str(row["action_id"]) for row in rows)]))
        interrupted_actions = [*self.interrupted_actions, *([interrupted_action] if interrupted_action else [])]
        stop = {
            "stop_reason": stop_reason,
            "reason_code": reason,
            "observed_at": self.withdrawn_at or _now().isoformat(),
            "interrupted_actions": list(dict.fromkeys(interrupted_actions)),
            "not_run_actions": not_run,
        }
        coverage = report.get("coverage") if isinstance(report.get("coverage"), dict) else {}
        reasons = [str(item) for item in coverage.get("reasons") or () if str(item).strip()]
        status = str(coverage.get("status") or "").strip().lower()
        # Never a complete clean scan: a scan that claimed completeness becomes partial; a
        # worse status (failed, cancelled) is kept.
        status = "partial" if status in {"", "complete", "completed"} else status
        report["coverage"] = {
            **coverage,
            "status": status,
            "reasons": [*reasons, *([] if stop_reason in reasons else [stop_reason])],
        }
        metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
        reliability = [str(item) for item in metadata.get("grade_reliability_reasons") or () if str(item).strip()]
        report["scan_metadata"] = {
            **metadata,
            # The same projection the finalizer writes, kept consistent with the coverage.
            "status": status,
            "partial": status == "partial",
            "grade_reliable": False,
            "grade_reliability_reasons": [*reliability, *([] if stop_reason in reliability
                                                          else [stop_reason])],
            "stop_reason": stop_reason,
            "authority_stop": stop,
        }
        return report
