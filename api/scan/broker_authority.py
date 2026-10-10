"""The control plane's re-check of broker actions running on fleet nodes.

A fleet node asks before and while each action runs (``BrokerActionAuthority``), and the control
plane also re-checks on every action heartbeat and when the result is settled, so a node that
does not ask (an older or misbehaving one) cannot keep a withdrawn action alive or settle it as
a clean success. Each running action gets one ``ScanAuthorityGuard`` per control-plane process:
its first check is the full decision, later ones the guard's cheap poll (one statement of
primary-key reads; the full check repeats only when a polled row changed, the approval reached
its expiry, or 30 s passed). A process that has not seen the action yet starts with a full check,
so the cache only saves work and never changes a decision.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from .action_authority_guard import ScanAuthorityGuard


class RunningBrokerAuthority:
    """Per-process guards for running broker actions, keyed by Scan, plan and action."""

    def __init__(self, max_entries: int = 1024) -> None:
        self._guards: OrderedDict[tuple[str, str, str], ScanAuthorityGuard] = OrderedDict()
        self._max_entries = max_entries

    async def reason(self, pool: Any, *, scan_id: str, plan_digest: str, job: Any, action: Any) -> str | None:
        """``None`` while the action is still authorized, else a ``CapabilityResultReason`` value."""
        key = (str(scan_id), str(plan_digest), str(action.action_id))
        guard = self._guards.get(key)
        if guard is None:
            policy = job.execution_plan.policy
            guard = ScanAuthorityGuard(
                pool=pool, target_binding=job.target,
                scope_receipt_id=job.target.scope_receipt_id or policy.scope_receipt_id,
                approval_receipt_id=policy.approval_receipt_id,
            )
            self._guards[key] = guard
            while len(self._guards) > self._max_entries:
                self._guards.popitem(last=False)
        self._guards.move_to_end(key)
        return await guard.poll(action)
