"""Opt-in scheduled Scan dispatch through an operator-configured admission gateway."""

from __future__ import annotations

import os
from datetime import datetime, timezone

from . import managed_occurrences as occurrences
from . import managed_options, managed_recovery
from . import router as schedule_ops
from .managed_dispatch import ManagedScheduleDispatcher


def configured_dispatcher():
    origin = os.environ.get("SHAKERSCAN_SCHEDULE_DISPATCH_ORIGIN", "")
    token = os.environ.get("SHAKERSCAN_SCHEDULE_DISPATCH_TOKEN", "")
    if not origin and not token:
        return None
    # Partial configuration is an error, never permission for local execution.
    if not origin or not token:
        raise ValueError("Managed schedule dispatch configuration is incomplete")
    return ManagedScheduleDispatcher(origin, token)


def scan_payload(schedule):
    kind = schedule_ops._schedule_kind_from_row(schedule)
    if kind != "normal_scan":
        raise ValueError(
            "Managed scheduled action requires its own admission integration"
        )
    options = schedule_ops._schedule_options_dict(schedule["scan_options"])
    return managed_options.validate(options, target=str(schedule["target_url"]))


async def run_due(pool, *, dispatcher=None, now=None):
    """Return False only when managed mode is completely unconfigured.

    Once configured, no unsupported, denied or uncertain action falls through
    to standalone enqueue. Public validation and gateway admission both apply.
    """
    dispatcher = dispatcher or configured_dispatcher()
    if dispatcher is None:
        return False
    now = now or datetime.now(timezone.utc)
    await occurrences.initialize(pool)
    await managed_recovery.reconcile(pool, dispatcher, now)
    for schedule in await occurrences.fetch_dispatchable(pool, now=now):
        try:
            occurrence = await occurrences.claim(
                pool,
                schedule["id"],
                dispatcher.origin,
                scan_payload,
                now=now,
            )
            if occurrence is None:
                continue
            outcome = None
            if not occurrence["new_occurrence"]:
                outcome = await dispatcher.lookup(str(schedule["id"]), str(occurrence["id"]))
            if outcome is None or outcome.code == "receipt_missing":
                outcome = await dispatcher.dispatch(
                    str(schedule["id"]),
                    str(occurrence["id"]),
                    occurrence["payload"],
                )
            next_run = None
            current_schedule = occurrence.get("schedule", schedule)
            if outcome.state != "retry":
                next_run = schedule_ops.schedule_next_run_at(current_schedule)
                if next_run.tzinfo is None:
                    next_run = next_run.replace(tzinfo=timezone.utc)
            await occurrences.settle(
                pool,
                occurrence["id"],
                occurrence["lease_id"],
                state=outcome.state,
                next_run_at=next_run,
                scan_id=outcome.scan_id,
                expected_updated_at=current_schedule.get("updated_at"),
            )
        except ValueError:
            # No payload/exception logging: future extensions may carry secrets.
            # Keep unsupported intent intact and do not enqueue locally.
            print("[scheduler] Managed schedule requires operator review", flush=True)
    return True
