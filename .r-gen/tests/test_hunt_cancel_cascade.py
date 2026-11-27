"""Cancelling a Hunt must stop the scans it queued, not just its own status row.

`HuntRunService.cancel` flipped `hunt_runs.status` and nothing else. That stopped the Hunt from
admitting new actions, but every scan it had already queued -- a device inventory sweep, its web
children -- kept running against the target. Actions still in flight learn of the cancellation
through HuntCancellationWatch; queued scans have to be cancelled where they live.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.api_sources import definition_source


SERVICE = Path("api/hunt/run_service.py")


def _cancel_source() -> str:
    # ``cancel`` composes helpers it shares with the startup authority repair (which cancels a
    # Hunt it cannot rebuild the same way); read them in the order cancel runs them.
    assert "cancel_hunt_rows(" in definition_source("cancel")
    assert "cancel_hunt_scans(" in definition_source("cancel")
    return "\n".join(definition_source(name) for name in (
        "cancel_hunt_rows", "cancel", "cancel_hunt_scans", "request_hunt_job_cancellation", "signal_hunt_jobs",
    ))


def test_cancel_targets_scans_owned_by_this_hunt():
    source = _cancel_source()
    # The correlation the device queue writes onto its downstream scan options.
    assert "options->'hunt_dispatch'->>'hunt_id'" in source
    assert "status IN ('pending','queued','running')" in source


def test_cancel_mirrors_the_device_cancelling_state():
    # Device traffic must not be marked terminal while a worker still has a live process group;
    # cancel_scan uses 'cancelling' for exactly this and the cascade has to agree.
    source = _cancel_source()
    assert "'cancelling'" in source
    assert "run_kind IN ('device_posture','device_probe')" in source
    # A device row held in 'cancelling' must not be given a completion timestamp yet.
    assert re.search(r"completed_at = CASE\s+WHEN run_kind IN \('device_posture','device_probe'\)"
                     r" AND status='running'\s+THEN NULL", source)


def test_cancel_fans_out_to_child_shards():
    source = _cancel_source()
    assert "parent_scan_id = ANY(" in source


def test_cancel_reports_what_it_stopped():
    # Silent cascade is untrustworthy: the caller must be able to see which scans were stopped.
    source = _cancel_source()
    assert 'payload["cancelled_scan_ids"] = cancelled_ids' in source


def test_cancelling_an_already_terminal_hunt_does_not_cascade():
    # The UPDATE ... RETURNING only matches a live hunt; a second cancel must not re-cancel scans
    # that some other path has since legitimately restarted or completed.
    rows = definition_source("cancel_hunt_rows")
    assert "status IN ('created','active','awaiting_planner','budget_exhausted')" in rows
    assert "AND completed_at IS NULL" in rows
    # Within cancel itself: the live-row update runs first, a finished (not cancelled) Hunt is
    # refused with 409 before the cascade, and a repeated cancel of a cancelled Hunt skips the
    # cascade branch entirely. Positions are read from cancel's own source, not from a join.
    cancel = definition_source("cancel")
    live_guard = cancel.index("cancel_hunt_rows(")
    early_refusal = cancel.index("cannot be cancelled")
    cascade = cancel.index("cancel_hunt_scans(")
    assert live_guard < early_refusal < cascade
    assert cancel.index("if not row:") < early_refusal < cancel.index("else:", early_refusal) < cascade


def test_the_shared_cancellation_helpers_keep_their_own_order():
    # cancel_hunt_rows: the live-row update, then the withheld private results, then the
    # permission requests, all in the caller's transaction.
    rows = definition_source("cancel_hunt_rows")
    update = rows.index("UPDATE hunt_runs SET status='cancelled'")
    assert update < rows.index("private_http_result=NULL") < rows.index("settle_for_ended_hunt(")
    assert rows.index("if row:") < rows.index("private_http_result=NULL")
    # cancel_hunt_scans: the Hunt's own scans, then the shards of those it cancelled.
    scans = definition_source("cancel_hunt_scans")
    assert scans.index("options->'hunt_dispatch'->>'hunt_id'") < scans.index("parent_scan_id = ANY(")
    assert scans.index("if cancelled_ids:") < scans.index("parent_scan_id = ANY(")
    # signal_hunt_jobs: Redis first, then only the durable jobs it reached are marked signalled.
    signal = definition_source("signal_hunt_jobs")
    assert signal.index("signal_cancelled_jobs(") < signal.index("signal_state='signalled'")
    # cancel uses them in that order: rows, scans, durable job requests, then the signal.
    cancel = definition_source("cancel")
    assert (cancel.index("cancel_hunt_rows(") < cancel.index("cancel_hunt_scans(")
            < cancel.index("request_hunt_job_cancellation(") < cancel.index("signal_hunt_jobs("))


def test_reservations_are_left_to_settle_and_that_choice_is_recorded():
    # Force-releasing a hold whose action is still running would let the next action spend budget
    # that is already committed. Keep the reasoning next to the code that relies on it.
    source = _cancel_source()
    assert "Reservations are" in source and "deliberately left to settle" in source
