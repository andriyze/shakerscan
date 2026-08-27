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
    return definition_source("cancel")


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
    source = _cancel_source()
    live_guard = source.index("status IN ('created','active','awaiting_planner')")
    early_return = source.index("return public_hunt_run(row)")
    cascade = source.index("options->'hunt_dispatch'")
    assert live_guard < early_return < cascade


def test_reservations_are_left_to_settle_and_that_choice_is_recorded():
    # Force-releasing a hold whose action is still running would let the next action spend budget
    # that is already committed. Keep the reasoning next to the code that relies on it.
    source = _cancel_source()
    assert "Reservations are" in source and "deliberately left to settle" in source
