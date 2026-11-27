"""A blocked Hunt action must not refund traffic that may already have happened.

`blocked` covers two very different situations: admission refused the action before any adapter
ran, or the action executed (or queued downstream work) and then failed in a way that cannot prove
what reached the target. The settlement zeroed every non-agent dimension for both, which handed
back HTTP, port and fragility holds after real traffic -- and specifically undid
`conservative_full_budget`, the flag candidate verification sets so an uncertain failure is charged
in full rather than assumed free.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from hunt.settlement import blocked_actual_charges as _hunt_blocked_actual  # noqa: E402


CHARGES = {
    "agent_actions": 1,
    "active_actions": 1,
    "http_requests": 4_008,
    "tcp_ports_attempted": 100,
    "udp_ports_attempted": 8,
    "device_fragility_points": 1,
    "tool_wall_seconds": 180,
}


def _settle(**kwargs):
    defaults = {
        "executed": False,
        "enqueued": False,
        "device_http_attempted": False,
        "elapsed_wall": 3,
    }
    defaults.update(kwargs)
    actual = dict(kwargs.pop("actual", dict(CHARGES)))
    defaults.pop("actual", None)
    return _hunt_blocked_actual(CHARGES, actual, **defaults)


def test_admission_refusal_releases_every_execution_hold():
    # Nothing ran and nothing was queued, so the holds are genuinely unused.
    settled = _settle()
    assert settled["agent_actions"] == 1
    assert settled["active_actions"] == 1
    for dimension in ("http_requests", "tcp_ports_attempted", "udp_ports_attempted",
                      "device_fragility_points", "tool_wall_seconds"):
        assert settled[dimension] == 0, dimension


def test_an_executed_action_keeps_the_conservative_charge():
    # The executor charges the full hold when an exception leaves the outcome uncertain. Refunding
    # it here is what made `conservative_full_budget` a no-op on the production route.
    settled = _settle(executed=True)
    assert settled["http_requests"] == CHARGES["http_requests"]
    assert settled["device_fragility_points"] == CHARGES["device_fragility_points"]
    assert settled["tcp_ports_attempted"] == CHARGES["tcp_ports_attempted"]


def test_enqueued_downstream_work_keeps_its_holds():
    # The action is over, but the queued scan is real: releasing the ports and fragility it will
    # spend lets the next action reserve budget that is already committed.
    settled = _settle(enqueued=True)
    assert settled["tcp_ports_attempted"] == CHARGES["tcp_ports_attempted"]
    assert settled["udp_ports_attempted"] == CHARGES["udp_ports_attempted"]
    assert settled["device_fragility_points"] == CHARGES["device_fragility_points"]


def test_an_attempted_device_request_is_still_charged_when_nothing_executed():
    # The pre-existing narrow case: one device HTTP attempt with no executor accounting.
    settled = _settle(device_http_attempted=True, elapsed_wall=7)
    assert settled["http_requests"] == 1
    assert settled["device_fragility_points"] == 1
    assert settled["tool_wall_seconds"] == 7
    # Ports were never swept, so they are still released.
    assert settled["tcp_ports_attempted"] == 0


def test_the_wall_charge_never_exceeds_the_reservation():
    settled = _settle(device_http_attempted=True, elapsed_wall=10_000)
    assert settled["tool_wall_seconds"] == CHARGES["tool_wall_seconds"]


def test_settlement_does_not_mutate_the_caller_dict():
    actual = dict(CHARGES)
    _hunt_blocked_actual(CHARGES, actual, executed=False, enqueued=False,
                         device_http_attempted=False, elapsed_wall=1)
    assert actual == CHARGES, "settlement must return a new mapping, not edit the caller's"
