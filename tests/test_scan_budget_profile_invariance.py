"""Fast and balanced Scan plans are pinned to what v2.11.0 (81caee26d) planned.

The thorough and deep budget changes (``contracts.budget_sufficiency``) must not move a single
fast or balanced action: not an id, an argument, a frozen budget, a slice shape or an input
binding. These unit-test fixtures compile the admission plan and continuation rounds 1-3 with
the real compilers and allocator over operator-supplied endpoints (no live discovery), settle
every round with synthetic results that exercise request-bound and wall-killed verifier slices,
zero-attempt body slices and active template sweeps, and compare every appended action with
``fixtures/scan_budget_invariance_2_11_0.json``, which was generated from v2.11.0.

The scanner argv of every batch attempt is derived from the slice's frozen budget and
capability arguments (pacing: ``external_process.paced_request_delay``), both pinned here.

Regenerate only from a v2.11.0 checkout:
``PYTHONPATH=.:api:scanner python tests/test_scan_budget_profile_invariance.py --write``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

from api.scan.capability_result import CapabilityResultReason, CapabilityResultStatus
from tests.scan_round_fixtures import (
    action_rows,
    admitted_round_fixture,
    appended_actions,
    compile_round,
    settle_lightly,
    settle_round,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "scan_budget_invariance_2_11_0.json"
PROFILES = ("fast", "balanced")
ACTIVE_GET_ONLY = ("recon", "nuclei_passive", "nuclei_active", "xss", "sqli")
# Explicitly named active templates hold the registry's mutation cost at admission, which a
# fast or balanced ledger cannot fund; the state-changing scenarios therefore leave them out.
VERIFIERS = ("recon", "nuclei_passive", "xss", "sqli")
# (name, endpoints, query candidates, body candidate, state-changing authority, zero attempts,
#  families)
SCENARIOS = (
    ("origin-only", 1, 0, False, False, False, ACTIVE_GET_ONLY),
    ("two-endpoints", 2, 1, False, False, False, ACTIVE_GET_ONLY),
    ("nine-endpoints", 9, 6, False, False, False, ACTIVE_GET_ONLY),
    ("thirty-three-endpoints", 33, 8, False, False, False, ACTIVE_GET_ONLY),
    ("large-app", 215, 14, False, False, False, ACTIVE_GET_ONLY),
    ("nine-endpoints-bodies", 9, 6, True, True, False, VERIFIERS),
    ("large-app-bodies", 215, 14, True, True, False, VERIFIERS),
    ("zero-attempt-bodies", 16, 1, True, True, True, VERIFIERS),
)
ROUNDS = 3


def _outcome(zero_attempts: bool):
    def outcome(action: Any):
        held = dict(action.requested_budget)
        extension = bool(action.capability_args.get("extends"))
        if action.capability_name == "sqli.verify_batch" and not extension:
            if zero_attempts:
                return (
                    CapabilityResultStatus.PARTIAL,
                    CapabilityResultReason.STATE_CHANGING_BUDGET_EXHAUSTED, {},
                )
            sent = held.get("http_requests", 0) * 7 // 10
            return (
                CapabilityResultStatus.PARTIAL,
                CapabilityResultReason.HTTP_REQUEST_BUDGET_EXHAUSTED,
                {
                    "http_requests": sent,
                    "state_changing_requests": min(held.get("state_changing_requests", 0), sent),
                    "tool_wall_seconds": held.get("tool_wall_seconds", 0) * 3 // 4,
                },
            )
        if action.capability_name == "xss.verify_batch" and not extension:
            if zero_attempts:
                return (
                    CapabilityResultStatus.PARTIAL,
                    CapabilityResultReason.STATE_CHANGING_BUDGET_EXHAUSTED, {},
                )
            sent = max(1, held.get("http_requests", 0) // 10)
            return (
                CapabilityResultStatus.TIMED_OUT, CapabilityResultReason.TIMED_OUT,
                {
                    "http_requests": sent,
                    "state_changing_requests": min(held.get("state_changing_requests", 0), sent),
                    "tool_wall_seconds": held.get("tool_wall_seconds", 0),
                },
            )
        if action.capability_name == "templates.active_batch":
            return (
                CapabilityResultStatus.SUCCESS, None,
                {**held, "tool_wall_seconds": held.get("tool_wall_seconds", 0) * 4 // 5},
            )
        return settle_lightly(action)
    return outcome


def _observations(action: Any):
    # A request-bound SQLi slice names what its unfinished candidates still need, so the
    # round compiler sizes its extension from the remaining units (sqli_stages.resume_plan).
    if action.capability_name != "sqli.verify_batch" or action.capability_args.get("extends"):
        return ()
    return ({
        "kind": "candidate_attempt", "attempt_id": f"{action.action_id}:0",
        "candidate_id": "candidate-0", "family": "sqli", "status": "partial",
        "resume_wall_seconds": 60, "remaining_wall_seconds": 111, "remaining_requests": 189,
    },)


def scenario_snapshot(profile: str, scenario: tuple) -> dict[str, Any]:
    _name, endpoints, queries, body, state_changing, zero_attempts, families = scenario
    fixture = admitted_round_fixture(
        profile, endpoints=endpoints, queries=queries, body=body,
        state_changing=state_changing, families=families,
    )
    rounds = {"admission": action_rows(fixture["parent_plan"].actions)}
    for number in range(1, ROUNDS + 1):
        settle_round(fixture, _outcome(zero_attempts), observations=_observations)
        parent_count = len(fixture["parent_plan"].actions)
        prepared = compile_round(fixture, number)
        appended = appended_actions(prepared, parent_count)
        rounds[f"r{number:02d}"] = action_rows(appended)
        if any(action.action_id == "finalize.report" for action in appended):
            break
    return rounds


def current_snapshot() -> dict[str, Any]:
    return {
        f"{profile}/{scenario[0]}": scenario_snapshot(profile, scenario)
        for profile in PROFILES for scenario in SCENARIOS
    }


@pytest.fixture(scope="module")
def pinned() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[item[0] for item in SCENARIOS])
def test_fast_and_balanced_plans_are_the_ones_v2_11_0_compiled(pinned, profile, scenario):
    expected = pinned[f"{profile}/{scenario[0]}"]
    actual = scenario_snapshot(profile, scenario)
    assert list(actual) == list(expected)
    for name, rows in expected.items():
        assert [row["action_id"] for row in actual[name]] == [row["action_id"] for row in rows], name
        for got, want in zip(actual[name], rows):
            assert got == want, (name, want["action_id"])


def test_the_pinned_rounds_exercise_extensions_and_active_sweeps(pinned):
    """The fixture is only worth pinning if it reaches the paths the thorough changes touch."""
    rows = [row for rounds in pinned.values() for name, items in rounds.items()
            if name != "admission" for row in items]
    capabilities = {row["capability_name"] for row in rows}
    assert {"templates.active_batch", "sqli.verify_batch", "xss.verify_batch"} <= capabilities
    assert any(row["extends"] for row in rows if row["capability_name"] == "sqli.verify_batch")
    assert any(row["extends"] for row in rows if row["capability_name"] == "xss.verify_batch")
    assert any(row["action_id"].startswith("active.templates") for row in rows
               if row["action_id"].endswith(".r02"))


if __name__ == "__main__" and "--write" in sys.argv:
    FIXTURE.write_text(
        json.dumps(current_snapshot(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
