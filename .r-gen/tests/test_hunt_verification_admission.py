import asyncio

import pytest

from api.hunt.verification_budget import record_budget_shortage, web_candidate_budget
from api.runtime.budgets import reserve_budget_snapshot


def test_http_exposure_verification_needs_no_browser_budget():
    charges = web_candidate_budget("data_exposure")
    used = reserve_budget_snapshot({"http_requests": 100, "browser_actions": 0}, {}, charges)
    assert used["http_requests"] == 24
    assert used.get("browser_actions", 0) == 0


@pytest.mark.parametrize("family", ["mass_assignment", "field_constraint", "workflow"])
def test_mutating_verifiers_keep_their_write_reservations(family):
    assert web_candidate_budget(family)["state_changing_requests"] == 12


class DB:
    def __init__(self): self.updates = []
    async def execute(self, query, *args): self.updates.append((query, args))


def test_oversized_action_leaves_budget_for_smaller_work():
    db = DB()
    result = asyncio.run(record_budget_shortage(db, hunt_id="h1", limits={"http_requests": 100}, used={"http_requests": 90}, shortages={"http_requests": 14}))
    assert result["retryable_with_smaller_action"]
    assert result["remaining"] == {"http_requests": 10}
    assert not db.updates
    assert reserve_budget_snapshot({"http_requests": 100}, {"http_requests": 90}, {"http_requests": 1})["http_requests"] == 91


def test_a_used_up_traffic_limit_refuses_the_action_but_only_the_clock_stops_the_run():
    db = DB()
    result = asyncio.run(record_budget_shortage(db, hunt_id="h1", limits={"http_requests": 100}, used={"http_requests": 100}, shortages={"http_requests": 1}))
    assert not result["retryable_with_smaller_action"]
    assert result["error"] == "budget_exhausted:http_requests"
    assert not db.updates
    result = asyncio.run(record_budget_shortage(db, hunt_id="h1", limits={"tool_wall_seconds": 100}, used={"tool_wall_seconds": 100}, shortages={"tool_wall_seconds": 1}))
    assert not result["retryable_with_smaller_action"]
    assert len(db.updates) == 1 and db.updates[0][1] == ("h1", "budget_exhausted:tool_wall_seconds")
