"""Hunt collection replay receipts must agree with the worker-owned ledger."""

from api.hunt.interaction_router import _worker_replay_actual


CHARGES = {
    "agent_actions": 1,
    "active_actions": 1,
    "http_requests": 1,
    "tool_wall_seconds": 60,
}


def test_budget_exhausted_before_replay_does_not_report_unspent_actions():
    result = {
        "status": "failed",
        "error": "budget_exhausted:active_actions",
        "budget_consumed": {},
        "durable_budget_settled": True,
    }

    assert _worker_replay_actual(CHARGES, result) == {}


def test_successful_managed_replay_reports_only_measured_worker_charges():
    result = {
        "status": "success",
        "budget_consumed": {
            "agent_actions": 1,
            "active_actions": 1,
            "http_requests": 1,
            "tool_wall_seconds": 2,
        },
        "durable_budget_settled": True,
    }

    assert _worker_replay_actual(CHARGES, result) == result["budget_consumed"]
    assert _worker_replay_actual(CHARGES, {"status": "failed"}) == {}
