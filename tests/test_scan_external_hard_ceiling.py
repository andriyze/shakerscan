from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import agent_tools


def test_external_execution_contract_requires_a_hard_reserved_wire_limit():
    plan = agent_tools.build_enforced_scanner_plan(
        "katana",
        "https://app.example.test/",
        {},
        reserved_budget={"http_requests": 3, "tool_wall_seconds": 5},
        pinned_address="192.0.2.1",
        pinned_proxy_url="socks5://127.0.0.1:41000",
    )

    assert plan.hard_budget_dict["http_requests"] == 3
    assert plan.budget_proof["method"] == "rate_time_upper_bound"
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "1"
