from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *_args, **_kwargs: None))

import agent_tools
import worker


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


def test_broker_external_process_uses_lease_cancel_file_without_redis(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_BROKER_LEASE", "1")
    monkeypatch.setattr(
        worker,
        "get_redis",
        lambda: (_ for _ in ()).throw(AssertionError("broker touched Redis")),
    )

    result = asyncio.run(worker._execute_agent_scanner_process({
        "job_id": "broker-action-1",
        "tool_name": "httpx",
        "execution_target": "not-an-http-url",
        "registered_target": "https://app.example.test",
        "scanner_options": {},
        "_reserved_budget": {"http_requests": 1, "tool_wall_seconds": 1},
        "pinned_address": "192.0.2.10",
        "authorized_addresses": ["192.0.2.10"],
    }))

    assert result["status"] == "failed"
    assert str(result["error"]).startswith("contract:")
