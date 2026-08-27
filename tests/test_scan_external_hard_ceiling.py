from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *_args, **_kwargs: None))

import agent_tools
import external_wire_acceptance
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


@pytest.mark.parametrize(
    ("tool", "reservation", "options", "runtime", "method"),
    [
        ("httpx", {"http_requests": 1, "tool_wall_seconds": 10}, {}, {}, "exact_request_count"),
        ("katana", {"http_requests": 3, "tool_wall_seconds": 2}, {}, {}, "rate_time_upper_bound"),
        (
            "ffuf", {"http_requests": 3, "tool_wall_seconds": 10}, {},
            {"ffuf_wordlist": "/tmp/bounded.txt", "ffuf_word_count": 3},
            "exact_wordlist",
        ),
        (
            "nuclei", {"http_requests": 7, "tool_wall_seconds": 30},
            {
                "template_ids": agent_tools._CANONICAL_PASSIVE_NUCLEI_IDS,
                "template_request_cost_upper_bound": (
                    agent_tools.canonical_passive_nuclei_request_upper_bound()
                ),
            }, {}, "reviewed_template_allowlist",
        ),
        # Reserved at the tool's own declared floor for the fixed conservative
        # profile, so raising the floor cannot silently leave this below it.
        (
            "dalfox", dict(agent_tools.EXTERNAL_VERIFICATION_FLOORS["dalfox"]),
            {}, {}, "fixed_conservative_profile",
        ),
        (
            "sqlmap", dict(agent_tools.EXTERNAL_VERIFICATION_FLOORS["sqlmap"]), {},
            {"sqlmap_output_dir": "/tmp/shakerscan-wire-sqlmap"},
            "fixed_conservative_profile",
        ),
        (
            "nmap", {"tcp_ports_attempted": 60, "tool_wall_seconds": 10},
            {}, {}, "version_probe_upper_bound",
        ),
        ("naabu", {"tcp_ports_attempted": 200, "tool_wall_seconds": 10}, {}, {}, "port_retry_upper_bound"),
    ],
)
def test_every_external_adapter_has_a_prelaunch_wire_proof(
    tool, reservation, options, runtime, method,
):
    plan = agent_tools.build_enforced_scanner_plan(
        tool,
        "http://app.example.test:8080/",
        options,
        reserved_budget=reservation,
        pinned_address="192.0.2.10",
        pinned_proxy_url=(
            None if tool in {"nmap", "naabu"}
            else "socks5://127.0.0.1:41000"
        ),
        runtime_paths=runtime,
    )

    assert plan.budget_proof["method"] == method
    assert plan.budget_proof["upper_bound"] == plan.hard_budget_dict
    assert all(
        amount <= reservation[name]
        for name, amount in plan.hard_budget_dict.items()
    )
    assert plan.timeout_ms <= reservation["tool_wall_seconds"] * 1_000


@pytest.mark.parametrize(
    ("tool", "reservation"),
    [
        ("httpx", {"tool_wall_seconds": 10}),
        ("katana", {"http_requests": 1, "tool_wall_seconds": 10}),
        ("katana", {"http_requests": 2, "tool_wall_seconds": 1}),
        ("nuclei", {"tool_wall_seconds": 10}),
        ("dalfox", {"http_requests": 1, "tool_wall_seconds": 10}),
        ("sqlmap", {"http_requests": 1, "tool_wall_seconds": 10}),
        ("nmap", {"tcp_ports_attempted": 59, "tool_wall_seconds": 10}),
        ("naabu", {"tcp_ports_attempted": 199, "tool_wall_seconds": 10}),
    ],
)
def test_external_adapter_refuses_to_start_below_provable_minimum(tool, reservation):
    with pytest.raises(agent_tools.AgentToolError):
        agent_tools.build_enforced_scanner_plan(
            tool,
            "http://app.example.test:8080/",
            {},
            reserved_budget=reservation,
            pinned_address="192.0.2.10",
            pinned_proxy_url=(
                None if tool in {"nmap", "naabu"}
                else "socks5://127.0.0.1:41000"
            ),
            runtime_paths={"sqlmap_output_dir": "/tmp/sqlmap"},
        )


def test_wire_gate_rejects_a_failed_or_zero_traffic_http_adapter():
    base_result = {
        "status": "success",
        "process_enforcement": {
            "schema_version": "external-process-enforcement/v1",
            "hard_budget": {"http_requests": 1, "tool_wall_seconds": 10},
        },
    }
    with pytest.raises(RuntimeError, match="did not execute successfully"):
        external_wire_acceptance._assert_wire_bound(
            tool="nuclei",
            result={**base_result, "status": "failed", "error": "no templates"},
            traffic={"traffic": [], "connections": 0},
        )
    with pytest.raises(RuntimeError, match="no target-observed HTTP traffic"):
        external_wire_acceptance._assert_wire_bound(
            tool="nuclei", result=base_result,
            traffic={"traffic": [], "connections": 0},
        )
