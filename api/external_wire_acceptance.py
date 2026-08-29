#!/usr/bin/env python3
"""Real-tool acceptance gate for external process and browser wire ceilings."""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import urllib.parse
import urllib.request
from typing import Any, Mapping

import agent_tools
from capabilities.browser import BrowserNavigateAdapter
from runtime.models import TargetBinding
from worker import _execute_agent_scanner_process


CONTROL_HEADER = {"X-Parity-Control": "shakerscan-parity-fixture-v1"}


TOOL_CASES: tuple[dict[str, Any], ...] = (
    {"tool": "httpx", "path": "/", "budget": {"http_requests": 1, "tool_wall_seconds": 10}},
    {"tool": "katana", "path": "/", "budget": {"http_requests": 3, "tool_wall_seconds": 2}},
    {"tool": "ffuf", "path": "/", "budget": {"http_requests": 3, "tool_wall_seconds": 10}},
    {
        "tool": "nuclei",
        "path": "/",
        "budget": {"http_requests": 7, "tool_wall_seconds": 30},
        "options": {
            "template_ids": agent_tools._CANONICAL_PASSIVE_NUCLEI_IDS,
            "template_request_cost_upper_bound": (
                agent_tools.canonical_passive_nuclei_request_upper_bound()
            ),
        },
    },
    {
        "tool": "dalfox",
        "path": "/dast/xss?message=control",
        "budget": {"http_requests": 11, "tool_wall_seconds": 10},
        # Wire acceptance proves the same low-budget, runtime-limited path used
        # for one candidate in a batch. Full verification keeps its larger
        # declared floor and is covered separately by the contract suite.
        "options": {"_batch_attempt": True},
    },
    {
        "tool": "sqlmap",
        "path": "/dast/sqli?id=1",
        "budget": {"http_requests": 21, "tool_wall_seconds": 20},
        "options": {"_batch_attempt": True},
    },
    {"tool": "nmap", "path": "/", "budget": {"tcp_ports_attempted": 60, "tool_wall_seconds": 10}},
    {"tool": "naabu", "path": "/", "budget": {"tcp_ports_attempted": 200, "tool_wall_seconds": 10}},
)


def _request_json(url: str, *, method: str = "GET") -> dict[str, Any]:
    request = urllib.request.Request(url, method=method, headers=CONTROL_HEADER)
    with urllib.request.urlopen(request, timeout=10) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise RuntimeError("parity fixture control response is invalid")
    return payload


def _reset(origin: str) -> None:
    _request_json(f"{origin}/__parity__/reset", method="POST")


def _traffic(origin: str) -> dict[str, Any]:
    return _request_json(f"{origin}/__parity__/traffic")


def _resolve_address(origin: str) -> str:
    host = str(urllib.parse.urlsplit(origin).hostname or "")
    addresses = []
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        address = str(item[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise RuntimeError("fixture target did not resolve inside the worker")
    return addresses[0]


def _assert_wire_bound(
    *,
    tool: str,
    result: Mapping[str, Any],
    traffic: Mapping[str, Any],
) -> dict[str, Any]:
    enforcement = dict(result.get("process_enforcement") or {})
    hard = dict(enforcement.get("hard_budget") or {})
    if not hard:
        raise RuntimeError(f"{tool} did not produce a pre-launch enforcement receipt")
    if result.get("error") == "scanner_not_available":
        raise RuntimeError(f"{tool} is absent from the release worker image")
    if str(result.get("error") or "").startswith("contract:"):
        raise RuntimeError(f"{tool} process contract failed: {result.get('error')}")
    status = str(result.get("status") or "failed")
    if status not in {"success", "timeout"}:
        raise RuntimeError(f"{tool} did not execute successfully: {result.get('error')}")
    request_count = len([
        item for item in traffic.get("traffic") or []
        if isinstance(item, Mapping)
    ])
    connections = max(0, int(traffic.get("connections") or 0))
    http_limit = int(hard.get("http_requests") or 0)
    connection_limit = max(
        http_limit,
        int(hard.get("tcp_ports_attempted") or 0),
    )
    if http_limit and request_count > http_limit:
        raise RuntimeError(
            f"{tool} exceeded its target-observed HTTP ceiling "
            f"({request_count}>{http_limit})"
        )
    if http_limit and request_count < 1:
        raise RuntimeError(f"{tool} produced no target-observed HTTP traffic")
    if connection_limit and connections > connection_limit:
        raise RuntimeError(
            f"{tool} exceeded its target-observed connection ceiling "
            f"({connections}>{connection_limit})"
        )
    return {
        "tool": tool,
        "status": status,
        "error": str(result.get("error") or "") or None,
        "hard_budget": hard,
        "target_observed_http_requests": request_count,
        "target_observed_connections": connections,
        "limiter_triggered": str(result.get("error") or "") in {
            "connection_limit_exceeded", "timeout",
        },
        "enforcement_schema": enforcement.get("schema_version"),
    }


async def _run_tool_case(
    origin: str,
    address: str,
    case: Mapping[str, Any],
) -> dict[str, Any]:
    tool = str(case["tool"])
    _reset(origin)
    result = await _execute_agent_scanner_process({
        "job_id": f"wire-acceptance-{tool}",
        "tool_name": tool,
        "execution_target": f"{origin}{case['path']}",
        "registered_target": origin,
        "scanner_options": dict(case.get("options") or {}),
        "_reserved_budget": dict(case["budget"]),
        "timeout_ms": int(case["budget"]["tool_wall_seconds"]) * 1_000,
        "pinned_address": address,
        "authorized_addresses": [address],
    })
    return _assert_wire_bound(
        tool=tool, result=result, traffic=_traffic(origin),
    )


async def _run_browser_case(origin: str, address: str) -> dict[str, Any]:
    _reset(origin)
    parsed = urllib.parse.urlsplit(origin)
    target = TargetBinding(
        target_id="wire-acceptance-target",
        target_kind="web",
        canonical_host=str(parsed.hostname or ""),
        allowed_origins=(origin,),
        allowed_addresses=(address,),
        allowed_root_domains=(str(parsed.hostname or ""),),
    )
    prepared = BrowserNavigateAdapter.prepare(
        target=target,
        base_url=origin,
        args={
            "path": "/",
            "wait_until": "load",
            "timeout_ms": 10_000,
            "max_requests": 3,
        },
    )

    async def heartbeat() -> None:
        return None

    result = await BrowserNavigateAdapter(prepared).execute(
        heartbeat=heartbeat,
        cancelled=lambda: False,
    )
    observed = _traffic(origin)
    if result.status != "success":
        raise RuntimeError(f"browser did not execute successfully: {result.errors}")
    request_count = len(observed.get("traffic") or [])
    consumed = dict(result.actual_budget or {})
    if request_count > 3 or int(consumed.get("http_requests") or 0) > 3:
        raise RuntimeError("browser exceeded its routed request ceiling")
    if int(consumed.get("browser_actions") or 0) > 1:
        raise RuntimeError("browser exceeded its action ceiling")
    return {
        "tool": "browser",
        "status": result.status,
        "error": list(result.errors),
        "hard_budget": prepared.estimated_budget,
        "target_observed_http_requests": request_count,
        "target_observed_connections": int(observed.get("connections") or 0),
        "limiter_triggered": any(
            item.get("reason") == "request_budget_exhausted"
            for item in result.observations
            if isinstance(item, Mapping)
        ),
        "enforcement_schema": "browser-route-enforcement/v1",
    }


async def run(origin: str) -> dict[str, Any]:
    normalized = origin.rstrip("/")
    parsed = urllib.parse.urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise RuntimeError("--target must be one HTTP(S) origin")
    address = _resolve_address(normalized)
    cases = [
        await _run_tool_case(normalized, address, case)
        for case in TOOL_CASES
    ]
    cases.append(await _run_browser_case(normalized, address))
    return {
        "schema_version": "external-wire-acceptance/v1",
        "status": "passed",
        "tool_count": len(cases),
        "cases": cases,
        "subfinder": {
            "status": "not_applicable",
            "reason": "subfinder does not send target-origin HTTP or TCP traffic",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(json.dumps(
        asyncio.run(run(args.target)),
        sort_keys=True,
        separators=(",", ":"),
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
