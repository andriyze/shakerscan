"""A crawl cut at its record bound settles partial with a truncation reason.

With the crawl's output allowance sized to what pages emit, the binding cap moved from the
byte allowance (flagged `output_truncated`) to the parser's 1,500-record bound, which was
silent: a crawl that found 4,000 distinct routes kept 1,500 and settled success, so the
finalizer could not count it as truncated discovery. The parser now reports how many
records it kept against how many it saw, and the worker settles a bounded crawl partial
with `output_truncated`, the reason `discovery_truncated` reads.
"""

from __future__ import annotations

import asyncio
import json

import pytest

import agent_tools
import worker
from tests.test_scanner_process_exit_truth import _PinnedProxy, _Process, _Redis


def _crawl_output(routes: int) -> bytes:
    return b"".join(
        json.dumps({
            "request": {
                "method": "GET",
                "endpoint": f"https://example.test/docs/page-{index}",
                "source": "https://example.test/docs",
            },
        }).encode() + b"\n"
        for index in range(routes)
    )


def _run(monkeypatch, tool: str, stdout: bytes) -> dict:
    monkeypatch.setattr(worker, "PinnedSocksProxy", _PinnedProxy)
    monkeypatch.setattr(worker, "get_redis", lambda: _Redis())

    async def _exec(*_cmd, **_kwargs):
        return _Process(0, stdout)

    monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", _exec)
    return asyncio.run(worker._execute_agent_scanner_process({
        "job_id": "crawl-job-limit",
        "tool_name": tool,
        "registered_target": "https://example.test",
        "execution_target": "https://example.test/",
        "scanner_options": {},
        "timeout_ms": 30_000,
        "pinned_address": "203.0.113.7",
        "authorized_addresses": ["203.0.113.7"],
        "_reserved_budget": {"http_requests": 1_500, "tool_wall_seconds": 300},
    }))


def test_a_crawl_past_its_record_bound_is_partial_and_says_why(monkeypatch):
    routes = agent_tools.MAX_TOOL_RECORDS + 500
    result = _run(monkeypatch, "katana", _crawl_output(routes))

    assert result["status"] == "success"
    assert result["partial"] is True
    assert result["error"] == "output_truncated"
    limit = result["typed_output"]["record_limit"]
    assert (limit["kept"], limit["seen"], limit["truncated"]) == (
        agent_tools.MAX_TOOL_RECORDS, routes, True,
    )


def test_a_crawl_within_its_record_bound_is_complete(monkeypatch):
    result = _run(monkeypatch, "katana", _crawl_output(300))

    assert result["partial"] is False
    assert result["error"] is None
    assert result["typed_output"]["record_limit"]["truncated"] is False


def test_the_adapter_settles_a_bounded_crawl_partial_with_the_marker():
    from capabilities.scanner import ScannerExecutionAdapter
    from runtime.capability_registry import CAPABILITY_REGISTRY
    from scan.capability_result import CapabilityResultReason, CapabilityResultStatus
    from tests.test_action_stop_dimension import _outcome

    typed = agent_tools.parse_scanner_output(
        "katana", _crawl_output(agent_tools.MAX_TOOL_RECORDS + 10).decode(),
        allowed_host="example.test",
    )
    spec = CAPABILITY_REGISTRY.require("web.crawl")
    requested = {"http_requests": 1_500, "tool_wall_seconds": 300}

    async def runner(payload, *, heartbeat):
        return {
            "status": "success", "error": agent_tools.scanner_truncation_error(None, typed),
            "partial": True, "timed_out": False, "elapsed_seconds": 20,
            "typed_output": typed,
            "settlement": {"mode": "unavailable", "actual": None, "observed_minimum": 0},
            "process_enforcement": {
                "schema_version": "external-process-enforcement/v1",
                "tool_name": spec.process_tool_name or spec.adapter,
                "process_plan_digest": "a" * 64,
                "hard_budget": dict(requested),
                "accounting_mode": "conservative",
                "proof_method": "rate_time_upper_bound",
                "parser_version": spec.output_schema,
            },
        }

    adapter = ScannerExecutionAdapter(
        specification=spec, process_payload={"tool_name": "katana"},
        process_runner=runner, requested_budget=requested,
        redacted_execution={"capability_name": "web.crawl"},
    )
    result = asyncio.run(adapter.execute(heartbeat=lambda: asyncio.sleep(0), cancelled=lambda: False))

    assert result.status == "partial"
    assert result.errors[0] == "output_truncated"
    assert result.redacted_execution["record_limit"]["truncated"] is True
    assert result.redacted_execution["record_limit"]["seen"] == agent_tools.MAX_TOOL_RECORDS + 10
    receipt = type("Receipt", (), {
        "status": result.status, "timed_out": result.timed_out,
        "partial": result.partial, "errors": result.errors,
    })()
    assert _outcome(receipt) == (
        CapabilityResultStatus.PARTIAL, CapabilityResultReason.OUTPUT_TRUNCATED,
    )


@pytest.mark.parametrize("tool, stdout", [
    ("nuclei", json.dumps({
        "template-id": "http-missing-security-headers", "matched-at": "https://example.test/",
        "info": {"severity": "info", "name": "missing headers"},
    })),
    ("httpx", json.dumps({"url": "https://example.test/", "status_code": 200})),
])
def test_other_tools_with_few_records_are_unmarked(tool, stdout):
    parsed = agent_tools.parse_scanner_output(tool, stdout)

    assert parsed["records_truncated"] is False
    assert agent_tools.scanner_truncation_error(None, parsed) is None


def test_a_tool_whose_items_exceed_the_bound_is_marked():
    lines = "\n".join(
        json.dumps({
            "template-id": f"template-{index}", "matched-at": f"https://example.test/{index}",
            "info": {"severity": "info"},
        })
        for index in range(agent_tools.MAX_TOOL_RECORDS + 1)
    )
    parsed = agent_tools.parse_scanner_output("nuclei", lines)

    assert parsed["records_truncated"] is True
    assert parsed["record_limit"]["kept"] == agent_tools.MAX_TOOL_RECORDS
