"""Hunt lifecycle tools answer with a compact projection unless the full record is asked for.

Soak 2026-10-07 (defect 18): hunt_start, hunt_get, hunt_finish, hunt_skill_bind and
hunt_skill_usage returned the whole Hunt record (70-150 KB: every capability's request, output
and identity contracts plus the context pack), OpenCode truncated it, and models spent calls
finding hunt_id and status. The default view now keeps identity, status, budget and use, next
action and counts; ``view: "full"`` returns the record unchanged and ``capability`` on hunt_get
returns that one capability's full contract. Unit fixtures: the record is synthetic.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_compact", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

HUNT = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def _capability(name):
    schema = {"type": "object", "additionalProperties": False, "required": ["path"], "properties": {
        "path": {"type": "string", "description": "x" * 400},
        "method": {"type": "string", "enum": ["GET", "HEAD"]},
        "max_pages": {"type": "integer", "minimum": 1, "maximum": 50},
    }}
    return {
        "name": name, "description": "d" * 300, "risk_tier": "passive", "input_schema": schema,
        "call": {"method": "POST", "request_schema": {"properties": {"input": schema}}},
        "output_schema": {"type": "object", "properties": {f"f{i}": {"type": "string"} for i in range(60)}},
        "identity_contract": {"schema_version": "capability-identity/v1"}, "placement": {},
        "evidence_contract": ["http_exchange"], "tool": {"name": "httpx"}, "target_kinds": ["web"],
        "budget_cost": {"http_requests": 150, "tool_wall_seconds": 75},
    }


def _record():
    return {
        "hunt_id": HUNT, "target_id": "t-1", "target_kind": "web", "status": "active",
        "budget_profile": "fast", "objective": "map the API", "next_action": f"POST /hunts/{HUNT}/query",
        "budget": {"max_http_requests": 500}, "budget_used": {"http_requests": 371},
        "policy": {"active_testing": False}, "stop_reason": None, "budget_revision": 0,
        "capabilities": [_capability(f"web.cap{i}") for i in range(30)],
        "context_pack": {"prior_knowledge": ["k" * 500] * 40},
        "actions": [{"action_id": f"a{i}", "capability_name": "web.cap1", "status": "completed",
                     "receipt_id": f"r{i}", "result": {"observations": ["o" * 300] * 10}} for i in range(12)],
        "skills": [{"skill_id": "skill.web.recon", "title": "Recon", "support": "supported", "phase": "discovery",
                    "body_sha256": "0" * 64, "methodology_url": "/x"}],
        "skill_activity": [{"event_type": "read", "skill_id": "skill.web.recon", "action_id": None}] * 7,
        "outcome_summary": {"capability_calls": 12, "candidate_ids": []},
    }


class Instance(mcp.ArsenalClient):
    def __init__(self):
        super().__init__("http://127.0.0.1:8080")
        self.sent = []

    def request_json(self, method, path, payload=None):
        self.sent.append((method, path, payload))
        return _record()


@pytest.mark.parametrize(("tool", "arguments"), [
    ("shakerscan_hunt_get", {}),
    ("shakerscan_hunt_finish", {"summary": "done"}),
    ("shakerscan_hunt_skill_bind", {"skill_id": "skill.web.recon"}),
    ("shakerscan_hunt_skill_usage", {"skill_id": "skill.web.recon", "state": "deferred"}),
    ("shakerscan_hunt_cancel", {}),
])
def test_lifecycle_tools_answer_compactly_by_default(tool, arguments):
    client = Instance()
    full_size = len(json.dumps(_record()))
    result = client.call_tool(tool, {"hunt_id": HUNT, **arguments})
    compact = result["structuredContent"]
    assert len(result["content"][0]["text"]) < min(12_000, full_size // 5)
    assert compact["hunt_id"] == HUNT and compact["status"] == "active"
    assert compact["budget"] == {"max_http_requests": 500} and compact["budget_used"] == {"http_requests": 371}
    assert compact["next_action"].endswith("/query")
    names = [item["name"] for item in compact["capabilities"]]
    assert names == [f"web.cap{i}" for i in range(30)]
    first = compact["capabilities"][0]
    assert first["input"]["required"] == ["path"]
    assert first["input"]["fields"]["method"] == "one of GET|HEAD"
    assert first["input"]["fields"]["max_pages"] == "integer 1..50"
    assert first["budget_cost"] == {"http_requests": 150, "tool_wall_seconds": 75}
    assert compact["counts"] == {"capabilities": 30, "actions": 12, "skills": 1, "skill_activity": 7}
    assert [a["action_id"] for a in compact["recent_actions"]] == ["a7", "a8", "a9", "a10", "a11"]
    assert "context_pack" not in compact and "context_pack" in compact["mcp_view"]["omitted"]
    assert "view" in compact["mcp_view"]["full_view"]
    # The MCP-only arguments never reach the server.
    assert all("view" not in (payload or {}) for _, _, payload in client.sent)


def test_full_view_returns_the_record_unchanged():
    client = Instance()
    result = client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "view": "full"})
    assert result["structuredContent"] == _record()
    assert client.sent == [("GET", f"/hunts/{HUNT}", None)]


def test_hunt_get_returns_one_capability_contract_on_request():
    client = Instance()
    result = client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "capability": "web.cap3"})
    assert result["structuredContent"]["capability"] == _capability("web.cap3")
    with pytest.raises(mcp.MCPError, match="not in this Hunt's manifest"):
        client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "capability": "web.missing"})


def test_a_response_that_is_not_a_hunt_record_is_left_alone():
    class Small(Instance):
        def request_json(self, method, path, payload=None):
            return {"hunt_id": HUNT, "skill_id": "skill.web.recon", "state": "deferred"}

    result = Small().call_tool("shakerscan_hunt_skill_usage", {
        "hunt_id": HUNT, "skill_id": "skill.web.recon", "state": "deferred",
    })
    assert result["structuredContent"] == {"hunt_id": HUNT, "skill_id": "skill.web.recon", "state": "deferred"}


def test_hunt_start_offers_the_view_and_does_not_send_it():
    contract_tool = mcp._hunt_start_tool({
        "schema_version": "hunt-start/v2", "target_kinds": ["web"], "policy_fields": ["active_testing"],
        "credential_ref_fields": [], "budget_profiles": {"fast": {"max_http_requests": 500}},
        "budget_dimensions": [{"name": "max_http_requests", "minimum": 0}],
    })
    assert contract_tool.properties["view"]["enum"] == ["compact", "full"]
    assert "view" not in contract_tool.required


def test_a_bound_skill_keeps_its_capability_gaps_and_every_reduction_is_marked():
    # AGENTS.md: report a bound skill's withheld/missing capabilities as coverage gaps. The bind
    # answer is the Hunt record, so the compact view is where the agent learns them.
    record = _record()
    record["skills"] = [{
        "skill_id": "web.idor", "title": "IDOR", "support": "partial", "phase": "verify",
        "withheld_capabilities": ["authz.verify"], "missing_capabilities": ["browser.workflow"],
        "methodology_url": "/x", "body_sha256": "0" * 64,
    }]
    compact = mcp._compact_hunt(record)
    (skill,) = compact["skills"]
    assert skill["withheld_capabilities"] == ["authz.verify"]
    assert skill["missing_capabilities"] == ["browser.workflow"]
    view = compact["mcp_view"]
    # Nothing is cut down silently: each reduced field says what it kept.
    assert set(view["reduced"]) == {"capabilities", "actions", "skills", "skill_activity"}
    assert "withheld_capabilities" in view["reduced"]["skills"]
    assert "last 5 of 12" in view["reduced"]["actions"]


def test_an_oversized_outcome_summary_keeps_its_counters_and_marks_the_trimmed_ids():
    record = _record()
    ids = [f"{i:08d}-0000-4000-8000-000000000000" for i in range(150)]
    record["outcome_summary"] = {
        "statuses": {"completed": 140, "partial": 10}, "executed_calls": 150, "successful_calls": 120,
        "partial_calls": 10, "unsuccessful_calls": 15, "indeterminate_calls": 5,
        "evidence_ids": ids, "finding_ids": ids[:30], "candidate_ids": [],
    }
    compact = mcp._compact_hunt(record)
    summary = compact["outcome_summary"]
    assert "outcome_summary" not in compact["mcp_view"]["omitted"]
    assert (summary["executed_calls"], summary["successful_calls"], summary["partial_calls"],
            summary["indeterminate_calls"]) == (150, 120, 10, 5)
    assert summary["evidence_ids"] == ids[:20] and summary["finding_ids"] == ids[:20]
    marked = compact["mcp_view"]["reduced"]["outcome_summary"]
    assert "evidence_ids (150 in all)" in marked and "finding_ids (30 in all)" in marked


def test_a_field_that_cannot_be_cut_down_is_omitted_and_named():
    record = {**_record(), "final_debrief": {"summary": "s" * 10_000}}
    compact = mcp._compact_hunt(record)
    assert "final_debrief" not in compact and "final_debrief" in compact["mcp_view"]["omitted"]
