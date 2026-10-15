"""MCP answers stay within what an agent host shows, and every list tool pages.

Every read-only list tool takes ``limit`` (default 20, at most 100) and the previous answer's
``next_cursor``, returns summary rows by default, and is cut on a row boundary to one answer
(``MCP_ANSWER_BYTES``) with a cursor that resumes at the first row left out. The engine's live
Arsenal catalog says whether a command pages itself (``limit`` and ``offset``): ``finding.list``
does from 2.11; before that, and for the lists that never did, the adapter pages over the first
rows the engine answers and says when the rest is out of its reach. Unit fixtures: the engine is
a scripted catalog and executor, not a live instance.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# The same loaded adapter as the fixtures reused from there, so its error class is this one.
from tests.test_read_only_mcp import ManifestHuntClient, _hunt_contract, mcp  # noqa: E402

FINDING_FILTERS = {"status": {"type": "string"}, "severity": {"type": "string"}}
FINDINGS_211 = {**FINDING_FILTERS, "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "offset": {"type": "integer", "minimum": 0, "maximum": 100_000}}
# The live catalog of each other read-only command, as the engine declares it.
CATALOG = {
    "target.list": {"limit": {"type": "integer", "minimum": 1, "maximum": 100},
                    "offset": {"type": "integer", "minimum": 0, "maximum": 100_000},
                    "include_inactive": {"type": "boolean"}},
    "asm.gaps": {"target_id": {"type": "string", "format": "uuid"}},
    "evidence.export_manifest": {"finding_id": {"type": "string"}, "scan_id": {"type": "string"},
                                 "retention_class": {"type": "string"},
                                 "limit": {"type": "integer", "minimum": 1, "maximum": 1000}},
    "mission.timeline": {"limit": {"type": "integer", "minimum": 1, "maximum": 200},
                         "target_id": {"type": "string", "format": "uuid"}},
    "operation_plan.list": {"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
    "tool.status": {},
}


def _finding(index, *, heavy=0):
    return {"id": f"f-{index:04d}", "title": f"Finding {index}", "severity": "high", "status": "active",
            "url": f"https://app.example.test/{index}", "proof_state": "suspected", "target_id": "t-1",
            "first_seen_at": "2026-10-01T00:00:00Z", "last_seen_at": "2026-10-14T00:00:00Z",
            "ai_verdict": "likely", "tool": "nuclei", "cwe": "CWE-79", "remediation": "r" * 400,
            "evidence_summary": "e" * heavy}


class Engine(mcp.ArsenalClient):
    """A scripted engine: the Arsenal catalog and the read-only executor (unit fixture)."""

    def __init__(self, *, findings_schema=FINDINGS_211, findings=(), stated_total=None, rows=None):
        super().__init__("http://127.0.0.1:8080")
        self.findings_schema = findings_schema
        self.findings = list(findings)
        self.stated_total = stated_total
        self.rows = rows or {}
        self.executed = []

    def request_json(self, method, path, payload=None):
        if path == "/arsenal/commands":
            schemas = {**CATALOG, "finding.list": self.findings_schema}
            return {"commands": [{"name": name, "status": "read_only", "risk_tier": "read_only", "method": "GET",
                                  "parameters_schema": schema} for name, schema in schemas.items()]}
        if path == "/hunts/contract":
            return _hunt_contract()
        assert (method, path) == ("POST", "/arsenal/execute"), path
        command, parameters = payload["command"], payload["parameters"]
        self.executed.append((command, dict(parameters)))
        if command == "finding.list":
            if "offset" in parameters:  # an engine that pages (2.11)
                start, size = parameters["offset"], parameters["limit"]
            else:  # 2.10: the first 100, whatever is asked
                start, size = 0, 100
            result = {"findings": self.findings[start:start + size],
                      "total": self.stated_total if self.stated_total is not None else len(self.findings),
                      "limit": size, "offset": start}
        elif command == "target.list":
            start, size = parameters["offset"], parameters["limit"]
            listed = self.rows.get("targets", [])
            result = {"targets": listed[start:start + size], "total": len(listed)}
        elif command == "evidence.export_manifest":
            listed = self.rows.get("objects", [])
            size = parameters.get("limit", 200)
            result = {"objects": listed[:size], "object_count": min(size, len(listed)), "manifest_hash": "h",
                      "truncated": len(listed) > size}
        elif command == "mission.timeline":
            listed = self.rows.get("events", [])
            result = {"events": listed[:parameters.get("limit", 50)], "upcoming": [], "count": 0}
        elif command == "operation_plan.list":
            listed = self.rows.get("operation_plans", [])
            result = {"operation_plans": listed[:parameters.get("limit", 20)], "execution_enabled": False}
        else:
            result = self.rows.get(command, {})
        return {"command": command, "dispatched": True, "result": result,
                "action_state": {"catalog_status": "read_only", "risk_tier": "read_only"}}

    def serves_route(self, method, path):
        return False


def _answer(result):
    text = result["content"][0]["text"]
    assert len(text.encode("utf-8")) <= mcp.MCP_ANSWER_BYTES, len(text)
    return result["structuredContent"]


def test_every_list_tool_takes_a_bounded_limit_and_a_cursor():
    tools = {tool["name"]: tool["inputSchema"]["properties"] for tool in Engine().list_tools()}
    for name in ("shakerscan_targets", "shakerscan_findings", "shakerscan_evidence_manifest",
                 "shakerscan_timeline", "shakerscan_plans", "shakerscan_hunt_query"):
        assert tools[name]["limit"]["maximum"] == 100 and tools[name]["limit"]["minimum"] == 1, name
        assert tools[name]["cursor"]["type"] == "string", name
    assert tools["shakerscan_findings"]["view"]["enum"] == ["summary", "full"]
    assert tools["shakerscan_hunt_capability"]["view"]["enum"] == ["compact", "full"]


def test_findings_page_on_an_engine_that_pages_them():
    engine = Engine(findings=[_finding(index) for index in range(45)])
    first = _answer(engine.call_tool("shakerscan_findings", {"severity": "high"}))
    assert engine.executed[-1] == ("finding.list", {"severity": "high", "limit": 20, "offset": 0})
    assert [row["id"] for row in first["findings"]] == [f"f-{index:04d}" for index in range(20)]
    assert "remediation" not in first["findings"][0] and first["mcp_view"]["rows"] == "summary"
    assert first["has_more"] is True and first["total"] == 45 and first["next_cursor"]

    second = _answer(engine.call_tool("shakerscan_findings", {"severity": "high", "cursor": first["next_cursor"]}))
    assert engine.executed[-1][1]["offset"] == 20
    third = _answer(engine.call_tool("shakerscan_findings", {"severity": "high", "cursor": second["next_cursor"]}))
    assert [row["id"] for row in third["findings"]] == [f"f-{index:04d}" for index in range(40, 45)]
    assert third["has_more"] is False and third["next_cursor"] is None

    full = _answer(engine.call_tool("shakerscan_findings", {"limit": 2, "view": "full"}))
    assert full["findings"][0]["remediation"] == "r" * 400


def test_a_cursor_belongs_to_its_tool_and_filters():
    engine = Engine(findings=[_finding(index) for index in range(45)])
    cursor = _answer(engine.call_tool("shakerscan_findings", {"severity": "high"}))["next_cursor"]
    with pytest.raises(mcp.MCPError, match="other filters"):
        engine.call_tool("shakerscan_findings", {"severity": "low", "cursor": cursor})
    with pytest.raises(mcp.MCPError, match="not a next_cursor of shakerscan_timeline"):
        engine.call_tool("shakerscan_timeline", {"cursor": cursor})
    forged = base64.urlsafe_b64encode(b'{"v":1,"t":"shakerscan_findings","o":-5,"q":"x"}').decode()
    for bad in ("not base64 at all!", forged):
        with pytest.raises(mcp.MCPError) as refused:
            engine.call_tool("shakerscan_findings", {"cursor": bad})
        assert refused.value.code == -32602
    with pytest.raises(mcp.MCPError, match="not both"):
        engine.call_tool("shakerscan_targets", {"cursor": cursor, "offset": 5})
    with pytest.raises(mcp.MCPError):
        engine.call_tool("shakerscan_findings", {"limit": 101})


def test_findings_on_an_engine_before_2_11_page_over_its_first_hundred():
    """2.10's finding.list takes no limit (its catalog says so, and the engine would refuse an
    unknown parameter): the adapter sends none and pages over the 100 rows the engine answers."""
    engine = Engine(findings_schema=FINDING_FILTERS, findings=[_finding(index) for index in range(350)])
    seen, cursor = [], None
    for _ in range(5):
        answer = _answer(engine.call_tool("shakerscan_findings", {"status": "active", **({"cursor": cursor} if cursor else {})}))
        assert engine.executed[-1] == ("finding.list", {"status": "active"})
        seen += [row["id"] for row in answer["findings"]]
        cursor = answer["next_cursor"]
        if not answer["has_more"]:
            break
    assert seen == [f"f-{index:04d}" for index in range(100)]
    assert answer["total"] == 350 and answer["has_more"] is False
    assert "narrow the filters (status, severity)" in answer["mcp_view"]["note"]


def test_a_page_larger_than_one_answer_is_cut_on_a_row_and_resumes_there():
    engine = Engine(findings=[_finding(index, heavy=6_000) for index in range(30)])
    cut = _answer(engine.call_tool("shakerscan_findings", {"limit": 30, "view": "full"}))
    kept = len(cut["findings"])
    assert 0 < kept < 30 and cut["has_more"] is True
    assert "did not fit one answer" in cut["mcp_view"]["note"]
    rest = _answer(engine.call_tool("shakerscan_findings", {"limit": 30, "view": "full", "cursor": cut["next_cursor"]}))
    assert rest["findings"][0]["id"] == f"f-{kept:04d}", "nothing skipped"

    huge = Engine(findings=[_finding(0, heavy=80_000), _finding(1)])
    alone = _answer(huge.call_tool("shakerscan_findings", {"view": "full"}))
    assert alone["findings"] == [{"mcp_omitted": alone["findings"][0]["mcp_omitted"], "id": "f-0000"}]
    assert alone["next_cursor"] and "by id only" in alone["mcp_view"]["note"]


def test_targets_page_with_a_cursor_or_the_offset_they_always_took():
    targets = [{"id": f"t-{index:03d}", "url": f"https://{index}.example.test", "name": "n", "is_active": True,
                "metadata_json": {"x": 1}} for index in range(25)]
    engine = Engine(rows={"targets": targets})
    first = _answer(engine.call_tool("shakerscan_targets", {}))
    assert engine.executed[-1] == ("target.list", {"limit": 20, "offset": 0})
    assert first["returned"] == 20 and first["has_more"] is True and "metadata_json" not in first["targets"][0]
    second = _answer(engine.call_tool("shakerscan_targets", {"cursor": first["next_cursor"]}))
    assert [row["id"] for row in second["targets"]] == [f"t-{index:03d}" for index in range(20, 25)]
    assert second["has_more"] is False
    assert _answer(engine.call_tool("shakerscan_targets", {"offset": 24}))["targets"][0]["id"] == "t-024"


def test_timeline_and_plans_page_over_what_the_engine_answers():
    events = [{"event_id": f"e-{index}", "kind": "scan"} for index in range(230)]
    plans = [{"id": f"p-{index}", "objective": "o", "plan_json": {"big": "x" * 500}, "actions": [1, 2]}
             for index in range(30)]
    engine = Engine(rows={"events": events, "operation_plans": plans})
    page = _answer(engine.call_tool("shakerscan_timeline", {"limit": 50}))
    assert engine.executed[-1] == ("mission.timeline", {"limit": 51})
    assert page["has_more"] is True and len(page["events"]) == 50
    cursor = page["next_cursor"]
    for _ in range(3):
        page = _answer(engine.call_tool("shakerscan_timeline", {"limit": 50, "cursor": cursor}))
        cursor = page["next_cursor"]
    assert engine.executed[-1] == ("mission.timeline", {"limit": 200}), "never past the engine's maximum"
    assert page["has_more"] is False and "narrow the filters (target_id)" in page["mcp_view"]["note"]

    planned = _answer(engine.call_tool("shakerscan_plans", {"limit": 5}))
    assert planned["operation_plans"][0] == {"id": "p-0", "objective": "o", "action_count": 2}
    assert planned["has_more"] is True


def test_the_evidence_manifest_stops_at_its_newest_200_and_says_so():
    objects = [{"id": f"o-{index}", "content_sha256": "a" * 64} for index in range(260)]
    engine = Engine(rows={"objects": objects})
    page = _answer(engine.call_tool("shakerscan_evidence_manifest", {"limit": 100}))
    assert engine.executed[-1] == ("evidence.export_manifest", {"limit": 101})
    page = _answer(engine.call_tool("shakerscan_evidence_manifest", {"limit": 100, "cursor": page["next_cursor"]}))
    assert engine.executed[-1] == ("evidence.export_manifest", {"limit": 200})
    assert len(page["objects"]) == 100 and page["has_more"] is False
    assert "finding_id, scan_id, retention_class" in page["mcp_view"]["note"]
    small = Engine(rows={"objects": objects[:7]})
    whole = _answer(small.call_tool("shakerscan_evidence_manifest", {}))
    assert whole["total"] == 7 and whole["has_more"] is False and "note" not in whole["mcp_view"]


def test_any_other_answer_larger_than_one_answer_says_what_was_left_out():
    engine = Engine(rows={"asm.gaps": {"target_id": "t", "gaps": ["g" * 1_000] * 100, "summary": "small"}})
    answer = _answer(engine.call_tool("shakerscan_asm_gaps", {"target_id": "11111111-1111-4111-8111-111111111111"}))
    assert answer["summary"] == "small" and "gaps" not in answer
    assert answer["mcp_view"]["truncated"] is True and answer["mcp_view"]["omitted"]["gaps"] > 64_000


class CapabilityEngine(ManifestHuntClient):
    """A Hunt capability whose answer carries its observations twice (unit fixture)."""

    def __init__(self, observations):
        super().__init__()
        self.observations = observations

    def request_json(self, method, path, payload=None):
        if path.endswith("/capabilities/http.request"):
            self.calls.append((method, path, payload))
            return {"hunt_id": self.HUNT_ID, "capability": "http.request", "action_id": "act-1",
                    "status": "completed", "idempotent_replay": False,
                    "action_result": {"status": "success", "observations": list(self.observations)},
                    "result": {"observations": list(self.observations), "budget_consumed": {"http_requests": 1},
                               "typed_output": {"records": list(self.observations), "parser": "http/v1"}}}
        return super().request_json(method, path, payload)


def _call(engine, **extra):
    return engine.call_tool("shakerscan_hunt_capability", {
        "hunt_id": engine.HUNT_ID, "capability_name": "http.request",
        "input": {"method": "GET", "path": "/"}, **extra,
    })


def test_a_capability_answer_keeps_one_copy_of_its_observations():
    observations = [{"kind": "http.response", "status": 200, "path": "/"}]
    answer = _answer(_call(CapabilityEngine(observations)))
    assert answer["action_result"]["observations"] == observations
    assert answer["result"]["observations"] == {"mcp_same_as": "action_result.observations"}
    assert answer["result"]["typed_output"]["records"] == {"mcp_same_as": "action_result.observations"}
    assert answer["result"]["budget_consumed"] == {"http_requests": 1}
    assert "same idempotency_key" in answer["mcp_view"]["full_view"]


def test_a_large_capability_answer_is_compacted_and_readable_whole_on_a_replay():
    observations = [{"kind": "http.response", "path": f"/{index}", "body": "b" * 20_000} for index in range(12)]
    engine = CapabilityEngine(observations)
    compact = _answer(_call(engine))
    reduced = compact["mcp_view"]["reduced"]
    assert any(key.startswith("action_result.observations") for key in reduced), reduced
    key = compact["mcp_idempotency_key"]
    with pytest.raises(mcp.MCPError, match="replay"):
        _call(engine, view="full", page=2)
    with pytest.raises(mcp.MCPError, match="view=full only"):
        _call(engine, idempotency_key=key, page=2)
    first = _answer(_call(engine, idempotency_key=key, view="full"))
    pages = first["mcp_view"]["pages"]
    assert pages > 1 and "view=full page=2" in first["mcp_view"]["note"]
    assert first["mcp_idempotency_key"] == key
    bodies = 0
    for page in range(1, pages + 1):
        part = _answer(_call(engine, idempotency_key=key, view="full", page=page))
        bodies += sum(1 for item in part["parts"] if str(item["path"]).endswith(".body")
                      or (isinstance(item["value"], dict) and "body" in item["value"]))
    assert bodies >= 12, "every observation is readable whole across the pages"
    sent = [payload for _m, path, payload in engine.calls if path.endswith("/capabilities/http.request")]
    assert all(set(payload) == {"idempotency_key", "input"} for payload in sent), "view and page stay in the adapter"


def test_hunt_query_pages_default_to_twenty():
    class QueryEngine(ManifestHuntClient):
        def request_json(self, method, path, payload=None):
            if path.endswith("/query"):
                self.calls.append((method, path, payload))
                return {"hunt_id": self.HUNT_ID, "kind": "endpoints", "rows": [], "count": 0,
                        "has_more": False, "next_cursor": None}
            return super().request_json(method, path, payload)

    engine = QueryEngine()
    engine.call_tool("shakerscan_hunt_query", {"hunt_id": engine.HUNT_ID, "kind": "endpoints"})
    assert engine.calls[-1][2]["limit"] == 20
    with pytest.raises(mcp.MCPError):
        engine.call_tool("shakerscan_hunt_query", {"hunt_id": engine.HUNT_ID, "kind": "endpoints", "limit": 500})


def test_against_this_engines_own_catalog_findings_are_paged_by_the_engine():
    """The real catalog (api/command_arsenal.py): every list tool's request passes the
    uncatalogued-argument check, and finding.list takes limit and offset."""
    sys.path.insert(0, str(ROOT / "api"))
    import command_arsenal

    real = {command.name: command.parameters_schema for command in command_arsenal.COMMANDS}

    class RealCatalog(Engine):
        def request_json(self, method, path, payload=None):
            if path == "/arsenal/commands":
                return {"commands": [{"name": name, "status": "read_only", "risk_tier": "read_only",
                                      "method": "GET", "parameters_schema": real[name]}
                                     for name in {tool.command for tool in mcp.TOOLS}]}
            return super().request_json(method, path, payload)

    engine = RealCatalog(findings=[_finding(index) for index in range(30)])
    for tool in ("shakerscan_targets", "shakerscan_findings", "shakerscan_evidence_manifest",
                 "shakerscan_timeline", "shakerscan_plans"):
        _answer(engine.call_tool(tool, {"limit": 5}))
    assert ("finding.list", {"limit": 5, "offset": 0}) in engine.executed
