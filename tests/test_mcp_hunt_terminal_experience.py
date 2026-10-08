"""MCP fixes from live OpenCode Hunt runs (soak reports plan-hunt-main732/maincec, 2026-10-08).

* D11: agents chose ``view: full`` and OpenCode truncated 50-100 KB answers. Compact stays the
  default, the full view is paged under 32 KB, and query pages are cut to fit.
* D12: after a Hunt ended, an MCP replay of an action the server had recorded answered a local
  "Hunt is not active" instead of the recorded result REST returns.
* D13/D27: the candidate tool names the published locus keys, evidence-reference forms and the
  families candidate.verify can prove.
* D17: a redirect is explained, not reported as a bare "HTTP 308".
* ``shakerscan agent --allow``: the launch bounds and the gateway's pre-authorization id ride on
  every Hunt the agent starts; the agent's own ``allow`` stays a proposal.

Unit fixtures: the HTTP layer is the scripted opener from test_mcp_refusal_reasons.
"""

from __future__ import annotations

import io
import json
import urllib.error

import pytest

from tests.test_mcp_refusal_reasons import HUNT, HUNT_RECORD, _client, mcp

CONTRACT = {
    "schema_version": "hunt-start/v2", "target_kinds": ["web"], "policy_fields": ["active_testing"],
    "credential_ref_fields": [], "budget_profiles": {"balanced": {"max_http_requests": 5000}},
    "budget_dimensions": [{"name": "max_http_requests", "minimum": 1}], "limits": {"allow": 32},
    "allow_bounds": {"grammar": ["budget.raise:<N>x"]},
    "candidates": {
        "locus_keys": {"path": "concrete request path", "route": "route template", "paths": "set of paths",
                       "method": "HTTP method"},
        "locus_set_keys": ["paths"], "max_locus_keys": 32,
        "verification_route_keys": ["route", "url", "path"],
        "evidence_ref_forms": ["<uuid>", "action:<uuid>", "receipt:<uuid>", "transaction:<uuid>"],
        "verification": {"verifiable_families": ["access_control", "bola", "data_exposure"],
                         "family_aliases": {"idor": "bola"}},
    },
}


def _big_record() -> dict:
    return {
        "hunt_id": HUNT, "status": "active", "target_kind": "web",
        "capabilities": [{"name": f"web.cap{i}", "input_schema": {"type": "object", "properties": {"x": {"type": "string"}}},
                          "output_contract": "o" * 2_000} for i in range(40)],
        "context_pack": {"prior_knowledge": ["k" * 1_000] * 30},
        "actions": [{"action_id": f"a{i}", "status": "completed", "result": "r" * 900} for i in range(40)],
        "budget": {"max_http_requests": 5000},
    }


class Recorded(mcp.ArsenalClient):
    def __init__(self, answer):
        super().__init__("http://127.0.0.1:8080")
        self.answer = answer
        self.sent = []

    def request_json(self, method, path, payload=None):
        self.sent.append((method, path, payload, dict(mcp._EXTRA_HEADERS.get() or {})))
        return self.answer(method, path, payload) if callable(self.answer) else self.answer

    def hunt_contract(self):
        return CONTRACT


def _put(record: dict, path: str, value) -> None:
    """Place one part by its path (``a.b[3].c``) -- how a reader rebuilds the record."""
    import re
    tokens = [int(index) if index else key for key, index in re.findall(r"([^.\[\]]+)|\[(\d+)\]", path)]
    node = record
    for here, after in zip(tokens, tokens[1:]):
        if isinstance(here, int):
            while len(node) <= here:
                node.append([] if isinstance(after, int) else {})
            node = node[here]
        else:
            node = node.setdefault(here, [] if isinstance(after, int) else {})
    last = tokens[-1]
    if isinstance(last, int):
        while len(node) <= last:
            node.append(None)
        node[last] = value
    else:
        node[last] = value


def test_the_full_view_is_paged_under_the_output_limit_and_reassembles_the_record():
    record = _big_record()
    assert len(json.dumps(record)) > 100_000
    client = Recorded(record)
    first = client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "view": "full"})
    pages = first["structuredContent"]["mcp_view"]["pages"]
    assert pages > 1
    rebuilt: dict = {}
    for page in range(1, pages + 1):
        answer = client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "view": "full", "page": page})
        assert len(answer["content"][0]["text"]) <= mcp.FULL_VIEW_PAGE_BYTES
        body = answer["structuredContent"]
        assert body["mcp_view"]["page"] == page and body["hunt_id"] == HUNT and body["status"] == "active"
        for part in body["parts"]:
            _put(rebuilt, part["path"], part["value"])
    assert rebuilt == record
    with pytest.raises(mcp.MCPError, match="past the last page"):
        client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT, "view": "full", "page": pages + 1})


def test_lifecycle_tools_still_answer_compactly_and_point_full_pages_at_hunt_get():
    client = Recorded(_big_record())
    compact = client.call_tool("shakerscan_hunt_finish", {"hunt_id": HUNT, "summary": "done"})
    assert compact["structuredContent"]["mcp_view"]["view"] == "compact"
    full = client.call_tool("shakerscan_hunt_finish", {"hunt_id": HUNT, "summary": "done", "view": "full"})
    assert "shakerscan_hunt_get" in full["structuredContent"]["mcp_view"]["note"]
    assert "page" not in mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_finish"].properties, (
        "paging a finish would repeat it; only shakerscan_hunt_get pages"
    )
    assert "avoid it" in mcp.VIEW_PROPERTY["description"]


def test_a_query_page_defaults_small_and_is_cut_to_fit():
    rows = [{"id": f"row-{i}", "evidence": "e" * 3_000} for i in range(40)]
    client = Recorded({"ok": True, "kind": "candidates", "count": 40, "rows": rows, "has_more": True,
                       "next_cursor": "opaque"})
    answer = client.call_tool("shakerscan_hunt_query", {"hunt_id": HUNT, "kind": "candidates"})
    (_method, _path, payload, _headers), = client.sent
    assert payload["limit"] == mcp.DEFAULT_QUERY_LIMIT
    body = answer["structuredContent"]
    assert len(answer["content"][0]["text"]) <= mcp.FULL_VIEW_PAGE_BYTES
    assert body["next_cursor"] is None and body["has_more"] is True
    assert body["mcp_view"]["rows_returned"] == len(body["rows"]) < 40
    assert f"limit={len(body['rows'])}" in body["mcp_view"]["note"]


def test_a_same_key_replay_after_the_hunt_ended_returns_the_recorded_action():
    """D12: REST replays the recorded action; MCP used to refuse locally with no action id."""
    path = f"/hunts/{HUNT}/capabilities/web.crawl"
    recorded = {"action_result": {"action_id": "a-1", "status": "completed"}, "idempotent_replay": True}
    client = _client({("GET", f"/hunts/{HUNT}"): {**HUNT_RECORD, "status": "cancelled"}, ("POST", path): recorded})
    result = client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": "key-before-cancel",
    })["structuredContent"]
    assert result["action_result"]["action_id"] == "a-1" and result["idempotent_replay"] is True
    # Without a key of its own the agent cannot be replaying anything: refused locally, with the hint.
    with pytest.raises(mcp.MCPError, match="call again with its idempotency_key"):
        client.call_tool("shakerscan_hunt_capability", {"hunt_id": HUNT, "capability_name": "web.crawl", "input": {}})


def test_a_new_key_on_an_ended_hunt_is_the_servers_refusal():
    path = f"/hunts/{HUNT}/capabilities/web.crawl"
    refusal = (409, {"detail": "Hunt is not active (status: completed)"})
    client = _client({("GET", f"/hunts/{HUNT}"): {**HUNT_RECORD, "status": "completed"}, ("POST", path): refusal})
    with pytest.raises(mcp.MCPError) as refused:
        client.call_tool("shakerscan_hunt_capability", {
            "hunt_id": HUNT, "capability_name": "web.crawl", "input": {}, "idempotency_key": "key-after-finish",
        })
    assert refused.value.data["outcome"] == "refused" and refused.value.data["http_status"] == 409


def test_the_candidate_tool_names_locus_keys_evidence_forms_and_verifiable_families():
    tools = {tool.name: tool for tool in mcp._hunt_tools(CONTRACT)}
    candidate = tools["shakerscan_hunt_candidate"].descriptor()
    schema = candidate["inputSchema"]["properties"]
    assert set(schema["locus"]["properties"]) == {"path", "route", "paths", "method"}
    assert schema["locus"]["properties"]["paths"]["type"] == "array"
    assert "route, url, path" in schema["locus"]["description"]
    assert "transaction:<uuid>" in schema["evidence_refs"]["description"]
    assert "access_control, bola, data_exposure" in schema["family"]["description"]
    assert "idor->bola" in schema["family"]["description"]
    assert "do not call candidate.verify" in schema["family"]["description"]
    assert "Verifiable families: access_control, bola, data_exposure" in candidate["description"]
    # An engine that publishes none of it keeps the plain schema.
    plain = {tool.name: tool for tool in mcp._hunt_tools({**CONTRACT, "candidates": {}})}
    assert plain["shakerscan_hunt_candidate"] == mcp.HUNT_TOOL_BY_NAME["shakerscan_hunt_candidate"]


def test_a_redirect_names_the_https_origin_and_the_option_that_sets_it():
    """D17: a bare "HTTP 308" left agents and people guessing."""
    redirect = urllib.error.HTTPError(
        "http://127.0.0.1:8080/hunts", 308, "Permanent Redirect",
        {"Location": "https://127.0.0.1:8080/hunts"}, io.BytesIO(b""),
    )
    client = _client({("GET", f"/hunts/{HUNT}"): redirect})
    with pytest.raises(mcp.MCPError) as refused:
        client.call_tool("shakerscan_hunt_get", {"hunt_id": HUNT})
    message = refused.value.message
    assert message.startswith("ShakerScan API returned HTTP 308: the instance answered HTTP 308 with a redirect")
    assert "served over HTTPS at https://127.0.0.1:8080" in message
    assert "shakerscan connect https://127.0.0.1:8080" in message and "shakerscan mcp --url" in message


def _start(client, **extra):
    return client.call_tool("shakerscan_hunt_start", {
        "schema_version": "hunt-start/v2", "target_id": "t1", "target_kind": "web", "goal": "g",
        "budget_profile": "balanced", "policy": {}, **extra,
    })


def test_launch_bounds_and_their_preauthorization_ride_on_every_start(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_HUNT_ALLOW", json.dumps(["budget.raise:2x", "capability:state-changing"]))
    monkeypatch.setenv("SHAKERSCAN_PREAUTHORIZATION_ID", "pre_0001")
    client = Recorded({"hunt_id": HUNT, "status": "active", "capabilities": []})
    _start(client, allow=["target.authorize:api.example.com"])
    (_method, path, payload, headers), = client.sent
    assert path == "/hunts"
    assert payload["allow"] == ["budget.raise:2x", "capability:state-changing"], "the person's launch bounds"
    assert payload["proposed_allow"] == ["target.authorize:api.example.com"], "the agent's stay a proposal"
    assert headers == {"X-ShakerScan-Preauthorization": "pre_0001"}


def test_without_launch_bounds_a_start_carries_no_allow_and_no_header(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HUNT_ALLOW", raising=False)
    monkeypatch.delenv("SHAKERSCAN_PREAUTHORIZATION_ID", raising=False)
    client = Recorded({"hunt_id": HUNT, "status": "active", "capabilities": []})
    _start(client)
    (_method, _path, payload, headers), = client.sent
    assert "allow" not in payload and headers == {}


def test_a_start_with_proposed_bounds_tells_the_agent_which_approve_to_ask_for(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_HUNT_ALLOW", raising=False)
    pending = [{"id": "req-1", "kind": "preauthorization", "title": "Pre-authorize the bounds the agent proposed",
                "approve_command": "shakerscan approve req-1"}]
    client = Recorded({"hunt_id": HUNT, "status": "active", "capabilities": [],
                       "pending_permission_requests": pending,
                       "budget_warnings": [{"code": "budget_below_mapping_minimum", "message": "too small"}]})
    result = _start(client, allow=["budget.raise:2x"])["structuredContent"]
    assert "run `shakerscan approve req-1`" in result["mcp_permission_requests"]
    assert "you cannot approve" in result["mcp_permission_requests"]
    assert result["budget_warnings"][0]["code"] == "budget_below_mapping_minimum", "warnings survive the compact view"


def test_the_start_tool_steers_budgets_to_the_profile_defaults():
    tool = mcp._hunt_start_tool(CONTRACT)
    assert "never lower max_http_requests below what discovery needs" in tool.properties["budgets"]["description"].replace("Never", "never")
    assert "budget_warnings" in tool.description
