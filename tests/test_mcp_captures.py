"""shakerscan_captures: list a target's browser captures and follow one capture's requests.
Unit fixtures: the engine's answers are scripted."""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.parse
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_captures", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

TARGET = "11111111-1111-4111-8111-111111111111"
CAPTURE = "22222222-2222-4222-8222-222222222222"


class Engine(mcp.ArsenalClient):
    def __init__(self, answers):
        super().__init__("http://127.0.0.1:8080")
        self.answers = answers
        self.paths = []

    def request_json(self, method, path, payload=None):
        self.paths.append((method, path))
        route = urllib.parse.urlsplit(path).path
        return self.answers[route](urllib.parse.parse_qs(urllib.parse.urlsplit(path).query))


def call(engine, **arguments):
    return engine.call_tool("shakerscan_captures", arguments)["structuredContent"]


def test_list_filters_captures_and_pages_with_an_adapter_cursor():
    rows = [{"id": f"c{n}", "name": f"Capture {n}", "format": "capture", "metadata_json": {"x": "y"},
             "capture": {"state": "open", "flow_count": n}} for n in range(3)]

    def listed(query):
        offset, limit = int(query["offset"][0]), int(query["limit"][0])
        assert query["source_format"] == ["capture"] and query["target_id"] == [TARGET]
        return {"collections": rows[offset:offset + limit]}

    engine = Engine({"/request-collections": listed})
    first = call(engine, action="list", target_id=TARGET, limit=2)
    assert [row["id"] for row in first["captures"]] == ["c0", "c1"] and first["has_more"]
    assert "metadata_json" not in first["captures"][0] and first["captures"][0]["capture"]["state"] == "open"
    second = call(engine, action="list", target_id=TARGET, limit=2, cursor=first["next_cursor"])
    assert [row["id"] for row in second["captures"]] == ["c2"] and not second["has_more"]
    with pytest.raises(mcp.MCPError, match="other filters"):
        call(engine, action="list", limit=2, cursor=first["next_cursor"])


def test_read_follows_a_capture_with_since_seq_and_keeps_only_masked_index_fields():
    def requests(query):
        assert query["count"] == ["none"] and query["since_seq"] == ["4"] and query["limit"] == ["2"]
        return {"items": [{"seq": 5, "method": "POST", "redacted_url": "https://app/api/login?t=%3Credacted%3E",
                           "normalized_path": "/api/login", "body_field_names": ["password"],
                           "tags": ["capture", "status:200"], "folder": "HAR capture"}],
                "since_seq": 4, "last_seq": 5, "has_more": False, "next_cursor": None,
                "capture": {"state": "open", "flow_count": 5}}

    engine = Engine({f"/request-collections/{CAPTURE}/requests": requests})
    answer = call(engine, action="read", capture_id=CAPTURE, since_seq=4, limit=2)
    assert answer["last_seq"] == 5 and answer["capture"]["state"] == "open"
    assert answer["requests"][0]["seq"] == 5 and "folder" not in answer["requests"][0]
    assert answer["secret_values_visible"] is False


def test_read_refuses_an_engine_without_list_v1_and_bad_arguments():
    engine = Engine({f"/request-collections/{CAPTURE}/requests": lambda query: {"requests": []}})
    with pytest.raises(mcp.MCPError, match="older than 2.11"):
        call(engine, action="read", capture_id=CAPTURE)
    with pytest.raises(mcp.MCPError, match="capture_id"):
        call(engine, action="read")
    with pytest.raises(mcp.MCPError, match="Unknown tool arguments"):
        call(engine, action="read", capture_id=CAPTURE, body=True)
    with pytest.raises(mcp.MCPError):
        call(engine, action="read", capture_id="not-a-uuid")


def test_the_tool_is_listed_read_only():
    descriptor = mcp._captures_descriptor()
    assert descriptor["annotations"]["readOnlyHint"] is True
    assert json.dumps(descriptor).count("since_seq") >= 2
