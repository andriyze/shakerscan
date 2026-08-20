import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "shakerscan_mcp.py"
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp", MODULE_PATH)
assert SPEC and SPEC.loader
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)


def _catalog(*, drift_command=None):
    commands = []
    for tool in mcp.TOOLS:
        commands.append({
            "name": tool.command,
            "status": "gated" if tool.command == drift_command else "read_only",
            "risk_tier": "read_only",
            "method": "GET",
            "parameters_schema": tool.properties,
        })
    return {"commands": commands}


class FakeClient(mcp.ArsenalClient):
    def __init__(self, *, drift_command=None):
        super().__init__("http://127.0.0.1:8080")
        self.drift_command = drift_command
        self.calls = []

    def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path == "/arsenal/commands":
            return _catalog(drift_command=self.drift_command)
        assert method == "POST"
        assert path == "/arsenal/execute"
        command = payload["command"]
        return {
            "command": command,
            "dispatched": True,
            "result": {"source": command, "rows": []},
            "action_state": {"catalog_status": "read_only", "risk_tier": "read_only"},
        }


def test_mcp_exposes_only_fixed_read_only_arsenal_commands():
    client = FakeClient()
    descriptors = client.list_tools()

    names = {item["name"] for item in descriptors}
    assert names >= {
        "shakerscan_targets",
        "shakerscan_asm_gaps",
        "shakerscan_findings",
        "shakerscan_evidence_manifest",
        "shakerscan_timeline",
        "shakerscan_plans",
        "shakerscan_tool_status",
    }
    assert {tool.name for tool in mcp.HUNT_TOOLS} <= names
    assert all(item["annotations"]["destructiveHint"] is False for item in descriptors)
    assert all(item["annotations"]["readOnlyHint"] is True for item in descriptors if item["name"] not in {tool.name for tool in mcp.HUNT_TOOLS})
    assert all(tool.command not in {"scan.submit", "asm.improve", "finding.retest"} for tool in mcp.TOOLS)


def test_mcp_catalog_drift_fails_closed():
    client = FakeClient(drift_command="finding.list")

    with pytest.raises(mcp.MCPError) as exc:
        client.list_tools()

    assert exc.value.code == -32006
    assert "no longer read-only" in exc.value.message


def test_mcp_tool_call_revalidates_catalog_and_dispatches_through_arsenal():
    client = FakeClient()

    result = client.call_tool("shakerscan_asm_gaps", {"target_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"})

    assert result["isError"] is False
    assert result["structuredContent"]["source"] == "asm.gaps"
    assert client.calls[-1] == (
        "POST",
        "/arsenal/execute",
        {
            "command": "asm.gaps",
            "parameters": {"target_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"},
            "execute": False,
            "confirmations": [],
            "created_by": "mcp:read_only",
        },
    )


def test_mcp_rejects_unknown_and_missing_arguments_before_dispatch():
    client = FakeClient()

    with pytest.raises(mcp.MCPError) as missing:
        client.call_tool("shakerscan_asm_gaps", {})
    with pytest.raises(mcp.MCPError) as unknown:
        client.call_tool("shakerscan_findings", {"execute": True})

    assert missing.value.code == -32602
    assert unknown.value.code == -32602
    assert not any(path == "/arsenal/execute" for _method, path, _payload in client.calls)


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("shakerscan_timeline", {"limit": 10_000_000}),
        ("shakerscan_plans", {"limit": True}),
        ("shakerscan_findings", {"severity": "urgent"}),
        ("shakerscan_asm_gaps", {"target_id": "not-a-uuid"}),
    ],
)
def test_mcp_enforces_tool_schema_values_before_dispatch(tool, arguments):
    client = FakeClient()

    with pytest.raises(mcp.MCPError) as exc:
        client.call_tool(tool, arguments)

    assert exc.value.code == -32602
    assert not any(path == "/arsenal/execute" for _method, path, _payload in client.calls)


def test_mcp_server_protocol_and_notifications():
    server = mcp.MCPServer(FakeClient())

    initialized = server.handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2024-11-05"},
    })
    notification = server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    assert initialized["result"]["protocolVersion"] == "2024-11-05"
    assert initialized["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert notification is None
    assert len(tools["result"]["tools"]) == 7 + len(mcp.HUNT_TOOLS)


def test_mcp_hunt_tools_wrap_canonical_api_and_validate_ids():
    class HuntClient(FakeClient):
        def request_json(self, method, path, payload=None):
            if path.startswith("/hunts/"):
                self.calls.append((method, path, payload))
                return {"hunt_id": path.split("/")[2], "status": "active"}
            return super().request_json(method, path, payload)

    client = HuntClient()
    hunt_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    result = client.call_tool("shakerscan_hunt_query", {
        "hunt_id": hunt_id, "kind": "endpoints", "limit": 25,
    })

    assert result["structuredContent"]["hunt_id"] == hunt_id
    assert client.calls[-1] == ("POST", f"/hunts/{hunt_id}/query", {"kind": "endpoints", "limit": 25})

    with pytest.raises(mcp.MCPError):
        client.call_tool("shakerscan_hunt_get", {"hunt_id": "not-a-uuid"})


def test_mcp_stdio_emits_only_json_rpc_on_stdout():
    server = mcp.MCPServer(FakeClient())
    stdin = io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
        b'{"jsonrpc":"2.0","id":2,"method":"missing"}\n'
    )
    stdout = io.BytesIO()

    assert mcp.serve(server, stdin, stdout) == 0

    messages = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert messages[0] == {"jsonrpc": "2.0", "id": 1, "result": {}}
    assert messages[1]["error"]["code"] == -32601


def test_mcp_api_origin_is_loopback_by_default_and_has_no_userinfo_or_path():
    assert mcp.normalize_api_url("http://localhost:8080/") == "http://localhost:8080"
    assert mcp.normalize_api_url("https://scanner.example.com", allow_remote=True) == "https://scanner.example.com"

    with pytest.raises(ValueError):
        mcp.normalize_api_url("http://scanner.example.com:8080")
    with pytest.raises(ValueError):
        mcp.normalize_api_url("http://user:pass@localhost:8080")
    with pytest.raises(ValueError):
        mcp.normalize_api_url("http://localhost:8080/api")


def test_scanner_wrapper_routes_mcp_to_the_configured_runtime_bind():
    scanner = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    assert 'export SHAKERSCAN_API_URL="${SHAKERSCAN_API_URL:-$(api_probe_url)}"' in scanner
    assert 'export SHAKERSCAN_MCP_ALLOW_REMOTE_API="${SHAKERSCAN_MCP_ALLOW_REMOTE_API:-true}"' in scanner
