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


def _hunt_contract():
    budget = {
        "max_duration_seconds": 900,
        "max_capability_calls": 20,
        "max_http_requests": 500,
        "max_active_actions": 4,
        "max_candidates": 20,
        "max_verifications": 4,
        "max_tcp_ports": 100,
        "max_browser_actions": 20,
        "max_state_changing_requests": 4,
        "max_device_fragility_points": 20,
        "max_hosts": 50,
        "max_udp_ports": 100,
        "max_oob_interactions": 10,
    }
    return {
        "schema_version": "hunt-start/v2",
        "budget_schema_version": "hunt-budget/v3",
        "target_kinds": ["api", "device", "network", "web"],
        "policy_fields": [
            "active_testing", "allow_oob_interactions", "allow_state_changing_http",
            "approval_receipt_id", "authorization_confirmed", "network_discovery",
            "scope_receipt_id",
        ],
        "credential_ref_fields": [
            "authorization_header_credential_id", "cookie_credential_id",
            "oauth_credential_profile_id", "primary_credential_profile_id",
            "secondary_credential_profile_id", "service_credential_profile_id",
            "ssh_credential_profile_id", "web_credential_profile_id",
        ],
        "limits": {
            "goal_chars": 20_000, "capabilities": 128,
            "request_collections": 32, "credential_refs": 16,
            "skill_ids": 4,
        },
        "patterns": {
            "identifier": r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$",
            "capability": r"^[a-z0-9][a-z0-9_.:-]{0,127}$",
            "skill_id": r"^[a-z0-9][a-z0-9_.:-]{0,159}$",
        },
        "budget_profiles": {
            "fast": budget,
            "balanced": {key: value * 2 for key, value in budget.items()},
            "thorough": {key: value * 4 for key, value in budget.items()},
        },
        "budget_dimensions": [
            {"name": key, "label": key.replace("_", " ").title(), "minimum": 0}
            for key in budget
        ],
        "policy_derived_zeros": {},
    }


class FakeClient(mcp.ArsenalClient):
    def __init__(self, *, drift_command=None):
        super().__init__("http://127.0.0.1:8080")
        self.drift_command = drift_command
        self.calls = []

    def request_json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if path == "/arsenal/commands":
            return _catalog(drift_command=self.drift_command)
        if path == "/hunts/contract":
            assert method == "GET"
            return _hunt_contract()
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
    assert all(item["annotations"]["readOnlyHint"] is True for item in descriptors if item["name"] not in {tool.name for tool in mcp.HUNT_TOOLS})
    assert all(tool.command not in {"scan.submit", "asm.improve", "finding.retest"} for tool in mcp.TOOLS)

    annotations = {item["name"]: item["annotations"] for item in descriptors}
    assert annotations["shakerscan_hunt_start"] == {
        "readOnlyHint": False, "destructiveHint": False,
        "idempotentHint": False, "openWorldHint": False,
    }
    assert annotations["shakerscan_hunt_get"]["readOnlyHint"] is True
    assert annotations["shakerscan_hunt_query"]["idempotentHint"] is True
    assert annotations["shakerscan_hunt_capability"] == {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": True, "openWorldHint": True,
    }
    assert annotations["shakerscan_hunt_verify"]["openWorldHint"] is True
    assert annotations["shakerscan_hunt_candidate_update"]["destructiveHint"] is True
    assert annotations["shakerscan_hunt_candidate_delete"] == {
        "readOnlyHint": False, "destructiveHint": True,
        "idempotentHint": True, "openWorldHint": False,
    }
    assert annotations["shakerscan_hunt_cancel"]["destructiveHint"] is True

    start = next(item for item in descriptors if item["name"] == "shakerscan_hunt_start")
    schema = start["inputSchema"]
    assert schema["required"] == [
        "schema_version", "target_id", "target_kind", "goal", "budget_profile", "policy",
    ]
    assert schema["properties"]["target_kind"]["enum"] == ["api", "device", "network", "web"]
    assert "max_http_requests" in schema["properties"]["budgets"]["properties"]
    assert "primary_credential_profile_id" in schema["properties"]["credential_refs"]["properties"]
    assert schema["properties"]["request_collection_ids"]["maxItems"] == 32
    assert schema["properties"]["skill_ids"]["maxItems"] == 4
    assert annotations["shakerscan_hunt_skills"]["readOnlyHint"] is True
    assert annotations["shakerscan_hunt_skill"]["idempotentHint"] is True


def test_mcp_hunt_methodology_catalog_and_detail_are_read_only_gets():
    class SkillClient(FakeClient):
        def request_json(self, method, path, payload=None):
            if path.startswith("/hunt/skills"):
                self.calls.append((method, path, payload))
                return {"path": path}
            return super().request_json(method, path, payload)

    client = SkillClient()
    catalog = client.call_tool("shakerscan_hunt_skills", {
        "target_kind": "web", "support": "supported",
        "goal": "Cloudflare origin exposure",
    })
    detail = client.call_tool("shakerscan_hunt_skill", {
        "skill_id": "skill.web.edge-waf-and-origin-exposure-validation",
        "include_methodology": True,
    })

    assert catalog["structuredContent"]["path"].startswith("/hunt/skills?")
    assert "goal=Cloudflare+origin+exposure" in catalog["structuredContent"]["path"]
    assert detail["structuredContent"]["path"].endswith("?include_methodology=true")
    assert all(call[0] == "GET" and call[2] is None for call in client.calls[-2:])


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


def test_mcp_target_list_defaults_to_bounded_compact_pagination():
    class TargetClient(FakeClient):
        def request_json(self, method, path, payload=None):
            if path == "/arsenal/execute":
                self.calls.append((method, path, payload))
                return {
                    "command": "target.list",
                    "dispatched": True,
                    "result": {
                        "total": 35,
                        "targets": [{
                            "id": "target-1",
                            "url": "https://" + "a" * 4_000,
                            "name": "n" * 1_000,
                            "root_domain": "example.com",
                            "is_active": True,
                            "metadata_json": "secret-or-bulk-metadata",
                            "canonical_key": "c" * 4_000,
                            "origins": ["https://example.com"] * 20,
                        }],
                    },
                    "action_state": {"catalog_status": "read_only", "risk_tier": "read_only"},
                }
            return super().request_json(method, path, payload)

    client = TargetClient()
    result = client.call_tool("shakerscan_targets", {})

    assert client.calls[-1][2]["parameters"] == {"limit": 20, "offset": 0}
    assert result["structuredContent"]["has_more"] is True
    assert result["structuredContent"]["returned"] == 1
    target = result["structuredContent"]["targets"][0]
    assert len(target["url"]) == 512
    assert len(target["name"]) == 160
    assert "metadata_json" not in target
    assert "canonical_key" not in target
    assert len(target["origins"]) == 8


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
    cancelled = server.handle({
        "jsonrpc": "2.0",
        "method": "notifications/cancelled",
        "params": {"requestId": 99, "reason": "client no longer needs the result"},
    })
    tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    assert initialized["result"]["protocolVersion"] == "2024-11-05"
    assert initialized["result"]["capabilities"] == {"tools": {"listChanged": False}}
    assert initialized["result"]["serverInfo"]["version"] == (ROOT / "VERSION").read_text().strip()
    assert notification is None
    assert cancelled is None
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

    candidate_id = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    client.call_tool("shakerscan_hunt_candidate_update", {
        "hunt_id": hunt_id, "candidate_id": candidate_id, "title": "Corrected",
    })
    assert client.calls[-1] == (
        "PATCH", f"/hunts/{hunt_id}/candidates/{candidate_id}", {"title": "Corrected"},
    )
    client.call_tool("shakerscan_hunt_candidate_delete", {
        "hunt_id": hunt_id, "candidate_id": candidate_id,
    })
    assert client.calls[-1] == (
        "DELETE", f"/hunts/{hunt_id}/candidates/{candidate_id}", None,
    )

    with pytest.raises(mcp.MCPError):
        client.call_tool("shakerscan_hunt_get", {"hunt_id": "not-a-uuid"})


def test_mcp_hunt_start_dispatches_complete_canonical_v2_request():
    class HuntClient(FakeClient):
        def request_json(self, method, path, payload=None):
            if path == "/hunts":
                self.calls.append((method, path, payload))
                return {"hunt_id": "hunt-1", "status": "active"}
            return super().request_json(method, path, payload)

    client = HuntClient()
    result = client.call_tool("shakerscan_hunt_start", {
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Inspect the authorized web target.",
        "budget_profile": "fast",
        "policy": {},
    })

    assert result["structuredContent"]["status"] == "active"
    assert client.calls[-1] == (
        "POST", "/hunts", {
            "schema_version": "hunt-start/v2",
            "target_id": "target-1",
            "target_kind": "web",
            "goal": "Inspect the authorized web target.",
            "budget_profile": "fast",
            "policy": {
                "active_testing": False,
                "allow_state_changing_http": False,
                "network_discovery": False,
                "allow_oob_interactions": False,
                "authorization_confirmed": False,
            },
            "budgets": {},
            "credential_refs": {},
                "capabilities": [],
                "request_collection_ids": [],
                "skill_ids": [],
            },
        )


@pytest.mark.parametrize(
    "update",
    [
        {"objective": "stale alias"},
        {"policy": {"active_testing": "yes"}},
        {"credential_refs": {"password": "secret"}},
        {"budgets": {"unknown_budget": 1}},
        {"request_collection_ids": ["collection-1", "collection-1"]},
    ],
)
def test_mcp_hunt_start_rejects_contract_drift_and_invalid_nested_values(update):
    payload = {
        "schema_version": "hunt-start/v2",
        "target_id": "target-1",
        "target_kind": "web",
        "goal": "Inspect the authorized web target.",
        "budget_profile": "fast",
        "policy": {},
    }
    payload.update(update)
    client = FakeClient()

    with pytest.raises(mcp.MCPError) as exc:
        client.call_tool("shakerscan_hunt_start", payload)

    assert exc.value.code == -32602
    assert not any(path == "/hunts" for _method, path, _payload in client.calls)


class ManifestHuntClient(FakeClient):
    HUNT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

    def __init__(self, *, status="active", capabilities=None):
        super().__init__()
        self.status = status
        self.capabilities = capabilities if capabilities is not None else [{
            "name": "http.request",
            "risk_tier": "active",
            "input_schema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "HEAD"]},
                    "path": {"type": "string", "minLength": 1, "maxLength": 4000},
                },
                "required": ["method", "path"],
                "additionalProperties": False,
            },
        }]
        self.action_by_key = {}

    def request_json(self, method, path, payload=None):
        if path == f"/hunts/{self.HUNT_ID}" and method == "GET":
            self.calls.append((method, path, payload))
            return {
                "hunt_id": self.HUNT_ID,
                "status": self.status,
                "capabilities": self.capabilities,
            }
        if path == f"/hunts/{self.HUNT_ID}/capabilities/http.request":
            self.calls.append((method, path, payload))
            key = payload["idempotency_key"]
            action_id = self.action_by_key.setdefault(key, f"action-{len(self.action_by_key) + 1}")
            return {
                "hunt_id": self.HUNT_ID,
                "capability": "http.request",
                "action_id": action_id,
                "idempotent_replay": sum(
                    1 for call in self.calls
                    if call[1] == path and call[2]["idempotency_key"] == key
                ) > 1,
                "status": "completed",
            }
        return super().request_json(method, path, payload)


def test_mcp_hunt_capability_validates_manifest_and_generates_a_returned_idempotency_key():
    client = ManifestHuntClient()
    result = client.call_tool("shakerscan_hunt_capability", {
        "hunt_id": client.HUNT_ID,
        "capability_name": "http.request",
        "input": {"method": "GET", "path": "/rest/products"},
    })

    structured = result["structuredContent"]
    assert structured["action_id"] == "action-1"
    assert structured["mcp_generated_idempotency_key"] is True
    assert structured["mcp_idempotency_key"].startswith("mcp-")
    assert client.calls[-1][2] == {
        "idempotency_key": structured["mcp_idempotency_key"],
        "input": {"method": "GET", "path": "/rest/products"},
    }


def test_mcp_hunt_capability_replays_with_the_same_caller_key():
    client = ManifestHuntClient()
    arguments = {
        "hunt_id": client.HUNT_ID,
        "capability_name": "http.request",
        "idempotency_key": "mcp-client-operation-1",
        "input": {"method": "HEAD", "path": "/"},
    }

    first = client.call_tool("shakerscan_hunt_capability", arguments)
    second = client.call_tool("shakerscan_hunt_capability", arguments)

    assert first["structuredContent"]["action_id"] == second["structuredContent"]["action_id"]
    assert second["structuredContent"]["idempotent_replay"] is True
    assert second["structuredContent"]["mcp_generated_idempotency_key"] is False


@pytest.mark.parametrize(
    ("client", "arguments", "message"),
    [
        (
            ManifestHuntClient(status="completed"),
            {"capability_name": "http.request", "input": {"method": "GET", "path": "/"}},
            "not active",
        ),
        (
            ManifestHuntClient(capabilities=[]),
            {"capability_name": "http.request", "input": {"method": "GET", "path": "/"}},
            "not allowed",
        ),
        (
            ManifestHuntClient(),
            {"capability_name": "http.request", "input": {"method": "POST", "path": "/"}},
            "one of",
        ),
        (
            ManifestHuntClient(),
            {"capability_name": "http.request", "input": {"method": "GET", "path": "/", "url": "https://other.example"}},
            "Unknown input fields",
        ),
    ],
)
def test_mcp_hunt_capability_fails_closed_before_execution(client, arguments, message):
    with pytest.raises(mcp.MCPError) as exc:
        client.call_tool("shakerscan_hunt_capability", {
            "hunt_id": client.HUNT_ID,
            **arguments,
        })

    assert message in exc.value.message
    assert not any("/capabilities/" in path for _method, path, _payload in client.calls)


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
