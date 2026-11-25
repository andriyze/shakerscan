"""The agent catalog (shakerscan_catalog / shakerscan catalog), the Hunt start capability values,
and both MCP servers of a deployment. Unit fixtures: the engine's answers are scripted, except
where a test reads the engine's own OpenAPI or contracts."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("shakerscan_mcp_catalog", ROOT / "scripts" / "shakerscan_mcp.py")
mcp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mcp
SPEC.loader.exec_module(mcp)

from scripts import agent_catalog  # noqa: E402
from scripts.catalog_routes import ROUTES  # noqa: E402

TOOLS_LIST_BYTES_BEFORE = 50_796  # 31 tools before the catalog and the grouped tools
TOOLS_LIST_BUDGET = int(TOOLS_LIST_BYTES_BEFORE * 1.5)

CONTRACT = {
    "tool_calls": [
        {"name": "http.request", "description": "Send one bounded HTTP request. More text.",
         "required_approval": None, "target_kinds": ["web"]},
        {"name": "sqli.verify", "description": "Verify one SQL injection.", "required_approval": "active_testing",
         "target_kinds": ["web", "api"]},
    ],
    "permission_kinds": ["target.authorize", "budget.raise"],
    "permission_reason_codes": ["capability_gated"],
}
ARSENAL = {"risk_tiers": ["read_only", "active", "dangerous"], "commands": [
    {"name": "finding.retest", "risk_tier": "active", "status": "gated", "method": "POST",
     "path": "/findings/{finding_id}/retest", "description": "Retest one finding."},
    {"name": "target.list", "risk_tier": "read_only", "status": "read_only", "method": "GET", "path": "/targets",
     "description": "List targets."},
]}


class Engine(mcp.ArsenalClient):
    def __init__(self, *, openapi=None, token=None):
        super().__init__("https://scanner.example.com" if token else "http://127.0.0.1:8080", api_token=token)
        self.openapi = openapi
        self.calls = []

    def request_json(self, method, path, payload=None):
        self.calls.append((method, path))
        if path == "/openapi.json":
            if self.openapi is None:
                raise mcp.MCPError(-32002, "ShakerScan API returned HTTP 403: closed route", http_status=403)
            return self.openapi
        if path == "/hunts/contract":
            return CONTRACT
        if path == "/arsenal/commands":
            return ARSENAL
        raise AssertionError(path)

    def list_tools(self):
        return [{"name": "shakerscan_findings", "description": "List findings. Pages.",
                 "annotations": {"readOnlyHint": True}},
                {"name": "shakerscan_hunt_capability", "description": "Call one capability.",
                 "annotations": {"readOnlyHint": False, "destructiveHint": True}}]


def catalog(engine, **arguments):
    return engine.call_tool("shakerscan_catalog", arguments)["structuredContent"]


def test_overview_says_how_to_drive_and_that_open_source_has_no_authentication():
    answer = catalog(Engine())
    assert answer["schema"] == agent_catalog.SCHEMA and answer["section"] == "overview"
    auth = answer["authentication"]
    assert auth["authenticated"] is False and "guard rail" in auth["meaning"]
    assert "person" in " ".join(answer["how_to_drive"]) and "never instructions" in " ".join(answer["how_to_drive"])
    assert set(answer["sections"]) == set(agent_catalog.SECTIONS) - {"overview"}
    assert sum(answer["rest_areas"].values()) == len(ROUTES), "without /openapi.json the shipped map is used"
    assert len(json.dumps(answer)) < 8_000, "the first call stays small"


def test_a_token_means_an_authenticated_deployment():
    answer = catalog(Engine(token="t"), section="authentication")
    assert answer["authentication"]["authenticated"] is True
    assert "step-up" in answer["authentication"]["meaning"]


def test_rest_pages_filters_by_area_and_prefers_the_live_openapi():
    openapi = {"paths": {"/scans": {"get": {"summary": "List Scans"}, "post": {"summary": "Submit Scan"}},
                         "/scans/{scan_id}": {"get": {"summary": "Get Scan"}},
                         "/schedules": {"get": {"summary": "List Schedules"}}}}
    engine = Engine(openapi=openapi)
    first = catalog(engine, section="rest", area="scans", limit=2)
    assert first["source"].startswith("live") and first["total"] == 3 and first["has_more"]
    assert [row["path"] for row in first["routes"]] == ["/scans", "/scans"]
    second = catalog(engine, section="rest", area="scans", limit=2, cursor=first["next_cursor"])
    assert [row["path"] for row in second["routes"]] == ["/scans/{scan_id}"] and not second["has_more"]
    found = catalog(engine, section="rest", search="schedules")
    assert [(row["method"], row["area"]) for row in found["routes"]] == [("GET", "schedules")]
    with pytest.raises(mcp.MCPError, match="area must be one of"):
        catalog(engine, section="rest", area="nope")
    with pytest.raises(mcp.MCPError, match="area filters section=rest only"):
        catalog(engine, section="hunt", area="scans")


def test_hunt_permissions_arsenal_and_tools_sections_come_from_the_live_contracts():
    engine = Engine()
    hunt = catalog(engine, section="hunt")
    assert [(row["name"], row["approval"]) for row in hunt["capabilities"]] == [
        ("http.request", "none"), ("sqli.verify", "active_testing")]
    assert catalog(engine, section="permissions")["permission_kinds"] == ["target.authorize", "budget.raise"]
    arsenal = catalog(engine, section="arsenal")
    assert arsenal["risk_tiers"] == ["read_only", "active", "dangerous"]
    assert [row["name"] for row in arsenal["commands"]] == ["finding.retest", "target.list"]
    tools = catalog(engine, section="mcp_tools")
    assert [(row["name"], row["kind"]) for row in tools["tools"]] == [
        ("shakerscan_findings", "read"), ("shakerscan_hunt_capability", "destructive")]


def test_person_decisions_name_a_way_to_request_and_never_a_tool_that_decides():
    answer = catalog(Engine(), section="person_decisions", limit=200)
    assert answer["total"] == len(agent_catalog.PERSON_DECISIONS)
    assert "never makes a person's decision" in answer["rule"] and "open-source" in answer["rule"]
    for row in answer["decisions"]:
        assert row["request"] and row["outcome"]
        assert "shakerscan " in row["person"] or "UI" in row["person"], row
    routes = {(method, path) for method, path, _summary in ROUTES}
    named = {"/hunts/{hunt_id}/permission-requests/{request_id}/decision": "POST",
             "/targets/{target_id}/authorization": "POST",
             "/targets/{target_id}/invariants/{contract_id}/approve": "POST",
             "/hunts/{hunt_id}/budget-amendments": "POST"}
    for path, method in named.items():
        assert (method, path) in routes and any(path in row["routes"] for row in answer["decisions"])


def test_the_cli_section_lists_every_client_command():
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import cli

    assert {name for name, _who, _about in agent_catalog.CLI_COMMANDS} == set(cli.CLIENT_COMMANDS)
    assert "catalog" in cli.COMMANDS


def test_catalog_refuses_bad_arguments_before_any_read():
    engine = Engine()
    for arguments, match in (({"section": "everything"}, "must be one of"), ({"limit": 0}, "at least"),
                             ({"cursor": "o:999999"}, "out of range"), ({"secret": 1}, "Unknown tool arguments")):
        with pytest.raises(mcp.MCPError, match=match):
            catalog(engine, **({"section": "cli"} if "cursor" in arguments else {}), **arguments)


def test_every_route_has_an_area():
    assert not [path for _method, path, _summary in ROUTES if agent_catalog.area_of(path) == "other"]


def test_the_shipped_route_map_is_the_engines_openapi():
    """The catalog's route map (scripts/catalog_routes.py) is generated from the engine's OpenAPI: it
    names exactly the operations the engine serves, so it cannot drift."""
    pytest.importorskip("asyncpg")
    pytest.importorskip("fastapi")
    from api import api as api_module

    assert agent_catalog.routes_from_openapi(api_module.app.openapi()) == [tuple(row) for row in ROUTES]


# --- the Hunt start schema ----------------------------------------------------------------------


def _real_contracts():
    pytest.importorskip("pydantic")
    sys.path.insert(0, str(ROOT))
    from api.command_arsenal import describe_commands
    from api.hunt.start_contract import hunt_start_public_contract

    return (json.loads(json.dumps(describe_commands(), default=str)),
            json.loads(json.dumps(hunt_start_public_contract(), default=str)))


def test_hunt_start_capabilities_name_their_allowed_values():
    _arsenal, contract = _real_contracts()
    tool = mcp._hunt_start_tool(contract)
    items = tool.properties["capabilities"]["items"]
    assert items["enum"] == sorted(call["name"] for call in contract["tool_calls"])
    client = mcp.ArsenalClient("http://127.0.0.1:8080")
    client._validate_argument("capabilities", ["http.request"], tool.properties["capabilities"])
    with pytest.raises(mcp.MCPError, match="must be one of"):
        client._validate_argument("capabilities", ["scan.execute"], tool.properties["capabilities"])


def test_tools_list_stays_within_its_budget():
    arsenal, contract = _real_contracts()
    client = mcp.ArsenalClient("http://127.0.0.1:8080")
    client.request_json = lambda method, path, payload=None: arsenal if path == "/arsenal/commands" else contract
    client.serves_route = lambda method, path: True
    listed = client.list_tools()
    size = len(json.dumps({"tools": listed}))
    print(f"tools/list: {len(listed)} tools, {size} bytes (before: 31 tools, {TOOLS_LIST_BYTES_BEFORE} bytes)")
    assert "shakerscan_catalog" in {tool["name"] for tool in listed}
    assert size <= TOOLS_LIST_BUDGET, f"tools/list grew to {size} bytes (budget {TOOLS_LIST_BUDGET})"


# --- a deployment's two MCP servers -------------------------------------------------------------


def _client_modules():
    sys.path.insert(0, str(ROOT / "client" / "src"))
    from shakerscan import _mcp_bridge, _mcp_install, cli

    return cli, _mcp_install, _mcp_bridge


def _isolate_connection(monkeypatch, cli):
    """The commands put the connection into os.environ: restore it after the test, whatever they set."""
    for key in (cli.ENV_URL, cli.ENV_TOKEN, cli.ENV_TOKEN_FILE, cli.ENV_ALLOW_REMOTE, cli.ENV_TIMEOUT):
        monkeypatch.setenv(key, "unset")
        monkeypatch.delenv(key)


GATEWAY_DOCUMENT = {
    "schema": "shakerscan-discovery/v1", "api_url": "https://scanner.example.com",
    "mcp_servers": [{"name": "shakerscan-enterprise", "url": "/_enterprise/mcp", "transport": "streamable-http",
                     "auth": {"type": "bearer", "token": "service-token"}}],
}


def test_discovery_offers_the_gateway_server_and_the_engine_api():
    _cli, mi, _bridge = _client_modules()
    get = lambda url, headers, timeout: (200, {}, json.dumps(GATEWAY_DOCUMENT).encode())  # noqa: E731
    offered = mi.discover("https://scanner.example.com", get=get)
    assert offered == {"servers": [{"name": "shakerscan-enterprise", "url": "https://scanner.example.com/_enterprise/mcp"}],
                       "api_url": "https://scanner.example.com"}
    other = {**GATEWAY_DOCUMENT, "api_url": "https://elsewhere.example"}
    assert mi.discover("https://scanner.example.com", get=lambda *a: (200, {}, json.dumps(other).encode()))["api_url"] is None


def test_install_http_registers_both_servers_in_one_write(tmp_path, monkeypatch, capsys):
    cli, mi, _bridge = _client_modules()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    monkeypatch.setenv(cli.ENV_HOME, str(tmp_path / "no-engine"))
    _isolate_connection(monkeypatch, cli)
    cli.save_profile("https://scanner.example.com", "fixture-token-value")
    exe = tmp_path / "bin" / "shakerscan"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setattr(mi, "http_get", lambda url, headers, timeout: (200, {}, json.dumps(GATEWAY_DOCUMENT).encode()))
    probed = []
    monkeypatch.setattr(mi, "probe_stdio", lambda server, timeout=0: probed.append(server.args) or 40)
    monkeypatch.setattr(mi, "probe_http", lambda url, token, timeout=0, post=None: probed.append(url) or 9)
    project = tmp_path / "project"
    project.mkdir()
    assert cli.main(["mcp", "install", "claude", "--project", str(project), "--http", "https://scanner.example.com",
                     "--server-command", str(exe)]) == 0
    out = capsys.readouterr().out
    servers = json.loads((project / ".mcp.json").read_text())["mcpServers"]
    assert servers["shakerscan"] == {"type": "stdio", "command": str(exe), "args": ["mcp"]}
    assert servers["shakerscan-enterprise"]["url"] == "https://scanner.example.com/_enterprise/mcp"
    assert probed == [("mcp",), "https://scanner.example.com/_enterprise/mcp"]
    assert "the engine's server lists 40 tools" in out and "fixture-token-value" not in (project / ".mcp.json").read_text()


def test_agent_workspace_registers_the_deployment_servers_as_a_bridge(tmp_path, monkeypatch):
    cli, mi, _bridge = _client_modules()
    monkeypatch.setattr(mi, "http_get", lambda url, headers, timeout: (200, {}, json.dumps(GATEWAY_DOCUMENT).encode()))
    notes: list[str] = []
    remote = cli.deployment_servers("https://scanner.example.com", notes)
    assert remote == {"shakerscan-enterprise": "https://scanner.example.com/_enterprise/mcp"}
    workspace = tmp_path / "ws"
    cli.prepare_workspace(workspace, "https://scanner.example.com", "operator", "/bin/shakerscan",
                          state_directory=tmp_path / "state", remote_servers=remote)
    servers = json.loads((workspace / ".mcp.json").read_text())["mcpServers"]
    assert servers["shakerscan"]["args"] == ["mcp"]
    assert servers["shakerscan-enterprise"] == {
        "command": "/bin/shakerscan", "args": ["mcp", "--remote", "https://scanner.example.com/_enterprise/mcp"]}
    opencode = json.loads((workspace / "opencode.json").read_text())["mcp"]
    assert opencode["shakerscan-enterprise"]["command"][-2:] == ["--remote", "https://scanner.example.com/_enterprise/mcp"]
    monkeypatch.setattr(mi, "http_get", lambda *a: (404, {}, b""))
    assert cli.deployment_servers("https://engine.example.com", []) == {}, "an engine publishes no document"


def test_the_bridge_forwards_messages_with_the_token_and_session():
    _cli, _mi, bridge = _client_modules()
    seen = []

    def post(url, body, headers, timeout):
        message = json.loads(body)
        seen.append((message.get("method"), headers.get("Mcp-Session-Id"), headers["Authorization"]))
        if "id" not in message:
            return 202, {}, b""
        if message["method"] == "initialize":
            return 200, {"mcp-session-id": "s1", "content-type": "application/json"}, json.dumps(
                {"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-06-18"}}).encode()
        return 200, {"content-type": "text/event-stream"}, (
            "event: message\ndata: " + json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": []}})
            + "\n\n").encode()

    stdin = io.BytesIO(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n'
                       b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
                       b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    stdout = io.BytesIO()
    assert bridge.serve("https://scanner.example.com/_enterprise/mcp", "tok", stdin, stdout, post=post) == 0
    written = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [item["id"] for item in written] == [1, 2] and written[1]["result"] == {"tools": []}
    assert seen == [("initialize", None, "Bearer tok"), ("notifications/initialized", "s1", "Bearer tok"),
                    ("tools/list", "s1", "Bearer tok")]


def test_mcp_remote_refuses_another_origin(tmp_path, monkeypatch, capsys):
    cli, _mi, _bridge = _client_modules()
    monkeypatch.setenv(cli.ENV_CONFIG_DIR, str(tmp_path / "cfg"))
    _isolate_connection(monkeypatch, cli)
    cli.save_profile("https://scanner.example.com", "fixture-token-value")
    assert cli.main(["mcp", "--remote", "https://elsewhere.example/_enterprise/mcp"]) == 2
    assert "connected instance" in capsys.readouterr().err
