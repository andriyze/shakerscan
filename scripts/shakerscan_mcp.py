#!/usr/bin/env python3
"""Read-only MCP stdio adapter over ShakerScan Command Arsenal.

The adapter has no scanner or database imports. It discovers the live REST
catalog, exposes a fixed subset of read-only commands, and dispatches each call
through POST /arsenal/execute. State-changing Arsenal commands are intentionally
not representable in this transport.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, BinaryIO


SERVER_NAME = "shakerscan-read-only"
SERVER_VERSION = "2026-07-09.v1"
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_REQUEST_BYTES = 256_000
MAX_RESPONSE_BYTES = 2_000_000


@dataclass(frozen=True)
class MCPTool:
    name: str
    command: str
    description: str
    properties: dict[str, dict[str, Any]]
    required: tuple[str, ...] = ()

    def descriptor(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "type": "object",
            "properties": self.properties,
            "additionalProperties": False,
        }
        if self.required:
            schema["required"] = list(self.required)
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": schema,
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
            "_meta": {
                "shakerscan/command": self.command,
                "shakerscan/maturity": "read_only",
            },
        }


TOOLS: tuple[MCPTool, ...] = (
    MCPTool(
        name="shakerscan_targets",
        command="target.list",
        description="List configured ShakerScan targets.",
        properties={},
    ),
    MCPTool(
        name="shakerscan_asm_gaps",
        command="asm.gaps",
        description="Read Continuous ASM coverage gaps and recommended campaigns for one target.",
        properties={"target_id": {"type": "string", "format": "uuid"}},
        required=("target_id",),
    ),
    MCPTool(
        name="shakerscan_findings",
        command="finding.list",
        description="List findings using optional lifecycle and severity filters.",
        properties={
            "status": {"type": "string", "enum": ["active", "resolved", "false_positive", "accepted_risk"]},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
        },
    ),
    MCPTool(
        name="shakerscan_evidence_manifest",
        command="evidence.export_manifest",
        description="Read a content-free evidence manifest with hashes and retention metadata.",
        properties={
            "finding_id": {"type": "string", "format": "uuid"},
            "scan_id": {"type": "string", "format": "uuid"},
            "retention_class": {
                "type": "string",
                "enum": ["standard", "short", "audit", "legal_hold", "sensitive"],
            },
            "limit": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
    ),
    MCPTool(
        name="shakerscan_timeline",
        command="mission.timeline",
        description="Read the cross-product mission timeline and its explicit execution states.",
        properties={
            "target_id": {"type": "string", "format": "uuid"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 200},
        },
    ),
    MCPTool(
        name="shakerscan_plans",
        command="operation_plan.list",
        description="Read recent validated dry-run OperationPlan records.",
        properties={"limit": {"type": "integer", "minimum": 1, "maximum": 100}},
    ),
    MCPTool(
        name="shakerscan_tool_status",
        command="tool.status",
        description="Read installed, runnable, waived, and catalog-only adapter states without version probes.",
        properties={},
    ),
)

TOOL_BY_NAME = {tool.name: tool for tool in TOOLS}


class MCPError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def normalize_api_url(value: str, *, allow_remote: bool = False) -> str:
    raw = str(value or DEFAULT_API_URL).strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("SHAKERSCAN_API_URL must be an http(s) origin without userinfo")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("SHAKERSCAN_API_URL must not include a path, query, or fragment")
    host = parsed.hostname.lower().rstrip(".")
    if not allow_remote and host not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("remote ShakerScan API origins require SHAKERSCAN_MCP_ALLOW_REMOTE_API=true")
    return raw


class ArsenalClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        self.base_url = base_url
        self.timeout_seconds = max(1.0, min(float(timeout_seconds), 60.0))
        self.max_response_bytes = max(1_024, min(int(max_response_bytes), MAX_RESPONSE_BYTES))
        self.opener = urllib.request.build_opener(_NoRedirect())

    def request_json(self, method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=body,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            raw = exc.read(min(self.max_response_bytes, 64_000))
            detail = raw.decode("utf-8", errors="replace")
            raise MCPError(-32002, f"ShakerScan API returned HTTP {exc.code}", detail[:4_000]) from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise MCPError(-32001, "ShakerScan API is unavailable", str(exc)[:1_000]) from exc
        if len(raw) > self.max_response_bytes:
            raise MCPError(-32003, "ShakerScan API response exceeded the MCP response cap")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MCPError(-32004, "ShakerScan API returned invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise MCPError(-32004, "ShakerScan API response must be a JSON object")
        return decoded

    def catalog(self) -> dict[str, dict[str, Any]]:
        payload = self.request_json("GET", "/arsenal/commands")
        commands = payload.get("commands")
        if not isinstance(commands, list):
            raise MCPError(-32005, "Command Arsenal catalog is missing")
        return {
            str(item.get("name")): item
            for item in commands
            if isinstance(item, dict) and item.get("name")
        }

    def validate_tool(self, tool: MCPTool, arguments: dict[str, Any]) -> None:
        command = self.catalog().get(tool.command)
        if not command:
            raise MCPError(-32005, f"Arsenal command {tool.command} is unavailable")
        if command.get("status") != "read_only" or command.get("risk_tier") != "read_only" or command.get("method") != "GET":
            raise MCPError(-32006, f"Arsenal command {tool.command} is no longer read-only")
        catalog_properties = command.get("parameters_schema") or {}
        if not isinstance(catalog_properties, dict):
            raise MCPError(-32005, f"Arsenal command {tool.command} has an invalid parameter schema")
        unknown = sorted(set(arguments) - set(tool.properties))
        uncatalogued = sorted(set(arguments) - set(catalog_properties))
        missing = sorted(set(tool.required) - set(arguments))
        if unknown:
            raise MCPError(-32602, f"Unknown tool arguments: {', '.join(unknown)}")
        if uncatalogued:
            raise MCPError(-32006, f"Arguments are not present in the live Arsenal contract: {', '.join(uncatalogued)}")
        if missing:
            raise MCPError(-32602, f"Missing required tool arguments: {', '.join(missing)}")

    def list_tools(self) -> list[dict[str, Any]]:
        catalog = self.catalog()
        descriptors = []
        for tool in TOOLS:
            command = catalog.get(tool.command)
            if not command:
                raise MCPError(-32005, f"Arsenal command {tool.command} is unavailable")
            if command.get("status") != "read_only" or command.get("risk_tier") != "read_only" or command.get("method") != "GET":
                raise MCPError(-32006, f"Arsenal command {tool.command} is no longer read-only")
            descriptors.append(tool.descriptor())
        return descriptors

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = TOOL_BY_NAME.get(name)
        if not tool:
            raise MCPError(-32602, f"Unknown read-only ShakerScan tool: {name}")
        self.validate_tool(tool, arguments)
        result = self.request_json("POST", "/arsenal/execute", {
            "command": tool.command,
            "parameters": arguments,
            "execute": False,
            "confirmations": [],
            "created_by": "mcp:read_only",
        })
        if result.get("command") != tool.command or result.get("dispatched") is not True:
            raise MCPError(-32007, "Arsenal did not dispatch the expected read-only command")
        action_state = result.get("action_state") if isinstance(result.get("action_state"), dict) else {}
        if action_state.get("catalog_status") != "read_only" or action_state.get("risk_tier") != "read_only":
            raise MCPError(-32007, "Arsenal response did not preserve the read-only contract")
        return {
            "content": [{"type": "text", "text": json.dumps(result.get("result"), sort_keys=True, default=str)}],
            "structuredContent": result.get("result"),
            "isError": False,
        }


class MCPServer:
    def __init__(self, client: ArsenalClient) -> None:
        self.client = client

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if request.get("jsonrpc") != "2.0":
            raise MCPError(-32600, "Expected JSON-RPC 2.0")
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        if request_id is None and method in {"notifications/initialized", "notifications/cancelled"}:
            return None
        if method == "initialize":
            requested = str(params.get("protocolVersion") or "")
            protocol = requested if requested in SUPPORTED_PROTOCOLS else SUPPORTED_PROTOCOLS[0]
            result = {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "instructions": "Read-only ShakerScan inspection. No scan, retest, replay, policy-write, or other state-changing command is exposed.",
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": self.client.list_tools()}
        elif method == "tools/call":
            name = str(params.get("name") or "")
            arguments = params.get("arguments") or {}
            if not isinstance(arguments, dict):
                raise MCPError(-32602, "Tool arguments must be a JSON object")
            result = self.client.call_tool(name, arguments)
        else:
            raise MCPError(-32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error_response(request_id: Any, error: MCPError) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": error.code, "message": error.message}
    if error.data is not None:
        payload["data"] = error.data
    return {"jsonrpc": "2.0", "id": request_id, "error": payload}


def serve(server: MCPServer, stdin: BinaryIO, stdout: BinaryIO) -> int:
    while True:
        line = stdin.readline(MAX_REQUEST_BYTES + 1)
        if not line:
            return 0
        request_id = None
        try:
            if len(line) > MAX_REQUEST_BYTES or not line.endswith(b"\n"):
                raise MCPError(-32700, "MCP request exceeded the input cap")
            request = json.loads(line.decode("utf-8"))
            if not isinstance(request, dict):
                raise MCPError(-32600, "JSON-RPC request must be an object")
            request_id = request.get("id")
            response = server.handle(request)
            if response is None:
                continue
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            response = _error_response(request_id, MCPError(-32700, "Invalid JSON", str(exc)))
        except MCPError as exc:
            response = _error_response(request_id, exc)
        encoded = json.dumps(response, separators=(",", ":"), default=str).encode("utf-8") + b"\n"
        stdout.write(encoded)
        stdout.flush()


def main() -> int:
    allow_remote = os.environ.get("SHAKERSCAN_MCP_ALLOW_REMOTE_API", "").strip().lower() in {"1", "true", "yes", "on"}
    try:
        base_url = normalize_api_url(os.environ.get("SHAKERSCAN_API_URL", DEFAULT_API_URL), allow_remote=allow_remote)
        timeout = float(os.environ.get("SHAKERSCAN_MCP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    except (TypeError, ValueError) as exc:
        print(f"shakerscan-mcp: {exc}", file=sys.stderr)
        return 2
    server = MCPServer(ArsenalClient(base_url, timeout_seconds=timeout))
    return serve(server, sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
