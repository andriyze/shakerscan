#!/usr/bin/env python3
"""MCP stdio adapter over ShakerScan Command Arsenal and canonical Hunt V2.

The adapter has no scanner or database imports. It discovers the live REST
catalog, exposes a fixed subset of read-only commands, and dispatches each call
through POST /arsenal/execute. State-changing Arsenal commands are not representable. Hunt calls
use the target-bound API, which revalidates approvals, scope, capabilities, and budgets.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


SERVER_NAME = "shakerscan"


def _server_version() -> str:
    """Use the same release identity as the installed/source runtime."""
    try:
        version = (Path(__file__).resolve().parents[1] / "VERSION").read_text(
            encoding="utf-8",
        ).strip()
    except OSError:
        return "development"
    return version or "development"


SERVER_VERSION = _server_version()
SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT_SECONDS = 20.0
MAX_REQUEST_BYTES = 256_000
MAX_RESPONSE_BYTES = 2_000_000
DEFAULT_TARGET_PAGE_SIZE = 20
DEFAULT_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$"
DEFAULT_CAPABILITY_PATTERN = r"^[a-z0-9][a-z0-9_.:-]{0,127}$"


def _bounded_text(value: Any, limit: int) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _compact_target_list(payload: dict[str, Any], *, limit: int, offset: int) -> dict[str, Any]:
    rows = payload.get("targets") if isinstance(payload.get("targets"), list) else []
    compact = []
    for raw in rows[:limit]:
        if not isinstance(raw, dict):
            continue
        origins = raw.get("origins") if isinstance(raw.get("origins"), list) else []
        compact.append({
            "id": _bounded_text(raw.get("id"), 64),
            "url": _bounded_text(raw.get("url"), 512),
            "name": _bounded_text(raw.get("name"), 160),
            "root_domain": _bounded_text(raw.get("root_domain"), 255),
            "is_active": bool(raw.get("is_active")),
            "last_scan_id": _bounded_text(raw.get("last_scan_id"), 64),
            "last_scanned_at": _bounded_text(raw.get("last_scanned_at"), 64),
            "last_score": raw.get("last_score"),
            "last_grade": _bounded_text(raw.get("last_grade"), 16),
            "total_scans": raw.get("total_scans"),
            "active_findings_count": raw.get("active_findings_count"),
            "origins": [_bounded_text(value, 512) for value in origins[:8]],
        })
    total = payload.get("total") if isinstance(payload.get("total"), int) else len(compact)
    return {
        "targets": compact,
        "total": total,
        "returned": len(compact),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(compact) < total,
    }


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


@dataclass(frozen=True)
class HuntMCPTool:
    name: str
    method: str
    path_template: str
    description: str
    properties: dict[str, dict[str, Any]]
    required: tuple[str, ...] = ()
    read_only: bool = False
    destructive: bool = False
    idempotent: bool = False
    open_world: bool = False

    def descriptor(self) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "type": "object", "properties": self.properties, "additionalProperties": False,
        }
        if self.required:
            schema["required"] = list(self.required)
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": schema,
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.destructive,
                "idempotentHint": self.idempotent,
                "openWorldHint": self.open_world,
            },
            "_meta": {"shakerscan/api": self.path_template, "shakerscan/maturity": "hunt_v2"},
        }


TOOLS: tuple[MCPTool, ...] = (
    MCPTool(
        name="shakerscan_targets",
        command="target.list",
        description="List configured ShakerScan targets using bounded pagination.",
        properties={
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "offset": {"type": "integer", "minimum": 0, "maximum": 100_000},
            "include_inactive": {"type": "boolean"},
        },
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

HUNT_TOOLS: tuple[HuntMCPTool, ...] = (
    HuntMCPTool(
        "shakerscan_hunt_start", "POST", "/hunts",
        "Start one target-bound Hunt using the live Hunt V2 authority contract.",
        {},
    ),
    HuntMCPTool(
        "shakerscan_hunt_get", "GET", "/hunts/{hunt_id}", "Read a Hunt and its capability manifest.",
        {"hunt_id": {"type": "string", "format": "uuid"}},
        ("hunt_id",), read_only=True, idempotent=True,
    ),
    HuntMCPTool(
        "shakerscan_hunt_query", "POST", "/hunts/{hunt_id}/query", "Query bounded Hunt context.",
        {
            "hunt_id": {"type": "string", "format": "uuid"},
            "kind": {"type": "string", "enum": ["summary", "endpoints", "findings", "principals", "services", "scans", "collections", "candidates", "notes", "receipts"]},
            "filter": {"type": "object"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
        },
        ("hunt_id", "kind"), read_only=True, idempotent=True,
    ),
    HuntMCPTool(
        "shakerscan_hunt_capability", "POST", "/hunts/{hunt_id}/capabilities/{capability_name}",
        "Execute one capability from the Hunt's server-returned manifest.",
        {
            "hunt_id": {"type": "string", "format": "uuid"},
            "capability_name": {
                "type": "string", "minLength": 1, "maxLength": 128,
                "pattern": DEFAULT_CAPABILITY_PATTERN,
            },
            "input": {"type": "object"},
            "idempotency_key": {
                "type": "string", "minLength": 8, "maxLength": 200,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
            },
        },
        ("hunt_id", "capability_name"),
        destructive=True, idempotent=True, open_world=True,
    ),
    HuntMCPTool(
        "shakerscan_hunt_candidate", "POST", "/hunts/{hunt_id}/candidates",
        "Record a non-authoritative, evidence-backed Hunt candidate.",
        {
            "hunt_id": {"type": "string", "format": "uuid"}, "family": {"type": "string"},
            "locus": {"type": "object"}, "title": {"type": "string"}, "claim": {"type": "string"},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
            "evidence_refs": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 100},
            "verifier_contract_id": {"type": "string"},
        },
        ("hunt_id", "family", "locus", "title", "claim", "evidence_refs"),
    ),
    HuntMCPTool(
        "shakerscan_hunt_verify", "POST", "/hunts/{hunt_id}/candidates/{candidate_id}/verify",
        "Request registered deterministic verification for one candidate.",
        {"hunt_id": {"type": "string", "format": "uuid"}, "candidate_id": {"type": "string", "format": "uuid"}},
        ("hunt_id", "candidate_id"),
        destructive=True, open_world=True,
    ),
    HuntMCPTool(
        "shakerscan_hunt_finish", "POST", "/hunts/{hunt_id}/finish", "Finish a Hunt with a debrief.",
        {"hunt_id": {"type": "string", "format": "uuid"}, "summary": {"type": "string"}, "next_actions": {"type": "array", "items": {"type": "string"}, "maxItems": 100}},
        ("hunt_id", "summary"),
    ),
    HuntMCPTool(
        "shakerscan_hunt_cancel", "POST", "/hunts/{hunt_id}/cancel", "Cancel a Hunt.",
        {"hunt_id": {"type": "string", "format": "uuid"}},
        ("hunt_id",), destructive=True,
    ),
)
HUNT_TOOL_BY_NAME = {tool.name: tool for tool in HUNT_TOOLS}


def _positive_int(value: Any, default: int) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else default


def _hunt_start_tool(contract: dict[str, Any]) -> HuntMCPTool:
    """Generate the MCP Hunt-start surface from the server's live authority contract."""
    schema_version = str(contract.get("schema_version") or "").strip()
    target_kinds = contract.get("target_kinds")
    policy_fields = contract.get("policy_fields")
    credential_fields = contract.get("credential_ref_fields")
    profiles = contract.get("budget_profiles")
    dimensions = contract.get("budget_dimensions")
    limits = contract.get("limits") if isinstance(contract.get("limits"), dict) else {}
    patterns = contract.get("patterns") if isinstance(contract.get("patterns"), dict) else {}
    if (
        not schema_version
        or not isinstance(target_kinds, list)
        or not target_kinds
        or not all(isinstance(item, str) and item for item in target_kinds)
        or not isinstance(policy_fields, list)
        or not isinstance(credential_fields, list)
        or not isinstance(profiles, dict)
        or not profiles
        or not isinstance(dimensions, list)
    ):
        raise MCPError(-32005, "Hunt start contract is missing required fields")

    profile_names = sorted(str(name) for name in profiles if str(name))
    profile_ceilings: dict[str, int] = {}
    for raw_profile in profiles.values():
        if not isinstance(raw_profile, dict):
            raise MCPError(-32005, "Hunt budget profile contract is invalid")
        for name, amount in raw_profile.items():
            if isinstance(amount, int) and not isinstance(amount, bool):
                profile_ceilings[str(name)] = max(profile_ceilings.get(str(name), 0), amount)

    budget_properties: dict[str, dict[str, Any]] = {}
    for raw_dimension in dimensions:
        if not isinstance(raw_dimension, dict):
            raise MCPError(-32005, "Hunt budget dimension contract is invalid")
        name = str(raw_dimension.get("name") or "").strip()
        if not name or name not in profile_ceilings:
            raise MCPError(-32005, "Hunt budget dimension has no profile ceiling")
        budget_properties[name] = {
            "type": "integer",
            "minimum": int(raw_dimension.get("minimum") or 0),
            "maximum": profile_ceilings[name],
            "description": str(raw_dimension.get("label") or name),
        }

    identifier_pattern = str(patterns.get("identifier") or DEFAULT_IDENTIFIER_PATTERN)
    capability_pattern = str(patterns.get("capability") or DEFAULT_CAPABILITY_PATTERN)
    identifier_schema = {
        "type": "string", "minLength": 1, "maxLength": 256,
        "pattern": identifier_pattern,
    }
    policy_properties = {
        str(name): (
            dict(identifier_schema)
            if str(name).endswith("_id")
            else {"type": "boolean"}
        )
        for name in policy_fields
    }
    credential_properties = {
        str(name): dict(identifier_schema) for name in credential_fields
    }
    properties: dict[str, dict[str, Any]] = {
        "schema_version": {"type": "string", "enum": [schema_version]},
        "target_id": dict(identifier_schema),
        "target_kind": {"type": "string", "enum": sorted(target_kinds)},
        "goal": {
            "type": "string", "minLength": 1,
            "maxLength": _positive_int(limits.get("goal_chars"), 20_000),
        },
        "budget_profile": {"type": "string", "enum": profile_names},
        "budgets": {
            "type": "object",
            "properties": budget_properties,
            "additionalProperties": False,
        },
        "policy": {
            "type": "object",
            "properties": policy_properties,
            "additionalProperties": False,
        },
        "credential_refs": {
            "type": "object",
            "properties": credential_properties,
            "additionalProperties": False,
            "maxProperties": _positive_int(limits.get("credential_refs"), 16),
        },
        "capabilities": {
            "type": "array",
            "items": {
                "type": "string", "minLength": 1, "maxLength": 128,
                "pattern": capability_pattern,
            },
            "maxItems": _positive_int(limits.get("capabilities"), 128),
            "uniqueItems": True,
        },
        "request_collection_ids": {
            "type": "array",
            "items": dict(identifier_schema),
            "maxItems": _positive_int(limits.get("request_collections"), 32),
            "uniqueItems": True,
        },
    }
    return HuntMCPTool(
        "shakerscan_hunt_start", "POST", "/hunts",
        "Start one target-bound Hunt using the live Hunt V2 authority contract.",
        properties,
        ("schema_version", "target_id", "target_kind", "goal", "budget_profile", "policy"),
    )


def _hunt_tools(contract: dict[str, Any]) -> tuple[HuntMCPTool, ...]:
    return (_hunt_start_tool(contract), *HUNT_TOOLS[1:])


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
        for name, value in arguments.items():
            self._validate_argument(name, value, tool.properties[name])

    @staticmethod
    def _validate_argument(name: str, value: Any, schema: dict[str, Any]) -> None:
        expected = schema.get("type")
        if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
            raise MCPError(-32602, f"Tool argument {name} must be an integer")
        if expected == "string" and not isinstance(value, str):
            raise MCPError(-32602, f"Tool argument {name} must be a string")
        if expected == "boolean" and not isinstance(value, bool):
            raise MCPError(-32602, f"Tool argument {name} must be a boolean")
        if expected == "object" and not isinstance(value, dict):
            raise MCPError(-32602, f"Tool argument {name} must be an object")
        if expected == "array" and not isinstance(value, list):
            raise MCPError(-32602, f"Tool argument {name} must be an array")

        allowed = schema.get("enum")
        if isinstance(allowed, list) and value not in allowed:
            raise MCPError(-32602, f"Tool argument {name} must be one of: {', '.join(map(str, allowed))}")
        if expected == "integer":
            minimum = schema.get("minimum")
            maximum = schema.get("maximum")
            if minimum is not None and value < minimum:
                raise MCPError(-32602, f"Tool argument {name} must be at least {minimum}")
            if maximum is not None and value > maximum:
                raise MCPError(-32602, f"Tool argument {name} must be at most {maximum}")
        if expected == "string":
            minimum = schema.get("minLength")
            maximum = schema.get("maxLength")
            if minimum is not None and len(value) < minimum:
                raise MCPError(-32602, f"Tool argument {name} must contain at least {minimum} character(s)")
            if maximum is not None and len(value) > maximum:
                raise MCPError(-32602, f"Tool argument {name} allows at most {maximum} character(s)")
            pattern = schema.get("pattern")
            if isinstance(pattern, str):
                try:
                    matches = re.fullmatch(pattern, value) is not None
                except re.error as exc:
                    raise MCPError(-32005, f"Live schema for {name} has an invalid pattern") from exc
                if not matches:
                    raise MCPError(-32602, f"Tool argument {name} has an invalid value")
        if schema.get("format") == "uuid" and isinstance(value, str):
            try:
                parsed = uuid.UUID(value)
            except (ValueError, AttributeError):
                raise MCPError(-32602, f"Tool argument {name} must be a UUID") from None
            if str(parsed) != value.lower():
                raise MCPError(-32602, f"Tool argument {name} must use canonical UUID form")
        if expected == "array":
            minimum = schema.get("minItems")
            maximum = schema.get("maxItems")
            if minimum is not None and len(value) < minimum:
                raise MCPError(-32602, f"Tool argument {name} needs at least {minimum} item(s)")
            if maximum is not None and len(value) > maximum:
                raise MCPError(-32602, f"Tool argument {name} allows at most {maximum} item(s)")
            if schema.get("uniqueItems"):
                serialized = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
                if len(serialized) != len(set(serialized)):
                    raise MCPError(-32602, f"Tool argument {name} must not contain duplicate items")
            item_schema = schema.get("items") if isinstance(schema.get("items"), dict) else {}
            for index, item in enumerate(value):
                ArsenalClient._validate_argument(f"{name}[{index}]", item, item_schema)
        if expected == "object":
            properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
            required = schema.get("required") if isinstance(schema.get("required"), list) else []
            unknown = sorted(set(value) - set(properties)) if schema.get("additionalProperties") is False else []
            missing = sorted(set(required) - set(value))
            if unknown:
                raise MCPError(-32602, f"Unknown {name} fields: {', '.join(unknown)}")
            if missing:
                raise MCPError(-32602, f"Missing required {name} fields: {', '.join(missing)}")
            maximum = schema.get("maxProperties")
            if maximum is not None and len(value) > maximum:
                raise MCPError(-32602, f"Tool argument {name} allows at most {maximum} field(s)")
            for key, item in value.items():
                child_schema = properties.get(key)
                if isinstance(child_schema, dict):
                    ArsenalClient._validate_argument(f"{name}.{key}", item, child_schema)

    def hunt_contract(self) -> dict[str, Any]:
        contract = self.request_json("GET", "/hunts/contract")
        # Constructing the generated descriptor is also the fail-closed contract validation.
        _hunt_start_tool(contract)
        return contract

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
        return descriptors + [tool.descriptor() for tool in _hunt_tools(self.hunt_contract())]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        hunt_tool = HUNT_TOOL_BY_NAME.get(name)
        if hunt_tool:
            if name == "shakerscan_hunt_start":
                hunt_tool = _hunt_start_tool(self.hunt_contract())
            unknown = sorted(set(arguments) - set(hunt_tool.properties))
            missing = sorted(set(hunt_tool.required) - set(arguments))
            if unknown:
                raise MCPError(-32602, f"Unknown tool arguments: {', '.join(unknown)}")
            if missing:
                raise MCPError(-32602, f"Missing required tool arguments: {', '.join(missing)}")
            for key, value in arguments.items():
                self._validate_argument(key, value, hunt_tool.properties[key])
            payload = dict(arguments)
            if name == "shakerscan_hunt_start":
                # MCP exposes only the canonical V2 names. Populate optional containers and
                # explicit policy booleans so the REST request is complete and audit-friendly.
                raw_policy = dict(payload.get("policy") or {})
                payload["policy"] = {
                    "active_testing": False,
                    "allow_state_changing_http": False,
                    "network_discovery": False,
                    "allow_oob_interactions": False,
                    "authorization_confirmed": False,
                    **raw_policy,
                }
                payload.setdefault("budgets", {})
                payload.setdefault("credential_refs", {})
                payload.setdefault("capabilities", [])
                payload.setdefault("request_collection_ids", [])
            path = hunt_tool.path_template
            for key in ("hunt_id", "capability_name", "candidate_id"):
                marker = "{" + key + "}"
                if marker in path:
                    path = path.replace(marker, urllib.parse.quote(str(payload.pop(key)), safe=""))
            generated_idempotency_key: str | None = None
            if name == "shakerscan_hunt_capability":
                hunt_id = str(arguments["hunt_id"])
                capability_name = str(arguments["capability_name"])
                hunt = self.request_json("GET", f"/hunts/{urllib.parse.quote(hunt_id, safe='')}")
                if str(hunt.get("status") or "") not in {"active", "awaiting_planner"}:
                    raise MCPError(-32006, f"Hunt is not active (status: {hunt.get('status') or 'unknown'})")
                manifest = hunt.get("capabilities")
                if not isinstance(manifest, list):
                    raise MCPError(-32005, "Hunt capability manifest is missing")
                capability = next((
                    item for item in manifest
                    if isinstance(item, dict) and str(item.get("name") or "") == capability_name
                ), None)
                if capability is None:
                    raise MCPError(-32006, "Capability is not allowed by this Hunt manifest")
                input_schema = capability.get("input_schema")
                if not isinstance(input_schema, dict) or input_schema.get("type") != "object":
                    raise MCPError(-32005, "Hunt capability manifest has an invalid input schema")
                capability_input = payload.get("input") or {}
                self._validate_argument("input", capability_input, input_schema)
                idempotency_key = str(payload.get("idempotency_key") or "").strip()
                if not idempotency_key:
                    idempotency_key = f"mcp-{uuid.uuid4().hex}"
                    generated_idempotency_key = idempotency_key
                payload = {
                    "idempotency_key": idempotency_key,
                    "input": capability_input,
                }
            result = self.request_json(hunt_tool.method, path, payload or None)
            if name == "shakerscan_hunt_capability":
                result = {
                    **result,
                    "mcp_idempotency_key": payload["idempotency_key"],
                    "mcp_generated_idempotency_key": generated_idempotency_key is not None,
                }
            return {
                "content": [{"type": "text", "text": json.dumps(result, sort_keys=True, default=str)}],
                "structuredContent": result,
                "isError": False,
            }
        tool = TOOL_BY_NAME.get(name)
        if not tool:
            raise MCPError(-32602, f"Unknown read-only ShakerScan tool: {name}")
        arguments = dict(arguments)
        if name == "shakerscan_targets":
            arguments.setdefault("limit", DEFAULT_TARGET_PAGE_SIZE)
            arguments.setdefault("offset", 0)
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
        structured = result.get("result")
        if name == "shakerscan_targets" and isinstance(structured, dict):
            structured = _compact_target_list(
                structured,
                limit=int(arguments["limit"]),
                offset=int(arguments["offset"]),
            )
        return {
            "content": [{"type": "text", "text": json.dumps(structured, sort_keys=True, default=str)}],
            "structuredContent": structured,
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
                "instructions": "Read-only inspection plus target-bound Hunt V2. Hunt calls remain subject to server scope, approval, capability, budget, evidence, and proof enforcement.",
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
