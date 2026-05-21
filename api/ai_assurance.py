"""AI assurance inventory, protocol readiness, and blast-radius helpers."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


AI_PATH_HINTS: tuple[tuple[str, str, float], ...] = (
    ("mcp_trace", r"(^|[/_.-])mcp([/_.-]|$)", 0.90),
    ("agent_trace", r"(^|[/_.-])(agent|agents|tool|tools|trace|workflow|run)([/_.-]|$)", 0.78),
    ("rag", r"(^|[/_.-])(rag|retrieval|retrieve|answer|ask|query|vector|embedding|search)([/_.-]|$)", 0.74),
    ("api_chat", r"(^|[/_.-])(chat|completion|completions|responses|assistant|assistants|message|messages|prompt|llm)([/_.-]|$)", 0.70),
)

AI_FIELD_HINTS = {
    "prompt",
    "message",
    "messages",
    "model",
    "assistant",
    "session",
    "session_id",
    "thread_id",
    "embedding",
    "embeddings",
    "retrieval",
    "vector",
    "tool",
    "tools",
    "jsonrpc",
}

AI_PROVIDER_HINTS = (
    "openai",
    "anthropic",
    "bedrock",
    "vertexai",
    "azure-openai",
    "azure_ai",
    "langchain",
    "langgraph",
    "llamaindex",
    "litellm",
    "ollama",
)

HIGH_RISK_SCOPE_HINTS = (
    "admin",
    "write",
    "delete",
    "refund",
    "payment",
    "transfer",
    "execute",
    "shell",
    "deploy",
    "iam",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _json_path_get(container: dict[str, Any], *path: str) -> Any:
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def _stable_id(*parts: Any) -> str:
    raw = "|".join(str(part or "") for part in parts)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:16]


def _normalize_url(base_url: str | None, value: str | None) -> str | None:
    if not value:
        return None
    value_s = str(value).strip()
    if not value_s:
        return None
    if value_s.startswith(("http://", "https://")):
        return value_s
    if base_url:
        return urllib.parse.urljoin(base_url if base_url.endswith("/") else f"{base_url}/", value_s.lstrip("/"))
    return value_s


def _path_from_url(value: str | None) -> str:
    if not value:
        return ""
    try:
        parsed = urllib.parse.urlparse(value if "://" in value else f"https://placeholder.local/{value.lstrip('/')}")
        return parsed.path or "/"
    except Exception:
        return str(value)


def infer_ai_target_type(
    url: str | None,
    *,
    method: str | None = None,
    fields: list[Any] | None = None,
    source: str | None = None,
) -> tuple[str | None, float, list[str]]:
    """Infer whether an endpoint looks like an AI surface and what type it is."""
    path = _path_from_url(url).lower()
    haystack = path.replace("-", "_")
    evidence: list[str] = []
    best_type: str | None = None
    best_confidence = 0.0

    for target_type, pattern, confidence in AI_PATH_HINTS:
        if re.search(pattern, haystack, re.I):
            best_type = target_type
            best_confidence = max(best_confidence, confidence)
            evidence.append(f"path:{target_type}")
            break

    field_names = {str(item).strip().lower() for item in (fields or []) if str(item).strip()}
    field_hits = sorted(field_names & AI_FIELD_HINTS)
    if field_hits:
        evidence.append(f"fields:{','.join(field_hits[:6])}")
        best_confidence = max(best_confidence, 0.68)
        if not best_type:
            if {"tool", "tools", "jsonrpc"} & set(field_hits):
                best_type = "mcp_trace" if "jsonrpc" in field_hits else "agent_trace"
            elif {"retrieval", "vector", "embedding", "embeddings"} & set(field_hits):
                best_type = "rag"
            else:
                best_type = "api_chat"

    provider_hit = next((hint for hint in AI_PROVIDER_HINTS if hint in haystack), None)
    if provider_hit:
        evidence.append(f"provider_hint:{provider_hit}")
        best_confidence = max(best_confidence, 0.64)
        best_type = best_type or "api_chat"

    if str(method or "").upper() == "POST" and best_type:
        best_confidence = min(0.99, best_confidence + 0.04)
        evidence.append("method:POST")

    if source in {"openapi", "browser_network", "har_network_capture"} and best_type:
        best_confidence = min(0.99, best_confidence + 0.05)
        evidence.append(f"source:{source}")

    if not best_type or best_confidence < 0.60:
        return None, best_confidence, evidence
    return best_type, round(best_confidence, 2), evidence


def _default_request_template(target_type: str) -> dict[str, Any]:
    if target_type == "mcp_trace":
        return {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {"prompt": "{{prompt}}"},
            "id": "{{session_id}}",
        }
    return {"message": "{{prompt}}", "session_id": "{{session_id}}"}


def _default_response_path(target_type: str) -> str:
    if target_type == "mcp_trace":
        return "$.result"
    if target_type == "agent_trace":
        return "$"
    return "$.answer"


def _candidate_from_endpoint(
    *,
    endpoint_url: str,
    method: str,
    source: str,
    fields: list[Any] | None,
    scan: dict[str, Any],
    existing_urls: set[str],
) -> dict[str, Any] | None:
    normalized_url = endpoint_url.rstrip("/")
    if normalized_url in existing_urls:
        return None
    normalized_method = str(method or "").upper()
    if normalized_method not in {"GET", "POST", "PUT", "PATCH"}:
        return None
    target_type, confidence, evidence = infer_ai_target_type(
        endpoint_url,
        method=normalized_method,
        fields=fields or [],
        source=source,
    )
    if not target_type:
        return None
    headers = {"Content-Type": "application/json"}
    if target_type == "mcp_trace":
        headers["Accept"] = "text/event-stream, application/json"
    suggested_target = {
        "name": f"Discovered {_path_from_url(endpoint_url).rstrip('/') or endpoint_url}",
        "target_type": target_type,
        "endpoint_url": endpoint_url,
        "method": normalized_method,
        "headers_template": headers,
        "request_template": _default_request_template(target_type),
        "response_path": _default_response_path(target_type),
        "streaming_mode": "sse" if target_type == "mcp_trace" else "json",
        "rate_limit_rps": 2,
        "request_budget": 5,
        "production_mode": False,
        "metadata_json": {
            "discovered_by": source,
            "discovery_scan_id": str(scan.get("id") or ""),
            "discovery_confidence": confidence,
            "discovery_evidence": evidence,
        },
        "credential": {"auth_kind": "none", "header_name": None, "secret": None, "metadata_json": None},
    }
    return {
        "candidate_id": _stable_id(source, endpoint_url, method, scan.get("id")),
        "source": source,
        "scan_id": str(scan.get("id") or ""),
        "target_url": scan.get("target_url"),
        "target_type": target_type,
        "endpoint_url": endpoint_url,
        "method": method.upper(),
        "confidence": confidence,
        "evidence": evidence,
        "suggested_target": suggested_target,
    }


def _iter_openapi_candidates(scan: dict[str, Any], existing_urls: set[str]) -> list[dict[str, Any]]:
    result = _as_dict(scan.get("result"))
    endpoint_sets = [
        _json_path_get(result, "discovery", "api_security", "openapi", "endpoints"),
        _json_path_get(result, "discovery", "openapi", "endpoints"),
        _json_path_get(result, "api_security", "openapi", "endpoints"),
        _json_path_get(result, "openapi", "endpoints"),
    ]
    base_url = str(scan.get("target_url") or "")
    candidates: list[dict[str, Any]] = []
    for endpoints in endpoint_sets:
        for endpoint in _as_list(endpoints):
            if isinstance(endpoint, dict):
                method = str(endpoint.get("method") or "GET").upper()
                path = endpoint.get("url") or endpoint.get("path")
                fields = (
                    _as_list(endpoint.get("query_params"))
                    + _as_list(endpoint.get("body_params"))
                    + _as_list(endpoint.get("params"))
                    + _as_list(endpoint.get("request_fields"))
                )
            else:
                method = "GET"
                path = str(endpoint or "")
                fields = []
            endpoint_url = _normalize_url(base_url, str(path or ""))
            if not endpoint_url:
                continue
            candidate = _candidate_from_endpoint(
                endpoint_url=endpoint_url,
                method=method,
                source="openapi",
                fields=fields,
                scan=scan,
                existing_urls=existing_urls,
            )
            if candidate:
                candidates.append(candidate)
    return candidates


def _iter_browser_candidates(scan: dict[str, Any], existing_urls: set[str]) -> list[dict[str, Any]]:
    result = _as_dict(scan.get("result"))
    endpoints = _json_path_get(result, "discovery", "browser_api_endpoints")
    base_url = str(scan.get("target_url") or "")
    candidates: list[dict[str, Any]] = []
    for endpoint in _as_list(endpoints):
        if isinstance(endpoint, dict):
            method = str(endpoint.get("method") or "GET").upper()
            url = endpoint.get("url") or endpoint.get("endpoint")
            fields = _as_list(endpoint.get("params")) + _as_list(endpoint.get("body_params"))
        else:
            method = "GET"
            url = str(endpoint or "")
            fields = []
        endpoint_url = _normalize_url(base_url, str(url or ""))
        if not endpoint_url:
            continue
        candidate = _candidate_from_endpoint(
            endpoint_url=endpoint_url,
            method=method,
            source="browser_network",
            fields=fields,
            scan=scan,
            existing_urls=existing_urls,
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def _iter_recursive_url_candidates(scan: dict[str, Any], existing_urls: set[str]) -> list[dict[str, Any]]:
    result = _as_dict(scan.get("result"))
    found: set[str] = set()

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
        elif isinstance(value, str):
            for match in re.findall(r"https?://[^\s\"'<>]+", value):
                found.add(match.rstrip(".,);]"))

    walk(result)
    candidates: list[dict[str, Any]] = []
    for url in sorted(found)[:200]:
        candidate = _candidate_from_endpoint(
            endpoint_url=url,
            method="POST",
            source="artifact_url",
            fields=[],
            scan=scan,
            existing_urls=existing_urls,
        )
        if candidate:
            candidates.append(candidate)
    return candidates


def build_agent_blast_radius(
    ai_target: dict[str, Any],
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarize operational AI risk from target metadata, privileges, and active findings."""
    metadata = _as_dict(ai_target.get("metadata_json"))
    target_type = str(ai_target.get("target_type") or "")
    tools = _as_list(metadata.get("tool_inventory") or metadata.get("tools") or metadata.get("mcp_tools"))
    scopes = _as_list(metadata.get("per_tool_scopes") or metadata.get("tool_scopes") or metadata.get("mcp_scopes") or metadata.get("oauth_scopes"))
    identities = _as_list(metadata.get("delegated_identity") or metadata.get("service_accounts") or metadata.get("agent_identities"))
    memory = _as_list(metadata.get("memory_stores") or metadata.get("memory") or metadata.get("state_stores"))
    data_classification = str(metadata.get("data_classification") or "unknown").lower()
    risk_tier = str(metadata.get("risk_tier") or "unknown").lower()

    score = 0
    factors: list[str] = []
    if ai_target.get("production_mode"):
        score += 18
        factors.append("production")
    if target_type in {"agent_trace", "mcp_trace", "widget"}:
        score += 18
        factors.append("agentic_surface")
    if tools:
        score += min(18, 6 + len(tools) * 3)
        factors.append("tool_inventory")
    if scopes:
        score += min(18, len(scopes) * 4)
        factors.append("scoped_permissions")
    if any(any(hint in str(scope).lower() for hint in HIGH_RISK_SCOPE_HINTS) for scope in scopes + tools):
        score += 20
        factors.append("high_risk_action_scope")
    if identities:
        score += 10
        factors.append("delegated_identity")
    if memory:
        score += 8
        factors.append("persistent_memory")
    if data_classification in {"restricted", "confidential", "sensitive", "pii", "phi"}:
        score += 15
        factors.append("sensitive_data")
    if risk_tier in {"critical", "high"}:
        score += 10
        factors.append("high_risk_tier")

    active_findings = [item for item in (findings or []) if str(item.get("status") or "active") == "active"]
    if active_findings:
        score += min(20, len(active_findings) * 5)
        factors.append("active_findings")

    missing_controls = []
    for key in ("write_action_approval", "dry_run_mode", "transaction_limits", "sandboxing", "audit_logs", "kill_switch"):
        if metadata.get(key) in (None, "", [], {}):
            missing_controls.append(key)
    if missing_controls and target_type in {"agent_trace", "mcp_trace", "widget"}:
        score += min(18, len(missing_controls) * 3)
        factors.append("missing_runtime_controls")

    score = min(100, score)
    if score >= 75:
        tier = "critical"
    elif score >= 55:
        tier = "high"
    elif score >= 30:
        tier = "medium"
    else:
        tier = "low"

    return {
        "score": score,
        "tier": tier,
        "factors": factors,
        "tools": tools[:25],
        "scopes": scopes[:25],
        "identities": identities[:10],
        "memory_stores": memory[:10],
        "data_classification": data_classification,
        "risk_tier": risk_tier,
        "active_findings": len(active_findings),
        "missing_runtime_controls": missing_controls,
    }


def build_ai_inventory(
    *,
    targets: list[dict[str, Any]] | None = None,
    ai_targets: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build an AI asset inventory and discovery candidate set from stored scan data."""
    findings_by_ai_target: dict[str, list[dict[str, Any]]] = {}
    for finding in findings or []:
        target_id = str(finding.get("ai_target_id") or "")
        if target_id:
            findings_by_ai_target.setdefault(target_id, []).append(finding)

    assets: list[dict[str, Any]] = []
    existing_urls: set[str] = set()
    by_type: dict[str, int] = {}
    highest_score = 0

    for target in ai_targets:
        metadata = _as_dict(target.get("metadata_json"))
        target_id = str(target.get("id") or "")
        endpoint_url = str(target.get("endpoint_url") or "")
        existing_urls.add(endpoint_url.rstrip("/"))
        blast_radius = build_agent_blast_radius(target, findings_by_ai_target.get(target_id, []))
        highest_score = max(highest_score, int(blast_radius.get("score") or 0))
        target_type = str(target.get("target_type") or "api_chat")
        by_type[target_type] = by_type.get(target_type, 0) + 1
        assets.append({
            "id": target_id,
            "kind": "saved_ai_target",
            "name": target.get("name"),
            "target_type": target_type,
            "endpoint_url": endpoint_url,
            "method": target.get("method"),
            "owner": metadata.get("asset_owner"),
            "risk_tier": metadata.get("risk_tier"),
            "data_classification": metadata.get("data_classification"),
            "production_mode": bool(target.get("production_mode")),
            "last_scanned_at": target.get("last_scanned_at"),
            "tools": blast_radius.get("tools", []),
            "scopes": blast_radius.get("scopes", []),
            "blast_radius": blast_radius,
        })

    for target in targets or []:
        if target.get("discovery_source") != "model-intake":
            continue
        assets.append({
            "id": str(target.get("id") or ""),
            "kind": "model_artifact",
            "name": target.get("name"),
            "target_type": "model_artifact",
            "endpoint_url": target.get("url"),
            "owner": None,
            "risk_tier": None,
            "data_classification": None,
            "production_mode": False,
            "last_scanned_at": target.get("last_scanned_at"),
            "tools": [],
            "scopes": [],
            "blast_radius": {"score": 0, "tier": "low", "factors": ["model_supply_chain_asset"]},
        })

    candidates_by_url: dict[str, dict[str, Any]] = {}
    for scan in scans:
        if str(scan.get("run_kind") or "") in {"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp", "model_intake"}:
            continue
        for candidate in (
            _iter_openapi_candidates(scan, existing_urls)
            + _iter_browser_candidates(scan, existing_urls)
            + _iter_recursive_url_candidates(scan, existing_urls)
        ):
            key = str(candidate.get("endpoint_url") or "").rstrip("/")
            existing = candidates_by_url.get(key)
            if not existing or float(candidate.get("confidence") or 0) > float(existing.get("confidence") or 0):
                candidates_by_url[key] = candidate

    candidates = sorted(
        candidates_by_url.values(),
        key=lambda item: (float(item.get("confidence") or 0), item.get("endpoint_url") or ""),
        reverse=True,
    )[:100]
    for candidate in candidates:
        by_type[candidate["target_type"]] = by_type.get(candidate["target_type"], 0) + 1

    coverage_gaps: list[str] = []
    if candidates:
        coverage_gaps.append("unsaved_ai_surface_candidates")
    if not any(asset.get("target_type") == "mcp_trace" for asset in assets):
        coverage_gaps.append("no_mcp_targets_registered")
    if not any(asset.get("target_type") == "agent_trace" for asset in assets):
        coverage_gaps.append("no_agent_targets_registered")
    if any(asset.get("blast_radius", {}).get("missing_runtime_controls") for asset in assets):
        coverage_gaps.append("agent_runtime_controls_missing")

    return {
        "generated_at": _utc_iso(),
        "assets": assets,
        "candidates": candidates,
        "summary": {
            "asset_count": len(assets),
            "saved_ai_targets": len(ai_targets),
            "model_artifacts": len([asset for asset in assets if asset.get("kind") == "model_artifact"]),
            "candidate_count": len(candidates),
            "by_type": by_type,
            "highest_blast_radius_score": highest_score,
            "coverage_gaps": coverage_gaps,
        },
    }


def _fetch_url_metadata(url: str, *, method: str = "GET", timeout_seconds: int = 8) -> dict[str, Any]:
    request = urllib.request.Request(url, method=method, headers={"Accept": "application/json"})
    started = _utc_now()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - operator-configured target
            body = response.read(100_000).decode("utf-8", errors="replace")
            headers = dict(response.headers.items())
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        body = exc.read(100_000).decode("utf-8", errors="replace")
        headers = dict(exc.headers.items()) if exc.headers else {}
        status = int(exc.code)
    except Exception as exc:  # noqa: BLE001 - caller needs precise network failure
        return {
            "ok": False,
            "url": url,
            "method": method,
            "error": str(exc),
            "latency_ms": round((_utc_now() - started).total_seconds() * 1000, 1),
        }

    parsed_json: Any = None
    try:
        parsed_json = json.loads(body) if body.strip() else None
    except json.JSONDecodeError:
        parsed_json = None
    return {
        "ok": 200 <= status < 400,
        "url": url,
        "method": method,
        "status_code": status,
        "latency_ms": round((_utc_now() - started).total_seconds() * 1000, 1),
        "headers": {
            key: value
            for key, value in headers.items()
            if key.lower() in {"www-authenticate", "content-type", "server"}
        },
        "json": parsed_json if isinstance(parsed_json, dict) else None,
        "body_excerpt": body[:1000],
    }


def _metadata_urls(endpoint_url: str) -> list[str]:
    parsed = urllib.parse.urlparse(endpoint_url)
    if not parsed.scheme or not parsed.netloc:
        return []
    origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    path = parsed.path.rstrip("/")
    urls = [f"{origin}/.well-known/oauth-protected-resource"]
    if path:
        urls.append(f"{origin}/.well-known/oauth-protected-resource{path}")
    urls.append(f"{origin}/.well-known/oauth-authorization-server")
    return list(dict.fromkeys(urls))


def run_mcp_live_readiness_probe(target: dict[str, Any], *, timeout_seconds: int = 8) -> dict[str, Any]:
    """Run safe live MCP/OAuth metadata checks plus declared-control checks."""
    endpoint_url = str(target.get("endpoint_url") or "")
    metadata = _as_dict(target.get("metadata_json"))
    if target.get("target_type") != "mcp_trace":
        return {
            "ok": False,
            "supported": False,
            "stage": "configuration",
            "error": "Live MCP readiness checks require an mcp_trace AI target.",
        }

    metadata_fetches = [_fetch_url_metadata(url, timeout_seconds=timeout_seconds) for url in _metadata_urls(endpoint_url)]
    endpoint_options = _fetch_url_metadata(endpoint_url, method="OPTIONS", timeout_seconds=timeout_seconds)
    json_docs = [item.get("json") for item in metadata_fetches if isinstance(item.get("json"), dict)]
    authenticate_headers = [
        str(fetch.get("headers", {}).get("WWW-Authenticate") or fetch.get("headers", {}).get("www-authenticate") or "")
        for fetch in metadata_fetches + [endpoint_options]
    ]
    metadata_text = json.dumps(json_docs).lower()
    auth_header_text = " ".join(authenticate_headers).lower()

    checks = [
        {
            "id": "mcp.protected_resource_metadata",
            "label": "Protected resource metadata",
            "status": "pass" if json_docs or "resource_metadata" in auth_header_text else "warn",
            "evidence": "OAuth protected-resource metadata discovered" if json_docs else "No OAuth protected-resource metadata document was discovered",
        },
        {
            "id": "mcp.authorization_server_discovery",
            "label": "Authorization server discovery",
            "status": "pass" if "authorization_servers" in metadata_text or "authorization_endpoint" in metadata_text or "authorization_uri" in auth_header_text else "warn",
            "evidence": "Authorization metadata was advertised" if ("authorization" in metadata_text or "authorization" in auth_header_text) else "Authorization metadata was not advertised",
        },
        {
            "id": "mcp.token_audience_validation",
            "label": "Token audience validation",
            "status": "pass" if metadata.get("token_audience_validation") else "warn",
            "evidence": "Declared in target metadata" if metadata.get("token_audience_validation") else "No target metadata attests audience validation",
        },
        {
            "id": "mcp.pkce_s256",
            "label": "PKCE S256",
            "status": "pass" if "s256" in metadata_text or metadata.get("pkce_s256") else "warn",
            "evidence": "PKCE S256 appears in metadata" if "s256" in metadata_text else "No PKCE S256 evidence discovered",
        },
        {
            "id": "mcp.no_token_passthrough",
            "label": "No token passthrough",
            "status": "pass" if metadata.get("no_token_passthrough") else "warn",
            "evidence": "Declared in target metadata" if metadata.get("no_token_passthrough") else "No target metadata attests token passthrough prevention",
        },
        {
            "id": "mcp.scope_minimization",
            "label": "Scope minimization",
            "status": "pass" if metadata.get("scope_minimization") or metadata.get("mcp_scopes") or metadata.get("tool_scopes") else "warn",
            "evidence": "Scopes are declared" if (metadata.get("mcp_scopes") or metadata.get("tool_scopes")) else "No declared minimal scope set",
        },
        {
            "id": "mcp.session_isolation",
            "label": "Session isolation",
            "status": "pass" if metadata.get("session_isolation") or metadata.get("tenant_isolation") else "warn",
            "evidence": "Declared in target metadata" if (metadata.get("session_isolation") or metadata.get("tenant_isolation")) else "No session-isolation attestation",
        },
        {
            "id": "mcp.ssrf_policy",
            "label": "SSRF policy",
            "status": "pass" if metadata.get("ssrf_protection") or metadata.get("egress_allowlist") else "warn",
            "evidence": "SSRF/egress policy declared" if (metadata.get("ssrf_protection") or metadata.get("egress_allowlist")) else "No egress/SSRF policy declared",
        },
    ]

    warnings = [check for check in checks if check["status"] == "warn"]
    return {
        "ok": not warnings,
        "supported": True,
        "stage": "complete",
        "endpoint_url": endpoint_url,
        "checked_at": _utc_iso(),
        "summary": {
            "checks": len(checks),
            "passed": len([check for check in checks if check["status"] == "pass"]),
            "warnings": len(warnings),
        },
        "checks": checks,
        "metadata_fetches": metadata_fetches,
        "endpoint_options": endpoint_options,
    }
