"""Exposure graph routes.

Extracted verbatim from the api.py monolith. Builds the cross-product exposure
graph — domains, targets, APIs, auth roles, third-party JS, cloud hints, AI
targets, MCP tools, model artifacts, scans, and findings — plus the derived node,
asset, change, and attack-path views.

The database pool is supplied by the composition root through
``configure_exposure_router``; the module imports shared helpers only.
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable, Literal, Optional
import urllib.parse

from fastapi import APIRouter, HTTPException, Query, Response

try:
    from ai_assurance import build_agent_blast_radius
    from api_utils import (
        SEVERITY_ORDER, extract_root_domain, _graph_get, _graph_list, _parse_graph_json, _scan_completion_flags,
        _severity_sort_value, _short_url_label,
    )
    from serialization import row_to_dict
    from finding_routes.list_query import without_jit
    from finding_routes.retirement import not_retired_sql
    from list_compat import direct, mark_deprecated, v1_page, wants_list_v1
    from list_contract import CURSOR_MAX_LENGTH, EXACT_COUNT_CAP, SqlParams, snapshot_time
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_assurance import build_agent_blast_radius
    from ..api_utils import (
        SEVERITY_ORDER, extract_root_domain, _graph_get, _graph_list, _parse_graph_json, _scan_completion_flags,
        _severity_sort_value, _short_url_label,
    )
    from ..serialization import row_to_dict
    from ..finding_routes.list_query import without_jit
    from ..finding_routes.retirement import not_retired_sql
    from ..list_compat import direct, mark_deprecated, v1_page, wants_list_v1
    from ..list_contract import CURSOR_MAX_LENGTH, EXACT_COUNT_CAP, SqlParams, snapshot_time


from .services_router import router as services_router
from .service_inventory import origin as _service_origin
from .asset_rank import (
    ASSETS_LIST, adjustment_rows_sql, exposure_class as exposure_class_for, keyset_page_sql, metrics_from,
    offset_page_sql, refresh_facts, stringify_keys,
)
from .proof_rollup import undetermined_adjustments

router = APIRouter()
router.include_router(services_router)

_pool_provider: Callable[[], Any] | None = None


def configure_exposure_router(pool_provider: Callable[[], Any]) -> None:
    """Bind the application database pool without importing the app module."""
    global _pool_provider
    _pool_provider = pool_provider


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool

def _build_exposure_graph(
    *,
    targets: list[dict[str, Any]],
    ai_targets: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a UI-friendly exposure graph from existing ShakerScan records."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    domain_severities: dict[str, list[str | None]] = {}

    def add_node(node: dict[str, Any]) -> None:
        existing = nodes.get(node["id"])
        if not existing:
            nodes[node["id"]] = node
            return
        existing_severity = existing.get("severity")
        next_severity = node.get("severity")
        if _severity_sort_value(next_severity) > _severity_sort_value(existing_severity):
            existing["severity"] = next_severity
        existing["meta"] = {**existing.get("meta", {}), **node.get("meta", {})}

    def add_domain(root_domain: str | None) -> str | None:
        if not root_domain:
            return None
        node_id = f"domain:{root_domain}"
        add_node(_graph_node(
            node_id,
            "domain",
            root_domain,
            subtitle="Root domain",
            href=f"/targets?search={urllib.parse.quote(root_domain)}",
        ))
        domain_severities.setdefault(root_domain, [])
        return node_id

    target_node_by_id: dict[str, str] = {}
    ai_node_by_id: dict[str, str] = {}
    ai_target_by_id: dict[str, dict[str, Any]] = {}
    scan_subject_by_id: dict[str, str] = {}
    endpoint_node_by_path: dict[tuple[str | None, str | None, str | None], list[str]] = {}
    findings_by_ai_target: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        ai_target_id = str(finding.get("ai_target_id") or "")
        if ai_target_id:
            findings_by_ai_target.setdefault(ai_target_id, []).append(finding)

    model_supply_chain_id = "group:model-supply-chain"

    for target in targets:
        target_id = str(target.get("id"))
        node_id = f"target:{target_id}"
        target_node_by_id[target_id] = node_id
        root_domain = target.get("root_domain") or extract_root_domain(target.get("url") or "")
        active_findings = int(target.get("active_findings_count") or target.get("active_findings") or 0)
        is_model_artifact = target.get("discovery_source") == "model-intake"
        add_node(_graph_node(
            node_id,
            "model_artifact" if is_model_artifact else "web_target",
            _short_url_label(target.get("url")),
            subtitle=target.get("name") or ("Model artifact" if is_model_artifact else root_domain),
            status="active" if target.get("is_active", True) else "inactive",
            href=f"/targets?search={urllib.parse.quote(str(target.get('url') or ''))}",
            meta={
                "url": target.get("url"),
                # Model artifacts record the hosting platform as an origin, not
                # a root domain — huggingface.co is not part of the user's
                # attack surface, the artifact pulled from it is.
                "origin" if is_model_artifact else "root_domain": root_domain,
                "exposure_class": _exposure_class(target.get("url"), kind="model" if is_model_artifact else "web"),
                "unscanned": int(target.get("total_scans") or 0) <= 0,
                "last_score": target.get("last_score"),
                "last_grade": target.get("last_grade"),
                "active_findings_count": active_findings,
                "total_scans": target.get("total_scans") or 0,
                "discovery_source": target.get("discovery_source"),
            },
        ))
        if is_model_artifact:
            add_node(_graph_node(
                model_supply_chain_id,
                "model_supply_chain",
                "Model supply chain",
                subtitle="External model artifacts",
                href="/model-intake",
            ))
            edges.append(_graph_edge(model_supply_chain_id, node_id, "contains_artifact", label="supply chain artifact"))
        else:
            domain_id = add_domain(root_domain)
            if domain_id:
                edges.append(_graph_edge(domain_id, node_id, "contains", label="contains target"))

    for ai_target in ai_targets:
        ai_id = str(ai_target.get("id"))
        node_id = f"ai_target:{ai_id}"
        ai_node_by_id[ai_id] = node_id
        ai_target_by_id[ai_id] = ai_target
        root_domain = extract_root_domain(ai_target.get("endpoint_url") or "")
        blast_radius = build_agent_blast_radius(ai_target, findings_by_ai_target.get(ai_id, []))
        add_node(_graph_node(
            node_id,
            "ai_target",
            ai_target.get("name") or _short_url_label(ai_target.get("endpoint_url")),
            subtitle=f"{ai_target.get('target_type') or 'ai'} surface",
            status="production" if ai_target.get("production_mode") else "non-production",
            href="/ai-gate",
            meta={
                "endpoint_url": ai_target.get("endpoint_url"),
                "root_domain": root_domain,
                "exposure_class": _exposure_class(ai_target.get("endpoint_url"), kind="ai"),
                "unscanned": not ai_target.get("last_scanned_at"),
                "target_type": ai_target.get("target_type"),
                "method": ai_target.get("method"),
                "production_mode": bool(ai_target.get("production_mode")),
                "last_scanned_at": ai_target.get("last_scanned_at"),
                "blast_radius": blast_radius,
                "blast_radius_score": blast_radius.get("score"),
                "blast_radius_tier": blast_radius.get("tier"),
            },
        ))
        domain_id = add_domain(root_domain)
        if domain_id:
            edges.append(_graph_edge(domain_id, node_id, "exposes_ai_surface", label="AI surface"))

    for scan in scans:
        scan_id = str(scan.get("id"))
        if not scan_id:
            continue
        subject_id = None
        if scan.get("ai_target_id"):
            subject_id = ai_node_by_id.get(str(scan.get("ai_target_id")))
        if not subject_id and scan.get("target_id"):
            subject_id = target_node_by_id.get(str(scan.get("target_id")))
        if not subject_id:
            continue
        # Scans are events, not exposure: they contribute derived assets and
        # linkage below but are not emitted as graph nodes themselves. Scan
        # context lives in the asset detail panels instead.
        scan_subject_by_id[scan_id] = subject_id

        result = _parse_graph_json(scan.get("result"))
        subject_root_domain = scan.get("root_domain") or extract_root_domain(scan.get("target_url") or scan.get("ai_endpoint_url") or "")

        openapi_endpoints = _iter_graph_openapi_endpoints(result)
        openapi_meta = _openapi_meta(result)
        if openapi_endpoints:
            api_node_id = f"api:{scan_id}:openapi:{_graph_hash(openapi_meta.get('url'), scan.get('target_url'))}"
            add_node(_graph_node(
                api_node_id,
                "api_surface",
                openapi_meta.get("title") or "OpenAPI schema",
                subtitle=f"{len(openapi_endpoints)} operations",
                href=f"/scans/{scan_id}",
                meta={
                    "source": "openapi",
                    "url": openapi_meta.get("url"),
                    "version": openapi_meta.get("version"),
                    "endpoint_count": openapi_meta.get("endpoint_count") or len(openapi_endpoints),
                },
            ))
            edges.append(_graph_edge(subject_id, api_node_id, "exposes_api", label="exposes API"))

            for endpoint in openapi_endpoints[:120]:
                method = str(endpoint.get("method") or "GET").upper()
                path = str(endpoint.get("path") or endpoint.get("url") or "/")
                endpoint_url = _normalize_graph_endpoint_url(scan.get("target_url"), endpoint.get("url") or path)
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _service_origin(endpoint_url), _endpoint_path_key(endpoint_url) or path)}"
                endpoint_node_by_path.setdefault((subject_id, _service_origin(endpoint_url), _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
                add_node(_graph_node(
                    endpoint_node_id,
                    "endpoint",
                    f"{method} {_endpoint_path_key(endpoint_url) or path}",
                    subtitle="OpenAPI operation",
                    href=f"/scans/{scan_id}",
                    meta={
                        "method": method,
                        "path": _endpoint_path_key(endpoint_url) or path,
                        "url": endpoint_url,
                        "source": "openapi",
                        "operation_id": endpoint.get("operation_id"),
                        "query_params": endpoint.get("query_params") or endpoint.get("params") or [],
                        "body_params": endpoint.get("body_params") or [],
                    },
                ))
                edges.append(_graph_edge(api_node_id, endpoint_node_id, "defines_endpoint", label="defines endpoint"))
                edges.append(_graph_edge(subject_id, endpoint_node_id, "exposes_endpoint", label="exposes endpoint"))

        browser_api_endpoints = _iter_browser_api_endpoints(result)
        if browser_api_endpoints:
            browser_api_node_id = f"api:{scan_id}:browser"
            add_node(_graph_node(
                browser_api_node_id,
                "api_surface",
                "Browser-observed API",
                subtitle=f"{len(browser_api_endpoints)} captured calls",
                href=f"/scans/{scan_id}",
                meta={"source": "browser_network", "endpoint_count": len(browser_api_endpoints)},
            ))
            edges.append(_graph_edge(subject_id, browser_api_node_id, "observed_api", label="browser observed API"))
            for endpoint in browser_api_endpoints[:80]:
                endpoint_url = _normalize_graph_endpoint_url(scan.get("target_url"), endpoint.get("url"))
                if not endpoint_url:
                    continue
                method = str(endpoint.get("method") or "GET").upper()
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _service_origin(endpoint_url), _endpoint_path_key(endpoint_url))}"
                endpoint_node_by_path.setdefault((subject_id, _service_origin(endpoint_url), _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
                add_node(_graph_node(
                    endpoint_node_id,
                    "endpoint",
                    f"{method} {_endpoint_path_key(endpoint_url) or _short_url_label(endpoint_url)}",
                    subtitle="Browser-captured API call",
                    href=f"/scans/{scan_id}",
                    meta={"method": method, "url": endpoint_url, "path": _endpoint_path_key(endpoint_url), "source": "browser_network"},
                ))
                edges.append(_graph_edge(browser_api_node_id, endpoint_node_id, "observed_endpoint", label="observed endpoint"))

        for role in _iter_graph_auth_roles(result, ai_target_by_id.get(str(scan.get("ai_target_id"))) if scan.get("ai_target_id") else None):
            label = str(role.get("label") or "unknown")
            role_node_id = f"auth_role:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                role_node_id,
                "auth_role",
                label,
                subtitle=role.get("source") or "authorization context",
                href=f"/scans/{scan_id}",
                meta=role,
            ))
            edges.append(_graph_edge(subject_id, role_node_id, "tests_auth_role", label="tests auth role"))

        for hint in _iter_graph_cloud_hints(result):
            label = str(hint.get("label") or "cloud")
            cloud_node_id = f"cloud_hint:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                cloud_node_id,
                "cloud_hint",
                label,
                subtitle="Cloud exposure hint",
                href=f"/scans/{scan_id}",
                meta=hint,
            ))
            edges.append(_graph_edge(subject_id, cloud_node_id, "has_cloud_hint", label="cloud hint"))

        for tool in _iter_graph_mcp_tools(result):
            label = str(tool.get("label") or "MCP tool")
            tool_node_id = f"mcp_tool:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                tool_node_id,
                "mcp_tool",
                label,
                subtitle="MCP/tool surface",
                severity=tool.get("severity"),
                href=f"/scans/{scan_id}",
                meta=tool,
            ))
            edges.append(_graph_edge(subject_id, tool_node_id, "exposes_mcp_tool", label="exposes MCP tool", severity=tool.get("severity")))

        model_intake = _parse_graph_json(result.get("model_intake"))
        model_summary = _parse_graph_json(model_intake.get("summary"))
        if model_summary:
            add_node(_graph_node(
                subject_id,
                "model_artifact",
                model_summary.get("artifact_name") or _short_url_label(model_summary.get("artifact_ref") or scan.get("target_url")),
                subtitle=model_summary.get("format_posture") or "Model artifact",
                status="approved" if model_summary.get("deployment_approved") else "needs approval",
                href=f"/scans/{scan_id}",
                meta={
                    "artifact_ref": model_summary.get("artifact_ref"),
                    "source_kind": model_summary.get("source_kind"),
                    "extension": model_summary.get("extension"),
                    "sha256": model_summary.get("sha256"),
                    "format_posture": model_summary.get("format_posture"),
                    "provenance_present": model_summary.get("provenance_present"),
                    "signature_present": model_summary.get("signature_present"),
                    "expected_hash_present": model_summary.get("expected_hash_present"),
                    "deployment_approved": model_summary.get("deployment_approved"),
                },
            ))

        vendor_risk = _parse_graph_json(result.get("vendor_risk"))
        for domain in (vendor_risk.get("third_party_domains") or [])[:20]:
            if not domain:
                continue
            vendor_node_id = f"vendor:{domain}"
            add_node(_graph_node(
                vendor_node_id,
                "vendor",
                str(domain),
                subtitle="Third-party resource",
                status=vendor_risk.get("risk_level"),
                meta={
                    "risk_score": vendor_risk.get("risk_score"),
                    "risk_level": vendor_risk.get("risk_level"),
                },
            ))
            edges.append(_graph_edge(subject_id, vendor_node_id, "loads_third_party", label="loads third party"))

        for resource in _graph_list(vendor_risk.get("resources"))[:30]:
            if not isinstance(resource, dict) or resource.get("type") != "script":
                continue
            script_url = resource.get("url")
            if not script_url:
                continue
            script_node_id = f"third_party_js:{_graph_hash(script_url)}"
            vendor_node_id = f"vendor:{resource.get('domain') or extract_root_domain(script_url)}"
            add_node(_graph_node(
                script_node_id,
                "third_party_js",
                _short_url_label(script_url),
                subtitle=resource.get("provider") or "Third-party script",
                status=resource.get("trust_level"),
                href=f"/scans/{scan_id}",
                meta={
                    "url": script_url,
                    "domain": resource.get("domain"),
                    "provider": resource.get("provider"),
                    "category": resource.get("category"),
                    "security_score": resource.get("security_score"),
                    "risk_factors": resource.get("risk_factors") or [],
                    "sri_present": resource.get("sri_present"),
                },
            ))
            if vendor_node_id in nodes:
                edges.append(_graph_edge(vendor_node_id, script_node_id, "serves_script", label="serves script"))
            edges.append(_graph_edge(subject_id, script_node_id, "loads_script", label="loads script"))

        attack_chains = _parse_graph_json(result.get("attack_chains"))
        for idx, chain in enumerate((attack_chains.get("chains") or [])[:10]):
            if not isinstance(chain, dict):
                continue
            chain_type = chain.get("chain_type") or chain.get("name") or idx
            chain_node_id = f"chain:{scan_id}:{chain_type}:{idx}"
            severity = str(chain.get("severity") or "").lower() or None
            add_node(_graph_node(
                chain_node_id,
                "attack_chain",
                chain.get("name") or str(chain_type),
                subtitle="Correlated exploit path",
                severity=severity,
                href=f"/scans/{scan_id}",
                meta={
                    "chain_type": chain.get("chain_type"),
                    "confidence": chain.get("confidence"),
                    "completeness": chain.get("completeness"),
                    "business_impact": chain.get("business_impact"),
                },
            ))
            edges.append(_graph_edge(subject_id, chain_node_id, "exploit_path", label="exploit path", severity=severity))

    for finding in findings:
        finding_id = str(finding.get("id"))
        if not finding_id:
            continue
        severity = str(finding.get("severity") or "info").lower()
        finding_node_id = f"finding:{finding_id}"
        href = f"/findings/{finding_id}"
        add_node(_graph_node(
            finding_node_id,
            "finding",
            finding.get("title") or "Finding",
            subtitle=finding.get("tool") or finding.get("source") or "finding",
            severity=severity,
            status=finding.get("status"),
            href=href,
            meta={
                "severity": severity,
                "status": finding.get("status"),
                "tool": finding.get("tool"),
                "source": finding.get("source"),
                "cvss_score": finding.get("cvss_score"),
                "last_seen_at": finding.get("last_seen_at"),
                "last_verification_verdict": finding.get("last_verification_verdict"),
                "url": finding.get("url"),
            },
        ))

        subject_id = None
        root_domain = finding.get("root_domain")
        if finding.get("ai_target_id"):
            subject_id = ai_node_by_id.get(str(finding.get("ai_target_id")))
            root_domain = root_domain or extract_root_domain(finding.get("ai_target_url") or finding.get("target_url") or "")
        if not subject_id and finding.get("target_id"):
            subject_id = target_node_by_id.get(str(finding.get("target_id")))
        if not subject_id and finding.get("scan_id"):
            subject_id = scan_subject_by_id.get(str(finding.get("scan_id")))
        if subject_id:
            edges.append(_graph_edge(subject_id, finding_node_id, "has_finding", label="has finding", severity=severity))
        finding_path = _endpoint_path_key(finding.get("url"))
        related_endpoints = list(dict.fromkeys(endpoint_node_by_path.get(
            (subject_id, _service_origin(finding.get("url")), finding_path), []
        )))
        # A path-only finding cannot choose between GET and POST (or other
        # operations) at the same origin. Keep it target-scoped when ambiguous.
        if len(related_endpoints) > 1:
            finding_method = str(finding.get("http_method") or finding.get("method") or "").upper()
            related_endpoints = [node_id for node_id in related_endpoints
                                 if finding_method and nodes[node_id].get("meta", {}).get("method") == finding_method]
        for endpoint_node_id in related_endpoints[:5]:
            edges.append(_graph_edge(endpoint_node_id, finding_node_id, "affected_by", label="affected by", severity=severity))
            # Risk-bearing endpoints inherit their worst finding's severity so
            # they rank into fan-out budgets and render with severity rings.
            endpoint_node = nodes.get(endpoint_node_id)
            if endpoint_node and _severity_sort_value(severity) > _severity_sort_value(endpoint_node.get("severity")):
                endpoint_node["severity"] = severity
        if root_domain:
            domain_severities.setdefault(str(root_domain), []).append(severity)

    for root_domain, severities in domain_severities.items():
        node_id = f"domain:{root_domain}"
        if node_id in nodes:
            nodes[node_id]["severity"] = _highest_severity(severities)
            nodes[node_id]["meta"]["active_findings_count"] = len([s for s in severities if s])

    node_list = list(nodes.values())
    node_type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for node in node_list:
        node_type_counts[node["type"]] = node_type_counts.get(node["type"], 0) + 1
        if node.get("type") == "finding" and node.get("severity"):
            severity = str(node["severity"])
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    hotspot_types = {"domain", "web_target", "ai_target", "model_artifact", "attack_chain"}
    hotspots = sorted(
        [node for node in node_list if node["type"] in hotspot_types and node.get("severity")],
        key=lambda item: (_severity_sort_value(item.get("severity")), int(item.get("meta", {}).get("active_findings_count") or 0)),
        reverse=True,
    )[:10]

    return {
        "nodes": node_list,
        "edges": edges,
        "summary": {
            "node_count": len(node_list),
            "edge_count": len(edges),
            "node_type_counts": node_type_counts,
            "severity_counts": severity_counts,
            "hotspots": hotspots,
        },
    }


def _focus_exposure_subgraph(
    graph: dict[str, Any],
    *,
    focus: str | None,
    depth: int,
    include_endpoints: bool,
    max_nodes: int = 350,
    max_fanout: int = 15,
) -> dict[str, Any]:
    """Reduce a full exposure graph to a focused, renderable subgraph.

    Without a focus node we return a seed view (risk hotspots + domains and
    their immediate neighbours). With a focus node we return its neighbourhood
    out to ``depth``. Endpoint plumbing is collapsed unless explicitly
    requested. The full-graph summary is preserved so overview stats stay
    accurate, with rendered counts and a ``truncated`` flag added.
    """
    nodes: list[dict[str, Any]] = graph.get("nodes", [])
    edges: list[dict[str, Any]] = graph.get("edges", [])
    nodes_by_id = {node["id"]: node for node in nodes}

    if include_endpoints:
        active_edges = edges
    else:
        # Finding-free endpoints are enumeration noise and stay collapsed into
        # API-surface counts; endpoints that carry findings are the connective
        # tissue between asset and vulnerability and stay in the default view.
        endpoint_ids = {n["id"] for n in nodes if n["type"] == "endpoint"}
        risky_endpoint_ids = {
            e["source"] for e in edges if e["type"] == "affected_by" and e["source"] in endpoint_ids
        }

        def _keep_edge(e: dict[str, Any]) -> bool:
            touches_endpoint = e["source"] in endpoint_ids or e["target"] in endpoint_ids
            if not touches_endpoint:
                return e["type"] not in _EXPOSURE_STRUCTURAL_EDGE_TYPES
            if e["type"] == "affected_by":
                return e["source"] in risky_endpoint_ids
            if e["type"] in ("exposes_endpoint", "observed_endpoint"):
                return e["target"] in risky_endpoint_ids
            return False

        active_edges = [e for e in edges if _keep_edge(e)]

    adjacency: dict[str, list[str]] = {}
    for edge in active_edges:
        adjacency.setdefault(edge["source"], []).append(edge["target"])
        adjacency.setdefault(edge["target"], []).append(edge["source"])

    def _risk_key(node_id: str) -> tuple[int, int]:
        node = nodes_by_id[node_id]
        return (
            _severity_sort_value(node.get("severity")),
            int(node.get("meta", {}).get("active_findings_count") or 0),
        )

    if focus and focus in nodes_by_id:
        seeds = [focus]
    else:
        focus = None
        # Lead the overview with risk: seed from hotspots and let BFS pull in
        # their neighbourhoods. Domains surface naturally as hotspot neighbours.
        hotspot_ids = [n["id"] for n in graph.get("summary", {}).get("hotspots", []) if n["id"] in nodes_by_id]
        if hotspot_ids:
            seeds = list(dict.fromkeys(hotspot_ids))
        else:
            anchor_ids = [n["id"] for n in nodes if n["type"] in ("domain", "model_supply_chain")]
            seeds = anchor_ids or [n["id"] for n in sorted(nodes, key=_risk_key, reverse=True)[:25]]

    # Cap per-node fan-out so hub nodes (a domain wired to hundreds of AI
    # surfaces) cannot explode the rendered graph; keep the riskiest neighbours.
    capped = False
    visited: set[str] = {s for s in seeds if s in nodes_by_id}
    queue: list[tuple[str, int]] = [(s, 0) for s in list(visited)]
    while queue:
        node_id, dist = queue.pop(0)
        if dist >= depth:
            continue
        neighbors = [n for n in dict.fromkeys(adjacency.get(node_id, [])) if n in nodes_by_id]
        if len(neighbors) > max_fanout:
            capped = True
            neighbors = sorted(neighbors, key=_risk_key, reverse=True)[:max_fanout]
        for neighbor in neighbors:
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, dist + 1))

    truncated = capped
    if len(visited) > max_nodes:
        truncated = True
        seed_set = set(seeds)
        ranked = sorted(
            visited,
            key=lambda nid: (
                nid in seed_set,
                _severity_sort_value(nodes_by_id[nid].get("severity")),
                int(nodes_by_id[nid].get("meta", {}).get("active_findings_count") or 0),
            ),
            reverse=True,
        )
        visited = set(ranked[:max_nodes])

    sub_nodes = [nodes_by_id[nid] for nid in visited]
    sub_edges = [e for e in active_edges if e["source"] in visited and e["target"] in visited]

    sub_nodes, sub_edges = _cluster_exposure_findings(sub_nodes, sub_edges, protect_id=focus)

    summary = dict(graph.get("summary", {}))
    summary["rendered_node_count"] = len(sub_nodes)
    summary["rendered_edge_count"] = len(sub_edges)
    summary["truncated"] = truncated
    summary["focus"] = focus
    summary["include_endpoints"] = include_endpoints

    return {"nodes": sub_nodes, "edges": sub_edges, "summary": summary}


@router.get("/exposure/graph")
async def exposure_graph(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit_findings: int = Query(250, ge=1, le=500),
    limit_scans: int = Query(150, ge=1, le=300),
    focus: Optional[str] = None,
    depth: int = Query(1, ge=1, le=3),
    include_endpoints: bool = False,
):
    """Return a derived exposure graph across web targets, AI targets, scans, findings, vendors, and chains."""
    async with _pool().acquire() as conn:
        target_query = """
            SELECT
                id, url, name, root_domain, is_root, discovery_source, is_active,
                last_score, last_grade, last_scanned_at, total_scans,
                active_findings_count, created_at, updated_at
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY active_findings_count DESC, updated_at DESC
            LIMIT 500
        """
        targets = [row_to_dict(row) for row in await conn.fetch(target_query, include_inactive, root_domain)]

        ai_query = """
            SELECT
                id, name, target_type, endpoint_url, method, streaming_mode,
                production_mode, rate_limit_rps, token_budget, request_budget,
                last_scanned_at, last_scan_id, metadata_json, is_active,
                created_at, updated_at
            FROM ai_targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT 250
        """
        ai_targets = [row_to_dict(row) for row in await conn.fetch(ai_query, include_inactive, root_domain)]

        scans_query = """
            SELECT
                s.id, s.target_id, s.ai_target_id, s.target_url, s.status, s.scan_type,
                s.run_kind, s.result, s.score, s.grade, s.findings_count,
                s.created_at, s.completed_at,
                t.root_domain,
                ait.endpoint_url as ai_endpoint_url
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND (
                $1::text IS NULL
                OR t.root_domain = $1::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%'
            )
            ORDER BY s.created_at DESC
            LIMIT $2
        """
        scans = [row_to_dict(row) for row in await conn.fetch(scans_query, root_domain, limit_scans)]

        findings_query = """
            SELECT
                f.id, f.scan_id, f.target_id, f.ai_target_id, f.title, f.severity,
                f.status, f.tool, f.source, f.cvss_score, f.url, f.last_seen_at,
                f.last_verification_verdict,
                t.root_domain,
                t.url as target_url,
                ait.endpoint_url as ai_target_url
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE ($1::boolean = true OR f.status = 'active')
              AND (
                $2::text IS NULL
                OR t.root_domain = $2::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%'
              )
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                f.last_seen_at DESC NULLS LAST
            LIMIT $3
        """
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(findings_query, include_resolved, root_domain, limit_findings)
        ]

        # Real, uncapped security counts for the headline metrics — the graph's
        # own node counts are limited by the fetch caps above and would
        # under-report on large datasets.
        metrics_row = await conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*) FROM targets t
                   WHERE ($1::boolean = true OR t.is_active = true)
                     AND ($2::text IS NULL OR t.root_domain = $2::text)) AS web_targets,
                (SELECT COUNT(*) FROM ai_targets a
                   WHERE ($1::boolean = true OR a.is_active = true)
                     AND ($2::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS ai_surfaces,
                (SELECT COUNT(*) FROM findings f
                   LEFT JOIN targets t ON f.target_id = t.id
                   LEFT JOIN ai_targets a ON f.ai_target_id = a.id
                   WHERE f.status = 'active' AND f.severity = 'critical'
                     AND ($2::text IS NULL OR t.root_domain = $2::text
                          OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS active_critical,
                (SELECT COUNT(*) FROM findings f
                   LEFT JOIN targets t ON f.target_id = t.id
                   LEFT JOIN ai_targets a ON f.ai_target_id = a.id
                   WHERE f.status = 'active' AND f.severity = 'high'
                     AND ($2::text IS NULL OR t.root_domain = $2::text
                          OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS active_high
            """,
            include_inactive,
            root_domain,
        )

    graph = _build_exposure_graph(
        targets=targets,
        ai_targets=ai_targets,
        scans=scans,
        findings=findings,
    )

    web_targets = int(metrics_row["web_targets"] or 0)
    ai_surfaces = int(metrics_row["ai_surfaces"] or 0)
    graph["summary"]["metrics"] = {
        "asset_count": web_targets + ai_surfaces,
        "web_targets": web_targets,
        "ai_surfaces": ai_surfaces,
        "active_critical": int(metrics_row["active_critical"] or 0),
        "active_high": int(metrics_row["active_high"] or 0),
        "attack_chains": int(graph["summary"]["node_type_counts"].get("attack_chain", 0)),
    }

    return _focus_exposure_subgraph(
        graph,
        focus=focus,
        depth=depth,
        include_endpoints=include_endpoints,
    )




def _exposure_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _exposure_is_new(created: Any, *, days: int = 7) -> bool:
    when = _exposure_datetime(created)
    if not when:
        return False
    return (datetime.now(timezone.utc) - when) < timedelta(days=days)



def _exposure_class(value: str | None, *, kind: str = "web") -> str:
    return exposure_class_for(value, kind=kind)


def _exposure_days_since(value: Any) -> int | None:
    when = _exposure_datetime(value)
    if not when:
        return None
    return max(0, (datetime.now(timezone.utc) - when).days)


def _exposure_recommended_actions(*, kind: str, reasons: list[str], active_verified: int, active_needs_verification: int) -> list[dict[str, str]]:
    """Prioritized, contextual next steps as ``{label, kind}``.

    ``kind`` tells the UI which action the recommendation maps to so it can be
    rendered as a real CTA: ``scan`` (run/refresh coverage), ``findings``
    (triage/verify), ``latest_scan`` (open the latest run), or ``none`` (advisory).
    """
    actions: list[dict[str, str]] = []
    rs = set(reasons)
    if "never_scanned" in rs:
        actions.append({"label": "Run first scan", "kind": "scan"})
    if "failed_scan" in rs:
        actions.append({"label": "Open latest failed scan", "kind": "latest_scan"})
    if "incomplete_scan" in rs:
        actions.append({"label": "Review skipped scan coverage", "kind": "latest_scan"})
    if "stale_scan" in rs:
        actions.append({"label": "Refresh scan", "kind": "scan"})
    if "critical_findings" in rs:
        actions.append({"label": "Triage critical findings", "kind": "findings"})
    elif "high_findings" in rs:
        actions.append({"label": "Triage high findings", "kind": "findings"})
    if "public_high_risk" in rs:
        actions.append({"label": "Prioritize public exposure", "kind": "none"})
    if kind == "ai" and "high_blast_radius" in rs:
        actions.append({"label": "Review AI runtime controls", "kind": "none"})
    if kind == "ai" and "production_ai_risk" in rs:
        actions.append({"label": "Retest production AI surface", "kind": "scan"})
    if kind == "model" and "model_not_approved" in rs:
        actions.append({"label": "Complete model approval", "kind": "none"})
    if active_verified > 0:
        actions.append({"label": "Fix verified findings", "kind": "findings"})
    if active_needs_verification > 0:
        actions.append({"label": "Review Hunt candidates", "kind": "deep_hunt"})
    # Stable de-dupe by label, preserving priority order.
    seen: set[str] = set()
    unique = [a for a in actions if not (a["label"] in seen or seen.add(a["label"]))]
    return unique[:5]


def _asset_from_row(record: Any) -> dict[str, Any]:
    """One response asset from a ranked page row (ranking values come from SQL)."""
    row = row_to_dict(record)
    reasons = list(row.get("action_reasons") or [])
    completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
    last_scanned_at = row.get("last_scanned_at")
    total, crit, high = int(row["total"]), int(row["crit"]), int(row["high"])
    verified, needs_verification = int(row["verified"]), int(row["needs_verification"])
    latest_scan_id = row.get("latest_scan_id")
    meta = _parse_graph_json(row.get("metadata_json"))
    scan = {
        "total_scans": int(row["total_scans"]),
        "last_scanned_at": last_scanned_at,
        "latest_scan_id": latest_scan_id,
        "latest_scan_status": row.get("latest_scan_status"),
        "latest_scan_type": row.get("latest_scan_type"),
        "latest_scan_href": f"/scans/{latest_scan_id}" if latest_scan_id else None,
        "scan_complete": completion["scan_complete"],
        "scan_limited": completion["scan_limited"],
        "coverage_status": completion["coverage_status"],
        "coverage_posture": row["coverage_posture"],
        "skipped_modules_count": completion["skipped_modules_count"],
        "capped_lists_count": completion["capped_lists_count"],
        "scan_age_days": _exposure_days_since(last_scanned_at),
        "action_reasons": reasons,
        "needs_action": bool(reasons),
        "action_priority": row.get("action_priority"),
        "action_score": int(row["action_score"]),
        "recommended_actions": _exposure_recommended_actions(
            kind=row["kind"], reasons=reasons, active_verified=verified,
            active_needs_verification=needs_verification,
        ),
        "first_seen_at": row.get("created_at"),
        "is_new": bool(row["is_new"]),
        "risk_score": int(row["risk_score"]),
    }
    counts = {
        "active_total": total, "active_critical": crit, "active_high": high,
        "active_verified": verified, "active_needs_verification": needs_verification,
    }
    if row["asset_kind"] == "target":
        is_model = row["kind"] == "model"
        return {
            "id": row["id"], "node_id": f"target:{row['id']}", "kind": row["kind"],
            "label": _short_url_label(row.get("url")) or row.get("name") or "",
            "url": row.get("url"),
            "root_domain": None if is_model else row.get("root_domain"),
            "origin": row.get("root_domain") if is_model else None,
            "exposure_class": row["exposure_class"], "cohort": row["cohort"],
            "owner": str(meta.get("owner") or meta.get("asset_owner") or "").strip() or None,
            "environment": str(meta.get("environment") or "").strip().lower() or None,
            "risk_tier": str(meta.get("risk_tier") or "").strip() or None,
            "data_classification": str(meta.get("data_classification") or "").strip() or None,
            "grade": row.get("last_grade"), "score": row.get("last_score"),
            **counts,
            "investigator_verified_count": int(row["investigator_verified"]),
            "investigator_suspected_count": int(row["suspected"]),
            **{key: scan[key] for key in scan if key not in ("first_seen_at", "is_new", "risk_score")},
            "first_seen_at": scan["first_seen_at"], "is_new": scan["is_new"], "risk_score": scan["risk_score"],
            "findings_href": f"/findings?target_id={row['id']}&status=active&freshness=all",
        }
    ai_row = {"metadata_json": row.get("metadata_json"), "target_type": row.get("target_type"),
              "production_mode": row.get("production_mode")}
    blast_radius = build_agent_blast_radius(ai_row, [{"status": "active"} for _ in range(total)])
    # Normalized once at emission (trimmed, lowercased) so every consumer compares the same value.
    environment = (
        str(meta.get("environment") or "").strip().lower()
        or ("production" if row.get("production_mode") else "")
    ) or None
    return {
        "id": row["id"], "node_id": f"ai_target:{row['id']}", "kind": "ai",
        "label": row.get("ai_name") or _short_url_label(row.get("endpoint_url")) or "",
        "url": row.get("endpoint_url"),
        "root_domain": extract_root_domain(row.get("endpoint_url") or ""),
        "target_type": row.get("target_type"),
        "production_mode": bool(row.get("production_mode")),
        "exposure_class": row["exposure_class"], "cohort": row["cohort"],
        "owner": str(meta.get("asset_owner") or meta.get("owner") or "").strip() or None,
        "environment": environment,
        "blast_radius_score": blast_radius.get("score"),
        "blast_radius_tier": blast_radius.get("tier"),
        "blast_radius_factors": blast_radius.get("factors") or [],
        "data_classification": blast_radius.get("data_classification"),
        "risk_tier": blast_radius.get("risk_tier"),
        "missing_runtime_controls": blast_radius.get("missing_runtime_controls") or [],
        "grade": None, "score": None,
        **counts,
        **{key: scan[key] for key in scan if key not in ("first_seen_at", "is_new", "risk_score")},
        "first_seen_at": scan["first_seen_at"], "is_new": scan["is_new"], "risk_score": scan["risk_score"],
        "findings_href": f"/findings?ai_target_id={row['id']}&status=active&freshness=all",
    }


async def _ranked_rows(conn: Any, build: Callable[[SqlParams, dict], str], *, kind: str | None) -> list[Any]:
    """Refresh changed per-asset facts (own short transaction), then run one ranking statement
    built by ``build`` with JIT off."""
    await refresh_facts(conn, include_web=kind in (None, "web", "model"), include_ai=kind in (None, "ai"))
    async with without_jit(conn):
        adjustments = stringify_keys(undetermined_adjustments(await conn.fetch(adjustment_rows_sql())))
        params = SqlParams()
        sql = build(params, adjustments)
        return await conn.fetch(sql, *params.values)


@router.get("/exposure/assets")
async def exposure_assets(
    response: Response = None,
    root_domain: Optional[str] = None,
    kind: Optional[str] = None,
    cohort: Optional[str] = Query(
        None,
        pattern="^(operational|non_operational|production|staging|lab|demo|calibration|internal|unclassified|all)$",
    ),
    limit: Optional[int] = Query(None, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    cursor: Optional[str] = Query(None, max_length=CURSOR_MAX_LENGTH),
    sort: Optional[str] = Query(None, max_length=65),
    fields: Optional[str] = Query(None, max_length=2048),
    count: Optional[Literal["none", "estimate", "exact"]] = None,
    since: Optional[datetime] = None,
):
    """Unified, risk-ranked asset inventory: web targets, AI surfaces and model artifacts with
    their active critical/high/total finding counts, proof counts, coverage and action priority.

    list/v1 (any of ``cursor``/``count``/``fields``): keyset pages (limit 1..200, default 50;
    ``sort`` = ``-priority`` (default) | ``-risk`` | ``-first_seen``, ``-`` descends) with the
    headline ``summary`` (metrics, cohort counts) over every matching asset. Otherwise the
    deprecated limit/offset response (limit up to 2000, default 1000). Ranking, metrics and
    cohort counts are SQL over per-asset summaries; only the page's rows are built here.
    """
    root_domain, kind, cohort, limit, offset, cursor, sort, fields, count, since = (direct(value) for value in (
        root_domain, kind, cohort, limit, offset, cursor, sort, fields, count, since))
    selected_cohort = str(cohort if isinstance(cohort, str) else "all")
    now = datetime.now(timezone.utc)
    if wants_list_v1(cursor=cursor, count=count, fields=fields, since=since):
        page = v1_page(limit=limit, cursor=cursor, sort=sort, fields=fields, count=count, since=since)
        plan = ASSETS_LIST.plan(page, filters={"root_domain": root_domain, "kind": kind, "cohort": selected_cohort})
        async with _pool().acquire() as conn:
            generated_at = await snapshot_time(conn)
            rows = await _ranked_rows(conn, lambda params, adjustments: keyset_page_sql(
                params, plan, root_domain=root_domain, kind=kind, cohort=selected_cohort, now=now,
                adjustments=adjustments), kind=kind)
        head = rows[0]
        metrics, new_count = metrics_from(head)
        empty = dict.fromkeys(ASSETS_LIST.fields)
        items = [{**empty, **_asset_from_row(row), **{key: row[key] for key in row.keys() if key.startswith("__list_")}}
                 for row in rows if row["id"] is not None]
        total, total_kind = metrics["asset_count"], (page.count or "none")
        if total_kind == "exact" and total > EXACT_COUNT_CAP:
            total, total_kind = EXACT_COUNT_CAP, "at_least"
        body = plan.envelope(items, total=total, total_kind=total_kind, generated_at=generated_at)
        body["summary"] = {
            "metrics": metrics, "new_count": new_count, "cohort": selected_cohort,
            "cohort_counts": _cohort_counts(head),
        }
        return body
    if sort is not None:
        raise HTTPException(400, "sort is list/v1 only; add count=none (or a cursor) to use it")
    limit = 1000 if limit is None else limit
    mark_deprecated(response)
    async with _pool().acquire() as conn:
        rows = await _ranked_rows(conn, lambda params, adjustments: offset_page_sql(
            params, root_domain=root_domain, kind=kind, cohort=selected_cohort, now=now,
            adjustments=adjustments, limit=limit, offset=offset), kind=kind)
    head = rows[0]
    metrics, new_count = metrics_from(head)
    assets = [_asset_from_row(row) for row in rows if row["id"] is not None]
    total = metrics["asset_count"]
    return {
        "assets": assets,
        "count": len(assets),
        "total": total,
        "offset": offset,
        "new_count": new_count,
        "metrics": metrics,
        "cohort": selected_cohort,
        "cohort_counts": _cohort_counts(head),
        "truncated": offset + len(assets) < total,
    }


def _cohort_counts(row: Any) -> dict[str, int]:
    value = row["cohort_counts"]
    decoded = json.loads(value) if isinstance(value, str) else (value or {})
    return {str(key): int(count) for key, count in decoded.items()}



@router.get("/exposure/changes")
async def exposure_changes(
    since: Optional[str] = None,
    root_domain: Optional[str] = None,
    days: int = Query(7, ge=1, le=90),
    examples: int = Query(5, ge=0, le=10),
):
    """Awareness deltas for the exposure page: what changed since an anchor.

    ``since`` (ISO timestamp, e.g. the user's last visit) wins over ``days``.
    Categories cover new assets, new active critical/high findings, resolved
    findings, failed scans, and assets whose coverage crossed the 30-day stale
    threshold inside the window. Each category carries an ``href`` to the
    exposure/findings view that shows that slice.
    """
    anchor = _exposure_datetime(since) if since else None
    if since and anchor is None:
        raise HTTPException(status_code=400, detail="Invalid 'since' timestamp")
    if anchor is None:
        anchor = datetime.now(timezone.utc) - timedelta(days=days)

    # Each category is a COUNT plus its newest ``examples`` rows: the window can hold every finding.
    async def counted(conn: Any, from_where: str, columns: str, order: str) -> tuple[int, list[Any]]:
        total = await conn.fetchval(f"SELECT count(*) {from_where}", anchor, root_domain)
        rows = await conn.fetch(
            f"SELECT {columns} {from_where} ORDER BY {order} LIMIT $3", anchor, root_domain, examples,
        ) if examples else []
        return int(total or 0), list(rows)

    findings_scope = """
              AND ($2::text IS NULL
                   OR f.target_id IN (SELECT id FROM targets WHERE root_domain = $2::text)
                   OR f.ai_target_id IN (SELECT id FROM ai_targets
                                         WHERE LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%'))"""
    finding_columns = """f.title, f.severity, f.first_seen_at, f.resolved_at,
                   COALESCE((SELECT root_domain FROM targets WHERE id = f.target_id),
                            (SELECT name FROM ai_targets WHERE id = f.ai_target_id), f.url) AS subject"""
    async with _pool().acquire() as conn:
        new_targets_count, new_targets = await counted(
            conn,
            """FROM targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR root_domain = $2::text)""",
            "COALESCE(name, url) AS label, url, discovery_source, created_at", "created_at DESC",
        )
        new_ai_count, new_ai = await counted(
            conn,
            """FROM ai_targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')""",
            "name AS label, endpoint_url AS url, created_at", "created_at DESC",
        )
        new_critical_count, new_critical = await counted(
            conn,
            f"""FROM findings f
            WHERE f.status = 'active' AND f.severity = 'critical' AND f.first_seen_at > $1{findings_scope}""",
            finding_columns, "f.first_seen_at DESC",
        )
        new_high_count, new_high = await counted(
            conn,
            f"""FROM findings f
            WHERE f.status = 'active' AND f.severity = 'high' AND f.first_seen_at > $1{findings_scope}""",
            finding_columns, "f.first_seen_at DESC",
        )
        resolved_count, resolved_findings = await counted(
            conn,
            f"""FROM findings f
            WHERE f.status = 'resolved' AND f.resolved_at > $1 AND {not_retired_sql("f")}{findings_scope}""",
            finding_columns, "f.resolved_at DESC",
        )
        failed_scans_count, failed_scans = await counted(
            conn,
            """FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.status = 'failed' AND s.created_at > $1
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')""",
            "s.id, s.target_url AS label, s.scan_type, s.created_at", "s.created_at DESC",
        )
        went_stale_web_count, went_stale_web = await counted(
            conn,
            """FROM targets
            WHERE is_active = true AND total_scans > 0 AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR root_domain = $2::text)""",
            "COALESCE(name, url) AS label, last_scanned_at", "last_scanned_at DESC",
        )
        # AI surfaces go stale too — the destination view's stale-window filter
        # spans every asset kind, so the tile must count the same population.
        went_stale_ai_count, went_stale_ai = await counted(
            conn,
            """FROM ai_targets
            WHERE is_active = true AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')""",
            "name AS label, last_scanned_at", "last_scanned_at DESC",
        )
    went_stale = sorted(
        [*went_stale_web, *went_stale_ai],
        key=lambda r: _exposure_datetime(r["last_scanned_at"]) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    def fmt_when(value: Any) -> str | None:
        when = _exposure_datetime(value)
        return when.isoformat() if when else None

    # Each category links to the *same slice it counted*: window, severity, and
    # domain scope all carry into the target view instead of dropping to a
    # broader list. Day-based windows pass through exactly; arbitrary `since`
    # anchors round up to whole days (links may include up to one extra day —
    # never less than what was counted).
    if since:
        window_days = max(1, math.ceil((datetime.now(timezone.utc) - anchor).total_seconds() / 86400))
    else:
        window_days = days

    def href(path: str, **params: Any) -> str:
        from urllib.parse import urlencode
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if root_domain:
            # The Targets page narrows by its search box; the other pages by domain.
            clean["search" if path == "/targets" else "domain"] = root_domain
        return f"{path}?{urlencode(clean)}" if clean else path

    new_asset_examples = [
        {
            "label": r["label"],
            "detail": "model" if r["discovery_source"] == "model-intake" else "web",
            "when": fmt_when(r["created_at"]),
        }
        for r in new_targets
    ] + [
        {"label": r["label"] or r["url"], "detail": "ai", "when": fmt_when(r["created_at"])}
        for r in new_ai
    ]
    new_asset_examples.sort(key=lambda e: e["when"] or "", reverse=True)

    def finding_examples(rows: list, when_key: str) -> list[dict[str, Any]]:
        return [
            {
                "label": r["title"],
                "detail": " · ".join(filter(None, [r["severity"], r["subject"]])),
                "when": fmt_when(r[when_key]),
            }
            for r in rows[:examples]
        ]

    categories = [
        {
            "key": "new_assets",
            "label": "New assets",
            "count": new_targets_count + new_ai_count,
            "href": href("/targets", sort="created"),
            "examples": new_asset_examples[:examples],
        },
        {
            "key": "new_critical",
            "label": "New critical findings",
            "count": new_critical_count,
            "href": href(
                "/findings", status="active", severity="critical",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_critical, "first_seen_at"),
        },
        {
            "key": "new_high",
            "label": "New high findings",
            "count": new_high_count,
            "href": href(
                "/findings", status="active", severity="high",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_high, "first_seen_at"),
        },
        {
            "key": "resolved",
            "label": "Findings resolved",
            "count": resolved_count,
            "href": href("/findings", status="resolved", resolved_within=window_days, sort_by="last_seen", sort_order="desc"),
            "examples": finding_examples(resolved_findings, "resolved_at"),
        },
        {
            "key": "failed_scans",
            "label": "Failed scans",
            "count": failed_scans_count,
            "href": href("/scans", status="failed", within=window_days),
            "examples": [
                {"label": r["label"], "detail": r["scan_type"], "when": fmt_when(r["created_at"])}
                for r in failed_scans[:examples]
            ],
        },
        {
            "key": "went_stale",
            "label": "Went stale",
            "count": went_stale_web_count + went_stale_ai_count,
            "href": href("/targets", activity="scanned"),
            "examples": [
                {
                    "label": r["label"],
                    "detail": f"{_exposure_days_since(r['last_scanned_at'])}d since scan",
                    "when": fmt_when(r["last_scanned_at"]),
                }
                for r in went_stale[:examples]
            ],
        },
    ]
    return {
        "since": anchor.isoformat(),
        "total_changes": sum(c["count"] for c in categories),
        "categories": categories,
    }


def _graph_node(
    node_id: str,
    node_type: str,
    label: str,
    *,
    subtitle: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    href: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "label": label,
        "subtitle": subtitle,
        "severity": severity,
        "status": status,
        "href": href,
        "meta": meta or {},
    }


def _graph_edge(
    source: str,
    target: str,
    edge_type: str,
    *,
    label: str | None = None,
    severity: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "type": edge_type,
        "label": label or edge_type.replace("_", " "),
        "severity": severity,
        "meta": meta or {},
    }


def _highest_severity(values: list[str | None]) -> str | None:
    severities = [v for v in values if v in SEVERITY_ORDER]
    if not severities:
        return None
    return max(severities, key=_severity_sort_value)


def _graph_hash(*values: Any) -> str:
    raw = "|".join(str(value or "") for value in values)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:14]


def _normalize_graph_endpoint_url(base_url: str | None, value: str | None) -> str | None:
    if not value:
        return None
    value_s = str(value)
    if value_s.startswith(("http://", "https://")):
        return value_s
    if base_url:
        try:
            return urllib.parse.urljoin(base_url if str(base_url).endswith("/") else f"{base_url}/", value_s.lstrip("/"))
        except Exception:
            return value_s
    return value_s


def _endpoint_path_key(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urllib.parse.urlparse(value if "://" in value else f"https://placeholder.local{value if str(value).startswith('/') else '/' + str(value)}")
        return (parsed.path or "/").rstrip("/") or "/"
    except Exception:
        return str(value).split("?", 1)[0].rstrip("/") or "/"


def _iter_graph_openapi_endpoints(result: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [
        _graph_get(result, "discovery", "api_security", "openapi", "endpoints"),
        _graph_get(result, "discovery", "openapi", "endpoints"),
        _graph_get(result, "api_security", "openapi", "endpoints"),
        _graph_get(result, "openapi", "endpoints"),
    ]
    for candidate in candidates:
        endpoints = _graph_list(candidate)
        if endpoints:
            normalized = []
            for item in endpoints:
                if isinstance(item, dict):
                    method = str(item.get("method") or "GET").upper()
                    path = item.get("path") or item.get("url")
                    if path:
                        normalized.append({**item, "method": method, "path": path})
                elif isinstance(item, str):
                    match = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+?)\s*$", item, re.I)
                    if match:
                        normalized.append({"method": match.group(1).upper(), "path": match.group(2)})
                    else:
                        normalized.append({"method": "GET", "path": item})
            return normalized
    return []


def _openapi_meta(result: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        _graph_get(result, "discovery", "api_security", "openapi"),
        _graph_get(result, "discovery", "openapi"),
        _graph_get(result, "api_security", "openapi"),
        _graph_get(result, "openapi"),
    ]
    for candidate in candidates:
        meta = _parse_graph_json(candidate)
        if meta:
            return meta
    return {}


def _iter_browser_api_endpoints(result: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints = _graph_list(_graph_get(result, "discovery", "browser_api_endpoints"))
    normalized = []
    for item in endpoints:
        if isinstance(item, dict):
            url = item.get("url") or item.get("endpoint")
            if url:
                normalized.append({
                    "url": url,
                    "method": str(item.get("method") or "GET").upper(),
                    "source": "browser",
                    **item,
                })
        elif isinstance(item, str):
            normalized.append({"url": item, "method": "GET", "source": "browser"})
    return normalized


def _iter_graph_cloud_hints(result: dict[str, Any]) -> list[dict[str, Any]]:
    cloud = _parse_graph_json(_graph_get(result, "discovery", "cloud_services") or result.get("cloud_services"))
    hints: list[dict[str, Any]] = []
    for key in ("providers", "detected_providers", "services", "hints"):
        for item in _graph_list(cloud.get(key)):
            if isinstance(item, dict):
                label = item.get("provider") or item.get("service") or item.get("name") or item.get("type")
                if label:
                    hints.append({**item, "label": str(label)})
            elif item:
                hints.append({"label": str(item), "source": key})
    for key in ("aws", "azure", "gcp", "cloudflare"):
        if cloud.get(key):
            hints.append({"label": key, "evidence": cloud.get(key)})
    return hints[:20]


def _iter_graph_auth_roles(result: dict[str, Any], ai_target: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    roles: list[dict[str, Any]] = []
    auth_states = _graph_list(_graph_get(result, "smart_coverage", "auth_states_tested"))
    for item in auth_states:
        if item:
            roles.append({"label": str(item), "source": "smart_coverage"})
    for key in ("roles_tested", "auth_roles", "scopes_tested"):
        for item in _graph_list(_graph_get(result, "auth", key) or _graph_get(result, "identity", key)):
            if isinstance(item, dict):
                label = item.get("role") or item.get("scope") or item.get("name")
                if label:
                    roles.append({**item, "label": str(label), "source": key})
            elif item:
                roles.append({"label": str(item), "source": key})
    metadata = _parse_graph_json((ai_target or {}).get("metadata_json"))
    for item in _graph_list(metadata.get("oauth_scopes") or metadata.get("default_scopes")):
        if item:
            roles.append({"label": str(item), "source": "ai_target_oauth_scope"})
    deduped: dict[str, dict[str, Any]] = {}
    for role in roles:
        deduped.setdefault(str(role.get("label")), role)
    return list(deduped.values())[:25]


def _iter_graph_mcp_tools(result: dict[str, Any]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    ai_gate = _parse_graph_json(result.get("ai_gate"))
    transcripts = _graph_list(ai_gate.get("transcripts"))
    for transcript in transcripts:
        evidence = _parse_graph_json(transcript.get("widget_evidence")) or _parse_graph_json(transcript.get("evidence"))
        for item in _graph_list(evidence.get("tool_inventory") or evidence.get("tools") or evidence.get("mcp_tools")):
            if isinstance(item, dict):
                name = item.get("name") or item.get("tool") or item.get("id")
                if name:
                    tools.append({**item, "label": str(name)})
            elif item:
                tools.append({"label": str(item)})
    for finding in _graph_list(ai_gate.get("findings")):
        if not isinstance(finding, dict):
            continue
        ev = _parse_graph_json(finding.get("evidence"))
        for marker in _graph_list(ev.get("matched_markers")):
            if "mcp" in str(marker).lower() or "tool" in str(marker).lower():
                tools.append({
                    "label": str(marker).replace("_", " "),
                    "source_finding_id": finding.get("id"),
                    "severity": finding.get("severity"),
                })
    deduped: dict[str, dict[str, Any]] = {}
    for tool in tools:
        deduped.setdefault(str(tool.get("label")), tool)
    return list(deduped.values())[:30]


_EXPOSURE_STRUCTURAL_EDGE_TYPES = {
    "defines_endpoint",
    "exposes_endpoint",
    "observed_endpoint",
}


def _cluster_exposure_findings(
    sub_nodes: list[dict[str, Any]],
    sub_edges: list[dict[str, Any]],
    *,
    min_group: int = 3,
    protect_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collapse repetitive findings on the same asset into one group node.

    Findings that share a parent asset (via a ``has_finding`` edge) and a
    normalised title are merged into a single ``finding_group`` node carrying
    the members in ``meta.members``. Groups smaller than ``min_group`` stay as
    individual nodes. Edges touching grouped members are rewired to the group.
    ``protect_id`` (the focused node) is never folded into a group so it stays
    addressable.
    """
    nodes_by_id = {n["id"]: n for n in sub_nodes}

    # Parent asset for each finding = source of its has_finding edge.
    parent_of: dict[str, str] = {}
    for edge in sub_edges:
        if edge["type"] == "has_finding" and edge["target"] in nodes_by_id:
            parent_of.setdefault(edge["target"], edge["source"])

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for node in sub_nodes:
        if node["type"] != "finding" or node["id"] == protect_id:
            continue
        parent = parent_of.get(node["id"])
        if not parent:
            continue
        key = (parent, _normalize_finding_title(node["label"]).lower())
        groups.setdefault(key, []).append(node)

    member_to_group: dict[str, str] = {}
    group_nodes: dict[str, dict[str, Any]] = {}
    for (parent, norm_key), members in groups.items():
        if len(members) < min_group:
            continue
        members_sorted = sorted(members, key=lambda m: _severity_sort_value(m.get("severity")), reverse=True)
        display_title = _normalize_finding_title(members_sorted[0]["label"])
        group_id = f"finding_group:{_graph_hash(parent, norm_key)}"
        top_severity = members_sorted[0].get("severity")
        for member in members_sorted:
            member_to_group[member["id"]] = group_id
        group_nodes[group_id] = _graph_node(
            group_id,
            "finding_group",
            f"{display_title} ×{len(members_sorted)}",
            subtitle=f"{len(members_sorted)} similar findings",
            severity=top_severity,
            meta={
                "count": len(members_sorted),
                "normalized_title": display_title,
                "members": [
                    {
                        "id": m["id"],
                        "title": m["label"],
                        "severity": m.get("severity"),
                        "status": m.get("meta", {}).get("status"),
                        "href": m.get("href"),
                    }
                    for m in members_sorted
                ],
            },
        )

    if not group_nodes:
        return sub_nodes, sub_edges

    new_nodes = [n for n in sub_nodes if n["id"] not in member_to_group]
    new_nodes.extend(group_nodes.values())

    seen_edges: set[tuple[str, str, str]] = set()
    new_edges: list[dict[str, Any]] = []
    for edge in sub_edges:
        source = member_to_group.get(edge["source"], edge["source"])
        target = member_to_group.get(edge["target"], edge["target"])
        if source == target:
            continue
        key = (source, target, edge["type"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        new_edges.append({**edge, "source": source, "target": target})

    return new_nodes, new_edges




def _normalize_finding_title(title: str) -> str:
    """Collapse instance-specific detail so similar findings group together.

    "Accessible Sensitive File: /.git/config" and ".../wp-config.php.old" both
    normalise to "Accessible Sensitive File"; "SQL Injection (post id)" to
    "SQL Injection".
    """
    base = re.split(r"[:(]", str(title or ""), maxsplit=1)[0]
    return base.strip() or str(title or "").strip()
