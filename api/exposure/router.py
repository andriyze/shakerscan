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
import ipaddress
import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any, Callable, Optional
import urllib.parse
import uuid

from fastapi import APIRouter, HTTPException, Query

try:
    from ai_assurance import build_agent_blast_radius
    from api_utils import (
        SEVERITY_ORDER, extract_root_domain, _graph_get, _graph_list, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_graph_json, _row_value, _scan_completion_flags, _severity_sort_value,
        _short_url_label, _uuid_or_400,
    )
    from serialization import _decode_json_value, _json_object, _str_list, row_to_dict
except ModuleNotFoundError:  # package import in host-side tests
    from ..ai_assurance import build_agent_blast_radius
    from ..api_utils import (
        SEVERITY_ORDER, extract_root_domain, _graph_get, _graph_list, _int_or_none, _iso_or_none, _optional_uuid,
        _parse_graph_json, _row_value, _scan_completion_flags, _severity_sort_value,
        _short_url_label, _uuid_or_400,
    )
    from ..serialization import _decode_json_value, _json_object, _str_list, row_to_dict


router = APIRouter()

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
    endpoint_node_by_path: dict[tuple[str | None, str | None], list[str]] = {}
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
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _endpoint_path_key(endpoint_url) or path)}"
                endpoint_node_by_path.setdefault((subject_root_domain, _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
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
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _endpoint_path_key(endpoint_url))}"
                endpoint_node_by_path.setdefault((subject_root_domain, _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
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
        for endpoint_node_id in endpoint_node_by_path.get((root_domain, finding_path), [])[:5]:
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


@router.get("/exposure/nodes")
async def exposure_nodes(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit: int = Query(2000, ge=1, le=5000),
):
    """Lightweight searchable index of exposure nodes (id/label/type/severity).

    Node ids match those produced by the graph builder so a selected result can
    be passed straight back as ``focus`` to /exposure/graph. Fetched once by the
    UI and filtered client-side as the user types.
    """
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def emit(node_id: str, node_type: str, label: str, severity: str | None = None) -> None:
        if not label or node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "label": label, "severity": severity})

    async with _pool().acquire() as conn:
        target_rows = await conn.fetch(
            """
            SELECT id, url, name, root_domain, discovery_source
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY active_findings_count DESC NULLS LAST
            LIMIT $3
            """,
            include_inactive,
            root_domain,
            limit,
        )
        for row in target_rows:
            row = row_to_dict(row)
            node_type = "model_artifact" if row.get("discovery_source") == "model-intake" else "web_target"
            emit(f"target:{row['id']}", node_type, _short_url_label(row.get("url")) or str(row.get("name") or ""))
            if row.get("root_domain"):
                emit(f"domain:{row['root_domain']}", "domain", str(row["root_domain"]))

        ai_rows = await conn.fetch(
            """
            SELECT id, name, endpoint_url, target_type
            FROM ai_targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT $3
            """,
            include_inactive,
            root_domain,
            limit,
        )
        for row in ai_rows:
            row = row_to_dict(row)
            emit(f"ai_target:{row['id']}", "ai_target", str(row.get("name") or _short_url_label(row.get("endpoint_url"))))

        finding_rows = await conn.fetch(
            """
            SELECT f.id, f.title, f.severity
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets a ON f.ai_target_id = a.id
            WHERE ($1::boolean = true OR f.status = 'active')
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4 ELSE 5
                END,
                f.last_seen_at DESC NULLS LAST
            LIMIT $3
            """,
            include_resolved,
            root_domain,
            limit,
        )
        for row in finding_rows:
            row = row_to_dict(row)
            emit(f"finding:{row['id']}", "finding", str(row.get("title") or "Finding"), row.get("severity"))

    return {"nodes": nodes, "count": len(nodes)}


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


def _exposure_risk_score(critical: int, high: int, total: int) -> int:
    return critical * 1000 + high * 50 + total


def _exposure_class(value: str | None, *, kind: str = "web") -> str:
    if kind == "model":
        return "supply_chain"
    host = _exposure_hostname(value)
    if not host:
        return "unknown"
    if host in {"localhost", "host.docker.internal"} or host.endswith(".internal") or host.endswith(".local"):
        return "internal"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return "internal"
    except ValueError:
        pass
    if "." not in host:
        return "internal"
    return "public"


def _exposure_days_since(value: Any) -> int | None:
    when = _exposure_datetime(value)
    if not when:
        return None
    return max(0, (datetime.now(timezone.utc) - when).days)


def _exposure_action_priority(
    reasons: list[str],
    *,
    exposure_class: str,
    active_critical: int,
    active_high: int,
) -> tuple[str | None, int]:
    """Return ``(priority, score)`` for ranking. ``None`` when no action needed.

    P1 = exploitable risk on an exposed/production surface, P2 = high-severity or
    high-blast exposure, P3 = scan-hygiene only (stale / incomplete / unscanned).
    """
    rs = set(reasons)
    if not rs:
        return None, 0
    if active_critical > 0 or "production_ai_risk" in rs:
        priority = "P1"
    elif "public_high_risk" in rs or "high_blast_radius" in rs or active_high > 0:
        priority = "P2"
    else:
        priority = "P3"
    score = _EXPOSURE_PRIORITY_WEIGHT[priority] + active_critical * 10 + active_high
    if exposure_class == "public":
        score += 25
    return priority, score


def _exposure_action_reasons(
    *,
    kind: str,
    exposure_class: str,
    active_critical: int,
    active_high: int,
    total_scans: int,
    last_scanned_at: Any,
    scan_limited: bool,
    production_mode: bool = False,
    blast_radius_tier: str | None = None,
    deployment_approved: bool | None = None,
    latest_scan_status: str | None = None,
) -> list[str]:
    reasons: list[str] = []
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        reasons.append("never_scanned")
    elif days is not None and days >= 30:
        reasons.append("stale_scan")
    if latest_scan_status == "failed":
        reasons.append("failed_scan")
    if scan_limited:
        reasons.append("incomplete_scan")
    if active_critical > 0:
        reasons.append("critical_findings")
    elif active_high > 0:
        reasons.append("high_findings")
    if exposure_class == "public" and (active_critical > 0 or active_high > 0):
        reasons.append("public_high_risk")
    if kind == "ai" and production_mode and (active_critical > 0 or active_high > 0):
        reasons.append("production_ai_risk")
    if kind == "ai" and blast_radius_tier in {"high", "critical"}:
        reasons.append("high_blast_radius")
    if kind == "model" and deployment_approved is False:
        reasons.append("model_not_approved")
    return reasons


def _exposure_coverage_posture(*, total_scans: int, last_scanned_at: Any, scan_limited: bool, latest_scan_status: str | None) -> str:
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        return "unscanned"
    if latest_scan_status == "failed":
        return "failed"
    if scan_limited:
        return "limited"
    if days is not None and days >= 30:
        return "stale"
    return "fresh"


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


@router.get("/exposure/assets")
async def exposure_assets(
    root_domain: Optional[str] = None,
    kind: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Unified, risk-ranked asset inventory for the triage view.

    Merges web targets, AI surfaces, and model artifacts with their active
    critical/high/total finding counts (uncapped SQL aggregation), grade, and
    first-seen timestamp. Each asset carries the graph ``node_id`` so the UI can
    jump straight into the Map lens focused on it.
    """
    async with _pool().acquire() as conn:
        target_rows = await conn.fetch(
            """
            SELECT t.id, t.url, t.name, t.root_domain, t.discovery_source, t.metadata_json,
                   t.last_grade, t.last_score, t.last_scanned_at, t.created_at, t.total_scans,
                   ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                   ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                   ls.completed_at AS latest_scan_completed_at,
                   COALESCE(fc.active_total, 0) AS active_total,
                   COALESCE(fc.active_critical, 0) AS active_critical,
                   COALESCE(fc.active_high, 0) AS active_high,
                   COALESCE(fc.active_verified, 0) AS active_verified,
                   COALESCE(fc.active_needs_verification, 0)
                       + COALESCE(ic.investigator_suspected_count, 0) AS active_needs_verification,
                   COALESCE(fc.investigator_verified_count, 0) AS investigator_verified_count,
                   COALESCE(ic.investigator_suspected_count, 0) AS investigator_suspected_count
            FROM targets t
            LEFT JOIN LATERAL (
                SELECT id, status, scan_type, completed_at,
                       result -> 'scan_completion_status' AS completion_status,
                       result ->> 'coverage_status' AS top_coverage_status
                FROM scans s
                WHERE s.target_id = t.id
                  AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
                ORDER BY s.created_at DESC
                LIMIT 1
            ) ls ON true
            LEFT JOIN (
                SELECT target_id,
                    COUNT(*) FILTER (WHERE status = 'active') AS active_total,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS active_critical,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS active_high,
                    COUNT(*) FILTER (WHERE status = 'active' AND last_verification_verdict = 'exploited') AS active_verified,
                    COUNT(*) FILTER (
                        WHERE status = 'active'
                          AND last_verification_verdict = 'exploited'
                          AND tool IN ('autonomous_workflow', 'bola')
                    ) AS investigator_verified_count,
                    COUNT(*) FILTER (
                        WHERE status = 'active'
                          AND (
                            last_verification_verdict IS NULL
                            OR last_verification_verdict IN ('inconclusive', 'error', 'likely_vulnerable')
                            OR analyst_verdict IN ('needs_review', 'retest_needed')
                          )
                    ) AS active_needs_verification
                FROM findings WHERE target_id IS NOT NULL GROUP BY target_id
            ) fc ON fc.target_id = t.id
            LEFT JOIN (
                SELECT target_id, COUNT(*) AS investigator_suspected_count
                FROM investigation_candidates
                WHERE plane='web'
                  AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
                GROUP BY target_id
            ) ic ON ic.target_id = t.id
            WHERE t.is_active = true
              AND ($1::text IS NULL OR t.root_domain = $1::text)
            """,
            root_domain,
        )

        ai_rows = await conn.fetch(
            """
            SELECT a.id, a.name, a.endpoint_url, a.target_type, a.production_mode,
                   a.last_scanned_at, a.created_at, a.metadata_json,
                   ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                   ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                   ls.completed_at AS latest_scan_completed_at,
                   COALESCE(sc.scan_count, 0) AS scan_count,
                   COALESCE(fc.active_total, 0) AS active_total,
                   COALESCE(fc.active_critical, 0) AS active_critical,
                   COALESCE(fc.active_high, 0) AS active_high,
                   COALESCE(fc.active_verified, 0) AS active_verified,
                   COALESCE(fc.active_needs_verification, 0) AS active_needs_verification
            FROM ai_targets a
            LEFT JOIN LATERAL (
                SELECT id, status, scan_type, completed_at,
                       result -> 'scan_completion_status' AS completion_status,
                       result ->> 'coverage_status' AS top_coverage_status
                FROM scans s
                WHERE s.ai_target_id = a.id
                ORDER BY s.created_at DESC
                LIMIT 1
            ) ls ON true
            LEFT JOIN (
                SELECT ai_target_id, COUNT(*) AS scan_count
                FROM scans WHERE ai_target_id IS NOT NULL GROUP BY ai_target_id
            ) sc ON sc.ai_target_id = a.id
            LEFT JOIN (
                SELECT ai_target_id,
                    COUNT(*) FILTER (WHERE status = 'active') AS active_total,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS active_critical,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS active_high,
                    COUNT(*) FILTER (WHERE status = 'active' AND last_verification_verdict = 'exploited') AS active_verified,
                    COUNT(*) FILTER (
                        WHERE status = 'active'
                          AND (
                            last_verification_verdict IS NULL
                            OR last_verification_verdict IN ('inconclusive', 'error', 'likely_vulnerable')
                            OR analyst_verdict IN ('needs_review', 'retest_needed')
                          )
                    ) AS active_needs_verification
                FROM findings WHERE ai_target_id IS NOT NULL GROUP BY ai_target_id
            ) fc ON fc.ai_target_id = a.id
            WHERE a.is_active = true
              AND ($1::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER($1::text) || '%')
            """,
            root_domain,
        )

    assets: list[dict[str, Any]] = []

    for row in target_rows:
        row = row_to_dict(row)
        is_model = row.get("discovery_source") == "model-intake"
        asset_kind = "model" if is_model else "web"
        if kind and kind != asset_kind:
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        verified = int(row.get("active_verified") or 0)
        needs_verification = int(row.get("active_needs_verification") or 0)
        investigator_verified = int(row.get("investigator_verified_count") or 0)
        investigator_suspected = int(row.get("investigator_suspected_count") or 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("url"), kind=asset_kind)
        total_scans = int(row.get("total_scans") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        action_reasons = _exposure_action_reasons(
            kind=asset_kind,
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            deployment_approved=None,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        meta = _parse_graph_json(row.get("metadata_json"))
        assets.append({
            "id": str(row["id"]),
            "node_id": f"target:{row['id']}",
            "kind": asset_kind,
            "label": _short_url_label(row.get("url")) or row.get("name") or "",
            "url": row.get("url"),
            "root_domain": None if is_model else row.get("root_domain"),
            "origin": row.get("root_domain") if is_model else None,
            "exposure_class": exposure_class,
            "owner": str(meta.get("owner") or meta.get("asset_owner") or "").strip() or None,
            "environment": str(meta.get("environment") or "").strip().lower() or None,
            "risk_tier": str(meta.get("risk_tier") or "").strip() or None,
            "data_classification": str(meta.get("data_classification") or "").strip() or None,
            "grade": row.get("last_grade"),
            "score": row.get("last_score"),
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "investigator_verified_count": investigator_verified,
            "investigator_suspected_count": investigator_suspected,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind=asset_kind,
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?target_id={row['id']}&status=active",
        })

    for row in ai_rows:
        row = row_to_dict(row)
        if kind and kind != "ai":
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        verified = int(row.get("active_verified") or 0)
        needs_verification = int(row.get("active_needs_verification") or 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("endpoint_url"), kind="ai")
        total_scans = int(row.get("scan_count") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        blast_radius = build_agent_blast_radius(row, [{"status": "active"} for _ in range(total)])
        blast_radius_tier = str(blast_radius.get("tier") or "")
        ai_meta = _parse_graph_json(row.get("metadata_json"))
        ai_owner = str(ai_meta.get("asset_owner") or ai_meta.get("owner") or "").strip() or None
        # Normalized once at emission (trimmed, lowercased) so every consumer —
        # UI prod filter/confirmation, API metrics, action reasons — compares
        # the same canonical value regardless of how metadata was written.
        ai_environment = (
            str(ai_meta.get("environment") or "").strip().lower()
            or ("production" if row.get("production_mode") else "")
        ) or None
        # Production semantics shared with the UI's isProductionAIAsset(): the
        # explicit flag OR declared environment metadata. Keeps action reasons,
        # P1 promotion, and metrics consistent with the UI's scan confirmation.
        ai_is_production = bool(row.get("production_mode")) or (
            str(ai_meta.get("environment") or "").strip().lower() == "production"
        )
        action_reasons = _exposure_action_reasons(
            kind="ai",
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            production_mode=ai_is_production,
            blast_radius_tier=blast_radius_tier,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        assets.append({
            "id": str(row["id"]),
            "node_id": f"ai_target:{row['id']}",
            "kind": "ai",
            "label": row.get("name") or _short_url_label(row.get("endpoint_url")) or "",
            "url": row.get("endpoint_url"),
            "root_domain": extract_root_domain(row.get("endpoint_url") or ""),
            "target_type": row.get("target_type"),
            "production_mode": bool(row.get("production_mode")),
            "exposure_class": exposure_class,
            "owner": ai_owner,
            "environment": ai_environment,
            "blast_radius_score": blast_radius.get("score"),
            "blast_radius_tier": blast_radius.get("tier"),
            "blast_radius_factors": blast_radius.get("factors") or [],
            "data_classification": blast_radius.get("data_classification"),
            "risk_tier": blast_radius.get("risk_tier"),
            "missing_runtime_controls": blast_radius.get("missing_runtime_controls") or [],
            "grade": None,
            "score": None,
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind="ai",
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?ai_target_id={row['id']}&status=active",
        })

    # Headline metrics from the full (uncapped) set so the stat row stays
    # accurate and independent of the heavier graph fetch. Compute before the
    # display limit is applied.
    metrics = {
        "asset_count": len(assets),
        "active_critical": sum(a["active_critical"] for a in assets),
        "active_high": sum(a["active_high"] for a in assets),
        "active_verified": sum(a.get("active_verified", 0) for a in assets),
        "active_needs_verification": sum(a.get("active_needs_verification", 0) for a in assets),
        "ai_surfaces": sum(1 for a in assets if a["kind"] == "ai"),
        "web_targets": sum(1 for a in assets if a["kind"] == "web"),
        "model_artifacts": sum(1 for a in assets if a["kind"] == "model"),
        "public_assets": sum(1 for a in assets if a.get("exposure_class") == "public"),
        "internal_assets": sum(1 for a in assets if a.get("exposure_class") == "internal"),
        "unscanned_assets": sum(1 for a in assets if "never_scanned" in a.get("action_reasons", [])),
        "stale_assets": sum(1 for a in assets if "stale_scan" in a.get("action_reasons", [])),
        "incomplete_scans": sum(1 for a in assets if "incomplete_scan" in a.get("action_reasons", [])),
        "failed_scans": sum(1 for a in assets if "failed_scan" in a.get("action_reasons", [])),
        "fresh_scans": sum(1 for a in assets if a.get("coverage_posture") == "fresh"),
        "verified_assets": sum(1 for a in assets if (a.get("active_verified") or 0) > 0),
        "investigator_verified_assets": sum(1 for a in assets if (a.get("investigator_verified_count") or 0) > 0),
        "investigator_suspected_assets": sum(1 for a in assets if (a.get("investigator_suspected_count") or 0) > 0),
        "unverified_high_assets": sum(
            1 for a in assets
            if (a.get("active_needs_verification") or 0) > 0
            and (a.get("active_critical", 0) + a.get("active_high", 0)) > 0
        ),
        "unowned_assets": sum(1 for a in assets if not a.get("owner")),
        "needs_action": sum(1 for a in assets if a.get("needs_action")),
        "p1_count": sum(1 for a in assets if a.get("action_priority") == "P1"),
        "p2_count": sum(1 for a in assets if a.get("action_priority") == "P2"),
        "p3_count": sum(1 for a in assets if a.get("action_priority") == "P3"),
        "prod_ai_surfaces": sum(
            1 for a in assets
            if a["kind"] == "ai" and (a.get("production_mode") or a.get("environment") == "production")
        ),
        "high_blast_ai_surfaces": sum(1 for a in assets if a["kind"] == "ai" and a.get("blast_radius_tier") in {"high", "critical"}),
    }
    new_count = sum(1 for a in assets if a["is_new"])

    # Rank by action priority first, then raw risk — so the urgent few surface
    # above the long tail. Stable id tiebreak keeps ordering deterministic.
    assets.sort(key=lambda a: (a.get("action_score") or 0, a["risk_score"], a["is_new"], a["id"]), reverse=True)
    total = len(assets)
    assets = assets[offset:offset + limit]
    return {
        "assets": assets,
        "count": len(assets),
        "total": total,
        "offset": offset,
        "new_count": new_count,
        "metrics": metrics,
    }


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

    async with _pool().acquire() as conn:
        new_targets = await conn.fetch(
            """
            SELECT COALESCE(name, url) AS label, url, discovery_source, created_at
            FROM targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY created_at DESC
            """,
            anchor,
            root_domain,
        )
        new_ai = await conn.fetch(
            """
            SELECT name AS label, endpoint_url AS url, created_at
            FROM ai_targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY created_at DESC
            """,
            anchor,
            root_domain,
        )
        new_findings = await conn.fetch(
            """
            SELECT f.title, f.severity, f.first_seen_at,
                   COALESCE(t.root_domain, ait.name, f.url) AS subject
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.status = 'active' AND f.severity IN ('critical', 'high')
              AND f.first_seen_at > $1
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.first_seen_at DESC
            """,
            anchor,
            root_domain,
        )
        resolved_findings = await conn.fetch(
            """
            SELECT f.title, f.severity, f.resolved_at,
                   COALESCE(t.root_domain, ait.name, f.url) AS subject
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.status = 'resolved' AND f.resolved_at > $1
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.resolved_at DESC
            """,
            anchor,
            root_domain,
        )
        failed_scans = await conn.fetch(
            """
            SELECT s.id, s.target_url AS label, s.scan_type, s.created_at
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.status = 'failed' AND s.created_at > $1
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY s.created_at DESC
            """,
            anchor,
            root_domain,
        )
        went_stale_web = await conn.fetch(
            """
            SELECT COALESCE(name, url) AS label, last_scanned_at
            FROM targets
            WHERE is_active = true AND total_scans > 0 AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY last_scanned_at DESC
            """,
            anchor,
            root_domain,
        )
        # AI surfaces go stale too — the destination view's stale-window filter
        # spans every asset kind, so the tile must count the same population.
        went_stale_ai = await conn.fetch(
            """
            SELECT name AS label, last_scanned_at
            FROM ai_targets
            WHERE is_active = true AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY last_scanned_at DESC
            """,
            anchor,
            root_domain,
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
            clean["domain"] = root_domain
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

    new_critical = [r for r in new_findings if r["severity"] == "critical"]
    new_high = [r for r in new_findings if r["severity"] == "high"]

    categories = [
        {
            "key": "new_assets",
            "label": "New assets",
            "count": len(new_targets) + len(new_ai),
            "href": href("/exposure", posture="new", window=window_days),
            "examples": new_asset_examples[:examples],
        },
        {
            "key": "new_critical",
            "label": "New critical findings",
            "count": len(new_critical),
            "href": href(
                "/findings", status="active", severity="critical",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_critical, "first_seen_at"),
        },
        {
            "key": "new_high",
            "label": "New high findings",
            "count": len(new_high),
            "href": href(
                "/findings", status="active", severity="high",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_high, "first_seen_at"),
        },
        {
            "key": "resolved",
            "label": "Findings resolved",
            "count": len(resolved_findings),
            "href": href("/findings", status="resolved", resolved_within=window_days, sort_by="last_seen", sort_order="desc"),
            "examples": finding_examples(resolved_findings, "resolved_at"),
        },
        {
            "key": "failed_scans",
            "label": "Failed scans",
            "count": len(failed_scans),
            "href": href("/scans", status="failed", within=window_days),
            "examples": [
                {"label": r["label"], "detail": r["scan_type"], "when": fmt_when(r["created_at"])}
                for r in failed_scans[:examples]
            ],
        },
        {
            "key": "went_stale",
            "label": "Went stale",
            "count": len(went_stale),
            "href": href("/exposure", posture="stale", sort="stale", window=window_days),
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


@router.get("/exposure/attack-paths")
async def exposure_attack_paths(
    root_domain: Optional[str] = None,
    limit_scans: int = Query(150, ge=1, le=300),
    include_partial: bool = True,
):
    """Flat, severity-ranked list of correlated attack chains across scans.

    Extracts ``attack_chains`` from recent completed scan results, dedupes a
    chain type to its most recent occurrence per asset, and surfaces the step
    narrative so the UI can render each path as a walkable sequence.
    """
    async with _pool().acquire() as conn:
        scan_rows = await conn.fetch(
            """
            SELECT s.id, s.target_id, s.ai_target_id, s.target_url, s.scan_type,
                   s.created_at, s.result, t.root_domain, ait.endpoint_url AS ai_endpoint_url
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.status = 'completed' AND s.result IS NOT NULL
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND ($1::text IS NULL OR t.root_domain = $1::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%')
            ORDER BY s.created_at DESC
            LIMIT $2
            """,
            root_domain,
            limit_scans,
        )

    paths: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str]] = set()

    for row in scan_rows:
        row = row_to_dict(row)
        result = _parse_graph_json(row.get("result"))
        attack_chains = _parse_graph_json(result.get("attack_chains"))
        chains = list(attack_chains.get("chains") or [])
        if include_partial:
            chains += list(attack_chains.get("partial_chains") or [])

        if row.get("ai_target_id"):
            subject_node = f"ai_target:{row['ai_target_id']}"
        elif row.get("target_id"):
            subject_node = f"target:{row['target_id']}"
        else:
            subject_node = None

        for idx, chain in enumerate(chains):
            if not isinstance(chain, dict):
                continue
            chain_type = str(chain.get("chain_type") or chain.get("name") or idx)
            key = (subject_node, chain_type)
            if key in seen:
                continue
            seen.add(key)
            steps = [
                {
                    "step_number": st.get("step_number"),
                    "description": st.get("description"),
                    "impact": st.get("impact"),
                    "finding_type": st.get("finding_type"),
                    "finding_id": st.get("finding_id") or st.get("source_finding_id"),
                    "evidence": st.get("evidence"),
                }
                for st in (chain.get("steps") or [])
                if isinstance(st, dict)
            ]
            severity = str(chain.get("severity") or "").lower() or None
            missing_required = chain.get("missing_required") or chain.get("missing_steps") or []
            if isinstance(missing_required, str):
                missing_required = [missing_required]
            elif not isinstance(missing_required, list):
                missing_required = []
            chain_evidence = chain.get("evidence") if isinstance(chain.get("evidence"), dict) else {}
            supporting = [
                sf for sf in (chain_evidence.get("supporting_findings") or [])
                if isinstance(sf, dict) and sf.get("id")
            ]
            paths.append({
                "_supporting": supporting,
                "id": f"{row['id']}:{chain_type}:{idx}",
                "name": chain.get("name") or chain_type,
                "chain_type": chain.get("chain_type"),
                "severity": severity,
                "status": chain.get("status"),
                "confidence": chain.get("confidence"),
                "completeness": chain.get("completeness"),
                "missing_required": missing_required,
                "business_impact": chain.get("business_impact"),
                "description": chain.get("description"),
                "remediation": chain.get("remediation"),
                "steps": steps,
                "asset_label": _short_url_label(row.get("target_url")),
                "asset_node_id": subject_node,
                "scan_id": str(row["id"]),
                "scan_href": f"/scans/{row['id']}",
            })

    # Resolve chain-step findings to DB finding ids so each step can deep-link
    # to its exact finding. Chains carry scanner fingerprints ("tool:hash") in
    # their supporting_findings evidence, which map onto findings.fingerprint
    # (with a suffix-only fallback for pre-rename findings).
    fingerprints: set[str] = set()
    for p in paths:
        for sf in p["_supporting"]:
            fid = str(sf.get("id") or "")
            if fid:
                fingerprints.add(fid)
                if ":" in fid:
                    fingerprints.add(fid.split(":")[-1])
    fp_map: dict[str, str] = {}
    if fingerprints:
        async with _pool().acquire() as conn:
            finding_rows = await conn.fetch(
                "SELECT id, fingerprint FROM findings WHERE fingerprint = ANY($1::text[])",
                list(fingerprints),
            )
        for fr in finding_rows:
            fp = str(fr["fingerprint"])
            fp_map[fp] = str(fr["id"])
            if ":" in fp:
                fp_map.setdefault(fp.split(":")[-1], str(fr["id"]))

    def _types_align(step_type: str, matched: str) -> bool:
        # Chain steps use template vocabulary ("sqli"); supporting findings use
        # the correlator's ("sqli_confirmed", "admin_panel_found") — treat a
        # shared underscore-prefix family as the same type.
        if not step_type or not matched:
            return False
        return matched == step_type or matched.startswith(f"{step_type}_") or step_type.startswith(f"{matched}_")

    def _resolve_step_finding(step: dict[str, Any], supporting: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        raw = str(step.get("finding_id") or "")
        if raw:
            if raw in fp_map:
                return fp_map[raw], None
            try:
                uuid.UUID(raw)
                return raw, None
            except ValueError:
                pass
        step_type = str(step.get("finding_type") or "")
        for sf in supporting:
            if _types_align(step_type, str(sf.get("matched_type") or "")):
                sf_id = str(sf.get("id") or "")
                resolved = fp_map.get(sf_id) or (fp_map.get(sf_id.split(":")[-1]) if ":" in sf_id else None)
                if resolved:
                    return resolved, sf.get("title")
        return None, None

    for p in paths:
        supporting = p.pop("_supporting")
        for step in p["steps"]:
            resolved_id, resolved_title = _resolve_step_finding(step, supporting)
            step["finding_id"] = resolved_id
            if resolved_title:
                step["finding_title"] = resolved_title
        # Card-level fallback drill-down when steps can't be resolved 1:1.
        p["findings_href"] = f"/findings?scan_id={p['scan_id']}"

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    paths.sort(
        key=lambda p: (
            severity_rank.get(p["severity"] or "", 0),
            1 if p["status"] == "complete" else 0,
            len(p["steps"]),
        ),
        reverse=True,
    )
    return {"attack_paths": paths, "count": len(paths)}
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


def _exposure_hostname(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").lower()


_EXPOSURE_PRIORITY_WEIGHT = {"P1": 300, "P2": 200, "P3": 100}
def _normalize_finding_title(title: str) -> str:
    """Collapse instance-specific detail so similar findings group together.

    "Accessible Sensitive File: /.git/config" and ".../wp-config.php.old" both
    normalise to "Accessible Sensitive File"; "SQL Injection (post id)" to
    "SQL Injection".
    """
    base = re.split(r"[:(]", str(title or ""), maxsplit=1)[0]
    return base.strip() or str(title or "").strip()
