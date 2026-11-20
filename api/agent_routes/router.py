"""Agent routes.

What remains of the keyless agent surface after the legacy Agent Hunt engine was removed: tool
readiness, per-target context packs, and the two-tier read of verified findings beside
non-authoritative candidates. Investigations run through ``/hunts``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Callable

from fastapi import APIRouter, HTTPException, Query

try:
    import agent_context_pack
    from action_scope import _decode_json_value
    from api_utils import _json_safe_row, _uuid_or_400
    from hunt.run_service import agent_tools
    from arsenal_routes import router as _arsenal_routes
    from devices import router as _devices
    from fleet_routes import router as _fleet_routes
except ModuleNotFoundError:  # package import in host-side tests
    from .. import agent_context_pack
    from ..action_scope import _decode_json_value
    from ..api_utils import _json_safe_row, _uuid_or_400
    from ..hunt.run_service import agent_tools
    from ..arsenal_routes import router as _arsenal_routes
    from ..devices import router as _devices
    from ..fleet_routes import router as _fleet_routes


router = APIRouter()

_pool_provider: Callable[[], Any] | None = None
_deps: dict[str, Callable[..., Any]] = {}


AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY = "shakerscan:agent_tool_worker_build"


def configure_agent_router(
    pool_provider: Callable[[], Any], **collaborators: Callable[..., Any]
) -> None:
    """Bind the pool and the collaborators this domain needs."""
    global _pool_provider
    _pool_provider = pool_provider
    _deps.update(collaborators)


def _pool():
    pool = _pool_provider() if _pool_provider is not None else None
    if pool is None:
        raise HTTPException(status_code=503, detail="database pool is not ready")
    return pool


def _dep(name: str) -> Callable[..., Any]:
    call = _deps.get(name)
    if call is None:
        raise HTTPException(status_code=503, detail=f"{name} is not ready")
    return call


def _get(name: str) -> Any:
    """Resolve an injected collaborator that still lives in the composition root."""
    return _dep(name)()


def current_scanner_version(*a: Any, **k: Any) -> Any:
    return _get("current_scanner_version")(*a, **k)


def expected_build_fingerprint(*a: Any, **k: Any) -> Any:
    return _get("expected_build_fingerprint")(*a, **k)


def get_redis(*a: Any, **k: Any) -> Any:
    return _get("get_redis")(*a, **k)


def worker_build_current(*a: Any, **k: Any) -> Any:
    return _get("worker_build_current")(*a, **k)


__all__ = ["configure_agent_router", "router"]


@router.get("/agent/tools/readiness")
async def get_agent_tool_readiness():
    return _agent_tool_worker_readiness()


@router.get("/agent/context/{target_id}")
async def get_agent_context_pack(
    target_id: str,
    objective: str = Query(default=""),
    token_budget: int = Query(default=6000, ge=500, le=24000),
    endpoint_limit: int = Query(default=25, ge=0, le=50),
    finding_limit: int = Query(default=15, ge=0, le=25),
):
    """Reasoning-grade, token-bounded context pack for the autonomous agent.

    Assembled from Layer-1 tables (endpoint inventory, application graph, findings,
    principals, hypotheses, recent scan tech/WAF/verification rollups) through the same
    redaction path as research observations, then packed with **honest drop telemetry**
    (borrows T3MP3ST ``packContext``: always-present map, relevance ranking by objective,
    head/tail elision, explicit included/dropped lists — no silent loss). Read-only.
    """
    async with _pool().acquire() as conn:
        context_req = await _arsenal_routes._build_agent_context_pack_from_target(
            conn,
            _arsenal_routes.AgentContextPackFromTargetRequest(
                target_id=target_id,
                include_findings=True,
                include_endpoints=True,
                include_gaps=True,
                finding_limit=finding_limit,
                endpoint_limit=endpoint_limit,
                created_by="agent_context_endpoint",
            ),
        )
    context = _arsenal_routes._canonical_agent_context_pack(context_req)
    sections = _agent_context_pack_sections(context)
    pack = agent_context_pack.pack_context(
        sections,
        token_budget=token_budget,
        objective=objective,
        prior_intel=_agent_pack_compact(context.get("known_preconditions"), 400),
    )
    return {
        "target_id": context.get("target_id"),
        "objective": objective,
        "context_hash": context.get("context_hash"),
        "token_budget": token_budget,
        "sections_available": [section["key"] for section in sections],
        "pack": pack,
    }


@router.get("/agent/findings/{target_id}")
async def get_agent_two_tier_findings(target_id: str):
    """Verified findings plus non-authoritative Deep Hunt candidates for one target."""
    target_uuid = _uuid_or_400(target_id, "target id")
    async with _pool().acquire() as conn:
        verified = await conn.fetch(
            """SELECT id, title, severity, tool, url, last_verification_verdict, first_seen_at
               FROM findings WHERE target_id=$1 AND status='active'
                 AND last_verification_verdict='exploited'
                 AND tool IN ('autonomous_workflow','bola')
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                        WHEN 'low' THEN 3 ELSE 4 END, first_seen_at DESC LIMIT 200""",
            target_uuid,
        )
        suspected = await conn.fetch(
            """SELECT id, title, claimed_severity AS severity, family,
                      canonical_locus, verification_context, status,
                      created_at AS first_seen_at, last_seen_at
               FROM investigation_candidates
               WHERE target_id=$1 AND plane='web'
                 AND status IN ('new','verification_queued','verifying','inconclusive','blocked')
               ORDER BY last_seen_at DESC LIMIT 200""",
            target_uuid,
        )
    def _suspected_row(row: Any) -> dict[str, Any]:
        item = _json_safe_row(row)
        locus = _decode_json_value(item.pop("canonical_locus", None)) or {}
        context = _decode_json_value(item.pop("verification_context", None)) or {}
        item["tool"] = "investigation_candidate"
        item["url"] = locus.get("route") or locus.get("url") or context.get("target_url")
        item["predicate"] = context.get("predicate")
        item["net_new_vs_known"] = context.get("net_new_vs_known")
        item["trust_tier"] = "candidate"
        item["candidate_status"] = item.pop("status", "new")
        return item
    return {
        "target_id": str(target_uuid),
        "verified": [_json_safe_row(row) for row in verified],
        "suspected": [_suspected_row(row) for row in suspected],
    }


def _agent_tool_worker_readiness() -> dict[str, Any]:
    """Return fresh, build-current isolated Hunt scanner capacity."""
    expected_fingerprint = expected_build_fingerprint()
    expected_version = current_scanner_version()
    now = datetime.now(timezone.utc)
    # The isolated worker must serve every registered external process adapter. V2-only
    # capabilities expose their own placement/readiness.
    required_tools = {
        str(spec.binary) for spec in agent_tools.CAPABILITY_REGISTRY.process_tools() if spec.binary
    }
    reports: list[dict[str, Any]] = []
    try:
        raw_reports = get_redis().hgetall(AGENT_TOOL_WORKER_BUILD_REGISTRY_KEY) or {}
    except Exception:
        raw_reports = {}
    for raw_host, raw_payload in raw_reports.items():
        host = raw_host.decode("utf-8", "replace") if isinstance(raw_host, bytes) else str(raw_host)
        payload = raw_payload.decode("utf-8", "replace") if isinstance(raw_payload, bytes) else raw_payload
        try:
            report = json.loads(payload) if isinstance(payload, str) else dict(payload)
            reported_at = datetime.fromisoformat(str(report.get("reported_at") or "").replace("Z", "+00:00"))
            if reported_at.tzinfo is None:
                reported_at = reported_at.replace(tzinfo=timezone.utc)
            age_seconds = (now - reported_at.astimezone(timezone.utc)).total_seconds()
            if not (-_devices._WORKER_BUILD_REPORT_CLOCK_SKEW_SECONDS <= age_seconds <= _devices._WORKER_BUILD_REPORT_MAX_AGE_SECONDS):
                continue
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        tools = sorted({str(item).strip().lower() for item in report.get("tools", []) if str(item).strip()})
        build_current = worker_build_current(
            reported_fingerprint=report.get("build_fingerprint"),
            reported_version=report.get("scanner_version"),
            expected_fingerprint=expected_fingerprint,
            expected_version=expected_version,
        )
        reports.append({
            "worker_id": host,
            "build_current": build_current,
            "tools": tools,
            "reported_at": report.get("reported_at"),
            "capable": build_current is True and required_tools.issubset(tools),
        })
    capable_count = sum(1 for report in reports if report["capable"])
    if capable_count:
        status, reason = "ready", None
    elif reports and any(report["build_current"] is False for report in reports):
        status, reason = "not_ready", "agent_tool_worker_build_stale"
    elif reports:
        status, reason = "not_ready", "agent_tool_worker_missing_tools_or_build_identity"
    else:
        status, reason = "not_ready", "no_fresh_agent_tool_worker"
    return {
        "status": status,
        "reason": reason,
        "queue_name": _get("AGENT_TOOL_QUEUE_NAME"),
        "worker_count": len(reports),
        "capable_worker_count": capable_count,
        "required_tools": sorted(required_tools),
        "workers": reports,
        "expected_build_fingerprint": expected_fingerprint,
    }


def _agent_context_pack_sections(context: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a canonical (already-redacted) agent context pack into rankable pack
    sections for :func:`agent_context_pack.pack_context`. Each section is
    ``{key, body, loc, bytes}``; bodies are compact human-readable text so the honest
    packer can relevance-rank, elide, and drop with visible telemetry."""
    surface = context.get("current_surface") if isinstance(context.get("current_surface"), dict) else {}
    principals = surface.get("principal_matrix") if isinstance(surface.get("principal_matrix"), dict) else {}
    graph = surface.get("attack_graph") if isinstance(surface.get("attack_graph"), dict) else {}

    def _rows(value: Any) -> list[dict[str, Any]]:
        return [item for item in (value or []) if isinstance(item, dict)]

    sections: list[dict[str, Any]] = []

    def _add(key: str, lines: Any, loc: int) -> None:
        body = ("\n".join(lines) if isinstance(lines, list) else str(lines)).strip()
        if body:
            sections.append({"key": key, "body": body, "loc": loc, "bytes": len(body)})

    target_summary = context.get("target_summary") if isinstance(context.get("target_summary"), dict) else {}
    if target_summary:
        _add("target", [f"{k}: {v}" for k, v in target_summary.items()], 1)

    endpoint_lines: list[str] = []
    for endpoint in _rows(surface.get("sample_endpoints")):
        method = str(endpoint.get("method") or "GET").upper()
        path = endpoint.get("path") or ""
        bits = [f"[{endpoint.get('auth_state') or 'anonymous'}]"]
        if endpoint.get("test_status"):
            bits.append(str(endpoint["test_status"]))
        if endpoint.get("last_verdict"):
            bits.append(f"verdict={endpoint['last_verdict']}")
        if endpoint.get("content_type"):
            bits.append(str(endpoint["content_type"]))
        line = f"{method} {path}  {' '.join(bits)}".rstrip()
        if endpoint.get("param_shape"):
            line += f"\n    params: {_agent_pack_compact(endpoint['param_shape'], 200)}"
        if endpoint.get("replay_spec"):
            line += f"\n    replay: {str(endpoint['replay_spec'])[:200]}"
        endpoint_lines.append(line)
    _add("endpoints", endpoint_lines, len(endpoint_lines))

    coverage_lines = [f"coverage: {_agent_pack_compact(surface.get('coverage'), 400)}"]
    for count in _rows(surface.get("endpoint_counts")):
        coverage_lines.append(f"  {count.get('auth_state')}/{count.get('test_status')}: {count.get('count')}")
    if surface.get("exhausted_families"):
        coverage_lines.append(f"exhausted_families: {_agent_pack_compact(surface.get('exhausted_families'), 200)}")
    _add("coverage", coverage_lines, len(coverage_lines))

    # B1: observed-artifact provenance — which collected artifacts (crawl / har / js bundle analysis /
    # ffuf / openapi / manual) the surface was mined from. Leads and drafts are derived from these
    # artifacts; this section is the planner's observability-coverage signal (missing js -> client
    # routes unexplored; missing har -> authenticated traffic never captured).
    source_rows = _rows(surface.get("endpoint_source_counts"))
    if source_rows:
        artifact_lines = [
            "endpoint discovery sources (what has been OBSERVED so far):",
            *[f"  {row.get('source')}: {row.get('count')} endpoints" for row in source_rows],
        ]
        if surface.get("asm_last_recon_at"):
            artifact_lines.append(f"last recon: {surface.get('asm_last_recon_at')}")
        if surface.get("asm_last_test_at"):
            artifact_lines.append(f"last endpoint test: {surface.get('asm_last_test_at')}")
        _add("observed_artifacts", artifact_lines, len(artifact_lines))

    principal_lines: list[str] = []
    for principal in _rows(principals.get("principals")):
        principal_lines.append(
            f"{principal.get('label')}  role={principal.get('role')} "
            f"tenant={principal.get('tenant_id') or '-'} auth={principal.get('auth_state')} "
            f"credential={'yes' if principal.get('credential_configured') else 'no'}"
        )
    for expectation in _rows(principals.get("expectations")):
        principal_lines.append(
            f"expect {expectation.get('method')} {expectation.get('path')} "
            f"role={expectation.get('principal_role')} access={expectation.get('expected_access')} "
            f"status={expectation.get('expected_http_status')}"
        )
    _add("principals", principal_lines, len(principal_lines))

    graph_lines = [
        f"nodes={len(_rows(graph.get('nodes')))} edges={len(_rows(graph.get('edges')))} "
        f"truncated={graph.get('truncated')}"
    ]
    for node in _rows(graph.get("nodes")):
        graph_lines.append(f"node {node.get('node_type')}:{node.get('node_key')} {node.get('label') or ''}".rstrip())
    for edge in _rows(graph.get("edges")):
        graph_lines.append(f"edge {edge.get('src_key')} -[{edge.get('edge_type')}]-> {edge.get('dst_key')}")
    _add("application_graph", graph_lines, len(graph_lines))

    hypothesis_lines: list[str] = []
    for hypothesis in _rows(context.get("hypotheses_summary")):
        hypothesis_lines.append(
            f"[{hypothesis.get('family')}] {hypothesis.get('title') or hypothesis.get('dedupe_key') or ''} "
            f"status={hypothesis.get('status')} conf={hypothesis.get('confidence')} src={hypothesis.get('source')}"
        )
    _add("hypotheses", hypothesis_lines, len(hypothesis_lines))

    finding_lines: list[str] = []
    for finding in _rows(context.get("findings_summary")):
        verdict = finding.get("last_verification_verdict") or "unverified"
        finding_lines.append(
            f"{str(finding.get('severity', '')).upper()} [{verdict}] {finding.get('title')} "
            f"@ {finding.get('url') or ''}  ({finding.get('tool')}/{finding.get('status')})"
        )
    _add("known_findings", finding_lines, len(finding_lines))

    gap_rows = _rows(context.get("current_gaps"))
    _add("gaps", [_agent_pack_compact(gap, 300) for gap in gap_rows], len(gap_rows))

    invariant_rows = _rows(surface.get("approved_invariant_contracts"))
    if invariant_rows:
        _add("invariant_contracts", [_agent_pack_compact(item, 400) for item in invariant_rows], len(invariant_rows))

    # A3: UNAPPROVED invariant candidates (auto-drafted from black-box facts + operator drafts).
    # Explicitly labeled non-authoritative: they are review hints for the planner, never rules;
    # a SUSPECTED observation matching one is the signal to ask the operator for approval.
    candidate_rows = _rows(surface.get("invariant_candidate_contracts"))
    if candidate_rows:
        candidate_lines = [
            f"UNAPPROVED CANDIDATE (no authority): {_agent_pack_compact(item, 300)}"
            for item in candidate_rows
        ]
        _add("invariant_candidates", candidate_lines, len(candidate_lines))

    scan_rows = _rows(surface.get("recent_scans"))
    if scan_rows:
        _add("recent_scans", [_agent_pack_compact(scan, 400) for scan in scan_rows], len(scan_rows))

    preconditions = context.get("known_preconditions") if isinstance(context.get("known_preconditions"), dict) else {}
    if preconditions:
        _add("preconditions", [f"{k}: {v}" for k, v in preconditions.items()], 1)

    return sections


async def _resolve_agent_target_addresses(
    url: str, *, environment: str | None = None,
) -> list[str]:
    """Compatibility name for Hunt's frozen runtime target binding.

    The resolver admits each answer under the deployment policy for a given environment. A
    caller that knows the target's environment must pass it: without it a Lab target that
    authorized correctly was refused here under a refusing deployment, because the resolver fell
    back to production and the Lab exception never applied.
    """
    return await _fleet_routes._resolve_runtime_target_addresses(
        url, subject="Hunt target", environment=str(environment or "production"),
    )


def _agent_pack_compact(value: Any, limit: int = 1500) -> str:
    try:
        text = json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = str(value)
    return text[:limit]


