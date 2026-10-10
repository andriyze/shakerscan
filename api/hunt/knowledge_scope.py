"""Target scope predicates and bounded counts for knowledge, shared by pages and the briefing.

Kept free of other product imports so the Hunt briefing can count knowledge without importing the
service-intelligence pages.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class QuerySpec:
    table: str
    columns: str
    timestamp: str
    filters: tuple[str, ...] = ()


QUERIES = {
    "endpoints": QuerySpec("target_endpoints", "method, path, auth_state, test_status, last_verdict, param_shape, content_type, priority_score, first_seen_at, last_seen_at", "last_seen_at", ("path_contains", "method", "test_status", "auth_state")),
    "findings": QuerySpec("findings", "title, severity, status, tool, url, last_verification_verdict, last_seen_at", "last_seen_at", ("severity", "status", "verified_only")),
    "hypotheses": QuerySpec("hypotheses", "family, title, status, confidence, source, dedupe_key, updated_at", "updated_at", ("family", "status")),
    "principals": QuerySpec("target_principals", "label, role, tenant_id, auth_state, is_active, updated_at", "updated_at", ("role", "auth_state")),
    "graph_nodes": QuerySpec("application_graph_nodes", "node_type, node_key, label, attributes, last_seen_at", "last_seen_at", ("node_type", "hunt_id")),
    "graph_edges": QuerySpec("application_graph_edges", "src_key, edge_type, dst_key, last_seen_at", "last_seen_at"),
    "receipts": QuerySpec("tool_receipts", "tool_name, status, redacted_argv, created_at", "created_at", ("status",)),
    "notes": QuerySpec("tool_receipts", "metadata_json, created_at", "created_at"),
    "scans": QuerySpec("scans", "status, progress, current_phase, findings_count, created_at", "created_at", ("status",)),
    "collections": QuerySpec("request_collections", "name, format, request_count, safe_request_count, potentially_mutating_request_count, payload_sha256, updated_at", "updated_at"),
    "candidates": QuerySpec("investigation_candidates", "family, canonical_locus, title, claim, claimed_severity, evidence_refs, verifier_contract_id, status, last_seen_at", "last_seen_at", ("family", "status")),
    "services": QuerySpec("device_services", "transport, port, state, service_name, product, version, encrypted, web_origin, policy_disposition, last_seen_at", "last_seen_at", ("state",)),
}


#: Kinds counted for a briefing. Receipts and notes are not: tool_receipts has no target index,
#: so a briefing names them as readable through the knowledge query instead of counting them.
COUNTED_KINDS = ("endpoints", "findings", "hypotheses", "principals", "graph_nodes", "graph_edges",
                 "scans", "collections", "candidates", "services")
#: Counts stop here; a capped count is reported as at least this many.
MAX_COUNT = 1000
DEVICE_KINDS = frozenset({"scans", "findings", "collections", "candidates", "services"})  # supported by query_knowledge_page


def _scope_where(kind: str, device: bool, bind: Any) -> list[str]:
    """The target-scope predicate every page and count of ``kind`` applies."""
    if kind in {"receipts", "notes"}:
        return [f"target_scope->>'target_id'={bind('target_text')}"]
    owner = bind("target")
    if kind == "collections":
        where = [f"target_collection_visible(id,{owner})"]
    elif device and kind in {"findings", "scans", "candidates"}:
        where = [f"target_id IN (SELECT id FROM targets WHERE id={owner} OR asset_owner_id={owner})"]
    else:
        where = [f"target_id={owner}"]
    if kind == "endpoints":
        where.append("COALESCE(test_status,'')<>'gone'")
    if kind in {"principals", "collections"}:
        where.append("is_active=true")
    if kind == "notes":
        where.append("tool_name='agent.note'")
    return where


async def knowledge_counts(conn: Any, *, target_id: Any, device: bool = False) -> dict[str, Any]:
    """How much target knowledge exists, by kind, each count bounded by MAX_COUNT."""
    counts: dict[str, Any] = {}
    for kind in COUNTED_KINDS:
        if (device and kind not in DEVICE_KINDS) or (not device and kind == "services"):
            continue
        spec = QUERIES[kind]
        params: list[Any] = []

        def bind(name: str, params: list[Any] = params) -> str:
            params.append(str(target_id) if name == "target_text" else target_id)
            return f"${len(params)}"

        where = _scope_where(kind, device, bind)
        params.append(MAX_COUNT + 1)
        value = int(await conn.fetchval(
            f"SELECT count(*) FROM (SELECT 1 FROM {spec.table} WHERE {' AND '.join(where)} "
            f"LIMIT ${len(params)}) bounded", *params,
        ) or 0)
        counts[kind] = {"count": min(value, MAX_COUNT), "at_least": value > MAX_COUNT}
    return {
        "counts": counts,
        "not_counted": ["receipts", "notes"],
        "read_with": "POST /hunts/{hunt_id}/query with kind=<name> (shakerscan_hunt_query)",
    }
