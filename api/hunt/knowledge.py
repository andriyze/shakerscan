"""Bounded, target-scoped knowledge pages for Hunt and legacy agent reads.

Cursors are positions, not authority. Every page reapplies the target and filters;
no query identifier or SQL fragment is accepted from the caller.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any, Mapping
import uuid

from .endpoint_grouping import group_endpoint_rows


MAX_QUERY_ROWS = 500


class KnowledgeQueryError(ValueError):
    pass


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
    "graph_nodes": QuerySpec("application_graph_nodes", "node_type, node_key, label, last_seen_at", "last_seen_at"),
    "graph_edges": QuerySpec("application_graph_edges", "src_key, edge_type, dst_key, last_seen_at", "last_seen_at"),
    "receipts": QuerySpec("tool_receipts", "tool_name, status, redacted_argv, created_at", "created_at", ("status",)),
    "notes": QuerySpec("tool_receipts", "metadata_json, created_at", "created_at"),
    "scans": QuerySpec("scans", "status, progress, current_phase, findings_count, created_at", "created_at", ("status",)),
    "collections": QuerySpec("request_collections", "name, format, request_count, safe_request_count, potentially_mutating_request_count, payload_sha256, updated_at", "updated_at"),
    "candidates": QuerySpec("investigation_candidates", "family, canonical_locus, title, claim, claimed_severity, evidence_refs, verifier_contract_id, status, last_seen_at", "last_seen_at", ("family", "status")),
    "services": QuerySpec("device_services", "transport, port, state, service_name, product, version, encrypted, web_origin, policy_disposition, last_seen_at", "last_seen_at", ("state",)),
}


def _encode(value: Mapping[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def _decode(value: str) -> dict[str, Any]:
    try:
        if not isinstance(value, str) or len(value) > 2048:
            raise ValueError("invalid length")
        result = json.loads(base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True))
        if not isinstance(result, dict):
            raise ValueError("not an object")
        return result
    except (ValueError, TypeError, UnicodeError) as exc:
        raise KnowledgeQueryError("Invalid knowledge cursor") from exc


def _filter_values(spec: QuerySpec, supplied: Mapping[str, Any]) -> dict[str, Any]:
    unknown = set(supplied) - {*spec.filters, "id"}
    if unknown:
        raise KnowledgeQueryError("Unsupported knowledge filters: " + ", ".join(sorted(unknown)))
    values: dict[str, Any] = {}
    for key, raw in supplied.items():
        if key == "verified_only":
            if not isinstance(raw, bool):
                raise KnowledgeQueryError("verified_only must be a boolean")
            values[key] = raw
        elif raw is not None:
            if not isinstance(raw, str) or len(raw) > 500:
                raise KnowledgeQueryError(f"{key} must be a bounded string")
            value = raw.strip()
            if key not in {"id", "path_contains"}:
                value = value.upper() if key == "method" else value.lower()
            if value:
                values[key] = value
    return values


#: Rows read before grouping. The grouped view is a projection over the whole inventory, so it
#: cannot be keyset-paged; this bounds the read and the page reports when it was hit.
MAX_GROUPING_ROWS = 20_000


async def _endpoint_group_page(
    conn: Any, *, target_id: Any, limit: int, cursor: str | None, scope: str,
) -> dict[str, Any]:
    """Collapse the endpoint inventory into route templates for the Hunt frontier.

    Opt-in: ``kind="endpoints"`` is unchanged. This exists because the raw frontier is dominated
    by repeated samples of a few handlers -- measured, 20,345 rows over 5,634 templates -- so the
    first page a Hunt reads was mostly one handler answering junk parameters. Grouping is
    non-destructive: every group carries its member ids, so any grouping can be drilled into.
    """
    rows = await conn.fetch(
        "SELECT id, method, path, auth_state, test_status, last_verdict, param_shape, "
        "last_http_status, priority_score FROM target_endpoints "
        f"WHERE target_id=$1 AND COALESCE(test_status,'')<>'gone' LIMIT {MAX_GROUPING_ROWS + 1}",
        target_id,
    )
    truncated = len(rows) > MAX_GROUPING_ROWS
    groups = group_endpoint_rows([dict(r) for r in rows[:MAX_GROUPING_ROWS]])
    offset = 0
    if cursor:
        position = _decode(cursor)
        if position.get("v") != 1 or position.get("scope") != scope:
            raise KnowledgeQueryError("Cursor does not match this knowledge query")
        offset = int(position.get("offset") or 0)
        if offset < 0:
            raise KnowledgeQueryError("Cursor does not match this knowledge query")
    page = groups[offset:offset + limit]
    has_more = len(groups) > offset + limit
    return {
        "ok": True, "kind": "endpoint_groups", "supported": True,
        "count": len(page), "rows": [g.as_row() for g in page],
        "has_more": has_more,
        "next_cursor": _encode({"v": 1, "scope": scope, "offset": offset + limit})
        if has_more else None,
        "group_count": len(groups),
        "sampled_requests": sum(g.sample_count for g in groups),
        "inventory_truncated": truncated,
    }


async def query_knowledge_page(
    conn: Any, *, target_id: Any, kind: str, device: bool = False,
    filters: Mapping[str, Any] | None = None, limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    kind = "receipts" if kind == "tool_receipts" else kind
    if kind == "endpoint_groups":
        if device:
            return {"ok": True, "kind": kind, "supported": False, "count": 0, "rows": [],
                    "has_more": False, "next_cursor": None}
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_QUERY_ROWS:
            raise KnowledgeQueryError(f"limit must be between 1 and {MAX_QUERY_ROWS}")
        return await _endpoint_group_page(
            conn, target_id=target_id, limit=limit, cursor=cursor,
            scope=f"web:{target_id}:endpoint_groups",
        )
    if kind not in QUERIES:
        raise KnowledgeQueryError("Unsupported knowledge kind")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_QUERY_ROWS:
        raise KnowledgeQueryError(f"limit must be between 1 and {MAX_QUERY_ROWS}")
    # A device has no web endpoint/principal graph. Explicitly report unsupported,
    # rather than pretending the requested surface was examined and empty.
    supported = {"scans", "findings", "collections", "candidates", "services"}
    if (device and kind not in supported) or (not device and kind == "services"):
        return {"ok": True, "kind": kind, "supported": False, "count": 0, "rows": [], "has_more": False, "next_cursor": None}
    spec = QUERIES[kind]
    values = _filter_values(spec, filters or {})
    scope = f"{'device' if device else 'web'}:{target_id}:{kind}"
    fingerprint = hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()
    params: list[Any] = []

    def bind(value: Any) -> str:
        params.append(value)
        return f"${len(params)}"

    if kind in {"receipts", "notes"}:
        where = [f"target_scope->>'target_id'={bind(str(target_id))}"]
    else:
        column = "device_target_id" if device else "target_id"
        where = [f"{column}={bind(target_id)}"]
    if kind == "endpoints":
        where.append("COALESCE(test_status,'')<>'gone'")
    if kind in {"principals", "collections"}:
        where.append("is_active=true")
    if kind == "notes":
        where.append("tool_name='agent.note'")
    for key, value in values.items():
        if key == "id":
            try:
                where.append(f"id={bind(uuid.UUID(value))}")
            except ValueError as exc:
                raise KnowledgeQueryError("id must be a UUID") from exc
        elif key == "path_contains":
            where.append(f"path ILIKE '%'||{bind(value)}||'%'")
        elif key == "verified_only":
            if value:
                where.append("last_verification_verdict='exploited'")
        else:
            where.append(f"{key}={bind(value)}")
    timestamp = f"COALESCE({spec.timestamp}, TIMESTAMPTZ '1970-01-01 00:00:00+00')"
    order = [timestamp, "id"]
    if kind == "endpoints":
        order.insert(0, "priority_score")
    if cursor:
        position = _decode(cursor)
        try:
            if position["v"] != 1 or position["scope"] != scope or position["filter"] != fingerprint:
                raise ValueError("cursor scope mismatch")
            seen = datetime.fromisoformat(position["time"])
            if seen.tzinfo is None:
                raise ValueError("timezone required")
            keys: list[Any] = [seen, uuid.UUID(position["id"])]
            if kind == "endpoints":
                priority = position["priority"]
                if isinstance(priority, bool) or not isinstance(priority, int) or not -(2**31) <= priority < 2**31:
                    raise ValueError("invalid priority")
                keys.insert(0, priority)
        except (KeyError, ValueError, TypeError) as exc:
            raise KnowledgeQueryError("Cursor does not match this knowledge query") from exc
        where.append(f"({', '.join(order)}) < ({', '.join(bind(key) for key in keys)})")
    rows = list(await conn.fetch(
        f"SELECT id, {spec.columns}, {timestamp} AS page_timestamp FROM {spec.table} "
        f"WHERE {' AND '.join(where)} ORDER BY {', '.join(key + ' DESC' for key in order)} "
        f"LIMIT {bind(limit + 1)}", *params,
    ))
    has_more = len(rows) > limit
    rows = [dict(row) for row in rows[:limit]]
    next_cursor = None
    if has_more:
        last = rows[-1]
        stamp = last["page_timestamp"]
        next_cursor = _encode({
            "v": 1, "scope": scope, "filter": fingerprint,
            "time": stamp.isoformat() if isinstance(stamp, datetime) else str(stamp),
            "id": str(last["id"]), "priority": last.get("priority_score"),
        })
    for row in rows:
        row.pop("page_timestamp", None)
    return {"ok": True, "kind": kind, "supported": True, "count": len(rows), "rows": rows, "has_more": has_more, "next_cursor": next_cursor}
