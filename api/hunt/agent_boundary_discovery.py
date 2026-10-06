"""Bounded derived graph view backed by an exact Hunt's redacted HTTP archive."""
from __future__ import annotations

import json
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID, uuid5

from .agent_boundary_model import NODE_TYPE, build_agent_boundary_model, origin
from .boundary_context import EVIDENCE_QUERY

MAX_CAPTURES = 256
MAX_EXTERNAL_BYTES = 4 * 1024 * 1024


def _mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    return dict(value) if isinstance(value, Mapping) else {}


async def agent_boundary_model_page(
    conn: Any, *, target_id: Any, device: bool, filters: Mapping[str, Any],
    limit: int, cursor: str | None,
) -> dict[str, Any]:
    """A derived view, not a graph write or a native executable capability.

    Historical evidence is permitted only from a Hunt on this exact target. The
    saved AI endpoint selects a same-asset service; it grants no credential use.
    """
    allowed = {"node_type", "hunt_id", "ai_target_id", "owner_role", "attacker_role"}
    if (set(filters) != allowed or filters.get("node_type") != NODE_TYPE
            or cursor is not None or type(limit) is not int or not 1 <= limit <= 500):
        raise ValueError("agent_authorization_model requires hunt_id, ai_target_id, owner_role and attacker_role; cursors are not supported")
    try:
        source_hunt = UUID(str(filters["hunt_id"]))
        ai_target = UUID(str(filters["ai_target_id"]))
        asset = UUID(str(target_id))
    except (ValueError, TypeError) as exc:
        raise ValueError("discovery references must be UUIDs") from exc
    roles = {"primary": filters["owner_role"], "secondary": filters["attacker_role"]}
    if any(not isinstance(role, str) or not 1 <= len(role) <= 128 for role in roles.values()):
        raise ValueError("select two bounded AI role names")

    # Import the owning archive implementation, including decryption, redaction,
    # private-workflow handling and external-payload bounds, rather than copying it.
    try:
        from runtime.http_archive_reader import project, read_transactions
    except ModuleNotFoundError:
        from ..runtime.http_archive_reader import project, read_transactions

    async with conn.transaction(isolation="repeatable_read", readonly=True):
        run = await conn.fetchrow(
            "SELECT id, target_id, device_target_id, target_kind, context_pack FROM hunt_runs WHERE id=$1",
            source_hunt,
        )
        if (not run or (str(run.get("device_target_id")) if device else str(run.get("target_id"))) != str(asset)
                or (not device and run.get("device_target_id") is not None)):
            raise ValueError("source Hunt is unavailable for this target")
        target = await conn.fetchrow(
            "SELECT id, endpoint_url, response_path FROM ai_targets WHERE id=$1 AND is_active=true", ai_target,
        )
        if not target:
            raise ValueError("configured AI target is unavailable")
        selected_origin = origin(target["endpoint_url"])
        context = _mapping(run["context_pack"])
        binding = _mapping(context.get("target"))
        locator = str(binding.get("url") or binding.get("locator") or "")
        if "://" not in locator:
            locator = "http://" + (f"[{locator}]" if ":" in locator and not locator.startswith("[") else locator)
        host = (urlsplit(locator).hostname or "").lower().rstrip(".")
        selected_host = urlsplit(selected_origin).hostname
        allowed_origins = {origin(value) for value in binding.get("origins", ())}
        if not host or (selected_host != host and selected_origin not in allowed_origins):
            raise ValueError("AI endpoint is not a service of the source Hunt target")
        saved_roles = await conn.fetch(
            "SELECT role FROM ai_target_principals WHERE ai_target_id=$1 AND is_active=true", ai_target,
        )
        if len(set(roles.values())) != 2 or not set(roles.values()) <= {item["role"] for item in saved_roles}:
            raise ValueError("select two distinct active roles from the configured AI target")
        rows = await read_transactions(
            conn, hunt_run_id=str(source_hunt), limit=MAX_CAPTURES + 1,
            external_payload_budget=MAX_EXTERNAL_BYTES,
        )
        capture_truncated = len(rows) > MAX_CAPTURES
        rows = rows[:MAX_CAPTURES]
        ids = [str(UUID(str(row["id"]))) for row in rows]
        owned = await conn.fetch(
            EVIDENCE_QUERY, ids, str(source_hunt),
            str(run["target_id"]) if run.get("target_id") else None,
            str(run["device_target_id"]) if run.get("device_target_id") else None,
        ) if ids else []
        owned_ids = {str(item["id"]) for item in owned if item["kind"] == "http_transaction"}
        redacted = []
        for row in rows:
            if str(row["id"]) not in owned_ids:
                continue
            item = project(row, redaction="redacted")
            item["capture"] = _mapping(item.get("capture"))
            redacted.append(item)
        model = build_agent_boundary_model(
            redacted, hunt_id=str(source_hunt), ai_target_id=str(ai_target),
            endpoint_url=target["endpoint_url"], response_path=target["response_path"], roles=roles,
        )
    model["source"] = {
        "captures_read": len(rows), "captures_owned": len(redacted),
        "capture_limit": MAX_CAPTURES, "captures_truncated": capture_truncated,
        "external_payload_budget_bytes": MAX_EXTERNAL_BYTES,
        "archive_completeness": "not_assessed", "redaction": "redacted",
    }
    key = f"agent-boundary-model:{source_hunt}:{ai_target}:{roles['primary']}:{roles['secondary']}"
    return {"ok": True, "kind": "graph_nodes", "supported": True,
            "derived_view": NODE_TYPE, "count": 1,
            "rows": [{"id": str(uuid5(asset, key)), "node_type": NODE_TYPE,
                      "node_key": key, "label": "Evidence-derived agent authorization model",
                      "attributes": model}],
            "has_more": False, "next_cursor": None,
            "projection_only": True, "execution_enabled": False}
