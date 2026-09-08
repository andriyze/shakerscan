"""PostgreSQL persistence using existing graph nodes and canonical action records.

Proposal/attempt nodes contain references and digests, not credentials, raw HTTP
bodies, or a second copy of proof. Hunt actions remain the execution source of
truth. All reads are scoped to the current Hunt and its target.
"""
from __future__ import annotations

from typing import Any, Mapping
import json
import uuid

from .authorization_evidence import AuthorizationWorkflowError, canonical_action_id, digest, mapping


PROPOSAL_TYPE = "authorization_proposal"
ATTEMPT_TYPE = "authorization_attempt"
DECISION_TYPE = "authorization_decision"
MAX_ATTEMPTS = 20


def uid(value: Any) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AuthorizationWorkflowError("Invalid authorization workflow reference", 422) from exc


class PostgresAuthorizationRepository:
    async def run(self, conn: Any, hunt_id: Any) -> dict[str, Any]:
        row = await conn.fetchrow(
            "SELECT id, target_id, device_target_id, target_kind, status, context_pack "
            "FROM hunt_runs WHERE id=$1", uid(hunt_id),
        )
        if not row:
            raise AuthorizationWorkflowError("Hunt not found", 404)
        result = dict(row)
        if result.get("target_kind") not in {"web", "api"} or result.get("device_target_id"):
            raise AuthorizationWorkflowError("Authorization investigations require a web/API Hunt", 422)
        return result

    async def capture(self, conn: Any, run: Mapping[str, Any], capture_id: Any) -> dict[str, Any]:
        # First integration deliberately supports this Hunt's own captured traffic.
        # A prior Scan's principal slot is not necessarily this Hunt's principal.
        row = await conn.fetchrow(
            "SELECT id, hunt_run_id, hunt_action_id, method, url, principal_slot, "
            "request_body_bytes, status_code, error, truncated "
            "FROM http_transactions WHERE id=$1 AND hunt_run_id=$2",
            uid(capture_id), uid(run["id"]),
        )
        if not row:
            raise AuthorizationWorkflowError("Captured request is unavailable for this Hunt", 404)
        return dict(row)

    async def session(self, conn: Any, run: Mapping[str, Any], session_ref: Any, slot: str) -> dict[str, Any]:
        # Metadata-only preflight. Worker resolution independently revalidates
        # profile rotation, capability compatibility, expiry and frozen authority.
        row = await conn.fetchrow(
            "SELECT id, profile_id, profile_version, principal_slot, refresh_count, target_binding_digest "
            "FROM auth_sessions WHERE id=$1 AND owner_kind='hunt' AND owner_id=$2 "
            "AND target_id=$3 AND target_kind=$4 AND principal_slot=$5 "
            "AND status='active' AND expires_at > NOW()",
            uid(session_ref), uid(run["id"]), uid(run["target_id"]), run["target_kind"], slot,
        )
        if not row:
            raise AuthorizationWorkflowError("The selected authentication session is unavailable, expired or bound elsewhere")
        return {name: str(value) if isinstance(value, uuid.UUID) else value for name, value in dict(row).items()}

    async def insert_node(self, conn: Any, run: Mapping[str, Any], node_id: Any, kind: str,
                          key: str, attributes: Mapping[str, Any]) -> None:
        await conn.execute(
            "INSERT INTO application_graph_nodes (id,target_id,node_type,node_key,label,attributes) "
            "VALUES ($1,$2,$3,$4,'Authorization investigation',$5::jsonb) "
            "ON CONFLICT (target_id,node_type,node_key) DO NOTHING",
            uid(node_id), uid(run["target_id"]), kind, key, json.dumps(dict(attributes)),
        )

    async def proposal(self, conn: Any, run: Mapping[str, Any], proposal_id: Any, *, lock: bool = False) -> dict[str, Any]:
        row = await conn.fetchrow(
            "SELECT attributes FROM application_graph_nodes WHERE id=$1 AND target_id=$2 "
            "AND node_type=$3" + (" FOR UPDATE" if lock else ""),
            uid(proposal_id), uid(run["target_id"]), PROPOSAL_TYPE,
        )
        item = mapping(dict(row).get("attributes")) if row else {}
        if not item or item.get("hunt_id") != str(run["id"]):
            raise AuthorizationWorkflowError("Authorization investigation not found", 404)
        if item.get("schema_version") != "hunt-authorization/v1":
            raise AuthorizationWorkflowError("Unsupported authorization investigation version")
        core = {key: value for key, value in item.items() if key not in {"proposal_id", "proposal_digest"}}
        if (digest(core) != item.get("proposal_digest")
                or str(uid(proposal_id)) != item.get("proposal_id")
                or uuid.uuid5(uid(run["id"]), "authorization:" + item["proposal_digest"]) != uid(proposal_id)):
            raise AuthorizationWorkflowError("The persisted proposal binding is inconsistent")
        return item

    async def attempts(self, conn: Any, run: Mapping[str, Any], proposal_id: Any) -> list[dict[str, Any]]:
        prefix = f"authz:{uid(proposal_id)}:attempt:"
        rows = await conn.fetch(
            "SELECT attributes FROM application_graph_nodes WHERE target_id=$1 "
            "AND node_type=$2 AND node_key LIKE $3 ORDER BY node_key LIMIT 21",
            uid(run["target_id"]), ATTEMPT_TYPE, prefix + "%",
        )
        result = [mapping(dict(row).get("attributes")) for row in rows]
        if len(result) > MAX_ATTEMPTS or any(r.get("hunt_id") != str(run["id"]) for r in result):
            raise AuthorizationWorkflowError("Invalid investigation attempt history")
        for number, item in enumerate(result, 1):
            key = f"authz-investigation:{uid(proposal_id)}:{number}"
            if (type(item.get("attempt")) is not int or item["attempt"] != number
                    or item.get("proposal_id") != str(uid(proposal_id))
                    or item.get("idempotency_key") != key
                    or item.get("action_id") != str(canonical_action_id(run["id"], key))):
                raise AuthorizationWorkflowError("Invalid investigation attempt binding")
        return result

    async def action(self, conn: Any, run: Mapping[str, Any], action_id: Any) -> dict[str, Any] | None:
        row = await conn.fetchrow(
            "SELECT id,hunt_run_id,capability_name,status,input_summary,result_summary,receipt_id,started_at,completed_at "
            "FROM hunt_actions WHERE id=$1 AND hunt_run_id=$2", uid(action_id), uid(run["id"]),
        )
        return dict(row) if row else None

    async def transactions(self, conn: Any, run: Mapping[str, Any], action_id: Any) -> list[dict[str, Any]]:
        rows = await conn.fetch(
            "SELECT id,hunt_run_id,hunt_action_id,principal_slot,method,url,request_body_bytes,status_code,error "
            "FROM http_transactions WHERE hunt_run_id=$1 AND hunt_action_id=$2 "
            "ORDER BY sequence LIMIT 101", uid(run["id"]), uid(action_id),
        )
        # Incomplete evidence is not a negative authorization conclusion.
        return [dict(row) for row in rows] if len(rows) <= 100 else []

    async def skipped(self, conn: Any, run: Mapping[str, Any], proposal_id: Any) -> bool:
        row = await conn.fetchrow(
            "SELECT id FROM application_graph_nodes WHERE target_id=$1 AND node_type=$2 AND node_key=$3",
            uid(run["target_id"]), DECISION_TYPE, f"authz:{uid(proposal_id)}:skip",
        )
        return row is not None
