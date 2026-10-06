"""Read-only authorization hypotheses from same-Hunt, same-asset captures.

Shared origin is a possible integration, not proof of delegation. Credential
slots and structural field names are observations, never identity/ownership or
authority. The existing candidate and AI Boundary lifecycles own later work.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from typing import Any, Mapping
from urllib.parse import urlsplit

from .boundary_context import BoundaryContextError, _json, _uuid
try:
    from runtime.http_structure import structure_fields
    from ai_gate.boundary.hypothesis import normalize_boundary_source_binding
except ModuleNotFoundError:
    from ..runtime.http_structure import structure_fields
    from ..ai_gate.boundary.hypothesis import normalize_boundary_source_binding

MAX_CAPTURES = 500
MAX_DRAFTS = 20
MAX_SURFACES = 50
CAPTURES_QUERY = """
SELECT t.id, t.hunt_action_id, t.url, t.method, t.status_code,
       t.principal_slot, t.metadata_json, t.error, t.truncated
FROM http_transactions t JOIN hunt_actions a ON a.id=t.hunt_action_id
WHERE t.hunt_run_id=$1::uuid AND a.hunt_run_id=$1::uuid
  AND t.plane='hunt' AND t.scan_id IS NULL
  AND a.status IN ('completed', 'partial')
  AND ((t.target_id=$2::uuid AND t.device_target_id IS NULL)
    OR (t.device_target_id=$3::uuid AND (t.target_id IS NULL OR t.target_id=$3::uuid)))
ORDER BY t.started_at DESC, t.id DESC LIMIT $4
"""


def _service(url: Any) -> tuple[str, str] | None:
    """Canonical default ports; preserve scheme/nonstandard ports, omit queries.

    Encoded paths, credentials, fragments and query-bound resources need a later
    fixture contract. Do not accidentally prepare an unfaithful replay of them.
    """
    if not isinstance(url, str) or len(url) > 2048:
        return None
    try:
        p = urlsplit(url)
        if (p.scheme not in {"http", "https"} or not p.hostname or p.username
                or p.password or p.query or p.fragment or not p.path
                or not re.fullmatch(r"/[A-Za-z0-9_./-]*", p.path)
                or any(x in {".", ".."} for x in p.path.split("/")) or "//" in p.path):
            return None
        port = p.port
    except ValueError:
        return None
    host = p.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port and port != (443 if p.scheme == "https" else 80) else ""
    return f"{p.scheme}://{host}{suffix}", p.path


def _pick(fields: Mapping[str, str], names: tuple[str, ...], *, string_only=False) -> str | None:
    matches = [path for path, kind in fields.items()
               if path.split(".")[-1] in names and kind in ({"string"} if string_only else {"string", "number"})]
    return matches[0] if len(matches) == 1 else None


def _provenance(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"origin_kind": "http_capture", "capture_id": str(row["id"]),
            "action_id": str(row["hunt_action_id"]), "authority": False}


def _observe(rows):
    agents, identities, resources, actions = [], [], [], []
    unavailable = skipped = 0
    for row in rows:
        service = _service(row.get("url"))
        if (service is None or row.get("error") or row.get("truncated")
                or type(row.get("status_code")) is not int or not 200 <= row["status_code"] < 300):
            skipped += 1
            continue
        origin, path = service
        method = str(row.get("method") or "").upper()
        source = {"origin": origin, "path": path, "method": method,
                  "principal_slot": row.get("principal_slot"), "provenance": _provenance(row)}
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            actions.append({
                **source,
                "missing_facts": [
                    "effect_classification",
                    "expected_business_rule",
                    "independent_postcondition",
                    "approval_semantics",
                ],
                "execution_enabled": False,
            })
        try:
            metadata = _json(row.get("metadata_json"), dict)
        except BoundaryContextError:
            unavailable += 1
            continue
        if metadata.get("workflow_values_private") is True:
            unavailable += 1
            continue
        fields = structure_fields(metadata.get("boundary_structure"))
        if not fields:
            unavailable += 1
            continue
        answer = _pick(fields, ("answer", "text"), string_only=True)
        if method == "POST" and answer:
            agents.append({**source, "response_path": answer, "agent_presence_verified": False})
        if method != "GET" or row.get("principal_slot") not in {"primary", "secondary"}:
            continue
        subject, tenant = _pick(fields, ("subject", "user_id")), _pick(fields, ("tenant", "tenant_id"))
        if subject and tenant:
            identities.append({**source, "subject_field": subject, "tenant_field": tenant})
        identifier = _pick(fields, ("id", "resource_id"))
        parts = path.rsplit("/", 1)
        if identifier and parts[0] and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", parts[-1]):
            resources.append({**source, "resource_id": parts[-1],
                              "path_template": parts[0] + "/{{resource_id}}", "id_field": identifier,
                              "owner_field": _pick(fields, ("owner", "owner_id")),
                              "tenant_field": tenant, "marker_field": _pick(fields, ("marker",), string_only=True)})
    return agents, identities, resources, actions, unavailable, skipped


def _stable_resources(resources):
    """Merge consistent repeated observations; reject ambiguous structure."""
    grouped = defaultdict(list)
    for resource in resources:
        grouped[(
            resource["origin"], resource["path_template"],
            resource["principal_slot"], resource["resource_id"],
        )].append(resource)
    stable, conflicts = [], 0
    for _, records in sorted(grouped.items()):
        signatures = {
            json.dumps(
                {key: record.get(key) for key in ("id_field", "owner_field", "tenant_field", "marker_field")},
                sort_keys=True, separators=(",", ":"),
            )
            for record in records
        }
        if len(signatures) != 1:
            conflicts += 1
            continue
        item = dict(records[0])
        item["provenance_records"] = list(dict.fromkeys(
            json.dumps(record["provenance"], sort_keys=True, separators=(",", ":"))
            for record in records
        ))
        item["provenance_records"] = [json.loads(value) for value in item["provenance_records"]]
        stable.append(item)
    return stable, conflicts


def _action_leads(actions):
    """Inventory non-GET observations without assuming they changed state or were authorized."""
    grouped = {}
    for action in actions:
        key = (action["origin"], action["path"], action["method"], action.get("principal_slot"))
        current = grouped.setdefault(key, {**action, "provenance": []})
        marker = json.dumps(action["provenance"], sort_keys=True, separators=(",", ":"))
        if marker not in {
            json.dumps(item, sort_keys=True, separators=(",", ":"))
            for item in current["provenance"]
        }:
            current["provenance"].append(action["provenance"])
    return [grouped[key] for key in sorted(grouped)]


def build_boundary_discovery(*, run: Mapping[str, Any], rows: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Pure bounded projection. Values outside structural metadata are unused."""
    hunt_id = _uuid(run.get("id"))
    rows_truncated = len(rows) > MAX_CAPTURES
    agents, identities, resources, actions, unavailable, skipped = _observe(rows[:MAX_CAPTURES])
    resources, resource_conflicts = _stable_resources(resources)
    actions = _action_leads(actions)
    # Stable ordering and grouping keep output deterministic; the query window is
    # explicitly incomplete when it hits its bound. No all-pairs explosion.
    groups = defaultdict(lambda: {"primary": {}, "secondary": {}})
    for resource in resources:
        key = (resource["origin"], resource["path_template"])
        groups[key][resource["principal_slot"]][resource["resource_id"]] = resource
    drafts = []
    draft_count = 0
    for (origin, template), slots in sorted(groups.items()):
        same_agents = {(a["path"], a["response_path"]) for a in agents if a["origin"] == origin}
        for owner_id, owner in sorted(slots["primary"].items()):
            for attacker_id, attacker in sorted(slots["secondary"].items()):
                if owner_id == attacker_id:
                    continue
                draft_count += 1
                if len(drafts) >= MAX_DRAFTS:
                    continue
                owner_sources = owner.get("provenance_records") or [owner["provenance"]]
                attacker_sources = attacker.get("provenance_records") or [attacker["provenance"]]
                sources = [*owner_sources, *attacker_sources]
                prefill: dict[str, Any] = {
                    "version": 1, "name": "discovered-read-boundary",
                    "owner": {"resource_id": owner_id}, "attacker": {"resource_id": attacker_id},
                    "resource": {"path": template},
                }
                field_sources = {
                    "owner.resource_id": owner_sources.copy(),
                    "attacker.resource_id": attacker_sources.copy(),
                    "resource.path": sources.copy(),
                }
                for key in ("id_field", "owner_field", "tenant_field", "marker_field"):
                    if owner[key] and owner[key] == attacker[key]:
                        prefill["resource"][key] = owner[key]
                        field_sources[f"resource.{key}"] = sources.copy()
                same_identities = [i for i in identities if i["origin"] == origin]
                # Both slots must have observed the same structure on this exact
                # service; competing bindings remain a gap, never first-match.
                by_slot = {slot: {(i["path"], i["subject_field"], i["tenant_field"])
                                  for i in same_identities if i["principal_slot"] == slot}
                           for slot in ("primary", "secondary")}
                if by_slot["primary"] == by_slot["secondary"] and len(by_slot["primary"]) == 1:
                    path, subject, tenant = next(iter(by_slot["primary"]))
                    prefill["identity"] = {"path": path, "subject_field": subject, "tenant_field": tenant}
                    identity_sources = [i["provenance"] for i in same_identities if i["path"] == path][:4]
                    sources.extend(identity_sources)
                    for key in prefill["identity"]:
                        field_sources[f"identity.{key}"] = identity_sources
                if len(same_agents) == 1:
                    path, response = next(iter(same_agents))
                    prefill["response_path"] = response
                    agent_sources = [a["provenance"] for a in agents if a["origin"] == origin and a["path"] == path][:2]
                    sources.extend(agent_sources)
                    field_sources["response_path"] = agent_sources
                missing = [f"{slot}.{key}" for slot in ("owner", "attacker")
                           for key in ("role", "subject", "tenant")]
                missing.extend(f"resource.{key}" for key in ("id_field", "owner_field", "tenant_field", "marker_field")
                               if key not in prefill["resource"])
                if "identity" not in prefill:
                    missing.append("identity")
                if "response_path" not in prefill:
                    missing.append("response_path")
                missing.extend(["controlled_fixture_ownership", "distinct_principals", "agent_endpoint_binding"])
                # Canonical candidate identity is shared across Hunts; immutable
                # observations retain each Hunt's own evidence association.
                digest = hashlib.sha256(json.dumps([origin, template, owner_id, attacker_id], separators=(",", ":")).encode()).hexdigest()
                refs = list(dict.fromkeys(s["capture_id"] for s in sources))
                agent_paths = sorted({p for p, _ in same_agents})
                target_ref = run.get("device_target_id") or run.get("target_id")
                source_binding = normalize_boundary_source_binding({
                    "schema_version": "hunt-boundary-source/v1",
                    "hunt_id": hunt_id,
                    "target_id": _uuid(target_ref),
                    "origin": origin,
                    "agent_paths": agent_paths,
                }) if agent_paths else None
                drafts.append({
                    "draft_id": digest, "kind": "cross_tenant_read", "status": "needs_context",
                    "origin": origin, "agent_paths": agent_paths,
                    "source_binding": source_binding,
                    "principal_slots": {"owner": "primary", "attacker": "secondary"},
                    "fixture_prefill": prefill, "field_provenance": field_sources,
                    "provenance": sources, "missing_facts": missing,
                    "candidate_request": {
                        "family": "cross_tenant_retrieval", "locus": {
                            "method": "GET", "url": origin + template, "route": template,
                            "ai_boundary_context": {
                                "discovery_draft_id": digest,
                                "owner_resource_id": owner_id,
                                "attacker_resource_id": attacker_id,
                            },
                        },
                        "title": "Possible cross-principal agent resource read",
                        "claim": "Two credential slots accessed different resources. Ownership, distinct identity and agent integration remain unverified.",
                        "severity": "info", "evidence_refs": refs,
                    },
                })
    return {
        "schema_version": "hunt-boundary-discovery/v1", "hunt_id": hunt_id,
        "status": "drafts_available" if drafts else "needs_evidence", "drafts": drafts,
        "agent_surfaces": agents[:MAX_SURFACES],
        "action_leads": actions[:MAX_SURFACES],
        "coverage": {"captures_read": min(len(rows), MAX_CAPTURES), "captures_truncated": rows_truncated,
                     "structure_unavailable": unavailable, "captures_skipped": skipped,
                     "conflicting_resource_observations": resource_conflicts,
                     "drafts_truncated": draft_count > MAX_DRAFTS, "agent_surfaces_truncated": len(agents) > MAX_SURFACES,
                     "action_leads_truncated": len(actions) > MAX_SURFACES,
                     "historical_backfill_performed": False},
        "gaps": ["agent_resource_relationship_unverified", "credentials_are_not_distinct_identity_proof",
                 "successful_access_is_not_ownership", "application_policy_unassessed"],
        "execution_enabled": False, "verification_performed": False, "promotion_authority": False,
    }


async def discover_hunt_boundaries(conn: Any, *, run: Mapping[str, Any]) -> dict[str, Any]:
    target_id = _uuid(run["target_id"]) if run.get("target_id") else None
    device_id = _uuid(run["device_target_id"]) if run.get("device_target_id") else None
    if ((not target_id and not device_id) or (device_id and target_id not in (None, device_id))):
        raise BoundaryContextError("invalid_discovery_target_binding")
    rows = await conn.fetch(CAPTURES_QUERY, _uuid(run["id"]), target_id, device_id, MAX_CAPTURES + 1)
    return build_boundary_discovery(run=run, rows=[dict(r) for r in rows])
