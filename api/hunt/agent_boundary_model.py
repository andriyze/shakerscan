"""Evidence-derived suggestions for the existing AI Boundary verifier, never proof.

Consumes only the canonical redacted archive projection. Field-name matches are
schema hints; observed subject/tenant/owner values remain application claims.
No response text is copied into prompts and no marker value leaves this module.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from itertools import product
import json
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit
from uuid import UUID, uuid5

try:
    from ai_gate.boundary.contract import NAME_RE, PATH_RE, canonical_hash, relative_path, valid_marker
    from ai_gate.boundary.hypothesis import compile_boundary_hypothesis, materialize_boundary_contract
except ModuleNotFoundError:
    from ..ai_gate.boundary.contract import NAME_RE, PATH_RE, canonical_hash, relative_path, valid_marker
    from ..ai_gate.boundary.hypothesis import compile_boundary_hypothesis, materialize_boundary_contract

SCHEMA = "agent-boundary-model/v1"
NODE_TYPE = "agent_authorization_model"
MAX_BODY_BYTES = 65536
MAX_FIELDS = 128
MAX_SUGGESTIONS = 16
ALIASES = {
    "subject": {"subject", "sub", "principal_id", "user_id"},
    "tenant": {"tenant", "tenant_id", "organization_id", "org_id"},
    "id": {"id", "resource_id", "record_id", "order_id"},
    "owner": {"owner", "owner_id", "owner_subject", "user_id"},
}


def origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username
            or parsed.password or any(ord(c) < 33 for c in value)):
        raise ValueError("invalid_agent_origin")
    host = parsed.hostname.lower().rstrip(".")
    host = f"[{host}]" if ":" in host else host
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://{host}:{port}"


def _identifier(value: Any) -> str | None:
    if type(value) is int:
        value = str(value)
    return value if isinstance(value, str) and NAME_RE.fullmatch(value) and not valid_marker(value) else None


def _fields(text: Any) -> dict[str, Any]:
    if not isinstance(text, str) or len(text.encode()) > MAX_BODY_BYTES:
        raise ValueError("response_body_unavailable_or_too_large")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous_json_keys")
            result[key] = value
        return result

    def reject_constant(_value):
        raise ValueError("non_finite_json")

    raw = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
    if not isinstance(raw, dict):
        raise ValueError("object_response_required")
    fields = {}

    def walk(item, prefix="", depth=0):
        if depth > 6:
            raise ValueError("response_shape_too_deep")
        for key, value in item.items():
            path = f"{prefix}.{key}" if prefix else key
            if not isinstance(key, str) or not PATH_RE.fullmatch(path) or len(path) > 128:
                continue
            if isinstance(value, dict):
                walk(value, path, depth + 1)
            elif not isinstance(value, list):
                fields[path] = value
            if len(fields) > MAX_FIELDS:
                raise ValueError("response_shape_too_wide")
    walk(raw)
    return fields


def _field(fields: Mapping[str, Any], kind: str) -> tuple[str, str] | None:
    matches = [(key, _identifier(value)) for key, value in fields.items()
               if key.split(".")[-1] in ALIASES[kind] and _identifier(value) is not None]
    return matches[0] if len(matches) == 1 else None


def _references(*records) -> list[str]:
    return sorted({ref for record in records for ref in record["evidence_refs"]})


def build_agent_boundary_model(
    captures: Sequence[Mapping[str, Any]], *, hunt_id: str, ai_target_id: str,
    endpoint_url: str, response_path: str, roles: Mapping[str, str],
) -> dict[str, Any]:
    """Suggest cross-tenant fixtures from consistent same-origin, two-slot captures.

    The supported automation is controlled JSON identity/resource discovery.
    Mutating calls and reported tools are inventoried, not promoted or executed.
    Missing synthetic controls are actionable gaps, never silently fabricated.
    """
    hunt_uuid = UUID(hunt_id)
    selected_origin = origin(endpoint_url)
    if (set(roles) != {"primary", "secondary"} or len(set(roles.values())) != 2
            or any(_identifier(value) is None for value in roles.values())):
        raise ValueError("distinct_saved_ai_roles_required")
    if not isinstance(response_path, str) or not PATH_RE.fullmatch(response_path) or len(response_path) > 128:
        raise ValueError("supported_agent_response_path_required")
    identities = defaultdict(list)
    resources = []
    nodes, edges, ignored = {}, [], Counter()
    marker_gaps = 0

    def node(kind, key, attributes, refs):
        node_key = f"agent-boundary:{kind}:{canonical_hash(key)[7:]}"
        previous = nodes.get(node_key)
        references = sorted(set(refs) | set(previous["evidence_refs"] if previous else ()))
        nodes[node_key] = {"node_type": kind, "node_key": node_key,
                           "attributes": attributes, "evidence_refs": references,
                           "certainty": "observed_application_claim", "verified": False}
        return node_key

    agent = node("agent", [ai_target_id, selected_origin], {"ai_target_id": ai_target_id, "origin": selected_origin}, [])
    nodes[agent]["certainty"] = "configured_not_observed"
    for row in captures:
        try:
            ref = str(UUID(str(row["id"])))
            if origin(str(row.get("url") or "")) != selected_origin:
                ignored["other_origin"] += 1
                continue
            parsed = urlsplit(row["url"])
            # Never discard a query or rewrite encoded identifiers into a different request.
            if parsed.query or parsed.fragment or "?" in row["url"] or "#" in row["url"]:
                raise ValueError("query_or_fragment_requires_explicit_fixture")
            path = relative_path(parsed.path or "/")
            if "{" in path or "}" in path:
                raise ValueError("captured_path_is_not_literal")
            method = str(row.get("method") or "").upper()
            if (row.get("error") or row.get("truncated") or row.get("payload_unavailable")
                    or row.get("payload_omitted") or type(row.get("status_code")) is not int
                    or not 200 <= row["status_code"] < 300
                    or not isinstance(row.get("capture"), Mapping)
                    or row["capture"].get("fidelity") != "wire_request"):
                raise ValueError("incomplete_or_unsuccessful_capture")
            slot = row.get("principal_slot")
            if slot not in roles:
                raise ValueError("unselected_principal")
            if method in {"POST", "PUT", "PATCH", "DELETE"}:
                action = node("action", [method, path, slot], {"method": method, "path": path, "principal_slot": slot,
                    "missing_facts": ["expected_business_rule", "independent_postcondition", "approval_semantics"]}, [ref])
                edges.append({"src_key": agent, "edge_type": "observed_request", "dst_key": action, "evidence_refs": [ref]})
                # Bodies of workflow mutations stay private in the archive; no attempt to recover them.
                continue
            if method != "GET":
                continue
            fields = _fields(row.get("response", {}).get("body"))
            if any(value is False for key, value in fields.items() if key.split(".")[-1] in {"success", "authenticated"}):
                raise ValueError("negative_authentication_or_operation_state")
            subject, tenant = _field(fields, "subject"), _field(fields, "tenant")
            rid, owner = _field(fields, "id"), _field(fields, "owner")
            if subject and tenant and rid is None:
                record = {"slot": slot, "subject": subject[1], "tenant": tenant[1],
                          "path": path, "subject_field": subject[0], "tenant_field": tenant[0], "evidence_refs": [ref]}
                identities[(path, subject[0], tenant[0], slot)].append(record)
                p = node("principal", [slot, subject[1], tenant[1]], {"slot": slot, "subject": subject[1], "tenant": tenant[1]}, [ref])
                t = node("tenant", tenant[1], {"tenant": tenant[1]}, [ref])
                edges.append({"src_key": p, "edge_type": "response_claims_tenant", "dst_key": t, "evidence_refs": [ref]})
            if rid and owner and tenant:
                segments = path.split("/")
                if segments.count(rid[1]) != 1:
                    raise ValueError("resource_id_not_one_exact_path_segment")
                markers = [key for key, value in fields.items() if valid_marker(value)]
                resource = {"slot": slot, "id": rid[1], "owner": owner[1], "tenant": tenant[1],
                            "path": path, "template": "/".join("{{resource_id}}" if part == rid[1] else part for part in segments),
                            "id_field": rid[0], "owner_field": owner[0], "tenant_field": tenant[0],
                            "marker_field": markers[0] if len(markers) == 1 else None,
                            "_marker_hash": canonical_hash(fields[markers[0]]) if len(markers) == 1 else None,
                            "evidence_refs": [ref]}
                resources.append(resource)
                marker_gaps += not bool(resource["marker_field"])
                r = node("resource", [path, slot, rid[1], owner[1], tenant[1]],
                         {key: resource[key] for key in ("slot", "id", "owner", "tenant", "path")}, [ref])
                p = node("principal", [slot, owner[1], tenant[1]], {"slot": slot, "subject": owner[1], "tenant": tenant[1]}, [ref])
                edges.append({"src_key": r, "edge_type": "response_claims_owner", "dst_key": p, "evidence_refs": [ref]})
        except (ValueError, KeyError, TypeError, RecursionError):
            ignored["unsupported_or_incomplete_capture"] += 1

    # Consistency is checked across every retained observation, not just the last convenient response.
    stable = {}
    for key, records in identities.items():
        if len({(r["subject"], r["tenant"]) for r in records}) == 1:
            stable[key] = {**records[0], "evidence_refs": _references(*records)}
        else:
            ignored["conflicting_identity_observations"] += 1
    grouped_resources = defaultdict(list)
    for resource in resources:
        grouped_resources[(resource["slot"], resource["path"])].append(resource)
    resources = []
    for key, records in sorted(grouped_resources.items()):
        signatures = {canonical_hash({k: v for k, v in r.items() if k != "evidence_refs"}) for r in records}
        if len(signatures) != 1:
            ignored["conflicting_resource_observations"] += 1
            continue
        resources.append({**records[0], "evidence_refs": _references(*records)})
    drafts = {}
    combinations = 0
    for key, owner_identity in sorted(stable.items()):
        if key[-1] != "primary":
            continue
        attacker_identity = stable.get((*key[:-1], "secondary"))
        if not attacker_identity:
            continue
        left = [r for r in resources if r["slot"] == "primary" and r["owner"] == owner_identity["subject"] and r["tenant"] == owner_identity["tenant"]]
        right = [r for r in resources if r["slot"] == "secondary" and r["owner"] == attacker_identity["subject"] and r["tenant"] == attacker_identity["tenant"]]
        for own, other in product(left, right):
            combinations += 1
            if combinations > 4096:
                break
            selector_keys = ("template", "id_field", "owner_field", "tenant_field", "marker_field")
            if (not own["marker_field"] or own["_marker_hash"] == other["_marker_hash"]
                    or any(own[k] != other[k] for k in selector_keys)):
                continue
            principal = lambda ident, resource: {"role": roles[ident["slot"]], "subject": ident["subject"], "tenant": ident["tenant"], "resource_id": resource["id"]}
            base = {"version": 1, "name": "hunt-discovered-isolation", "owner": principal(owner_identity, own),
                    "attacker": principal(attacker_identity, other),
                    "identity": {"path": key[0], "subject_field": key[1], "tenant_field": key[2]},
                    "resource": {"path": own["template"], **{k: own[k] for k in selector_keys[1:]}},
                    "response_path": response_path}
            refs = _references(owner_identity, attacker_identity, own, other)
            hypothesis = {"version": 1, "hypothesis_id": "discovered-" + canonical_hash(base)[7:31], "kind": "cross_tenant_read",
                          "owner": base["owner"], "attacker": base["attacker"],
                          "provenance": [{"kind": "http_transaction", "id": ref} for ref in refs[:20]]}
            try:
                proposal = compile_boundary_hypothesis(hypothesis)
                materialized = materialize_boundary_contract(proposal, boundary_base=base)
            except ValueError:
                ignored["incompatible_verifier_bindings"] += 1
                continue
            digest = materialized["boundary_contract_sha256"]
            drafts[digest] = {"id": str(uuid5(hunt_uuid, digest)), "kind": "cross_tenant_read", "hypothesis": hypothesis,
                "proposal": proposal, "boundary_base": base, "boundary_contract_sha256": digest,
                "candidate_request": {"family": "cross_tenant_retrieval", "locus": {"route": own["path"], "method": "GET"},
                    "title": "Investigate agent cross-tenant resource access", "severity": "info",
                    "claim": "Captured identity and resource responses suggest a controlled cross-tenant read test. Fresh ownership, denial and legitimate controls are still required.",
                    "evidence_refs": refs[:100]},
                "evidence_refs": refs, "principal_bindings_verified": False, "policy_verified": False,
                "missing_facts": [], "provenance_truncated": len(refs) > 20}
    gaps = []
    if not any(k[-1] == "primary" for k in stable) or not any(k[-1] == "secondary" for k in stable):
        gaps.append("Capture matching JSON identity responses for both selected Hunt principal slots.")
    if marker_gaps:
        gaps.append("Provide distinct synthetic canaries on controlled resources; arbitrary private data is not a canary.")
    if not drafts:
        gaps.append("No complete supported two-principal fixture was derived; review identity/resource shapes and missing controls.")
    ordered = [drafts[key] for key in sorted(drafts)]
    return {"schema_version": SCHEMA, "hunt_id": hunt_id, "ai_target_id": ai_target_id,
            "origin": selected_origin, "nodes": sorted(nodes.values(), key=lambda n: n["node_key"]),
            "edges": sorted({canonical_hash(edge): edge for edge in edges}.values(),
                            key=lambda e: (e["src_key"], e["dst_key"], e["evidence_refs"])),
            "suggestions": ordered[:MAX_SUGGESTIONS], "suggestions_truncated": len(ordered) > MAX_SUGGESTIONS or combinations > 4096,
            "ignored": dict(ignored), "gaps": gaps, "projection_only": True,
            "execution_enabled": False, "verification_performed": False, "promotion_authority": False}
