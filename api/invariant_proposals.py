"""Auto-draft typed invariant contracts from black-box observations (Phase 0: access_control).

Pure + dependency-free (stdlib + the equally-dep-free ``invariant_contracts``) so it is host-testable
and importable flat in the container. A proposer NEVER approves or promotes anything: every draft it
emits is ``status='draft'``, ``promotion_authority=False``. Approval is a human action through the
existing ``POST /targets/{id}/invariants/{id}/approve``; only an *approved* contract can route an
Explorer finding through the invariant binder (`_arsenal_dispatch_workflow` fetches
``WHERE status='approved'``). So a proposer can only ever create *candidate rules for review* — it
cannot widen the VERIFIED surface on its own.
"""
from __future__ import annotations

from typing import Any

import invariant_contracts

# Expectations that express an access-control policy the binder can prove (a role must be required for,
# or denied on, a route). "allow" is intentionally excluded — an allowed access is not a vulnerability.
_ACCESS_EXPECTATIONS: frozenset[str] = frozenset({"deny", "requires_role"})


def _row_get(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return row.get(key) if hasattr(row, "get") else None


def propose_access_control_drafts(expectation_rows: Any) -> list[dict[str, Any]]:
    """Turn ``target_endpoint_expectations`` rows into access_control invariant DRAFTS.

    One draft per (kind, method, path, role, expected_access) with a concrete method/path/role and an
    expected_access in {deny, requires_role}. Each draft carries ``approval_errors`` (from the shared
    validator) so a caller can tell which are approvable, but they are ALL emitted as drafts — the
    operator decides. Malformed rows are skipped, never raised.
    """
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in expectation_rows or []:
        expected = str(_row_get(row, "expected_access") or "").strip().lower()
        method = str(_row_get(row, "method") or "").strip().upper()
        path = str(_row_get(row, "path") or "").strip()
        role = str(_row_get(row, "principal_role") or _row_get(row, "subject_role") or "").strip()
        if expected not in _ACCESS_EXPECTATIONS or not method or not path or not role:
            continue
        raw = {
            "contract_kind": "access_control",
            "method": method,
            "path": path,
            "subject_role": role,
            "expected_access": expected,
            "title": f"{role} {expected.replace('_', ' ')} on {method} {path}"[:160],
        }
        try:
            contract = invariant_contracts.canonical_contract(raw)
        except (TypeError, ValueError):
            continue
        key = (
            contract.get("contract_kind"), contract.get("method"), contract.get("path"),
            contract.get("subject_role"), contract.get("expected_access"),
        )
        if key in seen:
            continue
        seen.add(key)
        errors = invariant_contracts.approval_errors({**contract, "status": "approved"})
        drafts.append({
            **contract,
            "status": "draft",
            "source": "auto_black_box",
            "promotion_authority": False,
            "approval_errors": errors,
            "approvable": not errors,
        })
    return drafts


def _emit_draft(raw: dict[str, Any], seen: set[tuple[Any, ...]]) -> dict[str, Any] | None:
    """Canonicalize one proposed contract into a review DRAFT, or None when malformed/duplicate.

    Every draft carries ``approval_errors`` (missing fields are NORMAL for black-box proposals —
    the operator completes the rule at review), is ``status='draft'``, ``promotion_authority=False``.
    """
    if isinstance(raw.get("expected_value"), str):
        raw = {**raw, "expected_value": raw["expected_value"][:500]}
    try:
        contract = invariant_contracts.canonical_contract(raw)
    except (TypeError, ValueError):
        return None
    key = (
        contract.get("contract_kind"), contract.get("method"), contract.get("path"),
        contract.get("subject_role"), contract.get("expected_access"),
        contract.get("field_name"), invariant_contracts.normalize_identifier(
            (contract.get("conditions") or {}).get("from_state")),
    )
    if key in seen:
        return None
    seen.add(key)
    errors = invariant_contracts.approval_errors({**contract, "status": "approved"})
    return {
        **contract,
        "status": "draft",
        "source": "auto_black_box",
        "promotion_authority": False,
        "approval_errors": errors,
        "approvable": not errors,
    }


def propose_ownership_drafts(graph_edges: Any) -> list[dict[str, Any]]:
    """Turn app-graph ``auth_boundary`` edges with an object id into ownership invariant DRAFTS.

    An auth_boundary edge (producer route -> consumer route crossing a principal boundary over an
    object id) is exactly an ownership rule candidate: "other principals must be DENIED this object
    on the consumer route". Malformed rows are skipped, never raised.
    """
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in graph_edges or []:
        if str(_row_get(row, "edge_type") or "") != "auth_boundary":
            continue
        attrs = _row_get(row, "attributes")
        attrs = attrs if isinstance(attrs, dict) else {}
        object_id_key = str(attrs.get("object_id_key") or "").strip()
        if not object_id_key:
            continue
        consumer = str(_row_get(row, "dst_key") or "").strip()
        # Consumer keys are route labels ("GET /api/x/{id}" or bare "/api/x/{id}").
        parts = consumer.split(" ", 1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            method, path = parts[0].upper(), parts[1].strip()
        else:
            method, path = "GET", consumer
        if not path.startswith("/"):
            continue
        excluded = str(attrs.get("excluded_principal") or attrs.get("excluded_from_principal") or "").strip()
        draft = _emit_draft({
            "contract_kind": "ownership",
            "method": method,
            "path": path,
            "subject_role": excluded or None,
            "expected_access": "deny",
            "conditions": {"resource_owner": "other"},
            "title": f"Non-owners denied on {method} {path}"[:160],
        }, seen)
        if draft:
            drafts.append(draft)
    return drafts


def propose_field_constraint_drafts(observation_rows: Any) -> list[dict[str, Any]]:
    """Turn observed numeric-cap hints into field_constraint invariant DRAFTS.

    Rows: ``{method, path, field_name, operator, expected_value}`` — any may be missing (the
    draft's approval_errors then guide the operator). Malformed rows are skipped, never raised.
    """
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in observation_rows or []:
        path = str(_row_get(row, "path") or "").strip()
        field = str(_row_get(row, "field_name") or _row_get(row, "param") or "").strip()
        if not path.startswith("/") or not field:
            continue
        draft = _emit_draft({
            "contract_kind": "field_constraint",
            "method": str(_row_get(row, "method") or "").strip().upper() or None,
            "path": path,
            "field_name": field,
            "operator": str(_row_get(row, "operator") or "").strip().lower() or None,
            "expected_value": _row_get(row, "expected_value"),
            "title": f"{field} bounded on {str(_row_get(row, 'method') or 'WRITE').upper()} {path}"[:160],
        }, seen)
        if draft:
            drafts.append(draft)
    return drafts


def propose_workflow_transition_drafts(observation_rows: Any) -> list[dict[str, Any]]:
    """Turn observed status-field state hints into workflow_transition invariant DRAFTS.

    Rows: ``{method, path, field_name, from_state?, to_state?, probe_state?}`` — black-box
    observation rarely knows the LEGAL pair, so missing pieces are expected (approval_errors
    guide the operator; probe_state is an approval requirement since the F5 gate).
    """
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in observation_rows or []:
        path = str(_row_get(row, "path") or "").strip()
        field = str(_row_get(row, "field_name") or "").strip()
        if not path.startswith("/") or not field:
            continue
        conditions = {
            key: str(_row_get(row, key) or "").strip()
            for key in ("from_state", "to_state", "probe_state")
            if str(_row_get(row, key) or "").strip()
        }
        draft = _emit_draft({
            "contract_kind": "workflow_transition",
            "method": str(_row_get(row, "method") or "").strip().upper() or None,
            "path": path,
            "field_name": field,
            "conditions": conditions,
            "title": f"{field} transition rule on {str(_row_get(row, 'method') or 'WRITE').upper()} {path}"[:160],
        }, seen)
        if draft:
            drafts.append(draft)
    return drafts


def propose_drafts_from_suspected_findings(findings: Any) -> list[dict[str, Any]]:
    """Turn SUSPECTED autonomous findings into matching invariant DRAFTS (A3).

    The operator then approves the exact suspected rule and re-verifies. field_constraint /
    workflow (workflow_transition) families map to their contract kinds; evidence rarely carries
    every field, so drafts lean on approval_errors. Malformed rows are skipped, never raised.
    """
    field_rows: list[dict[str, Any]] = []
    workflow_rows: list[dict[str, Any]] = []
    for finding in findings or []:
        evidence = _row_get(finding, "evidence")
        if isinstance(evidence, str):
            try:
                import json as _json
                evidence = _json.loads(evidence)
            except (TypeError, ValueError):
                evidence = None
        evidence = evidence if isinstance(evidence, dict) else {}
        family = str(evidence.get("family") or "").strip().lower().replace("-", "_")
        # Route: the finding URL path (concrete) is the rule's locus.
        url = str(_row_get(finding, "url") or "")
        path = url.split("://", 1)[-1]
        path = "/" + path.split("/", 1)[1].split("?", 1)[0] if "/" in path else ""
        if not path or path == "/":
            continue
        method = str(evidence.get("method") or "").strip().upper() or None
        if family == "field_constraint":
            field_rows.append({
                "method": method,
                "path": path,
                "field_name": evidence.get("field_name") or evidence.get("param"),
                "operator": evidence.get("operator"),
                "expected_value": evidence.get("expected_value", evidence.get("bound")),
            })
        elif family in {"workflow", "workflow_transition", "business_logic"}:
            workflow_rows.append({
                "method": method,
                "path": path,
                "field_name": evidence.get("state_field") or evidence.get("field_name"),
                "from_state": evidence.get("from_state"),
                "to_state": evidence.get("to_state"),
                "probe_state": evidence.get("probe_state"),
            })
    return propose_field_constraint_drafts(field_rows) + propose_workflow_transition_drafts(workflow_rows)
