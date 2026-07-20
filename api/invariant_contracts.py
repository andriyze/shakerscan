"""Typed, operator-approved target invariants for autonomous planning.

Free text is useful intake, but it is not a security oracle. This module keeps draft text separate
from the structured contract that an operator approves. Approved contracts may guide hypothesis and
experiment design; they deliberately carry no finding-promotion authority until a family-specific,
deterministic verifier consumes them.
"""

from __future__ import annotations

import math
import re
from typing import Any


CONTRACT_VERSION = "target-invariant-2026-07-14.v1"
CONTRACT_KINDS = frozenset({"access_control", "field_constraint", "workflow_transition", "ownership"})
CONTRACT_STATUSES = frozenset({"draft", "approved", "retired"})
EXPECTED_ACCESS = frozenset({"allow", "deny", "requires_role"})
VALUE_OPERATORS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in"})
CONDITION_KEYS = frozenset({"from_state", "to_state", "prerequisite_state", "tenant_relation", "resource_owner", "read_path"})
COMPILER_VERSION = "target-invariant-compiler-2026-07-14.v1"


def _clean_phrase(value: Any, *, limit: int = 160) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip(" .,:;!?\t\r\n")
    return text[:limit]


def _resource_phrase(value: Any) -> str:
    text = re.sub(r"\s+(?:at|on)\s+/\S+.*$", "", _clean_phrase(value), flags=re.IGNORECASE)
    text = re.sub(r"^(?:a|an|the)\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^(?:another|other)\s+(?:users?'?\s+)?", "", text, flags=re.IGNORECASE)
    return text


def _number(value: str) -> int | float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("invariant numeric value must be finite")
    return int(parsed) if parsed.is_integer() else parsed


def compile_rule_text(
    rule_text: str,
    *,
    method: str | None = None,
    path: str | None = None,
) -> dict[str, Any]:
    """Compile a deliberately small rule grammar into non-authoritative typed candidates.

    This is not an LLM parser and never guesses through ambiguity. Unsupported prose returns no
    candidate; partial candidates expose their approval errors for operator correction.
    """
    text = _clean_phrase(rule_text, limit=4000)
    inferred_path = path or next(iter(re.findall(r"/[A-Za-z0-9_./{}:*-]+", text)), None)
    inferred_method = method
    if not inferred_method:
        method_match = re.search(r"\b(GET|POST|PUT|PATCH|DELETE)\b", text, re.IGNORECASE)
        inferred_method = method_match.group(1) if method_match else None
    candidates: list[dict[str, Any]] = []

    workflow = re.search(
        r"^(?P<resource>[a-z][a-z0-9 _-]{0,80}?)\s+(?:can|may|must)\s+(?:only\s+)?"
        r"(?:move|transition|go|change)\s+from\s+(?P<from>[a-z0-9_.:-]+)\s+to\s+(?P<to>[a-z0-9_.:-]+)",
        text,
        re.IGNORECASE,
    )
    cap = re.search(
        r"^(?P<field>[a-z][a-z0-9 _.-]{0,80}?)\s+(?:must|should)\s+(?:be\s+)?"
        r"(?P<operator><=|>=|<|>)\s*(?P<value>-?\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    ) or re.search(
        r"^(?P<field>[a-z][a-z0-9 _.-]{0,80}?)\s+(?:must\s+)?never\s+"
        r"(?P<verb>exceed|exceeds|fall below)\s+(?P<value>-?\d+(?:\.\d+)?)",
        text,
        re.IGNORECASE,
    )
    ownership = re.search(
        r"^(?P<role>[a-z][a-z0-9 _-]{0,50}?)\s+(?:cannot|can't|must not|may not)\s+"
        r"(?P<action>[a-z][a-z0-9_-]{0,40})\s+(?P<resource>.*?\b(?:other|another)\b.+)$",
        text,
        re.IGNORECASE,
    )
    only_role = re.search(
        r"^only\s+(?P<role>[a-z][a-z0-9 _-]{0,50}?)\s+(?:can|may)\s+"
        r"(?P<action>[a-z][a-z0-9_-]{0,40})\s+(?P<resource>.+)$",
        text,
        re.IGNORECASE,
    )
    denied_role = re.search(
        r"^(?P<role>[a-z][a-z0-9 _-]{0,50}?)\s+(?:cannot|can't|must not|may not)\s+"
        r"(?P<action>[a-z][a-z0-9_-]{0,40})\s+(?P<resource>.+)$",
        text,
        re.IGNORECASE,
    )

    base = {"method": inferred_method, "path": inferred_path, "source_text": text}
    if workflow:
        resource = _resource_phrase(workflow.group("resource"))
        candidates.append({
            **base,
            "contract_kind": "workflow_transition",
            "title": f"{resource} transition {workflow.group('from')} to {workflow.group('to')}",
            "action": "transition",
            "resource": resource,
            # Draft hint only; the operator can correct it before approval. Requiring an exact
            # state field prevents an unrelated changing timestamp from becoming workflow proof.
            "field_name": "status",
            "conditions": {"from_state": workflow.group("from"), "to_state": workflow.group("to")},
        })
    elif cap:
        field = _clean_phrase(cap.group("field"))
        symbol = cap.groupdict().get("operator")
        verb = str(cap.groupdict().get("verb") or "").lower()
        operator = {"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}.get(symbol)
        if not operator:
            operator = "gte" if "fall below" in verb else "lte"
        candidates.append({
            **base,
            "contract_kind": "field_constraint",
            "title": f"{field} constraint",
            "action": "update",
            "resource": _resource_phrase(field),
            "field_name": field,
            "operator": operator,
            "expected_value": _number(cap.group("value")),
        })
    elif ownership:
        role = _clean_phrase(ownership.group("role"))
        resource = _resource_phrase(ownership.group("resource"))
        candidates.append({
            **base,
            "contract_kind": "ownership",
            "title": f"{role} cannot {ownership.group('action')} another owner's {resource}",
            "subject_role": role,
            "action": ownership.group("action"),
            "resource": resource,
            "expected_access": "deny",
            "conditions": {"resource_owner": "other"},
        })
    elif only_role:
        role = _clean_phrase(only_role.group("role"))
        resource = _resource_phrase(only_role.group("resource"))
        candidates.append({
            **base,
            "contract_kind": "access_control",
            "title": f"{role} role required to {only_role.group('action')} {resource}",
            "subject_role": role,
            "action": only_role.group("action"),
            "resource": resource,
            "expected_access": "requires_role",
            "conditions": {},
        })
    elif denied_role:
        role = _clean_phrase(denied_role.group("role"))
        resource = _resource_phrase(denied_role.group("resource"))
        candidates.append({
            **base,
            "contract_kind": "access_control",
            "title": f"{role} denied from {denied_role.group('action')} {resource}",
            "subject_role": role,
            "action": denied_role.group("action"),
            "resource": resource,
            "expected_access": "deny",
            "conditions": {},
        })

    compiled: list[dict[str, Any]] = []
    for candidate in candidates:
        canonical = canonical_contract(candidate)
        errors = approval_errors(canonical)
        compiled.append({
            **canonical,
            "compiler_version": COMPILER_VERSION,
            "ready_for_approval": not errors,
            "approval_errors": errors,
            "planning_authority": False,
            "promotion_authority": False,
        })
    return {
        "compiler_version": COMPILER_VERSION,
        "candidates": compiled,
        "candidate_count": len(compiled),
        "matched": bool(compiled),
        "warnings": ([] if compiled else ["unsupported_or_ambiguous_rule; provide typed fields manually"]),
        "execution_enabled": False,
        "findings_created": 0,
    }


def verification_plan(value: dict[str, Any]) -> dict[str, Any]:
    """Map an approved typed rule to the existing deterministic workflow proof boundary."""
    contract = canonical_contract(value)
    kind = contract["contract_kind"]
    family = {
        "ownership": "bola",
        "access_control": "access_control",
        "workflow_transition": "workflow",
        "field_constraint": "field_constraint",
    }[kind]
    # A positive "allow" rule cannot establish a vulnerability when it succeeds; only a denied or
    # role-restricted operation has a deterministic forbidden-principal counterexample. Keep that
    # shape planning-only until a separate omission-of-access verifier exists.
    supported = not (kind == "access_control" and contract.get("expected_access") == "allow")
    required_inputs = [
        "approved_contract", "concrete_route", "concrete_method", "independent_live_replay",
    ]
    if kind == "ownership":
        required_inputs += ["primary_credentials", "second_user_credentials", "object_producer", "cleanup_step"]
    elif kind == "access_control":
        required_inputs += ["authorized_control", "unauthorized_principal"]
    elif kind == "workflow_transition":
        required_inputs += ["state_field", "before_checkpoint", "forbidden_transition", "restoration_step"]
    else:
        required_inputs += ["baseline_read", "bounded_mutation", "restoration_step"]
    missing = []
    if str(value.get("status") or "") != "approved":
        missing.append("approved_contract")
    if not contract.get("path"):
        missing.append("concrete_route")
    if not contract.get("method"):
        missing.append("concrete_method")
    # These are runtime bindings, intentionally never inferred from prose or stored as fake proof.
    missing += [
        item for item in required_inputs
        if item not in {"approved_contract", "concrete_route", "concrete_method"}
    ]
    if not supported:
        missing.append("deterministic_contract_binder")
    return {
        "verifier": "experiment.workflow",
        "proof_family": family,
        "deterministic_family_supported": supported,
        "required_inputs": list(dict.fromkeys(required_inputs)),
        "missing_inputs": list(dict.fromkeys(missing)),
        "ready_to_execute": not missing,
        "requires_two_live_executions": True,
        "requires_restoration": kind in {"ownership", "workflow_transition", "field_constraint"},
        "promotion_authority": False,
        "promotion_gate": "trusted_workflow_family_proof" if supported else None,
    }


def normalize_identifier(value: Any, *, default: str = "", limit: int = 120) -> str:
    text = re.sub(r"[^a-z0-9_.:-]+", "_", str(value or "").strip().lower()).strip("_")
    return (text or default)[:limit]


def normalize_method(value: Any) -> str | None:
    method = str(value or "").strip().upper()
    if not method:
        return None
    if not re.fullmatch(r"[A-Z]{2,12}", method):
        raise ValueError("invariant method is invalid")
    return method


def normalize_path(value: Any) -> str | None:
    path = str(value or "").strip()
    if not path:
        return None
    if "://" in path:
        from urllib.parse import urlsplit

        path = urlsplit(path).path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path[:1000]


def canonical_contract(value: dict[str, Any]) -> dict[str, Any]:
    """Return the bounded, normalized representation stored and shown to planners."""
    payload = dict(value or {})
    kind = normalize_identifier(payload.get("contract_kind"), limit=40)
    if kind not in CONTRACT_KINDS:
        raise ValueError(f"unsupported invariant contract_kind:{kind or 'missing'}")
    operator = normalize_identifier(payload.get("operator"), limit=20) or None
    if operator and operator not in VALUE_OPERATORS:
        raise ValueError(f"unsupported invariant operator:{operator}")
    expected_access = normalize_identifier(payload.get("expected_access"), limit=40) or None
    if expected_access and expected_access not in EXPECTED_ACCESS:
        raise ValueError(f"unsupported invariant expected_access:{expected_access}")
    conditions_input = payload.get("conditions") if isinstance(payload.get("conditions"), dict) else {}
    unsupported_conditions = sorted(set(conditions_input) - CONDITION_KEYS)
    if unsupported_conditions:
        raise ValueError(f"unsupported invariant conditions:{','.join(unsupported_conditions)}")
    conditions: dict[str, str] = {}
    for key in ("from_state", "to_state", "prerequisite_state"):
        normalized = normalize_identifier(conditions_input.get(key), limit=120)
        if normalized:
            conditions[key] = normalized
    for key, allowed in (
        ("tenant_relation", {"same", "cross", "any"}),
        ("resource_owner", {"self", "other", "any"}),
    ):
        normalized = normalize_identifier(conditions_input.get(key), limit=40)
        if normalized and normalized not in allowed:
            raise ValueError(f"unsupported invariant condition {key}:{normalized}")
        if normalized:
            conditions[key] = normalized
    # read_path (field_constraint): the dotted response projection to observe the field on the READ,
    # for APIs whose read wraps the field differently than the WRITE body — e.g. write {"quantity": N}
    # but read $.data.quantity. Preserved VERBATIM (dots kept, unlike the identifier-normalized
    # conditions above); optional, defaulting to field_name. It only redirects the read projection —
    # a wrong read_path means the binder never observes the field -> fails closed (stays SUSPECTED).
    read_path = str(conditions_input.get("read_path") or "").strip()
    if read_path:
        if len(read_path) > 200 or not re.fullmatch(r"[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)*", read_path):
            raise ValueError("unsupported invariant condition read_path (dotted field path only)")
        conditions["read_path"] = read_path
    return {
        "version": CONTRACT_VERSION,
        "contract_kind": kind,
        "title": str(payload.get("title") or "").strip()[:300],
        "source_text": str(payload.get("source_text") or "").strip()[:4000] or None,
        "subject_role": normalize_identifier(payload.get("subject_role"), limit=80) or None,
        "action": normalize_identifier(payload.get("action"), limit=120) or None,
        "resource": normalize_identifier(payload.get("resource"), limit=160) or None,
        "method": normalize_method(payload.get("method")),
        "path": normalize_path(payload.get("path")),
        "field_name": normalize_identifier(payload.get("field_name"), limit=160) or None,
        "operator": operator,
        "expected_value": payload.get("expected_value"),
        "expected_access": expected_access,
        "conditions": conditions,
    }


def approval_errors(value: dict[str, Any]) -> list[str]:
    """Validate that a draft is machine-actionable before operator approval.

    This validates contract shape, not truth. Approval records the operator's policy assertion; a
    later live verifier must still establish the observed violation before any finding promotion.
    """
    try:
        contract = canonical_contract(value)
    except ValueError as exc:
        return [str(exc)]
    errors: list[str] = []
    if not contract["title"]:
        errors.append("title_required")
    if not (contract["action"] or contract["method"]):
        errors.append("action_or_method_required")
    if not (contract["resource"] or contract["path"]):
        errors.append("resource_or_path_required")
    kind = contract["contract_kind"]
    if kind == "access_control":
        if not contract["subject_role"]:
            errors.append("subject_role_required")
        if not contract["expected_access"]:
            errors.append("expected_access_required")
    elif kind == "field_constraint":
        if not contract["field_name"]:
            errors.append("field_name_required")
        if not contract["operator"]:
            errors.append("operator_required")
        if contract["expected_value"] is None:
            errors.append("expected_value_required")
        elif contract["operator"] in {"in", "not_in"} and not (
            isinstance(contract["expected_value"], list) and contract["expected_value"]
        ):
            errors.append("set_operator_expected_value_must_be_nonempty_array")
        elif contract["operator"] in {"lt", "lte", "gt", "gte"} and not (
            isinstance(contract["expected_value"], (int, float))
            and not isinstance(contract["expected_value"], bool)
        ):
            errors.append("ordered_operator_expected_value_must_be_number")
    elif kind == "workflow_transition":
        if not contract["field_name"]:
            errors.append("state_field_name_required")
        if not contract["conditions"].get("from_state"):
            errors.append("transition_from_state_required")
        if not contract["conditions"].get("to_state"):
            errors.append("transition_to_state_required")
        if (
            contract["conditions"].get("from_state")
            and contract["conditions"].get("from_state") == contract["conditions"].get("to_state")
        ):
            errors.append("transition_states_must_differ")
    elif kind == "ownership":
        if not contract["subject_role"]:
            errors.append("subject_role_required")
        if contract["expected_access"] != "deny":
            errors.append("ownership_cross_principal_expected_access_must_be_deny")
        if not (
            contract["conditions"].get("resource_owner") == "other"
            or contract["conditions"].get("tenant_relation") == "cross"
        ):
            errors.append("ownership_cross_principal_condition_required")
    return list(dict.fromkeys(errors))


def planner_projection(row: dict[str, Any]) -> dict[str, Any]:
    """Bounded planning view; explicitly denies direct proof/promotion authority."""
    contract = canonical_contract(row)
    # Keep operator prose available in the management API for review, but never place it in the
    # model's autonomous context. It is untyped, may contain prompt-like text, and was not part of
    # the structure the approval validator checked.
    contract.pop("source_text", None)
    contract.pop("title", None)
    return {
        "id": str(row.get("id") or "") or None,
        **contract,
        "status": str(row.get("status") or "draft"),
        "source": str(row.get("source") or "manual")[:80],
        "approved_at": row.get("approved_at"),
        "approved_by": str(row.get("approved_by") or "")[:120] or None,
        "planning_authority": str(row.get("status") or "") == "approved",
        "promotion_authority": False,
        "verification_required": True,
        "verification_plan": verification_plan(row),
    }
