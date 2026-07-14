"""Principal-bound bounded HTTP/browser workflows for adaptive research."""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any, Awaitable, Callable
from urllib.parse import urljoin

import httpx

from http_experiment import (
    ALLOWED_METHODS,
    FORBIDDEN_HEADERS,
    MAX_BODY_BYTES,
    ExperimentContractError,
    _bounded_json_size,
    _contains_control_character,
    _json_path_get,
    _mapping_contains_control_character,
    _origin,
    _render_variables,
    _sensitive_name,
    _sensitive_object_key,
    _variable_references,
    compare_summaries,
    response_summary,
)


WORKFLOW_VERSION = "principal-workflow-2026-07-12.v1"
MAX_WORKFLOW_STEPS = 12
MAX_WORKFLOW_VARIABLES = 40
MAX_WORKFLOW_SECONDS = 180
MAX_WORKFLOW_ASSERTIONS = 16
ALLOWED_STEP_KINDS = {"http", "browser"}
ALLOWED_CHECKPOINTS = {"before", "mutation", "after", "action", "cleanup", "rollback"}
ALLOWED_BROWSER_ACTIONS = {"navigate", "click", "fill", "submit", "wait", "extract"}
PRINCIPAL_SLOT_PATTERN = re.compile(r"^(anonymous|user1|user2|admin|tenant:[A-Za-z0-9_.-]{1,80})$")
ASSERTION_TYPES = {
    "status_in", "status_not_in", "comparison_changed", "comparison_equivalent",
    "distinct_principals", "restored",
}
PREDICATE_ASSERTION_TYPES = {
    "distinct_identity": {"distinct_principals"},
    "ownership_established": {"status_in", "comparison_equivalent"},
    "cross_principal_access": {"status_in", "comparison_equivalent"},
    "denial_control": {"status_not_in", "comparison_changed"},
    "cross_principal_denied": {"status_not_in"},
    "same_account": {"distinct_principals"},
    "forbidden_field_accepted": {"status_in"},
    "observable_state_change": {"comparison_changed"},
    "control_rejected": {"status_not_in"},
    "forbidden_field_rejected": {"status_not_in"},
    "payload_control_differential": {"comparison_changed"},
    "deterministic_family_proof": {"comparison_changed", "status_in"},
    "control_equivalent": {"comparison_equivalent"},
    "protected_resource_accessed": {"status_in"},
    "unauthenticated_control": {"status_not_in", "comparison_changed"},
    "access_denied_unauthenticated": {"status_not_in"},
    "transition_invariant_broken": {"comparison_changed"},
    "before_after_state": {"comparison_changed", "restored"},
    "invariant_held": {"comparison_equivalent"},
    "sensitive_value_present": {"comparison_changed", "status_in"},
    "name_only_classification": {"comparison_equivalent"},
}

# These fields carry an authorization/security meaning independent of planner prose.  Ordinary
# application fields must never become "forbidden" merely because a model labels them that way.
SECURITY_SENSITIVE_MUTATION_FIELDS = frozenset({
    "admin", "is_admin", "isadmin", "role", "roles", "permission", "permissions",
    "tenant", "tenant_id", "tenantid", "owner", "owner_id", "ownerid", "user_id",
    "userid", "account_id", "accountid", "verified", "is_verified", "isverified",
    "balance", "credit", "price", "total", "status",
})


def _normalize_assertions(raw: Any, labels: set[str]) -> list[dict[str, Any]]:
    items = raw if isinstance(raw, list) else []
    if len(items) > MAX_WORKFLOW_ASSERTIONS:
        raise WorkflowContractError("workflow_assertion_limit_exceeded")
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise WorkflowContractError(f"assertion_{index}_must_be_object")
        assertion_type = str(item.get("type") or "").strip().lower()
        if assertion_type not in ASSERTION_TYPES:
            raise WorkflowContractError(f"assertion_{index}_type_not_allowed")
        step = str(item.get("step") or "").strip()
        control = str(item.get("control") or "").strip()
        candidate = str(item.get("candidate") or "").strip()
        steps = [str(value).strip() for value in (item.get("steps") or []) if str(value).strip()]
        referenced = {value for value in (step, control, candidate, *steps) if value}
        if not referenced or not referenced.issubset(labels):
            raise WorkflowContractError(f"assertion_{index}_references_unknown_step")
        values: list[int] = []
        if assertion_type in {"status_in", "status_not_in"}:
            if not step:
                raise WorkflowContractError(f"assertion_{index}_step_required")
            try:
                values = sorted({int(value) for value in item.get("values") or []})
            except (TypeError, ValueError) as exc:
                raise WorkflowContractError(f"assertion_{index}_status_values_invalid") from exc
            if not values or any(value < 100 or value > 599 for value in values):
                raise WorkflowContractError(f"assertion_{index}_status_values_invalid")
        elif assertion_type in {"comparison_changed", "comparison_equivalent", "restored"}:
            if not control or not candidate or control == candidate:
                raise WorkflowContractError(f"assertion_{index}_comparison_steps_required")
        elif assertion_type == "distinct_principals" and len(set(steps)) < 2:
            raise WorkflowContractError(f"assertion_{index}_distinct_steps_required")
        predicate = str(item.get("predicate") or "").strip().lower()[:80] or None
        if predicate and assertion_type not in PREDICATE_ASSERTION_TYPES.get(predicate, set()):
            raise WorkflowContractError(f"assertion_{index}_predicate_type_mismatch")
        normalized.append({
            "id": str(item.get("id") or f"assertion_{index + 1}").strip()[:80],
            "type": assertion_type,
            "step": step or None,
            "control": control or None,
            "candidate": candidate or None,
            "steps": steps,
            "values": values,
            "predicate": predicate,
        })
    return normalized


def evaluate_assertions(workflow: dict[str, Any], observations: list[dict[str, Any]], comparisons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_label = {str(item.get("label") or ""): item for item in observations}
    by_pair = {(str(item.get("control") or ""), str(item.get("candidate") or "")): item for item in comparisons}
    results: list[dict[str, Any]] = []
    for assertion in workflow.get("assertions") or []:
        assertion_type = assertion["type"]
        passed = False
        observed: dict[str, Any] = {}
        if assertion_type in {"status_in", "status_not_in"}:
            observation = by_label.get(str(assertion.get("step") or ""), {})
            response = observation.get("response") if isinstance(observation.get("response"), dict) else {}
            status = response.get("status")
            passed = not observation.get("error") and isinstance(status, int) and (
                status in assertion["values"] if assertion_type == "status_in" else status not in assertion["values"]
            )
            observed = {"status": status, "error": observation.get("error")}
        elif assertion_type in {"comparison_changed", "comparison_equivalent", "restored"}:
            comparison = by_pair.get((str(assertion.get("control") or ""), str(assertion.get("candidate") or "")), {})
            changed = any(bool(comparison.get(key)) for key in (
                "state_changed", "status_changed", "body_changed", "selected_json_changed", "selected_headers_changed"
            ))
            comparable = bool(comparison.get("comparable"))
            passed = comparable and (not changed if assertion_type in {"comparison_equivalent", "restored"} else changed)
            observed = {"comparable": comparable, "changed": changed}
        elif assertion_type == "distinct_principals":
            principals = [str(by_label.get(label, {}).get("principal") or "") for label in assertion["steps"]]
            passed = all(principals) and len(set(principals)) == len(principals)
            observed = {"distinct_count": len(set(principals)), "step_count": len(principals)}
        results.append({**assertion, "passed": passed, "observed": observed})
    return results


# --- Server-side sensitive-VALUE classifier (values, not field names) --------------------
# A data_exposure promotion must be grounded in an actual sensitive value the server observed
# in a live response, never in a model-supplied predicate label. Patterns are deliberately
# high-precision: a false positive would wrongly promote a finding, so the safe failure mode
# is a miss (fail closed), not a false "verified".
_SENSITIVE_VALUE_PATTERNS: tuple[tuple[str, "re.Pattern[str]"], ...] = (
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("stripe_key", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{24,}")),
)

_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, ch in enumerate(reversed(digits)):
        value = ord(ch) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _classify_sensitive_values(text: str) -> list[str]:
    """Return high-precision sensitive-value category labels found in a live response body.

    Returns only category labels (e.g. "jwt", "ssn"), never the raw values, so the signal is
    safe to persist on an observation.
    """
    if not text:
        return []
    sample = text[:MAX_BODY_BYTES]
    categories: set[str] = set()
    for label, pattern in _SENSITIVE_VALUE_PATTERNS:
        if pattern.search(sample):
            categories.add(label)
    for match in _CARD_CANDIDATE.finditer(sample):
        digits = re.sub(r"[ -]", "", match.group())
        if 13 <= len(digits) <= 19 and digits[0] in "3456" and _luhn_ok(digits):
            categories.add("credit_card")
            break
    return sorted(categories)


# --- Server-corroborated family predicates ----------------------------------------------
# A workflow's model declares assertions (mechanical checks) and CLAIMS a security predicate
# for each. The claim is never trusted: the security MEANING of every predicate is confirmed
# here from server-computed signals (real sensitive values, distinct authenticated principals,
# genuine access/denial differentials). Predicates the server cannot independently confirm are
# not granted (fail closed); injection is never workflow-proven and hands off to the
# deterministic SQLi/XSS/SSTI verifiers.
def _obs_status(obs: dict[str, Any]) -> int | None:
    response = obs.get("response") if isinstance(obs.get("response"), dict) else {}
    status = response.get("status")
    return status if isinstance(status, int) else None


def _obs_success(obs: dict[str, Any]) -> bool:
    status = _obs_status(obs)
    return status is not None and 200 <= status < 300 and not obs.get("error")


def _obs_authenticated(obs: dict[str, Any]) -> bool:
    return str(obs.get("principal") or "anonymous").strip().lower() != "anonymous"


def _comparison_changed(comparison: dict[str, Any]) -> bool:
    return any(bool(comparison.get(key)) for key in (
        "state_changed", "status_changed", "body_changed",
        "selected_json_changed", "selected_headers_changed",
    ))


def _request_signature(observation: dict[str, Any]) -> tuple[str, str] | None:
    request = observation.get("request") if isinstance(observation.get("request"), dict) else {}
    method = str(request.get("method") or "").upper()
    path = str(request.get("path") or "")
    return (method, path) if method and path else None


def _same_resource(left: dict[str, Any], right: dict[str, Any], *, same_method: bool = True) -> bool:
    left_signature = _request_signature(left)
    right_signature = _request_signature(right)
    if not left_signature or not right_signature:
        return False
    if same_method:
        return left_signature == right_signature
    return left_signature[1] == right_signature[1]


def _server_confirms_predicate(
    predicate: str,
    assertion: dict[str, Any],
    by_label: dict[str, dict[str, Any]],
    by_pair: dict[tuple[str, str], dict[str, Any]],
    principal_identities: dict[str, str],
) -> bool:
    step = by_label.get(str(assertion.get("step") or ""), {})
    control = by_label.get(str(assertion.get("control") or ""), {})
    candidate = by_label.get(str(assertion.get("candidate") or ""), {})
    comparison = by_pair.get((str(assertion.get("control") or ""), str(assertion.get("candidate") or "")), {})
    changed = _comparison_changed(comparison)
    equivalent = bool(comparison.get("comparable")) and not changed
    step_principals = [
        str(by_label.get(str(label), {}).get("principal") or "").strip().lower()
        for label in (assertion.get("steps") or [])
    ]
    step_principals = [p for p in step_principals if p]

    # Every predicate's SECURITY MEANING is derived here from real observation signals, never from
    # the model's label (the P0 guarantee). BOLA carries the strongest proof (owner-created object,
    # exact owner/attacker request equivalence, distinct verified identities, anonymous denial
    # control); the other families are corroborated from real server-classified values, live status,
    # and state differentials. Injection is never workflow-proven -> deterministic SQLi/XSS/SSTI.
    if predicate in {"ownership_established", "cross_principal_access"}:
        control_request = control.get("request") if isinstance(control.get("request"), dict) else {}
        candidate_request = candidate.get("request") if isinstance(candidate.get("request"), dict) else {}
        control_principal = str(control.get("principal") or "").lower()
        candidate_principal = str(candidate.get("principal") or "").lower()
        distinct = (
            _obs_authenticated(control) and _obs_authenticated(candidate)
            and control_principal != candidate_principal
            and principal_identities.get(control_principal)
            and principal_identities.get(candidate_principal)
            and principal_identities.get(control_principal) != principal_identities.get(candidate_principal)
        )
        same_request = (
            str(control_request.get("method") or "").upper()
            == str(candidate_request.get("method") or "").upper()
            and str(control_request.get("path") or "")
            == str(candidate_request.get("path") or "")
        )
        # Ownership needs provenance stronger than "an authenticated user could read it".  The
        # object identifier used by the owner read must come from a successful mutation performed by
        # that same principal in this workflow.  Anonymous denial only proves authentication, not
        # ownership, and therefore cannot replace this provenance check.
        referenced = set(control_request.get("variable_references") or [])
        owner_established = any(
            obs.get("checkpoint") == "mutation"
            and str(obs.get("principal") or "").lower() == control_principal
            and _obs_success(obs)
            and bool(referenced & set(obs.get("extracted_names") or []))
            for obs in by_label.values()
        )
        base = bool(distinct and same_request and equivalent and _obs_success(control) and _obs_success(candidate))
        return base and (owner_established if predicate == "ownership_established" else True)
    if predicate == "distinct_identity":
        identities = [principal_identities.get(slot) for slot in step_principals]
        return len(identities) >= 2 and all(identities) and len(set(identities)) == len(identities)
    if predicate == "same_account":  # refute
        identities = [principal_identities.get(slot) for slot in step_principals]
        return len(identities) >= 2 and all(identities) and len(set(identities)) < len(identities)
    if predicate == "cross_principal_denied":  # refute: the cross principal was actually denied
        return not _obs_success(candidate or step)
    if predicate == "denial_control":
        target = step or candidate
        target_request = target.get("request") if isinstance(target.get("request"), dict) else {}
        if str(target.get("principal") or "anonymous").lower() != "anonymous" or _obs_success(target):
            return False
        return any(
            _obs_success(obs)
            and str((obs.get("request") or {}).get("method") or "").upper()
            == str(target_request.get("method") or "").upper()
            and str((obs.get("request") or {}).get("path") or "")
            == str(target_request.get("path") or "")
            for obs in by_label.values()
            if isinstance(obs.get("request"), dict)
        )

    # --- data_exposure: an UNAUTHORIZED observer received a real sensitive VALUE. An anonymous
    # request returning a classified secret is exposure; a principal reading its OWN data (its own
    # JWT) is not, so the observer must be anonymous.
    if predicate == "sensitive_value_present":
        target = step or candidate
        categories = set(target.get("sensitive_value_categories") or [])
        return (
            str(target.get("principal") or "anonymous").lower() == "anonymous"
            and bool(categories - {"jwt", "bearer_token"})
        )
    if predicate == "name_only_classification":  # refute: sensitive-looking keys, no values
        target = step or candidate
        response = target.get("response") if isinstance(target.get("response"), dict) else {}
        keys = response.get("json_keys") or []
        return (not target.get("sensitive_value_categories")) and any(_sensitive_name(str(k)) for k in keys)

    # --- auth_bypass: an AUTHENTICATED principal reaches the resource (it is real + used behind auth)
    # AND an anonymous request SUCCEEDS returning actual sensitive DATA -> it reached protected
    # content, not a public route. A denied (non-2xx) anonymous request is not a bypass.
    if predicate == "protected_resource_accessed":
        return _obs_authenticated(step or candidate) and _obs_success(step or candidate)
    if predicate == "unauthenticated_control":
        target = step or candidate
        return (
            str(target.get("principal") or "anonymous").lower() == "anonymous"
            and _obs_success(target)
            and bool(target.get("sensitive_value_categories"))
        )
    if predicate == "access_denied_unauthenticated":  # refute
        target = step or candidate
        return str(target.get("principal") or "anonymous").lower() == "anonymous" and not _obs_success(target)

    # --- mass_assignment: a MUTATION submitted a body field AND the server echoed it back (accepted /
    # persisted it), with an observable state change and a rejected control.
    if predicate == "forbidden_field_accepted":
        target = step or candidate
        if str(target.get("checkpoint") or "") != "mutation" or not _obs_success(target):
            return False
        submitted = {str(name) for name in (target.get("submitted_fields") or [])}
        response = target.get("response") if isinstance(target.get("response"), dict) else {}
        echoed = {str(key) for key in (response.get("json_keys") or [])}
        forbidden = {name.lower() for name in submitted} & SECURITY_SENSITIVE_MUTATION_FIELDS
        return bool(forbidden) and bool(forbidden & {name.lower() for name in echoed})
    if predicate == "observable_state_change":
        return changed
    if predicate in {"control_rejected", "forbidden_field_rejected"}:  # rejected control / refute
        return not _obs_success(step or candidate)

    # --- workflow: a real state transition -- the change is between a BEFORE and an AFTER checkpoint
    # and the workflow contains a mutation (an action caused it), not two reads of a changing clock.
    if predicate in {"transition_invariant_broken", "before_after_state"}:
        # A state change is not itself an invariant violation.  Until a target policy supplies a
        # server-trusted transition invariant, workflow-family signals remain unverified.
        return False
    if predicate in {"invariant_held", "control_equivalent"}:  # refute
        return equivalent

    # injection ({payload_control_differential, deterministic_family_proof}) and anything else is
    # never workflow-proven -> hands off to the deterministic verifiers.
    return False


def _server_corroborated_evidence(
    result: dict[str, Any],
) -> tuple[set[str], dict[str, tuple[str, str]]]:
    """Server-confirmed family predicates for a single workflow execution.

    Reads only server-computed signals from the observations/comparisons; the model's
    predicate label selects which server check to run, and is never itself treated as proof.
    """
    observations = [o for o in (result.get("observations") or []) if isinstance(o, dict)]
    by_label = {str(o.get("label")): o for o in observations}
    by_pair = {
        (str(c.get("control")), str(c.get("candidate"))): c
        for c in (result.get("comparisons") or []) if isinstance(c, dict)
    }
    principal_identities = {
        str(item.get("slot") or "").strip().lower(): str(item.get("identity_fingerprint") or "")
        for item in (result.get("principal_receipts") or [])
        if isinstance(item, dict) and item.get("slot") and item.get("identity_fingerprint")
    }
    granted: set[str] = set()
    assertions_by_predicate: dict[str, list[dict[str, Any]]] = {}
    for assertion in result.get("assertion_results") or []:
        if not isinstance(assertion, dict) or assertion.get("passed") is not True:
            continue
        predicate = str(assertion.get("predicate") or "").strip().lower()
        if predicate and _server_confirms_predicate(
            predicate, assertion, by_label, by_pair, principal_identities
        ):
            granted.add(predicate)
            assertions_by_predicate.setdefault(predicate, []).append(assertion)

    # Family predicates must describe the same live security surface.  This prevents a successful
    # authenticated request on route A and an anonymous sample-token response on route B from being
    # combined into an auth-bypass proof.
    auth_protected = assertions_by_predicate.get("protected_resource_accessed") or []
    auth_anon = assertions_by_predicate.get("unauthenticated_control") or []
    if auth_protected and auth_anon:
        protected = by_label.get(str(auth_protected[0].get("step") or ""), {})
        anonymous = by_label.get(str(auth_anon[0].get("step") or ""), {})
        trusted_protected = {
            (str(item.get("method") or "").upper(), str(item.get("path") or ""))
            for item in (result.get("trusted_protected_routes") or []) if isinstance(item, dict)
        }
        if not _same_resource(protected, anonymous) or _request_signature(protected) not in trusted_protected:
            granted -= {"protected_resource_accessed", "unauthenticated_control"}

    mass_accept = assertions_by_predicate.get("forbidden_field_accepted") or []
    mass_change = assertions_by_predicate.get("observable_state_change") or []
    mass_control = assertions_by_predicate.get("control_rejected") or []
    if mass_accept and mass_change and mass_control:
        mutation = by_label.get(str(mass_accept[0].get("step") or ""), {})
        changed_assertion = mass_change[0]
        after = by_label.get(str(changed_assertion.get("candidate") or ""), {})
        rejected = by_label.get(str(mass_control[0].get("step") or ""), {})
        submitted = {str(name).lower() for name in mutation.get("submitted_fields") or []}
        response = after.get("response") if isinstance(after.get("response"), dict) else {}
        persisted = submitted & {str(name).lower() for name in response.get("json_keys") or []}
        if not (
            after.get("checkpoint") == "after"
            and _same_resource(mutation, after, same_method=False)
            and _same_resource(mutation, rejected)
            and bool(persisted & SECURITY_SENSITIVE_MUTATION_FIELDS)
        ):
            granted -= {"forbidden_field_accepted", "observable_state_change", "control_rejected"}

    bindings: dict[str, tuple[str, str]] = {}
    for predicate in granted:
        assertions = assertions_by_predicate.get(predicate) or []
        if not assertions:
            continue
        assertion = assertions[0]
        observation = by_label.get(str(
            assertion.get("step") or assertion.get("candidate") or assertion.get("control") or ""
        ), {})
        signature = _request_signature(observation)
        if signature:
            bindings[predicate] = signature
    return granted, bindings


def server_corroborated_predicates(result: dict[str, Any]) -> set[str]:
    """Return security predicates corroborated by server-derived, route-bound evidence."""
    return _server_corroborated_evidence(result)[0]


def server_corroborated_predicate_bindings(result: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """Return the live method/path bound to every corroborated predicate."""
    return _server_corroborated_evidence(result)[1]


class WorkflowContractError(ExperimentContractError):
    pass


def _normalize_extracts(index: int, raw: Any, *, browser: bool) -> list[dict[str, str]]:
    items = raw if isinstance(raw, list) else []
    if len(items) > 8:
        raise WorkflowContractError(f"step_{index}_too_many_extracts")
    result: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            raise WorkflowContractError(f"step_{index}_extract_must_be_object")
        name = str(item.get("name") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) or _sensitive_name(name):
            raise WorkflowContractError(f"step_{index}_extract_name_invalid")
        if browser:
            selector = str(item.get("selector") or "").strip()
            attribute = str(item.get("attribute") or "text").strip()
            if not selector or len(selector) > 500 or len(attribute) > 120:
                raise WorkflowContractError(f"step_{index}_browser_extract_invalid")
            result.append({"name": name, "source": "browser", "selector": selector, "attribute": attribute})
            continue
        source = str(item.get("source") or "json").strip().lower()
        selector = str(item.get("path") if source == "json" else item.get("header") or "").strip()
        if source not in {"json", "header"}:
            raise WorkflowContractError(f"step_{index}_extract_source_not_allowed")
        if source == "json" and (not selector.startswith("$.") or _sensitive_name(selector)):
            raise WorkflowContractError(f"step_{index}_extract_json_path_invalid")
        if source == "header" and (
            not selector or selector.lower() in {"set-cookie", *FORBIDDEN_HEADERS} or _sensitive_name(selector)
        ):
            raise WorkflowContractError(f"step_{index}_extract_header_forbidden")
        result.append({"name": name, "source": source, "selector": selector})
    return result


def _normalize_mapping(index: int, field: str, raw: Any, *, max_items: int) -> dict[str, Any]:
    value = raw if isinstance(raw, dict) else {}
    result: dict[str, Any] = {}
    for key, item in list(value.items())[:max_items]:
        name = str(key).strip()
        if not name or len(name) > 120 or name in result or _sensitive_name(name):
            raise WorkflowContractError(f"step_{index}_{field}_key_forbidden")
        if _contains_control_character(name):
            raise WorkflowContractError(f"step_{index}_{field}_contains_control_character")
        values = item if isinstance(item, list) else [item]
        if not values or any(nested is None or isinstance(nested, (dict, list)) for nested in values):
            raise WorkflowContractError(f"step_{index}_{field}_value_must_be_scalar")
        normalized_values = [str(nested)[:1000] for nested in values]
        if any(_contains_control_character(nested) for nested in normalized_values):
            raise WorkflowContractError(f"step_{index}_{field}_contains_control_character")
        result[name] = normalized_values if isinstance(item, list) else normalized_values[0]
    return result


def normalize_workflow(target_url: str, raw: Any) -> dict[str, Any]:
    payload = raw if isinstance(raw, dict) else {}
    steps = payload.get("steps") if isinstance(payload.get("steps"), list) else []
    if not 2 <= len(steps) <= MAX_WORKFLOW_STEPS:
        raise WorkflowContractError("workflow_requires_2_to_12_steps")
    target_origin = _origin(target_url)
    labels: set[str] = set()
    declared: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(steps):
        if not isinstance(item, dict):
            raise WorkflowContractError(f"step_{index}_must_be_object")
        label = str(item.get("label") or f"step_{index + 1}").strip()[:80]
        if not label or label in labels:
            raise WorkflowContractError("step_labels_must_be_unique")
        labels.add(label)
        kind = str(item.get("kind") or "http").strip().lower()
        if kind not in ALLOWED_STEP_KINDS:
            raise WorkflowContractError(f"step_{index}_kind_not_allowed")
        principal = str(item.get("principal") or "anonymous").strip().lower()
        if not PRINCIPAL_SLOT_PATTERN.fullmatch(principal):
            raise WorkflowContractError(f"step_{index}_principal_slot_invalid")
        checkpoint = str(item.get("checkpoint") or "action").strip().lower()
        if checkpoint not in ALLOWED_CHECKPOINTS:
            raise WorkflowContractError(f"step_{index}_checkpoint_invalid")
        compare_to = str(item.get("compare_to") or "").strip()
        if compare_to and compare_to not in labels:
            raise WorkflowContractError(f"step_{index}_compare_to_must_reference_prior_step")

        normalized_step: dict[str, Any] = {
            "label": label,
            "kind": kind,
            "principal": principal,
            "checkpoint": checkpoint,
            "compare_to": compare_to,
        }
        reference_values: list[Any] = []
        if kind == "http":
            method = str(item.get("method") or "GET").strip().upper()
            path = str(item.get("path") or "").strip()
            if method not in ALLOWED_METHODS:
                raise WorkflowContractError(f"step_{index}_method_not_allowed")
            if not path.startswith("/") or path.startswith("//") or len(path.encode()) > 2000:
                raise WorkflowContractError(f"step_{index}_path_must_be_relative")
            if _contains_control_character(path):
                raise WorkflowContractError(f"step_{index}_path_contains_control_character")
            rendered_url = urljoin(target_url, path)
            if _origin(rendered_url) != target_origin:
                raise WorkflowContractError(f"step_{index}_resolved_outside_target_origin")
            query = _normalize_mapping(index, "query", item.get("query"), max_items=30)
            headers = _normalize_mapping(index, "headers", item.get("headers"), max_items=20)
            for header in headers:
                if header.lower() in FORBIDDEN_HEADERS:
                    raise WorkflowContractError(f"step_{index}_header_forbidden")
            json_body = item.get("json_body")
            form_body = _normalize_mapping(index, "form_body", item.get("form_body"), max_items=50) if isinstance(item.get("form_body"), dict) else None
            if json_body is not None and form_body is not None:
                raise WorkflowContractError(f"step_{index}_multiple_body_types")
            if _sensitive_object_key(json_body):
                raise WorkflowContractError(f"step_{index}_json_body_sensitive_key_forbidden")
            _bounded_json_size(query)
            _bounded_json_size(json_body)
            _bounded_json_size(form_body)
            extracts = _normalize_extracts(index, item.get("extract"), browser=False)
            normalized_step.update({
                "method": method,
                "path": path,
                "query": query,
                "headers": headers,
                "json_body": json_body,
                "form_body": form_body,
                "extract": extracts,
            })
            reference_values.extend([path, query, headers, json_body, form_body])
        else:
            action = str(item.get("action") or "").strip().lower()
            if action not in ALLOWED_BROWSER_ACTIONS:
                raise WorkflowContractError(f"step_{index}_browser_action_not_allowed")
            data = item.get("data") if isinstance(item.get("data"), dict) else {}
            allowed_data = {
                "navigate": {"path"},
                "click": {"selector"},
                "fill": {"selector", "value"},
                "submit": {"selector"},
                "wait": {"selector", "timeout"},
                "extract": {"selector", "attribute"},
            }[action]
            unknown_data = sorted(set(data) - allowed_data)
            if unknown_data:
                raise WorkflowContractError(f"step_{index}_browser_data_field_not_allowed:{unknown_data[0]}")
            if _sensitive_object_key(data):
                raise WorkflowContractError(f"step_{index}_browser_sensitive_field_forbidden")
            if action == "navigate":
                path = str(data.get("path") or "").strip()
                if not path.startswith("/") or path.startswith("//") or _origin(urljoin(target_url, path)) != target_origin:
                    raise WorkflowContractError(f"step_{index}_browser_path_must_be_relative")
                if _contains_control_character(path):
                    raise WorkflowContractError(f"step_{index}_browser_path_contains_control_character")
            if action in {"click", "fill", "submit", "wait", "extract"}:
                selector = str(data.get("selector") or "").strip()
                if not selector or len(selector) > 500:
                    raise WorkflowContractError(f"step_{index}_browser_selector_required")
                if action == "fill" and _sensitive_name(selector):
                    raise WorkflowContractError(f"step_{index}_browser_sensitive_fill_forbidden")
            if action == "wait":
                try:
                    wait_timeout = int(data.get("timeout") or 5000)
                except (TypeError, ValueError) as exc:
                    raise WorkflowContractError(f"step_{index}_browser_wait_timeout_invalid") from exc
                if not 0 <= wait_timeout <= 10_000:
                    raise WorkflowContractError(f"step_{index}_browser_wait_timeout_invalid")
                data = {**data, "timeout": wait_timeout}
            _bounded_json_size(data, limit=4096)
            extracts = _normalize_extracts(index, item.get("extract"), browser=True)
            if action == "extract" and len(extracts) != 1:
                raise WorkflowContractError(f"step_{index}_browser_extract_requires_one_variable")
            if action != "extract" and extracts:
                raise WorkflowContractError(f"step_{index}_browser_extract_only_allowed_for_extract_action")
            normalized_step.update({"action": action, "data": data, "extract": extracts})
            reference_values.append(data)

        extract_names = [spec["name"] for spec in extracts]
        if len(extract_names) != len(set(extract_names)) or any(name in declared for name in extract_names):
            raise WorkflowContractError(f"step_{index}_extract_name_ambiguous")
        if len(declared) + len(extract_names) > MAX_WORKFLOW_VARIABLES:
            raise WorkflowContractError("workflow_variable_limit_exceeded")
        references = set().union(*(_variable_references(value) for value in reference_values)) if reference_values else set()
        missing = sorted(references - declared)
        if missing:
            raise WorkflowContractError(f"step_{index}_variable_not_declared:{missing[0]}")
        declared.update(extract_names)
        normalized.append(normalized_step)

    assertions = _normalize_assertions(payload.get("assertions"), labels)
    steps_by_label = {step["label"]: step for step in normalized}
    for index, assertion in enumerate(assertions):
        if assertion["type"] in {"comparison_changed", "comparison_equivalent", "restored"}:
            candidate_step = steps_by_label.get(str(assertion.get("candidate") or ""), {})
            if candidate_step.get("compare_to") != assertion.get("control"):
                raise WorkflowContractError(f"assertion_{index}_must_match_candidate_compare_to")
    write_steps = [
        step for step in normalized
        if step.get("kind") == "http" and step.get("method") in {"POST", "PUT", "PATCH", "DELETE"}
        and step.get("checkpoint") not in {"cleanup", "rollback"}
    ]
    mutation_steps = [
        step for step in normalized
        if step.get("checkpoint") == "mutation" and (
            (step.get("kind") == "http" and step.get("method") in {"POST", "PUT", "PATCH", "DELETE"})
            or (step.get("kind") == "browser" and step.get("action") in {"click", "fill", "submit"})
        )
    ]
    restoration_steps = [step for step in normalized if step.get("checkpoint") in {"cleanup", "rollback"}]
    restoration_assertions = [item for item in assertions if item.get("type") == "restored"]
    for step in write_steps:
        if step.get("checkpoint") != "mutation":
            raise WorkflowContractError("state_changing_request_requires_mutation_checkpoint")
    mutating_steps = list({id(step): step for step in [*write_steps, *mutation_steps]}.values())
    if mutating_steps:
        if not restoration_steps:
            raise WorkflowContractError("mutating_workflow_requires_cleanup_or_rollback_step")
        if not restoration_assertions:
            raise WorkflowContractError("mutating_workflow_requires_restoration_assertion")
        last_mutation = max(normalized.index(step) for step in mutating_steps)
        if any(normalized.index(step) <= last_mutation for step in restoration_steps):
            raise WorkflowContractError("cleanup_or_rollback_must_follow_mutation")
        last_cleanup = max(normalized.index(step) for step in restoration_steps)
        for index, assertion in enumerate(restoration_assertions):
            control_step = steps_by_label.get(str(assertion.get("control") or ""), {})
            candidate_step = steps_by_label.get(str(assertion.get("candidate") or ""), {})
            if (
                control_step.get("checkpoint") != "before"
                or candidate_step.get("checkpoint") != "after"
                or normalized.index(control_step) >= min(normalized.index(step) for step in mutating_steps)
                or normalized.index(candidate_step) <= last_cleanup
            ):
                raise WorkflowContractError(f"assertion_{index}_restoration_order_invalid")
    # DELETE is destructive and cannot be reliably restored, so it is permitted ONLY as cleanup of an
    # object THIS workflow created: it must sit at a cleanup/rollback checkpoint and target a variable
    # extracted from a mutation (create) step. That keeps the BOLA create->cleanup pattern working
    # while forbidding deletion of pre-existing/arbitrary resources.
    created_variables = {
        spec["name"]
        for step in normalized if step.get("checkpoint") == "mutation"
        for spec in (step.get("extract") or [])
    }
    for step in normalized:
        if step.get("kind") == "http" and step.get("method") == "DELETE":
            if step.get("checkpoint") not in {"cleanup", "rollback"}:
                raise WorkflowContractError("delete_only_allowed_as_cleanup_of_created_object")
            if not (_variable_references(step.get("path") or "") & created_variables):
                raise WorkflowContractError("delete_must_target_a_workflow_created_object")
    timeout_seconds = max(1, min(int(payload.get("timeout_seconds") or 30), MAX_WORKFLOW_SECONDS))
    return {
        "version": WORKFLOW_VERSION,
        "objective": str(payload.get("objective") or "").strip()[:1000],
        "expected_signal": str(payload.get("expected_signal") or "").strip()[:1000],
        "falsifier": str(payload.get("falsifier") or "").strip()[:1000],
        "target_url": target_url,
        "timeout_seconds": timeout_seconds,
        "steps": normalized,
        "proof_family": str(payload.get("proof_family") or "workflow").strip().lower()[:80],
        "assertions": assertions,
        "mutating": bool(mutating_steps),
    }


def validate_principal_contexts(contexts: dict[str, dict[str, Any]], used_slots: set[str]) -> list[dict[str, Any]]:
    nonanonymous = sorted(slot for slot in used_slots if slot != "anonymous")
    receipts: list[dict[str, Any]] = []
    profile_ids: dict[str, str] = {}
    identities: dict[str, str] = {}
    for slot in nonanonymous:
        context = contexts.get(slot)
        if not context:
            raise WorkflowContractError(f"principal_context_missing:{slot}")
        profile_id = str(context.get("profile_id") or "").strip()
        identity = str(context.get("identity_fingerprint") or "").strip()
        if not profile_id:
            raise WorkflowContractError(f"principal_profile_missing:{slot}")
        if len(nonanonymous) > 1 and not identity:
            raise WorkflowContractError(f"principal_identity_unverified:{slot}")
        if profile_id in profile_ids:
            raise WorkflowContractError(f"principal_profiles_not_distinct:{profile_ids[profile_id]}:{slot}")
        if identity and identity in identities:
            raise WorkflowContractError(f"principal_accounts_not_distinct:{identities[identity]}:{slot}")
        profile_ids[profile_id] = slot
        if identity:
            identities[identity] = slot
        receipts.append({
            "slot": slot,
            "principal_id": context.get("principal_id"),
            "profile_id": profile_id,
            "identity_fingerprint": identity or None,
            "role": context.get("role"),
            "tenant_id": context.get("tenant_id"),
            "identity_verified": bool(identity),
        })
    return receipts


BrowserAction = Callable[[str, str, dict[str, Any]], Awaitable[dict[str, Any]]]
CancelCheck = Callable[[], bool]


def _restoration_verified(
    workflow: dict[str, Any],
    observations: list[dict[str, Any]],
    assertion_results: list[dict[str, Any]],
) -> bool:
    """A mutating workflow is restored only if every cleanup/rollback step actually SUCCEEDED (2xx --
    an HTTP 4xx/5xx cleanup is a FAILED restore, not merely "no error"), AND a `restored` assertion
    passed comparing a post-mutation AFTER state to the pre-mutation BEFORE state (not two
    pre-mutation reads). Otherwise the target may remain modified while claiming restoration.
    """
    if not workflow.get("mutating"):
        return True
    by_label = {str(o.get("label")): o for o in observations if isinstance(o, dict)}
    observation_index = {
        str(observation.get("label")): index for index, observation in enumerate(observations)
        if isinstance(observation, dict)
    }
    cleanup = [o for o in observations if isinstance(o, dict) and o.get("checkpoint") in {"cleanup", "rollback"}]
    if not cleanup or not all(_obs_success(o) for o in cleanup):
        return False
    restored = [a for a in assertion_results if isinstance(a, dict) and a.get("type") == "restored"]
    if not restored or not all(a.get("passed") for a in restored):
        return False
    for assertion in restored:
        control = by_label.get(str(assertion.get("control") or ""), {})
        candidate = by_label.get(str(assertion.get("candidate") or ""), {})
        if control.get("checkpoint") != "before" or candidate.get("checkpoint") != "after":
            return False
        control_index = observation_index.get(str(assertion.get("control") or ""), -1)
        candidate_index = observation_index.get(str(assertion.get("candidate") or ""), -1)
        cleanup_indexes = [
            observation_index.get(str(item.get("label") or ""), -1) for item in cleanup
        ]
        mutation_indexes = [
            observation_index.get(str(item.get("label") or ""), -1)
            for item in observations if isinstance(item, dict) and item.get("checkpoint") == "mutation"
        ]
        if (
            control_index < 0 or candidate_index < 0 or not mutation_indexes
            or control_index >= min(mutation_indexes)
            or candidate_index <= max([*mutation_indexes, *cleanup_indexes])
        ):
            return False
    return True


async def execute_workflow(
    target_url: str,
    raw: Any,
    *,
    principal_contexts: dict[str, dict[str, Any]],
    browser_action: BrowserAction | None = None,
    cancelled: CancelCheck | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    workflow = normalize_workflow(target_url, raw)
    used_slots = {step["principal"] for step in workflow["steps"]}
    receipts = validate_principal_contexts(principal_contexts, used_slots)
    variables: dict[str, str] = {}
    observations: list[dict[str, Any]] = []
    request_count = 0
    mutation_succeeded = False
    started = time.monotonic()
    timeout = httpx.Timeout(min(workflow["timeout_seconds"], 15))
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False, transport=transport) as client:
        for step in workflow["steps"]:
            interrupted = (cancelled and cancelled()) or time.monotonic() - started > workflow["timeout_seconds"]
            if interrupted and not (
                mutation_succeeded and step.get("checkpoint") in {"cleanup", "rollback"}
            ):
                observations.append({"label": step["label"], "kind": step["kind"], "checkpoint": step.get("checkpoint"), "error": "workflow_cancelled_or_timed_out"})
                if mutation_succeeded:
                    continue
                break
            extracted: dict[str, str] = {}
            sensitive_value_categories: list[str] = []
            submitted_fields: list[str] = []
            response: dict[str, Any] | None = None
            request_view: dict[str, Any] = {"kind": step["kind"], "principal": step["principal"]}
            error: str | None = None
            try:
                if step["kind"] == "http":
                    variable_references = sorted(set().union(*(
                        _variable_references(value)
                        for value in (
                            step["path"], step["query"], step["headers"],
                            step["json_body"], step["form_body"],
                        )
                    )))
                    path = _render_variables(step["path"], variables)
                    url = urljoin(target_url, path)
                    if not str(path).startswith("/") or str(path).startswith("//") or _origin(url) != _origin(target_url):
                        raise WorkflowContractError("rendered_path_outside_target_origin")
                    query = _render_variables(step["query"], variables)
                    headers = _render_variables(step["headers"], variables)
                    json_body = _render_variables(step["json_body"], variables)
                    form_body = _render_variables(step["form_body"], variables)
                    submitted_fields = sorted(
                        json_body.keys() if isinstance(json_body, dict)
                        else form_body.keys() if isinstance(form_body, dict) else []
                    )
                    if len(str(path).encode()) > 4000:
                        raise WorkflowContractError("rendered_path_exceeds_size_limit")
                    if _contains_control_character(path):
                        raise WorkflowContractError("rendered_path_contains_control_character")
                    _bounded_json_size(query)
                    _bounded_json_size(json_body)
                    _bounded_json_size(form_body)
                    if any(
                        not str(name).strip()
                        or str(name).strip().lower() in FORBIDDEN_HEADERS
                        or _sensitive_name(name)
                        or _contains_control_character(name)
                        or _contains_control_character(value)
                        or not str(name).isascii()
                        or not str(value).isascii()
                        for name, value in headers.items()
                    ):
                        raise WorkflowContractError("rendered_header_forbidden")
                    if any(_sensitive_object_key(value) for value in (query, json_body, form_body)):
                        raise WorkflowContractError("rendered_sensitive_key_forbidden")
                    if _mapping_contains_control_character(query):
                        raise WorkflowContractError("rendered_query_contains_control_character")
                    context = principal_contexts.get(step["principal"], {})
                    auth_headers = context.get("headers") if isinstance(context.get("headers"), dict) else {}
                    cookies = context.get("cookies") if isinstance(context.get("cookies"), dict) else {}
                    headers = {**headers, **auth_headers}
                    request_view.update({
                        "method": step["method"], "path": path,
                        "query_keys": sorted(query),
                        "body_kind": "json" if json_body is not None else "form" if form_body is not None else None,
                        "variable_references": variable_references,
                    })
                    request = client.build_request(step["method"], url, params=query, headers=headers, cookies=cookies, json=json_body, data=form_body)
                    request_count += 1
                    request_started = time.perf_counter()
                    http_response = await client.send(request, stream=True)
                    chunks: list[bytes] = []
                    received = 0
                    try:
                        async for chunk in http_response.aiter_bytes():
                            remaining = MAX_BODY_BYTES + 1 - received
                            if remaining <= 0:
                                break
                            chunks.append(chunk[:remaining])
                            received += min(len(chunk), remaining)
                            if received > MAX_BODY_BYTES:
                                break
                    finally:
                        await http_response.aclose()
                    body = b"".join(chunks)
                    response = response_summary(http_response, body, elapsed_ms=round((time.perf_counter() - request_started) * 1000))
                    body_text = body[:MAX_BODY_BYTES].decode(http_response.encoding or "utf-8", errors="replace")
                    sensitive_value_categories = _classify_sensitive_values(body_text)
                    parsed: Any = None
                    try:
                        parsed = json.loads(body_text)
                    except (TypeError, ValueError):
                        pass
                    for spec in step["extract"]:
                        value = _json_path_get(parsed, spec["selector"]) if spec["source"] == "json" else http_response.headers.get(spec["selector"])
                        if value is None:
                            raise WorkflowContractError(f"extract_value_missing:{spec['name']}")
                        rendered_value = str(value)[:1000]
                        if _contains_control_character(rendered_value):
                            raise WorkflowContractError(f"extract_value_contains_control_character:{spec['name']}")
                        extracted[spec["name"]] = rendered_value
                else:
                    if not browser_action:
                        raise WorkflowContractError("browser_runtime_unavailable")
                    data = _render_variables(step["data"], variables)
                    _bounded_json_size(data, limit=4096)
                    if _sensitive_object_key(data):
                        raise WorkflowContractError("rendered_browser_sensitive_field_forbidden")
                    if step["action"] == "navigate":
                        path = str(data.get("path") or "")
                        if not path.startswith("/") or path.startswith("//") or _origin(urljoin(target_url, path)) != _origin(target_url):
                            raise WorkflowContractError("rendered_browser_path_outside_target_origin")
                    if step["action"] == "fill" and _sensitive_name(data.get("selector")):
                        raise WorkflowContractError("rendered_browser_sensitive_fill_forbidden")
                    result = await browser_action(step["principal"], step["action"], data)
                    response = {"success": bool(result.get("success")), "url": result.get("url"), "value_present": result.get("value") is not None}
                    request_view.update({"action": step["action"], "selector": data.get("selector")})
                    if not result.get("success"):
                        raise WorkflowContractError(str(result.get("error") or "browser_action_failed"))
                    for spec in step["extract"]:
                        value = result.get("value")
                        if value is None or isinstance(value, (dict, list)):
                            raise WorkflowContractError(f"extract_value_missing:{spec['name']}")
                        rendered_value = str(value)[:1000]
                        if _contains_control_character(rendered_value):
                            raise WorkflowContractError(f"extract_value_contains_control_character:{spec['name']}")
                        extracted[spec["name"]] = rendered_value
                variables.update(extracted)
            except (httpx.InvalidURL, httpx.HTTPError, WorkflowContractError, UnicodeError, ValueError) as exc:
                error = str(exc) if isinstance(exc, WorkflowContractError) else type(exc).__name__
            observations.append({
                "label": step["label"], "kind": step["kind"], "principal": step["principal"],
                "checkpoint": step["checkpoint"], "compare_to": step["compare_to"],
                "request": request_view, "response": response,
                "sensitive_value_categories": sensitive_value_categories if not error else [],
                "submitted_fields": submitted_fields if not error else [],
                "extracted_names": sorted(extracted) if not error else [],
                "extracted": {name: {"sha256": hashlib.sha256(value.encode()).hexdigest(), "length": len(value)} for name, value in extracted.items()} if not error else {},
                "error": error,
            })
            # A server may commit a mutation before returning an error status, so once a mutation
            # request completed without a transport/contract error we must still attempt cleanup.
            if step.get("checkpoint") == "mutation" and not error:
                mutation_succeeded = True
    by_label = {item["label"]: item for item in observations}
    comparisons: list[dict[str, Any]] = []
    for item in observations:
        if not item.get("compare_to"):
            continue
        control = by_label.get(item["compare_to"], {})
        if item.get("kind") == "http" and control.get("kind") == "http":
            comparison = compare_summaries({} if control.get("error") else control.get("response") or {}, {} if item.get("error") else item.get("response") or {})
        else:
            comparison = {"comparable": not control.get("error") and not item.get("error"), "state_changed": control.get("response") != item.get("response")}
        comparisons.append({"control": item["compare_to"], "candidate": item["label"], **comparison})
    assertion_results = evaluate_assertions(workflow, observations, comparisons)
    restoration_results = [item for item in assertion_results if item.get("type") == "restored"]
    cleanup_observations = [item for item in observations if item.get("checkpoint") in {"cleanup", "rollback"}]
    return {
        "version": WORKFLOW_VERSION,
        "objective": workflow["objective"],
        "expected_signal": workflow["expected_signal"],
        "falsifier": workflow["falsifier"],
        "request_count": request_count,
        "step_count": len(observations),
        "principal_receipts": receipts,
        "variable_names": sorted(variables),
        "observations": observations,
        "comparisons": comparisons,
        "proof_family": workflow["proof_family"],
        "assertion_results": assertion_results,
        "assertions_passed": bool(assertion_results) and all(item.get("passed") for item in assertion_results),
        "restoration_verified": _restoration_verified(workflow, observations, assertion_results),
        "mutating": workflow["mutating"],
        "cancelled": any(item.get("error") == "workflow_cancelled_or_timed_out" for item in observations),
        "finding_created": False,
        "proof_state": "unverified_workflow_signal",
    }
