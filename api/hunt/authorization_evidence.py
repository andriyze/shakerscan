"""Bind authorization outcomes to canonical actions and the selected request.

These functions interpret server-owned records. They are not proof validators and
must never be called with planner-supplied result/receipt data.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid


class AuthorizationWorkflowError(ValueError):
    def __init__(self, message: str, status_code: int = 409) -> None:
        super().__init__(message)
        self.status_code = status_code


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return dict(value) if isinstance(value, Mapping) else {}


def canonical_action_id(hunt_id: Any, idempotency_key: str) -> uuid.UUID:
    # This is the existing execute_hunt_capability idempotency contract, not a
    # new execution identity. A crash before saving a response remains recoverable.
    return uuid.uuid5(uuid.UUID(str(hunt_id)), f"hunt-capability:{idempotency_key}")


def request_identity(row: Mapping[str, Any]) -> str:
    return digest({"method": row["method"], "url": row["url"],
                   "request_body_bytes": row["request_body_bytes"]})


def _origin(url: str) -> tuple[str, str | None, int]:
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("invalid origin")
    return parts.scheme.lower(), parts.hostname.lower(), parts.port or (443 if parts.scheme.lower() == "https" else 80)


def supported_capture(row: Mapping[str, Any], origins: list[str]) -> str:
    """Validate, never repair, a captured request. Returns its exact path."""
    url = row.get("url")
    if (str(row.get("method") or "").upper() != "GET"
            or row.get("request_body_bytes") != 0):
        raise AuthorizationWorkflowError("This workflow requires a captured, body-free GET request", 422)
    if not isinstance(url, str) or not url or len(url) > 4000:
        raise AuthorizationWorkflowError("The captured request URL is unavailable", 422)
    try:
        if any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
            raise ValueError("invalid characters")
        parts = urlsplit(url)
        if parts.username or parts.password or parts.query or parts.fragment or "?" in url or "#" in url:
            raise ValueError("unsupported request shape")
        if _origin(url) not in {_origin(origin) for origin in origins}:
            raise AuthorizationWorkflowError("Captured request is outside this Hunt's frozen origins", 409)
        if not parts.path.startswith("/") or "//" in parts.path or "<" in parts.path or ">" in parts.path:
            raise ValueError("unreplayable path")
        return parts.path
    except ValueError as exc:
        if isinstance(exc, AuthorizationWorkflowError):
            raise
        raise AuthorizationWorkflowError("Query, fragment, redacted or malformed captures cannot be replayed by this workflow", 422) from exc


def _observations(result: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    # Only documented result envelopes, not an arbitrary recursive search that
    # could turn a quotation of an old proof into this action's proof.
    values: list[Mapping[str, Any]] = []
    for envelope in (result, mapping(result.get("result"))):
        single = envelope.get("observation")
        if isinstance(single, Mapping):
            values.append(single)
        for rows in (envelope.get("observations"), mapping(envelope.get("typed_output")).get("records")):
            if isinstance(rows, list):
                values.extend(row for row in rows[:100] if isinstance(row, Mapping))
    return values


def attributed_outcome(
    proposal: Mapping[str, Any], attempt: Mapping[str, Any],
    action: Mapping[str, Any] | None, transactions: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """No other object's finding, aggregate count, or claimed outcome can settle this request."""
    result: dict[str, Any] = {
        "outcome": "inconclusive", "certainty": "unknown",
        "reason": "The canonical action has not produced attributable evidence for this request",
        "proof_state": "inconclusive", "action_id": attempt["action_id"],
        "receipt_id": None, "transaction_ids": [],
        "selected_request_examined": False,
        "scope": "the selected request, object, principal pair and recorded conditions only",
    }
    if not action:
        result["execution_status"] = "not_dispatched"
        return result
    result["execution_status"] = action.get("status")
    stamp = action.get("completed_at")
    result["completed_at"] = stamp.isoformat() if hasattr(stamp, "isoformat") else stamp
    summary = mapping(action.get("input_summary"))
    if (str(action.get("id")) != attempt["action_id"]
            or str(action.get("hunt_run_id")) != proposal["hunt_id"]
            or action.get("capability_name") != "authz.verify"
            or summary.get("input_digest") != attempt["input_digest"]
            or summary.get("idempotency_key_sha256") != hashlib.sha256(attempt["idempotency_key"].encode()).hexdigest()):
        raise AuthorizationWorkflowError("The canonical action does not match this investigation")
    if action.get("status") not in {"completed", "partial"} or not action.get("receipt_id"):
        result["reason"] = "Execution is incomplete, blocked or failed; no authorization conclusion is justified"
        return result
    result["receipt_id"] = str(action["receipt_id"])
    for observation in _observations(mapping(action.get("result_summary"))):
        if (observation.get("kind") == "authz_differential"
                and observation.get("proof_state") == "verified"
                and observation.get("proof_type") == "cross_principal_replay"
                and observation.get("method") == "GET"
                and observation.get("principal_contexts_distinct") is True
                and observation.get("object_absent_from_secondary_listing") is True
                and observation.get("responses_equivalent") is True
                and observation.get("resource_id_sha256") == proposal["resource_id_sha256"]
                and observation.get("producer_url") == proposal["public_baseline_url"]
                and observation.get("consumer_url") == proposal["public_consumer_url"]
                and type(observation.get("owner_status")) is int
                and 200 <= observation["owner_status"] < 300
                and type(observation.get("attacker_status")) is int
                and 200 <= observation["attacker_status"] < 300):
            result.update(outcome="supported", certainty="confirmed", proof_state="verified",
                          owner_status=observation["owner_status"], attacker_status=observation["attacker_status"],
                          selected_request_examined=True,
                          reason="The canonical authz validator verified a crossing for the selected request and object")
            return result
    # A negative aggregate result is not a refutation. Only exact, same-action
    # primary/secondary transactions may establish that this request was denied.
    pairs: dict[str, set[int]] = {"primary": set(), "secondary": set()}
    for transaction in transactions:
        if (str(transaction.get("hunt_run_id")) != proposal["hunt_id"]
                or str(transaction.get("hunt_action_id")) != attempt["action_id"]
                or transaction.get("method") != "GET" or transaction.get("error")
                or request_identity(transaction) != proposal["capture_sha256"]):
            continue
        slot = transaction.get("principal_slot")
        status = transaction.get("status_code")
        if slot in pairs and type(status) is int:
            pairs[slot].add(status)
            result["transaction_ids"].append(str(transaction["id"]))
    result["selected_request_examined"] = bool(pairs["primary"] and pairs["secondary"])
    result["status_codes_by_principal"] = {key: sorted(value) for key, value in pairs.items()}
    if pairs["primary"] and all(200 <= code < 300 for code in pairs["primary"]) and pairs["secondary"] == {403}:
        result.update(outcome="refuted", certainty="observed",
                      reason="This exact GET was denied to the secondary principal while primary access succeeded; other objects and conditions remain unexamined")
    return result
