"""``authz.verify`` mode ``planted_object``: another user reads a private value one principal planted.

The object mode compares objects found in listings and skips any object the second principal's
own listing shows; on an application whose collection is shared (every user's books in one list)
it can never prove anything, although each object's private field is returned to whoever asks.

Here the object was created in this Hunt by one of the two principals (the creator), with a
distinctive value in a field named for something private (``hunt/authz_planted`` reads both from
the server's own records of that create request). Five reads, all GET:

1. the creator reads the object: the value is there (it is the creator's object, as planted);
2. the other principal reads the collection listing: 2xx, and the value is NOT there (the
   application itself withholds that field from the shared view);
3. the other principal reads the object, twice: 2xx, the value is there both times;
4. an anonymous read of the object does not carry the value.

Verified only when all of them hold: the other principal received a private value of an object
it did not create, which the application does not show it otherwise.
"""
from __future__ import annotations

import math
import time
import urllib.parse
from typing import Any, Callable, Mapping, Sequence

from .authz import AuthzVerificationContractError, _normalized_routes, _public_proof_url
from .http import WorkerPrivateHTTPResponse, execute_bound_http_request

try:
    from capabilities.secret_material import keyed_body_digest
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import keyed_body_digest

PROOF_TYPE = "planted_private_field_cross_read"
REQUESTS = 5
MAX_BODY_BYTES = 1_048_576


async def verify_planted_object(
    base_url: str, routes: Sequence[Any], *, target: Any, primary_headers: Mapping[str, str],
    secondary_headers: Mapping[str, str], creator: str, planted_field: str, planted_value: str,
    transaction_recorder: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    normalized = _normalized_routes(base_url, routes, target=target)
    if len(normalized) != 2 or len(routes) != 2:
        raise AuthzVerificationContractError(
            "planted_object compares two bound GET routes: the object, then its collection listing")
    if not primary_headers or not secondary_headers or dict(primary_headers) == dict(secondary_headers):
        raise AuthzVerificationContractError("planted_object requires two distinct authenticated principals")
    if creator not in {"primary", "secondary"}:
        raise AuthzVerificationContractError("planted_object needs the principal that created the object")
    headers = {"primary": dict(primary_headers), "secondary": dict(secondary_headers), "anonymous": {}}
    other = "secondary" if creator == "primary" else "primary"
    object_url, listing_url = normalized
    started = time.monotonic()
    sent = 0
    needle = planted_value.encode("utf-8")

    async def read(url: str, who: str) -> tuple[int, bool]:
        nonlocal sent
        seen: dict[str, Any] = {}

        def keep(private: WorkerPrivateHTTPResponse) -> None:
            seen["status"], seen["body"] = private.status_code, private.body()

        parts = urllib.parse.urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        path = urllib.parse.urlunsplit(("", "", parts.path or "/", parts.query, ""))
        result = await execute_bound_http_request(
            origin, {"method": "GET", "path": path, "follow_redirects": False}, target=target,
            allow_write=False, trusted_headers=headers[who], principal_slot=who,
            timeout_seconds=15, private_response_sink=keep, transaction_recorder=transaction_recorder,
            response_body_limit=MAX_BODY_BYTES)
        if isinstance(result.get("request"), Mapping):
            sent += 1
        if str(result.get("error") or "").startswith("scope:"):
            raise AuthzVerificationContractError("planted_object destination left its frozen target")
        status = int(seen.get("status") or 0)
        return status, needle in bytes(seen.get("body") or b"")

    steps: dict[str, tuple[int, bool]] = {}
    reason = None
    steps["creator_object"] = await read(object_url, creator)
    if not (200 <= steps["creator_object"][0] < 300 and steps["creator_object"][1]):
        reason = "creator_read_lacks_planted_value"
    if reason is None:
        steps["other_listing"] = await read(listing_url, other)
        if not 200 <= steps["other_listing"][0] < 300:
            reason = "listing_not_readable_by_other_principal"
        elif steps["other_listing"][1]:
            reason = "listing_shows_planted_value"  # the application shows it to everyone: not private
    if reason is None:
        steps["other_object"] = await read(object_url, other)
        steps["other_object_repeat"] = await read(object_url, other)
        if not all(200 <= steps[key][0] < 300 and steps[key][1] for key in ("other_object", "other_object_repeat")):
            reason = "other_principal_denied_or_value_absent"
    if reason is None:
        steps["anonymous_object"] = await read(object_url, "anonymous")
        if 200 <= steps["anonymous_object"][0] < 300 and steps["anonymous_object"][1]:
            reason = "anonymous_reads_planted_value"  # an exposure to everyone, not this boundary
    verified = reason is None
    origin = target.allowed_origins[0]
    observation: dict[str, Any] = {
        "kind": "authz_differential", "mode": "planted_object",
        "proof_state": "verified" if verified else "inconclusive",
        "reason": reason,
        "principal_contexts_distinct": True,
        "secret_values_visible": False,
        "statuses": {key: status for key, (status, _found) in steps.items()},
    }
    if verified:
        observation.update({
            "proof_type": PROOF_TYPE, "method": "GET",
            "consumer_url": _public_proof_url(object_url, base_origin=origin),
            "producer_url": _public_proof_url(listing_url, base_origin=origin),
            "creator_principal": creator, "reader_principal": other,
            "planted_field": str(planted_field)[:120],
            "planted_value_sha256": keyed_body_digest(needle),
            "owner_status": steps["creator_object"][0],
            "attacker_status": steps["other_object"][0],
            "listing_withholds_value": True, "repeated": True, "anonymous_denied": True,
            "accepted_principal_responses": {key: status for key, (status, _f) in steps.items()},
        })
    return {"ok": True, "status": "success", "observation": observation,
            "budget_consumed": {"http_requests": sent,
                                "tool_wall_seconds": max(1, math.ceil(time.monotonic() - started))}}
