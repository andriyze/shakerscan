"""Selected-object comparison without an invented collection listing.

Two same-collection object URLs mean, in order: primary's selected object and
secondary's own-object reference. Four bounded GETs establish the secondary
baseline, read the selection as primary and secondary, and re-read as primary.
The caller supplies the existing target-bound transport and principal headers.

This measures access, not entitlement. Equal private response objects are useful
cross-access evidence, NEVER a fabricated ``absent_from_listing`` assertion or
an automatic verified BOLA. An operator's expected access rule is interpretation
context, not permission to promote a finding. No target-specific facts live here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any, Awaitable, Callable, Mapping, Sequence
from urllib.parse import unquote, urlsplit

_IDENTIFIERS = (
    re.compile(r"[0-9]+"),
    re.compile(r"[0-9a-fA-F]{24,}"),
    re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
)
Fetch = Callable[..., Awaitable[Mapping[str, Any]]]
MAX_BODY_BYTES = 262_144
DEADLINE_SECONDS = 50


def selected_object_pair(routes: Sequence[str]) -> tuple[str, str] | None:
    """Recognize an exact pair, not two guesses about collection existence.

    The existing capability's ordered routes remain the only wire input. A
    collection+object inventory retains its existing listing-based behavior.
    """
    if len(routes) != 2:
        return None
    parts = []
    for value in routes:
        if not isinstance(value, str) or len(value) > 4000:
            return None
        if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
            return None
        try:
            url = urlsplit(value)
            port = url.port or (443 if url.scheme == "https" else 80)
        except ValueError:
            return None
        if (url.scheme not in {"http", "https"} or not url.hostname or url.username
                or url.password or url.query or url.fragment or "?" in value or "#" in value
                or "//" in url.path or any(unquote(s) in {".", ".."} for s in url.path.split("/"))):
            return None
        parent, _, identifier = url.path.rstrip("/").rpartition("/")
        if not parent or not any(p.fullmatch(identifier) for p in _IDENTIFIERS):
            return None
        parts.append(((url.scheme, url.hostname.lower(), port, parent, url.path.endswith("/")), identifier))
    if parts[0][0] != parts[1][0] or parts[0][1] == parts[1][1]:
        return None
    return parts[0][1], parts[1][1]


def request_digest(url: str) -> str:
    """Same request identity as the captured-request workflow, without its imports."""
    return hashlib.sha256(json.dumps(
        {"method": "GET", "url": url, "request_body_bytes": 0},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def _unique_object(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError("duplicate JSON key")
        result[name] = value
    return result


def _document(response: Mapping[str, Any], identifier: str) -> tuple[str | None, str]:
    """Return a canonical object only from complete, non-error JSON evidence.

    Follow object wrappers, not arrays/collection entries. A catch-all, login
    page, ambiguous duplicate ID or a nested related object is not the selection.
    """
    if response.get("error") or response.get("complete") is not True:
        return None, "response_incomplete"
    status = response.get("status_code")
    if type(status) is not int or status != 200:
        return None, "response_not_successful"
    headers = response.get("headers") or {}
    if not isinstance(headers, Mapping):
        return None, "response_not_json"
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").split(";", 1)[0].lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        return None, "response_not_json"
    body = response.get("body")
    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_BODY_BYTES:
        return None, "response_unavailable"
    try:
        obj = json.loads(body, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        for _ in range(4):
            if not isinstance(obj, dict) or any(str(k).lower() in {"error", "errors"} for k in obj):
                return None, "response_not_object"
            ids = [v for k, v in obj.items() if k.lower() in {"id", "uuid"}]
            if ids:
                if len(ids) != 1 or isinstance(ids[0], bool) or not isinstance(ids[0], (str, int)) or str(ids[0]) != identifier:
                    return None, "response_object_mismatch"
                if len(obj) <= 1:
                    return None, "object_has_no_content"
                return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False), "object_observed"
            children = [v for v in obj.values() if isinstance(v, dict)]
            if len(children) != 1:
                return None, "response_object_ambiguous"
            obj = children[0]
    except (ValueError, TypeError, RecursionError):
        return None, "response_not_valid_json"
    return None, "response_object_unresolved"


async def compare_selected_objects(
    routes: Sequence[str], *, fetcher: Fetch,
    primary_headers: Mapping[str, str], secondary_headers: Mapping[str, str],
    cancelled: Callable[[], bool] = lambda: False,
) -> dict[str, Any]:
    """Perform at most four GETs; return bounded metadata, never response contents."""
    ids = selected_object_pair(routes)
    if ids is None:
        raise ValueError("selected-object comparison requires two distinct same-collection object GETs")
    if not primary_headers or not secondary_headers or dict(primary_headers) == dict(secondary_headers):
        raise ValueError("selected-object comparison requires distinct authenticated contexts")
    selected, own = routes
    selected_id, own_id = ids
    observation: dict[str, Any] = {
        "kind": "authz_differential", "mode": "selected_object", "method": "GET",
        "proof_state": "inconclusive", "proof_type": "selected_object_comparison",
        "selected_request_sha256": request_digest(selected), "baseline_request_sha256": request_digest(own),
        "resource_id_sha256": hashlib.sha256(selected_id.encode()).hexdigest(),
        "baseline_resource_id_sha256": hashlib.sha256(own_id.encode()).hexdigest(),
        "principal_contexts_distinct": True, "secret_values_visible": False,
        "selected_request_examined": False, "cross_access_observed": False,
        "secondary_baseline_valid": False, "owner_repeat_stable": False,
        "responses_equivalent": False, "access_denied": False,
        "requires_entitlement_review": True, "listing_used": False,
        "reason": "selected_object_not_examined", "requests_attempted": 0,
    }

    async def get(url: str, headers: Mapping[str, str]) -> Mapping[str, Any]:
        if cancelled():
            raise asyncio.CancelledError()
        observation["requests_attempted"] += 1
        return await fetcher(url, method="GET", headers=headers, timeout=10)

    try:
        async with asyncio.timeout(DEADLINE_SECONDS):
            baseline = await get(own, secondary_headers)
            baseline_doc, reason = _document(baseline, own_id)
            observation["secondary_baseline_status"] = baseline.get("status_code", 0)
            if baseline_doc is None:
                observation["reason"] = "secondary_baseline_" + reason
                return observation
            observation["secondary_baseline_valid"] = True
            owner = await get(selected, primary_headers)
            owner_doc, reason = _document(owner, selected_id)
            observation["owner_status"] = owner.get("status_code", 0)
            if owner_doc is None:
                observation["reason"] = "primary_" + reason
                return observation
            crossing = await get(selected, secondary_headers)
            observation["attacker_status"] = crossing.get("status_code", 0)
            observation["selected_request_examined"] = (not bool(crossing.get("error"))
                and type(crossing.get("status_code")) is int and 100 <= crossing["status_code"] <= 599)
            if crossing.get("status_code") == 403 and not crossing.get("error") and crossing.get("complete") is True:
                observation.update(access_denied=True, reason="selected_object_denied_to_secondary")
                return observation
            cross_doc, reason = _document(crossing, selected_id)
            if cross_doc is None:
                observation["reason"] = "secondary_" + reason
                return observation
            repeated = await get(selected, primary_headers)
            repeat_doc, reason = _document(repeated, selected_id)
            if repeat_doc is None:
                observation["reason"] = "primary_repeat_" + reason
                return observation
            observation["owner_repeat_stable"] = owner_doc == repeat_doc
            if owner_doc != repeat_doc:
                observation["reason"] = "selected_object_changed_during_comparison"
                return observation
            observation["responses_equivalent"] = owner_doc == cross_doc
            if owner_doc != cross_doc:
                observation["reason"] = "selected_object_response_differs_review_fields"
                return observation
            observation.update(
                cross_access_observed=True,
                reason="selected_object_cross_access_observed_entitlement_unproven",
                selected_object_content_sha256=hashlib.sha256(owner_doc.encode()).hexdigest(),
            )
            return observation
    except TimeoutError:
        observation.update(reason="selected_object_deadline_exceeded", partial=True)
        return observation
