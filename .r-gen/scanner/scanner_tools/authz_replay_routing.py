"""Resource-aware ordering for the existing bounded authorization verifier.

These helpers choose which existing candidate to try first. They do not infer
ownership, grant scope, add HTTP requests, or decide whether a finding is proven.
Identifier eligibility remains owned by access_control_checks' existing parsers.
"""
from __future__ import annotations

import re
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import unquote, urlsplit

Location = tuple[Literal["path", "query"], int]
_GENERIC_IDENTIFIERS = frozenset({"", "id", "uuid", "uid", "object", "resource"})


def _resource_name(value: str) -> str:
    """Comparable routing label, never an access-control assertion."""
    value = unquote(str(value)).strip("{}<>:$ ")
    value = re.sub(r"[^a-z0-9]", "", value.lower())
    if value in _GENERIC_IDENTIFIERS:
        return ""
    for suffix in ("uuid", "id"):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break
    if value in _GENERIC_IDENTIFIERS:
        return ""
    if value.endswith("ies") and len(value) > 3:
        return value[:-3] + "y"
    if value.endswith(("sses", "shes", "ches", "xes", "zes")):
        return value[:-2]
    if value.endswith("s") and not value.endswith(("ss", "us", "is")):
        return value[:-1]
    return value


def select_replay_identifier(
    path_segments: Sequence[str],
    path_indices: Sequence[int],
    query_pairs: Sequence[tuple[str, str]],
    query_indices: Sequence[int],
    *,
    object_id_key: str = "id",
) -> Location | None:
    """Choose one already-eligible identifier, preserving other parent IDs.

    Prefer a field-name match, then the deepest path identifier. A generic query
    ID on a collection leaf outranks a parent path ID, e.g.
    /tenants/7/invoices?id=8. A named parent reference such as tenant_id can still
    intentionally select the parent. No eligible slot is invented by this helper.
    """
    hint = _resource_name(object_id_key)
    matches: list[tuple[int, int, Location]] = []
    if hint:
        for index in path_indices:
            own = _resource_name(path_segments[index])
            previous = _resource_name(path_segments[index - 1]) if index else ""
            score = 3 if own == hint else 2 if previous == hint else 0
            if score:
                matches.append((score, index, ("path", index)))
        for index in query_indices:
            if _resource_name(query_pairs[index][0]) == hint:
                matches.append((3, len(path_segments) + index, ("query", index)))
    if matches:
        return max(matches, key=lambda item: (item[0], item[1]))[2]

    # A non-generic query filter (e.g. owner_id) must not displace the concrete
    # selected resource at /invoices/8 merely because the query follows the path.
    generic_queries = [i for i in query_indices if not _resource_name(query_pairs[i][0])]
    last_path = max(path_indices) if path_indices else None
    if generic_queries and (
        last_path is None or any(path_segments[last_path + 1:])
    ):
        return "query", generic_queries[0]
    if last_path is not None:
        return "path", last_path
    if query_indices:
        return "query", query_indices[0]
    return None


def _origin(url: str) -> tuple[str, str, int] | None:
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        return (parsed.scheme, parsed.hostname.lower().rstrip("."),
                parsed.port or (443 if parsed.scheme == "https" else 80))
    except (TypeError, ValueError):
        return None


def prioritize_replay_candidates(
    producer_url: str,
    candidates: Sequence[Mapping[str, Any]],
    *,
    object_id: str,
    object_id_key: str = "id",
    item_base_path: str | None = None,
) -> list[dict[str, Any]]:
    """Stable ordering before the existing cap, not another execution filter.

    Observed consumers for this resource beat unrelated high-ranked routes.
    An inferred direct item route also beats an unrelated observed template.
    Foreign-key references may intentionally prefer a different resource family.
    Every input candidate is returned; callers retain their existing bounds.
    """
    source_origin = _origin(producer_url)
    try:
        producer_path = urlsplit(producer_url).path.rstrip("/") or "/"
    except (TypeError, ValueError):
        return [dict(item) for item in candidates]
    canonical_path = (item_base_path or producer_path).rstrip("/") or "/"
    hint = _resource_name(object_id_key)
    producer_noun = _resource_name(canonical_path.rsplit("/", 1)[-1])

    def rank(item: Mapping[str, Any]) -> tuple[int, int, int]:
        url = str(item.get("url") or "")
        if source_origin is None or _origin(url) != source_origin:
            return -1, -1, -1
        try:
            path = urlsplit(url).path.rstrip("/") or "/"
        except ValueError:
            return -1, -1, -1
        segments = path.split("/")
        selected_names = [
            _resource_name(segments[i - 1])
            for i, segment in enumerate(segments) if i and unquote(segment) == object_id
        ] if item.get("object_id_location") == "path" else []
        parent = path
        if item.get("object_id_location") == "path" and unquote(segments[-1]) == object_id:
            parent = path.rsplit("/", 1)[0] or "/"
        leaf = _resource_name(parent.rsplit("/", 1)[-1])
        field_match = int(bool(hint and hint in (*selected_names, leaf)))
        topology = (
            4 if parent == canonical_path else
            3 if parent == producer_path else
            1 if producer_noun and leaf == producer_noun else 0
        )
        observed = int(item.get("source") == "discovered_consumer_template")
        return field_match, topology, observed

    return [dict(item) for item in sorted(candidates, key=rank, reverse=True)]
