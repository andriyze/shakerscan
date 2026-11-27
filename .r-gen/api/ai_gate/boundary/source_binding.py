"""Hunt discovery provenance carried by an AI boundary proposal.

A leaf module: both the contract parser and the hypothesis compiler validate the binding,
so it depends on nothing in this package except the shared error type.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

from .errors import ContractError


BOUNDARY_SOURCE_SCHEMA = "hunt-boundary-source/v1"
MAX_BOUNDARY_SOURCE_AGENT_PATHS = 16


def normalize_boundary_source_binding(
    raw: Any,
    *,
    hunt_id: Any | None = None,
    target_id: Any | None = None,
) -> dict[str, Any] | None:
    """Validate optional Hunt discovery provenance without turning it into authority."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "hunt_id", "target_id", "origin", "agent_paths",
    }:
        raise ContractError("invalid_boundary_source_binding")
    if raw.get("schema_version") != BOUNDARY_SOURCE_SCHEMA:
        raise ContractError("invalid_boundary_source_binding")
    source_hunt = _canonical_uuid(raw.get("hunt_id"), "source_hunt_id")
    source_target = _canonical_uuid(raw.get("target_id"), "source_target_id")
    if hunt_id is not None and source_hunt != str(hunt_id):
        raise ContractError("boundary_source_hunt_mismatch")
    if target_id is not None and source_target != str(target_id):
        raise ContractError("boundary_source_target_mismatch")

    origin = raw.get("origin")
    if not isinstance(origin, str) or len(origin) > 2048:
        raise ContractError("invalid_boundary_source_origin")
    try:
        parsed = urlsplit(origin)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment):
            raise ValueError("origin")
        host = parsed.hostname.lower()
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
    except ValueError as exc:
        raise ContractError("invalid_boundary_source_origin") from exc
    suffix = (
        f":{port}"
        if port and port != (443 if parsed.scheme == "https" else 80)
        else ""
    )
    normalized_origin = f"{parsed.scheme}://{host}{suffix}"
    if origin.rstrip("/") != normalized_origin:
        raise ContractError("invalid_boundary_source_origin")

    paths = raw.get("agent_paths")
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_BOUNDARY_SOURCE_AGENT_PATHS:
        raise ContractError("invalid_boundary_source_agent_paths")
    normalized_paths: list[str] = []
    for item in paths:
        if (not isinstance(item, str) or len(item) > 2048 or not item.startswith("/")
                or item.startswith("//") or "?" in item or "#" in item
                or "\\" in item or any(ord(ch) < 33 for ch in item)):
            raise ContractError("invalid_boundary_source_agent_paths")
        try:
            p = urlsplit(item)
        except ValueError as exc:
            raise ContractError("invalid_boundary_source_agent_paths") from exc
        if p.scheme or p.netloc or p.query or p.fragment or p.path != item:
            raise ContractError("invalid_boundary_source_agent_paths")
        if item not in normalized_paths:
            normalized_paths.append(item)
    return {
        "schema_version": BOUNDARY_SOURCE_SCHEMA,
        "hunt_id": source_hunt,
        "target_id": source_target,
        "origin": normalized_origin,
        "agent_paths": normalized_paths,
    }


def _canonical_uuid(value: Any, field: str) -> str:
    """Server-written bindings carry canonical UUIDs; anything else is not one of them."""
    try:
        canonical = str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ContractError(f"invalid_boundary_hypothesis_{field}") from exc
    if value != canonical:
        raise ContractError(f"invalid_boundary_hypothesis_{field}")
    return canonical


def boundary_source_matches_endpoint(source_binding: Any, endpoint_url: Any) -> bool:
    """True only when a configured AI endpoint is one of the observed Hunt agent paths."""
    try:
        source = normalize_boundary_source_binding(source_binding)
    except ContractError:
        return False
    if source is None or not isinstance(endpoint_url, str) or len(endpoint_url) > 4096:
        return False
    try:
        parsed = urlsplit(endpoint_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            return False
        host = parsed.hostname.lower()
        host = f"[{host}]" if ":" in host else host
        port = parsed.port
    except ValueError:
        return False
    suffix = (
        f":{port}"
        if port and port != (443 if parsed.scheme == "https" else 80)
        else ""
    )
    origin = f"{parsed.scheme}://{host}{suffix}"
    return origin == source["origin"] and (parsed.path or "/") in source["agent_paths"]
