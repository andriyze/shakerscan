"""Canonical service provenance shared by finding writers and compatibility readers."""
from __future__ import annotations

from typing import Any, Mapping
import json
from urllib.parse import urlsplit, parse_qsl


def service_origin(url: Any) -> str | None:
    try:
        parsed = urlsplit(str(url or ""))
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().rstrip(".")
        defaults = {"http": 80, "https": 443, "ws": 80, "wss": 443}
        if scheme not in defaults or not host or parsed.username is not None:
            return None
        port = parsed.port if parsed.port is not None else defaults[scheme]
        if not 1 <= port <= 65535:
            return None
        host = f"[{host}]" if ":" in host else host
        return f"{scheme}://{host}:{port}"
    except (TypeError, ValueError):
        return None


def finding_service_origin(finding: Mapping[str, Any]) -> str | None:
    evidence = finding.get("evidence")
    evidence = evidence if isinstance(evidence, Mapping) else {}
    for value in (finding.get("url"), *(evidence.get(key) for key in (
        "url", "endpoint", "affected_url", "target", "path", "consumer_endpoint", "producer_endpoint",
    ))):
        origin = service_origin(value)
        if origin:
            return origin
    return None


def finding_client_route_key(finding: Mapping[str, Any]) -> tuple[str, tuple[str, ...]] | None:
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            return None
    if not isinstance(evidence, Mapping) or not evidence.get("client_route"):
        return None
    try:
        from .findings import template_path
    except ImportError:
        from findings import template_path
    try:
        route = urlsplit(str(evidence["client_route"]).lstrip("!"))
    except ValueError:
        return None
    return template_path(route.path or "/"), tuple(sorted({key for key, _ in parse_qsl(route.query, keep_blank_values=True)}))


def finding_provenance_key(finding: Mapping[str, Any]) -> tuple:
    """Compatibility keys are meaningful only on the captured service/client route."""
    return finding_service_origin(finding), finding_client_route_key(finding)


def same_finding_service(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    """Legacy keys alone cannot transfer triage/proof between different services."""
    first, second = finding_service_origin(left), finding_service_origin(right)
    return first is not None and first == second and finding_client_route_key(left) == finding_client_route_key(right)


def service_suffix(url: Any) -> str:
    origin = service_origin(url)
    return f"|service={origin}" if origin else ""
