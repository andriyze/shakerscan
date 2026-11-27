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


def _evidence(finding: Mapping[str, Any]) -> Mapping[str, Any]:
    """Evidence as a mapping. Database rows carry the jsonb column as text (no codec)."""
    evidence = finding.get("evidence")
    if isinstance(evidence, (str, bytes)):
        try:
            evidence = json.loads(evidence)
        except ValueError:
            return {}
    return evidence if isinstance(evidence, Mapping) else {}


def finding_service_origin(finding: Mapping[str, Any]) -> str | None:
    evidence = _evidence(finding)
    for value in (finding.get("url"), *(evidence.get(key) for key in (
        "url", "endpoint", "affected_url", "target", "path", "consumer_endpoint", "producer_endpoint",
    ))):
        origin = service_origin(value)
        if origin:
            return origin
    return None


def finding_client_route_key(finding: Mapping[str, Any]) -> tuple[str, tuple[str, ...]] | None:
    evidence = _evidence(finding)
    if not evidence.get("client_route"):
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
    """Legacy keys alone cannot transfer triage/proof between different services.

    Two findings whose service is unknown on both sides (path-only URLs, as pre-2.3.8 rows
    stored them) carry no service suffix in either key, so they are the same finding when the
    client route matches; a known service never matches an unknown one."""
    first, second = finding_service_origin(left), finding_service_origin(right)
    return first == second and finding_client_route_key(left) == finding_client_route_key(right)


def service_suffix(url: Any) -> str:
    origin = service_origin(url)
    return f"|service={origin}" if origin else ""
