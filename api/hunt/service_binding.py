"""Select services of an admitted Hunt asset without changing its host or addresses.

Callers pass persisted, revalidated Hunt policy, never request-body authorization.
A service selection is per action. Responses and redirects never call this resolver.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass, replace
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

try:
    from capabilities.http import _origin, _origin_key, resolve_hunt_http_origin
    from runtime.models import TargetBinding
except ModuleNotFoundError:
    from ..capabilities.http import _origin, _origin_key, resolve_hunt_http_origin
    from ..runtime.models import TargetBinding
from .target_binding import web_hunt_target


def policy_mapping(policy: Any) -> Mapping[str, Any]:
    return asdict(policy) if is_dataclass(policy) else policy


def endpoint_target(target: TargetBinding, endpoint: str, policy: Any, *,
                    base_url: str | None = None) -> tuple[TargetBinding, str]:
    """Resolve an operator-saved endpoint, keeping paths out of the origin binding."""
    text = str(endpoint or "")
    if not text or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text) or "\\" in text:
        raise ValueError("saved service endpoint is invalid")
    base = base_url or (target.allowed_origins[0] if target.allowed_origins else "")
    url = urljoin(base.rstrip("/") + "/", text)
    parsed = urlsplit(url)
    # urlsplit validates the numeric range when .port is read.
    if parsed.port == 0 or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("saved service endpoint is invalid")
    origin = _origin(url)
    if origin is None:
        raise ValueError("saved service endpoint must use HTTP or HTTPS")
    selected = resolve_hunt_http_origin(target, origin, policy_mapping(policy))
    return selected, urlunsplit((*urlsplit(origin)[:2], parsed.path or "/", parsed.query, ""))


def collection_target(run: Mapping[str, Any], context: Mapping[str, Any],
                      policy: Mapping[str, Any], origins: Sequence[str]) -> TargetBinding:
    """Bind only the saved collection's origins, never host data from a queue payload."""
    if not origins or len(origins) > 64:
        raise ValueError("collection requires 1-64 saved service origins")
    target, _ = web_hunt_target(run, context, policy)
    normalized = []
    for origin in origins:
        target = resolve_hunt_http_origin(target, origin, policy)
        value = _origin(origin)
        if value not in normalized:
            normalized.append(value)
    return replace(target, allowed_origins=tuple(normalized))


def service_origin_changed(target: TargetBinding, origin: Any) -> bool:
    return origin is not None and _origin_key(origin) not in {_origin_key(o) for o in target.allowed_origins}


def collection_uses_service_origin(target: TargetBinding, context: Mapping[str, Any],
                                   collection_id: Any) -> bool:
    """Whether a bound collection reaches a service origin beyond the Hunt's own."""
    wanted = str(collection_id or "")
    bound = next((
        item for item in context.get("request_collections") or []
        if isinstance(item, Mapping) and wanted
        and wanted in {str(item.get("collection_id") or ""), str(item.get("selection_id") or "")}
    ), None)
    return bound is not None and any(
        service_origin_changed(target, origin) for origin in bound.get("allowed_origins") or ()
    )
