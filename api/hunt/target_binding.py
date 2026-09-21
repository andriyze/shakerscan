"""Frozen HTTP asset bindings for web/API/network Hunt execution."""
from __future__ import annotations
import urllib.parse
from typing import Any, Mapping
try:
    from runtime.models import TargetBinding
    from capabilities.network import CapabilityInputError
except ModuleNotFoundError:
    from ..runtime.models import TargetBinding
    from ..capabilities.network import CapabilityInputError


def web_hunt_target(
    run: Mapping[str, Any],
    context: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> tuple[TargetBinding, str]:
    if str(run["target_kind"]) not in {"web", "api", "network"} or not run["target_id"]:
        raise CapabilityInputError("HTTP capability requires a Web, API or network Hunt target")
    target_context = (
        dict(context.get("target") or {})
        if isinstance(context.get("target"), Mapping) else {}
    )
    target_url = str(target_context.get("url") or "").strip()
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise CapabilityInputError("persisted Hunt target URL is invalid")
    root_domain = str(
        target_context.get("root_domain") or parsed.hostname
    ).lower().rstrip(".")
    target = TargetBinding(
        target_id=str(run["target_id"]),
        target_kind=str(run["target_kind"]),
        canonical_host=parsed.hostname,
        allowed_origins=tuple(target_context.get("origins") or ()),
        allowed_addresses=tuple(
            str(item)
            for item in context.get("authorized_target_addresses") or ()
            if str(item)
        ),
        allowed_root_domains=(root_domain,) if root_domain else (),
        environment=str(target_context.get("environment") or "unknown"),
        scope_receipt_id=str(policy.get("scope_receipt_id") or "") or None,
    )
    return target, target_url

