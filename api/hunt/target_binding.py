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
    kind = str(run["target_kind"])
    target_id = run["target_id"] or run["device_target_id"]
    if kind not in {"web", "api", "network", "device"} or not target_id:
        raise CapabilityInputError(
            "HTTP capability requires a Web, API, network or device Hunt target"
        )
    target_context = (
        dict(context.get("target") or {})
        if isinstance(context.get("target"), Mapping) else {}
    )
    # A device records a bare locator rather than a URL, and the same host examined as a
    # device should reach the same service it reaches as a web target. The scheme is supplied
    # here only so the binding parses; the capability still names the exact origin it wants.
    target_url = str(target_context.get("url") or "").strip()
    if not target_url:
        locator = str(target_context.get("locator") or "").strip()
        if locator:
            target_url = locator if "://" in locator else (
                f"http://[{locator}]" if ":" in locator and not locator.startswith("[")
                else f"http://{locator}"
            )
    parsed = urllib.parse.urlsplit(target_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise CapabilityInputError("persisted Hunt target URL is invalid")
    root_domain = str(
        target_context.get("root_domain") or parsed.hostname
    ).lower().rstrip(".")
    target = TargetBinding(
        target_id=str(target_id),
        target_kind=kind,
        canonical_host=parsed.hostname,
        allowed_origins=tuple(target_context.get("origins") or (
            (f"{parsed.scheme}://{parsed.netloc}",) if kind == "device" else ()
        )),
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
