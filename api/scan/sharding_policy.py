"""Auto-sharding policy for the canonical Scan.

Whether a Scan becomes a parallel parent, and which strategy it fans out with,
is Scan planning -- not composition. It lived in the API module beside route
wiring, which is how a resolved one-worker ceiling came to be ignored here while
the deprecated ``options.parallel`` flag still worked.

The environment-dependent inputs (effective settings, current worker count) stay
with the caller and arrive as arguments, so this module is pure decision logic.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

try:
    import check_registry
    import parallel_scan
    from settings_routes.router import _normalize_parallel_strategy
except ModuleNotFoundError:  # package import in host-side tests
    from .. import check_registry, parallel_scan
    from ..settings_routes.router import _normalize_parallel_strategy


def scan_option_was_explicit(options: Any, field: str) -> bool:
    return field in getattr(options, "model_fields_set", set())


def scan_check_family_value(options_payload: Mapping[str, Any]) -> Any:
    return (
        options_payload.get("check_family")
        or options_payload.get("asm_check_family")
        or options_payload.get("coverage_attempt_family")
    )


def custom_endpoint_count(options_payload: dict[str, Any]) -> int:
    endpoints = options_payload.get("custom_endpoints")
    if not isinstance(endpoints, list):
        return 0
    seen: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        value = endpoint.strip()
        if value:
            seen.add(value)
    return len(seen)


def auto_shard_eligibility(
    active_testing: bool, options_payload: dict[str, Any],
) -> tuple[bool, str]:
    endpoint_count = custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return True, f"{endpoint_count} explicit endpoints can be split by scope"
    # A focused check_family scan (sqli/xss/bola/auth) is a deep single-family
    # pass. Auto-sharding it into broad `coverage` dilutes that family's budget
    # and adds the slow recon+merge path (observed: a focused SQLi scan hung in
    # coverage and found nothing, while the direct pass found the login SQLi).
    # Focused scans therefore run DIRECT; only broad scans fan out.
    family = check_registry.normalize_check_family(scan_check_family_value(options_payload))
    if family and family != "all":
        return False, f"focused {family} scan runs direct (auto-sharding would dilute the family pass)"
    if active_testing:
        return True, "active Scan can fan out endpoint coverage across workers"
    return False, "passive Scan has no endpoint list and no active families to shard"


def resolve_auto_parallel_strategy(
    strategy: Any,
    active_testing: bool,
    options_payload: dict[str, Any],
) -> str:
    """Resolve auto-sharding to the concrete strategy we will store/execute."""
    normalized = _normalize_parallel_strategy(strategy, default="auto")
    # A focused check_family scan must never run the broad `coverage` strategy:
    # that fans out broad/sqli/xss lanes and dilutes (or skips) the requested
    # family. `coverage_family` with a single requested family runs ONLY that
    # family across endpoint slices, so it parallelizes without diluting. This
    # holds for both explicit `coverage` and the auto path below.
    focused = bool(
        (lambda fam: fam and fam != "all")(
            check_registry.normalize_check_family(scan_check_family_value(options_payload))
        )
    )
    if focused and normalized == "coverage":
        return "coverage_family"
    if normalized != "auto":
        return normalized
    endpoint_count = custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return "scope"
    # Authenticated active scans: prefer the additive auth split so a primary
    # credential ADDS an authenticated pass on top of the anonymous baseline
    # instead of REPLACING it (which silently drops anonymous-only findings like
    # unauthenticated SQLi). Each auth_split shard is a full smart scan — no
    # family/scope fragmentation of the global+browser checks — and the authed
    # shard keeps user1+user2 so cross-user BOLA still runs. Focused-family scans
    # keep coverage_family (they need per-family endpoint slicing).
    has_primary_auth = any(options_payload.get(k) for k in parallel_scan._PRIMARY_AUTH_KEYS)
    if has_primary_auth and not focused and active_testing:
        return "auth_split"
    if active_testing:
        return "coverage_family" if focused else "coverage"
    return "family"


