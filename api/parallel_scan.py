"""Parallel scan orchestration: plan a parent scan into independent shards.

A parallel scan splits one logical scan of a single target across the worker
fleet (see docs/parallel-scan-architecture.md). The flow is a scatter-gather:

    POST /scans {parallel:true}
        -> parent scan row (scan_role='parent')
        -> scan_plan job
             -> N child scan rows (scan_role='shard') + N scan_shard jobs
        -> each shard runs run_scan() with a focused option override
        -> last shard to finish enqueues a scan_merge job
        -> scan_merge aggregates child results into the parent report

This module is the *planner*: it is pure logic (no I/O) so it can be unit
tested. Given the parent scan options it returns a ParallelPlan whose shards
each carry a full child-options dict (parent options + a focused override).

Strategies:

  - ``scope``: partition an explicit ``custom_endpoints`` list across shards.
    Each shard tests only its slice with a trimmed discovery budget. This is a
    real division of work (genuine speed-up) and is the best fit for API
    targets where the endpoints are known up front.

  - ``family``: split active testing by capability using the scanner's focused
    flags (``--sqli`` / ``--xss``). One broad shard covers full breadth at the
    parent budget; additional shards run deeper, higher-budget SQLi- and
    XSS-focused passes. This buys *depth* (more coverage / larger budget in the
    same wall-clock), not raw speed, because discovery repeats per shard. The
    raw-speed "discover once, slice endpoints" path is handled by ``coverage``.

  - ``coverage``: run a single recon pass, harvest the emitted active worklist,
    then partition that full endpoint list across coverage shards. This is the
    high-budget path for testing the whole target, not just the top endpoints.

``auto`` resolves to ``scope`` when >=2 custom endpoints are present, else
``family``.
"""

from __future__ import annotations

import copy
import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any

try:
    from constants import resolve_scan_budget
except ModuleNotFoundError as exc:
    if exc.name != "constants":
        raise
    from scanner.constants import resolve_scan_budget


def _env_int(name: str, default: int) -> int:
    """Operator override for a shard cap via env var, falling back to default."""
    try:
        value = int(os.environ.get(name, "") or default)
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default

# Job ``type`` values routed by the worker's process_job().
PLAN_JOB_TYPE = "scan_plan"
SHARD_JOB_TYPE = "scan_shard"
MERGE_JOB_TYPE = "scan_merge"

# Statuses that mean a scan row will not change on its own.
TERMINAL_STATUSES = ("completed", "failed", "cancelled")

# Option keys that control orchestration itself. They must never be propagated
# into a child shard's options or a shard would try to fan out recursively.
PARALLEL_OPTION_KEYS = (
    "parallel",
    "shards",
    "shard_strategy",
    "auto_sharded",
    "auto_sharding_reason",
)

# Scan types that actually run active injection testing. ``family`` sharding is
# only meaningful for these; for passive types it degrades to a single shard.
ACTIVE_SCAN_TYPES = frozenset({"full", "aggressive", "smart"})

VALID_STRATEGIES = frozenset({"auto", "scope", "family", "coverage"})

# exploit-depth: drive confirmed findings to proof rather than capping early.
EXPLOIT_DEPTH_BUDGET = {
    "sqli_extract_max": 8,
    "oob_max_findings": 8,
    "max_findings_per_family": None,  # None -> unlimited (worker maps to -1)
}

# coverage strategy: active endpoints tested per shard. Smaller values create
# more shards and more queue fan-out; larger values create fewer heavier shards.
COVERAGE_PER_SHARD_CAP = 150

# Default harvested worklist size. The scanner also emits 5000 by default, but
# callers can raise this with custom_budget.active_worklist_max.
COVERAGE_WORKLIST_MAX = 5000

STATIC_ASSET_EXTENSIONS = frozenset({
    ".avif", ".bmp", ".css", ".eot", ".gif", ".ico", ".jpeg", ".jpg",
    ".js", ".map", ".mp4", ".otf", ".png", ".svg", ".ttf", ".webm", ".webp",
    ".woff", ".woff2",
})

# Lean discovery budget for the coverage "discover-once" recon pass. The recon
# only needs to ENUMERATE the endpoint worklist quickly (the shards do the real
# active testing), so we cap browser crawl, skip parameter discovery, disable
# active and Nuclei, and hard-bound the runtime. Without this the recon inherits
# heavy scan work and "planning" can run for minutes before fan-out.
RECON_DISCOVERY_BUDGET = {
    # Keep one selected endpoint so the scanner still reaches the active block
    # and emits the full pre-cap active_worklist, but give active probes no time.
    "active_max_endpoints": 1,
    "active_max_seconds": 0,
    "nuclei_max_targets": 0,
    "max_urls": 3000,            # worklist breadth is cheap; depth was the cost
    "browser_max_pages": 25,
    "browser_max_depth": 3,
    "discovery_depth": 3,
    "param_discovery_url_limit": 0,   # skip per-URL param discovery in recon
    "param_discovery_max_params": 0,
    "max_duration_minutes": 10,       # hard bound so planning can't run away
}

# Auth fields that establish the primary (user1) authenticated identity.
_PRIMARY_AUTH_KEYS = (
    "auth_header", "auth_cookies", "auth_headers_json",
    "login_username", "login_password", "login_url", "login_extra_fields",
    "auto_auth", "auth_scenario_json",
)
_SECONDARY_AUTH_KEYS = ("user2_header", "user2_cookies")

# Shard caps. All overridable via env so operators can right-size for their
# fleet/DB without a code change (e.g. SHAKERSCAN_COVERAGE_MAX_TOTAL_SHARDS=64).

# Hard ceiling on generic non-coverage shards regardless of request, so a stray
# ``shards: 999`` cannot flood the queue.
MAX_SHARDS = _env_int("SHAKERSCAN_MAX_SHARDS", 24)

# Auth-state expansion multiplies useful work (anonymous/user1/user2), so it
# needs its own cap instead of reusing the generic base-shard ceiling.
AUTH_STATE_MAX_SHARDS = _env_int("SHAKERSCAN_AUTH_STATE_MAX_SHARDS", 96)

# Coverage strategy partitions the FULL endpoint worklist, so big estates need
# more shards than the generic cap. Excess shards queue and run as workers free up.
COVERAGE_MAX_SHARDS = _env_int("SHAKERSCAN_COVERAGE_MAX_SHARDS", 128)

# Total expanded coverage shards after auth-state multiplication. If a target
# would exceed this, we keep all endpoints but use fewer, larger base shards
# before multiplying by auth state. We never silently drop endpoint buckets.
COVERAGE_MAX_TOTAL_SHARDS = _env_int("SHAKERSCAN_COVERAGE_MAX_TOTAL_SHARDS", 256)

# Dynamic Full Coverage uses queued pull workers instead of preassigned static
# endpoint slices. It shares the same broad cap family so queue fan-out stays
# bounded by default.
COVERAGE_DYNAMIC_BATCH_SIZE = _env_int("SHAKERSCAN_COVERAGE_DYNAMIC_BATCH_SIZE", COVERAGE_PER_SHARD_CAP)
COVERAGE_MAX_DYNAMIC_BATCHES = _env_int("SHAKERSCAN_COVERAGE_MAX_DYNAMIC_BATCHES", COVERAGE_MAX_TOTAL_SHARDS)

# Per-shard active-endpoint ceiling (mirrors SCAN_BUDGET_CEILINGS["active_max_endpoints"]
# in scanner/constants.py). Used only to warn when capped slices grow past it.
ACTIVE_ENDPOINTS_CEILING = 10000

# ``family`` strategy can express at most these distinct, non-overlapping shards
# with the focused flags the scanner exposes today.
FAMILY_SHARD_LABELS = ("broad", "sqli", "xss")


@dataclass
class ShardSpec:
    """One unit of fan-out work: a focused child scan."""

    index: int
    label: str
    options: dict[str, Any]


@dataclass
class ParallelPlan:
    """Result of planning. ``shards`` may be length 1 (caller should then fall
    back to a normal standalone scan rather than orchestrating)."""

    strategy: str
    shards: list[ShardSpec] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def shard_count(self) -> int:
        return len(self.shards)

    @property
    def is_parallel(self) -> bool:
        return len(self.shards) >= 2


def _base_child_options(parent_options: dict[str, Any]) -> dict[str, Any]:
    """Copy parent options minus the orchestration keys."""
    child = copy.deepcopy(parent_options or {})
    for key in PARALLEL_OPTION_KEYS:
        child.pop(key, None)
    return child


def _merge_custom_budget(options: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Merge ``overrides`` into ``options['custom_budget']`` in place."""
    budget = dict(options.get("custom_budget") or {})
    budget.update(overrides)
    options["custom_budget"] = budget
    _sync_resolved_budget(options)


def _merge_custom_budget_defaults(options: dict[str, Any], defaults: dict[str, Any]) -> None:
    """Set per-shard budget defaults without overwriting explicit caller caps."""
    budget = dict(options.get("custom_budget") or {})
    for key, value in defaults.items():
        if budget.get(key) is None:
            budget[key] = value
    options["custom_budget"] = budget
    _sync_resolved_budget(options)


def _sync_resolved_budget(options: dict[str, Any]) -> None:
    """Keep child scan metadata aligned with the worker's effective budget.

    Child shards execute from ``custom_budget`` CLI flags. Parent options often
    already contain a resolved parent budget, so copying the dict into a shard
    without recomputing it makes API/UI consumers think every shard still has
    the full parent crawl/Nuclei budget.
    """
    custom_budget = options.get("custom_budget")
    if not isinstance(custom_budget, dict):
        return
    budget_profile = options.get("budget_profile")
    if options.get("thorough_params") and not budget_profile:
        budget_profile = "exhaustive"
    options["resolved_budget"] = resolve_scan_budget(
        options.get("scan_type") or "standard",
        budget_profile,
        custom_budget,
    )


def _coerce_shard_request(requested_shards: Any, worker_count: int) -> int:
    """Resolve the requested shard count to a concrete integer.

    ``"auto"``/None scales to the available worker fleet (so fan-out matches
    capacity), bounded to a sensible default range.
    """
    if isinstance(requested_shards, bool):  # bool is an int subclass; reject it
        requested_shards = None
    if isinstance(requested_shards, int) and requested_shards > 0:
        return min(requested_shards, MAX_SHARDS)
    if isinstance(requested_shards, str) and requested_shards.strip().isdigit():
        return min(max(1, int(requested_shards.strip())), MAX_SHARDS)
    # auto: scale to the available worker fleet so fan-out matches capacity,
    # bounded by MAX_SHARDS. Falls back to 3 when the fleet size is unknown.
    auto = max(2, min(MAX_SHARDS, int(worker_count or 0) or 3))
    return auto


def _partition_round_robin(items: list[Any], n: int) -> list[list[Any]]:
    """Split ``items`` into ``n`` round-robin buckets (balanced sizes)."""
    buckets: list[list[Any]] = [[] for _ in range(n)]
    for i, item in enumerate(items):
        buckets[i % n].append(item)
    return [b for b in buckets if b]


def _normalize_endpoint_list(endpoints: Any) -> list[str]:
    """Return non-empty, de-duplicated endpoint strings preserving order."""
    if not isinstance(endpoints, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        value = endpoint.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _endpoint_path(endpoint_spec: str) -> str:
    """Extract the path part from a custom endpoint string."""
    from urllib.parse import urlparse

    raw = endpoint_spec.strip()
    parts = raw.split(None, 2)
    if len(parts) >= 2 and parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raw = parts[1]
    if "://" not in raw:
        raw = "http://x" + (raw if raw.startswith("/") else "/" + raw)
    try:
        return urlparse(raw).path or "/"
    except Exception:
        return "/"


def _is_static_asset_endpoint(endpoint_spec: str) -> bool:
    """Return true for static asset files that should not consume active budget."""
    path = _endpoint_path(endpoint_spec).lower()
    last_segment = path.rsplit("/", 1)[-1]
    return any(last_segment.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def finding_merge_key(finding: dict[str, Any]) -> str | None:
    """Canonical key for parent shard merge dedupe.

    Scanner fingerprints can include evidence details that differ slightly per
    shard for passive/global context findings. Parent merge needs a stable
    product-level key so the same target-wide finding does not appear once per
    shard.
    """
    if not isinstance(finding, dict):
        return None
    tool = str(finding.get("tool") or finding.get("type") or "").strip().lower()
    title = str(finding.get("title") or finding.get("name") or "").strip().lower()
    severity = str(finding.get("severity") or "").strip().lower()
    if not tool and not title:
        return None
    url = str(finding.get("url") or "").strip().lower()
    parameter = str(
        finding.get("parameter")
        or finding.get("param")
        or finding.get("param_name")
        or ""
    ).strip().lower()
    cwe = str(finding.get("cwe") or "").strip().lower()
    return "|".join(["finding", tool, title, severity, url, parameter, cwe])


def _coverage_active_seconds(parent_options: dict[str, Any], endpoint_count: int) -> int:
    """Size per-shard active time so deep coverage shards can finish both families."""
    profile = str(parent_options.get("budget_profile") or "").strip().lower()
    if parent_options.get("exploit_depth") or parent_options.get("no_early_stop") or profile == "exhaustive":
        seconds_per_endpoint = 15
        ceiling = 3600
    elif profile == "thorough":
        seconds_per_endpoint = 12
        ceiling = 3000
    else:
        seconds_per_endpoint = 8
        ceiling = 2400
    return min(ceiling, max(300, seconds_per_endpoint * max(1, endpoint_count)))


def _apply_exploit_depth(options: dict[str, Any]) -> None:
    """Raise exploitation caps + disable early stop so confirmed findings get
    driven to proof instead of being capped at a few per family."""
    options["no_early_stop"] = True
    _merge_custom_budget_defaults(options, dict(EXPLOIT_DEPTH_BUDGET))


def available_auth_states(options: dict[str, Any]) -> list[str]:
    """Auth identities the parent options can exercise: always anonymous, plus
    user1 (primary creds) and user2 (secondary creds) when present."""
    states = ["anonymous"]
    if any(options.get(k) for k in _PRIMARY_AUTH_KEYS):
        states.append("user1")
    if any(options.get(k) for k in _SECONDARY_AUTH_KEYS):
        states.append("user2")
    return states


def _apply_auth_state(options: dict[str, Any], state: str) -> dict[str, Any]:
    """Return a copy of options scoped to a single auth identity."""
    o = dict(options)
    if state == "anonymous":
        for k in (*_PRIMARY_AUTH_KEYS, *_SECONDARY_AUTH_KEYS):
            o.pop(k, None)
    elif state == "user1":
        for k in _SECONDARY_AUTH_KEYS:
            o.pop(k, None)
    elif state == "user2":
        # Use ONLY the secondary identity. Never fall back to primary creds, or a
        # user2 shard given just user2_cookies would inherit user1's auth_header
        # and corrupt BOLA/IDOR results. Clear all primary creds first.
        for k in _PRIMARY_AUTH_KEYS:
            o.pop(k, None)
        if options.get("user2_header"):
            o["auth_header"] = options["user2_header"]
        if options.get("user2_cookies"):
            o["auth_cookies"] = options["user2_cookies"]
        for k in _SECONDARY_AUTH_KEYS:
            o.pop(k, None)
    o["auth_state"] = state
    return o


def _expand_auth_states(
    shards: list[ShardSpec],
    parent_options: dict[str, Any],
    notes: list[str],
    *,
    max_expanded_shards: int | None = None,
) -> list[ShardSpec]:
    """If auth-state sharding is requested and >1 identity is available, fan each
    base shard out per identity (anonymous/user1/user2).

    The caller controls the cap. When the expansion would exceed it, this
    function returns the original shards instead of truncating endpoint buckets;
    coverage planning should reduce base shard count before calling this.
    """
    if not parent_options.get("auth_state_shards"):
        return shards
    states = available_auth_states(parent_options)
    if len(states) < 2:
        notes.append("auth_state_shards requested but no credentials supplied; staying anonymous")
        return shards
    cap = max_expanded_shards if max_expanded_shards is not None else AUTH_STATE_MAX_SHARDS
    required = len(shards) * len(states)
    if required > cap:
        notes.append(
            f"auth-state expansion needs {required} shards, cap is {cap}; "
            "leaving base shards unexpanded to avoid dropping endpoint coverage"
        )
        return shards

    expanded: list[ShardSpec] = []
    for shard in shards:
        for state in states:
            opts = _apply_auth_state(shard.options, state)
            expanded.append(ShardSpec(index=len(expanded), label=f"{shard.label}:{state}", options=opts))
    for i, shard in enumerate(expanded):
        shard.index = i
    return expanded


def _finalize_shards(
    shards: list[ShardSpec],
    parent_options: dict[str, Any],
    notes: list[str],
    *,
    max_expanded_shards: int | None = None,
    global_checks_once: bool = False,
) -> list[ShardSpec]:
    """Apply cross-strategy shard transforms (exploit-depth, auth-state)."""
    if parent_options.get("exploit_depth"):
        for shard in shards:
            _apply_exploit_depth(shard.options)
    shards = _expand_auth_states(
        shards,
        parent_options,
        notes,
        max_expanded_shards=max_expanded_shards,
    )
    if global_checks_once:
        seen_auth_states: set[str] = set()
        for shard in shards:
            state = str(shard.options.get("auth_state") or "anonymous")
            if state in seen_auth_states:
                shard.options["skip_global_checks"] = True
            else:
                shard.options["skip_global_checks"] = False
                seen_auth_states.add(state)
    return shards


def harvest_endpoints(recon_result: Any, *, max_endpoints: int = COVERAGE_WORKLIST_MAX) -> list[str]:
    """Extract a testable endpoint worklist ("METHOD /path?query" strings) from a
    discover-once recon scan result. Endpoints that carry query params (the ones
    worth active injection testing) are ordered first. Defensive against the many
    discovery shapes the scanner emits."""
    from urllib.parse import urlparse

    rep = recon_result or {}

    # Preferred source: the scanner's FULL emitted worklist (already
    # custom-endpoint strings, pre-cap). Gives true ~100% coverage. Falls back
    # to discovery samples for older scanners that don't emit it.
    worklist = ((rep.get("active_checks") or {}).get("active_worklist"))
    if isinstance(worklist, list) and worklist:
        full = _normalize_endpoint_list([w for w in worklist if isinstance(w, str)])
        if full:
            return [endpoint for endpoint in full if not _is_static_asset_endpoint(endpoint)][:max_endpoints]

    # `discovery` is a TOP-LEVEL report section (report['result'] is only the
    # grade block). Fall back to the nested location defensively.
    disc = rep.get("discovery")
    if not isinstance(disc, dict):
        disc = ((rep.get("result") or {}).get("discovery")) or {}
    with_params: list[str] = []
    without_params: list[str] = []
    seen: set[str] = set()

    def add(method: Any, url: Any) -> None:
        if not url or not isinstance(url, str):
            return
        raw = url.strip()
        if not raw:
            return
        try:
            if "://" in raw:
                pu = urlparse(raw)
            else:
                pu = urlparse("http://x" + (raw if raw.startswith("/") else "/" + raw))
        except Exception:
            return
        path = pu.path or "/"
        key = f"{(method or 'GET').upper()} {path}?{pu.query}" if pu.query else f"{(method or 'GET').upper()} {path}"
        if key in seen:
            return
        if _is_static_asset_endpoint(key):
            return
        seen.add(key)
        (with_params if pu.query else without_params).append(key)

    def add_list(items: Any, default_method: str = "GET") -> None:
        for e in items or []:
            if isinstance(e, str):
                add(default_method, e)
            elif isinstance(e, dict):
                add(e.get("method") or default_method, e.get("url") or e.get("path"))

    add_list(disc.get("browser_api_endpoints"))
    har = disc.get("har_discovery") or {}
    if isinstance(har, dict):
        add_list(har.get("endpoints"))
    jb = disc.get("js_bundle_analysis") or {}
    if isinstance(jb, dict):
        add_list(jb.get("api_endpoints"))
        add_list(jb.get("routes"))
        add_list(jb.get("internal_urls"))
    add_list(disc.get("katana_sample"))
    sm = disc.get("smart_discovery") or {}
    if isinstance(sm, dict):
        for k in ("api_endpoints_sample", "probed_endpoints_sample",
                  "all_urls_sample", "recursive_paths_sample"):
            add_list(sm.get(k))

    return (with_params + without_params)[:max_endpoints]


def plan_coverage_shards(
    parent_options: dict[str, Any],
    endpoints: Any,
    *,
    per_shard_cap: int | None = None,
    max_shards: int | None = None,
    notes: list[str] | None = None,
) -> "ParallelPlan":
    """Partition a discovered endpoint worklist across N=ceil(len/cap) shards.

    The plan handler harvests ``endpoints`` from a single discover-once recon
    pass; child shards then run the full active suite over only their assigned
    slice in zero-rediscovery mode.
    """
    notes = notes if notes is not None else []
    if max_shards is None:
        try:
            max_shards = int(parent_options.get("coverage_max_shards") or COVERAGE_MAX_SHARDS)
        except (TypeError, ValueError):
            max_shards = COVERAGE_MAX_SHARDS
    max_shards = max(2, min(COVERAGE_MAX_SHARDS, int(max_shards)))

    # Honor an explicit `shards` request as a HARD upper bound on the coverage
    # fan-out. Least-surprise: a user capping shards (e.g. to avoid DoSing a
    # small single-process target) must not be silently overridden by
    # auto-sizing. "auto"/absent -> auto-size as before. Endpoints are preserved
    # by using larger per-shard slices (handled below).
    _req = parent_options.get("shards")
    if isinstance(_req, bool):
        _req = None
    _req_n = None
    if isinstance(_req, int) and _req > 0:
        _req_n = _req
    elif isinstance(_req, str) and _req.strip().isdigit():
        _req_n = int(_req.strip())
    if _req_n:
        capped = max(2, min(max_shards, _req_n))
        if capped < max_shards:
            notes.append(
                f"coverage: capping fan-out to requested {_req_n} shard(s) "
                f"(auto-size would allow up to {max_shards}); per-shard slices grow accordingly"
            )
        max_shards = capped

    auth_state_count = 1
    if parent_options.get("auth_state_shards"):
        auth_state_count = max(1, len(available_auth_states(parent_options)))
    expanded_cap = COVERAGE_MAX_TOTAL_SHARDS
    if auth_state_count > 1:
        max_base_for_auth = max(1, expanded_cap // auth_state_count)
        if max_shards > max_base_for_auth:
            notes.append(
                f"coverage max shards reduced from {max_shards} to {max_base_for_auth} "
                f"to preserve all endpoints across {auth_state_count} auth states"
            )
            max_shards = max_base_for_auth

    # Tunable per-shard endpoint cap: smaller cap -> more (smaller) shards.
    if per_shard_cap is None:
        try:
            per_shard_cap = int(parent_options.get("coverage_per_shard_cap") or COVERAGE_PER_SHARD_CAP)
        except (TypeError, ValueError):
            per_shard_cap = COVERAGE_PER_SHARD_CAP
    per_shard_cap = max(1, per_shard_cap)
    eps = _normalize_endpoint_list(endpoints)

    def _coverage_child_options(slice_eps: list[str]) -> dict[str, Any]:
        opts = _base_child_options(parent_options)
        opts["custom_endpoints"] = slice_eps
        opts["focused_endpoints_only"] = True
        opts["zero_rediscovery"] = True
        opts["no_early_stop"] = True
        cnt = max(1, len(slice_eps))
        # Endpoints are injected, so skip discovery work and run the full active
        # suite deeply over every endpoint in the assigned slice.
        _merge_custom_budget_defaults(
            opts,
            {
                "max_urls": max(200, min(1000, cnt + 50)),
                "browser_max_pages": 0,
                "browser_max_depth": 1,
                "discovery_depth": 1,
                "api_probe_limit": 0,
                "param_discovery_url_limit": 0,
                "param_discovery_max_params": 0,
                "nuclei_max_targets": 0,
                "active_max_endpoints": cnt,
                "active_max_seconds": _coverage_active_seconds(parent_options, cnt),
                "active_params_per_endpoint": 8,
                "smart_bola_max_endpoints": cnt,
            },
        )
        return opts

    if len(eps) < 2:
        notes.append(f"coverage: only {len(eps)} endpoints to partition; single shard")
        opts = _coverage_child_options(eps) if eps else _base_child_options(parent_options)
        shards = _finalize_shards(
            [ShardSpec(0, "coverage[0]", opts)],
            parent_options,
            notes,
            max_expanded_shards=expanded_cap,
            global_checks_once=True,
        )
        if eps:
            notes.append("coverage: zero-rediscovery shards skip crawl, parameter discovery, and nuclei")
        return ParallelPlan(strategy="coverage", shards=shards, notes=notes)

    import math
    n = max(1, min(max_shards, math.ceil(len(eps) / max(1, per_shard_cap))))
    buckets = _partition_round_robin(eps, n)
    if len(eps) > len(buckets) * per_shard_cap:
        notes.append(
            f"coverage: {len(eps)} endpoints exceed {len(buckets)} shards x {per_shard_cap} cap; "
            "using larger per-shard slices to preserve endpoint coverage"
        )
    biggest = max((len(b) for b in buckets), default=0)
    if biggest > ACTIVE_ENDPOINTS_CEILING:
        notes.append(
            f"coverage: largest shard slice ({biggest}) exceeds the active_max_endpoints "
            f"ceiling ({ACTIVE_ENDPOINTS_CEILING}); raise coverage_max_shards or lower "
            "coverage_per_shard_cap to keep every endpoint actively tested"
        )
    shards: list[ShardSpec] = []
    for i, slice_eps in enumerate(buckets):
        opts = _coverage_child_options(slice_eps)
        shards.append(ShardSpec(index=i, label=f"coverage[{i}]", options=opts))
    shards = _finalize_shards(
        shards,
        parent_options,
        notes,
        max_expanded_shards=expanded_cap,
        global_checks_once=True,
    )
    notes.append("coverage: zero-rediscovery shards skip crawl, parameter discovery, and nuclei")
    return ParallelPlan(strategy="coverage", shards=shards, notes=notes)


def coverage_allocation_mode(parent_options: dict[str, Any]) -> str:
    """Resolve Full Coverage allocation mode.

    ``static`` keeps the shipped round-robin endpoint slices. ``dynamic`` uses
    campaign-scoped inventory claims so child jobs pull work at execution time.
    """
    raw = str(parent_options.get("coverage_allocation") or "").strip().lower()
    if not raw and parent_options.get("dynamic_coverage_allocation") is not None:
        raw = "dynamic" if parent_options.get("dynamic_coverage_allocation") else "static"
    if raw in {"dynamic", "pull", "allocator", "campaign"}:
        return "dynamic"
    return "static"


def _coverage_dynamic_batch_size(parent_options: dict[str, Any]) -> int:
    raw = (
        parent_options.get("coverage_dynamic_batch_size")
        or parent_options.get("coverage_per_shard_cap")
        or COVERAGE_DYNAMIC_BATCH_SIZE
    )
    try:
        value = int(raw)
    except (TypeError, ValueError):
        value = COVERAGE_DYNAMIC_BATCH_SIZE
    return max(1, value)


def plan_dynamic_coverage_shards(
    parent_options: dict[str, Any],
    endpoint_count: int,
    *,
    auth_state_count: int = 1,
    notes: list[str] | None = None,
) -> ParallelPlan:
    """Plan pull-based Full Coverage workers over a campaign-scoped inventory.

    These children do not receive static endpoint slices. Each child job claims
    a small batch from ``target_endpoints`` when it starts, so faster workers can
    keep pulling the next eligible batch instead of waiting behind a large static
    shard.
    """
    notes = notes if notes is not None else []
    batch_size = _coverage_dynamic_batch_size(parent_options)
    total = max(0, int(endpoint_count or 0)) * max(1, int(auth_state_count or 1))
    if total < 1:
        notes.append("coverage dynamic allocation requested but no endpoints were harvested")
        return ParallelPlan(strategy="coverage", shards=[], notes=notes)

    import math

    try:
        max_batches = int(parent_options.get("coverage_dynamic_max_batches") or COVERAGE_MAX_DYNAMIC_BATCHES)
    except (TypeError, ValueError):
        max_batches = COVERAGE_MAX_DYNAMIC_BATCHES
    max_batches = max(1, min(COVERAGE_MAX_DYNAMIC_BATCHES, max_batches))
    shard_count = max(1, min(max_batches, math.ceil(total / batch_size)))
    if shard_count * batch_size < total:
        notes.append(
            f"coverage dynamic allocation capped at {shard_count} batches x {batch_size}; "
            "raise coverage_dynamic_max_batches or lower coverage_dynamic_batch_size for full fan-out"
        )
    notes.append(
        f"coverage: dynamic campaign allocation with {shard_count} pull worker(s), "
        f"batch_size={batch_size}, eligible_auth_scoped_endpoints={total}"
    )

    shards: list[ShardSpec] = []
    for i in range(shard_count):
        opts = _base_child_options(parent_options)
        opts["coverage_allocation"] = "dynamic"
        opts["coverage_dynamic_worker"] = True
        opts["coverage_dynamic_batch_size"] = batch_size
        opts["coverage_dynamic_campaign_only"] = True
        opts["coverage_stale_days"] = 0
        opts["focused_endpoints_only"] = True
        opts["zero_rediscovery"] = True
        opts["skip_global_checks"] = True
        opts["no_early_stop"] = True
        _merge_custom_budget_defaults(
            opts,
            {
                "max_urls": 200,
                "browser_max_pages": 0,
                "browser_max_depth": 1,
                "discovery_depth": 1,
                "api_probe_limit": 0,
                "param_discovery_url_limit": 0,
                "param_discovery_max_params": 0,
                "nuclei_max_targets": 0,
                "active_max_endpoints": batch_size,
                "active_max_seconds": _coverage_active_seconds(parent_options, batch_size),
                "active_params_per_endpoint": 8,
                "smart_bola_max_endpoints": batch_size,
            },
        )
        shards.append(ShardSpec(index=i, label=f"coverage-dynamic[{i}]", options=opts))
    return ParallelPlan(strategy="coverage", shards=shards, notes=notes)


def _plan_scope(
    parent_options: dict[str, Any],
    endpoints: list[str],
    requested: int,
    notes: list[str],
) -> list[ShardSpec]:
    n = min(requested, len(endpoints))
    if n < 2:
        notes.append(
            f"scope strategy needs >=2 endpoints to fan out; got {len(endpoints)} "
            "- falling back to a single shard"
        )
    buckets = _partition_round_robin(list(endpoints), max(1, n))
    if len(buckets) < n:
        notes.append(f"scope shards reduced to {len(buckets)} (fewer endpoints than requested)")
    shards: list[ShardSpec] = []
    for i, slice_eps in enumerate(buckets):
        opts = _base_child_options(parent_options)
        opts["custom_endpoints"] = slice_eps
        # Endpoints are explicit, so a deep site crawl per shard is wasted work.
        # Trim discovery and active breadth unless the caller provided stricter
        # custom caps. This is the raw speed path for known API endpoints.
        endpoint_count = max(1, len(slice_eps))
        _merge_custom_budget_defaults(
            opts,
            {
                "max_duration_minutes": max(5, min(10, 4 + (2 * endpoint_count))),
                "max_urls": 150,
                "browser_max_pages": 5,
                "browser_max_depth": 1,
                "param_discovery_url_limit": min(endpoint_count, 3),
                "param_discovery_max_params": 4,
                "nuclei_max_targets": 120,
                "phase4_max_seconds": 20,
                "active_max_seconds": min(120, max(60, 30 * endpoint_count)),
                "active_max_endpoints": endpoint_count,
                "active_params_per_endpoint": 2,
                "smart_bola_max_endpoints": endpoint_count,
            },
        )
        shards.append(ShardSpec(index=i, label=f"scope[{i}]", options=opts))
    return shards


def _plan_family(
    parent_options: dict[str, Any],
    scan_type: str,
    requested: int,
    notes: list[str],
) -> list[ShardSpec]:
    if scan_type not in ACTIVE_SCAN_TYPES:
        notes.append(
            f"family strategy is only meaningful for active scan types "
            f"({', '.join(sorted(ACTIVE_SCAN_TYPES))}); '{scan_type}' is passive "
            "- running a single broad shard"
        )
        broad = _base_child_options(parent_options)
        return [ShardSpec(index=0, label="broad", options=broad)]

    # broad: full breadth at the parent budget (all active families).
    broad = _base_child_options(parent_options)

    # sqli: focused, deeper. Disable XSS so the scanner enters focused mode and
    # limits active modules to SQLi; bump depth/budget.
    sqli = _base_child_options(parent_options)
    sqli.update({"sqli": True, "xss": False, "no_early_stop": True, "thorough_params": True})
    if (sqli.get("budget_profile") or "balanced") in ("fast", "balanced"):
        sqli["budget_profile"] = "thorough"

    xss = _base_child_options(parent_options)
    xss.update({"xss": True, "sqli": False, "no_early_stop": True, "thorough_params": True})
    if (xss.get("budget_profile") or "balanced") in ("fast", "balanced"):
        xss["budget_profile"] = "thorough"

    ordered = [
        ShardSpec(index=0, label="broad", options=broad),
        ShardSpec(index=1, label="sqli", options=sqli),
        ShardSpec(index=2, label="xss", options=xss),
    ]

    n = min(requested, len(FAMILY_SHARD_LABELS))
    if requested > len(FAMILY_SHARD_LABELS):
        notes.append(
            f"family strategy caps at {len(FAMILY_SHARD_LABELS)} shards "
            f"(broad/sqli/xss); requested {requested}"
        )
    selected = ordered[:n]
    for i, shard in enumerate(selected):  # reindex contiguously
        shard.index = i
    return selected


def plan_shards(
    parent_options: dict[str, Any],
    *,
    scan_type: str,
    requested_shards: Any = "auto",
    strategy: str = "auto",
    worker_count: int = 0,
) -> ParallelPlan:
    """Build a ParallelPlan from parent scan options.

    Args:
        parent_options: the parent scan's options dict (as submitted).
        scan_type: resolved scan type (quick/standard/deep/full/aggressive/smart).
        requested_shards: int, numeric string, or "auto".
        strategy: "auto" | "scope" | "family" | "coverage".
        worker_count: current worker fleet size (used to auto-scale shards).
    """
    notes: list[str] = []
    strategy = (strategy or "auto").strip().lower()
    if strategy not in VALID_STRATEGIES:
        notes.append(f"unknown strategy '{strategy}', defaulting to auto")
        strategy = "auto"

    scan_type = (scan_type or "standard").strip().lower()
    endpoints = _normalize_endpoint_list(parent_options.get("custom_endpoints"))

    resolved = strategy
    if strategy == "auto":
        resolved = "scope" if len(endpoints) >= 2 else "family"
    if resolved == "coverage":
        # coverage needs a harvested worklist that only the plan handler can
        # produce (discover-once recon). plan_shards is pure, so degrade safely.
        notes.append("coverage strategy requires the plan stage's recon pass; falling back to family")
        resolved = "family"

    requested = _coerce_shard_request(requested_shards, worker_count)

    if resolved == "scope":
        if len(endpoints) < 2:
            notes.append("no endpoint list to partition; switching to family strategy")
            resolved = "family"
        else:
            shards = _finalize_shards(_plan_scope(parent_options, endpoints, requested, notes),
                                      parent_options, notes)
            return ParallelPlan(strategy="scope", shards=shards, notes=notes)

    shards = _finalize_shards(_plan_family(parent_options, scan_type, requested, notes),
                              parent_options, notes)
    return ParallelPlan(strategy="family", shards=shards, notes=notes)


# ---------------------------------------------------------------------------
# Orchestration helpers (Redis keys + merge reconciliation)
# ---------------------------------------------------------------------------

def shards_remaining_key(parent_id: str) -> str:
    return f"scan:{parent_id}:shards:remaining"


def merge_guard_key(parent_id: str) -> str:
    return f"scan:{parent_id}:merge:enqueued"


def merge_job(parent_id: str) -> dict[str, Any]:
    """Build the scan_merge job payload for a parent scan."""
    return {"type": MERGE_JOB_TYPE, "parent_scan_id": parent_id}


def aggregate_shard_coverage(strategy: str | None, shard_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Build parent smart_coverage fields from shard reports.

    For scope/coverage strategies the assigned ``custom_endpoints`` are the
    authoritative split contract. Per-shard scanner coverage is useful context,
    but its ``discovered`` denominator is local to a child scan and can wildly
    overstate parent coverage when merged with ``max(discovered)``. Use the
    union of assigned endpoints for parent endpoint coverage and expose
    endpoint-auth attempts separately when auth-state shards repeat the same
    endpoint under multiple identities.
    """
    records = shard_records or []
    covs = [r.get("smart_coverage") for r in records if isinstance(r.get("smart_coverage"), dict) and r.get("smart_coverage")]
    if not records:
        return {}

    def _ep(c: dict[str, Any], key: str) -> int:
        try:
            return int(((c.get("endpoints") or {}).get(key)) or 0)
        except (TypeError, ValueError):
            return 0

    normalized_strategy = (strategy or "").strip().lower()
    disjoint_strategy = normalized_strategy in {"scope", "coverage"}
    all_assigned: set[str] = set()
    completed_assigned: set[str] = set()
    assigned_attempts = 0
    completed_attempts = 0
    for record in records:
        options = record.get("options") if isinstance(record.get("options"), dict) else {}
        endpoints = _normalize_endpoint_list(options.get("custom_endpoints"))
        if not endpoints:
            continue
        all_assigned.update(endpoints)
        assigned_attempts += len(endpoints)
        if record.get("status") == "completed":
            completed_assigned.update(endpoints)
            completed_attempts += len(endpoints)

    endpoints_summary: dict[str, Any]
    if disjoint_strategy and all_assigned:
        discovered = len(all_assigned)
        tested = min(discovered, len(completed_assigned))
        endpoints_summary = {
            "discovered": discovered,
            "tested": tested,
            "coverage": round(tested / discovered, 3) if discovered else 0.0,
            "basis": "assigned_custom_endpoints",
        }
        if assigned_attempts != discovered:
            endpoints_summary["auth_attempts_assigned"] = assigned_attempts
            endpoints_summary["auth_attempts_completed"] = completed_attempts
            endpoints_summary["auth_attempt_coverage"] = (
                round(completed_attempts / assigned_attempts, 3) if assigned_attempts else 0.0
            )
    elif covs:
        discovered = max((_ep(c, "discovered") for c in covs), default=0)
        if disjoint_strategy:
            tested = min(discovered or 10**9, sum(_ep(c, "tested") for c in covs))
        else:
            tested = max((_ep(c, "tested") for c in covs), default=0)
        endpoints_summary = {
            "discovered": discovered,
            "tested": tested,
            "coverage": round(tested / discovered, 3) if discovered else 0.0,
            "basis": "shard_smart_coverage",
        }
    else:
        return {}

    auth_state_values = {
        str(state)
        for c in covs
        for state in (c.get("auth_states_tested") or [])
        if state
    }
    for record in records:
        options = record.get("options") if isinstance(record.get("options"), dict) else {}
        state = options.get("auth_state")
        if record.get("status") == "completed" and state:
            auth_state_values.add(str(state))
    auth_states = sorted(auth_state_values)
    sources = sorted({
        str(source)
        for c in covs
        for source in (c.get("discovery_sources") or [])
        if source
    })
    out: dict[str, Any] = {
        "endpoints": endpoints_summary,
        "aggregated_from_shards": len(records),
        "coverage_reports_from_shards": len(covs),
    }
    if auth_states:
        out["auth_states_tested"] = auth_states
    if sources:
        out["discovery_sources"] = sources
    return out


async def reconcile_parallel_parent(conn, parent_id: str, redis_client, queue_name: str) -> bool:
    """Enqueue the merge job once all of a parent's shards are terminal.

    Safe to call repeatedly and from multiple processes: the actual enqueue is
    guarded by a Redis SET NX so the merge runs exactly once. Returns True iff
    this call enqueued the merge.
    """
    pid = uuid.UUID(parent_id)
    parent_status = await conn.fetchval("SELECT status FROM scans WHERE id = $1", pid)
    if parent_status == "cancelled":
        try:
            redis_client.set(merge_guard_key(parent_id), "cancelled", nx=True, ex=86400)
        except Exception:
            pass
        return False
    total = await conn.fetchval(
        "SELECT count(*) FROM scans WHERE parent_scan_id = $1", pid
    )
    if not total:
        return False
    non_terminal = await conn.fetchval(
        """
        SELECT count(*) FROM scans
        WHERE parent_scan_id = $1 AND status NOT IN ('completed', 'failed', 'cancelled')
        """,
        pid,
    )
    if non_terminal:
        return False
    # All shards terminal — enqueue merge exactly once. Put merge jobs at the
    # front of the shared scan queue so completed parents finalize before new
    # shard work starts behind them.
    if redis_client.set(merge_guard_key(parent_id), "1", nx=True, ex=86400):
        redis_client.lpush(queue_name, json.dumps(merge_job(parent_id)))
        return True
    return False
