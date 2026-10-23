"""Canonical Scan V2 request resolution."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping

try:
    from check_registry import get_check_family, normalize_scan_policy_families
except ModuleNotFoundError:
    from ..check_registry import get_check_family, normalize_scan_policy_families

try:
    from runtime.models import ScanBudget, ScanPolicy
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.models import ScanBudget, ScanPolicy

try:
    from runtime.credentials import HTTP_CREDENTIAL_KINDS
    from runtime.request_collection_store import REPLAY_POLICIES
    from runtime.scan_credentials import (
        SCAN_SEMANTIC_CREDENTIAL_CAPABILITIES,
    )
except ModuleNotFoundError:  # package import in host-side tests
    from ..runtime.credentials import HTTP_CREDENTIAL_KINDS
    from ..runtime.request_collection_store import REPLAY_POLICIES
    from ..runtime.scan_credentials import (
        SCAN_SEMANTIC_CREDENTIAL_CAPABILITIES,
    )

from .execution import ScanExecutionPlan

# These are hard ceilings, not target runtimes. Batch planning and continuation
# decide how much can be spent, while advanced limits may only lower these values.
# Tool wall never exceeds total wall, so every advertised dimension is reachable.
BUDGET_PROFILES: Mapping[str, ScanBudget] = {
    "fast": ScanBudget(1_800, 5_000, 2_500, 250, 5_000, 1_500, 2, 500, 50),
    "balanced": ScanBudget(3_600, 20_000, 10_000, 1_000, 20_000, 3_600, 4, 2_000, 200),
    "thorough": ScanBudget(10_800, 60_000, 30_000, 3_000, 60_000, 10_800, 8, 6_000, 1_000),
    "deep": ScanBudget(21_600, 150_000, 75_000, 7_500, 150_000, 21_600, 16, 15_000, 2_500),
}
# The profiles whose plans are sized for the work to finish, not only to fit: their tool wall
# follows a lowered duration, their SQLi extensions hold the wall their remaining techniques
# need, later rounds step down to a slice the residual can fund, and their direct Scans run
# every active-template window. Fast and balanced plans are unchanged.
BUDGET_SUFFICIENCY_PROFILES = frozenset({"thorough", "deep"})


def budget_sufficiency(profile: Any) -> bool:
    """Whether a Scan of this budget profile plans its work to completion (see above)."""
    return str(profile or "").strip().lower() in BUDGET_SUFFICIENCY_PROFILES

# These are the only family names with concrete canonical action-graph semantics.
# The broader check registry remains available to ASM; accepting unimplemented
# names here would create a successful no-op Scan.
SCAN_V2_FAMILY_NAMES = (
    "recon", "nuclei_passive", "nuclei_active", "xss", "sqli", "bola",
    "sensitive_exposure", "nosqli", "authz_surface", "graphql", "recon_active",
)
# Families that examine the application itself: they discover its surface or test what was
# discovered. sensitive_exposure alone only reads a fixed list of well-known locations (its
# discovered-endpoint sweep needs recon to discover anything), so a plan of it alone is not
# an application assessment (soak N46).
SCAN_APPLICATION_SURFACE_FAMILIES = frozenset(SCAN_V2_FAMILY_NAMES) - {"sensitive_exposure"}
SCAN_FAMILY_PRESETS: Mapping[str, tuple[str, ...]] = {
    # sensitive_exposure is read-only GET traffic (ADR 0001 passive) and the only family
    # that verifies exposed .env, .git, actuator, OpenAPI-secret, backup and debug
    # files. Kept opt-in behind a Lab/deep gate it never ran: every soak Scan of the
    # honeypot verified none of the four exposures a Hunt proved in seconds.
    "passive": ("recon", "nuclei_passive", "sensitive_exposure"),
    "standard_active": ("recon", "nuclei_passive", "xss", "sqli", "sensitive_exposure"),
    "custom": (),
}
# Families a preset adds on a budget profile. The thorough and deep profiles hold the wall to run
# every active-template window, so their standard active set runs the active templates too; a
# fast or balanced one does not, and an operator adds them there with include_families. The
# sweep holds thousands of requests at admission (and one mutation for each when state-changing
# HTTP is allowed), so a Scan whose operator lowered the request or mutation ceiling below the
# profile's keeps the standard set without them, and is admitted exactly as before; naming
# nuclei_active still adds them.
SCAN_FAMILY_PRESET_PROFILE_ADDITIONS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "standard_active": {"thorough": ("nuclei_active",), "deep": ("nuclei_active",)},
}


def scan_family_preset_families(
    preset: str, budget_profile: str | None, *, lowered_request_ceiling: bool = False,
) -> tuple[str, ...]:
    """The families ``preset`` selects on ``budget_profile``, in canonical family order."""
    additions = () if lowered_request_ceiling else SCAN_FAMILY_PRESET_PROFILE_ADDITIONS.get(
        preset, {},
    ).get(str(budget_profile or "balanced").strip().lower(), ())
    chosen = set(SCAN_FAMILY_PRESETS[preset]) | set(additions)
    return tuple(family for family in SCAN_V2_FAMILY_NAMES if family in chosen)


def _lowers_request_ceiling(
    profile: str, advanced: Mapping[str, Any] | None, *, state_changing_allowed: bool,
) -> bool:
    """Whether ``advanced`` lowers the profile's request (or, when used, mutation) ceiling."""
    budget = BUDGET_PROFILES.get(profile)
    if budget is None or not isinstance(advanced, Mapping):
        return False
    limits = ["max_http_requests"] + (["max_state_changing_requests"] if state_changing_allowed else [])
    for name in limits:
        value = advanced.get(name)
        if value is None or isinstance(value, bool):
            continue
        try:
            if int(value) < int(getattr(budget, name)):
                return True
        except (TypeError, ValueError):
            continue
    return False
# The minimum candidates a profile's ROOT plan executes per family when the target
# offers them. These are what the profile can actually run at the measured cost of
# an attempt (an external XSS candidate holds 200 s, a SQLi candidate 180 s), not a
# breadth promise: the old quotas assumed 30-second candidates and were met only by
# wall-killing every attempt. Continuation rounds add breadth beyond these floors.
SCAN_MINIMUM_FAMILY_QUOTAS: Mapping[str, Mapping[str, int]] = {
    "fast": {"xss": 1, "sqli": 1, "sensitive_exposure": 5, "nosqli": 5, "authz_surface": 5,
             "graphql": 5},
    "balanced": {"xss": 4, "sqli": 4, "sensitive_exposure": 10, "nosqli": 10, "authz_surface": 10,
                 "graphql": 10},
    "thorough": {"xss": 12, "sqli": 16, "sensitive_exposure": 20, "nosqli": 25, "authz_surface": 20,
                 "graphql": 20},
    "deep": {"xss": 24, "sqli": 32, "sensitive_exposure": 50, "nosqli": 50, "authz_surface": 50,
             "graphql": 50},
}
_SCAN_V2_FAMILY_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "recon": (
        "web.probe", "web.crawl", "web.browser_crawl", "web.content_discover",
        "web.spec_ingest",
    ),
    "nuclei_passive": ("templates.passive_batch",),
    "nuclei_active": ("templates.active_batch",),
    "xss": ("xss.verify_batch", "xss.request_verify_batch"),
    "sqli": ("sqli.verify_batch", "sqli.request_verify_batch"),
    "bola": ("authz.verify",),
    "sensitive_exposure": ("exposure.verify_batch",),
    "nosqli": ("nosqli.verify_batch",),
    "authz_surface": ("authz_surface.verify_batch",),
    "graphql": ("graphql.verify_batch",),
    # Parameter discovery first: it is the one recon_active action every web Scan can plan.
    "recon_active": ("web.param_discover", "vhost.discover", "dns.enumerate"),
}
# Proof capabilities are additional verifiers a family may escalate to after its
# batch action produces a candidate. They are part of the family's authority even
# though the family is complete without them.
_SCAN_V2_FAMILY_PROOF_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    # The open-redirect probe reads the same discovered query parameters (see action_plan).
    "xss": ("xss.browser_prove_batch", "redirect.verify_batch"),
    "sqli": ("sqli.prove_batch",),
}


def scan_family_required_capability(family: str) -> str | None:
    """The capability whose absence means the family did not run at all."""
    capabilities = _SCAN_V2_FAMILY_CAPABILITIES.get(family) or ()
    spec = get_check_family(family)
    if not capabilities or spec is None or not spec.is_active:
        return None
    return capabilities[0]


def scan_family_capabilities(family: str) -> tuple[str, ...]:
    """Every capability a selected family may execute, proof verifiers included.

    Callers must not maintain their own family-to-capability table. The
    continuation allocation did, and it still named the pre-batching
    ``xss.verify``/``sqli.verify`` capabilities, so a continuation that
    legitimately compiled ``xss.verify_batch`` was rejected as outside its
    allocation.

    A passive family has real execution authority. Gating this accessor on
    ``is_active`` -- which only answers "did this active family run at all?"
    for :func:`scan_family_required_capability` -- discarded the capabilities
    ``recon`` and ``nuclei_passive`` correctly declare below. That left the
    default passive Scan with an empty continuation allowlist, so the first
    continuation to compile ``templates.passive_batch`` was rejected as
    outside its own allocation and the scan failed. An unknown family still
    fails closed.
    """
    spec = get_check_family(family)
    if spec is None:
        return ()
    return (
        *(_SCAN_V2_FAMILY_CAPABILITIES.get(family) or ()),
        *(_SCAN_V2_FAMILY_PROOF_CAPABILITIES.get(family) or ()),
    )


_SCAN_V2_BASELINE_CAPABILITIES = (
    "scan.origin_select", "http.request", "dns.inspect", "infrastructure.inspect", "tls.inspect",
)
SCAN_V2_ZEROABLE_LIMITS = frozenset({"max_state_changing_requests"})
SCAN_V2_INTERACTIVE_AUTH_KINDS = frozenset({
    "form_login", "oauth_client_credentials", "oauth_password", "json_login",
})
SCAN_V2_SECONDARY_AUTH_KINDS = frozenset({
    "authorization_header", "bearer_token", "cookie", "basic_auth", "form_login",
})

_BUDGET_CEILINGS = {
    "max_duration_seconds": 172_800,
    "max_http_requests": 1_000_000,
    "max_endpoints": 100_000,
    "max_browser_actions": 20_000,
    "max_tcp_ports": 262_140,
    "max_tool_wall_seconds": 86_400,
    "max_workers": 128,
    "max_state_changing_requests": 100_000,
    "max_hosts": 100_000,
}

SCAN_AUTHENTICATION_KEYS = frozenset({
    "auth_cookies", "auth_header", "auth_headers_json", "auth_scenario_json",
    "login_url", "login_username", "login_password", "login_extra_fields", "auto_auth",
    "disposable_login_credentials",
    "oauth_client_id", "oauth_client_secret", "oauth_token_url", "oauth_scope",
    "oauth_username", "oauth_password", "user2_cookies", "user2_header",
    "user2_login_url", "user2_login_username", "user2_login_password",
    # Worker-private projection used only to create an ephemeral, target-bound
    # headless-browser profile. Public Scan payloads may never provide it.
    "auth_browser_storage",
    # Legacy managed references survived into a worker hydration path that decrypts without the
    # canonical approval, profile-version, target-kind, capability-allowlist and placement checks.
    # credential_profile_ids is the validated replacement, so the legacy key is refused as raw
    # authentication wherever options are admitted.
    "managed_credential_profiles",
})


def scan_authentication_value_present(value: Any) -> bool:
    """Return whether an authentication field carries executable private material."""
    if isinstance(value, bool):
        return value
    return value not in (None, "", [], {})


def raw_scan_authentication_keys(options: Mapping[str, Any] | None) -> list[str]:
    """Return the raw authentication keys present in a scan-options mapping.

    Every boundary that admits scan options -- the direct route, schedules, target and ASM paths --
    must refuse the same set, so they share this helper rather than each keeping a list that drifts
    out of step with :data:`SCAN_AUTHENTICATION_KEYS`.
    """
    if not isinstance(options, Mapping):
        return []
    return sorted(
        key for key in SCAN_AUTHENTICATION_KEYS
        if scan_authentication_value_present(options.get(key))
    )


def public_scan_contract() -> dict[str, Any]:
    """Return the generated UI/CLI contract for one canonical deterministic Scan."""
    families: list[dict[str, Any]] = []
    for name in SCAN_V2_FAMILY_NAMES:
        specification = get_check_family(name)
        if specification is None:  # pragma: no cover - guarded by contract tests
            raise RuntimeError(f"canonical Scan family {name} is not registered")
        families.append({
            "name": specification.name,
            "label": specification.label,
            "description": specification.description,
            "risk_level": specification.risk_level,
            "requires_active_testing": bool(specification.is_active),
            "requires_credentials": specification.requires_credentials,
            "default_enabled": name in SCAN_FAMILY_PRESETS["passive"],
            "capabilities": list(_SCAN_V2_FAMILY_CAPABILITIES[name]),
        })
    limits = []
    profile_dicts = {
        name: asdict(budget) for name, budget in BUDGET_PROFILES.items()
    }
    for name, maximum in _BUDGET_CEILINGS.items():
        limits.append({
            "name": name,
            "minimum": 0 if name in SCAN_V2_ZEROABLE_LIMITS else 1,
            "maximum": maximum,
            "profile_ceilings": {
                profile: int(values[name]) for profile, values in profile_dicts.items()
            },
        })
    return {
        "schema_version": "scan-public-contract/v1",
        "generation": "v2",
        "engine": "scan",
        "execution_plan_schema": "scan-execution-plan/v1",
        "action_plan_schema": "scan-action-plan/v1",
        "budget_profiles": profile_dicts,
        "advanced_limits": limits,
        "families": families,
        "family_presets": {
            name: list(families) for name, families in SCAN_FAMILY_PRESETS.items()
        },
        # What a preset adds on a budget profile (standard_active runs the active templates on
        # thorough and deep).
        "family_preset_profile_additions": {
            preset: {profile: list(families) for profile, families in additions.items()}
            for preset, additions in SCAN_FAMILY_PRESET_PROFILE_ADDITIONS.items()
        },
        "passive_coverage": {
            "description": (
                "Every passive Scan runs the target baseline, surface discovery, "
                "the reviewed read-only template pack and the read-only verified "
                "exposure checks unless a family is excluded."
            ),
            "baseline_capabilities": list(_SCAN_V2_BASELINE_CAPABILITIES),
            "default_families": list(SCAN_FAMILY_PRESETS["passive"]),
        },
        "credentials": {
            "supported_auth_kinds": sorted(
                set(HTTP_CREDENTIAL_KINDS) - {"query_parameter"}
            ),
            "interactive_auth_kinds": sorted(SCAN_V2_INTERACTIVE_AUTH_KINDS),
            "secondary_auth_kinds": sorted(SCAN_V2_SECONDARY_AUTH_KINDS),
            "semantic_capabilities": sorted(SCAN_SEMANTIC_CREDENTIAL_CAPABILITIES),
        },
        "request_collections": {
            "replay_policies": sorted(REPLAY_POLICIES),
            "active_policy": "confirmed_active",
        },
    }


@dataclass(frozen=True)
class ResolvedScanContract:
    generation: str
    policy: ScanPolicy
    budget_profile: str
    budget: ScanBudget
    execution_plan: ScanExecutionPlan

    def option_metadata(self) -> dict[str, Any]:
        return self.execution_plan.option_metadata()


def scan_family_resolution(contract: ResolvedScanContract) -> dict[str, Any]:
    """How the submitted families resolved, returned by preview and submission alike.

    ``include_families`` is exact only under the ``custom`` preset. Otherwise it adds to the
    preset, named or implied by ``active_testing`` (``standard_active``) or its absence
    (``passive``), and ``families_added_by_preset`` names what the preset contributed beyond
    the families the caller listed, so a client that meant "only these" sees that it did not
    say so.
    """
    plan = contract.execution_plan
    requested = list(plan.requested_families)
    resolved = list(plan.resolved_families)
    return {
        "family_preset": plan.family_preset,
        "requested_families": requested,
        "resolved_families": resolved,
        "include_families_mode": (
            "exact" if plan.family_preset == "custom" else "added_to_preset"
        ),
        "families_added_by_preset": [
            family for family in resolved if family not in set(requested)
        ] if plan.family_preset != "custom" else [],
    }


def bind_scan_scope_receipt(
    contract: ResolvedScanContract, scope_receipt_id: str | None,
) -> ResolvedScanContract:
    """Bind a validated scope receipt into every canonical Scan snapshot.

    Target-bound approval is validated only after the target row exists. Rebuild
    the immutable plan at that boundary instead of mutating the flattened policy
    and leaving the execution-plan digest stale.
    """
    scope_id = str(scope_receipt_id or "").strip() or None
    if contract.policy.scope_receipt_id == scope_id:
        return contract
    if contract.policy.scope_receipt_id and scope_id != contract.policy.scope_receipt_id:
        raise ValueError("validated scope receipt conflicts with the Scan contract")
    policy = replace(contract.policy, scope_receipt_id=scope_id)
    plan = ScanExecutionPlan(
        policy=policy,
        budget_profile=contract.budget_profile,
        budget=contract.budget,
        family_preset=contract.execution_plan.family_preset,
        requested_families=contract.execution_plan.requested_families,
        resolved_families=contract.execution_plan.resolved_families,
    )
    return replace(contract, policy=policy, execution_plan=plan)


def bind_scan_approval_receipt(
    contract: ResolvedScanContract, replaced_receipt_id: str | None, approval_receipt_id: str,
) -> ResolvedScanContract:
    """Rebind a contract resolved with ``replaced_receipt_id`` to ``approval_receipt_id``.

    Admission replaces the standing receipt a credentialed Scan resolved with by the
    credential-tier receipt derived from it; the plan is rebuilt so its digest names the receipt
    the Scan runs under. A contract resolved with another receipt (or none) is left as it is.
    """
    current = contract.policy.approval_receipt_id
    if not replaced_receipt_id or current != str(replaced_receipt_id):
        return contract
    policy = replace(contract.policy, approval_receipt_id=str(approval_receipt_id))
    plan = ScanExecutionPlan(
        policy=policy,
        budget_profile=contract.budget_profile,
        budget=contract.budget,
        family_preset=contract.execution_plan.family_preset,
        requested_families=contract.execution_plan.requested_families,
        resolved_families=contract.execution_plan.resolved_families,
    )
    return replace(contract, policy=policy, execution_plan=plan)


def _tool_wall_follows_duration(profile: str, advanced: Mapping[str, Any] | None) -> bool:
    """Whether a lowered duration also lowers this Scan's tool wall (thorough and deep only)."""
    advanced = advanced if isinstance(advanced, Mapping) else {}
    return (
        budget_sufficiency(profile)
        and advanced.get("max_duration_seconds") is not None
        and advanced.get("max_tool_wall_seconds") is None
    )


def bind_scan_fan_out(
    contract: ResolvedScanContract, advanced: Mapping[str, Any] | None,
) -> ResolvedScanContract:
    """The contract of a Scan that fans out into parallel children, from its resolved one.

    A lowered duration lowers a thorough or deep Scan's tool wall because the Scan runs its
    actions one at a time (``_resolve_budget``). A parallel parent's tool wall is divided among
    children that run at the same time, each under the whole duration, so lowering it cut every
    child's share by the number of children: a thorough parent at 3,600 s with four endpoint
    children gave each about 720 s instead of about 2,160 s. Such a parent keeps the profile's
    tool wall, exactly as it resolved before the duration lowered it; every other limit, the
    policy and the families are unchanged. ``advanced`` is the limits the contract resolved
    from, so an explicit tool-wall limit is never raised.
    """
    if not _tool_wall_follows_duration(contract.budget_profile, advanced):
        return contract
    profile_wall = int(BUDGET_PROFILES[contract.budget_profile].max_tool_wall_seconds)
    if int(contract.budget.max_tool_wall_seconds) >= profile_wall:
        return contract
    budget = replace(contract.budget, max_tool_wall_seconds=profile_wall)
    plan = ScanExecutionPlan(
        policy=contract.policy,
        budget_profile=contract.budget_profile,
        budget=budget,
        family_preset=contract.execution_plan.family_preset,
        requested_families=contract.execution_plan.requested_families,
        resolved_families=contract.execution_plan.resolved_families,
    )
    return replace(contract, budget=budget, execution_plan=plan)


def _resolve_budget(
    profile: str,
    advanced: Mapping[str, Any] | None,
    *,
    state_changing_allowed: bool,
) -> ScanBudget:
    try:
        base = asdict(BUDGET_PROFILES[profile])
    except KeyError as exc:
        raise ValueError("budget_profile must be fast, balanced, thorough, or deep") from exc
    advanced = advanced if isinstance(advanced, Mapping) else {}
    unknown = set(advanced) - set(_BUDGET_CEILINGS) - {
        "include_families", "exclude_families", "force_single_worker"
    }
    if unknown:
        raise ValueError(f"unsupported advanced scan limits: {', '.join(sorted(unknown))}")
    for key, ceiling in _BUDGET_CEILINGS.items():
        if key not in advanced or advanced[key] is None:
            continue
        value = advanced[key]
        if isinstance(value, bool):
            raise ValueError(f"{key} must be a positive integer")
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{key} must be a positive integer") from exc
        minimum = 0 if key == "max_state_changing_requests" else 1
        if not minimum <= value <= ceiling:
            raise ValueError(f"{key} must be between {minimum} and {ceiling}")
        if value > int(base[key]):
            raise ValueError(
                f"{key} cannot exceed the {profile} profile ceiling of {base[key]}"
            )
        base[key] = value
    if "max_hosts" not in advanced:
        base["max_hosts"] = min(base["max_hosts"], base["max_endpoints"])
    if _tool_wall_follows_duration(profile, advanced):
        # Tool wall never exceeds total wall. A Scan's actions run one at a time, so a lowered
        # duration left at the profile's tool wall planned about three times the work the
        # deadline lets run, and the deadline then killed it (lab Scans at 3,600 s planned
        # 10,800 s). An explicit tool-wall limit is kept as given. A Scan that fans out into
        # parallel children keeps the profile's tool wall (``bind_scan_fan_out``).
        base["max_tool_wall_seconds"] = min(
            base["max_tool_wall_seconds"], base["max_duration_seconds"],
        )
    if "max_state_changing_requests" not in advanced:
        base["max_state_changing_requests"] = min(
            base["max_state_changing_requests"], base["max_http_requests"],
        )
    if not state_changing_allowed:
        if int(base.get("max_state_changing_requests") or 0) > 0 and (
            "max_state_changing_requests" in advanced
        ):
            raise ValueError(
                "max_state_changing_requests requires state-changing HTTP authority"
            )
        base["max_state_changing_requests"] = 0
    if advanced.get("force_single_worker"):
        base["max_workers"] = 1
    return ScanBudget(**base)


def resolve_scan_contract(
    *,
    budget_profile: str | None = None,
    policy: Mapping[str, Any] | None = None,
    advanced: Mapping[str, Any] | None = None,
    approval_receipt_id: str | None = None,
) -> ResolvedScanContract:
    """Resolve one immutable V2 Scan plan from canonical policy and budget input."""
    profile = str(budget_profile or "balanced").strip().lower()

    policy_data = policy if isinstance(policy, Mapping) else {}
    allowed_policy_keys = {
        "active_testing", "allow_state_changing_http", "network_discovery",
        "subdomain_discovery", "include_families", "exclude_families", "preset",
    }
    unknown_policy = set(policy_data) - allowed_policy_keys
    if unknown_policy:
        raise ValueError(f"unsupported scan policy fields: {', '.join(sorted(unknown_policy))}")
    active_testing = bool(policy_data.get("active_testing", False))
    include = normalize_scan_policy_families(
        policy_data.get("include_families")
        or (advanced or {}).get("include_families")
        or [],
        field="include_families",
    )
    exclude = normalize_scan_policy_families(
        policy_data.get("exclude_families")
        or (advanced or {}).get("exclude_families")
        or [],
        field="exclude_families",
    )
    unsupported_families = (set(include) | set(exclude)) - set(SCAN_V2_FAMILY_NAMES)
    if unsupported_families:
        raise ValueError(
            "families are not implemented by canonical Scan: "
            + ", ".join(sorted(unsupported_families))
        )
    if set(include) & set(exclude):
        raise ValueError("include_families and exclude_families must not overlap")
    # Allowing active testing without naming a preset is a request for the
    # standard active set. Defaulting it to passive ran nothing active while the
    # page read "Active allowed"; an operator who wants permission without work
    # says "preset": "passive" explicitly. include_families adds to the preset, named or
    # implied; only `custom` is exactly include_families. Because that is easy to misread
    # (soak N45: `active_testing` with `include_families: ["sensitive_exposure"]` also ran
    # XSS and SQLi), preview and submission state it (scan_family_resolution).
    preset = str(
        policy_data.get("preset") or ("standard_active" if active_testing else "passive")
    ).strip().lower()
    if preset not in SCAN_FAMILY_PRESETS:
        raise ValueError("scan family preset must be passive, standard_active, or custom")
    if preset == "standard_active" and not active_testing:
        raise ValueError("standard_active preset requires active_testing")
    preset_defaults = set(scan_family_preset_families(
        preset, profile, lowered_request_ceiling=_lowers_request_ceiling(
            profile, advanced,
            state_changing_allowed=bool(policy_data.get("allow_state_changing_http", False)),
        ),
    ))
    resolved = tuple(
        family for family in SCAN_V2_FAMILY_NAMES
        if family in ((preset_defaults | set(include)) - set(exclude))
    )
    if preset == "custom" and not resolved:
        raise ValueError("custom preset requires at least one selected family")
    if not resolved:
        # Every family of the preset was excluded. Such a Scan ran only the baseline probes
        # and was graded A 100 with coverage "complete" (soak 89770439): a no-op dressed as a
        # clean result. The compiler also reads an empty resolved set as "no restriction".
        raise ValueError(
            f"exclude_families removes every family of the {preset} preset "
            f"({', '.join(sorted(preset_defaults))}); select at least one family"
        )
    # Derived from the canonical check registry, never a second hardcoded list.
    # A family added to SCAN_V2_FAMILY_NAMES without being added here would
    # otherwise be admissible under a passive policy: sensitive_exposure,
    # nosqli, and authz_surface all shipped that way. An unknown family fails
    # closed as active, so a registry gap cannot widen passive admission.
    active_only_families = {
        family
        for family in resolved
        if (lambda spec: spec is None or spec.is_active)(get_check_family(family))
    }
    if active_only_families and not active_testing:
        raise ValueError(
            "active_testing is required to include families: "
            + ", ".join(sorted(active_only_families))
        )
    resolved_policy = ScanPolicy(
        active_testing=active_testing,
        allow_state_changing_http=bool(policy_data.get("allow_state_changing_http", False)),
        network_discovery=bool(policy_data.get("network_discovery", False)),
        subdomain_discovery=bool(policy_data.get("subdomain_discovery", False)),
        # Downstream compatibility readers treat include_families as the exact
        # allowlist. The execution plan separately preserves what the operator
        # requested and what preset resolution selected.
        include_families=resolved,
        exclude_families=exclude,
        approval_receipt_id=str(approval_receipt_id or "").strip() or None,
    )
    if resolved_policy.allow_state_changing_http and not resolved_policy.active_testing:
        raise ValueError("state-changing HTTP requires active_testing")
    if (
        resolved_policy.allow_state_changing_http
        and not resolved_policy.approval_receipt_id
    ):
        raise ValueError(
            "state-changing HTTP requires a target-bound approval receipt"
        )
    if resolved_policy.network_discovery and not resolved_policy.active_testing:
        raise ValueError("network_discovery requires active_testing")
    if resolved_policy.network_discovery and not resolved_policy.approval_receipt_id:
        raise ValueError("network_discovery requires a target-bound approval receipt")
    if "recon_active" in resolved and not resolved_policy.approval_receipt_id:
        raise ValueError("recon_active requires a target-bound approval receipt")
    merged_advanced = dict(advanced or {})
    budget = _resolve_budget(
        profile,
        merged_advanced,
        state_changing_allowed=(
            resolved_policy.active_testing
            and resolved_policy.allow_state_changing_http
            and bool(resolved_policy.approval_receipt_id)
        ),
    )
    execution_plan = ScanExecutionPlan(
        policy=resolved_policy,
        budget_profile=profile,
        budget=budget,
        family_preset=preset,
        requested_families=include,
        resolved_families=resolved,
    )
    return ResolvedScanContract(
        generation="v2",
        policy=resolved_policy,
        budget_profile=profile,
        budget=budget,
        execution_plan=execution_plan,
    )
