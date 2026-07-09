"""Check-family registry for DAST/ASM scheduling.

The scanner still exposes focused active execution through legacy boolean
flags today. This module centralizes the product contract around check
families so API validation, ASM scheduling, and future planner work do not
grow another set of hardcoded family lists.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CheckFamilySpec:
    name: str
    phase: str
    family: str
    label: str
    default_profiles: tuple[str, ...] = ("balanced", "thorough", "exhaustive")
    is_active: bool = False
    requires_auth_states: bool = False
    requires_credentials: bool = False
    risk_level: str = "low"
    allowed_presets: tuple[str, ...] = ("safe", "balanced", "lab")
    telemetry_schema: str | None = None
    proof_contract: tuple[str, ...] = ()
    severity_rules: dict[str, Any] = field(default_factory=dict)
    scanner_options: dict[str, Any] = field(default_factory=dict)
    runnable: bool = False
    description: str = ""


CHECK_REGISTRY: tuple[CheckFamilySpec, ...] = (
    CheckFamilySpec(
        name="recon",
        phase="recon",
        family="passive",
        label="Recon",
        default_profiles=("fast", "balanced", "thorough", "exhaustive"),
        telemetry_schema="discovery",
        proof_contract=("source_url", "discovery_method", "normalized_endpoint"),
        severity_rules={"finding_ceiling_without_concrete_evidence": "info"},
        runnable=True,
        description="Crawl, API/HAR/OpenAPI discovery, and passive surface refresh.",
    ),
    CheckFamilySpec(
        name="nuclei",
        phase="template",
        family="nuclei",
        label="Nuclei",
        is_active=False,
        telemetry_schema="nuclei_template",
        proof_contract=("template_id", "matched_at", "matcher_name", "request_url"),
        severity_rules={"template_severity_is_input": True, "promotion_requires": ["matched_at", "template_id"]},
        runnable=True,
        description="Nuclei template checks by severity/tag. Not an ASM endpoint-test family yet.",
    ),
    CheckFamilySpec(
        name="sqli",
        phase="active",
        family="injection",
        label="SQL Injection",
        is_active=True,
        risk_level="medium",
        telemetry_schema="active_endpoint_attempt_v1",
        proof_contract=("method", "url", "parameter", "payload", "response_delta"),
        severity_rules={"critical_requires": ["exploitation_proof"], "high_requires": ["response_delta"]},
        scanner_options={"sqli": True, "xss": False, "asm_check_family": "sqli"},
        runnable=True,
        description="SQL injection probes and proof/extraction depth.",
    ),
    CheckFamilySpec(
        name="xss",
        phase="active",
        family="client",
        label="Cross-site Scripting",
        is_active=True,
        risk_level="medium",
        telemetry_schema="active_endpoint_attempt_v1",
        proof_contract=("method", "url", "parameter", "payload", "sink_or_reflection"),
        severity_rules={"high_requires": ["confirmed_execution_or_dangerous_sink"], "medium_requires": ["reflection"]},
        scanner_options={"xss": True, "sqli": False, "asm_check_family": "xss"},
        runnable=True,
        description="Reflected, stored, and DOM XSS probes.",
    ),
    CheckFamilySpec(
        name="bola",
        phase="active",
        family="access_control",
        label="BOLA / IDOR",
        is_active=True,
        requires_auth_states=True,
        requires_credentials=True,
        risk_level="high",
        allowed_presets=("lab",),
        telemetry_schema="active_endpoint_attempt_v1",
        proof_contract=("resource_template", "resource_id", "primary_auth", "second_user_auth", "status_delta"),
        severity_rules={"critical_requires": ["cross_user_data_access"], "high_requires": ["object_authorization_bypass"]},
        scanner_options={"sqli": False, "xss": False, "asm_check_family": "bola"},
        runnable=True,
        description="Multi-user object authorization comparisons. Requires Lab/deep policy and two auth contexts.",
    ),
    CheckFamilySpec(
        name="auth",
        phase="active",
        family="access_control",
        label="Authentication",
        is_active=True,
        requires_credentials=True,
        risk_level="medium",
        telemetry_schema="active_endpoint_attempt_v1",
        proof_contract=("method", "url", "anonymous_status", "authenticated_status", "response_delta"),
        severity_rules={"high_requires": ["protected_resource_anonymous_access"], "medium_requires": ["auth_boundary_delta"]},
        scanner_options={"sqli": False, "xss": False, "asm_check_family": "auth"},
        runnable=True,
        description="Read-only authenticated-vs-anonymous access checks for focused ASM endpoint batches.",
    ),
    CheckFamilySpec(
        name="mass_assignment",
        phase="active",
        family="access_control",
        label="Mass Assignment",
        is_active=True,
        risk_level="medium",
        telemetry_schema="active_endpoint_attempt_v1",
        proof_contract=("method", "url", "field", "baseline_value", "observed_privilege_effect"),
        severity_rules={
            "high_requires": ["persisted_or_response_privilege_effect"],
            "reflection_only_ceiling": "medium",
        },
        runnable=True,
        description="Bounded privileged-field mutation with baseline-vs-response effect proof.",
    ),
    CheckFamilySpec(
        name="jwt",
        phase="active",
        family="authentication",
        label="JWT Security",
        is_active=True,
        risk_level="medium",
        telemetry_schema="jwt_probe_result_v1",
        proof_contract=("token_source", "mutation", "baseline_status", "forged_status", "acceptance_delta"),
        severity_rules={
            "critical_requires": ["forged_token_accepted_with_privileged_effect"],
            "high_requires": ["forged_token_accepted"],
            "metadata_only_ceiling": "medium",
        },
        runnable=True,
        description="JWT algorithm, signature, key, and claim mutation checks with acceptance proof.",
    ),
    CheckFamilySpec(
        name="headers",
        phase="passive",
        family="headers",
        label="Headers",
        is_active=False,
        telemetry_schema="planned_passive_attempt",
        proof_contract=("request_url", "response_headers", "parsed_policy_state"),
        severity_rules={"missing_baseline_headers": "low_or_medium", "csp_absent": "medium"},
        description="HTTP security header posture checks.",
    ),
    CheckFamilySpec(
        name="ssrf",
        phase="active",
        family="server_side",
        label="SSRF",
        is_active=True,
        risk_level="high",
        allowed_presets=("lab",),
        telemetry_schema="planned_high_risk_attempt",
        proof_contract=("method", "url", "payload", "callback_or_response_evidence"),
        severity_rules={"critical_requires": ["confirmed_callback"], "high_requires": ["internal_resource_fetch"]},
        description="Server-side request forgery checks. Planned and permission-gated.",
    ),
    CheckFamilySpec(
        name="lfi",
        phase="active",
        family="server_side",
        label="LFI / Path Traversal",
        is_active=True,
        risk_level="high",
        allowed_presets=("lab",),
        telemetry_schema="planned_high_risk_attempt",
        proof_contract=("method", "url", "payload", "file_evidence"),
        severity_rules={"critical_requires": ["sensitive_file_read"], "high_requires": ["path_traversal_confirmed"]},
        description="File inclusion and path traversal checks. Planned and permission-gated.",
    ),
    CheckFamilySpec(
        name="rce",
        phase="active",
        family="server_side",
        label="RCE",
        is_active=True,
        risk_level="high",
        allowed_presets=("lab",),
        telemetry_schema="planned_high_risk_attempt",
        proof_contract=("method", "url", "payload", "command_output_or_callback"),
        severity_rules={"critical_requires": ["command_execution_proof"]},
        description="Command/code execution checks. Planned and permission-gated.",
    ),
    CheckFamilySpec(
        name="business_logic",
        phase="active",
        family="workflow",
        label="Business Logic",
        is_active=True,
        requires_credentials=True,
        risk_level="high",
        allowed_presets=("lab",),
        telemetry_schema="planned_workflow_attempt",
        proof_contract=("workflow_step", "principal", "precondition", "observed_state_change"),
        severity_rules={"severity_requires_business_impact": True, "high_requires": ["unauthorized_state_change"]},
        description="Workflow/business-logic testing. Planned for AI/manual-assisted campaigns.",
    ),
)


CHECK_REGISTRY_BY_NAME = {spec.name: spec for spec in CHECK_REGISTRY}
CHECK_FAMILY_ALIASES = {
    "all": "all",
    "sql": "sqli",
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "cross-site-scripting": "xss",
    "cross_site_scripting": "xss",
    "idor": "bola",
    "path_traversal": "lfi",
    "path-traversal": "lfi",
    "cmdi": "rce",
    "command_injection": "rce",
    "command-injection": "rce",
}


def normalize_check_family(value: Any, *, allow_all: bool = True) -> str | None:
    raw = str(value or "").strip().lower()
    if not raw:
        return None
    normalized = CHECK_FAMILY_ALIASES.get(raw, raw)
    if normalized == "all":
        return "all" if allow_all else None
    return normalized


def get_check_family(name: Any) -> CheckFamilySpec | None:
    normalized = normalize_check_family(name, allow_all=False)
    return CHECK_REGISTRY_BY_NAME.get(normalized or "")


def runnable_families(*, phase: str | None = None, active_only: bool | None = None) -> tuple[CheckFamilySpec, ...]:
    specs = [spec for spec in CHECK_REGISTRY if spec.runnable]
    if phase is not None:
        specs = [spec for spec in specs if spec.phase == phase]
    if active_only is not None:
        specs = [spec for spec in specs if spec.is_active is active_only]
    return tuple(specs)


def asm_focus_families() -> tuple[CheckFamilySpec, ...]:
    return tuple(spec for spec in runnable_families(phase="active", active_only=True) if spec.scanner_options)


def default_parallel_focus_families() -> tuple[CheckFamilySpec, ...]:
    """Families safe to include in automatic broad/sqli/xss-style fan-out.

    High-risk and credential-required families are runnable only by explicit
    focused ASM/API request with their own preconditions; they must not appear
    in default parallel family lanes.
    """
    return tuple(
        spec
        for spec in asm_focus_families()
        if str(spec.risk_level or "").lower() != "high"
        and not spec.requires_credentials
    )


def asm_focus_family_names(*, include_all: bool = True) -> tuple[str, ...]:
    names = tuple(spec.name for spec in asm_focus_families())
    return (("all",) + names) if include_all else names


def describe_check_families() -> list[dict[str, Any]]:
    return [
        {
            "name": spec.name,
            "phase": spec.phase,
            "family": spec.family,
            "label": spec.label,
            "default_profiles": list(spec.default_profiles),
            "is_active": spec.is_active,
            "requires_auth_states": spec.requires_auth_states,
            "requires_credentials": spec.requires_credentials,
            "risk_level": spec.risk_level,
            "allowed_presets": list(spec.allowed_presets),
            "telemetry_schema": spec.telemetry_schema,
            "proof_contract": list(spec.proof_contract),
            "severity_rules": dict(spec.severity_rules),
            "runnable": spec.runnable,
            "description": spec.description,
        }
        for spec in CHECK_REGISTRY
    ]


def scanner_execution_plan(
    *,
    scan_mode: str,
    public_only: bool = False,
    quick_mode: bool = False,
    active_checks: bool = False,
    check_family_scope: dict[str, Any] | None = None,
    skip_global_checks: bool = False,
    focused_endpoints_only: bool = False,
    zero_rediscovery: bool = False,
) -> dict[str, Any]:
    """Return the registry view of scanner-family execution for a scan.

    This is intentionally metadata-only: detector dispatch can migrate behind
    this plan family by family while existing report behavior remains stable.
    """
    scope = check_family_scope if isinstance(check_family_scope, dict) else {}
    requested_families = {
        normalize_check_family(name, allow_all=True) or str(name)
        for name in (scope.get("families") or [])
    }
    if "all" in requested_families:
        requested_families.update(spec.name for spec in asm_focus_families())

    families: list[dict[str, Any]] = []
    for spec in CHECK_REGISTRY:
        enabled = False
        expected = False
        reason = "not_selected"
        requested = spec.name in requested_families
        blocked_by: list[str] = []

        if spec.name == "recon":
            enabled = not zero_rediscovery
            expected = enabled
            reason = "zero_rediscovery_scope" if zero_rediscovery else "default_recon"
        elif spec.name == "headers":
            enabled = not skip_global_checks
            expected = enabled
            reason = "global_checks_skipped" if skip_global_checks else "default_passive"
        elif spec.name == "nuclei":
            enabled = not public_only and not quick_mode and not focused_endpoints_only
            expected = enabled
            if public_only:
                reason = "public_only"
            elif quick_mode:
                reason = "quick_mode"
            elif focused_endpoints_only:
                reason = "focused_endpoints_only"
            else:
                reason = "template_scan_expected"
        elif spec.is_active:
            enabled = bool(active_checks and not public_only and requested and spec.runnable)
            expected = enabled
            if not active_checks:
                reason = "active_checks_disabled"
            elif public_only:
                reason = "public_only"
            elif requested and not spec.runnable:
                reason = "registered_not_runnable"
                blocked_by.append("registry_family_not_runnable")
            elif requested:
                reason = "selected_by_check_family_scope"
            elif spec.runnable:
                reason = "not_selected"
            else:
                reason = "registered_not_runnable"

        dispatch_adapter = "none"
        if enabled:
            if spec.name in {"sqli", "xss"}:
                dispatch_adapter = "legacy_active_loop"
            elif spec.name in {"bola", "auth"}:
                dispatch_adapter = "asm_endpoint_batch"
            elif spec.name == "mass_assignment":
                dispatch_adapter = "legacy_phase4_mass_assignment"
            elif spec.name == "jwt":
                dispatch_adapter = "legacy_advanced_jwt"
            elif spec.name in {"recon", "headers"}:
                dispatch_adapter = "legacy_passive_or_template"
            elif spec.name == "nuclei":
                dispatch_adapter = "legacy_nuclei_template"
            else:
                dispatch_adapter = "adapter_pending"
                blocked_by.append("dispatch_adapter_pending")

        families.append(
            {
                "name": spec.name,
                "phase": spec.phase,
                "family": spec.family,
                "runnable": spec.runnable,
                "enabled": enabled,
                "expected": expected,
                "status": "enabled" if enabled else "skipped",
                "reason": reason,
                "requested": requested,
                "blocked_by": blocked_by,
                "dispatch_adapter": dispatch_adapter,
                "requires_auth_states": spec.requires_auth_states,
                "requires_credentials": spec.requires_credentials,
                "risk_level": spec.risk_level,
                "telemetry_schema": spec.telemetry_schema,
                "proof_contract": list(spec.proof_contract),
                "severity_rules": dict(spec.severity_rules),
            }
        )

    enabled_families = [item for item in families if item.get("enabled")]
    skipped_families = [item for item in families if not item.get("enabled")]
    reason_counts = Counter(str(item.get("reason") or "unknown") for item in skipped_families)
    enabled_by_phase = Counter(str(item.get("phase") or "unknown") for item in enabled_families)
    enabled_by_risk = Counter(str(item.get("risk_level") or "unknown") for item in enabled_families)
    proof_contracts = {
        str(item.get("name")): list(item.get("proof_contract") or [])
        for item in enabled_families
        if item.get("proof_contract")
    }
    dispatch_counts = Counter(str(item.get("dispatch_adapter") or "none") for item in enabled_families)
    requested_blocked = [
        {
            "name": str(item.get("name")),
            "reason": str(item.get("reason") or "blocked"),
            "blocked_by": list(item.get("blocked_by") or []),
        }
        for item in families
        if item.get("requested") and not item.get("enabled") and item.get("blocked_by")
    ]
    # A family can be planned (enabled) yet have no dispatch adapter wired. Surface it
    # explicitly so `enabled_families` is never read as achieved coverage.
    unwired_enabled = [
        {
            "name": str(item.get("name")),
            "dispatch_adapter": str(item.get("dispatch_adapter") or "none"),
            "blocked_by": list(item.get("blocked_by") or []),
        }
        for item in enabled_families
        if item.get("dispatch_adapter") == "adapter_pending"
    ]

    return {
        "registry_version": "check_family_v1",
        "scan_mode": scan_mode,
        "check_family_scope": dict(scope),
        "summary": {
            "family_count": len(families),
            "enabled_count": len(enabled_families),
            "skipped_count": len(skipped_families),
            "enabled_families": [str(item.get("name")) for item in enabled_families],
            "skipped_families": [str(item.get("name")) for item in skipped_families],
            "skip_reason_counts": dict(reason_counts),
            "enabled_by_phase": dict(enabled_by_phase),
            "enabled_by_risk": dict(enabled_by_risk),
            "proof_contracts": proof_contracts,
            "runnable_enabled_count": sum(1 for item in enabled_families if item.get("runnable")),
            "dispatch_adapter_counts": dict(dispatch_counts),
            "requested_blocked": requested_blocked,
            "unwired_enabled": unwired_enabled,
            "dispatched_enabled_count": len(enabled_families) - len(unwired_enabled),
        },
        "families": families,
    }


def validate_asm_focus_family(value: Any) -> str | None:
    normalized = normalize_check_family(value)
    if normalized in (None, "all"):
        return None
    allowed = set(asm_focus_family_names(include_all=False))
    if normalized in allowed:
        return normalized
    known = get_check_family(normalized)
    allowed_text = ", ".join(asm_focus_family_names())
    if known:
        raise ValueError(
            f"check_family '{normalized}' is registered but not runnable for ASM endpoint batches yet; "
            f"allowed families: {allowed_text}"
        )
    raise ValueError(f"unknown check_family '{normalized}'; allowed families: {allowed_text}")


def apply_asm_focus(options: dict[str, Any], value: Any) -> tuple[dict[str, Any], str | None]:
    family = validate_asm_focus_family(value)
    opts = dict(options or {})
    if not family:
        opts.pop("asm_check_family", None)
        return opts, None
    spec = CHECK_REGISTRY_BY_NAME[family]
    opts.update(spec.scanner_options)
    return opts, family


def has_primary_auth_context(options: dict[str, Any]) -> bool:
    opts = options or {}
    return bool(
        opts.get("auth_header")
        or opts.get("auth_cookies")
        or opts.get("auth_headers_json")
        or opts.get("auth_scenario_json")
        or (opts.get("login_username") and opts.get("login_password"))
    )


def has_second_user_auth_context(options: dict[str, Any]) -> bool:
    opts = options or {}
    return bool(opts.get("user2_header") or opts.get("user2_cookies"))


def family_precondition_error(
    family: str | None,
    options: dict[str, Any],
    *,
    exploit_depth: bool,
) -> str | None:
    """Return a fail-closed policy error for a focused runnable family.

    This intentionally has no FastAPI dependency so API, ASM, AI routing, and
    tests can share one policy contract.
    """
    if not family:
        return None
    spec = get_check_family(family)
    if not spec:
        return None
    allowed = {str(p).lower() for p in spec.allowed_presets or ()}
    if spec.risk_level == "high" and "lab" in allowed and not exploit_depth:
        return f"check_family '{family}' requires Lab/deep policy (set exploit_depth=true)"
    if spec.requires_credentials and not has_primary_auth_context(options):
        return f"check_family '{family}' requires primary user credentials in target scan options"
    if spec.requires_auth_states and not has_second_user_auth_context(options):
        return f"check_family '{family}' requires second-user credentials in target scan options"
    return None


def enforce_family_preconditions(
    family: str | None,
    options: dict[str, Any],
    *,
    exploit_depth: bool,
) -> None:
    error = family_precondition_error(family, options, exploit_depth=exploit_depth)
    if error:
        raise ValueError(error)


def validate_scan_focus_family(value: Any) -> str | None:
    """Validate a DAST focused-family request for POST /scans.

    Unlike ASM, this validator is for the public scan API contract, so it uses
    the same runnable family set but says "DAST scans" in errors.
    """
    normalized = normalize_check_family(value)
    if normalized in (None, "all"):
        return None
    allowed = set(asm_focus_family_names(include_all=False))
    if normalized in allowed:
        return normalized
    known = get_check_family(normalized)
    allowed_text = ", ".join(asm_focus_family_names())
    if known:
        raise ValueError(
            f"check_family '{normalized}' is registered but not runnable for DAST scans yet; "
            f"allowed families: {allowed_text}"
        )
    raise ValueError(f"unknown check_family '{normalized}'; allowed families: {allowed_text}")


def apply_scan_focus(options: dict[str, Any], value: Any) -> tuple[dict[str, Any], str | None]:
    family = validate_scan_focus_family(value)
    opts = dict(options or {})
    if not family:
        opts.pop("asm_check_family", None)
        opts.pop("check_family", None)
        return opts, None
    spec = CHECK_REGISTRY_BY_NAME[family]
    opts.update(spec.scanner_options)
    opts["check_family"] = family
    return opts, family
