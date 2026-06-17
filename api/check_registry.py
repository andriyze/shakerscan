"""Check-family registry for DAST/ASM scheduling.

The scanner still exposes focused active execution through legacy boolean
flags today. This module centralizes the product contract around check
families so API validation, ASM scheduling, and future planner work do not
grow another set of hardcoded family lists.
"""

from __future__ import annotations

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
        scanner_options={"sqli": False, "xss": False, "asm_check_family": "auth"},
        runnable=True,
        description="Read-only authenticated-vs-anonymous access checks for focused ASM endpoint batches.",
    ),
    CheckFamilySpec(
        name="headers",
        phase="passive",
        family="headers",
        label="Headers",
        is_active=False,
        telemetry_schema="planned_passive_attempt",
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
            "runnable": spec.runnable,
            "description": spec.description,
        }
        for spec in CHECK_REGISTRY
    ]


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
