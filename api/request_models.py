"""Shared public request models.

Pydantic models used by more than one API domain — the scan-request family and
the hypothesis request — extracted verbatim from the api.py monolith so a router
peeled off the monolith can annotate its handlers without importing api.api.
FastAPI needs the real class at decoration time, so these cannot be injected the
way behavioural collaborators are.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Mapping, Optional, Sequence, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

try:
    import check_registry
    import parallel_scan
    from constants import SMART_SCAN_BUDGETS
    from job_queue import normalize_placement
except ModuleNotFoundError:  # package import in host-side tests
    from . import check_registry, parallel_scan
    from .job_queue import normalize_placement
    from scanner.constants import SMART_SCAN_BUDGETS

class ScanOptions(BaseModel):
    # Historical/internal fields remain readable for stored rows and migrations.
    # Canonical ScanRequest and BatchRequest reject them as new authority.
    scan_type: Optional[str] = None  # quick, standard, deep, full, aggressive, smart

    # Historical/internal compatibility fields.
    quick: bool = False
    public: bool = False
    active: bool = False
    xss: bool = False
    sqli: bool = False
    check_family: Optional[str] = None
    asm_check_family: Optional[str] = None
    thorough: bool = False
    deep_domxss: Optional[bool] = None

    # Additional options
    nuclei: bool = False
    enhanced_dns: bool = False
    subfinder: bool = False
    include_partial_attack_chains: bool = False
    js_dependency_scanning: bool = False
    js_secret_scanning: bool = False
    grpc_discovery: bool = False
    json_link_following: bool = False
    options_method_discovery: bool = False
    # Internal/focused execution controls are also explicit model fields so
    # server-authored research preflights survive Pydantic serialization.
    # They remain safe for public callers: they only narrow work and never
    # expand scope beyond the submitted target/custom endpoints.
    skip_global_checks: bool = False
    focused_endpoints_only: bool = False
    zero_rediscovery: bool = False
    no_browser: bool = False
    placement: Optional[dict[str, Any]] = Field(
        default=None,
        description="Execution placement constraints: use node_scope='remote' for any fleet node, node_id='local' for control-plane workers, a fleet node UUID for one remote node, or region/egress/network/tool constraints.",
    )

    @field_validator("placement", mode="before")
    @classmethod
    def _validate_placement(cls, value):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("placement must be an object")
        unknown = set(value) - {
            "region", "egress_group", "network", "budget_profile",
            "data_residency", "node_id", "node_scope", "requires",
        }
        if unknown:
            raise ValueError(f"unsupported placement keys: {', '.join(sorted(unknown))}")
        normalized = normalize_placement(value)
        if normalized.get("node_scope") not in {None, "local", "remote"}:
            raise ValueError("placement node_scope must be local or remote")
        if value and not normalized:
            raise ValueError("placement must contain at least one non-empty constraint")
        return normalized

    # AI options
    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    model: Optional[str] = None
    ai_mask_host: Optional[str] = None
    ai_scan_classification_enabled: Optional[bool] = None
    ai_classify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    ai_verify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")

    # Authentication options (for authenticated scanning)
    # Session-based auth
    auth_cookies: Optional[str] = None           # "session=abc; token=xyz"
    auth_header: Optional[str] = None            # "Bearer eyJ..." or "Basic xxx"
    auth_headers_json: Optional[str] = None      # '{"X-API-Key": "abc", "X-Custom": "val"}'

    # Form-based login (scanner auto-detects login forms)
    login_url: Optional[str] = None              # Login page URL (auto-detected if not provided)
    login_username: Optional[str] = None
    login_password: Optional[str] = None
    login_extra_fields: Optional[str] = None     # Extra form fields as JSON: '{"remember": "true"}'
    auto_auth: bool = False                      # Attempt API login with provided credentials
    disposable_login_credentials: bool = False  # Permit bounded safe-authentication verification

    # Multi-user auth for BOLA/IDOR testing
    user2_cookies: Optional[str] = None          # Second user session cookies
    user2_header: Optional[str] = None           # Second user auth header

    @field_validator(
        "auth_cookies",
        "auth_header",
        "auth_headers_json",
        "user2_cookies",
        "user2_header",
        "login_username",
        "login_password",
        "login_url",
        mode="before",
    )
    @classmethod
    def _strip_crlf_from_header_inputs(cls, value):
        """Reject CR/LF in auth-related inputs to prevent outbound header injection.

        These values flow into curl `-H name: value` arguments downstream. A
        `\\r\\n` in any of them would let a scan submitter inject arbitrary
        request headers (or full requests) against the scan target.
        """
        if value is None:
            return value
        if isinstance(value, str) and ("\r" in value or "\n" in value):
            raise ValueError("value must not contain CR or LF characters")
        return value

    @field_validator("oob_callback_url", mode="before")
    @classmethod
    def _validate_oob_callback_url(cls, value):
        """Ensure oob_callback_url parses as http(s)://host[:port][/path].

        The value is interpolated into SQLi/SSRF payloads and rendered into
        findings JSON. Garbage values break payload formatting and pollute
        the report; explicit validation keeps the contract honest.
        """
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            raise ValueError("oob_callback_url must be a string")
        if "\r" in value or "\n" in value:
            raise ValueError("oob_callback_url must not contain CR or LF characters")
        import urllib.parse as _urlparse

        parsed = _urlparse.urlparse(value.strip())
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("oob_callback_url must use http or https scheme")
        if not parsed.netloc:
            raise ValueError("oob_callback_url must include a host")
        return value.strip()

    # Manual endpoint specification for API-only targets
    # Format: "METHOD /path params" or just "/path"
    # Examples: "POST /api/login username,password", "/api/users", "GET /api/items?id=1"
    custom_endpoints: Optional[list[str]] = None
    # Inline content-discovery keywords appended to ffuf directory fuzzing.
    # e.g. ["admin", "backup", "api/v2", ".git/config"]. Additive; off when omitted.
    custom_wordlist: Optional[list[str]] = None
    # Inline injection payloads appended to the active SQLi/XSS payload sets.
    # Additive; off when omitted. Also loadable via payloads/<cat>/custom.txt.
    custom_sqli_payloads: Optional[list[str]] = None
    custom_xss_payloads: Optional[list[str]] = None
    auth_scenario_json: Optional[str] = None  # JSON auth DSL with login flow/success condition/TOTP secret
    focus_rules_json: Optional[str] = None  # JSON array of scope focus rules
    avoid_rules_json: Optional[str] = None  # JSON array of scope avoid rules
    verified_findings_only: Optional[bool] = None

    # Historical detector tuning fields; never public Scan identity or authority.
    no_early_stop: bool = False
    thorough_params: bool = False                  # Test more parameters (50x10 vs 25x5)
    oob_callback_url: Optional[str] = None         # OOB callback URL for blind SQLi
    budget_profile: Optional[Literal["fast", "balanced", "thorough", "deep"]] = Field(
        default=None,
        description=(
            "Resource ceiling for the deterministic Scan pipeline; it does not "
            "select an engine or module set."
        ),
    )
    custom_budget: Optional[dict[str, Any]] = Field(
        default=None,
        description="Advanced per-scan budget overrides such as max_urls, active_max_seconds, or browser_max_pages.",
    )
    request_budget_mode: str = Field(
        default="compatibility",
        pattern="^(off|compatibility|enforce)$",
        description="Outbound target request accounting mode for standalone scans.",
    )

    # Safety/performance limits
    smart_bola_max_endpoints: Optional[int] = Field(
        default=None,
        description=f"Max endpoints for BOLA testing (default: {SMART_SCAN_BUDGETS.smart_bola_max_endpoints})",
    )
    dom_xss_max_files: Optional[int] = Field(
        default=None,
        description=f"Max JS files for DOM XSS analysis (default: {SMART_SCAN_BUDGETS.dom_xss_max_files})",
    )
    sqli_extract_max: Optional[int] = Field(
        default=None,
        description=f"Max SQLi findings for extraction (default: {SMART_SCAN_BUDGETS.sqli_extract_max})",
    )
    oob_max_findings: Optional[int] = Field(
        default=None,
        description=f"Max findings for OOB SQLi testing (default: {SMART_SCAN_BUDGETS.oob_max_findings})",
    )
    oob_max_payloads: Optional[int] = None         # Deprecated alias for oob_max_findings
    target_scheme_inferred: Optional[bool] = None  # Output-only: set by API when scheme was auto-inferred (do not use as input)

    # Parallel scanning: split one scan of this target across the worker fleet.
    # See docs/dast-asm-architecture.md.
    parallel: bool = False                          # Fan this scan out into shards
    shards: Optional[Any] = None                    # int or "auto" (scale to workers)
    shard_strategy: Optional[str] = Field(
        default=None,
        pattern="^(auto|scope|family|coverage|coverage_family)$",
        description="auto (default), scope (partition custom_endpoints), family (broad + deep sqli/xss), coverage (discover-once, partition all endpoints), or coverage_family (coverage buckets x broad/sqli/xss lanes).",
    )
    exploit_depth: bool = False                      # Raise exploitation caps + no early stop on shards
    require_current_workers: bool = False            # Reject active scans if any worker is build-stale (§2)
    auth_state_shards: bool = False                  # Fan shards out per auth identity (anon/user1/user2)
    coverage_per_shard_cap: Optional[int] = None     # Endpoints per coverage shard (smaller -> more shards)
    coverage_max_shards: Optional[int] = Field(
        default=None,
        ge=2,
        le=parallel_scan.COVERAGE_MAX_SHARDS,
        description="Maximum base coverage shards before auth-state expansion.",
    )
    coverage_allocation: Optional[str] = Field(
        default=None,
        pattern="^(static|dynamic)$",
        description="Full Coverage allocator mode. dynamic is the default; static preserves legacy round-robin slices as an explicit fallback.",
    )
    coverage_dynamic_batch_size: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000,
        description="Endpoint batch size for dynamic Full Coverage campaign workers.",
    )
    coverage_dynamic_max_batches: Optional[int] = Field(
        default=None,
        ge=1,
        le=parallel_scan.COVERAGE_MAX_DYNAMIC_BATCHES,
        description="Maximum queued pull-worker batches for dynamic Full Coverage.",
    )
    shard_concurrency: Optional[int] = Field(
        default=None,
        ge=1,
        le=20,
        description="Advanced API/AI override for max active shard jobs per parent scan.",
    )
    approval_receipt_id: Optional[str] = Field(
        default=None,
        description="Optional durable approval receipt to validate and stamp on state-changing scan submissions.",
    )
    benchmark_principal_validation: Optional[dict[str, Any]] = Field(
        default=None,
        description="Non-secret benchmark receipt proving distinct configured principals.",
    )

    @field_validator("check_family", "asm_check_family")
    @classmethod
    def validate_scan_check_family(cls, value):
        return check_registry.validate_scan_focus_family(value)


class ScanPublicCompatibilityOptions(BaseModel):
    """Narrow, secret-free compatibility controls published for ``/scans``.

    The worker's historical ``ScanOptions`` model remains available for stored
    rows and internal migrations. It is deliberately not the public schema:
    aliases, output-only fields, raw authentication, and removed Smart Scan
    tuning knobs cannot become new V2 client authority.
    """

    model_config = ConfigDict(extra="forbid")

    custom_endpoints: list[str] = Field(default_factory=list, max_length=2_000)
    require_current_workers: bool = False
    placement: Optional[ScanPublicPlacement] = None
    parallel: Optional[bool] = None
    shards: Optional[
        Union[Annotated[int, Field(ge=2, le=20)], Literal["auto"]]
    ] = None
    shard_strategy: Optional[Literal["auto", "scope", "family", "coverage", "coverage_family"]] = None
    auth_state_shards: bool = False

    @model_validator(mode="after")
    def validate_parallel_controls(self):
        has_parallel_detail = bool(
            self.shards is not None
            or self.shard_strategy is not None
            or self.auth_state_shards
        )
        if has_parallel_detail and self.parallel is not True:
            raise ValueError(
                "shards, shard_strategy, and auth_state_shards require parallel=true"
            )
        return self


class _ScanRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    name: Optional[str] = None
    target_kind: Literal["web", "api"] = "web"
    budget_profile: Optional[Literal["fast", "balanced", "thorough", "deep"]] = None
    policy: Optional[dict[str, Any]] = None
    request_collections: list[dict[str, Any]] = Field(default_factory=list, max_length=16)
    credential_profile_ids: list[str] = Field(default_factory=list, max_length=2)
    advanced: Optional[ScanAdvancedLimits] = None
    approval_receipt_id: Optional[str] = None
    options: ScanPublicCompatibilityOptions = Field(
        default_factory=ScanPublicCompatibilityOptions,
        description=(
            "Deprecated secret-free compatibility controls. New permission and "
            "budget authority belongs in policy, budget_profile, and advanced."
        ),
    )


class HypothesisRequest(BaseModel):
    source: str = Field(pattern="^(app_graph|source_ingest|ai_planner|scanner_signal|ai_gate|model_intake|benchmark|invariant|manual)$")
    family: str = Field(min_length=1, max_length=80)
    dedupe_key: str = Field(min_length=1, max_length=500)
    dedupe_dimensions: dict[str, Any] = Field(default_factory=dict)
    target_id: Optional[str] = None
    campaign_id: Optional[str] = None
    campaign_action_id: Optional[str] = None
    cwe: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity_guess: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    confidence: float = Field(default=0.0, ge=0, le=1)
    smoke_score: Optional[float] = Field(default=None, ge=0, le=1)
    evidence_object_ids: list[str] = Field(default_factory=list)
    tool_receipt_ids: list[str] = Field(default_factory=list)
    next_test_action: Optional[dict[str, Any]] = None
    endorsement: Optional[dict[str, Any]] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None
class ScanAdvancedLimits(BaseModel):
    """Public lower ceilings for one immutable Scan budget."""

    model_config = ConfigDict(extra="forbid")
    max_duration_seconds: Optional[int] = Field(default=None, ge=1, le=172_800)
    max_http_requests: Optional[int] = Field(default=None, ge=1, le=1_000_000)
    max_state_changing_requests: Optional[int] = Field(
        default=None, ge=0, le=100_000,
    )
    max_endpoints: Optional[int] = Field(default=None, ge=1, le=100_000)
    max_hosts: Optional[int] = Field(default=None, ge=1, le=100_000)
    max_browser_actions: Optional[int] = Field(default=None, ge=1, le=20_000)
    max_tcp_ports: Optional[int] = Field(default=None, ge=1, le=262_140)
    max_tool_wall_seconds: Optional[int] = Field(default=None, ge=1, le=86_400)
    max_workers: Optional[int] = Field(default=None, ge=1, le=128)
    include_families: list[str] = Field(default_factory=list, max_length=100)
    exclude_families: list[str] = Field(default_factory=list, max_length=100)
    force_single_worker: bool = False


class ScanPublicPlacement(BaseModel):
    """Typed placement constraints accepted by public Scan clients."""

    model_config = ConfigDict(extra="forbid")

    region: Optional[str] = Field(default=None, min_length=1, max_length=120)
    egress_group: Optional[str] = Field(default=None, min_length=1, max_length=120)
    network: Optional[str] = Field(default=None, min_length=1, max_length=120)
    budget_profile: Optional[Literal["fast", "balanced", "thorough", "deep"]] = None
    data_residency: Optional[str] = Field(default=None, min_length=1, max_length=120)
    node_id: Optional[str] = Field(default=None, min_length=1, max_length=160)
    node_scope: Optional[Literal["local", "remote"]] = None
    requires: list[str] = Field(default_factory=list, max_length=32)
class ScanRequest(_ScanRequestBase):
    """Canonical secret-free Scan submission using only durable references."""
