"""
Scanner package - DAST scanner core modules.

This package contains the core scanner functionality organized into modules:

- config: Scan configuration dataclasses (ScanConfig, AuthConfig, etc.)
- constants: Centralized constants (CVSS scores, CWE mappings, endpoint patterns)
- protocols: Tool interface protocols (ToolResult, SecurityTool, Finding)
- errors: Unified error handling (ErrorCollector, ToolError)
- stubs: Dummy function factories for disabled tools
- grading: Security grading and scoring (grade(), calculate_cvss_score())
- findings: Finding normalization and deduplication
- signals: Signal extraction from nuclei results for guiding scan phases
- reporting: Configuration findings emission and AI review helpers

Example usage:
    from scanner.config import ScanConfig, ScanType, AuthConfig
    from scanner.constants import EndpointPatterns, FINDING_CVSS_SCORES
    from scanner.protocols import ToolResult, Finding
    from scanner.errors import ErrorCollector
    from scanner.grading import grade, calculate_cvss_score
    from scanner.findings import normalize_finding, deduplicate_findings
    from scanner.signals import extract_signals_from_nuclei, merge_signals
    from scanner.reporting import emit_config_findings, _generate_fallback_executive_summary
"""

from .config import (
    ScanConfig,
    ScanType,
    AuthConfig,
    TestConfig,
    LimitConfig,
    OutputConfig,
)

from .constants import (
    EndpointPatterns,
    FINDING_CVSS_SCORES,
    SHORT_CVSS_PATTERNS,
    SEVERITY_BASE_SCORES,
    OWASP_WEIGHT,
    OWASP_MAPPING,
    CWE_MAPPING,
    CWE_DESCRIPTIONS,
    SOC2_CRITERIA_MAP,
    TOOL_CONFIDENCE,
    INFO_ONLY_PATTERNS,
    NUCLEI_INFO_TEMPLATES,
    NUCLEI_EXCLUDE_TEMPLATES,
    NUCLEI_PROMOTE_TEMPLATES,
    DBMS_ERROR_PATTERNS,
    DBMS_SQLI_PAYLOADS,
    XSS_CONTEXT_PATTERNS,
    XSS_CONTEXT_PAYLOADS,
)

from .protocols import (
    Finding,
    ToolResult,
    SecurityTool,
    DiscoveryTool,
    DiscoveryResult,
)

from .errors import (
    ErrorCollector,
    ToolError,
    ErrorSeverity,
    ScanError,
    ToolExecutionError,
    AuthenticationError,
    RateLimitError,
    TimeoutError,
    ConfigurationError,
    safe_execute,
)

from .stubs import (
    create_dummy_result,
    dummy_factory,
    dummy_discovery_factory,
    dummy_browser_factory,
    dummy_nuclei_factory,
    dummy_tls_factory,
    dummy_active_test_factory,
    get_dummy_for_tool,
    DUMMY_FUNCTIONS,
)

from .grading import (
    grade,
    calculate_cvss_score,
    apply_context_modifiers,
    validate_severity_cvss,
    map_to_cwe,
    get_cwe_description,
    get_cwe_url,
    owasp_mapping,
    soc2_mapping,
    hsts_preload_readiness,
)

from .findings import (
    normalize_finding,
    deduplicate_findings,
    filter_low_confidence,
    filter_excluded,
    sort_findings_by_severity,
    group_findings_by_severity,
    count_findings_by_severity,
    get_unique_cwes,
    get_unique_tools,
    merge_finding_evidence,
    calculate_confidence,
    get_confidence_tier,
    now_utc_iso,
)

from .signals import (
    extract_signals_from_nuclei,
    merge_signals,
    signals_to_dict,
)

from .reporting import (
    emit_config_findings,
    _reproCurlHost,
    _reproCurlCors,
    _reproDig,
    _reproDelv,
    _reproTLS,
    _ai_safe_commands_for_finding,
    _ai_rule_verdict,
    _mask_text_host,
    _redact_sensitive,
    _redact_body_for_report,
    _mask_structure,
    _generate_fallback_executive_summary,
    HONEYPOT_TEST_DOMAINS,
)

__all__ = [
    # Config
    "ScanConfig",
    "ScanType",
    "AuthConfig",
    "TestConfig",
    "LimitConfig",
    "OutputConfig",
    # Constants
    "EndpointPatterns",
    "FINDING_CVSS_SCORES",
    "SHORT_CVSS_PATTERNS",
    "SEVERITY_BASE_SCORES",
    "OWASP_WEIGHT",
    "OWASP_MAPPING",
    "CWE_MAPPING",
    "CWE_DESCRIPTIONS",
    "SOC2_CRITERIA_MAP",
    "TOOL_CONFIDENCE",
    "INFO_ONLY_PATTERNS",
    "NUCLEI_INFO_TEMPLATES",
    "NUCLEI_EXCLUDE_TEMPLATES",
    "NUCLEI_PROMOTE_TEMPLATES",
    "DBMS_ERROR_PATTERNS",
    "DBMS_SQLI_PAYLOADS",
    "XSS_CONTEXT_PATTERNS",
    "XSS_CONTEXT_PAYLOADS",
    # Protocols
    "Finding",
    "ToolResult",
    "SecurityTool",
    "DiscoveryTool",
    "DiscoveryResult",
    # Errors
    "ErrorCollector",
    "ToolError",
    "ErrorSeverity",
    "ScanError",
    "ToolExecutionError",
    "AuthenticationError",
    "RateLimitError",
    "TimeoutError",
    "ConfigurationError",
    "safe_execute",
    # Stubs
    "create_dummy_result",
    "dummy_factory",
    "dummy_discovery_factory",
    "dummy_browser_factory",
    "dummy_nuclei_factory",
    "dummy_tls_factory",
    "dummy_active_test_factory",
    "get_dummy_for_tool",
    "DUMMY_FUNCTIONS",
    # Grading
    "grade",
    "calculate_cvss_score",
    "apply_context_modifiers",
    "validate_severity_cvss",
    "map_to_cwe",
    "get_cwe_description",
    "get_cwe_url",
    "owasp_mapping",
    "soc2_mapping",
    "hsts_preload_readiness",
    # Findings
    "normalize_finding",
    "deduplicate_findings",
    "filter_low_confidence",
    "filter_excluded",
    "sort_findings_by_severity",
    "group_findings_by_severity",
    "count_findings_by_severity",
    "get_unique_cwes",
    "get_unique_tools",
    "merge_finding_evidence",
    "calculate_confidence",
    "get_confidence_tier",
    "now_utc_iso",
    # Signals
    "extract_signals_from_nuclei",
    "merge_signals",
    "signals_to_dict",
    # Reporting
    "emit_config_findings",
    "_reproCurlHost",
    "_reproCurlCors",
    "_reproDig",
    "_reproDelv",
    "_reproTLS",
    "_ai_safe_commands_for_finding",
    "_ai_rule_verdict",
    "_mask_text_host",
    "_redact_sensitive",
    "_redact_body_for_report",
    "_mask_structure",
    "_generate_fallback_executive_summary",
    "HONEYPOT_TEST_DOMAINS",
]
