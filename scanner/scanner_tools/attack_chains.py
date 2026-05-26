"""
Attack Chain Orchestration Engine

Chains individual vulnerability findings together to demonstrate
real-world attack scenarios. This helps prioritize remediation
by showing the business impact of combined vulnerabilities.

Attack Chains:
1. XSS -> Session Theft -> Account Takeover
2. SQLi -> Data Extraction -> Privilege Escalation
3. SSRF -> Cloud Metadata -> IAM Credential Theft
4. LFI -> Source Code Disclosure -> Credential Extraction
5. Authentication Bypass -> Admin Access -> Full Compromise
6. IDOR -> PII Exposure -> Mass Data Breach

IMPORTANT: This module is for DEFENSIVE security testing - helping
organizations understand the real-world impact of vulnerabilities
so they can prioritize remediation effectively.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class ChainType(Enum):
    """Types of attack chains"""
    XSS_TO_ATO = "xss_to_account_takeover"
    SQLI_TO_ESCALATION = "sqli_to_privilege_escalation"
    SSRF_TO_CLOUD_BREACH = "ssrf_to_cloud_breach"
    LFI_TO_CREDENTIAL_THEFT = "lfi_to_credential_theft"
    AUTH_BYPASS_TO_ADMIN = "auth_bypass_to_admin_access"
    IDOR_TO_DATA_BREACH = "idor_to_data_breach"
    CORS_TO_DATA_THEFT = "cors_to_data_theft"
    WEAK_JWT_TO_IMPERSONATION = "weak_jwt_to_impersonation"
    DESERIALIZATION_TO_RCE = "deserialization_to_rce"
    XXE_TO_DATA_EXFIL = "xxe_to_data_exfil"


@dataclass
class ChainStep:
    """A single step in an attack chain"""
    step_number: int
    finding_type: str
    description: str
    impact: str
    prerequisites: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackChain:
    """Represents a complete attack chain"""
    chain_type: ChainType
    name: str
    description: str
    severity: str  # critical, high, medium
    business_impact: str
    steps: list[ChainStep] = field(default_factory=list)
    # Matching semantics
    required_any_of: list[str] = field(default_factory=list)
    required_all_of: list[str] = field(default_factory=list)
    matched_required_any: list[str] = field(default_factory=list)
    matched_required_all: list[str] = field(default_factory=list)
    matched_optional: list[str] = field(default_factory=list)
    # Legacy fields (matched lists for compatibility)
    required_findings: list[str] = field(default_factory=list)
    optional_findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: list[str] = field(default_factory=list)
    completeness: float = 0.0  # 0-1, how complete the chain is
    status: str = "complete"  # complete or partial
    missing_required: list[str] = field(default_factory=list)
    missing_required_any: list[str] = field(default_factory=list)
    missing_required_all: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    confidence: float = 0.0  # 0-1, confidence in chain plausibility


# Define attack chain templates
CHAIN_TEMPLATES = {
    ChainType.XSS_TO_ATO: {
        "name": "XSS to Account Takeover",
        "description": (
            "Cross-Site Scripting vulnerabilities can be chained with weak session "
            "management to steal user sessions and take over accounts."
        ),
        "business_impact": (
            "Attackers can steal user sessions, access private data, perform actions "
            "as the victim, and potentially escalate to admin accounts."
        ),
        "severity": "critical",
        "required_any_of": ["reflected_xss", "stored_xss", "dom_xss"],
        "required_all_of": [],
        "optional_findings": ["weak_csp", "missing_httponly", "missing_secure_flag", "missing_samesite"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="xss",
                description="Attacker injects malicious JavaScript via XSS vulnerability",
                impact="Code execution in victim's browser",
                prerequisites=["XSS vulnerability (reflected, stored, or DOM)"],
                outputs=["JavaScript execution context"],
            ),
            ChainStep(
                step_number=2,
                finding_type="session_theft",
                description="Malicious script exfiltrates session cookies",
                impact="Session token captured by attacker",
                prerequisites=["Missing HttpOnly flag or alternative extraction"],
                outputs=["Valid session token"],
            ),
            ChainStep(
                step_number=3,
                finding_type="account_takeover",
                description="Attacker uses stolen session to impersonate victim",
                impact="Full account access without credentials",
                prerequisites=["Valid session token", "No session binding to IP/device"],
                outputs=["Compromised user account"],
            ),
        ],
        "remediation": [
            "Fix XSS vulnerabilities with proper output encoding",
            "Implement Content Security Policy (CSP)",
            "Set HttpOnly flag on session cookies",
            "Set Secure and SameSite flags on cookies",
            "Implement session binding to device/IP",
            "Add re-authentication for sensitive actions",
        ],
    },
    ChainType.SQLI_TO_ESCALATION: {
        "name": "SQL Injection to Privilege Escalation",
        "description": (
            "SQL Injection can be leveraged to extract credentials, modify user "
            "privileges, or directly access admin functionality in the database."
        ),
        "business_impact": (
            "Complete database compromise, extraction of all user data including "
            "credentials, modification of user roles to gain admin access."
        ),
        "severity": "critical",
        "required_any_of": ["sqli_confirmed", "sqli_error_based", "sqli_time_based", "sqli_union"],
        "required_all_of": [],
        "optional_findings": ["admin_panel_found", "weak_password_hashing", "default_credentials"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="sqli",
                description="Attacker exploits SQL injection to extract database schema",
                impact="Database structure revealed",
                prerequisites=["SQL injection vulnerability"],
                outputs=["Table names", "Column names"],
            ),
            ChainStep(
                step_number=2,
                finding_type="credential_extraction",
                description="Attacker extracts user credentials from database",
                impact="User passwords/hashes exposed",
                prerequisites=["Database read access"],
                outputs=["User credentials", "Password hashes"],
            ),
            ChainStep(
                step_number=3,
                finding_type="privilege_escalation",
                description="Attacker cracks passwords or modifies user roles",
                impact="Admin-level access obtained",
                prerequisites=["Extracted credentials or write access"],
                outputs=["Admin account access"],
            ),
        ],
        "remediation": [
            "Use parameterized queries/prepared statements",
            "Implement proper input validation",
            "Apply principle of least privilege to database accounts",
            "Use strong password hashing (bcrypt, Argon2)",
            "Implement database activity monitoring",
            "Encrypt sensitive data at rest",
        ],
    },
    ChainType.SSRF_TO_CLOUD_BREACH: {
        "name": "SSRF to Cloud Infrastructure Breach",
        "description": (
            "Server-Side Request Forgery can access cloud metadata services to "
            "steal IAM credentials, leading to full cloud infrastructure compromise."
        ),
        "business_impact": (
            "Complete cloud infrastructure takeover, access to all cloud resources, "
            "data exfiltration, cryptomining, ransomware deployment."
        ),
        "severity": "critical",
        "required_any_of": ["ssrf_confirmed"],
        "required_all_of": ["ssrf_internal_access"],
        "optional_findings": ["cloud_metadata_exposed", "aws_credentials_found", "gcp_credentials_found"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="ssrf",
                description="Attacker exploits SSRF to access internal network",
                impact="Internal network access from application",
                prerequisites=["SSRF vulnerability"],
                outputs=["Internal network requests"],
            ),
            ChainStep(
                step_number=2,
                finding_type="metadata_access",
                description="SSRF used to query cloud metadata service (169.254.169.254)",
                impact="Cloud instance metadata exposed",
                prerequisites=["SSRF reaching metadata endpoint"],
                outputs=["Instance metadata", "IAM role name"],
            ),
            ChainStep(
                step_number=3,
                finding_type="credential_theft",
                description="Temporary IAM credentials extracted from metadata",
                impact="Cloud API access obtained",
                prerequisites=["Metadata access", "IAM role attached to instance"],
                outputs=["AWS/GCP/Azure credentials"],
            ),
            ChainStep(
                step_number=4,
                finding_type="cloud_breach",
                description="Stolen credentials used to access cloud resources",
                impact="Cloud infrastructure compromised",
                prerequisites=["Valid cloud credentials"],
                outputs=["S3 buckets", "Databases", "Other cloud resources"],
            ),
        ],
        "remediation": [
            "Validate and sanitize URLs server-side",
            "Block requests to internal IP ranges (RFC 1918)",
            "Block requests to cloud metadata endpoints",
            "Use IMDSv2 (Instance Metadata Service v2) on AWS",
            "Apply network segmentation",
            "Use VPC endpoints instead of public internet",
        ],
    },
    ChainType.LFI_TO_CREDENTIAL_THEFT: {
        "name": "LFI to Credential Extraction",
        "description": (
            "Local File Inclusion can read configuration files, environment variables, "
            "and source code to extract database credentials, API keys, and secrets."
        ),
        "business_impact": (
            "Exposure of all application secrets, database credentials, API keys, "
            "enabling further attacks on backend systems."
        ),
        "severity": "critical",
        "required_any_of": ["lfi_confirmed", "path_traversal"],
        "required_all_of": [],
        "optional_findings": ["env_file_exposed", "config_file_exposed", "source_code_disclosure"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="lfi",
                description="Attacker exploits LFI to read local files",
                impact="Arbitrary file read access",
                prerequisites=["LFI/Path Traversal vulnerability"],
                outputs=["File contents"],
            ),
            ChainStep(
                step_number=2,
                finding_type="config_extraction",
                description="Attacker reads configuration files (.env, config.php, etc.)",
                impact="Application configuration exposed",
                prerequisites=["File read access"],
                outputs=["Database credentials", "API keys", "Secrets"],
            ),
            ChainStep(
                step_number=3,
                finding_type="lateral_movement",
                description="Extracted credentials used to access other systems",
                impact="Access to databases, APIs, third-party services",
                prerequisites=["Valid credentials"],
                outputs=["Database access", "API access"],
            ),
        ],
        "remediation": [
            "Never pass user input directly to file operations",
            "Use allowlists for file paths",
            "Implement proper file path validation",
            "Store secrets in secure vaults, not files",
            "Apply principle of least privilege to file permissions",
            "Use environment variable injection at runtime",
        ],
    },
    ChainType.IDOR_TO_DATA_BREACH: {
        "name": "IDOR to Mass Data Breach",
        "description": (
            "Insecure Direct Object References can be exploited to enumerate and "
            "access all user data, leading to a mass data breach."
        ),
        "business_impact": (
            "Exposure of all user personal data, regulatory violations (GDPR, CCPA), "
            "reputational damage, potential class action lawsuits."
        ),
        "severity": "high",
        "required_any_of": ["idor_confirmed", "bola_confirmed"],
        "required_all_of": [],
        "optional_findings": ["broken_access_control", "api_enumerable_ids", "sequential_ids", "predictable_ids"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="idor",
                description="Attacker identifies IDOR in API endpoint",
                impact="Unauthorized data access",
                prerequisites=["IDOR vulnerability"],
                outputs=["Single user data access"],
            ),
            ChainStep(
                step_number=2,
                finding_type="enumeration",
                description="Attacker enumerates object IDs to access all records",
                impact="All user records accessible",
                prerequisites=["Sequential or predictable IDs"],
                outputs=["User enumeration"],
            ),
            ChainStep(
                step_number=3,
                finding_type="data_exfiltration",
                description="Automated extraction of all user data",
                impact="Mass data breach",
                prerequisites=["Enumerable IDOR"],
                outputs=["All user PII", "Sensitive data"],
            ),
        ],
        "remediation": [
            "Implement proper authorization checks on all endpoints",
            "Use UUIDs instead of sequential IDs",
            "Verify resource ownership before access",
            "Implement rate limiting",
            "Log and alert on bulk data access patterns",
            "Use API gateways with authorization policies",
        ],
    },
    ChainType.WEAK_JWT_TO_IMPERSONATION: {
        "name": "Weak JWT to User Impersonation",
        "description": (
            "Weak JWT implementation (none algorithm, weak secret, no expiry) can "
            "be exploited to forge tokens and impersonate any user."
        ),
        "business_impact": (
            "Ability to impersonate any user including admins, access all user data, "
            "perform privileged actions."
        ),
        "severity": "critical",
        "required_any_of": ["jwt_none_algorithm", "jwt_weak_secret", "jwt_missing_expiry", "jwt_algorithm_confusion"],
        "required_all_of": [],
        "optional_findings": ["jwt_kid_injection", "jwt_jku_spoofing"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="jwt_weakness",
                description="Attacker identifies JWT implementation weakness",
                impact="JWT validation can be bypassed",
                prerequisites=["Weak JWT configuration"],
                outputs=["JWT bypass technique"],
            ),
            ChainStep(
                step_number=2,
                finding_type="token_forgery",
                description="Attacker forges JWT with target user claims",
                impact="Valid-looking JWT for any user",
                prerequisites=["JWT bypass capability"],
                outputs=["Forged JWT token"],
            ),
            ChainStep(
                step_number=3,
                finding_type="impersonation",
                description="Forged token used to impersonate target user",
                impact="Full access as target user",
                prerequisites=["Forged JWT"],
                outputs=["User impersonation"],
            ),
        ],
        "remediation": [
            "Use strong signing algorithms (RS256, ES256)",
            "Use strong, random secrets for symmetric algorithms",
            "Always validate algorithm in code, not from token",
            "Set and validate token expiration",
            "Implement token revocation mechanism",
            "Use asymmetric keys when possible",
        ],
    },
    ChainType.CORS_TO_DATA_THEFT: {
        "name": "CORS Misconfiguration to Data Theft",
        "description": (
            "CORS misconfigurations allowing arbitrary origins can be exploited to "
            "steal sensitive data from authenticated users via malicious websites."
        ),
        "business_impact": (
            "Theft of user data, session tokens, and sensitive information when "
            "users visit attacker-controlled websites."
        ),
        "severity": "high",
        "required_any_of": ["cors_wildcard", "cors_null_origin", "cors_arbitrary_origin"],
        "required_all_of": [],
        "optional_findings": ["cors_credentials_exposed"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="cors_misconfiguration",
                description="Application allows cross-origin requests from any origin",
                impact="Cross-origin data access possible",
                prerequisites=["CORS misconfiguration"],
                outputs=["Cross-origin request capability"],
            ),
            ChainStep(
                step_number=2,
                finding_type="phishing_setup",
                description="Attacker creates malicious website with exploit code",
                impact="Attack delivery mechanism ready",
                prerequisites=["CORS bypass"],
                outputs=["Malicious website"],
            ),
            ChainStep(
                step_number=3,
                finding_type="data_theft",
                description="Victim visits site, their data is exfiltrated cross-origin",
                impact="User data stolen via authenticated requests",
                prerequisites=["Victim visiting malicious site while logged in"],
                outputs=["Stolen user data", "Session tokens"],
            ),
        ],
        "remediation": [
            "Use explicit origin allowlist, never wildcard with credentials",
            "Validate Origin header against allowlist",
            "Never reflect Origin header directly",
            "Use same-origin cookies where possible",
            "Implement CSRF protection as defense in depth",
        ],
    },
    ChainType.XXE_TO_DATA_EXFIL: {
        "name": "XXE to Data Exfiltration",
        "description": (
            "XML External Entity (XXE) injection can be used to read local files, "
            "perform SSRF attacks, and exfiltrate sensitive data from the server."
        ),
        "business_impact": (
            "Exposure of sensitive server files including configuration, credentials, "
            "and source code. Can escalate to SSRF for internal network access."
        ),
        "severity": "critical",
        "required_any_of": ["xxe_confirmed", "xml_external_entity", "xxe_injection"],
        "required_all_of": [],
        "optional_findings": ["internal_file_read", "ssrf_via_xxe", "out_of_band_xxe", "blind_xxe"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="xxe",
                description="Attacker injects malicious XML with external entity declaration",
                impact="XML parser processes external entities",
                prerequisites=["XXE vulnerability in XML parser"],
                outputs=["Entity resolution capability"],
            ),
            ChainStep(
                step_number=2,
                finding_type="file_read",
                description="External entity used to read local files (e.g., /etc/passwd, config files)",
                impact="Sensitive file contents exposed",
                prerequisites=["XXE injection", "File system access"],
                outputs=["Configuration files", "Credentials", "Source code"],
            ),
            ChainStep(
                step_number=3,
                finding_type="data_exfiltration",
                description="Extracted data sent to attacker via out-of-band channel or response",
                impact="Sensitive data exfiltrated",
                prerequisites=["File read capability or SSRF"],
                outputs=["Stolen credentials", "Internal network access"],
            ),
        ],
        "remediation": [
            "Disable external entity processing in XML parsers",
            "Use less complex data formats (JSON) where possible",
            "Update XML parsing libraries to latest versions",
            "Implement input validation for XML content",
            "Use allowlists for XML schemas",
            "Apply principle of least privilege to application file access",
        ],
    },
    ChainType.DESERIALIZATION_TO_RCE: {
        "name": "Insecure Deserialization to Remote Code Execution",
        "description": (
            "Insecure deserialization vulnerabilities allow attackers to manipulate "
            "serialized objects to achieve remote code execution on the server."
        ),
        "business_impact": (
            "Complete server compromise with arbitrary code execution. Attackers can "
            "access all data, pivot to internal systems, and establish persistence."
        ),
        "severity": "critical",
        "required_any_of": ["insecure_deserialization", "java_deserialization", "php_deserialization", "python_deserialization", "dotnet_deserialization"],
        "required_all_of": [],
        "optional_findings": ["java_detected", "php_detected", "known_gadget_chain", "serialized_object_found"],
        "steps": [
            ChainStep(
                step_number=1,
                finding_type="deserialization_sink",
                description="Attacker identifies deserialization endpoint accepting untrusted data",
                impact="Entry point for malicious serialized objects",
                prerequisites=["Application deserializes user-controlled data"],
                outputs=["Deserialization endpoint"],
            ),
            ChainStep(
                step_number=2,
                finding_type="gadget_chain",
                description="Attacker crafts malicious serialized object using known gadget chains",
                impact="Exploit payload prepared",
                prerequisites=["Knowledge of application libraries", "Available gadget chains"],
                outputs=["Malicious serialized payload"],
            ),
            ChainStep(
                step_number=3,
                finding_type="rce",
                description="Malicious object triggers code execution during deserialization",
                impact="Arbitrary code execution on server",
                prerequisites=["Successful gadget chain execution"],
                outputs=["Shell access", "System compromise"],
            ),
        ],
        "remediation": [
            "Avoid deserializing untrusted data",
            "Use integrity checks (HMAC) on serialized objects",
            "Implement type constraints during deserialization",
            "Keep serialization libraries updated",
            "Use allowlists for deserializable classes",
            "Consider using safer data formats like JSON",
            "Implement application-level sandboxing",
        ],
    },
}


CHAIN_COMPLETENESS_THRESHOLD = 0.8


def _normalize_type(value: str | None) -> str:
    if not value:
        return ""
    return value.lower().replace(" ", "_").replace("-", "_")


def extract_finding_types(finding: dict) -> set[str]:
    """
    Extract finding types from a single finding.

    Args:
        finding: Finding dictionary

    Returns:
        Set of finding type strings
    """
    types = set()

    # Get the finding type/name - check multiple field names used by scanner
    finding_type = finding.get("type", finding.get("name", finding.get("vulnerability_type", finding.get("tool", ""))))
    finding_type_norm = _normalize_type(finding_type)
    if finding_type_norm:
        types.add(finding_type_norm)

    # Also check for specific vulnerability indicators
    # Check both description and title fields (scanner uses title)
    description = finding.get("description", finding.get("title", "")).lower()
    # Get tool name for pattern matching
    tool_name = finding.get("tool", "").lower()

    # XSS detection - check tool name and description
    if "xss" in description or "cross-site scripting" in description or "xss" in tool_name or "dalfox" in tool_name:
        if "reflected" in description:
            types.add("reflected_xss")
        elif "stored" in description:
            types.add("stored_xss")
        elif "dom" in description or "dom_xss" in tool_name:
            types.add("dom_xss")
        else:
            types.add("xss")

    # SQLi detection - check tool name and description
    if "sql injection" in description or "sqli" in finding_type_norm or "sqli" in tool_name or "sql_injection" in tool_name:
        types.add("sqli_confirmed")
        if "union" in description:
            types.add("sqli_union")
        if "time" in description or "blind" in description:
            types.add("sqli_time_based")
        if "error" in description:
            types.add("sqli_error_based")

    # NoSQL injection detection
    if "nosql" in description or "nosql" in finding_type_norm or "nosql" in tool_name:
        types.add("nosql_injection")

    # SSRF detection
    if "ssrf" in description or "server-side request" in description:
        types.add("ssrf_confirmed")
        if "internal" in description or "localhost" in description:
            types.add("ssrf_internal_access")
        if "metadata" in description or "169.254" in description:
            types.add("cloud_metadata_exposed")

    # LFI detection
    if "local file" in description or "path traversal" in description or "lfi" in finding_type_norm:
        types.add("lfi_confirmed")
        types.add("path_traversal")

    # IDOR detection
    if "idor" in description or "insecure direct object" in description or "bola" in description:
        types.add("idor_confirmed")
        types.add("bola_confirmed")
        types.add("broken_access_control")

    # JWT detection
    if "jwt" in description:
        if "none" in description and "algorithm" in description:
            types.add("jwt_none_algorithm")
        if "weak" in description and "secret" in description:
            types.add("jwt_weak_secret")
        if "expir" in description:
            types.add("jwt_missing_expiry")
        if "algorithm confusion" in description or ("alg" in description and "confusion" in description):
            types.add("jwt_algorithm_confusion")
        if "kid" in description and "inject" in description:
            types.add("jwt_kid_injection")
        if "jku" in description:
            types.add("jwt_jku_spoofing")

    # Cookie flags - check description/title
    if "httponly" in description and ("missing" in description or "not set" in description or "without" in description):
        types.add("missing_httponly")
        types.add("insecure_cookie")
    if "secure" in description and ("missing" in description or "not set" in description or "without" in description):
        types.add("missing_secure_flag")
        types.add("insecure_cookie")
    if "samesite" in description and ("missing" in description or "not set" in description or "none" in description):
        types.add("missing_samesite")
        types.add("insecure_cookie")
    # Direct cookie security check
    if "cookie" in description and ("insecure" in description or "session" in description):
        types.add("insecure_cookie")

    # CSP - check tool name and description
    if "csp" in description or "content-security-policy" in description or "csp" in tool_name:
        if "weak" in description or "missing" in description or "unsafe" in description or tool_name == "csp_evaluator":
            types.add("weak_csp")

    # CORS - check tool name and description
    if "cors" in description or "cors" in tool_name:
        types.add("cors_misconfiguration")
        if "wildcard" in description or "access-control-allow-origin: *" in description or "*" in description:
            types.add("cors_wildcard")
        if "null" in description:
            types.add("cors_null_origin")
        if "arbitrary origin" in description or ("origin" in description and "reflect" in description):
            types.add("cors_arbitrary_origin")

    # Admin panels
    if "admin" in description and ("panel" in description or "interface" in description):
        types.add("admin_panel_found")

    # XXE detection
    if "xxe" in description or "xml external entity" in description or "xml injection" in finding_type_norm:
        types.add("xxe_confirmed")
        types.add("xml_external_entity")
        types.add("xxe_injection")
        if "file" in description and "read" in description:
            types.add("internal_file_read")
        if "ssrf" in description or "server-side request" in description:
            types.add("ssrf_via_xxe")
        if "out-of-band" in description or "oob" in description or "blind" in description:
            types.add("out_of_band_xxe")
            types.add("blind_xxe")

    # Deserialization detection
    if "deserialization" in description or "deserialize" in description or "unserialize" in description:
        types.add("insecure_deserialization")
        if "java" in description or "objectinputstream" in description:
            types.add("java_deserialization")
            types.add("java_detected")
        if "php" in description or "unserialize" in finding_type_norm:
            types.add("php_deserialization")
            types.add("php_detected")
        if "python" in description:
            types.add("python_deserialization")
        if ".net" in description or "binaryformatter" in description:
            types.add("dotnet_deserialization")
        if "gadget" in description:
            types.add("known_gadget_chain")

    return types


def analyze_finding_types(findings: list[dict]) -> tuple[set[str], dict[str, list[dict]]]:
    """
    Extract finding types from a list of findings.

    Args:
        findings: List of finding dictionaries

    Returns:
        Tuple of (set of finding type strings, mapping of type -> findings)
    """
    types: set[str] = set()
    type_to_findings: dict[str, list[dict]] = {}

    for finding in findings:
        finding_types = extract_finding_types(finding)
        for t in finding_types:
            types.add(t)
            type_to_findings.setdefault(t, []).append(finding)

    return types, type_to_findings


def calculate_chain_completeness(
    chain_template: dict,
    found_types: set[str],
) -> tuple[float, list[str], list[str], list[str], list[str], list[str], list[str]]:
    """
    Calculate how complete an attack chain is based on found vulnerabilities.

    Args:
        chain_template: Chain template definition
        found_types: Set of found vulnerability types

    Returns:
        Tuple of (completeness_score, matched_required_any, matched_required_all, matched_optional,
        missing_required_any, missing_required_all, missing_optional)
    """
    required_any_of = chain_template.get("required_any_of") or chain_template.get("required_findings", [])
    required_all_of = chain_template.get("required_all_of", [])
    optional = chain_template.get("optional_findings", [])

    matched_required_any = []
    matched_required_all = []
    matched_optional = []

    # Check required_any_of (any one match is enough)
    for req in required_any_of:
        if req in found_types:
            matched_required_any.append(req)

    # Check required_all_of (all must be present for completion)
    for req in required_all_of:
        if req in found_types:
            matched_required_all.append(req)

    # Check optional findings
    for opt in optional:
        if opt in found_types:
            matched_optional.append(opt)

    missing_required_any = [req for req in required_any_of if req not in found_types]
    missing_required_all = [req for req in required_all_of if req not in found_types]
    missing_optional = [opt for opt in optional if opt not in found_types]

    # Calculate completeness
    required_any_satisfied = not required_any_of or bool(matched_required_any)
    if not required_any_satisfied:
        return 0.0, [], [], [], missing_required_any, missing_required_all, missing_optional

    # Base score for having required_any_of (or none configured)
    base_score = 0.5 if required_any_of else 0.3

    # Required-all contribution
    if required_all_of:
        required_all_ratio = len(matched_required_all) / len(required_all_of)
        base_score += 0.3 * required_all_ratio
    else:
        base_score += 0.3

    # Bonus for optional findings (up to 0.2 extra)
    if optional:
        optional_bonus = (len(matched_optional) / len(optional)) * 0.2
        base_score += optional_bonus

    return min(base_score, 1.0), matched_required_any, matched_required_all, matched_optional, missing_required_any, missing_required_all, missing_optional


def _downgrade_severity(severity: str) -> str:
    """Lower severity by one step for partial chains."""
    order = ["critical", "high", "medium", "low", "info"]
    try:
        idx = order.index(severity)
    except ValueError:
        return severity
    return order[min(idx + 1, len(order) - 1)]


def build_attack_chain(
    chain_type: ChainType,
    template: dict,
    required_any_of: list[str],
    required_all_of: list[str],
    matched_required_any: list[str],
    matched_required_all: list[str],
    matched_optional: list[str],
    findings: list[dict],
    status: str = "complete",
    missing_required_any: list[str] | None = None,
    missing_required_all: list[str] | None = None,
    missing_optional: list[str] | None = None,
    confidence: float = 0.0,
    type_to_findings: dict[str, list[dict]] | None = None,
) -> AttackChain:
    """
    Build an AttackChain object from template and matched findings.

    Args:
        chain_type: Type of attack chain
        template: Chain template
        matched_required: Matched required findings
        matched_optional: Matched optional findings
        findings: Original findings list for evidence

    Returns:
        AttackChain object
    """
    required_any_of = required_any_of or []
    required_all_of = required_all_of or []
    matched_required_any = matched_required_any or []
    matched_required_all = matched_required_all or []
    matched_optional = matched_optional or []
    missing_required_any = missing_required_any or []
    missing_required_all = missing_required_all or []
    missing_optional = missing_optional or []

    matched_required = sorted(set(matched_required_any + matched_required_all))

    missing_required = []
    if required_any_of and not matched_required_any:
        missing_required.append(f"one_of:{' | '.join(required_any_of)}")
    missing_required.extend(missing_required_all)

    # Find relevant evidence from findings
    evidence = {
        "matched_vulnerabilities": matched_required + matched_optional,
        "supporting_findings": [],
    }

    def summarize_finding(finding: dict, matched_type: str | None = None) -> dict:
        validation = finding.get("validation", {}) if isinstance(finding.get("validation"), dict) else {}
        return {
            "id": finding.get("id") or finding.get("fingerprint"),
            "title": finding.get("title", finding.get("name", finding.get("type"))),
            "severity": finding.get("severity"),
            "url": finding.get("url", finding.get("location")),
            "confidence": finding.get("confidence"),
            "confidence_tier": finding.get("confidence_tier"),
            "verified": finding.get("verified") is True or validation.get("verified") is True,
            "tool": finding.get("tool"),
            "matched_type": matched_type,
        }

    def dedupe_findings(items: list[dict]) -> list[dict]:
        seen = set()
        unique = []
        for item in items:
            key = item.get("id") or (item.get("title"), item.get("url"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        return unique

    if type_to_findings:
        collected = []
        for t in sorted(set(matched_required + matched_optional)):
            for finding in type_to_findings.get(t, []):
                collected.append(summarize_finding(finding, matched_type=t))
        evidence["supporting_findings"] = dedupe_findings(collected)
    else:
        for finding in findings:
            finding_type = _normalize_type(finding.get("type", finding.get("name", "")))
            if any(m in finding_type or finding_type in m for m in matched_required + matched_optional):
                evidence["supporting_findings"].append(summarize_finding(finding))

    confidence = calculate_chain_confidence(evidence.get("supporting_findings", [])) or confidence

    # Create chain steps with evidence
    steps = []
    for step_data in template.get("steps", []):
        step = ChainStep(
            step_number=step_data.step_number,
            finding_type=step_data.finding_type,
            description=step_data.description,
            impact=step_data.impact,
            prerequisites=step_data.prerequisites,
            outputs=step_data.outputs,
        )
        steps.append(step)

    return AttackChain(
        chain_type=chain_type,
        name=template["name"],
        description=template["description"],
        severity=template["severity"],
        business_impact=template["business_impact"],
        steps=steps,
        required_any_of=required_any_of,
        required_all_of=required_all_of,
        matched_required_any=matched_required_any,
        matched_required_all=matched_required_all,
        matched_optional=matched_optional,
        required_findings=matched_required,
        optional_findings=matched_optional,
        evidence=evidence,
        remediation=template["remediation"],
        status=status,
        missing_required=missing_required,
        missing_required_any=missing_required_any,
        missing_required_all=missing_required_all,
        missing_optional=missing_optional,
        confidence=confidence,
    )


def calculate_chain_confidence(supporting_findings: list[dict]) -> float:
    if not supporting_findings:
        return 0.0

    tier_scores = {
        "verified": 0.9,
        "high": 0.75,
        "medium": 0.5,
        "low": 0.3,
        "uncertain": 0.2,
    }

    scores = []
    verified_count = 0
    for finding in supporting_findings:
        conf = finding.get("confidence")
        if isinstance(conf, (int, float)):
            score = max(0.0, min(1.0, float(conf)))
        else:
            tier = finding.get("confidence_tier")
            score = tier_scores.get(tier, 0.4)
        scores.append(score)
        if finding.get("verified") is True:
            verified_count += 1

    base = sum(scores) / len(scores)
    if verified_count:
        base += 0.1
        if verified_count == len(scores):
            base += 0.1

    return min(base, 1.0)


def _chain_has_verified_supporting_evidence(chain: AttackChain) -> bool:
    supporting = chain.evidence.get("supporting_findings", [])
    return any(isinstance(item, dict) and item.get("verified") is True for item in supporting)


def _mark_chain_partial_for_unverified_evidence(chain: AttackChain) -> None:
    chain.status = "partial"
    chain.severity = _downgrade_severity(chain.severity)
    chain.missing_required.append("verified_exploit_evidence")
    chain.missing_required_all.append("verified_exploit_evidence")
    chain.evidence["chain_quality"] = "unverified_supporting_evidence"
    chain.evidence["quality_reason"] = (
        "Complete attack-chain reporting requires at least one verified supporting finding."
    )


def _identify_attack_chains_internal(findings: list[dict]) -> tuple[list[AttackChain], list[AttackChain]]:
    """
    Identify possible attack chains from a list of findings.

    Args:
        findings: List of vulnerability findings

    Returns:
        Tuple of (complete_chains, partial_chains)
    """
    if not findings:
        return [], []

    # Extract finding types
    found_types, type_to_findings = analyze_finding_types(findings)

    if not found_types:
        return [], []

    chains: list[AttackChain] = []
    partial_chains: list[AttackChain] = []

    # Check each chain template
    for chain_type, template in CHAIN_TEMPLATES.items():
        required_any_of = template.get("required_any_of") or template.get("required_findings", [])
        required_all_of = template.get("required_all_of", [])

        completeness, matched_any, matched_all, matched_opt, missing_any, missing_all, missing_opt = calculate_chain_completeness(
            template, found_types
        )

        if completeness > 0:
            required_any_satisfied = not required_any_of or bool(matched_any)
            required_all_satisfied = not required_all_of or len(matched_all) == len(required_all_of)
            is_complete = required_any_satisfied and required_all_satisfied and completeness >= CHAIN_COMPLETENESS_THRESHOLD
            status = "complete" if is_complete else "partial"

            chain = build_attack_chain(
                chain_type=chain_type,
                template=template,
                required_any_of=required_any_of,
                required_all_of=required_all_of,
                matched_required_any=matched_any,
                matched_required_all=matched_all,
                matched_optional=matched_opt,
                findings=findings,
                status=status,
                missing_required_any=missing_any,
                missing_required_all=missing_all,
                missing_optional=missing_opt,
                confidence=completeness,
                type_to_findings=type_to_findings,
            )
            chain.completeness = completeness
            if is_complete:
                if _chain_has_verified_supporting_evidence(chain):
                    chains.append(chain)
                else:
                    _mark_chain_partial_for_unverified_evidence(chain)
                    partial_chains.append(chain)
            else:
                chain.severity = _downgrade_severity(chain.severity)
                partial_chains.append(chain)

    # Sort by completeness and severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    chains.sort(key=lambda c: (severity_order.get(c.severity, 4), -c.completeness))
    partial_chains.sort(key=lambda c: (severity_order.get(c.severity, 4), -c.completeness))

    return chains, partial_chains


def identify_attack_chains(findings: list[dict]) -> list[AttackChain]:
    """Return complete attack chains only (backwards-compatible)."""
    chains, _ = _identify_attack_chains_internal(findings)
    return chains


def format_chain_report(
    chains: list[AttackChain],
    partial_chains: list[AttackChain] | None = None,
    include_partial_chains: bool = False,
) -> str:
    """Format attack chains into a readable report."""
    if not chains and not (include_partial_chains and partial_chains):
        return "No attack chains identified from the current findings."

    lines = []
    lines.append("=" * 70)
    lines.append("ATTACK CHAIN ANALYSIS")
    lines.append("=" * 70)
    lines.append(f"\nIdentified {len(chains)} complete attack chain(s):\n")

    for i, chain in enumerate(chains, 1):
        lines.append(f"\n{'─' * 60}")
        lines.append(f"Chain #{i}: {chain.name}")
        lines.append(f"{'─' * 60}")
        lines.append(f"Severity: {chain.severity.upper()}")
        lines.append(f"Completeness: {chain.completeness * 100:.0f}%")
        lines.append(f"\nDescription:\n{chain.description}")
        lines.append(f"\nBusiness Impact:\n{chain.business_impact}")

        lines.append("\nAttack Steps:")
        for step in chain.steps:
            lines.append(f"  {step.step_number}. {step.description}")
            lines.append(f"     Impact: {step.impact}")

        lines.append("\nMatched Vulnerabilities:")
        for vuln in chain.required_findings:
            lines.append(f"  [REQUIRED] {vuln}")
        for vuln in chain.optional_findings:
            lines.append(f"  [SUPPORTING] {vuln}")

        lines.append("\nRemediation:")
        for j, rem in enumerate(chain.remediation, 1):
            lines.append(f"  {j}. {rem}")

    if include_partial_chains and partial_chains:
        lines.append("\n" + "=" * 70)
        lines.append("POTENTIAL ATTACK CHAINS (PARTIAL)")
        lines.append("=" * 70)
        lines.append(f"\nIdentified {len(partial_chains)} partial chain(s):\n")

        for i, chain in enumerate(partial_chains, 1):
            lines.append(f"\n{'─' * 60}")
            lines.append(f"Partial Chain #{i}: {chain.name}")
            lines.append(f"{'─' * 60}")
            lines.append(f"Severity (downgraded): {chain.severity.upper()}")
            lines.append(f"Confidence: {chain.confidence * 100:.0f}%")
            lines.append(f"\nDescription:\n{chain.description}")
            lines.append(f"\nBusiness Impact:\n{chain.business_impact}")

            lines.append("\nMatched Vulnerabilities:")
            for vuln in chain.required_findings:
                lines.append(f"  [REQUIRED] {vuln}")
            for vuln in chain.optional_findings:
                lines.append(f"  [SUPPORTING] {vuln}")

            if chain.missing_required or chain.missing_optional:
                lines.append("\nMissing Evidence:")
                for vuln in chain.missing_required:
                    lines.append(f"  [REQUIRED] {vuln}")
                for vuln in chain.missing_optional:
                    lines.append(f"  [SUPPORTING] {vuln}")

            lines.append("\nRemediation:")
            for j, rem in enumerate(chain.remediation, 1):
                lines.append(f"  {j}. {rem}")

    return "\n".join(lines)


def chains_to_dict(chains: list[AttackChain]) -> list[dict]:
    """Convert attack chains to dictionary format."""
    return [
        {
            "chain_type": chain.chain_type.value,
            "name": chain.name,
            "description": chain.description,
            "severity": chain.severity,
            "business_impact": chain.business_impact,
            "completeness": chain.completeness,
            "status": chain.status,
            "confidence": chain.confidence,
            "required_any_of": chain.required_any_of,
            "required_all_of": chain.required_all_of,
            "matched_required_any": chain.matched_required_any,
            "matched_required_all": chain.matched_required_all,
            "matched_optional": chain.matched_optional,
            "missing_required": chain.missing_required,
            "missing_required_any": chain.missing_required_any,
            "missing_required_all": chain.missing_required_all,
            "missing_optional": chain.missing_optional,
            "steps": [
                {
                    "step_number": s.step_number,
                    "finding_type": s.finding_type,
                    "description": s.description,
                    "impact": s.impact,
                    "prerequisites": s.prerequisites,
                    "outputs": s.outputs,
                }
                for s in chain.steps
            ],
            "matched_vulnerabilities": {
                "required": chain.required_findings,
                "supporting": chain.optional_findings,
            },
            "evidence": chain.evidence,
            "remediation": chain.remediation,
        }
        for chain in chains
    ]


# Main entry point for scanner integration
def analyze_attack_chains(findings: list[dict], include_partial_chains: bool = False) -> dict[str, Any]:
    """
    Main entry point for attack chain analysis.

    Args:
        findings: List of vulnerability findings from scan
        include_partial_chains: Include partial chains in the human-readable report

    Returns:
        Dict with chains, report, and summary
    """
    chains, partial_chains = _identify_attack_chains_internal(findings)

    report_partials = partial_chains if include_partial_chains else []

    return {
        "chains": chains_to_dict(chains),
        "partial_chains": chains_to_dict(partial_chains),
        "report": format_chain_report(chains, report_partials, include_partial_chains=include_partial_chains),
        "summary": {
            "total_chains": len(chains),
            "total_partial_chains": len(partial_chains),
            "critical_chains": sum(1 for c in chains if c.severity == "critical"),
            "high_chains": sum(1 for c in chains if c.severity == "high"),
            "chain_types": [c.chain_type.value for c in chains],
            "partial_chain_types": [c.chain_type.value for c in partial_chains],
            "partial_chains_included": include_partial_chains,
        },
    }
