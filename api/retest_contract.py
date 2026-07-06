#!/usr/bin/env python3
"""
Shared retest queue contract and policy helpers.

This module is imported by both API and worker processes to keep retest
payload semantics, type normalization, and retry classification consistent.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

RETEST_QUEUE_SCHEMA_VERSION = 1
ASM_ENDPOINT_FINGERPRINT_MIGRATION = "asm_endpoint_fingerprint_v2"

# ---------------------------------------------------------------------------
# Verification Policy: single source of truth for severity gates
# ---------------------------------------------------------------------------

SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _normalize_severity(value: str | None, default: str = "high") -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in SEVERITY_ORDER else default


@dataclass(frozen=True)
class VerificationPolicy:
    """Single source of truth for all verification severity gates.

    Workers, scanner, and API should all derive thresholds from a single
    ``VerificationPolicy`` instance rather than reading independent env vars.
    """

    verification_min_severity: str = "medium"
    """Minimum finding severity for *any* verification (scan-time + retest)."""

    ai_escalation_min_severity: str = "high"
    """Minimum finding severity to escalate from deterministic to AI tier."""

    auto_retest_enabled: bool = True
    auto_retest_max_per_scan: int = 25
    proof_required_for_smart: bool = False
    """When True, smart scans default to verified-findings-only output."""

    auto_fp_on_retest: bool = False
    """When True, a retest that concludes a high-confidence false_positive may
    flip the finding's lifecycle status active -> false_positive. OFF by default:
    a wrong auto-FP hides a real vulnerability, so a human stays in the loop
    unless a team explicitly opts in."""

    auto_fp_min_confidence: float = 0.9
    """Minimum retest confidence required before auto_fp_on_retest acts. Higher
    than the false_positive verdict bar (0.7) because auto-closing a finding is
    riskier than merely labeling the verdict."""

    @classmethod
    def from_env(cls, overrides: dict[str, Any] | None = None) -> "VerificationPolicy":
        """Build policy from env vars with optional Redis/runtime overrides."""
        ov = overrides or {}

        verification_min = _normalize_severity(
            ov.get("verification_min_severity")
            or ov.get("auto_retest_min_severity")
            or os.environ.get("VERIFICATION_MIN_SEVERITY")
            or os.environ.get("AUTO_RETEST_MIN_SEVERITY"),
            default="medium",
        )
        ai_min = _normalize_severity(
            ov.get("ai_escalation_min_severity")
            or ov.get("ai_verify_min_severity")
            or os.environ.get("AI_ESCALATION_MIN_SEVERITY")
            or os.environ.get("AI_VERIFY_MIN_SEVERITY"),
            default="high",
        )

        def _truthy(val: Any, default: bool) -> bool:
            if val is None:
                return default
            return str(val).strip().lower() in {"1", "true", "yes", "on"}

        auto_enabled = _truthy(
            ov.get("auto_retest_on_scan_complete")
            if "auto_retest_on_scan_complete" in (ov or {})
            else os.environ.get("AUTO_RETEST_ON_SCAN_COMPLETE", "true"),
            default=True,
        )

        max_per = 25
        raw_max = ov.get("auto_retest_max_per_scan") if ov.get("auto_retest_max_per_scan") is not None else os.environ.get("AUTO_RETEST_MAX_PER_SCAN", "25")
        try:
            max_per = max(0, int(raw_max))
        except (TypeError, ValueError):
            pass

        proof_req = _truthy(
            ov.get("proof_required_for_smart")
            if "proof_required_for_smart" in (ov or {})
            else os.environ.get("PROOF_REQUIRED_FOR_SMART", "false"),
            default=False,
        )

        auto_fp = _truthy(
            ov.get("auto_fp_on_retest")
            if "auto_fp_on_retest" in (ov or {})
            else os.environ.get("AUTO_FP_ON_RETEST", "false"),
            default=False,
        )

        auto_fp_conf = 0.9
        raw_fp_conf = (
            ov.get("auto_fp_min_confidence")
            if ov.get("auto_fp_min_confidence") is not None
            else os.environ.get("AUTO_FP_MIN_CONFIDENCE", "0.9")
        )
        try:
            auto_fp_conf = min(1.0, max(0.0, float(raw_fp_conf)))
        except (TypeError, ValueError):
            pass

        return cls(
            verification_min_severity=verification_min,
            ai_escalation_min_severity=ai_min,
            auto_retest_enabled=auto_enabled,
            auto_retest_max_per_scan=max_per,
            proof_required_for_smart=proof_req,
            auto_fp_on_retest=auto_fp,
            auto_fp_min_confidence=auto_fp_conf,
        )

    def severity_allows_verification(self, severity: str) -> bool:
        return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(
            self.verification_min_severity, SEVERITY_ORDER["medium"]
        )

    def severity_allows_ai(self, severity: str) -> bool:
        return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(
            self.ai_escalation_min_severity, SEVERITY_ORDER["high"]
        )

SUPPORTED_RETEST_TYPES: tuple[str, ...] = (
    "xss",
    "sqli",
    "nosqli",
    "ssrf",
    "path_traversal",
    "open_redirect",
    "cors",
    "2fa_bypass",
    "command_injection",
    "ssti",
    "xxe",
    "jwt",
    "idor",
    "bola",
    "exposed_file",
    "generic_http",
)

# Types whose attempt ladder has no deterministic prover steps; the worker
# returns an "escalate to AI" base result instead of walking provers.
AI_ONLY_RETEST_TYPES: frozenset[str] = frozenset({"2fa_bypass", "generic_http"})

SUPPORTED_RETEST_VERDICTS: tuple[str, ...] = (
    "exploited",
    "likely_vulnerable",
    "blocked_by_security",
    "out_of_scope_internal",
    "false_positive",
    "likely_fixed",
    "inconclusive",
    "error",
)

RETEST_TYPE_ALIASES: dict[str, str] = {
    "xss": "xss",
    "cross-site-scripting": "xss",
    "cross_site_scripting": "xss",
    "sqli": "sqli",
    "sql-injection": "sqli",
    "sql_injection": "sqli",
    "nosqli": "nosqli",
    "nosql_injection": "nosqli",
    "nosql-injection": "nosqli",
    "no_sql_injection": "nosqli",
    "nosqli_injection": "nosqli",
    "ssrf": "ssrf",
    "server-side-request-forgery": "ssrf",
    "server_side_request_forgery": "ssrf",
    "path_traversal": "path_traversal",
    "path-traversal": "path_traversal",
    "lfi": "path_traversal",
    "local-file-inclusion": "path_traversal",
    "open_redirect": "open_redirect",
    "open-redirect": "open_redirect",
    "url_redirect": "open_redirect",
    "url-redirect": "open_redirect",
    "cors": "cors",
    "cors_misconfiguration": "cors",
    "2fa_bypass": "2fa_bypass",
    "2fa-bypass": "2fa_bypass",
    "mfa_bypass": "2fa_bypass",
    "mfa-bypass": "2fa_bypass",
    "otp_bypass": "2fa_bypass",
    "otp-bypass": "2fa_bypass",
    "command_injection": "command_injection",
    "command-injection": "command_injection",
    "os_command_injection": "command_injection",
    "os-command-injection": "command_injection",
    "rce": "command_injection",
    "remote_code_execution": "command_injection",
    "ssti": "ssti",
    "server_side_template_injection": "ssti",
    "server-side-template-injection": "ssti",
    "template_injection": "ssti",
    "template-injection": "ssti",
    "xxe": "xxe",
    "xml_external_entity": "xxe",
    "xml-external-entity": "xxe",
    "jwt": "jwt",
    "jwt_weakness": "jwt",
    "jwt-weakness": "jwt",
    "jwt_vulnerability": "jwt",
    "idor": "idor",
    "insecure_direct_object_reference": "idor",
    "insecure-direct-object-reference": "idor",
    "bola": "bola",
    "broken_object_level_authorization": "bola",
    "broken-object-level-authorization": "bola",
    # BFLA / broken access control -> cross_user_access (bola) prover: replaying a
    # privileged request as a lower-privileged user is the deterministic proof.
    "bfla": "bola",
    "broken_function_level_authorization": "bola",
    "broken-function-level-authorization": "bola",
    "broken_function_level_auth": "bola",
    "function_level_authorization": "bola",
    "broken_access_control": "bola",
    "broken-access-control": "bola",
    "missing_function_level_access_control": "bola",
    "exposed_file": "exposed_file",
    "exposed-file": "exposed_file",
    "exposed_files": "exposed_file",
    "sensitive_file_exposure": "exposed_file",
    "forced_browsing": "exposed_file",
    "forced-browsing": "exposed_file",
    "generic_http": "generic_http",
}

# Scanner tool name -> retest type. Tool names are stable identifiers, so they
# are a far more reliable inference signal than title keyword matching.
RETEST_TOOL_TYPE_MAP: dict[str, str] = {
    "dalfox": "xss",
    "dom_xss": "xss",
    "smart_xss": "xss",
    "custom_xss": "xss",
    "sqlmap": "sqli",
    "smart_sqli": "sqli",
    "custom_sqli": "sqli",
    "oob_sqli": "sqli",
    "nosql_injection": "nosqli",
    "smart_nosql": "nosqli",
    "nosqli": "nosqli",
    "2fa_bypass": "2fa_bypass",
    "mfa_bypass": "2fa_bypass",
    "commix": "command_injection",
    "smart_bola": "bola",
    "bola": "bola",
    "idor_bola": "bola",
    # BFLA / broken-access-control tools -> cross_user_access (bola) prover.
    "bfla": "bola",
    "smart_bfla": "bola",
    "broken_function_level_authorization": "bola",
    "access_control": "bola",
    "forced_browsing": "exposed_file",
    "exposed_files": "exposed_file",
    # Singular tool name emitted by the directory-listing harvest
    # (scanner.py normalize_finding("exposed_file", ...)). Without this the
    # harvested exposures fell back to title matching, which their
    # "Sensitive file exposed: X" wording missed, leaving them permanently
    # unverified. Evidence.type also carries this now; the tool map is the
    # more reliable identifier so both routes agree.
    "exposed_file": "exposed_file",
}

DEFAULT_REPLAY_PAYLOADS: dict[str, str] = {
    "xss": "<script>alert(1)</script>",
    "sqli": "' OR '1'='1",
    "ssrf": "http://127.0.0.1:80/",
    "path_traversal": "../../../etc/passwd",
    "open_redirect": "https://example.org/",
    "cors": "https://evil.example.org",
    "2fa_bypass": "000000",
    "command_injection": "; id",
    "ssti": "{{7*7}}",
    "xxe": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
    "jwt": '{"alg":"none"}',
    "idor": "",
    "bola": "",
    "exposed_file": "",
    "generic_http": "",
}

# Ladder names intentionally use stable identifiers so UI/reporting can
# consistently aggregate attempt strategy analytics across versions.
ATTEMPT_LADDERS: dict[str, list[str]] = {
    "xss": ["headless_dom_execution", "reflection_context", "alternate_payloads", "ai_reasoning"],
    "sqli": ["dbms_extraction", "boolean_diff", "timing_fallback", "ai_reasoning"],
    "ssrf": ["oob_callback", "internal_resource_access", "ai_reasoning"],
    "path_traversal": ["direct_traversal", "encoding_bypass", "ai_reasoning"],
    "open_redirect": ["query_redirect_param", "post_redirect_param", "location_header_check", "ai_reasoning"],
    "cors": ["origin_reflection_probe", "wildcard_credentials_probe", "ai_reasoning"],
    "2fa_bypass": ["otp_bruteforce_window", "ai_reasoning"],
    "command_injection": ["oob_callback", "time_delay_proof", "output_injection", "ai_reasoning"],
    "ssti": ["template_expression_proof", "error_based_detection", "ai_reasoning"],
    "xxe": ["oob_xxe", "file_read_xxe", "ai_reasoning"],
    "jwt": ["none_algorithm", "weak_secret_bruteforce", "signature_strip", "ai_reasoning"],
    "idor": ["cross_user_access", "sequential_id_probe", "ai_reasoning"],
    "bola": ["cross_user_access", "sequential_id_probe", "ai_reasoning"],
    "exposed_file": ["content_marker_replay", "ai_reasoning"],
    "generic_http": ["ai_reasoning"],
}

RETRY_CLASS_PATTERNS: dict[str, tuple[str, ...]] = {
    "rate_limited": ("429", "too many requests", "rate limit"),
    "auth": ("401", "403", "unauthorized", "forbidden", "authentication"),
    "validation": ("invalid", "missing", "malformed", "unsupported"),
    "config": ("module unavailable", "no such file", "not installed", "dependency"),
    "transient": ("timeout", "timed out", "connection reset", "connection refused", "service unavailable"),
}

RETRYABLE_CLASSES: set[str] = {"rate_limited", "transient"}


def normalize_retest_type(value: str | None) -> str | None:
    if not value:
        return None
    return RETEST_TYPE_ALIASES.get(str(value).strip().lower())


def infer_type_from_title_tool(title: str | None, tool: str | None) -> str | None:
    """Infer a retest type from a finding's title/tool.

    Single source of truth for both the API retest endpoint and the worker
    (auto-retest + retest execution) so the two never disagree on whether a
    finding is retestable.
    """
    title = str(title or "").lower()
    tool = str(tool or "").lower()

    # NoSQL injection routes to the dedicated NoSQLi prover (operator-injection
    # differential), NOT the SQLi prover. This guard runs BEFORE the generic
    # "sql"+"inject" title check below (note "sql" is a substring of "nosql", so
    # without this guard a NoSQL finding would misroute to sqli and report a false
    # "likely_fixed"). Tool match is also handled here for nosql tools.
    if "nosql" in title or "no sql" in title or tool in ("nosql_injection", "smart_nosql", "nosqli"):
        return "nosqli"

    mapped = RETEST_TOOL_TYPE_MAP.get(tool)
    if mapped:
        return mapped

    if "xss" in title or "cross-site scripting" in title:
        return "xss"
    if ("sql" in title and "inject" in title) or "sqli" in title:
        return "sqli"
    if "ssrf" in title or "server-side request forgery" in title:
        return "ssrf"
    if any(k in title for k in ("path traversal", "local file inclusion", "directory traversal", "lfi", "../")):
        return "path_traversal"
    if "open redirect" in title or "url redirect" in title:
        return "open_redirect"
    if "cors" in title:
        return "cors"
    if "2fa bypass" in title or "mfa bypass" in title:
        return "2fa_bypass"
    if "command injection" in title or "rce" in title or "remote code execution" in title:
        return "command_injection"
    if "ssti" in title or "template injection" in title:
        return "ssti"
    if "xxe" in title or "xml external entity" in title:
        return "xxe"
    if "jwt" in title:
        return "jwt"
    if "bola" in title or "broken object level" in title:
        return "bola"
    # BFLA / broken access control -> cross_user_access (bola) prover.
    if any(k in title for k in (
        "broken function level", "broken function-level", "bfla",
        "broken access control", "function level authorization",
        "function-level authorization", "missing function level access")):
        return "bola"
    if "idor" in title or "insecure direct object" in title:
        return "idor"
    if (
        "exposed file" in title
        or "file exposed" in title          # "Sensitive file exposed: X" harvest wording
        or "sensitive file" in title
        or (title.startswith("accessible ") and ":" in title)
    ):
        return "exposed_file"
    return None


def get_attempt_ladder(finding_type: str | None) -> list[str]:
    normalized = normalize_retest_type(finding_type)
    if not normalized:
        return []
    return list(ATTEMPT_LADDERS.get(normalized, []))


def classify_retry(message: str | None) -> tuple[str, bool]:
    raw = str(message or "").strip().lower()
    if not raw:
        return "none", False

    for retry_class, patterns in RETRY_CLASS_PATTERNS.items():
        if any(p in raw for p in patterns):
            return retry_class, retry_class in RETRYABLE_CLASSES
    return "internal", False


def parse_json_field(value: Any) -> dict[str, Any]:
    """Parse a value into a dict, handling str/dict/None."""
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def infer_retest_inputs(verification: dict[str, Any]) -> dict[str, Any]:
    """Build effective retest inputs using verification row and finding evidence."""
    evidence = parse_json_field(verification.get("evidence"))

    finding_type = normalize_retest_type(verification.get("finding_type"))
    if not finding_type:
        finding_type = normalize_retest_type(evidence.get("type"))
    if not finding_type:
        finding_type = infer_type_from_title_tool(verification.get("title"), verification.get("tool"))

    target_url = verification.get("target_url") or verification.get("target") or verification.get("finding_url") or evidence.get("target") or ""
    original_url = verification.get("original_url") or verification.get("finding_url") or evidence.get("url") or target_url
    param = verification.get("param") or evidence.get("param") or evidence.get("parameter") or ""
    payload = verification.get("payload") or evidence.get("payload") or ""
    if not payload and isinstance(evidence.get("detail"), dict):
        payload = evidence.get("detail", {}).get("payload") or ""
    method = (verification.get("method") or evidence.get("method") or "GET").upper()
    request_body = verification.get("request_body") or evidence.get("body") or ""

    return {
        "finding_type": finding_type,
        "target_url": str(target_url).strip(),
        "original_url": str(original_url).strip() if original_url else "",
        "param": str(param).strip() if param else "",
        "payload": str(payload) if payload else "",
        "method": method,
        "request_body": str(request_body) if request_body else "",
        "evidence": evidence,
    }


def build_replay_commands(inputs: dict[str, Any]) -> list[str]:
    """Generate copy/paste commands to replay a verification attempt."""
    finding_type = str(inputs.get("finding_type") or "").strip().lower()
    target_url = str(inputs.get("original_url") or inputs.get("target_url") or "").strip()
    method = str(inputs.get("method") or "GET").strip().upper()
    param = str(inputs.get("param") or "").strip()
    payload = str(inputs.get("payload") or "").strip() or DEFAULT_REPLAY_PAYLOADS.get(finding_type, "test")

    if not target_url:
        return []

    commands: list[str] = []
    quoted_url = urllib.parse.quote(target_url, safe=":/?&=%#.-_~")

    commands.append(f"curl -i -k '{quoted_url}'")

    if finding_type in ("exposed_file", "generic_http"):
        # Exposure replays are a plain GET; injection-style payload commands
        # would be misleading here.
        return commands

    if param:
        if method == "POST":
            commands.append(
                "curl -i -k -X POST "
                f"'{quoted_url}' "
                "-H 'Content-Type: application/x-www-form-urlencoded' "
                f"--data-urlencode '{param}={payload}'"
            )
        else:
            parsed = urllib.parse.urlparse(target_url)
            q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            q[param] = [payload]
            injected_query = urllib.parse.urlencode(q, doseq=True)
            injected_url = urllib.parse.urlunparse(parsed._replace(query=injected_query))
            commands.append(f"curl -i -k '{injected_url}'")
    else:
        commands.append(
            "curl -i -k -X POST "
            f"'{quoted_url}' "
            f"-H 'Content-Type: application/x-www-form-urlencoded' --data 'payload={urllib.parse.quote_plus(payload)}'"
        )

    return commands


def extract_auth_context(scan_options: dict[str, Any] | None) -> dict[str, str] | None:
    """Extract auth credentials from scan options for retest forwarding."""
    if not scan_options:
        return None
    ctx: dict[str, str] = {}
    for key in ("auth_header", "auth_cookies", "auth_headers_json",
                "user2_header", "user2_cookies"):
        val = scan_options.get(key)
        if val:
            ctx[key] = str(val)
    if not ctx:
        return None
    return ctx


def auth_context_to_headers(auth_context: dict[str, str] | None) -> dict[str, str]:
    """Convert stored auth context into HTTP headers dict for proof functions."""
    if not auth_context:
        return {}
    headers: dict[str, str] = {}
    if auth_context.get("auth_header"):
        headers["Authorization"] = auth_context["auth_header"]
    if auth_context.get("auth_cookies"):
        headers["Cookie"] = auth_context["auth_cookies"]
    extra = auth_context.get("auth_headers_json")
    if extra:
        try:
            parsed = json.loads(extra) if isinstance(extra, str) else extra
            if isinstance(parsed, dict):
                headers.update({str(k): str(v) for k, v in parsed.items()})
        except (json.JSONDecodeError, TypeError):
            pass
    return headers


async def _backfill_target_endpoint_fingerprints(conn) -> None:
    """One-time ASM inventory backfill for the auth-aware endpoint identity."""
    applied = await conn.fetchval(
        "SELECT 1 FROM app_schema_migrations WHERE name = $1",
        ASM_ENDPOINT_FINGERPRINT_MIGRATION,
    )
    if applied:
        return

    from asm_inventory import endpoint_fingerprint, normalize_auth_state

    rows = await conn.fetch("""
        SELECT
            id, target_id, method, path, param_shape, fingerprint, source,
            auth_state, param_location, replay_spec, content_type, content_hash,
            priority_score, test_status, last_attempt_status, last_verdict,
            last_finding_id, first_seen_at, last_seen_at, last_tested_at,
            updated_at
        FROM target_endpoints
    """)

    if not rows:
        await conn.execute(
            "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
            ASM_ENDPOINT_FINGERPRINT_MIGRATION,
        )
        return

    final_fingerprints: dict[Any, str] = {}
    groups: dict[tuple[Any, str], list[Any]] = {}
    for row in rows:
        final_fp = endpoint_fingerprint(
            row["method"],
            row["path"],
            row["param_shape"] or "",
            param_location=row["param_location"] or "query",
            auth_state=normalize_auth_state(row["auth_state"]),
        )
        final_fingerprints[row["id"]] = final_fp
        groups.setdefault((row["target_id"], final_fp), []).append(row)

    # Avoid transient UNIQUE(target_id, fingerprint) conflicts such as
    # A(old=x -> new=y) while B still has old=y.
    temp_updates = [
        (f"__asm_fp_v2_tmp__{row['id']}", row["id"])
        for row in rows
        if row["fingerprint"] != final_fingerprints[row["id"]]
    ]
    if temp_updates:
        await conn.executemany(
            """
            UPDATE target_endpoints
            SET fingerprint = $1, updated_at = NOW()
            WHERE id = $2
            """,
            temp_updates,
        )

    def _ts(value: Any) -> float:
        if not isinstance(value, datetime):
            return 0.0
        try:
            return value.timestamp()
        except (OverflowError, OSError, ValueError):
            return 0.0

    status_rank = {
        "tested": 5,
        "in_progress": 4,
        "stale": 3,
        "untested": 2,
        "gone": 1,
    }
    deleted_ids: set[Any] = set()
    for group_rows in groups.values():
        if len(group_rows) <= 1:
            continue
        keeper = max(
            group_rows,
            key=lambda row: (
                status_rank.get(str(row["test_status"] or ""), 0),
                _ts(row["last_tested_at"]),
                _ts(row["last_seen_at"]),
                _ts(row["updated_at"]),
                str(row["id"]),
            ),
        )
        group_ids = [row["id"] for row in group_rows]
        loser_ids = [row_id for row_id in group_ids if row_id != keeper["id"]]
        await conn.execute(
            """
            WITH merged AS (
                SELECT
                    MIN(first_seen_at) AS first_seen_at,
                    MAX(last_seen_at) AS last_seen_at,
                    MAX(last_tested_at) AS last_tested_at,
                    MAX(priority_score) AS priority_score,
                    BOOL_OR(test_status = 'tested') AS has_tested,
                    BOOL_OR(test_status = 'in_progress') AS has_in_progress,
                    BOOL_OR(test_status = 'stale') AS has_stale,
                    (array_remove(array_agg(source ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS source,
                    (array_remove(array_agg(replay_spec ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS replay_spec,
                    (array_remove(array_agg(content_type ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS content_type,
                    (array_remove(array_agg(content_hash ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS content_hash,
                    (array_remove(array_agg(last_attempt_status ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS last_attempt_status,
                    (array_remove(array_agg(last_verdict ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS last_verdict,
                    (array_remove(array_agg(last_finding_id ORDER BY last_seen_at DESC NULLS LAST), NULL))[1] AS last_finding_id
                FROM target_endpoints
                WHERE id = ANY($2::uuid[])
            )
            UPDATE target_endpoints kept
            SET
                first_seen_at = LEAST(kept.first_seen_at, merged.first_seen_at),
                last_seen_at = GREATEST(kept.last_seen_at, merged.last_seen_at),
                last_tested_at = GREATEST(kept.last_tested_at, merged.last_tested_at),
                priority_score = GREATEST(kept.priority_score, merged.priority_score),
                test_status = CASE
                    WHEN merged.has_tested THEN 'tested'
                    WHEN merged.has_in_progress THEN 'in_progress'
                    WHEN merged.has_stale THEN 'stale'
                    ELSE kept.test_status
                END,
                source = COALESCE(kept.source, merged.source),
                replay_spec = COALESCE(kept.replay_spec, merged.replay_spec),
                content_type = COALESCE(kept.content_type, merged.content_type),
                content_hash = COALESCE(kept.content_hash, merged.content_hash),
                last_attempt_status = COALESCE(kept.last_attempt_status, merged.last_attempt_status),
                last_verdict = COALESCE(kept.last_verdict, merged.last_verdict),
                last_finding_id = COALESCE(kept.last_finding_id, merged.last_finding_id),
                updated_at = NOW()
            FROM merged
            WHERE kept.id = $1
            """,
            keeper["id"],
            group_ids,
        )
        await conn.execute(
            "DELETE FROM target_endpoints WHERE id = ANY($1::uuid[])",
            loser_ids,
        )
        deleted_ids.update(loser_ids)

    final_updates = [
        (fingerprint, row_id)
        for row_id, fingerprint in final_fingerprints.items()
        if row_id not in deleted_ids
    ]
    if final_updates:
        await conn.executemany(
            """
            UPDATE target_endpoints
            SET fingerprint = $1, updated_at = NOW()
            WHERE id = $2 AND fingerprint <> $1
            """,
            final_updates,
        )

    await conn.execute(
        "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
        ASM_ENDPOINT_FINGERPRINT_MIGRATION,
    )


async def run_schema_migrations(pool) -> None:
    """Run all retest-related schema migrations with advisory lock to avoid races.

    Called from both API and worker startup. Uses pg_advisory_lock so only one
    process actually executes the DDL statements.
    """
    async with pool.acquire() as conn:
        # Advisory lock key: arbitrary 64-bit int unique to this migration set
        await conn.execute("SELECT pg_advisory_lock(8675309)")
        try:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS app_schema_migrations (
                    name TEXT PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # Durable key/value store for settings that must survive a Redis
            # flush/restart. Redis remains a cache for non-security automation
            # settings, but security-gating flags (e.g. the approval-receipt
            # requirement) read Postgres as the source of truth so the policy
            # cannot silently fail open when the Redis hash is lost.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)

            # findings table verification columns
            await conn.execute("""
                ALTER TABLE findings
                ADD COLUMN IF NOT EXISTS last_verification_status TEXT,
                ADD COLUMN IF NOT EXISTS last_verification_verdict TEXT,
                ADD COLUMN IF NOT EXISTS last_verification_confidence NUMERIC(3,2),
                ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS verification_count INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS ai_classification_source TEXT,
                ADD COLUMN IF NOT EXISTS ai_target_id UUID,
                ADD COLUMN IF NOT EXISTS analyst_verdict TEXT,
                ADD COLUMN IF NOT EXISTS analyst_verdict_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS analyst_verdict_notes TEXT
            """)
            await conn.execute("""
                UPDATE findings SET verification_count = 0
                WHERE verification_count IS NULL
            """)

            # Ownership/accountability metadata for the exposure inventory,
            # mirroring ai_targets.metadata_json (owner, environment, ...).
            await conn.execute("""
                ALTER TABLE targets
                ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
            """)

            # Continuous ASM policy (docs §16 Phase 3/4): per-target enable +
            # config for the background dispatcher that auto-drains/refreshes
            # the endpoint inventory.
            await conn.execute("""
                ALTER TABLE targets
                ADD COLUMN IF NOT EXISTS asm_enabled BOOLEAN NOT NULL DEFAULT false,
                ADD COLUMN IF NOT EXISTS asm_config JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS asm_last_test_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS asm_last_recon_at TIMESTAMPTZ
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_targets_asm_enabled
                ON targets(asm_enabled) WHERE asm_enabled = true
            """)

            # Recurring schedules now have a first-class kind. Existing
            # installs may still encode ASM waves as scan_options.kind.
            await conn.execute("""
                ALTER TABLE schedules
                ADD COLUMN IF NOT EXISTS schedule_kind TEXT DEFAULT 'normal_scan'
            """)
            await conn.execute("""
                UPDATE schedules
                SET schedule_kind = 'asm_improve'
                WHERE COALESCE(scan_options->>'kind', '') = 'asm_improve'
                  AND COALESCE(schedule_kind, 'normal_scan') <> 'asm_improve'
            """)
            await conn.execute("""
                UPDATE schedules
                SET schedule_kind = 'normal_scan'
                WHERE schedule_kind IS NULL
                   OR schedule_kind NOT IN ('normal_scan', 'asm_improve')
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_schedules_kind_next_run
                ON schedules(schedule_kind, next_run_at) WHERE is_active = true
            """)

            # Parallel scan orchestration (parent/shard/merge fan-out).
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS scan_role TEXT NOT NULL DEFAULT 'standalone',
                ADD COLUMN IF NOT EXISTS shard_index INTEGER,
                ADD COLUMN IF NOT EXISTS shard_count INTEGER
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_parent
                ON scans(parent_scan_id) WHERE parent_scan_id IS NOT NULL
            """)

            # Shared campaign records for one-shot Full Coverage and Continuous ASM.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_campaigns (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    root_domain TEXT,
                    requested_by TEXT NOT NULL DEFAULT 'api',
                    mode TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 100,
                    budget_profile TEXT,
                    wide_budget JSONB NOT NULL DEFAULT '{}'::jsonb,
                    deep_budget JSONB NOT NULL DEFAULT '{}'::jsonb,
                    check_families JSONB NOT NULL DEFAULT '[]'::jsonb,
                    auth_states JSONB NOT NULL DEFAULT '[]'::jsonb,
                    allowed_windows JSONB NOT NULL DEFAULT '{}'::jsonb,
                    daily_cap INTEGER,
                    rate_caps JSONB NOT NULL DEFAULT '{}'::jsonb,
                    parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    policy_id UUID,
                    status TEXT NOT NULL DEFAULT 'active',
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_campaigns_target_status
                ON scan_campaigns(target_id, status, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_campaigns_parent
                ON scan_campaigns(parent_scan_id) WHERE parent_scan_id IS NOT NULL
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL
            """)

            # Continuous ASM: persistent per-target endpoint inventory (docs §16).
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_endpoints (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    method TEXT NOT NULL DEFAULT 'GET',
                    path TEXT NOT NULL,
                    param_shape TEXT NOT NULL DEFAULT '',
                    fingerprint TEXT NOT NULL,
                    source TEXT,
                    auth_state TEXT NOT NULL DEFAULT 'anonymous',
                    param_location TEXT NOT NULL DEFAULT 'query',
                    replay_spec TEXT,
                    content_type TEXT,
                    content_hash TEXT,
                    priority_score INTEGER NOT NULL DEFAULT 10,
                    test_status TEXT NOT NULL DEFAULT 'untested',
                    last_attempt_status TEXT,
                    last_verdict TEXT,
                    last_finding_id UUID,
                    credential_ref TEXT,
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMPTZ,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_tested_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE target_endpoints
                ADD COLUMN IF NOT EXISTS param_location TEXT NOT NULL DEFAULT 'query',
                ADD COLUMN IF NOT EXISTS replay_spec TEXT,
                ADD COLUMN IF NOT EXISTS content_type TEXT,
                ADD COLUMN IF NOT EXISTS last_attempt_status TEXT,
                ADD COLUMN IF NOT EXISTS credential_ref TEXT,
                ADD COLUMN IF NOT EXISTS campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS lease_owner TEXT,
                ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
                ADD COLUMN IF NOT EXISTS last_http_status INTEGER,
                ADD COLUMN IF NOT EXISTS unreachable_streak INTEGER NOT NULL DEFAULT 0,
                ADD COLUMN IF NOT EXISTS last_reachability_at TIMESTAMPTZ
            """)
            async with conn.transaction():
                await _backfill_target_endpoint_fingerprints(conn)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_target_endpoints_fp
                ON target_endpoints(target_id, fingerprint)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_endpoints_status
                ON target_endpoints(target_id, test_status, priority_score DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_endpoints_auth_status
                ON target_endpoints(target_id, auth_state, test_status, priority_score DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_endpoints_lease
                ON target_endpoints(lease_expires_at) WHERE test_status = 'in_progress'
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_endpoints_campaign
                ON target_endpoints(campaign_id) WHERE campaign_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_principals (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    label TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    tenant_id TEXT,
                    auth_state TEXT NOT NULL DEFAULT 'user1',
                    credential_profile TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE target_principals
                ADD COLUMN IF NOT EXISTS auth_state TEXT NOT NULL DEFAULT 'user1',
                ADD COLUMN IF NOT EXISTS credential_profile TEXT,
                ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
                ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_target_principals_identity
                ON target_principals(target_id, lower(label), COALESCE(tenant_id, ''), COALESCE(auth_state, ''))
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_principals_target_active
                ON target_principals(target_id, is_active, role)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_endpoint_expectations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    endpoint_id UUID REFERENCES target_endpoints(id) ON DELETE CASCADE,
                    method TEXT NOT NULL DEFAULT 'GET',
                    path TEXT NOT NULL,
                    param_shape TEXT NOT NULL DEFAULT '',
                    param_location TEXT NOT NULL DEFAULT 'query',
                    principal_id UUID REFERENCES target_principals(id) ON DELETE SET NULL,
                    principal_role TEXT,
                    tenant_id TEXT,
                    expected_access TEXT NOT NULL DEFAULT 'unknown',
                    expected_http_status INTEGER,
                    expectation_source TEXT NOT NULL DEFAULT 'manual',
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT target_endpoint_expectations_access_check
                        CHECK (expected_access IN ('allow','deny','requires_role','unknown'))
                )
            """)
            await conn.execute("""
                ALTER TABLE target_endpoint_expectations
                ADD COLUMN IF NOT EXISTS endpoint_id UUID REFERENCES target_endpoints(id) ON DELETE CASCADE,
                ADD COLUMN IF NOT EXISTS param_location TEXT NOT NULL DEFAULT 'query',
                ADD COLUMN IF NOT EXISTS expected_http_status INTEGER,
                ADD COLUMN IF NOT EXISTS expectation_source TEXT NOT NULL DEFAULT 'manual',
                ADD COLUMN IF NOT EXISTS metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_target_endpoint_expectations_identity
                ON target_endpoint_expectations(
                    target_id, method, path, param_shape, param_location,
                    COALESCE(principal_id, '00000000-0000-0000-0000-000000000000'::uuid),
                    COALESCE(principal_role, ''), COALESCE(tenant_id, '')
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_endpoint_expectations_target
                ON target_endpoint_expectations(target_id, path, expected_access)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS asm_endpoint_attempts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    endpoint_id UUID NOT NULL REFERENCES target_endpoints(id) ON DELETE CASCADE,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    parent_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    worker_id TEXT,
                    auth_state TEXT NOT NULL DEFAULT 'anonymous',
                    check_family TEXT NOT NULL DEFAULT 'all',
                    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    status TEXT NOT NULL,
                    attempted_params_count INTEGER NOT NULL DEFAULT 0,
                    completed_params_count INTEGER NOT NULL DEFAULT 0,
                    finding_ids UUID[] NOT NULL DEFAULT '{}'::uuid[],
                    error_summary TEXT,
                    scanner_telemetry_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE asm_endpoint_attempts
                ADD COLUMN IF NOT EXISTS check_family TEXT NOT NULL DEFAULT 'all'
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_endpoint_attempts_endpoint
                ON asm_endpoint_attempts(endpoint_id, started_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_endpoint_attempts_scan
                ON asm_endpoint_attempts(scan_id) WHERE scan_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_endpoint_attempts_campaign
                ON asm_endpoint_attempts(campaign_id, status)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_asm_endpoint_attempts_campaign_family
                ON asm_endpoint_attempts(campaign_id, check_family, status)
            """)
            await conn.execute("""
                CREATE OR REPLACE VIEW latest_scans AS
                SELECT DISTINCT ON (target_url) *
                FROM scans
                WHERE status = 'completed'
                  AND (scan_role IS NULL OR scan_role <> 'shard')
                ORDER BY target_url, completed_at DESC
            """)
            await conn.execute("""
                CREATE OR REPLACE VIEW dashboard_metrics AS
                SELECT
                    (SELECT COUNT(*) FROM targets WHERE is_active = true) as total_targets,
                    (SELECT COUNT(*) FROM scans WHERE status = 'completed' AND (scan_role IS NULL OR scan_role <> 'shard')) as total_scans,
                    (SELECT COUNT(*) FROM scans WHERE status = 'running' AND (scan_role IS NULL OR scan_role <> 'shard')) as running_scans,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active') as active_findings,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'critical') as critical_findings,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'high') as high_findings,
                    (SELECT AVG(score) FROM latest_scans) as avg_score
            """)
            await conn.execute("""
                CREATE OR REPLACE FUNCTION update_target_stats()
                RETURNS TRIGGER AS $$
                BEGIN
                    IF NEW.status = 'completed'
                       AND NEW.target_id IS NOT NULL
                       AND COALESCE(NEW.scan_role, 'standalone') <> 'shard' THEN
                        UPDATE targets SET
                            last_scan_id = NEW.id,
                            last_scanned_at = NEW.completed_at,
                            last_score = NEW.score,
                            last_grade = NEW.grade,
                            total_scans = total_scans + 1,
                            active_findings_count = (
                                SELECT COUNT(*) FROM findings
                                WHERE target_id = NEW.target_id AND status = 'active'
                            ),
                            updated_at = NOW()
                        WHERE id = NEW.target_id;
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
            """)

            # AI Gate targets.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_targets (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'api_chat',
                    endpoint_url TEXT UNIQUE NOT NULL,
                    method TEXT NOT NULL DEFAULT 'POST',
                    headers_template JSONB NOT NULL DEFAULT '{}'::jsonb,
                    request_template JSONB NOT NULL DEFAULT '{}'::jsonb,
                    response_path TEXT,
                    streaming_mode TEXT NOT NULL DEFAULT 'json',
                    rate_limit_rps INTEGER,
                    token_budget INTEGER,
                    request_budget INTEGER,
                    production_mode BOOLEAN NOT NULL DEFAULT false,
                    last_scanned_at TIMESTAMPTZ,
                    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT ai_targets_target_type_check
                        CHECK (target_type IN ('api_chat', 'widget', 'rag', 'agent_trace', 'mcp_trace')),
                    CONSTRAINT ai_targets_method_check
                        CHECK (method IN ('GET', 'POST', 'PUT', 'PATCH')),
                    CONSTRAINT ai_targets_streaming_mode_check
                        CHECK (streaming_mode IN ('json', 'sse'))
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_target_credentials (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    ai_target_id UUID NOT NULL REFERENCES ai_targets(id) ON DELETE CASCADE,
                    auth_kind TEXT NOT NULL DEFAULT 'none',
                    header_name TEXT,
                    secret_value TEXT,
                    secret_preview TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rotated_at TIMESTAMPTZ,
                    CONSTRAINT ai_target_credentials_target_unique UNIQUE (ai_target_id),
                    CONSTRAINT ai_target_credentials_auth_kind_check
                        CHECK (auth_kind IN (
                            'none',
                            'bearer',
                            'api_key_header',
                            'custom_header',
                            'basic_auth',
                            'cookie',
                            'multi_header',
                            'query_param'
                        ))
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_target_principals (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    ai_target_id UUID NOT NULL REFERENCES ai_targets(id) ON DELETE CASCADE,
                    label TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'attacker',
                    tenant_id TEXT,
                    auth_kind TEXT NOT NULL DEFAULT 'none',
                    header_name TEXT,
                    secret_value TEXT,
                    secret_preview TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rotated_at TIMESTAMPTZ,
                    CONSTRAINT ai_target_principals_target_label_unique UNIQUE (ai_target_id, label),
                    CONSTRAINT ai_target_principals_role_check
                        CHECK (role IN (
                            'attacker',
                            'victim',
                            'admin',
                            'service',
                            'observer'
                        )),
                    CONSTRAINT ai_target_principals_auth_kind_check
                        CHECK (auth_kind IN (
                            'none',
                            'bearer',
                            'api_key_header',
                            'custom_header',
                            'basic_auth',
                            'cookie',
                            'multi_header',
                            'query_param'
                        ))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ai_target_principals_target_active
                ON ai_target_principals(ai_target_id, is_active)
            """)
            # R4: durable policy profiles + finding exceptions (replaces the
            # hard-coded POLICY_PROFILES dict and payload-only exceptions).
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_profiles (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL UNIQUE,
                    product_area TEXT NOT NULL DEFAULT 'ai_gate',
                    environment TEXT NOT NULL DEFAULT 'production',
                    minimum_block_severity TEXT NOT NULL DEFAULT 'high',
                    expires_days INTEGER NOT NULL DEFAULT 30,
                    strict_model_intake BOOLEAN NOT NULL DEFAULT false,
                    allow_active_exceptions BOOLEAN NOT NULL DEFAULT true,
                    required_trust_anchor_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    owner TEXT,
                    version TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    active_from TIMESTAMPTZ,
                    active_until TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE policy_profiles
                ADD COLUMN IF NOT EXISTS required_trust_anchor_ids JSONB NOT NULL DEFAULT '[]'::jsonb
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_exceptions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    finding_id TEXT,
                    fingerprint TEXT,
                    policy_id UUID REFERENCES policy_profiles(id) ON DELETE SET NULL,
                    target_id UUID,
                    scope TEXT,
                    owner TEXT,
                    approver TEXT,
                    reason TEXT,
                    compensating_controls TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT finding_exceptions_status_check
                        CHECK (status IN ('active','approved','accepted_risk','revoked','expired'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_finding_exceptions_target_status
                ON finding_exceptions(target_id, status)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_finding_exceptions_finding
                ON finding_exceptions(finding_id)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scope_receipts (
                    id TEXT PRIMARY KEY,
                    target_id UUID,
                    input_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
                    normalized_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
                    verdict TEXT NOT NULL,
                    blocked_by JSONB NOT NULL DEFAULT '[]'::jsonb,
                    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
                    checks JSONB NOT NULL DEFAULT '[]'::jsonb,
                    environment TEXT NOT NULL DEFAULT 'production',
                    allowed_hosts JSONB NOT NULL DEFAULT '[]'::jsonb,
                    allowed_root_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
                    redirect_destinations JSONB NOT NULL DEFAULT '[]'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT scope_receipts_verdict_check
                        CHECK (verdict IN ('allowed','blocked','needs_approval'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scope_receipts_created_at
                ON scope_receipts(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scope_receipts_target
                ON scope_receipts(target_id, created_at DESC) WHERE target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS approval_receipts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    risk_tier TEXT NOT NULL,
                    confirmations JSONB NOT NULL DEFAULT '[]'::jsonb,
                    approved_by TEXT,
                    denial_reason TEXT,
                    expires_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT approval_receipts_risk_check
                        CHECK (risk_tier IN ('active','intrusive','credential','dangerous')),
                    CONSTRAINT approval_receipts_approved_or_denied_check
                        CHECK (approved_by IS NOT NULL OR denial_reason IS NOT NULL)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_approval_receipts_scope
                ON approval_receipts(scope_receipt_id)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS operation_plans (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    objective TEXT NOT NULL,
                    planner JSONB NOT NULL DEFAULT '{}'::jsonb,
                    context_hash TEXT NOT NULL,
                    target_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
                    risk_tier TEXT NOT NULL,
                    actions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    confirmations JSONB NOT NULL DEFAULT '[]'::jsonb,
                    missing_inputs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    stop_conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    success_criteria JSONB NOT NULL DEFAULT '[]'::jsonb,
                    status TEXT NOT NULL DEFAULT 'planned',
                    validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
                    validation_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    approval_receipt_id UUID REFERENCES approval_receipts(id) ON DELETE SET NULL,
                    plan_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT operation_plans_risk_check
                        CHECK (risk_tier IN ('read_only','passive','active','intrusive','credential','dangerous')),
                    CONSTRAINT operation_plans_status_check
                        CHECK (status IN ('planned','blocked','approved','rejected','stale'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation_plans_created_at
                ON operation_plans(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_operation_plans_scope
                ON operation_plans(scope_receipt_id, created_at DESC) WHERE scope_receipt_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS command_results (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    command TEXT NOT NULL,
                    status TEXT NOT NULL,
                    dry_run BOOLEAN NOT NULL DEFAULT false,
                    risk_tier TEXT NOT NULL DEFAULT 'read_only',
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    approval_receipt_id UUID REFERENCES approval_receipts(id) ON DELETE SET NULL,
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    hypothesis_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    tool_receipt_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    blocked_by JSONB NOT NULL DEFAULT '[]'::jsonb,
                    next_action TEXT,
                    operator_message TEXT NOT NULL,
                    result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT command_results_status_check
                        CHECK (status IN ('planned','blocked','approval_required','approved','queued','running','completed','partial','degraded','failed','cancelled','evidence_bound','retest_scheduled','refuter_requested')),
                    CONSTRAINT command_results_risk_check
                        CHECK (risk_tier IN ('read_only','passive','active','intrusive','credential','dangerous'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_command_results_created_at
                ON command_results(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_command_results_scan
                ON command_results(scan_id, created_at DESC) WHERE scan_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_command_results_campaign
                ON command_results(campaign_id, created_at DESC) WHERE campaign_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS campaign_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    command_result_id UUID REFERENCES command_results(id) ON DELETE SET NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    approval_receipt_id UUID REFERENCES approval_receipts(id) ON DELETE SET NULL,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    command TEXT NOT NULL,
                    action_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    dry_run BOOLEAN NOT NULL DEFAULT false,
                    risk_tier TEXT NOT NULL DEFAULT 'read_only',
                    finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    hypothesis_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    tool_receipt_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    blocked_by JSONB NOT NULL DEFAULT '[]'::jsonb,
                    next_action TEXT,
                    operator_message TEXT,
                    result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT campaign_actions_status_check
                        CHECK (status IN ('planned','blocked','approval_required','approved','queued','running','completed','partial','degraded','failed','cancelled','evidence_bound','retest_scheduled','refuter_requested')),
                    CONSTRAINT campaign_actions_risk_check
                        CHECK (risk_tier IN ('read_only','passive','active','intrusive','credential','dangerous'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaign_actions_created_at
                ON campaign_actions(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaign_actions_campaign
                ON campaign_actions(campaign_id, created_at DESC) WHERE campaign_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaign_actions_command_result
                ON campaign_actions(command_result_id) WHERE command_result_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaign_actions_target
                ON campaign_actions(target_id, created_at DESC) WHERE target_id IS NOT NULL
            """)
            # §7 mission campaigns: the operating wrapper over ASM waves, scans,
            # focused-family work, AI Gate/Model Intake runs, retests, and exports.
            # A campaign is a planning/audit record; it does not execute work or
            # create findings — individual actions still flow through existing
            # product routes and receipt gates. (Distinct from scan_campaigns,
            # which is the parallel-scan parent concept.)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT,
                    objective TEXT NOT NULL,
                    campaign_type TEXT NOT NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    target_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
                    risk_tier TEXT NOT NULL DEFAULT 'read_only',
                    policy_profile TEXT,
                    planner JSONB NOT NULL DEFAULT '{}'::jsonb,
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    context_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'planned',
                    deployment_impact JSONB NOT NULL DEFAULT '{}'::jsonb,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT campaigns_type_check CHECK (campaign_type IN (
                        'continuous_asm','authenticated_dast','api_authz','ai_red_team',
                        'model_intake','benchmark','incident_retest','source_informed_dast',
                        'finding_retest','focused_family'
                    )),
                    CONSTRAINT campaigns_status_check CHECK (status IN (
                        'planned','active','paused','completed','cancelled'
                    )),
                    CONSTRAINT campaigns_risk_check CHECK (risk_tier IN (
                        'read_only','passive','active','intrusive','credential','dangerous'
                    ))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaigns_created_at
                ON campaigns(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaigns_target
                ON campaigns(target_id, created_at DESC) WHERE target_id IS NOT NULL
            """)
            # Link campaign_actions to a mission campaign (the existing campaign_id
            # column points at scan_campaigns for parallel-scan context).
            await conn.execute("""
                ALTER TABLE campaign_actions
                ADD COLUMN IF NOT EXISTS mission_campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_campaign_actions_mission_campaign
                ON campaign_actions(mission_campaign_id, created_at DESC) WHERE mission_campaign_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hypotheses (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    campaign_action_id UUID REFERENCES campaign_actions(id) ON DELETE SET NULL,
                    source TEXT NOT NULL,
                    family TEXT NOT NULL,
                    cwe TEXT,
                    title TEXT,
                    description TEXT,
                    severity_guess TEXT,
                    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
                    dedupe_key TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    version INTEGER NOT NULL DEFAULT 1,
                    claim_owner TEXT,
                    claim_lease_expires_at TIMESTAMPTZ,
                    smoke_score DOUBLE PRECISION,
                    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    tool_receipt_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    next_test_action JSONB,
                    endorsements JSONB NOT NULL DEFAULT '[]'::jsonb,
                    refutations JSONB NOT NULL DEFAULT '[]'::jsonb,
                    terminal_reason TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT hypotheses_source_check
                        CHECK (source IN ('app_graph','source_ingest','ai_planner','scanner_signal','ai_gate','model_intake','manual')),
                    CONSTRAINT hypotheses_status_check
                        CHECK (status IN ('open','claimed','testing','supported','refuted','promoted','dead')),
                    CONSTRAINT hypotheses_severity_check
                        CHECK (severity_guess IS NULL OR severity_guess IN ('critical','high','medium','low','info')),
                    CONSTRAINT hypotheses_confidence_check
                        CHECK (confidence >= 0 AND confidence <= 1),
                    CONSTRAINT hypotheses_smoke_score_check
                        CHECK (smoke_score IS NULL OR (smoke_score >= 0 AND smoke_score <= 1))
                )
            """)
            # Dedupe key must match the application find-or-create key, which is
            # (target, family, dedupe_key) WITHOUT source — a new source endorses
            # an existing lead rather than forking a duplicate card (roadmap §7.8).
            # The original index included source; collapse any duplicates it
            # allowed, then rebuild the index on the correct columns.
            await conn.execute("""
                DELETE FROM hypotheses h
                USING (
                    SELECT id,
                           ROW_NUMBER() OVER (
                               PARTITION BY
                                   COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid),
                                   family, dedupe_key
                               ORDER BY created_at ASC, id ASC
                           ) AS rn
                    FROM hypotheses
                ) dups
                WHERE h.id = dups.id AND dups.rn > 1
            """)
            await conn.execute("DROP INDEX IF EXISTS idx_hypotheses_dedupe")
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_hypotheses_dedupe
                ON hypotheses(COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid), family, dedupe_key)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hypotheses_target_status
                ON hypotheses(target_id, status, updated_at DESC) WHERE target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hypotheses_claim
                ON hypotheses(status, claim_lease_expires_at, updated_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS refuter_reviews (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    subject_type TEXT NOT NULL,
                    subject_id TEXT,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
                    hypothesis_id UUID REFERENCES hypotheses(id) ON DELETE SET NULL,
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    trigger_reason TEXT NOT NULL,
                    refuter_signal TEXT NOT NULL DEFAULT 'question',
                    refuter_verdict TEXT,
                    verdict_basis TEXT NOT NULL DEFAULT 'signal_only',
                    confidence_delta DOUBLE PRECISION,
                    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    tool_receipt_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    counterevidence JSONB NOT NULL DEFAULT '{}'::jsonb,
                    notes TEXT,
                    status TEXT NOT NULL DEFAULT 'recorded',
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT refuter_reviews_subject_check
                        CHECK (subject_type IN ('finding','hypothesis','ai_gate_scan','model_intake','benchmark','planner','deployment_gate','parser_output','manual')),
                    CONSTRAINT refuter_reviews_signal_check
                        CHECK (refuter_signal IN ('support','question','weaken','refute')),
                    CONSTRAINT refuter_reviews_verdict_check
                        CHECK (refuter_verdict IS NULL OR refuter_verdict IN ('supported','weakened','refuted','inconclusive')),
                    CONSTRAINT refuter_reviews_basis_check
                        CHECK (verdict_basis IN ('signal_only','deterministic_replay','cryptographic','parser_protocol','human_approved_review')),
                    CONSTRAINT refuter_reviews_status_check
                        CHECK (status IN ('recorded','verdict_recorded','rejected'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_refuter_reviews_subject
                ON refuter_reviews(subject_type, subject_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_refuter_reviews_finding
                ON refuter_reviews(finding_id, created_at DESC) WHERE finding_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_refuter_reviews_hypothesis
                ON refuter_reviews(hypothesis_id, created_at DESC) WHERE hypothesis_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_context_packs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    context_version TEXT NOT NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    context_hash TEXT NOT NULL,
                    target_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    current_surface JSONB NOT NULL DEFAULT '{}'::jsonb,
                    current_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
                    hypotheses_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
                    findings_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
                    allowed_commands JSONB NOT NULL DEFAULT '[]'::jsonb,
                    disallowed_commands JSONB NOT NULL DEFAULT '[]'::jsonb,
                    known_preconditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                    redaction_profile TEXT NOT NULL DEFAULT 'agent-plan-default',
                    context_pack JSONB NOT NULL DEFAULT '{}'::jsonb,
                    validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
                    validation_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
                    status TEXT NOT NULL DEFAULT 'recorded',
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT agent_context_packs_status_check
                        CHECK (status IN ('recorded','invalid'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_context_packs_created_at
                ON agent_context_packs(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_context_packs_hash
                ON agent_context_packs(context_hash)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_decision_traces (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    context_pack_id UUID REFERENCES agent_context_packs(id) ON DELETE SET NULL,
                    planner JSONB NOT NULL DEFAULT '{}'::jsonb,
                    context_hash TEXT NOT NULL,
                    command_schema_version TEXT NOT NULL,
                    steps JSONB NOT NULL DEFAULT '[]'::jsonb,
                    final_rationale TEXT,
                    redaction_profile TEXT NOT NULL DEFAULT 'agent-trace-default',
                    validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
                    validation_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
                    status TEXT NOT NULL DEFAULT 'recorded',
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT agent_decision_traces_status_check
                        CHECK (status IN ('recorded','invalid'))
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_decision_traces_created_at
                ON agent_decision_traces(created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_decision_traces_plan
                ON agent_decision_traces(operation_plan_id, created_at DESC) WHERE operation_plan_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_intake_trust_anchors (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    public_key_pem TEXT,
                    public_key_sha256 TEXT,
                    policy_profile TEXT,
                    owner TEXT,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT model_intake_trust_anchor_material_check
                        CHECK (
                            (public_key_pem IS NOT NULL AND btrim(public_key_pem) <> '')
                            OR (public_key_sha256 IS NOT NULL AND btrim(public_key_sha256) <> '')
                        )
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_trust_anchors_active
                ON model_intake_trust_anchors(is_active, policy_profile)
            """)
            # R9: durable AI surface inventory + attempt ledger (mirrors the DAST
            # target_endpoints + asm_endpoint_attempts pair for the AI surface).
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_surfaces (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    ai_target_id UUID REFERENCES ai_targets(id) ON DELETE CASCADE,
                    surface_type TEXT NOT NULL DEFAULT 'api_chat',
                    endpoint_url TEXT,
                    auth_kind TEXT,
                    owner TEXT,
                    environment TEXT,
                    risk_tier TEXT,
                    data_classification TEXT,
                    tools_count INTEGER NOT NULL DEFAULT 0,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    last_seen TIMESTAMPTZ,
                    last_tested TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT ai_surfaces_target_unique UNIQUE (ai_target_id)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_surface_attempts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    surface_id UUID REFERENCES ai_surfaces(id) ON DELETE CASCADE,
                    scan_id UUID,
                    probe_pack TEXT,
                    scan_profile TEXT,
                    environment TEXT,
                    families TEXT[],
                    status TEXT,
                    proof_state TEXT,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    critical_high_count INTEGER NOT NULL DEFAULT 0,
                    started_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT ai_surface_attempts_unique UNIQUE (surface_id, scan_id)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ai_surface_attempts_surface
                ON ai_surface_attempts(surface_id, completed_at DESC)
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS run_kind TEXT DEFAULT 'web_dast',
                ADD COLUMN IF NOT EXISTS subject_ref TEXT,
                ADD COLUMN IF NOT EXISTS ai_target_id UUID REFERENCES ai_targets(id) ON DELETE SET NULL
            """)
            await conn.execute("""
                UPDATE scans SET run_kind = 'web_dast'
                WHERE run_kind IS NULL
            """)
            await conn.execute("""
                ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_run_kind_check
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD CONSTRAINT scans_run_kind_check
                CHECK (run_kind IN (
                    'web_dast',
                    'ai_api',
                    'ai_widget',
                    'ai_rag',
                    'ai_trace',
                    'ai_mcp',
                    'model_intake'
                ))
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'findings_ai_target_id_fkey'
                    ) THEN
                        ALTER TABLE findings
                        ADD CONSTRAINT findings_ai_target_id_fkey
                        FOREIGN KEY (ai_target_id) REFERENCES ai_targets(id) ON DELETE CASCADE;
                    END IF;
                END $$;
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_ai_targets_active_created
                ON ai_targets(is_active, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_ai_target_created
                ON scans(ai_target_id, created_at DESC)
                WHERE ai_target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_run_kind_created
                ON scans(run_kind, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_ai_target
                ON findings(ai_target_id)
                WHERE ai_target_id IS NOT NULL
            """)

            # finding_verifications table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_verifications (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    job_id TEXT,
                    requested_by TEXT DEFAULT 'api',
                    status TEXT NOT NULL DEFAULT 'queued',
                    result_status TEXT,
                    verdict TEXT,
                    verdict_reason TEXT,
                    finding_type TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    original_url TEXT,
                    param TEXT,
                    payload TEXT,
                    method TEXT,
                    request_body TEXT,
                    replay_commands JSONB,
                    proof JSONB,
                    artifacts JSONB,
                    confidence NUMERIC(3,2),
                    attempt_count INTEGER DEFAULT 0,
                    attempts_exhausted BOOLEAN DEFAULT FALSE,
                    retry_class TEXT,
                    retryable BOOLEAN DEFAULT FALSE,
                    message TEXT,
                    error_message TEXT,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    started_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)

            # Additional columns added after initial schema
            await conn.execute("""
                ALTER TABLE finding_verifications
                ADD COLUMN IF NOT EXISTS verdict TEXT,
                ADD COLUMN IF NOT EXISTS verdict_reason TEXT,
                ADD COLUMN IF NOT EXISTS replay_commands JSONB,
                ADD COLUMN IF NOT EXISTS artifacts JSONB,
                ADD COLUMN IF NOT EXISTS attempt_count INTEGER DEFAULT 0,
                ADD COLUMN IF NOT EXISTS attempts_exhausted BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS retry_class TEXT,
                ADD COLUMN IF NOT EXISTS retryable BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS auth_context JSONB,
                ADD COLUMN IF NOT EXISTS verification_mode TEXT DEFAULT 'deterministic',
                ADD COLUMN IF NOT EXISTS ai_plan JSONB,
                ADD COLUMN IF NOT EXISTS ai_reasoning TEXT,
                ADD COLUMN IF NOT EXISTS campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL
            """)

            # Backfill NULLs to defaults
            await conn.execute("UPDATE finding_verifications SET attempt_count = 0 WHERE attempt_count IS NULL")
            await conn.execute("UPDATE finding_verifications SET attempts_exhausted = FALSE WHERE attempts_exhausted IS NULL")
            await conn.execute("UPDATE finding_verifications SET retryable = FALSE WHERE retryable IS NULL")

            # Indexes (idempotent)
            for stmt in [
                "CREATE INDEX IF NOT EXISTS idx_findings_last_verified_at ON findings(last_verified_at DESC) WHERE last_verified_at IS NOT NULL",
                "CREATE INDEX IF NOT EXISTS idx_findings_last_verification_verdict ON findings(last_verification_verdict)",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_finding_id ON finding_verifications(finding_id, created_at DESC)",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_status ON finding_verifications(status)",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_result_status ON finding_verifications(result_status)",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_verdict ON finding_verifications(verdict)",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_job_id ON finding_verifications(job_id) WHERE job_id IS NOT NULL",
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_retry_class ON finding_verifications(retry_class) WHERE retry_class IS NOT NULL",
                # Sort/filter hot paths for the /findings list endpoint.
                "CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings(last_seen_at DESC NULLS LAST)",
            ]:
                await conn.execute(stmt)

            # Dedup hot path + race guard for save_findings. On upgraded
            # databases that pre-date this constraint we may have duplicate
            # rows from concurrent inserts; collapse them keeping the most
            # recently seen row before creating the UNIQUE index.
            await conn.execute("""
                WITH ranked AS (
                    SELECT
                        id,
                        ROW_NUMBER() OVER (
                            PARTITION BY target_id, fingerprint
                            ORDER BY last_seen_at DESC NULLS LAST, updated_at DESC NULLS LAST, id DESC
                        ) AS rn
                    FROM findings
                    WHERE target_id IS NOT NULL
                )
                DELETE FROM findings
                USING ranked
                WHERE findings.id = ranked.id AND ranked.rn > 1
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_target_fingerprint
                    ON findings(target_id, fingerprint)
                    WHERE target_id IS NOT NULL
            """)
            # First-class durable evidence objects (hash, redaction profile, retention
            # class, storage URI, scan/finding links) — evidence is no longer only an
            # embedded JSONB column on the finding.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_objects (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID,
                    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
                    object_type TEXT NOT NULL DEFAULT 'finding_evidence',
                    content_sha256 TEXT,
                    size_bytes INTEGER,
                    storage_uri TEXT,
                    redaction_profile TEXT,
                    retention_class TEXT NOT NULL DEFAULT 'standard',
                    content JSONB,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT evidence_objects_finding_type_unique UNIQUE (finding_id, object_type)
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_objects_finding ON evidence_objects(finding_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_objects_scan ON evidence_objects(scan_id)")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS export_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    export_kind TEXT NOT NULL,
                    command TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    risk_tier TEXT NOT NULL DEFAULT 'read_only',
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    scan_id UUID,
                    finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
                    bundle_hash TEXT,
                    manifest_hash TEXT,
                    object_count INTEGER NOT NULL DEFAULT 0,
                    filters JSONB NOT NULL DEFAULT '{}'::jsonb,
                    evidence_object_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    scan_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    replay_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
                    operator_message TEXT,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT export_events_status_check
                        CHECK (status IN ('completed','partial','degraded','failed')),
                    CONSTRAINT export_events_risk_check
                        CHECK (risk_tier IN ('read_only','passive','active','intrusive','credential','dangerous'))
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_export_events_created_at ON export_events(created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_export_events_target ON export_events(target_id, created_at DESC) WHERE target_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_export_events_scan ON export_events(scan_id, created_at DESC) WHERE scan_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_export_events_finding ON export_events(finding_id, created_at DESC) WHERE finding_id IS NOT NULL")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS tool_receipts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    tool_name TEXT NOT NULL,
                    tool_version TEXT,
                    adapter_version TEXT NOT NULL,
                    command_hash TEXT NOT NULL,
                    redacted_argv JSONB NOT NULL DEFAULT '[]'::jsonb,
                    worker_build TEXT,
                    container_image TEXT,
                    target_scope JSONB NOT NULL DEFAULT '{}'::jsonb,
                    scope_receipt_id UUID REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    approval_receipt_id UUID REFERENCES approval_receipts(id) ON DELETE SET NULL,
                    policy_profile_id UUID REFERENCES policy_profiles(id) ON DELETE SET NULL,
                    status TEXT NOT NULL DEFAULT 'recorded',
                    parser_status TEXT NOT NULL DEFAULT 'not_run',
                    exit_code INTEGER,
                    timed_out BOOLEAN NOT NULL DEFAULT false,
                    started_at TIMESTAMPTZ,
                    finished_at TIMESTAMPTZ,
                    stdout_evidence_object_id UUID REFERENCES evidence_objects(id) ON DELETE SET NULL,
                    stderr_evidence_object_id UUID REFERENCES evidence_objects(id) ON DELETE SET NULL,
                    parsed_evidence_instance_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    redaction_summary TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT tool_receipts_status_check
                        CHECK (status IN ('success','failed','timeout','skipped','waived','parser_error','recorded')),
                    CONSTRAINT tool_receipts_parser_status_check
                        CHECK (parser_status IN ('not_run','parsed','partial','failed','not_applicable'))
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_receipts_tool_created ON tool_receipts(tool_name, created_at DESC)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_receipts_scope ON tool_receipts(scope_receipt_id) WHERE scope_receipt_id IS NOT NULL")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_instances (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
                    evidence_object_id UUID REFERENCES evidence_objects(id) ON DELETE SET NULL,
                    scan_id UUID,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    concrete_url TEXT,
                    object_id TEXT,
                    payload_variant TEXT,
                    request_response_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    principal_pair JSONB NOT NULL DEFAULT '{}'::jsonb,
                    proof_observation JSONB NOT NULL DEFAULT '{}'::jsonb,
                    campaign_action_id UUID REFERENCES campaign_actions(id) ON DELETE SET NULL,
                    tool_receipt_id UUID REFERENCES tool_receipts(id) ON DELETE SET NULL,
                    redaction_profile TEXT NOT NULL DEFAULT 'redact_sensitive_v1',
                    hash TEXT NOT NULL,
                    retention_policy TEXT NOT NULL DEFAULT 'standard',
                    proof_state TEXT NOT NULL DEFAULT 'unverified',
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT evidence_instances_proof_state_check
                        CHECK (proof_state IN ('verified','suspected','unverified','refuted','inconclusive')),
                    CONSTRAINT evidence_instances_retention_check
                        CHECK (retention_policy IN ('standard','short','audit','legal_hold','sensitive'))
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_finding ON evidence_instances(finding_id, created_at DESC) WHERE finding_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_tool_receipt ON evidence_instances(tool_receipt_id) WHERE tool_receipt_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_hash ON evidence_instances(hash)")
            # First-class application graph (routes, objects, producer/consumer,
            # auth boundaries) persisted from the BOLA resource_map + discovery.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS application_graph_nodes (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    node_type TEXT NOT NULL,
                    node_key TEXT NOT NULL,
                    label TEXT,
                    attributes JSONB,
                    scan_id UUID,
                    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT app_graph_node_unique UNIQUE (target_id, node_type, node_key)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS application_graph_edges (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    src_key TEXT NOT NULL,
                    dst_key TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    attributes JSONB,
                    scan_id UUID,
                    first_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT app_graph_edge_unique UNIQUE (target_id, src_key, dst_key, edge_type)
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_app_graph_nodes_target ON application_graph_nodes(target_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_app_graph_edges_target ON application_graph_edges(target_id)")

            # Canonical de-dupe PREVENTION: a scheme/trailing-slash-insensitive key on
            # targets, auto-maintained by a trigger, with a UNIQUE index so duplicate
            # origins can't re-form. Must stay byte-identical to the Python
            # _canonical_target_key in api.py (strip scheme, lowercase, strip trailing /).
            await conn.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS canonical_key TEXT")
            await conn.execute("""
                CREATE OR REPLACE FUNCTION targets_set_canonical_key() RETURNS trigger AS $$
                BEGIN
                    NEW.canonical_key := rtrim(
                        regexp_replace(lower(btrim(COALESCE(NEW.url, ''))), '^https?://', ''), '/');
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
            """)
            await conn.execute("DROP TRIGGER IF EXISTS trg_targets_canonical_key ON targets")
            await conn.execute("""
                CREATE TRIGGER trg_targets_canonical_key
                    BEFORE INSERT OR UPDATE OF url ON targets
                    FOR EACH ROW EXECUTE FUNCTION targets_set_canonical_key()
            """)
            await conn.execute("""
                UPDATE targets
                SET canonical_key = rtrim(regexp_replace(lower(btrim(url)), '^https?://', ''), '/')
                WHERE url IS NOT NULL AND (canonical_key IS NULL OR canonical_key = '')
            """)
            try:
                await conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_canonical_key ON targets(canonical_key)"
                )
            except Exception as canon_err:  # only on a dirty install with residual dupes
                # The UNIQUE index can't be built while canonical-duplicate targets
                # exist — and the new ON CONFLICT (canonical_key) insert paths would
                # then break (no matching constraint). Auto-heal with the same tested
                # merge, then retry so the install ends up consistent and functional
                # rather than half-migrated.
                from target_dedupe import merge_all_canonical_duplicates
                print(f"[schema] canonical_key unique index blocked by duplicates "
                      f"({canon_err}); auto-merging…", flush=True)
                try:
                    removed = await merge_all_canonical_duplicates(conn)
                    await conn.execute(
                        "CREATE UNIQUE INDEX IF NOT EXISTS idx_targets_canonical_key ON targets(canonical_key)"
                    )
                    print(f"[schema] auto-merged {removed} duplicate target row(s); "
                          "idx_targets_canonical_key created", flush=True)
                except Exception as heal_err:
                    print(f"[schema] FAILED to auto-heal canonical duplicates: {heal_err}. "
                          "Run POST /targets/dedupe?dry_run=false then restart.", flush=True)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(8675309)")


def build_retest_job_payload(
    *,
    job_id: str,
    verification_id: str,
    finding_id: str,
    submitted_at: str,
    trigger: str | None = None,
    attempt: int = 1,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "finding_retest",
        "queue_schema_version": RETEST_QUEUE_SCHEMA_VERSION,
        "job_id": str(job_id),
        "verification_id": str(verification_id),
        "finding_id": str(finding_id),
        "submitted_at": str(submitted_at),
        "attempt": max(1, int(attempt)),
    }
    if trigger:
        payload["trigger"] = str(trigger)
    return payload


def validate_retest_job_payload(payload: Any) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "payload_not_object"

    if payload.get("type") != "finding_retest":
        return False, "invalid_type"

    schema_version = payload.get("queue_schema_version")
    try:
        schema_version_int = int(schema_version)
    except (TypeError, ValueError):
        return False, "invalid_queue_schema_version"
    if schema_version_int != RETEST_QUEUE_SCHEMA_VERSION:
        return False, "unsupported_queue_schema_version"

    for field in ("job_id", "verification_id", "finding_id", "submitted_at"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"missing_{field}"

    for field in ("verification_id", "finding_id"):
        try:
            uuid.UUID(str(payload[field]))
        except (ValueError, TypeError):
            return False, f"invalid_{field}"

    try:
        datetime.fromisoformat(str(payload["submitted_at"]))
    except (TypeError, ValueError):
        return False, "invalid_submitted_at"

    attempt = payload.get("attempt", 1)
    try:
        attempt_int = int(attempt)
    except (TypeError, ValueError):
        return False, "invalid_attempt"
    if attempt_int < 1:
        return False, "invalid_attempt"

    return True, ""
