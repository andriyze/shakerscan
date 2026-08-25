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

from runtime.credential_store import PostgresCredentialProfileStore
from runtime.auth_session_store import PostgresAuthSessionStore
from runtime.credential_migration import (
    migrate_legacy_ai_credentials,
    migrate_legacy_device_credentials,
    migrate_legacy_web_credentials,
    migrate_scan_execute_capabilities,
)
from runtime.reservation_store import PostgresBudgetReservationStore
from runtime.observation_store import PostgresObservationManifestStore
from runtime.request_collection_store import PostgresRequestCollectionStore
from scan.stage_store import PostgresScanStageCheckpointStore
from scan.action_store import PostgresScanActionStore
from scan.manifest_store import PostgresScanManifestStore

RETEST_QUEUE_SCHEMA_VERSION = 1
ASM_ENDPOINT_FINGERPRINT_MIGRATION = "asm_endpoint_fingerprint_v2"
CAMPAIGN_SCAN_FINDING_LINKS_MIGRATION = "campaign_scan_finding_links_v1"
TARGET_HOST_IDENTITY_MIGRATION = "target_host_identity_v1"
LEGACY_AUTONOMOUS_CANDIDATE_MIGRATION = "legacy_autonomous_candidates_v1"


class SchemaMigrationError(RuntimeError):
    """A required database invariant could not be established safely."""


async def backfill_campaign_scan_finding_links(conn, *, campaign_id=None, scan_id=None) -> int:
    """Link research-driven scan findings back to the campaign ledger and stamp provenance.

    A research decision that queues a scan (scan.focused_family, ASM wave) records the scan on
    the campaign_actions row, but findings the scan produced were never linked back: the
    campaign impact panel (campaign_actions.finding_ids) stayed empty and the finding rows were
    indistinguishable from organic DAST output. Idempotently repairs both:

      1. campaign_actions.finding_ids := distinct findings.id where findings.scan_id = action's scan
      2. findings.evidence.research := {driven_by: 'autonomous_research', campaign_id, campaign_action_id}
         so hunt-driven scanner findings are distinguishable from organic DAST (no `research`
         key) and from agent-native output (source='autonomous').

    Returns the number of campaign_action rows (re)linked.
    """
    rows = await conn.fetch(
        """
        WITH linked AS (
            SELECT ca.id AS action_id, jsonb_agg(DISTINCT f.id::text ORDER BY f.id::text) AS ids
            FROM campaign_actions ca
            JOIN findings f ON f.scan_id = ca.scan_id
            WHERE ca.scan_id IS NOT NULL
              AND ($1::uuid IS NULL OR ca.mission_campaign_id = $1)
              AND ($2::uuid IS NULL OR ca.scan_id = $2)
            GROUP BY ca.id
        )
        UPDATE campaign_actions ca
        SET finding_ids = linked.ids, updated_at = NOW()
        FROM linked
        WHERE ca.id = linked.action_id
          AND COALESCE(ca.finding_ids, '[]'::jsonb) <> linked.ids
        RETURNING ca.id
        """,
        campaign_id,
        scan_id,
    )
    await conn.execute(
        """
        UPDATE findings f
        SET evidence = jsonb_set(
                COALESCE(f.evidence, '{}'::jsonb),
                '{research}',
                jsonb_build_object(
                    'driven_by', 'autonomous_research',
                    'campaign_id', ca.mission_campaign_id::text,
                    'campaign_action_id', ca.id::text
                ),
                true
            ),
            updated_at = NOW()
        FROM campaign_actions ca
        WHERE f.scan_id = ca.scan_id
          AND ca.mission_campaign_id IS NOT NULL
          AND ($1::uuid IS NULL OR ca.mission_campaign_id = $1)
          AND ($2::uuid IS NULL OR ca.scan_id = $2)
          AND COALESCE(f.evidence->'research'->>'driven_by', '') <> 'autonomous_research'
        """,
        campaign_id,
        scan_id,
    )
    return len(rows)

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
    # Autonomous workflow findings carry the exact family in evidence. This
    # generic fallback keeps legacy records retestable when that field is absent.
    "autonomous_workflow": "generic_http",
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


async def _migrate_target_principal_slots(conn) -> None:
    """Make the two executable principal slots unambiguous."""
    await conn.execute("""
        UPDATE target_principals
        SET is_active = false,
            metadata_json = metadata_json || '{"deactivated_by":"principal_slot_v1"}'::jsonb,
            updated_at = NOW()
        WHERE is_active = true
          AND auth_state NOT IN ('user1', 'user2')
    """)
    await conn.execute("""
        WITH ranked AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY target_id, auth_state
                       ORDER BY updated_at DESC, id DESC
                   ) AS slot_rank
            FROM target_principals
            WHERE is_active = true
              AND auth_state IN ('user1', 'user2')
        )
        UPDATE target_principals p
        SET is_active = false,
            metadata_json = metadata_json || '{"deactivated_by":"principal_slot_v1_duplicate"}'::jsonb,
            updated_at = NOW()
        FROM ranked r
        WHERE p.id = r.id AND r.slot_rank > 1
    """)
    await conn.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_target_principals_active_auth_slot
        ON target_principals(target_id, auth_state)
        WHERE is_active = true AND auth_state IN ('user1', 'user2')
    """)


async def _migrate_hypothesis_proof_links(conn) -> None:
    """Add durable finding links used by proof reconciliation."""
    await conn.execute("""
        ALTER TABLE hypotheses
        ADD COLUMN IF NOT EXISTS promoted_finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb
    """)


async def _ensure_target_canonical_key_invariant(conn) -> None:
    """Create the canonical target key and fail startup if uniqueness cannot heal.

    Web identity is host-level, so an upgrade may need to merge rows that previously
    differed only by scheme or port. Model Intake artifact rows retain full subject
    identity. Continuing without the unique index is not safe: insert paths rely on it.
    """
    await conn.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS canonical_key TEXT")
    await conn.execute(r"""
        CREATE OR REPLACE FUNCTION targets_set_canonical_key() RETURNS trigger AS $$
        DECLARE
            raw TEXT;
            authority TEXT;
            host_part TEXT;
        BEGIN
            raw := regexp_replace(lower(btrim(COALESCE(NEW.url, ''))), '^https?://', '');
            IF lower(COALESCE(NEW.discovery_source, '')) = 'model-intake' THEN
                NEW.canonical_key := 'artifact:' || rtrim(raw, '/');
            ELSE
                authority := regexp_replace(raw, '[/?#].*$', '');
                authority := regexp_replace(authority, '^.*@', '');
                IF authority ~ '^\[[^]]+\]' THEN
                    host_part := substring(authority FROM '^\[([^]]+)\]');
                ELSE
                    host_part := regexp_replace(authority, ':[0-9]+$', '');
                END IF;
                NEW.canonical_key := 'web:' || rtrim(host_part, '.');
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)
    await conn.execute("DROP TRIGGER IF EXISTS trg_targets_canonical_key ON targets")
    await conn.execute("""
        CREATE TRIGGER trg_targets_canonical_key
            BEFORE INSERT OR UPDATE OF url, discovery_source ON targets
            FOR EACH ROW EXECUTE FUNCTION targets_set_canonical_key()
    """)

    migration_applied = bool(await conn.fetchval(
        "SELECT EXISTS (SELECT 1 FROM app_schema_migrations WHERE name=$1)",
        TARGET_HOST_IDENTITY_MIGRATION,
    ))
    existing_index_is_unique = await conn.fetchval(
        "SELECT indisunique FROM pg_index WHERE indexrelid=to_regclass('idx_targets_canonical_key')"
    )
    if migration_applied and existing_index_is_unique is True:
        return

    # The former unique origin index would reject the first host-key rewrite when two
    # historical rows use different ports. Startup runs under the schema advisory lock,
    # so remove it, repair complete target groups, recompute every key through the trigger,
    # and restore the invariant before serving requests.
    await conn.execute("DROP INDEX IF EXISTS idx_targets_canonical_key")
    from target_dedupe import merge_all_canonical_duplicates
    try:
        removed = await merge_all_canonical_duplicates(conn)
        await conn.execute("UPDATE targets SET url=url WHERE url IS NOT NULL")
        await conn.execute(
            "CREATE UNIQUE INDEX idx_targets_canonical_key ON targets(canonical_key)"
        )
        await conn.execute(
            "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
            TARGET_HOST_IDENTITY_MIGRATION,
        )
    except Exception as repair_error:
        message = (
            "Required schema invariant idx_targets_canonical_key could not be established "
            "after automatic host-level duplicate-target repair. ShakerScan startup is blocked to avoid "
            "running against a half-migrated database. Restore a database backup or repair "
            "canonical duplicate targets in maintenance mode, then restart. "
            f"Repair/retry error: {repair_error}"
        )
        print(f"[schema] FATAL: {message}", flush=True)
        raise SchemaMigrationError(message) from repair_error

    print(
        f"[schema] auto-merged {removed} duplicate target row(s); "
        "idx_targets_canonical_key created",
        flush=True,
    )


async def _reconcile_active_finding_counts(conn) -> None:
    """Repair denormalized owner badges from the authoritative finding rows."""
    await conn.execute("""
        UPDATE targets t
        SET active_findings_count=(
            SELECT COUNT(*) FROM findings f
            WHERE f.target_id=t.id AND f.status='active'
        )
    """)
    await conn.execute("""
        UPDATE device_targets d
        SET active_findings_count=(
            SELECT COUNT(*) FROM findings f
            WHERE f.device_target_id=d.id AND f.status='active'
        )
    """)


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

            # Scan and Hunt capability budgets share one durable reservation store. Keep its
            # schema under the same startup advisory lock as the rest of the authoritative
            # control-plane schema so rolling API and worker starts cannot observe a half-created
            # ledger.
            await PostgresBudgetReservationStore().ensure_schema(conn)

            # The fixed Scan graph records content-free stage outcomes after each
            # stage so worker loss does not erase trustworthy partial orchestration
            # state. Capability observations remain in their evidence/receipt stores.
            await PostgresScanStageCheckpointStore().ensure_schema(conn)

            # Canonical Scan admission persists the complete immutable action
            # allocation before queue handoff. Install its scheduler index under
            # the same startup lock as the shared reservation ledger.
            await PostgresScanActionStore().ensure_schema(conn)

            # Endpoint, candidate, saved-request, and template worklists are
            # durable content-addressed inputs to the same action scheduler.
            await PostgresScanManifestStore().ensure_schema(conn)

            # Generic capability results expose only these content-free
            # references; the bounded observation objects remain private.
            await PostgresObservationManifestStore().ensure_schema(conn)

            # Scan and Hunt share one encrypted, target-bound credential system.  Install it
            # under the same startup lock so neither API nor workers can observe profiles
            # without their immutable version and binding tables.
            await PostgresCredentialProfileStore().ensure_schema(conn)

            # Interactive Hunt identities are durable opaque references whose
            # cookies/tokens remain encrypted until a leased worker uses them.
            await PostgresAuthSessionStore().ensure_schema(conn)

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
                   OR schedule_kind NOT IN ('normal_scan', 'asm_improve', 'evidence_retention_sweep')
            """)
            await conn.execute("""
                UPDATE schedules
                SET is_active = false, updated_at = NOW()
                WHERE schedule_kind = 'evidence_retention_sweep'
                  AND is_active = true
            """)
            # Retire legacy Scan identities as executable schedule authority.
            # Passive historical presets are mapped once into canonical budget
            # ceilings. Formerly active presets are disabled for human review;
            # they are never silently re-authorized by the migration.
            await conn.execute("""
                UPDATE schedules
                SET scan_options = (
                        COALESCE(scan_options, '{}'::jsonb)
                        - ARRAY['scan_type','quick','thorough','active','xss','sqli',
                                'check_family','asm_check_family']::text[]
                    ) || jsonb_build_object(
                        'budget_profile', CASE
                            WHEN scan_type = 'quick' THEN 'fast'
                            WHEN scan_type IN ('deep','full','aggressive','smart') THEN 'thorough'
                            ELSE 'balanced'
                        END,
                        'scan_generation', 'v2',
                        'legacy_schedule_migrated', true
                    ),
                    is_active = CASE
                        WHEN scan_type IN ('full','aggressive','smart')
                          OR lower(COALESCE(scan_options->>'active', ''))
                             IN ('1','true','yes','on')
                        THEN false ELSE is_active END,
                    scan_type = 'scan',
                    updated_at = NOW()
                WHERE schedule_kind = 'normal_scan'
                  AND (
                    COALESCE(scan_type, '') <> 'scan'
                    OR scan_options ?| ARRAY[
                        'scan_type','quick','thorough','active','xss','sqli',
                        'check_family','asm_check_family'
                    ]
                  )
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
                ADD COLUMN IF NOT EXISTS run_kind TEXT DEFAULT 'web_dast',
                ADD COLUMN IF NOT EXISTS shard_index INTEGER,
                ADD COLUMN IF NOT EXISTS shard_count INTEGER
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS scan_generation TEXT NOT NULL DEFAULT 'legacy',
                ADD COLUMN IF NOT EXISTS policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS budget_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS budget_used_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS coverage_status TEXT,
                ADD COLUMN IF NOT EXISTS coverage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS scan_job_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS scan_job_digest TEXT
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
                    last_seen_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
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
                ADD COLUMN IF NOT EXISTS last_reachability_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS last_seen_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL
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
                CREATE INDEX IF NOT EXISTS idx_target_endpoints_seen_scan_auth
                ON target_endpoints(target_id, last_seen_scan_id, auth_state)
                WHERE last_seen_scan_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_credential_profiles (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    auth_kind TEXT NOT NULL,
                    secret_value TEXT NOT NULL,
                    secret_preview TEXT,
                    expires_at TIMESTAMPTZ,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT target_credential_profiles_auth_kind_check
                        CHECK (auth_kind IN ('authorization_header', 'cookie'))
                )
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_target_credential_profiles_name
                ON target_credential_profiles(target_id, lower(name))
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_credential_profiles_active
                ON target_credential_profiles(target_id, is_active, expires_at)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_principal_provisioning_attempts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    principal_label TEXT NOT NULL,
                    auth_state TEXT NOT NULL,
                    encrypted_variables TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT target_principal_provisioning_attempts_status_check
                        CHECK (status IN ('pending','completed','failed')),
                    CONSTRAINT target_principal_provisioning_attempts_unique
                        UNIQUE (target_id, auth_state)
                )
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
            # Scanner execution has exactly two authenticated identity slots.
            # Retain legacy rows for audit, but deactivate unsupported slots and
            # duplicate active assignments before enforcing one principal per slot.
            await _migrate_target_principal_slots(conn)
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
            # Operator-authored business/security rules. Free text remains draft intake; only a typed,
            # explicitly approved contract enters autonomous planner context. These records are planning
            # facts and cannot directly create findings or mark proof verified.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS target_invariant_contracts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    contract_version TEXT NOT NULL,
                    contract_kind TEXT NOT NULL,
                    title TEXT NOT NULL,
                    source_text TEXT,
                    subject_role TEXT,
                    action TEXT,
                    resource TEXT,
                    method TEXT,
                    path TEXT,
                    field_name TEXT,
                    operator TEXT,
                    expected_value JSONB,
                    expected_access TEXT,
                    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
                    status TEXT NOT NULL DEFAULT 'draft',
                    source TEXT NOT NULL DEFAULT 'manual',
                    approved_at TIMESTAMPTZ,
                    approved_by TEXT,
                    retired_at TIMESTAMPTZ,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT target_invariant_contracts_kind_check CHECK (
                        contract_kind IN ('access_control','field_constraint','workflow_transition','ownership')
                    ),
                    CONSTRAINT target_invariant_contracts_status_check CHECK (
                        status IN ('draft','approved','retired')
                    ),
                    CONSTRAINT target_invariant_contracts_access_check CHECK (
                        expected_access IS NULL OR expected_access IN ('allow','deny','requires_role')
                    ),
                    CONSTRAINT target_invariant_contracts_operator_check CHECK (
                        operator IS NULL OR operator IN ('eq','ne','lt','lte','gt','gte','in','not_in')
                    )
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_target_invariant_contracts_target_status
                ON target_invariant_contracts(target_id, status, updated_at DESC)
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
                  AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')
                ORDER BY target_url, completed_at DESC
            """)
            await conn.execute("""
                CREATE OR REPLACE VIEW dashboard_metrics AS
                SELECT
                    (SELECT COUNT(*) FROM targets WHERE is_active = true AND COALESCE(discovery_source, 'manual') <> 'model-intake') as total_targets,
                    (SELECT COUNT(*) FROM scans WHERE status = 'completed' AND (scan_role IS NULL OR scan_role <> 'shard') AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')) as total_scans,
                    (SELECT COUNT(*) FROM scans WHERE status = 'running' AND (scan_role IS NULL OR scan_role <> 'shard') AND COALESCE(run_kind, 'web_dast') NOT IN ('device_posture', 'device_probe', 'device_web_dast')) as running_scans,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND COALESCE(source, 'scan') <> 'device') as active_findings,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'critical' AND COALESCE(source, 'scan') <> 'device') as critical_findings,
                    (SELECT COUNT(*) FROM findings WHERE status = 'active' AND severity = 'high' AND COALESCE(source, 'scan') <> 'device') as high_findings,
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
                ALTER TABLE finding_exceptions
                ADD COLUMN IF NOT EXISTS edit_history JSONB NOT NULL DEFAULT '[]'::jsonb
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
                    action_name TEXT,
                    action_context JSONB NOT NULL DEFAULT '{}'::jsonb,
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
                ALTER TABLE approval_receipts
                ADD COLUMN IF NOT EXISTS action_name TEXT,
                ADD COLUMN IF NOT EXISTS action_context JSONB NOT NULL DEFAULT '{}'::jsonb
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
                CREATE INDEX IF NOT EXISTS idx_command_results_created_by
                ON command_results(created_by, created_at DESC) WHERE created_by IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS campaign_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    campaign_id UUID REFERENCES scan_campaigns(id) ON DELETE SET NULL,
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    command_result_id UUID REFERENCES command_results(id) ON DELETE SET NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    submission_id UUID,
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
                        'finding_retest','focused_family','autonomous_research'
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
            await conn.execute("""
                ALTER TABLE campaigns DROP CONSTRAINT IF EXISTS campaigns_type_check
            """)
            await conn.execute("""
                ALTER TABLE campaigns ADD CONSTRAINT campaigns_type_check CHECK (campaign_type IN (
                    'continuous_asm','authenticated_dast','api_authz','ai_red_team','model_intake',
                    'benchmark','incident_retest','source_informed_dast','finding_retest',
                    'focused_family','autonomous_research'
                ))
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
            # Findings produced by research-driven scans are linked back to the campaign ledger
            # by scan_id; the join needs an index on large findings tables.
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)
            """)
            # One-time retroactive repair: a research decision that queued a scan recorded the
            # scan on campaign_actions but never backfilled finding_ids, so hunt-driven scanner
            # findings were invisible in the campaign impact panel and indistinguishable from
            # organic DAST output. Idempotent; settles instantly on re-run.
            applied = await conn.fetchval(
                "SELECT 1 FROM app_schema_migrations WHERE name = $1",
                CAMPAIGN_SCAN_FINDING_LINKS_MIGRATION,
            )
            if not applied:
                linked = await backfill_campaign_scan_finding_links(conn)
                print(f"[schema] campaign scan finding links backfill: {linked} actions linked", flush=True)
                await conn.execute(
                    "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
                    CAMPAIGN_SCAN_FINDING_LINKS_MIGRATION,
                )
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
                    promoted_finding_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                    next_test_action JSONB,
                    endorsements JSONB NOT NULL DEFAULT '[]'::jsonb,
                    refutations JSONB NOT NULL DEFAULT '[]'::jsonb,
                    terminal_reason TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT hypotheses_source_check
                        CHECK (source IN ('app_graph','source_ingest','ai_planner','scanner_signal','ai_gate','model_intake','benchmark','invariant','manual')),
                    CONSTRAINT hypotheses_status_check
                        CHECK (status IN ('open','claimed','testing','supported','refuted','blocked','exhausted','promoted','dead')),
                    CONSTRAINT hypotheses_severity_check
                        CHECK (severity_guess IS NULL OR severity_guess IN ('critical','high','medium','low','info')),
                    CONSTRAINT hypotheses_confidence_check
                        CHECK (confidence >= 0 AND confidence <= 1),
                    CONSTRAINT hypotheses_smoke_score_check
                        CHECK (smoke_score IS NULL OR (smoke_score >= 0 AND smoke_score <= 1))
                )
            """)
            await conn.execute("ALTER TABLE hypotheses DROP CONSTRAINT IF EXISTS hypotheses_source_check")
            await _migrate_hypothesis_proof_links(conn)
            await conn.execute("""
                ALTER TABLE hypotheses
                ADD CONSTRAINT hypotheses_source_check
                CHECK (source IN ('app_graph','source_ingest','ai_planner','scanner_signal','ai_gate','model_intake','benchmark','invariant','manual'))
            """)
            # Wave 4: widen the lifecycle to include blocked/exhausted (see hypothesis_lifecycle.py).
            # Widening a CHECK is safe — every existing row already satisfies the superset.
            await conn.execute("ALTER TABLE hypotheses DROP CONSTRAINT IF EXISTS hypotheses_status_check")
            await conn.execute("""
                ALTER TABLE hypotheses
                ADD CONSTRAINT hypotheses_status_check
                CHECK (status IN ('open','claimed','testing','supported','refuted','blocked','exhausted','promoted','dead'))
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
                ALTER TABLE refuter_reviews DROP CONSTRAINT IF EXISTS refuter_reviews_subject_check
            """)
            await conn.execute("""
                ALTER TABLE refuter_reviews ADD CONSTRAINT refuter_reviews_subject_check
                    CHECK (subject_type IN ('finding','hypothesis','target','ai_gate_scan','model_intake','benchmark','planner','deployment_gate','parser_output','manual'))
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
            # Durable, turn-based ReAct hunt runs (keyless planner). The server suspends at each
            # planner turn and an external coding-agent session drives it via /agent/hunt/session/*;
            # the loop transcript + counters + evidence live in `state` (JSONB) so a run survives
            # across turns and restarts. Tool execution and gating remain server-side; findings land
            # in the SUSPECTED tier (findings table), never the family_proof VERIFIED moat.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_hunt_runs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    -- research_episodes is created later in this upgrade path. Add
                    -- the FK after both tables exist so published schemas can upgrade.
                    episode_id UUID,
                    objective TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'awaiting_planner',
                    planner_mode TEXT NOT NULL DEFAULT 'agent',
                    max_iterations INT NOT NULL DEFAULT 12,
                    allow_write BOOLEAN NOT NULL DEFAULT FALSE,
                    allow_active BOOLEAN NOT NULL DEFAULT FALSE,
                    approval_receipt_id UUID,
                    token_budget INT NOT NULL DEFAULT 6000,
                    state JSONB NOT NULL DEFAULT '{}'::jsonb,
                    planning_token UUID,
                    stop_reason TEXT,
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT agent_hunt_runs_status_check
                        CHECK (status IN ('awaiting_planner','planning','completed','cancelled','failed'))
                )
            """)
            await conn.execute("""
                ALTER TABLE agent_hunt_runs
                ADD COLUMN IF NOT EXISTS planning_token UUID
            """)
            # 'planning' is a transient claim status: a reply flips awaiting_planner->planning under a
            # short row lock, RELEASES the lock, executes tools, then writes the result back. This keeps
            # target HTTP/subprocess work OUT of the row-locked transaction (audit N3). Widen the
            # constraint on already-created tables.
            await conn.execute("""
                ALTER TABLE agent_hunt_runs DROP CONSTRAINT IF EXISTS agent_hunt_runs_status_check
            """)
            await conn.execute("""
                ALTER TABLE agent_hunt_runs ADD CONSTRAINT agent_hunt_runs_status_check
                    CHECK (status IN ('awaiting_planner','planning','completed','cancelled','failed'))
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_hunt_runs_target
                ON agent_hunt_runs(target_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_agent_hunt_runs_status
                ON agent_hunt_runs(status, updated_at DESC)
            """)
            # Bounded adaptive research agent. The model owns no authorization
            # state: episodes reference durable scope/approval receipts and each
            # immutable decision is validated before Arsenal dispatch.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_episodes (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    operation_plan_id UUID REFERENCES operation_plans(id) ON DELETE SET NULL,
                    campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
                    objective TEXT NOT NULL,
                    episode_version TEXT NOT NULL,
                    planner JSONB NOT NULL DEFAULT '{}'::jsonb,
                    execution_mode TEXT NOT NULL DEFAULT 'read_only',
                    status TEXT NOT NULL DEFAULT 'created',
                    version INTEGER NOT NULL DEFAULT 1,
                    max_risk_tier TEXT NOT NULL DEFAULT 'read_only',
                    allowed_families JSONB NOT NULL DEFAULT '[]'::jsonb,
                    budget_limits JSONB NOT NULL DEFAULT '{}'::jsonb,
                    budget_used JSONB NOT NULL DEFAULT '{}'::jsonb,
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
                    approval_receipt_id UUID REFERENCES approval_receipts(id) ON DELETE SET NULL,
                    current_observation_id UUID,
                    current_decision_id UUID,
                    step_count INTEGER NOT NULL DEFAULT 0,
                    cancel_requested BOOLEAN NOT NULL DEFAULT false,
                    autopilot_enabled BOOLEAN NOT NULL DEFAULT false,
                    autopilot_error TEXT,
                    autopilot_consecutive_failures INTEGER NOT NULL DEFAULT 0,
                    stop_reason TEXT,
                    requested_input TEXT,
                    lease_owner TEXT,
                    lease_expires_at TIMESTAMPTZ,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT research_episodes_status_check CHECK (status IN (
                        'created','awaiting_planner','validating_decision','dispatching',
                        'awaiting_observation','awaiting_input','approval_required',
                        'completed','cancelled','failed','budget_exhausted','blocked'
                    )),
                    CONSTRAINT research_episodes_execution_mode_check CHECK (execution_mode IN (
                        'shadow','read_only','gated'
                    )),
                    CONSTRAINT research_episodes_risk_check CHECK (max_risk_tier IN (
                        'read_only','passive','active','intrusive','credential','dangerous'
                    )),
                    CONSTRAINT research_episodes_step_count_check CHECK (step_count >= 0)
                )
            """)
            await conn.execute("""
                ALTER TABLE research_episodes
                ADD COLUMN IF NOT EXISTS autopilot_enabled BOOLEAN NOT NULL DEFAULT false,
                ADD COLUMN IF NOT EXISTS autopilot_error TEXT,
                ADD COLUMN IF NOT EXISTS autopilot_consecutive_failures INTEGER NOT NULL DEFAULT 0
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_episodes_autopilot
                ON research_episodes(updated_at)
                WHERE autopilot_enabled = true AND status = 'awaiting_planner'
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_episodes_autopilot_work
                ON research_episodes(updated_at)
                WHERE autopilot_enabled = true
                  AND status IN ('awaiting_planner', 'awaiting_observation')
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_episodes_target
                ON research_episodes(target_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_episodes_status
                ON research_episodes(status, updated_at DESC)
            """)
            await conn.execute("""
                DROP INDEX IF EXISTS idx_research_episodes_active_campaign
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_research_episodes_active_campaign
                ON research_episodes(campaign_id)
                WHERE campaign_id IS NOT NULL
                  AND planner->>'campaign_autopilot' = 'true'
                  AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_research_episodes_active_launch
                ON research_episodes (
                    target_id,
                    (planner #>> '{mission,profile}'),
                    (planner #>> '{mission,subject,type}'),
                    (planner #>> '{mission,subject,id}'),
                    execution_mode,
                    (planner->>'launch_intensity')
                )
                WHERE planner->>'dedupe_launch' = 'true'
                  AND status NOT IN ('completed','cancelled','failed','budget_exhausted','blocked')
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'agent_hunt_runs_episode_id_fkey'
                          AND conrelid = 'agent_hunt_runs'::regclass
                    ) THEN
                        ALTER TABLE agent_hunt_runs
                        ADD CONSTRAINT agent_hunt_runs_episode_id_fkey
                        FOREIGN KEY (episode_id) REFERENCES research_episodes(id) ON DELETE SET NULL;
                    END IF;
                END $$
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_observations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    episode_id UUID NOT NULL REFERENCES research_episodes(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    observation_version TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    episode_version INTEGER NOT NULL,
                    observation_pack JSONB NOT NULL,
                    previous_command_result_id UUID REFERENCES command_results(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT research_observations_sequence_check CHECK (sequence >= 0),
                    CONSTRAINT research_observations_episode_sequence_unique UNIQUE (episode_id, sequence)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_observations_episode
                ON research_observations(episode_id, sequence DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_decisions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    episode_id UUID NOT NULL REFERENCES research_episodes(id) ON DELETE CASCADE,
                    observation_id UUID NOT NULL REFERENCES research_observations(id) ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    decision_version TEXT NOT NULL,
                    planner JSONB NOT NULL DEFAULT '{}'::jsonb,
                    decision_type TEXT NOT NULL,
                    hypothesis_id UUID REFERENCES hypotheses(id) ON DELETE SET NULL,
                    action JSONB NOT NULL DEFAULT '{}'::jsonb,
                    expected_signal TEXT,
                    falsifier TEXT,
                    reason TEXT,
                    confidence DOUBLE PRECISION NOT NULL DEFAULT 0,
                    requested_input TEXT,
                    stop_reason TEXT,
                    status TEXT NOT NULL,
                    validation_errors JSONB NOT NULL DEFAULT '[]'::jsonb,
                    validation_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
                    policy_result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    command_result_id UUID REFERENCES command_results(id) ON DELETE SET NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT research_decisions_type_check CHECK (decision_type IN (
                        'execute_action','request_input','stop'
                    )),
                    CONSTRAINT research_decisions_status_check CHECK (status IN (
                        'accepted','rejected','dispatching','completed','blocked','failed'
                    )),
                    CONSTRAINT research_decisions_confidence_check CHECK (confidence >= 0 AND confidence <= 1),
                    CONSTRAINT research_decisions_sequence_check CHECK (sequence >= 1)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_decisions_episode
                ON research_decisions(episode_id, sequence DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    episode_id UUID NOT NULL REFERENCES research_episodes(id) ON DELETE CASCADE,
                    sequence BIGSERIAL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    observation_id UUID REFERENCES research_observations(id) ON DELETE SET NULL,
                    decision_id UUID REFERENCES research_decisions(id) ON DELETE SET NULL,
                    command_result_id UUID REFERENCES command_results(id) ON DELETE SET NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_research_events_episode
                ON research_events(episode_id, sequence)
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'research_episodes_current_observation_id_fkey'
                          AND conrelid = 'research_episodes'::regclass
                    ) THEN
                        ALTER TABLE research_episodes
                        ADD CONSTRAINT research_episodes_current_observation_id_fkey
                        FOREIGN KEY (current_observation_id) REFERENCES research_observations(id) ON DELETE SET NULL;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'research_episodes_current_decision_id_fkey'
                          AND conrelid = 'research_episodes'::regclass
                    ) THEN
                        ALTER TABLE research_episodes
                        ADD CONSTRAINT research_episodes_current_decision_id_fkey
                        FOREIGN KEY (current_decision_id) REFERENCES research_decisions(id) ON DELETE SET NULL;
                    END IF;
                END
                $$
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_intake_trust_anchors (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    public_key_pem TEXT,
                    public_key_sha256 TEXT,
                    policy_profile TEXT,
                    purpose TEXT NOT NULL DEFAULT 'publisher_signature',
                    environment TEXT NOT NULL DEFAULT 'production',
                    valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    valid_until TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ,
                    revocation_reason TEXT,
                    issuer_constraint TEXT,
                    subject_constraint TEXT,
                    builder_id_constraint TEXT,
                    source TEXT NOT NULL DEFAULT 'operator',
                    version TEXT NOT NULL DEFAULT '1',
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
                ALTER TABLE model_intake_trust_anchors
                    ADD COLUMN IF NOT EXISTS purpose TEXT NOT NULL DEFAULT 'publisher_signature',
                    ADD COLUMN IF NOT EXISTS environment TEXT NOT NULL DEFAULT 'production',
                    ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ADD COLUMN IF NOT EXISTS valid_until TIMESTAMPTZ,
                    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
                    ADD COLUMN IF NOT EXISTS revocation_reason TEXT,
                    ADD COLUMN IF NOT EXISTS issuer_constraint TEXT,
                    ADD COLUMN IF NOT EXISTS subject_constraint TEXT,
                    ADD COLUMN IF NOT EXISTS builder_id_constraint TEXT,
                    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'operator',
                    ADD COLUMN IF NOT EXISTS version TEXT NOT NULL DEFAULT '1'
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_trust_anchors_active
                ON model_intake_trust_anchors(is_active, policy_profile)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_trust_anchors_scope
                ON model_intake_trust_anchors(is_active, purpose, environment, policy_profile)
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
            # Connected-device posture uses a separate asset and finding namespace.
            # Device-owned web children deliberately keep target_id NULL so they
            # cannot mutate the Web DAST target inventory or ASM statistics.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_policies (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    device_class TEXT NOT NULL DEFAULT 'generic',
                    environment TEXT NOT NULL DEFAULT 'production',
                    rules JSONB NOT NULL DEFAULT '[]'::jsonb,
                    is_builtin BOOLEAN NOT NULL DEFAULT false,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                INSERT INTO device_policies (name, description, device_class, rules, is_builtin)
                VALUES (
                    'connected-device-default-v1',
                    'Safe baseline: forbid cleartext administration, flag unknown services, and require secure SSH.',
                    'generic',
                    '[
                      {"action":"deny","transport":"tcp","ports":[23,2323],"service":"any","severity":"critical","reason":"Cleartext remote administration is forbidden."},
                      {"action":"deny","transport":"tcp","ports":[21],"service":"any","severity":"high","reason":"Cleartext file transfer is forbidden."},
                      {"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false},"severity":"high"},
                      {"action":"allow","transport":"tcp","service":"http","encrypted":false,"severity":"medium"},
                      {"action":"allow","transport":"tcp","service":"https","encrypted":true},
                      {"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"An unclassified listening service requires review."}
                    ]'::jsonb,
                    true
                )
                ON CONFLICT (name) DO NOTHING
            """)
            await conn.execute("""
                INSERT INTO device_policies (name, description, device_class, rules, is_builtin)
                VALUES
                ('connected-device-default-v2', 'Fail-closed generic baseline: block cleartext administration, require hardened SSH, review cleartext web and unknown services.', 'generic',
                 '[{"action":"deny","transport":"tcp","ports":[23,2323],"service":"any","severity":"critical","reason":"Cleartext remote administration is forbidden."},{"action":"deny","transport":"tcp","ports":[21],"service":"any","severity":"high","reason":"Cleartext file transfer is forbidden."},{"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},{"action":"allow","transport":"tcp","service":"https","encrypted":true},{"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Cleartext device management should be isolated or upgraded to HTTPS."},{"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"An unclassified listening service requires review."}]'::jsonb, true),
                ('media-device-baseline-v1', 'Smart TV, streaming, and conference display service baseline.', 'media',
                 '[{"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},{"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},{"action":"allow","transport":"tcp","service":"https","encrypted":true},{"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Cleartext media-device web management requires network isolation."},{"action":"allow","transport":"udp","ports":[1900],"service":"upnp"},{"action":"allow","transport":"udp","ports":[5353],"service":"mdns"},{"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"Unexpected media-device service."}]'::jsonb, true),
                ('camera-baseline-v1', 'IP camera and video endpoint baseline.', 'camera',
                 '[{"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},{"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},{"action":"allow","transport":"tcp","service":"https","encrypted":true},{"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"high","reason":"Camera management traffic is unencrypted."},{"action":"review","transport":"tcp","service":"rtsp","severity":"medium","reason":"Confirm RTSP authentication and network isolation."},{"action":"review","transport":"any","service":"unknown","severity":"high","reason":"Unexpected camera service."}]'::jsonb, true),
                ('printer-baseline-v1', 'Printer and multifunction-device baseline.', 'printer',
                 '[{"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"high","reason":"Legacy cleartext administration is forbidden."},{"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},{"action":"allow","transport":"tcp","service":"https","encrypted":true},{"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"medium","reason":"Printer management is unencrypted."},{"action":"review","transport":"tcp","ports":[631,9100],"service":"any","severity":"low","reason":"Confirm print service access is limited to print networks."},{"action":"review","transport":"udp","ports":[161],"service":"snmp","severity":"medium","reason":"Confirm SNMPv3 and restricted management access."},{"action":"review","transport":"any","service":"unknown","severity":"medium","reason":"Unexpected printer service."}]'::jsonb, true),
                ('network-appliance-baseline-v1', 'Router, access point, NAS, and network appliance baseline.', 'router',
                 '[{"action":"deny","transport":"tcp","ports":[21,23,2323],"service":"any","severity":"critical","reason":"Legacy cleartext administration is forbidden."},{"action":"require","transport":"tcp","service":"ssh","requirements":{"password_auth":false,"weak_algorithms":false,"publickey_auth":true},"severity":"high"},{"action":"allow","transport":"tcp","service":"https","encrypted":true},{"action":"review","transport":"tcp","service":"http","encrypted":false,"severity":"high","reason":"Network appliance management is unencrypted."},{"action":"allow","transport":"any","ports":[53],"service":"domain"},{"action":"review","transport":"udp","ports":[161],"service":"snmp","severity":"medium","reason":"Confirm SNMPv3 and management-plane isolation."},{"action":"review","transport":"any","service":"unknown","severity":"high","reason":"Unexpected network appliance service."}]'::jsonb, true)
                ON CONFLICT (name) DO NOTHING
            """)
            await conn.execute("""
                UPDATE device_policies AS policy
                SET rules=(
                    SELECT COALESCE(jsonb_agg(
                        CASE
                            WHEN rule->>'action'='deny'
                             AND rule->>'transport'='tcp'
                             AND EXISTS (
                                 SELECT 1
                                 FROM jsonb_array_elements_text(
                                     CASE
                                         WHEN jsonb_typeof(rule->'ports') = 'array'
                                         THEN rule->'ports'
                                         ELSE '[]'::jsonb
                                     END
                                 ) AS denied_port(value)
                                 WHERE denied_port.value IN ('21','23','2323')
                             )
                            THEN jsonb_set(rule, '{service}', '"any"'::jsonb, true)
                            ELSE rule
                        END
                    ), '[]'::jsonb)
                    FROM jsonb_array_elements(policy.rules) AS rule
                ), updated_at=NOW()
                WHERE policy.name IN ('connected-device-default-v1','connected-device-default-v2')
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_targets (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL,
                    primary_locator TEXT NOT NULL,
                    device_class TEXT NOT NULL DEFAULT 'generic',
                    manufacturer TEXT,
                    model TEXT,
                    firmware_version TEXT,
                    stable_identity TEXT,
                    identity_confidence TEXT NOT NULL DEFAULT 'low',
                    environment TEXT NOT NULL DEFAULT 'production',
                    policy_id UUID REFERENCES device_policies(id) ON DELETE SET NULL,
                    sensor_affinity TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    last_scanned_at TIMESTAMPTZ,
                    last_scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    last_score INTEGER,
                    last_grade TEXT,
                    active_findings_count INTEGER NOT NULL DEFAULT 0,
                    locator_generation INTEGER NOT NULL DEFAULT 1,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT device_targets_identity_confidence_check CHECK (identity_confidence IN ('low','medium','high','verified'))
                )
            """)
            await conn.execute("""
                ALTER TABLE device_targets
                ADD COLUMN IF NOT EXISTS locator_generation INTEGER NOT NULL DEFAULT 1
            """)
            await conn.execute("ALTER TABLE device_targets DROP CONSTRAINT IF EXISTS device_targets_locator_unique")
            await conn.execute("ALTER TABLE device_targets DROP CONSTRAINT IF EXISTS device_targets_primary_locator_key")
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_device_targets_active_locator
                ON device_targets(primary_locator) WHERE is_active=true
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_interfaces (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    interface_type TEXT NOT NULL DEFAULT 'network',
                    locator_type TEXT NOT NULL DEFAULT 'ip',
                    locator TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    network_zone TEXT,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    CONSTRAINT device_interfaces_locator_unique UNIQUE (device_target_id, interface_type, locator_type, locator)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_locator_history (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    previous_locator TEXT,
                    locator TEXT NOT NULL,
                    locator_type TEXT NOT NULL,
                    change_reason TEXT,
                    change_source TEXT NOT NULL DEFAULT 'operator',
                    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_locator_history_device
                ON device_locator_history(device_target_id, changed_at DESC)
            """)
            await conn.execute("""
                INSERT INTO device_locator_history (
                    device_target_id, previous_locator, locator, locator_type,
                    change_reason, change_source
                )
                SELECT d.id, NULL, d.primary_locator,
                       CASE
                           WHEN d.primary_locator ~ '^([0-9]{1,3}\\.){3}[0-9]{1,3}$'
                                OR d.primary_locator LIKE '%:%' THEN 'ip'
                           ELSE 'hostname'
                       END,
                       'Initial registered locator', 'migration'
                FROM device_targets d
                WHERE NOT EXISTS (
                    SELECT 1 FROM device_locator_history h WHERE h.device_target_id=d.id
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_credential_profiles (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    auth_kind TEXT NOT NULL,
                    username TEXT,
                    secret_value TEXT NOT NULL,
                    secret_preview TEXT,
                    login_path TEXT,
                    port INTEGER CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
                    expires_at TIMESTAMPTZ,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT device_credential_profiles_kind_check CHECK (auth_kind IN (
                        'ssh_password','ssh_private_key','web_authorization_header','web_cookie','web_form'
                    )),
                    CONSTRAINT device_credential_profiles_name_unique UNIQUE (device_target_id, name)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_credential_profiles_active
                ON device_credential_profiles(device_target_id, is_active, expires_at)
            """)
            await conn.execute("UPDATE device_credential_profiles SET secret_preview=NULL WHERE secret_preview IS NOT NULL")
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_request_collections (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    format TEXT NOT NULL DEFAULT 'postman_collection',
                    document_sha256 TEXT NOT NULL,
                    encrypted_payload TEXT NOT NULL,
                    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT device_request_collections_format_check CHECK (format IN ('postman_collection','har','openapi')),
                    CONSTRAINT device_request_collections_name_unique UNIQUE (device_target_id, name)
                )
            """)
            await conn.execute("ALTER TABLE device_request_collections DROP CONSTRAINT IF EXISTS device_request_collections_format_check")
            await conn.execute("""
                ALTER TABLE device_request_collections
                ADD CONSTRAINT device_request_collections_format_check
                CHECK (format IN ('postman_collection','har','openapi'))
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_request_collections_active
                ON device_request_collections(device_target_id, is_active, updated_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_credential_attempts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    credential_profile_id UUID NOT NULL REFERENCES device_credential_profiles(id) ON DELETE CASCADE,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    outcome TEXT NOT NULL,
                    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT device_credential_attempts_outcome_check CHECK (outcome IN ('succeeded','rejected','error')),
                    CONSTRAINT device_credential_attempts_scan_profile_unique UNIQUE (scan_id, credential_profile_id)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_credential_attempts_profile_time
                ON device_credential_attempts(credential_profile_id, attempted_at DESC)
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS run_kind TEXT DEFAULT 'web_dast',
                ADD COLUMN IF NOT EXISTS subject_ref TEXT,
                ADD COLUMN IF NOT EXISTS ai_target_id UUID REFERENCES ai_targets(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS device_target_id UUID REFERENCES device_targets(id) ON DELETE SET NULL
            """)
            await conn.execute("""
                ALTER TABLE findings
                ADD COLUMN IF NOT EXISTS device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE
            """)
            await conn.execute("""
                CREATE OR REPLACE FUNCTION refresh_device_active_findings_count()
                RETURNS TRIGGER AS $$
                BEGIN
                    UPDATE device_targets d
                    SET active_findings_count=(
                        SELECT COUNT(*) FROM findings f
                        WHERE f.device_target_id=d.id AND f.status='active'
                    ), updated_at=NOW()
                    WHERE d.id IN (OLD.device_target_id, NEW.device_target_id);
                    RETURN NULL;
                END;
                $$ LANGUAGE plpgsql
            """)
            await conn.execute("DROP TRIGGER IF EXISTS trg_refresh_device_active_findings_count ON findings")
            await conn.execute("""
                CREATE TRIGGER trg_refresh_device_active_findings_count
                AFTER INSERT OR UPDATE OF status, device_target_id OR DELETE ON findings
                FOR EACH ROW EXECUTE FUNCTION refresh_device_active_findings_count()
            """)
            await _reconcile_active_finding_counts(conn)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_services (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    interface_id UUID REFERENCES device_interfaces(id) ON DELETE SET NULL,
                    transport TEXT NOT NULL,
                    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
                    state TEXT NOT NULL DEFAULT 'open',
                    service_name TEXT NOT NULL DEFAULT 'unknown',
                    product TEXT,
                    version TEXT,
                    cpe TEXT,
                    encrypted BOOLEAN,
                    web_origin TEXT,
                    policy_disposition TEXT,
                    policy_reason TEXT,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    CONSTRAINT device_services_identity_unique UNIQUE (device_target_id, transport, port)
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_agent_runs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    objective TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'awaiting_planner',
                    planner_mode TEXT NOT NULL DEFAULT 'agent',
                    safety_profile TEXT NOT NULL DEFAULT 'safe_remote',
                    max_turns INTEGER NOT NULL DEFAULT 12 CHECK (max_turns BETWEEN 1 AND 30),
                    approval_receipt_id UUID,
                    state JSONB NOT NULL DEFAULT '{}'::jsonb,
                    planning_token UUID,
                    stop_reason TEXT,
                    result JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT device_agent_runs_status_check CHECK (
                        status IN ('awaiting_planner','planning','completed','cancelled','failed')
                    ),
                    CONSTRAINT device_agent_runs_safety_check CHECK (
                        safety_profile IN ('observe_only','safe_remote','authenticated_active','lab_invasive')
                    )
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_agent_runs_device
                ON device_agent_runs(device_target_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_agent_runs_status
                ON device_agent_runs(status, updated_at DESC)
            """)
            await conn.execute("""
                WITH ranked AS (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY device_target_id ORDER BY created_at, id
                    ) AS position
                    FROM device_agent_runs
                    WHERE status IN ('awaiting_planner','planning')
                )
                UPDATE device_agent_runs
                SET status='cancelled', stop_reason='migration_duplicate_active_session',
                    planning_token=NULL, updated_at=NOW()
                WHERE id IN (SELECT id FROM ranked WHERE position > 1)
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_device_agent_runs_one_active_per_device
                ON device_agent_runs(device_target_id)
                WHERE status IN ('awaiting_planner','planning')
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS device_agent_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    run_id UUID NOT NULL REFERENCES device_agent_runs(id) ON DELETE CASCADE,
                    device_target_id UUID NOT NULL REFERENCES device_targets(id) ON DELETE CASCADE,
                    tool_name TEXT NOT NULL,
                    tool_tier INTEGER NOT NULL CHECK (tool_tier BETWEEN 0 AND 3),
                    fragility_cost INTEGER NOT NULL DEFAULT 0 CHECK (fragility_cost BETWEEN 0 AND 100),
                    rationale TEXT,
                    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    outcome TEXT NOT NULL CHECK (outcome IN ('completed','blocked','failed')),
                    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_agent_actions_run
                ON device_agent_actions(run_id, created_at)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_agent_actions_device_day
                ON device_agent_actions(device_target_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS request_collections (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    format TEXT NOT NULL,
                    schema_version TEXT NOT NULL DEFAULT 'request-collection/v2',
                    encrypted_payload TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    safe_request_count INTEGER NOT NULL DEFAULT 0,
                    potentially_mutating_request_count INTEGER NOT NULL DEFAULT 0,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    is_active BOOLEAN NOT NULL DEFAULT true,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT request_collections_target_check CHECK (
                        (target_id IS NOT NULL AND device_target_id IS NULL) OR
                        (device_target_id IS NOT NULL AND target_id IS NULL)
                    )
                )
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_request_collections_target_name
                ON request_collections(
                    COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid),
                    COALESCE(device_target_id, '00000000-0000-0000-0000-000000000000'::uuid), name
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_request_collections_web
                ON request_collections(target_id, updated_at DESC)
                WHERE target_id IS NOT NULL AND is_active=true
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_request_collections_device
                ON request_collections(device_target_id, updated_at DESC)
                WHERE device_target_id IS NOT NULL AND is_active=true
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS request_collection_requests (
                    collection_id UUID NOT NULL REFERENCES request_collections(id) ON DELETE CASCADE,
                    request_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL,
                    folder TEXT,
                    name TEXT,
                    method TEXT NOT NULL,
                    redacted_url TEXT,
                    normalized_path TEXT,
                    body_mode TEXT,
                    auth_type TEXT,
                    safe_method BOOLEAN NOT NULL DEFAULT false,
                    supported BOOLEAN NOT NULL DEFAULT true,
                    PRIMARY KEY (collection_id, request_id)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_request_collection_requests_page
                ON request_collection_requests(collection_id, ordinal)
            """)
            await PostgresRequestCollectionStore().ensure_schema(conn)
            await conn.execute("""
                INSERT INTO request_collections (
                    id, device_target_id, name, format, encrypted_payload, payload_sha256,
                    request_count, safe_request_count, potentially_mutating_request_count,
                    metadata_json, is_active, created_at, updated_at
                )
                SELECT id, device_target_id, name, format, encrypted_payload, document_sha256,
                       COALESCE((summary_json->>'request_count')::int, 0),
                       COALESCE((summary_json->>'safe_request_count')::int, 0),
                       COALESCE((summary_json->>'state_changing_request_count')::int, 0),
                       summary_json, is_active, created_at, updated_at
                FROM device_request_collections
                ON CONFLICT (id) DO NOTHING
            """)
            # Legacy connected-device collections already persist a bounded,
            # redacted request inventory in summary_json. Mirror that inventory
            # into the canonical V2 index as well as the collection header so
            # pagination, selections, and the unified UI never report 0 rows
            # for a collection whose durable metadata reports requests.
            await conn.execute("""
                INSERT INTO request_collection_requests (
                    collection_id, request_id, ordinal, folder, name, method,
                    redacted_url, normalized_path, body_mode, auth_type,
                    tags_json, safe_method, supported
                )
                SELECT drc.id,
                       LEFT(COALESCE(NULLIF(item->>'id', ''),
                           'legacy-device-' || (ordinality - 1)::text), 128),
                       (ordinality - 1)::int,
                       NULLIF(LEFT(item->>'folder', 500), ''),
                       NULLIF(LEFT(item->>'name', 500), ''),
                       LEFT(UPPER(COALESCE(NULLIF(item->>'method', ''), 'GET')), 16),
                       NULLIF(LEFT(item->>'url', 4000), ''),
                       NULLIF(LEFT(SPLIT_PART(
                           REGEXP_REPLACE(
                               REGEXP_REPLACE(COALESCE(item->>'url', ''),
                                   '^[A-Za-z][A-Za-z0-9+.-]*://[^/]*', ''),
                               '^\\{\\{[^}]+\\}\\}', ''
                           ), '?', 1
                       ), 2000), ''),
                       NULLIF(LEFT(item->>'body_mode', 100), ''),
                       NULLIF(LEFT(item->>'auth_type', 200), ''),
                       '[]'::jsonb,
                       COALESCE((item->>'safe_method')::boolean, false),
                       COALESCE((item->>'supported')::boolean, true)
                FROM device_request_collections drc
                JOIN request_collections rc ON rc.id=drc.id
                CROSS JOIN LATERAL JSONB_ARRAY_ELEMENTS(
                    CASE
                        WHEN JSONB_TYPEOF(COALESCE(drc.summary_json, '{}'::jsonb)->'requests')='array'
                        THEN drc.summary_json->'requests'
                        ELSE '[]'::jsonb
                    END
                ) WITH ORDINALITY AS legacy_request(item, ordinality)
                ON CONFLICT (collection_id, request_id) DO UPDATE SET
                    ordinal=EXCLUDED.ordinal,
                    folder=EXCLUDED.folder,
                    name=EXCLUDED.name,
                    method=EXCLUDED.method,
                    redacted_url=EXCLUDED.redacted_url,
                    normalized_path=EXCLUDED.normalized_path,
                    body_mode=EXCLUDED.body_mode,
                    auth_type=EXCLUDED.auth_type,
                    tags_json=EXCLUDED.tags_json,
                    safe_method=EXCLUDED.safe_method,
                    supported=EXCLUDED.supported
            """)
            # Canonical Hunt V2 keeps server authority and audit state without owning model
            # reasoning. Legacy web/device run tables remain compatibility adapters.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_runs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_kind TEXT NOT NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,
                    objective TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'active',
                    budget_profile TEXT NOT NULL DEFAULT 'balanced',
                    policy_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    budget_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    budget_used_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    context_pack JSONB NOT NULL DEFAULT '{}'::jsonb,
                    notes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    final_debrief JSONB NOT NULL DEFAULT '{}'::jsonb,
                    approval_receipt_id UUID,
                    stop_reason TEXT,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    CONSTRAINT hunt_runs_target_kind_check CHECK (target_kind IN ('web','api','device','network')),
                    CONSTRAINT hunt_runs_status_check CHECK (status IN (
                        'created','active','awaiting_planner','completed','cancelled','failed','budget_exhausted'
                    )),
                    CONSTRAINT hunt_runs_budget_profile_check CHECK (budget_profile IN ('fast','balanced','thorough')),
                    CONSTRAINT hunt_runs_target_check CHECK (
                        (target_kind IN ('web','api','network') AND target_id IS NOT NULL AND device_target_id IS NULL) OR
                        (target_kind='device' AND device_target_id IS NOT NULL AND target_id IS NULL)
                    )
                )
            """)
            await conn.execute("""
                ALTER TABLE hunt_runs
                ALTER COLUMN policy_json
                SET DEFAULT '{"allow_oob_interactions":false}'::jsonb
            """)
            await conn.execute("""
                UPDATE hunt_runs
                SET policy_json = jsonb_set(
                    COALESCE(policy_json, '{}'::jsonb),
                    '{allow_oob_interactions}',
                    'false'::jsonb,
                    true
                )
                WHERE NOT COALESCE(policy_json, '{}'::jsonb)
                    ? 'allow_oob_interactions'
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hunt_runs_web
                ON hunt_runs(target_id, created_at DESC) WHERE target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hunt_runs_device
                ON hunt_runs(device_target_id, created_at DESC) WHERE device_target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hunt_runs_status
                ON hunt_runs(status, updated_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS hunt_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    hunt_run_id UUID NOT NULL REFERENCES hunt_runs(id) ON DELETE CASCADE,
                    capability_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    input_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    result_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
                    receipt_id UUID,
                    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    CONSTRAINT hunt_actions_status_check CHECK (
                        status IN ('reserved','running','completed','blocked','cancelled','failed','partial')
                    )
                )
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conrelid = 'hunt_actions'::regclass
                          AND conname = 'hunt_actions_status_check'
                    ) THEN
                        ALTER TABLE hunt_actions
                        ADD CONSTRAINT hunt_actions_status_check CHECK (
                            status IN ('reserved','running','completed','blocked','cancelled','failed','partial')
                        );
                    ELSIF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conrelid = 'hunt_actions'::regclass
                          AND conname = 'hunt_actions_status_check'
                          AND pg_get_constraintdef(oid) LIKE '%reserved%'
                          AND pg_get_constraintdef(oid) LIKE '%cancelled%'
                    ) THEN
                        ALTER TABLE hunt_actions
                        DROP CONSTRAINT hunt_actions_status_check;
                        ALTER TABLE hunt_actions
                        ADD CONSTRAINT hunt_actions_status_check CHECK (
                            status IN ('reserved','running','completed','blocked','cancelled','failed','partial')
                        );
                    END IF;
                END
                $$
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_hunt_actions_run
                ON hunt_actions(hunt_run_id, started_at)
            """)
            # Hunt output is a non-authoritative candidate until a registered server-side
            # verifier satisfies its proof contract. Web and device candidates share this
            # lifecycle while retaining mutually exclusive target namespaces.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_candidates (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    plane TEXT NOT NULL,
                    target_id UUID REFERENCES targets(id) ON DELETE CASCADE,
                    device_target_id UUID REFERENCES device_targets(id) ON DELETE CASCADE,
                    research_episode_id UUID REFERENCES research_episodes(id) ON DELETE SET NULL,
                    agent_hunt_run_id UUID REFERENCES agent_hunt_runs(id) ON DELETE SET NULL,
                    device_agent_run_id UUID REFERENCES device_agent_runs(id) ON DELETE SET NULL,
                    hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL,
                    family TEXT NOT NULL,
                    canonical_locus JSONB NOT NULL DEFAULT '{}'::jsonb,
                    title TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    claimed_severity TEXT NOT NULL DEFAULT 'info',
                    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    verifier_contract_id TEXT,
                    verification_context JSONB NOT NULL DEFAULT '{}'::jsonb,
                    source_kind TEXT NOT NULL DEFAULT 'hunt',
                    fingerprint TEXT NOT NULL UNIQUE,
                    status TEXT NOT NULL DEFAULT 'new',
                    latest_verification_id UUID,
                    created_by TEXT,
                    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT investigation_candidates_plane_check CHECK (plane IN ('web','device')),
                    CONSTRAINT investigation_candidates_target_check CHECK (
                        (plane='web' AND target_id IS NOT NULL AND device_target_id IS NULL) OR
                        (plane='device' AND device_target_id IS NOT NULL AND target_id IS NULL)
                    ),
                    CONSTRAINT investigation_candidates_status_check CHECK (status IN (
                        'new','verification_queued','verifying','verified','refuted',
                        'inconclusive','blocked','expired'
                    )),
                    CONSTRAINT investigation_candidates_severity_check CHECK (
                        claimed_severity IN ('critical','high','medium','low','info')
                    )
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidates_web
                ON investigation_candidates(target_id, status, last_seen_at DESC)
                WHERE target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidates_device
                ON investigation_candidates(device_target_id, status, last_seen_at DESC)
                WHERE device_target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidates_run
                ON investigation_candidates(device_agent_run_id, created_at)
                WHERE device_agent_run_id IS NOT NULL
            """)
            await conn.execute("""
                ALTER TABLE investigation_candidates
                ADD COLUMN IF NOT EXISTS verification_context JSONB NOT NULL DEFAULT '{}'::jsonb
            """)
            await conn.execute("""
                ALTER TABLE investigation_candidates
                ADD COLUMN IF NOT EXISTS agent_hunt_run_id UUID REFERENCES agent_hunt_runs(id) ON DELETE SET NULL
            """)
            await conn.execute("""
                ALTER TABLE investigation_candidates
                ADD COLUMN IF NOT EXISTS hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL
            """)
            # Every hunt observation is immutable and retains its own run provenance even when the
            # canonical family+locus candidate already exists. This prevents global dedupe from
            # erasing which run made which claim and preserves later observations of terminal rows.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS investigation_candidate_observations (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    candidate_id UUID NOT NULL REFERENCES investigation_candidates(id) ON DELETE CASCADE,
                    research_episode_id UUID REFERENCES research_episodes(id) ON DELETE SET NULL,
                    agent_hunt_run_id UUID REFERENCES agent_hunt_runs(id) ON DELETE SET NULL,
                    device_agent_run_id UUID REFERENCES device_agent_runs(id) ON DELETE SET NULL,
                    hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL,
                    source_kind TEXT NOT NULL DEFAULT 'hunt',
                    title TEXT NOT NULL,
                    claim TEXT NOT NULL,
                    claimed_severity TEXT NOT NULL DEFAULT 'info',
                    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
                    verifier_contract_id TEXT,
                    observation_context JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT investigation_candidate_observation_severity_check CHECK (
                        claimed_severity IN ('critical','high','medium','low','info')
                    )
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidate_observations_candidate
                ON investigation_candidate_observations(candidate_id, observed_at DESC)
            """)
            await conn.execute("""
                ALTER TABLE investigation_candidate_observations
                ADD COLUMN IF NOT EXISTS hunt_run_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidate_observations_web_run
                ON investigation_candidate_observations(agent_hunt_run_id, observed_at DESC)
                WHERE agent_hunt_run_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigation_candidate_observations_device_run
                ON investigation_candidate_observations(device_agent_run_id, observed_at DESC)
                WHERE device_agent_run_id IS NOT NULL
            """)
            # Before Investigation Candidates existed, Deep Hunt placed unverified model
            # claims in ``findings`` with tool=autonomous_agent. Move those provisional
            # records into the candidate ledger once and retire the old rows so findings
            # once again means a proof-promoted security result. The migration deliberately
            # excludes exploited rows: those already crossed the deterministic proof gate.
            applied = await conn.fetchval(
                "SELECT 1 FROM app_schema_migrations WHERE name = $1",
                LEGACY_AUTONOMOUS_CANDIDATE_MIGRATION,
            )
            if not applied:
                await conn.execute("""
                    INSERT INTO investigation_candidates (
                        plane, target_id, family, canonical_locus, title, claim,
                        claimed_severity, evidence_refs, verifier_contract_id,
                        verification_context, source_kind, fingerprint, status,
                        created_by, first_seen_at, last_seen_at, created_at, updated_at
                    )
                    SELECT
                        'web', f.target_id,
                        COALESCE(NULLIF(f.evidence->>'family',''), 'unknown'),
                        jsonb_strip_nulls(jsonb_build_object(
                            'method', NULLIF(upper(COALESCE(f.evidence->>'method','')), ''),
                            'route', COALESCE(NULLIF(f.evidence->>'route',''), NULLIF(f.url,'')),
                            'parameter', NULLIF(f.evidence->>'param','')
                        )),
                        f.title, COALESCE(NULLIF(f.description,''), f.title),
                        CASE WHEN f.severity IN ('critical','high','medium','low','info')
                             THEN f.severity ELSE 'info' END,
                        CASE WHEN jsonb_typeof(f.evidence->'evidence_refs')='array'
                             THEN f.evidence->'evidence_refs' ELSE '[]'::jsonb END,
                        CASE WHEN NULLIF(f.evidence->>'retest_type','') IS NOT NULL
                             THEN 'web.' || lower(f.evidence->>'retest_type') ELSE NULL END,
                        jsonb_build_object(
                            'legacy_finding_id', f.id::text,
                            'target_url', f.url,
                            'method', f.evidence->>'method',
                            'route', f.evidence->>'route',
                            'parameter', f.evidence->>'param',
                            'payload', f.evidence->>'payload',
                            'retest_type', f.evidence->>'retest_type',
                            'proof', f.evidence->'proof',
                            'remediation', f.evidence->'remediation',
                            'evidence', f.evidence
                        ),
                        'legacy_deep_hunt',
                        md5('legacy-autonomous-candidate:' || f.id::text)
                            || md5('legacy-autonomous-candidate:v2:' || f.id::text),
                        CASE
                            WHEN f.last_verification_status IN ('queued','running')
                                THEN 'inconclusive'
                            ELSE 'new'
                        END,
                        'schema_migration',
                        COALESCE(f.first_seen_at, f.created_at, NOW()),
                        COALESCE(f.last_seen_at, f.updated_at, NOW()),
                        COALESCE(f.created_at, NOW()), NOW()
                    FROM findings f
                    WHERE f.target_id IS NOT NULL
                      AND f.source='autonomous'
                      AND f.tool='autonomous_agent'
                      AND COALESCE(f.last_verification_verdict,'') <> 'exploited'
                    ON CONFLICT (fingerprint) DO NOTHING
                """)
                await conn.execute("""
                    UPDATE findings
                    SET status='resolved', resolved_at=COALESCE(resolved_at,NOW()),
                        notes=concat_ws(E'\n', NULLIF(notes,''),
                            'Migrated to Investigation Candidates; this unverified claim is not a finding.'),
                        updated_at=NOW()
                    WHERE target_id IS NOT NULL
                      AND source='autonomous'
                      AND tool='autonomous_agent'
                      AND COALESCE(last_verification_verdict,'') <> 'exploited'
                      AND status='active'
                """)
                await conn.execute(
                    "INSERT INTO app_schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING",
                    LEGACY_AUTONOMOUS_CANDIDATE_MIGRATION,
                )
            # Backfill exactly one source observation for candidates created before the observation
            # ledger (including legacy candidates inserted immediately above). New writes append an
            # observation transactionally in ``upsert_candidate``.
            await conn.execute("""
                INSERT INTO investigation_candidate_observations (
                    candidate_id, research_episode_id, agent_hunt_run_id, device_agent_run_id,
                    source_kind, title, claim, claimed_severity, evidence_refs,
                    verifier_contract_id, observation_context, created_by, observed_at
                )
                SELECT c.id, c.research_episode_id, c.agent_hunt_run_id, c.device_agent_run_id,
                       c.source_kind, c.title, c.claim, c.claimed_severity, c.evidence_refs,
                       c.verifier_contract_id, c.verification_context, c.created_by, c.first_seen_at
                FROM investigation_candidates c
                WHERE NOT EXISTS (
                    SELECT 1 FROM investigation_candidate_observations o
                    WHERE o.candidate_id=c.id
                )
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
                    'model_intake',
                    'device_posture',
                    'device_probe',
                    'device_web_dast'
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
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'findings_device_target_id_fkey'
                    ) THEN
                        ALTER TABLE findings
                        ADD CONSTRAINT findings_device_target_id_fkey
                        FOREIGN KEY (device_target_id) REFERENCES device_targets(id) ON DELETE CASCADE;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'device_services_transport_check'
                    ) THEN
                        ALTER TABLE device_services ADD CONSTRAINT device_services_transport_check
                        CHECK (transport IN ('tcp','udp')) NOT VALID;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'device_services_policy_disposition_check'
                    ) THEN
                        ALTER TABLE device_services ADD CONSTRAINT device_services_policy_disposition_check
                        CHECK (policy_disposition IS NULL OR policy_disposition IN (
                            'allow','deny','review','require','not_evaluated'
                        )) NOT VALID;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'device_agent_runs_planner_mode_check'
                    ) THEN
                        ALTER TABLE device_agent_runs ADD CONSTRAINT device_agent_runs_planner_mode_check
                        CHECK (planner_mode IN ('agent')) NOT VALID;
                    END IF;
                END $$;
            """)
            await conn.execute("""
                ALTER TABLE device_services DROP CONSTRAINT IF EXISTS device_services_state_check
            """)
            await conn.execute("""
                ALTER TABLE device_services ADD CONSTRAINT device_services_state_check
                CHECK (state IN ('open','open|filtered','not_observed')) NOT VALID
            """)
            await conn.execute("""
                ALTER TABLE device_services VALIDATE CONSTRAINT device_services_state_check
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
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_targets_active_updated
                ON device_targets(is_active, updated_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_device_target_created
                ON scans(device_target_id, created_at DESC)
                WHERE device_target_id IS NOT NULL
            """)
            await conn.execute("DROP INDEX IF EXISTS idx_scans_device_target_id")
            await conn.execute("""
                WITH ranked AS (
                    SELECT id, ROW_NUMBER() OVER (
                        PARTITION BY device_target_id ORDER BY created_at, id
                    ) AS position
                    FROM scans
                    WHERE device_target_id IS NOT NULL
                      AND run_kind IN ('device_posture','device_probe')
                      AND status IN ('pending','queued','running','cancelling')
                )
                UPDATE scans
                SET status='failed', error_message='Duplicate active device scan repaired during migration',
                    completed_at=NOW(), progress=100, current_phase='failed'
                WHERE id IN (SELECT id FROM ranked WHERE position > 1)
            """)
            await conn.execute("""
                DROP INDEX IF EXISTS idx_scans_one_active_device_posture
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_scans_one_active_device_traffic
                ON scans(device_target_id)
                WHERE device_target_id IS NOT NULL
                  AND run_kind IN ('device_posture','device_probe')
                  AND status IN ('pending','queued','running','cancelling')
            """)
            await conn.execute("DROP INDEX IF EXISTS idx_findings_device_target_id")
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_device_fingerprint
                ON findings(device_target_id, fingerprint)
                WHERE device_target_id IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_services_target_seen
                ON device_services(device_target_id, last_seen_at DESC)
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
            await conn.execute("""
                ALTER TABLE finding_verifications
                ALTER COLUMN finding_id DROP NOT NULL,
                ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES investigation_candidates(id) ON DELETE CASCADE,
                ADD COLUMN IF NOT EXISTS device_target_id UUID REFERENCES device_targets(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS research_episode_id UUID REFERENCES research_episodes(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS device_agent_run_id UUID REFERENCES device_agent_runs(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS contract_id TEXT,
                ADD COLUMN IF NOT EXISTS contract_version TEXT,
                ADD COLUMN IF NOT EXISTS proof_basis TEXT,
                ADD COLUMN IF NOT EXISTS traffic_receipt_id UUID
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname='finding_verifications_subject_check'
                    ) THEN
                        ALTER TABLE finding_verifications
                        ADD CONSTRAINT finding_verifications_subject_check
                        CHECK (finding_id IS NOT NULL OR candidate_id IS NOT NULL) NOT VALID;
                    END IF;
                END $$
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
                "CREATE INDEX IF NOT EXISTS idx_finding_verifications_requested_by ON finding_verifications(requested_by, created_at DESC) WHERE requested_by IS NOT NULL",
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
                    retention_delete_preview_id UUID,
                    retention_delete_pending_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    CONSTRAINT evidence_objects_finding_type_unique UNIQUE (finding_id, object_type)
                )
            """)
            await conn.execute("""
                ALTER TABLE evidence_objects
                ADD COLUMN IF NOT EXISTS retention_delete_preview_id UUID,
                ADD COLUMN IF NOT EXISTS retention_delete_pending_at TIMESTAMPTZ
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_objects_finding ON evidence_objects(finding_id)")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_objects_scan ON evidence_objects(scan_id)")
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_objects_retention_pending
                ON evidence_objects(retention_delete_pending_at)
                WHERE retention_delete_pending_at IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_artifacts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    parent_scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
                    shard_index INTEGER,
                    executing_node_id UUID,
                    artifact_type TEXT NOT NULL,
                    artifact_key TEXT NOT NULL,
                    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                    storage_uri TEXT NOT NULL,
                    storage_backend TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    size_bytes BIGINT NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'available'
                        CHECK (status IN ('available','deleting','upload_failed','missing','deleted')),
                    retention_class TEXT NOT NULL DEFAULT 'standard',
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    expires_at TIMESTAMPTZ,
                    deleted_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT scan_artifacts_identity_unique
                        UNIQUE (scan_id, artifact_type, artifact_key)
                )
            """)
            await conn.execute("""
                ALTER TABLE scan_artifacts
                DROP CONSTRAINT IF EXISTS scan_artifacts_status_check
            """)
            await conn.execute("""
                ALTER TABLE scan_artifacts
                ADD CONSTRAINT scan_artifacts_status_check
                CHECK (status IN ('available','deleting','upload_failed','missing','deleted'))
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_artifacts_scan ON scan_artifacts(scan_id, created_at DESC)")
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scan_artifacts_retention
                ON scan_artifacts(expires_at)
                WHERE status = 'available' AND expires_at IS NOT NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS evidence_retention_previews (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    target_id UUID NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
                    schema_version INTEGER NOT NULL,
                    criteria_json JSONB NOT NULL,
                    candidate_snapshot_json JSONB NOT NULL,
                    preview_hash TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ready',
                    approval_receipt_id UUID,
                    scope_receipt_id TEXT,
                    operation_id UUID,
                    result_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    expires_at TIMESTAMPTZ NOT NULL,
                    execution_started_at TIMESTAMPTZ,
                    consumed_at TIMESTAMPTZ,
                    CONSTRAINT evidence_retention_previews_status_check
                        CHECK (status IN ('ready','executing','consumed','stale'))
                )
            """)
            await conn.execute("""
                ALTER TABLE evidence_retention_previews
                ADD COLUMN IF NOT EXISTS scope_receipt_id TEXT,
                ADD COLUMN IF NOT EXISTS execution_started_at TIMESTAMPTZ
            """)
            await conn.execute("""
                ALTER TABLE evidence_retention_previews
                DROP CONSTRAINT IF EXISTS evidence_retention_previews_status_check
            """)
            await conn.execute("""
                ALTER TABLE evidence_retention_previews
                ADD CONSTRAINT evidence_retention_previews_status_check
                CHECK (status IN ('ready','executing','consumed','stale'))
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_retention_previews_target
                ON evidence_retention_previews(target_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_retention_previews_ready
                ON evidence_retention_previews(expires_at) WHERE status = 'ready'
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_evidence_retention_previews_approval_once
                ON evidence_retention_previews(approval_receipt_id)
                WHERE approval_receipt_id IS NOT NULL
            """)
            await conn.execute("""
                DO $retention_preview_fk$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conname = 'evidence_objects_retention_delete_preview_fk'
                          AND conrelid = 'evidence_objects'::regclass
                    ) THEN
                        -- NOT VALID installs the delete-side protection without
                        -- making an upgrade fail if an older build already left an
                        -- orphaned pending marker. PostgreSQL still enforces the FK
                        -- for every subsequent write and referenced-row delete.
                        ALTER TABLE evidence_objects
                            ADD CONSTRAINT evidence_objects_retention_delete_preview_fk
                            FOREIGN KEY (retention_delete_preview_id)
                            REFERENCES evidence_retention_previews(id)
                            ON DELETE RESTRICT
                            NOT VALID;
                    END IF;

                    -- Clean upgrades get a fully validated constraint. Dirty
                    -- installs retain the enforced NOT VALID constraint and their
                    -- legacy orphan rows for explicit operator reconciliation.
                    IF NOT EXISTS (
                        SELECT 1
                        FROM evidence_objects eo
                        LEFT JOIN evidence_retention_previews erp
                          ON erp.id = eo.retention_delete_preview_id
                        WHERE eo.retention_delete_preview_id IS NOT NULL
                          AND erp.id IS NULL
                    ) THEN
                        ALTER TABLE evidence_objects
                            VALIDATE CONSTRAINT evidence_objects_retention_delete_preview_fk;
                    END IF;
                END
                $retention_preview_fk$
            """)
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
                    scope_receipt_id TEXT REFERENCES scope_receipts(id) ON DELETE SET NULL,
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
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS capability_name TEXT")
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS adapter_name TEXT")
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS budget_json JSONB NOT NULL DEFAULT '{}'::jsonb")
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS partial BOOLEAN NOT NULL DEFAULT false")
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS output_artifact_id UUID REFERENCES evidence_objects(id) ON DELETE SET NULL")
            await conn.execute("ALTER TABLE tool_receipts ADD COLUMN IF NOT EXISTS hunt_id UUID REFERENCES hunt_runs(id) ON DELETE SET NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_tool_receipts_hunt ON tool_receipts(hunt_id, created_at DESC) WHERE hunt_id IS NOT NULL")
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
                    evidence_strength TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_by TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT evidence_instances_proof_state_check
                        CHECK (proof_state IN ('verified','suspected','unverified','refuted','inconclusive')),
                    CONSTRAINT evidence_instances_strength_check
                        CHECK (evidence_strength IS NULL OR evidence_strength IN ('claimed','signal','reproduced','cross_principal_verified')),
                    CONSTRAINT evidence_instances_retention_check
                        CHECK (retention_policy IN ('standard','short','audit','legal_hold','sensitive'))
                )
            """)
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_finding ON evidence_instances(finding_id, created_at DESC) WHERE finding_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_tool_receipt ON evidence_instances(tool_receipt_id) WHERE tool_receipt_id IS NOT NULL")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_instances_hash ON evidence_instances(hash)")
            await conn.execute("""
                ALTER TABLE evidence_instances
                ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES investigation_candidates(id) ON DELETE CASCADE,
                ADD COLUMN IF NOT EXISTS device_target_id UUID REFERENCES device_targets(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS research_episode_id UUID REFERENCES research_episodes(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS device_agent_run_id UUID REFERENCES device_agent_runs(id) ON DELETE SET NULL,
                ADD COLUMN IF NOT EXISTS contract_id TEXT,
                ADD COLUMN IF NOT EXISTS contract_version TEXT,
                ADD COLUMN IF NOT EXISTS proof_basis TEXT
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_instances_candidate
                ON evidence_instances(candidate_id, created_at DESC)
                WHERE candidate_id IS NOT NULL
            """)
            # Wave 5: evidence-strength ladder column (claimed<signal<reproduced<cross_principal_verified).
            await conn.execute("ALTER TABLE evidence_instances ADD COLUMN IF NOT EXISTS evidence_strength TEXT")
            await conn.execute("ALTER TABLE evidence_instances DROP CONSTRAINT IF EXISTS evidence_instances_strength_check")
            await conn.execute("""
                ALTER TABLE evidence_instances
                ADD CONSTRAINT evidence_instances_strength_check
                CHECK (evidence_strength IS NULL OR evidence_strength IN ('claimed','signal','reproduced','cross_principal_verified'))
            """)
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

            # Phase-1 owned-fleet identity and enrollment foundation. These
            # tables intentionally contain only hashes of join/node secrets.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL,
                    hostname TEXT,
                    role TEXT NOT NULL CHECK (role IN ('control_plane', 'worker')),
                    overlay_ip INET UNIQUE,
                    wireguard_public_key TEXT UNIQUE,
                    egress_ip INET,
                    region TEXT,
                    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
                    build_fingerprint TEXT,
                    worker_image_digest TEXT,
                    active_worker_image_digest TEXT,
                    agent_version TEXT,
                    desired_state_version INTEGER NOT NULL DEFAULT 1,
                    desired_state_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    applied_state_version INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    desired_worker_count INTEGER NOT NULL DEFAULT 0,
                    active_worker_count INTEGER NOT NULL DEFAULT 0,
                    capacity JSONB NOT NULL DEFAULT '{}'::jsonb,
                    status TEXT NOT NULL DEFAULT 'joining'
                        CHECK (status IN ('joining', 'healthy', 'stale', 'draining', 'disabled')),
                    drain BOOLEAN NOT NULL DEFAULT false,
                    rollout_in_progress BOOLEAN NOT NULL DEFAULT false,
                    last_heartbeat_at TIMESTAMPTZ,
                    connection_bundle_delivered_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE nodes
                ADD COLUMN IF NOT EXISTS wireguard_public_key TEXT,
                ADD COLUMN IF NOT EXISTS worker_image_digest TEXT,
                ADD COLUMN IF NOT EXISTS active_worker_image_digest TEXT,
                ADD COLUMN IF NOT EXISTS agent_version TEXT,
                ADD COLUMN IF NOT EXISTS desired_state_version INTEGER NOT NULL DEFAULT 1,
                ADD COLUMN IF NOT EXISTS desired_state_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ADD COLUMN IF NOT EXISTS applied_state_version INTEGER NOT NULL DEFAULT 0,
                ADD COLUMN IF NOT EXISTS last_error TEXT,
                ADD COLUMN IF NOT EXISTS rollout_in_progress BOOLEAN NOT NULL DEFAULT false,
                ADD COLUMN IF NOT EXISTS connection_bundle_delivered_at TIMESTAMPTZ
            """)
            await conn.execute("""
                ALTER TABLE scans
                ADD COLUMN IF NOT EXISTS executing_node_id UUID,
                ADD COLUMN IF NOT EXISTS execution_context JSONB NOT NULL DEFAULT '{}'::jsonb
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'scans_executing_node_fk'
                          AND conrelid = 'scans'::regclass
                    ) THEN
                        ALTER TABLE scans
                        ADD CONSTRAINT scans_executing_node_fk
                        FOREIGN KEY (executing_node_id) REFERENCES nodes(id) ON DELETE SET NULL;
                    END IF;
                END $$
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_executing_node
                ON scans(executing_node_id, created_at DESC)
                WHERE executing_node_id IS NOT NULL
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF EXISTS (
                        SELECT 1
                        FROM pg_class c
                        JOIN pg_index i ON i.indexrelid = c.oid
                        WHERE c.relname = 'idx_nodes_wireguard_public_key'
                          AND NOT i.indisunique
                    ) THEN
                        DROP INDEX idx_nodes_wireguard_public_key;
                    END IF;
                END $$
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_wireguard_public_key
                ON nodes(wireguard_public_key) WHERE wireguard_public_key IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_nodes_status_heartbeat
                ON nodes(status, last_heartbeat_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS fleet_node_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    node_id UUID REFERENCES nodes(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    actor_type TEXT NOT NULL CHECK (actor_type IN ('operator','node','system','broker')),
                    severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info','warning','error')),
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_fleet_node_events_node_created
                ON fleet_node_events(node_id, created_at DESC)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS broker_job_leases (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                    worker_id TEXT NOT NULL,
                    queue_name TEXT NOT NULL,
                    stream_key TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    consumer_name TEXT NOT NULL,
                    lease_token_hash TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    budget_reservation JSONB NOT NULL DEFAULT '{}'::jsonb,
                    job_id TEXT,
                    scan_id UUID,
                    status TEXT NOT NULL DEFAULT 'leased'
                        CHECK (status IN ('leased','submitted','ingesting','completed','failed','cancelled','lost')),
                    delivery_attempts INTEGER NOT NULL DEFAULT 1,
                    lease_expires_at TIMESTAMPTZ NOT NULL,
                    last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ingest_enqueued_at TIMESTAMPTZ,
                    completed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (stream_key, message_id)
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_broker_job_leases_node_status
                ON broker_job_leases(node_id, status, lease_expires_at)
            """)
            await conn.execute("""
                ALTER TABLE broker_job_leases
                ADD COLUMN IF NOT EXISTS budget_reservation JSONB NOT NULL DEFAULT '{}'::jsonb,
                ADD COLUMN IF NOT EXISTS ingest_enqueued_at TIMESTAMPTZ
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_broker_job_leases_active_worker
                ON broker_job_leases(node_id, worker_id) WHERE status = 'leased'
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS broker_job_results (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    lease_id UUID NOT NULL UNIQUE REFERENCES broker_job_leases(id) ON DELETE CASCADE,
                    result_sha256 TEXT NOT NULL,
                    result JSONB NOT NULL,
                    submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    ingested_at TIMESTAMPTZ
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS node_join_tokens (
                    token_hash TEXT PRIMARY KEY,
                    token_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
                    role TEXT NOT NULL CHECK (role = 'worker'),
                    transport TEXT NOT NULL CHECK (transport IN ('overlay', 'broker')),
                    expires_at TIMESTAMPTZ NOT NULL,
                    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses BETWEEN 1 AND 128),
                    use_count INTEGER NOT NULL DEFAULT 0 CHECK (use_count BETWEEN 0 AND max_uses),
                    last_used_at TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ,
                    consumed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE node_join_tokens
                    ADD COLUMN IF NOT EXISTS token_id UUID DEFAULT gen_random_uuid(),
                    ADD COLUMN IF NOT EXISTS transport TEXT,
                    ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1,
                    ADD COLUMN IF NOT EXISTS use_count INTEGER NOT NULL DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ,
                    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ
            """)
            await conn.execute("""
                UPDATE node_join_tokens
                SET token_id = COALESCE(token_id, gen_random_uuid()),
                    use_count = CASE
                        WHEN consumed_at IS NOT NULL AND use_count = 0 THEN 1
                        ELSE use_count
                    END
            """)
            await conn.execute("""
                ALTER TABLE node_join_tokens
                    ALTER COLUMN token_id SET NOT NULL
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_node_join_tokens_token_id
                ON node_join_tokens(token_id)
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'node_join_tokens_max_uses_check'
                          AND conrelid = 'node_join_tokens'::regclass
                    ) THEN
                        ALTER TABLE node_join_tokens
                        ADD CONSTRAINT node_join_tokens_max_uses_check
                        CHECK (max_uses BETWEEN 1 AND 128);
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'node_join_tokens_use_count_check'
                          AND conrelid = 'node_join_tokens'::regclass
                    ) THEN
                        ALTER TABLE node_join_tokens
                        ADD CONSTRAINT node_join_tokens_use_count_check
                        CHECK (use_count BETWEEN 0 AND max_uses);
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'node_join_tokens_transport_check'
                          AND conrelid = 'node_join_tokens'::regclass
                    ) THEN
                        ALTER TABLE node_join_tokens
                        ADD CONSTRAINT node_join_tokens_transport_check
                        CHECK (transport IS NULL OR transport IN ('overlay', 'broker'));
                    END IF;
                END
                $$
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_node_join_tokens_expires
                ON node_join_tokens(expires_at) WHERE consumed_at IS NULL
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS node_credentials (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
                    credential_hash TEXT NOT NULL UNIQUE,
                    credential_version INTEGER NOT NULL DEFAULT 1,
                    expires_at TIMESTAMPTZ,
                    revoked_at TIMESTAMPTZ,
                    last_used_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT node_credentials_node_version_unique UNIQUE (node_id, credential_version)
                )
            """)
            await conn.execute("""
                ALTER TABLE node_credentials
                ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_node_credentials_active
                ON node_credentials(node_id, credential_version DESC) WHERE revoked_at IS NULL
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_node_credentials_node_version
                ON node_credentials(node_id, credential_version)
            """)

            # Signed Model Intake admission lifecycle. Historical packages are
            # preserved while the status field controls future deployment.
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_intake_admissions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID NOT NULL UNIQUE REFERENCES scans(id) ON DELETE CASCADE,
                    target_id UUID REFERENCES targets(id) ON DELETE SET NULL,
                    artifact_sha256 TEXT NOT NULL,
                    repository_snapshot_sha256 TEXT,
                    statement_sha256 TEXT NOT NULL UNIQUE,
                    admission_package JSONB NOT NULL,
                    decision TEXT NOT NULL,
                    status TEXT NOT NULL,
                    schema_version TEXT NOT NULL DEFAULT 'model-intake-admission/v1',
                    deployment_bundle_sha256 TEXT,
                    evidence_manifest_sha256 TEXT,
                    policy_decision_sha256 TEXT,
                    target_environment TEXT,
                    idempotency_key_sha256 TEXT UNIQUE,
                    policy_profile TEXT,
                    policy_version TEXT,
                    issued_at TIMESTAMPTZ NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    reassessment_due_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ,
                    revoked_by TEXT,
                    revocation_reason TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT model_intake_admission_status_check
                        CHECK (status IN ('active','denied','reassessment_required','revoked','expired','superseded'))
                )
            """)
            await conn.execute("""
                ALTER TABLE model_intake_admissions
                    ADD COLUMN IF NOT EXISTS schema_version TEXT NOT NULL DEFAULT 'model-intake-admission/v1',
                    ADD COLUMN IF NOT EXISTS submission_id UUID,
                    ADD COLUMN IF NOT EXISTS deployment_bundle_sha256 TEXT,
                    ADD COLUMN IF NOT EXISTS evidence_manifest_sha256 TEXT,
                    ADD COLUMN IF NOT EXISTS policy_decision_sha256 TEXT,
                    ADD COLUMN IF NOT EXISTS target_environment TEXT,
                    ADD COLUMN IF NOT EXISTS idempotency_key_sha256 TEXT
            """)
            await conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_model_intake_admissions_idempotency
                ON model_intake_admissions(idempotency_key_sha256)
                WHERE idempotency_key_sha256 IS NOT NULL
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_admissions_subject
                ON model_intake_admissions(artifact_sha256, status, expires_at)
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_admissions_reassessment
                ON model_intake_admissions(status, reassessment_due_at)
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_intake_admission_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    admission_id UUID NOT NULL REFERENCES model_intake_admissions(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    trigger_type TEXT,
                    actor TEXT,
                    reason TEXT,
                    previous_status TEXT,
                    new_status TEXT,
                    evidence_digest TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_intake_admission_events_admission
                ON model_intake_admission_events(admission_id, created_at DESC)
            """)
            await conn.execute("""
                WITH quarantined AS (
                    UPDATE model_intake_admissions
                    SET status='reassessment_required', updated_at=NOW()
                    WHERE status='active' AND schema_version='model-intake-admission/v1'
                    RETURNING id, statement_sha256
                )
                INSERT INTO model_intake_admission_events
                    (admission_id,event_type,actor,reason,previous_status,new_status,evidence_digest)
                SELECT id,'legacy_schema_quarantined','schema_migration',
                       'Legacy v1 authority model requires reassessment',
                       'active','reassessment_required',statement_sha256
                FROM quarantined
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS model_intake_submissions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    requested_by TEXT NOT NULL,
                    requested_environment TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_reference_hash TEXT NOT NULL,
                    expected_artifact_sha256 TEXT,
                    intended_use JSONB NOT NULL DEFAULT '{}'::jsonb,
                    declared_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    state TEXT NOT NULL DEFAULT 'submitted',
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_submissions_state
                    ON model_intake_submissions(state, created_at DESC);
                CREATE TABLE IF NOT EXISTS model_intake_submission_events (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    previous_state TEXT NOT NULL,
                    new_state TEXT NOT NULL,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_submission_events_submission
                    ON model_intake_submission_events(submission_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS model_intake_subjects (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    subject_kind TEXT NOT NULL,
                    immutable_uri TEXT,
                    sha256 TEXT NOT NULL,
                    size_bytes BIGINT,
                    manifest_sha256 TEXT,
                    source_revision TEXT,
                    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT model_intake_subject_unique UNIQUE (submission_id, subject_kind, sha256)
                );
                CREATE TABLE IF NOT EXISTS model_intake_evidence_records (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    evidence_type TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    provenance_class TEXT NOT NULL,
                    producer_id TEXT NOT NULL,
                    producer_version TEXT NOT NULL,
                    builder_id TEXT NOT NULL,
                    invocation_id TEXT NOT NULL,
                    subject_bindings JSONB NOT NULL,
                    input_manifest_sha256 TEXT,
                    payload_sha256 TEXT NOT NULL,
                    payload_json JSONB,
                    object_storage_uri TEXT,
                    signature_envelope JSONB,
                    status TEXT NOT NULL,
                    started_at TIMESTAMPTZ,
                    finished_at TIMESTAMPTZ,
                    expires_at TIMESTAMPTZ,
                    supersedes_id UUID REFERENCES model_intake_evidence_records(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT model_intake_evidence_invocation_unique UNIQUE (producer_id, invocation_id)
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_evidence_submission
                    ON model_intake_evidence_records(submission_id, evidence_type, created_at DESC);
                ALTER TABLE model_intake_evidence_records
                    ADD COLUMN IF NOT EXISTS payload_json JSONB;
                CREATE TABLE IF NOT EXISTS model_intake_runner_jobs (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    operation TEXT NOT NULL CHECK (operation IN ('calibration','runtime','conversion')),
                    state TEXT NOT NULL CHECK (state IN ('pending','running','completed','failed')),
                    remote_job_id UUID NOT NULL UNIQUE,
                    request_sha256 TEXT NOT NULL,
                    request_json JSONB NOT NULL,
                    result_json JSONB,
                    error_json JSONB,
                    evidence_record_id UUID REFERENCES model_intake_evidence_records(id) ON DELETE SET NULL,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    started_at TIMESTAMPTZ,
                    finished_at TIMESTAMPTZ,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_runner_jobs_submission
                    ON model_intake_runner_jobs(submission_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS model_intake_automatic_reviews (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
                    submission_id UUID REFERENCES model_intake_submissions(id) ON DELETE SET NULL,
                    conversion_job_id UUID REFERENCES model_intake_runner_jobs(id) ON DELETE SET NULL,
                    calibration_job_id UUID REFERENCES model_intake_runner_jobs(id) ON DELETE SET NULL,
                    runtime_job_id UUID REFERENCES model_intake_runner_jobs(id) ON DELETE SET NULL,
                    source_kind TEXT NOT NULL,
                    source_label TEXT NOT NULL DEFAULT 'Model review',
                    source_reference_hash TEXT NOT NULL,
                    requested_environment TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'static_scan_pending',
                    current_step TEXT NOT NULL DEFAULT 'static_scan',
                    progress INTEGER NOT NULL DEFAULT 5 CHECK (progress BETWEEN 0 AND 100),
                    technical_outcome TEXT,
                    deployment_bundle_json JSONB,
                    known_answer_embedding_sha256 TEXT,
                    pending_controls JSONB NOT NULL DEFAULT '[]'::jsonb,
                    timeline_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                    error_json JSONB,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    completed_at TIMESTAMPTZ,
                    CONSTRAINT model_intake_automatic_review_scan_unique UNIQUE (scan_id)
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_automatic_reviews_state
                    ON model_intake_automatic_reviews(state, updated_at ASC);
                ALTER TABLE model_intake_automatic_reviews
                    ADD COLUMN IF NOT EXISTS conversion_job_id UUID
                    REFERENCES model_intake_runner_jobs(id) ON DELETE SET NULL;
                ALTER TABLE model_intake_automatic_reviews
                    ADD COLUMN IF NOT EXISTS source_label TEXT NOT NULL DEFAULT 'Model review';
                CREATE TABLE IF NOT EXISTS model_intake_agent_sessions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    objective TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('awaiting_planner','completed','cancelled')),
                    max_iterations INTEGER NOT NULL CHECK (max_iterations BETWEEN 1 AND 30),
                    iteration INTEGER NOT NULL DEFAULT 0,
                    action_budget INTEGER NOT NULL CHECK (action_budget BETWEEN 1 AND 100),
                    actions_used INTEGER NOT NULL DEFAULT 0,
                    transcript_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                    final_assessment_json JSONB,
                    created_by TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_agent_sessions_submission
                    ON model_intake_agent_sessions(submission_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS model_intake_agent_actions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    session_id UUID NOT NULL REFERENCES model_intake_agent_sessions(id) ON DELETE CASCADE,
                    iteration INTEGER NOT NULL,
                    action_name TEXT NOT NULL,
                    arguments_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('completed','rejected','error')),
                    result_json JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_model_intake_agent_actions_session
                    ON model_intake_agent_actions(session_id, created_at);
                CREATE TABLE IF NOT EXISTS model_intake_evidence_manifests (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    version INTEGER NOT NULL,
                    manifest_sha256 TEXT NOT NULL UNIQUE,
                    evidence_ids JSONB NOT NULL,
                    manifest_json JSONB NOT NULL,
                    deployment_bundle_json JSONB NOT NULL,
                    subject_bundle_sha256 TEXT NOT NULL,
                    frozen_at TIMESTAMPTZ NOT NULL,
                    frozen_by TEXT NOT NULL,
                    supersedes_id UUID REFERENCES model_intake_evidence_manifests(id) ON DELETE SET NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT model_intake_evidence_manifest_version_unique UNIQUE (submission_id, version)
                );
                CREATE TABLE IF NOT EXISTS model_intake_approval_receipts (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    evidence_manifest_id UUID NOT NULL REFERENCES model_intake_evidence_manifests(id) ON DELETE CASCADE,
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    receipt_json JSONB NOT NULL,
                    approval_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    approved_by_subject TEXT NOT NULL,
                    approved_by_role TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    revoked_at TIMESTAMPTZ,
                    revocation_reason TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS model_intake_policy_decisions (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    evidence_manifest_id UUID NOT NULL REFERENCES model_intake_evidence_manifests(id) ON DELETE CASCADE,
                    decision_sha256 TEXT NOT NULL UNIQUE,
                    decision_json JSONB NOT NULL,
                    decision TEXT NOT NULL,
                    policy_provider TEXT NOT NULL,
                    policy_bundle_sha256 TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS model_intake_deployment_bindings (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    submission_id UUID NOT NULL REFERENCES model_intake_submissions(id) ON DELETE CASCADE,
                    admission_id UUID REFERENCES model_intake_admissions(id) ON DELETE SET NULL,
                    deployment_bundle_sha256 TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    observed_bundle_sha256 TEXT,
                    verifier_status TEXT NOT NULL DEFAULT 'not_observed',
                    deployment_reference TEXT,
                    observed_at TIMESTAMPTZ,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )
            """)
            await conn.execute("""
                ALTER TABLE model_intake_evidence_manifests
                ADD COLUMN IF NOT EXISTS deployment_bundle_json JSONB
            """)
            await conn.execute("""
                UPDATE model_intake_submissions
                SET state='blocked',updated_at=NOW()
                WHERE state NOT IN (
                    'submitted','scanning','evidence_ready','evidence_frozen','awaiting_approval',
                    'policy_decided','admitted','promoted','blocked','cancelled'
                )
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'model_intake_submission_state_check'
                          AND conrelid = 'model_intake_submissions'::regclass
                    ) THEN
                        ALTER TABLE model_intake_submissions
                        ADD CONSTRAINT model_intake_submission_state_check CHECK (state IN (
                            'submitted','scanning','evidence_ready','evidence_frozen','awaiting_approval',
                            'policy_decided','admitted','promoted','blocked','cancelled'
                        ));
                    END IF;
                END
                $$
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'model_intake_admissions_submission_id_fkey'
                          AND conrelid = 'model_intake_admissions'::regclass
                    ) THEN
                        ALTER TABLE model_intake_admissions
                        ADD CONSTRAINT model_intake_admissions_submission_id_fkey
                        FOREIGN KEY (submission_id) REFERENCES model_intake_submissions(id) ON DELETE SET NULL;
                    END IF;
                END
                $$
            """)
            # Older fresh-install schemas created deployment bindings before
            # admissions existed and therefore omitted this FK. Preserve the
            # binding row, clear any orphan reference, and converge both fresh
            # and upgraded databases on the same ON DELETE SET NULL contract.
            await conn.execute("""
                UPDATE model_intake_deployment_bindings AS binding
                SET admission_id = NULL
                WHERE admission_id IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM model_intake_admissions AS admission
                      WHERE admission.id = binding.admission_id
                  )
            """)
            await conn.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'model_intake_deployment_bindings_admission_id_fkey'
                          AND conrelid = 'model_intake_deployment_bindings'::regclass
                    ) THEN
                        ALTER TABLE model_intake_deployment_bindings
                        ADD CONSTRAINT model_intake_deployment_bindings_admission_id_fkey
                        FOREIGN KEY (admission_id) REFERENCES model_intake_admissions(id) ON DELETE SET NULL;
                    END IF;
                END
                $$
            """)

            # Move legacy Web credential rows into the shared immutable profile store.
            # The compatibility endpoints keep both representations synchronized until
            # the old tables and callers are deleted later in the V2 migration.
            async with conn.transaction():
                await migrate_legacy_web_credentials(conn)
                await migrate_scan_execute_capabilities(conn)
                await migrate_legacy_device_credentials(conn)
                await migrate_legacy_ai_credentials(conn)

            # Canonical de-dupe prevention must be present before startup completes;
            # current ON CONFLICT insert paths rely on this unique index. Keep the
            # trigger rewrite, every child-row merge, and index replacement atomic so
            # a failed collision repair cannot leave a half-migrated database.
            async with conn.transaction():
                await _ensure_target_canonical_key_invariant(conn)
        finally:
            await conn.execute("SELECT pg_advisory_unlock(8675309)")


def build_retest_job_payload(
    *,
    job_id: str,
    verification_id: str,
    submitted_at: str,
    finding_id: str | None = None,
    candidate_id: str | None = None,
    trigger: str | None = None,
    attempt: int = 1,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": "finding_retest",
        "queue_schema_version": RETEST_QUEUE_SCHEMA_VERSION,
        "job_id": str(job_id),
        "verification_id": str(verification_id),
        "submitted_at": str(submitted_at),
        "attempt": max(1, int(attempt)),
    }
    if finding_id:
        payload["finding_id"] = str(finding_id)
    if candidate_id:
        payload["candidate_id"] = str(candidate_id)
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

    for field in ("job_id", "verification_id", "submitted_at"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            return False, f"missing_{field}"

    if not payload.get("finding_id") and not payload.get("candidate_id"):
        return False, "missing_retest_subject"
    if payload.get("finding_id") and payload.get("candidate_id"):
        return False, "ambiguous_retest_subject"
    for field in ("verification_id", "finding_id", "candidate_id"):
        if not payload.get(field):
            continue
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
