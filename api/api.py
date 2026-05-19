#!/usr/bin/env python3
"""
ShakerScan API - Open Source Edition
FastAPI server with PostgreSQL persistence and Redis queue.
"""

import asyncio
import copy
import hashlib
import json
import logging
import os
import random
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import asyncpg
import redis
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field

try:
    from constants import SMART_SCAN_BUDGETS, resolve_scan_budget
except ModuleNotFoundError as exc:
    if exc.name != "constants":
        raise
    from scanner.constants import SMART_SCAN_BUDGETS, resolve_scan_budget

from retest_contract import (
    DEFAULT_REPLAY_PAYLOADS,
    SUPPORTED_RETEST_TYPES,
    SUPPORTED_RETEST_VERDICTS,
    VerificationPolicy,
    build_replay_commands,
    build_retest_job_payload,
    extract_auth_context,
    infer_retest_inputs,
    normalize_retest_type,
    parse_json_field,
    run_schema_migrations,
    validate_retest_job_payload,
)

try:
    from ai_demo_scenarios import get_ai_test_scenarios
except ModuleNotFoundError as exc:
    if exc.name != "ai_demo_scenarios":
        raise
    from api.ai_demo_scenarios import get_ai_test_scenarios

try:
    from ai_redteam_artifacts import (
        build_ai_learning_guide,
        build_ai_redteam_report,
        build_ai_test_case_catalog,
        build_ai_test_case_export,
        render_ai_redteam_markdown,
    )
except ModuleNotFoundError as exc:
    if exc.name != "ai_redteam_artifacts":
        raise
    from api.ai_redteam_artifacts import (
        build_ai_learning_guide,
        build_ai_redteam_report,
        build_ai_test_case_catalog,
        build_ai_test_case_export,
        render_ai_redteam_markdown,
    )

try:
    from ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )
except ModuleNotFoundError as exc:
    if exc.name not in {"ai_gate", "ai_gate.targets", "ai_gate.targets.rest_json"}:
        raise
    from api.ai_gate.targets.rest_json import (
        append_query_params as ai_append_query_params,
        build_headers as ai_build_headers,
        build_url as ai_build_url,
        extract_response_text as ai_extract_response_text,
        replace_placeholders as ai_replace_placeholders,
    )

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")
HEARTBEAT_TIMEOUT_MINUTES = 5  # Mark scan stale if no heartbeat for this long
RETEST_RUNNING_TIMEOUT_MINUTES = int(os.environ.get("RETEST_RUNNING_TIMEOUT_MINUTES", "30"))
FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES = int(
    os.environ.get("FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES", "15")
)
STALE_CHECK_INTERVAL_SECONDS = 60  # How often to check for stale scans
SCHEDULE_CHECK_INTERVAL_SECONDS = 60  # How often to check for due schedules
AI_SETTINGS_KEY = os.environ.get("AI_SETTINGS_KEY", "settings:ai")
LOCAL_ENV_FILE = Path(os.environ.get("LOCAL_ENV_FILE", "/workspace/.env"))
logger = logging.getLogger(__name__)

# Maximum allowed duration per scan type (minutes) - safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 600,       # 10 hours
    'aggressive': 600,  # 10 hours
    'smart': 360,
}

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def row_to_dict(row) -> dict:
    """Convert asyncpg Record to JSON-serializable dict."""
    d = dict(row)
    for k, v in d.items():
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def get_redis():
    """Get Redis connection."""
    return redis.from_url(REDIS_URL, decode_responses=True)


def _is_truthy(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_severity(value: Any, default: str = "high") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in SEVERITY_ORDER:
        return candidate
    return default


def _normalize_non_negative_int(value: Any, default: int) -> int:
    try:
        return max(0, int(str(value)))
    except (TypeError, ValueError):
        return default


def _decode_json_value(value: Any) -> Any:
    """Decode JSON strings returned from JSON/JSONB columns when needed."""
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return value
    return value


SENSITIVE_SCAN_OPTION_KEYS = {
    "ai_api_key",
    "secret",
    "secret_value",
    "auth_cookies",
    "auth_header",
    "auth_headers_json",
    "auth_scenario_json",
    "login_password",
    "user2_cookies",
    "user2_header",
}


def _sanitize_scan_options(value: Any) -> Any:
    """Decode scan options and mask sensitive credentials before returning."""
    options = _decode_json_value(value)
    if not isinstance(options, dict):
        return options

    def mask_nested(candidate: Any) -> Any:
        if isinstance(candidate, dict):
            masked_dict = {}
            for key, item in candidate.items():
                if key in SENSITIVE_SCAN_OPTION_KEYS and item not in (None, "", [], {}):
                    masked_dict[key] = "***"
                else:
                    masked_dict[key] = mask_nested(item)
            return masked_dict
        if isinstance(candidate, list):
            return [mask_nested(item) for item in candidate]
        return candidate

    return mask_nested(options)


def _mask_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def _default_ai_settings() -> dict[str, Any]:
    shared_ai_url = os.environ.get("AI_URL", "").strip()
    shared_ai_key = os.environ.get("AI_API_KEY", "").strip()
    shared_ai_model = os.environ.get("AI_MODEL", "").strip()
    shared_ai_fallback = os.environ.get("AI_FALLBACK_MODEL", "").strip()

    return {
        "ai_url": shared_ai_url,
        "ai_api_key": shared_ai_key,
        "ai_model": shared_ai_model,
        "ai_model_fallback": shared_ai_fallback,
        "ai_mask_host": os.environ.get("AI_MASK_HOST", "example.com"),
        "ai_scan_classification_enabled": _is_truthy(
            os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED", "false"),
            default=False,
        ),
        "ai_classify_min_severity": _normalize_severity(
            os.environ.get("AI_CLASSIFY_MIN_SEVERITY", os.environ.get("AI_VERIFY_MIN_SEVERITY", "high")),
            default=_normalize_severity(os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"), default="high"),
        ),
        "ai_verify_enabled": _is_truthy(os.environ.get("AI_VERIFY_ENABLED", "false"), default=False),
        "ai_verify_min_severity": _normalize_severity(os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"), default="high"),
        "auto_retest_on_scan_complete": _is_truthy(
            os.environ.get("AUTO_RETEST_ON_SCAN_COMPLETE", "true"),
            default=True,
        ),
        "auto_retest_min_severity": _normalize_severity(
            os.environ.get("AUTO_RETEST_MIN_SEVERITY", "medium"),
            default="medium",
        ),
        "auto_retest_max_per_scan": _normalize_non_negative_int(
            os.environ.get("AUTO_RETEST_MAX_PER_SCAN", "25"),
            default=25,
        ),
        # Unified verification policy fields (canonical names)
        "verification_min_severity": _normalize_severity(
            os.environ.get("VERIFICATION_MIN_SEVERITY")
            or os.environ.get("AUTO_RETEST_MIN_SEVERITY", "medium"),
            default="medium",
        ),
        "ai_escalation_min_severity": _normalize_severity(
            os.environ.get("AI_ESCALATION_MIN_SEVERITY")
            or os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"),
            default="high",
        ),
        "proof_required_for_smart": _is_truthy(
            os.environ.get("PROOF_REQUIRED_FOR_SMART", "false"),
            default=False,
        ),
        "demo_mode_enabled": _is_truthy(
            os.environ.get("AI_DEMO_MODE_ENABLED", "false"),
            default=False,
        ),
        "demo_honey_public_url": os.environ.get("AI_DEMO_HONEY_PUBLIC_URL", "").strip(),
        "demo_honey_scanner_url": os.environ.get("AI_DEMO_HONEY_SCANNER_URL", "").strip(),
    }


def _load_effective_ai_settings() -> dict[str, Any]:
    settings = _default_ai_settings()
    try:
        r = get_redis()
        overrides = r.hgetall(AI_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "ai_url" in overrides:
        settings["ai_url"] = str(overrides.get("ai_url") or "")
    if "ai_api_key" in overrides:
        settings["ai_api_key"] = str(overrides.get("ai_api_key") or "")
    if "ai_model" in overrides:
        settings["ai_model"] = str(overrides.get("ai_model") or "")
    if "ai_model_fallback" in overrides:
        settings["ai_model_fallback"] = str(overrides.get("ai_model_fallback") or "")
    if "ai_mask_host" in overrides:
        settings["ai_mask_host"] = str(overrides.get("ai_mask_host") or "")
    if "ai_scan_classification_enabled" in overrides:
        settings["ai_scan_classification_enabled"] = _is_truthy(
            overrides.get("ai_scan_classification_enabled"),
            default=settings["ai_scan_classification_enabled"],
        )
    if "ai_classify_min_severity" in overrides:
        settings["ai_classify_min_severity"] = _normalize_severity(
            overrides.get("ai_classify_min_severity"),
            default=settings["ai_classify_min_severity"],
        )
    if "ai_verify_enabled" in overrides:
        settings["ai_verify_enabled"] = _is_truthy(overrides.get("ai_verify_enabled"), default=settings["ai_verify_enabled"])
    if "ai_verify_min_severity" in overrides:
        settings["ai_verify_min_severity"] = _normalize_severity(
            overrides.get("ai_verify_min_severity"), default=settings["ai_verify_min_severity"]
        )

    if "ai_classify_min_severity" not in overrides:
        settings["ai_classify_min_severity"] = settings["ai_verify_min_severity"]
    if "auto_retest_on_scan_complete" in overrides:
        settings["auto_retest_on_scan_complete"] = _is_truthy(
            overrides.get("auto_retest_on_scan_complete"),
            default=settings["auto_retest_on_scan_complete"],
        )
    if "auto_retest_min_severity" in overrides:
        settings["auto_retest_min_severity"] = _normalize_severity(
            overrides.get("auto_retest_min_severity"),
            default=settings["auto_retest_min_severity"],
        )
    if "auto_retest_max_per_scan" in overrides:
        settings["auto_retest_max_per_scan"] = _normalize_non_negative_int(
            overrides.get("auto_retest_max_per_scan"),
            default=int(settings["auto_retest_max_per_scan"]),
        )
    settings["ai_classify_min_severity"] = _normalize_severity(
        settings.get("ai_classify_min_severity"),
        default=settings.get("ai_verify_min_severity") or "high",
    )
    # Unified policy fields: apply overrides and keep bidirectional sync
    if "verification_min_severity" in overrides:
        settings["verification_min_severity"] = _normalize_severity(
            overrides.get("verification_min_severity"), default=settings["verification_min_severity"]
        )
        settings["auto_retest_min_severity"] = settings["verification_min_severity"]
    else:
        settings["verification_min_severity"] = settings["auto_retest_min_severity"]
    if "ai_escalation_min_severity" in overrides:
        settings["ai_escalation_min_severity"] = _normalize_severity(
            overrides.get("ai_escalation_min_severity"), default=settings["ai_escalation_min_severity"]
        )
        settings["ai_verify_min_severity"] = settings["ai_escalation_min_severity"]
    else:
        settings["ai_escalation_min_severity"] = settings["ai_verify_min_severity"]
    if "proof_required_for_smart" in overrides:
        settings["proof_required_for_smart"] = _is_truthy(
            overrides.get("proof_required_for_smart"), default=settings["proof_required_for_smart"]
        )
    if "demo_mode_enabled" in overrides:
        settings["demo_mode_enabled"] = _is_truthy(
            overrides.get("demo_mode_enabled"), default=settings["demo_mode_enabled"]
        )
    if "demo_honey_public_url" in overrides:
        settings["demo_honey_public_url"] = _coerce_demo_base_url(
            overrides.get("demo_honey_public_url"),
            default=settings["demo_honey_public_url"],
        )
    if "demo_honey_scanner_url" in overrides:
        settings["demo_honey_scanner_url"] = _coerce_demo_base_url(
            overrides.get("demo_honey_scanner_url"),
            default=settings["demo_honey_scanner_url"],
        )
    return settings


def _sanitize_ai_settings_response(settings: dict[str, Any]) -> dict[str, Any]:
    shared_key = str(settings.get("ai_api_key") or "")
    return {
        "ai_url": settings.get("ai_url") or "",
        "ai_model": settings.get("ai_model") or "",
        "ai_model_fallback": settings.get("ai_model_fallback") or "",
        "ai_mask_host": settings.get("ai_mask_host") or "",
        "ai_scan_classification_enabled": bool(settings.get("ai_scan_classification_enabled")),
        "ai_classify_min_severity": settings.get("ai_classify_min_severity") or settings.get("ai_verify_min_severity") or "high",
        "ai_api_key_configured": bool(shared_key),
        "ai_api_key_masked": _mask_secret(shared_key),
        "ai_verify_enabled": bool(settings.get("ai_verify_enabled")),
        "ai_verify_min_severity": settings.get("ai_verify_min_severity") or "high",
        "auto_retest_on_scan_complete": bool(settings.get("auto_retest_on_scan_complete")),
        "auto_retest_min_severity": settings.get("auto_retest_min_severity") or "medium",
        "auto_retest_max_per_scan": _normalize_non_negative_int(
            settings.get("auto_retest_max_per_scan"),
            default=0,
        ),
        # Unified verification policy fields
        "verification_min_severity": settings.get("verification_min_severity") or settings.get("auto_retest_min_severity") or "medium",
        "ai_escalation_min_severity": settings.get("ai_escalation_min_severity") or settings.get("ai_verify_min_severity") or "high",
        "proof_required_for_smart": bool(settings.get("proof_required_for_smart", False)),
        "demo_mode_enabled": bool(settings.get("demo_mode_enabled", False)),
        "demo_honey_public_url": settings.get("demo_honey_public_url") or "",
        "demo_honey_scanner_url": settings.get("demo_honey_scanner_url") or "",
    }


def _normalize_demo_base_url(value: Any, *, default: str = "") -> str:
    return _validate_demo_base_url(value, default=default)


def _validate_demo_base_url(value: Any, *, default: str = "") -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        raw = default.rstrip("/")
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Demo Honey URL must be an http(s) URL")
    return raw


def _coerce_demo_base_url(value: Any, *, default: str = "") -> str:
    try:
        return _validate_demo_base_url(value, default=default)
    except HTTPException:
        return ""


def _normalize_env_value(value: str) -> str:
    return value.replace("\n", "\\n")


def _persist_env_updates(env_path: Path, updates: dict[str, Optional[str]]) -> tuple[bool, str]:
    try:
        if env_path.exists():
            lines = env_path.read_text(encoding="utf-8").splitlines()
        else:
            lines = []
            if not env_path.parent.exists():
                env_path.parent.mkdir(parents=True, exist_ok=True)

        indexed: dict[str, int] = {}
        key_pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
        for idx, line in enumerate(lines):
            m = key_pattern.match(line)
            if m:
                indexed[m.group(1)] = idx

        for key, raw_value in updates.items():
            if raw_value is None:
                if key in indexed:
                    lines[indexed[key]] = f"# {key}=  # removed by settings API"
                continue
            line = f"{key}={_normalize_env_value(raw_value)}"
            if key in indexed:
                lines[indexed[key]] = line
            else:
                lines.append(line)

        env_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
        return True, f"Persisted settings to {env_path}"
    except Exception as e:
        return False, f"Failed to persist .env: {e}"


def _load_probe_ai_provider():
    import importlib

    import_errors: list[str] = []
    for module_name in ("scanner_tools.ai_classifier", "scanner.scanner_tools.ai_classifier"):
        try:
            module = importlib.import_module(module_name)
            fn = getattr(module, "probe_ai_provider", None)
            if callable(fn):
                return fn, None
        except Exception as exc:
            import_errors.append(f"{module_name}: {type(exc).__name__}")
    return None, "; ".join(import_errors) if import_errors else "probe function not found"


async def _probe_ai_provider(
    ai_url: str,
    ai_api_key: str,
    model: str,
    fallback_models: str | None = None,
) -> dict[str, Any]:
    probe_fn, probe_import_error = _load_probe_ai_provider()
    if probe_fn is None:
        return {
            "ok": False,
            "error": f"AI probe unavailable ({probe_import_error})",
            "latency_ms": None,
            "provider_meta": {},
            "response": None,
        }
    try:
        return await probe_fn(
            ai_url=ai_url,
            ai_api_key=ai_api_key,
            model=model,
            fallback_models=fallback_models,
        )
    except Exception as exc:
        return {
            "ok": False,
            "error": f"AI probe failed: {type(exc).__name__}: {str(exc)[:160]}",
            "latency_ms": None,
            "provider_meta": {},
            "response": None,
        }


def generate_finding_fingerprint(finding: dict) -> str:
    """Generate a unique fingerprint for deduplication."""
    scanner_id = finding.get('id', '')
    if scanner_id:
        return scanner_id
    key_parts = [
        finding.get('title', ''),
        finding.get('tool', ''),
        finding.get('url', ''),
        finding.get('cwe', '')
    ]
    key_string = '|'.join(str(p) for p in key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


def infer_retest_type(finding: dict[str, Any], evidence: dict[str, Any], override_type: str | None = None) -> str | None:
    normalized = normalize_retest_type(override_type)
    if normalized:
        return normalized

    evidence_type = normalize_retest_type(evidence.get("type"))
    if evidence_type:
        return evidence_type

    title = str(finding.get("title", "")).lower()
    tool = str(finding.get("tool", "")).lower()

    if "xss" in title or "cross-site scripting" in title or tool in {"dalfox", "dom_xss", "smart_xss", "custom_xss"}:
        return "xss"
    if (("sql" in title and "inject" in title) or "sqli" in title or
            tool in {"sqlmap", "smart_sqli", "custom_sqli", "oob_sqli"}):
        return "sqli"
    if "ssrf" in title or "server-side request forgery" in title:
        return "ssrf"
    if any(k in title for k in ("path traversal", "local file inclusion", "directory traversal", "lfi", "../")):
        return "path_traversal"
    if "open redirect" in title or "url redirect" in title:
        return "open_redirect"
    if "cors" in title:
        return "cors"
    if "2fa bypass" in title or "mfa bypass" in title or tool in {"2fa_bypass", "mfa_bypass"}:
        return "2fa_bypass"

    return None


def extract_retest_inputs(
    finding: dict[str, Any],
    override_type: str | None = None,
    override_target: str | None = None,
    override_original_url: str | None = None,
    override_param: str | None = None,
    override_payload: str | None = None,
    override_method: str | None = None,
    override_request_body: str | None = None,
) -> dict[str, Any]:
    evidence = parse_json_field(finding.get("evidence"))
    finding_type = infer_retest_type(finding, evidence, override_type=override_type)

    target_url = override_target or finding.get("target_url") or finding.get("url") or evidence.get("target") or ""
    original_url = override_original_url or finding.get("url") or evidence.get("url") or target_url
    param = override_param or finding.get("param") or evidence.get("param") or evidence.get("parameter") or ""
    payload = override_payload or finding.get("payload") or evidence.get("payload") or ""
    if not payload and isinstance(evidence.get("detail"), dict):
        payload = evidence.get("detail", {}).get("payload") or ""
    method = (override_method or finding.get("method") or evidence.get("method") or "GET").upper()
    request_body = override_request_body or finding.get("body") or evidence.get("body") or ""

    return {
        "finding_type": finding_type,
        "target_url": str(target_url).strip(),
        "original_url": str(original_url).strip() if original_url else None,
        "param": str(param).strip() if param else None,
        "payload": str(payload) if payload else None,
        "method": method,
        "request_body": str(request_body) if request_body else None,
    }


async def get_finding_record(conn, finding_id: str):
    """Fetch finding by UUID or fingerprint (with backward-compatible suffix lookup)."""
    finding = None

    try:
        finding_uuid = uuid.UUID(finding_id)
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url) as target_url,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.id = $1
        """, finding_uuid)
    except ValueError:
        pass

    if not finding:
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url) as target_url,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.fingerprint = $1
            ORDER BY f.last_seen_at DESC
            LIMIT 1
        """, finding_id)

    if not finding and ':' in finding_id:
        suffix = finding_id.split(':')[-1]
        finding = await conn.fetchrow("""
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url) as target_url,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.fingerprint = $1
            ORDER BY f.last_seen_at DESC
            LIMIT 1
        """, suffix)

    return finding


async def ensure_verification_schema(pool: asyncpg.Pool):
    """Ensure verification schema exists for upgraded installations."""
    await run_schema_migrations(pool)


async def save_findings_from_partial(conn, scan_id: uuid.UUID, target_id: uuid.UUID, findings: list):
    """Save findings from partial results to database with deduplication."""
    if not findings:
        return 0

    saved_count = 0
    for finding in findings:
        fingerprint = generate_finding_fingerprint(finding)
        evidence_json = json.dumps(finding.get('evidence')) if finding.get('evidence') else None
        ai_recommendations_json = json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None
        ai_classification_source = finding.get('ai_classification_source')

        # Check if this finding already exists for this target
        existing = await conn.fetchrow("""
            SELECT id, status, resurfaced_count
            FROM findings
            WHERE target_id = $1 AND fingerprint = $2
        """, target_id, fingerprint)

        if existing:
            # Update existing finding
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings SET
                        status = 'active',
                        last_seen_at = NOW(),
                        resurfaced_count = $1,
                        scan_id = $2,
                        title = $3,
                        description = $4,
                        severity = $5,
                        cvss_score = $6,
                        tool = $7,
                        cwe = $8,
                        cwe_name = $9,
                        owasp = $10,
                        url = $11,
                        evidence = $12,
                        ai_verdict = $13,
                        ai_confidence = $14,
                        ai_rationale = $15,
                        ai_recommendations = $16,
                        ai_classification_source = $17,
                        updated_at = NOW()
                    WHERE id = $18
                """,
                    existing['resurfaced_count'] + 1,
                    scan_id,
                    finding.get('title'),
                    finding.get('description'),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score'),
                    finding.get('tool'),
                    finding.get('cwe'),
                    finding.get('cwe_name'),
                    finding.get('owasp'),
                    finding.get('url'),
                    evidence_json,
                    finding.get('ai_verdict'),
                    finding.get('ai_confidence'),
                    finding.get('ai_rationale'),
                    ai_recommendations_json,
                    ai_classification_source,
                    existing['id'],
                )
            else:
                await conn.execute("""
                    UPDATE findings SET
                        last_seen_at = NOW(),
                        scan_id = $1,
                        title = $2,
                        description = $3,
                        severity = $4,
                        cvss_score = $5,
                        tool = $6,
                        cwe = $7,
                        cwe_name = $8,
                        owasp = $9,
                        url = $10,
                        evidence = $11,
                        ai_verdict = $12,
                        ai_confidence = $13,
                        ai_rationale = $14,
                        ai_recommendations = $15,
                        ai_classification_source = $16,
                        updated_at = NOW()
                    WHERE id = $17
                """,
                    scan_id,
                    finding.get('title'),
                    finding.get('description'),
                    finding.get('severity', 'info'),
                    finding.get('cvss_score'),
                    finding.get('tool'),
                    finding.get('cwe'),
                    finding.get('cwe_name'),
                    finding.get('owasp'),
                    finding.get('url'),
                    evidence_json,
                    finding.get('ai_verdict'),
                    finding.get('ai_confidence'),
                    finding.get('ai_rationale'),
                    ai_recommendations_json,
                    ai_classification_source,
                    existing['id'],
                )
            saved_count += 1
        else:
            # Insert new finding
            await conn.execute("""
                INSERT INTO findings (
                    scan_id, target_id, fingerprint, title, description,
                    severity, cvss_score, tool, cwe, cwe_name, owasp,
                    url, evidence, ai_verdict, ai_confidence, ai_rationale, ai_recommendations, ai_classification_source
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            """,
                scan_id,
                target_id,
                fingerprint,
                finding.get('title'),
                finding.get('description'),
                finding.get('severity', 'info'),
                finding.get('cvss_score'),
                finding.get('tool'),
                finding.get('cwe'),
                finding.get('cwe_name'),
                finding.get('owasp'),
                finding.get('url'),
                evidence_json,
                finding.get('ai_verdict'),
                finding.get('ai_confidence'),
                finding.get('ai_rationale'),
                ai_recommendations_json,
                ai_classification_source,
            )
            saved_count += 1

    return saved_count


async def cleanup_stale_scans(pool: asyncpg.Pool):
    """Check for and mark stale scans as failed.

    A scan is considered stale if:
    1. No heartbeat received for timeout window (adaptive near finalization), OR
    2. Running longer than MAX_SCAN_DURATION for its scan type
    """
    r = get_redis()
    now = datetime.utcnow()

    async with pool.acquire() as conn:
        # Get all running scans
        running_scans = await conn.fetch("""
            SELECT id, scan_type, started_at, target_id, current_phase, progress, options
            FROM scans
            WHERE status = 'running' AND started_at IS NOT NULL
        """)

        for scan in running_scans:
            scan_id = str(scan['id'])
            scan_type = scan['scan_type'] or 'standard'
            options = _decode_json_value(scan['options']) or {}
            started_at = scan['started_at']
            current_phase = (scan['current_phase'] or '').lower()
            progress = int(scan['progress'] or 0)

            heartbeat_timeout_minutes = HEARTBEAT_TIMEOUT_MINUTES
            if progress >= 95 or current_phase in {"validation", "attack_chains", "finalizing"}:
                heartbeat_timeout_minutes = max(
                    HEARTBEAT_TIMEOUT_MINUTES,
                    FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES,
                )

            is_stale = False
            reason = ""

            # Check 1: Heartbeat timeout
            # Look for job with this scan_id
            job_keys = r.keys("job:*")
            heartbeat_found = False

            for key in job_keys:
                job_data = r.hgetall(key)
                if job_data.get('scan_id') == scan_id or key.endswith(scan_id):
                    heartbeat_str = job_data.get('heartbeat')
                    if heartbeat_str:
                        try:
                            heartbeat_time = datetime.fromisoformat(heartbeat_str.replace('Z', '+00:00').replace('+00:00', ''))
                            heartbeat_age = (now - heartbeat_time).total_seconds() / 60
                            heartbeat_found = True

                            if heartbeat_age > heartbeat_timeout_minutes:
                                is_stale = True
                                reason = (
                                    f"No heartbeat for {heartbeat_age:.1f} minutes "
                                    f"(timeout {heartbeat_timeout_minutes} min, "
                                    f"phase={current_phase or 'unknown'}, progress={progress})"
                                )
                        except (ValueError, TypeError):
                            pass
                    break

            # If no heartbeat found at all and scan started beyond timeout, it's stale
            if not heartbeat_found:
                scan_age = (now - started_at.replace(tzinfo=None)).total_seconds() / 60
                if scan_age > heartbeat_timeout_minutes:
                    is_stale = True
                    reason = (
                        f"No heartbeat found, scan started {scan_age:.1f} minutes ago "
                        f"(timeout {heartbeat_timeout_minutes} min)"
                    )

            # Check 2: Max duration exceeded (safety net)
            if not is_stale and started_at:
                effective_budget_profile = options.get("budget_profile") if isinstance(options, dict) else None
                if isinstance(options, dict) and options.get("thorough_params") and not effective_budget_profile and not options.get("custom_budget"):
                    effective_budget_profile = "thorough"
                resolved_budget = resolve_scan_budget(
                    scan_type,
                    effective_budget_profile,
                    options.get("custom_budget") if isinstance(options, dict) else None,
                )
                max_duration = int(resolved_budget.get("max_duration_minutes") or MAX_SCAN_DURATION.get(scan_type, 120))
                scan_duration = (now - started_at.replace(tzinfo=None)).total_seconds() / 60

                if scan_duration > max_duration:
                    is_stale = True
                    reason = f"Exceeded max duration ({scan_duration:.0f} min > {max_duration} min for {scan_type} scan)"

            # Mark stale scan as failed
            if is_stale:
                print(f"[cleanup] Marking scan {scan_id[:8]} as failed: {reason}", flush=True)

                # Try to recover partial results from checkpoint file
                partial_result = None
                checkpoint_phase = None
                checkpoint_file = RESULTS_DIR / f"{scan_id}_checkpoint.json"
                try:
                    if checkpoint_file.exists():
                        with open(checkpoint_file) as f:
                            checkpoint_data = json.load(f)
                        partial_result = checkpoint_data.get("report")
                        checkpoint_phase = checkpoint_data.get("phase")
                        print(f"[cleanup] Found checkpoint at phase '{checkpoint_phase}' for scan {scan_id[:8]}", flush=True)
                        # Clean up checkpoint file
                        checkpoint_file.unlink()
                except Exception as e:
                    print(f"[cleanup] Failed to read checkpoint: {e}", flush=True)

                # Try to get last few log lines for debugging
                last_logs = None
                try:
                    r = redis.from_url(REDIS_URL)
                    log_lines = r.lrange(f"scan:{scan_id}:logs", -20, -1)
                    if log_lines:
                        last_logs = "\n".join(line.decode() if isinstance(line, bytes) else line for line in log_lines)
                except Exception:
                    pass

                error_msg = f"Scan terminated: {reason}"
                if checkpoint_phase:
                    error_msg += f"\nPartial results recovered from phase: {checkpoint_phase}"
                if last_logs:
                    error_msg += f"\n\nLast logs:\n{last_logs}"

                # Extract score/grade from partial result if available
                partial_score = None
                partial_grade = None
                partial_findings_count = 0
                if partial_result:
                    result_section = partial_result.get("result", {})
                    partial_score = result_section.get("score")
                    partial_grade = result_section.get("grade")
                    partial_findings_count = len(partial_result.get("findings", []))
                    # Mark as partial in metadata
                    if "scan_metadata" not in partial_result:
                        partial_result["scan_metadata"] = {}
                    partial_result["scan_metadata"]["partial"] = True
                    partial_result["scan_metadata"]["terminated_reason"] = reason
                    partial_result["scan_metadata"]["terminated_at_phase"] = checkpoint_phase

                await conn.execute("""
                    UPDATE scans
                    SET status = 'failed',
                        error_message = $1,
                        completed_at = $2,
                        result = $3,
                        score = $4,
                        grade = $5,
                        findings_count = $6,
                        progress = 100,
                        current_phase = 'terminated'
                    WHERE id = $7
                """, error_msg, now, json.dumps(partial_result) if partial_result else None,
                    partial_score, partial_grade, partial_findings_count, scan['id'])

                # Save partial findings to findings table so they appear in /findings
                partial_findings = partial_result.get("findings", []) if partial_result else []
                target_id = scan['target_id']
                if partial_findings and target_id:
                    saved = await save_findings_from_partial(conn, scan['id'], target_id, partial_findings)
                    print(f"[cleanup] Saved {saved} findings from partial results for scan {scan_id[:8]}", flush=True)


async def stale_scan_checker(pool: asyncpg.Pool):
    """Background task to periodically check for stale scans."""
    print("[cleanup] Stale scan checker started", flush=True)
    while True:
        try:
            await asyncio.sleep(STALE_CHECK_INTERVAL_SECONDS)
            await cleanup_stale_scans(pool)
        except asyncio.CancelledError:
            print("[cleanup] Stale scan checker stopped", flush=True)
            break
        except Exception as e:
            print(f"[cleanup] Error checking stale scans: {e}", flush=True)


def calculate_next_run(frequency: str, day_of_week: int | None, time_of_day: str, timezone: str, jitter_minutes: int = 0) -> datetime:
    """Calculate the next UTC datetime for a scheduled run.

    Args:
        frequency: 'daily' or 'weekly'
        day_of_week: 0-6 (Monday-Sunday) for weekly schedules
        time_of_day: 'HH:MM' format
        timezone: IANA timezone string (e.g. 'UTC', 'America/New_York')
        jitter_minutes: Random jitter range (±minutes) to avoid thundering herd

    Returns:
        UTC datetime for the next scheduled run
    """
    try:
        tz = ZoneInfo(timezone)
    except (KeyError, Exception):
        tz = ZoneInfo('UTC')

    now_utc = datetime.utcnow()
    now_local = now_utc.replace(tzinfo=ZoneInfo('UTC')).astimezone(tz)

    hour, minute = 2, 0
    try:
        parts = time_of_day.split(':')
        hour, minute = int(parts[0]), int(parts[1])
    except (ValueError, IndexError):
        pass

    # Start with today at the specified time
    candidate = now_local.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if frequency == 'weekly' and day_of_week is not None:
        # day_of_week: 0=Monday, 6=Sunday (Python weekday convention)
        current_weekday = now_local.weekday()
        days_ahead = day_of_week - current_weekday
        if days_ahead < 0 or (days_ahead == 0 and candidate <= now_local):
            days_ahead += 7
        candidate = candidate + timedelta(days=days_ahead)
    else:
        # Daily: if today's time has passed, schedule for tomorrow
        if candidate <= now_local:
            candidate = candidate + timedelta(days=1)

    # Apply jitter
    if jitter_minutes > 0:
        jitter = random.randint(-jitter_minutes, jitter_minutes)
        candidate = candidate + timedelta(minutes=jitter)

    # Convert to UTC
    return candidate.astimezone(ZoneInfo('UTC')).replace(tzinfo=None)


async def run_due_schedules(pool: asyncpg.Pool):
    """Check for and execute due scheduled scans."""
    r = get_redis()
    now = datetime.utcnow()

    async with pool.acquire() as conn:
        due_schedules = await conn.fetch("""
            SELECT s.*, t.url as target_url
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE s.is_active = true AND s.next_run_at <= $1
        """, now)

        for schedule in due_schedules:
            schedule_id = schedule['id']
            target_id = schedule['target_id']
            target_url = schedule['target_url']
            scan_type = schedule['scan_type'] or 'standard'

            # Check if target already has a running/pending scan
            existing = await conn.fetchval("""
                SELECT COUNT(*) FROM scans
                WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
            """, target_id)

            if existing > 0:
                print(f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: target already has active scan", flush=True)
                # Recalculate next_run_at anyway so we don't keep retrying every 60s
                next_run = calculate_next_run(
                    schedule['frequency'],
                    schedule['day_of_week'],
                    schedule['time_of_day'] or '02:00',
                    schedule['timezone'] or 'UTC',
                    schedule['jitter_minutes'] or 0
                )
                await conn.execute("""
                    UPDATE schedules SET next_run_at = $1, updated_at = NOW() WHERE id = $2
                """, next_run, schedule_id)
                continue

            # Create scan record + queue job (reuse scan submission logic)
            job_id = str(uuid.uuid4())
            scan_id = str(uuid.uuid4())

            scan_options = {}
            if schedule['scan_options']:
                if isinstance(schedule['scan_options'], str):
                    scan_options = json.loads(schedule['scan_options'])
                else:
                    scan_options = dict(schedule['scan_options'])
            scan_options['scan_type'] = scan_type

            await conn.execute("""
                INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6)
            """, uuid.UUID(scan_id), target_id, target_url, job_id,
                 json.dumps(scan_options), scan_type)

            job_data = {
                'job_id': job_id,
                'scan_id': scan_id,
                'target': target_url,
                'options': scan_options,
                'submitted_at': datetime.utcnow().isoformat(),
                'scheduled': True,
                'schedule_id': str(schedule_id)
            }
            r.rpush(QUEUE_NAME, json.dumps(job_data))
            r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': target_url})

            # Update schedule
            next_run = calculate_next_run(
                schedule['frequency'],
                schedule['day_of_week'],
                schedule['time_of_day'] or '02:00',
                schedule['timezone'] or 'UTC',
                schedule['jitter_minutes'] or 0
            )
            await conn.execute("""
                UPDATE schedules SET last_run_at = $1, next_run_at = $2, updated_at = NOW()
                WHERE id = $3
            """, now, next_run, schedule_id)

            print(f"[scheduler] Triggered scan {scan_id[:8]} for schedule {str(schedule_id)[:8]} ({target_url}, {scan_type})", flush=True)


async def schedule_runner(pool: asyncpg.Pool):
    """Background task to periodically check and run due schedules."""
    print("[scheduler] Schedule runner started", flush=True)
    while True:
        try:
            await asyncio.sleep(SCHEDULE_CHECK_INTERVAL_SECONDS)
            await run_due_schedules(pool)
        except asyncio.CancelledError:
            print("[scheduler] Schedule runner stopped", flush=True)
            break
        except Exception as e:
            print(f"[scheduler] Error running schedules: {e}", flush=True)


# Database connection pool
db_pool: Optional[asyncpg.Pool] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage database connection pool lifecycle and background tasks."""
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=2, max_size=10)
    await ensure_verification_schema(db_pool)

    # Start background tasks
    cleanup_task = asyncio.create_task(stale_scan_checker(db_pool))
    scheduler_task = asyncio.create_task(schedule_runner(db_pool))

    yield

    # Stop background tasks
    cleanup_task.cancel()
    scheduler_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    try:
        await scheduler_task
    except asyncio.CancelledError:
        pass

    await db_pool.close()


app = FastAPI(
    title="ShakerScan API",
    description="Open Source Dynamic Application Security Testing Scanner",
    version="1.0.0",
    lifespan=lifespan
)

# CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PYDANTIC MODELS
# ============================================================

class ScanOptions(BaseModel):
    # Scan type preset (mutually exclusive)
    # quick: DNS, TLS, headers (1-2 min)
    # standard: + tech detection, basic nuclei (5-10 min)
    # deep: + full nuclei, port scan, JS scanning (30-60 min)
    # full: + active XSS/SQLi, all security tests (1-2 hours)
    # aggressive: + aggressive exploit level, extended ports (2+ hours)
    scan_type: Optional[str] = None  # quick, standard, deep, full, aggressive, smart

    # Legacy fields (for backwards compatibility)
    quick: bool = False
    public: bool = False
    active: bool = False
    xss: bool = False
    sqli: bool = False
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

    # Multi-user auth for BOLA/IDOR testing
    user2_cookies: Optional[str] = None          # Second user session cookies
    user2_header: Optional[str] = None           # Second user auth header

    # Manual endpoint specification for API-only targets
    # Format: "METHOD /path params" or just "/path"
    # Examples: "POST /api/login username,password", "/api/users", "GET /api/items?id=1"
    custom_endpoints: Optional[list[str]] = None
    auth_scenario_json: Optional[str] = None  # JSON auth DSL with login flow/success condition/TOTP secret
    focus_rules_json: Optional[str] = None  # JSON array of scope focus rules
    avoid_rules_json: Optional[str] = None  # JSON array of scope avoid rules
    verified_findings_only: Optional[bool] = None

    # Smart scan tuning options
    no_early_stop: bool = False                    # Disable early stopping in smart scan
    thorough_params: bool = False                  # Test more parameters (50x10 vs 25x5)
    oob_callback_url: Optional[str] = None         # OOB callback URL for blind SQLi
    budget_profile: Optional[str] = Field(
        default=None,
        pattern="^(fast|balanced|thorough|exhaustive)$",
        description="Depth/time budget profile. Scan type controls modules; budget controls how hard to run them.",
    )
    custom_budget: Optional[dict[str, Any]] = Field(
        default=None,
        description="Advanced per-scan budget overrides such as max_urls, active_max_seconds, or browser_max_pages.",
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


class ScanRequest(BaseModel):
    target: str
    name: Optional[str] = None
    options: ScanOptions = Field(default_factory=ScanOptions)


class BatchRequest(BaseModel):
    targets: list[str]
    options: ScanOptions = Field(default_factory=ScanOptions)


class ModelIntakeScanRequest(BaseModel):
    artifact_url: str
    name: Optional[str] = None
    metadata_url: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    expected_sha256: Optional[str] = None
    signature_url: Optional[str] = None
    model_card_url: Optional[str] = None
    deployment_approved: bool = False
    require_deployment_approval: bool = True
    require_signature: bool = True
    require_hash: bool = True
    require_model_governance: bool = True
    max_download_bytes: int = Field(default=10_000_000, ge=1024, le=100_000_000)
    timeout_seconds: int = Field(default=20, ge=1, le=120)


AI_TARGET_TYPES = {"api_chat", "widget", "rag", "agent_trace", "mcp_trace"}
AI_TARGET_METHODS = {"GET", "POST", "PUT", "PATCH"}
AI_STREAMING_MODES = {"json", "sse"}
AI_AUTH_KINDS = {
    "none",
    "bearer",
    "api_key_header",
    "custom_header",
    "basic_auth",
    "cookie",
    "multi_header",
    "query_param",
}
AI_PROBE_PACKS = {
    "shaker-ai-smoke",
    "shaker-owasp-llm",
    "shaker-agent-abuse",
    "shaker-mcp-security",
    "shaker-rag-lite",
}
AI_SCAN_PROFILES = {"smoke", "trace", "standard", "deep"}
AI_ENVIRONMENTS = {"preview", "staging", "production", "development"}
AI_DEMO_DEFAULT_SCENARIOS = (
    "rag.safe.tenant_scoped_answer.v1",
    "rag.unsafe.cross_tenant_inventory.v1",
    "agent.unsafe.approval_bypass.v1",
    "mcp.unsafe.oauth_audience_wildcard.v1",
)


class AITargetCredential(BaseModel):
    auth_kind: str = "none"
    header_name: Optional[str] = None
    secret: Optional[str] = None
    metadata_json: Optional[dict[str, Any]] = None


class AITargetCreate(BaseModel):
    name: Optional[str] = None
    target_type: str = "api_chat"
    endpoint_url: str
    method: str = "POST"
    headers_template: dict[str, Any] = Field(default_factory=dict)
    request_template: dict[str, Any] = Field(default_factory=dict)
    response_path: Optional[str] = "$.answer"
    streaming_mode: str = "json"
    rate_limit_rps: Optional[int] = Field(default=None, ge=1)
    token_budget: Optional[int] = Field(default=None, ge=1)
    request_budget: Optional[int] = Field(default=None, ge=1)
    production_mode: bool = False
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    credential: AITargetCredential = Field(default_factory=AITargetCredential)


class AITargetUpdate(BaseModel):
    name: Optional[str] = None
    endpoint_url: Optional[str] = None
    method: Optional[str] = None
    headers_template: Optional[dict[str, Any]] = None
    request_template: Optional[dict[str, Any]] = None
    response_path: Optional[str] = None
    streaming_mode: Optional[str] = None
    rate_limit_rps: Optional[int] = Field(default=None, ge=1)
    token_budget: Optional[int] = Field(default=None, ge=1)
    request_budget: Optional[int] = Field(default=None, ge=1)
    production_mode: Optional[bool] = None
    metadata_json: Optional[dict[str, Any]] = None
    is_active: Optional[bool] = None
    credential: Optional[AITargetCredential] = None


class AITargetScanRequest(BaseModel):
    probe_pack: str = "shaker-ai-smoke"
    scan_profile: str = "smoke"
    environment: str = "preview"
    confirm_production: bool = False
    ai_judge_enabled: Optional[bool] = None
    semantic_judge_enabled: Optional[bool] = None


class AITargetConnectivityTestRequest(BaseModel):
    prompt: str = "ShakerScan connectivity check. Reply with a short safe response."
    timeout_seconds: int = Field(default=15, ge=1, le=60)


class AIDemoRunRequest(BaseModel):
    scenario_ids: Optional[list[str]] = None
    scan_profile: str = Field(default="smoke", pattern="^(smoke|trace|standard|deep)$")
    request_budget: int = Field(default=1, ge=1, le=10)


class TargetCreate(BaseModel):
    url: str
    name: Optional[str] = None
    scan_options: Optional[dict] = None


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    scan_options: Optional[dict] = None


class FindingUpdate(BaseModel):
    status: str  # active, resolved, false_positive, accepted_risk
    notes: Optional[str] = None
    analyst_verdict: Optional[str] = Field(
        default=None,
        pattern="^(needs_review|true_positive|false_positive|duplicate|accepted_risk|retest_needed)$",
    )


class FindingRetestRequest(BaseModel):
    finding_type: Optional[str] = None  # xss, sqli, ssrf, path_traversal, open_redirect, cors
    target: Optional[str] = None
    original_url: Optional[str] = None
    param: Optional[str] = None
    payload: Optional[str] = None
    method: Optional[str] = None
    request_body: Optional[str] = None
    requested_by: Optional[str] = "api"


class FindingsBulkRetestRequest(BaseModel):
    finding_ids: Optional[list[str]] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    root_domain: Optional[str] = None
    search: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=200)
    finding_type: Optional[str] = None
    requested_by: Optional[str] = "api"
    mode: Optional[str] = None  # "ai" or "deterministic"; None = tiered


class ManualFindingCreate(BaseModel):
    """Create a finding from manual testing or AI session."""
    target: str  # Target URL (required for manual, optional for session)
    title: str
    severity: str  # critical, high, medium, low, info
    description: Optional[str] = None
    category: Optional[str] = None  # BOLA, XSS, SQLi, etc.
    cwe: Optional[str] = None  # CWE ID (e.g., "CWE-639")
    cvss_score: Optional[float] = None
    url: Optional[str] = None  # Specific vulnerable URL/endpoint
    evidence: Optional[str] = None  # Proof of vulnerability
    request: Optional[str] = None  # HTTP request that triggered it
    response: Optional[str] = None  # HTTP response showing vuln
    remediation: Optional[str] = None  # How to fix
    notes: Optional[str] = None


class SessionFindingCreate(BaseModel):
    """Create a finding from an AI security session (target auto-populated)."""
    title: str
    severity: str  # critical, high, medium, low, info
    description: Optional[str] = None
    category: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    remediation: Optional[str] = None
    notes: Optional[str] = None


class ScheduleCreate(BaseModel):
    target_id: str
    name: Optional[str] = None
    frequency: str  # daily, weekly
    day_of_week: Optional[int] = None  # 0-6 (Monday-Sunday)
    time_of_day: str = '02:00'  # HH:MM
    timezone: str = 'UTC'
    scan_type: str = 'standard'
    scan_options: Optional[dict] = None
    jitter_minutes: int = 30


class ScheduleUpdate(BaseModel):
    name: Optional[str] = None
    frequency: Optional[str] = None
    day_of_week: Optional[int] = None
    time_of_day: Optional[str] = None
    timezone: Optional[str] = None
    scan_type: Optional[str] = None
    scan_options: Optional[dict] = None
    jitter_minutes: Optional[int] = None
    is_active: Optional[bool] = None


class AISettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: Optional[str] = None
    ai_model_fallback: Optional[str] = None
    ai_mask_host: Optional[str] = None
    ai_scan_classification_enabled: Optional[bool] = None
    ai_classify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    ai_verify_enabled: Optional[bool] = None
    ai_verify_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    auto_retest_on_scan_complete: Optional[bool] = None
    auto_retest_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    auto_retest_max_per_scan: Optional[int] = Field(default=None, ge=0, le=500)
    # Unified verification policy fields
    verification_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    ai_escalation_min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    proof_required_for_smart: Optional[bool] = None
    demo_mode_enabled: Optional[bool] = None
    demo_honey_public_url: Optional[str] = None
    demo_honey_scanner_url: Optional[str] = None
    persist_to_env: bool = False


class AISettingsProbeRequest(BaseModel):
    scope: str = Field(default="scan", pattern="^(scan|verify)$")
    ai_url: Optional[str] = None
    ai_api_key: Optional[str] = None
    ai_model: Optional[str] = None
    ai_fallback_model: Optional[str] = None


def _normalize_ai_endpoint_url(raw: str) -> str:
    candidate = str(raw or "").strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="endpoint_url is required")
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="endpoint_url must use http or https")
    return urllib.parse.urlunparse(parsed)


def _normalize_ai_target_type(value: str | None) -> str:
    candidate = str(value or "api_chat").strip()
    if candidate not in AI_TARGET_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"target_type must be one of: {', '.join(sorted(AI_TARGET_TYPES))}",
        )
    return candidate


def _normalize_ai_method(value: str | None) -> str:
    candidate = str(value or "POST").strip().upper()
    if candidate not in AI_TARGET_METHODS:
        raise HTTPException(status_code=400, detail="method must be GET, POST, PUT, or PATCH")
    return candidate


def _normalize_ai_streaming_mode(value: str | None) -> str:
    candidate = str(value or "json").strip().lower()
    if candidate not in AI_STREAMING_MODES:
        raise HTTPException(status_code=400, detail="streaming_mode must be json or sse")
    return candidate


def _normalize_ai_headers_template(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    headers: dict[str, str] = {}
    for key, header_value in value.items():
        if isinstance(key, str) and key.strip() and isinstance(header_value, str) and header_value.strip():
            headers[key.strip()] = header_value
    return headers


def _contains_prompt_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return "{{prompt}}" in value
    if isinstance(value, list):
        return any(_contains_prompt_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(_contains_prompt_placeholder(item) for item in value.values())
    return False


def _normalize_ai_request_template(value: Any, *, method: str, target_type: str) -> dict[str, Any]:
    if value is None:
        value = {}
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="request_template must be a JSON object")
    if target_type != "widget" and method != "GET" and not _contains_prompt_placeholder(value):
        raise HTTPException(
            status_code=400,
            detail="request_template must contain a {{prompt}} placeholder for non-GET AI targets",
        )
    return value


def _mask_ai_target_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    trimmed = secret.strip()
    if not trimmed:
        return None
    if len(trimmed) <= 8:
        return f"{trimmed[:2]}****"
    return f"{trimmed[:4]}...{trimmed[-2:]}"


def _parse_multi_header_lines(raw: str | None) -> list[dict[str, str]]:
    if not raw:
        return []
    pairs: list[dict[str, str]] = []
    for line in raw.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip() and value.strip():
            pairs.append({"name": name.strip(), "value": value.strip()})
    return pairs


def _normalize_multi_header_pairs(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    pairs: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        header_value = str(item.get("value") or "").strip()
        if name and header_value:
            pairs.append({"name": name, "value": header_value})
    return pairs


def _build_ai_credential_db_record(
    credential: AITargetCredential,
    existing: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    auth_kind = str(credential.auth_kind or "none").strip()
    if auth_kind not in AI_AUTH_KINDS:
        raise HTTPException(
            status_code=400,
            detail=f"auth_kind must be one of: {', '.join(sorted(AI_AUTH_KINDS))}",
        )

    metadata = credential.metadata_json if isinstance(credential.metadata_json, dict) else {}
    header_name = str(credential.header_name or "").strip() or None
    secret = str(credential.secret or "").strip()
    existing_secret = (
        str(existing.get("secret_value") or "")
        if existing and existing.get("auth_kind") == auth_kind
        else ""
    )

    if auth_kind == "none":
        return {
            "auth_kind": "none",
            "header_name": None,
            "secret_value": None,
            "secret_preview": None,
            "metadata_json": {},
        }

    if auth_kind == "bearer":
        header_name = "Authorization"
    elif auth_kind == "api_key_header":
        header_name = header_name or "X-API-Key"
    elif auth_kind == "basic_auth":
        header_name = "Authorization"
    elif auth_kind == "cookie":
        header_name = "Cookie"
    elif auth_kind == "custom_header" and not header_name:
        raise HTTPException(status_code=400, detail="header_name is required for custom_header auth")
    elif auth_kind == "query_param":
        header_name = header_name or str(metadata.get("param_name") or "").strip() or None
        if not header_name:
            raise HTTPException(status_code=400, detail="Parameter name is required for query_param auth")
        metadata = {**metadata, "param_name": header_name}

    if auth_kind == "multi_header":
        pairs = _normalize_multi_header_pairs(metadata.get("headers")) or _parse_multi_header_lines(secret)
        if not pairs and existing_secret:
            secret_value = existing_secret
            try:
                pairs = _normalize_multi_header_pairs(json.loads(existing_secret))
            except json.JSONDecodeError:
                pairs = []
        elif pairs:
            secret_value = json.dumps(pairs)
        else:
            raise HTTPException(status_code=400, detail="At least one header pair is required")
        return {
            "auth_kind": auth_kind,
            "header_name": None,
            "secret_value": secret_value,
            "secret_preview": f"{len(pairs)} header{'s' if len(pairs) != 1 else ''}",
            "metadata_json": {"headers": [{"name": pair["name"], "value": "***"} for pair in pairs]},
        }

    if not secret and existing_secret:
        secret = existing_secret
    if not secret:
        raise HTTPException(status_code=400, detail=f"secret is required for {auth_kind} auth")

    return {
        "auth_kind": auth_kind,
        "header_name": header_name,
        "secret_value": secret,
        "secret_preview": _mask_ai_target_secret(secret),
        "metadata_json": metadata,
    }


def _sanitize_ai_credential(row: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not row:
        return {
            "auth_kind": "none",
            "header_name": None,
            "secret_configured": False,
            "secret_preview": None,
            "metadata_json": {},
        }
    return {
        "auth_kind": row.get("auth_kind") or "none",
        "header_name": row.get("header_name"),
        "secret_configured": bool(row.get("secret_value")),
        "secret_preview": row.get("secret_preview"),
        "metadata_json": _decode_json_value(row.get("credential_metadata_json") or row.get("metadata_json") or {}),
    }


def _ai_target_response(target_row: Any, credential_row: Optional[Any] = None) -> dict[str, Any]:
    target = row_to_dict(target_row)
    for key in ("headers_template", "request_template", "metadata_json"):
        target[key] = _decode_json_value(target.get(key)) or {}
    credential = dict(credential_row) if credential_row else None
    target["credential"] = _sanitize_ai_credential(credential)
    return target


def _ai_target_run_kind(target_type: str) -> str:
    if target_type == "widget":
        return "ai_widget"
    if target_type == "rag":
        return "ai_rag"
    if target_type == "agent_trace":
        return "ai_trace"
    if target_type == "mcp_trace":
        return "ai_mcp"
    return "ai_api"


def _ai_demo_target_sql_predicate() -> str:
    return """(
        COALESCE(metadata_json->>'shakerscan_demo', '') = 'true'
        OR (metadata_json ? 'calibration_run' AND COALESCE(metadata_json->>'calibration_run', '') <> '')
        OR metadata_json ? 'honey_scenario_id'
        OR metadata_json ? 'safe_fixture'
        OR metadata_json ? 'expected_shakerscan_findings'
    )"""


def _is_ai_demo_target_row(row: dict[str, Any]) -> bool:
    metadata = _decode_json_value(row.get("metadata_json")) or {}
    demo_flag = metadata.get("shakerscan_demo")
    return (
        demo_flag is True
        or str(demo_flag).strip().lower() == "true"
        or bool(metadata.get("calibration_run"))
        or "honey_scenario_id" in metadata
        or "safe_fixture" in metadata
        or "expected_shakerscan_findings" in metadata
    )


def _demo_target_url(url: str, scanner_base_url: str, run_id: str, scenario_id: str) -> str:
    parsed = urllib.parse.urlparse(str(url or ""))
    if not parsed.path:
        raise HTTPException(status_code=400, detail=f"Honey scenario {scenario_id} has no target path")
    base = urllib.parse.urlparse(_normalize_demo_base_url(scanner_base_url))
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query["calibration_run"] = run_id
    query["calibration_scenario"] = scenario_id
    return urllib.parse.urlunparse((base.scheme, base.netloc, parsed.path, "", urllib.parse.urlencode(query), ""))


def _demo_request_template_with_prompt(template: Any, surface: str) -> dict[str, Any]:
    updated = copy.deepcopy(template) if isinstance(template, dict) else {}
    if surface in {"rag", "agent"}:
        updated["message"] = "{{prompt}}"
        updated.setdefault("session_id", "{{session_id}}")
    elif surface == "mcp":
        params = updated.setdefault("params", {})
        if not isinstance(params, dict):
            params = {}
            updated["params"] = params
        params["prompt"] = "{{prompt}}"
        updated.setdefault("id", "{{session_id}}")
    else:
        updated["message"] = "{{prompt}}"
    return updated


def _fetch_json_url(url: str, *, timeout: int = 15) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        logger.warning("Honey registry fetch failed with HTTP %s for %s", exc.code, url)
        raise HTTPException(status_code=502, detail=f"Honey registry returned HTTP {exc.code}: {body[:200]}") from exc
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError, UnicodeDecodeError) as exc:
        logger.warning("Honey registry fetch failed for %s", url, exc_info=True)
        raise HTTPException(status_code=502, detail=f"Unable to read Honey registry: {exc}") from exc


async def _fetch_honey_ai_gate_registry(base_url: str) -> dict[str, Any]:
    url = f"{_normalize_demo_base_url(base_url)}/api/ai-gate/scenarios"
    return await asyncio.to_thread(_fetch_json_url, url)


async def _queue_ai_target_scan(target_id: str, request: AITargetScanRequest) -> dict[str, Any]:
    if request.probe_pack not in AI_PROBE_PACKS:
        raise HTTPException(status_code=400, detail=f"probe_pack must be one of: {', '.join(sorted(AI_PROBE_PACKS))}")
    if request.scan_profile not in AI_SCAN_PROFILES:
        raise HTTPException(status_code=400, detail=f"scan_profile must be one of: {', '.join(sorted(AI_SCAN_PROFILES))}")
    if request.environment not in AI_ENVIRONMENTS:
        raise HTTPException(status_code=400, detail=f"environment must be one of: {', '.join(sorted(AI_ENVIRONMENTS))}")

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    async with db_pool.acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        if not target_row["is_active"]:
            raise HTTPException(status_code=409, detail="AI target is inactive")
        if target_row["production_mode"] and not request.confirm_production:
            raise HTTPException(
                status_code=409,
                detail="This AI target is marked production. Re-submit with confirm_production=true.",
            )
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

        target = row_to_dict(target_row)
        for key in ("headers_template", "request_template", "metadata_json"):
            target[key] = _decode_json_value(target.get(key)) or {}
        credential = _runtime_credential_from_row(dict(credential_row) if credential_row else None)
        worker_options, storage_options = _build_ai_worker_options(
            target=target,
            credential=credential,
            request=request,
        )
        run_kind = storage_options["run_kind"]

        await conn.execute("""
            INSERT INTO scans (
                id, target_id, ai_target_id, target_url, job_id, status,
                options, scan_type, run_kind, subject_ref
            ) VALUES ($1, NULL, $2, $3, $4, 'pending', $5, 'ai_gate', $6, $7)
        """,
            uuid.UUID(scan_id),
            uuid.UUID(target_id),
            target["endpoint_url"],
            job_id,
            json.dumps(storage_options),
            run_kind,
            f"ai_target:{target_id}",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": target["endpoint_url"],
        "options": worker_options,
        "submitted_at": datetime.utcnow().isoformat(),
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target["endpoint_url"], "scan_id": scan_id})

    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": target["endpoint_url"],
        "run_kind": run_kind,
        "ai_target_id": target_id,
        "probe_pack": request.probe_pack,
        "scan_profile": request.scan_profile,
        "ui_url": f"/scans/{scan_id}",
    }


def _graph_node(
    node_id: str,
    node_type: str,
    label: str,
    *,
    subtitle: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    href: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": node_id,
        "type": node_type,
        "label": label,
        "subtitle": subtitle,
        "severity": severity,
        "status": status,
        "href": href,
        "meta": meta or {},
    }


def _graph_edge(
    source: str,
    target: str,
    edge_type: str,
    *,
    label: str | None = None,
    severity: str | None = None,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "target": target,
        "type": edge_type,
        "label": label or edge_type.replace("_", " "),
        "severity": severity,
        "meta": meta or {},
    }


def _severity_sort_value(value: Any) -> int:
    return SEVERITY_ORDER.get(str(value or "").lower(), 0)


def _highest_severity(values: list[str | None]) -> str | None:
    severities = [v for v in values if v in SEVERITY_ORDER]
    if not severities:
        return None
    return max(severities, key=_severity_sort_value)


def _parse_graph_json(value: Any) -> dict[str, Any]:
    decoded = _decode_json_value(value)
    return decoded if isinstance(decoded, dict) else {}


def _short_url_label(value: str | None) -> str:
    if not value:
        return "unknown"
    try:
        parsed = urllib.parse.urlparse(value if "://" in value else f"https://{value}")
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        label = f"{host}{path}" if path and path != "/" else host
        return label[:90] if label else value[:90]
    except Exception:
        return str(value)[:90]


def _graph_hash(*values: Any) -> str:
    raw = "|".join(str(value or "") for value in values)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:14]


def _graph_list(value: Any) -> list[Any]:
    decoded = _decode_json_value(value)
    if isinstance(decoded, list):
        return decoded
    if isinstance(decoded, tuple):
        return list(decoded)
    return []


def _graph_get(container: dict[str, Any], *path: str) -> Any:
    cursor: Any = container
    for key in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(key)
    return cursor


def _normalize_graph_endpoint_url(base_url: str | None, value: str | None) -> str | None:
    if not value:
        return None
    value_s = str(value)
    if value_s.startswith(("http://", "https://")):
        return value_s
    if base_url:
        try:
            return urllib.parse.urljoin(base_url if str(base_url).endswith("/") else f"{base_url}/", value_s.lstrip("/"))
        except Exception:
            return value_s
    return value_s


def _endpoint_path_key(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urllib.parse.urlparse(value if "://" in value else f"https://placeholder.local{value if str(value).startswith('/') else '/' + str(value)}")
        return (parsed.path or "/").rstrip("/") or "/"
    except Exception:
        return str(value).split("?", 1)[0].rstrip("/") or "/"


def _iter_graph_openapi_endpoints(result: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [
        _graph_get(result, "discovery", "api_security", "openapi", "endpoints"),
        _graph_get(result, "discovery", "openapi", "endpoints"),
        _graph_get(result, "api_security", "openapi", "endpoints"),
        _graph_get(result, "openapi", "endpoints"),
    ]
    for candidate in candidates:
        endpoints = _graph_list(candidate)
        if endpoints:
            normalized = []
            for item in endpoints:
                if isinstance(item, dict):
                    method = str(item.get("method") or "GET").upper()
                    path = item.get("path") or item.get("url")
                    if path:
                        normalized.append({**item, "method": method, "path": path})
                elif isinstance(item, str):
                    match = re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+?)\s*$", item, re.I)
                    if match:
                        normalized.append({"method": match.group(1).upper(), "path": match.group(2)})
                    else:
                        normalized.append({"method": "GET", "path": item})
            return normalized
    return []


def _openapi_meta(result: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        _graph_get(result, "discovery", "api_security", "openapi"),
        _graph_get(result, "discovery", "openapi"),
        _graph_get(result, "api_security", "openapi"),
        _graph_get(result, "openapi"),
    ]
    for candidate in candidates:
        meta = _parse_graph_json(candidate)
        if meta:
            return meta
    return {}


def _iter_browser_api_endpoints(result: dict[str, Any]) -> list[dict[str, Any]]:
    endpoints = _graph_list(_graph_get(result, "discovery", "browser_api_endpoints"))
    normalized = []
    for item in endpoints:
        if isinstance(item, dict):
            url = item.get("url") or item.get("endpoint")
            if url:
                normalized.append({
                    "url": url,
                    "method": str(item.get("method") or "GET").upper(),
                    "source": "browser",
                    **item,
                })
        elif isinstance(item, str):
            normalized.append({"url": item, "method": "GET", "source": "browser"})
    return normalized


def _iter_graph_cloud_hints(result: dict[str, Any]) -> list[dict[str, Any]]:
    cloud = _parse_graph_json(_graph_get(result, "discovery", "cloud_services") or result.get("cloud_services"))
    hints: list[dict[str, Any]] = []
    for key in ("providers", "detected_providers", "services", "hints"):
        for item in _graph_list(cloud.get(key)):
            if isinstance(item, dict):
                label = item.get("provider") or item.get("service") or item.get("name") or item.get("type")
                if label:
                    hints.append({**item, "label": str(label)})
            elif item:
                hints.append({"label": str(item), "source": key})
    for key in ("aws", "azure", "gcp", "cloudflare"):
        if cloud.get(key):
            hints.append({"label": key, "evidence": cloud.get(key)})
    return hints[:20]


def _iter_graph_auth_roles(result: dict[str, Any], ai_target: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    roles: list[dict[str, Any]] = []
    auth_states = _graph_list(_graph_get(result, "smart_coverage", "auth_states_tested"))
    for item in auth_states:
        if item:
            roles.append({"label": str(item), "source": "smart_coverage"})
    for key in ("roles_tested", "auth_roles", "scopes_tested"):
        for item in _graph_list(_graph_get(result, "auth", key) or _graph_get(result, "identity", key)):
            if isinstance(item, dict):
                label = item.get("role") or item.get("scope") or item.get("name")
                if label:
                    roles.append({**item, "label": str(label), "source": key})
            elif item:
                roles.append({"label": str(item), "source": key})
    metadata = _parse_graph_json((ai_target or {}).get("metadata_json"))
    for item in _graph_list(metadata.get("oauth_scopes") or metadata.get("default_scopes")):
        if item:
            roles.append({"label": str(item), "source": "ai_target_oauth_scope"})
    deduped: dict[str, dict[str, Any]] = {}
    for role in roles:
        deduped.setdefault(str(role.get("label")), role)
    return list(deduped.values())[:25]


def _iter_graph_mcp_tools(result: dict[str, Any]) -> list[dict[str, Any]]:
    tools: list[dict[str, Any]] = []
    ai_gate = _parse_graph_json(result.get("ai_gate"))
    transcripts = _graph_list(ai_gate.get("transcripts"))
    for transcript in transcripts:
        evidence = _parse_graph_json(transcript.get("widget_evidence")) or _parse_graph_json(transcript.get("evidence"))
        for item in _graph_list(evidence.get("tool_inventory") or evidence.get("tools") or evidence.get("mcp_tools")):
            if isinstance(item, dict):
                name = item.get("name") or item.get("tool") or item.get("id")
                if name:
                    tools.append({**item, "label": str(name)})
            elif item:
                tools.append({"label": str(item)})
    for finding in _graph_list(ai_gate.get("findings")):
        if not isinstance(finding, dict):
            continue
        ev = _parse_graph_json(finding.get("evidence"))
        for marker in _graph_list(ev.get("matched_markers")):
            if "mcp" in str(marker).lower() or "tool" in str(marker).lower():
                tools.append({
                    "label": str(marker).replace("_", " "),
                    "source_finding_id": finding.get("id"),
                    "severity": finding.get("severity"),
                })
    deduped: dict[str, dict[str, Any]] = {}
    for tool in tools:
        deduped.setdefault(str(tool.get("label")), tool)
    return list(deduped.values())[:30]


def _build_exposure_graph(
    *,
    targets: list[dict[str, Any]],
    ai_targets: list[dict[str, Any]],
    scans: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a UI-friendly exposure graph from existing ShakerScan records."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    domain_severities: dict[str, list[str | None]] = {}

    def add_node(node: dict[str, Any]) -> None:
        existing = nodes.get(node["id"])
        if not existing:
            nodes[node["id"]] = node
            return
        existing_severity = existing.get("severity")
        next_severity = node.get("severity")
        if _severity_sort_value(next_severity) > _severity_sort_value(existing_severity):
            existing["severity"] = next_severity
        existing["meta"] = {**existing.get("meta", {}), **node.get("meta", {})}

    def add_domain(root_domain: str | None) -> str | None:
        if not root_domain:
            return None
        node_id = f"domain:{root_domain}"
        add_node(_graph_node(
            node_id,
            "domain",
            root_domain,
            subtitle="Root domain",
            href=f"/targets?search={urllib.parse.quote(root_domain)}",
        ))
        domain_severities.setdefault(root_domain, [])
        return node_id

    target_node_by_id: dict[str, str] = {}
    ai_node_by_id: dict[str, str] = {}
    ai_target_by_id: dict[str, dict[str, Any]] = {}
    scan_subject_by_id: dict[str, str] = {}
    endpoint_node_by_path: dict[tuple[str | None, str | None], list[str]] = {}

    for target in targets:
        target_id = str(target.get("id"))
        node_id = f"target:{target_id}"
        target_node_by_id[target_id] = node_id
        root_domain = target.get("root_domain") or extract_root_domain(target.get("url") or "")
        active_findings = int(target.get("active_findings_count") or target.get("active_findings") or 0)
        is_model_artifact = target.get("discovery_source") == "model-intake"
        add_node(_graph_node(
            node_id,
            "model_artifact" if is_model_artifact else "web_target",
            _short_url_label(target.get("url")),
            subtitle=target.get("name") or ("Model artifact" if is_model_artifact else root_domain),
            status="active" if target.get("is_active", True) else "inactive",
            href=f"/targets?search={urllib.parse.quote(str(target.get('url') or ''))}",
            meta={
                "url": target.get("url"),
                "root_domain": root_domain,
                "last_score": target.get("last_score"),
                "last_grade": target.get("last_grade"),
                "active_findings_count": active_findings,
                "total_scans": target.get("total_scans") or 0,
                "discovery_source": target.get("discovery_source"),
            },
        ))
        domain_id = add_domain(root_domain)
        if domain_id:
            edges.append(_graph_edge(domain_id, node_id, "contains", label="contains target"))

    for ai_target in ai_targets:
        ai_id = str(ai_target.get("id"))
        node_id = f"ai_target:{ai_id}"
        ai_node_by_id[ai_id] = node_id
        ai_target_by_id[ai_id] = ai_target
        root_domain = extract_root_domain(ai_target.get("endpoint_url") or "")
        add_node(_graph_node(
            node_id,
            "ai_target",
            ai_target.get("name") or _short_url_label(ai_target.get("endpoint_url")),
            subtitle=f"{ai_target.get('target_type') or 'ai'} surface",
            status="production" if ai_target.get("production_mode") else "non-production",
            href="/settings/ai-gate",
            meta={
                "endpoint_url": ai_target.get("endpoint_url"),
                "root_domain": root_domain,
                "target_type": ai_target.get("target_type"),
                "method": ai_target.get("method"),
                "production_mode": bool(ai_target.get("production_mode")),
                "last_scanned_at": ai_target.get("last_scanned_at"),
            },
        ))
        domain_id = add_domain(root_domain)
        if domain_id:
            edges.append(_graph_edge(domain_id, node_id, "exposes_ai_surface", label="AI surface"))

    for scan in scans:
        scan_id = str(scan.get("id"))
        if not scan_id:
            continue
        subject_id = None
        if scan.get("ai_target_id"):
            subject_id = ai_node_by_id.get(str(scan.get("ai_target_id")))
        if not subject_id and scan.get("target_id"):
            subject_id = target_node_by_id.get(str(scan.get("target_id")))
        if not subject_id:
            continue
        scan_node_id = f"scan:{scan_id}"
        scan_subject_by_id[scan_id] = subject_id
        add_node(_graph_node(
            scan_node_id,
            "scan",
            f"{scan.get('scan_type') or scan.get('run_kind') or 'scan'} scan",
            subtitle=_short_url_label(scan.get("target_url")),
            status=scan.get("status"),
            href=f"/scans/{scan_id}",
            meta={
                "scan_type": scan.get("scan_type"),
                "run_kind": scan.get("run_kind"),
                "score": scan.get("score"),
                "grade": scan.get("grade"),
                "findings_count": scan.get("findings_count") or 0,
                "created_at": scan.get("created_at"),
                "completed_at": scan.get("completed_at"),
            },
        ))
        edges.append(_graph_edge(subject_id, scan_node_id, "scanned_by", label="scanned by"))

        result = _parse_graph_json(scan.get("result"))
        subject_root_domain = scan.get("root_domain") or extract_root_domain(scan.get("target_url") or scan.get("ai_endpoint_url") or "")

        openapi_endpoints = _iter_graph_openapi_endpoints(result)
        openapi_meta = _openapi_meta(result)
        if openapi_endpoints:
            api_node_id = f"api:{scan_id}:openapi:{_graph_hash(openapi_meta.get('url'), scan.get('target_url'))}"
            add_node(_graph_node(
                api_node_id,
                "api_surface",
                openapi_meta.get("title") or "OpenAPI schema",
                subtitle=f"{len(openapi_endpoints)} operations",
                href=f"/scans/{scan_id}",
                meta={
                    "source": "openapi",
                    "url": openapi_meta.get("url"),
                    "version": openapi_meta.get("version"),
                    "endpoint_count": openapi_meta.get("endpoint_count") or len(openapi_endpoints),
                },
            ))
            edges.append(_graph_edge(subject_id, api_node_id, "exposes_api", label="exposes API"))
            edges.append(_graph_edge(scan_node_id, api_node_id, "observed_api", label="observed API"))

            for endpoint in openapi_endpoints[:120]:
                method = str(endpoint.get("method") or "GET").upper()
                path = str(endpoint.get("path") or endpoint.get("url") or "/")
                endpoint_url = _normalize_graph_endpoint_url(scan.get("target_url"), endpoint.get("url") or path)
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _endpoint_path_key(endpoint_url) or path)}"
                endpoint_node_by_path.setdefault((subject_root_domain, _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
                add_node(_graph_node(
                    endpoint_node_id,
                    "endpoint",
                    f"{method} {_endpoint_path_key(endpoint_url) or path}",
                    subtitle="OpenAPI operation",
                    href=f"/scans/{scan_id}",
                    meta={
                        "method": method,
                        "path": _endpoint_path_key(endpoint_url) or path,
                        "url": endpoint_url,
                        "source": "openapi",
                        "operation_id": endpoint.get("operation_id"),
                        "query_params": endpoint.get("query_params") or endpoint.get("params") or [],
                        "body_params": endpoint.get("body_params") or [],
                    },
                ))
                edges.append(_graph_edge(api_node_id, endpoint_node_id, "defines_endpoint", label="defines endpoint"))
                edges.append(_graph_edge(subject_id, endpoint_node_id, "exposes_endpoint", label="exposes endpoint"))

        browser_api_endpoints = _iter_browser_api_endpoints(result)
        if browser_api_endpoints:
            browser_api_node_id = f"api:{scan_id}:browser"
            add_node(_graph_node(
                browser_api_node_id,
                "api_surface",
                "Browser-observed API",
                subtitle=f"{len(browser_api_endpoints)} captured calls",
                href=f"/scans/{scan_id}",
                meta={"source": "browser_network", "endpoint_count": len(browser_api_endpoints)},
            ))
            edges.append(_graph_edge(subject_id, browser_api_node_id, "observed_api", label="browser observed API"))
            for endpoint in browser_api_endpoints[:80]:
                endpoint_url = _normalize_graph_endpoint_url(scan.get("target_url"), endpoint.get("url"))
                if not endpoint_url:
                    continue
                method = str(endpoint.get("method") or "GET").upper()
                endpoint_node_id = f"endpoint:{_graph_hash(subject_id, method, _endpoint_path_key(endpoint_url))}"
                endpoint_node_by_path.setdefault((subject_root_domain, _endpoint_path_key(endpoint_url)), []).append(endpoint_node_id)
                add_node(_graph_node(
                    endpoint_node_id,
                    "endpoint",
                    f"{method} {_endpoint_path_key(endpoint_url) or _short_url_label(endpoint_url)}",
                    subtitle="Browser-captured API call",
                    href=f"/scans/{scan_id}",
                    meta={"method": method, "url": endpoint_url, "path": _endpoint_path_key(endpoint_url), "source": "browser_network"},
                ))
                edges.append(_graph_edge(browser_api_node_id, endpoint_node_id, "observed_endpoint", label="observed endpoint"))

        for role in _iter_graph_auth_roles(result, ai_target_by_id.get(str(scan.get("ai_target_id"))) if scan.get("ai_target_id") else None):
            label = str(role.get("label") or "unknown")
            role_node_id = f"auth_role:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                role_node_id,
                "auth_role",
                label,
                subtitle=role.get("source") or "authorization context",
                href=f"/scans/{scan_id}",
                meta=role,
            ))
            edges.append(_graph_edge(subject_id, role_node_id, "tests_auth_role", label="tests auth role"))

        for hint in _iter_graph_cloud_hints(result):
            label = str(hint.get("label") or "cloud")
            cloud_node_id = f"cloud_hint:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                cloud_node_id,
                "cloud_hint",
                label,
                subtitle="Cloud exposure hint",
                href=f"/scans/{scan_id}",
                meta=hint,
            ))
            edges.append(_graph_edge(subject_id, cloud_node_id, "has_cloud_hint", label="cloud hint"))

        for tool in _iter_graph_mcp_tools(result):
            label = str(tool.get("label") or "MCP tool")
            tool_node_id = f"mcp_tool:{_graph_hash(subject_id, label)}"
            add_node(_graph_node(
                tool_node_id,
                "mcp_tool",
                label,
                subtitle="MCP/tool surface",
                severity=tool.get("severity"),
                href=f"/scans/{scan_id}",
                meta=tool,
            ))
            edges.append(_graph_edge(subject_id, tool_node_id, "exposes_mcp_tool", label="exposes MCP tool", severity=tool.get("severity")))

        model_intake = _parse_graph_json(result.get("model_intake"))
        model_summary = _parse_graph_json(model_intake.get("summary"))
        if model_summary:
            add_node(_graph_node(
                subject_id,
                "model_artifact",
                model_summary.get("artifact_name") or _short_url_label(model_summary.get("artifact_ref") or scan.get("target_url")),
                subtitle=model_summary.get("format_posture") or "Model artifact",
                status="approved" if model_summary.get("deployment_approved") else "needs approval",
                href=f"/scans/{scan_id}",
                meta={
                    "artifact_ref": model_summary.get("artifact_ref"),
                    "source_kind": model_summary.get("source_kind"),
                    "extension": model_summary.get("extension"),
                    "sha256": model_summary.get("sha256"),
                    "format_posture": model_summary.get("format_posture"),
                    "provenance_present": model_summary.get("provenance_present"),
                    "signature_present": model_summary.get("signature_present"),
                    "expected_hash_present": model_summary.get("expected_hash_present"),
                    "deployment_approved": model_summary.get("deployment_approved"),
                },
            ))
            edges.append(_graph_edge(scan_node_id, subject_id, "inspected_model_artifact", label="inspected model artifact"))

        vendor_risk = _parse_graph_json(result.get("vendor_risk"))
        for domain in (vendor_risk.get("third_party_domains") or [])[:20]:
            if not domain:
                continue
            vendor_node_id = f"vendor:{domain}"
            add_node(_graph_node(
                vendor_node_id,
                "vendor",
                str(domain),
                subtitle="Third-party resource",
                status=vendor_risk.get("risk_level"),
                meta={
                    "risk_score": vendor_risk.get("risk_score"),
                    "risk_level": vendor_risk.get("risk_level"),
                },
            ))
            edges.append(_graph_edge(subject_id, vendor_node_id, "loads_third_party", label="loads third party"))

        for resource in _graph_list(vendor_risk.get("resources"))[:30]:
            if not isinstance(resource, dict) or resource.get("type") != "script":
                continue
            script_url = resource.get("url")
            if not script_url:
                continue
            script_node_id = f"third_party_js:{_graph_hash(script_url)}"
            vendor_node_id = f"vendor:{resource.get('domain') or extract_root_domain(script_url)}"
            add_node(_graph_node(
                script_node_id,
                "third_party_js",
                _short_url_label(script_url),
                subtitle=resource.get("provider") or "Third-party script",
                status=resource.get("trust_level"),
                href=f"/scans/{scan_id}",
                meta={
                    "url": script_url,
                    "domain": resource.get("domain"),
                    "provider": resource.get("provider"),
                    "category": resource.get("category"),
                    "security_score": resource.get("security_score"),
                    "risk_factors": resource.get("risk_factors") or [],
                    "sri_present": resource.get("sri_present"),
                },
            ))
            if vendor_node_id in nodes:
                edges.append(_graph_edge(vendor_node_id, script_node_id, "serves_script", label="serves script"))
            edges.append(_graph_edge(subject_id, script_node_id, "loads_script", label="loads script"))

        attack_chains = _parse_graph_json(result.get("attack_chains"))
        for idx, chain in enumerate((attack_chains.get("chains") or [])[:10]):
            if not isinstance(chain, dict):
                continue
            chain_type = chain.get("chain_type") or chain.get("name") or idx
            chain_node_id = f"chain:{scan_id}:{chain_type}:{idx}"
            severity = str(chain.get("severity") or "").lower() or None
            add_node(_graph_node(
                chain_node_id,
                "attack_chain",
                chain.get("name") or str(chain_type),
                subtitle="Correlated exploit path",
                severity=severity,
                href=f"/scans/{scan_id}",
                meta={
                    "chain_type": chain.get("chain_type"),
                    "confidence": chain.get("confidence"),
                    "completeness": chain.get("completeness"),
                    "business_impact": chain.get("business_impact"),
                },
            ))
            edges.append(_graph_edge(scan_node_id, chain_node_id, "produced_chain", label="produced chain", severity=severity))

    for finding in findings:
        finding_id = str(finding.get("id"))
        if not finding_id:
            continue
        severity = str(finding.get("severity") or "info").lower()
        finding_node_id = f"finding:{finding_id}"
        href = f"/findings/{finding_id}"
        add_node(_graph_node(
            finding_node_id,
            "finding",
            finding.get("title") or "Finding",
            subtitle=finding.get("tool") or finding.get("source") or "finding",
            severity=severity,
            status=finding.get("status"),
            href=href,
            meta={
                "severity": severity,
                "status": finding.get("status"),
                "tool": finding.get("tool"),
                "source": finding.get("source"),
                "cvss_score": finding.get("cvss_score"),
                "last_seen_at": finding.get("last_seen_at"),
                "last_verification_verdict": finding.get("last_verification_verdict"),
                "url": finding.get("url"),
            },
        ))

        subject_id = None
        root_domain = finding.get("root_domain")
        if finding.get("ai_target_id"):
            subject_id = ai_node_by_id.get(str(finding.get("ai_target_id")))
            root_domain = root_domain or extract_root_domain(finding.get("ai_target_url") or finding.get("target_url") or "")
        if not subject_id and finding.get("target_id"):
            subject_id = target_node_by_id.get(str(finding.get("target_id")))
        if not subject_id and finding.get("scan_id"):
            subject_id = scan_subject_by_id.get(str(finding.get("scan_id")))
        if subject_id:
            edges.append(_graph_edge(subject_id, finding_node_id, "has_finding", label="has finding", severity=severity))
        finding_path = _endpoint_path_key(finding.get("url"))
        for endpoint_node_id in endpoint_node_by_path.get((root_domain, finding_path), [])[:5]:
            edges.append(_graph_edge(endpoint_node_id, finding_node_id, "affected_by", label="affected by", severity=severity))
        if finding.get("scan_id"):
            scan_node_id = f"scan:{finding.get('scan_id')}"
            if scan_node_id in nodes:
                edges.append(_graph_edge(scan_node_id, finding_node_id, "reported_finding", label="reported finding", severity=severity))
        if root_domain:
            domain_severities.setdefault(str(root_domain), []).append(severity)

    for root_domain, severities in domain_severities.items():
        node_id = f"domain:{root_domain}"
        if node_id in nodes:
            nodes[node_id]["severity"] = _highest_severity(severities)
            nodes[node_id]["meta"]["active_findings_count"] = len([s for s in severities if s])

    node_list = list(nodes.values())
    node_type_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for node in node_list:
        node_type_counts[node["type"]] = node_type_counts.get(node["type"], 0) + 1
        if node.get("type") == "finding" and node.get("severity"):
            severity = str(node["severity"])
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    hotspot_types = {"domain", "web_target", "ai_target", "model_artifact", "attack_chain"}
    hotspots = sorted(
        [node for node in node_list if node["type"] in hotspot_types and node.get("severity")],
        key=lambda item: (_severity_sort_value(item.get("severity")), int(item.get("meta", {}).get("active_findings_count") or 0)),
        reverse=True,
    )[:10]

    return {
        "nodes": node_list,
        "edges": edges,
        "summary": {
            "node_count": len(node_list),
            "edge_count": len(edges),
            "node_type_counts": node_type_counts,
            "severity_counts": severity_counts,
            "hotspots": hotspots,
        },
    }


def _runtime_credential_from_row(row: Optional[dict[str, Any]]) -> dict[str, Any]:
    if not row or row.get("auth_kind") == "none":
        return {"auth_kind": "none", "header_name": None, "secret": None, "metadata_json": {}}

    auth_kind = row.get("auth_kind")
    metadata = _decode_json_value(row.get("metadata_json")) or {}
    secret = row.get("secret_value")
    if auth_kind == "multi_header":
        try:
            headers = json.loads(secret or "[]")
        except json.JSONDecodeError:
            headers = []
        metadata = {**metadata, "headers": headers}
        secret = None
    elif auth_kind == "query_param":
        metadata = {**metadata, "param_name": row.get("header_name") or metadata.get("param_name")}

    return {
        "auth_kind": auth_kind,
        "header_name": row.get("header_name"),
        "secret": secret,
        "metadata_json": metadata,
    }


def _build_ai_worker_options(
    *,
    target: dict[str, Any],
    credential: dict[str, Any],
    request: AITargetScanRequest,
) -> tuple[dict[str, Any], dict[str, Any]]:
    probe_pack = request.probe_pack if request.probe_pack in AI_PROBE_PACKS else "shaker-ai-smoke"
    scan_profile = request.scan_profile if request.scan_profile in AI_SCAN_PROFILES else "smoke"
    environment = request.environment if request.environment in AI_ENVIRONMENTS else "preview"
    run_kind = _ai_target_run_kind(target["target_type"])
    metadata_json = dict(target.get("metadata_json") or {})
    metadata_json["scan_profile"] = scan_profile
    if request.ai_judge_enabled is not None:
        metadata_json["ai_judge_enabled"] = request.ai_judge_enabled
    if request.semantic_judge_enabled is not None:
        metadata_json["semantic_judge_enabled"] = request.semantic_judge_enabled

    storage_options = {
        "run_kind": run_kind,
        "ai_enabled": True,
        "ai_target_id": target["id"],
        "ai_target_type": target["target_type"],
        "ai_target_name": target["name"],
        "ai_probe_pack": probe_pack,
        "ai_scan_profile": scan_profile,
        "ai_environment": environment,
        "ai_response_path": target.get("response_path"),
        "ai_streaming_mode": target.get("streaming_mode"),
        "ai_request_budget": target.get("request_budget"),
        "ai_token_budget": target.get("token_budget"),
    }
    worker_options = {
        **storage_options,
        "ai_target": {
            "id": target["id"],
            "name": target["name"],
            "target_type": target["target_type"],
            "endpoint_url": target["endpoint_url"],
            "method": target["method"],
            "headers_template": target.get("headers_template") or {},
            "request_template": target.get("request_template") or {},
            "response_path": target.get("response_path"),
            "streaming_mode": target.get("streaming_mode") or "json",
            "rate_limit_rps": target.get("rate_limit_rps"),
            "token_budget": target.get("token_budget"),
            "request_budget": target.get("request_budget"),
            "production_mode": target.get("production_mode"),
            "metadata_json": metadata_json,
            "credential": credential,
        },
    }
    ai_settings = _load_effective_ai_settings()
    if ai_settings.get("ai_url") and ai_settings.get("ai_api_key"):
        worker_options["ai_url"] = ai_settings.get("ai_url")
        worker_options["ai_api_key"] = ai_settings.get("ai_api_key")
        worker_options["ai_model"] = ai_settings.get("ai_model") or "gpt-4o-mini"
    return worker_options, storage_options


def _mask_ai_headers_for_preview(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in headers.items():
        normalized = key.lower()
        if normalized in {"authorization", "cookie", "x-api-key"} or "token" in normalized or "secret" in normalized:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def _run_ai_target_connectivity_probe(target: dict[str, Any], *, prompt: str, timeout_seconds: int) -> dict[str, Any]:
    method = str(target.get("method") or "POST").upper()
    if target.get("target_type") == "widget":
        return {
            "ok": False,
            "supported": False,
            "stage": "configuration",
            "error": "Widget connectivity requires a browser session and is validated during widget scans.",
        }

    replacements = {
        "prompt": prompt,
        "probe_id": "connectivity.preflight",
        "session_id": f"connectivity-{uuid.uuid4().hex[:12]}",
    }
    headers = ai_build_headers(target)
    headers.setdefault("User-Agent", "ShakerScan AI Gate connectivity check")
    endpoint_url = ai_build_url(str(target.get("endpoint_url") or ""), target)
    body = ai_replace_placeholders(target.get("request_template") or {}, replacements)
    request_url = ai_append_query_params(endpoint_url, body) if method == "GET" else endpoint_url
    data = None
    if method != "GET":
        data = json.dumps(body).encode("utf-8")
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(request_url, data=data, headers=headers, method=method)
    started = datetime.utcnow()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - user-configured local scanner target
            raw_bytes = response.read(100_000)
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            content_type = response.headers.get("Content-Type", "")
            response_text = ai_extract_response_text(raw_text, content_type, target.get("response_path"))
            status_code = int(response.status)
    except urllib.error.HTTPError as exc:
        raw_bytes = exc.read(100_000)
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
        response_text = ai_extract_response_text(raw_text, content_type, target.get("response_path"))
        status_code = int(exc.code)
    except Exception as exc:  # noqa: BLE001 - surface precise connectivity errors to the operator
        elapsed_ms = round((datetime.utcnow() - started).total_seconds() * 1000, 1)
        return {
            "ok": False,
            "supported": True,
            "stage": "request",
            "error": str(exc),
            "request": {
                "method": method,
                "url": request_url,
                "headers": _mask_ai_headers_for_preview(headers),
                "body": body if method != "GET" else None,
            },
            "latency_ms": elapsed_ms,
        }

    elapsed_ms = round((datetime.utcnow() - started).total_seconds() * 1000, 1)
    response_path_ok = bool(str(response_text or "").strip())
    ok = 200 <= status_code < 400 and response_path_ok
    return {
        "ok": ok,
        "supported": True,
        "stage": "response_path" if not response_path_ok else "complete",
        "status_code": status_code,
        "latency_ms": elapsed_ms,
        "content_type": content_type,
        "response_path": target.get("response_path"),
        "response_path_ok": response_path_ok,
        "request": {
            "method": method,
            "url": request_url,
            "headers": _mask_ai_headers_for_preview(headers),
            "body": body if method != "GET" else None,
        },
        "response": {
            "excerpt": raw_text[:2000],
            "extracted_text": str(response_text or "")[:2000],
        },
    }


# ============================================================
# HEALTH & INFO
# ============================================================

@app.get("/")
async def root():
    """API info."""
    return {
        "name": "ShakerScan API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "scans": "/scans",
            "targets": "/targets",
            "ai_targets": "/ai/targets",
            "ai_test_scenarios": "/ai/test-scenarios",
            "ai_learning_guide": "/ai/learning-guide",
            "ai_test_cases": "/ai/test-cases",
            "model_intake": "/model-intake/scan",
            "findings": "/findings",
            "discovery": "/discovery",
            "exposure_graph": "/exposure/graph",
            "dashboard": "/dashboard",
            "queue": "/queue/stats"
        }
    }


@app.get("/ai/test-scenarios")
async def list_ai_test_scenarios(include_demo: bool = Query(False)):
    """Return scenario templates for AI Gate and model-intake workflows."""
    settings = _load_effective_ai_settings()
    return get_ai_test_scenarios(include_demo=bool(include_demo and settings.get("demo_mode_enabled")))


@app.get("/ai/learning-guide")
async def get_ai_learning_guide():
    """Return a ShakerScan-oriented AI red-team learning and capstone map."""
    return build_ai_learning_guide()


@app.get("/ai/test-cases")
async def list_ai_test_cases(pack: Optional[str] = Query(None)):
    """Return AI Gate probe/test-case metadata for eval planning and review."""
    try:
        return build_ai_test_case_catalog(pack=pack)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/ai/test-cases/export")
async def export_ai_test_cases(
    format: str = Query("json", pattern="^(json|promptfoo|pyrit|garak)$"),
    pack: Optional[str] = Query(None),
):
    """Export AI Gate probes into common red-team/eval seed formats."""
    try:
        payload, media_type, extension = build_ai_test_case_export(format, pack=pack)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    filename = f"shakerscan-ai-test-cases.{extension}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    if isinstance(payload, (dict, list)):
        return Response(
            content=json.dumps(payload, indent=2),
            media_type=media_type,
            headers=headers,
        )
    return Response(content=payload, media_type=media_type, headers=headers)


@app.post("/ai/demo/run")
async def run_ai_honey_demo(request: AIDemoRunRequest):
    """Queue a small Honey AI Gate demo suite when demo mode is enabled."""
    settings = _load_effective_ai_settings()
    if not settings.get("demo_mode_enabled"):
        raise HTTPException(status_code=403, detail="AI demo mode is disabled in settings")

    scenario_ids = request.scenario_ids or list(AI_DEMO_DEFAULT_SCENARIOS)
    scenario_ids = [str(item).strip() for item in scenario_ids if str(item).strip()]
    if not scenario_ids:
        raise HTTPException(status_code=400, detail="At least one demo scenario is required")
    if len(scenario_ids) > 10:
        raise HTTPException(status_code=400, detail="Demo run is limited to 10 scenarios")

    scanner_base_url = str(settings.get("demo_honey_scanner_url") or "").strip()
    if not scanner_base_url:
        raise HTTPException(status_code=400, detail="Configure a Honey scanner URL before running the demo")

    public_base_url = str(settings.get("demo_honey_public_url") or scanner_base_url).strip()
    registry = await _fetch_honey_ai_gate_registry(scanner_base_url)
    scenarios = {
        str(scenario.get("id")): scenario
        for scenario in registry.get("scenarios", [])
        if isinstance(scenario, dict) and scenario.get("id")
    }
    missing = [scenario_id for scenario_id in scenario_ids if scenario_id not in scenarios]
    if missing:
        raise HTTPException(status_code=400, detail=f"Honey registry does not include scenarios: {', '.join(missing)}")

    surface_config = {
        "rag": ("rag", "$.answer", "shaker-rag-lite"),
        "agent": ("agent_trace", "$", "shaker-agent-abuse"),
        "mcp": ("mcp_trace", "$.result", "shaker-mcp-security"),
    }
    run_id = f"demo-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    queued: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []

    async with db_pool.acquire() as conn:
        for scenario_id in scenario_ids:
            target_id: Any = None
            scenario = scenarios[scenario_id]
            try:
                surface = str(scenario.get("surface") or "rag")
                target_type, response_path, probe_pack = surface_config.get(surface, surface_config["rag"])
                metadata = copy.deepcopy(scenario.get("metadata_json") or {})
                expected = scenario.get("expected_shakerscan_findings") or []
                metadata.update({
                    "shakerscan_demo": True,
                    "demo_run_id": run_id,
                    "calibration_run": run_id,
                    "honey_scenario_id": scenario_id,
                    "expected_shakerscan_findings": expected,
                    "safe_fixture": scenario.get("safe_fixture") is True,
                })
                endpoint_url = _demo_target_url(
                    str(scenario.get("target_url") or ""),
                    scanner_base_url,
                    run_id,
                    scenario_id,
                )
                request_template = _normalize_ai_request_template(
                    _demo_request_template_with_prompt(scenario.get("target_template"), surface),
                    method=str(scenario.get("method") or "POST"),
                    target_type=target_type,
                )

                async with conn.transaction():
                    target_id = await conn.fetchval("""
                        INSERT INTO ai_targets (
                            name, target_type, endpoint_url, method, headers_template,
                            request_template, response_path, streaming_mode, rate_limit_rps,
                            token_budget, request_budget, production_mode, metadata_json, is_active
                        ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'json', 10, 4000, $8, false, $9, true)
                        RETURNING id
                    """,
                        f"Honey demo {scenario_id}",
                        target_type,
                        endpoint_url,
                        _normalize_ai_method(str(scenario.get("method") or "POST")),
                        json.dumps({"Content-Type": "application/json", "Accept": "application/json"}),
                        json.dumps(request_template),
                        response_path,
                        request.request_budget,
                        json.dumps(metadata),
                    )
                    await conn.execute("""
                        INSERT INTO ai_target_credentials (
                            ai_target_id, auth_kind, header_name, secret_value,
                            secret_preview, metadata_json, rotated_at
                        ) VALUES ($1, 'none', NULL, NULL, NULL, '{}'::jsonb, NOW())
                    """,
                        target_id,
                    )

                scan = await _queue_ai_target_scan(
                    str(target_id),
                    AITargetScanRequest(
                        probe_pack=probe_pack,
                        scan_profile=request.scan_profile,
                        environment="development",
                        ai_judge_enabled=False,
                        semantic_judge_enabled=False,
                    ),
                )
                queued.append({
                    "scenario_id": scenario_id,
                    "name": scenario.get("name") or scenario_id,
                    "surface": surface,
                    "safe_fixture": scenario.get("safe_fixture") is True,
                    "expected_findings": expected,
                    "target_id": str(target_id),
                    "scan_id": scan["scan_id"],
                    "ui_url": scan["ui_url"],
                    "probe_pack": probe_pack,
                    "scan_profile": request.scan_profile,
                })
            except Exception as exc:
                logger.warning("Honey demo scenario %s failed to queue", scenario_id, exc_info=True)
                if target_id:
                    reason = f"Honey demo queue failed: {type(exc).__name__}: {exc}"
                    await conn.execute(
                        "UPDATE ai_targets SET is_active = false, updated_at = NOW() WHERE id = $1",
                        target_id,
                    )
                    await conn.execute(
                        """
                        UPDATE scans
                        SET status = 'failed',
                            error_message = $2,
                            completed_at = COALESCE(completed_at, NOW()),
                            updated_at = NOW()
                        WHERE ai_target_id = $1 AND status = 'pending'
                        """,
                        target_id,
                        reason[:1000],
                    )
                failed.append({
                    "scenario_id": scenario_id,
                    "name": scenario.get("name") or scenario_id,
                    "target_id": str(target_id) if target_id else None,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    return {
        "run_id": run_id,
        "honey_registry_url": f"{public_base_url}/api/ai-gate/scenarios",
        "queued": queued,
        "failed": failed,
    }


@app.get("/health")
async def health():
    """Health check."""
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    try:
        r = get_redis()
        r.ping()
        redis_ok = True
    except Exception:
        redis_ok = False

    return {
        "status": "healthy" if db_ok and redis_ok else "degraded",
        "database": "ok" if db_ok else "error",
        "redis": "ok" if redis_ok else "error"
    }


@app.get("/settings/ai")
async def get_ai_settings():
    """Get effective AI settings (secrets masked)."""
    settings = _load_effective_ai_settings()
    return _sanitize_ai_settings_response(settings)


@app.put("/settings/ai")
async def update_ai_settings(request: AISettingsUpdate):
    """Update runtime AI settings, optionally persisting to local .env."""
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    string_fields = (
        "ai_url",
        "ai_api_key",
        "ai_model",
        "ai_model_fallback",
        "ai_mask_host",
    )

    updates: dict[str, str] = {}
    deletes: list[str] = []
    clear_demo_honey_public_url = False
    clear_demo_honey_scanner_url = False

    for field in string_fields:
        value = getattr(request, field)
        if value is None:
            continue
        normalized = str(value).strip()
        if normalized == "":
            deletes.append(field)
        else:
            updates[field] = normalized

    # Always remove legacy per-verify provider keys from runtime settings.
    deletes.extend([
        "ai_verify_url",
        "ai_verify_api_key",
        "ai_verify_model",
        "ai_verify_model_fallback",
    ])

    if request.ai_verify_enabled is not None:
        updates["ai_verify_enabled"] = "true" if request.ai_verify_enabled else "false"

    if request.ai_verify_min_severity is not None:
        updates["ai_verify_min_severity"] = _normalize_severity(request.ai_verify_min_severity, default="high")

    if request.ai_scan_classification_enabled is not None:
        updates["ai_scan_classification_enabled"] = "true" if request.ai_scan_classification_enabled else "false"

    if request.ai_classify_min_severity is not None:
        updates["ai_classify_min_severity"] = _normalize_severity(
            request.ai_classify_min_severity,
            default=_normalize_severity(request.ai_verify_min_severity, default="high")
            if request.ai_verify_min_severity is not None
            else "high",
        )

    if request.auto_retest_on_scan_complete is not None:
        updates["auto_retest_on_scan_complete"] = "true" if request.auto_retest_on_scan_complete else "false"

    if request.auto_retest_min_severity is not None:
        updates["auto_retest_min_severity"] = _normalize_severity(request.auto_retest_min_severity, default="medium")

    if request.auto_retest_max_per_scan is not None:
        updates["auto_retest_max_per_scan"] = str(max(0, int(request.auto_retest_max_per_scan)))

    # Unified verification policy fields (bidirectional sync with legacy names)
    if request.verification_min_severity is not None:
        updates["verification_min_severity"] = _normalize_severity(request.verification_min_severity, default="medium")
        updates["auto_retest_min_severity"] = updates["verification_min_severity"]
    if request.ai_escalation_min_severity is not None:
        updates["ai_escalation_min_severity"] = _normalize_severity(request.ai_escalation_min_severity, default="high")
        updates["ai_verify_min_severity"] = updates["ai_escalation_min_severity"]
    if request.proof_required_for_smart is not None:
        updates["proof_required_for_smart"] = "true" if request.proof_required_for_smart else "false"
    if request.demo_mode_enabled is not None:
        updates["demo_mode_enabled"] = "true" if request.demo_mode_enabled else "false"
    if request.demo_honey_public_url is not None:
        normalized = _validate_demo_base_url(request.demo_honey_public_url)
        if normalized:
            updates["demo_honey_public_url"] = normalized
        else:
            clear_demo_honey_public_url = True
            deletes.append("demo_honey_public_url")
    if request.demo_honey_scanner_url is not None:
        normalized = _validate_demo_base_url(request.demo_honey_scanner_url)
        if normalized:
            updates["demo_honey_scanner_url"] = normalized
        else:
            clear_demo_honey_scanner_url = True
            deletes.append("demo_honey_scanner_url")

    if updates:
        r.hset(AI_SETTINGS_KEY, mapping=updates)
    if deletes:
        r.hdel(AI_SETTINGS_KEY, *deletes)

    persisted_to_env = False
    persist_message = "Runtime settings updated"
    if request.persist_to_env:
        effective = _load_effective_ai_settings()
        env_updates: dict[str, Optional[str]] = {
            "AI_URL": effective.get("ai_url") or None,
            "AI_API_KEY": effective.get("ai_api_key") or None,
            "AI_MODEL": effective.get("ai_model") or None,
            "AI_FALLBACK_MODEL": effective.get("ai_model_fallback") or None,
            "AI_MASK_HOST": effective.get("ai_mask_host") or None,
            "AI_SCAN_CLASSIFICATION_ENABLED": "true" if effective.get("ai_scan_classification_enabled") else "false",
            "AI_CLASSIFY_MIN_SEVERITY": effective.get("ai_classify_min_severity") or effective.get("ai_verify_min_severity") or "high",
            "AI_VERIFY_ENABLED": "true" if effective.get("ai_verify_enabled") else "false",
            # Single provider model: keep legacy verify-provider env vars cleared.
            "AI_VERIFY_URL": None,
            "AI_VERIFY_API_KEY": None,
            "AI_VERIFY_MODEL": None,
            "AI_VERIFY_FALLBACK_MODEL": None,
            "AI_VERIFY_MIN_SEVERITY": effective.get("ai_verify_min_severity") or "high",
            "AUTO_RETEST_ON_SCAN_COMPLETE": "true" if effective.get("auto_retest_on_scan_complete") else "false",
            "AUTO_RETEST_MIN_SEVERITY": effective.get("auto_retest_min_severity") or "medium",
            "AUTO_RETEST_MAX_PER_SCAN": str(max(0, int(effective.get("auto_retest_max_per_scan") or 0))),
            "VERIFICATION_MIN_SEVERITY": effective.get("verification_min_severity") or "medium",
            "AI_ESCALATION_MIN_SEVERITY": effective.get("ai_escalation_min_severity") or "high",
            "PROOF_REQUIRED_FOR_SMART": "true" if effective.get("proof_required_for_smart", False) else "false",
            "AI_DEMO_MODE_ENABLED": "true" if effective.get("demo_mode_enabled", False) else "false",
            "AI_DEMO_HONEY_PUBLIC_URL": None if clear_demo_honey_public_url else effective.get("demo_honey_public_url") or None,
            "AI_DEMO_HONEY_SCANNER_URL": None if clear_demo_honey_scanner_url else effective.get("demo_honey_scanner_url") or None,
        }
        persisted_to_env, persist_message = _persist_env_updates(LOCAL_ENV_FILE, env_updates)

    return {
        "status": "updated",
        "persisted_to_env": persisted_to_env,
        "persist_message": persist_message,
        "settings": _sanitize_ai_settings_response(_load_effective_ai_settings()),
    }


@app.post("/settings/ai/test")
async def test_ai_settings(request: AISettingsProbeRequest):
    """Test AI provider connectivity/parsing for scan or verify scope."""
    effective = _load_effective_ai_settings()
    scope = request.scope

    if scope == "verify":
        ai_url = (request.ai_url or effective.get("ai_url") or "").strip()
        ai_api_key = (request.ai_api_key or effective.get("ai_api_key") or "").strip()
        ai_model = (request.ai_model or effective.get("ai_model") or "").strip()
        fallback_models = request.ai_fallback_model
        if fallback_models is None:
            fallback_models = effective.get("ai_model_fallback") or ""
    else:
        ai_url = (request.ai_url or effective.get("ai_url") or "").strip()
        ai_api_key = (request.ai_api_key or effective.get("ai_api_key") or "").strip()
        ai_model = (request.ai_model or effective.get("ai_model") or "").strip()
        fallback_models = request.ai_fallback_model
        if fallback_models is None:
            fallback_models = effective.get("ai_model_fallback") or ""

    if not ai_url:
        raise HTTPException(status_code=400, detail="AI URL is required for probe")
    if not ai_api_key:
        raise HTTPException(status_code=400, detail="AI API key is required for probe")
    if not ai_model:
        raise HTTPException(status_code=400, detail="AI model is required for probe")

    probe = await _probe_ai_provider(
        ai_url=ai_url,
        ai_api_key=ai_api_key,
        model=ai_model,
        fallback_models=(fallback_models or "").strip() or None,
    )
    return {
        "status": "ok" if probe.get("ok") else "failed",
        "scope": scope,
        "probe": probe,
    }


# ============================================================
# MODEL INTAKE
# ============================================================

@app.post("/model-intake/scan")
async def scan_model_intake(request: ModelIntakeScanRequest):
    """Queue a model artifact intake scan."""
    artifact_ref = (request.artifact_url or "").strip()
    if not artifact_ref:
        raise HTTPException(status_code=400, detail="artifact_url is required")
    parsed = urllib.parse.urlparse(artifact_ref)
    if parsed.scheme and parsed.scheme not in {"http", "https", "hf", "oci"}:
        raise HTTPException(status_code=400, detail="artifact_url must use http(s), hf://, or oci://")

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    target_name = request.name or f"Model artifact: {_short_url_label(artifact_ref)}"
    options = {
        "run_kind": "model_intake",
        "artifact_name": request.name,
        "metadata_url": request.metadata_url,
        "metadata_json": request.metadata_json or {},
        "expected_sha256": request.expected_sha256,
        "signature_url": request.signature_url,
        "model_card_url": request.model_card_url,
        "deployment_approved": request.deployment_approved,
        "require_deployment_approval": request.require_deployment_approval,
        "require_signature": request.require_signature,
        "require_hash": request.require_hash,
        "require_model_governance": request.require_model_governance,
        "max_download_bytes": request.max_download_bytes,
        "timeout_seconds": request.timeout_seconds,
    }

    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("SELECT id FROM targets WHERE url = $1", artifact_ref)
        if target:
            target_id = target["id"]
        else:
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source)
                VALUES ($1, $2, $3, 'model-intake')
                RETURNING id
            """, artifact_ref, target_name, extract_root_domain(artifact_ref))

        await conn.execute("""
            INSERT INTO scans (
                id, target_id, target_url, job_id, status, options, scan_type, run_kind, subject_ref
            ) VALUES ($1, $2, $3, $4, 'pending', $5, 'model_intake', 'model_intake', $6)
        """,
            uuid.UUID(scan_id),
            target_id,
            artifact_ref,
            job_id,
            json.dumps(options),
            f"model_artifact:{hashlib.sha256(artifact_ref.encode()).hexdigest()[:16]}",
        )

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": artifact_ref,
        "options": options,
        "submitted_at": datetime.utcnow().isoformat(),
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": artifact_ref})

    return {
        "scan_id": scan_id,
        "job_id": job_id,
        "status": "queued",
        "target": artifact_ref,
        "scan_type": "model_intake",
        "run_kind": "model_intake",
        "ui_url": f"/scans/{scan_id}",
    }


# ============================================================
# AI GATE TARGETS
# ============================================================

@app.get("/ai/targets")
async def list_ai_targets(
    include_inactive: bool = False,
    include_demo: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0,
):
    """List saved AI Gate targets."""
    async with db_pool.acquire() as conn:
        query = "SELECT * FROM ai_targets"
        params: list[Any] = []
        conditions: list[str] = []
        if not include_inactive:
            conditions.append("is_active = true")
        if not include_demo:
            conditions.append(f"NOT {_ai_demo_target_sql_predicate()}")
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY created_at DESC LIMIT $1 OFFSET $2"
        params.extend([limit, offset])
        targets = await conn.fetch(query, *params)
        count_query = "SELECT COUNT(*) FROM ai_targets"
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
        total = await conn.fetchval(count_query)
        target_ids = [row["id"] for row in targets]
        credentials = []
        if target_ids:
            credentials = await conn.fetch(
                "SELECT * FROM ai_target_credentials WHERE ai_target_id = ANY($1::uuid[])",
                target_ids,
            )

    credential_by_target = {row["ai_target_id"]: row for row in credentials}
    return {
        "targets": [_ai_target_response(row, credential_by_target.get(row["id"])) for row in targets],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.post("/ai/targets")
async def create_ai_target(request: AITargetCreate):
    """Create an AI Gate target."""
    target_type = _normalize_ai_target_type(request.target_type)
    endpoint_url = _normalize_ai_endpoint_url(request.endpoint_url)
    method = _normalize_ai_method(request.method)
    streaming_mode = _normalize_ai_streaming_mode(request.streaming_mode)
    headers_template = _normalize_ai_headers_template(request.headers_template)
    request_template = _normalize_ai_request_template(
        request.request_template,
        method=method,
        target_type=target_type,
    )
    credential = _build_ai_credential_db_record(request.credential)
    target_name = request.name or urllib.parse.urlparse(endpoint_url).hostname or endpoint_url

    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT id FROM ai_targets WHERE endpoint_url = $1", endpoint_url)
        if existing:
            raise HTTPException(status_code=409, detail="AI target already exists for this endpoint_url")

        async with conn.transaction():
            target_id = await conn.fetchval("""
                INSERT INTO ai_targets (
                    name, target_type, endpoint_url, method, headers_template,
                    request_template, response_path, streaming_mode, rate_limit_rps,
                    token_budget, request_budget, production_mode, metadata_json, is_active
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                RETURNING id
            """,
                target_name,
                target_type,
                endpoint_url,
                method,
                json.dumps(headers_template),
                json.dumps(request_template),
                request.response_path,
                streaming_mode,
                request.rate_limit_rps,
                request.token_budget,
                request.request_budget,
                request.production_mode,
                json.dumps(request.metadata_json or {}),
                request.is_active,
            )
            await conn.execute("""
                INSERT INTO ai_target_credentials (
                    ai_target_id, auth_kind, header_name, secret_value,
                    secret_preview, metadata_json, rotated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
            """,
                target_id,
                credential["auth_kind"],
                credential["header_name"],
                credential["secret_value"],
                credential["secret_preview"],
                json.dumps(credential["metadata_json"]),
            )

        target = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", target_id)
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            target_id,
        )
    return {"target": _ai_target_response(target, credential_row)}


@app.patch("/ai/targets/{target_id}")
async def update_ai_target(target_id: str, request: AITargetUpdate):
    """Update an AI Gate target."""
    payload = request.model_dump(exclude_unset=True)
    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not existing:
            raise HTTPException(status_code=404, detail="AI target not found")
        existing_credential = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

        update_data: dict[str, Any] = {}
        if "name" in payload:
            update_data["name"] = payload["name"] or existing["name"]
        if "endpoint_url" in payload and payload["endpoint_url"] is not None:
            update_data["endpoint_url"] = _normalize_ai_endpoint_url(payload["endpoint_url"])
        effective_method = _normalize_ai_method(payload.get("method") or existing["method"])
        if "method" in payload:
            update_data["method"] = effective_method
        if "headers_template" in payload:
            update_data["headers_template"] = json.dumps(_normalize_ai_headers_template(payload.get("headers_template")))
        if "request_template" in payload:
            update_data["request_template"] = json.dumps(
                _normalize_ai_request_template(
                    payload.get("request_template"),
                    method=effective_method,
                    target_type=existing["target_type"],
                )
            )
        if "response_path" in payload:
            update_data["response_path"] = payload.get("response_path") or None
        if "streaming_mode" in payload and payload["streaming_mode"] is not None:
            update_data["streaming_mode"] = _normalize_ai_streaming_mode(payload["streaming_mode"])
        for key in ("rate_limit_rps", "token_budget", "request_budget"):
            if key in payload:
                update_data[key] = payload[key]
        if "production_mode" in payload:
            update_data["production_mode"] = bool(payload["production_mode"])
        if "metadata_json" in payload:
            update_data["metadata_json"] = json.dumps(payload.get("metadata_json") or {})
        if "is_active" in payload:
            update_data["is_active"] = bool(payload["is_active"])

        async with conn.transaction():
            if update_data:
                assignments = []
                values = []
                for idx, (key, value) in enumerate(update_data.items(), start=1):
                    assignments.append(f"{key} = ${idx}")
                    values.append(value)
                assignments.append("updated_at = NOW()")
                values.append(uuid.UUID(target_id))
                await conn.execute(
                    f"UPDATE ai_targets SET {', '.join(assignments)} WHERE id = ${len(values)}",
                    *values,
                )

            if request.credential is not None:
                credential = _build_ai_credential_db_record(
                    request.credential,
                    dict(existing_credential) if existing_credential else None,
                )
                await conn.execute("""
                    INSERT INTO ai_target_credentials (
                        ai_target_id, auth_kind, header_name, secret_value,
                        secret_preview, metadata_json, rotated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
                    ON CONFLICT (ai_target_id) DO UPDATE SET
                        auth_kind = EXCLUDED.auth_kind,
                        header_name = EXCLUDED.header_name,
                        secret_value = EXCLUDED.secret_value,
                        secret_preview = EXCLUDED.secret_preview,
                        metadata_json = EXCLUDED.metadata_json,
                        rotated_at = NOW(),
                        updated_at = NOW()
                """,
                    uuid.UUID(target_id),
                    credential["auth_kind"],
                    credential["header_name"],
                    credential["secret_value"],
                    credential["secret_preview"],
                    json.dumps(credential["metadata_json"]),
                )

        target = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )
    return {"target": _ai_target_response(target, credential_row)}


@app.delete("/ai/targets/{target_id}")
async def delete_ai_target(target_id: str):
    """Deactivate an AI Gate target."""
    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE ai_targets
            SET is_active = false, updated_at = NOW()
            WHERE id = $1
        """, uuid.UUID(target_id))
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="AI target not found")
    return {"status": "deleted", "target_id": target_id}


@app.post("/ai/targets/{target_id}/scan")
async def scan_ai_target(target_id: str, request: AITargetScanRequest):
    """Queue an AI Gate scan for a saved AI target."""
    return await _queue_ai_target_scan(target_id, request)


@app.post("/ai/targets/{target_id}/test")
async def test_ai_target_connectivity(target_id: str, request: AITargetConnectivityTestRequest):
    """Send one sanitized preflight request to validate AI target wiring before a scan."""
    async with db_pool.acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )

    target = row_to_dict(target_row)
    for key in ("headers_template", "request_template", "metadata_json"):
        target[key] = _decode_json_value(target.get(key)) or {}
    target["credential"] = _runtime_credential_from_row(dict(credential_row) if credential_row else None)

    result = await asyncio.to_thread(
        _run_ai_target_connectivity_probe,
        target,
        prompt=request.prompt,
        timeout_seconds=request.timeout_seconds,
    )
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        **result,
    }


@app.get("/ai/scans/{scan_id}/transcript")
async def get_ai_scan_transcript(scan_id: str):
    """Return AI Gate transcripts for a completed scan."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result, run_kind FROM scans WHERE id = $1",
            uuid.UUID(scan_id),
        )
    if not scan or scan["run_kind"] not in {"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp"}:
        raise HTTPException(status_code=404, detail="AI scan not found")
    result = _decode_json_value(scan["result"]) or {}
    ai_gate = result.get("ai_gate") if isinstance(result, dict) else None
    transcripts = ai_gate.get("transcripts") if isinstance(ai_gate, dict) else None
    if not transcripts:
        raise HTTPException(status_code=404, detail="Transcript not available")
    return {"scan_id": scan_id, "transcripts": transcripts}


# ============================================================
# DASHBOARD
# ============================================================

@app.get("/dashboard")
async def dashboard():
    """Get dashboard metrics."""
    async with db_pool.acquire() as conn:
        metrics = await conn.fetchrow("SELECT * FROM dashboard_metrics")
        recent_scans = await conn.fetch("""
            SELECT id, target_url, status, score, grade, created_at, completed_at
            FROM scans ORDER BY created_at DESC LIMIT 10
        """)
        recent_findings = await conn.fetch("""
            SELECT id, title, severity, status, tool, first_seen_at
            FROM findings WHERE status = 'active'
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                first_seen_at DESC
            LIMIT 10
        """)

    return {
        "metrics": dict(metrics) if metrics else {},
        "recent_scans": [dict(s) for s in recent_scans],
        "recent_findings": [dict(f) for f in recent_findings]
    }


@app.get("/exposure/graph")
async def exposure_graph(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit_findings: int = Query(250, ge=1, le=500),
    limit_scans: int = Query(150, ge=1, le=300),
):
    """Return a derived exposure graph across web targets, AI targets, scans, findings, vendors, and chains."""
    async with db_pool.acquire() as conn:
        target_query = """
            SELECT
                id, url, name, root_domain, is_root, discovery_source, is_active,
                last_score, last_grade, last_scanned_at, total_scans,
                active_findings_count, created_at, updated_at
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY active_findings_count DESC, updated_at DESC
            LIMIT 500
        """
        targets = [row_to_dict(row) for row in await conn.fetch(target_query, include_inactive, root_domain)]

        ai_query = """
            SELECT
                id, name, target_type, endpoint_url, method, streaming_mode,
                production_mode, rate_limit_rps, token_budget, request_budget,
                last_scanned_at, last_scan_id, metadata_json, is_active,
                created_at, updated_at
            FROM ai_targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT 250
        """
        ai_targets = [row_to_dict(row) for row in await conn.fetch(ai_query, include_inactive, root_domain)]

        scans_query = """
            SELECT
                s.id, s.target_id, s.ai_target_id, s.target_url, s.status, s.scan_type,
                s.run_kind, s.result, s.score, s.grade, s.findings_count,
                s.created_at, s.completed_at,
                t.root_domain,
                ait.endpoint_url as ai_endpoint_url
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE (
                $1::text IS NULL
                OR t.root_domain = $1::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%'
            )
            ORDER BY s.created_at DESC
            LIMIT $2
        """
        scans = [row_to_dict(row) for row in await conn.fetch(scans_query, root_domain, limit_scans)]

        findings_query = """
            SELECT
                f.id, f.scan_id, f.target_id, f.ai_target_id, f.title, f.severity,
                f.status, f.tool, f.source, f.cvss_score, f.url, f.last_seen_at,
                f.last_verification_verdict,
                t.root_domain,
                t.url as target_url,
                ait.endpoint_url as ai_target_url
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE ($1::boolean = true OR f.status = 'active')
              AND (
                $2::text IS NULL
                OR t.root_domain = $2::text
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%'
              )
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                f.last_seen_at DESC NULLS LAST
            LIMIT $3
        """
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(findings_query, include_resolved, root_domain, limit_findings)
        ]

    return _build_exposure_graph(
        targets=targets,
        ai_targets=ai_targets,
        scans=scans,
        findings=findings,
    )


# ============================================================
# SCANS
# ============================================================

@app.post("/scans")
async def submit_scan(request: ScanRequest):
    """Submit a new scan job."""
    scheme_inferred = "://" not in (request.target or "")
    try:
        normalized_target, target_note = normalize_target_url(request.target)
    except TargetNormalizationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not normalized_target:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    # If scheme was inferred (not provided), pass scheme-less target to scanner for auto-detect
    scan_target = normalized_target
    if scheme_inferred:
        scan_target = strip_target_scheme(normalized_target)

    r = get_redis()
    job_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    # Determine scan type
    # Priority: explicit scan_type > legacy boolean flags > default (quick)
    if request.options.scan_type:
        # Use explicit scan_type if provided
        scan_type = request.options.scan_type
        if scan_type not in ['quick', 'standard', 'deep', 'full', 'aggressive', 'smart']:
            scan_type = 'quick'  # Fallback to quick for invalid types
    elif request.options.thorough and request.options.active:
        # Legacy: thorough + active = full
        scan_type = 'full'
        request.options.scan_type = 'full'
    elif request.options.thorough:
        # Legacy: thorough = deep
        scan_type = 'deep'
        request.options.scan_type = 'deep'
    elif request.options.active:
        # Legacy: just active = standard + active tests
        scan_type = 'full'
        request.options.scan_type = 'full'
    elif request.options.quick:
        scan_type = 'quick'
        request.options.scan_type = 'quick'
    else:
        # Default to quick scan
        scan_type = 'quick'
        request.options.scan_type = 'quick'

    # Validate: public option is incompatible with active-enforced scan types
    active_enforced_types = {'smart', 'full', 'aggressive'}
    if scan_type in active_enforced_types and request.options.public:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_options",
                "message": f"'public' option is incompatible with '{scan_type}' scan type. "
                           f"{scan_type.capitalize()} scans require active testing (XSS/SQLi probes). "
                           "Use 'deep' scan type for passive-only comprehensive scanning.",
                "hint": f"Either remove 'public: true' or change scan_type to 'deep'"
            }
        )

    options_payload = request.options.dict()
    effective_budget_profile = options_payload.get("budget_profile")
    if options_payload.get("thorough_params") and not effective_budget_profile and not options_payload.get("custom_budget"):
        effective_budget_profile = "thorough"
    resolved_budget = resolve_scan_budget(
        scan_type,
        effective_budget_profile,
        options_payload.get("custom_budget"),
    )
    options_payload["budget_profile"] = resolved_budget["budget_profile"]
    options_payload["resolved_budget"] = resolved_budget

    # Create or find target
    async with db_pool.acquire() as conn:
        # Check if target exists
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1", normalized_target
        )
        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain)
                VALUES ($1, $2, $3)
                RETURNING id
            """, normalized_target, request.name, extract_root_domain(normalized_target))

        # Create scan record
        await conn.execute("""
            INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6)
        """, uuid.UUID(scan_id), target_id, normalized_target, job_id,
             json.dumps(_attach_target_note(options_payload, request.target, target_note, scheme_inferred)), scan_type)

    # Queue the job
    job_data = {
        'job_id': job_id,
        'scan_id': scan_id,
        'target': scan_target,
        'options': _attach_target_note(options_payload, request.target, target_note, scheme_inferred),
        'submitted_at': datetime.utcnow().isoformat()
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))
    r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': scan_target})

    response = {
        'scan_id': scan_id,
        'job_id': job_id,
        'status': 'queued',
        'target': normalized_target,
        'scan_type': scan_type
    }
    # Surface warning if path/query was stripped
    if target_note:
        response['warning'] = target_note
        response['original_target'] = request.target
    return response


@app.post("/scans/batch")
async def submit_batch(request: BatchRequest):
    """Submit multiple scan jobs."""
    jobs = []
    for target in request.targets:
        req = ScanRequest(target=target, options=request.options)
        result = await submit_scan(req)
        jobs.append(result)

    return {
        'jobs': jobs,
        'count': len(jobs),
        'status': 'queued'
    }


@app.get("/scans")
async def list_scans(
    status: Optional[str] = None,
    target: Optional[str] = None,
    root_domain: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List scans with optional filtering."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT s.*,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.target_type as ai_target_type
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE 1=1
        """
        count_query = """
            SELECT COUNT(*)
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE 1=1
        """
        params = []
        count_params = []
        param_idx = 1
        count_param_idx = 1

        if status:
            query += f" AND s.status = ${param_idx}"
            count_query += f" AND s.status = ${count_param_idx}"
            params.append(status)
            count_params.append(status)
            param_idx += 1
            count_param_idx += 1

        if target:
            query += f" AND s.target_url ILIKE ${param_idx}"
            count_query += f" AND s.target_url ILIKE ${count_param_idx}"
            params.append(f"%{target}%")
            count_params.append(f"%{target}%")
            param_idx += 1
            count_param_idx += 1

        if root_domain:
            query += f" AND t.root_domain = ${param_idx}"
            count_query += f" AND t.root_domain = ${count_param_idx}"
            params.append(root_domain)
            count_params.append(root_domain)
            param_idx += 1
            count_param_idx += 1

        query += f" ORDER BY s.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *count_params)

    scans = []
    for row in rows:
        scan = dict(row)
        if scan.get("options") is not None:
            scan["options"] = _sanitize_scan_options(scan["options"])
        scans.append(scan)

    return {
        'scans': scans,
        'total': total,
        'limit': limit,
        'offset': offset
    }


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str, verified_only: bool = False):
    """Get scan details."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT s.*,
                   COALESCE(t.name, ait.name) as target_name,
                   ait.target_type as ai_target_type
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.id = $1
        """, uuid.UUID(scan_id))

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Get findings for this scan
        findings = await conn.fetch("""
            SELECT id, fingerprint, title, severity, cvss_score, status, tool, url, last_verification_verdict
            FROM findings WHERE scan_id = $1
            AND ($2::boolean = false OR last_verification_verdict = 'exploited')
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id), verified_only)

    result = dict(scan)
    result['findings'] = [dict(f) for f in findings]
    if result.get('result') is not None:
        result['result'] = _decode_json_value(result['result'])
    if result.get('options') is not None:
        result['options'] = _sanitize_scan_options(result['options'])
    return result


@app.get("/scans/{scan_id}/ai-redteam-report")
async def get_ai_redteam_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|markdown)$"),
):
    """Export an AI red-team evidence pack for AI Gate or Model Intake scans."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT s.*,
                   COALESCE(t.name, ait.name) as target_name,
                   ait.target_type as ai_target_type,
                   ait.metadata_json as ai_target_metadata
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.id = $1
        """, uuid.UUID(scan_id))

        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = await conn.fetch("""
            SELECT id, fingerprint, title, description, severity, cvss_score, status,
                   tool, cwe, cwe_name, owasp, url, evidence, ai_verdict,
                   ai_confidence, ai_rationale, ai_recommendations,
                   ai_classification_source, notes, last_verification_verdict,
                   last_verification_confidence, last_verified_at, source,
                   first_seen_at, last_seen_at
            FROM findings
            WHERE scan_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id))

    scan_payload = row_to_dict(scan)
    scan_payload["result"] = _decode_json_value(scan_payload.get("result"))
    scan_payload["options"] = _sanitize_scan_options(scan_payload.get("options"))
    scan_payload["ai_target_metadata"] = _decode_json_value(scan_payload.get("ai_target_metadata"))
    scan_payload["findings"] = [row_to_dict(item) for item in findings]

    report = build_ai_redteam_report(
        scan_payload,
        target_metadata=scan_payload.get("ai_target_metadata"),
    )
    if format == "markdown":
        return Response(
            content=render_ai_redteam_markdown(report),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="shakerscan-ai-redteam-{scan_id}.md"'},
        )
    return report


@app.get("/scans/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get full scan result JSON."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result FROM scans WHERE id = $1", uuid.UUID(scan_id)
        )
        if not scan or not scan['result']:
            raise HTTPException(status_code=404, detail="Scan result not found")
        return _decode_json_value(scan['result'])


@app.get("/scans/{scan_id}/logs")
async def get_scan_logs(scan_id: str, limit: int = 200):
    """Get recent scan logs (tail)."""
    r = get_redis()
    log_key = f"scan:{scan_id}:logs"
    # Return tail lines
    try:
        lines = r.lrange(log_key, max(-limit, -1000), -1) if limit else r.lrange(log_key, -200, -1)
    except Exception:
        lines = []
    return {
        "scan_id": scan_id,
        "lines": lines,
        "count": len(lines),
        "limit": limit,
    }


@app.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """Cancel a running or pending scan."""
    r = get_redis()

    async with db_pool.acquire() as conn:
        # Check scan exists and is cancellable
        scan = await conn.fetchrow(
            "SELECT id, status, target_url FROM scans WHERE id = $1",
            uuid.UUID(scan_id)
        )
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        if scan['status'] not in ('pending', 'running', 'queued'):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel scan with status '{scan['status']}'"
            )

        # Update database
        await conn.execute("""
            UPDATE scans
            SET status = 'cancelled',
                error_message = 'Cancelled by user',
                completed_at = NOW()
            WHERE id = $1
        """, uuid.UUID(scan_id))

    # Signal worker to stop via Redis (set cancel flag)
    # Workers should check this flag periodically
    r.set(f"scan:{scan_id}:cancel", "1", ex=3600)  # Expires in 1 hour

    # Also try to find and update the job in Redis
    for key in r.keys("job:*"):
        job_data = r.hgetall(key)
        if job_data.get('scan_id') == scan_id:
            r.hset(key, 'status', 'cancelled')
            break

    return {
        "status": "cancelled",
        "scan_id": scan_id,
        "target": scan['target_url'],
        "message": "Scan cancelled successfully"
    }


# ============================================================
# TARGETS
# ============================================================

@app.get("/targets")
async def list_targets(
    include_inactive: bool = False,
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List all targets."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT t.*, fs.total_active as active_findings
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += f" AND t.is_active = true"

        query += f" ORDER BY t.updated_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(
            "SELECT COUNT(*) FROM targets" + ("" if include_inactive else " WHERE is_active = true")
        )

    return {
        'targets': [dict(r) for r in rows],
        'total': total
    }


@app.get("/targets/grouped")
async def list_targets_grouped(
    include_inactive: bool = False,
    search: Optional[str] = None,
    discovery_source: Optional[str] = Query(None, pattern="^(manual|subfinder|gungnir-monitor|import|model-intake)$"),
    grade: Optional[str] = Query(None, pattern="^[A-Fa-f]$"),
    has_findings: Optional[bool] = None,
    sort_by: Optional[str] = Query("root_domain", pattern="^(root_domain|last_scanned_at|active_findings_count|last_score|created_at)$"),
    sort_order: Optional[str] = Query("asc", pattern="^(asc|desc)$")
):
    """List all targets grouped by root domain for hierarchical display."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT
                t.id, t.url, t.name, t.root_domain, t.is_root,
                t.discovery_source, t.is_active,
                t.last_scanned_at, t.last_score, t.last_grade,
                t.total_scans, t.active_findings_count,
                t.created_at
            FROM targets t
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if not include_inactive:
            query += " AND t.is_active = true"

        if search:
            query += f" AND (t.url ILIKE '%' || ${param_idx} || '%' OR t.name ILIKE '%' || ${param_idx} || '%' OR t.root_domain ILIKE '%' || ${param_idx} || '%')"
            params.append(search)
            param_idx += 1

        if discovery_source:
            query += f" AND t.discovery_source = ${param_idx}"
            params.append(discovery_source)
            param_idx += 1

        if grade:
            query += f" AND UPPER(t.last_grade) = UPPER(${param_idx})"
            params.append(grade)
            param_idx += 1

        if has_findings is not None:
            if has_findings:
                query += " AND t.active_findings_count > 0"
            else:
                query += " AND t.active_findings_count = 0"

        query += " ORDER BY t.root_domain, t.is_root DESC, t.url"

        rows = await conn.fetch(query, *params)

    # Group by root_domain
    grouped = {}
    for row in rows:
        rd = row['root_domain'] or 'unknown'
        if rd not in grouped:
            grouped[rd] = {
                'root_domain': rd,
                'root_target': None,
                'subdomains': []
            }

        target_data = row_to_dict(row)
        if row['is_root']:
            grouped[rd]['root_target'] = target_data
        else:
            grouped[rd]['subdomains'].append(target_data)

    # Convert to list and add summary stats
    result = []
    for rd, data in grouped.items():
        data['subdomain_count'] = len(data['subdomains'])
        data['total_count'] = data['subdomain_count'] + (1 if data['root_target'] else 0)
        # Add aggregate stats for sorting
        root_findings = data['root_target']['active_findings_count'] if data['root_target'] else 0
        subdomain_findings = sum(s['active_findings_count'] for s in data['subdomains'])
        data['total_findings'] = root_findings + subdomain_findings
        data['best_score'] = data['root_target']['last_score'] if data['root_target'] and data['root_target']['last_score'] is not None else None
        data['latest_scan'] = data['root_target']['last_scanned_at'] if data['root_target'] else None
        data['earliest_created'] = data['root_target']['created_at'] if data['root_target'] else (
            min((s['created_at'] for s in data['subdomains']), default=None)
        )
        result.append(data)

    # Sort based on sort_by and sort_order
    reverse = sort_order == 'desc'

    def sort_key(x):
        if sort_by == 'root_domain':
            return x['root_domain'].lower()
        elif sort_by == 'last_scanned_at':
            return x['latest_scan'] or ''
        elif sort_by == 'active_findings_count':
            return x['total_findings']
        elif sort_by == 'last_score':
            # None values should sort last in ascending, first in descending
            score = x['best_score']
            if score is None:
                return -1 if reverse else 101
            return score
        elif sort_by == 'created_at':
            return x['earliest_created'] or ''
        return x['root_domain'].lower()

    result.sort(key=sort_key, reverse=reverse)

    return {
        'domains': result,
        'total_root_domains': len(result),
        'total_targets': sum(d['total_count'] for d in result)
    }


@app.get("/domains")
async def list_domains():
    """List unique root domains from DAST and AI targets."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT DISTINCT root_domain
            FROM targets
            WHERE root_domain IS NOT NULL AND is_active = true
            ORDER BY root_domain
        """)
        ai_rows = await conn.fetch("""
            SELECT endpoint_url
            FROM ai_targets
            WHERE endpoint_url IS NOT NULL AND is_active = true
        """)

    return {
        'domains': sorted({
            *(r['root_domain'] for r in rows),
            *(extract_root_domain(r['endpoint_url']) for r in ai_rows if r['endpoint_url'])
        })
    }


@app.post("/targets")
async def create_target(request: TargetCreate):
    """Create a new target."""
    scheme_inferred = "://" not in (request.url or "")
    try:
        normalized_target, target_note = normalize_target_url(request.url)
    except TargetNormalizationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not normalized_target:
        raise HTTPException(status_code=400, detail="Invalid target URL")
    root_domain = extract_root_domain(normalized_target)
    is_root = is_root_domain(normalized_target)

    async with db_pool.acquire() as conn:
        try:
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, is_root, scan_options)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            """, normalized_target, request.name, root_domain, is_root,
                 json.dumps(_attach_target_note(request.scan_options or {}, request.url, target_note, scheme_inferred)))

            response = {
                'id': str(target_id),
                'url': normalized_target,
                'root_domain': root_domain,
                'is_root': is_root,
                'status': 'created'
            }
            # Surface warning if path/query was stripped
            if target_note:
                response['warning'] = target_note
                response['original_url'] = request.url
            return response
        except asyncpg.UniqueViolationError:
            raise HTTPException(status_code=409, detail="Target already exists")


@app.get("/targets/{target_id}")
async def get_target(target_id: str):
    """Get target details."""
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("""
            SELECT t.*, fs.*
            FROM targets t
            LEFT JOIN findings_summary fs ON t.id = fs.target_id
            WHERE t.id = $1
        """, uuid.UUID(target_id))

        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        # Get recent scans
        scans = await conn.fetch("""
            SELECT id, status, score, grade, created_at, completed_at
            FROM scans WHERE target_id = $1
            ORDER BY created_at DESC LIMIT 10
        """, uuid.UUID(target_id))

    result = dict(target)
    result['recent_scans'] = [dict(s) for s in scans]
    return result


@app.patch("/targets/{target_id}")
async def update_target(target_id: str, request: TargetUpdate):
    """Update a target."""
    async with db_pool.acquire() as conn:
        updates = []
        params = []
        param_idx = 1

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.is_active is not None:
            updates.append(f"is_active = ${param_idx}")
            params.append(request.is_active)
            param_idx += 1

        if request.scan_options is not None:
            updates.append(f"scan_options = ${param_idx}")
            params.append(json.dumps(request.scan_options))
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(target_id))

        query = f"UPDATE targets SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        result = await conn.fetchval(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'updated'}


@app.delete("/targets/{target_id}")
async def delete_target(target_id: str):
    """Delete a target (soft delete - sets inactive)."""
    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE targets SET is_active = false, updated_at = NOW()
            WHERE id = $1
        """, uuid.UUID(target_id))

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Target not found")

    return {'id': target_id, 'status': 'deleted'}


@app.post("/targets/{target_id}/scan")
async def scan_target(target_id: str, options: ScanOptions = None):
    """Start a scan for a specific target."""
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow(
            "SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id)
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

    # Merge target's default options with provided options
    stored_options = target['scan_options']
    if isinstance(stored_options, str):
        merged_options = json.loads(stored_options) if stored_options else {}
    else:
        merged_options = stored_options or {}
    if options:
        merged_options.update(options.dict(exclude_unset=True))

    request = ScanRequest(target=target['url'], options=ScanOptions(**merged_options))
    return await submit_scan(request)


# ============================================================
# FINDINGS
# ============================================================

async def enqueue_finding_retest(
    conn,
    finding: dict[str, Any],
    inputs: dict[str, Any],
    requested_by: str = "api",
    auth_context: dict[str, str] | None = None,
):
    """Create a queued finding retest record and return (retest_id, job_id)."""
    retest_id = uuid.uuid4()
    job_id = str(uuid.uuid4())
    replay_commands = build_replay_commands(inputs)

    # If no auth_context provided, try to pull from the finding's scan
    if auth_context is None and finding.get("scan_id"):
        scan_row = await conn.fetchrow(
            "SELECT options FROM scans WHERE id = $1", finding["scan_id"]
        )
        if scan_row:
            auth_context = extract_auth_context(parse_json_field(scan_row["options"]))

    auth_ctx_json = json.dumps(auth_context) if auth_context else None

    await conn.execute("""
        INSERT INTO finding_verifications (
            id, finding_id, scan_id, target_id, job_id, requested_by, status,
            finding_type, target_url, original_url, param, payload, method, request_body,
            replay_commands, auth_context
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'queued',
            $7, $8, $9, $10, $11, $12, $13, $14, $15
        )
    """,
        retest_id,
        finding["id"],
        finding.get("scan_id"),
        finding.get("target_id"),
        job_id,
        requested_by or "api",
        inputs["finding_type"],
        inputs["target_url"],
        inputs.get("original_url"),
        inputs.get("param"),
        inputs.get("payload"),
        inputs.get("method"),
        inputs.get("request_body"),
        json.dumps(replay_commands) if replay_commands else None,
        auth_ctx_json,
    )

    await conn.execute("""
        UPDATE findings
        SET last_verification_status = 'queued',
            last_verification_verdict = NULL,
            updated_at = NOW()
        WHERE id = $1
    """, finding["id"])

    return retest_id, job_id


async def mark_retest_enqueue_failed(
    conn,
    *,
    verification_id: uuid.UUID,
    finding_id: uuid.UUID,
    error_message: str,
):
    """Mark a queued retest as failed when it cannot be enqueued to Redis."""
    reason = (error_message or "Queue enqueue failed").strip()
    await conn.execute(
        """
        UPDATE finding_verifications
        SET status = 'failed',
            result_status = 'error',
            verdict = 'error',
            verdict_reason = $2,
            attempts_exhausted = TRUE,
            retry_class = 'transient',
            retryable = FALSE,
            error_message = $2,
            completed_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        """,
        verification_id,
        reason,
    )
    await conn.execute(
        """
        UPDATE findings
        SET last_verification_status = 'error',
            last_verification_verdict = 'error',
            last_verification_confidence = NULL,
            last_verified_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
        """,
        finding_id,
    )


@app.get("/findings")
async def list_findings(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = Query(None, regex="^(dast|ai|model_intake)$"),
    target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    root_domain: Optional[str] = None,
    verification_verdict: Optional[str] = Query(None, regex="^(exploited|likely_vulnerable|blocked_by_security|out_of_scope_internal|false_positive|likely_fixed|inconclusive|error)$"),
    verification_mode: Optional[str] = Query(None, regex="^(deterministic|ai_driven)$"),
    verified_only: bool = False,
    search: Optional[str] = None,
    seen_within_days: Optional[int] = Query(None, ge=1),
    sort_by: Optional[str] = Query(None, regex="^(severity|first_seen|last_seen|cvss)$"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List findings with filtering and sorting."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url) as target_url,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE 1=1
        """
        count_query = """
            SELECT COUNT(*)
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE 1=1
        """
        params = []
        count_params = []
        param_idx = 1
        count_param_idx = 1

        if severity:
            query += f" AND f.severity = ${param_idx}"
            count_query += f" AND f.severity = ${count_param_idx}"
            params.append(severity)
            count_params.append(severity)
            param_idx += 1
            count_param_idx += 1

        if status:
            query += f" AND f.status = ${param_idx}"
            count_query += f" AND f.status = ${count_param_idx}"
            params.append(status)
            count_params.append(status)
            param_idx += 1
            count_param_idx += 1

        if source_type == "ai":
            query += " AND (f.source IN ('ai_gate', 'ai_session') OR f.ai_target_id IS NOT NULL)"
            count_query += " AND (f.source IN ('ai_gate', 'ai_session') OR f.ai_target_id IS NOT NULL)"
        elif source_type == "model_intake":
            query += " AND (f.source = 'model_intake' OR f.tool = 'model_intake')"
            count_query += " AND (f.source = 'model_intake' OR f.tool = 'model_intake')"
        elif source_type == "dast":
            query += " AND COALESCE(f.source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake') AND f.ai_target_id IS NULL AND COALESCE(f.tool, '') <> 'model_intake'"
            count_query += " AND COALESCE(f.source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake') AND f.ai_target_id IS NULL AND COALESCE(f.tool, '') <> 'model_intake'"

        if target_id:
            query += f" AND f.target_id = ${param_idx}"
            count_query += f" AND f.target_id = ${count_param_idx}"
            params.append(uuid.UUID(target_id))
            count_params.append(uuid.UUID(target_id))
            param_idx += 1
            count_param_idx += 1

        if scan_id:
            query += f" AND f.scan_id = ${param_idx}"
            count_query += f" AND f.scan_id = ${count_param_idx}"
            params.append(uuid.UUID(scan_id))
            count_params.append(uuid.UUID(scan_id))
            param_idx += 1
            count_param_idx += 1

        if root_domain:
            query += f""" AND (
                t.root_domain = ${param_idx}
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER(${param_idx}) || '%'
            )"""
            count_query += f""" AND (
                t.root_domain = ${count_param_idx}
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER(${count_param_idx}) || '%'
            )"""
            params.append(root_domain)
            count_params.append(root_domain)
            param_idx += 1
            count_param_idx += 1

        if verification_verdict:
            query += f" AND f.last_verification_verdict = ${param_idx}"
            count_query += f" AND f.last_verification_verdict = ${count_param_idx}"
            params.append(verification_verdict)
            count_params.append(verification_verdict)
            param_idx += 1
            count_param_idx += 1

        if verified_only:
            query += " AND f.last_verification_verdict = 'exploited'"
            count_query += " AND f.last_verification_verdict = 'exploited'"

        if verification_mode:
            mode_filter = f""" AND EXISTS (
                SELECT 1 FROM finding_verifications fv2
                WHERE fv2.finding_id = f.id AND fv2.verification_mode = ${param_idx}
            )"""
            query += mode_filter
            count_query_mode = f""" AND EXISTS (
                SELECT 1 FROM finding_verifications fv2
                WHERE fv2.finding_id = f.id AND fv2.verification_mode = ${count_param_idx}
            )"""
            count_query += count_query_mode
            params.append(verification_mode)
            count_params.append(verification_mode)
            param_idx += 1
            count_param_idx += 1

        if search:
            search_pattern = f"%{search}%"
            query += f""" AND (
                f.title ILIKE ${param_idx}
                OR f.url ILIKE ${param_idx}
                OR t.url ILIKE ${param_idx}
                OR ait.endpoint_url ILIKE ${param_idx}
                OR ait.name ILIKE ${param_idx}
            )"""
            count_query += f""" AND (
                f.title ILIKE ${count_param_idx}
                OR f.url ILIKE ${count_param_idx}
                OR t.url ILIKE ${count_param_idx}
                OR ait.endpoint_url ILIKE ${count_param_idx}
                OR ait.name ILIKE ${count_param_idx}
            )"""
            params.append(search_pattern)
            count_params.append(search_pattern)
            param_idx += 1
            count_param_idx += 1

        if seen_within_days:
            query += f" AND f.last_seen_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            count_query += f" AND f.last_seen_at >= NOW() - INTERVAL '1 day' * ${count_param_idx}"
            params.append(seen_within_days)
            count_params.append(seen_within_days)
            param_idx += 1
            count_param_idx += 1

        # Build ORDER BY clause based on sort_by parameter
        order_dir = "DESC" if sort_order == "desc" else "ASC"
        if sort_by == "first_seen":
            order_clause = f"f.first_seen_at {order_dir} NULLS LAST"
        elif sort_by == "last_seen":
            order_clause = f"f.last_seen_at {order_dir} NULLS LAST"
        elif sort_by == "cvss":
            order_clause = f"f.cvss_score {order_dir} NULLS LAST"
        else:
            severity_dir = "ASC" if sort_order == "desc" else "DESC"
            order_clause = """
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END""" + f" {severity_dir}, f.last_seen_at DESC NULLS LAST"

        query += f"""
            ORDER BY {order_clause}
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)
        total = await conn.fetchval(count_query, *count_params)

    return {
        'findings': [dict(r) for r in rows],
        'total': total,
        'limit': limit,
        'offset': offset
    }


@app.get("/findings/{finding_id:path}")
async def get_finding(finding_id: str):
    """Get finding details by ID or fingerprint."""
    async with db_pool.acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

    return dict(finding)


@app.post("/findings/{finding_id:path}/retest")
async def retest_finding(
    finding_id: str,
    request: FindingRetestRequest | None = None,
    mode: Optional[str] = Query(None, regex="^(ai|deterministic)$"),
):
    """Queue a retest for a finding and persist verification history.

    Pass mode=ai to skip deterministic provers and go straight to AI verification.
    """
    request = request or FindingRetestRequest()
    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")

    async with db_pool.acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding_data = dict(finding)
        if finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id"):
            raise HTTPException(
                status_code=400,
                detail="AI Gate findings are not supported by the web retest endpoint; re-run the AI Gate target instead.",
            )
        retest_inputs = extract_retest_inputs(
            finding_data,
            override_type=request.finding_type,
            override_target=request.target,
            override_original_url=request.original_url,
            override_param=request.param,
            override_payload=request.payload,
            override_method=request.method,
            override_request_body=request.request_body,
        )

        if not retest_inputs.get("finding_type"):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "unsupported_finding_type",
                    "message": "Could not infer retest type from finding.",
                    "supported_types": list(SUPPORTED_RETEST_TYPES),
                },
            )

        if not retest_inputs.get("target_url"):
            raise HTTPException(
                status_code=400,
                detail="Finding is missing target URL context required for retest"
            )

        retest_id, job_id = await enqueue_finding_retest(
            conn,
            finding_data,
            retest_inputs,
            requested_by=request.requested_by or "api",
        )

    job_data = build_retest_job_payload(
        job_id=job_id,
        verification_id=str(retest_id),
        finding_id=str(finding_data["id"]),
        submitted_at=datetime.utcnow().isoformat(),
        trigger=request.requested_by or "api",
    )
    # Pass mode through to the worker
    if mode:
        job_data["mode"] = mode
    valid, reason = validate_retest_job_payload(job_data)
    if not valid:
        async with db_pool.acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=retest_id,
                finding_id=finding_data["id"],
                error_message=f"Retest job payload failed contract validation: {reason}",
            )
        raise HTTPException(
            status_code=500,
            detail={
                "error": "invalid_retest_job_payload",
                "message": "Retest job payload failed contract validation",
                "reason": reason,
            },
        )
    try:
        r.rpush(RETEST_QUEUE_NAME, json.dumps(job_data))
    except Exception as e:
        async with db_pool.acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=retest_id,
                finding_id=finding_data["id"],
                error_message=f"Retest queue enqueue failed: {type(e).__name__}: {e}",
            )
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")
    try:
        r.hset(
            f"retest_job:{job_id}",
            mapping={
                "status": "queued",
                "verification_id": str(retest_id),
                "finding_id": str(finding_data["id"]),
                "queue_schema_version": str(job_data.get("queue_schema_version", "")),
            },
        )
        r.expire(f"retest_job:{job_id}", 86400)
    except Exception:
        # Non-critical metadata cache write; queue already has the job.
        pass

    return {
        "retest_id": str(retest_id),
        "job_id": job_id,
        "status": "queued",
        "mode": mode or "tiered",
        "finding_id": str(finding_data["id"]),
        "finding_type": retest_inputs["finding_type"],
        "target_url": retest_inputs["target_url"],
        "replay_commands": build_replay_commands(retest_inputs),
    }


@app.get("/retests/finding/{finding_id:path}")
async def list_finding_retests(finding_id: str, limit: int = Query(20, ge=1, le=200)):
    """List retest history for a finding."""
    async with db_pool.acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        rows = await conn.fetch("""
            SELECT *
            FROM finding_verifications
            WHERE finding_id = $1
            ORDER BY created_at DESC
            LIMIT $2
        """, finding["id"], limit)

    return {
        "finding_id": str(finding["id"]),
        "retests": [row_to_dict(r) for r in rows],
        "count": len(rows),
    }


@app.get("/retests/{retest_id}")
async def get_retest(retest_id: str):
    """Get a single retest record by ID."""
    async with db_pool.acquire() as conn:
        try:
            retest_uuid = uuid.UUID(retest_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid retest ID")

        row = await conn.fetchrow("""
            SELECT fv.*, f.title, f.severity, f.fingerprint
            FROM finding_verifications fv
            JOIN findings f ON fv.finding_id = f.id
            WHERE fv.id = $1
        """, retest_uuid)

        if not row:
            raise HTTPException(status_code=404, detail="Retest not found")

    return row_to_dict(row)


@app.post("/findings/retest")
async def bulk_retest_findings(request: FindingsBulkRetestRequest):
    """Queue retests for multiple findings by IDs or filters."""
    if request.mode and request.mode not in {"ai", "deterministic"}:
        raise HTTPException(status_code=400, detail="mode must be 'ai' or 'deterministic'")

    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {e}")

    queued: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    async with db_pool.acquire() as conn:
        findings: list[Any] = []

        if request.finding_ids:
            for fid in request.finding_ids:
                finding = await get_finding_record(conn, fid)
                if finding:
                    findings.append(finding)
                else:
                    skipped.append({"finding_id": fid, "reason": "not_found"})
        else:
            scoped = any([
                request.severity,
                request.status,
                request.target_id,
                request.scan_id,
                request.root_domain,
                request.search,
            ])
            if not scoped:
                raise HTTPException(
                    status_code=400,
                    detail="Provide finding_ids or at least one filter to scope bulk retest request"
                )

            query = """
                SELECT f.*,
                       COALESCE(t.url, ait.endpoint_url) as target_url,
                       COALESCE(t.name, ait.name) as target_name,
                       t.root_domain,
                       ait.endpoint_url as ai_target_url,
                       ait.name as ai_target_name
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
                WHERE 1=1
            """
            params: list[Any] = []
            idx = 1

            if request.severity:
                query += f" AND f.severity = ${idx}"
                params.append(request.severity)
                idx += 1
            if request.status:
                query += f" AND f.status = ${idx}"
                params.append(request.status)
                idx += 1
            else:
                query += " AND f.status = 'active'"
            if request.target_id:
                try:
                    target_uuid = uuid.UUID(request.target_id)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid target_id")
                query += f" AND f.target_id = ${idx}"
                params.append(target_uuid)
                idx += 1
            if request.scan_id:
                try:
                    scan_uuid = uuid.UUID(request.scan_id)
                except ValueError:
                    raise HTTPException(status_code=400, detail="Invalid scan_id")
                query += f" AND f.scan_id = ${idx}"
                params.append(scan_uuid)
                idx += 1
            if request.root_domain:
                query += f" AND t.root_domain = ${idx}"
                params.append(request.root_domain)
                idx += 1
            if request.search:
                query += f""" AND (
                    f.title ILIKE ${idx}
                    OR f.url ILIKE ${idx}
                    OR t.url ILIKE ${idx}
                    OR ait.endpoint_url ILIKE ${idx}
                    OR ait.name ILIKE ${idx}
                )"""
                params.append(f"%{request.search}%")
                idx += 1

            query += f"""
                ORDER BY
                    CASE f.severity
                        WHEN 'critical' THEN 1
                        WHEN 'high' THEN 2
                        WHEN 'medium' THEN 3
                        WHEN 'low' THEN 4
                        ELSE 5
                    END,
                    f.last_seen_at DESC
                LIMIT ${idx}
            """
            params.append(request.limit)
            findings = await conn.fetch(query, *params)

        queue_failed_at: int | None = None
        queue_error: str | None = None
        for idx, row in enumerate(findings):
            finding_data = dict(row)
            if finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "ai_gate_findings_require_ai_gate_rescan",
                })
                continue
            retest_inputs = extract_retest_inputs(
                finding_data,
                override_type=request.finding_type,
            )

            if not retest_inputs.get("finding_type"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "unsupported_type",
                })
                continue
            if not retest_inputs.get("target_url"):
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "missing_target_url",
                })
                continue

            retest_id, job_id = await enqueue_finding_retest(
                conn,
                finding_data,
                retest_inputs,
                requested_by=request.requested_by or "api",
            )

            job_data = build_retest_job_payload(
                job_id=job_id,
                verification_id=str(retest_id),
                finding_id=str(finding_data["id"]),
                submitted_at=datetime.utcnow().isoformat(),
                trigger=request.requested_by or "api",
            )
            if request.mode:
                job_data["mode"] = request.mode
            valid, reason = validate_retest_job_payload(job_data)
            if not valid:
                await mark_retest_enqueue_failed(
                    conn,
                    verification_id=retest_id,
                    finding_id=finding_data["id"],
                    error_message=f"Retest job payload failed contract validation: {reason}",
                )
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": f"invalid_job_payload:{reason}",
                })
                continue
            try:
                r.rpush(RETEST_QUEUE_NAME, json.dumps(job_data))
            except Exception as e:
                await mark_retest_enqueue_failed(
                    conn,
                    verification_id=retest_id,
                    finding_id=finding_data["id"],
                    error_message=f"Retest queue enqueue failed: {type(e).__name__}: {e}",
                )
                skipped.append({
                    "finding_id": str(finding_data["id"]),
                    "reason": "queue_unavailable",
                })
                queue_failed_at = idx
                queue_error = f"{type(e).__name__}: {e}"
                break
            try:
                r.hset(
                    f"retest_job:{job_id}",
                    mapping={
                        "status": "queued",
                        "verification_id": str(retest_id),
                        "finding_id": str(finding_data["id"]),
                        "queue_schema_version": str(job_data.get("queue_schema_version", "")),
                    },
                )
                r.expire(f"retest_job:{job_id}", 86400)
            except Exception:
                # Non-critical metadata cache write; queue already has the job.
                pass

            queued.append({
                "finding_id": str(finding_data["id"]),
                "retest_id": str(retest_id),
                "job_id": job_id,
                "finding_type": retest_inputs["finding_type"],
                "replay_commands": build_replay_commands(retest_inputs),
            })

        if queue_failed_at is not None:
            for remaining in findings[queue_failed_at + 1:]:
                skipped.append({
                    "finding_id": str(remaining["id"]),
                    "reason": "queue_unavailable",
                })
            if not queued:
                raise HTTPException(status_code=503, detail=f"Retest queue unavailable: {queue_error or 'unknown error'}")

    return {
        "status": "queued",
        "mode": request.mode or "tiered",
        "queued_count": len(queued),
        "skipped_count": len(skipped),
        "queued": queued,
        "skipped": skipped,
    }


@app.patch("/findings/{finding_id:path}")
async def update_finding(
    finding_id: str,
    request: FindingUpdate,
    scan_id: Optional[str] = Query(None, description="Scope update to specific scan")
):
    """Update a finding status by ID or fingerprint.

    Lookup order:
    1. UUID (exact match)
    2. Full scanner ID as fingerprint (new format: "tool:hash")
    3. Suffix-only fingerprint (backward compat)
    4. Legacy computed fingerprint (pre-change findings)

    Pass scan_id to scope updates to a specific scan and prevent cross-target collisions.
    """
    async with db_pool.acquire() as conn:
        updated_id = None
        scan_uuid = None
        if scan_id:
            try:
                scan_uuid = uuid.UUID(scan_id)
            except ValueError:
                pass

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            result = await conn.fetchrow("""
                UPDATE findings
                SET status = $1,
                    notes = COALESCE($2, notes),
                    analyst_verdict = COALESCE($3, analyst_verdict),
                    analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                    analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                    updated_at = NOW()
                WHERE id = $4
                RETURNING id
            """, request.status, request.notes, request.analyst_verdict, finding_uuid)
            if result:
                updated_id = result['id']
        except ValueError:
            pass

        # Try full scanner ID as fingerprint (new format: "tool:hash")
        if not updated_id:
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE fingerprint = $4 AND scan_id = $5
                    RETURNING id
                """, request.status, request.notes, request.analyst_verdict, finding_id, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $4
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id
                """, request.status, request.notes, request.analyst_verdict, finding_id)
            if result:
                updated_id = result['id']

        # Backward compat: try suffix-only for old findings
        if not updated_id and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            if scan_uuid:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE fingerprint = $4 AND scan_id = $5
                    RETURNING id
                """, request.status, request.notes, request.analyst_verdict, suffix, scan_uuid)
            else:
                result = await conn.fetchrow("""
                    UPDATE findings
                    SET status = $1,
                        notes = COALESCE($2, notes),
                        analyst_verdict = COALESCE($3, analyst_verdict),
                        analyst_verdict_at = CASE WHEN $3 IS NULL THEN analyst_verdict_at ELSE NOW() END,
                        analyst_verdict_notes = CASE WHEN $3 IS NULL THEN analyst_verdict_notes ELSE COALESCE($2, analyst_verdict_notes) END,
                        updated_at = NOW()
                    WHERE id = (
                        SELECT id FROM findings WHERE fingerprint = $4
                        ORDER BY last_seen_at DESC LIMIT 1
                    )
                    RETURNING id
                """, request.status, request.notes, request.analyst_verdict, suffix)
            if result:
                updated_id = result['id']

        if not updated_id:
            raise HTTPException(status_code=404, detail="Finding not found")

    return {'id': str(updated_id), 'status': request.status, 'analyst_verdict': request.analyst_verdict}


@app.delete("/findings/{finding_id:path}")
async def delete_finding(finding_id: str):
    """Delete a finding by ID or fingerprint."""
    async with db_pool.acquire() as conn:
        deleted_id = None

        # Try UUID first
        try:
            finding_uuid = uuid.UUID(finding_id)
            result = await conn.fetchrow(
                "DELETE FROM findings WHERE id = $1 RETURNING id", finding_uuid
            )
            if result:
                deleted_id = result['id']
        except ValueError:
            pass

        # Try fingerprint
        if not deleted_id:
            result = await conn.fetchrow("""
                DELETE FROM findings
                WHERE id = (
                    SELECT id FROM findings WHERE fingerprint = $1
                    ORDER BY last_seen_at DESC LIMIT 1
                )
                RETURNING id
            """, finding_id)
            if result:
                deleted_id = result['id']

        # Backward compat: suffix-only
        if not deleted_id and ':' in finding_id:
            suffix = finding_id.split(':')[-1]
            result = await conn.fetchrow("""
                DELETE FROM findings
                WHERE id = (
                    SELECT id FROM findings WHERE fingerprint = $1
                    ORDER BY last_seen_at DESC LIMIT 1
                )
                RETURNING id
            """, suffix)
            if result:
                deleted_id = result['id']

        if not deleted_id:
            raise HTTPException(status_code=404, detail="Finding not found")

    return {'id': str(deleted_id), 'status': 'deleted'}


class FindingsCleanup(BaseModel):
    older_than_days: int = Field(..., ge=1)
    status: Optional[str] = None
    root_domain: Optional[str] = None
    dry_run: bool = True


@app.post("/findings/cleanup")
async def cleanup_findings(request: FindingsCleanup):
    """Delete old findings by age, optionally filtered by status and domain."""
    async with db_pool.acquire() as conn:
        where = "f.last_seen_at < NOW() - INTERVAL '1 day' * $1"
        params: list = [request.older_than_days]
        idx = 2

        if request.status:
            where += f" AND f.status = ${idx}"
            params.append(request.status)
            idx += 1

        if request.root_domain:
            where += f" AND t.root_domain = ${idx}"
            params.append(request.root_domain)
            idx += 1

        if request.dry_run:
            count = await conn.fetchval(f"""
                SELECT COUNT(*)
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE {where}
            """, *params)
            return {'would_delete': count, 'dry_run': True}
        else:
            # Use subquery to select IDs, then delete by ID
            ids = await conn.fetch(f"""
                SELECT f.id
                FROM findings f
                LEFT JOIN targets t ON f.target_id = t.id
                WHERE {where}
            """, *params)
            if ids:
                id_list = [r['id'] for r in ids]
                await conn.execute(
                    "DELETE FROM findings WHERE id = ANY($1)", id_list
                )
            return {'deleted': len(ids), 'dry_run': False}


@app.post("/findings/bulk")
async def bulk_update_findings(finding_ids: list[str], status: str, notes: Optional[str] = None):
    """Bulk update finding statuses."""
    async with db_pool.acquire() as conn:
        ids = [uuid.UUID(fid) for fid in finding_ids]
        result = await conn.execute("""
            UPDATE findings
            SET status = $1, notes = COALESCE($2, notes), updated_at = NOW()
            WHERE id = ANY($3)
        """, status, notes, ids)

    return {'updated': len(finding_ids), 'status': status}


@app.post("/findings/manual")
async def create_manual_finding(request: ManualFindingCreate):
    """
    Create a finding from manual testing.

    Use this endpoint to record vulnerabilities discovered during manual
    penetration testing, bug bounty hunting, or AI-assisted security sessions.

    The finding will be linked to the target (created if it doesn't exist).
    """
    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if request.severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Normalize target URL
    from urllib.parse import urlparse
    target_url = request.target.strip()
    if not target_url.startswith(('http://', 'https://')):
        target_url = f"https://{target_url}"

    parsed = urlparse(target_url)
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid target URL")

    # Normalize to origin (scheme + host)
    normalized_target = f"{parsed.scheme}://{parsed.netloc}"

    # Generate fingerprint for deduplication
    fingerprint_source = f"{normalized_target}:{request.title}:{request.severity}"
    if request.url:
        fingerprint_source += f":{request.url}"
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:32]

    async with db_pool.acquire() as conn:
        # Get or create target
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1",
            normalized_target
        )

        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source)
                VALUES ($1, $2, $3, 'manual')
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname)

        # Check for existing finding with same fingerprint
        existing = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE fingerprint = $1 AND target_id = $2",
            fingerprint, target_id
        )

        if existing:
            # Update last_seen and potentially resurface
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings
                    SET status = 'active', last_seen_at = NOW(),
                        resurfaced_count = resurfaced_count + 1, updated_at = NOW()
                    WHERE id = $1
                """, existing['id'])
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'resurfaced',
                    'message': 'Existing finding resurfaced'
                }
            else:
                await conn.execute(
                    "UPDATE findings SET last_seen_at = NOW() WHERE id = $1",
                    existing['id']
                )
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'duplicate',
                    'message': 'Finding already exists'
                }

        # Build evidence JSON if provided
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation

        # Create new finding
        finding_id = await conn.fetchval("""
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity,
                cvss_score, tool, cwe, url, evidence, request, response,
                notes, source, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'manual', 'active'
            )
            RETURNING id
        """,
            target_id,
            fingerprint,
            request.title,
            request.description,
            request.severity.lower(),
            request.cvss_score,
            request.category or 'manual',
            request.cwe,
            request.url or normalized_target,
            json.dumps(evidence_json) if evidence_json else None,
            request.request,
            request.response,
            request.notes
        )

        # Update target finding count
        await conn.execute("""
            UPDATE targets SET
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = $1 AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = $1
        """, target_id)

    return {
        'id': str(finding_id),
        'fingerprint': fingerprint,
        'target_id': str(target_id),
        'target': normalized_target,
        'status': 'created',
        'message': 'Finding created successfully'
    }


# ============================================================
# DISCOVERY (Subdomain Enumeration)
# ============================================================

@app.post("/discovery")
async def start_discovery(root_domain: str):
    """Start subdomain discovery for a domain."""
    r = get_redis()
    job_id = str(uuid.uuid4())
    discovery_id = str(uuid.uuid4())

    async with db_pool.acquire() as conn:
        await conn.execute("""
            INSERT INTO discovery_runs (id, root_domain, status)
            VALUES ($1, $2, 'pending')
        """, uuid.UUID(discovery_id), root_domain)

    # Queue the discovery job
    job_data = {
        'job_id': job_id,
        'discovery_id': discovery_id,
        'type': 'discovery',
        'root_domain': root_domain,
        'submitted_at': datetime.utcnow().isoformat()
    }
    r.rpush(QUEUE_NAME, json.dumps(job_data))

    return {
        'discovery_id': discovery_id,
        'job_id': job_id,
        'root_domain': root_domain,
        'status': 'queued'
    }


@app.get("/discovery")
async def list_discovery_runs(limit: int = 20):
    """List discovery runs."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT * FROM discovery_runs
            ORDER BY created_at DESC LIMIT $1
        """, limit)

    return {'discovery_runs': [dict(r) for r in rows]}


@app.get("/discovery/{discovery_id}")
async def get_discovery(discovery_id: str):
    """Get discovery run details."""
    async with db_pool.acquire() as conn:
        discovery = await conn.fetchrow(
            "SELECT * FROM discovery_runs WHERE id = $1", uuid.UUID(discovery_id)
        )
        if not discovery:
            raise HTTPException(status_code=404, detail="Discovery run not found")

    return dict(discovery)


# ============================================================
# WORKER MANAGEMENT
# ============================================================

class WorkerScaleRequest(BaseModel):
    count: int = Field(..., ge=1, le=20, description="Number of workers (1-20)")


def docker_socket_request(method: str, path: str, body: dict = None) -> tuple[int, dict | list]:
    """Send HTTP request to Docker socket API.

    Args:
        method: HTTP method (GET, POST, DELETE)
        path: API path (e.g., /containers/json)
        body: Optional JSON body for POST requests

    Returns:
        Tuple of (status_code, response_data)
    """
    import socket as sock_module
    import json as json_module

    docker_socket = "/var/run/docker.sock"
    s = sock_module.socket(sock_module.AF_UNIX, sock_module.SOCK_STREAM)
    s.settimeout(30)
    s.connect(docker_socket)

    if body:
        body_str = json_module.dumps(body)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: localhost\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body_str)}\r\n"
            f"Connection: close\r\n"
            f"\r\n{body_str}"
        )
    else:
        request = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"

    s.sendall(request.encode())

    # Read response
    response = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        response += chunk
    s.close()

    # Parse HTTP response (bytes-safe for chunked payloads).
    status_code = 0
    response_body = {}

    header_bytes, sep, body_bytes = response.partition(b"\r\n\r\n")
    header_text = header_bytes.decode("iso-8859-1", errors="ignore")

    if header_text:
        status_line = header_text.split("\r\n", 1)[0]
        parts = status_line.split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

    if sep:
        header_lines = header_text.lower().split("\r\n")
        is_chunked = any(
            line.startswith("transfer-encoding:") and "chunked" in line
            for line in header_lines
        )

        if is_chunked:
            # Parse chunked encoding from raw bytes:
            # size\r\ndata\r\nsize\r\ndata\r\n...0\r\n\r\n
            assembled = bytearray()
            remaining = body_bytes
            while remaining:
                line_end = remaining.find(b"\r\n")
                if line_end == -1:
                    break
                size_line = remaining[:line_end].decode("ascii", errors="ignore")
                remaining = remaining[line_end + 2:]
                size_str = size_line.split(";", 1)[0].strip()
                if not size_str:
                    break
                try:
                    chunk_size = int(size_str, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    break
                if len(remaining) < chunk_size:
                    break
                assembled.extend(remaining[:chunk_size])
                remaining = remaining[chunk_size:]
                if remaining.startswith(b"\r\n"):
                    remaining = remaining[2:]
            body_bytes = bytes(assembled)

        if body_bytes.strip():
            try:
                response_body = json_module.loads(body_bytes.decode("utf-8", errors="ignore"))
            except json_module.JSONDecodeError:
                response_body = {}

    return status_code, response_body


def get_compose_context(containers: list) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Infer compose project, network, and image from existing containers."""
    if not containers or not isinstance(containers, list):
        return None, None, None

    def extract_context(c: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
        labels = c.get("Labels", {}) or {}
        project = labels.get("com.docker.compose.project")
        image = c.get("Image")
        networks = (c.get("NetworkSettings") or {}).get("Networks", {})
        network = next(iter(networks.keys()), None) if networks else None
        if project and image and network:
            return project, network, image
        return None, None, None

    def find_by_service(service: str, running_only: bool) -> tuple[Optional[str], Optional[str], Optional[str]]:
        for c in containers:
            labels = c.get("Labels", {}) or {}
            if labels.get("com.docker.compose.service") != service:
                continue
            if running_only and c.get("State") != "running":
                continue
            project, network, image = extract_context(c)
            if project and network and image:
                return project, network, image
        return None, None, None

    preferred_services = ("worker", "api")
    for service in preferred_services:
        project, network, image = find_by_service(service, running_only=True)
        if project and network and image:
            return project, network, image
        project, network, image = find_by_service(service, running_only=False)
        if project and network and image:
            return project, network, image

    for c in containers:
        if c.get("State") != "running":
            continue
        project, network, image = extract_context(c)
        if project and network and image:
            return project, network, image

    for c in containers:
        project, network, image = extract_context(c)
        if project and network and image:
            return project, network, image

    return None, None, None


@app.get("/workers")
async def get_workers():
    """Get current worker count and status via Docker socket API."""
    import socket
    import json as json_module

    docker_socket = "/var/run/docker.sock"

    try:
        # Connect to Docker socket directly
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(docker_socket)

        # Request container list filtered by name
        request = (
            "GET /containers/json?all=true&filters=%7B%22name%22%3A%5B%22worker%22%5D%7D HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())

        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()

        # Parse HTTP response
        response_str = response.decode('utf-8')
        if '\r\n\r\n' in response_str:
            headers, body = response_str.split('\r\n\r\n', 1)
            # Handle chunked transfer encoding
            if 'Transfer-Encoding: chunked' in headers:
                # Simple chunked parsing - get content after first chunk size
                lines = body.split('\r\n')
                body = '\r\n'.join(lines[1:]) if len(lines) > 1 else ''
                # Find JSON array
                if '[' in body:
                    body = body[body.find('['):]
                    if ']' in body:
                        body = body[:body.rfind(']')+1]
        else:
            body = response_str

        containers = json_module.loads(body) if body.strip().startswith('[') else []

        # Filter and format worker containers (only shakerscan workers)
        worker_list = []
        for c in containers:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else 'unknown'
            if 'shakerscan' in name.lower() and 'worker' in name.lower():
                state = c.get('State', 'unknown')
                worker_list.append({
                    "name": name,
                    "status": state,
                    "health": c.get('Status', '')
                })

        running = len([w for w in worker_list if w.get("status") == "running"])

        return {
            "count": running,
            "workers": worker_list,
            "max_allowed": 20
        }
    except FileNotFoundError:
        return {
            "count": -1,
            "error": "Docker socket not available",
            "workers": []
        }
    except Exception as e:
        return {
            "count": -1,
            "error": f"Failed to query Docker: {str(e)}",
            "workers": []
        }


@app.post("/workers")
async def scale_workers(request: WorkerScaleRequest):
    """Scale the number of worker containers using Docker socket API."""
    import urllib.parse

    try:
        count = request.count
        if count < 1 or count > 20:
            raise HTTPException(400, "Workers must be between 1 and 20")

        # Get current workers via socket API
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Filter to shakerscan workers only (exclude gungnir-worker)
        workers = []
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'shakerscan' in name.lower() and 'worker' in name.lower() and 'gungnir' not in name.lower():
                workers.append(c)

        running = [c for c in workers if c.get('State') == 'running']
        stopped = [c for c in workers if c.get('State') != 'running']
        current_count = len(running)

        if count == current_count:
            return {
                "status": "success",
                "target_count": current_count,
                "message": f"Already at {count} worker(s)"
            }

        if count > current_count:
            # Scale up - start stopped workers first
            started = 0
            for container in stopped[:count - current_count]:
                container_id = container.get('Id')
                start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")
                if start_status in [204, 304]:  # 204 = started, 304 = already running
                    started += 1

            new_count = current_count + started

            # If we still need more workers, create new containers
            needed = count - new_count
            if needed > 0:
                # Get compose context from existing workers
                project, network, image = get_compose_context(workers)
                if project and network and image:
                    # Find the highest worker number
                    existing_numbers = []
                    for w in workers:
                        names = w.get('Names', [])
                        name = names[0].lstrip('/') if names else ''
                        # Extract number from name like "shakerscan-oss-worker-3"
                        if '-worker-' in name:
                            try:
                                num = int(name.split('-worker-')[-1])
                                existing_numbers.append(num)
                            except ValueError:
                                pass

                    next_num = max(existing_numbers) + 1 if existing_numbers else 1
                    created = 0

                    # Get env vars and bind mounts from an existing worker (via inspect)
                    existing_env = [f"REDIS_URL={REDIS_URL}", f"DATABASE_URL={DATABASE_URL}"]
                    existing_binds = [f"{os.environ.get('HOST_RESULTS_PATH', '/tmp/scanner-results')}:/results:rw"]

                    if workers:
                        # Inspect first running worker to get full config
                        ref_worker = workers[0]
                        ref_id = ref_worker.get("Id", "")
                        if ref_id:
                            inspect_status, inspect_data = docker_socket_request("GET", f"/containers/{ref_id}/json")
                            if inspect_status == 200 and isinstance(inspect_data, dict):
                                # Copy env vars from existing worker
                                config_env = inspect_data.get("Config", {}).get("Env", [])
                                if config_env:
                                    existing_env = config_env

                                # Copy bind mounts from existing worker
                                mounts = inspect_data.get("Mounts", [])
                                binds = []
                                for mount in mounts:
                                    if mount.get("Type") == "bind":
                                        src = mount.get("Source", "")
                                        dst = mount.get("Destination", "")
                                        mode = "ro" if not mount.get("RW", True) else "rw"
                                        if src and dst:
                                            binds.append(f"{src}:{dst}:{mode}")
                                if binds:
                                    existing_binds = binds

                    for i in range(needed):
                        worker_num = next_num + i
                        name = f"{project}-worker-{worker_num}"

                        labels = {
                            "com.docker.compose.project": project,
                            "com.docker.compose.service": "worker",
                            "com.docker.compose.oneoff": "False",
                            "com.docker.compose.container-number": str(worker_num)
                        }

                        create_body = {
                            "Image": image,
                            "Cmd": ["python3", "/app/worker.py"],
                            "Env": existing_env,
                            "Labels": labels,
                            "HostConfig": {
                                "NetworkMode": network,
                                "RestartPolicy": {"Name": "unless-stopped"},
                                "Binds": existing_binds
                            }
                        }

                        create_path = f"/containers/create?name={urllib.parse.quote(name)}"
                        create_status, create_data = docker_socket_request("POST", create_path, create_body)

                        if create_status == 201:
                            container_id = create_data.get("Id")
                            # Start the new container
                            start_status, _ = docker_socket_request("POST", f"/containers/{container_id}/start")
                            if start_status in [204, 304]:
                                created += 1
                                new_count += 1

                    if created > 0:
                        # Return success only if we reached the target, otherwise partial
                        status = "success" if new_count >= count else "partial"
                        return {
                            "status": status,
                            "target_count": new_count,
                            "message": f"Scaled to {new_count} worker(s) (started {started}, created {created})"
                        }

            if new_count < count:
                return {
                    "status": "partial",
                    "target_count": new_count,
                    "message": f"Could only scale to {new_count} workers"
                }

            return {
                "status": "success",
                "target_count": new_count,
                "message": f"Scaled to {new_count} worker(s)"
            }

        else:
            # Scale down - stop excess workers
            to_stop = running[count:]
            stopped_count = 0
            for container in to_stop:
                container_id = container.get('Id')
                stop_status, _ = docker_socket_request("POST", f"/containers/{container_id}/stop")
                if stop_status in [204, 304]:  # 204 = stopped, 304 = already stopped
                    stopped_count += 1

            return {
                "status": "success",
                "target_count": count,
                "message": f"Scaled down to {count} worker(s) (stopped {stopped_count})"
            }

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh scale <N>"
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to scale workers: {str(e)}")


# ============================================================
# GUNGNIR CT MONITOR
# ============================================================

@app.get("/gungnir/status")
async def gungnir_status():
    """Get Gungnir CT monitor status."""
    r = get_redis()
    status = r.hgetall("gungnir:status")

    # Decode bytes if needed
    if status and isinstance(next(iter(status.values()), None), bytes):
        status = {k.decode() if isinstance(k, bytes) else k:
                  v.decode() if isinstance(v, bytes) else v
                  for k, v in status.items()}

    return {
        "running": status.get("running") == "true" if status else False,
        "domains_monitored": int(status.get("domains_monitored", 0)) if status else 0,
        "subdomains_found": int(status.get("subdomains_found", 0)) if status else 0,
        "session_found": int(status.get("session_found", 0)) if status else 0,
        "last_discovery": status.get("last_discovery") if status else None,
        "started_at": status.get("started_at") if status else None,
        "uptime_seconds": int(status.get("uptime_seconds", 0)) if status else 0,
    }


@app.post("/gungnir/start")
async def gungnir_start():
    """Start Gungnir CT monitor worker using Docker socket API."""
    import urllib.parse

    r = get_redis()

    try:
        def ensure_gungnir_container() -> dict:
            """Find or create a gungnir container from current compose context."""
            status_code, all_containers = docker_socket_request("GET", "/containers/json?all=true")
            if status_code != 200:
                raise HTTPException(500, f"Failed to query containers: status {status_code}")

            project, network, image = get_compose_context(all_containers if isinstance(all_containers, list) else [])
            if not image or not network:
                raise HTTPException(
                    status_code=404,
                    detail="Gungnir container not found and auto-create failed. Start the stack with ./scanner.sh start first."
                )

            # Look for gungnir-worker image specifically, fall back to worker image.
            gungnir_image = None
            if project:
                img_status, images = docker_socket_request("GET", "/images/json")
                if img_status == 200 and isinstance(images, list):
                    gungnir_image_name = f"{project}-gungnir-worker"
                    for img in images:
                        repo_tags = img.get("RepoTags") or []
                        for tag in repo_tags:
                            if gungnir_image_name in tag:
                                gungnir_image = tag
                                break
                        if gungnir_image:
                            break

            image = gungnir_image or image
            name = f"{project}-gungnir-worker-1" if project else "gungnir-worker"
            labels = {}
            if project:
                labels = {
                    "com.docker.compose.project": project,
                    "com.docker.compose.service": "gungnir-worker",
                    "com.docker.compose.oneoff": "False"
                }

            create_body = {
                "Image": image,
                "Cmd": ["python3", "/app/gungnir_worker.py"],
                "Env": [f"REDIS_URL={REDIS_URL}", f"DATABASE_URL={DATABASE_URL}"],
                "Labels": labels,
                "HostConfig": {
                    "NetworkMode": network,
                    "RestartPolicy": {"Name": "unless-stopped"}
                }
            }

            create_path = f"/containers/create?name={urllib.parse.quote(name)}"
            create_status, create_data = docker_socket_request("POST", create_path, create_body)
            if create_status not in (201, 409):
                raise HTTPException(500, f"Failed to create Gungnir container: status {create_status}")

            container_id = create_data.get("Id") if isinstance(create_data, dict) else None
            if not container_id and create_status == 409:
                inspect_status, inspect_data = docker_socket_request("GET", f"/containers/{urllib.parse.quote(name)}/json")
                if inspect_status == 200 and isinstance(inspect_data, dict):
                    container_id = inspect_data.get("Id")

            if not container_id:
                raise HTTPException(500, "Failed to resolve Gungnir container ID after creation.")

            return {"Id": container_id, "State": "created"}

        # Find gungnir container via socket API
        filters = urllib.parse.quote('{"name":["gungnir"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Find the gungnir-worker container
        gungnir = None
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'gungnir' in name.lower():
                gungnir = c
                break

        if not gungnir:
            gungnir = ensure_gungnir_container()

        if gungnir.get('State') == 'running':
            return {
                "status": "already_running",
                "message": "Gungnir is already running"
            }

        # Start the container
        container_id = gungnir.get('Id')
        start_status, start_data = docker_socket_request("POST", f"/containers/{container_id}/start")

        if start_status in [204, 304]:  # 204 = started, 304 = already started
            # Update Redis status
            r.hset("gungnir:status", "running", "true")
            return {
                "status": "started",
                "message": "Gungnir CT monitor started successfully"
            }

        # Self-heal stale containers (e.g., old network ID no longer exists).
        if start_status == 404 and container_id:
            docker_socket_request("DELETE", f"/containers/{container_id}?force=true")
            gungnir = ensure_gungnir_container()
            container_id = gungnir.get('Id')
            start_status, start_data = docker_socket_request("POST", f"/containers/{container_id}/start")
            if start_status in [204, 304]:
                r.hset("gungnir:status", "running", "true")
                return {
                    "status": "started",
                    "message": "Gungnir CT monitor started successfully"
                }

        docker_message = ""
        if isinstance(start_data, dict) and start_data.get("message"):
            docker_message = f" ({start_data.get('message')})"
        raise HTTPException(500, f"Failed to start Gungnir: Docker returned status {start_status}{docker_message}")

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh gungnir start"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start Gungnir: {str(e)}")


@app.post("/gungnir/stop")
async def gungnir_stop():
    """Stop Gungnir CT monitor worker using Docker socket API."""
    import urllib.parse

    r = get_redis()

    try:
        # Find gungnir container via socket API
        filters = urllib.parse.quote('{"name":["gungnir"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}"
        )

        if status_code != 200:
            raise HTTPException(500, f"Failed to query containers: status {status_code}")

        # Find the gungnir-worker container
        gungnir = None
        for c in containers if isinstance(containers, list) else []:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else ''
            if 'gungnir' in name.lower():
                gungnir = c
                break

        if not gungnir:
            # Update Redis status anyway
            r.hset("gungnir:status", "running", "false")
            return {
                "status": "not_found",
                "message": "Gungnir container not found"
            }

        if gungnir.get('State') != 'running':
            # Update Redis status
            r.hset("gungnir:status", "running", "false")
            return {
                "status": "already_stopped",
                "message": "Gungnir is not running"
            }

        # Stop the container
        container_id = gungnir.get('Id')
        stop_status, _ = docker_socket_request("POST", f"/containers/{container_id}/stop")

        # Update Redis status
        r.hset("gungnir:status", "running", "false")

        if stop_status in [204, 304]:  # 204 = stopped, 304 = already stopped
            return {
                "status": "stopped",
                "message": "Gungnir CT monitor stopped"
            }
        else:
            raise HTTPException(500, f"Failed to stop Gungnir: Docker returned status {stop_status}")

    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Docker socket not accessible. Use CLI: ./scanner.sh gungnir stop"
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to stop Gungnir: {str(e)}")


# ============================================================
# INTERACTIVE SESSIONS (AI Security Testing)
# ============================================================

# Import session manager
from session_manager import InteractiveSessionManager, InteractiveSession


class SessionStartRequest(BaseModel):
    target: str


class SessionActionRequest(BaseModel):
    action: str  # navigate, click, fill, set_auth, register, login, submit, wait, extract
    user: Optional[str] = "default"
    data: Optional[dict] = None


class EndpointTestRequest(BaseModel):
    endpoint: str
    method: str = "GET"
    as_user: Optional[str] = None
    body: Optional[dict] = None
    allow_out_of_scope: bool = False  # Set True to allow cross-origin requests (SSRF risk)


@app.post("/session/start")
async def start_session(request: SessionStartRequest):
    """
    Start an interactive browser session for AI-assisted security testing.

    This creates a headless browser session that can be used for:
    - Taking screenshots to analyze UI
    - Navigating and interacting with the application
    - Registering and logging in test users
    - Testing endpoints with different user contexts (BOLA testing)

    Returns a session_id to use in subsequent requests.

    Unlike scan endpoints which strip paths, sessions preserve the full URL
    so you can start at specific pages (e.g., /login).
    """
    # Validate and normalize URL (but preserve path for sessions)
    from urllib.parse import urlparse, urlunparse
    raw_target = (request.target or "").strip()
    if not raw_target:
        raise HTTPException(status_code=400, detail="Target URL required")

    # Add scheme if missing
    has_scheme = "://" in raw_target
    url_to_parse = raw_target if has_scheme else f"https://{raw_target}"

    try:
        parsed = urlparse(url_to_parse)
        # Validate scheme
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail=f"Invalid scheme '{parsed.scheme}': only http/https allowed")
        # Validate host
        if not parsed.hostname:
            raise HTTPException(status_code=400, detail="Invalid target URL: no hostname")
        # Reject URLs with credentials (prevents credential leakage in logs/artifacts)
        if parsed.username or parsed.password:
            raise HTTPException(status_code=400, detail="URLs with embedded credentials (user:pass@host) are not allowed")
        # Access port early to catch malformed URLs
        _ = parsed.port
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {e}")

    # Reconstruct URL preserving path (but normalizing host to lowercase)
    normalized_target = urlunparse((
        parsed.scheme,
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.params,
        parsed.query,
        ""  # Strip fragment
    ))

    try:
        manager = await InteractiveSessionManager.get_instance()
        session = await manager.create_session(normalized_target, RESULTS_DIR)
        result = await session.start()

        if not result.get("success"):
            await manager.close_session(session.session_id)
            raise HTTPException(status_code=500, detail=result.get("error", "Failed to start session"))

        return result

    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start session: {str(e)}")


@app.get("/session/{session_id}")
async def get_session_state(session_id: str):
    """Get current state of an interactive session."""
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    return await session.get_state()


@app.post("/session/{session_id}/screenshot")
async def session_screenshot(
    session_id: str,
    full_page: bool = False,
    user: str = "default"
):
    """
    Capture a screenshot of the current page.

    Args:
        session_id: The session ID
        full_page: Capture full scrollable page (default: viewport only)
        user: Which user's browser context to screenshot (default: "default")

    Returns base64-encoded PNG image.
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    result = await session.screenshot(full_page=full_page, user=user)

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Screenshot failed"))

    return result


@app.get("/session/{session_id}/screenshot.png")
async def session_screenshot_raw(
    session_id: str,
    full_page: bool = False,
    user: str = "default"
):
    """
    Capture a screenshot and return raw PNG bytes.

    This endpoint returns the image directly (not JSON), making it easy to
    save to a file with curl:
        curl -s "http://localhost:8080/session/{id}/screenshot.png" -o screenshot.png

    Args:
        session_id: The session ID
        full_page: Capture full scrollable page (default: viewport only)
        user: Which user's browser context to screenshot (default: "default")
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    screenshot_bytes = await session.screenshot_raw(full_page=full_page, user=user)

    if screenshot_bytes is None:
        raise HTTPException(status_code=500, detail=f"Screenshot failed for user '{user}'")

    return Response(content=screenshot_bytes, media_type="image/png")


@app.post("/session/{session_id}/action")
async def session_action(session_id: str, request: SessionActionRequest):
    """
    Execute a browser action in the session.

    Supported actions:
    - navigate: Go to URL (data: {"url": "/path"})
    - click: Click element (data: {"selector": "button#submit"})
    - fill: Fill input (data: {"selector": "input#email", "value": "test@example.com"})
    - set_auth: Set auth context (data: {"token":"..."} or {"auth_header":"Bearer ..."} or {"cookies":{"session":"..."}})
    - register: Register user (data: {"email": "...", "password": "..."})
    - login: Login user (data: {"email": "...", "password": "..."})
    - submit: Submit form (data: {"selector": "form"})
    - wait: Wait for selector/timeout (data: {"selector": "...", "timeout": 5000})
    - extract: Extract data (data: {"selector": "...", "attribute": "href"})

    The 'user' parameter creates separate browser contexts for multi-user testing.
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    result = await session.action({
        "action": request.action,
        "user": request.user,
        "data": request.data or {}
    })

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Action failed"))

    return result


@app.post("/session/{session_id}/test-endpoint")
async def session_test_endpoint(session_id: str, request: EndpointTestRequest):
    """
    Test a specific API endpoint with optional user authentication.

    This is the core BOLA testing endpoint. It makes a request to the
    specified endpoint using the authentication context of 'as_user'.

    By default, only same-origin requests are allowed to prevent SSRF.
    Set allow_out_of_scope=True to test cross-origin endpoints.

    Example BOLA test:
    1. Login as user1, discover resource at /api/items/42
    2. Login as user2
    3. Call this endpoint with endpoint="/api/items/42" and as_user="user2"
    4. If status is 200, BOLA vulnerability confirmed

    Args:
        endpoint: API endpoint path (e.g., "/api/items/42")
        method: HTTP method (GET, POST, PUT, DELETE, etc.)
        as_user: Test as this user's session (uses their cookies/token)
        body: Request body for POST/PUT/PATCH
        allow_out_of_scope: Allow cross-origin requests (default: False for SSRF protection)
    """
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    result = await session.test_endpoint(
        endpoint=request.endpoint,
        method=request.method,
        as_user=request.as_user,
        body=request.body,
        allow_out_of_scope=request.allow_out_of_scope
    )

    # Don't raise exception on request failure - return the result
    # so Claude can analyze the access control behavior
    return result


@app.delete("/session/{session_id}")
async def end_session(session_id: str):
    """
    End an interactive session and cleanup resources.

    This closes the browser and frees memory. Sessions also auto-expire
    after 30 minutes of inactivity.
    """
    manager = await InteractiveSessionManager.get_instance()
    closed = await manager.close_session(session_id)

    if not closed:
        raise HTTPException(status_code=404, detail="Session not found")

    return {
        "status": "closed",
        "session_id": session_id,
        "message": "Session ended successfully"
    }


@app.get("/sessions")
async def list_sessions():
    """List all active interactive sessions."""
    manager = await InteractiveSessionManager.get_instance()

    sessions = []
    for session_id, session in manager.sessions.items():
        sessions.append({
            "session_id": session_id,
            "target_url": session.state.target_url,
            "created_at": session.state.created_at.isoformat(),
            "last_activity": session.state.last_activity.isoformat(),
            "is_expired": session.is_expired()
        })

    return {
        "sessions": sessions,
        "count": len(sessions)
    }


@app.post("/session/{session_id}/findings")
async def create_session_finding(session_id: str, request: SessionFindingCreate):
    """
    Create a finding from an AI security session.

    The target is automatically populated from the session.
    Use this during interactive testing to record discovered vulnerabilities.

    Example:
        curl -X POST "http://localhost:8080/session/{id}/findings" \\
          -H "Content-Type: application/json" \\
          -d '{
            "title": "BOLA on Basket API",
            "severity": "critical",
            "description": "User2 can access User1 basket via /rest/basket/{id}",
            "category": "BOLA",
            "cwe": "CWE-639",
            "evidence": "GET /rest/basket/9 with User2 token returns User1 data"
          }'
    """
    # Get session to extract target
    manager = await InteractiveSessionManager.get_instance()
    session = await manager.get_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Session not found or expired")

    target_url = session.target_url

    # Validate severity
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if request.severity.lower() not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {', '.join(valid_severities)}"
        )

    # Normalize target URL to origin
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    normalized_target = f"{parsed.scheme}://{parsed.netloc}"

    # Generate fingerprint for deduplication
    fingerprint_source = f"{normalized_target}:{request.title}:{request.severity}"
    if request.url:
        fingerprint_source += f":{request.url}"
    fingerprint = hashlib.sha256(fingerprint_source.encode()).hexdigest()[:32]

    async with db_pool.acquire() as conn:
        # Get or create target
        target = await conn.fetchrow(
            "SELECT id FROM targets WHERE url = $1",
            normalized_target
        )

        if target:
            target_id = target['id']
        else:
            # Create new target
            target_id = await conn.fetchval("""
                INSERT INTO targets (url, name, root_domain, discovery_source)
                VALUES ($1, $2, $3, 'ai_session')
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname)

        # Check for existing finding with same fingerprint
        existing = await conn.fetchrow(
            "SELECT id, status FROM findings WHERE fingerprint = $1 AND target_id = $2",
            fingerprint, target_id
        )

        if existing:
            # Update last_seen and potentially resurface
            if existing['status'] == 'resolved':
                await conn.execute("""
                    UPDATE findings
                    SET status = 'active', last_seen_at = NOW(),
                        resurfaced_count = resurfaced_count + 1,
                        session_id = $2, updated_at = NOW()
                    WHERE id = $1
                """, existing['id'], session_id)
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'resurfaced',
                    'message': 'Existing finding resurfaced'
                }
            else:
                await conn.execute(
                    "UPDATE findings SET last_seen_at = NOW(), session_id = $2 WHERE id = $1",
                    existing['id'], session_id
                )
                return {
                    'id': str(existing['id']),
                    'fingerprint': fingerprint,
                    'status': 'duplicate',
                    'message': 'Finding already exists'
                }

        # Build evidence JSON if provided
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation

        # Create new finding
        finding_id = await conn.fetchval("""
            INSERT INTO findings (
                target_id, fingerprint, title, description, severity,
                cvss_score, tool, cwe, url, evidence, request, response,
                notes, source, session_id, status
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                'ai_session', $14, 'active'
            )
            RETURNING id
        """,
            target_id,
            fingerprint,
            request.title,
            request.description,
            request.severity.lower(),
            request.cvss_score,
            request.category or 'ai_session',
            request.cwe,
            request.url or normalized_target,
            json.dumps(evidence_json) if evidence_json else None,
            request.request,
            request.response,
            request.notes,
            session_id
        )

        # Update target finding count
        await conn.execute("""
            UPDATE targets SET
                active_findings_count = (
                    SELECT COUNT(*) FROM findings
                    WHERE target_id = $1 AND status = 'active'
                ),
                updated_at = NOW()
            WHERE id = $1
        """, target_id)

    return {
        'id': str(finding_id),
        'fingerprint': fingerprint,
        'target_id': str(target_id),
        'target': normalized_target,
        'session_id': session_id,
        'status': 'created',
        'message': 'Finding created successfully'
    }


# ============================================================
# QUEUE MANAGEMENT
# ============================================================

@app.get("/queue/stats")
async def queue_stats():
    """Get queue statistics."""
    r = get_redis()
    cached = r.get("queue:stats_cache")
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass
    now = datetime.utcnow()

    completed = 0
    running = 0
    queued = 0
    failed = 0
    retest_completed = 0
    retest_running = 0
    retest_queued = 0
    retest_failed = 0

    for key in r.scan_iter("job:*"):
        job_data = r.hgetall(key)
        if not job_data:
            continue

        # Redis client uses decode_responses=True, so values are already strings
        status_str = job_data.get('status', '')

        if status_str == 'running':
            heartbeat = job_data.get('heartbeat', '')
            if heartbeat:
                try:
                    last_beat = datetime.fromisoformat(heartbeat)
                    if now - last_beat > timedelta(minutes=HEARTBEAT_TIMEOUT_MINUTES):
                        r.hset(key, 'status', 'failed')
                        r.hset(key, 'error', 'Worker stopped responding')
                        failed += 1
                        continue
                except ValueError:
                    pass
            running += 1
        elif status_str == 'completed':
            completed += 1
        elif status_str == 'queued':
            queued += 1
        elif status_str == 'failed':
            failed += 1

    for key in r.scan_iter("retest_job:*"):
        job_data = r.hgetall(key)
        if not job_data:
            continue

        status_str = job_data.get('status', '')

        if status_str == 'running':
            started_at = job_data.get('started_at', '')
            if started_at:
                try:
                    started = datetime.fromisoformat(started_at)
                    if now - started > timedelta(minutes=RETEST_RUNNING_TIMEOUT_MINUTES):
                        r.hset(key, mapping={
                            'status': 'failed',
                            'error': 'Retest worker did not complete in time',
                        })
                        retest_failed += 1
                        continue
                except ValueError:
                    pass
            retest_running += 1
        elif status_str == 'completed':
            retest_completed += 1
        elif status_str == 'queued':
            retest_queued += 1
        elif status_str == 'failed':
            retest_failed += 1

    result = {
        'pending': r.llen(QUEUE_NAME),
        'queued': queued,
        'running': running,
        'completed': completed,
        'failed': failed,
        'retest_pending': r.llen(RETEST_QUEUE_NAME),
        'retest_queued': retest_queued,
        'retest_running': retest_running,
        'retest_completed': retest_completed,
        'retest_failed': retest_failed,
    }
    try:
        r.setex("queue:stats_cache", 5, json.dumps(result))
    except Exception:
        pass
    return result


@app.delete("/queue/clear")
async def clear_queue(include_retests: bool = False):
    """Clear all pending scan jobs. Optionally clear retest jobs too."""
    r = get_redis()
    count = r.llen(QUEUE_NAME)
    r.delete(QUEUE_NAME)
    retest_cleared = 0
    if include_retests:
        retest_cleared = r.llen(RETEST_QUEUE_NAME)
        r.delete(RETEST_QUEUE_NAME)
    return {'cleared': count, 'retest_cleared': retest_cleared}


# ============================================================
# RESULTS (File-based)
# ============================================================

@app.get("/results")
async def list_results(limit: int = 50):
    """List recent scan results from files."""
    if not RESULTS_DIR.exists():
        return {'results': [], 'count': 0}

    results = []
    for target_dir in RESULTS_DIR.iterdir():
        if target_dir.is_dir():
            latest = target_dir / "latest.json"
            if latest.exists():
                try:
                    with open(latest) as fp:
                        data = json.load(fp)
                        results.append({
                            'folder': target_dir.name,
                            'target': data.get('input', {}).get('target'),
                            'score': data.get('result', {}).get('score'),
                            'grade': data.get('result', {}).get('grade'),
                            'timestamp': data.get('timestamp_utc'),
                        })
                except Exception:
                    pass

    results.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return {'results': results[:limit], 'count': len(results)}


@app.get("/results/{target_folder}/latest")
async def get_latest_result(target_folder: str):
    """Get latest scan result for a target."""
    filepath = RESULTS_DIR / target_folder / "latest.json"
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Result not found")
    with open(filepath) as f:
        return json.load(f)


# ============================================================
# SCHEDULES (Recurring Scans)
# ============================================================

@app.get("/schedules")
async def list_schedules(
    target_id: Optional[str] = None,
    is_active: Optional[bool] = None,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List scan schedules."""
    async with db_pool.acquire() as conn:
        query = """
            SELECT s.*, t.url as target_url, t.name as target_name
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE 1=1
        """
        params = []
        param_idx = 1

        if target_id:
            query += f" AND s.target_id = ${param_idx}"
            params.append(uuid.UUID(target_id))
            param_idx += 1

        if is_active is not None:
            query += f" AND s.is_active = ${param_idx}"
            params.append(is_active)
            param_idx += 1

        query += f" ORDER BY s.created_at DESC LIMIT ${param_idx} OFFSET ${param_idx + 1}"
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

    return {
        'schedules': [row_to_dict(r) for r in rows],
        'total': len(rows)
    }


@app.post("/schedules")
async def create_schedule(request: ScheduleCreate):
    """Create a new scan schedule."""
    # Validate frequency
    if request.frequency not in ('daily', 'weekly'):
        raise HTTPException(status_code=400, detail="Frequency must be 'daily' or 'weekly'")

    # Validate time_of_day format
    try:
        parts = request.time_of_day.split(':')
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="time_of_day must be in HH:MM format (00:00 - 23:59)")

    # Validate day_of_week for weekly
    if request.frequency == 'weekly':
        if request.day_of_week is None:
            raise HTTPException(status_code=400, detail="day_of_week is required for weekly schedules (0=Monday, 6=Sunday)")
        if not (0 <= request.day_of_week <= 6):
            raise HTTPException(status_code=400, detail="day_of_week must be 0-6 (Monday-Sunday)")

    # Validate scan_type
    valid_scan_types = ['quick', 'standard', 'deep', 'full', 'aggressive', 'smart']
    if request.scan_type not in valid_scan_types:
        raise HTTPException(status_code=400, detail=f"scan_type must be one of: {', '.join(valid_scan_types)}")

    # Validate timezone
    try:
        ZoneInfo(request.timezone)
    except (KeyError, Exception):
        raise HTTPException(status_code=400, detail=f"Invalid timezone: {request.timezone}")

    async with db_pool.acquire() as conn:
        # Verify target exists
        target = await conn.fetchrow("SELECT id, url FROM targets WHERE id = $1", uuid.UUID(request.target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")

        next_run = calculate_next_run(
            request.frequency,
            request.day_of_week,
            request.time_of_day,
            request.timezone,
            request.jitter_minutes
        )

        schedule_id = await conn.fetchval("""
            INSERT INTO schedules (
                target_id, name, frequency, day_of_week, time_of_day,
                timezone, jitter_minutes, scan_type, scan_options,
                is_active, next_run_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, $10)
            RETURNING id
        """,
            uuid.UUID(request.target_id),
            request.name,
            request.frequency,
            request.day_of_week,
            request.time_of_day,
            request.timezone,
            request.jitter_minutes,
            request.scan_type,
            json.dumps(request.scan_options) if request.scan_options else '{}',
            next_run
        )

    return {
        'id': str(schedule_id),
        'target_url': target['url'],
        'next_run_at': next_run.isoformat(),
        'status': 'created'
    }


@app.get("/schedules/{schedule_id}")
async def get_schedule(schedule_id: str):
    """Get schedule details."""
    async with db_pool.acquire() as conn:
        schedule = await conn.fetchrow("""
            SELECT s.*, t.url as target_url, t.name as target_name
            FROM schedules s
            JOIN targets t ON s.target_id = t.id
            WHERE s.id = $1
        """, uuid.UUID(schedule_id))

        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")

    return row_to_dict(schedule)


@app.patch("/schedules/{schedule_id}")
async def update_schedule(schedule_id: str, request: ScheduleUpdate):
    """Update a schedule."""
    async with db_pool.acquire() as conn:
        # Get existing schedule to check timing field changes
        existing = await conn.fetchrow("SELECT * FROM schedules WHERE id = $1", uuid.UUID(schedule_id))
        if not existing:
            raise HTTPException(status_code=404, detail="Schedule not found")

        updates = []
        params = []
        param_idx = 1
        timing_changed = False

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.frequency is not None:
            if request.frequency not in ('daily', 'weekly'):
                raise HTTPException(status_code=400, detail="Frequency must be 'daily' or 'weekly'")
            updates.append(f"frequency = ${param_idx}")
            params.append(request.frequency)
            param_idx += 1
            timing_changed = True

        if request.day_of_week is not None:
            if not (0 <= request.day_of_week <= 6):
                raise HTTPException(status_code=400, detail="day_of_week must be 0-6")
            updates.append(f"day_of_week = ${param_idx}")
            params.append(request.day_of_week)
            param_idx += 1
            timing_changed = True

        if request.time_of_day is not None:
            try:
                parts = request.time_of_day.split(':')
                h, m = int(parts[0]), int(parts[1])
                if not (0 <= h <= 23 and 0 <= m <= 59):
                    raise ValueError
            except (ValueError, IndexError):
                raise HTTPException(status_code=400, detail="time_of_day must be HH:MM")
            updates.append(f"time_of_day = ${param_idx}")
            params.append(request.time_of_day)
            param_idx += 1
            timing_changed = True

        if request.timezone is not None:
            try:
                ZoneInfo(request.timezone)
            except (KeyError, Exception):
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {request.timezone}")
            updates.append(f"timezone = ${param_idx}")
            params.append(request.timezone)
            param_idx += 1
            timing_changed = True

        if request.scan_type is not None:
            valid_scan_types = ['quick', 'standard', 'deep', 'full', 'aggressive', 'smart']
            if request.scan_type not in valid_scan_types:
                raise HTTPException(status_code=400, detail=f"Invalid scan_type")
            updates.append(f"scan_type = ${param_idx}")
            params.append(request.scan_type)
            param_idx += 1

        if request.scan_options is not None:
            updates.append(f"scan_options = ${param_idx}")
            params.append(json.dumps(request.scan_options))
            param_idx += 1

        if request.jitter_minutes is not None:
            updates.append(f"jitter_minutes = ${param_idx}")
            params.append(request.jitter_minutes)
            param_idx += 1
            timing_changed = True

        if request.is_active is not None:
            updates.append(f"is_active = ${param_idx}")
            params.append(request.is_active)
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        # Recalculate next_run_at if timing fields changed
        if timing_changed:
            freq = request.frequency or existing['frequency']
            dow = request.day_of_week if request.day_of_week is not None else existing['day_of_week']
            tod = request.time_of_day or existing['time_of_day'] or '02:00'
            tz = request.timezone or existing['timezone'] or 'UTC'
            jitter = request.jitter_minutes if request.jitter_minutes is not None else (existing['jitter_minutes'] or 0)
            next_run = calculate_next_run(freq, dow, tod, tz, jitter)
            updates.append(f"next_run_at = ${param_idx}")
            params.append(next_run)
            param_idx += 1

        updates.append("updated_at = NOW()")
        params.append(uuid.UUID(schedule_id))

        query = f"UPDATE schedules SET {', '.join(updates)} WHERE id = ${param_idx} RETURNING id"
        result = await conn.fetchval(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Schedule not found")

    return {'id': schedule_id, 'status': 'updated'}


@app.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    """Delete a schedule."""
    async with db_pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM schedules WHERE id = $1", uuid.UUID(schedule_id)
        )
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Schedule not found")

    return {'id': schedule_id, 'status': 'deleted'}


# ============================================================
# UTILITIES
# ============================================================

def extract_root_domain(url: str) -> str:
    """Extract root domain from URL."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.hostname or parsed.netloc or parsed.path.split('/')[0]
        # Note: parsed.hostname already strips ports and IPv6 brackets
        # Return IPs as-is (no root domain)
        try:
            ipaddress.ip_address(host.strip("[]"))
            return host.strip("[]")
        except ValueError:
            pass
        # Get root domain (last 2 parts)
        parts = host.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    except Exception:
        return url


class TargetNormalizationError(ValueError):
    """Raised when target URL is malformed or invalid."""
    pass


def normalize_target_url(target: str) -> tuple[str, str | None]:
    """
    Normalize target URL to canonical origin (strip path/query/fragment).

    Returns:
        tuple: (normalized_url, warning_note)

    Raises:
        TargetNormalizationError: If URL is malformed (e.g., invalid IPv6)
    """
    from urllib.parse import urlparse
    raw = (target or "").strip()
    if not raw:
        return "", None

    # Parse URL, handling missing scheme
    has_scheme = "://" in raw
    url_to_parse = raw if has_scheme else f"https://{raw}"

    try:
        parsed = urlparse(url_to_parse)
        # Access port early to catch ValueError for malformed ports/IPv6
        port = parsed.port
        host = parsed.hostname
    except ValueError as e:
        # Malformed URL (e.g., IPv6 without brackets, invalid port)
        hint = " (hint: wrap IPv6 addresses in brackets, e.g. [2001:db8::1])"
        raise TargetNormalizationError(f"Invalid target URL: {e}{hint}")

    # Extract host from path if hostname is empty (e.g., bare domain)
    if not host:
        host = (parsed.path.split("/")[0] if parsed.path else "")
    if not host:
        return "", None

    # Lowercase host for consistent canonicalization
    host = host.lower()

    # Validate scheme (only http/https allowed when explicitly provided)
    scheme = parsed.scheme.lower() if has_scheme else "https"
    if scheme not in ("http", "https"):
        raise TargetNormalizationError(f"Invalid scheme '{scheme}': only http/https allowed")

    # Format host (bracket IPv6 addresses)
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host

    # Strip default ports for cleaner canonicalization when scheme is known
    port_suffix = ""
    if port:
        if scheme:
            is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
            if not is_default_port:
                port_suffix = f":{port}"
        else:
            port_suffix = f":{port}"

    normalized = f"{scheme}://{host_display}{port_suffix}"

    # Track if path/query/fragment was stripped
    had_path = bool(parsed.path and parsed.path not in ("", "/"))
    had_query = bool(parsed.query)
    had_fragment = bool(parsed.fragment)
    note = None
    if had_path or had_query or had_fragment:
        note = "Target URL contained a path/query/fragment; scanning root origin instead."

    return normalized, note


def _attach_target_note(options: dict, original_target: str, note: str | None, scheme_inferred: bool = False) -> dict:
    """Attach original target info to scan options for transparency."""
    updated = dict(options) if options else {}
    if note:
        updated.setdefault("_original_target", original_target)
        updated.setdefault("_target_warning", note)
    if scheme_inferred:
        updated.setdefault("target_scheme_inferred", True)
    return updated


def strip_target_scheme(target: str) -> str:
    """Strip scheme from a normalized URL (used to trigger auto-detect)."""
    from urllib.parse import urlparse
    parsed = urlparse(target)
    host = parsed.hostname or ""
    if not host:
        return target
    host_display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{host_display}{f':{parsed.port}' if parsed.port else ''}"


def is_root_domain(url: str) -> bool:
    """Check if URL is a root domain (not a subdomain)."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        parsed = urlparse(url if '://' in url else f'https://{url}')
        host = parsed.hostname or parsed.netloc or parsed.path.split('/')[0]
        host = host.lower()  # parsed.hostname already strips port
        # IPs are treated as root targets
        try:
            ipaddress.ip_address(host.strip("[]"))
            return True
        except ValueError:
            pass
        root = extract_root_domain(url).lower()
        # It's a root if host equals root_domain or www.root_domain
        return host == root or host == f'www.{root}'
    except Exception:
        return False


# ============================================================
# MAIN
# ============================================================

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8080)
