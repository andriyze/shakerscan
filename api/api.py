#!/usr/bin/env python3
"""
ShakerScan API - Open Source Edition
FastAPI server with PostgreSQL persistence and Redis queue.
"""

import asyncio
import copy
import hashlib
import ipaddress
import json
import logging
import math
import os
import random
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

import asyncpg
import redis
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

try:
    from constants import SMART_SCAN_BUDGETS, resolve_scan_budget
except ModuleNotFoundError as exc:
    if exc.name != "constants":
        raise
    from scanner.constants import SMART_SCAN_BUDGETS, resolve_scan_budget

VALID_DAST_SCAN_TYPES = {"quick", "standard", "deep", "full", "aggressive", "smart"}
ACTIVE_ENFORCED_SCAN_TYPES = {"smart", "full", "aggressive"}


def utc_now() -> datetime:
    """Return UTC as a naive datetime to match existing DB timestamp columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    return utc_now().isoformat()

try:
    from evidence_triage import (
        build_evidence_with_triage as _build_evidence_with_triage,
        redact_finding_evidence as _redact_finding_evidence,
    )
except ModuleNotFoundError as exc:
    if exc.name != "evidence_triage":
        raise
    from api.evidence_triage import (
        build_evidence_with_triage as _build_evidence_with_triage,
        redact_finding_evidence as _redact_finding_evidence,
    )

try:
    from scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields
except ModuleNotFoundError as exc:
    if exc.name != "scan_verification_state":
        raise
    from api.scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields

from retest_contract import (
    AI_ONLY_RETEST_TYPES,
    DEFAULT_REPLAY_PAYLOADS,
    SUPPORTED_RETEST_TYPES,
    SUPPORTED_RETEST_VERDICTS,
    VerificationPolicy,
    build_replay_commands,
    build_retest_job_payload,
    extract_auth_context,
    infer_retest_inputs,
    infer_type_from_title_tool,
    normalize_retest_type,
    parse_json_field,
    run_schema_migrations,
    validate_retest_job_payload,
)
import parallel_scan
import asm_inventory
import check_registry

AUTO_SHARD_ACTIVE_SCAN_TYPES = ACTIVE_ENFORCED_SCAN_TYPES
AUTO_SHARD_MAX_SHARDS = parallel_scan.MAX_SHARDS

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

try:
    from ai_assurance import (
        build_agent_blast_radius,
        build_ai_inventory,
        run_mcp_live_readiness_probe,
    )
except ModuleNotFoundError as exc:
    if exc.name != "ai_assurance":
        raise
    from api.ai_assurance import (
        build_agent_blast_radius,
        build_ai_inventory,
        run_mcp_live_readiness_probe,
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
    # Post-active phases (validation/attack-chains/grading) are CPU-heavy and emit
    # few heartbeats; on large (raised-budget §3) scans they legitimately run long.
    # 15 min reaped completed work; 30 gives margin while the resilient heartbeat
    # thread (worker) keeps writing.
    os.environ.get("FINALIZATION_HEARTBEAT_TIMEOUT_MINUTES", "30")
)
STALE_CHECK_INTERVAL_SECONDS = 60  # How often to check for stale scans
# A parent row runs no scanner subprocess; it is finalized by the merge job once
# all shards are terminal. If a shard is lost from the queue it never goes terminal
# and the parent hangs forever. Reap parents running past this generous threshold.
PARENT_STALE_TIMEOUT_MINUTES = int(os.environ.get("PARENT_STALE_TIMEOUT_MINUTES", "90"))
SCHEDULE_CHECK_INTERVAL_SECONDS = 60  # How often to check for due schedules
try:
    ASM_DISPATCH_INTERVAL_SECONDS = int(os.environ.get("SHAKERSCAN_ASM_DISPATCH_INTERVAL", "60"))
except (TypeError, ValueError):
    ASM_DISPATCH_INTERVAL_SECONDS = 60  # How often the continuous ASM dispatcher ticks
# Grace minutes added to a scan's max_duration before the stale-checker safety
# net force-terminates it, so the scanner's own termination (which returns
# recovered results) wins the race on slow targets.
try:
    STALE_DURATION_GRACE_MINUTES = float(os.environ.get("SHAKERSCAN_STALE_DURATION_GRACE_MIN", "5"))
except (TypeError, ValueError):
    STALE_DURATION_GRACE_MINUTES = 5.0
AI_SETTINGS_KEY = os.environ.get("AI_SETTINGS_KEY", "settings:ai")
SCAN_SETTINGS_KEY = os.environ.get("SCAN_SETTINGS_KEY", "settings:scan")
AUTOMATION_SETTINGS_KEY = os.environ.get("AUTOMATION_SETTINGS_KEY", "settings:automation")
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


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parallel_shard_contribution(shard: dict[str, Any]) -> dict[str, Any]:
    """Summarize child shard work without returning the full child report."""
    report = _decode_json_value(shard.get('result'))
    options = _decode_json_value(shard.get('options')) or {}
    if not isinstance(report, dict):
        report = {}
    if not isinstance(options, dict):
        options = {}
    active = report.get('active_checks') if isinstance(report.get('active_checks'), dict) else {}
    custom_endpoints = options.get('custom_endpoints') if isinstance(options.get('custom_endpoints'), list) else []
    attempts = active.get('endpoint_attempts') if isinstance(active.get('endpoint_attempts'), list) else []
    attempt_statuses: dict[str, int] = {}
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        status = str(attempt.get('status') or 'unknown').strip().lower() or 'unknown'
        attempt_statuses[status] = attempt_statuses.get(status, 0) + 1
    scope = active.get('check_family_scope') if isinstance(active.get('check_family_scope'), dict) else {}
    requested_family = (
        scope.get('requested_family')
        or scope.get('focused_family')
        or options.get('asm_check_family')
        or options.get('check_family')
    )
    budget = options.get('custom_budget') if isinstance(options.get('custom_budget'), dict) else {}
    contribution = {
        'assigned_endpoints': len(custom_endpoints),
        'attempted_endpoints': len(attempts) if attempts else _int_or_none(active.get('endpoint_attempts_total')),
        'attempt_statuses': attempt_statuses,
        'active_worklist_total': _int_or_none(active.get('active_worklist_total')),
        'active_endpoints_selected': _int_or_none(active.get('active_endpoints_selected')),
        'active_endpoint_budget': _int_or_none(active.get('active_endpoint_budget') or budget.get('active_max_endpoints')),
        'active_max_seconds': _int_or_none(budget.get('active_max_seconds')),
        'budget_profile': options.get('budget_profile'),
        'check_family': requested_family or 'all',
        'auth_state': asm_inventory.auth_state_from_options(options),
        'per_endpoint_telemetry': bool(active.get('per_endpoint_telemetry')) or bool(attempts),
    }
    return {key: value for key, value in contribution.items() if value not in (None, {}, [])}


def _public_parallel_shard(row: dict[str, Any]) -> dict[str, Any]:
    shard = dict(row)
    shard['contribution'] = _parallel_shard_contribution(shard)
    shard.pop('result', None)
    shard.pop('options', None)
    return shard


def _add_rollup_bucket_value(bucket: dict[str, Any], key: str, value: int) -> None:
    if value:
        bucket[key] = int(bucket.get(key) or 0) + int(value)


def _parallel_shard_contribution_rollup(shards: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Aggregate per-shard contribution facts for parent scan detail."""
    totals: dict[str, Any] = {}
    by_auth_state: dict[str, dict[str, Any]] = {}
    by_check_family: dict[str, dict[str, Any]] = {}
    attempt_statuses: dict[str, int] = {}
    numeric_fields = (
        'assigned_endpoints',
        'attempted_endpoints',
        'active_worklist_total',
        'active_endpoints_selected',
        'active_endpoint_budget',
        'active_max_seconds',
    )
    shards_with_contribution = 0
    telemetry_shards = 0

    for shard in shards:
        contribution = shard.get('contribution') if isinstance(shard.get('contribution'), dict) else {}
        duration_seconds = _int_or_none(shard.get('duration_seconds')) or 0
        shard_has_fact = bool(duration_seconds)
        for field in numeric_fields:
            value = _int_or_none(contribution.get(field)) or 0
            if value:
                totals[field] = int(totals.get(field) or 0) + value
                shard_has_fact = True

        statuses = contribution.get('attempt_statuses') if isinstance(contribution.get('attempt_statuses'), dict) else {}
        for status, raw_count in statuses.items():
            count = _int_or_none(raw_count) or 0
            if count <= 0:
                continue
            key = str(status or 'unknown')
            attempt_statuses[key] = attempt_statuses.get(key, 0) + count
            shard_has_fact = True

        if contribution.get('per_endpoint_telemetry'):
            telemetry_shards += 1
            shard_has_fact = True
        if duration_seconds:
            totals['duration_seconds'] = int(totals.get('duration_seconds') or 0) + duration_seconds

        if not shard_has_fact:
            continue
        shards_with_contribution += 1
        auth_state = str(contribution.get('auth_state') or 'unknown')
        family = str(contribution.get('check_family') or 'all')
        for bucket_map, bucket_key in ((by_auth_state, auth_state), (by_check_family, family)):
            bucket = bucket_map.setdefault(bucket_key, {'shards': 0})
            bucket['shards'] += 1
            for field in numeric_fields:
                _add_rollup_bucket_value(bucket, field, _int_or_none(contribution.get(field)) or 0)
            _add_rollup_bucket_value(bucket, 'duration_seconds', duration_seconds)
            if contribution.get('per_endpoint_telemetry'):
                bucket['telemetry_shards'] = int(bucket.get('telemetry_shards') or 0) + 1

    if not shards_with_contribution:
        return None
    if attempt_statuses:
        totals['attempt_statuses'] = attempt_statuses
    if by_auth_state:
        totals['by_auth_state'] = by_auth_state
    if by_check_family:
        totals['by_check_family'] = by_check_family
    totals['shards_with_contribution'] = shards_with_contribution
    if telemetry_shards:
        totals['telemetry_shards'] = telemetry_shards
    active_seconds = int(totals.get('active_max_seconds') or 0)
    duration = int(totals.get('duration_seconds') or 0)
    if active_seconds > 0 and duration > 0:
        totals['active_budget_utilization'] = round(min(1.0, duration / active_seconds), 3)
    return totals


def _attach_parallel_shard_rollup(result: dict[str, Any], shards: list[dict[str, Any]]) -> None:
    """Attach shard rollup and derive live parent progress from child progress."""
    terminal = {'completed', 'failed', 'cancelled'}
    progress_values = [int(s.get('progress') or 0) for s in shards]
    average_progress = int(round(sum(progress_values) / len(progress_values))) if progress_values else 0
    public_shards = [_public_parallel_shard(shard) for shard in shards]
    result['shards'] = public_shards
    result['shard_rollup'] = {
        'total': len(shards),
        'completed': sum(1 for s in shards if s.get('status') == 'completed'),
        'failed': sum(1 for s in shards if s.get('status') == 'failed'),
        'running': sum(1 for s in shards if s.get('status') == 'running'),
        'pending': sum(1 for s in shards if s.get('status') == 'pending'),
        'terminal': sum(1 for s in shards if s.get('status') in terminal),
        'average_progress': average_progress,
    }
    contribution_rollup = _parallel_shard_contribution_rollup(public_shards)
    if contribution_rollup:
        result['shard_rollup']['contribution'] = contribution_rollup
    if shards and result.get('status') in {'pending', 'running'}:
        current = int(result.get('progress') or 0)
        # Keep unfinished parents below 100; the merge job owns completion.
        result['progress'] = min(99, max(current, average_progress))


def get_redis():
    """Get Redis connection."""
    return redis.from_url(REDIS_URL, decode_responses=True)


def _asm_domain_rate_key(root_domain: str) -> str:
    return asm_inventory.domain_rate_key(root_domain)


def _asm_reserved_count(r, root_domain: str) -> int:
    if not root_domain:
        return 0
    return asm_inventory.reserved_domain_rate_count(r, root_domain)


def _reserve_asm_domain_rate(r, root_domain: str, cap: int, amount: int) -> int:
    """Reserve endpoint budget before queuing an ASM batch.

    The DB count only sees endpoints after they finish. This Redis counter
    closes the race where several targets under one root all queue full batches
    in the same dispatcher tick and exceed the per-hour domain cap.
    """
    try:
        cap = max(0, int(cap or 0))
        amount = max(0, int(amount or 0))
    except (TypeError, ValueError):
        return 0
    if amount <= 0:
        return 0
    if not root_domain or cap <= 0:
        return amount
    try:
        return asm_inventory.reserve_domain_rate(r, root_domain, cap, amount)
    except Exception as exc:
        print(f"[asm] domain rate reservation failed for {root_domain}: {exc}", flush=True)
        return 0


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


def _normalize_confidence(value: Any, default: float) -> float:
    """Clamp a confidence value into [0, 1], falling back to default on error."""
    try:
        return min(1.0, max(0.0, float(value)))
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
    "access_token",
    "ai_api_key",
    "api_key",
    "api_token",
    "auth_cookies",
    "auth_header",
    "auth_headers_json",
    "auth_scenario_json",
    "authorization",
    "bearer_token",
    "client_secret",
    "credential",
    "credentials",
    "hf_token",
    "huggingface_token",
    "login_password",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_value",
    "session_token",
    "token",
    "user2_cookies",
    "user2_header",
}

SENSITIVE_SCAN_OPTION_KEY_FRAGMENTS = (
    "_secret",
    "secret_",
    "_token",
    "token_",
    "_credential",
    "credential_",
    "private_key",
    "password",
)


def _is_sensitive_scan_option_key(key: Any) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return normalized in SENSITIVE_SCAN_OPTION_KEYS or any(
        fragment in normalized for fragment in SENSITIVE_SCAN_OPTION_KEY_FRAGMENTS
    )


def _sanitize_scan_options(value: Any) -> Any:
    """Decode scan options and mask sensitive credentials before returning."""
    options = _decode_json_value(value)
    if not isinstance(options, dict):
        return options

    def mask_nested(candidate: Any) -> Any:
        if isinstance(candidate, dict):
            masked_dict = {}
            for key, item in candidate.items():
                if _is_sensitive_scan_option_key(key) and item not in (None, "", [], {}):
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
        "auto_fp_on_retest": _is_truthy(
            os.environ.get("AUTO_FP_ON_RETEST", "false"),
            default=False,
        ),
        "auto_fp_min_confidence": _normalize_confidence(
            os.environ.get("AUTO_FP_MIN_CONFIDENCE", "0.9"), default=0.9
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
    if "auto_fp_on_retest" in overrides:
        settings["auto_fp_on_retest"] = _is_truthy(
            overrides.get("auto_fp_on_retest"), default=settings["auto_fp_on_retest"]
        )
    if "auto_fp_min_confidence" in overrides:
        settings["auto_fp_min_confidence"] = _normalize_confidence(
            overrides.get("auto_fp_min_confidence"), default=settings["auto_fp_min_confidence"]
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
        "auto_fp_on_retest": bool(settings.get("auto_fp_on_retest", False)),
        "auto_fp_min_confidence": _normalize_confidence(settings.get("auto_fp_min_confidence"), default=0.9),
        "demo_mode_enabled": bool(settings.get("demo_mode_enabled", False)),
        "demo_honey_public_url": settings.get("demo_honey_public_url") or "",
        "demo_honey_scanner_url": settings.get("demo_honey_scanner_url") or "",
    }


def _normalize_parallel_strategy(value: Any, default: str = "auto") -> str:
    candidate = str(value or "").strip().lower()
    if candidate in parallel_scan.VALID_STRATEGIES:
        return candidate
    return default


def _normalize_auto_shard_count(value: Any, default: int = 4) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        parsed = default
    return max(2, min(AUTO_SHARD_MAX_SHARDS, parsed))


def _default_scan_execution_settings() -> dict[str, Any]:
    return {
        "auto_sharding_enabled": _is_truthy(
            os.environ.get("AUTO_SHARDING_ENABLED", "true"),
            default=True,
        ),
        "auto_sharding_strategy": _normalize_parallel_strategy(
            os.environ.get("AUTO_SHARDING_STRATEGY", "auto"),
            default="auto",
        ),
        "auto_sharding_max_shards": _normalize_auto_shard_count(
            os.environ.get("AUTO_SHARDING_MAX_SHARDS", "4"),
            default=4,
        ),
        "auto_sharding_min_workers": max(
            1,
            _normalize_non_negative_int(
                os.environ.get("AUTO_SHARDING_MIN_WORKERS", "2"),
                default=2,
            ),
        ),
    }


def _load_effective_scan_execution_settings() -> dict[str, Any]:
    settings = _default_scan_execution_settings()
    try:
        r = get_redis()
        overrides = r.hgetall(SCAN_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "auto_sharding_enabled" in overrides:
        settings["auto_sharding_enabled"] = _is_truthy(
            overrides.get("auto_sharding_enabled"),
            default=settings["auto_sharding_enabled"],
        )
    if "auto_sharding_strategy" in overrides:
        settings["auto_sharding_strategy"] = _normalize_parallel_strategy(
            overrides.get("auto_sharding_strategy"),
            default=settings["auto_sharding_strategy"],
        )
    if "auto_sharding_max_shards" in overrides:
        settings["auto_sharding_max_shards"] = _normalize_auto_shard_count(
            overrides.get("auto_sharding_max_shards"),
            default=int(settings["auto_sharding_max_shards"]),
        )
    if "auto_sharding_min_workers" in overrides:
        settings["auto_sharding_min_workers"] = max(
            1,
            _normalize_non_negative_int(
                overrides.get("auto_sharding_min_workers"),
                default=int(settings["auto_sharding_min_workers"]),
            ),
        )
    return settings


def _default_asm_enabled_setting() -> bool:
    return _is_truthy(
        os.environ.get("DEFAULT_ASM_ENABLED", os.environ.get("ASM_DEFAULT_ENABLED", "true")),
        default=True,
    )


def _safe_default_asm_config(config: Any = None) -> dict[str, Any]:
    cfg = asm_inventory.merge_asm_config(config or {})
    # Global automation defaults must stay safe. Lab/deep active depth is still
    # explicit per target/action, not a broad default.
    cfg["exploit_depth"] = False
    return cfg


def _merge_safe_default_asm_config(base: Any, update: Any) -> dict[str, Any]:
    """Apply a partial automation default update without resetting unrelated knobs."""
    merged = dict(_safe_default_asm_config(base))
    if isinstance(update, dict):
        merged.update(update)
    return _safe_default_asm_config(merged)


def _load_effective_automation_settings() -> dict[str, Any]:
    settings: dict[str, Any] = {
        "default_asm_enabled": _default_asm_enabled_setting(),
        "default_asm_config": _safe_default_asm_config({}),
    }
    try:
        r = get_redis()
        overrides = r.hgetall(AUTOMATION_SETTINGS_KEY) or {}
    except Exception:
        overrides = {}

    if "default_asm_enabled" in overrides:
        settings["default_asm_enabled"] = _is_truthy(
            overrides.get("default_asm_enabled"),
            default=settings["default_asm_enabled"],
        )
    if "default_asm_config" in overrides:
        settings["default_asm_config"] = _safe_default_asm_config(
            _decode_json_value(overrides.get("default_asm_config"))
        )
    return settings


def _sanitize_scan_execution_settings_response(settings: dict[str, Any]) -> dict[str, Any]:
    worker_count = _running_scan_worker_count_best_effort()
    return {
        "auto_sharding_enabled": bool(settings.get("auto_sharding_enabled")),
        "auto_sharding_strategy": _normalize_parallel_strategy(
            settings.get("auto_sharding_strategy"),
            default="auto",
        ),
        "auto_sharding_max_shards": _normalize_auto_shard_count(
            settings.get("auto_sharding_max_shards"),
            default=4,
        ),
        "auto_sharding_min_workers": max(
            1,
            _normalize_non_negative_int(settings.get("auto_sharding_min_workers"), default=2),
        ),
        "eligible_scan_types": sorted(AUTO_SHARD_ACTIVE_SCAN_TYPES),
        "running_workers": worker_count,
    }


def _sanitize_automation_settings_response(
    automation: dict[str, Any] | None = None,
    scan_execution: dict[str, Any] | None = None,
) -> dict[str, Any]:
    automation = automation or _load_effective_automation_settings()
    scan_execution = scan_execution or _load_effective_scan_execution_settings()
    default_asm_config = _safe_default_asm_config(automation.get("default_asm_config"))
    return {
        "scan_execution": _sanitize_scan_execution_settings_response(scan_execution),
        "default_continuous_asm": {
            "enabled_for_new_web_targets": bool(automation.get("default_asm_enabled")),
            "config": default_asm_config,
            "active_depth_confirmation_required": True,
            "high_risk_families_require_explicit_request": True,
            "applies_to": "new web targets",
        },
        "safety_boundaries": {
            "global_exploit_depth": False,
            "lab_depth_requires_explicit_action": True,
            "planned_high_risk_families_fail_closed": True,
        },
    }


def _default_asm_enabled_for_new_web_target(discovery_source: str = "manual") -> bool:
    """Default Continuous ASM only for web targets the product should track.

    The targets table also stores model artifacts and other non-web subjects, so
    callers should opt those out explicitly instead of relying on a table-wide
    default.
    """
    if str(discovery_source or "").strip().lower() in {"model-intake", "model_intake"}:
        return False
    return bool(_load_effective_automation_settings().get("default_asm_enabled"))


def _default_asm_config_for_new_web_target(discovery_source: str = "manual") -> dict[str, Any]:
    if str(discovery_source or "").strip().lower() in {"model-intake", "model_intake"}:
        return {}
    return _safe_default_asm_config(_load_effective_automation_settings().get("default_asm_config"))


def _scan_option_was_explicit(options: Any, field: str) -> bool:
    return field in getattr(options, "model_fields_set", set())


def _custom_endpoint_count(options_payload: dict[str, Any]) -> int:
    endpoints = options_payload.get("custom_endpoints")
    if not isinstance(endpoints, list):
        return 0
    seen: set[str] = set()
    for endpoint in endpoints:
        if not isinstance(endpoint, str):
            continue
        value = endpoint.strip()
        if value:
            seen.add(value)
    return len(seen)


def _auto_shard_eligibility(scan_type: str, options_payload: dict[str, Any]) -> tuple[bool, str]:
    endpoint_count = _custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return True, f"{endpoint_count} explicit endpoints can be split by scope"
    # A focused check_family scan (sqli/xss/bola/auth) is a deep single-family
    # pass. Auto-sharding it into broad `coverage` dilutes that family's budget
    # and adds the slow recon+merge path (observed: a focused SQLi scan hung in
    # coverage and found nothing, while the direct pass found the login SQLi).
    # Focused scans therefore run DIRECT; only broad scans fan out.
    family = check_registry.normalize_check_family(_scan_check_family_value(options_payload))
    if family and family != "all":
        return False, f"focused {family} scan runs direct (auto-sharding would dilute the family pass)"
    if scan_type in AUTO_SHARD_ACTIVE_SCAN_TYPES:
        return True, f"{scan_type} scan can fan out endpoint coverage across workers"
    return False, f"{scan_type} scan has no endpoint list and no active families to shard"


def _resolve_auto_parallel_strategy(
    strategy: Any,
    scan_type: str,
    options_payload: dict[str, Any],
) -> str:
    """Resolve auto-sharding to the concrete strategy we will store/execute."""
    normalized = _normalize_parallel_strategy(strategy, default="auto")
    # A focused check_family scan must never run the broad `coverage` strategy:
    # that fans out broad/sqli/xss lanes and dilutes (or skips) the requested
    # family. `coverage_family` with a single requested family runs ONLY that
    # family across endpoint slices, so it parallelizes without diluting. This
    # holds for both explicit `coverage` and the auto path below.
    focused = bool(
        (lambda fam: fam and fam != "all")(
            check_registry.normalize_check_family(_scan_check_family_value(options_payload))
        )
    )
    if focused and normalized == "coverage":
        return "coverage_family"
    if normalized != "auto":
        return normalized
    endpoint_count = _custom_endpoint_count(options_payload)
    if endpoint_count >= 2:
        return "scope"
    if scan_type in AUTO_SHARD_ACTIVE_SCAN_TYPES:
        return "coverage_family" if focused else "coverage"
    return "family"


def _build_scan_options_payload(options: Any, scan_type: str) -> dict[str, Any]:
    options_payload = options.model_dump() if hasattr(options, "model_dump") else options.dict()
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
    options_payload, _family = _apply_scan_check_family_policy(options_payload)
    return options_payload


def _apply_auto_sharding_policy(
    options: Any,
    options_payload: dict[str, Any],
    scan_type: str,
) -> tuple[bool, int | None]:
    """Resolve whether this scan should become a parallel parent.

    Explicit per-scan intent wins. If `parallel` is omitted, the global
    scan-execution setting can turn eligible scans into parent scans.
    """
    if _scan_option_was_explicit(options, "parallel"):
        if options.parallel:
            options_payload["parallel"] = True
            if not options_payload.get("shards"):
                options_payload["shards"] = "auto"
            options_payload["shard_strategy"] = _resolve_auto_parallel_strategy(
                options_payload.get("shard_strategy"),
                scan_type,
                options_payload,
            )
            return True, _running_scan_worker_count_best_effort()
        options_payload["parallel"] = False
        return False, None

    settings = _load_effective_scan_execution_settings()
    if not settings.get("auto_sharding_enabled"):
        options_payload["parallel"] = False
        return False, None

    eligible, reason = _auto_shard_eligibility(scan_type, options_payload)
    if not eligible:
        options_payload["parallel"] = False
        return False, None

    worker_count = _running_scan_worker_count_best_effort()
    min_workers = max(1, int(settings.get("auto_sharding_min_workers") or 2))
    if worker_count is not None and worker_count < min_workers:
        options_payload["parallel"] = False
        options_payload["auto_sharding_reason"] = (
            f"auto-sharding skipped: {worker_count} running worker(s), "
            f"minimum is {min_workers}"
        )
        return False, worker_count

    strategy = _resolve_auto_parallel_strategy(
        settings.get("auto_sharding_strategy"),
        scan_type,
        options_payload,
    )
    max_shards = _normalize_auto_shard_count(settings.get("auto_sharding_max_shards"), default=4)
    if _custom_endpoint_count(options_payload) < 2 and scan_type in AUTO_SHARD_ACTIVE_SCAN_TYPES:
        if strategy == "family":
            max_shards = min(max_shards, len(parallel_scan.FAMILY_SHARD_LABELS))
    requested_shards: Any = "auto"
    if worker_count is not None:
        requested_shards = max(2, min(max_shards, worker_count))

    options_payload["parallel"] = True
    options_payload["shards"] = requested_shards
    options_payload["shard_strategy"] = strategy
    options_payload["auto_sharded"] = True
    options_payload["auto_sharding_reason"] = reason
    return True, worker_count


def _normalize_asm_check_family(value: Any) -> str | None:
    return check_registry.validate_asm_focus_family(value)


def _apply_asm_check_family(options: dict[str, Any], check_family: Any) -> dict[str, Any]:
    """Apply a supported focused ASM family to scan options.

    This uses the first-class check registry, while preserving the scanner's
    current legacy focused flags for SQLi/XSS and explicit check-family routing
    for gated families such as BOLA.
    """
    opts, _family = check_registry.apply_asm_focus(options or {}, check_family)
    return opts


def _validate_asm_check_family_value(value: Any) -> str | None:
    return check_registry.validate_asm_focus_family(value)


def _validate_asm_endpoint_filter_value(value: Any) -> str | None:
    return asm_inventory.normalize_endpoint_filter(value)


def _has_primary_auth_context(options: dict[str, Any]) -> bool:
    return check_registry.has_primary_auth_context(options or {})


def _has_second_user_auth_context(options: dict[str, Any]) -> bool:
    return check_registry.has_second_user_auth_context(options or {})


def _enforce_asm_family_preconditions(
    family: str | None,
    options: dict[str, Any],
    *,
    exploit_depth: bool,
) -> None:
    """Fail closed for focused families whose registry metadata needs more context."""
    error = check_registry.family_precondition_error(
        family,
        options or {},
        exploit_depth=exploit_depth,
    )
    if error:
        raise HTTPException(
            status_code=400,
            detail=error,
        )


def _scan_check_family_value(options_payload: dict[str, Any]) -> Any:
    return (
        options_payload.get("check_family")
        or options_payload.get("asm_check_family")
        or options_payload.get("coverage_attempt_family")
    )


def _apply_scan_check_family_policy(options_payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    """Apply the shared DAST family policy to a public POST /scans payload."""
    try:
        opts, family = check_registry.apply_scan_focus(
            options_payload,
            _scan_check_family_value(options_payload),
        )
        check_registry.enforce_family_preconditions(
            family,
            opts,
            exploit_depth=bool(opts.get("exploit_depth")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return opts, family


def _hidden_scan_roles_for_list(*, include_shards: bool = False, include_internal: bool = False) -> list[str]:
    hidden: list[str] = []
    if not include_shards:
        hidden.append("shard")
    if not include_internal:
        hidden.extend([asm_inventory.ASM_BATCH_ROLE, asm_inventory.ASM_RECON_ROLE])
    return hidden


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


def _scan_result_verification_overrides(scan_result: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not isinstance(scan_result, dict):
        return {}

    overrides: dict[str, dict[str, Any]] = {}
    for finding in scan_result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        fields = _scan_time_verification_fields(finding)
        if not fields:
            continue
        fingerprint = generate_finding_fingerprint(finding)
        if fingerprint:
            overrides[fingerprint] = fields
    return overrides


_NUCLEI_NOT_EXECUTED_COVERAGE_GAP = "Nuclei templates not executed - check nuclei configuration or timeouts"


# Inference sources that are counted directly from nuclei stats vs. estimated
# from coarser wave/duration signals. Estimates are flagged so the UI can show
# coverage as approximate rather than presenting a guess as a measured count.
_NUCLEI_APPROXIMATE_RUN_SOURCES = {"staged_nuclei_wave_tags", "staged_nuclei_wave_estimate"}


def _infer_nuclei_templates_run(scan_result: dict[str, Any]) -> tuple[int, str | None]:
    """Best-effort count of nuclei templates run, with its provenance.

    Returns ``(count, source)``. ``source`` identifies where the number came
    from so callers can distinguish measured counts from coarse estimates.
    """
    discovery = scan_result.get("discovery") if isinstance(scan_result.get("discovery"), dict) else {}
    nuclei = discovery.get("nuclei") if isinstance(discovery.get("nuclei"), dict) else {}
    if not nuclei:
        return 0, None

    for key in ("templates_executed", "templates_used"):
        try:
            value = int(nuclei.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value, "nuclei_templates_executed"

    stats = nuclei.get("statistics") if isinstance(nuclei.get("statistics"), dict) else {}
    for key in ("templates_executed", "templates_loaded"):
        try:
            value = int(stats.get(key) or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value, "nuclei_statistics"

    if nuclei.get("scan_completed") is not True:
        return 0, None

    wave_tags: set[str] = set()
    for wave in nuclei.get("wave_stats") or []:
        if not isinstance(wave, dict):
            continue
        for tag in wave.get("tags") or []:
            if tag:
                wave_tags.add(str(tag))
    if wave_tags:
        return len(wave_tags), "staged_nuclei_wave_tags"

    try:
        waves_completed = int(nuclei.get("waves_completed") or 0)
    except (TypeError, ValueError):
        waves_completed = 0
    try:
        duration = int(nuclei.get("total_duration_seconds") or 0)
    except (TypeError, ValueError):
        duration = 0
    if waves_completed > 0 or duration > 0:
        return max(1, waves_completed), "staged_nuclei_wave_estimate"
    return 0, None


def _normalize_scan_result_for_api(scan_result: Any) -> Any:
    if not isinstance(scan_result, dict):
        return scan_result

    inferred_nuclei_run, inferred_source = _infer_nuclei_templates_run(scan_result)
    if inferred_nuclei_run > 0:
        smart_coverage = scan_result.setdefault("smart_coverage", {})
        if isinstance(smart_coverage, dict):
            nuclei_cov = smart_coverage.setdefault("nuclei_templates", {})
            if isinstance(nuclei_cov, dict):
                try:
                    current_run = int(nuclei_cov.get("run") or 0)
                except (TypeError, ValueError):
                    current_run = 0
                if current_run <= 0:
                    nuclei_cov["run"] = inferred_nuclei_run
                    nuclei_cov.setdefault("matched", 0)
                    nuclei_cov.setdefault("hit_rate", 0.0)
                    nuclei_cov.setdefault("by_category", {})
                    nuclei_cov["run_source"] = inferred_source or "inferred"
                    nuclei_cov["run_approximate"] = inferred_source in _NUCLEI_APPROXIMATE_RUN_SOURCES

        coverage_gaps = scan_result.get("coverage_gaps")
        if isinstance(coverage_gaps, dict) and isinstance(coverage_gaps.get("issues"), list):
            issues = [
                issue for issue in coverage_gaps.get("issues") or []
                if issue != _NUCLEI_NOT_EXECUTED_COVERAGE_GAP
            ]
            coverage_gaps["issues"] = issues
            coverage_gaps["count"] = len(issues)

    return scan_result


def infer_retest_type(finding: dict[str, Any], evidence: dict[str, Any], override_type: str | None = None) -> str | None:
    normalized = normalize_retest_type(override_type)
    if normalized:
        return normalized

    evidence_type = normalize_retest_type(evidence.get("type"))
    if evidence_type:
        return evidence_type

    # Shared title/tool inference from retest_contract so API, worker, and
    # auto-retest policy always agree on whether a finding is retestable.
    return infer_type_from_title_tool(finding.get("title"), finding.get("tool"))


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
        evidence_with_triage = _redact_finding_evidence(_build_evidence_with_triage(finding))
        evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
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
                        resolved_at = NULL,
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
    now = utc_now()

    async with pool.acquire() as conn:
        # Get all running scans. Parent rows of a parallel scan never run a
        # scanner subprocess (they only wait on shards) so they emit no
        # heartbeat; they are finalized by the merge job and reconciled below,
        # so exclude them from heartbeat/duration staleness here.
        running_scans = await conn.fetch("""
            SELECT id, scan_type, started_at, target_id, current_phase, progress,
                   options, scan_role, parent_scan_id
            FROM scans
            WHERE status = 'running' AND started_at IS NOT NULL
              AND (scan_role IS NULL OR scan_role <> 'parent')
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
            duration_exceeded = False
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

                # Grace buffer so the safety net doesn't pre-empt a scan the
                # instant it reaches its budget: the scanner's own termination
                # (which returns recovered results -> 'completed') should win the
                # race. Without this, a slow target (e.g. a high-latency API)
                # that runs slightly past budget gets marked 'failed' even though
                # results are seconds from being returned.
                duration_grace = max(STALE_DURATION_GRACE_MINUTES, max_duration * 0.5)
                if scan_duration > max_duration + duration_grace:
                    is_stale = True
                    duration_exceeded = True
                    reason = f"Exceeded max duration ({scan_duration:.0f} min > {max_duration} min for {scan_type} scan)"

            # Mark stale scan terminal (failed, or completed-partial when it
            # merely hit its time budget but recovered results — decided below).
            if is_stale:
                print(f"[cleanup] Terminating scan {scan_id[:8]}: {reason}", flush=True)

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

                # A scan that reached its TIME BUDGET but recovered partial
                # results (with a checkpoint) is a soft success, not a failure:
                # it ran to its configured limit and produced findings. Mark it
                # 'completed' (partial) so parallel rollups and the Scans list
                # don't show alarming failures for shards/scans that contributed
                # results. A genuine hang/crash (no heartbeat, Check 1) or a
                # duration-exceed with NO recoverable results stays 'failed'.
                stale_status = 'completed' if (duration_exceeded and partial_result) else 'failed'
                stale_phase = 'completed' if stale_status == 'completed' else 'terminated'
                await conn.execute("""
                    UPDATE scans
                    SET status = $8,
                        error_message = $1,
                        completed_at = $2,
                        result = $3,
                        score = $4,
                        grade = $5,
                        findings_count = $6,
                        progress = 100,
                        current_phase = $9
                    WHERE id = $7
                """, error_msg, now, json.dumps(partial_result) if partial_result else None,
                    partial_score, partial_grade, partial_findings_count, scan['id'],
                    stale_status, stale_phase)

                # Save partial findings to findings table so they appear in /findings
                partial_findings = partial_result.get("findings", []) if partial_result else []
                target_id = scan['target_id']
                if partial_findings and target_id:
                    saved = await save_findings_from_partial(conn, scan['id'], target_id, partial_findings)
                    print(f"[cleanup] Saved {saved} findings from partial results for scan {scan_id[:8]}", flush=True)

                # If this was a shard of a parallel scan, its parent may now have
                # all children terminal — make sure the merge gets enqueued so the
                # parent doesn't hang forever on a crashed shard.
                parent_id = scan['parent_scan_id']
                if parent_id:
                    try:
                        await parallel_scan.reconcile_parallel_parent(
                            conn, str(parent_id), get_redis(), QUEUE_NAME
                        )
                    except Exception as e:
                        print(f"[cleanup] parent reconcile error for {str(parent_id)[:8]}: {e}", flush=True)


async def cleanup_stale_parents(pool: asyncpg.Pool):
    """Finalize parent scans that would otherwise hang forever.

    A parent waits on its shards and is finalized by the merge job. If a shard is
    lost from the queue (``pending`` in the DB but never queued/dequeued in Redis)
    it never reaches a terminal state, the merge never enqueues, and the parent
    stays ``running`` indefinitely (observed: a 9h parent with 21 orphaned pending
    shards on an empty queue). For parents running past a generous threshold, fail
    the orphaned (queue-missing) pending shards, then reconcile so the parent
    merges/finalizes instead of hanging.
    """
    r = get_redis()
    now = utc_now()
    async with pool.acquire() as conn:
        parents = await conn.fetch(
            """
            SELECT id FROM scans
            WHERE status = 'running' AND scan_role = 'parent' AND started_at IS NOT NULL
              AND started_at < $1
            """,
            now - timedelta(minutes=PARENT_STALE_TIMEOUT_MINUTES),
        )
        if not parents:
            return
        # Snapshot queued job_ids once for orphan detection. If the queue can't be
        # read, leave pending children alone (conservative — never fail a child we
        # can't prove is orphaned).
        queued_job_ids: set[str] | None = set()
        try:
            for raw in r.lrange(QUEUE_NAME, 0, -1):
                try:
                    jid = json.loads(raw).get("job_id")
                except Exception:
                    continue
                if jid:
                    queued_job_ids.add(str(jid))
        except Exception:
            queued_job_ids = None

        for parent in parents:
            parent_id = str(parent["id"])
            pending = await conn.fetch(
                "SELECT id, job_id FROM scans WHERE parent_scan_id = $1 AND status = 'pending'",
                parent["id"],
            )
            failed = 0
            for child in pending:
                jid = str(child["job_id"]) if child["job_id"] else None
                if queued_job_ids is not None and jid not in queued_job_ids:
                    await conn.execute(
                        """
                        UPDATE scans SET status = 'failed', current_phase = 'terminated',
                               completed_at = $1,
                               error_message = 'orphaned shard: pending but not in scan queue (stale-parent reaper)'
                        WHERE id = $2 AND status = 'pending'
                        """,
                        now, child["id"],
                    )
                    failed += 1
            if failed:
                print(f"[cleanup] stale parent {parent_id[:8]}: failed {failed} orphaned pending shard(s)", flush=True)
            try:
                await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[cleanup] stale-parent reconcile error for {parent_id[:8]}: {e}", flush=True)


async def stale_scan_checker(pool: asyncpg.Pool):
    """Background task to periodically check for stale scans."""
    print("[cleanup] Stale scan checker started", flush=True)
    while True:
        try:
            await asyncio.sleep(STALE_CHECK_INTERVAL_SECONDS)
            await cleanup_stale_scans(pool)
            await cleanup_stale_parents(pool)
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

    now_utc = utc_now()
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
    """Check for and execute due scheduled scans.

    Connection lifetime: acquire a connection only to fetch the due list, then
    release it. Each due schedule then re-acquires for its own short-lived
    transaction. Previously this method pinned a single connection across the
    entire loop, which could starve the shared API pool when many schedules
    fire together or when a single schedule got slow (e.g. Redis push delay).
    """
    r = get_redis()
    now = utc_now()

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

        async with pool.acquire() as conn:
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

            # Use the shared helper so JSONB shapes (raw string vs decoded
            # dict, depending on asyncpg version / column type) are handled
            # consistently with the rest of the codebase.
            decoded_options = _decode_json_value(schedule['scan_options']) or {}
            if not isinstance(decoded_options, dict):
                decoded_options = {}
            scan_options = dict(decoded_options)

            # §9: ASM-aware schedule. kind='asm_improve' queues a bounded coverage
            # wave (test if claimable, else recon) instead of a full scan — the
            # "keep this target covered" cadence, spread across the schedule. Stored
            # in scan_options so no schema migration is needed.
            if str(scan_options.get('kind') or '').lower() == 'asm_improve':
                asm_opts = {k: v for k, v in scan_options.items() if k != 'kind'}
                try:
                    cfg_row = await conn.fetchrow(
                        "SELECT asm_config FROM targets WHERE id = $1", target_id)
                    cfg = asm_inventory.merge_asm_config(
                        _decode_asm_config(cfg_row["asm_config"]) if cfg_row else {})
                    claimable = await asm_inventory.claimable_count(
                        conn, str(target_id), stale_days=cfg["stale_days"])
                    if claimable > 0:
                        enq = await _enqueue_asm_exploit_batch(
                            conn, r, str(target_id), target_url, asm_opts,
                            batch_size=min(cfg["batch_size"], claimable),
                            stale_days=cfg["stale_days"], exploit_depth=cfg["exploit_depth"],
                            triggered_by="schedule")
                        await conn.execute(
                            "UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", target_id)
                        _asm_kind = "test"
                    else:
                        enq = await _enqueue_asm_recon(
                            conn, r, str(target_id), target_url, asm_opts, triggered_by="schedule")
                        await conn.execute(
                            "UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", target_id)
                        _asm_kind = "recon"
                    print(f"[scheduler] ASM improve ({_asm_kind}) queued for schedule "
                          f"{str(schedule_id)[:8]} -> {str(enq.get('scan_id', ''))[:8]}", flush=True)
                except Exception as exc:
                    print(f"[scheduler] ASM improve failed for schedule {str(schedule_id)[:8]}: {exc}", flush=True)
                next_run = calculate_next_run(
                    schedule["frequency"], schedule["day_of_week"],
                    schedule["time_of_day"] or "02:00", schedule["timezone"] or "UTC",
                    schedule["jitter_minutes"] or 0)
                await conn.execute(
                    "UPDATE schedules SET last_run_at = NOW(), next_run_at = $1, updated_at = NOW() WHERE id = $2",
                    next_run, schedule_id)
                continue

            scan_options['scan_type'] = scan_type
            scan_options_model = ScanOptions(**scan_options)
            scan_type = normalize_dast_scan_options(scan_options_model)
            if scan_type in ACTIVE_ENFORCED_SCAN_TYPES and scan_options_model.public:
                print(
                    f"[scheduler] Skipping schedule {str(schedule_id)[:8]}: "
                    f"public option is incompatible with '{scan_type}' scan type",
                    flush=True,
                )
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
            scan_options = _build_scan_options_payload(scan_options_model, scan_type)
            parallel_enabled, parallel_worker_count = _apply_auto_sharding_policy(
                scan_options_model,
                scan_options,
                scan_type,
            )
            scan_role = 'parent' if parallel_enabled else 'standalone'

            await conn.execute("""
                INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type, scan_role)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
            """, uuid.UUID(scan_id), target_id, target_url, job_id,
                 json.dumps(scan_options), scan_type, scan_role)

        job_data = {
            'job_id': job_id,
            'scan_id': scan_id,
            'target': target_url,
            'options': scan_options,
            'submitted_at': utc_now_iso(),
            'scheduled': True,
            'schedule_id': str(schedule_id)
        }
        if parallel_enabled:
            job_data['type'] = 'scan_plan'
            if parallel_worker_count is not None:
                job_data['parallel_worker_count'] = parallel_worker_count

        try:
            r.rpush(QUEUE_NAME, json.dumps(job_data))
        except Exception as exc:
            # Do not advance the schedule if Redis failed to accept the queue
            # item. Mark the inserted scan failed so the next scheduler pass can
            # retry the still-due schedule instead of being blocked by a
            # phantom pending scan that no worker can ever receive.
            async with pool.acquire() as conn:
                await conn.execute("""
                    UPDATE scans
                    SET status = 'failed', error_message = $1, completed_at = NOW()
                    WHERE id = $2
                """, f"scheduled enqueue failed: {exc}", uuid.UUID(scan_id))
            print(
                f"[scheduler] Failed to enqueue scheduled scan {scan_id[:8]} for schedule "
                f"{str(schedule_id)[:8]}: {exc}",
                flush=True,
            )
            continue

        try:
            r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': target_url})
        except Exception as exc:
            print(
                f"[scheduler] Scheduled scan {scan_id[:8]} queued, but Redis job status update failed: {exc}",
                flush=True,
            )

        next_run = calculate_next_run(
            schedule['frequency'],
            schedule['day_of_week'],
            schedule['time_of_day'] or '02:00',
            schedule['timezone'] or 'UTC',
            schedule['jitter_minutes'] or 0
        )
        async with pool.acquire() as conn:
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


async def run_asm_dispatch(pool: asyncpg.Pool):
    """One tick of the Continuous ASM dispatcher (docs §16 Phase 3/4): for each
    ASM-enabled target, pick at most ONE action (recon or exploit batch) within
    its freshness/rate/window budget and enqueue it. Never stacks load on a
    target (the crash lesson) and honours a per-root-domain rate cap."""
    r = get_redis()
    now = utc_now()

    async with pool.acquire() as conn:
        targets = await conn.fetch("""
            SELECT id, url, root_domain, scan_options, asm_config,
                   asm_last_test_at, asm_last_recon_at
            FROM targets
            WHERE asm_enabled = true AND is_active = true
        """)

    for t in targets:
        target_id = str(t['id'])
        target_url = t['url']
        root_domain = t['root_domain']
        raw_config = _decode_asm_config(t['asm_config'])
        cfg = asm_inventory.merge_asm_config(raw_config)
        try:
            async with pool.acquire() as conn:
                active = await conn.fetchval("""
                    SELECT COUNT(*) FROM scans
                    WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
                """, t['id'])
                claimable = await asm_inventory.claimable_count(conn, target_id, stale_days=cfg['stale_days'])
                tested_today = await asm_inventory.tested_recently_count(conn, target_id, hours=24)
                domain_rate_exceeded = False
                cap = cfg['max_requests_per_hour_per_domain']
                used = 0
                if cap > 0 and root_domain:
                    used = await asm_inventory.domain_tested_recently_count(conn, root_domain, hours=1)
                    reserved = _asm_reserved_count(r, root_domain)
                    domain_rate_exceeded = (used + reserved) >= cap

                decision = asm_inventory.decide_asm_action(
                    now=now,
                    last_test_at=t['asm_last_test_at'],
                    last_recon_at=t['asm_last_recon_at'],
                    has_active_scan=bool(active and active > 0),
                    claimable=claimable,
                    tested_today=tested_today,
                    domain_rate_exceeded=domain_rate_exceeded,
                    config=raw_config,
                )
                action = decision['action']
                if action == 'none':
                    continue

                base_opts = _decode_json_value(t['scan_options']) or {}
                if not isinstance(base_opts, dict):
                    base_opts = {}

                if action == 'recon':
                    enq = await _enqueue_asm_recon(conn, r, target_id, target_url, base_opts)
                    await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", t['id'])
                    print(f"[asm] recon queued for {target_url} -> scan {enq['scan_id'][:8]}", flush=True)
                elif action == 'test':
                    dispatch_batch_size = min(cfg['batch_size'], claimable)
                    daily_cap = cfg['daily_endpoint_cap']
                    if daily_cap > 0:
                        dispatch_batch_size = min(dispatch_batch_size, max(0, daily_cap - tested_today))
                    if cap > 0 and root_domain:
                        dispatch_batch_size = _reserve_asm_domain_rate(
                            r,
                            root_domain,
                            max(0, cap - used),
                            dispatch_batch_size,
                        )
                    if dispatch_batch_size <= 0:
                        continue
                    enq = await _enqueue_asm_exploit_batch(
                        conn, r, target_id, target_url, base_opts,
                        batch_size=dispatch_batch_size, stale_days=cfg['stale_days'],
                        exploit_depth=cfg['exploit_depth'], triggered_by='dispatcher',
                        domain_rate_reserved=dispatch_batch_size,
                    )
                    await conn.execute("UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", t['id'])
                    print(f"[asm] test batch queued for {target_url} "
                          f"({dispatch_batch_size} eps, {claimable} claimable) -> scan {enq['scan_id'][:8]}", flush=True)
        except Exception as e:
            print(f"[asm] dispatch error for {target_url}: {e}", flush=True)


async def asm_dispatcher(pool: asyncpg.Pool):
    """Background loop driving Continuous ASM (docs §16 Phase 3)."""
    print("[asm] Continuous ASM dispatcher started", flush=True)
    while True:
        try:
            await asyncio.sleep(ASM_DISPATCH_INTERVAL_SECONDS)
            await run_asm_dispatch(pool)
        except asyncio.CancelledError:
            print("[asm] Continuous ASM dispatcher stopped", flush=True)
            break
        except Exception as e:
            print(f"[asm] dispatcher error: {e}", flush=True)


# Database connection pool
db_pool: Optional[asyncpg.Pool] = None


def _int_env(name: str, default: int) -> int:
    """Coerce an env var to int, falling back to default on bad values."""
    try:
        raw = os.environ.get(name)
        return int(raw) if raw is not None and raw != "" else default
    except (TypeError, ValueError):
        return default


def _strip_pagination_for_count(query: str, params: list) -> tuple[str, list]:
    """Convert a SELECT…ORDER BY…LIMIT $N OFFSET $N+1 into a COUNT(*) query.

    Used by list endpoints that optimize the common case with COUNT(*) OVER()
    but still need a fallback `COUNT(*)` when the page is past the end of the
    result set (the window function returns no rows in that case).
    """
    # Remove ORDER BY ... LIMIT ... OFFSET ... — everything from ORDER BY on.
    order_by_idx = query.rfind("ORDER BY")
    body = query[:order_by_idx] if order_by_idx != -1 else query
    # Replace the SELECT … FROM with SELECT COUNT(*) FROM.
    from_idx = body.find("FROM")
    count_sql = "SELECT COUNT(*) " + body[from_idx:]
    # Drop the trailing LIMIT and OFFSET placeholders (always the last two args).
    return count_sql, params[:-2]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage database connection pool lifecycle and background tasks."""
    global db_pool
    # Larger pool defaults: with up to ~20 workers persisting findings, two
    # always-running background tasks (stale_scan_checker, schedule_runner),
    # and concurrent UI requests, min=2/max=10 starves under load. Tune via
    # DB_POOL_MIN_SIZE / DB_POOL_MAX_SIZE / DB_STATEMENT_TIMEOUT_MS env vars.
    db_pool_min = _int_env("DB_POOL_MIN_SIZE", 5)
    db_pool_max = _int_env("DB_POOL_MAX_SIZE", 25)
    db_statement_timeout_ms = _int_env("DB_STATEMENT_TIMEOUT_MS", 30000)

    async def _init_conn(conn):
        # Server-side cap so a runaway query (e.g. ILIKE without a usable
        # index) can't pin a pool slot indefinitely. 0 disables.
        if db_statement_timeout_ms > 0:
            await conn.execute(f"SET statement_timeout = {db_statement_timeout_ms}")

    db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=db_pool_min,
        max_size=db_pool_max,
        init=_init_conn,
    )
    await ensure_verification_schema(db_pool)

    # Publish the active-scan concurrency cap up front so a fresh/headless
    # deployment doesn't run on the worker fallback until /workers is first hit.
    try:
        _publish_max_active_scans()
        _publish_scanner_version()
    except Exception:
        pass

    # Start background tasks
    cleanup_task = asyncio.create_task(stale_scan_checker(db_pool))
    scheduler_task = asyncio.create_task(schedule_runner(db_pool))
    asm_task = asyncio.create_task(asm_dispatcher(db_pool))

    yield

    # Stop background tasks
    cleanup_task.cancel()
    scheduler_task.cancel()
    asm_task.cancel()
    for task in (cleanup_task, scheduler_task, asm_task):
        try:
            await task
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

    # Parallel scanning: split one scan of this target across the worker fleet.
    # See docs/parallel-scan-architecture.md.
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

    @field_validator("check_family", "asm_check_family")
    @classmethod
    def validate_scan_check_family(cls, value):
        return check_registry.validate_scan_focus_family(value)


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
    require_signature_verification: bool = False
    require_hash: bool = True
    require_model_governance: bool = True
    policy_profile: Optional[str] = None
    policy_exceptions: Optional[list[dict[str, Any]]] = None
    max_download_bytes: int = Field(default=10_000_000, ge=1024, le=100_000_000)
    timeout_seconds: int = Field(default=20, ge=1, le=120)


class ModelIntakeResolveRequest(BaseModel):
    platform: str = Field(default="auto", pattern="^(auto|huggingface|http|s3|gcs|azure|oci|mlflow)$")
    ref: str
    revision: Optional[str] = None
    filename: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=15, ge=1, le=60)


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
AI_PRINCIPAL_ROLES = {"attacker", "victim", "admin", "service", "observer"}
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


class AITargetPrincipalCreate(BaseModel):
    label: str
    role: str = "attacker"
    tenant_id: Optional[str] = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    credential: AITargetCredential = Field(default_factory=AITargetCredential)


class AITargetPrincipalUpdate(BaseModel):
    label: Optional[str] = None
    role: Optional[str] = None
    tenant_id: Optional[str] = None
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


class AIMCPLiveReadinessRequest(BaseModel):
    timeout_seconds: int = Field(default=8, ge=1, le=30)


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
    # Merged into the existing metadata (JSONB ||), so partial ownership
    # updates don't clobber unrelated keys. Set a key to "" to clear it.
    metadata_json: Optional[dict] = None


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


class AIFindingRetestRequest(BaseModel):
    mode: str = Field(default="same_probe", pattern="^(same_probe|same_family|strict_replay)$")
    requested_by: Optional[str] = "api"
    confirm_production: bool = False


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
    auto_fp_on_retest: Optional[bool] = None
    auto_fp_min_confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    demo_mode_enabled: Optional[bool] = None
    demo_honey_public_url: Optional[str] = None
    demo_honey_scanner_url: Optional[str] = None
    persist_to_env: bool = False


class ScanExecutionSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_sharding_enabled: Optional[bool] = None
    auto_sharding_strategy: Optional[str] = Field(default=None, pattern="^(auto|scope|family|coverage|coverage_family)$")
    auto_sharding_max_shards: Optional[int] = Field(default=None, ge=2, le=AUTO_SHARD_MAX_SHARDS)
    auto_sharding_min_workers: Optional[int] = Field(default=None, ge=1, le=20)


class AutomationSettingsUpdate(ScanExecutionSettingsUpdate):
    default_asm_enabled: Optional[bool] = None
    default_asm_config: Optional[dict[str, Any]] = None


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


def _normalize_ai_principal_role(value: Any) -> str:
    role = str(value or "attacker").strip().lower().replace("-", "_")
    if role not in AI_PRINCIPAL_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"role must be one of: {', '.join(sorted(AI_PRINCIPAL_ROLES))}",
        )
    return role


def _normalize_ai_principal_label(value: Any) -> str:
    label = str(value or "").strip()
    if not label:
        raise HTTPException(status_code=400, detail="principal label is required")
    if len(label) > 80:
        raise HTTPException(status_code=400, detail="principal label must be 80 characters or fewer")
    return label


def _sanitize_ai_principal(row: Any) -> dict[str, Any]:
    principal = row_to_dict(row)
    principal["metadata_json"] = _sanitize_scan_options(
        _decode_json_value(principal.get("metadata_json")) or {}
    )
    principal["credential"] = _sanitize_ai_credential(principal)
    for secret_key in ("secret_value", "secret_preview", "auth_kind", "header_name"):
        principal.pop(secret_key, None)
    return principal


def _ai_principal_ref(row: Any) -> dict[str, Any]:
    principal = row_to_dict(row)
    metadata = _decode_json_value(principal.get("metadata_json")) or {}
    return {
        "id": principal.get("id"),
        "label": principal.get("label"),
        "role": principal.get("role"),
        "tenant_id": principal.get("tenant_id"),
        "auth_kind": principal.get("auth_kind") or "none",
        "credential_configured": bool(principal.get("secret_value")),
        "metadata_json": _sanitize_scan_options(metadata),
    }


def _runtime_ai_principal_from_row(row: dict[str, Any]) -> dict[str, Any]:
    credential = _runtime_credential_from_row(row)
    return {
        "id": str(row.get("id")),
        "label": row.get("label"),
        "role": row.get("role") or "attacker",
        "tenant_id": row.get("tenant_id"),
        "metadata_json": _decode_json_value(row.get("metadata_json")) or {},
        "credential": credential,
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
        production_scan = bool(target_row["production_mode"]) or request.environment == "production"
        if production_scan and not request.confirm_production:
            reason = (
                "This AI target is marked production"
                if target_row["production_mode"]
                else "This AI Gate scan targets the production environment"
            )
            raise HTTPException(
                status_code=409,
                detail=f"{reason}. Re-submit with confirm_production=true.",
            )
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            uuid.UUID(target_id),
        )
        principal_rows = await conn.fetch(
            """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1 AND is_active = true
            ORDER BY role, label
            """,
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
            principals=list(principal_rows),
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
        "submitted_at": utc_now_iso(),
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


def _deployment_gate_findings(findings: Any, *, minimum: str = "high", limit: int = 20) -> list[dict[str, Any]]:
    if not isinstance(findings, list):
        return []
    threshold = SEVERITY_ORDER.get(minimum, SEVERITY_ORDER["high"])
    selected: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info").lower()
        if SEVERITY_ORDER.get(severity, 0) < threshold:
            continue
        selected.append({
            "id": finding.get("id") or finding.get("source_finding_id"),
            "title": finding.get("title"),
            "severity": severity,
            "tool": finding.get("tool"),
            "url": finding.get("url"),
        })
    selected.sort(key=lambda item: SEVERITY_ORDER.get(str(item.get("severity")), 0), reverse=True)
    return selected[:limit]


def _deployment_gate_required_evidence_missing(result: dict[str, Any], product: str) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    if product == "ai_gate":
        ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        execution_plan = ai_gate.get("execution_plan") if isinstance(ai_gate.get("execution_plan"), dict) else {}
        quality_gate = execution_plan.get("judging_quality_gate") if isinstance(execution_plan.get("judging_quality_gate"), dict) else {}
        if quality_gate.get("judging_required") and not quality_gate.get("judging_completed"):
            missing.append({
                "id": "semantic_judging",
                "label": "Semantic judging",
                "status": quality_gate.get("status") or "judging_required",
            })
    elif product == "model_intake":
        model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        checks = model_intake.get("checks") if isinstance(model_intake.get("checks"), dict) else {}
        for key, value in checks.items():
            if value is False:
                missing.append({"id": str(key), "label": str(key).replace("_", " "), "status": "failed"})
            elif value is None and key in {"signature_verification", "approval_evidence"}:
                missing.append({"id": str(key), "label": str(key).replace("_", " "), "status": "missing"})
    return missing


POLICY_PROFILES: dict[str, dict[str, Any]] = {
    "development": {
        "name": "development-ai-v1",
        "minimum_block_severity": "critical",
        "expires_days": 14,
        "allow_active_exceptions": True,
        "strict_model_intake": False,
    },
    "staging": {
        "name": "staging-ai-v1",
        "minimum_block_severity": "high",
        "expires_days": 21,
        "allow_active_exceptions": True,
        "strict_model_intake": False,
    },
    "production": {
        "name": "production-ai-v1",
        "minimum_block_severity": "high",
        "expires_days": 30,
        "allow_active_exceptions": True,
        "strict_model_intake": True,
    },
}


def _policy_profile_for_scan(scan: dict[str, Any], result: dict[str, Any], product: str) -> dict[str, Any]:
    options = _sanitize_scan_options(scan.get("options")) if scan.get("options") is not None else {}
    raw_options = _decode_json_value(scan.get("options")) if scan.get("options") is not None else {}
    policy_profile = ""
    if isinstance(raw_options, dict):
        policy_profile = str(
            raw_options.get("policy_profile")
            or raw_options.get("ai_environment")
            or raw_options.get("environment")
            or ""
        ).strip().lower()
    if not policy_profile and product == "ai_gate":
        ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        decision = ai_gate.get("decision") if isinstance(ai_gate.get("decision"), dict) else {}
        policy_profile = str(decision.get("environment") or "").strip().lower()
    if not policy_profile and product == "model_intake":
        summary = (result.get("model_intake") or {}).get("summary") if isinstance(result.get("model_intake"), dict) else {}
        policy_profile = str((summary or {}).get("deployment_environment") or "").strip().lower()
    if policy_profile not in POLICY_PROFILES:
        policy_profile = "production" if product in {"ai_gate", "model_intake"} else "staging"
    profile = dict(POLICY_PROFILES[policy_profile])
    profile["id"] = policy_profile
    if isinstance(options, dict) and options.get("policy_profile"):
        profile["requested_profile"] = options.get("policy_profile")
    return profile


def _exception_records(scan: dict[str, Any], result: dict[str, Any]) -> list[dict[str, Any]]:
    raw_options = _decode_json_value(scan.get("options")) if scan.get("options") is not None else {}
    candidates: list[Any] = []
    if isinstance(raw_options, dict):
        candidates.append(raw_options.get("policy_exceptions"))
        candidates.append(raw_options.get("exceptions"))
    if isinstance(result, dict):
        candidates.append(result.get("policy_exceptions"))
        for product_key in ("ai_gate", "model_intake"):
            product = result.get(product_key)
            if isinstance(product, dict):
                candidates.append(product.get("policy_exceptions"))
    exceptions: list[dict[str, Any]] = []
    for candidate in candidates:
        if isinstance(candidate, list):
            exceptions.extend(item for item in candidate if isinstance(item, dict))
    return exceptions


def _parse_iso_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _active_exception_ids(exceptions: list[dict[str, Any]]) -> set[str]:
    now = datetime.now(timezone.utc)
    active: set[str] = set()
    for item in exceptions:
        finding_id = str(item.get("finding_id") or item.get("id") or "").strip()
        if not finding_id:
            continue
        status = str(item.get("status") or item.get("decision") or "active").strip().lower()
        if status not in {"active", "approved", "accepted_risk"}:
            continue
        expires_at = _parse_iso_datetime(item.get("expires_at") or item.get("expiry"))
        if expires_at is None or expires_at <= now:
            continue
        if not item.get("approved_by") and not item.get("approver"):
            continue
        active.add(finding_id)
    return active


def _apply_policy_exceptions(
    blocking_findings: list[dict[str, Any]],
    exceptions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active_ids = _active_exception_ids(exceptions)
    if not active_ids:
        return blocking_findings, []
    remaining: list[dict[str, Any]] = []
    applied: list[dict[str, Any]] = []
    for finding in blocking_findings:
        finding_id = str(finding.get("id") or "")
        if finding_id in active_ids:
            applied.append(finding)
        else:
            remaining.append(finding)
    return remaining, applied


def build_deployment_decision(scan: dict[str, Any]) -> dict[str, Any]:
    result = _decode_json_value(scan.get("result")) or {}
    run_kind = str(scan.get("run_kind") or "")
    scan_type = str(scan.get("scan_type") or "")
    product = "dast"
    policy_name = "dast-default-v1"
    raw_decision = "needs_review"
    rationale = "Scan has not completed or has no deployment decision."
    findings = result.get("findings") if isinstance(result, dict) else []

    product_for_policy = "dast"
    if isinstance(result, dict) and (result.get("ai_gate") or run_kind.startswith("ai_")):
        product_for_policy = "ai_gate"
    elif isinstance(result, dict) and (result.get("model_intake") or run_kind == "model_intake"):
        product_for_policy = "model_intake"
    policy_profile = _policy_profile_for_scan(scan, result if isinstance(result, dict) else {}, product_for_policy)

    if isinstance(result, dict) and (result.get("ai_gate") or run_kind.startswith("ai_")):
        product = "ai_gate"
        decision_obj = (result.get("ai_gate") or {}).get("decision") if isinstance(result.get("ai_gate"), dict) else {}
        raw_decision = str((decision_obj or {}).get("decision") or "needs_review")
        rationale = str((decision_obj or {}).get("rationale") or "AI Gate decision requires review.")
        policy_name = str((decision_obj or {}).get("policy_name") or policy_profile["name"])
    elif isinstance(result, dict) and (result.get("model_intake") or run_kind == "model_intake"):
        product = "model_intake"
        result_obj = result.get("result") if isinstance(result.get("result"), dict) else {}
        intake_decision = str(result_obj.get("decision") or "review")
        raw_decision = "needs_approval" if intake_decision == "review" else intake_decision
        rationale = str(result_obj.get("decision_reason") or "Model Intake decision requires review.")
        policy_name = policy_profile["name"]
    elif isinstance(result, dict) and scan.get("status") == "completed":
        blocking = _deployment_gate_findings(findings)
        if blocking:
            raw_decision = "block"
            rationale = f"{len(blocking)} high/critical finding(s) require a block before deploy."
        else:
            raw_decision = "allow"
            rationale = "No high/critical findings met the deployment block threshold."
        policy_name = f"{scan_type or 'scan'}-default-v1"

    if raw_decision == "review":
        raw_decision = "needs_approval"
    if raw_decision not in {"allow", "needs_approval", "needs_review", "block"}:
        raw_decision = "needs_review"

    missing = _deployment_gate_required_evidence_missing(result if isinstance(result, dict) else {}, product)
    if raw_decision == "allow" and missing:
        raw_decision = "needs_review"
        rationale = "Required deployment evidence is missing or incomplete."
    blocking_findings = _deployment_gate_findings(
        findings,
        minimum=str(policy_profile.get("minimum_block_severity") or "high"),
    )
    exceptions = _exception_records(scan, result if isinstance(result, dict) else {})
    blocking_findings, applied_exceptions = _apply_policy_exceptions(blocking_findings, exceptions)
    if blocking_findings and raw_decision == "allow":
        raw_decision = "block"
        rationale = f"{len(blocking_findings)} finding(s) meet the {policy_profile['id']} block threshold."
    if raw_decision == "block" and not blocking_findings and applied_exceptions:
        raw_decision = "needs_approval"
        rationale = "Blocking findings are covered by active time-bound policy exceptions."

    return {
        "scan_id": str(scan.get("id")),
        "status": scan.get("status"),
        "decision": raw_decision,
        "product": product,
        "policy_name": policy_name,
        "policy_profile": policy_profile["id"],
        "rationale": rationale,
        "blocking_findings": blocking_findings,
        "applied_exceptions": applied_exceptions,
        "expired_or_invalid_exceptions": max(0, len(exceptions) - len(applied_exceptions)),
        "required_evidence_missing": missing,
        "score": scan.get("score") or (result.get("result") or {}).get("score") if isinstance(result, dict) else scan.get("score"),
        "grade": scan.get("grade") or (result.get("result") or {}).get("grade") if isinstance(result, dict) else scan.get("grade"),
        "expires_at": (datetime.now(timezone.utc) + timedelta(days=int(policy_profile.get("expires_days") or 30))).isoformat(),
    }


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
    findings_by_ai_target: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        ai_target_id = str(finding.get("ai_target_id") or "")
        if ai_target_id:
            findings_by_ai_target.setdefault(ai_target_id, []).append(finding)

    model_supply_chain_id = "group:model-supply-chain"

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
                # Model artifacts record the hosting platform as an origin, not
                # a root domain — huggingface.co is not part of the user's
                # attack surface, the artifact pulled from it is.
                "origin" if is_model_artifact else "root_domain": root_domain,
                "exposure_class": _exposure_class(target.get("url"), kind="model" if is_model_artifact else "web"),
                "unscanned": int(target.get("total_scans") or 0) <= 0,
                "last_score": target.get("last_score"),
                "last_grade": target.get("last_grade"),
                "active_findings_count": active_findings,
                "total_scans": target.get("total_scans") or 0,
                "discovery_source": target.get("discovery_source"),
            },
        ))
        if is_model_artifact:
            add_node(_graph_node(
                model_supply_chain_id,
                "model_supply_chain",
                "Model supply chain",
                subtitle="External model artifacts",
                href="/settings/model-intake",
            ))
            edges.append(_graph_edge(model_supply_chain_id, node_id, "contains_artifact", label="supply chain artifact"))
        else:
            domain_id = add_domain(root_domain)
            if domain_id:
                edges.append(_graph_edge(domain_id, node_id, "contains", label="contains target"))

    for ai_target in ai_targets:
        ai_id = str(ai_target.get("id"))
        node_id = f"ai_target:{ai_id}"
        ai_node_by_id[ai_id] = node_id
        ai_target_by_id[ai_id] = ai_target
        root_domain = extract_root_domain(ai_target.get("endpoint_url") or "")
        blast_radius = build_agent_blast_radius(ai_target, findings_by_ai_target.get(ai_id, []))
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
                "exposure_class": _exposure_class(ai_target.get("endpoint_url"), kind="ai"),
                "unscanned": not ai_target.get("last_scanned_at"),
                "target_type": ai_target.get("target_type"),
                "method": ai_target.get("method"),
                "production_mode": bool(ai_target.get("production_mode")),
                "last_scanned_at": ai_target.get("last_scanned_at"),
                "blast_radius": blast_radius,
                "blast_radius_score": blast_radius.get("score"),
                "blast_radius_tier": blast_radius.get("tier"),
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
        # Scans are events, not exposure: they contribute derived assets and
        # linkage below but are not emitted as graph nodes themselves. Scan
        # context lives in the asset detail panels instead.
        scan_subject_by_id[scan_id] = subject_id

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
            edges.append(_graph_edge(subject_id, chain_node_id, "exploit_path", label="exploit path", severity=severity))

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
            # Risk-bearing endpoints inherit their worst finding's severity so
            # they rank into fan-out budgets and render with severity rings.
            endpoint_node = nodes.get(endpoint_node_id)
            if endpoint_node and _severity_sort_value(severity) > _severity_sort_value(endpoint_node.get("severity")):
                endpoint_node["severity"] = severity
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


# Edge types that are pure structural plumbing (endpoint enumeration). They
# dominate edge volume and carry no exposure signal, so they are collapsed out
# of the rendered subgraph unless endpoints are explicitly requested.
_EXPOSURE_STRUCTURAL_EDGE_TYPES = {
    "defines_endpoint",
    "exposes_endpoint",
    "observed_endpoint",
}


def _focus_exposure_subgraph(
    graph: dict[str, Any],
    *,
    focus: str | None,
    depth: int,
    include_endpoints: bool,
    max_nodes: int = 350,
    max_fanout: int = 15,
) -> dict[str, Any]:
    """Reduce a full exposure graph to a focused, renderable subgraph.

    Without a focus node we return a seed view (risk hotspots + domains and
    their immediate neighbours). With a focus node we return its neighbourhood
    out to ``depth``. Endpoint plumbing is collapsed unless explicitly
    requested. The full-graph summary is preserved so overview stats stay
    accurate, with rendered counts and a ``truncated`` flag added.
    """
    nodes: list[dict[str, Any]] = graph.get("nodes", [])
    edges: list[dict[str, Any]] = graph.get("edges", [])
    nodes_by_id = {node["id"]: node for node in nodes}

    if include_endpoints:
        active_edges = edges
    else:
        # Finding-free endpoints are enumeration noise and stay collapsed into
        # API-surface counts; endpoints that carry findings are the connective
        # tissue between asset and vulnerability and stay in the default view.
        endpoint_ids = {n["id"] for n in nodes if n["type"] == "endpoint"}
        risky_endpoint_ids = {
            e["source"] for e in edges if e["type"] == "affected_by" and e["source"] in endpoint_ids
        }

        def _keep_edge(e: dict[str, Any]) -> bool:
            touches_endpoint = e["source"] in endpoint_ids or e["target"] in endpoint_ids
            if not touches_endpoint:
                return e["type"] not in _EXPOSURE_STRUCTURAL_EDGE_TYPES
            if e["type"] == "affected_by":
                return e["source"] in risky_endpoint_ids
            if e["type"] in ("exposes_endpoint", "observed_endpoint"):
                return e["target"] in risky_endpoint_ids
            return False

        active_edges = [e for e in edges if _keep_edge(e)]

    adjacency: dict[str, list[str]] = {}
    for edge in active_edges:
        adjacency.setdefault(edge["source"], []).append(edge["target"])
        adjacency.setdefault(edge["target"], []).append(edge["source"])

    def _risk_key(node_id: str) -> tuple[int, int]:
        node = nodes_by_id[node_id]
        return (
            _severity_sort_value(node.get("severity")),
            int(node.get("meta", {}).get("active_findings_count") or 0),
        )

    if focus and focus in nodes_by_id:
        seeds = [focus]
    else:
        focus = None
        # Lead the overview with risk: seed from hotspots and let BFS pull in
        # their neighbourhoods. Domains surface naturally as hotspot neighbours.
        hotspot_ids = [n["id"] for n in graph.get("summary", {}).get("hotspots", []) if n["id"] in nodes_by_id]
        if hotspot_ids:
            seeds = list(dict.fromkeys(hotspot_ids))
        else:
            anchor_ids = [n["id"] for n in nodes if n["type"] in ("domain", "model_supply_chain")]
            seeds = anchor_ids or [n["id"] for n in sorted(nodes, key=_risk_key, reverse=True)[:25]]

    # Cap per-node fan-out so hub nodes (a domain wired to hundreds of AI
    # surfaces) cannot explode the rendered graph; keep the riskiest neighbours.
    capped = False
    visited: set[str] = {s for s in seeds if s in nodes_by_id}
    queue: list[tuple[str, int]] = [(s, 0) for s in list(visited)]
    while queue:
        node_id, dist = queue.pop(0)
        if dist >= depth:
            continue
        neighbors = [n for n in dict.fromkeys(adjacency.get(node_id, [])) if n in nodes_by_id]
        if len(neighbors) > max_fanout:
            capped = True
            neighbors = sorted(neighbors, key=_risk_key, reverse=True)[:max_fanout]
        for neighbor in neighbors:
            if neighbor in visited:
                continue
            visited.add(neighbor)
            queue.append((neighbor, dist + 1))

    truncated = capped
    if len(visited) > max_nodes:
        truncated = True
        seed_set = set(seeds)
        ranked = sorted(
            visited,
            key=lambda nid: (
                nid in seed_set,
                _severity_sort_value(nodes_by_id[nid].get("severity")),
                int(nodes_by_id[nid].get("meta", {}).get("active_findings_count") or 0),
            ),
            reverse=True,
        )
        visited = set(ranked[:max_nodes])

    sub_nodes = [nodes_by_id[nid] for nid in visited]
    sub_edges = [e for e in active_edges if e["source"] in visited and e["target"] in visited]

    sub_nodes, sub_edges = _cluster_exposure_findings(sub_nodes, sub_edges, protect_id=focus)

    summary = dict(graph.get("summary", {}))
    summary["rendered_node_count"] = len(sub_nodes)
    summary["rendered_edge_count"] = len(sub_edges)
    summary["truncated"] = truncated
    summary["focus"] = focus
    summary["include_endpoints"] = include_endpoints

    return {"nodes": sub_nodes, "edges": sub_edges, "summary": summary}


def _normalize_finding_title(title: str) -> str:
    """Collapse instance-specific detail so similar findings group together.

    "Accessible Sensitive File: /.git/config" and ".../wp-config.php.old" both
    normalise to "Accessible Sensitive File"; "SQL Injection (post id)" to
    "SQL Injection".
    """
    base = re.split(r"[:(]", str(title or ""), maxsplit=1)[0]
    return base.strip() or str(title or "").strip()


def _cluster_exposure_findings(
    sub_nodes: list[dict[str, Any]],
    sub_edges: list[dict[str, Any]],
    *,
    min_group: int = 3,
    protect_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Collapse repetitive findings on the same asset into one group node.

    Findings that share a parent asset (via a ``has_finding`` edge) and a
    normalised title are merged into a single ``finding_group`` node carrying
    the members in ``meta.members``. Groups smaller than ``min_group`` stay as
    individual nodes. Edges touching grouped members are rewired to the group.
    ``protect_id`` (the focused node) is never folded into a group so it stays
    addressable.
    """
    nodes_by_id = {n["id"]: n for n in sub_nodes}

    # Parent asset for each finding = source of its has_finding edge.
    parent_of: dict[str, str] = {}
    for edge in sub_edges:
        if edge["type"] == "has_finding" and edge["target"] in nodes_by_id:
            parent_of.setdefault(edge["target"], edge["source"])

    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for node in sub_nodes:
        if node["type"] != "finding" or node["id"] == protect_id:
            continue
        parent = parent_of.get(node["id"])
        if not parent:
            continue
        key = (parent, _normalize_finding_title(node["label"]).lower())
        groups.setdefault(key, []).append(node)

    member_to_group: dict[str, str] = {}
    group_nodes: dict[str, dict[str, Any]] = {}
    for (parent, norm_key), members in groups.items():
        if len(members) < min_group:
            continue
        members_sorted = sorted(members, key=lambda m: _severity_sort_value(m.get("severity")), reverse=True)
        display_title = _normalize_finding_title(members_sorted[0]["label"])
        group_id = f"finding_group:{_graph_hash(parent, norm_key)}"
        top_severity = members_sorted[0].get("severity")
        for member in members_sorted:
            member_to_group[member["id"]] = group_id
        group_nodes[group_id] = _graph_node(
            group_id,
            "finding_group",
            f"{display_title} ×{len(members_sorted)}",
            subtitle=f"{len(members_sorted)} similar findings",
            severity=top_severity,
            meta={
                "count": len(members_sorted),
                "normalized_title": display_title,
                "members": [
                    {
                        "id": m["id"],
                        "title": m["label"],
                        "severity": m.get("severity"),
                        "status": m.get("meta", {}).get("status"),
                        "href": m.get("href"),
                    }
                    for m in members_sorted
                ],
            },
        )

    if not group_nodes:
        return sub_nodes, sub_edges

    new_nodes = [n for n in sub_nodes if n["id"] not in member_to_group]
    new_nodes.extend(group_nodes.values())

    seen_edges: set[tuple[str, str, str]] = set()
    new_edges: list[dict[str, Any]] = []
    for edge in sub_edges:
        source = member_to_group.get(edge["source"], edge["source"])
        target = member_to_group.get(edge["target"], edge["target"])
        if source == target:
            continue
        key = (source, target, edge["type"])
        if key in seen_edges:
            continue
        seen_edges.add(key)
        new_edges.append({**edge, "source": source, "target": target})

    return new_nodes, new_edges


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
    principals: Optional[list[Any]] = None,
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
    production_scan = bool(target.get("production_mode")) or environment == "production"
    production_confirmation = None
    if production_scan:
        production_confirmation = {
            "confirmed": bool(request.confirm_production),
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
            "environment": environment,
            "target_production_mode": bool(target.get("production_mode")),
            "probe_pack": probe_pack,
            "scan_profile": scan_profile,
        }
        metadata_json["production_confirmation"] = production_confirmation

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
    if production_confirmation:
        storage_options["production_confirmation"] = production_confirmation
    principal_refs = [_ai_principal_ref(row) for row in (principals or [])]
    if principal_refs:
        metadata_json["principal_count"] = len(principal_refs)
        metadata_json["principal_roles"] = sorted(
            {str(item.get("role") or "") for item in principal_refs if item.get("role")}
        )
        storage_options["ai_principal_count"] = len(principal_refs)
        storage_options["ai_principal_roles"] = metadata_json["principal_roles"]
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
            "credential_ref": {
                "ai_target_id": target["id"],
                "configured": bool(credential.get("secret"))
                or bool((credential.get("metadata_json") or {}).get("headers")),
            },
        },
    }
    if principal_refs:
        worker_options["ai_target"]["principal_refs"] = principal_refs
    return worker_options, storage_options


def _ai_finding_probe_context(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = parse_json_field(finding.get("evidence")) or {}
    probe_id = str(evidence.get("probe_id") or "").strip()
    probe_family = str(evidence.get("probe_family") or evidence.get("strategy_id") or "").strip()
    source_finding_id = str(evidence.get("source_finding_id") or "").strip()
    if not source_finding_id:
        raw_expected = evidence.get("expected_finding") or evidence.get("oracle_expected_finding")
        if probe_id and raw_expected:
            source_finding_id = f"{probe_id}:{str(raw_expected).split(':')[-1]}"
    if not probe_id and source_finding_id and ":" in source_finding_id:
        probe_id = source_finding_id.split(":", 1)[0]
    turns = evidence.get("turns")
    if not probe_family and isinstance(turns, list) and turns:
        first_turn = turns[0] if isinstance(turns[0], dict) else {}
        probe_family = str(first_turn.get("probe_family") or "").strip()
    return {
        "probe_id": probe_id,
        "probe_family": probe_family,
        "source_finding_id": source_finding_id,
        "evidence": evidence,
    }


def _ai_scan_options_from_row(scan_row: Any) -> dict[str, Any]:
    if not scan_row:
        return {}
    options = scan_row.get("options") if isinstance(scan_row, dict) else scan_row["options"]
    return parse_json_field(options) or {}


def _build_ai_finding_retest_scan_options(
    *,
    target: dict[str, Any],
    credential: dict[str, Any],
    finding: dict[str, Any],
    original_scan_options: dict[str, Any],
    request: AIFindingRetestRequest,
    verification_id: uuid.UUID,
    principals: Optional[list[Any]] = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    context = _ai_finding_probe_context(finding)
    probe_id = context.get("probe_id")
    probe_family = context.get("probe_family")
    if request.mode in {"same_probe", "strict_replay"} and not probe_id:
        raise HTTPException(status_code=400, detail="AI Gate finding is missing probe_id context for focused replay")
    if request.mode == "same_family" and not probe_family:
        raise HTTPException(status_code=400, detail="AI Gate finding is missing probe_family context for family replay")

    original_confirmation = original_scan_options.get("production_confirmation")
    original_confirmed = isinstance(original_confirmation, dict) and original_confirmation.get("confirmed") is True
    scan_request = AITargetScanRequest(
        probe_pack=str(original_scan_options.get("ai_probe_pack") or "shaker-ai-smoke"),
        scan_profile=str(original_scan_options.get("ai_scan_profile") or "smoke"),
        environment=str(original_scan_options.get("ai_environment") or "preview"),
        confirm_production=bool(request.confirm_production or original_confirmed),
        ai_judge_enabled=original_scan_options.get("ai_judge_enabled"),
        semantic_judge_enabled=original_scan_options.get("semantic_judge_enabled"),
    )
    worker_options, storage_options = _build_ai_worker_options(
        target=target,
        credential=credential,
        request=scan_request,
        principals=principals,
    )

    focus_probe_ids = [probe_id] if request.mode in {"same_probe", "strict_replay"} and probe_id else []
    focus_probe_family = probe_family if request.mode == "same_family" else None
    metadata_json = worker_options["ai_target"].setdefault("metadata_json", {})
    if focus_probe_ids:
        worker_options["ai_focus_probe_ids"] = focus_probe_ids
        metadata_json["ai_focus_probe_ids"] = focus_probe_ids
    if focus_probe_family:
        worker_options["ai_focus_probe_family"] = focus_probe_family
        metadata_json["ai_focus_probe_family"] = focus_probe_family
    if request.mode == "strict_replay":
        metadata_json["strict_replay"] = True
        metadata_json["replay_previous_response"] = context["evidence"].get("response_excerpt")

    replay_plan = {
        "mode": request.mode,
        "finding_id": str(finding["id"]),
        "verification_id": str(verification_id),
        "probe_id": probe_id,
        "probe_family": probe_family,
        "source_finding_id": context.get("source_finding_id"),
        "probe_pack": scan_request.probe_pack,
        "scan_profile": scan_request.scan_profile,
        "environment": scan_request.environment,
    }
    worker_options["ai_finding_retest"] = replay_plan
    storage_options["ai_finding_retest"] = replay_plan
    return worker_options, storage_options, replay_plan


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
    started = utc_now()
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
        elapsed_ms = round((utc_now() - started).total_seconds() * 1000, 1)
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

    elapsed_ms = round((utc_now() - started).total_seconds() * 1000, 1)
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
            "ai_inventory": "/ai/inventory",
            "ai_test_scenarios": "/ai/test-scenarios",
            "ai_learning_guide": "/ai/learning-guide",
            "ai_test_cases": "/ai/test-cases",
            "model_intake": "/model-intake/scan",
            "model_intake_resolve": "/model-intake/resolve",
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
    run_id = f"demo-{utc_now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
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


def _hash_source_files(file_map: dict) -> Optional[str]:
    """Hash runtime source files keyed by logical name (basename), stable order.

    Immutable build identity that detects drift even when GIT_COMMIT is unset:
    keyed by basename so the API (hashing the host checkout) and a worker (hashing
    /app) yield the SAME checksum when the code matches, and differ when it doesn't.
    """
    import hashlib
    h = hashlib.sha256()
    hashed = 0
    for name in sorted(file_map):
        try:
            with open(file_map[name], "rb") as fh:
                h.update(name.encode())
                h.update(b"\0")
                h.update(fh.read())
            hashed += 1
        except OSError:
            continue
    return h.hexdigest()[:16] if hashed else None


def expected_build_fingerprint() -> Optional[str]:
    """Source checksum of the CURRENT checkout (host bind-mount at /workspace),
    falling back to the API's own /app runtime. This is the 'current build' the UI
    compares each scan's / worker's reported fingerprint against."""
    # Must match (by basename) scanner.SCANNER_FINGERPRINT_FILES and the worker's
    # report set, including worker.py and the output-shaping modules, so a worker
    # running stale orchestration/output code is not reported as build_current.
    workspace = {
        "scanner.py": "/workspace/scanner/scanner.py",
        "active_checks.py": "/workspace/scanner/scanner_tools/active_checks.py",
        "parallel_scan.py": "/workspace/api/parallel_scan.py",
        "finding_validator.py": "/workspace/scanner/scanner_tools/finding_validator.py",
        "worker.py": "/workspace/api/worker.py",
        "constants.py": "/workspace/scanner/constants.py",
        "findings.py": "/workspace/scanner/findings.py",
        "grading.py": "/workspace/scanner/grading.py",
        "reporting.py": "/workspace/scanner/reporting.py",
        "data_exposure.py": "/workspace/scanner/scanner_tools/data_exposure.py",
        "webhook_checks.py": "/workspace/scanner/scanner_tools/webhook_checks.py",
        "approval_checks.py": "/workspace/scanner/scanner_tools/approval_checks.py",
        "access_control_checks.py": "/workspace/scanner/scanner_tools/access_control_checks.py",
        "infrastructure_checks.py": "/workspace/scanner/scanner_tools/infrastructure_checks.py",
    }
    if all(os.path.exists(p) for p in workspace.values()):
        return _hash_source_files(workspace)
    return _hash_source_files({
        "scanner.py": "/app/scanner.py",
        "active_checks.py": "/app/scanner_tools/active_checks.py",
        "parallel_scan.py": "/app/parallel_scan.py",
        "finding_validator.py": "/app/scanner_tools/finding_validator.py",
        "worker.py": "/app/worker.py",
        "constants.py": "/app/constants.py",
        "findings.py": "/app/findings.py",
        "grading.py": "/app/grading.py",
        "reporting.py": "/app/reporting.py",
        "data_exposure.py": "/app/scanner_tools/data_exposure.py",
        "webhook_checks.py": "/app/scanner_tools/webhook_checks.py",
        "approval_checks.py": "/app/scanner_tools/approval_checks.py",
        "access_control_checks.py": "/app/scanner_tools/access_control_checks.py",
        "infrastructure_checks.py": "/app/scanner_tools/infrastructure_checks.py",
    })


def _git_head_short(repo: str = "/workspace") -> Optional[str]:
    """Resolve the real short commit of the mounted checkout (the API bind-mounts
    the repo at /workspace). Pure-file resolution so it works without a git binary;
    handles symbolic HEAD, packed-refs, and detached HEAD."""
    try:
        git_dir = os.path.join(repo, ".git")
        head = open(os.path.join(git_dir, "HEAD")).read().strip()
        if head.startswith("ref:"):
            ref = head.split(" ", 1)[1].strip()
            loose = os.path.join(git_dir, ref)
            if os.path.exists(loose):
                return open(loose).read().strip()[:7]
            packed = os.path.join(git_dir, "packed-refs")
            if os.path.exists(packed):
                for line in open(packed):
                    line = line.strip()
                    if line and not line.startswith(("#", "^")) and line.endswith(ref):
                        return line.split()[0][:7]
            return None
        return head[:7] if len(head) >= 7 else None
    except Exception:
        return None


def current_scanner_version() -> str:
    """Human build label used by API/workers to detect mixed deployments. Prefer
    the live checkout's real commit (the API bind-mounts the repo at /workspace) so
    the label reflects code deployed via volume-mount restarts, not the commit baked
    into SCANNER_VERSION/GIT_COMMIT env when the container image was built."""
    return (
        _git_head_short()
        or os.environ.get("SCANNER_VERSION")
        or os.environ.get("GIT_COMMIT")
        or "dev"
    )


def _publish_scanner_version() -> str:
    """Publish the real current build label to Redis so workers stamp/report the
    deployed commit (their baked SCANNER_VERSION env is frozen at image build)."""
    v = current_scanner_version()
    try:
        get_redis().set("shakerscan:scanner_version", v, ex=120)
    except Exception:
        pass
    return v


def worker_build_current(
    *,
    reported_fingerprint: Optional[str],
    reported_version: Optional[str],
    expected_fingerprint: Optional[str],
    expected_version: Optional[str],
) -> Optional[bool]:
    """Return whether a worker matches the API's current runtime identity.

    The source fingerprint catches most code changes, but it is deliberately a
    curated file set. The git/version label catches commits outside that set and
    prevents old scaled-out workers from being reported current after rebuilds.
    """
    if not reported_fingerprint and not reported_version:
        return None
    fingerprint_ok = (
        reported_fingerprint == expected_fingerprint
        if reported_fingerprint and expected_fingerprint
        else None
    )
    version_ok = (
        reported_version == expected_version
        if reported_version and expected_version
        else None
    )
    # The source fingerprint is the authoritative currency signal — it now covers
    # every detection/orchestration module. The git version label is volatile (it
    # is the real commit, and workers snapshot the published value once at startup),
    # so a current worker that snapshotted a slightly older label would look falsely
    # stale if version had to match too. Trust the fingerprint when we have it; fall
    # back to the version label only when no fingerprint is reported.
    if fingerprint_ok is not None:
        return fingerprint_ok
    return version_ok


def _worker_freshness_snapshot() -> dict:
    """Fleet build-freshness snapshot for scan-submit guards/metadata (§2).

    Returns fleet_size, running, stale_count, stale_names, and the expected build
    fingerprint. Best-effort: when Docker/Redis are unavailable, returns
    available=False so callers fail open (never block a scan on missing telemetry).
    """
    snap = {
        "available": False,
        "fleet_size": 0,
        "running": 0,
        "stale_count": 0,
        "stale_names": [],
        "expected_build_fingerprint": expected_build_fingerprint(),
    }
    try:
        filters = urllib.parse.quote('{"name":["worker"]}')
        status, containers = docker_socket_request(
            "GET", f"/containers/json?all=true&filters={filters}")
        if status != 200 or not isinstance(containers, list):
            return snap
        expected_fp = snap["expected_build_fingerprint"]
        expected_version = current_scanner_version()
        try:
            wb_raw = get_redis().hgetall("shakerscan:worker_build") or {}
        except Exception:
            wb_raw = {}
        wb: dict = {}
        for host, raw in wb_raw.items():
            hs = host.decode() if isinstance(host, bytes) else str(host)
            rs = raw.decode() if isinstance(raw, bytes) else raw
            try:
                wb[hs.lower()] = json.loads(rs)
            except Exception:
                continue

        def _bfc(cid: str):
            cid = (cid or "").lower()
            for hs, info in wb.items():
                if hs and cid.startswith(hs):
                    return info
            return None

        snap["available"] = True
        for c in containers:
            names = c.get("Names", [])
            name = names[0].lstrip("/") if names else ""
            if not _is_scan_worker_container_name(name):
                continue
            snap["fleet_size"] += 1
            if c.get("State") == "running":
                snap["running"] += 1
            info = _bfc(c.get("Id", "")) or {}
            cur = worker_build_current(
                reported_fingerprint=info.get("build_fingerprint"),
                reported_version=info.get("scanner_version"),
                expected_fingerprint=expected_fp,
                expected_version=expected_version,
            )
            if cur is False:
                snap["stale_count"] += 1
                snap["stale_names"].append(name)
    except Exception:
        pass
    return snap


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
        "redis": "ok" if redis_ok else "error",
        # Current build identity. scanner_version is the human label (git short sha
        # when set, else "dev"); build_fingerprint is a source-tree checksum that
        # differs whenever the runtime code differs — so the UI can flag a scan or
        # worker on a stale image even when scanner_version is "dev" on both.
        "scanner_version": current_scanner_version(),
        "build_fingerprint": expected_build_fingerprint(),
    }


@app.get("/settings/ai")
async def get_ai_settings():
    """Get effective AI settings (secrets masked)."""
    settings = _load_effective_ai_settings()
    return _sanitize_ai_settings_response(settings)


@app.get("/settings/scan-execution")
async def get_scan_execution_settings():
    """Get effective scan execution settings."""
    settings = _load_effective_scan_execution_settings()
    return _sanitize_scan_execution_settings_response(settings)


def _scan_execution_update_mapping(request: ScanExecutionSettingsUpdate) -> dict[str, str]:
    updates: dict[str, str] = {}
    if request.auto_sharding_enabled is not None:
        updates["auto_sharding_enabled"] = "true" if request.auto_sharding_enabled else "false"
    if request.auto_sharding_strategy is not None:
        updates["auto_sharding_strategy"] = _normalize_parallel_strategy(
            request.auto_sharding_strategy,
            default="auto",
        )
    if request.auto_sharding_max_shards is not None:
        updates["auto_sharding_max_shards"] = str(
            _normalize_auto_shard_count(request.auto_sharding_max_shards, default=4)
        )
    if request.auto_sharding_min_workers is not None:
        updates["auto_sharding_min_workers"] = str(max(1, int(request.auto_sharding_min_workers)))
    return updates


@app.put("/settings/scan-execution")
async def update_scan_execution_settings(request: ScanExecutionSettingsUpdate):
    """Update runtime scan execution settings."""
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    updates = _scan_execution_update_mapping(request)
    if updates:
        r.hset(SCAN_SETTINGS_KEY, mapping=updates)

    settings = _load_effective_scan_execution_settings()
    return {
        "status": "updated",
        "settings": _sanitize_scan_execution_settings_response(settings),
    }


@app.get("/settings/automation")
async def get_automation_settings():
    """Get compact safe automation defaults for Settings, API, and AI agents."""
    return _sanitize_automation_settings_response()


@app.put("/settings/automation")
async def update_automation_settings(request: AutomationSettingsUpdate):
    """Update compact safe automation defaults.

    This intentionally allows only safe default ASM policy. Lab/deep active depth
    remains an explicit per-target or per-operation decision.
    """
    try:
        r = get_redis()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {e}")

    current_automation = _load_effective_automation_settings()

    scan_updates = _scan_execution_update_mapping(request)
    if scan_updates:
        r.hset(SCAN_SETTINGS_KEY, mapping=scan_updates)

    automation_updates: dict[str, str] = {}
    if request.default_asm_enabled is not None:
        automation_updates["default_asm_enabled"] = "true" if request.default_asm_enabled else "false"
    if request.default_asm_config is not None:
        automation_updates["default_asm_config"] = json.dumps(
            _merge_safe_default_asm_config(
                current_automation.get("default_asm_config"),
                request.default_asm_config,
            )
        )
    if automation_updates:
        r.hset(AUTOMATION_SETTINGS_KEY, mapping=automation_updates)

    return {
        "status": "updated",
        "settings": _sanitize_automation_settings_response(),
    }


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
    if request.auto_fp_on_retest is not None:
        updates["auto_fp_on_retest"] = "true" if request.auto_fp_on_retest else "false"
    if request.auto_fp_min_confidence is not None:
        updates["auto_fp_min_confidence"] = str(_normalize_confidence(request.auto_fp_min_confidence, default=0.9))
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
            "AUTO_FP_ON_RETEST": "true" if effective.get("auto_fp_on_retest", False) else "false",
            "AUTO_FP_MIN_CONFIDENCE": str(_normalize_confidence(effective.get("auto_fp_min_confidence"), default=0.9)),
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

MODEL_INTAKE_SAFER_EXTENSIONS = {".safetensors", ".onnx", ".tflite", ".gguf"}
MODEL_INTAKE_RISKY_EXTENSIONS = {".pkl", ".pickle", ".joblib", ".pt", ".pth", ".ckpt", ".bin", ".mar"}
MODEL_INTAKE_COMMON_ARTIFACTS = {
    "model.safetensors",
    "pytorch_model.bin",
    "tf_model.h5",
    "model.onnx",
    "model.tflite",
    "model.gguf",
    "adapter_model.safetensors",
    "adapter_model.bin",
}
MODEL_INTAKE_TOKENIZER_FILES = {
    "merges.txt",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer.model",
    "tokenizer_config.json",
    "vocab.json",
    "vocab.txt",
}
MODEL_INTAKE_DEPENDENCY_FILES = {
    "conda.yml",
    "dockerfile",
    "environment.yml",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
    "setup.cfg",
    "setup.py",
}
MODEL_INTAKE_METADATA_FILES = {
    "config.json",
    "generation_config.json",
    "model_index.json",
    "model.safetensors.index.json",
    "readme.md",
}
HF_MODEL_INFO_MAX_BYTES = 10_000_000


def _import_model_intake_helpers():
    try:
        from scanner_tools.model_intake import normalize_model_artifact_reference, parse_huggingface_ref
    except ModuleNotFoundError as exc:
        if exc.name != "scanner_tools":
            raise
        from scanner.scanner_tools.model_intake import normalize_model_artifact_reference, parse_huggingface_ref
    return normalize_model_artifact_reference, parse_huggingface_ref


def _is_hf_ref(ref: str) -> bool:
    parsed = urllib.parse.urlparse(ref)
    return parsed.scheme == "hf" or parsed.netloc.endswith("huggingface.co")


def _detect_model_intake_platform(ref: str, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    platform_hint = str(
        metadata.get("artifact_platform")
        or metadata.get("storage_provider")
        or metadata.get("registry_provider")
        or ""
    ).strip().lower().replace("-", "_")
    if platform_hint in {"huggingface", "http", "s3", "gcs", "azure", "azure_blob", "oci", "mlflow"}:
        return "azure" if platform_hint == "azure_blob" else platform_hint

    raw = str(ref or "").strip()
    lowered = raw.lower()
    parsed = urllib.parse.urlparse(raw)
    host = parsed.netloc.lower()

    if _is_hf_ref(raw) or re.fullmatch(r"[\w.-]+/[\w.-]+", raw):
        return "huggingface"
    if lowered.startswith("oci://"):
        return "oci"
    if lowered.startswith(("mlflow://", "models:/", "runs:/")):
        return "mlflow"
    if parsed.scheme == "s3" or host == "s3.amazonaws.com" or host.startswith("s3.") or ".s3." in host or ".s3-" in host:
        return "s3"
    if parsed.scheme in {"gs", "gcs"} or host == "storage.googleapis.com" or host.endswith(".storage.googleapis.com"):
        return "gcs"
    if parsed.scheme == "azure" or "blob.core.windows.net" in host:
        return "azure"
    return "http"


def _hf_api_model_info(repo_id: str, revision: str | None, timeout_seconds: int) -> dict[str, Any]:
    suffix = f"/revision/{urllib.parse.quote(revision, safe='')}" if revision and revision != "main" else ""
    # `blobs=true` asks the Hub to include file metadata, including LFS sha256/size
    # for hosted large model artifacts. Without it, `siblings` only contains names.
    query = urllib.parse.urlencode({"blobs": "true"})
    url = f"https://huggingface.co/api/models/{urllib.parse.quote(repo_id, safe='/')}{suffix}?{query}"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ShakerScan-ModelIntake/1.0",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read(HF_MODEL_INFO_MAX_BYTES + 1)
        if len(raw) > HF_MODEL_INFO_MAX_BYTES:
            raise RuntimeError(f"Hugging Face model metadata exceeded {HF_MODEL_INFO_MAX_BYTES} byte cap")
        return json.loads(raw.decode("utf-8"))


def _hf_candidate_score(path: str) -> int:
    name = Path(path).name.lower()
    ext = Path(path).suffix.lower()
    if name in MODEL_INTAKE_COMMON_ARTIFACTS:
        return 120
    if ext == ".safetensors":
        return 100
    if ext == ".onnx":
        return 90
    if ext == ".gguf":
        return 85
    if ext == ".tflite":
        return 80
    if ext in MODEL_INTAKE_RISKY_EXTENSIONS:
        return 45
    return 0


def _hf_file_candidates(model_info: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for sibling in model_info.get("siblings") or []:
        path = str(sibling.get("rfilename") or sibling.get("path") or "")
        score = _hf_candidate_score(path)
        if not path or score <= 0:
            continue
        ext = Path(path).suffix.lower()
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        candidates.append({
            "path": path,
            "extension": ext,
            "format_posture": "safer_static_format" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "unsafe_or_review_required",
            "risk": "lower" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "higher",
            "size_bytes": sibling.get("size") or lfs.get("size"),
            "sha256": lfs.get("sha256"),
            "blob_id": sibling.get("blobId"),
            "score": score,
        })
    return sorted(candidates, key=lambda item: (-int(item.get("score") or 0), str(item.get("path") or "")))


def _hf_include_inventory_file(path: str) -> bool:
    name = Path(path).name.lower()
    if _hf_candidate_score(path) > 0:
        return True
    if name in MODEL_INTAKE_TOKENIZER_FILES | MODEL_INTAKE_DEPENDENCY_FILES | MODEL_INTAKE_METADATA_FILES:
        return True
    if name.endswith("_config.json"):
        return True
    return False


def _hf_repo_file_inventory(model_info: dict[str, Any], limit: int = 100) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for sibling in model_info.get("siblings") or []:
        path = str(sibling.get("rfilename") or sibling.get("path") or "")
        if not path or not _hf_include_inventory_file(path):
            continue
        lfs = sibling.get("lfs") if isinstance(sibling.get("lfs"), dict) else {}
        item = {
            "path": path,
            "size_bytes": sibling.get("size") or lfs.get("size"),
            "sha256": lfs.get("sha256"),
            "blob_id": sibling.get("blobId"),
            "source": "huggingface_model_info",
        }
        inventory.append({key: value for key, value in item.items() if value not in (None, "", [], {})})
    return inventory[:limit]


def _hf_files_named(model_info: dict[str, Any], names: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in _hf_repo_file_inventory(model_info):
        name = Path(str(item.get("path") or "")).name.lower()
        if name in names:
            matches.append(item)
    return matches


def _hf_metadata_from_model_info(model_info: dict[str, Any], repo_id: str, revision: str, selected: dict[str, Any] | None) -> dict[str, Any]:
    card_data = model_info.get("cardData") if isinstance(model_info.get("cardData"), dict) else {}
    tags = model_info.get("tags") if isinstance(model_info.get("tags"), list) else []
    datasets = card_data.get("datasets") or [tag.removeprefix("dataset:") for tag in tags if isinstance(tag, str) and tag.startswith("dataset:")]
    base_model = card_data.get("base_model") or card_data.get("base_models")
    license_ref = card_data.get("license") or next((tag.removeprefix("license:") for tag in tags if isinstance(tag, str) and tag.startswith("license:")), None)
    evals = card_data.get("model-index") or card_data.get("eval_results") or card_data.get("eval_results_v2")
    sha = model_info.get("sha") or revision
    file_inventory = _hf_repo_file_inventory(model_info)
    tokenizer_files = _hf_files_named(model_info, MODEL_INTAKE_TOKENIZER_FILES)
    dependency_files = _hf_files_named(model_info, MODEL_INTAKE_DEPENDENCY_FILES)
    metadata: dict[str, Any] = {
        "huggingface_repo": repo_id,
        "revision": sha,
        "source_repo": f"https://huggingface.co/{repo_id}",
        "model_card_url": f"https://huggingface.co/{repo_id}",
        "publisher": repo_id.split("/", 1)[0],
        "pipeline_tag": model_info.get("pipeline_tag") or card_data.get("pipeline_tag"),
        "library_name": model_info.get("library_name") or card_data.get("library_name"),
        "tags": tags[:50],
        "gated": model_info.get("gated"),
        "private": model_info.get("private"),
        "huggingface_file_inventory": file_inventory,
    }
    if license_ref:
        metadata["license"] = license_ref
    if datasets:
        metadata["training_data_ref"] = datasets
    if base_model:
        metadata["base_model"] = base_model
    if tokenizer_files:
        metadata["tokenizer"] = tokenizer_files
    if dependency_files:
        metadata["package_dependencies"] = {
            "source": "huggingface_repo_files",
            "files": dependency_files,
        }
    if evals:
        metadata["security_evals"] = {"source": "huggingface_model_card", "results": evals}
    if selected:
        metadata["huggingface_file"] = selected.get("path")
        if selected.get("sha256"):
            metadata["sha256"] = selected.get("sha256")
            metadata["sha256_source"] = "huggingface_lfs"
            metadata["sha256_scope"] = "full_artifact"
        if selected.get("size_bytes"):
            metadata["artifact_size_bytes"] = selected.get("size_bytes")
    return {key: value for key, value in metadata.items() if value not in (None, "", [], {})}


def _resolve_huggingface_model_intake(request: ModelIntakeResolveRequest) -> dict[str, Any]:
    _, parse_huggingface_ref = _import_model_intake_helpers()
    metadata = dict(request.metadata_json or {})
    if request.revision:
        metadata["revision"] = request.revision
    if request.filename:
        metadata["huggingface_file"] = request.filename
    hf_ref = parse_huggingface_ref(request.ref, metadata)
    repo_id = str(hf_ref.get("repo_id") or "")
    if not repo_id:
        raise HTTPException(status_code=400, detail="Hugging Face reference must include a model repo, such as org/model")

    warnings: list[str] = []
    model_info: dict[str, Any] = {}
    try:
        model_info = _hf_api_model_info(repo_id, str(hf_ref.get("revision") or "main"), request.timeout_seconds)
    except Exception as exc:
        warnings.append(f"Could not fetch Hugging Face model metadata: {type(exc).__name__}: {exc}")

    candidates = _hf_file_candidates(model_info) if model_info else []
    requested_filename = request.filename or hf_ref.get("filename")
    if not model_info and not requested_filename:
        warnings.append("Hugging Face metadata is required to choose a model artifact. Enter a direct artifact file path or retry when the Hub is reachable.")
        metadata_out = {
            **metadata,
            "huggingface_repo": repo_id,
            "revision": hf_ref.get("revision") or metadata.get("revision") or "main",
            "source_repo": f"https://huggingface.co/{repo_id}",
            "model_card_url": f"https://huggingface.co/{repo_id}",
        }
        return {
            "platform": "huggingface",
            "normalized_ref": request.ref,
            "repository": repo_id,
            "revision": hf_ref.get("revision"),
            "selected_file": None,
            "candidate_files": [],
            "metadata_json": {key: value for key, value in metadata_out.items() if value not in (None, "", [], {})},
            "warnings": warnings,
            "scan_payload": None,
        }
    selected = next((item for item in candidates if item["path"] == requested_filename), None) if requested_filename else None
    selected = selected or (candidates[0] if candidates else None)
    if selected:
        hf_ref = parse_huggingface_ref(request.ref, {
            **metadata,
            "revision": model_info.get("sha") or hf_ref.get("revision") or "main",
            "huggingface_file": selected["path"],
        })
    elif not hf_ref.get("filename"):
        warnings.append("No model artifact file was selected. Choose a .safetensors, .onnx, .gguf, .tflite, or reviewed legacy artifact.")

    if selected and selected.get("extension") in MODEL_INTAKE_RISKY_EXTENSIONS:
        warnings.append("Selected artifact uses a pickle-like or executable serialization format and should be reviewed before deployment.")
    if str(hf_ref.get("revision") or "main") == "main" and not model_info.get("sha"):
        warnings.append("Reference is not pinned to an immutable commit yet.")
    if model_info.get("gated") or model_info.get("private"):
        warnings.append("This model may require authenticated Hub access from the scanner worker.")

    metadata_out = {
        **_hf_metadata_from_model_info(model_info, repo_id, str(hf_ref.get("revision") or "main"), selected),
        **metadata,
    }
    artifact_url = str(hf_ref.get("resolve_url") or request.ref).strip()
    model_card_url = str(metadata_out.get("model_card_url") or f"https://huggingface.co/{repo_id}")
    scan_payload = {
        "artifact_url": artifact_url,
        "name": f"Hugging Face: {repo_id}",
        "metadata_json": metadata_out,
        "expected_sha256": selected.get("sha256") if selected else metadata_out.get("sha256"),
        "model_card_url": model_card_url,
        "require_deployment_approval": True,
        "require_signature": True,
        "require_hash": True,
        "require_model_governance": True,
        "max_download_bytes": 10_000_000,
        "timeout_seconds": 20,
    }
    return {
        "platform": "huggingface",
        "normalized_ref": artifact_url,
        "repository": repo_id,
        "revision": hf_ref.get("revision"),
        "selected_file": selected,
        "candidate_files": candidates[:25],
        "metadata_json": metadata_out,
        "warnings": warnings,
        "scan_payload": scan_payload,
    }


@app.post("/model-intake/resolve")
async def resolve_model_intake(request: ModelIntakeResolveRequest):
    """Resolve a platform-specific model reference into a scan-ready payload."""
    ref = (request.ref or "").strip()
    if not ref:
        raise HTTPException(status_code=400, detail="ref is required")
    platform = request.platform
    metadata = dict(request.metadata_json or {})
    if platform == "auto":
        platform = _detect_model_intake_platform(ref, metadata)
    if platform == "huggingface":
        normalized_ref = ref if _is_hf_ref(ref) else f"https://huggingface.co/{ref}"
        return await asyncio.to_thread(
            _resolve_huggingface_model_intake,
            request.model_copy(update={"ref": normalized_ref, "platform": "huggingface"}),
        )

    normalize_model_artifact_reference, _ = _import_model_intake_helpers()
    normalized = normalize_model_artifact_reference(ref, metadata, platform)
    source_kind = str(normalized.get("kind") or platform or "http")
    metadata_out = {
        **(normalized.get("metadata") if isinstance(normalized.get("metadata"), dict) else {}),
        **metadata,
    }
    ext = str(normalized.get("extension") or Path(urllib.parse.urlparse(ref).path).suffix or "")
    selected_file = {
        "path": normalized.get("path") or _short_url_label(ref),
        "extension": ext,
        "format_posture": normalized.get("format_posture"),
        "risk": "lower" if ext in MODEL_INTAKE_SAFER_EXTENSIONS else "higher" if ext in MODEL_INTAKE_RISKY_EXTENSIONS else "unknown",
        "size_bytes": None,
        "sha256": metadata_out.get("sha256") or metadata_out.get("expected_sha256"),
        "score": 70 if ext in MODEL_INTAKE_SAFER_EXTENSIONS else 45 if ext in MODEL_INTAKE_RISKY_EXTENSIONS else 10,
    } if normalized.get("path") or ext else None
    scan_payload = {
        "artifact_url": ref,
        "name": f"{source_kind.replace('_', ' ').title()}: {_short_url_label(ref)}",
        "metadata_json": metadata_out,
        "expected_sha256": metadata_out.get("sha256") or metadata_out.get("expected_sha256"),
        "model_card_url": metadata_out.get("model_card_url"),
        "require_deployment_approval": True,
        "require_signature": True,
        "require_hash": True,
        "require_model_governance": True,
        "max_download_bytes": 10_000_000,
        "timeout_seconds": 20,
    }
    return {
        "platform": source_kind,
        "normalized_ref": ref,
        "repository": normalized.get("repository") or normalized.get("registry"),
        "revision": normalized.get("revision") or request.revision or normalized.get("tag") or normalized.get("digest"),
        "selected_file": selected_file,
        "candidate_files": [selected_file] if selected_file else [],
        "metadata_json": metadata_out,
        "warnings": normalized.get("warnings") or [],
        "scan_payload": scan_payload,
    }


async def _enrich_model_intake_scan_request(request: ModelIntakeScanRequest) -> ModelIntakeScanRequest:
    """Best-effort provider metadata lookup for direct API/UI scan submissions."""
    artifact_ref = (request.artifact_url or "").strip()
    metadata = dict(request.metadata_json or {})
    if _detect_model_intake_platform(artifact_ref, metadata) != "huggingface":
        return request

    try:
        resolve_request = ModelIntakeResolveRequest(
            platform="huggingface",
            ref=artifact_ref if _is_hf_ref(artifact_ref) else f"https://huggingface.co/{artifact_ref}",
            revision=metadata.get("revision") if isinstance(metadata.get("revision"), str) else None,
            filename=metadata.get("huggingface_file") if isinstance(metadata.get("huggingface_file"), str) else None,
            metadata_json=metadata,
            timeout_seconds=min(max(int(request.timeout_seconds or 20), 1), 60),
        )
        resolved = await asyncio.to_thread(_resolve_huggingface_model_intake, resolve_request)
    except Exception as exc:
        logger.warning("Could not auto-enrich Hugging Face model intake request: %s: %s", type(exc).__name__, exc)
        return request

    scan_payload = resolved.get("scan_payload") if isinstance(resolved.get("scan_payload"), dict) else {}
    resolved_metadata = scan_payload.get("metadata_json") if isinstance(scan_payload.get("metadata_json"), dict) else {}
    merged_metadata = {**resolved_metadata, **metadata}
    expected_sha = request.expected_sha256 or scan_payload.get("expected_sha256") or merged_metadata.get("sha256")
    model_card_url = request.model_card_url or scan_payload.get("model_card_url") or merged_metadata.get("model_card_url")
    artifact_url = scan_payload.get("artifact_url") or request.artifact_url
    name = request.name or scan_payload.get("name")

    return request.model_copy(update={
        "artifact_url": artifact_url,
        "name": name,
        "metadata_json": merged_metadata,
        "expected_sha256": expected_sha,
        "model_card_url": model_card_url,
    })


@app.post("/model-intake/scan")
async def scan_model_intake(request: ModelIntakeScanRequest):
    """Queue a model artifact intake scan."""
    request = await _enrich_model_intake_scan_request(request)
    artifact_ref = (request.artifact_url or "").strip()
    if not artifact_ref:
        raise HTTPException(status_code=400, detail="artifact_url is required")
    parsed = urllib.parse.urlparse(artifact_ref)
    if parsed.scheme and parsed.scheme not in {"http", "https", "hf", "oci", "s3", "gs", "gcs", "azure", "mlflow", "models"}:
        raise HTTPException(status_code=400, detail="artifact_url must use http(s), hf://, oci://, s3://, gs://, gcs://, azure://, mlflow://, or models:/")

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
        "require_signature_verification": request.require_signature_verification,
        "require_hash": request.require_hash,
        "require_model_governance": request.require_model_governance,
        "policy_profile": request.policy_profile,
        "policy_exceptions": request.policy_exceptions or [],
        "max_download_bytes": request.max_download_bytes,
        "timeout_seconds": request.timeout_seconds,
    }
    if request.policy_profile in POLICY_PROFILES:
        options["environment"] = request.policy_profile
        if request.policy_profile == "production":
            options["strict_governance"] = True

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
        "submitted_at": utc_now_iso(),
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


@app.post("/model-intake/targets/{target_id}/rescan")
async def rescan_model_intake_target(target_id: str):
    """Re-queue a model intake scan for an existing model target.

    Reuses the options of the target's most recent intake scan (policy profile,
    metadata, signature/hash requirements), so one-click re-checks from the
    exposure inventory run the same evaluation the artifact was admitted with.
    """
    try:
        target_uuid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target id")

    async with db_pool.acquire() as conn:
        target = await conn.fetchrow(
            "SELECT id, url FROM targets WHERE id = $1 AND is_active = true",
            target_uuid,
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        last_scan = await conn.fetchrow(
            """
            SELECT options FROM scans
            WHERE target_id = $1 AND run_kind = 'model_intake'
            ORDER BY created_at DESC LIMIT 1
            """,
            target_uuid,
        )
        if not last_scan:
            raise HTTPException(
                status_code=409,
                detail="No previous model intake scan to re-run. Submit one from Model Intake settings first.",
            )
        options = _decode_json_value(last_scan["options"]) or {}
        options["run_kind"] = "model_intake"
        artifact_ref = target["url"]

        r = get_redis()
        job_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        await conn.execute("""
            INSERT INTO scans (
                id, target_id, target_url, job_id, status, options, scan_type, run_kind, subject_ref
            ) VALUES ($1, $2, $3, $4, 'pending', $5, 'model_intake', 'model_intake', $6)
        """,
            uuid.UUID(scan_id),
            target_uuid,
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
        "submitted_at": utc_now_iso(),
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

@app.get("/ai/inventory")
async def get_ai_inventory(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit_scans: int = Query(150, ge=1, le=300),
):
    """Return AI assets, discovered AI-surface candidates, and blast-radius summaries."""
    async with db_pool.acquire() as conn:
        targets_query = """
            SELECT
                id, url, name, root_domain, is_active, discovery_source,
                last_score, last_grade, last_scanned_at, total_scans,
                active_findings_count, created_at, updated_at
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY updated_at DESC
            LIMIT 500
        """
        targets = [row_to_dict(row) for row in await conn.fetch(targets_query, include_inactive, root_domain)]

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
            LIMIT 500
        """
        ai_targets = [row_to_dict(row) for row in await conn.fetch(ai_query, include_inactive, root_domain)]

        scans_query = """
            SELECT
                s.id, s.target_id, s.ai_target_id, s.target_url, s.status,
                s.scan_type, s.run_kind, s.result, s.created_at, s.completed_at,
                t.root_domain
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.result IS NOT NULL
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND (
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
                f.id, f.ai_target_id, f.scan_id, f.title, f.severity, f.status,
                f.source, f.tool, f.last_seen_at, ait.endpoint_url as ai_target_url
            FROM findings f
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.ai_target_id IS NOT NULL
              AND ($1::boolean = true OR f.status = 'active')
              AND ($2::text IS NULL OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.last_seen_at DESC NULLS LAST
            LIMIT 500
        """
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(findings_query, include_resolved, root_domain)
        ]

    return build_ai_inventory(
        targets=targets,
        ai_targets=ai_targets,
        scans=scans,
        findings=findings,
    )


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


@app.get("/ai/targets/{target_id}/principals")
async def list_ai_target_principals(target_id: str, include_inactive: bool = False):
    """List non-secret principal identities configured for one AI Gate target."""
    async with db_pool.acquire() as conn:
        target_exists = await conn.fetchval(
            "SELECT 1 FROM ai_targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not target_exists:
            raise HTTPException(status_code=404, detail="AI target not found")
        query = """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1
        """
        if not include_inactive:
            query += " AND is_active = true"
        query += " ORDER BY role, label"
        rows = await conn.fetch(query, uuid.UUID(target_id))

    return {
        "target_id": target_id,
        "principals": [_sanitize_ai_principal(row) for row in rows],
    }


@app.post("/ai/targets/{target_id}/principals")
async def create_ai_target_principal(target_id: str, request: AITargetPrincipalCreate):
    """Create a principal credential for cross-user RAG and agent authorization tests."""
    label = _normalize_ai_principal_label(request.label)
    role = _normalize_ai_principal_role(request.role)
    credential = _build_ai_credential_db_record(request.credential)
    principal_metadata = {**(credential["metadata_json"] or {}), **(request.metadata_json or {})}
    async with db_pool.acquire() as conn:
        target_exists = await conn.fetchval(
            "SELECT 1 FROM ai_targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not target_exists:
            raise HTTPException(status_code=404, detail="AI target not found")
        try:
            principal_id = await conn.fetchval("""
                INSERT INTO ai_target_principals (
                    ai_target_id, label, role, tenant_id, auth_kind, header_name,
                    secret_value, secret_preview, metadata_json, is_active, rotated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                RETURNING id
            """,
                uuid.UUID(target_id),
                label,
                role,
                str(request.tenant_id or "").strip() or None,
                credential["auth_kind"],
                credential["header_name"],
                credential["secret_value"],
                credential["secret_preview"],
                json.dumps(principal_metadata),
                request.is_active,
            )
        except Exception as exc:
            if "unique" in str(exc).lower():
                raise HTTPException(status_code=409, detail="Principal label already exists for this AI target") from exc
            raise
        row = await conn.fetchrow("SELECT * FROM ai_target_principals WHERE id = $1", principal_id)
    return {"principal": _sanitize_ai_principal(row)}


@app.patch("/ai/targets/{target_id}/principals/{principal_id}")
async def update_ai_target_principal(
    target_id: str,
    principal_id: str,
    request: AITargetPrincipalUpdate,
):
    """Update a principal credential without returning its raw secret."""
    payload = request.model_dump(exclude_unset=True)
    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT * FROM ai_target_principals WHERE id = $1 AND ai_target_id = $2",
            uuid.UUID(principal_id),
            uuid.UUID(target_id),
        )
        if not existing:
            raise HTTPException(status_code=404, detail="AI target principal not found")

        update_data: dict[str, Any] = {}
        if "label" in payload and payload["label"] is not None:
            update_data["label"] = _normalize_ai_principal_label(payload["label"])
        if "role" in payload and payload["role"] is not None:
            update_data["role"] = _normalize_ai_principal_role(payload["role"])
        if "tenant_id" in payload:
            update_data["tenant_id"] = str(payload.get("tenant_id") or "").strip() or None
        if "metadata_json" in payload:
            update_data["metadata_json"] = json.dumps(payload.get("metadata_json") or {})
        if "is_active" in payload:
            update_data["is_active"] = bool(payload["is_active"])

        if request.credential is not None:
            credential = _build_ai_credential_db_record(request.credential, dict(existing))
            update_data.update({
                "auth_kind": credential["auth_kind"],
                "header_name": credential["header_name"],
                "secret_value": credential["secret_value"],
                "secret_preview": credential["secret_preview"],
                "metadata_json": json.dumps(
                    {
                        **(_decode_json_value(existing.get("metadata_json")) or {}),
                        **(credential["metadata_json"] or {}),
                        **(
                            payload.get("metadata_json")
                            if isinstance(payload.get("metadata_json"), dict)
                            else {}
                        ),
                    }
                ),
                "rotated_at": datetime.now(timezone.utc),
            })

        if update_data:
            assignments = []
            values = []
            for idx, (key, value) in enumerate(update_data.items(), start=1):
                assignments.append(f"{key} = ${idx}")
                values.append(value)
            assignments.append("updated_at = NOW()")
            values.extend([uuid.UUID(principal_id), uuid.UUID(target_id)])
            await conn.execute(
                f"""
                UPDATE ai_target_principals
                SET {', '.join(assignments)}
                WHERE id = ${len(values) - 1} AND ai_target_id = ${len(values)}
                """,
                *values,
            )

        row = await conn.fetchrow(
            "SELECT * FROM ai_target_principals WHERE id = $1 AND ai_target_id = $2",
            uuid.UUID(principal_id),
            uuid.UUID(target_id),
        )
    return {"principal": _sanitize_ai_principal(row)}


@app.delete("/ai/targets/{target_id}/principals/{principal_id}")
async def delete_ai_target_principal(target_id: str, principal_id: str):
    """Deactivate a principal credential."""
    async with db_pool.acquire() as conn:
        result = await conn.execute("""
            UPDATE ai_target_principals
            SET is_active = false, updated_at = NOW()
            WHERE id = $1 AND ai_target_id = $2
        """,
            uuid.UUID(principal_id),
            uuid.UUID(target_id),
        )
    if result == "UPDATE 0":
        raise HTTPException(status_code=404, detail="AI target principal not found")
    return {"status": "deleted", "target_id": target_id, "principal_id": principal_id}


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


@app.post("/ai/targets/{target_id}/mcp/live-readiness")
async def test_ai_target_mcp_live_readiness(target_id: str, request: AIMCPLiveReadinessRequest):
    """Run safe live MCP/OAuth metadata readiness checks for an MCP target."""
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
        run_mcp_live_readiness_probe,
        target,
        timeout_seconds=request.timeout_seconds,
    )
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        **result,
    }


@app.get("/ai/targets/{target_id}/runtime-risk")
async def get_ai_target_runtime_risk(target_id: str):
    """Return blast-radius risk for one AI target from metadata and active findings."""
    async with db_pool.acquire() as conn:
        target_row = await conn.fetchrow("SELECT * FROM ai_targets WHERE id = $1", uuid.UUID(target_id))
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        findings = [
            row_to_dict(row)
            for row in await conn.fetch(
                """
                SELECT id, ai_target_id, status, severity, title, source, tool, last_seen_at
                FROM findings
                WHERE ai_target_id = $1 AND status = 'active'
                ORDER BY last_seen_at DESC NULLS LAST
                LIMIT 100
                """,
                uuid.UUID(target_id),
            )
        ]

    target = row_to_dict(target_row)
    target["metadata_json"] = _decode_json_value(target.get("metadata_json")) or {}
    return {
        "target_id": target_id,
        "target_name": target.get("name"),
        "target_type": target.get("target_type"),
        "blast_radius": build_agent_blast_radius(target, findings),
    }


@app.get("/ai/scans/{scan_id}/transcript")
async def get_ai_scan_transcript(scan_id: str, include_sensitive: bool = False):
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
    retention = ai_gate.get("transcript_retention") if isinstance(ai_gate, dict) else {}
    return {
        "scan_id": scan_id,
        "transcripts": transcripts,
        "transcript_retention": retention or {
            "redaction_applied": True,
            "include_sensitive_available": False,
        },
        "include_sensitive": include_sensitive,
        "include_sensitive_available": bool((retention or {}).get("include_sensitive_available")),
    }


@app.delete("/ai/scans/{scan_id}/transcript")
async def purge_ai_scan_transcript(scan_id: str):
    """Purge stored AI Gate transcript bodies while preserving scan and finding metadata."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow(
            "SELECT result, run_kind FROM scans WHERE id = $1",
            uuid.UUID(scan_id),
        )
        if not scan or scan["run_kind"] not in {"ai_api", "ai_widget", "ai_rag", "ai_trace", "ai_mcp"}:
            raise HTTPException(status_code=404, detail="AI scan not found")
        result = _decode_json_value(scan["result"]) or {}
        ai_gate = result.get("ai_gate") if isinstance(result, dict) else None
        if not isinstance(ai_gate, dict):
            raise HTTPException(status_code=404, detail="AI Gate result not available")
        transcripts = ai_gate.get("transcripts")
        purged_count = len(transcripts) if isinstance(transcripts, list) else 0
        ai_gate["transcripts"] = []
        retention = ai_gate.get("transcript_retention") if isinstance(ai_gate.get("transcript_retention"), dict) else {}
        retention.update({
            "purged": True,
            "purged_at": datetime.now(timezone.utc).isoformat(),
            "purged_transcript_count": purged_count,
            "redaction_applied": True,
            "include_sensitive_available": False,
        })
        ai_gate["transcript_retention"] = retention
        result["ai_gate"] = ai_gate
        await conn.execute(
            "UPDATE scans SET result = $1 WHERE id = $2",
            json.dumps(result),
            uuid.UUID(scan_id),
        )
    return {"scan_id": scan_id, "purged": True, "purged_transcript_count": purged_count}


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
            FROM scans
            WHERE (scan_role IS NULL OR scan_role <> 'shard')
            ORDER BY created_at DESC LIMIT 10
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
    focus: Optional[str] = None,
    depth: int = Query(1, ge=1, le=3),
    include_endpoints: bool = False,
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
            WHERE (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND (
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

        # Real, uncapped security counts for the headline metrics — the graph's
        # own node counts are limited by the fetch caps above and would
        # under-report on large datasets.
        metrics_row = await conn.fetchrow(
            """
            SELECT
                (SELECT COUNT(*) FROM targets t
                   WHERE ($1::boolean = true OR t.is_active = true)
                     AND ($2::text IS NULL OR t.root_domain = $2::text)) AS web_targets,
                (SELECT COUNT(*) FROM ai_targets a
                   WHERE ($1::boolean = true OR a.is_active = true)
                     AND ($2::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS ai_surfaces,
                (SELECT COUNT(*) FROM findings f
                   LEFT JOIN targets t ON f.target_id = t.id
                   LEFT JOIN ai_targets a ON f.ai_target_id = a.id
                   WHERE f.status = 'active' AND f.severity = 'critical'
                     AND ($2::text IS NULL OR t.root_domain = $2::text
                          OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS active_critical,
                (SELECT COUNT(*) FROM findings f
                   LEFT JOIN targets t ON f.target_id = t.id
                   LEFT JOIN ai_targets a ON f.ai_target_id = a.id
                   WHERE f.status = 'active' AND f.severity = 'high'
                     AND ($2::text IS NULL OR t.root_domain = $2::text
                          OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')) AS active_high
            """,
            include_inactive,
            root_domain,
        )

    graph = _build_exposure_graph(
        targets=targets,
        ai_targets=ai_targets,
        scans=scans,
        findings=findings,
    )

    web_targets = int(metrics_row["web_targets"] or 0)
    ai_surfaces = int(metrics_row["ai_surfaces"] or 0)
    graph["summary"]["metrics"] = {
        "asset_count": web_targets + ai_surfaces,
        "web_targets": web_targets,
        "ai_surfaces": ai_surfaces,
        "active_critical": int(metrics_row["active_critical"] or 0),
        "active_high": int(metrics_row["active_high"] or 0),
        "attack_chains": int(graph["summary"]["node_type_counts"].get("attack_chain", 0)),
    }

    return _focus_exposure_subgraph(
        graph,
        focus=focus,
        depth=depth,
        include_endpoints=include_endpoints,
    )


@app.get("/exposure/nodes")
async def exposure_nodes(
    root_domain: Optional[str] = None,
    include_inactive: bool = False,
    include_resolved: bool = False,
    limit: int = Query(2000, ge=1, le=5000),
):
    """Lightweight searchable index of exposure nodes (id/label/type/severity).

    Node ids match those produced by the graph builder so a selected result can
    be passed straight back as ``focus`` to /exposure/graph. Fetched once by the
    UI and filtered client-side as the user types.
    """
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def emit(node_id: str, node_type: str, label: str, severity: str | None = None) -> None:
        if not label or node_id in seen:
            return
        seen.add(node_id)
        nodes.append({"id": node_id, "type": node_type, "label": label, "severity": severity})

    async with db_pool.acquire() as conn:
        target_rows = await conn.fetch(
            """
            SELECT id, url, name, root_domain, discovery_source
            FROM targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY active_findings_count DESC NULLS LAST
            LIMIT $3
            """,
            include_inactive,
            root_domain,
            limit,
        )
        for row in target_rows:
            row = row_to_dict(row)
            node_type = "model_artifact" if row.get("discovery_source") == "model-intake" else "web_target"
            emit(f"target:{row['id']}", node_type, _short_url_label(row.get("url")) or str(row.get("name") or ""))
            if row.get("root_domain"):
                emit(f"domain:{row['root_domain']}", "domain", str(row["root_domain"]))

        ai_rows = await conn.fetch(
            """
            SELECT id, name, endpoint_url, target_type
            FROM ai_targets
            WHERE ($1::boolean = true OR is_active = true)
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY production_mode DESC, updated_at DESC
            LIMIT $3
            """,
            include_inactive,
            root_domain,
            limit,
        )
        for row in ai_rows:
            row = row_to_dict(row)
            emit(f"ai_target:{row['id']}", "ai_target", str(row.get("name") or _short_url_label(row.get("endpoint_url"))))

        finding_rows = await conn.fetch(
            """
            SELECT f.id, f.title, f.severity
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets a ON f.ai_target_id = a.id
            WHERE ($1::boolean = true OR f.status = 'active')
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(a.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4 ELSE 5
                END,
                f.last_seen_at DESC NULLS LAST
            LIMIT $3
            """,
            include_resolved,
            root_domain,
            limit,
        )
        for row in finding_rows:
            row = row_to_dict(row)
            emit(f"finding:{row['id']}", "finding", str(row.get("title") or "Finding"), row.get("severity"))

    return {"nodes": nodes, "count": len(nodes)}


def _exposure_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _exposure_is_new(created: Any, *, days: int = 7) -> bool:
    when = _exposure_datetime(created)
    if not when:
        return False
    return (datetime.now(timezone.utc) - when) < timedelta(days=days)


def _exposure_risk_score(critical: int, high: int, total: int) -> int:
    return critical * 1000 + high * 50 + total


def _exposure_hostname(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or "").lower()


def _exposure_class(value: str | None, *, kind: str = "web") -> str:
    if kind == "model":
        return "supply_chain"
    host = _exposure_hostname(value)
    if not host:
        return "unknown"
    if host in {"localhost", "host.docker.internal"} or host.endswith(".internal") or host.endswith(".local"):
        return "internal"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            return "internal"
    except ValueError:
        pass
    if "." not in host:
        return "internal"
    return "public"


def _exposure_days_since(value: Any) -> int | None:
    when = _exposure_datetime(value)
    if not when:
        return None
    return max(0, (datetime.now(timezone.utc) - when).days)


def _scan_completion_flags(completion_status: Any, top_coverage_status: Any = None) -> dict[str, Any]:
    """Build scan-coverage flags from the small ``scan_completion_status`` object.

    Callers extract only that sub-object (and the top-level coverage string) in
    SQL so the multi-hundred-KB scan ``result`` blob is never shipped per asset.
    """
    status = _parse_graph_json(completion_status)
    complete = status.get("complete")
    limited = bool(status.get("limited") or status.get("budget_exhausted"))
    return {
        "scan_complete": complete if complete is not None else (False if limited else None),
        "scan_limited": limited,
        "coverage_status": status.get("coverage_status") or top_coverage_status,
        "skipped_modules_count": len(status.get("skipped_modules") or []) if isinstance(status.get("skipped_modules"), list) else 0,
        "capped_lists_count": len(status.get("capped_lists") or {}) if isinstance(status.get("capped_lists"), dict) else 0,
    }


# Action priority tiers, so the triage queue ranks the genuinely urgent few
# instead of flagging the majority of assets with an undifferentiated boolean.
_EXPOSURE_PRIORITY_WEIGHT = {"P1": 300, "P2": 200, "P3": 100}


def _exposure_action_priority(
    reasons: list[str],
    *,
    exposure_class: str,
    active_critical: int,
    active_high: int,
) -> tuple[str | None, int]:
    """Return ``(priority, score)`` for ranking. ``None`` when no action needed.

    P1 = exploitable risk on an exposed/production surface, P2 = high-severity or
    high-blast exposure, P3 = scan-hygiene only (stale / incomplete / unscanned).
    """
    rs = set(reasons)
    if not rs:
        return None, 0
    if active_critical > 0 or "production_ai_risk" in rs:
        priority = "P1"
    elif "public_high_risk" in rs or "high_blast_radius" in rs or active_high > 0:
        priority = "P2"
    else:
        priority = "P3"
    score = _EXPOSURE_PRIORITY_WEIGHT[priority] + active_critical * 10 + active_high
    if exposure_class == "public":
        score += 25
    return priority, score


def _exposure_action_reasons(
    *,
    kind: str,
    exposure_class: str,
    active_critical: int,
    active_high: int,
    total_scans: int,
    last_scanned_at: Any,
    scan_limited: bool,
    production_mode: bool = False,
    blast_radius_tier: str | None = None,
    deployment_approved: bool | None = None,
    latest_scan_status: str | None = None,
) -> list[str]:
    reasons: list[str] = []
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        reasons.append("never_scanned")
    elif days is not None and days >= 30:
        reasons.append("stale_scan")
    if latest_scan_status == "failed":
        reasons.append("failed_scan")
    if scan_limited:
        reasons.append("incomplete_scan")
    if active_critical > 0:
        reasons.append("critical_findings")
    elif active_high > 0:
        reasons.append("high_findings")
    if exposure_class == "public" and (active_critical > 0 or active_high > 0):
        reasons.append("public_high_risk")
    if kind == "ai" and production_mode and (active_critical > 0 or active_high > 0):
        reasons.append("production_ai_risk")
    if kind == "ai" and blast_radius_tier in {"high", "critical"}:
        reasons.append("high_blast_radius")
    if kind == "model" and deployment_approved is False:
        reasons.append("model_not_approved")
    return reasons


def _exposure_coverage_posture(*, total_scans: int, last_scanned_at: Any, scan_limited: bool, latest_scan_status: str | None) -> str:
    days = _exposure_days_since(last_scanned_at)
    if total_scans <= 0 or not last_scanned_at:
        return "unscanned"
    if latest_scan_status == "failed":
        return "failed"
    if scan_limited:
        return "limited"
    if days is not None and days >= 30:
        return "stale"
    return "fresh"


def _exposure_recommended_actions(*, kind: str, reasons: list[str], active_verified: int, active_needs_verification: int) -> list[dict[str, str]]:
    """Prioritized, contextual next steps as ``{label, kind}``.

    ``kind`` tells the UI which action the recommendation maps to so it can be
    rendered as a real CTA: ``scan`` (run/refresh coverage), ``findings``
    (triage/verify), ``latest_scan`` (open the latest run), or ``none`` (advisory).
    """
    actions: list[dict[str, str]] = []
    rs = set(reasons)
    if "never_scanned" in rs:
        actions.append({"label": "Run first scan", "kind": "scan"})
    if "failed_scan" in rs:
        actions.append({"label": "Open latest failed scan", "kind": "latest_scan"})
    if "incomplete_scan" in rs:
        actions.append({"label": "Review skipped scan coverage", "kind": "latest_scan"})
    if "stale_scan" in rs:
        actions.append({"label": "Refresh scan", "kind": "scan"})
    if "critical_findings" in rs:
        actions.append({"label": "Triage critical findings", "kind": "findings"})
    elif "high_findings" in rs:
        actions.append({"label": "Triage high findings", "kind": "findings"})
    if "public_high_risk" in rs:
        actions.append({"label": "Prioritize public exposure", "kind": "none"})
    if kind == "ai" and "high_blast_radius" in rs:
        actions.append({"label": "Review AI runtime controls", "kind": "none"})
    if kind == "ai" and "production_ai_risk" in rs:
        actions.append({"label": "Retest production AI surface", "kind": "scan"})
    if kind == "model" and "model_not_approved" in rs:
        actions.append({"label": "Complete model approval", "kind": "none"})
    if active_verified > 0:
        actions.append({"label": "Fix verified findings", "kind": "findings"})
    if active_needs_verification > 0:
        actions.append({"label": "Verify suspected findings", "kind": "findings"})
    # Stable de-dupe by label, preserving priority order.
    seen: set[str] = set()
    unique = [a for a in actions if not (a["label"] in seen or seen.add(a["label"]))]
    return unique[:5]


@app.get("/exposure/assets")
async def exposure_assets(
    root_domain: Optional[str] = None,
    kind: Optional[str] = None,
    limit: int = Query(1000, ge=1, le=2000),
    offset: int = Query(0, ge=0),
):
    """Unified, risk-ranked asset inventory for the triage view.

    Merges web targets, AI surfaces, and model artifacts with their active
    critical/high/total finding counts (uncapped SQL aggregation), grade, and
    first-seen timestamp. Each asset carries the graph ``node_id`` so the UI can
    jump straight into the Map lens focused on it.
    """
    async with db_pool.acquire() as conn:
        target_rows = await conn.fetch(
            """
            SELECT t.id, t.url, t.name, t.root_domain, t.discovery_source, t.metadata_json,
                   t.last_grade, t.last_score, t.last_scanned_at, t.created_at, t.total_scans,
                   ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                   ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                   ls.completed_at AS latest_scan_completed_at,
                   COALESCE(fc.active_total, 0) AS active_total,
                   COALESCE(fc.active_critical, 0) AS active_critical,
                   COALESCE(fc.active_high, 0) AS active_high,
                   COALESCE(fc.active_verified, 0) AS active_verified,
                   COALESCE(fc.active_needs_verification, 0) AS active_needs_verification
            FROM targets t
            LEFT JOIN LATERAL (
                SELECT id, status, scan_type, completed_at,
                       result -> 'scan_completion_status' AS completion_status,
                       result ->> 'coverage_status' AS top_coverage_status
                FROM scans s
                WHERE s.target_id = t.id
                  AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
                ORDER BY s.created_at DESC
                LIMIT 1
            ) ls ON true
            LEFT JOIN (
                SELECT target_id,
                    COUNT(*) FILTER (WHERE status = 'active') AS active_total,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS active_critical,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS active_high,
                    COUNT(*) FILTER (WHERE status = 'active' AND last_verification_verdict = 'exploited') AS active_verified,
                    COUNT(*) FILTER (
                        WHERE status = 'active'
                          AND (
                            last_verification_verdict IS NULL
                            OR last_verification_verdict IN ('inconclusive', 'error', 'likely_vulnerable')
                            OR analyst_verdict IN ('needs_review', 'retest_needed')
                          )
                    ) AS active_needs_verification
                FROM findings WHERE target_id IS NOT NULL GROUP BY target_id
            ) fc ON fc.target_id = t.id
            WHERE t.is_active = true
              AND ($1::text IS NULL OR t.root_domain = $1::text)
            """,
            root_domain,
        )

        ai_rows = await conn.fetch(
            """
            SELECT a.id, a.name, a.endpoint_url, a.target_type, a.production_mode,
                   a.last_scanned_at, a.created_at, a.metadata_json,
                   ls.id AS latest_scan_id, ls.status AS latest_scan_status,
                   ls.scan_type AS latest_scan_type, ls.completion_status, ls.top_coverage_status,
                   ls.completed_at AS latest_scan_completed_at,
                   COALESCE(sc.scan_count, 0) AS scan_count,
                   COALESCE(fc.active_total, 0) AS active_total,
                   COALESCE(fc.active_critical, 0) AS active_critical,
                   COALESCE(fc.active_high, 0) AS active_high,
                   COALESCE(fc.active_verified, 0) AS active_verified,
                   COALESCE(fc.active_needs_verification, 0) AS active_needs_verification
            FROM ai_targets a
            LEFT JOIN LATERAL (
                SELECT id, status, scan_type, completed_at,
                       result -> 'scan_completion_status' AS completion_status,
                       result ->> 'coverage_status' AS top_coverage_status
                FROM scans s
                WHERE s.ai_target_id = a.id
                ORDER BY s.created_at DESC
                LIMIT 1
            ) ls ON true
            LEFT JOIN (
                SELECT ai_target_id, COUNT(*) AS scan_count
                FROM scans WHERE ai_target_id IS NOT NULL GROUP BY ai_target_id
            ) sc ON sc.ai_target_id = a.id
            LEFT JOIN (
                SELECT ai_target_id,
                    COUNT(*) FILTER (WHERE status = 'active') AS active_total,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'critical') AS active_critical,
                    COUNT(*) FILTER (WHERE status = 'active' AND severity = 'high') AS active_high,
                    COUNT(*) FILTER (WHERE status = 'active' AND last_verification_verdict = 'exploited') AS active_verified,
                    COUNT(*) FILTER (
                        WHERE status = 'active'
                          AND (
                            last_verification_verdict IS NULL
                            OR last_verification_verdict IN ('inconclusive', 'error', 'likely_vulnerable')
                            OR analyst_verdict IN ('needs_review', 'retest_needed')
                          )
                    ) AS active_needs_verification
                FROM findings WHERE ai_target_id IS NOT NULL GROUP BY ai_target_id
            ) fc ON fc.ai_target_id = a.id
            WHERE a.is_active = true
              AND ($1::text IS NULL OR LOWER(a.endpoint_url) LIKE '%' || LOWER($1::text) || '%')
            """,
            root_domain,
        )

    assets: list[dict[str, Any]] = []

    for row in target_rows:
        row = row_to_dict(row)
        is_model = row.get("discovery_source") == "model-intake"
        asset_kind = "model" if is_model else "web"
        if kind and kind != asset_kind:
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        verified = int(row.get("active_verified") or 0)
        needs_verification = int(row.get("active_needs_verification") or 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("url"), kind=asset_kind)
        total_scans = int(row.get("total_scans") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        action_reasons = _exposure_action_reasons(
            kind=asset_kind,
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            deployment_approved=None,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        meta = _parse_graph_json(row.get("metadata_json"))
        assets.append({
            "id": str(row["id"]),
            "node_id": f"target:{row['id']}",
            "kind": asset_kind,
            "label": _short_url_label(row.get("url")) or row.get("name") or "",
            "url": row.get("url"),
            "root_domain": None if is_model else row.get("root_domain"),
            "origin": row.get("root_domain") if is_model else None,
            "exposure_class": exposure_class,
            "owner": str(meta.get("owner") or meta.get("asset_owner") or "").strip() or None,
            "environment": str(meta.get("environment") or "").strip().lower() or None,
            "risk_tier": str(meta.get("risk_tier") or "").strip() or None,
            "data_classification": str(meta.get("data_classification") or "").strip() or None,
            "grade": row.get("last_grade"),
            "score": row.get("last_score"),
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind=asset_kind,
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?target_id={row['id']}&status=active",
        })

    for row in ai_rows:
        row = row_to_dict(row)
        if kind and kind != "ai":
            continue
        crit = int(row["active_critical"] or 0)
        high = int(row["active_high"] or 0)
        total = int(row["active_total"] or 0)
        verified = int(row.get("active_verified") or 0)
        needs_verification = int(row.get("active_needs_verification") or 0)
        completion = _scan_completion_flags(row.get("completion_status"), row.get("top_coverage_status"))
        exposure_class = _exposure_class(row.get("endpoint_url"), kind="ai")
        total_scans = int(row.get("scan_count") or 0)
        last_scanned_at = row.get("latest_scan_completed_at") or row.get("last_scanned_at")
        latest_scan_status = row.get("latest_scan_status")
        blast_radius = build_agent_blast_radius(row, [{"status": "active"} for _ in range(total)])
        blast_radius_tier = str(blast_radius.get("tier") or "")
        ai_meta = _parse_graph_json(row.get("metadata_json"))
        ai_owner = str(ai_meta.get("asset_owner") or ai_meta.get("owner") or "").strip() or None
        # Normalized once at emission (trimmed, lowercased) so every consumer —
        # UI prod filter/confirmation, API metrics, action reasons — compares
        # the same canonical value regardless of how metadata was written.
        ai_environment = (
            str(ai_meta.get("environment") or "").strip().lower()
            or ("production" if row.get("production_mode") else "")
        ) or None
        # Production semantics shared with the UI's isProductionAIAsset(): the
        # explicit flag OR declared environment metadata. Keeps action reasons,
        # P1 promotion, and metrics consistent with the UI's scan confirmation.
        ai_is_production = bool(row.get("production_mode")) or (
            str(ai_meta.get("environment") or "").strip().lower() == "production"
        )
        action_reasons = _exposure_action_reasons(
            kind="ai",
            exposure_class=exposure_class,
            active_critical=crit,
            active_high=high,
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            production_mode=ai_is_production,
            blast_radius_tier=blast_radius_tier,
            latest_scan_status=latest_scan_status,
        )
        action_priority, action_score = _exposure_action_priority(
            action_reasons, exposure_class=exposure_class, active_critical=crit, active_high=high
        )
        coverage_posture = _exposure_coverage_posture(
            total_scans=total_scans,
            last_scanned_at=last_scanned_at,
            scan_limited=bool(completion["scan_limited"]),
            latest_scan_status=latest_scan_status,
        )
        assets.append({
            "id": str(row["id"]),
            "node_id": f"ai_target:{row['id']}",
            "kind": "ai",
            "label": row.get("name") or _short_url_label(row.get("endpoint_url")) or "",
            "url": row.get("endpoint_url"),
            "root_domain": extract_root_domain(row.get("endpoint_url") or ""),
            "target_type": row.get("target_type"),
            "production_mode": bool(row.get("production_mode")),
            "exposure_class": exposure_class,
            "owner": ai_owner,
            "environment": ai_environment,
            "blast_radius_score": blast_radius.get("score"),
            "blast_radius_tier": blast_radius.get("tier"),
            "blast_radius_factors": blast_radius.get("factors") or [],
            "data_classification": blast_radius.get("data_classification"),
            "risk_tier": blast_radius.get("risk_tier"),
            "missing_runtime_controls": blast_radius.get("missing_runtime_controls") or [],
            "grade": None,
            "score": None,
            "active_total": total,
            "active_critical": crit,
            "active_high": high,
            "active_verified": verified,
            "active_needs_verification": needs_verification,
            "total_scans": total_scans,
            "last_scanned_at": last_scanned_at,
            "latest_scan_id": str(row["latest_scan_id"]) if row.get("latest_scan_id") else None,
            "latest_scan_status": latest_scan_status,
            "latest_scan_type": row.get("latest_scan_type"),
            "latest_scan_href": f"/scans/{row['latest_scan_id']}" if row.get("latest_scan_id") else None,
            "scan_complete": completion["scan_complete"],
            "scan_limited": completion["scan_limited"],
            "coverage_status": completion["coverage_status"],
            "coverage_posture": coverage_posture,
            "skipped_modules_count": completion["skipped_modules_count"],
            "capped_lists_count": completion["capped_lists_count"],
            "scan_age_days": _exposure_days_since(last_scanned_at),
            "action_reasons": action_reasons,
            "needs_action": bool(action_reasons),
            "action_priority": action_priority,
            "action_score": action_score,
            "recommended_actions": _exposure_recommended_actions(
                kind="ai",
                reasons=action_reasons,
                active_verified=verified,
                active_needs_verification=needs_verification,
            ),
            "first_seen_at": row.get("created_at"),
            "is_new": _exposure_is_new(row.get("created_at")),
            "risk_score": _exposure_risk_score(crit, high, total),
            "findings_href": f"/findings?ai_target_id={row['id']}&status=active",
        })

    # Headline metrics from the full (uncapped) set so the stat row stays
    # accurate and independent of the heavier graph fetch. Compute before the
    # display limit is applied.
    metrics = {
        "asset_count": len(assets),
        "active_critical": sum(a["active_critical"] for a in assets),
        "active_high": sum(a["active_high"] for a in assets),
        "active_verified": sum(a.get("active_verified", 0) for a in assets),
        "active_needs_verification": sum(a.get("active_needs_verification", 0) for a in assets),
        "ai_surfaces": sum(1 for a in assets if a["kind"] == "ai"),
        "web_targets": sum(1 for a in assets if a["kind"] == "web"),
        "model_artifacts": sum(1 for a in assets if a["kind"] == "model"),
        "public_assets": sum(1 for a in assets if a.get("exposure_class") == "public"),
        "internal_assets": sum(1 for a in assets if a.get("exposure_class") == "internal"),
        "unscanned_assets": sum(1 for a in assets if "never_scanned" in a.get("action_reasons", [])),
        "stale_assets": sum(1 for a in assets if "stale_scan" in a.get("action_reasons", [])),
        "incomplete_scans": sum(1 for a in assets if "incomplete_scan" in a.get("action_reasons", [])),
        "failed_scans": sum(1 for a in assets if "failed_scan" in a.get("action_reasons", [])),
        "fresh_scans": sum(1 for a in assets if a.get("coverage_posture") == "fresh"),
        "verified_assets": sum(1 for a in assets if (a.get("active_verified") or 0) > 0),
        "unverified_high_assets": sum(
            1 for a in assets
            if (a.get("active_needs_verification") or 0) > 0
            and (a.get("active_critical", 0) + a.get("active_high", 0)) > 0
        ),
        "unowned_assets": sum(1 for a in assets if not a.get("owner")),
        "needs_action": sum(1 for a in assets if a.get("needs_action")),
        "p1_count": sum(1 for a in assets if a.get("action_priority") == "P1"),
        "p2_count": sum(1 for a in assets if a.get("action_priority") == "P2"),
        "p3_count": sum(1 for a in assets if a.get("action_priority") == "P3"),
        "prod_ai_surfaces": sum(
            1 for a in assets
            if a["kind"] == "ai" and (a.get("production_mode") or a.get("environment") == "production")
        ),
        "high_blast_ai_surfaces": sum(1 for a in assets if a["kind"] == "ai" and a.get("blast_radius_tier") in {"high", "critical"}),
    }
    new_count = sum(1 for a in assets if a["is_new"])

    # Rank by action priority first, then raw risk — so the urgent few surface
    # above the long tail. Stable id tiebreak keeps ordering deterministic.
    assets.sort(key=lambda a: (a.get("action_score") or 0, a["risk_score"], a["is_new"], a["id"]), reverse=True)
    total = len(assets)
    assets = assets[offset:offset + limit]
    return {
        "assets": assets,
        "count": len(assets),
        "total": total,
        "offset": offset,
        "new_count": new_count,
        "metrics": metrics,
    }


@app.get("/exposure/changes")
async def exposure_changes(
    since: Optional[str] = None,
    root_domain: Optional[str] = None,
    days: int = Query(7, ge=1, le=90),
    examples: int = Query(5, ge=0, le=10),
):
    """Awareness deltas for the exposure page: what changed since an anchor.

    ``since`` (ISO timestamp, e.g. the user's last visit) wins over ``days``.
    Categories cover new assets, new active critical/high findings, resolved
    findings, failed scans, and assets whose coverage crossed the 30-day stale
    threshold inside the window. Each category carries an ``href`` to the
    exposure/findings view that shows that slice.
    """
    anchor = _exposure_datetime(since) if since else None
    if since and anchor is None:
        raise HTTPException(status_code=400, detail="Invalid 'since' timestamp")
    if anchor is None:
        anchor = datetime.now(timezone.utc) - timedelta(days=days)

    async with db_pool.acquire() as conn:
        new_targets = await conn.fetch(
            """
            SELECT COALESCE(name, url) AS label, url, discovery_source, created_at
            FROM targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY created_at DESC
            """,
            anchor,
            root_domain,
        )
        new_ai = await conn.fetch(
            """
            SELECT name AS label, endpoint_url AS url, created_at
            FROM ai_targets
            WHERE is_active = true AND created_at > $1
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY created_at DESC
            """,
            anchor,
            root_domain,
        )
        new_findings = await conn.fetch(
            """
            SELECT f.title, f.severity, f.first_seen_at,
                   COALESCE(t.root_domain, ait.name, f.url) AS subject
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.status = 'active' AND f.severity IN ('critical', 'high')
              AND f.first_seen_at > $1
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.first_seen_at DESC
            """,
            anchor,
            root_domain,
        )
        resolved_findings = await conn.fetch(
            """
            SELECT f.title, f.severity, f.resolved_at,
                   COALESCE(t.root_domain, ait.name, f.url) AS subject
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE f.status = 'resolved' AND f.resolved_at > $1
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY f.resolved_at DESC
            """,
            anchor,
            root_domain,
        )
        failed_scans = await conn.fetch(
            """
            SELECT s.id, s.target_url AS label, s.scan_type, s.created_at
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.status = 'failed' AND s.created_at > $1
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND ($2::text IS NULL OR t.root_domain = $2::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY s.created_at DESC
            """,
            anchor,
            root_domain,
        )
        went_stale_web = await conn.fetch(
            """
            SELECT COALESCE(name, url) AS label, last_scanned_at
            FROM targets
            WHERE is_active = true AND total_scans > 0 AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR root_domain = $2::text)
            ORDER BY last_scanned_at DESC
            """,
            anchor,
            root_domain,
        )
        # AI surfaces go stale too — the destination view's stale-window filter
        # spans every asset kind, so the tile must count the same population.
        went_stale_ai = await conn.fetch(
            """
            SELECT name AS label, last_scanned_at
            FROM ai_targets
            WHERE is_active = true AND last_scanned_at IS NOT NULL
              AND last_scanned_at <= NOW() - INTERVAL '30 days'
              AND last_scanned_at > $1::timestamptz - INTERVAL '30 days'
              AND ($2::text IS NULL OR LOWER(endpoint_url) LIKE '%' || LOWER($2::text) || '%')
            ORDER BY last_scanned_at DESC
            """,
            anchor,
            root_domain,
        )
    went_stale = sorted(
        [*went_stale_web, *went_stale_ai],
        key=lambda r: _exposure_datetime(r["last_scanned_at"]) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    def fmt_when(value: Any) -> str | None:
        when = _exposure_datetime(value)
        return when.isoformat() if when else None

    # Each category links to the *same slice it counted*: window, severity, and
    # domain scope all carry into the target view instead of dropping to a
    # broader list. Day-based windows pass through exactly; arbitrary `since`
    # anchors round up to whole days (links may include up to one extra day —
    # never less than what was counted).
    if since:
        window_days = max(1, math.ceil((datetime.now(timezone.utc) - anchor).total_seconds() / 86400))
    else:
        window_days = days

    def href(path: str, **params: Any) -> str:
        from urllib.parse import urlencode
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if root_domain:
            clean["domain"] = root_domain
        return f"{path}?{urlencode(clean)}" if clean else path

    new_asset_examples = [
        {
            "label": r["label"],
            "detail": "model" if r["discovery_source"] == "model-intake" else "web",
            "when": fmt_when(r["created_at"]),
        }
        for r in new_targets
    ] + [
        {"label": r["label"] or r["url"], "detail": "ai", "when": fmt_when(r["created_at"])}
        for r in new_ai
    ]
    new_asset_examples.sort(key=lambda e: e["when"] or "", reverse=True)

    def finding_examples(rows: list, when_key: str) -> list[dict[str, Any]]:
        return [
            {
                "label": r["title"],
                "detail": " · ".join(filter(None, [r["severity"], r["subject"]])),
                "when": fmt_when(r[when_key]),
            }
            for r in rows[:examples]
        ]

    new_critical = [r for r in new_findings if r["severity"] == "critical"]
    new_high = [r for r in new_findings if r["severity"] == "high"]

    categories = [
        {
            "key": "new_assets",
            "label": "New assets",
            "count": len(new_targets) + len(new_ai),
            "href": href("/exposure", posture="new", window=window_days),
            "examples": new_asset_examples[:examples],
        },
        {
            "key": "new_critical",
            "label": "New critical findings",
            "count": len(new_critical),
            "href": href(
                "/findings", status="active", severity="critical",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_critical, "first_seen_at"),
        },
        {
            "key": "new_high",
            "label": "New high findings",
            "count": len(new_high),
            "href": href(
                "/findings", status="active", severity="high",
                first_seen_within=window_days, sort_by="first_seen", sort_order="desc",
            ),
            "examples": finding_examples(new_high, "first_seen_at"),
        },
        {
            "key": "resolved",
            "label": "Findings resolved",
            "count": len(resolved_findings),
            "href": href("/findings", status="resolved", resolved_within=window_days, sort_by="last_seen", sort_order="desc"),
            "examples": finding_examples(resolved_findings, "resolved_at"),
        },
        {
            "key": "failed_scans",
            "label": "Failed scans",
            "count": len(failed_scans),
            "href": href("/scans", status="failed", within=window_days),
            "examples": [
                {"label": r["label"], "detail": r["scan_type"], "when": fmt_when(r["created_at"])}
                for r in failed_scans[:examples]
            ],
        },
        {
            "key": "went_stale",
            "label": "Went stale",
            "count": len(went_stale),
            "href": href("/exposure", posture="stale", sort="stale", window=window_days),
            "examples": [
                {
                    "label": r["label"],
                    "detail": f"{_exposure_days_since(r['last_scanned_at'])}d since scan",
                    "when": fmt_when(r["last_scanned_at"]),
                }
                for r in went_stale[:examples]
            ],
        },
    ]
    return {
        "since": anchor.isoformat(),
        "total_changes": sum(c["count"] for c in categories),
        "categories": categories,
    }


@app.get("/exposure/attack-paths")
async def exposure_attack_paths(
    root_domain: Optional[str] = None,
    limit_scans: int = Query(150, ge=1, le=300),
    include_partial: bool = True,
):
    """Flat, severity-ranked list of correlated attack chains across scans.

    Extracts ``attack_chains`` from recent completed scan results, dedupes a
    chain type to its most recent occurrence per asset, and surfaces the step
    narrative so the UI can render each path as a walkable sequence.
    """
    async with db_pool.acquire() as conn:
        scan_rows = await conn.fetch(
            """
            SELECT s.id, s.target_id, s.ai_target_id, s.target_url, s.scan_type,
                   s.created_at, s.result, t.root_domain, ait.endpoint_url AS ai_endpoint_url
            FROM scans s
            LEFT JOIN targets t ON s.target_id = t.id
            LEFT JOIN ai_targets ait ON s.ai_target_id = ait.id
            WHERE s.status = 'completed' AND s.result IS NOT NULL
              AND (s.scan_role IS NULL OR s.scan_role <> 'shard')
              AND ($1::text IS NULL OR t.root_domain = $1::text
                   OR LOWER(ait.endpoint_url) LIKE '%' || LOWER($1::text) || '%')
            ORDER BY s.created_at DESC
            LIMIT $2
            """,
            root_domain,
            limit_scans,
        )

    paths: list[dict[str, Any]] = []
    seen: set[tuple[str | None, str]] = set()

    for row in scan_rows:
        row = row_to_dict(row)
        result = _parse_graph_json(row.get("result"))
        attack_chains = _parse_graph_json(result.get("attack_chains"))
        chains = list(attack_chains.get("chains") or [])
        if include_partial:
            chains += list(attack_chains.get("partial_chains") or [])

        if row.get("ai_target_id"):
            subject_node = f"ai_target:{row['ai_target_id']}"
        elif row.get("target_id"):
            subject_node = f"target:{row['target_id']}"
        else:
            subject_node = None

        for idx, chain in enumerate(chains):
            if not isinstance(chain, dict):
                continue
            chain_type = str(chain.get("chain_type") or chain.get("name") or idx)
            key = (subject_node, chain_type)
            if key in seen:
                continue
            seen.add(key)
            steps = [
                {
                    "step_number": st.get("step_number"),
                    "description": st.get("description"),
                    "impact": st.get("impact"),
                    "finding_type": st.get("finding_type"),
                    "finding_id": st.get("finding_id") or st.get("source_finding_id"),
                    "evidence": st.get("evidence"),
                }
                for st in (chain.get("steps") or [])
                if isinstance(st, dict)
            ]
            severity = str(chain.get("severity") or "").lower() or None
            missing_required = chain.get("missing_required") or chain.get("missing_steps") or []
            if isinstance(missing_required, str):
                missing_required = [missing_required]
            elif not isinstance(missing_required, list):
                missing_required = []
            chain_evidence = chain.get("evidence") if isinstance(chain.get("evidence"), dict) else {}
            supporting = [
                sf for sf in (chain_evidence.get("supporting_findings") or [])
                if isinstance(sf, dict) and sf.get("id")
            ]
            paths.append({
                "_supporting": supporting,
                "id": f"{row['id']}:{chain_type}:{idx}",
                "name": chain.get("name") or chain_type,
                "chain_type": chain.get("chain_type"),
                "severity": severity,
                "status": chain.get("status"),
                "confidence": chain.get("confidence"),
                "completeness": chain.get("completeness"),
                "missing_required": missing_required,
                "business_impact": chain.get("business_impact"),
                "description": chain.get("description"),
                "remediation": chain.get("remediation"),
                "steps": steps,
                "asset_label": _short_url_label(row.get("target_url")),
                "asset_node_id": subject_node,
                "scan_id": str(row["id"]),
                "scan_href": f"/scans/{row['id']}",
            })

    # Resolve chain-step findings to DB finding ids so each step can deep-link
    # to its exact finding. Chains carry scanner fingerprints ("tool:hash") in
    # their supporting_findings evidence, which map onto findings.fingerprint
    # (with a suffix-only fallback for pre-rename findings).
    fingerprints: set[str] = set()
    for p in paths:
        for sf in p["_supporting"]:
            fid = str(sf.get("id") or "")
            if fid:
                fingerprints.add(fid)
                if ":" in fid:
                    fingerprints.add(fid.split(":")[-1])
    fp_map: dict[str, str] = {}
    if fingerprints:
        async with db_pool.acquire() as conn:
            finding_rows = await conn.fetch(
                "SELECT id, fingerprint FROM findings WHERE fingerprint = ANY($1::text[])",
                list(fingerprints),
            )
        for fr in finding_rows:
            fp = str(fr["fingerprint"])
            fp_map[fp] = str(fr["id"])
            if ":" in fp:
                fp_map.setdefault(fp.split(":")[-1], str(fr["id"]))

    def _types_align(step_type: str, matched: str) -> bool:
        # Chain steps use template vocabulary ("sqli"); supporting findings use
        # the correlator's ("sqli_confirmed", "admin_panel_found") — treat a
        # shared underscore-prefix family as the same type.
        if not step_type or not matched:
            return False
        return matched == step_type or matched.startswith(f"{step_type}_") or step_type.startswith(f"{matched}_")

    def _resolve_step_finding(step: dict[str, Any], supporting: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        raw = str(step.get("finding_id") or "")
        if raw:
            if raw in fp_map:
                return fp_map[raw], None
            try:
                uuid.UUID(raw)
                return raw, None
            except ValueError:
                pass
        step_type = str(step.get("finding_type") or "")
        for sf in supporting:
            if _types_align(step_type, str(sf.get("matched_type") or "")):
                sf_id = str(sf.get("id") or "")
                resolved = fp_map.get(sf_id) or (fp_map.get(sf_id.split(":")[-1]) if ":" in sf_id else None)
                if resolved:
                    return resolved, sf.get("title")
        return None, None

    for p in paths:
        supporting = p.pop("_supporting")
        for step in p["steps"]:
            resolved_id, resolved_title = _resolve_step_finding(step, supporting)
            step["finding_id"] = resolved_id
            if resolved_title:
                step["finding_title"] = resolved_title
        # Card-level fallback drill-down when steps can't be resolved 1:1.
        p["findings_href"] = f"/findings?scan_id={p['scan_id']}"

    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    paths.sort(
        key=lambda p: (
            severity_rank.get(p["severity"] or "", 0),
            1 if p["status"] == "complete" else 0,
            len(p["steps"]),
        ),
        reverse=True,
    )
    return {"attack_paths": paths, "count": len(paths)}


# ============================================================
# SCANS
# ============================================================

def normalize_dast_scan_options(options: ScanOptions) -> str:
    """Resolve scan_type from explicit or legacy options and mutate options consistently.

    When an explicit scan_type is provided, the legacy boolean flags
    (thorough/active/quick) are rewritten to match it. This prevents downstream
    consumers from seeing contradictory state such as scan_type='quick' with
    active=True, which previously caused worker.py to add both --quick and
    --active to the scanner CLI.
    """
    raw_scan_type = (options.scan_type or "").strip().lower()
    if raw_scan_type:
        if raw_scan_type not in VALID_DAST_SCAN_TYPES:
            allowed = ", ".join(sorted(VALID_DAST_SCAN_TYPES))
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_scan_type",
                    "message": f"scan_type must be one of: {allowed}",
                    "scan_type": raw_scan_type,
                },
            )
        options.scan_type = raw_scan_type
        # Sync legacy flags to match the explicit scan_type so worker.py never
        # sees a "scan_type=X plus contradictory boolean flag" combination.
        options.quick = raw_scan_type == "quick"
        options.thorough = raw_scan_type in {"deep", "full", "aggressive", "smart"}
        options.active = raw_scan_type in {"full", "aggressive", "smart"}
        return raw_scan_type

    if options.thorough and options.active:
        scan_type = "full"
    elif options.thorough:
        scan_type = "deep"
    elif options.active:
        scan_type = "full"
    elif options.quick:
        scan_type = "quick"
    else:
        scan_type = "quick"

    options.scan_type = scan_type
    return scan_type


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

    # Determine scan type.
    # Priority: explicit scan_type > legacy boolean flags > default quick.
    scan_type = normalize_dast_scan_options(request.options)

    # Validate: public option is incompatible with active-enforced scan types
    if scan_type in ACTIVE_ENFORCED_SCAN_TYPES and request.options.public:
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

    options_payload = _build_scan_options_payload(request.options, scan_type)

    # §2 Operational freshness: record which build the fleet was on at submit, and
    # optionally refuse active scans on a stale fleet (opt-in, fail-open).
    _freshness = _worker_freshness_snapshot()
    if _freshness.get("available"):
        options_payload["expected_build_fingerprint_at_submit"] = _freshness.get("expected_build_fingerprint")
        options_payload["stale_worker_count_at_submit"] = _freshness.get("stale_count")
        options_payload["worker_fleet_size_at_submit"] = _freshness.get("fleet_size")
        if (getattr(request.options, "require_current_workers", False)
                and scan_type in ACTIVE_ENFORCED_SCAN_TYPES
                and _freshness.get("stale_count", 0) > 0):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "stale_workers",
                    "message": (
                        f"{_freshness['stale_count']} of {_freshness['fleet_size']} workers are "
                        f"build-stale; refusing '{scan_type}' scan with require_current_workers=true. "
                        "Restart workers to deploy current code, then re-submit."
                    ),
                    "stale_workers": _freshness.get("stale_names", []),
                },
            )

    parallel_enabled, parallel_worker_count = _apply_auto_sharding_policy(
        request.options,
        options_payload,
        scan_type,
    )

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
                INSERT INTO targets (url, name, root_domain, asm_enabled, asm_config)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            """, normalized_target, request.name, extract_root_domain(normalized_target),
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

        # Parallel scans become a parent row; the scan_plan job fans out shards.
        scan_role = 'parent' if parallel_enabled else 'standalone'

        # Create scan record
        await conn.execute("""
            INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type, scan_role)
            VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
        """, uuid.UUID(scan_id), target_id, normalized_target, job_id,
             json.dumps(_attach_target_note(options_payload, request.target, target_note, scheme_inferred)),
             scan_type, scan_role)

    # Queue the job
    job_data = {
        'job_id': job_id,
        'scan_id': scan_id,
        'target': scan_target,
        'options': _attach_target_note(options_payload, request.target, target_note, scheme_inferred),
        'submitted_at': utc_now_iso()
    }
    # Parallel scans are routed to the plan stage, which decomposes the parent
    # into shard jobs. Everything else stays on the standard scan path.
    if parallel_enabled:
        job_data['type'] = 'scan_plan'
        if parallel_worker_count is not None:
            job_data['parallel_worker_count'] = parallel_worker_count
    r.rpush(QUEUE_NAME, json.dumps(job_data))
    r.hset(f"job:{job_id}", mapping={'status': 'queued', 'target': scan_target})

    response = {
        'scan_id': scan_id,
        'job_id': job_id,
        'status': 'queued',
        'target': normalized_target,
        'scan_type': scan_type
    }
    if parallel_enabled:
        response['parallel'] = True
        if options_payload.get("auto_sharded"):
            response['auto_sharded'] = True
            response['auto_sharding_reason'] = options_payload.get("auto_sharding_reason")
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
    created_within_days: Optional[int] = Query(None, ge=1),
    include_shards: bool = False,
    include_internal: bool = False,
    limit: int = Query(50, le=200),
    offset: int = 0
):
    """List scans with optional filtering.

    Child shard rows and Continuous ASM implementation rows are hidden by
    default so the Scans page shows logical user actions. Use include_shards
    and include_internal for debugging or administrative views.
    """
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
        hidden_roles = _hidden_scan_roles_for_list(
            include_shards=include_shards,
            include_internal=include_internal,
        )
        if hidden_roles:
            role_values = ", ".join(f"'{role}'" for role in hidden_roles)
            role_filter = f" AND (s.scan_role IS NULL OR s.scan_role NOT IN ({role_values}))"
            query += role_filter
            count_query += role_filter

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

        if created_within_days:
            query += f" AND s.created_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            count_query += f" AND s.created_at >= NOW() - INTERVAL '1 day' * ${count_param_idx}"
            params.append(created_within_days)
            count_params.append(created_within_days)
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
        # Drop the heavy full report from list rows. The Scans page only needs
        # summary columns (status/grade/score/findings_count); returning the full
        # result for every row made this response ~9 MB for 50 scans (slow load +
        # intermittent timeouts). The detail endpoint still returns the full result.
        scan.pop("result", None)
        scan.pop("result_partial", None)
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

        # Get findings for this scan. Verified-only filtering is applied after
        # merging raw scan-time proof below, so stale persisted retest verdicts
        # cannot hide findings that this scan just proved.
        findings = await conn.fetch("""
            SELECT id, fingerprint, title, severity, cvss_score, status, tool, url,
                   last_verification_status, last_verification_verdict, last_verification_confidence
            FROM findings WHERE scan_id = $1
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """, uuid.UUID(scan_id))

    result = dict(scan)
    if result.get('result') is not None:
        result['result'] = _normalize_scan_result_for_api(_decode_json_value(result['result']))
    verification_overrides = _scan_result_verification_overrides(result.get('result'))
    merged_findings = []
    for row in findings:
        finding = dict(row)
        override = verification_overrides.get(str(finding.get("fingerprint") or ""))
        if override:
            finding.update(override)
        if verified_only and finding.get("last_verification_verdict") != "exploited":
            continue
        merged_findings.append(finding)
    result['findings'] = merged_findings
    if result.get('options') is not None:
        result['options'] = _sanitize_scan_options(result['options'])

    # Surface a top-level `parallel` boolean (mirrors options.parallel and the
    # submit response, which already returns parallel:true for a parent). Without
    # this, GET detail omitted `parallel`, so clients reading `parallel` saw None
    # on a genuine parent and mis-read it as standalone. scan_role is the source
    # of truth; this is the convenience mirror that keeps the two responses consistent.
    _opts = result.get('options') if isinstance(result.get('options'), dict) else {}
    result['parallel'] = result.get('scan_role') == 'parent' or bool(_opts.get('parallel'))

    # Parent of a parallel scan: attach a live rollup of its shards so the UI
    # can show per-shard progress under the single parent row.
    if result.get('scan_role') == 'parent':
        async with db_pool.acquire() as conn:
            shard_rows = await conn.fetch("""
                SELECT id, scan_role, shard_index, status, score, grade,
                       findings_count, current_phase, progress, duration_seconds,
                       result, options
                FROM scans
                WHERE parent_scan_id = $1
                ORDER BY shard_index
        """, uuid.UUID(scan_id))
        shards = [row_to_dict(row) for row in shard_rows]
        _attach_parallel_shard_rollup(result, shards)
    return result


@app.get("/scans/{scan_id}/deployment-decision")
async def get_scan_deployment_decision(scan_id: str):
    """Return a machine-readable deployment gate decision for CI/CD."""
    async with db_pool.acquire() as conn:
        scan = await conn.fetchrow("""
            SELECT id, status, scan_type, run_kind, result, score, grade, completed_at
            FROM scans
            WHERE id = $1
        """, uuid.UUID(scan_id))
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    return build_deployment_decision(row_to_dict(scan))


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
        return _normalize_scan_result_for_api(_decode_json_value(scan['result']))


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
    child_rows = []
    parent_to_reconcile = None

    async with db_pool.acquire() as conn:
        # Check scan exists and is cancellable
        scan = await conn.fetchrow(
            """
            SELECT id, status, target_url, job_id, scan_role, parent_scan_id
            FROM scans WHERE id = $1
            """,
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
                completed_at = NOW(),
                progress = 100,
                current_phase = 'cancelled'
            WHERE id = $1
        """, uuid.UUID(scan_id))

        if scan['scan_role'] == 'parent':
            # Fan out cancellation to queued/running child shards. Workers may
            # still finish their subprocesses, but completion handlers must not
            # overwrite these terminal rows.
            child_rows = await conn.fetch("""
                UPDATE scans
                SET status = 'cancelled',
                    error_message = 'Cancelled by parent scan',
                    completed_at = NOW(),
                    progress = 100,
                    current_phase = 'cancelled'
                WHERE parent_scan_id = $1
                  AND status IN ('pending', 'queued', 'running')
                RETURNING id, job_id
            """, uuid.UUID(scan_id))
            try:
                r.set(parallel_scan.merge_guard_key(scan_id), "cancelled", nx=True, ex=86400)
            except Exception:
                pass
        elif scan['scan_role'] == 'shard' and scan['parent_scan_id']:
            parent_to_reconcile = str(scan['parent_scan_id'])

    # Signal worker to stop via Redis (set cancel flag)
    # Workers should check this flag periodically
    r.set(f"scan:{scan_id}:cancel", "1", ex=3600)  # Expires in 1 hour
    for child in child_rows:
        r.set(f"scan:{str(child['id'])}:cancel", "1", ex=3600)

    # Also update known job hashes in Redis so UI/queue status reflects the
    # cancellation immediately.
    job_ids = [scan['job_id']] + [child['job_id'] for child in child_rows]
    for job_id in job_ids:
        if job_id:
            r.hset(
                f"job:{job_id}",
                mapping={
                    'status': 'cancelled',
                    'progress': '100',
                    'current_phase': 'cancelled',
                },
            )
            r.expire(f"job:{job_id}", 86400)

    # Backward-compatible fallback for older/odd job hashes.
    for key in r.keys("job:*"):
        job_data = r.hgetall(key)
        if job_data.get('scan_id') == scan_id:
            r.hset(key, 'status', 'cancelled')
            break

    if parent_to_reconcile:
        async with db_pool.acquire() as conn:
            await parallel_scan.reconcile_parallel_parent(
                conn, parent_to_reconcile, r, QUEUE_NAME
            )

    return {
        "status": "cancelled",
        "scan_id": scan_id,
        "target": scan['target_url'],
        "cancelled_child_shards": len(child_rows),
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

        # Per-target ASM coverage (one aggregate query over the persistent inventory).
        asm_by_target: dict[str, dict] = {}
        target_ids = [row['id'] for row in rows]
        if target_ids:
            asm_rows = await conn.fetch(
                """
                WITH inventory AS (
                    SELECT target_id,
                           COUNT(*) AS total,
                           COUNT(*) FILTER (WHERE test_status <> 'gone') AS testable,
                           COUNT(*) FILTER (WHERE test_status = 'tested') AS status_tested
                    FROM target_endpoints
                    WHERE target_id = ANY($1::uuid[])
                    GROUP BY target_id
                ),
                latest_attempt AS (
                    SELECT DISTINCT ON (te.id)
                        te.target_id,
                        te.id AS endpoint_id,
                        CASE
                            WHEN aea.status = 'completed'
                             AND lower(COALESCE(aea.scanner_telemetry_json->>'per_endpoint_telemetry', 'false')) <> 'true'
                            THEN 'partial'
                            ELSE aea.status
                        END AS status
                    FROM target_endpoints te
                    JOIN asm_endpoint_attempts aea ON aea.endpoint_id = te.id
                    WHERE te.target_id = ANY($1::uuid[]) AND te.test_status <> 'gone'
                    ORDER BY te.id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
                ),
                attempts AS (
                    SELECT target_id,
                           COUNT(*) AS attempted,
                           COUNT(*) FILTER (WHERE status = 'completed') AS completed
                    FROM latest_attempt
                    GROUP BY target_id
                )
                SELECT i.target_id, i.total, i.testable, i.status_tested,
                       COALESCE(a.attempted, 0) AS attempted,
                       COALESCE(a.completed, 0) AS attempt_completed
                FROM inventory i
                LEFT JOIN attempts a ON a.target_id = i.target_id
                """,
                target_ids,
            )
            for ar in asm_rows:
                total = int(ar['total'] or 0)
                testable = int(ar['testable'] or total)
                attempted = int(ar['attempted'] or 0)
                tested = int(ar['attempt_completed'] if attempted > 0 else (ar['status_tested'] or 0))
                denominator = testable
                asm_by_target[str(ar['target_id'])] = {
                    'total': total,
                    'tested': tested,
                    'untested': max(0, denominator - tested),
                    'coverage': round(tested / denominator, 4) if denominator else 0.0,
                    'coverage_basis': 'attempt_ledger' if attempted > 0 else 'endpoint_status',
                    'attempted': attempted,
                }

    def _attach_asm(target_data):
        if target_data:
            target_data['asm_coverage'] = asm_by_target.get(str(target_data['id']))
        return target_data

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

        target_data = _attach_asm(row_to_dict(row))
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
        # Domain-level ASM coverage rollup across root + subdomains.
        cov_targets = ([data['root_target']] if data['root_target'] else []) + data['subdomains']
        cov_total = sum((t.get('asm_coverage') or {}).get('total', 0) for t in cov_targets)
        cov_tested = sum((t.get('asm_coverage') or {}).get('tested', 0) for t in cov_targets)
        data['asm_coverage'] = {
            'total': cov_total,
            'tested': cov_tested,
            'untested': cov_total - cov_tested,
            'coverage': round(cov_tested / cov_total, 4) if cov_total else 0.0,
        } if cov_total else None
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
                INSERT INTO targets (url, name, root_domain, is_root, scan_options, asm_enabled, asm_config)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id
            """, normalized_target, request.name, root_domain, is_root,
                 json.dumps(_attach_target_note(request.scan_options or {}, request.url, target_note, scheme_inferred)),
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

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

        # Get recent scans (exclude child shard rows of parallel scans)
        scans = await conn.fetch("""
            SELECT id, status, score, grade, created_at, completed_at
            FROM scans
            WHERE target_id = $1 AND (scan_role IS NULL OR scan_role <> 'shard')
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

        if request.metadata_json is not None:
            updates.append(f"metadata_json = COALESCE(metadata_json, '{{}}'::jsonb) || ${param_idx}::jsonb")
            params.append(json.dumps(request.metadata_json))
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
# CONTINUOUS ASM - per-target endpoint inventory + async testing (docs §16)
# ============================================================

@app.get("/asm/check-families")
async def asm_check_families():
    """Return the registered check-family contract for API/UI/AI clients."""
    return {
        "families": check_registry.describe_check_families(),
        "asm_focus_allowed": list(check_registry.asm_focus_family_names()),
        "default": "all",
    }


class AsmTestRequest(BaseModel):
    batch_size: int = Field(default=100, ge=1, le=1000)
    stale_days: int = Field(default=30, ge=0)
    exploit_depth: bool = False
    check_family: Optional[str] = None
    endpoint_filter: Optional[str] = None

    @field_validator("check_family")
    @classmethod
    def validate_check_family(cls, value):
        return _validate_asm_check_family_value(value)

    @field_validator("endpoint_filter")
    @classmethod
    def validate_endpoint_filter(cls, value):
        return _validate_asm_endpoint_filter_value(value)


class AsmReconRequest(BaseModel):
    budget_profile: Optional[str] = None


class AsmImproveRequest(BaseModel):
    batch_size: Optional[int] = Field(default=None, ge=1, le=1000)
    stale_days: Optional[int] = Field(default=None, ge=0)
    exploit_depth: Optional[bool] = None
    check_family: Optional[str] = None
    endpoint_filter: Optional[str] = None

    @field_validator("check_family")
    @classmethod
    def validate_check_family(cls, value):
        return _validate_asm_check_family_value(value)

    @field_validator("endpoint_filter")
    @classmethod
    def validate_endpoint_filter(cls, value):
        return _validate_asm_endpoint_filter_value(value)


class AsmPolicyUpdate(BaseModel):
    """Per-target Continuous ASM policy (docs §16 Phase 3/4)."""
    enabled: Optional[bool] = None
    config: Optional[dict] = None


class AIOpsRouterRequest(BaseModel):
    """Natural-language DAST/ASM intent planner for AI agents.

    Execution is intentionally conservative: active or state-changing intents
    dry-run by default and require both request confirmation and the
    AI_OPS_ROUTER_EXECUTE_ENABLED feature flag before this API queues work.
    """

    prompt: Optional[str] = None
    utterance: Optional[str] = None
    target: Optional[str] = None
    target_id: Optional[str] = None
    execute: bool = False
    confirm_execution: bool = False
    confirm_authorized: bool = False
    confirm_high_risk: bool = False
    auth_context: dict[str, Any] = Field(default_factory=dict)


def _ai_ops_execute_enabled() -> bool:
    return str(os.environ.get("AI_OPS_ROUTER_EXECUTE_ENABLED") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _ai_ops_prompt_text(request: AIOpsRouterRequest) -> str:
    return str(request.prompt or request.utterance or "").strip()


def _ai_ops_has_auth_context(request: AIOpsRouterRequest, key: str) -> bool:
    ctx = request.auth_context if isinstance(request.auth_context, dict) else {}
    aliases = {
        "primary": ("primary", "has_primary", "has_primary_auth", "has_primary_auth_context"),
        "second_user": ("second_user", "user2", "has_second_user", "has_second_user_auth", "has_second_user_auth_context"),
    }
    return any(bool(ctx.get(alias)) for alias in aliases.get(key, (key,)))


def _ai_ops_call(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    call: dict[str, Any] = {"method": method, "path": path}
    if body is not None:
        call["body"] = body
    return call


def _build_ai_ops_router_plan(request: AIOpsRouterRequest) -> dict[str, Any]:
    text = _ai_ops_prompt_text(request)
    lowered = text.lower()
    missing: list[str] = []
    non_goals = [
        "no implicit Lab/deep upgrade",
        "no hidden shard or ASM implementation rows",
        "no active work without explicit authorization",
    ]
    authorization_assumption = (
        "The requester confirms they own or are authorized to test the target before execution."
    )
    intent = "unknown"
    planned_call: dict[str, Any] | None = None
    safety_preset = "safe"
    active_or_budget = False
    high_risk_families: list[str] = []
    active_families: list[str] = []
    rate_cap_changes: dict[str, Any] = {}
    explanation = "I could not map the request to a supported DAST/ASM operation."

    if not text:
        missing.append("prompt")
    elif "full coverage" in lowered or ("coverage" in lowered and "scan" in lowered) or "scan all endpoint" in lowered:
        intent = "run_full_coverage"
        active_or_budget = True
        active_families = ["all"]
        safety_preset = "balanced"
        if not request.target:
            missing.append("target")
        planned_call = _ai_ops_call(
            "POST",
            "/scans",
            {
                "target": request.target or "<target>",
                "options": {
                    "scan_type": "smart",
                    "budget_profile": "thorough",
                    "parallel": True,
                    "shard_strategy": "coverage",
                    "exploit_depth": False,
                },
            },
        )
        explanation = "Plan a one-shot Full Coverage scan with discover-once dynamic fan-out."
    elif ("keep" in lowered and "covered" in lowered) or "enable asm" in lowered or "continuous asm" in lowered:
        intent = "enable_continuous_asm"
        active_or_budget = True
        safety_preset = "safe"
        if not request.target_id:
            missing.append("target_id")
        body = {
            "enabled": True,
            "config": {
                "batch_size": asm_inventory.DEFAULT_ASM_CONFIG["batch_size"],
                "stale_days": asm_inventory.DEFAULT_ASM_CONFIG["stale_days"],
                "recon_interval_hours": asm_inventory.DEFAULT_ASM_CONFIG["recon_interval_hours"],
                "exploit_depth": False,
            },
        }
        planned_call = _ai_ops_call("PUT", f"/targets/{request.target_id or '<target_id>'}/asm/policy", body)
        explanation = "Enable safe Continuous ASM defaults for the target."
    elif "untested" in lowered or "gaps" in lowered or "not tested" in lowered or "still needs" in lowered:
        intent = "explain_asm_gaps"
        safety_preset = "read_only"
        if not request.target_id:
            missing.append("target_id")
        planned_call = _ai_ops_call("GET", f"/targets/{request.target_id or '<target_id>'}/asm/gaps")
        explanation = "Read the ASM coverage gap summary without queueing work."
    elif "budget" in lowered and ("api" in lowered or "apis" in lowered or "endpoint" in lowered):
        intent = "increase_api_endpoint_budget"
        active_or_budget = True
        active_families = ["all"]
        safety_preset = "safe"
        if not request.target_id:
            missing.append("target_id")
        api_batch_size = min(200, max(100, int(asm_inventory.DEFAULT_ASM_CONFIG["batch_size"]) * 2))
        body = {"endpoint_filter": "api", "batch_size": api_batch_size, "exploit_depth": False}
        planned_call = _ai_ops_call(
            "POST",
            f"/targets/{request.target_id or '<target_id>'}/asm/improve",
            body,
        )
        rate_cap_changes = {
            "global_defaults_changed": False,
            "endpoint_filter": "api",
            "batch_size": api_batch_size,
        }
        explanation = (
            "Queue the next ASM improvement pass with extra batch budget scoped to API-like endpoints only; "
            "target-wide defaults stay unchanged."
        )
    else:
        family: str | None = None
        if "bola" in lowered or "idor" in lowered or "object authorization" in lowered:
            family = "bola"
        elif (
            "authentication" in lowered
            or "auth bypass" in lowered
            or "anonymous access" in lowered
            or "unauthenticated" in lowered
            or "access control" in lowered
        ):
            family = "auth"
        elif "sqli" in lowered or "sql injection" in lowered:
            family = "sqli"
        elif "xss" in lowered or "cross-site scripting" in lowered:
            family = "xss"
        if family:
            intent = f"focused_asm_{family}"
            active_or_budget = True
            active_families = [family]
            if not request.target_id:
                missing.append("target_id")
            body: dict[str, Any] = {"check_family": family}
            if family == "bola":
                high_risk_families = ["bola"]
                body["exploit_depth"] = True
                safety_preset = "lab"
                if not _ai_ops_has_auth_context(request, "primary"):
                    missing.append("primary_auth_context")
                if not _ai_ops_has_auth_context(request, "second_user"):
                    missing.append("second_user_auth_context")
            elif family == "auth":
                safety_preset = "balanced"
                if not _ai_ops_has_auth_context(request, "primary"):
                    missing.append("primary_auth_context")
            else:
                safety_preset = "balanced"
            planned_call = _ai_ops_call("POST", f"/targets/{request.target_id or '<target_id>'}/asm/improve", body)
            explanation = f"Queue a focused ASM endpoint batch for {family} only."

    requires_confirmation = bool(active_or_budget or high_risk_families)
    execution_enabled = _ai_ops_execute_enabled()
    confirmation_ok = (
        request.execute
        and (not requires_confirmation or request.confirm_execution)
        and (not active_or_budget or request.confirm_authorized)
        and (not high_risk_families or request.confirm_high_risk)
    )
    execution_allowed = bool(
        request.execute
        and not missing
        and planned_call
        and (not requires_confirmation or (execution_enabled and confirmation_ok))
    )
    dry_run = not execution_allowed
    execution_blocked_reason = None
    if request.execute and dry_run:
        if missing:
            execution_blocked_reason = "missing_inputs"
        elif requires_confirmation and not execution_enabled:
            execution_blocked_reason = "AI_OPS_ROUTER_EXECUTE_ENABLED is not enabled"
        elif requires_confirmation and not confirmation_ok:
            execution_blocked_reason = "confirmation_required"
        else:
            execution_blocked_reason = "unsupported_intent"

    return {
        "intent": intent,
        "dry_run": dry_run,
        "execute_requested": bool(request.execute),
        "execution_allowed": execution_allowed,
        "execution_blocked_reason": execution_blocked_reason,
        "requires_confirmation": requires_confirmation,
        "safety_preset": safety_preset,
        "missing_inputs": list(dict.fromkeys(missing)),
        "planned_api_call": planned_call,
        "planned_api_calls": [planned_call] if planned_call else [],
        "explanation": explanation,
        "authorization_assumption": authorization_assumption if active_or_budget else None,
        "blast_radius": {
            "target": request.target,
            "target_id": request.target_id,
            "active_families": active_families,
            "high_risk_families": high_risk_families,
            "auth_states": ["configured target credentials"] if active_or_budget else [],
            "rate_cap_changes": rate_cap_changes,
        },
        "non_goals": non_goals,
    }


def _decode_target_scan_options(raw) -> dict:
    decoded = _decode_json_value(raw) or {}
    return decoded if isinstance(decoded, dict) else {}


async def _asm_active_scan_count(conn, target_id: str) -> int:
    return int(await conn.fetchval(
        """
        SELECT COUNT(*) FROM scans
        WHERE target_id = $1 AND status IN ('pending', 'queued', 'running')
        """,
        uuid.UUID(target_id),
    ) or 0)


def _asm_recommended_campaigns(
    *,
    coverage: dict[str, Any],
    family_coverage: dict[str, Any] | None = None,
    by_auth: dict[str, Any] | None = None,
    last_attempt_counts: dict[str, int] | None = None,
    active_scans: int = 0,
) -> list[dict[str, Any]]:
    """§7: prioritized next-campaign suggestions for UI/AI.

    Maps current coverage/family/blocker state to concrete campaign types:
    recon, add_credentials, sqli_wave, xss_wave, bola_wave, retest_stale, test.
    Family waves are suggested when no PROOF-quality (completed) attempt exists for
    that family — endpoint-attempted is not family-proved.
    """
    attempts = last_attempt_counts or {}
    fams = family_coverage or {}
    total = int(coverage.get("total") or 0)
    untested = int(coverage.get("untested") or 0)
    stale = int(coverage.get("stale") or 0)
    auth_missing = int(attempts.get("auth_missing") or 0) + int(attempts.get("auth_failed") or 0)

    if active_scans > 0:
        return [{"campaign": "wait", "label": "Wait for current work",
                 "reason": "A scan is already active for this target.", "priority": "low"}]
    if total == 0:
        return [{"campaign": "recon", "label": "Discover endpoints",
                 "reason": "No persistent endpoint inventory exists yet.", "priority": "high"}]

    recs: list[dict[str, Any]] = []
    if auth_missing > 0:
        recs.append({"campaign": "add_credentials", "label": "Add credentials",
                     "reason": f"{auth_missing} endpoints need auth to replay.", "priority": "high"})

    def _completed(fam: str) -> int:
        return int((fams.get(fam) or {}).get("completed") or 0)

    for fam, label, prio in (("sqli", "Run SQLi wave", "high"),
                             ("xss", "Run XSS wave", "medium"),
                             ("bola", "Run BOLA wave (needs 2 users + Lab/deep)", "medium")):
        if _completed(fam) == 0 and _completed("all") == 0:
            recs.append({"campaign": f"{fam}_wave", "label": label,
                         "reason": f"No proof-quality {fam.upper()} attempt recorded yet.",
                         "priority": prio})
    if stale > 0:
        recs.append({"campaign": "retest_stale", "label": "Retest stale endpoints",
                     "reason": f"{stale} endpoints are stale and may have changed.", "priority": "medium"})
    if untested > 0 and not any(r["campaign"].endswith("_wave") for r in recs):
        recs.append({"campaign": "test", "label": "Test untested endpoints",
                     "reason": f"{untested} endpoints have never been tested.", "priority": "medium"})
    if not recs:
        recs.append({"campaign": "recon", "label": "Refresh discovery",
                     "reason": "Inventory looks covered; refresh to catch new surface.", "priority": "low"})
    return recs


def _asm_recommendation(
    coverage: dict[str, Any],
    *,
    claimable: int = 0,
    active_scans: int = 0,
    last_attempt_counts: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Small, stable decision model for UI/API/AI callers.

    This intentionally exposes one recommended next action instead of every
    allocator knob. It is conservative: active scan first, then empty inventory
    recon, then claimable endpoint testing, then recon refresh.
    """
    attempts = last_attempt_counts or {}
    total = int(coverage.get("total") or 0)
    untested = int(coverage.get("untested") or 0)
    stale = int(coverage.get("stale") or 0)
    in_progress = int(coverage.get("in_progress") or 0)
    auth_missing = int(attempts.get("auth_missing") or attempts.get("auth_failed") or 0)
    partial = sum(v for k, v in attempts.items() if str(k or "").startswith("partial"))

    blockers: list[dict[str, Any]] = []
    if active_scans > 0:
        blockers.append({"kind": "active_scan", "count": active_scans, "message": "A scan is already active for this target."})
    if auth_missing > 0:
        blockers.append({"kind": "auth_missing", "count": auth_missing, "message": "Some authenticated endpoints need credentials before they can be replayed."})
    if partial > 0:
        blockers.append({"kind": "partial", "count": partial, "message": "Some endpoints have partial attempts and need another pass."})

    if active_scans > 0:
        return {
            "next_action": "wait",
            "label": "Wait for current work",
            "reason": "A scan is already queued or running for this target.",
            "blockers": blockers,
        }
    if total == 0:
        return {
            "next_action": "recon",
            "label": "Discover endpoints",
            "reason": "No persistent endpoint inventory exists yet.",
            "blockers": blockers,
        }
    if claimable > 0 or untested > 0 or stale > 0:
        return {
            "next_action": "test",
            "label": "Test next endpoint batch",
            "reason": f"{max(claimable, untested + stale)} endpoint(s) are untested or stale.",
            "blockers": blockers,
        }
    if in_progress > 0:
        return {
            "next_action": "wait",
            "label": "Wait for current batch",
            "reason": f"{in_progress} endpoint(s) are currently being tested.",
            "blockers": blockers,
        }
    return {
        "next_action": "recon",
        "label": "Refresh discovery",
        "reason": "Current inventory has no claimable endpoints; refresh discovery to find new surface.",
        "blockers": blockers,
    }


async def _enqueue_asm_exploit_batch(
    conn, r, target_id: str, target_url: str, base_opts: dict,
    *, batch_size: int, stale_days: int, exploit_depth: bool,
    check_family: str | None = None,
    endpoint_filter: str | None = None,
    triggered_by: str = "api",
    domain_rate_reserved: int = 0,
) -> dict:
    """Create an asm_batch scan row and enqueue the exploit_batch job. Shared by
    POST /asm/test and the continuous dispatcher."""
    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    opts = _apply_asm_check_family(base_opts or {}, check_family)
    family = _normalize_asm_check_family(check_family)
    endpoint_filter = _validate_asm_endpoint_filter_value(endpoint_filter)
    _enforce_asm_family_preconditions(family, opts, exploit_depth=exploit_depth)
    if endpoint_filter:
        opts["asm_endpoint_filter"] = endpoint_filter
    campaign_id = await asm_inventory.create_campaign(
        conn,
        target_id,
        mode=asm_inventory.CAMPAIGN_FOCUSED_FAMILY if family else asm_inventory.CAMPAIGN_CONTINUOUS_ASM,
        requested_by=triggered_by,
        budget_profile=opts.get("budget_profile"),
        wide_budget={"batch_size": batch_size, "stale_days": stale_days, "endpoint_filter": endpoint_filter},
        deep_budget={"exploit_depth": exploit_depth},
        check_families=[family] if family else ["all"],
        auth_states=[],
        metadata_json={"scan_role": asm_inventory.ASM_BATCH_ROLE, "endpoint_filter": endpoint_filter},
    )
    await conn.execute(
        """INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type, scan_role, campaign_id)
           VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, $8)""",
        uuid.UUID(scan_id), uuid.UUID(target_id), target_url, job_id,
        json.dumps(opts), (opts.get("scan_type") or "smart"),
        asm_inventory.ASM_BATCH_ROLE, uuid.UUID(campaign_id),
    )
    r.rpush(QUEUE_NAME, json.dumps({
        "type": asm_inventory.EXPLOIT_BATCH_JOB_TYPE,
        "job_id": job_id, "scan_id": scan_id,
        "target_id": target_id, "target": target_url,
        "batch_size": batch_size, "stale_days": stale_days, "exploit_depth": exploit_depth,
        "campaign_id": campaign_id,
        "check_family": family,
        "endpoint_filter": endpoint_filter,
        "domain_rate_reserved": max(0, int(domain_rate_reserved or 0)),
        "options": opts, "triggered_by": triggered_by,
        "submitted_at": utc_now_iso(),
    }))
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target_url})
    return {"scan_id": scan_id, "job_id": job_id, "campaign_id": campaign_id}


async def _enqueue_asm_recon(
    conn, r, target_id: str, target_url: str, base_opts: dict,
    *, triggered_by: str = "dispatcher",
) -> dict:
    """Create an asm_recon scan row and enqueue a lean standalone discovery scan
    that refreshes/grows the inventory (worklist persisted on completion)."""
    opts = dict(base_opts or {})
    opts["scan_type"] = "smart"
    opts.pop("parallel", None)  # recon is one lightweight standalone scan
    cb = dict(opts.get("custom_budget") or {})
    cb.update(parallel_scan.RECON_DISCOVERY_BUDGET)  # lean enumeration, active off
    opts["custom_budget"] = cb
    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    campaign_id = await asm_inventory.create_campaign(
        conn,
        target_id,
        mode=asm_inventory.CAMPAIGN_SURFACE_RECON,
        requested_by=triggered_by,
        budget_profile=opts.get("budget_profile"),
        wide_budget=cb,
        check_families=["recon"],
        metadata_json={"scan_role": asm_inventory.ASM_RECON_ROLE},
    )
    await conn.execute(
        """INSERT INTO scans (id, target_id, target_url, job_id, status, options, scan_type, scan_role, campaign_id)
           VALUES ($1, $2, $3, $4, 'pending', $5, 'smart', $6, $7)""",
        uuid.UUID(scan_id), uuid.UUID(target_id), target_url, job_id,
        json.dumps(opts), asm_inventory.ASM_RECON_ROLE, uuid.UUID(campaign_id),
    )
    r.rpush(QUEUE_NAME, json.dumps({
        "job_id": job_id, "scan_id": scan_id, "target": target_url,
        "options": opts, "triggered_by": triggered_by, "asm_recon": True,
        "campaign_id": campaign_id,
        "submitted_at": utc_now_iso(),
    }))
    r.hset(f"job:{job_id}", mapping={"status": "queued", "target": target_url})
    return {"scan_id": scan_id, "job_id": job_id, "campaign_id": campaign_id}


@app.get("/targets/{target_id}/asm/endpoints")
async def asm_list_endpoints(
    target_id: str,
    status: Optional[str] = None,
    limit: int = Query(200, le=1000),
    offset: int = 0,
):
    """List the persistent attack-surface inventory for a target + coverage."""
    async with db_pool.acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        params: list[Any] = [uuid.UUID(target_id)]
        q = """SELECT id, method, path, param_shape, param_location, replay_spec, content_type,
                      source, auth_state, priority_score, test_status, last_attempt_status,
                      last_verdict, first_seen_at, last_seen_at, last_tested_at
               FROM target_endpoints WHERE target_id = $1"""
        if status:
            params.append(status)
            q += f" AND test_status = ${len(params)}"
        q += " ORDER BY priority_score DESC, last_seen_at DESC"
        params.append(limit)
        q += f" LIMIT ${len(params)}"
        params.append(offset)
        q += f" OFFSET ${len(params)}"
        rows = await conn.fetch(q, *params)
        coverage = await asm_inventory.coverage_summary(conn, target_id)
    return {"endpoints": [row_to_dict(r) for r in rows], "coverage": coverage}


@app.get("/targets/{target_id}/asm/coverage")
async def asm_coverage(target_id: str):
    """Per-target ASM coverage counts (tested / total over time)."""
    async with db_pool.acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        return await asm_inventory.coverage_summary(conn, target_id)


@app.post("/targets/{target_id}/asm/test")
async def asm_test(target_id: str, request: AsmTestRequest = None):
    """Queue an async exploitation batch over untested/stale inventory endpoints."""
    request = request or AsmTestRequest()
    r = get_redis()
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        if await _asm_active_scan_count(conn, target_id) > 0:
            raise HTTPException(status_code=409, detail="Target already has an active scan; wait for it to finish before queueing another ASM action")
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        if coverage["total"] == 0:
            raise HTTPException(status_code=400, detail="No endpoints in inventory yet; run a scan or coverage recon first")
        base_opts = _decode_target_scan_options(target["scan_options"])
        enq = await _enqueue_asm_exploit_batch(
            conn, r, target_id, target["url"], base_opts,
            batch_size=request.batch_size, stale_days=request.stale_days,
            exploit_depth=request.exploit_depth, check_family=request.check_family,
            endpoint_filter=request.endpoint_filter,
            triggered_by="api",
        )
    return {
        "scan_id": enq["scan_id"], "job_id": enq["job_id"], "campaign_id": enq["campaign_id"], "status": "queued",
        "batch_size": request.batch_size,
        "check_family": _normalize_asm_check_family(request.check_family) or "all",
        "endpoint_filter": _validate_asm_endpoint_filter_value(request.endpoint_filter),
        "inventory_total": coverage["total"], "untested": coverage["untested"],
    }


@app.post("/targets/{target_id}/asm/recon")
async def asm_recon(target_id: str, request: AsmReconRequest = None):
    """Queue an explicit ASM recon refresh for a target."""
    request = request or AsmReconRequest()
    r = get_redis()
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        if await _asm_active_scan_count(conn, target_id) > 0:
            raise HTTPException(status_code=409, detail="Target already has an active scan; wait for it to finish before queueing another ASM action")
        base_opts = _decode_target_scan_options(target["scan_options"])
        if request.budget_profile:
            base_opts["budget_profile"] = request.budget_profile
        enq = await _enqueue_asm_recon(conn, r, target_id, target["url"], base_opts, triggered_by="api")
        await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", uuid.UUID(target_id))
    return {
        "action": "recon",
        "scan_id": enq["scan_id"],
        "job_id": enq["job_id"],
        "campaign_id": enq["campaign_id"],
        "status": "queued",
        "reason": "Queued discovery refresh for the persistent ASM inventory",
    }


class AsmPruneRequest(BaseModel):
    """On-demand reachability sweep / GC of the persistent endpoint inventory."""
    max_probe: int = Field(default=2000, ge=1, le=20000)
    retire_threshold: Optional[int] = Field(default=None, ge=1, le=10)


@app.post("/targets/{target_id}/asm/prune")
async def asm_prune(target_id: str, request: AsmPruneRequest = None):
    """Re-probe existing inventory rows, persist reachability, and retire phantom
    (404/soft-404) endpoints to ``gone`` so they stop consuming test budget and
    inflating coverage. Read-only GET probes + status bookkeeping; safe anytime.
    Retirement is reversible (re-discovery resurrects ``gone`` -> ``untested``).
    Probes least-recently-swept paths first, so repeated calls rotate the whole
    inventory; bounded by ``max_probe`` to stay responsive."""
    request = request or AsmPruneRequest()
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow("SELECT url, scan_options FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        before = await asm_inventory.coverage_summary(conn, target_id)
        base_opts = _decode_target_scan_options(target["scan_options"])
        result = await asm_inventory.sweep_endpoint_reachability(
            conn, target["url"], target_id, base_opts,
            max_probe=request.max_probe, retire_threshold=request.retire_threshold,
        )
        after = await asm_inventory.coverage_summary(conn, target_id)
    return {
        "action": "prune",
        "target_id": target_id,
        "sweep": result,
        "inventory_total_before": before.get("total"),
        "inventory_testable_after": (after.get("total") or 0) - (after.get("gone") or 0),
        "gone_after": after.get("gone"),
        "reason": (
            f"Probed {result.get('probed', 0)} path(s); retired {result.get('retired', 0)} "
            f"unreachable endpoint(s) to 'gone' (reversible on re-discovery)."
        ),
    }


@app.post("/targets/{target_id}/asm/improve")
async def asm_improve(target_id: str, request: AsmImproveRequest = None):
    """Choose and queue the next best ASM action: recon if inventory is empty,
    otherwise a test batch when endpoints are claimable."""
    request = request or AsmImproveRequest()
    r = get_redis()
    async with db_pool.acquire() as conn:
        target = await conn.fetchrow(
            "SELECT url, scan_options, asm_config FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not target:
            raise HTTPException(status_code=404, detail="Target not found")
        active = await _asm_active_scan_count(conn, target_id)
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        cfg = asm_inventory.merge_asm_config(_decode_asm_config(target["asm_config"]))
        stale_days = request.stale_days if request.stale_days is not None else cfg["stale_days"]
        endpoint_filter = _validate_asm_endpoint_filter_value(request.endpoint_filter)
        claimable = await asm_inventory.claimable_count(
            conn,
            target_id,
            stale_days=stale_days,
            endpoint_filter=endpoint_filter,
        )
        attempts = await conn.fetch(
            """
            SELECT COALESCE(last_attempt_status, 'none') AS status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(last_attempt_status, 'none')
            """,
            uuid.UUID(target_id),
        )
        attempt_counts = {str(rw["status"]): int(rw["count"] or 0) for rw in attempts}
        rec = _asm_recommendation(coverage, claimable=claimable, active_scans=active, last_attempt_counts=attempt_counts)
        if rec["next_action"] == "wait":
            return {"action": "wait", "status": "busy", "endpoint_filter": endpoint_filter, **rec}

        if endpoint_filter and rec["next_action"] == "test" and claimable <= 0:
            filtered_rec = {
                "next_action": "wait",
                "label": "No matching endpoints",
                "reason": f"No {endpoint_filter}-like endpoints are currently untested or stale.",
                "blockers": rec.get("blockers") or [],
            }
            return {
                "action": "wait",
                "status": "no_claimable_endpoints",
                "endpoint_filter": endpoint_filter,
                "reason": filtered_rec["reason"],
                "recommendation": filtered_rec,
            }

        base_opts = _decode_target_scan_options(target["scan_options"])
        if rec["next_action"] == "recon":
            enq = await _enqueue_asm_recon(conn, r, target_id, target["url"], base_opts, triggered_by="improve")
            await conn.execute("UPDATE targets SET asm_last_recon_at = NOW() WHERE id = $1", uuid.UUID(target_id))
            return {
                "action": "recon",
                "scan_id": enq["scan_id"],
                "job_id": enq["job_id"],
                "campaign_id": enq["campaign_id"],
                "status": "queued",
                "reason": rec["reason"],
                "recommendation": rec,
            }

        batch_size = request.batch_size if request.batch_size is not None else cfg["batch_size"]
        if claimable > 0:
            batch_size = min(batch_size, claimable)
        exploit_depth = request.exploit_depth if request.exploit_depth is not None else bool(cfg["exploit_depth"])
        enq = await _enqueue_asm_exploit_batch(
            conn, r, target_id, target["url"], base_opts,
            batch_size=batch_size, stale_days=stale_days,
            exploit_depth=exploit_depth, check_family=request.check_family,
            endpoint_filter=endpoint_filter,
            triggered_by="improve",
        )
        await conn.execute("UPDATE targets SET asm_last_test_at = NOW() WHERE id = $1", uuid.UUID(target_id))
    return {
        "action": "test",
        "scan_id": enq["scan_id"],
        "job_id": enq["job_id"],
        "campaign_id": enq["campaign_id"],
        "status": "queued",
        "batch_size": batch_size,
        "check_family": _normalize_asm_check_family(request.check_family) or "all",
        "endpoint_filter": endpoint_filter,
        "reason": rec["reason"],
        "recommendation": rec,
    }


def _decode_asm_config(raw) -> dict:
    decoded = _decode_json_value(raw) or {}
    return decoded if isinstance(decoded, dict) else {}


@app.get("/targets/{target_id}/asm/policy")
async def asm_get_policy(target_id: str):
    """Return the effective Continuous ASM policy for a target."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT asm_enabled, asm_config, asm_last_test_at, asm_last_recon_at FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
    return {
        "enabled": bool(row["asm_enabled"]),
        "config": asm_inventory.merge_asm_config(_decode_asm_config(row["asm_config"])),
        "last_test_at": row["asm_last_test_at"].isoformat() if row["asm_last_test_at"] else None,
        "last_recon_at": row["asm_last_recon_at"].isoformat() if row["asm_last_recon_at"] else None,
    }


@app.put("/targets/{target_id}/asm/policy")
async def asm_set_policy(target_id: str, body: AsmPolicyUpdate):
    """Enable/disable continuous ASM and update the per-target policy (validated
    + clamped to safe bounds)."""
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow("SELECT asm_config FROM targets WHERE id = $1", uuid.UUID(target_id))
        if not row:
            raise HTTPException(status_code=404, detail="Target not found")
        current = _decode_asm_config(row["asm_config"])
        new_config = asm_inventory.merge_asm_config(
            {**current, **body.config} if isinstance(body.config, dict) else current
        )
        await conn.execute(
            """UPDATE targets
               SET asm_enabled = COALESCE($1, asm_enabled), asm_config = $2, updated_at = NOW()
               WHERE id = $3""",
            body.enabled, json.dumps(new_config), uuid.UUID(target_id),
        )
        out = await conn.fetchrow(
            "SELECT asm_enabled, asm_last_test_at, asm_last_recon_at FROM targets WHERE id = $1",
            uuid.UUID(target_id),
        )
    return {
        "enabled": bool(out["asm_enabled"]),
        "config": new_config,
        "last_test_at": out["asm_last_test_at"].isoformat() if out["asm_last_test_at"] else None,
        "last_recon_at": out["asm_last_recon_at"].isoformat() if out["asm_last_recon_at"] else None,
    }


@app.get("/targets/{target_id}/asm/diff")
async def asm_diff(
    target_id: str,
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(100, le=500),
):
    """New attack surface for a target: endpoints first seen within N days."""
    async with db_pool.acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        return await asm_inventory.new_surface(conn, target_id, days=days, limit=limit)


@app.get("/targets/{target_id}/asm/gaps")
async def asm_gaps(target_id: str):
    """Explain remaining ASM coverage gaps for UI and AI agents."""
    async with db_pool.acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        coverage = await asm_inventory.coverage_summary(conn, target_id)
        cfg_row = await conn.fetchrow("SELECT asm_config FROM targets WHERE id = $1", uuid.UUID(target_id))
        cfg = asm_inventory.merge_asm_config(_decode_asm_config(cfg_row["asm_config"] if cfg_row else {}))
        claimable = await asm_inventory.claimable_count(conn, target_id, stale_days=cfg["stale_days"])
        active = await _asm_active_scan_count(conn, target_id)
        by_auth_rows = await conn.fetch(
            """
            SELECT auth_state, test_status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY auth_state, test_status
            ORDER BY auth_state, test_status
            """,
            uuid.UUID(target_id),
        )
        by_location_rows = await conn.fetch(
            """
            SELECT COALESCE(param_location, 'none') AS param_location, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(param_location, 'none')
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        attempt_rows = await conn.fetch(
            """
            SELECT COALESCE(last_attempt_status, 'none') AS status, COUNT(*) AS count
            FROM target_endpoints WHERE target_id = $1
            GROUP BY COALESCE(last_attempt_status, 'none')
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        samples = await conn.fetch(
            """
            SELECT id, method, path, param_shape, param_location, auth_state, priority_score,
                   test_status, last_attempt_status, last_verdict, lease_owner,
                   lease_expires_at, attempt_count, last_seen_at, last_tested_at
            FROM target_endpoints
            WHERE target_id = $1
              AND (test_status IN ('untested', 'stale', 'in_progress')
                   OR last_attempt_status IN ('auth_missing', 'partial', 'partial_timeout', 'partial_findings'))
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT 25
            """,
            uuid.UUID(target_id),
        )
        ledger_rows = await conn.fetch(
            """
            SELECT status, COUNT(*) AS count
            FROM asm_endpoint_attempts
            WHERE endpoint_id IN (
                SELECT id FROM target_endpoints WHERE target_id = $1
            )
            GROUP BY status
            ORDER BY count DESC
            """,
            uuid.UUID(target_id),
        )
        # §7: family-level coverage — which vuln families have PROOF-quality attempts
        # (completed) vs only touched. "endpoint attempted" != "family proved".
        family_rows = await conn.fetch(
            """
            SELECT COALESCE(check_family, 'all') AS family,
                   COUNT(*) FILTER (WHERE status = 'completed') AS completed,
                   COUNT(*) AS attempts
            FROM asm_endpoint_attempts
            WHERE endpoint_id IN (SELECT id FROM target_endpoints WHERE target_id = $1)
            GROUP BY COALESCE(check_family, 'all')
            """,
            uuid.UUID(target_id),
        )

    attempt_counts = {str(r["status"]): int(r["count"] or 0) for r in attempt_rows}
    family_coverage = {
        str(r["family"]): {"completed": int(r["completed"] or 0), "attempts": int(r["attempts"] or 0)}
        for r in family_rows
    }
    recommendation = _asm_recommendation(
        coverage,
        claimable=claimable,
        active_scans=active,
        last_attempt_counts=attempt_counts,
    )
    recommended_campaigns = _asm_recommended_campaigns(
        coverage=coverage,
        family_coverage=family_coverage,
        by_auth=None,
        last_attempt_counts=attempt_counts,
        active_scans=active,
    )
    by_auth: dict[str, dict[str, int]] = {}
    for row in by_auth_rows:
        state = str(row["auth_state"] or "anonymous")
        by_auth.setdefault(state, {})[str(row["test_status"])] = int(row["count"] or 0)
    return {
        "coverage": coverage,
        "claimable": claimable,
        "active_scans": active,
        "recommendation": recommendation,
        "recommended_campaigns": recommended_campaigns,
        "by_auth_state": by_auth,
        "by_param_location": {str(r["param_location"]): int(r["count"] or 0) for r in by_location_rows},
        "family_coverage": family_coverage,
        "last_attempt_status": attempt_counts,
        "attempt_ledger_status": {str(r["status"]): int(r["count"] or 0) for r in ledger_rows},
        "sample_gaps": [row_to_dict(r) for r in samples],
    }


@app.get("/targets/{target_id}/asm/activity")
async def asm_activity(
    target_id: str,
    limit: int = Query(25, ge=1, le=100),
):
    """Recent ASM recon/test jobs for a target, grouped away from normal scan rows."""
    async with db_pool.acquire() as conn:
        if not await conn.fetchrow("SELECT 1 FROM targets WHERE id = $1", uuid.UUID(target_id)):
            raise HTTPException(status_code=404, detail="Target not found")
        rows = await conn.fetch(
            """
            SELECT s.id, s.job_id, s.scan_role, s.scan_type, s.status, s.current_phase, s.progress,
                   s.findings_count, s.score, s.grade, s.error_message,
                   s.created_at, s.started_at, s.completed_at, s.duration_seconds,
                   s.campaign_id, c.mode AS campaign_mode, c.requested_by AS campaign_requested_by,
                   c.status AS campaign_status, c.check_families AS campaign_check_families
            FROM scans s
            LEFT JOIN scan_campaigns c ON c.id = s.campaign_id
            WHERE s.target_id = $1 AND s.scan_role IN ($2, $3)
            ORDER BY s.created_at DESC
            LIMIT $4
            """,
            uuid.UUID(target_id), asm_inventory.ASM_BATCH_ROLE, asm_inventory.ASM_RECON_ROLE, limit,
        )
        campaign_ids = [r["campaign_id"] for r in rows if r["campaign_id"]]
        attempt_counts: dict[str, dict[str, int]] = {}
        if campaign_ids:
            attempts = await conn.fetch(
                """
                SELECT campaign_id, status, COUNT(*) AS count
                FROM asm_endpoint_attempts
                WHERE campaign_id = ANY($1::uuid[])
                GROUP BY campaign_id, status
                """,
                campaign_ids,
            )
            for attempt in attempts:
                cid = str(attempt["campaign_id"])
                attempt_counts.setdefault(cid, {})[str(attempt["status"])] = int(attempt["count"] or 0)
    activity = []
    for row in rows:
        item = row_to_dict(row)
        cid = str(row["campaign_id"]) if row["campaign_id"] else None
        item["attempt_status_counts"] = attempt_counts.get(cid, {}) if cid else {}
        activity.append(item)
    return {"activity": activity}


@app.post("/ai/ops/route")
async def ai_ops_route(request: AIOpsRouterRequest):
    """Map natural-language DAST/ASM operations to safe API calls.

    This is a deterministic router for agents, not a free-form LLM executor.
    Active/state-changing actions dry-run unless the caller explicitly requests
    execution, provides the required confirmations, and the server enables
    AI_OPS_ROUTER_EXECUTE_ENABLED.
    """
    plan = _build_ai_ops_router_plan(request)
    if plan["dry_run"]:
        return plan

    call = plan.get("planned_api_call") or {}
    method = call.get("method")
    path = str(call.get("path") or "")
    body = call.get("body") if isinstance(call.get("body"), dict) else {}
    executed: dict[str, Any]

    if plan["intent"] == "run_full_coverage" and method == "POST" and path == "/scans":
        result = await submit_scan(
            ScanRequest(
                target=body["target"],
                options=ScanOptions(**(body.get("options") or {})),
            )
        )
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else None,
            "result": result,
        }
    elif plan["intent"] == "enable_continuous_asm" and method == "PUT" and request.target_id:
        result = await asm_set_policy(request.target_id, AsmPolicyUpdate(**body))
        executed = {
            "target_id": request.target_id,
            "status": "updated",
            "ui_link": f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif plan["intent"] == "explain_asm_gaps" and method == "GET" and request.target_id:
        result = await asm_gaps(request.target_id)
        executed = {
            "target_id": request.target_id,
            "status": "read",
            "ui_link": f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif plan["intent"] == "increase_api_endpoint_budget" and method == "POST" and request.target_id:
        result = await asm_improve(request.target_id, AsmImproveRequest(**body))
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "campaign_id": result.get("campaign_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else f"/asm?target_id={request.target_id}",
            "result": result,
        }
    elif str(plan["intent"]).startswith("focused_asm_") and method == "POST" and request.target_id:
        result = await asm_improve(request.target_id, AsmImproveRequest(**body))
        executed = {
            "scan_id": result.get("scan_id"),
            "job_id": result.get("job_id"),
            "campaign_id": result.get("campaign_id"),
            "status": result.get("status"),
            "ui_link": f"/scans/{result.get('scan_id')}" if result.get("scan_id") else f"/asm?target_id={request.target_id}",
            "result": result,
        }
    else:
        raise HTTPException(status_code=400, detail="Unsupported planned API call")

    plan["dry_run"] = False
    plan["executed"] = executed
    return plan


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
    campaign_id = None
    if finding.get("target_id"):
        try:
            campaign_id = await asm_inventory.create_campaign(
                conn,
                str(finding["target_id"]),
                mode=asm_inventory.CAMPAIGN_FINDING_RETEST,
                requested_by=requested_by or "api",
                priority=90,
                check_families=[str(inputs.get("finding_type") or "generic_http")],
                metadata_json={
                    "finding_id": str(finding["id"]),
                    "source_scan_id": str(finding.get("scan_id") or ""),
                    "target_url": str(inputs.get("target_url") or ""),
                    "original_url": str(inputs.get("original_url") or ""),
                    "method": str(inputs.get("method") or ""),
                    "param": str(inputs.get("param") or ""),
                },
            )
        except Exception:
            campaign_id = None

    await conn.execute("""
        INSERT INTO finding_verifications (
            id, finding_id, scan_id, target_id, job_id, requested_by, status,
            finding_type, target_url, original_url, param, payload, method, request_body,
            replay_commands, auth_context, campaign_id
        ) VALUES (
            $1, $2, $3, $4, $5, $6, 'queued',
            $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
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
        uuid.UUID(str(campaign_id)) if campaign_id else None,
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
    request: Request,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = Query(None, regex="^(dast|ai|model_intake)$"),
    target_id: Optional[str] = None,
    ai_target_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    root_domain: Optional[str] = None,
    verification_verdict: Optional[str] = Query(None, regex="^(exploited|likely_vulnerable|blocked_by_security|out_of_scope_internal|false_positive|likely_fixed|inconclusive|error)$"),
    verification_mode: Optional[str] = Query(None, regex="^(deterministic|ai_driven)$"),
    verified_only: bool = False,
    search: Optional[str] = None,
    seen_within_days: Optional[int] = Query(None, ge=1),
    first_seen_within_days: Optional[int] = Query(None, ge=1),
    resolved_within_days: Optional[int] = Query(None, ge=1),
    sort_by: Optional[str] = Query(None, regex="^(severity|first_seen|last_seen|cvss)$"),
    sort_order: Optional[str] = Query("desc", regex="^(asc|desc)$"),
    limit: int = Query(100, le=500),
    offset: int = 0
):
    """List findings with filtering and sorting.

    The COUNT(*) OVER() window emits the unbounded row total alongside each
    paginated row, so we only execute the (expensive, ILIKE-heavy) query
    once instead of twice.
    """
    # Reject unknown query parameters instead of silently ignoring them. A typo'd
    # filter (e.g. ?domain= instead of ?root_domain=) would otherwise return the
    # full, unfiltered result set with no indication the filter did nothing.
    allowed_params = {
        "severity", "status", "source_type", "target_id", "ai_target_id",
        "scan_id", "root_domain", "verification_verdict", "verification_mode",
        "verified_only", "search", "seen_within_days", "first_seen_within_days",
        "resolved_within_days", "sort_by", "sort_order",
        "limit", "offset",
    }
    unknown_params = sorted({k for k in request.query_params if k not in allowed_params})
    if unknown_params:
        hint = ""
        if any(p in ("domain", "last_seen") for p in unknown_params):
            hint = " (did you mean 'root_domain' / 'seen_within_days'?)"
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unknown query parameter(s): {', '.join(unknown_params)}{hint}. "
                f"Allowed: {', '.join(sorted(allowed_params))}"
            ),
        )

    async with db_pool.acquire() as conn:
        query = """
            SELECT f.*,
                   COALESCE(t.url, ait.endpoint_url) as target_url,
                   COALESCE(t.name, ait.name) as target_name,
                   t.root_domain,
                   ait.endpoint_url as ai_target_url,
                   ait.name as ai_target_name,
                   COUNT(*) OVER() AS total_count
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            LEFT JOIN ai_targets ait ON f.ai_target_id = ait.id
            WHERE 1=1
        """
        params: list = []
        param_idx = 1

        if severity:
            query += f" AND f.severity = ${param_idx}"
            params.append(severity)
            param_idx += 1

        if status:
            query += f" AND f.status = ${param_idx}"
            params.append(status)
            param_idx += 1

        if source_type == "ai":
            query += " AND (f.source IN ('ai_gate', 'ai_session') OR f.ai_target_id IS NOT NULL)"
        elif source_type == "model_intake":
            query += " AND (f.source = 'model_intake' OR f.tool = 'model_intake')"
        elif source_type == "dast":
            query += " AND COALESCE(f.source, 'scan') NOT IN ('ai_gate', 'ai_session', 'model_intake') AND f.ai_target_id IS NULL AND COALESCE(f.tool, '') <> 'model_intake'"

        if target_id:
            query += f" AND f.target_id = ${param_idx}"
            params.append(uuid.UUID(target_id))
            param_idx += 1

        if ai_target_id:
            query += f" AND f.ai_target_id = ${param_idx}"
            params.append(uuid.UUID(ai_target_id))
            param_idx += 1

        if scan_id:
            query += f" AND f.scan_id = ${param_idx}"
            params.append(uuid.UUID(scan_id))
            param_idx += 1

        if root_domain:
            query += f""" AND (
                t.root_domain = ${param_idx}
                OR LOWER(ait.endpoint_url) LIKE '%' || LOWER(${param_idx}) || '%'
            )"""
            params.append(root_domain)
            param_idx += 1

        if verification_verdict:
            query += f" AND f.last_verification_verdict = ${param_idx}"
            params.append(verification_verdict)
            param_idx += 1

        if verified_only:
            query += " AND f.last_verification_verdict = 'exploited'"

        if verification_mode:
            query += f""" AND EXISTS (
                SELECT 1 FROM finding_verifications fv2
                WHERE fv2.finding_id = f.id AND fv2.verification_mode = ${param_idx}
            )"""
            params.append(verification_mode)
            param_idx += 1

        if search:
            search_pattern = f"%{search}%"
            query += f""" AND (
                f.title ILIKE ${param_idx}
                OR f.url ILIKE ${param_idx}
                OR t.url ILIKE ${param_idx}
                OR ait.endpoint_url ILIKE ${param_idx}
                OR ait.name ILIKE ${param_idx}
            )"""
            params.append(search_pattern)
            param_idx += 1

        if seen_within_days:
            query += f" AND f.last_seen_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(seen_within_days)
            param_idx += 1

        if first_seen_within_days:
            query += f" AND f.first_seen_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(first_seen_within_days)
            param_idx += 1

        if resolved_within_days:
            query += f" AND f.resolved_at >= NOW() - INTERVAL '1 day' * ${param_idx}"
            params.append(resolved_within_days)
            param_idx += 1

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

        # `total_count` is identical on every row of the window. The empty
        # result set is ambiguous (truly no matches vs offset past end), so
        # only trust the window count when we got rows back. With offset > 0
        # and no rows we fall back to a dedicated COUNT(*) query so the UI
        # paginator can render correctly.
        if rows:
            total = rows[0]["total_count"]
        elif offset > 0:
            # Strip the window column from the SELECT, drop LIMIT/OFFSET
            # parameters, and wrap as COUNT(*).
            count_sql, count_args = _strip_pagination_for_count(query, params)
            total = await conn.fetchval(count_sql, *count_args) or 0
        else:
            total = 0

    findings_out = []
    for row in rows:
        row_dict = dict(row)
        row_dict.pop("total_count", None)
        findings_out.append(row_dict)

    return {
        'findings': findings_out,
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

    result = dict(finding)

    # Retest capability hints so the UI can gate the retest button instead of
    # surfacing a 400 after the click.
    if result.get("source") == "ai_gate" or result.get("ai_target_id"):
        result["retest_supported"] = True
        result["retest_type"] = None
        result["retest_modes"] = ["same_probe", "same_family", "strict_replay"]
    else:
        evidence = parse_json_field(result.get("evidence"))
        retest_type = infer_retest_type(result, evidence)
        tool = str(result.get("tool") or "").lower()
        if retest_type:
            result["retest_supported"] = True
            result["retest_type"] = retest_type
            result["retest_modes"] = (
                ["tiered", "ai"] if retest_type in AI_ONLY_RETEST_TYPES
                else ["tiered", "deterministic", "ai"]
            )
        elif tool == "model_intake":
            result["retest_supported"] = False
            result["retest_type"] = None
            result["retest_modes"] = []
            result["retest_unsupported_reason"] = "model_intake"
        else:
            ai_settings = _load_effective_ai_settings()
            ai_ready = bool(
                ai_settings.get("ai_verify_enabled")
                and (ai_settings.get("ai_verify_url") or ai_settings.get("ai_url"))
                and (ai_settings.get("ai_verify_api_key") or ai_settings.get("ai_api_key"))
            )
            if ai_ready:
                result["retest_supported"] = True
                result["retest_type"] = "generic_http"
                result["retest_modes"] = ["ai"]
            else:
                result["retest_supported"] = False
                result["retest_type"] = None
                result["retest_modes"] = []
                result["retest_unsupported_reason"] = "no_deterministic_prover_and_ai_verification_disabled"

    return result


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
            tool = str(finding_data.get("tool") or "").lower()
            if tool == "model_intake":
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "unsupported_finding_type",
                        "message": "Model Intake findings cannot be retested via HTTP replay; re-run the Model Intake scan for this artifact instead.",
                    },
                )

            # No deterministic prover for this finding. Fall back to the AI
            # verification tier (generic_http) when an AI verifier is configured.
            ai_settings = _load_effective_ai_settings()
            ai_ready = bool(
                ai_settings.get("ai_verify_enabled")
                and (ai_settings.get("ai_verify_url") or ai_settings.get("ai_url"))
                and (ai_settings.get("ai_verify_api_key") or ai_settings.get("ai_api_key"))
            )
            if not ai_ready:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "unsupported_finding_type",
                        "message": (
                            "Could not infer a deterministic retest type from this finding, "
                            "and AI verification is not configured. Enable AI verification in "
                            "AI settings to retest this finding type."
                        ),
                        "supported_types": list(SUPPORTED_RETEST_TYPES),
                    },
                )
            if mode == "deterministic":
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "no_deterministic_prover",
                        "message": "This finding has no deterministic prover; retest it in tiered or AI mode.",
                    },
                )
            retest_inputs["finding_type"] = "generic_http"
            # Force the AI tier so an explicit user retest is not silently
            # skipped by the severity-based AI escalation gate.
            mode = "ai"

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
        submitted_at=utc_now_iso(),
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


@app.post("/ai/findings/{finding_id:path}/retest")
async def retest_ai_finding(finding_id: str, request: AIFindingRetestRequest | None = None):
    """Queue a focused AI Gate replay for one AI Gate finding."""
    request = request or AIFindingRetestRequest()
    r = get_redis()
    try:
        r.ping()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    scan_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    verification_id = uuid.uuid4()

    async with db_pool.acquire() as conn:
        finding = await get_finding_record(conn, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        finding_data = dict(finding)
        if not (finding_data.get("source") == "ai_gate" or finding_data.get("ai_target_id")):
            raise HTTPException(status_code=400, detail="Finding is not an AI Gate finding")
        if not finding_data.get("ai_target_id"):
            raise HTTPException(status_code=400, detail="AI Gate finding is missing ai_target_id")

        target_row = await conn.fetchrow(
            "SELECT * FROM ai_targets WHERE id = $1",
            finding_data["ai_target_id"],
        )
        if not target_row:
            raise HTTPException(status_code=404, detail="AI target not found")
        if not target_row["is_active"]:
            raise HTTPException(status_code=409, detail="AI target is inactive")
        credential_row = await conn.fetchrow(
            "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
            finding_data["ai_target_id"],
        )
        principal_rows = await conn.fetch(
            """
            SELECT * FROM ai_target_principals
            WHERE ai_target_id = $1 AND is_active = true
            ORDER BY role, label
            """,
            finding_data["ai_target_id"],
        )
        original_scan = None
        if finding_data.get("scan_id"):
            original_scan = await conn.fetchrow(
                "SELECT options FROM scans WHERE id = $1",
                finding_data["scan_id"],
            )

        target = row_to_dict(target_row)
        for key in ("headers_template", "request_template", "metadata_json"):
            target[key] = _decode_json_value(target.get(key)) or {}
        credential = _runtime_credential_from_row(dict(credential_row) if credential_row else None)
        original_options = _ai_scan_options_from_row(original_scan)
        worker_options, storage_options, replay_plan = _build_ai_finding_retest_scan_options(
            target=target,
            credential=credential,
            finding=finding_data,
            original_scan_options=original_options,
            request=request,
            verification_id=verification_id,
            principals=list(principal_rows),
        )

        production_scan = bool(target.get("production_mode")) or storage_options.get("ai_environment") == "production"
        confirmed = bool((storage_options.get("production_confirmation") or {}).get("confirmed"))
        if production_scan and not confirmed:
            raise HTTPException(
                status_code=409,
                detail="Focused AI Gate replay targets production. Re-submit with confirm_production=true.",
            )

        run_kind = storage_options["run_kind"]
        await conn.execute("""
            INSERT INTO scans (
                id, target_id, ai_target_id, target_url, job_id, status,
                options, scan_type, run_kind, subject_ref
            ) VALUES ($1, NULL, $2, $3, $4, 'pending', $5, 'ai_gate', $6, $7)
        """,
            uuid.UUID(scan_id),
            finding_data["ai_target_id"],
            target["endpoint_url"],
            job_id,
            json.dumps(storage_options),
            run_kind,
            f"ai_finding_retest:{finding_data['id']}",
        )
        await conn.execute("""
            INSERT INTO finding_verifications (
                id, finding_id, scan_id, target_id, job_id, requested_by, status,
                finding_type, target_url, original_url, replay_commands,
                verification_mode, ai_plan, message
            ) VALUES (
                $1, $2, $3, NULL, $4, $5, 'queued',
                'ai_gate', $6, $7, $8,
                'ai_driven', $9, $10
            )
        """,
            verification_id,
            finding_data["id"],
            uuid.UUID(scan_id),
            job_id,
            request.requested_by or "api",
            target["endpoint_url"],
            finding_data.get("url"),
            json.dumps([{
                "description": "Focused AI Gate replay",
                "scan_id": scan_id,
                **replay_plan,
            }]),
            json.dumps(replay_plan),
            "Queued focused AI Gate replay",
        )
        await conn.execute("""
            UPDATE findings
            SET last_verification_status = 'queued',
                last_verification_verdict = NULL,
                updated_at = NOW()
            WHERE id = $1
        """, finding_data["id"])

    job_data = {
        "job_id": job_id,
        "scan_id": scan_id,
        "target": target["endpoint_url"],
        "options": worker_options,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        r.rpush(QUEUE_NAME, json.dumps(job_data))
        r.hset(
            f"job:{job_id}",
            mapping={
                "status": "queued",
                "target": target["endpoint_url"],
                "scan_id": scan_id,
                "verification_id": str(verification_id),
                "finding_id": str(finding_data["id"]),
            },
        )
        r.expire(f"job:{job_id}", 86400)
    except Exception as e:
        async with db_pool.acquire() as conn:
            await mark_retest_enqueue_failed(
                conn,
                verification_id=verification_id,
                finding_id=finding_data["id"],
                error_message=f"AI Gate replay queue enqueue failed: {type(e).__name__}: {e}",
            )
        raise HTTPException(status_code=503, detail=f"AI Gate scan queue unavailable: {e}")

    return {
        "retest_id": str(verification_id),
        "job_id": job_id,
        "scan_id": scan_id,
        "status": "queued",
        "mode": request.mode,
        "finding_id": str(finding_data["id"]),
        "finding_type": "ai_gate",
        "target_url": target["endpoint_url"],
        "probe_id": replay_plan.get("probe_id"),
        "probe_family": replay_plan.get("probe_family"),
        "ui_url": f"/scans/{scan_id}",
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
                submitted_at=utc_now_iso(),
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
                    resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                       WHEN $1 = 'active' THEN NULL
                                       ELSE resolved_at END,
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
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
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
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
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
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
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
                        resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                           WHEN $1 = 'active' THEN NULL
                                           ELSE resolved_at END,
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
            SET status = $1,
                resolved_at = CASE WHEN $1 = 'resolved' THEN COALESCE(resolved_at, NOW())
                                   WHEN $1 = 'active' THEN NULL
                                   ELSE resolved_at END,
                notes = COALESCE($2, notes),
                updated_at = NOW()
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
                INSERT INTO targets (url, name, root_domain, discovery_source, asm_enabled, asm_config)
                VALUES ($1, $2, $3, 'manual', $4, $5)
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname,
                 _default_asm_enabled_for_new_web_target("manual"),
                 json.dumps(_default_asm_config_for_new_web_target("manual")))

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

        # Build evidence JSON if provided. Redact live auth material (bearer
        # tokens, JWTs, auth headers/cookies) the same way scanner findings are
        # sanitised in save_findings_from_partial — manual/session evidence
        # captured during interactive testing routinely carries live credentials
        # we must never persist (they leak via the API/UI and outlive the
        # engagement).
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation
            evidence_json = _redact_finding_evidence(evidence_json)
        redacted_request = _redact_finding_evidence(request.request)
        redacted_response = _redact_finding_evidence(request.response)

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
            redacted_request,
            redacted_response,
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
        'submitted_at': utc_now_iso()
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

# Fleet container ceiling the /workers scaler allows. Default is derived from
# Docker RAM (~1.2GB budgeted per worker) so a bigger Docker allocation auto-raises
# the cap instead of a hardcoded number; an explicit SHAKERSCAN_MAX_WORKERS env
# always overrides. Hard sanity bound: 200.
def _compute_max_allowed_workers() -> int:
    env_override = os.environ.get("SHAKERSCAN_MAX_WORKERS")
    if env_override:
        try:
            return max(1, min(200, int(env_override)))
        except (TypeError, ValueError):
            pass
    try:
        status, info = docker_socket_request("GET", "/info")
        mem_gb = (info.get("MemTotal") or 0) / 1024 ** 3 if (status == 200 and isinstance(info, dict)) else 0
    except Exception:
        mem_gb = 0
    try:
        per_worker_gb = float(os.environ.get("SHAKERSCAN_PER_WORKER_MEM_GB") or 1.2)
    except (TypeError, ValueError):
        per_worker_gb = 1.2
    try:
        fraction = float(os.environ.get("SHAKERSCAN_SCAN_MEM_FRACTION") or 0.85)
    except (TypeError, ValueError):
        fraction = 0.85
    if mem_gb <= 0 or per_worker_gb <= 0:
        return 30
    return max(2, min(200, int((mem_gb * fraction) / per_worker_gb)))

# Hard per-worker memory cap applied to scaler-created worker containers. Without
# it, a runaway/large scan can exhaust the whole Docker VM and OOM-thrash every
# container; with it, a single worker is OOM-killed in isolation and its job is
# requeued by the stale-scan checker. 0 disables the cap. (compose `deploy.resources`
# is ignored outside Swarm, so we set HostConfig.Memory explicitly here.)
try:
    WORKER_MEM_LIMIT_BYTES = int(float(os.environ.get("SHAKERSCAN_WORKER_MEM_LIMIT_GB") or 4) * (1024 ** 3))
except (TypeError, ValueError):
    WORKER_MEM_LIMIT_BYTES = 4 * (1024 ** 3)


def _worker_hostconfig(network: str, binds: list) -> dict:
    """HostConfig for a scaler-created worker, incl. the hard memory cap."""
    hc = {
        "NetworkMode": network,
        "RestartPolicy": {"Name": "unless-stopped"},
        "Binds": binds,
    }
    if WORKER_MEM_LIMIT_BYTES > 0:
        hc["Memory"] = WORKER_MEM_LIMIT_BYTES
        # MemorySwap == Memory disables swap for the container (no swap thrash);
        # the worker is OOM-killed cleanly at the limit instead.
        hc["MemorySwap"] = WORKER_MEM_LIMIT_BYTES
    return hc


def _compute_max_active_scans(max_allowed: int | None = None) -> int:
    """Max concurrent ACTIVE scans across the fleet (workers enforce it via a Redis
    semaphore). Memory safety primarily comes from the RAM-derived fleet cap
    (_compute_max_allowed_workers, ~1.2GB/worker) plus the per-worker hard memory
    cap (each worker is OOM-isolated and its job requeued). With no explicit
    override this defaults to the full RAM-derived fleet capacity so a busy fleet —
    and single large Full Coverage parents — can actually use every worker instead
    of leaving most idle behind a flat cap. Set SHAKERSCAN_MAX_ACTIVE_SCANS to pin
    a lower burst ceiling; it is always clamped to the RAM-derived fleet cap."""
    if max_allowed is None:
        max_allowed = _compute_max_allowed_workers()
    env_override = os.environ.get("SHAKERSCAN_MAX_ACTIVE_SCANS")
    if env_override:
        try:
            n = max(1, int(env_override))
        except (TypeError, ValueError):
            n = max_allowed
    else:
        n = max_allowed
    return max(1, min(n, max_allowed))


def _publish_max_active_scans(max_allowed: int | None = None) -> int:
    """Compute + publish the active-scan concurrency cap to Redis for workers."""
    n = _compute_max_active_scans(max_allowed)
    try:
        get_redis().set("shakerscan:max_active_scans", n, ex=120)
    except Exception:
        pass
    return n


class WorkerScaleRequest(BaseModel):
    # Hard ceiling here is just a sanity bound; the effective cap is
    # _compute_max_allowed_workers() (RAM-derived, or SHAKERSCAN_MAX_WORKERS),
    # enforced in scale_workers.
    count: int = Field(..., ge=1, le=200, description="Number of worker containers")


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


def _is_scan_worker_container_name(name: str) -> bool:
    normalized = str(name or "").lstrip("/").lower()
    return "shakerscan" in normalized and "worker" in normalized and "gungnir" not in normalized


def _running_scan_worker_count_best_effort() -> int | None:
    """Return running scanner worker count, or None when Docker is unavailable.

    Auto-sharding should use real fleet capacity when the standard Docker
    deployment exposes it, but should not fail API requests in environments
    without a mounted Docker socket.
    """
    try:
        filters = urllib.parse.quote('{"name":["worker"]}')
        status_code, containers = docker_socket_request(
            "GET",
            f"/containers/json?all=true&filters={filters}",
        )
        if status_code != 200 or not isinstance(containers, list):
            return None
        count = 0
        for container in containers:
            names = container.get("Names", [])
            name = names[0].lstrip("/") if names else ""
            if _is_scan_worker_container_name(name) and container.get("State") == "running":
                count += 1
        return count
    except Exception:
        return None


@app.get("/system/resources")
async def get_system_resources():
    """CPU/RAM the Docker engine can give containers (i.e. the worker fleet).

    IMPORTANT platform nuance: on macOS/Windows Docker runs inside a Linux VM
    (Docker Desktop), so these numbers are the **VM allocation you set in Docker
    Desktop**, not the physical machine. On native Linux they are the real host.
    Either way this is the correct capacity ceiling for workers — read it from the
    Docker engine (/info), never from os/psutil inside the API container (that
    reports the cgroup/VM view and is misleading)."""
    try:
        status_code, info = docker_socket_request("GET", "/info")
        if status_code != 200 or not isinstance(info, dict):
            return {"available": False, "error": f"docker /info status {status_code}"}
        os_name = str(info.get("OperatingSystem") or "")
        return {
            "available": True,
            "cpus": info.get("NCPU"),
            "mem_total_bytes": info.get("MemTotal"),
            "operating_system": os_name,
            "os_type": info.get("OSType"),
            "server_version": info.get("ServerVersion"),
            # Docker Desktop (mac/win) reports a tunable VM allocation, not host HW.
            "is_desktop_vm": "desktop" in os_name.lower(),
        }
    except Exception as e:  # pragma: no cover - docker socket optional
        return {"available": False, "error": str(e)}


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

        # Per-worker build identity: workers self-register their source fingerprint
        # in Redis (keyed by container hostname == short container id) on startup.
        # Match it here so the UI can show current/stale per worker WITHOUT shelling
        # into containers.
        expected_fp = expected_build_fingerprint()
        expected_version = current_scanner_version()
        try:
            worker_build_raw = get_redis().hgetall("shakerscan:worker_build") or {}
        except Exception:
            worker_build_raw = {}
        worker_build: dict = {}
        for host, raw in worker_build_raw.items():
            host_s = host.decode() if isinstance(host, bytes) else str(host)
            raw_s = raw.decode() if isinstance(raw, bytes) else raw
            try:
                worker_build[host_s.lower()] = json.loads(raw_s)
            except Exception:
                continue

        def _build_for_container(container_id: str):
            cid = (container_id or "").lower()
            for host_s, info in worker_build.items():
                if host_s and cid.startswith(host_s):
                    return info
            return None

        # Filter and format worker containers (only shakerscan workers)
        worker_list = []
        for c in containers:
            names = c.get('Names', [])
            name = names[0].lstrip('/') if names else 'unknown'
            if _is_scan_worker_container_name(name):
                state = c.get('State', 'unknown')
                wb = _build_for_container(c.get('Id', '')) or {}
                reported_fp = wb.get('build_fingerprint')
                reported_version = wb.get('scanner_version')
                worker_list.append({
                    "name": name,
                    "status": state,
                    "health": c.get('Status', ''),
                    "build_fingerprint": reported_fp,
                    "scanner_version": reported_version,
                    # True/False when the worker reported a fingerprint; null until it
                    # has registered (e.g. just started, or not yet picked up a job).
                    "build_current": worker_build_current(
                        reported_fingerprint=reported_fp,
                        reported_version=reported_version,
                        expected_fingerprint=expected_fp,
                        expected_version=expected_version,
                    ),
                })

        running = len([w for w in worker_list if w.get("status") == "running"])
        stale_workers = [w["name"] for w in worker_list if w.get("build_current") is False]
        max_allowed_workers = _compute_max_allowed_workers()
        # Refresh the per-scan active-scan concurrency cap for workers.
        max_active_scans = _publish_max_active_scans(max_allowed=max_allowed_workers)
        # Refresh the real build label so workers stamp/report the deployed commit.
        _publish_scanner_version()

        return {
            "count": running,
            "workers": worker_list,
            "max_allowed": max_allowed_workers,
            "max_active_scans": max_active_scans,
            "expected_build_fingerprint": expected_fp,
            "expected_scanner_version": expected_version,
            "stale_workers": stale_workers,
        }
    except FileNotFoundError:
        return {
            "count": -1,
            "error": "Docker socket not available",
            "workers": [],
            "max_allowed": _compute_max_allowed_workers(),
            "max_active_scans": _compute_max_active_scans(),
        }
    except Exception as e:
        return {
            "count": -1,
            "error": f"Failed to query Docker: {str(e)}",
            "workers": [],
            "max_allowed": _compute_max_allowed_workers(),
            "max_active_scans": _compute_max_active_scans(),
        }


@app.post("/workers")
async def scale_workers(request: WorkerScaleRequest):
    """Scale the number of worker containers using Docker socket API."""
    import urllib.parse

    try:
        count = request.count
        _max_allowed = _compute_max_allowed_workers()
        if count < 1 or count > _max_allowed:
            raise HTTPException(400, f"Workers must be between 1 and {_max_allowed}")

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
            if _is_scan_worker_container_name(name):
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
            # Remove non-running worker containers (stopped, crash-looping, or left
            # over from a prior scale-down) instead of restarting them. Restarting a
            # stopped container brings back its OUTDATED baked image, which then
            # crashes against the bind-mounted current code (the version-skew bug).
            # We always (re)create the shortfall from the running fleet's current
            # image so the whole fleet stays on one code version.
            for container in stopped:
                cid = container.get('Id')
                if cid:
                    docker_socket_request("DELETE", f"/containers/{cid}?force=true")

            started = 0  # stale stopped containers are recreated, never restarted
            new_count = current_count

            needed = count - new_count
            if needed > 0:
                # Infer image/project/network from a RUNNING worker (freshest image),
                # never a stopped/stale one. If nothing is running we have no trusted
                # current-image reference to clone from -- cloning a stopped/stale
                # worker would reintroduce the version-skew bug -- so refuse and let
                # the compose stack (which always uses the current image) start them.
                ref_pool = running
                if not ref_pool:
                    raise HTTPException(
                        status_code=409,
                        detail=(
                            "No running worker to clone the current image from. "
                            "Start the stack first (./scanner.sh start, or "
                            "docker compose up -d --scale worker=N) so new workers "
                            "use the current code instead of a stale baked image."
                        ),
                    )
                project, network, image = get_compose_context(ref_pool)
                if project and network and image:
                    # Find the highest worker number (among the surviving running fleet)
                    existing_numbers = []
                    for w in ref_pool:
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

                    if ref_pool:
                        # Inspect a running worker to copy its env + bind mounts.
                        ref_worker = ref_pool[0]
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
                            "HostConfig": _worker_hostconfig(network, existing_binds),
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
            # Scale down - REMOVE excess workers (not just stop them). A merely
            # stopped worker lingers and gets restarted on the next scale-up running
            # a stale baked image; removing forces a fresh create from the current
            # image next time, keeping the fleet on one code version.
            to_remove = running[count:]
            removed_count = 0
            for container in to_remove:
                container_id = container.get('Id')
                rm_status, _ = docker_socket_request("DELETE", f"/containers/{container_id}?force=true")
                if rm_status in [204, 200]:
                    removed_count += 1

            return {
                "status": "success",
                "target_count": count,
                "message": f"Scaled down to {count} worker(s) (removed {removed_count})"
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
                INSERT INTO targets (url, name, root_domain, discovery_source, asm_enabled, asm_config)
                VALUES ($1, $2, $3, 'ai_session', $4, $5)
                RETURNING id
            """, normalized_target, parsed.hostname, parsed.hostname,
                 _default_asm_enabled_for_new_web_target("ai_session"),
                 json.dumps(_default_asm_config_for_new_web_target("ai_session")))

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

        # Build evidence JSON if provided. Redact live auth material (bearer
        # tokens, JWTs, auth headers/cookies) the same way scanner findings are
        # sanitised in save_findings_from_partial — manual/session evidence
        # captured during interactive testing routinely carries live credentials
        # we must never persist (they leak via the API/UI and outlive the
        # engagement).
        evidence_json = None
        if request.evidence or request.remediation:
            evidence_json = {}
            if request.evidence:
                evidence_json['proof'] = request.evidence
            if request.remediation:
                evidence_json['remediation'] = request.remediation
            evidence_json = _redact_finding_evidence(evidence_json)
        redacted_request = _redact_finding_evidence(request.request)
        redacted_response = _redact_finding_evidence(request.response)

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
            redacted_request,
            redacted_response,
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
    now = utc_now()

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
