#!/usr/bin/env python3
"""
ShakerScan Worker - Open Source Edition
Redis-based job worker with PostgreSQL persistence.
"""

import asyncio
import copy
import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import asyncpg
import redis

from retest_contract import (
    AI_ONLY_RETEST_TYPES,
    DEFAULT_REPLAY_PAYLOADS,
    SUPPORTED_RETEST_TYPES,
    VerificationPolicy,
    auth_context_to_headers,
    build_replay_commands,
    build_retest_job_payload,
    classify_retry,
    extract_auth_context,
    get_attempt_ladder,
    infer_retest_inputs,
    normalize_retest_type,
    parse_json_field,
    run_schema_migrations,
    validate_retest_job_payload,
)
import parallel_scan
import asm_inventory

try:
    from constants import resolve_scan_budget
except ImportError:
    from scanner.constants import resolve_scan_budget

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")
AI_GATE_RUN_KINDS = {"ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget"}
MODEL_INTAKE_RUN_KINDS = {"model_intake"}
SCANNER_PATH = '/app/scanner.py'
SCAN_LOG_TAIL = int(os.environ.get('SCAN_LOG_TAIL', '200'))
SCAN_LOG_TTL_SECONDS = int(os.environ.get('SCAN_LOG_TTL_SECONDS', '86400'))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('HEARTBEAT_INTERVAL_SECONDS', '30'))

# Maximum allowed duration per scan type (minutes) - worker-side safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 600,        # 10 hours
    'aggressive': 600,  # 10 hours
    'smart': 360,
}
VALID_DAST_SCAN_TYPES = {"quick", "standard", "deep", "full", "aggressive", "smart"}
ACTIVE_ENFORCED_SCAN_TYPES = {"smart", "full", "aggressive"}


def utc_now() -> datetime:
    """Return UTC as a naive datetime to match existing DB timestamp columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    return utc_now().isoformat()


DEFAULT_MAX_DURATION_MINUTES = int(os.environ.get('SCAN_MAX_DURATION_DEFAULT_MINUTES', '120'))
SCAN_KILL_GRACE_SECONDS = int(os.environ.get('SCAN_KILL_GRACE_SECONDS', '10'))
SCAN_CANCEL_POLL_SECONDS = max(0.5, float(os.environ.get('SCAN_CANCEL_POLL_SECONDS', '2')))
SCAN_COOPERATIVE_CANCEL_GRACE_SECONDS = max(
    0.0,
    float(os.environ.get('SCAN_COOPERATIVE_CANCEL_GRACE_SECONDS', '2')),
)
RETEST_MAX_PARALLEL = max(1, int(os.environ.get("RETEST_MAX_PARALLEL", "2")))
RETEST_SLOT_KEY = os.environ.get("RETEST_SLOT_KEY", "retest:active_workers")
RETEST_SLOT_TTL_SECONDS = int(os.environ.get("RETEST_SLOT_TTL_SECONDS", "120"))
RETEST_REQUEUE_DELAY_SECONDS = int(os.environ.get("RETEST_REQUEUE_DELAY_SECONDS", "2"))
RETEST_QUEUE_MAX_RETRIES = max(1, int(os.environ.get("RETEST_QUEUE_MAX_RETRIES", "5")))
# Maximum wall-clock time to wait for a retest slot before marking verification failed.
RETEST_SLOT_WAIT_MAX_SECONDS = max(30, int(os.environ.get("RETEST_SLOT_WAIT_MAX_SECONDS", "900")))
# Maximum time budget for one AI verifier attempt per retest job. The AI
# verifier runs an agentic plan->execute->classify loop (60s per LLM call plus
# HTTP steps), so 120s was frequently too tight and the whole verification was
# discarded as a timeout instead of reaching a verdict. 240s gives it room.
RETEST_AI_BUDGET_SECONDS = max(15, int(os.environ.get("RETEST_AI_BUDGET_SECONDS", "240")))
# AI verification circuit breaker controls for transient upstream/provider failures.
RETEST_AI_CIRCUIT_KEY = os.environ.get("RETEST_AI_CIRCUIT_KEY", "retest:ai:circuit")
RETEST_AI_CIRCUIT_WINDOW_SECONDS = max(30, int(os.environ.get("RETEST_AI_CIRCUIT_WINDOW_SECONDS", "300")))
RETEST_AI_CIRCUIT_ERROR_THRESHOLD = max(1, int(os.environ.get("RETEST_AI_CIRCUIT_ERROR_THRESHOLD", "5")))
RETEST_AI_CIRCUIT_COOLDOWN_SECONDS = max(30, int(os.environ.get("RETEST_AI_CIRCUIT_COOLDOWN_SECONDS", "180")))
# Watchdog for stale retests stuck in running status.
RETEST_STALE_CHECK_INTERVAL_SECONDS = max(10, int(os.environ.get("RETEST_STALE_CHECK_INTERVAL_SECONDS", "30")))
RETEST_RUNNING_STALE_SECONDS = max(30, int(os.environ.get("RETEST_RUNNING_STALE_SECONDS", "600")))
RETEST_STALE_BATCH_SIZE = max(1, int(os.environ.get("RETEST_STALE_BATCH_SIZE", "25")))
RETEST_STALE_REQUEUE_LIMIT = max(0, int(os.environ.get("RETEST_STALE_REQUEUE_LIMIT", "1")))
RETEST_WATCHDOG_LOCK_KEY = os.environ.get("RETEST_WATCHDOG_LOCK_KEY", "retest:watchdog:lock")
RETEST_WATCHDOG_LOCK_SECONDS = max(10, int(os.environ.get("RETEST_WATCHDOG_LOCK_SECONDS", "30")))
AI_SETTINGS_KEY = os.environ.get("AI_SETTINGS_KEY", "settings:ai")
PARALLEL_SHARD_MAX_PER_PARENT = max(1, int(os.environ.get("PARALLEL_SHARD_MAX_PER_PARENT", "4")))
PARALLEL_SHARD_CONCURRENCY_HARD_MAX = max(
    PARALLEL_SHARD_MAX_PER_PARENT,
    int(os.environ.get("PARALLEL_SHARD_CONCURRENCY_HARD_MAX", "20")),
)
PARALLEL_SHARD_SLOT_TTL_SECONDS = max(
    300,
    int(os.environ.get("PARALLEL_SHARD_SLOT_TTL_SECONDS", str(8 * 60 * 60))),
)
PARALLEL_SHARD_REQUEUE_DELAY_SECONDS = max(1, int(os.environ.get("PARALLEL_SHARD_REQUEUE_DELAY_SECONDS", "2")))
DOMAIN_RATE_REQUEUE_DELAY_SECONDS = max(1, int(os.environ.get("DOMAIN_RATE_REQUEUE_DELAY_SECONDS", "60")))

# Verification policy: single source of truth for severity gates.
# Legacy env vars (AUTO_RETEST_MIN_SEVERITY, AI_VERIFY_MIN_SEVERITY) are still
# read as fallbacks inside VerificationPolicy.from_env().
_DEFAULT_POLICY = VerificationPolicy.from_env()

AUTO_RETEST_ON_SCAN_COMPLETE = _DEFAULT_POLICY.auto_retest_enabled
AUTO_RETEST_MIN_SEVERITY = _DEFAULT_POLICY.verification_min_severity
AUTO_RETEST_MAX_PER_SCAN = _DEFAULT_POLICY.auto_retest_max_per_scan
AUTO_RETEST_REQUESTED_BY = "auto_scan_policy"

# AI verification (opt-in, Tier 2 after deterministic provers)
AI_VERIFY_ENABLED = os.environ.get("AI_VERIFY_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
AI_VERIFY_URL = os.environ.get("AI_URL", "")
AI_VERIFY_API_KEY = os.environ.get("AI_API_KEY", "")
AI_VERIFY_MODEL = os.environ.get("AI_MODEL", "claude-sonnet-4-5-20250929")
AI_VERIFY_FALLBACK_MODEL = os.environ.get("AI_FALLBACK_MODEL", "")
AI_VERIFY_MAX_PER_SCAN = max(0, int(os.environ.get("AI_VERIFY_MAX_PER_SCAN", "10")))
AI_VERIFY_MIN_SEVERITY = _DEFAULT_POLICY.ai_escalation_min_severity
AI_VERIFY_USE_BROWSER = os.environ.get("AI_VERIFY_USE_BROWSER", "true").lower() in {"1", "true", "yes", "on"}
AI_SCAN_CLASSIFICATION_ENABLED = os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED", "false").lower() in {
    "1", "true", "yes", "on"
}
AI_CLASSIFY_MIN_SEVERITY = os.environ.get("AI_CLASSIFY_MIN_SEVERITY", AI_VERIFY_MIN_SEVERITY).lower()

from retest_contract import SEVERITY_ORDER
try:
    from evidence_triage import build_evidence_with_triage as _build_evidence_with_triage
except ModuleNotFoundError as exc:
    if exc.name != "evidence_triage":
        raise
    from api.evidence_triage import build_evidence_with_triage as _build_evidence_with_triage

try:
    from scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields_dict
except ModuleNotFoundError as exc:
    if exc.name != "scan_verification_state":
        raise
    from api.scan_verification_state import scan_time_verification_fields as _scan_time_verification_fields_dict

# Database pool (initialized in main)
db_pool = None
ASYNC_PG_ERROR = getattr(asyncpg, "PostgresError", Exception)


def _canonicalize_jsonish(value: Any) -> str | None:
    """Return a deterministic JSON string for an asyncpg JSONB cell or local dump.

    Used to compare stored vs. incoming finding evidence without false-positive
    diffs from JSONB key-order or whitespace changes.
    """
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    if isinstance(value, str):
        try:
            return json.dumps(json.loads(value), sort_keys=True, separators=(",", ":"), default=str)
        except (TypeError, ValueError):
            return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _scan_time_verification_fields(finding: dict[str, Any]) -> tuple[str | None, str | None, float | None]:
    fields = _scan_time_verification_fields_dict(finding)
    if not fields:
        return None, None, None
    return (
        fields.get("last_verification_status"),
        fields.get("last_verification_verdict"),
        fields.get("last_verification_confidence"),
    )


def run_worker_preflight() -> None:
    """Fail fast when the container has an inconsistent scanner import graph."""
    if os.environ.get("WORKER_PREFLIGHT_ENABLED", "true").lower() not in {"1", "true", "yes", "on"}:
        print("[preflight] worker preflight disabled", flush=True)
        return

    try:
        try:
            from findings import apply_dast_precision_policy  # noqa: F401
        except ModuleNotFoundError as exc:
            if exc.name != "findings":
                raise
            from scanner.findings import apply_dast_precision_policy  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            "worker preflight failed: findings.apply_dast_precision_policy is unavailable"
        ) from exc

    scanner_path = Path(SCANNER_PATH)
    if not scanner_path.exists():
        if os.environ.get("WORKER_PREFLIGHT_REQUIRE_SCANNER", "true").lower() in {"1", "true", "yes", "on"}:
            raise RuntimeError(f"worker preflight failed: scanner entrypoint missing at {SCANNER_PATH}")
        print(f"[preflight] scanner entrypoint missing at {SCANNER_PATH}; skipping CLI import check", flush=True)
        return

    timeout = int(os.environ.get("WORKER_PREFLIGHT_TIMEOUT_SECONDS", "30"))

    def _run_check(label: str, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            cmd,
            cwd=str(scanner_path.parent),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != 0:
            output = "\n".join(part for part in (result.stderr.strip(), result.stdout.strip()) if part)
            raise RuntimeError(
                f"worker preflight failed: {label} exited {result.returncode}: {output[:2000]}"
            )
        return result

    _run_check("scanner CLI import check", [sys.executable, SCANNER_PATH, "--help"])

    import_check = r"""
import hashlib
import importlib
import json
from pathlib import Path

required = {
    "constants": ["NUCLEI_PROMOTE_TEMPLATES", "SMART_SCAN_BUDGETS", "resolve_scan_budget"],
    "grading": ["grade"],
    "findings": ["normalize_finding", "deduplicate_findings", "apply_dast_precision_policy", "now_utc_iso"],
    "reporting": ["emit_config_findings"],
    "signals": ["extract_signals_from_nuclei"],
    # target_context is a top-level module imported by grading/findings/reporting.
    # It must be mounted/baked alongside them; listing it here turns a missing
    # mount into a clear preflight failure instead of a worker crash loop.
    "target_context": ["is_local_or_private_scan_target"],
}
report = {}
for module_name, symbols in required.items():
    module = importlib.import_module(module_name)
    missing = [symbol for symbol in symbols if not hasattr(module, symbol)]
    if missing:
        raise RuntimeError(f"{module_name} missing symbols: {', '.join(missing)}")
    path = Path(getattr(module, "__file__", "")).resolve()
    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16] if path.exists() else None
    report[module_name] = {"file": str(path), "sha256_16": digest}
print(json.dumps(report, sort_keys=True))
"""
    module_result = _run_check("scanner module symbol check", [sys.executable, "-c", import_check])
    module_summary = module_result.stdout.strip()
    if module_summary:
        print(f"[preflight] scanner module symbols passed: {module_summary}", flush=True)

    entrypoint_digest = hashlib.sha256(scanner_path.read_bytes()).hexdigest()[:16]
    print(f"[preflight] worker scanner import check passed: scanner.py sha256_16={entrypoint_digest}", flush=True)


def get_redis():
    return redis.from_url(REDIS_URL)


def _is_truthy(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_severity(value: Any, default: str = "high") -> str:
    severity = str(value or "").strip().lower()
    if severity in SEVERITY_ORDER:
        return severity
    return default


def _decode_redis_hash(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    decoded: dict[str, str] = {}
    for key, value in raw.items():
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        decoded[str(key)] = str(value)
    return decoded


def _load_runtime_ai_settings() -> dict[str, Any]:
    shared_ai_url = os.environ.get("AI_URL", "")
    shared_ai_key = os.environ.get("AI_API_KEY", "")
    shared_ai_model = os.environ.get("AI_MODEL", "")
    shared_ai_fallback = os.environ.get("AI_FALLBACK_MODEL", "")

    settings: dict[str, Any] = {
        "ai_url": shared_ai_url,
        "ai_api_key": shared_ai_key,
        "ai_model": shared_ai_model,
        "ai_model_fallback": shared_ai_fallback,
        "ai_mask_host": os.environ.get("AI_MASK_HOST", "example.com"),
        "ai_verify_enabled": AI_VERIFY_ENABLED,
        "ai_verify_url": shared_ai_url,
        "ai_verify_api_key": shared_ai_key,
        "ai_verify_model": shared_ai_model,
        "ai_verify_model_fallback": shared_ai_fallback,
        "ai_verify_min_severity": os.environ.get("AI_VERIFY_MIN_SEVERITY", AI_VERIFY_MIN_SEVERITY),
        "ai_scan_classification_enabled": _is_truthy(
            os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED", "false"),
            default=AI_SCAN_CLASSIFICATION_ENABLED,
        ),
        "ai_classify_min_severity": os.environ.get("AI_CLASSIFY_MIN_SEVERITY", AI_CLASSIFY_MIN_SEVERITY),
        "auto_retest_on_scan_complete": AUTO_RETEST_ON_SCAN_COMPLETE,
        "auto_retest_min_severity": os.environ.get("AUTO_RETEST_MIN_SEVERITY", AUTO_RETEST_MIN_SEVERITY),
        "auto_retest_max_per_scan": max(0, int(os.environ.get("AUTO_RETEST_MAX_PER_SCAN", str(AUTO_RETEST_MAX_PER_SCAN)))),
        "verification_min_severity": os.environ.get(
            "VERIFICATION_MIN_SEVERITY",
            os.environ.get("AUTO_RETEST_MIN_SEVERITY", AUTO_RETEST_MIN_SEVERITY),
        ),
        "ai_escalation_min_severity": os.environ.get(
            "AI_ESCALATION_MIN_SEVERITY",
            os.environ.get("AI_VERIFY_MIN_SEVERITY", AI_VERIFY_MIN_SEVERITY),
        ),
        "proof_required_for_smart": _is_truthy(
            os.environ.get("PROOF_REQUIRED_FOR_SMART", "false"),
            default=False,
        ),
        "auto_fp_on_retest": _is_truthy(
            os.environ.get("AUTO_FP_ON_RETEST", "false"),
            default=False,
        ),
        "auto_fp_min_confidence": os.environ.get("AUTO_FP_MIN_CONFIDENCE", "0.9"),
    }
    try:
        r = get_redis()
        overrides = _decode_redis_hash(r.hgetall(AI_SETTINGS_KEY))
    except Exception:
        overrides = {}

    for key in (
        "ai_url",
        "ai_api_key",
        "ai_model",
        "ai_model_fallback",
        "ai_mask_host",
        "ai_verify_min_severity",
        "ai_escalation_min_severity",
        "ai_classify_min_severity",
        "auto_retest_min_severity",
        "verification_min_severity",
    ):
        if key in overrides:
            settings[key] = overrides.get(key) or ""

    # The UI presents a single "Shared Provider" whose model is authoritative for
    # retest verification ("Retest AI uses the shared provider settings"). The
    # verify-specific fields are seeded from env (AI_MODEL / AI_FALLBACK_MODEL),
    # so without this a stale env model silently overrides the saved one for
    # retests even though the UI/Redis shows the new model. Mirror the
    # Redis-configured shared model onto the verify fields so what you save wins.
    if "ai_model" in overrides:
        settings["ai_verify_model"] = settings["ai_model"]
    if "ai_model_fallback" in overrides:
        settings["ai_verify_model_fallback"] = settings["ai_model_fallback"]

    if "ai_verify_enabled" in overrides:
        settings["ai_verify_enabled"] = _is_truthy(overrides.get("ai_verify_enabled"), default=AI_VERIFY_ENABLED)
    if "auto_retest_on_scan_complete" in overrides:
        settings["auto_retest_on_scan_complete"] = _is_truthy(
            overrides.get("auto_retest_on_scan_complete"),
            default=AUTO_RETEST_ON_SCAN_COMPLETE,
        )
    if "ai_scan_classification_enabled" in overrides:
        settings["ai_scan_classification_enabled"] = _is_truthy(
            overrides.get("ai_scan_classification_enabled"),
            default=AI_SCAN_CLASSIFICATION_ENABLED,
        )
    if "proof_required_for_smart" in overrides:
        settings["proof_required_for_smart"] = _is_truthy(
            overrides.get("proof_required_for_smart"),
            default=False,
        )
    if "auto_fp_on_retest" in overrides:
        settings["auto_fp_on_retest"] = _is_truthy(
            overrides.get("auto_fp_on_retest"),
            default=False,
        )
    if "auto_fp_min_confidence" in overrides:
        settings["auto_fp_min_confidence"] = overrides.get("auto_fp_min_confidence")
    if "auto_retest_max_per_scan" in overrides:
        try:
            settings["auto_retest_max_per_scan"] = max(0, int(str(overrides.get("auto_retest_max_per_scan") or "0")))
        except (TypeError, ValueError):
            settings["auto_retest_max_per_scan"] = AUTO_RETEST_MAX_PER_SCAN

    # Canonicalize verification thresholds through shared policy.
    policy = VerificationPolicy.from_env(overrides=settings)
    settings["auto_retest_on_scan_complete"] = policy.auto_retest_enabled
    settings["auto_retest_max_per_scan"] = policy.auto_retest_max_per_scan
    settings["proof_required_for_smart"] = policy.proof_required_for_smart
    settings["auto_fp_on_retest"] = policy.auto_fp_on_retest
    settings["auto_fp_min_confidence"] = policy.auto_fp_min_confidence
    settings["verification_min_severity"] = policy.verification_min_severity
    settings["auto_retest_min_severity"] = policy.verification_min_severity
    settings["ai_escalation_min_severity"] = policy.ai_escalation_min_severity
    settings["ai_verify_min_severity"] = policy.ai_escalation_min_severity

    if "ai_classify_min_severity" not in overrides:
        settings["ai_classify_min_severity"] = settings["ai_verify_min_severity"]
    classify_severity = str(settings.get("ai_classify_min_severity") or settings["ai_verify_min_severity"]).lower()
    if classify_severity not in SEVERITY_ORDER:
        classify_severity = settings["ai_verify_min_severity"]
    settings["ai_classify_min_severity"] = classify_severity
    return settings


def _runtime_ai_target_credential_from_row(row: dict[str, Any] | None) -> dict[str, Any]:
    if not row:
        return {"auth_kind": "none", "header_name": None, "secret": None, "metadata_json": {}}

    metadata = parse_json_field(row.get("metadata_json")) or {}
    auth_kind = row.get("auth_kind") or "none"
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


async def _hydrate_ai_gate_options(options: dict[str, Any]) -> dict[str, Any]:
    hydrated = dict(options)
    ai_target = dict(hydrated.get("ai_target") or {})
    if not ai_target:
        return hydrated

    credential_ref = ai_target.get("credential_ref") if isinstance(ai_target.get("credential_ref"), dict) else {}
    target_id = ai_target.get("id") or hydrated.get("ai_target_id") or credential_ref.get("ai_target_id")
    if "credential" not in ai_target and target_id and db_pool is not None:
        try:
            credential_row = await db_pool.fetchrow(
                "SELECT * FROM ai_target_credentials WHERE ai_target_id = $1",
                uuid.UUID(str(target_id)),
            )
            ai_target["credential"] = _runtime_ai_target_credential_from_row(
                dict(credential_row) if credential_row else None
            )
        except (ValueError, TypeError, ASYNC_PG_ERROR):
            ai_target["credential"] = {"auth_kind": "none", "header_name": None, "secret": None, "metadata_json": {}}

    ai_target.pop("credential_ref", None)
    if "principals" not in ai_target and target_id and db_pool is not None:
        principal_refs = ai_target.get("principal_refs")
        try:
            principal_rows = await db_pool.fetch(
                """
                SELECT * FROM ai_target_principals
                WHERE ai_target_id = $1 AND is_active = true
                ORDER BY role, label
                """,
                uuid.UUID(str(target_id)),
            )
            principals: list[dict[str, Any]] = []
            for row in principal_rows:
                principal = dict(row)
                principals.append({
                    "id": str(principal.get("id")),
                    "label": principal.get("label"),
                    "role": principal.get("role") or "attacker",
                    "tenant_id": principal.get("tenant_id"),
                    "metadata_json": parse_json_field(principal.get("metadata_json")) or {},
                    "credential": _runtime_ai_target_credential_from_row(principal),
                })
            if principals:
                ai_target["principals"] = principals
        except (ValueError, TypeError, ASYNC_PG_ERROR):
            if isinstance(principal_refs, list):
                ai_target["principal_refs"] = principal_refs
    ai_target.pop("principal_refs", None)
    hydrated["ai_target"] = ai_target

    ai_runtime = _load_runtime_ai_settings()
    if ai_runtime.get("ai_url") and ai_runtime.get("ai_api_key"):
        hydrated.setdefault("ai_url", ai_runtime.get("ai_url"))
        hydrated.setdefault("ai_api_key", ai_runtime.get("ai_api_key"))
        hydrated.setdefault("ai_model", ai_runtime.get("ai_model") or "gpt-4o-mini")
        hydrated.setdefault("ai_model_fallback", ai_runtime.get("ai_model_fallback") or "")
    return hydrated


def _int_env(name: str, default: int) -> int:
    try:
        raw = os.environ.get(name)
        return int(raw) if raw is not None and raw != "" else default
    except (TypeError, ValueError):
        return default


async def init_db():
    """Initialize database connection pool."""
    global db_pool
    db_pool_min = _int_env("DB_POOL_MIN_SIZE", 2)
    db_pool_max = _int_env("DB_POOL_MAX_SIZE", 8)
    db_statement_timeout_ms = _int_env("DB_STATEMENT_TIMEOUT_MS", 60000)

    async def _init_conn(conn):
        # Per-worker statement timeout. Longer than the API default because
        # save_findings can run a tight loop of inserts under heavy churn.
        if db_statement_timeout_ms > 0:
            await conn.execute(f"SET statement_timeout = {db_statement_timeout_ms}")

    db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=db_pool_min,
        max_size=db_pool_max,
        init=_init_conn,
    )
    await run_schema_migrations(db_pool)


def _scanner_process_kwargs() -> dict[str, Any]:
    """Start scanner subprocesses in their own session on POSIX.

    That lets cancellation terminate the whole scanner process group, including
    child tools spawned by scanner.py.
    """
    if os.name == "posix":
        return {"start_new_session": True}
    return {}


def _scan_cancel_requested(scan_id: str | None, redis_client: Any | None = None) -> bool:
    if not scan_id:
        return False
    try:
        client = redis_client or get_redis()
        return bool(client.get(f"scan:{scan_id}:cancel"))
    except Exception:
        return False


def _signal_scanner_cancel_file(cancel_file: str | None) -> None:
    if not cancel_file:
        return
    try:
        path = Path(cancel_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("1\n", encoding="utf-8")
    except Exception:
        pass


async def _terminate_scanner_process(proc: Any) -> None:
    """Terminate a scanner subprocess, preferring the process group on POSIX."""
    if getattr(proc, "returncode", None) is not None:
        return

    try:
        pid = getattr(proc, "pid", None)
        if os.name == "posix" and pid:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        else:
            proc.terminate()
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.terminate()
        except Exception:
            pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=SCAN_KILL_GRACE_SECONDS)
        return
    except asyncio.TimeoutError:
        pass

    try:
        pid = getattr(proc, "pid", None)
        if os.name == "posix" and pid:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        else:
            proc.kill()
    except ProcessLookupError:
        return
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass

    try:
        await asyncio.wait_for(proc.wait(), timeout=max(1.0, SCAN_KILL_GRACE_SECONDS / 2))
    except Exception:
        pass


async def run_scan(target: str, options: dict, scan_id: str | None = None, job_id: str | None = None) -> dict:
    """Execute scanner and return results."""
    if options.get("run_kind") in MODEL_INTAKE_RUN_KINDS:
        if scan_id:
            await update_scan_progress(scan_id, "model_intake", 15, job_id=job_id)
        try:
            from scanner_tools.model_intake import run_model_intake_scan
        except ImportError:
            from scanner.scanner_tools.model_intake import run_model_intake_scan

        result = await run_model_intake_scan(target, options)
        if scan_id:
            await update_scan_progress(scan_id, "model_intake_finalize", 95, job_id=job_id)
        return result

    if options.get("run_kind") in AI_GATE_RUN_KINDS:
        if scan_id:
            await update_scan_progress(scan_id, "ai_gate", 15, job_id=job_id)
        from ai_gate_scan import run_ai_target_scan

        result = await run_ai_target_scan(target, await _hydrate_ai_gate_options(options))
        if scan_id:
            await update_scan_progress(scan_id, "ai_gate_finalize", 95, job_id=job_id)
        return result

    cmd = ['python3', SCANNER_PATH, target]

    # Map scan_type to CLI flags (mutually exclusive presets)
    # Scan types: quick, standard, deep, full, aggressive, smart
    scan_type = (options.get('scan_type') or '').strip().lower()
    if scan_type and scan_type not in VALID_DAST_SCAN_TYPES:
        allowed = ", ".join(sorted(VALID_DAST_SCAN_TYPES))
        raise ValueError(f"scan_type must be one of: {allowed}")

    # Validate: public mode is incompatible with active-enforced scan types
    if scan_type in ACTIVE_ENFORCED_SCAN_TYPES and options.get('public'):
        raise ValueError(
            f"public option is incompatible with '{scan_type}' scan type. "
            f"{scan_type.capitalize()} scans require active testing. "
            "Use 'deep' scan type for passive-only comprehensive scanning."
        )

    if scan_type == 'smart':
        cmd.append('--smart')
    elif scan_type == 'aggressive':
        cmd.append('--aggressive')
    elif scan_type == 'full':
        cmd.append('--full')
    elif scan_type == 'deep' or options.get('thorough'):
        cmd.append('--deep')
    elif scan_type == 'standard':
        cmd.append('--standard')
    elif scan_type == 'quick' or options.get('quick'):
        cmd.append('--quick')
    # If no scan_type, run standard scan (no flag needed)

    # Additional flags (can be combined with scan types)
    # Pass --active when explicitly requested (even with explicit scan_type)
    # Note: full/aggressive/smart already include active tests, so skip for those
    if options.get('active') and scan_type not in ['full', 'aggressive', 'smart']:
        cmd.append('--active')

    # Note: public is not allowed for smart/full/aggressive (validated above)
    if options.get('public'):
        cmd.append('--public')
    check_family = options.get('asm_check_family') or options.get('check_family')
    if check_family:
        cmd.extend(['--check-family', str(check_family)])
    if options.get('xss'):
        cmd.append('--xss')
    if options.get('sqli'):
        cmd.append('--sqli')
    if options.get('deep_domxss'):
        cmd.append('--deep-domxss')
    if options.get('nuclei') and scan_type not in ['full', 'aggressive', 'deep']:
        cmd.append('--nuclei')
    if options.get('enhanced_dns'):
        cmd.append('--enhanced-dns')
    if options.get('subfinder'):
        cmd.append('--subfinder')

    # Client-Side Security
    if options.get('js_dependency_scanning'):
        cmd.append('--js-dependency-scanning')
    if options.get('js_secret_scanning'):
        cmd.append('--js-secret-scanning')
    if options.get('grpc_discovery'):
        cmd.append('--grpc-discovery')
    if options.get('json_link_following'):
        cmd.append('--json-link-following')
    if options.get('options_method_discovery'):
        cmd.append('--options-method-discovery')
    if options.get('include_partial_attack_chains'):
        cmd.append('--include-partial-attack-chains')
    if options.get('skip_global_checks'):
        cmd.append('--skip-global-checks')
    if options.get('focused_endpoints_only'):
        cmd.append('--focused-endpoints-only')
    if options.get('zero_rediscovery'):
        cmd.append('--zero-rediscovery')

    # Smart scan tuning options
    if options.get('no_early_stop'):
        cmd.append('--no-early-stop')
    if options.get('thorough_params'):
        cmd.append('--thorough-params')
    if options.get('oob_callback_url'):
        cmd.extend(['--oob-callback-url', options['oob_callback_url']])
    if options.get('budget_profile'):
        cmd.extend(['--budget-profile', str(options['budget_profile'])])

    custom_budget = options.get("custom_budget")
    if isinstance(custom_budget, dict):
        custom_budget_flag_map = {
            "max_duration_minutes": "--budget-max-duration-minutes",
            "discovery_depth": "--budget-discovery-depth",
            "max_urls": "--budget-max-urls",
            "browser_max_pages": "--budget-browser-max-pages",
            "browser_max_depth": "--budget-browser-max-depth",
            "api_probe_limit": "--budget-api-probe-limit",
            "param_discovery_url_limit": "--budget-param-discovery-url-limit",
            "param_discovery_max_params": "--budget-param-discovery-max-params",
            "phase4_max_seconds": "--budget-phase4-max-seconds",
            "nuclei_max_targets": "--budget-nuclei-max-targets",
            "active_max_seconds": "--budget-active-max-seconds",
            "active_max_endpoints": "--budget-active-max-endpoints",
            "active_params_per_endpoint": "--budget-active-params-per-endpoint",
            "active_worklist_max": "--budget-active-worklist-max",
            "dom_xss_max_files": "--dom-xss-max-files",
            "smart_bola_max_endpoints": "--smart-bola-max-endpoints",
            "sqli_extract_max": "--sqli-extract-max",
            "oob_max_findings": "--oob-max-findings",
        }
        for budget_key, flag in custom_budget_flag_map.items():
            if custom_budget.get(budget_key) is not None:
                cmd.extend([flag, str(custom_budget[budget_key])])
        if custom_budget.get("nuclei_early_stop") is False:
            cmd.append("--budget-disable-nuclei-early-stop")
        if "max_findings_per_family" in custom_budget:
            value = custom_budget.get("max_findings_per_family")
            cmd.extend(["--budget-max-findings-per-family", "-1" if value is None else str(value)])

    # Safety/performance limits
    if options.get('smart_bola_max_endpoints'):
        cmd.extend(['--smart-bola-max-endpoints', str(options['smart_bola_max_endpoints'])])
    if options.get('dom_xss_max_files'):
        cmd.extend(['--dom-xss-max-files', str(options['dom_xss_max_files'])])
    if options.get('sqli_extract_max'):
        cmd.extend(['--sqli-extract-max', str(options['sqli_extract_max'])])
    # oob_max_findings (prefer new name, fall back to deprecated oob_max_payloads)
    oob_max = options.get('oob_max_findings')
    if oob_max is None:
        oob_max = options.get('oob_max_payloads')
    if oob_max is not None:
        cmd.extend(['--oob-max-findings', str(oob_max)])

    # AI options
    ai_runtime = _load_runtime_ai_settings()
    ai_url = options.get('ai_url') or ai_runtime.get("ai_url")
    ai_api_key = options.get('ai_api_key') or ai_runtime.get("ai_api_key")
    model = options.get('model') or ai_runtime.get("ai_model")
    ai_fallback_model = (
        options.get("ai_fallback_model")
        or options.get("ai_model_fallback")
        or ai_runtime.get("ai_model_fallback")
    )
    ai_mask_host = options.get('ai_mask_host') or ai_runtime.get("ai_mask_host") or 'example.com'
    runtime_policy = VerificationPolicy.from_env(overrides=ai_runtime)
    scan_classify_override = options.get("ai_scan_classification_enabled")
    scan_classify_alias_override = options.get("ai_classify_enabled")
    if scan_classify_override is not None:
        ai_scan_classify_enabled = _is_truthy(scan_classify_override, default=False)
    elif scan_classify_alias_override is not None:
        ai_scan_classify_enabled = _is_truthy(scan_classify_alias_override, default=False)
    else:
        # Treat null/omitted option values as "no override" so runtime settings apply.
        ai_scan_classify_enabled = bool(ai_runtime.get("ai_scan_classification_enabled"))
    ai_classify_min_severity = str(
        options.get("ai_classify_min_severity")
        or options.get("ai_min_severity")
        or ai_runtime.get("ai_classify_min_severity")
        or ai_runtime.get("ai_verify_min_severity")
        or AI_VERIFY_MIN_SEVERITY
    ).lower()
    ai_classify_min_severity = _normalize_severity(
        ai_classify_min_severity,
        default=_normalize_severity(ai_runtime.get("ai_verify_min_severity"), default="high"),
    )
    verification_min_severity = _normalize_severity(
        options.get("verification_min_severity") or ai_runtime.get("verification_min_severity"),
        default=runtime_policy.verification_min_severity,
    )
    ai_verify_min_severity = _normalize_severity(
        options.get("ai_escalation_min_severity")
        or options.get("ai_verify_min_severity")
        or ai_runtime.get("ai_escalation_min_severity")
        or ai_runtime.get("ai_verify_min_severity"),
        default=runtime_policy.ai_escalation_min_severity,
    )

    # Scan-time AI should only run when scan classification is explicitly enabled.
    scan_ai_enabled = bool(ai_scan_classify_enabled)

    if scan_ai_enabled and ai_url and ai_api_key and model:
        cmd.append('--ai')
        cmd.extend(['--ai-url', ai_url])
        cmd.extend(['--ai-api-key', ai_api_key])
        cmd.extend(['--model', model])
        if ai_fallback_model:
            cmd.extend(['--ai-fallback-model', str(ai_fallback_model)])
        cmd.extend(['--ai-mask-host', ai_mask_host])

    # Authentication options
    # Session-based auth (cookies, headers)
    if options.get('auth_cookies'):
        cmd.extend(['--auth-cookies', options['auth_cookies']])
    if options.get('auth_header'):
        cmd.extend(['--auth-header', options['auth_header']])
    if options.get('auth_headers_json'):
        cmd.extend(['--auth-headers-json', options['auth_headers_json']])

    # Form-based login
    if options.get('login_username') and options.get('login_password'):
        cmd.extend(['--login-username', options['login_username']])
        cmd.extend(['--login-password', options['login_password']])
    if options.get('login_url'):
        cmd.extend(['--login-url', options['login_url']])
    if options.get('login_extra_fields'):
        cmd.extend(['--login-extra-fields', options['login_extra_fields']])
    if options.get('auto_auth'):
        cmd.append('--auto-auth')

    # Multi-user auth (for BOLA/IDOR testing)
    if options.get('user2_cookies'):
        cmd.extend(['--user2-cookies', options['user2_cookies']])
    if options.get('user2_header'):
        cmd.extend(['--user2-header', options['user2_header']])
    if options.get('auth_scenario_json'):
        cmd.extend(['--auth-scenario-json', options['auth_scenario_json']])

    # Manual endpoints for API-only targets
    custom_endpoints = options.get('custom_endpoints')
    if custom_endpoints and isinstance(custom_endpoints, list):
        for endpoint in custom_endpoints:
            if endpoint and isinstance(endpoint, str):
                cmd.extend(['--endpoints', endpoint.strip()])
    if options.get('focus_rules_json'):
        cmd.extend(['--focus-rules-json', options['focus_rules_json']])
    if options.get('avoid_rules_json'):
        cmd.extend(['--avoid-rules-json', options['avoid_rules_json']])
    if options.get('verified_findings_only') is True:
        cmd.append('--verified-findings-only')
    elif options.get('verified_findings_only') is False:
        cmd.append('--no-verified-findings-only')

    # Log command (mask API key and sensitive auth data)
    sensitive_flags = ['--ai-api-key', '--auth-cookies', '--auth-header', '--auth-headers-json',
                       '--login-password', '--user2-cookies', '--user2-header', '--auth-scenario-json']
    cmd_masked = []
    for i, c in enumerate(cmd):
        if i > 0 and cmd[i-1] in sensitive_flags:
            cmd_masked.append('***')
        else:
            cmd_masked.append(c)
    print(f"  Command: {' '.join(cmd_masked)}", flush=True)

    # Set up checkpoint file for partial result recovery
    checkpoint_file = None
    scan_env = os.environ.copy()
    # Scan-time AI classification is opt-in and severity-gated.
    scan_env["AI_SCAN_CLASSIFICATION_ENABLED"] = "true" if scan_ai_enabled else "false"
    scan_env["AI_CLASSIFY_MIN_SEVERITY"] = ai_classify_min_severity
    scan_env["AI_VERIFY_MIN_SEVERITY"] = ai_verify_min_severity
    # Pass unified policy env vars so scanner picks up consolidated thresholds
    scan_env["VERIFICATION_MIN_SEVERITY"] = verification_min_severity
    scan_env["AI_ESCALATION_MIN_SEVERITY"] = ai_verify_min_severity
    _policy_overrides = dict(ai_runtime)
    _policy_overrides["verification_min_severity"] = verification_min_severity
    _policy_overrides["ai_escalation_min_severity"] = ai_verify_min_severity
    if "proof_required_for_smart" in options:
        _policy_overrides["proof_required_for_smart"] = options.get("proof_required_for_smart")
    _policy_for_env = VerificationPolicy.from_env(overrides=_policy_overrides)
    scan_env["PROOF_REQUIRED_FOR_SMART"] = "true" if _policy_for_env.proof_required_for_smart else "false"
    if scan_id:
        checkpoint_file = RESULTS_DIR / f"{scan_id}_checkpoint.json"
        scan_env["SCAN_CHECKPOINT_FILE"] = str(checkpoint_file)
        cancel_file = RESULTS_DIR / f"{scan_id}_cancel"
        scan_env["SHAKERSCAN_CANCEL_FILE"] = str(cancel_file)
        try:
            cancel_file.unlink(missing_ok=True)
        except Exception:
            pass
    else:
        cancel_file = None

    # User-supplied content-discovery keywords (additive; off when absent).
    custom_wordlist = options.get("custom_wordlist")
    if isinstance(custom_wordlist, list) and custom_wordlist:
        words = []
        for w in custom_wordlist:
            if isinstance(w, str) and w.strip() and "\n" not in w and "\r" not in w:
                words.append(w.strip())
            if len(words) >= 10000:  # bound env size
                break
        if words:
            scan_env["SHAKERSCAN_CUSTOM_WORDLIST"] = "\n".join(words)

    # User-supplied injection payloads (additive; off when absent).
    for opt_key, env_key in (
        ("custom_sqli_payloads", "SHAKERSCAN_CUSTOM_SQLI_PAYLOADS"),
        ("custom_xss_payloads", "SHAKERSCAN_CUSTOM_XSS_PAYLOADS"),
    ):
        vals = options.get(opt_key)
        if isinstance(vals, list) and vals:
            clean = [v.strip() for v in vals
                     if isinstance(v, str) and v.strip() and "\n" not in v and "\r" not in v]
            if clean:
                scan_env[env_key] = "\n".join(clean[:2000])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=scan_env,
        **_scanner_process_kwargs(),
    )

    timeout_reason: str | None = None
    cancel_reason: str | None = None
    max_duration_minutes = DEFAULT_MAX_DURATION_MINUTES
    override_minutes = os.environ.get("SCAN_MAX_DURATION_MINUTES")
    if override_minutes:
        try:
            max_duration_minutes = int(override_minutes)
        except Exception:
            max_duration_minutes = DEFAULT_MAX_DURATION_MINUTES
    else:
        if scan_type:
            resolved_budget = options.get("resolved_budget")
            if not isinstance(resolved_budget, dict):
                effective_budget_profile = options.get("budget_profile")
                if options.get("thorough_params") and not effective_budget_profile and not options.get("custom_budget"):
                    effective_budget_profile = "thorough"
                resolved_budget = resolve_scan_budget(
                    scan_type,
                    effective_budget_profile,
                    options.get("custom_budget") if isinstance(options.get("custom_budget"), dict) else None,
                )
            max_duration_minutes = int(
                resolved_budget.get("max_duration_minutes")
                or MAX_SCAN_DURATION.get(scan_type, DEFAULT_MAX_DURATION_MINUTES)
            )

    async def _watchdog_timeout() -> None:
        nonlocal timeout_reason
        if max_duration_minutes <= 0:
            return
        await asyncio.sleep(max_duration_minutes * 60)
        if proc.returncode is None:
            timeout_reason = (
                f"Exceeded max duration ({max_duration_minutes} min for {scan_type or 'standard'} scan)"
            )
            await _terminate_scanner_process(proc)

    watchdog_task = asyncio.create_task(_watchdog_timeout())

    async def _watchdog_cancel() -> None:
        nonlocal cancel_reason
        if not scan_id:
            return
        while proc.returncode is None:
            if await asyncio.to_thread(_scan_cancel_requested, scan_id):
                cancel_reason = "Cancelled by user"
                await asyncio.to_thread(_signal_scanner_cancel_file, str(cancel_file) if cancel_file else None)
                if SCAN_COOPERATIVE_CANCEL_GRACE_SECONDS > 0:
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=SCAN_COOPERATIVE_CANCEL_GRACE_SECONDS)
                        return
                    except asyncio.TimeoutError:
                        pass
                await _terminate_scanner_process(proc)
                return
            await asyncio.sleep(SCAN_CANCEL_POLL_SECONDS)

    cancel_task = asyncio.create_task(_watchdog_cancel())

    stdout_chunks: list[bytes] = []
    stderr_lines: list[str] = []
    last_progress: tuple[str | None, int | None] = (None, None)
    log_key = f"scan:{scan_id}:logs" if scan_id else None

    def _parse_progress(line: str) -> tuple[str, int] | None:
        if not line.startswith("[progress]"):
            return None
        phase_match = re.search(r"\bphase=([^\s]+)", line)
        pct_match = re.search(r"\bpct=(\d{1,3})", line)
        if not phase_match or not pct_match:
            return None
        phase = phase_match.group(1)
        try:
            pct = int(pct_match.group(1))
        except ValueError:
            return None
        pct = max(0, min(100, pct))
        return phase, pct

    async def _handle_stdout(line: bytes) -> None:
        stdout_chunks.append(line)

    async def _handle_stderr(line: bytes) -> None:
        nonlocal last_progress
        text = line.decode(errors="replace").rstrip("\n")
        if not text:
            return
        stderr_lines.append(text)
        # Limit in-memory stderr to avoid bloat
        if len(stderr_lines) > 2000:
            stderr_lines.pop(0)

        if log_key:
            try:
                r = get_redis()
                r.rpush(log_key, text)
                r.ltrim(log_key, -SCAN_LOG_TAIL, -1)
                r.expire(log_key, SCAN_LOG_TTL_SECONDS)
            except Exception:
                pass

        progress = _parse_progress(text)
        if progress and scan_id:
            phase, pct = progress
            last_phase, last_pct = last_progress
            if phase != last_phase or pct != last_pct:
                await update_scan_progress(scan_id, phase, pct, job_id=job_id)
                last_progress = (phase, pct)
            elif job_id:
                try:
                    # Sync Redis client blocks the event loop; run it on a worker thread
                    # so a slow Redis connect cannot stall stderr/progress handling.
                    await asyncio.to_thread(
                        get_redis().hset,
                        f"job:{job_id}",
                        "heartbeat",
                        utc_now_iso(),
                    )
                except Exception as exc:
                    # Heartbeat is best-effort; log so a sustained Redis outage is
                    # observable instead of silently failing forever.
                    print(f"[worker] heartbeat hset failed: {exc}", file=sys.stderr, flush=True)

    async def _read_stream_lines(stream: asyncio.StreamReader, handler) -> None:
        """Read stream line-by-line (for stderr progress messages)."""
        while True:
            try:
                line = await stream.readline()
            except asyncio.LimitOverrunError:
                # Line exceeds buffer limit - read what we can and continue
                partial = await stream.read(65536)
                if partial:
                    await handler(partial)
                continue
            if not line:
                break
            await handler(line)

    async def _read_stream_full(stream: asyncio.StreamReader, handler) -> None:
        """Read entire stream (for stdout JSON output that may exceed line buffer)."""
        chunks = []
        while True:
            chunk = await stream.read(65536)  # Read in 64KB chunks
            if not chunk:
                break
            chunks.append(chunk)
        if chunks:
            await handler(b''.join(chunks))

    # Use full read for stdout (JSON output can exceed 64KB line buffer)
    # Use line-by-line for stderr (progress messages are always short lines)
    stdout_task = asyncio.create_task(_read_stream_full(proc.stdout, _handle_stdout))
    stderr_task = asyncio.create_task(_read_stream_lines(proc.stderr, _handle_stderr))

    await proc.wait()
    for task in (watchdog_task, cancel_task):
        task.cancel()
        try:
            await task
        except BaseException:
            pass  # CancelledError is BaseException in Python 3.8+
    await stdout_task
    await stderr_task

    stdout_text = b"".join(stdout_chunks).decode(errors="replace") if stdout_chunks else ""
    stderr_text = "\n".join(stderr_lines)

    try:
        result = json.loads(stdout_text)
    except json.JSONDecodeError:
        if timeout_reason and checkpoint_file and checkpoint_file.exists():
            try:
                with open(checkpoint_file) as f:
                    checkpoint_data = json.load(f)
                partial = checkpoint_data.get("report")
                if partial:
                    # Reaching the time budget with recovered partial results is a
                    # soft success, not a failure: surface it as partial/timed-out
                    # in metadata (NOT result['error']) so the caller marks the scan
                    # 'completed' and its findings are kept. Only a timeout with no
                    # recoverable results (handled below) is a hard failure.
                    meta = partial.get("scan_metadata")
                    if not isinstance(meta, dict):
                        meta = {}
                        partial["scan_metadata"] = meta
                    meta["partial"] = True
                    meta["timed_out"] = True
                    meta["terminated_reason"] = timeout_reason
                    return partial
            except Exception:
                pass
        # Always surface a non-empty error: the caller marks a scan failed only
        # when result["error"] is truthy. A crashed/silent scanner (no JSON, no
        # stderr, no timeout) must not be mislabeled "completed".
        return {
            'error': (
                cancel_reason
                or timeout_reason
                or stderr_text
                or f"Scanner produced no output (exit code {proc.returncode})"
            ),
            'target': target,
            'exit_code': proc.returncode
        }

    if stderr_text:
        print(stderr_text, flush=True)
        # Preserve a trimmed copy in scan metadata for troubleshooting.
        if isinstance(result, dict):
            scan_metadata = result.get("scan_metadata")
            if isinstance(scan_metadata, dict):
                scan_metadata.setdefault("scanner_stderr", stderr_text[-20000:])
            else:
                result["scan_metadata"] = {"scanner_stderr": stderr_text[-20000:]}

    # Clean up checkpoint file on successful completion
    if checkpoint_file and checkpoint_file.exists():
        try:
            checkpoint_file.unlink()
        except Exception:
            pass

    return result


async def run_discovery(root_domain: str) -> dict:
    """Execute subdomain discovery."""
    cmd = ['python3', SCANNER_PATH, root_domain, '--subfinder', '--quick']

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    try:
        result = json.loads(stdout.decode())
        return {
            'subdomains': result.get('subdomains', []),
            'by_source': result.get('by_source', {}),
            'total': result.get('subdomain_count', 0)
        }
    except json.JSONDecodeError:
        return {
            'error': stderr.decode(),
            'root_domain': root_domain,
            'subdomains': []
        }


def generate_finding_fingerprint(finding: dict) -> str:
    """Generate a unique fingerprint for deduplication.

    Uses the full scanner ID (e.g., 'exposed_files:abc123') as fingerprint
    to ensure consistency with UI and avoid collisions from suffix-only matching.
    """
    # Prefer scanner's original ID if available (full format: "tool:hash")
    scanner_id = finding.get('id', '')
    if scanner_id:
        return scanner_id

    # Fallback to computed fingerprint for findings without scanner ID
    key_parts = [
        finding.get('title', ''),
        finding.get('tool', ''),
        finding.get('url', ''),
        finding.get('cwe', '')
    ]
    key_string = '|'.join(str(p) for p in key_parts)
    return hashlib.sha256(key_string.encode()).hexdigest()[:16]


async def save_findings(scan_id: str, target_id: str, findings: list) -> int:
    """Save findings to database with deduplication. Returns count of saved findings."""
    if not findings:
        return 0

    saved = 0
    target_uuid = uuid.UUID(target_id)
    scan_uuid = uuid.UUID(scan_id)

    async with db_pool.acquire() as conn:
        for finding in findings:
            fingerprint = generate_finding_fingerprint(finding)
            evidence_with_triage = _build_evidence_with_triage(finding)
            evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
            ai_recommendations_json = json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None
            ai_classification_source = finding.get('ai_classification_source')
            finding_tool = finding.get('tool')
            finding_source = finding.get('source') or ('model_intake' if finding_tool == 'model_intake' else None)
            scan_verification_status, scan_verification_verdict, scan_verification_confidence = _scan_time_verification_fields(finding)

            # Wrap each finding in a transaction so the SELECT-then-INSERT race
            # between concurrent workers (e.g. a retest + scheduled scan) is
            # serialised. The UNIQUE(target_id, fingerprint) index added in
            # run_schema_migrations is the ultimate guard; on the race-loser
            # side we fall back to UPDATE rather than crashing.
            async with conn.transaction():
                existing = await conn.fetchrow("""
                    SELECT id, status, resurfaced_count, title, tool, cwe, evidence
                    FROM findings
                    WHERE target_id = $1 AND fingerprint = $2
                    FOR UPDATE
                """, target_uuid, fingerprint)

                if existing:
                    # Canonicalize JSON so cosmetic key-order/whitespace differences
                    # (PG JSONB does not preserve key order on read-back) do not
                    # falsely fire verification_signature_changed and churn
                    # last_verification_* on every re-scan.
                    existing_evidence = _canonicalize_jsonish(existing['evidence'])
                    new_evidence = _canonicalize_jsonish(evidence_json)
                    verification_signature_changed = (
                        existing['title'] != finding.get('title') or
                        existing['tool'] != finding_tool or
                        existing['cwe'] != finding.get('cwe') or
                        existing_evidence != new_evidence
                    )
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
                                source = COALESCE($18, source),
                                last_verification_status = CASE WHEN $20::text IS NOT NULL THEN $20 ELSE CASE WHEN $19 THEN NULL ELSE last_verification_status END END,
                                last_verification_verdict = CASE WHEN $21::text IS NOT NULL THEN $21 ELSE CASE WHEN $19 THEN NULL ELSE last_verification_verdict END END,
                                last_verification_confidence = CASE WHEN $21::text IS NOT NULL THEN $22 ELSE CASE WHEN $19 THEN NULL ELSE last_verification_confidence END END,
                                last_verified_at = CASE WHEN $21::text IS NOT NULL THEN NOW() ELSE CASE WHEN $19 THEN NULL ELSE last_verified_at END END,
                                updated_at = NOW()
                            WHERE id = $23
                        """,
                            existing['resurfaced_count'] + 1,
                            scan_uuid,
                            finding.get('title'),
                            finding.get('description'),
                            finding.get('severity', 'info'),
                            finding.get('cvss_score'),
                            finding_tool,
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
                            finding_source,
                            verification_signature_changed,
                            scan_verification_status,
                            scan_verification_verdict,
                            scan_verification_confidence,
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
                                source = COALESCE($17, source),
                                last_verification_status = CASE WHEN $19::text IS NOT NULL THEN $19 ELSE CASE WHEN $18 THEN NULL ELSE last_verification_status END END,
                                last_verification_verdict = CASE WHEN $20::text IS NOT NULL THEN $20 ELSE CASE WHEN $18 THEN NULL ELSE last_verification_verdict END END,
                                last_verification_confidence = CASE WHEN $20::text IS NOT NULL THEN $21 ELSE CASE WHEN $18 THEN NULL ELSE last_verification_confidence END END,
                                last_verified_at = CASE WHEN $20::text IS NOT NULL THEN NOW() ELSE CASE WHEN $18 THEN NULL ELSE last_verified_at END END,
                                updated_at = NOW()
                            WHERE id = $22
                        """,
                            scan_uuid,
                            finding.get('title'),
                            finding.get('description'),
                            finding.get('severity', 'info'),
                            finding.get('cvss_score'),
                            finding_tool,
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
                            finding_source,
                            verification_signature_changed,
                            scan_verification_status,
                            scan_verification_verdict,
                            scan_verification_confidence,
                            existing['id'],
                        )
                    saved += 1
                else:
                    # Use ON CONFLICT as a belt-and-braces guard: if a
                    # concurrent worker inserted the same (target_id, fingerprint)
                    # between our SELECT and INSERT, the UNIQUE index would
                    # otherwise raise UniqueViolationError and abort the
                    # transaction. ON CONFLICT DO NOTHING lets us treat the
                    # race-loser path as "already saved" without crashing the
                    # whole save_findings batch.
                    result = await conn.fetchval("""
                        INSERT INTO findings (
                            scan_id, target_id, fingerprint, title, description,
                            severity, cvss_score, tool, cwe, cwe_name, owasp,
                            url, evidence, ai_verdict, ai_confidence, ai_rationale, ai_recommendations,
                            ai_classification_source, source, last_verification_status,
                            last_verification_verdict, last_verification_confidence, last_verified_at
                        ) VALUES (
                            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                            $14, $15, $16, $17, $18, $19, $20, $21, $22,
                            CASE WHEN $21::text IS NOT NULL THEN NOW() ELSE NULL END
                        )
                        ON CONFLICT (target_id, fingerprint) WHERE target_id IS NOT NULL DO NOTHING
                        RETURNING id
                    """,
                        scan_uuid,
                        target_uuid,
                        fingerprint,
                        finding.get('title'),
                        finding.get('description'),
                        finding.get('severity', 'info'),
                        finding.get('cvss_score'),
                        finding_tool,
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
                        finding_source,
                        scan_verification_status,
                        scan_verification_verdict,
                        scan_verification_confidence,
                    )
                    if result:
                        saved += 1

    return saved


async def save_ai_findings(scan_id: str, ai_target_id: str, findings: list) -> int:
    """Save AI Gate findings against an AI target."""
    if not findings:
        return 0

    saved = 0
    ai_target_uuid = uuid.UUID(ai_target_id)
    scan_uuid = uuid.UUID(scan_id)

    async with db_pool.acquire() as conn:
        for finding in findings:
            fingerprint = generate_finding_fingerprint(finding)
            evidence_with_triage = _build_evidence_with_triage(finding)
            evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
            ai_recommendations_json = json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None

            existing = await conn.fetchrow("""
                SELECT id, status, resurfaced_count
                FROM findings
                WHERE ai_target_id = $1 AND fingerprint = $2
            """, ai_target_uuid, fingerprint)

            common_values = (
                scan_uuid,
                finding.get('title'),
                finding.get('description'),
                finding.get('severity', 'info'),
                finding.get('cvss_score'),
                finding.get('tool') or 'ai_gate',
                finding.get('cwe'),
                finding.get('cwe_name'),
                finding.get('owasp'),
                finding.get('url'),
                evidence_json,
                finding.get('ai_verdict'),
                finding.get('ai_confidence'),
                finding.get('ai_rationale'),
                ai_recommendations_json,
                finding.get('ai_classification_source'),
            )

            if existing:
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
                            source = 'ai_gate',
                            updated_at = NOW()
                        WHERE id = $18
                    """, existing['resurfaced_count'] + 1, *common_values, existing['id'])
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
                            source = 'ai_gate',
                            updated_at = NOW()
                        WHERE id = $17
                    """, *common_values, existing['id'])
                saved += 1
                continue

            result = await conn.fetchval("""
                INSERT INTO findings (
                    scan_id, target_id, ai_target_id, fingerprint, title, description,
                    severity, cvss_score, tool, cwe, cwe_name, owasp,
                    url, evidence, ai_verdict, ai_confidence, ai_rationale,
                    ai_recommendations, ai_classification_source, source
                ) VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, 'ai_gate')
                RETURNING id
            """,
                scan_uuid,
                ai_target_uuid,
                fingerprint,
                finding.get('title'),
                finding.get('description'),
                finding.get('severity', 'info'),
                finding.get('cvss_score'),
                finding.get('tool') or 'ai_gate',
                finding.get('cwe'),
                finding.get('cwe_name'),
                finding.get('owasp'),
                finding.get('url'),
                evidence_json,
                finding.get('ai_verdict'),
                finding.get('ai_confidence'),
                finding.get('ai_rationale'),
                ai_recommendations_json,
                finding.get('ai_classification_source'),
            )
            if result:
                saved += 1

    return saved


def _ai_finding_matches_retest(finding: dict[str, Any], replay_plan: dict[str, Any]) -> bool:
    evidence = parse_json_field(finding.get("evidence")) or {}
    source_finding_id = str(finding.get("source_finding_id") or evidence.get("source_finding_id") or "")
    expected_source_id = str(replay_plan.get("source_finding_id") or "")
    if expected_source_id and source_finding_id == expected_source_id:
        return True
    probe_id = str(evidence.get("probe_id") or "")
    expected_probe_id = str(replay_plan.get("probe_id") or "")
    if expected_probe_id and probe_id == expected_probe_id:
        return True
    probe_family = str(evidence.get("probe_family") or evidence.get("strategy_id") or finding.get("type") or "")
    expected_family = str(replay_plan.get("probe_family") or "")
    return bool(replay_plan.get("mode") == "same_family" and expected_family and probe_family == expected_family)


def _ai_retest_confidence(findings: list[dict[str, Any]]) -> float | None:
    values: list[float] = []
    for finding in findings:
        value = finding.get("ai_confidence", finding.get("confidence"))
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return round(max(values), 2) if values else None


async def finalize_ai_finding_retest(
    *,
    options: dict[str, Any],
    result: dict[str, Any],
    scan_id: str,
    completed_at: datetime,
    error: str | None,
) -> None:
    replay_plan = options.get("ai_finding_retest") if isinstance(options.get("ai_finding_retest"), dict) else None
    if not replay_plan:
        return
    verification_id = replay_plan.get("verification_id")
    finding_id = replay_plan.get("finding_id")
    if not verification_id or not finding_id:
        return

    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
    matched_findings = [
        finding for finding in findings if isinstance(finding, dict) and _ai_finding_matches_retest(finding, replay_plan)
    ]
    ai_errors = ai_gate.get("errors") if isinstance(ai_gate.get("errors"), list) else []
    if error:
        status = "failed"
        result_status = "error"
        verdict = "error"
        verdict_reason = error
        confidence = None
    elif matched_findings:
        status = "completed"
        result_status = "still_vulnerable"
        verdict = "exploited"
        verdict_reason = "Focused AI Gate replay reproduced the matching finding."
        confidence = _ai_retest_confidence(matched_findings)
    elif ai_errors:
        status = "completed"
        result_status = "inconclusive"
        verdict = "inconclusive"
        verdict_reason = "Focused AI Gate replay completed with execution errors and did not reproduce the finding."
        confidence = None
    else:
        status = "completed"
        result_status = "likely_fixed"
        verdict = "likely_fixed"
        verdict_reason = "Focused AI Gate replay did not reproduce the matching finding."
        confidence = 0.80

    proof = {
        "scan_id": scan_id,
        "probe_id": replay_plan.get("probe_id"),
        "probe_family": replay_plan.get("probe_family"),
        "matched_finding_count": len(matched_findings),
        "matched_findings": matched_findings[:5],
        "execution_errors": ai_errors[:5],
        "decision": ai_gate.get("decision"),
    }
    artifacts = {
        "transcripts": (ai_gate.get("transcripts") or [])[:5] if isinstance(ai_gate, dict) else [],
        "coverage_matrix": ai_gate.get("coverage_matrix") if isinstance(ai_gate, dict) else None,
    }
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE finding_verifications
            SET status = $1,
                result_status = $2,
                verdict = $3,
                verdict_reason = $4,
                proof = $5,
                artifacts = $6,
                confidence = $7,
                verification_mode = 'ai_driven',
                ai_plan = $8,
                ai_reasoning = $9,
                completed_at = $10,
                updated_at = NOW()
            WHERE id = $11
            """,
            status,
            result_status,
            verdict,
            verdict_reason,
            json.dumps(proof),
            json.dumps(artifacts),
            confidence,
            json.dumps(replay_plan),
            verdict_reason,
            completed_at,
            uuid.UUID(str(verification_id)),
        )
        await conn.execute(
            """
            UPDATE findings
            SET last_verification_status = $1,
                last_verification_verdict = $2,
                last_verification_confidence = $3,
                last_verified_at = $4,
                updated_at = NOW()
            WHERE id = $5
            """,
            result_status,
            verdict,
            confidence,
            completed_at,
            uuid.UUID(str(finding_id)),
        )


def _is_internal_target(url: str) -> bool:
    """Heuristic check for internal-only hosts."""
    if not url:
        return False

    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
    except Exception:
        host = str(url).lower()

    if not host:
        return False

    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True

    try:
        ip_obj = ipaddress.ip_address(host)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return True
    except ValueError:
        pass

    return False


def _detect_security_block_text(*parts: str | None) -> bool:
    """Best-effort detection for WAF/edge blocks from response text."""
    merged = " ".join([p for p in parts if p]).lower()
    if not merged:
        return False

    patterns = (
        "forbidden",
        "access denied",
        "request blocked",
        "blocked by",
        "blocked",
        "waf",
        "modsecurity",
        "cloudflare",
        "security policy",
        "captcha",
        "too many requests",
        "rate limit",
        "not allowed",
    )
    return any(p in merged for p in patterns)


def classify_retest_outcome(
    *,
    proof: dict | None,
    proven: bool,
    confidence: float | None,
    inputs: dict,
    error_message: str | None = None,
) -> tuple[str, str, str]:
    """
    Return (result_status, verdict, verdict_reason).

    result_status keeps backwards-compatible semantics.
    verdict introduces Shannon-style classification.
    """
    if proven:
        return (
            "still_vulnerable",
            "exploited",
            "Proof-of-exploit succeeded and impact was reproduced.",
        )

    if error_message:
        return (
            "error",
            "error",
            f"Retest execution error: {error_message}",
        )

    evidence_type = str((proof or {}).get("evidence_type") or "")
    response_snippet = str((proof or {}).get("response_snippet") or "")
    extracted_data = str((proof or {}).get("extracted_data") or "")
    target_url = str(inputs.get("original_url") or inputs.get("target_url") or "")

    if _is_internal_target(target_url):
        return (
            "inconclusive",
            "out_of_scope_internal",
            "Target appears internal/private and could require internal network access.",
        )

    if _detect_security_block_text(response_snippet, extracted_data):
        return (
            "inconclusive",
            "blocked_by_security",
            "Exploit path appears blocked by security controls or edge filtering.",
        )

    if evidence_type in {"no_url", "unsupported_vulnerability_type"}:
        # Missing replay context is "we could not verify", NOT proof the finding
        # was invalid. false_positive must be reserved for objective FP evidence.
        return (
            "inconclusive",
            "inconclusive",
            "Finding lacks replayable exploit context for this verifier; could not verify.",
        )

    if evidence_type in {"catch_all_server", "shape_match_over_catch_all", "ambiguous_200_response"}:
        return (
            "inconclusive",
            "inconclusive",
            "Retest could not distinguish the original exposure from a catch-all or ambiguous HTTP 200 response.",
        )

    if confidence is not None and confidence <= 0.2:
        # No exploit evidence reproduced, but a non-reproduction at low confidence
        # is inconclusive — it is not objective proof the original finding was a
        # false positive. Returning false_positive here mislabels timeouts and
        # weak replays as terminal FPs.
        return (
            "inconclusive",
            "inconclusive",
            "Retest reproduced no exploit evidence (low confidence); inconclusive.",
        )

    return (
        "likely_fixed",
        "likely_fixed",
        "Retest could not reproduce exploit behavior with available inputs.",
    )


def _result_status_for_verdict(verdict: str | None) -> str:
    """Map normalized verdicts to backwards-compatible result_status values."""
    v = str(verdict or "").lower()
    if v == "exploited":
        return "still_vulnerable"
    if v == "likely_fixed":
        return "likely_fixed"
    if v in {"likely_vulnerable", "false_positive", "inconclusive", "blocked_by_security", "out_of_scope_internal"}:
        return "inconclusive"
    return "error"


# A false_positive verdict must be backed by high-confidence objective evidence.
FALSE_POSITIVE_MIN_CONFIDENCE = 0.7
PARTIAL_EVIDENCE_MIN_CONFIDENCE = 0.3

NON_VULNERABILITY_EVIDENCE_TYPES: frozenset[str] = frozenset({
    "",
    "no_url",
    "unsupported_vulnerability_type",
    "catch_all_server",
    "shape_match_over_catch_all",
    "ambiguous_200_response",
    "access_denied",
    "not_found",
    "sensitive_markers_absent",
    "soft_404_page",
    "content_replaced_with_html",
})


def _enforce_verdict_invariants(result: dict[str, Any]) -> dict[str, Any]:
    """Guarantee the persisted verdict is internally consistent.

    A ``false_positive`` verdict asserts the original finding was invalid, so it
    must carry high-confidence evidence. A low/no-confidence "false_positive"
    (a deterministic non-reproduction, or an AI error/timeout) is downgraded to
    ``inconclusive`` so the UI never shows a terminal "False positive" at 0%
    confidence. This is the single enforcement point regardless of code path.
    """
    verdict = str(result.get("verdict") or "").lower()
    if verdict == "false_positive":
        try:
            conf_val = float(result.get("confidence")) if result.get("confidence") is not None else 0.0
        except (TypeError, ValueError):
            conf_val = 0.0
        if conf_val < FALSE_POSITIVE_MIN_CONFIDENCE:
            result["verdict"] = "inconclusive"
            result["result_status"] = "inconclusive"
            result["verdict_reason"] = (
                "Retest could not confirm the original finding is invalid; "
                "treating as inconclusive (insufficient confidence for false positive)."
            )
    return result


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _is_partial_vulnerability_signal(candidate: dict[str, Any] | None) -> bool:
    """Return true only for actual partial exploit evidence.

    Attempting a prover is not evidence. The candidate must carry a meaningful
    non-benign evidence type or technique with non-trivial confidence.
    """
    if not isinstance(candidate, dict):
        return False
    if candidate.get("proven"):
        return True
    confidence = _as_float(candidate.get("confidence"), 0.0)
    if confidence < PARTIAL_EVIDENCE_MIN_CONFIDENCE:
        return False
    evidence_type = str(candidate.get("evidence_type") or "").strip().lower()
    if evidence_type and evidence_type not in NON_VULNERABILITY_EVIDENCE_TYPES:
        return True
    technique = str(candidate.get("technique") or "").strip()
    return bool(technique and evidence_type not in NON_VULNERABILITY_EVIDENCE_TYPES)


def _has_partial_deterministic_evidence(result: dict[str, Any]) -> bool:
    """Whether an inconclusive deterministic replay found partial vuln evidence."""
    proof = result.get("proof")
    if _is_partial_vulnerability_signal(proof if isinstance(proof, dict) else None):
        return True
    artifacts = result.get("artifacts")
    step_attempts = (
        artifacts.get("step_attempts")
        if isinstance(artifacts, dict) and isinstance(artifacts.get("step_attempts"), list)
        else []
    )
    return any(
        _is_partial_vulnerability_signal(attempt if isinstance(attempt, dict) else None)
        for attempt in step_attempts
    )


def _merge_ai_result_into_retest_result(result: dict[str, Any], ai_result: dict[str, Any]) -> dict[str, Any]:
    """
    Merge AI verdict into deterministic retest result.

    AI can upgrade or clarify inconclusive/error deterministic outcomes. When AI
    provides a supported verdict, treat the verification as completed.
    """
    if not isinstance(ai_result, dict):
        return result

    ai_verdict = str(ai_result.get("verdict") or "").lower()
    if not ai_verdict:
        return result

    current_verdict = str(result.get("verdict") or "").lower()

    # Always trust explicit AI exploit confirmation.
    if ai_verdict == "exploited":
        result["status"] = "completed"
        result["result_status"] = "still_vulnerable"
        result["verdict"] = "exploited"
        result["verdict_reason"] = ai_result.get("reasoning", "AI verification confirmed vulnerability")
        result["confidence"] = ai_result.get("confidence")
        result["verification_mode"] = "ai_driven"
        return result

    ai_confidence = ai_result.get("confidence")
    ai_high_conf = isinstance(ai_confidence, (int, float)) and float(ai_confidence) >= FALSE_POSITIVE_MIN_CONFIDENCE

    # An AI "false_positive" only stands when it is high-confidence. A timeout,
    # error, or low-confidence AI guess (which surfaces as false_positive or
    # inconclusive) must not stamp the finding as a terminal false positive —
    # downgrade it to inconclusive so it stays active and retryable.
    if ai_verdict == "false_positive" and not ai_high_conf:
        ai_verdict = "inconclusive"
        ai_result = {**ai_result, "verdict": "inconclusive"}

    # Only replace deterministic outcomes when they were inconclusive or failed.
    # A strong deterministic conclusion (exploited / likely_fixed / likely_vulnerable
    # / objective false_positive) survives even an AI error or timeout.
    if current_verdict not in {"", "error", "inconclusive"}:
        return result

    result["status"] = "completed"
    result["verification_mode"] = "ai_driven"
    result["verdict"] = ai_verdict
    result["verdict_reason"] = ai_result.get("reasoning", "")
    result["confidence"] = ai_confidence
    result["result_status"] = _result_status_for_verdict(ai_verdict)
    return _enforce_verdict_invariants(result)


def _severity_allows_auto_retest(severity: str, min_severity: str) -> bool:
    min_rank = SEVERITY_ORDER.get(min_severity, SEVERITY_ORDER["high"])
    sev_rank = SEVERITY_ORDER.get(str(severity or "").lower(), 0)
    return sev_rank >= min_rank


def _try_acquire_retest_slot(r) -> bool:
    active = r.incr(RETEST_SLOT_KEY)
    if active <= RETEST_MAX_PARALLEL:
        r.expire(RETEST_SLOT_KEY, RETEST_SLOT_TTL_SECONDS)
        return True
    r.decr(RETEST_SLOT_KEY)
    return False


def _release_retest_slot(r) -> None:
    try:
        remaining = r.decr(RETEST_SLOT_KEY)
        if remaining <= 0:
            r.delete(RETEST_SLOT_KEY)
    except Exception:
        pass


def _parallel_shard_slot_key(parent_id: str) -> str:
    return f"scan:{parent_id}:active_shards"


def _parallel_shard_concurrency_limit(options: dict[str, Any] | None = None) -> int:
    raw = None
    if isinstance(options, dict):
        if options.get("shard_concurrency") is not None:
            raw = options.get("shard_concurrency")
        elif options.get("parallel_shard_concurrency") is not None:
            raw = options.get("parallel_shard_concurrency")
    if raw is None:
        raw = PARALLEL_SHARD_MAX_PER_PARENT
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = PARALLEL_SHARD_MAX_PER_PARENT
    return max(1, min(PARALLEL_SHARD_CONCURRENCY_HARD_MAX, limit))


def _try_acquire_parallel_shard_slot(r, parent_id: str | None, options: dict[str, Any] | None = None) -> tuple[bool, int]:
    if not parent_id:
        return True, 0
    limit = _parallel_shard_concurrency_limit(options)
    key = _parallel_shard_slot_key(parent_id)
    active = r.incr(key)
    if active <= limit:
        r.expire(key, PARALLEL_SHARD_SLOT_TTL_SECONDS)
        return True, limit
    r.decr(key)
    return False, limit


def _release_parallel_shard_slot(r, parent_id: str | None) -> None:
    if not parent_id:
        return
    key = _parallel_shard_slot_key(parent_id)
    try:
        remaining = r.decr(key)
        if remaining <= 0:
            r.delete(key)
    except Exception:
        pass


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    if row is None:
        return default
    try:
        return row[key]
    except Exception:
        try:
            return row.get(key, default)
        except Exception:
            return default


def _known_endpoint_count(options: dict[str, Any] | None) -> int:
    endpoints = (options or {}).get("custom_endpoints") if isinstance(options, dict) else None
    return len(endpoints) if isinstance(endpoints, list) else 0


async def _reserve_target_domain_endpoint_budget(
    conn,
    r,
    *,
    target_id: str | None,
    amount: int,
    already_reserved: int = 0,
    all_or_nothing: bool = False,
) -> dict[str, Any]:
    """Reserve known-endpoint execution budget for a target root domain.

    The cap lives in the target's ASM config and is enforced by combining
    completed endpoint attempts from Postgres with in-flight reservations in
    Redis. This is intentionally endpoint-count based because that is the
    durable unit Full Coverage and ASM allocators can prove before execution.
    """
    try:
        amount = max(0, int(amount or 0))
        already_reserved = max(0, int(already_reserved or 0))
    except (TypeError, ValueError):
        amount = 0
        already_reserved = 0
    if amount <= 0:
        return {"granted": 0, "limited": False, "reason": "no_known_endpoints"}
    if not target_id:
        return {"granted": amount, "limited": False, "reason": "no_target_id"}
    try:
        tid = uuid.UUID(str(target_id))
    except (TypeError, ValueError):
        return {"granted": amount, "limited": False, "reason": "invalid_target_id"}

    row = await conn.fetchrow("SELECT root_domain, asm_config FROM targets WHERE id = $1", tid)
    root_domain = str(_row_get(row, "root_domain") or "").strip().lower()
    cfg = asm_inventory.merge_asm_config(parse_json_field(_row_get(row, "asm_config")) or {})
    cap = int(cfg.get("max_requests_per_hour_per_domain") or 0)
    if not root_domain or cap <= 0:
        return {"granted": amount, "limited": False, "reason": "unlimited", "root_domain": root_domain, "cap": cap}

    used = await asm_inventory.domain_tested_recently_count(conn, root_domain, hours=1)
    remaining_cap = max(0, cap - int(used or 0))
    needed = max(0, amount - already_reserved)
    granted_new = asm_inventory.reserve_domain_rate(
        r,
        root_domain,
        remaining_cap,
        needed,
        all_or_nothing=all_or_nothing,
    )
    granted = min(amount, already_reserved + granted_new)
    return {
        "granted": granted,
        "limited": granted < amount,
        "root_domain": root_domain,
        "cap": cap,
        "used": int(used or 0),
        "reserved": asm_inventory.reserved_domain_rate_count(r, root_domain),
        "already_reserved": already_reserved,
        "requested": amount,
        "reason": "reserved" if granted >= amount else "domain_rate_limited",
    }


async def _requeue_for_domain_rate(
    r,
    job_data: dict[str, Any],
    *,
    job_id: str,
    scan_id: str | None,
    parent_id: str | None = None,
    log_prefix: str,
    rate: dict[str, Any],
) -> None:
    wait_cycles = int(job_data.get("domain_rate_wait_cycles") or 0) + 1
    requeued = dict(job_data)
    requeued["domain_rate_wait_cycles"] = wait_cycles
    requeued["last_domain_rate_wait_at"] = utc_now_iso()
    r.rpush(QUEUE_NAME, json.dumps(requeued))
    mapping = {
        "status": "queued",
        "scan_id": scan_id or "",
        "current_phase": "waiting_for_domain_rate",
        "domain_rate_wait_cycles": str(wait_cycles),
        "domain_rate_root_domain": str(rate.get("root_domain") or ""),
        "domain_rate_requested": str(rate.get("requested") or ""),
        "domain_rate_granted": str(rate.get("granted") or 0),
        "domain_rate_cap": str(rate.get("cap") or ""),
    }
    if parent_id:
        mapping["parent_scan_id"] = parent_id
    r.hset(f"job:{job_id}", mapping=mapping)
    r.expire(f"job:{job_id}", 86400)
    print(
        f"[{log_prefix}] waiting for domain rate budget "
        f"({rate.get('root_domain') or 'unknown'}: granted {rate.get('granted') or 0}/"
        f"{rate.get('requested') or 0}, cap={rate.get('cap') or 'unlimited'})",
        flush=True,
    )
    await asyncio.sleep(DOMAIN_RATE_REQUEUE_DELAY_SECONDS)


async def _release_claimed_endpoints_for_domain_rate(conn, endpoint_ids: list[Any]) -> None:
    if not endpoint_ids:
        return
    await conn.execute(
        """UPDATE target_endpoints
           SET test_status='stale', last_attempt_status='rate_limited',
               lease_owner=NULL, lease_expires_at=NULL, updated_at=NOW()
           WHERE id = ANY($1::uuid[]) AND test_status='in_progress'""",
        endpoint_ids,
    )


def _parse_iso_datetime(raw: Any) -> datetime | None:
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def _slot_wait_state(job_data: dict[str, Any], now: datetime) -> tuple[datetime, int, int]:
    """
    Return (wait_started_at, wait_cycles, waited_seconds) for slot contention handling.
    """
    wait_started_at = _parse_iso_datetime(job_data.get("slot_wait_started_at")) or now
    try:
        previous_cycles = int(job_data.get("slot_wait_cycles") or 0)
    except (TypeError, ValueError):
        previous_cycles = 0
    wait_cycles = max(1, previous_cycles + 1)
    waited_seconds = max(0, int((now - wait_started_at).total_seconds()))
    return wait_started_at, wait_cycles, waited_seconds


def _slot_wait_backoff_seconds(wait_cycles: int) -> int:
    base = max(1, RETEST_REQUEUE_DELAY_SECONDS)
    # Exponential backoff with cap to avoid hot-loop queue churn under saturation.
    return max(1, min(base * (2 ** min(max(wait_cycles - 1, 0), 4)), 30))


RETRYABLE_AI_ERROR_PATTERNS: tuple[str, ...] = (
    "network error",
    "connection",
    "connection closed",
    "connection reset",
    "timeout",
    "timed out",
    "temporarily unavailable",
    "rate limit",
    "overloaded",
    "server_error",
    "internal server error",
    "service unavailable",
    "bad gateway",
    "capacity",
    "429",
    "500",
    "502",
    "503",
    "504",
)

NON_RETRYABLE_AI_ERROR_PATTERNS: tuple[str, ...] = (
    "401",
    "403",
    "invalid_api_key",
    "invalid api key",
    "unauthorized",
    "model_not_found",
    "model not found",
    "content_policy",
    "content policy",
    "billing",
    "quota exceeded",
)


def _is_non_retryable_ai_error(error_text: str | None) -> bool:
    text = str(error_text or "").strip().lower()
    if not text:
        return False
    return any(pattern in text for pattern in NON_RETRYABLE_AI_ERROR_PATTERNS)


def _is_retryable_ai_error(error_text: str | None) -> bool:
    text = str(error_text or "").strip().lower()
    if not text:
        return False
    if _is_non_retryable_ai_error(text):
        return False
    return any(pattern in text for pattern in RETRYABLE_AI_ERROR_PATTERNS)


def _should_open_ai_circuit(error_count: int) -> bool:
    return int(error_count) >= RETEST_AI_CIRCUIT_ERROR_THRESHOLD


def _is_ai_circuit_open(open_until: datetime | None, now: datetime) -> bool:
    return bool(open_until and open_until > now)


def _get_ai_circuit_state(r, now: datetime) -> dict[str, Any]:
    state: dict[str, Any] = {"error_count": 0, "open_until": None, "is_open": False}
    try:
        raw = _decode_redis_hash(r.hgetall(RETEST_AI_CIRCUIT_KEY))
    except Exception:
        return state
    try:
        state["error_count"] = max(0, int(raw.get("error_count") or 0))
    except (TypeError, ValueError):
        state["error_count"] = 0
    state["open_until"] = _parse_iso_datetime(raw.get("open_until"))
    state["is_open"] = _is_ai_circuit_open(state["open_until"], now)
    return state


def _register_ai_circuit_failure(r, error_text: str, now: datetime) -> tuple[bool, int]:
    if not _is_retryable_ai_error(error_text):
        return False, 0

    try:
        error_count = max(0, int(r.hincrby(RETEST_AI_CIRCUIT_KEY, "error_count", 1)))
        r.hset(
            RETEST_AI_CIRCUIT_KEY,
            mapping={
                "last_error": str(error_text)[:400],
                "last_error_at": now.isoformat(),
            },
        )
        if _should_open_ai_circuit(error_count):
            open_until = now + timedelta(seconds=RETEST_AI_CIRCUIT_COOLDOWN_SECONDS)
            r.hset(
                RETEST_AI_CIRCUIT_KEY,
                mapping={
                    "open_until": open_until.isoformat(),
                    "opened_at": now.isoformat(),
                },
            )
            r.expire(RETEST_AI_CIRCUIT_KEY, max(RETEST_AI_CIRCUIT_WINDOW_SECONDS, RETEST_AI_CIRCUIT_COOLDOWN_SECONDS * 2))
            return True, error_count
        r.expire(RETEST_AI_CIRCUIT_KEY, RETEST_AI_CIRCUIT_WINDOW_SECONDS)
        return False, error_count
    except Exception:
        return False, 0


def _clear_ai_circuit_state(r) -> None:
    try:
        r.delete(RETEST_AI_CIRCUIT_KEY)
        # Signal that blocked retests should be re-queued on next watchdog cycle
        r.set("retest:ai:circuit_recovered", "1", ex=120)
    except Exception:
        pass


def _stale_retest_should_requeue(attempt_count: int) -> bool:
    return int(attempt_count) <= RETEST_STALE_REQUEUE_LIMIT


def _current_retest_capabilities() -> dict[str, bool]:
    """
    Snapshot proof-engine capabilities for standardized observability.

    This keeps report keys stable even when scanner runtime dependencies differ
    across worker images/environments.
    """
    capabilities = {finding_type: False for finding_type in SUPPORTED_RETEST_TYPES}
    try:
        from scanner_tools import proof_of_exploit as poe
    except Exception:
        return capabilities

    func_map = {
        "xss": "prove_xss",
        "sqli": "prove_sqli",
        "ssrf": "prove_ssrf",
        "path_traversal": "prove_path_traversal",
        "open_redirect": "prove_open_redirect",
        "cors": "prove_cors",
        "command_injection": "prove_command_injection",
        "ssti": "prove_ssti",
        "xxe": "prove_xxe",
        "jwt": "prove_jwt",
        "idor": "prove_bola",
        "bola": "prove_bola",
        "exposed_file": "prove_exposed_file",
    }
    # AI-only types (2fa_bypass, generic_http) keep False: there is no
    # deterministic prover, the AI verification tier handles them.
    for finding_type, func_name in func_map.items():
        capabilities[finding_type] = callable(getattr(poe, func_name, None))
    return capabilities


async def run_finding_retest(verification: dict) -> dict:
    """Execute a proof-based retest for a finding verification record."""
    started_at = utc_now()
    capabilities = _current_retest_capabilities()
    try:
        from scanner_tools.proof_of_exploit import (
            end_scan_session,
            prove_bola,
            prove_command_injection,
            prove_cors,
            prove_exposed_file,
            prove_jwt,
            prove_open_redirect,
            prove_path_traversal,
            prove_sqli,
            prove_sqli_reflection_fp,
            prove_ssrf,
            prove_ssrf_oob,
            prove_ssti,
            prove_xss,
            prove_xss_headless,
            prove_xxe,
            start_scan_session,
        )
    except ImportError as e:
        replay_commands = build_replay_commands(infer_retest_inputs(verification))
        retry_class, retryable = classify_retry(str(e))
        return {
            "status": "failed",
            "result_status": "error",
            "verdict": "error",
            "verdict_reason": "Proof module unavailable in worker runtime.",
            "error_message": f"Proof module unavailable: {e}",
            "confidence": None,
            "proof": None,
            "replay_commands": replay_commands,
            "artifacts": {
                "started_at": started_at.isoformat(),
                "completed_at": utc_now_iso(),
                "failure_stage": "module_import",
                "tool_capabilities": capabilities,
            },
            "message": "Retest could not run because proof module is unavailable",
            "attempt_ladder": [],
            "attempts_exhausted": True,
            "retry_class": retry_class,
            "retryable": retryable,
        }

    inputs = infer_retest_inputs(verification)
    replay_commands = build_replay_commands(inputs)
    finding_type = inputs.get("finding_type")
    attempt_ladder = get_attempt_ladder(finding_type)
    if finding_type not in SUPPORTED_RETEST_TYPES:
        return {
            "status": "failed",
            "result_status": "error",
            "verdict": "error",
            "verdict_reason": "Finding type is unsupported by proof engine.",
            "error_message": f"Unsupported finding type: {finding_type}",
            "confidence": None,
            "proof": None,
            "replay_commands": replay_commands,
            "artifacts": {
                "started_at": started_at.isoformat(),
                "completed_at": utc_now_iso(),
                "failure_stage": "type_check",
                "finding_type": finding_type,
                "tool_capabilities": capabilities,
            },
            "message": f"Unsupported finding type: {finding_type}",
            "attempt_ladder": attempt_ladder,
            "attempts_exhausted": True,
            "retry_class": "validation",
            "retryable": False,
        }

    test_url = inputs.get("original_url") or inputs.get("target_url")
    if not test_url:
        return {
            "status": "failed",
            "result_status": "error",
            "verdict": "error",
            "verdict_reason": "Missing replay URL for verification.",
            "error_message": "Missing target/original URL for retest",
            "confidence": None,
            "proof": None,
            "replay_commands": replay_commands,
            "artifacts": {
                "started_at": started_at.isoformat(),
                "completed_at": utc_now_iso(),
                "failure_stage": "input_validation",
                "tool_capabilities": capabilities,
            },
            "message": "Missing target/original URL for retest",
            "attempt_ladder": attempt_ladder,
            "attempts_exhausted": True,
            "retry_class": "validation",
            "retryable": False,
        }

    # AI-only types (2fa_bypass, generic_http) rely on AI reasoning (Tier 2)
    # rather than a deterministic prover. Return a deterministic "inconclusive"
    # base result that explicitly allows AI escalation.
    if finding_type in AI_ONLY_RETEST_TYPES:
        completed_at = utc_now()
        has_ai_step = "ai_reasoning" in attempt_ladder
        return {
            "status": "completed",
            "result_status": "inconclusive",
            "verdict": "inconclusive",
            "verdict_reason": f"No deterministic prover available for {finding_type}; escalating to AI reasoning.",
            "error_message": None,
            "confidence": None,
            "proof": None,
            "replay_commands": replay_commands,
            "artifacts": {
                "started_at": started_at.isoformat(),
                "completed_at": completed_at.isoformat(),
                "finding_type": finding_type,
                "target_url": test_url,
                "tool_capabilities": capabilities,
                "attempt_ladder": attempt_ladder,
                "steps_tried": [],
                "step_attempts": [],
                "succeeded_step": None,
                "deterministic_skipped_reason": "ai_only_type",
            },
            "message": f"Deterministic prover unavailable for {finding_type}; AI verification required.",
            "attempt_ladder": attempt_ladder,
            "attempts_exhausted": False,
            "deterministic_exhausted": True,
            "has_ai_step": has_ai_step,
            "retry_class": "none",
            "retryable": False,
            "verification_mode": "deterministic",
        }

    verification_id = str(verification.get("id", "unknown"))
    session_id = f"retest-{verification_id}"

    # Build auth headers from verification's auth_context
    auth_ctx = parse_json_field(verification.get("auth_context"))
    auth_headers = auth_context_to_headers(auth_ctx) if auth_ctx else None

    # Deterministic reflection check (SQLi): a finding whose parameter merely
    # echoes input — with no real SQL execution — is an objective false positive.
    # Settle it here without spending an AI call, so reflection FPs are cleared
    # reliably even when the AI provider is unavailable.
    if finding_type == "sqli":
        try:
            fp_proof = await prove_sqli_reflection_fp(
                test_url, inputs.get("param", ""), headers=auth_headers,
            )
        except Exception as _refl_err:
            fp_proof = None
        if fp_proof is not None and getattr(fp_proof, "is_false_positive", False):
            fp_data = fp_proof.to_dict()
            completed_at = utc_now()
            return {
                "status": "completed",
                "result_status": "inconclusive",
                "verdict": "false_positive",
                "verdict_reason": fp_proof.extracted_data or "Parameter reflects input; no SQL execution.",
                "error_message": None,
                "confidence": fp_proof.confidence,
                "proof": fp_data,
                "replay_commands": replay_commands,
                "artifacts": {
                    "started_at": started_at.isoformat(),
                    "completed_at": completed_at.isoformat(),
                    "finding_type": finding_type,
                    "target_url": test_url,
                    "tool_capabilities": capabilities,
                    "technique": fp_proof.technique,
                    "evidence_type": fp_proof.evidence_type,
                    "deterministic_fp": True,
                },
                "message": "Deterministic reflection check proved the finding is a false positive.",
                "attempt_ladder": attempt_ladder,
                "attempts_exhausted": True,
                "deterministic_exhausted": True,
                # Objective evidence — do not escalate to AI.
                "has_ai_step": False,
                "retry_class": "none",
                "retryable": False,
                "verification_mode": "deterministic",
            }

    # -- Attempt ladder execution --
    # Iterate through escalating proof strategies, stop on first proven result.
    proof = None
    succeeded_step: str | None = None
    last_error: str | None = None
    steps_tried: list[str] = []
    step_attempts: list[dict[str, Any]] = []

    # Map ladder step names to prover calls via shared verification engine.
    from scanner_tools.verification_engine import dispatch_ladder_step

    _prover_map = {
        "prove_xss": prove_xss,
        "prove_xss_headless": prove_xss_headless,
        "prove_sqli": prove_sqli,
        "prove_ssrf": prove_ssrf,
        "prove_ssrf_oob": prove_ssrf_oob,
        "prove_path_traversal": prove_path_traversal,
        "prove_open_redirect": prove_open_redirect,
        "prove_cors": prove_cors,
        "prove_command_injection": prove_command_injection,
        "prove_ssti": prove_ssti,
        "prove_xxe": prove_xxe,
        "prove_jwt": prove_jwt,
        "prove_bola": prove_bola,
        "prove_exposed_file": prove_exposed_file,
    }

    def _call_prover(step_name: str):
        param = inputs.get("param", "")
        payload = inputs.get("payload") or None
        evidence = inputs.get("evidence", {})
        return dispatch_ladder_step(
            finding_type, step_name, test_url, param, payload,
            evidence=evidence,
            **_prover_map,
        )

    try:
        try:
            start_scan_session(session_id, auth_headers=auth_headers)
        except Exception:
            pass

        # If no ladder defined, do a single-shot proof call
        effective_ladder = attempt_ladder if attempt_ladder else ["default"]

        for step in effective_ladder:
            # Skip AI step here — handled by the AI verifier tier in process_finding_retest_job
            if step == "ai_reasoning":
                continue

            steps_tried.append(step)
            try:
                coro, step_meta = _call_prover(step)
                if coro is None:
                    last_error = f"No prover for finding type: {finding_type}"
                    step_attempts.append({
                        "step": step,
                        "error": last_error,
                    })
                    break
                proof = await coro
                step_attempts.append({
                    "step": step,
                    "meta": step_meta,
                    "proven": bool(getattr(proof, "proven", False)) if proof else False,
                    "confidence": getattr(proof, "confidence", None) if proof else None,
                    "technique": getattr(proof, "technique", None) if proof else None,
                    "evidence_type": getattr(proof, "evidence_type", None) if proof else None,
                })

                if proof and getattr(proof, "proven", False):
                    succeeded_step = step
                    break
            except Exception as step_err:
                last_error = str(step_err)
                step_attempts.append({
                    "step": step,
                    "error": last_error,
                })
                # Continue to next ladder step on failure
                continue

    except Exception as e:
        result_status, verdict, verdict_reason = classify_retest_outcome(
            proof=None, proven=False, confidence=None, inputs=inputs, error_message=str(e),
        )
        retry_class, retryable = classify_retry(str(e))
        return {
            "status": "failed",
            "result_status": result_status,
            "verdict": verdict,
            "verdict_reason": verdict_reason,
            "error_message": f"Retest execution failed: {e}",
            "confidence": None,
            "proof": None,
            "replay_commands": replay_commands,
            "artifacts": {
                "started_at": started_at.isoformat(),
                "completed_at": utc_now_iso(),
                "failure_stage": "execution",
                "finding_type": finding_type,
                "tool_capabilities": capabilities,
            },
            "message": "Retest execution failed",
            "attempt_ladder": attempt_ladder,
            "attempts_exhausted": True,
            "retry_class": retry_class,
            "retryable": retryable,
        }
    finally:
        try:
            end_scan_session(session_id)
        except Exception:
            pass

    proof_data = proof.to_dict() if proof else None
    still_vulnerable = bool(getattr(proof, "proven", False))
    confidence = getattr(proof, "confidence", None)

    if not still_vulnerable and last_error and not proof:
        result_status, verdict, verdict_reason = classify_retest_outcome(
            proof=None, proven=False, confidence=None, inputs=inputs, error_message=last_error,
        )
    else:
        result_status, verdict, verdict_reason = classify_retest_outcome(
            proof=proof_data, proven=still_vulnerable, confidence=confidence, inputs=inputs,
        )

    # Deterministic ladder is exhausted only when all non-AI steps have been tried
    deterministic_exhausted = not still_vulnerable and len(steps_tried) >= len([s for s in attempt_ladder if s != "ai_reasoning"])
    # Check if AI step is available but not yet tried
    has_ai_step = "ai_reasoning" in attempt_ladder

    completed_at = utc_now()
    artifacts = {
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "finding_type": finding_type,
        "target_url": test_url,
        "attempted_url": (proof_data or {}).get("request"),
        "technique": (proof_data or {}).get("technique"),
        "evidence_type": (proof_data or {}).get("evidence_type"),
        "payload_used": inputs.get("payload") or DEFAULT_REPLAY_PAYLOADS.get(finding_type),
        "tool_capabilities": capabilities,
        "attempt_ladder": attempt_ladder,
        "steps_tried": steps_tried,
        "step_attempts": step_attempts,
        "succeeded_step": succeeded_step,
    }

    return {
        "status": "completed",
        "result_status": result_status,
        "verdict": verdict,
        "verdict_reason": verdict_reason,
        "error_message": last_error if not still_vulnerable else None,
        "confidence": confidence,
        "proof": proof_data,
        "replay_commands": replay_commands,
        "artifacts": artifacts,
        "message": verdict_reason,
        "attempt_ladder": attempt_ladder,
        "attempts_exhausted": deterministic_exhausted and not has_ai_step,
        "deterministic_exhausted": deterministic_exhausted,
        "has_ai_step": has_ai_step,
        "retry_class": "none",
        "retryable": False,
        "verification_mode": "deterministic",
    }


async def process_finding_retest_job(job_data: dict):
    """Process a queued finding retest job."""
    valid, reason = validate_retest_job_payload(job_data)
    job_id = str(job_data.get("job_id", "unknown"))
    verification_id = str(job_data.get("verification_id", ""))
    try:
        attempt = max(1, int(job_data.get("attempt", 1) or 1))
    except (TypeError, ValueError):
        attempt = 1
    trigger = str(job_data.get("trigger") or "unspecified")
    requested_mode = str(job_data.get("mode") or "").strip().lower()
    r = get_redis()
    retest_key = f"retest_job:{job_id}"

    if not valid:
        r.hset(retest_key, mapping={
            "status": "failed",
            "error": f"invalid_job_payload:{reason}",
            "job_id": job_id,
        })
        r.expire(retest_key, 86400)
        print(f"[retest:{job_id[:8]}] Invalid job payload: {reason}", flush=True)
        return

    print(f"[retest:{job_id[:8]}] Starting retest {verification_id}", flush=True)
    now = utc_now()
    if not _try_acquire_retest_slot(r):
        # Wait with bounded backoff/time budget; do not consume retest attempt
        # counters just because global worker slots are currently saturated.
        wait_started_at, wait_cycles, waited_seconds = _slot_wait_state(job_data, now)
        if waited_seconds >= RETEST_SLOT_WAIT_MAX_SECONDS:
            r.hset(retest_key, mapping={
                "status": "failed",
                "verification_id": verification_id,
                "error": "retest_slot_exhausted",
                "attempt": str(attempt),
                "slot_wait_cycles": str(wait_cycles),
                "slot_waited_seconds": str(waited_seconds),
                "attempts_exhausted": "true",
            })
            r.expire(retest_key, 86400)
            async with db_pool.acquire() as conn:
                try:
                    finding_uuid = uuid.UUID(str(job_data.get("finding_id")))
                except Exception:
                    finding_uuid = None
                try:
                    await conn.execute("""
                        UPDATE finding_verifications
                        SET status = 'failed',
                            result_status = 'error',
                            verdict = 'error',
                            verdict_reason = 'Retest retries exhausted waiting for worker slot.',
                            attempt_count = $2,
                            attempts_exhausted = TRUE,
                            retry_class = 'transient',
                            retryable = FALSE,
                            error_message = $3,
                            completed_at = NOW(),
                            updated_at = NOW()
                        WHERE id = $1
                    """, uuid.UUID(verification_id), attempt, f"Retest slot wait exceeded {RETEST_SLOT_WAIT_MAX_SECONDS}s.")
                    if finding_uuid is not None:
                        await conn.execute(
                            """
                            UPDATE findings
                            SET last_verification_status = 'error',
                                last_verification_verdict = 'error',
                                last_verification_confidence = NULL,
                                last_verified_at = NOW(),
                                verification_count = COALESCE(verification_count, 0) + 1,
                                updated_at = NOW()
                            WHERE id = $1
                            """,
                            finding_uuid,
                        )
                except Exception:
                    pass
            print(
                f"[retest:{job_id[:8]}] Exhausted retest slot wait budget "
                f"({waited_seconds}s >= {RETEST_SLOT_WAIT_MAX_SECONDS}s)",
                flush=True,
            )
            return

        requeued_payload = build_retest_job_payload(
            job_id=job_id,
            verification_id=verification_id,
            finding_id=str(job_data["finding_id"]),
            submitted_at=str(job_data["submitted_at"]),
            trigger=trigger,
            attempt=attempt,
        )
        if requested_mode in {"ai", "deterministic"}:
            requeued_payload["mode"] = requested_mode
        requeued_payload["slot_wait_started_at"] = wait_started_at.isoformat()
        requeued_payload["slot_wait_cycles"] = wait_cycles
        backoff_seconds = _slot_wait_backoff_seconds(wait_cycles)
        r.hset(retest_key, mapping={
            "status": "queued",
            "verification_id": verification_id,
            "requeued_at": now.isoformat(),
            "note": "waiting_for_retest_slot",
            "attempt": str(attempt),
            "slot_wait_cycles": str(wait_cycles),
            "slot_waited_seconds": str(waited_seconds),
            "next_backoff_seconds": str(backoff_seconds),
        })
        r.rpush(RETEST_QUEUE_NAME, json.dumps(requeued_payload))
        r.expire(retest_key, 86400)
        await asyncio.sleep(backoff_seconds)
        return

    try:
        r.hset(retest_key, mapping={
            "status": "running",
            "verification_id": verification_id,
            "started_at": now.isoformat(),
            "attempt": str(attempt),
        })

        async with db_pool.acquire() as conn:
            verification = await conn.fetchrow("""
                SELECT fv.*, f.title, f.tool, f.evidence, f.url as finding_url
                FROM finding_verifications fv
                JOIN findings f ON fv.finding_id = f.id
                WHERE fv.id = $1
            """, uuid.UUID(verification_id))

            if not verification:
                r.hset(retest_key, mapping={
                    "status": "failed",
                    "error": "verification_not_found",
                })
                r.expire(retest_key, 86400)
                print(f"[retest:{job_id[:8]}] Verification not found: {verification_id}", flush=True)
                return

            await conn.execute("""
                UPDATE finding_verifications
                SET status = 'running',
                    started_at = NOW(),
                    attempt_count = GREATEST(COALESCE(attempt_count, 0), $2),
                    updated_at = NOW()
                WHERE id = $1
            """, verification["id"], attempt)
            await conn.execute("""
                UPDATE findings
                SET last_verification_status = 'running',
                    last_verification_verdict = NULL,
                    updated_at = NOW()
                WHERE id = $1
            """, verification["finding_id"])

            # Check if this is a forced AI-only retest (mode=ai from API)
            ai_runtime = _load_runtime_ai_settings()
            force_ai = requested_mode == "ai"
            ai_verify_enabled = bool(ai_runtime.get("ai_verify_enabled"))
            ai_verify_url = str(ai_runtime.get("ai_verify_url") or ai_runtime.get("ai_url") or "")
            ai_verify_api_key = str(ai_runtime.get("ai_verify_api_key") or ai_runtime.get("ai_api_key") or "")
            ai_verify_model = str(ai_runtime.get("ai_verify_model") or ai_runtime.get("ai_model") or AI_VERIFY_MODEL)
            ai_verify_fallback_model = str(
                ai_runtime.get("ai_verify_model_fallback")
                or ai_runtime.get("ai_model_fallback")
                or AI_VERIFY_FALLBACK_MODEL
            )
            _retest_policy = VerificationPolicy.from_env(overrides=ai_runtime)
            ai_verify_min_severity = _retest_policy.ai_escalation_min_severity
            ai_config_ready = bool(ai_verify_enabled and ai_verify_url and ai_verify_api_key)

            # Tier 1: Deterministic proof (fast, free) — skip if forced AI
            if force_ai and not ai_config_ready:
                result = {
                    "status": "failed",
                    "result_status": "error",
                    "verdict": "error",
                    "verdict_reason": "AI verification requested but AI verifier is not configured",
                    "deterministic_exhausted": True,
                    "has_ai_step": True,
                    "verification_mode": "ai_driven",
                    "confidence": None,
                    "proof": None,
                    "replay_commands": [],
                    "artifacts": {},
                    "attempt_ladder": [],
                    "attempts_exhausted": True,
                    "retry_class": "config",
                    "retryable": False,
                    "message": "AI retest requested but AI verifier is disabled or missing credentials",
                    "error_message": "AI verifier not configured",
                }
            elif not force_ai:
                result = await run_finding_retest(dict(verification))
                if requested_mode == "deterministic" and result.get("verdict") != "exploited":
                    result["has_ai_step"] = False
                    result["attempts_exhausted"] = bool(result.get("deterministic_exhausted"))
            else:
                result = {
                    "status": "completed",
                    "result_status": "inconclusive",
                    "verdict": "inconclusive",
                    "verdict_reason": "Skipped deterministic tier (mode=ai)",
                    "deterministic_exhausted": True,
                    "has_ai_step": True,
                    "verification_mode": "ai_driven",
                    "confidence": None,
                    "proof": None,
                    "replay_commands": [],
                    "artifacts": {},
                    "attempt_ladder": [],
                    "retry_class": "none",
                    "retryable": False,
                }

            # Tier 2: AI-driven verification — escalate when deterministic didn't prove it
            ai_result = None
            ai_failure_error: str | None = None
            still_vulnerable_deterministic = result.get("verdict") == "exploited"
            should_try_ai = (
                not still_vulnerable_deterministic
                and requested_mode != "deterministic"
                and (result.get("has_ai_step") or force_ai)
                and ai_config_ready
            )

            finding_severity = str(verification.get("severity") or "").lower()
            if not finding_severity:
                # Look up severity from the finding itself
                f_row = await conn.fetchrow("SELECT severity FROM findings WHERE id = $1", verification["finding_id"])
                finding_severity = str(f_row["severity"]).lower() if f_row else ""

            severity_ok = force_ai or (
                SEVERITY_ORDER.get(finding_severity, 0)
                >= SEVERITY_ORDER.get(ai_verify_min_severity, SEVERITY_ORDER["high"])
            )

            if should_try_ai and severity_ok:
                circuit_state = _get_ai_circuit_state(r, utc_now())
                if circuit_state.get("is_open"):
                    open_until = circuit_state.get("open_until")
                    open_until_text = open_until.isoformat() if isinstance(open_until, datetime) else "unknown"
                    ai_failure_error = f"AI verification bypassed: circuit open until {open_until_text}"
                    result.update({
                        "status": "completed",
                        "result_status": "inconclusive",
                        "verdict": "inconclusive",
                        "verdict_reason": ai_failure_error,
                        "message": ai_failure_error,
                        "retry_class": "transient",
                        "retryable": True,
                        "attempts_exhausted": False,
                    })
                    if force_ai:
                        result["verification_mode"] = "ai_driven"
                    print(f"[retest:{job_id[:8]}] {ai_failure_error}", flush=True)
                else:
                    try:
                        from ai_verifier import ai_verify_finding, AI_VERIFIABLE_TYPES

                        finding_type = str(verification.get("finding_type") or "")
                        if finding_type in AI_VERIFIABLE_TYPES:
                            auth_ctx = parse_json_field(verification.get("auth_context"))
                            target = str(verification.get("target_url") or "")

                            print(
                                f"[retest:{job_id[:8]}] Escalating to AI verification "
                                f"(budget={RETEST_AI_BUDGET_SECONDS}s)",
                                flush=True,
                            )
                            ai_result = await asyncio.wait_for(
                                ai_verify_finding(
                                    finding=dict(verification),
                                    auth_context=auth_ctx if auth_ctx else None,
                                    ai_url=ai_verify_url,
                                    ai_api_key=ai_verify_api_key,
                                    model=ai_verify_model,
                                    fallback_models=ai_verify_fallback_model or None,
                                    target_url=target,
                                ),
                                timeout=RETEST_AI_BUDGET_SECONDS,
                            )

                            if ai_result and ai_result.get("error"):
                                ai_failure_error = str(ai_result.get("error"))
                            if ai_result:
                                result = _merge_ai_result_into_retest_result(result, ai_result)
                        else:
                            ai_failure_error = f"AI verifier does not support finding_type={finding_type}"
                    except asyncio.TimeoutError:
                        ai_failure_error = (
                            f"AI verification timeout: exceeded {RETEST_AI_BUDGET_SECONDS}s budget"
                        )
                        ai_result = {
                            "verdict": "inconclusive",
                            "confidence": None,
                            "reasoning": ai_failure_error,
                            "error": ai_failure_error,
                        }
                        result = _merge_ai_result_into_retest_result(result, ai_result)
                        print(f"[retest:{job_id[:8]}] {ai_failure_error}", flush=True)
                    except ImportError:
                        ai_failure_error = "AI verifier module not available"
                        print(f"[retest:{job_id[:8]}] {ai_failure_error}", flush=True)
                    except Exception as ai_err:
                        ai_failure_error = f"AI verification error: {type(ai_err).__name__}: {ai_err}"
                        ai_result = {
                            "verdict": "inconclusive",
                            "confidence": None,
                            "reasoning": ai_failure_error,
                            "error": ai_failure_error,
                        }
                        result = _merge_ai_result_into_retest_result(result, ai_result)
                        print(f"[retest:{job_id[:8]}] {ai_failure_error}", flush=True)

                    if ai_failure_error and _is_retryable_ai_error(ai_failure_error):
                        opened, error_count = _register_ai_circuit_failure(r, ai_failure_error, utc_now())
                        result["retry_class"] = "transient"
                        result["retryable"] = True
                        result["attempts_exhausted"] = False
                        if opened:
                            print(
                                f"[retest:{job_id[:8]}] AI circuit opened after {error_count} retryable errors",
                                flush=True,
                            )
                    elif ai_failure_error and not _is_retryable_ai_error(ai_failure_error):
                        # Non-retryable AI error: don't trip circuit breaker
                        pass
                    elif ai_result and not ai_result.get("error"):
                        _clear_ai_circuit_state(r)

            # Deterministic fallback: if AI was unavailable and deterministic tier
            # found partial evidence, promote from inconclusive → likely_vulnerable.
            _current_verdict = str(result.get("verdict") or "").lower()
            if _current_verdict == "inconclusive" and result.get("deterministic_exhausted"):
                if _has_partial_deterministic_evidence(result):
                    result["verdict"] = "likely_vulnerable"
                    result["verdict_reason"] = (
                        (result.get("verdict_reason") or "")
                        + " [promoted from inconclusive: deterministic tier found partial evidence]"
                    ).strip()
                    result["result_status"] = _result_status_for_verdict(result["verdict"])
                    print(f"[retest:{job_id[:8]}] Promoted inconclusive → likely_vulnerable (partial deterministic evidence)", flush=True)

            # Final consistency guard before persistence: never write a
            # low-confidence "false_positive" (single enforcement point).
            result = _enforce_verdict_invariants(result)

            completed_at = utc_now()
            verification_mode = result.get("verification_mode", "deterministic")
            ai_plan_json = json.dumps(ai_result.get("ai_plan")) if ai_result and ai_result.get("ai_plan") else None
            ai_reasoning = ai_result.get("reasoning") if ai_result else None

            if result["status"] == "completed" or result.get("verdict") == "exploited":
                await conn.execute("""
                    UPDATE finding_verifications
                    SET status = 'completed',
                        result_status = $1,
                        verdict = $2,
                        verdict_reason = $3,
                        replay_commands = $4,
                        proof = $5,
                        artifacts = $6,
                        confidence = $7,
                        attempt_count = $8,
                        attempts_exhausted = $9,
                        retry_class = $10,
                        retryable = $11,
                        message = $12,
                        error_message = NULL,
                        completed_at = $13,
                        verification_mode = $14,
                        ai_plan = $15,
                        ai_reasoning = $16,
                        updated_at = NOW()
                    WHERE id = $17
                """,
                    result.get("result_status"),
                    result.get("verdict"),
                    result.get("verdict_reason"),
                    json.dumps(result.get("replay_commands")) if result.get("replay_commands") else None,
                    json.dumps(result.get("proof")) if result.get("proof") else None,
                    json.dumps(result.get("artifacts")) if result.get("artifacts") else None,
                    result.get("confidence"),
                    attempt,
                    bool(result.get("attempts_exhausted")),
                    result.get("retry_class"),
                    bool(result.get("retryable")),
                    result.get("message"),
                    completed_at,
                    verification_mode,
                    ai_plan_json,
                    ai_reasoning,
                    verification["id"],
                )
            else:
                await conn.execute("""
                    UPDATE finding_verifications
                    SET status = 'failed',
                        result_status = $1,
                        verdict = $2,
                        verdict_reason = $3,
                        replay_commands = $4,
                        proof = $5,
                        artifacts = $6,
                        confidence = $7,
                        attempt_count = $8,
                        attempts_exhausted = $9,
                        retry_class = $10,
                        retryable = $11,
                        message = $12,
                        error_message = $13,
                        completed_at = $14,
                        verification_mode = $15,
                        ai_plan = $16,
                        ai_reasoning = $17,
                        updated_at = NOW()
                    WHERE id = $18
                """,
                    result.get("result_status") or "error",
                    result.get("verdict") or "error",
                    result.get("verdict_reason"),
                    json.dumps(result.get("replay_commands")) if result.get("replay_commands") else None,
                    json.dumps(result.get("proof")) if result.get("proof") else None,
                    json.dumps(result.get("artifacts")) if result.get("artifacts") else None,
                    result.get("confidence"),
                    attempt,
                    bool(result.get("attempts_exhausted", True)),
                    result.get("retry_class"),
                    bool(result.get("retryable")),
                    result.get("message"),
                    result.get("error_message"),
                    completed_at,
                    verification_mode,
                    ai_plan_json,
                    ai_reasoning,
                    verification["id"],
                )

            await conn.execute("""
                UPDATE findings
                SET last_verification_status = $1,
                    last_verification_verdict = $2,
                    last_verification_confidence = $3,
                    last_verified_at = $4,
                    verification_count = COALESCE(verification_count, 0) + 1,
                    updated_at = NOW()
                WHERE id = $5
            """,
                result.get("result_status") if result.get("verdict") == "exploited" or result.get("status") == "completed" else "error",
                result.get("verdict") if result.get("verdict") == "exploited" or result.get("status") == "completed" else "error",
                result.get("confidence"),
                completed_at,
                verification["finding_id"],
            )

            # Optional policy: auto-close a finding when a retest concludes a
            # high-confidence false positive. OFF by default and intentionally
            # conservative — a wrong auto-FP hides a real vulnerability. Only an
            # active finding is touched, the action is audited via analyst_verdict
            # fields, and it remains fully reversible by an analyst.
            auto_fp_applied = False
            try:
                final_verdict = str(result.get("verdict") or "").lower()
                final_conf = float(result.get("confidence")) if result.get("confidence") is not None else 0.0
            except (TypeError, ValueError):
                final_verdict, final_conf = "", 0.0
            if (
                _retest_policy.auto_fp_on_retest
                and final_verdict == "false_positive"
                and final_conf >= _retest_policy.auto_fp_min_confidence
            ):
                audit_note = (
                    f"Auto-set false positive by retest {verification_id} "
                    f"(mode={verification_mode}, confidence={final_conf:.2f}). Reversible by an analyst."
                )
                updated_status = await conn.fetchval("""
                    UPDATE findings
                    SET status = 'false_positive',
                        analyst_verdict = 'false_positive',
                        analyst_verdict_at = NOW(),
                        analyst_verdict_notes = $2,
                        resolved_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1 AND status = 'active'
                    RETURNING id
                """, verification["finding_id"], audit_note)
                auto_fp_applied = updated_status is not None
                if auto_fp_applied:
                    print(
                        f"[retest:{job_id[:8]}] Auto-closed finding {verification['finding_id']} "
                        f"as false_positive (confidence={final_conf:.2f})",
                        flush=True,
                    )

        r.hset(retest_key, mapping={
            "status": "completed" if result.get("verdict") == "exploited" or result["status"] == "completed" else "failed",
            "result_status": result.get("result_status") or "error",
            "verdict": result.get("verdict") or "error",
            "verification_mode": verification_mode,
            "retry_class": result.get("retry_class") or "none",
            "retryable": str(bool(result.get("retryable"))).lower(),
            "attempt": str(attempt),
            "completed_at": completed_at.isoformat(),
        })
        if result.get("error_message"):
            r.hset(retest_key, "error", result["error_message"])
        r.expire(retest_key, 86400)

        print(
            f"[retest:{job_id[:8]}] Completed retest {verification_id} -> "
            f"{result.get('verdict') or result.get('result_status')} (mode={verification_mode})",
            flush=True,
        )
    finally:
        _release_retest_slot(r)


async def queue_auto_retests_for_scan(scan_id: str, target_id: str | None, target_url: str | None) -> dict[str, int]:
    """
    Auto-enqueue retests for high-risk findings from a completed scan.

    This is a best-effort policy hook and should never fail the scan job itself.
    """
    runtime_settings = _load_runtime_ai_settings()
    policy = VerificationPolicy.from_env(overrides=runtime_settings)
    auto_retest_enabled = policy.auto_retest_enabled
    auto_retest_max_per_scan = policy.auto_retest_max_per_scan
    auto_retest_min_severity = policy.verification_min_severity

    if not auto_retest_enabled or auto_retest_max_per_scan <= 0:
        return {"queued": 0, "skipped": 0}

    r = get_redis()
    queued = 0
    skipped = 0

    async with db_pool.acquire() as conn:
        # Look up scan options to extract auth context for retests
        scan_row = await conn.fetchrow(
            "SELECT options FROM scans WHERE id = $1", uuid.UUID(scan_id)
        )
        scan_options = parse_json_field(scan_row["options"]) if scan_row else {}
        auth_ctx = extract_auth_context(scan_options)
        auth_ctx_json = json.dumps(auth_ctx) if auth_ctx else None

        rows = await conn.fetch("""
            SELECT f.*, t.url as target_url
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            WHERE f.scan_id = $1 AND f.status = 'active'
            ORDER BY
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                f.last_seen_at DESC
        """, uuid.UUID(scan_id))

        for row in rows:
            if queued >= auto_retest_max_per_scan:
                break

            finding = dict(row)
            if not _severity_allows_auto_retest(
                str(finding.get("severity") or ""),
                auto_retest_min_severity,
            ):
                skipped += 1
                continue

            pending = await conn.fetchval("""
                SELECT 1
                FROM finding_verifications
                WHERE finding_id = $1
                  AND status IN ('queued', 'running')
                LIMIT 1
            """, finding["id"])
            if pending:
                skipped += 1
                continue

            inferred = infer_retest_inputs({
                **finding,
                "finding_url": finding.get("url"),
                "target_url": finding.get("target_url") or target_url or "",
            })
            finding_type = inferred.get("finding_type")
            effective_target = inferred.get("target_url") or target_url or ""

            if finding_type not in SUPPORTED_RETEST_TYPES or not effective_target:
                skipped += 1
                continue

            replay_commands = build_replay_commands(inferred)
            verification_id = uuid.uuid4()
            job_id = str(uuid.uuid4())

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
                verification_id,
                finding["id"],
                finding.get("scan_id"),
                finding.get("target_id") or (uuid.UUID(target_id) if target_id else None),
                job_id,
                AUTO_RETEST_REQUESTED_BY,
                finding_type,
                effective_target,
                inferred.get("original_url") or effective_target,
                inferred.get("param") or None,
                inferred.get("payload") or None,
                inferred.get("method") or "GET",
                inferred.get("request_body") or None,
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

            job_payload = build_retest_job_payload(
                job_id=job_id,
                verification_id=str(verification_id),
                finding_id=str(finding["id"]),
                submitted_at=utc_now_iso(),
                trigger=AUTO_RETEST_REQUESTED_BY,
            )
            valid, reason = validate_retest_job_payload(job_payload)
            if not valid:
                skipped += 1
                await conn.execute("""
                    UPDATE finding_verifications
                    SET status = 'failed',
                        result_status = 'error',
                        verdict = 'error',
                        verdict_reason = $2,
                        attempts_exhausted = TRUE,
                        retry_class = 'validation',
                        retryable = FALSE,
                        error_message = $2,
                        completed_at = NOW(),
                        updated_at = NOW()
                    WHERE id = $1
                """, verification_id, f"Retest job payload invalid: {reason}")
                continue
            r.rpush(RETEST_QUEUE_NAME, json.dumps(job_payload))
            r.hset(f"retest_job:{job_id}", mapping={
                "status": "queued",
                "verification_id": str(verification_id),
                "finding_id": str(finding["id"]),
                "trigger": AUTO_RETEST_REQUESTED_BY,
                "queue_schema_version": str(job_payload.get("queue_schema_version", "")),
                "attempt": str(job_payload.get("attempt", 1)),
            })
            r.expire(f"retest_job:{job_id}", 86400)
            queued += 1

    return {"queued": queued, "skipped": skipped}


async def reap_stale_retests(now: datetime | None = None) -> dict[str, int]:
    """
    Recover retests stuck in `running` state beyond SLA.

    For stale rows we either requeue once (bounded by RETEST_STALE_REQUEUE_LIMIT)
    or fail them explicitly to prevent permanent `running` noise.
    """
    if RETEST_RUNNING_STALE_SECONDS <= 0:
        return {"requeued": 0, "failed": 0}

    now = now or utc_now()
    cutoff = now - timedelta(seconds=RETEST_RUNNING_STALE_SECONDS)
    r = get_redis()

    # Best-effort distributed lock across worker replicas.
    lock_token = str(uuid.uuid4())
    try:
        acquired = bool(r.set(RETEST_WATCHDOG_LOCK_KEY, lock_token, nx=True, ex=RETEST_WATCHDOG_LOCK_SECONDS))
    except Exception:
        acquired = False
    if not acquired:
        return {"requeued": 0, "failed": 0}

    requeued = 0
    failed = 0

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, finding_id, job_id, attempt_count
            FROM finding_verifications
            WHERE status = 'running'
              AND started_at IS NOT NULL
              AND started_at < $1
            ORDER BY started_at ASC
            LIMIT $2
            """,
            cutoff,
            RETEST_STALE_BATCH_SIZE,
        )

        for row in rows:
            verification_id = row["id"]
            finding_id = row["finding_id"]
            old_job_id = str(row["job_id"] or "")
            attempt_count = max(1, int(row["attempt_count"] or 1))
            stale_reason = (
                f"Retest watchdog detected stale running job "
                f"(>{RETEST_RUNNING_STALE_SECONDS}s)."
            )

            if _stale_retest_should_requeue(attempt_count):
                new_job_id = str(uuid.uuid4())
                next_attempt = attempt_count + 1
                payload = build_retest_job_payload(
                    job_id=new_job_id,
                    verification_id=str(verification_id),
                    finding_id=str(finding_id),
                    submitted_at=now.isoformat(),
                    trigger="stale_watchdog_requeue",
                    attempt=next_attempt,
                )
                valid, reason = validate_retest_job_payload(payload)
                if valid:
                    await conn.execute(
                        """
                        UPDATE finding_verifications
                        SET status = 'queued',
                            job_id = $2,
                            started_at = NULL,
                            completed_at = NULL,
                            result_status = NULL,
                            verdict = NULL,
                            verdict_reason = $3,
                            message = $3,
                            error_message = NULL,
                            attempt_count = $4,
                            attempts_exhausted = FALSE,
                            retry_class = 'transient',
                            retryable = TRUE,
                            updated_at = NOW()
                        WHERE id = $1
                        """,
                        verification_id,
                        new_job_id,
                        stale_reason,
                        next_attempt,
                    )
                    await conn.execute(
                        """
                        UPDATE findings
                        SET last_verification_status = 'queued',
                            last_verification_verdict = NULL,
                            updated_at = NOW()
                        WHERE id = $1
                        """,
                        finding_id,
                    )

                    r.rpush(RETEST_QUEUE_NAME, json.dumps(payload))
                    r.hset(
                        f"retest_job:{new_job_id}",
                        mapping={
                            "status": "queued",
                            "verification_id": str(verification_id),
                            "finding_id": str(finding_id),
                            "trigger": "stale_watchdog_requeue",
                            "queue_schema_version": str(payload.get("queue_schema_version", "")),
                            "attempt": str(payload.get("attempt", next_attempt)),
                        },
                    )
                    r.expire(f"retest_job:{new_job_id}", 86400)
                    if old_job_id:
                        r.hset(
                            f"retest_job:{old_job_id}",
                            mapping={
                                "status": "failed",
                                "error": "stale_job_requeued",
                                "completed_at": now.isoformat(),
                            },
                        )
                        r.expire(f"retest_job:{old_job_id}", 86400)
                    requeued += 1
                    continue
                stale_reason = f"{stale_reason} Requeue blocked: {reason}"

            await conn.execute(
                """
                UPDATE finding_verifications
                SET status = 'failed',
                    result_status = 'error',
                    verdict = 'error',
                    verdict_reason = $2,
                    message = $2,
                    error_message = $2,
                    attempts_exhausted = TRUE,
                    retry_class = 'transient',
                    retryable = FALSE,
                    completed_at = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                """,
                verification_id,
                stale_reason,
            )
            await conn.execute(
                """
                UPDATE findings
                SET last_verification_status = 'error',
                    last_verification_verdict = 'error',
                    last_verification_confidence = NULL,
                    last_verified_at = NOW(),
                    verification_count = COALESCE(verification_count, 0) + 1,
                    updated_at = NOW()
                WHERE id = $1
                """,
                finding_id,
            )
            if old_job_id:
                r.hset(
                    f"retest_job:{old_job_id}",
                    mapping={
                        "status": "failed",
                        "error": "stale_retest_failed",
                        "completed_at": now.isoformat(),
                    },
                )
                r.expire(f"retest_job:{old_job_id}", 86400)
            failed += 1

    if requeued or failed:
        print(
            f"[watchdog] stale retests recovered: requeued={requeued}, failed={failed}",
            flush=True,
        )
    return {"requeued": requeued, "failed": failed}


RETEST_INCONCLUSIVE_RETRY_AFTER_HOURS = max(1, int(os.environ.get("RETEST_INCONCLUSIVE_RETRY_AFTER_HOURS", "24")))
RETEST_INCONCLUSIVE_MAX_REQUEUE = max(0, int(os.environ.get("RETEST_INCONCLUSIVE_MAX_REQUEUE", "25")))


async def requeue_circuit_recovered_retests() -> dict[str, int]:
    """Re-queue inconclusive retests that were blocked by AI circuit breaker.

    Called from the watchdog loop when the circuit-recovered signal is set.
    Also handles stale inconclusive findings older than the retry window.
    """
    r = get_redis()
    recovered_signal = r.get("retest:ai:circuit_recovered")
    if not recovered_signal:
        return {"requeued": 0}

    r.delete("retest:ai:circuit_recovered")
    requeued = 0
    try:
        async with db_pool.acquire() as conn:
            cutoff = utc_now() - timedelta(hours=RETEST_INCONCLUSIVE_RETRY_AFTER_HOURS)
            rows = await conn.fetch("""
                SELECT fv.id, fv.finding_id, fv.retry_class, fv.attempt_count
                FROM finding_verifications fv
                WHERE fv.verdict = 'inconclusive'
                  AND fv.retry_class IN ('transient', 'rate_limited')
                  AND fv.retryable = TRUE
                  AND fv.completed_at < $1
                ORDER BY fv.completed_at ASC
                LIMIT $2
            """, cutoff, RETEST_INCONCLUSIVE_MAX_REQUEUE)

            for row in rows:
                verification_id = str(row["id"])
                finding_id = str(row["finding_id"])
                job_id = f"circuit-recovery-{uuid.uuid4().hex[:12]}"
                now_iso = utc_now_iso()
                payload = build_retest_job_payload(
                    job_id=job_id,
                    verification_id=verification_id,
                    finding_id=finding_id,
                    submitted_at=now_iso,
                    trigger="circuit_recovery",
                    attempt=int(row["attempt_count"] or 0) + 1,
                )
                r.rpush(RETEST_QUEUE_NAME, json.dumps(payload))
                requeued += 1

            if requeued:
                print(f"[watchdog] circuit recovery: requeued {requeued} inconclusive retests", flush=True)
    except Exception as err:
        print(f"[watchdog] circuit recovery requeue error: {err}", flush=True)
    return {"requeued": requeued}


def save_result_file(result: dict, job_id: str) -> str:
    """Save scan result to JSON file."""
    target = result.get('input', {}).get('normalized_host', 'unknown')
    target_safe = "".join(c if c.isalnum() or c in '.-_' else '_' for c in target)

    target_dir = RESULTS_DIR / target_safe
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = utc_now().strftime('%Y%m%d_%H%M%S')
    filename = f"{timestamp}_{job_id[:8]}.json"
    filepath = target_dir / filename

    with open(filepath, 'w') as f:
        json.dump(result, f, indent=2)

    # Update latest.json
    latest_path = target_dir / "latest.json"
    try:
        if latest_path.exists() or latest_path.is_symlink():
            latest_path.unlink()
        with open(latest_path, 'w') as f:
            json.dump(result, f, indent=2)
    except Exception:
        pass

    return str(filepath)


def send_heartbeats(job_id: str, stop_event: threading.Event):
    """Send periodic heartbeats from a dedicated thread.

    This avoids heartbeat starvation when the asyncio event loop is busy with
    synchronous CPU/JSON work.
    """
    r = get_redis()
    while not stop_event.is_set():
        try:
            r.hset(f"job:{job_id}", 'heartbeat', utc_now_iso())
        except Exception as e:
            print(f"[{job_id[:8]}] Heartbeat error: {e}", flush=True)
        stop_event.wait(timeout=HEARTBEAT_INTERVAL_SECONDS)


async def update_scan_progress(scan_id: str, phase: str, progress: int, job_id: str | None = None):
    """Update scan progress in database (and Redis if job_id provided)."""
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE scans SET current_phase = $1, progress = $2
            WHERE id = $3
        """, phase, progress, uuid.UUID(scan_id))
    if job_id:
        try:
            r = get_redis()
            now_iso = utc_now_iso()
            r.hset(
                f"job:{job_id}",
                mapping={
                    'current_phase': phase,
                    'progress': str(progress),
                    'heartbeat': now_iso,
                },
            )
        except Exception:
            pass


async def process_scan_job(job_data: dict):
    """Process a scan job."""
    job_id = job_data.get('job_id', 'unknown')
    scan_id = job_data.get('scan_id')
    target = job_data.get('target')
    options = job_data.get('options', {})
    campaign_id = job_data.get('campaign_id')

    print(f"[{job_id[:8]}] Starting scan: {target}", flush=True)
    print(f"[{job_id[:8]}] Options keys: {list(options.keys())}", flush=True)
    print(f"[{job_id[:8]}] auth_header present: {bool(options.get('auth_header'))}", flush=True)
    print(f"[{job_id[:8]}] custom_endpoints: {len(options.get('custom_endpoints') or [])} endpoints", flush=True)

    r = get_redis()
    now = utc_now()

    async with db_pool.acquire() as conn:
        current = await conn.fetchrow("SELECT status FROM scans WHERE id = $1", uuid.UUID(scan_id))
    if current and current['status'] == 'cancelled':
        print(f"[{job_id[:8]}] Scan already cancelled; skipping", flush=True)
        r.hset(
            f"job:{job_id}",
            mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
        )
        r.expire(f"job:{job_id}", 86400)
        return

    # Update Redis status
    r.hset(f"job:{job_id}", mapping={
        'status': 'running',
        'scan_id': scan_id,
        'started_at': now.isoformat(),
        'heartbeat': now.isoformat()
    })
    r.delete(f"scan:{scan_id}:logs")

    # Update database
    target_id = None
    ai_target_id = None
    async with db_pool.acquire() as conn:
        update_result = await conn.execute("""
            UPDATE scans SET status = 'running', started_at = $1
            WHERE id = $2 AND status <> 'cancelled'
        """, now, uuid.UUID(scan_id))
        if update_result.endswith("0"):
            print(f"[{job_id[:8]}] Scan cancelled before start; skipping", flush=True)
            r.hset(
                f"job:{job_id}",
                mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
            )
            r.expire(f"job:{job_id}", 86400)
            return

        # Get target references
        row = await conn.fetchrow("SELECT target_id, ai_target_id FROM scans WHERE id = $1", uuid.UUID(scan_id))
        if row:
            target_id = str(row['target_id']) if row['target_id'] else None
            ai_target_id = str(row['ai_target_id']) if row['ai_target_id'] else None

    # Initial progress
    await update_scan_progress(scan_id, "starting", 5, job_id=job_id)

    # Keep heartbeat alive for the entire job lifecycle, including post-scan persistence.
    stop_heartbeat = threading.Event()
    heartbeat_thread = threading.Thread(
        target=send_heartbeats,
        args=(job_id, stop_heartbeat),
        name=f"heartbeat-{job_id[:8]}",
        daemon=True,
    )
    heartbeat_thread.start()

    try:
        try:
            result = await run_scan(target, options, scan_id=scan_id, job_id=job_id)
        except ValueError as e:
            # Validation errors (e.g., incompatible options like public+smart)
            result = {
                'target': target,
                'error': str(e),
                'result': {'score': None, 'grade': None},
                'findings': []
            }
            print(f"[{job_id[:8]}] Validation error: {e}", flush=True)

        result['job_id'] = job_id
        result['scan_id'] = scan_id

        # Extract results
        score = result.get('result', {}).get('score')
        grade = result.get('result', {}).get('grade')
        findings = result.get('findings', [])
        error = result.get('error')

        # Save to file
        filepath = save_result_file(result, job_id)

        # Calculate duration
        completed_at = utc_now()
        duration = int((completed_at - now).total_seconds())

        # Update database - but check if scan was already marked terminal by
        # stale cleanup or user cancellation.
        async with db_pool.acquire() as conn:
            # Check current status - don't overwrite if already terminal.
            current = await conn.fetchrow(
                "SELECT status FROM scans WHERE id = $1",
                uuid.UUID(scan_id)
            )
            if current and current['status'] in ('failed', 'cancelled'):
                terminal_status = current['status']
                print(f"[{job_id[:8]}] Scan already marked {terminal_status}, not overwriting scan row", flush=True)
                # Don't save findings - stale checker already saved partial findings from checkpoint.
                # Saving late-completing findings would cause inconsistency between scan report and /findings.
                # Update Redis to mark job as done so it doesn't stay "running"
                # Don't set result_path - the late-completing output doesn't match the official partial results
                job_key = f"job:{job_id}"
                r.hset(job_key, mapping={
                    'status': terminal_status,
                    'score': str(score) if score else 'N/A',
                    'grade': str(grade) if grade else 'N/A',
                    'completed_at': completed_at.isoformat(),
                    'progress': '100',
                    'current_phase': 'terminated' if terminal_status == 'failed' else 'cancelled'
                })
                r.expire(job_key, 86400)
                return

            if error:
                await conn.execute("""
                    UPDATE scans SET
                        status = 'failed',
                        error_message = $1,
                        completed_at = $2,
                        duration_seconds = $3,
                        progress = 100,
                        current_phase = 'failed'
                    WHERE id = $4
                """, error, completed_at, duration, uuid.UUID(scan_id))
                await asm_inventory.finish_campaign(conn, campaign_id, status='failed')
            else:
                await conn.execute("""
                    UPDATE scans SET
                        status = 'completed',
                        result = $1,
                        score = $2,
                        grade = $3,
                        findings_count = $4,
                        completed_at = $5,
                        duration_seconds = $6,
                        progress = 100
                    WHERE id = $7
                """, json.dumps(result), score, grade, len(findings),
                     completed_at, duration, uuid.UUID(scan_id))
                await asm_inventory.finish_campaign(conn, campaign_id, status='completed')
                if ai_target_id:
                    await conn.execute("""
                        UPDATE ai_targets SET
                            last_scan_id = $1,
                            last_scanned_at = $2,
                            updated_at = NOW()
                        WHERE id = $3
                    """, uuid.UUID(scan_id), completed_at, uuid.UUID(ai_target_id))

        # Save findings (pure DB persistence)
        saved_count = 0
        if target_id and findings:
            try:
                saved_count = await save_findings(scan_id, target_id, findings)
            except Exception as e:
                print(f"[{job_id[:8]}] save_findings error: {e}", flush=True)
        elif ai_target_id and findings:
            try:
                saved_count = await save_ai_findings(scan_id, ai_target_id, findings)
            except Exception as e:
                print(f"[{job_id[:8]}] save_ai_findings error: {e}", flush=True)

        # Continuous ASM: persist this scan's discovered endpoint worklist into
        # the per-target inventory (docs §16). Best-effort; never fails the scan.
        if target_id and not error:
            try:
                worklist = (result.get('active_checks') or {}).get('active_worklist')
                if worklist:
                    # Drop spec/OPTIONS-derived phantom (404) endpoints before recording.
                    worklist = await asm_inventory.filter_reachable_worklist(target, worklist, options)
                if worklist:
                    async with db_pool.acquire() as conn:
                        auth_state = asm_inventory.auth_state_from_options(options)
                        n = await asm_inventory.upsert_endpoints(
                            conn, target_id, worklist, source='scan', auth_state=auth_state
                        )
                    print(f"[{job_id[:8]}] ASM inventory: upserted {n} endpoints", flush=True)
            except Exception as e:
                print(f"[{job_id[:8]}] ASM inventory error: {e}", flush=True)

        # Incremental reachability GC: re-probe a bounded slice of the existing
        # inventory (least-recently-swept first) and retire phantom/dead endpoints
        # to 'gone' so they stop consuming test budget. Best-effort, bounded so it
        # adds little to scan time; successive scans rotate through the inventory.
        if target_id and not error:
            try:
                try:
                    _sweep_max = int(os.environ.get("ASM_SCAN_SWEEP_MAX") or 400)
                except (TypeError, ValueError):
                    _sweep_max = 400
                if _sweep_max > 0:
                    async with db_pool.acquire() as conn:
                        _sw = await asm_inventory.sweep_endpoint_reachability(
                            conn, target, target_id, options, max_probe=_sweep_max
                        )
                    if _sw.get("probed"):
                        print(
                            f"[{job_id[:8]}] ASM reachability sweep: probed {_sw.get('probed', 0)}, "
                            f"reachable {_sw.get('reachable', 0)}, unreachable {_sw.get('unreachable', 0)}, "
                            f"retired {_sw.get('retired', 0)} to 'gone'",
                            flush=True,
                        )
            except Exception as e:
                print(f"[{job_id[:8]}] ASM reachability sweep error: {e}", flush=True)

        try:
            await finalize_ai_finding_retest(
                options=options,
                result=result,
                scan_id=scan_id,
                completed_at=completed_at,
                error=error,
            )
        except Exception as e:
            print(f"[{job_id[:8]}] finalize_ai_finding_retest error: {e}", flush=True)

        # Auto-retest severity-gated findings (separate from persistence)
        auto_retests = {"queued": 0, "skipped": 0}
        if target_id and findings and not error:
            try:
                auto_retests = await queue_auto_retests_for_scan(scan_id, target_id, target)
            except Exception as e:
                print(f"[{job_id[:8]}] auto-retest error: {e}", flush=True)

        # Update Redis
        status = 'failed' if error else 'completed'
        job_key = f"job:{job_id}"
        r.hset(job_key, mapping={
            'status': status,
            'result_path': filepath,
            'score': str(score) if score else 'N/A',
            'grade': str(grade) if grade else 'N/A',
            'completed_at': completed_at.isoformat(),
            'progress': '100',
            'current_phase': status,
            'auto_retests_queued': str(auto_retests.get("queued", 0)),
        })
        r.expire(job_key, 86400)

        print(
            f"[{job_id[:8]}] Completed: {target} | Score: {score} | Grade: {grade} | "
            f"Findings: {len(findings)} (saved: {saved_count}) | AutoRetests: {auto_retests.get('queued', 0)}",
            flush=True,
        )
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=max(1.0, HEARTBEAT_INTERVAL_SECONDS / 2))


async def process_discovery_job(job_data: dict):
    """Process a discovery job."""
    job_id = job_data.get('job_id', 'unknown')
    discovery_id = job_data.get('discovery_id')
    root_domain = job_data.get('root_domain')

    print(f"[{job_id[:8]}] Starting discovery: {root_domain}", flush=True)

    r = get_redis()
    now = utc_now()

    # Update status
    r.hset(f"job:{job_id}", mapping={'status': 'running', 'started_at': now.isoformat()})

    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE discovery_runs SET status = 'running', started_at = $1
            WHERE id = $2
        """, now, uuid.UUID(discovery_id))

    # Run discovery
    result = await run_discovery(root_domain)

    completed_at = utc_now()
    error = result.get('error')

    # Update database
    async with db_pool.acquire() as conn:
        if error:
            await conn.execute("""
                UPDATE discovery_runs SET
                    status = 'failed',
                    error_message = $1,
                    completed_at = $2
                WHERE id = $3
            """, error, completed_at, uuid.UUID(discovery_id))
        else:
            await conn.execute("""
                UPDATE discovery_runs SET
                    status = 'completed',
                    subdomains_found = $1,
                    result = $2,
                    sources_used = $3,
                    completed_at = $4
                WHERE id = $5
            """, result.get('total', 0), json.dumps(result.get('subdomains', [])),
                 json.dumps(result.get('by_source', {})), completed_at, uuid.UUID(discovery_id))

            # Auto-create targets for discovered subdomains
            for subdomain in result.get('subdomains', [])[:100]:  # Limit to 100
                try:
                    await conn.execute("""
                        INSERT INTO targets (url, root_domain, is_root, discovery_source)
                        VALUES ($1, $2, false, 'subfinder')
                        ON CONFLICT (url) DO NOTHING
                    """, f"https://{subdomain}", root_domain)
                except Exception:
                    pass

    job_key = f"job:{job_id}"
    r.hset(job_key, mapping={
        'status': 'failed' if error else 'completed',
        'completed_at': completed_at.isoformat()
    })
    # Expire completed/failed job keys after 24 hours
    r.expire(job_key, 86400)

    print(f"[{job_id[:8]}] Discovery completed: {root_domain} | Found: {result.get('total', 0)} subdomains", flush=True)


# ===========================================================================
# Parallel scan orchestration: plan -> shards -> merge (scatter-gather).
# See docs/parallel-scan-architecture.md and api/parallel_scan.py.
# ===========================================================================

def _as_report_dict(value) -> dict | None:
    """Decode a scans.result column (asyncpg may return JSONB as str or dict)."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode()
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return None


def _asm_scan_options_for_auth_state(options: dict[str, Any], auth_state: Any) -> dict[str, Any] | None:
    """Scope scan options to the auth identity claimed from ASM inventory.

    Returning None means the endpoint was discovered under an auth state that
    the current target options can no longer reproduce; testing it anonymously
    would corrupt coverage and BOLA/IDOR results.
    """
    state = asm_inventory.normalize_auth_state(auth_state)
    base = dict(options or {})
    if state not in parallel_scan.available_auth_states(base):
        return None
    return parallel_scan._apply_auth_state(base, state)


def _active_endpoint_attempts_from_report(report: dict | None) -> list[dict[str, Any]]:
    active = (report or {}).get('active_checks') if isinstance(report, dict) else None
    attempts = active.get('endpoint_attempts') if isinstance(active, dict) else None
    if not isinstance(attempts, list):
        return []
    out: list[dict[str, Any]] = []
    for attempt in attempts:
        if isinstance(attempt, dict) and attempt.get('custom_endpoint'):
            out.append(attempt)
    return out


def _active_endpoint_telemetry_present(report: dict | None) -> bool:
    active = (report or {}).get('active_checks') if isinstance(report, dict) else None
    if not isinstance(active, dict):
        return False
    return bool(active.get('per_endpoint_telemetry')) or isinstance(active.get('endpoint_attempts'), list)


def _ledger_status_from_endpoint_attempt(attempt: dict[str, Any]) -> tuple[str, str | None]:
    status = str(attempt.get('status') or '').strip().lower()
    reason = attempt.get('budget_exhausted_reason') or attempt.get('skip_reason')
    if status == 'completed':
        return 'completed', None
    if reason == 'time_budget':
        return 'timeout', 'time_budget'
    if status == 'skipped':
        return 'partial', str(reason or 'skipped')
    if status in {'partial', 'started'}:
        return 'partial', str(reason or 'partial')
    return 'partial', str(reason or status or 'partial')


def _apply_campaign_coverage_rollup(merged: dict[str, Any], campaign_coverage: dict[str, Any]) -> bool:
    """Overlay parent smart coverage with campaign attempt-ledger facts."""
    if not isinstance(campaign_coverage, dict) or int(campaign_coverage.get('attempted') or 0) <= 0:
        return False
    agg_cov = dict(merged.get('smart_coverage') or {})
    assignment_rollup = agg_cov.get('endpoints')
    if assignment_rollup:
        agg_cov['endpoint_assignment_rollup'] = assignment_rollup
    agg_cov['endpoints'] = campaign_coverage
    agg_cov['coverage_basis'] = 'attempt_ledger'
    merged['smart_coverage'] = agg_cov
    return True


async def _record_endpoint_telemetry_attempts(
    conn,
    *,
    target_id: str,
    attempts: list[dict[str, Any]],
    scan_id: str | None = None,
    parent_scan_id: str | None = None,
    campaign_id: str | None = None,
    worker_id: str | None = None,
    auth_state: str = 'anonymous',
    check_family: str = 'all',
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    source: str,
    replace_existing: bool = False,
) -> dict[str, Any]:
    """Persist scanner-proven endpoint attempts and return resolved IDs by status."""
    completed_ids: list[Any] = []
    partial_ids: list[Any] = []
    error_ids: list[Any] = []
    written = 0
    for attempt in attempts:
        custom_endpoint = attempt.get('custom_endpoint')
        if not custom_endpoint:
            continue
        endpoint_ids = await asm_inventory.endpoint_ids_for_worklist(
            conn,
            target_id,
            [custom_endpoint],
            auth_state=auth_state,
        )
        if not endpoint_ids:
            continue
        status, error_summary = _ledger_status_from_endpoint_attempt(attempt)
        attempted_count = int(attempt.get('attempted_params_count') or 0)
        completed_count = int(attempt.get('completed_params_count') or 0)
        written += await asm_inventory.record_endpoint_attempts(
            conn,
            endpoint_ids,
            scan_id=scan_id,
            parent_scan_id=parent_scan_id,
            campaign_id=campaign_id,
            worker_id=worker_id,
            auth_state=auth_state,
            check_family=check_family,
            started_at=started_at,
            completed_at=completed_at,
            status=status,
            attempted_params_count=attempted_count,
            completed_params_count=completed_count,
            error_summary=error_summary,
            scanner_telemetry_json={
                'source': source,
                'per_endpoint_telemetry': True,
                'endpoint_attempt': attempt,
            },
            replace_existing=replace_existing,
        )
        if status == 'completed':
            completed_ids.extend(endpoint_ids)
        elif status == 'error':
            error_ids.extend(endpoint_ids)
        else:
            partial_ids.extend(endpoint_ids)
    return {
        'written': written,
        'completed_ids': completed_ids,
        'partial_ids': partial_ids,
        'error_ids': error_ids,
    }


async def _create_full_coverage_campaign(
    conn,
    *,
    target_id: str,
    parent_scan_id: str,
    options: dict[str, Any],
    shard_count: int,
    harvested_count: int,
    coverage_auth_states: list[str],
    allocation_mode: str,
    strategy: str = 'coverage',
    check_families: list[str] | None = None,
) -> str:
    custom_budget = options.get('custom_budget') if isinstance(options.get('custom_budget'), dict) else {}
    normalized_strategy = str(strategy or 'coverage').strip().lower()
    families = (
        [asm_inventory.normalize_check_family(f) for f in check_families]
        if check_families
        else (['all', 'sqli', 'xss'] if normalized_strategy == 'coverage_family' else ['all'])
    )
    return await asm_inventory.create_campaign(
        conn,
        target_id,
        mode=asm_inventory.CAMPAIGN_FULL_COVERAGE,
        requested_by=str(options.get('requested_by') or options.get('triggered_by') or 'api'),
        parent_scan_id=parent_scan_id,
        priority=150,
        budget_profile=options.get('budget_profile'),
        wide_budget={
            'harvested_endpoints': harvested_count,
            'shard_count': shard_count,
            'coverage_per_shard_cap': options.get('coverage_per_shard_cap'),
            'coverage_dynamic_batch_size': options.get('coverage_dynamic_batch_size'),
            'coverage_dynamic_max_batches': options.get('coverage_dynamic_max_batches'),
            'coverage_max_shards': options.get('coverage_max_shards'),
            'active_worklist_max': custom_budget.get('active_worklist_max'),
            'allocation_mode': allocation_mode,
            'expected_attempts': harvested_count * max(1, len(coverage_auth_states or ['anonymous'])) * len(families),
        },
        deep_budget={
            'exploit_depth': bool(options.get('exploit_depth')),
            'custom_budget': custom_budget,
        },
        check_families=families,
        auth_states=coverage_auth_states,
        metadata_json={
            'parallel_strategy': normalized_strategy,
            'coverage_allocation': allocation_mode,
            'family_aware_attempts': normalized_strategy == 'coverage_family',
        },
    )


async def process_scan_plan_job(job_data: dict):
    """Plan stage: decompose a parent scan into shard jobs (or fall back to a
    standalone scan when there is nothing to parallelize)."""
    parent_id = job_data.get('scan_id')
    parent_job_id = job_data.get('job_id', 'unknown')
    target = job_data.get('target')
    options = job_data.get('options', {}) or {}
    scan_type = (options.get('scan_type') or 'standard').strip().lower() or 'standard'

    r = get_redis()
    now = utc_now()

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT target_id, target_url, status FROM scans WHERE id = $1", uuid.UUID(parent_id)
        )
    if not row:
        print(f"[{parent_id[:8]}] parent scan not found; plan job skipped", flush=True)
        return
    if row['status'] == 'cancelled':
        print(f"[{parent_id[:8]}] parent scan already cancelled; plan job skipped", flush=True)
        r.hset(
            f"job:{parent_job_id}",
            mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
        )
        r.expire(f"job:{parent_job_id}", 86400)
        return
    target_id = str(row['target_id']) if row and row['target_id'] else None
    target_url = (row['target_url'] if row else None) or target

    requested_strategy = parallel_scan.resolve_auto_strategy(
        options,
        scan_type,
        options.get('shard_strategy') or 'auto',
    )
    coverage_auth_states: list[str] = []
    coverage_allocation = 'static'
    harvested: list[str] = []
    precreated_campaign_id: str | None = None
    if requested_strategy in {'coverage', 'coverage_family'}:
        # Discover-once: run a discovery-focused recon pass (active disabled),
        # harvest the endpoint worklist, then partition it across shards so the
        # union approaches full endpoint coverage. Full discovery runs once
        # here; shards then run zero-rediscovery active checks over their
        # assigned endpoint slice.
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status = 'running', started_at = $1, current_phase = 'recon', progress = 3 WHERE id = $2",
                now, uuid.UUID(parent_id),
            )
        recon_opts = parallel_scan._base_child_options(options)
        recon_opts['scan_type'] = 'smart'
        recon_opts.pop('custom_endpoints', None)
        # Lean enumeration budget so "planning" finishes fast (overrides any
        # heavy discovery knobs inherited from the parent/coverage payload).
        parallel_scan._merge_custom_budget(recon_opts, dict(parallel_scan.RECON_DISCOVERY_BUDGET))
        print(f"[{parent_id[:8]}] coverage: running discover-once recon", flush=True)
        try:
            recon_result = await run_scan(target, recon_opts, scan_id=parent_id, job_id=parent_job_id)
        except Exception as e:
            recon_result = {}
            print(f"[{parent_id[:8]}] coverage recon error: {e}", flush=True)
        try:
            harvest_limit = int(
                ((options.get('custom_budget') or {}).get('active_worklist_max'))
                or parallel_scan.COVERAGE_WORKLIST_MAX
            )
        except (TypeError, ValueError):
            harvest_limit = parallel_scan.COVERAGE_WORKLIST_MAX
        harvested = parallel_scan.harvest_endpoints(recon_result, max_endpoints=harvest_limit)
        # Drop spec/OPTIONS-derived phantom endpoints (declared but 404) before they
        # feed the shard plan and the ASM inventory. Filter recon-discovered only;
        # user-supplied custom_endpoints are always kept.
        _raw_harvested = len(harvested)
        harvested = await asm_inventory.filter_reachable_worklist(
            target,
            harvested,
            options,
            max_probe=max(2000, min(harvest_limit, 6000)),
            concurrency=48,
            timeout=3,
        )
        harvested = parallel_scan._normalize_endpoint_list(
            list(options.get('custom_endpoints') or []) + harvested
        )
        print(f"[{parent_id[:8]}] coverage: harvested {len(harvested)} endpoints from recon "
              f"({_raw_harvested} pre-reachability-filter)", flush=True)
        coverage_allocation = parallel_scan.coverage_allocation_mode(options)
        coverage_auth_states = (
            parallel_scan.available_auth_states(options)
            if options.get('auth_state_shards')
            else [asm_inventory.auth_state_from_options(options)]
        )
        if coverage_allocation == 'dynamic' and target_id and harvested:
            planned = (
                parallel_scan.plan_dynamic_coverage_family_shards(
                    options,
                    len(harvested),
                    auth_state_count=len(coverage_auth_states),
                )
                if requested_strategy == 'coverage_family'
                else parallel_scan.plan_dynamic_coverage_shards(
                    options,
                    len(harvested),
                    auth_state_count=len(coverage_auth_states),
                )
            )
            planned_families = sorted({
                asm_inventory.normalize_check_family(s.options.get('coverage_attempt_family') or 'all')
                for s in planned.shards
            }) if requested_strategy == 'coverage_family' else ['all']
            async with db_pool.acquire() as conn:
                precreated_campaign_id = await _create_full_coverage_campaign(
                    conn,
                    target_id=target_id,
                    parent_scan_id=parent_id,
                    options=options,
                    shard_count=planned.shard_count,
                    harvested_count=len(harvested),
                    coverage_auth_states=coverage_auth_states,
                    allocation_mode='dynamic',
                    strategy=requested_strategy,
                    check_families=planned_families,
                )
        # Continuous ASM: the recon worklist is the richest endpoint source —
        # persist the whole thing into the per-target inventory (docs §16).
        if target_id and harvested:
            try:
                async with db_pool.acquire() as conn:
                    upsert_states = (
                        coverage_auth_states
                        if coverage_allocation == 'dynamic' and precreated_campaign_id
                        else [asm_inventory.auth_state_from_options(recon_opts)]
                    )
                    n = 0
                    for auth_state in upsert_states:
                        n += await asm_inventory.upsert_endpoints(
                            conn,
                            target_id,
                            harvested,
                            source='coverage_recon' if coverage_allocation == 'dynamic' else 'recon',
                            auth_state=auth_state,
                            campaign_id=precreated_campaign_id if coverage_allocation == 'dynamic' else None,
                        )
                print(
                    f"[{parent_id[:8]}] ASM inventory: upserted {n} endpoint/auth rows from recon",
                    flush=True,
                )
            except Exception as e:
                print(f"[{parent_id[:8]}] ASM inventory error: {e}", flush=True)
        if coverage_allocation == 'dynamic' and target_id and harvested:
            plan = (
                parallel_scan.plan_dynamic_coverage_family_shards(
                    options,
                    len(harvested),
                    auth_state_count=len(coverage_auth_states),
                )
                if requested_strategy == 'coverage_family'
                else parallel_scan.plan_dynamic_coverage_shards(
                    options,
                    len(harvested),
                    auth_state_count=len(coverage_auth_states),
                )
            )
        elif requested_strategy == 'coverage_family':
            coverage_allocation = 'static'
            plan = parallel_scan.plan_coverage_family_shards(options, harvested)
        else:
            if coverage_allocation == 'dynamic':
                print(
                    f"[{parent_id[:8]}] coverage: dynamic allocation unavailable; falling back to static slices",
                    flush=True,
                )
            coverage_allocation = 'static'
            plan = parallel_scan.plan_coverage_shards(options, harvested)
    else:
        plan = parallel_scan.plan_shards(
            options,
            scan_type=scan_type,
            requested_shards=options.get('shards', 'auto'),
            strategy=requested_strategy,
            worker_count=job_data.get('parallel_worker_count') or 0,
        )
    for note in plan.notes:
        print(f"[{parent_id[:8]}] plan note: {note}", flush=True)

    # Not worth parallelizing -> run the parent as a normal standalone scan.
    force_parent = any(s.options.get('coverage_dynamic_worker') for s in plan.shards)
    if not plan.is_parallel and not force_parent:
        print(f"[{parent_id[:8]}] plan produced {plan.shard_count} shard; running standalone", flush=True)
        single_opts = (
            plan.shards[0].options if plan.shards
            else parallel_scan._base_child_options(options)
        )
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET scan_role = 'standalone', options = $1 WHERE id = $2",
                json.dumps(single_opts), uuid.UUID(parent_id),
            )
        r.rpush(QUEUE_NAME, json.dumps({
            'job_id': parent_job_id,
            'scan_id': parent_id,
            'target': target,
            'options': single_opts,
            'submitted_at': utc_now_iso(),
        }))
        return

    # Mark parent running and fan out child shard rows + jobs. Record the
    # resolved strategy on the parent options so the merge can report it.
    parent_options = dict(options)
    parent_options['parallel_strategy'] = plan.strategy
    if plan.strategy in {'coverage', 'coverage_family'}:
        parent_options['coverage_allocation'] = coverage_allocation
        if harvested and coverage_auth_states:
            planned_families = {
                asm_inventory.normalize_check_family(s.options.get('coverage_attempt_family') or 'all')
                for s in plan.shards
            } if plan.strategy == 'coverage_family' and coverage_allocation == 'dynamic' else {'all'}
            parent_options['coverage_check_families'] = sorted(planned_families)
            family_multiplier = max(1, len(planned_families))
            parent_options['coverage_expected_attempts'] = len(harvested) * max(1, len(coverage_auth_states)) * family_multiplier
    async with db_pool.acquire() as conn:
        campaign_id = precreated_campaign_id
        if plan.strategy in {'coverage', 'coverage_family'} and coverage_allocation == 'dynamic' and target_id:
            if not coverage_auth_states:
                coverage_auth_states = (
                    parallel_scan.available_auth_states(options)
                    if options.get('auth_state_shards')
                    else [asm_inventory.auth_state_from_options(options)]
                )
            if not campaign_id:
                planned_families = sorted({
                    asm_inventory.normalize_check_family(s.options.get('coverage_attempt_family') or 'all')
                    for s in plan.shards
                }) if plan.strategy == 'coverage_family' else ['all']
                campaign_id = await _create_full_coverage_campaign(
                    conn,
                    target_id=target_id,
                    parent_scan_id=parent_id,
                    options=options,
                    shard_count=plan.shard_count,
                    harvested_count=len(harvested) if requested_strategy in {'coverage', 'coverage_family'} else 0,
                    coverage_auth_states=coverage_auth_states,
                    allocation_mode=coverage_allocation,
                    strategy=plan.strategy,
                    check_families=planned_families,
                )
            parent_options['campaign_id'] = campaign_id
        update_result = await conn.execute("""
            UPDATE scans SET status = 'running', started_at = $1,
                current_phase = $2, progress = 5, shard_count = $3,
                options = $4, campaign_id = COALESCE($5, campaign_id)
            WHERE id = $6
              AND status <> 'cancelled'
        """, now, f'sharded:{plan.strategy}', plan.shard_count,
             json.dumps(parent_options),
             uuid.UUID(campaign_id) if campaign_id else None,
             uuid.UUID(parent_id))
        if update_result.endswith("0"):
            print(f"[{parent_id[:8]}] parent scan cancelled before fan-out; plan job skipped", flush=True)
            if campaign_id:
                await asm_inventory.finish_campaign(conn, campaign_id, status='cancelled')
            r.hset(
                f"job:{parent_job_id}",
                mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
            )
            r.expire(f"job:{parent_job_id}", 86400)
            return

        for shard in plan.shards:
            child_id = str(uuid.uuid4())
            child_job_id = str(uuid.uuid4())
            await conn.execute("""
                INSERT INTO scans (id, target_id, target_url, job_id, status, options,
                                   scan_type, parent_scan_id, scan_role, shard_index, shard_count,
                                   campaign_id)
                VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7, 'shard', $8, $9, $10)
            """, uuid.UUID(child_id),
                 uuid.UUID(target_id) if target_id else None,
                 target_url, child_job_id, json.dumps(shard.options), scan_type,
                 uuid.UUID(parent_id), shard.index, plan.shard_count,
                 uuid.UUID(campaign_id) if campaign_id else None)
            r.rpush(QUEUE_NAME, json.dumps({
                'type': asm_inventory.EXPLOIT_BATCH_JOB_TYPE if shard.options.get('coverage_dynamic_worker') else parallel_scan.SHARD_JOB_TYPE,
                'job_id': child_job_id,
                'scan_id': child_id,
                'parent_scan_id': parent_id,
                'campaign_id': campaign_id,
                'target_id': target_id,
                'target': target,
                'options': shard.options,
                'shard_label': shard.label,
                'shard_index': shard.index,
                'shard_count': plan.shard_count,
                'batch_size': shard.options.get('coverage_dynamic_batch_size') or options.get('coverage_dynamic_batch_size') or options.get('coverage_per_shard_cap') or parallel_scan.COVERAGE_DYNAMIC_BATCH_SIZE,
                'stale_days': shard.options.get('coverage_stale_days', 0),
                'exploit_depth': bool(options.get('exploit_depth')),
                'check_family': shard.options.get('coverage_attempt_family') or shard.options.get('asm_check_family') or 'all',
                'campaign_only': bool(shard.options.get('coverage_dynamic_campaign_only')),
                'finish_campaign_on_complete': False,
                'coverage_dynamic_worker': bool(shard.options.get('coverage_dynamic_worker')),
                'submitted_at': utc_now_iso(),
            }))
            r.hset(f"job:{child_job_id}", mapping={'status': 'queued', 'target': target})

    r.set(parallel_scan.shards_remaining_key(parent_id), plan.shard_count, ex=86400)
    _dyn_shards = sum(1 for s in plan.shards if s.options.get('coverage_dynamic_worker'))
    _static_shards = plan.shard_count - _dyn_shards
    if _dyn_shards and not _static_shards:
        _allocation = 'dynamic'
    elif _static_shards and not _dyn_shards:
        _allocation = 'static'
    else:
        _allocation = 'mixed'
    print(
        f"[{parent_id[:8]}] fanned out {plan.shard_count} '{plan.strategy}' shards "
        f"(allocation={_allocation}, dynamic_pull_workers={_dyn_shards}, static_slices={_static_shards})",
        flush=True,
    )


async def process_scan_shard_job(job_data: dict):
    """Shard stage: run run_scan() for one child scan. Findings are NOT saved to
    the findings table here; the merge stage persists the deduped union under the
    parent so the parent cleanly owns all findings."""
    job_id = job_data.get('job_id', 'unknown')
    scan_id = job_data.get('scan_id')            # child scan id
    parent_id = job_data.get('parent_scan_id')
    target_id = job_data.get('target_id')
    target = job_data.get('target')
    options = job_data.get('options', {}) or {}
    label = job_data.get('shard_label', 'shard')
    idx = job_data.get('shard_index')
    total = job_data.get('shard_count')

    r = get_redis()
    now = utc_now()
    print(f"[{job_id[:8]}] Shard '{label}' ({idx}/{total}) start: {target}", flush=True)
    slot_acquired = False

    async with db_pool.acquire() as conn:
        current = await conn.fetchrow("""
            SELECT child.status, parent.status AS parent_status
            FROM scans child
            LEFT JOIN scans parent ON child.parent_scan_id = parent.id
            WHERE child.id = $1
        """, uuid.UUID(scan_id))
    if current and (current['status'] == 'cancelled' or current['parent_status'] == 'cancelled'):
        print(f"[{job_id[:8]}] Shard '{label}' already cancelled; skipping", flush=True)
        if current['status'] != 'cancelled':
            async with db_pool.acquire() as conn:
                await conn.execute("""
                    UPDATE scans
                    SET status = 'cancelled',
                        error_message = 'Cancelled by parent scan',
                        completed_at = NOW(),
                        progress = 100,
                        current_phase = 'cancelled'
                    WHERE id = $1
                """, uuid.UUID(scan_id))
        r.hset(
            f"job:{job_id}",
            mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
        )
        r.expire(f"job:{job_id}", 86400)
        if parent_id:
            try:
                async with db_pool.acquire() as conn:
                    await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[{job_id[:8]}] merge reconcile error after cancelled shard skip: {e}", flush=True)
        return

    slot_acquired, shard_limit = _try_acquire_parallel_shard_slot(r, parent_id, options)
    if not slot_acquired:
        wait_cycles = int(job_data.get('shard_slot_wait_cycles') or 0) + 1
        requeued = dict(job_data)
        requeued['shard_slot_wait_cycles'] = wait_cycles
        requeued['last_shard_slot_wait_at'] = utc_now_iso()
        r.rpush(QUEUE_NAME, json.dumps(requeued))
        r.hset(f"job:{job_id}", mapping={
            'status': 'queued',
            'scan_id': scan_id,
            'current_phase': 'waiting_for_shard_slot',
            'parallel_shard_concurrency': str(shard_limit),
            'shard_slot_wait_cycles': str(wait_cycles),
        })
        r.expire(f"job:{job_id}", 86400)
        if wait_cycles == 1 or wait_cycles % 15 == 0:
            print(
                f"[{job_id[:8]}] Shard '{label}' waiting for parent slot "
                f"({shard_limit} max active shards for {parent_id[:8]}; wait_cycle {wait_cycles})",
                flush=True,
            )
        await asyncio.sleep(PARALLEL_SHARD_REQUEUE_DELAY_SECONDS)
        return

    endpoint_count = _known_endpoint_count(options)
    if endpoint_count > 0:
        try:
            async with db_pool.acquire() as conn:
                rate = await _reserve_target_domain_endpoint_budget(
                    conn,
                    r,
                    target_id=target_id,
                    amount=endpoint_count,
                    all_or_nothing=True,
                )
        except Exception as exc:
            rate = {"granted": 0, "limited": True, "requested": endpoint_count, "reason": str(exc)}
        if rate.get("limited"):
            _release_parallel_shard_slot(r, parent_id)
            slot_acquired = False
            await _requeue_for_domain_rate(
                r,
                job_data,
                job_id=job_id,
                scan_id=scan_id,
                parent_id=parent_id,
                log_prefix=job_id[:8],
                rate=rate,
            )
            return

    r.hset(f"job:{job_id}", mapping={
        'status': 'running', 'scan_id': scan_id,
        'started_at': now.isoformat(), 'heartbeat': now.isoformat(),
        'parallel_shard_concurrency': str(shard_limit),
    })
    r.delete(f"scan:{scan_id}:logs")
    async with db_pool.acquire() as conn:
        update_result = await conn.execute(
            """
            UPDATE scans SET status = 'running', started_at = $1
            WHERE id = $2 AND status <> 'cancelled'
            """,
            now, uuid.UUID(scan_id),
        )
    if update_result.endswith("0"):
        print(f"[{job_id[:8]}] Shard '{label}' cancelled before start; skipping", flush=True)
        _release_parallel_shard_slot(r, parent_id)
        slot_acquired = False
        r.hset(
            f"job:{job_id}",
            mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
        )
        r.expire(f"job:{job_id}", 86400)
        if parent_id:
            try:
                async with db_pool.acquire() as conn:
                    await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[{job_id[:8]}] merge reconcile error after cancelled shard start: {e}", flush=True)
        return
    await update_scan_progress(scan_id, f"shard:{label}", 5, job_id=job_id)

    stop_heartbeat = threading.Event()
    heartbeat_thread = threading.Thread(
        target=send_heartbeats, args=(job_id, stop_heartbeat),
        name=f"heartbeat-{job_id[:8]}", daemon=True,
    )
    heartbeat_thread.start()
    try:
        try:
            result = await run_scan(target, options, scan_id=scan_id, job_id=job_id)
        except Exception as e:
            result = {'target': target, 'error': str(e),
                      'result': {'score': None, 'grade': None}, 'findings': []}
            print(f"[{job_id[:8]}] Shard '{label}' run_scan error: {e}", flush=True)

        result['job_id'] = job_id
        result['scan_id'] = scan_id
        result['shard_label'] = label
        score = result.get('result', {}).get('score')
        grade = result.get('result', {}).get('grade')
        findings = result.get('findings', [])
        error = result.get('error')
        filepath = save_result_file(result, job_id)
        completed_at = utc_now()
        duration = int((completed_at - now).total_seconds())

        async with db_pool.acquire() as conn:
            current = await conn.fetchrow("SELECT status FROM scans WHERE id = $1", uuid.UUID(scan_id))
            if current and current['status'] in ('failed', 'cancelled'):
                # Stale cleanup or user cancellation already finalized this
                # shard. Do not overwrite it with late subprocess output.
                pass
            elif error:
                await conn.execute("""
                    UPDATE scans SET status = 'failed', error_message = $1, result = $2,
                        score = $3, grade = $4, findings_count = $5, completed_at = $6,
                        duration_seconds = $7, progress = 100, current_phase = 'failed'
                    WHERE id = $8
                """, error, json.dumps(result), score, grade, len(findings),
                     completed_at, duration, uuid.UUID(scan_id))
            else:
                await conn.execute("""
                    UPDATE scans SET status = 'completed', result = $1, score = $2,
                        grade = $3, findings_count = $4, completed_at = $5,
                        duration_seconds = $6, progress = 100, current_phase = 'completed'
                    WHERE id = $7
                """, json.dumps(result), score, grade, len(findings),
                     completed_at, duration, uuid.UUID(scan_id))

        final_status = 'failed' if error else 'completed'
        if current and current['status'] in ('failed', 'cancelled'):
            final_status = current['status']
        r.hset(f"job:{job_id}", mapping={
            'status': final_status,
            'result_path': filepath,
            'completed_at': completed_at.isoformat(),
            'progress': '100',
            'current_phase': final_status,
        })
        r.expire(f"job:{job_id}", 86400)
        print(f"[{job_id[:8]}] Shard '{label}' done | findings: {len(findings)} | error: {bool(error)}", flush=True)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=max(1.0, HEARTBEAT_INTERVAL_SECONDS / 2))
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
        # Barrier + merge trigger. The DB all-terminal check in
        # reconcile_parallel_parent is the source of truth (robust to a shard
        # that crashed before reaching here and was failed by the stale checker).
        if parent_id:
            try:
                r.decr(parallel_scan.shards_remaining_key(parent_id))
            except Exception:
                pass
            try:
                async with db_pool.acquire() as conn:
                    enqueued = await parallel_scan.reconcile_parallel_parent(
                        conn, parent_id, r, QUEUE_NAME
                    )
                if enqueued:
                    print(f"[{job_id[:8]}] all shards terminal -> enqueued merge for {parent_id[:8]}", flush=True)
            except Exception as e:
                print(f"[{job_id[:8]}] merge reconcile error: {e}", flush=True)


async def process_scan_merge_job(job_data: dict):
    """Merge stage: aggregate child shard results into the parent report."""
    parent_id = job_data.get('parent_scan_id')
    if not parent_id:
        return
    r = get_redis()
    print(f"[merge {parent_id[:8]}] merging shards", flush=True)

    async with db_pool.acquire() as conn:
        parent = await conn.fetchrow("""
            SELECT target_id, target_url, options, scan_type, created_at, started_at,
                   job_id, status, campaign_id
            FROM scans WHERE id = $1
        """, uuid.UUID(parent_id))
        if not parent:
            print(f"[merge {parent_id[:8]}] parent not found; aborting", flush=True)
            return
        if parent['status'] == 'cancelled':
            parent_job_id = parent['job_id'] or parent_id
            r.hset(
                f"job:{parent_job_id}",
                mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
            )
            r.expire(f"job:{parent_job_id}", 86400)
            r.delete(parallel_scan.shards_remaining_key(parent_id))
            print(f"[merge {parent_id[:8]}] parent cancelled; merge skipped", flush=True)
            return
        children = await conn.fetch("""
            SELECT id, status, result, score, grade, findings_count, shard_index,
                   options, started_at, completed_at, campaign_id
            FROM scans WHERE parent_scan_id = $1 ORDER BY shard_index
        """, uuid.UUID(parent_id))

    target_id = str(parent['target_id']) if parent['target_id'] else None
    target_url = parent['target_url']
    parent_job_id = parent['job_id'] or parent_id
    campaign_id = str(parent['campaign_id']) if parent['campaign_id'] else None

    # Aggregate findings (union, deduped by canonical fingerprint) and pick the
    # richest completed child report as the base skeleton for the merged report.
    union: dict[str, dict] = {}
    base_result = None
    base_section_count = -1
    shard_summaries = []
    shard_coverage_records: list[dict] = []
    shard_worklists_by_auth: dict[str, list] = {}  # ASM: union per auth identity
    min_score = None
    min_score_grade = None
    for ch in children:
        cres = _as_report_dict(ch['result'])
        status = ch['status']
        child_options = _as_report_dict(ch['options']) or {}
        sc = cres.get('smart_coverage') if isinstance(cres, dict) else None
        shard_coverage_records.append({
            'status': status,
            'options': child_options,
            'smart_coverage': sc if isinstance(sc, dict) else {},
        })
        shard_summaries.append({
            'shard_index': ch['shard_index'],
            'status': status,
            'score': ch['score'],
            'grade': ch['grade'],
            'findings_count': ch['findings_count'],
        })
        if status == 'completed' and ch['score'] is not None:
            if min_score is None or ch['score'] < min_score:
                min_score = ch['score']
                min_score_grade = ch['grade']
        if not cres:
            continue
        wl = (cres.get('active_checks') or {}).get('active_worklist')
        if wl:
            auth_state = asm_inventory.auth_state_from_options(child_options)
            shard_worklists_by_auth.setdefault(auth_state, []).extend(wl)
        if status == 'completed':
            section_count = len(cres.get('result', {}) or {})
            if section_count > base_section_count:
                base_section_count = section_count
                base_result = cres
        for f in cres.get('findings', []) or []:
            fp = parallel_scan.finding_merge_key(f)
            if not fp:
                try:
                    fp = generate_finding_fingerprint(f)
                except Exception:
                    fp = json.dumps(f, sort_keys=True, default=str)[:256]
            union.setdefault(fp, f)

    union_findings = list(union.values())

    # Build merged report.
    merged = copy.deepcopy(base_result) if base_result else {'target': target_url, 'result': {}, 'findings': []}
    merged['findings'] = union_findings
    if not isinstance(merged.get('result'), dict):
        merged['result'] = {}

    # Conservative aggregate: the parent is at least as bad as its worst shard.
    agg_score = min_score if min_score is not None else merged['result'].get('score')
    agg_grade = min_score_grade if min_score is not None else merged['result'].get('grade')
    if agg_score is not None:
        merged['result']['score'] = agg_score
    if agg_grade is not None:
        merged['result']['grade'] = agg_grade

    # Recompute attack chains over the full union (they need every finding).
    # attack_chains is a TOP-LEVEL report section, not part of the grade block.
    parent_options = _as_report_dict(parent['options']) or {}
    try:
        from scanner_tools.attack_chains import analyze_attack_chains
        include_partial = bool(parent_options.get('include_partial_attack_chains'))
        merged['attack_chains'] = analyze_attack_chains(union_findings, include_partial)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] attack-chain recompute skipped: {e}", flush=True)

    completed_n = sum(1 for c in children if c['status'] == 'completed')
    failed_n = sum(1 for c in children if c['status'] == 'failed')
    strategy = parent_options.get('parallel_strategy')
    merged['parallel'] = {
        'strategy': strategy,
        'shards': shard_summaries,
        'shards_total': len(children),
        'shards_completed': completed_n,
        'shards_failed': failed_n,
    }

    # Coverage-aware merge: the parent must reflect the whole fan-out, not just
    # the base shard. For scope/coverage shards, use the assigned endpoint
    # slices as the source of truth so failed shards still remain in the
    # denominator. Family/auto shards fall back to reported shard coverage.
    if shard_coverage_records:
        coverage_merge = parallel_scan.aggregate_shard_coverage(strategy, shard_coverage_records)
        agg_cov = dict(merged.get('smart_coverage') or {})
        if coverage_merge.get('endpoints'):
            agg_cov['endpoints'] = {**(agg_cov.get('endpoints') or {}), **coverage_merge['endpoints']}
        if coverage_merge.get('auth_states_tested'):
            agg_cov['auth_states_tested'] = coverage_merge['auth_states_tested']
        if coverage_merge.get('discovery_sources'):
            agg_cov['discovery_sources'] = coverage_merge['discovery_sources']
        agg_cov['aggregated_from_shards'] = coverage_merge.get('aggregated_from_shards', 0)
        agg_cov['coverage_reports_from_shards'] = coverage_merge.get('coverage_reports_from_shards', 0)
        merged['smart_coverage'] = agg_cov  # top-level report section

    # Correct the report's target identity to the actual scanned target (guards
    # against any stale per-shard input drift). `input` is a top-level section.
    try:
        from urllib.parse import urlparse as _urlparse
        _pu = _urlparse(target_url)
        if isinstance(merged.get('input'), dict):
            merged['input'].update({
                'target': target_url,
                'normalized_host': _pu.hostname,
                'port': _pu.port or (443 if _pu.scheme == 'https' else 80),
                'scheme': _pu.scheme,
            })
    except Exception:
        pass

    merged['job_id'] = parent_job_id
    merged['scan_id'] = parent_id

    filepath = save_result_file(merged, parent_job_id)

    # Persist the deduped union under the PARENT scan id (clean ownership).
    saved = 0
    if target_id and union_findings:
        try:
            saved = await save_findings(parent_id, target_id, union_findings)
        except Exception as e:
            print(f"[merge {parent_id[:8]}] save_findings error: {e}", flush=True)

    completed_at = utc_now()
    start = parent['started_at'] or parent['created_at']
    duration = None
    if start is not None:
        duration = int((completed_at - start.replace(tzinfo=None)).total_seconds())

    # Parent is failed only if every shard failed; otherwise it completed.
    parent_status = 'failed' if (children and completed_n == 0) else 'completed'
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE scans SET status = $1, result = $2, score = $3, grade = $4,
                findings_count = $5, completed_at = $6, duration_seconds = $7,
                progress = 100, current_phase = $8
            WHERE id = $9
        """, parent_status, json.dumps(merged), agg_score, agg_grade,
             len(union_findings), completed_at, duration,
             'completed' if parent_status == 'completed' else 'failed',
             uuid.UUID(parent_id))

    # Continuous ASM: persist the UNION of every shard's discovered worklist
    # into the per-target inventory (docs §16). Closes the Phase-1 gap so
    # parallel/sharded scans populate the attack surface, not just standalone
    # scans. Best-effort; never fails the merge.
    if parent_status == 'completed' and target_id and shard_worklists_by_auth:
        try:
            async with db_pool.acquire() as conn:
                total = 0
                for auth_state, worklist in shard_worklists_by_auth.items():
                    total += await asm_inventory.upsert_endpoints(
                        conn, target_id, worklist, source='scan', auth_state=auth_state
                    )
            print(f"[merge {parent_id[:8]}] ASM inventory: upserted {total} endpoints from {len(children)} shards", flush=True)
        except Exception as e:
            print(f"[merge {parent_id[:8]}] ASM inventory error: {e}", flush=True)

    # Campaign attempt ledger for one-shot Full Coverage. This records shard
    # assignment outcomes without changing endpoint test_status. New scanner
    # reports carry per-endpoint telemetry. Legacy/no-telemetry completed
    # children are recorded as partial, never completed, so coverage cannot be
    # inflated by a batch-level success.
    if campaign_id and target_id and strategy in {'coverage', 'coverage_family'}:
        try:
            async with db_pool.acquire() as conn:
                expected_attempts = 0
                dynamic_coverage = str(parent_options.get('coverage_allocation') or '').strip().lower() == 'dynamic'
                family_aware = strategy == 'coverage_family'
                expected_total = parent_options.get('coverage_expected_attempts') if dynamic_coverage else None
                for ch in children:
                    cres = _as_report_dict(ch['result'])
                    child_options = _as_report_dict(ch['options']) or {}
                    endpoints = child_options.get('custom_endpoints') or []
                    if not isinstance(endpoints, list):
                        endpoints = []
                    attempt_family = asm_inventory.normalize_check_family(
                        child_options.get('coverage_attempt_family')
                        or child_options.get('asm_check_family')
                        or 'all'
                    )
                    if not endpoints:
                        continue
                    expected_attempts += len(endpoints)
                    auth_state = asm_inventory.auth_state_from_options(child_options)
                    telemetry_present = _active_endpoint_telemetry_present(cres)
                    attempts = _active_endpoint_attempts_from_report(cres)
                    if telemetry_present:
                        recorded = {'written': 0, 'completed_ids': [], 'partial_ids': [], 'error_ids': []}
                        missing_written = 0
                        if attempts:
                            recorded = await _record_endpoint_telemetry_attempts(
                                conn,
                                target_id=target_id,
                                attempts=attempts,
                                scan_id=str(ch['id']),
                                parent_scan_id=parent_id,
                                campaign_id=campaign_id,
                                worker_id=None,
                                auth_state=auth_state,
                                check_family=attempt_family,
                                started_at=ch['started_at'],
                                completed_at=ch['completed_at'] or completed_at,
                                source='parallel_coverage_merge',
                                replace_existing=True,
                            )
                        assigned_ids = await asm_inventory.endpoint_ids_for_worklist(
                            conn, target_id, endpoints, auth_state=auth_state
                        )
                        accounted = {
                            str(eid)
                            for eid in (
                                recorded.get('completed_ids', [])
                                + recorded.get('partial_ids', [])
                                + recorded.get('error_ids', [])
                            )
                        }
                        missing_ids = [eid for eid in assigned_ids if str(eid) not in accounted]
                        if missing_ids:
                            missing_written = await asm_inventory.record_endpoint_attempts(
                                conn,
                                missing_ids,
                                scan_id=str(ch['id']),
                                parent_scan_id=parent_id,
                                campaign_id=campaign_id,
                                worker_id=None,
                                auth_state=auth_state,
                                check_family=attempt_family,
                                started_at=ch['started_at'],
                                completed_at=ch['completed_at'] or completed_at,
                                status='partial',
                                attempted_params_count=0,
                                completed_params_count=0,
                                error_summary='not_reported_by_scanner_telemetry',
                                scanner_telemetry_json={
                                    'source': 'parallel_coverage_merge',
                                    'per_endpoint_telemetry': True,
                                    'missing_from_telemetry': True,
                                    'assigned_endpoints': len(endpoints),
                                    'child_status': str(ch['status'] or ''),
                                    'shard_index': ch['shard_index'],
                                },
                                replace_existing=True,
                            )
                        if not recorded['written'] and not missing_written:
                            print(
                                f"[merge {parent_id[:8]}] telemetry present but no endpoint attempts resolved "
                                f"for shard {ch['shard_index']}",
                                flush=True,
                            )
                        continue
                    endpoint_ids = await asm_inventory.endpoint_ids_for_worklist(
                        conn, target_id, endpoints, auth_state=auth_state
                    )
                    if not endpoint_ids:
                        continue
                    child_status = str(ch['status'] or '')
                    if child_status == 'completed':
                        attempt_status = 'partial'
                        attempted_params = 0
                        completed_params = 0
                        error_summary = 'completed_without_endpoint_telemetry'
                    elif child_status == 'cancelled':
                        attempt_status = 'partial'
                        attempted_params = 0
                        completed_params = 0
                        error_summary = 'cancelled'
                    else:
                        attempt_status = 'error'
                        attempted_params = 0
                        completed_params = 0
                        error_summary = child_status or 'failed'
                    await asm_inventory.record_endpoint_attempts(
                        conn,
                        endpoint_ids,
                        scan_id=str(ch['id']),
                        parent_scan_id=parent_id,
                        campaign_id=campaign_id,
                        worker_id=None,
                        auth_state=auth_state,
                        check_family=attempt_family,
                        started_at=ch['started_at'],
                        completed_at=ch['completed_at'] or completed_at,
                        status=attempt_status,
                        attempted_params_count=attempted_params,
                        completed_params_count=completed_params,
                        error_summary=error_summary,
                        scanner_telemetry_json={
                            'source': 'parallel_coverage_merge',
                            'per_endpoint_telemetry': False,
                            'completed_without_endpoint_telemetry': child_status == 'completed',
                            'assigned_endpoints': len(endpoints),
                            'child_status': child_status,
                            'shard_index': ch['shard_index'],
                        },
                        replace_existing=True,
                    )
                await asm_inventory.finish_campaign(conn, campaign_id, status=parent_status)
                campaign_coverage = await asm_inventory.campaign_attempt_summary(
                    conn,
                    campaign_id,
                    expected_total=int(expected_total or 0) if dynamic_coverage and expected_total else expected_attempts,
                    check_families=parent_options.get('coverage_check_families') if family_aware else None,
                    family_aware=family_aware,
                )
                if _apply_campaign_coverage_rollup(merged, campaign_coverage):
                    filepath = save_result_file(merged, parent_job_id)
                    await conn.execute(
                        "UPDATE scans SET result = $1 WHERE id = $2",
                        json.dumps(merged), uuid.UUID(parent_id),
                    )
        except Exception as e:
            print(f"[merge {parent_id[:8]}] coverage attempt-ledger error: {e}", flush=True)

    # Auto-retest severity-gated findings once, on the parent.
    if parent_status == 'completed' and target_id and union_findings:
        try:
            await queue_auto_retests_for_scan(parent_id, target_id, target_url)
        except Exception as e:
            print(f"[merge {parent_id[:8]}] auto-retest error: {e}", flush=True)

    r.hset(f"job:{parent_job_id}", mapping={
        'status': parent_status,
        'result_path': filepath,
        'score': str(agg_score) if agg_score is not None else 'N/A',
        'grade': str(agg_grade) if agg_grade else 'N/A',
        'completed_at': completed_at.isoformat(),
        'progress': '100',
        'current_phase': parent_status,
    })
    r.expire(f"job:{parent_job_id}", 86400)
    r.delete(parallel_scan.shards_remaining_key(parent_id))
    print(
        f"[merge {parent_id[:8]}] {parent_status} | shards {completed_n}/{len(children)} ok | "
        f"findings(union): {len(union_findings)} saved:{saved} | score:{agg_score} grade:{agg_grade}",
        flush=True,
    )


async def _reconcile_parallel_child_completion(parent_id: str | None, r, log_prefix: str) -> None:
    """Notify the parent barrier that one child reached a terminal state."""
    if not parent_id:
        return
    try:
        r.decr(parallel_scan.shards_remaining_key(parent_id))
    except Exception:
        pass
    try:
        async with db_pool.acquire() as conn:
            enqueued = await parallel_scan.reconcile_parallel_parent(
                conn, parent_id, r, QUEUE_NAME
            )
        if enqueued:
            print(f"[{log_prefix}] all children terminal -> enqueued merge for {parent_id[:8]}", flush=True)
    except Exception as e:
        print(f"[{log_prefix}] merge reconcile error: {e}", flush=True)


async def process_exploit_batch_job(job_data: dict):
    """Continuous ASM exploitation (docs §16): claim a batch of untested/stale
    inventory endpoints, test them, save findings, and stamp the inventory."""
    job_id = job_data.get('job_id', 'unknown')
    scan_id = job_data.get('scan_id')
    parent_id = job_data.get('parent_scan_id')
    target_id = job_data.get('target_id')
    target = job_data.get('target')
    options = job_data.get('options', {}) or {}
    campaign_id = job_data.get('campaign_id')
    batch_size = int(job_data.get('batch_size') or 100)
    stale_days = int(job_data.get('stale_days') if job_data.get('stale_days') is not None else 30)
    exploit_depth = bool(job_data.get('exploit_depth'))
    coverage_dynamic_worker = bool(options.get('coverage_dynamic_worker') or job_data.get('coverage_dynamic_worker'))
    campaign_only = bool(job_data.get('campaign_only') or options.get('coverage_dynamic_campaign_only'))
    check_family = asm_inventory.normalize_check_family(
        job_data.get('check_family')
        or options.get('coverage_attempt_family')
        or options.get('asm_check_family')
        or 'all'
    )
    endpoint_filter = asm_inventory.normalize_endpoint_filter(
        job_data.get('endpoint_filter') or options.get('asm_endpoint_filter')
    )
    finish_campaign_on_complete = bool(job_data.get('finish_campaign_on_complete', not bool(parent_id)))
    worker_id = os.environ.get('HOSTNAME') or os.environ.get('WORKER_ID') or f"worker:{job_id[:8]}"
    r = get_redis()
    now = utc_now()
    slot_acquired = False

    if parent_id:
        async with db_pool.acquire() as conn:
            current = await conn.fetchrow("""
                SELECT child.status, parent.status AS parent_status
                FROM scans child
                LEFT JOIN scans parent ON child.parent_scan_id = parent.id
                WHERE child.id = $1
            """, uuid.UUID(scan_id))
        if current and (current['status'] == 'cancelled' or current['parent_status'] == 'cancelled'):
            print(f"[asm {job_id[:8]}] Coverage batch already cancelled; skipping", flush=True)
            if current['status'] != 'cancelled':
                async with db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE scans
                        SET status = 'cancelled',
                            error_message = 'Cancelled by parent scan',
                            completed_at = NOW(),
                            progress = 100,
                            current_phase = 'cancelled'
                        WHERE id = $1
                    """, uuid.UUID(scan_id))
            r.hset(
                f"job:{job_id}",
                mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
            )
            r.expire(f"job:{job_id}", 86400)
            try:
                async with db_pool.acquire() as conn:
                    await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[asm {job_id[:8]}] merge reconcile error after cancelled batch skip: {e}", flush=True)
            return

    if campaign_only and not campaign_id:
        error_message = "campaign_only exploit batch missing campaign_id"
        print(f"[asm {job_id[:8]}] {error_message}", flush=True)
        async with db_pool.acquire() as conn:
            await conn.execute(
                """UPDATE scans SET status='failed', current_phase='corrupt_shard_context',
                       progress=100, completed_at=$1, error_message=$2 WHERE id=$3""",
                utc_now(), error_message, uuid.UUID(scan_id),
            )
        r.hset(
            f"job:{job_id}",
            mapping={
                'status': 'failed',
                'scan_id': scan_id,
                'current_phase': 'corrupt_shard_context',
                'progress': '100',
                'error_message': error_message,
            },
        )
        r.expire(f"job:{job_id}", 86400)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")
        return

    if parent_id:
        slot_acquired, shard_limit = _try_acquire_parallel_shard_slot(r, parent_id, options)
        if not slot_acquired:
            wait_cycles = int(job_data.get('shard_slot_wait_cycles') or 0) + 1
            requeued = dict(job_data)
            requeued['shard_slot_wait_cycles'] = wait_cycles
            requeued['last_shard_slot_wait_at'] = utc_now_iso()
            r.rpush(QUEUE_NAME, json.dumps(requeued))
            r.hset(f"job:{job_id}", mapping={
                'status': 'queued',
                'scan_id': scan_id,
                'current_phase': 'waiting_for_shard_slot',
                'parallel_shard_concurrency': str(shard_limit),
                'shard_slot_wait_cycles': str(wait_cycles),
            })
            r.expire(f"job:{job_id}", 86400)
            if wait_cycles == 1 or wait_cycles % 15 == 0:
                print(
                    f"[asm {job_id[:8]}] Coverage batch waiting for parent slot "
                    f"({shard_limit} max active children for {parent_id[:8]}; wait_cycle {wait_cycles})",
                    flush=True,
                )
            await asyncio.sleep(PARALLEL_SHARD_REQUEUE_DELAY_SECONDS)
            return

    # Claim the next batch (priority-ordered, FOR UPDATE SKIP LOCKED → work-stealing).
    claimed: list[dict] = []
    try:
        async with db_pool.acquire() as conn:
            claimed = await asm_inventory.claim_test_batch(
                conn,
                target_id,
                limit=batch_size,
                stale_days=stale_days,
                lease_owner=f"{worker_id}:{job_id}",
                campaign_id=campaign_id,
                campaign_only=campaign_only,
                check_family=check_family,
                endpoint_filter=endpoint_filter,
            )
    except Exception as e:
        print(f"[asm {job_id[:8]}] claim error: {e}", flush=True)

    if not claimed:
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET status='completed', current_phase='no_untested_endpoints', progress=100, completed_at=$1, findings_count=0 WHERE id=$2",
                utc_now(), uuid.UUID(scan_id),
            )
            if finish_campaign_on_complete:
                await asm_inventory.finish_campaign(conn, campaign_id, status='completed')
        r.hset(f"job:{job_id}", mapping={'status': 'completed', 'current_phase': 'no_untested_endpoints', 'progress': '100'})
        r.expire(f"job:{job_id}", 86400)
        print(f"[asm {job_id[:8]}] no untested/stale endpoints to test", flush=True)
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")
        return

    auth_state = asm_inventory.normalize_auth_state(claimed[0].get('auth_state') if claimed else "anonymous")
    endpoints = [
        asm_inventory.to_custom_endpoint(
            c['method'], c['path'], c['param_shape'],
            param_location=c.get('param_location') or 'query',
            replay_spec=c.get('replay_spec'),
        )
        for c in claimed
    ]
    endpoint_ids = [c['id'] for c in claimed]

    try:
        async with db_pool.acquire() as conn:
            rate = await _reserve_target_domain_endpoint_budget(
                conn,
                r,
                target_id=target_id,
                amount=len(endpoint_ids),
                already_reserved=int(job_data.get('domain_rate_reserved') or 0),
                all_or_nothing=False,
            )
    except Exception as exc:
        rate = {"granted": 0, "limited": True, "requested": len(endpoint_ids), "reason": str(exc)}
    granted = max(0, int(rate.get("granted") or 0))
    if granted <= 0 and endpoint_ids:
        try:
            async with db_pool.acquire() as conn:
                await _release_claimed_endpoints_for_domain_rate(conn, endpoint_ids)
        except Exception as exc:
            print(f"[asm {job_id[:8]}] domain-rate release error: {exc}", flush=True)
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
            slot_acquired = False
        await _requeue_for_domain_rate(
            r,
            job_data,
            job_id=job_id,
            scan_id=scan_id,
            parent_id=parent_id,
            log_prefix=f"asm {job_id[:8]}",
            rate=rate,
        )
        return
    if 0 < granted < len(endpoint_ids):
        denied_ids = endpoint_ids[granted:]
        try:
            async with db_pool.acquire() as conn:
                await _release_claimed_endpoints_for_domain_rate(conn, denied_ids)
        except Exception as exc:
            print(f"[asm {job_id[:8]}] partial domain-rate release error: {exc}", flush=True)
        claimed = claimed[:granted]
        endpoints = endpoints[:granted]
        endpoint_ids = endpoint_ids[:granted]
        print(
            f"[asm {job_id[:8]}] domain rate limited batch to {granted} endpoint(s) "
            f"for {rate.get('root_domain') or 'unknown'}",
            flush=True,
        )

    print(
        f"[asm {job_id[:8]}] testing {len(endpoints)} inventory endpoints "
        f"(auth_state={auth_state}, check_family={check_family}, endpoint_filter={endpoint_filter or 'all'}, "
        f"exploit_depth={exploit_depth})",
        flush=True,
    )

    # Active testing over the injected endpoints; lean discovery (they're known).
    scoped_opts = _asm_scan_options_for_auth_state(options, auth_state)
    if scoped_opts is None:
        completed_at = utc_now()
        result = {
            'target': target,
            'findings': [],
            'result': {'score': None, 'grade': None},
            'scan_metadata': {
                'asm_auth_state': auth_state,
                'auth_missing': True,
                'claimed_endpoints': len(endpoint_ids),
            },
        }
        filepath = save_result_file(result, job_id)
        try:
            async with db_pool.acquire() as conn:
                await asm_inventory.mark_partial(conn, endpoint_ids, verdict='auth_missing')
                await asm_inventory.record_endpoint_attempts(
                    conn,
                    endpoint_ids,
                    scan_id=scan_id,
                    parent_scan_id=parent_id,
                    campaign_id=campaign_id,
                    worker_id=worker_id,
                    auth_state=auth_state,
                    check_family=check_family,
                    started_at=now,
                    completed_at=completed_at,
                    status='auth_missing',
                    attempted_params_count=0,
                    completed_params_count=0,
                    error_summary=f"auth_state={auth_state} credentials unavailable",
                    scanner_telemetry_json={
                        "claimed_endpoints": len(endpoint_ids),
                        "per_endpoint_telemetry": False,
                    },
                )
                if finish_campaign_on_complete:
                    await asm_inventory.finish_campaign(conn, campaign_id, status='completed')
                await conn.execute(
                    """UPDATE scans SET status='completed', result=$1, score=NULL, grade=NULL,
                           findings_count=0, completed_at=$2, duration_seconds=0,
                           progress=100, current_phase='auth_missing', error_message=NULL
                       WHERE id=$3""",
                    json.dumps(result), completed_at, uuid.UUID(scan_id),
                )
        except Exception as e:
            print(f"[asm {job_id[:8]}] auth-missing inventory stamp error: {e}", flush=True)
        r.hset(f"job:{job_id}", mapping={
            'status': 'completed',
            'result_path': filepath,
            'completed_at': completed_at.isoformat(),
            'progress': '100',
            'current_phase': 'auth_missing',
        })
        r.expire(f"job:{job_id}", 86400)
        print(
            f"[asm {job_id[:8]}] skipped {len(endpoint_ids)} endpoints: "
            f"auth_state={auth_state} no longer available",
            flush=True,
        )
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")
        return

    scan_opts = scoped_opts
    scan_opts['scan_type'] = scan_opts.get('scan_type') or 'smart'
    scan_opts['parallel'] = False
    for k in ('shard_strategy', 'shards', 'auth_state_shards'):
        scan_opts.pop(k, None)
    scan_opts['custom_endpoints'] = endpoints
    if coverage_dynamic_worker:
        scan_opts['focused_endpoints_only'] = True
        scan_opts['zero_rediscovery'] = True
        scan_opts['skip_global_checks'] = True
    _active_secs = min(2400, max(120, 8 * len(endpoints)))
    lean = {
        'max_urls': 200, 'browser_max_pages': 5, 'browser_max_depth': 1,
        'param_discovery_url_limit': 0, 'param_discovery_max_params': 0,
        'nuclei_max_targets': 50,
        'active_max_endpoints': len(endpoints),
        'active_max_seconds': _active_secs,
        # Bound the WHOLE batch so a hang on a slow/remote endpoint can't tie up
        # the claimed in_progress endpoints for hours (the target's default smart
        # max_duration is 600 min). Active budget + overhead for discovery/nuclei.
        'max_duration_minutes': max(5, min(30, (_active_secs // 60) + 5)),
    }
    if coverage_dynamic_worker:
        lean.update({
            'browser_max_pages': 0,
            'api_probe_limit': 0,
            'nuclei_max_targets': 0,
            'phase4_max_seconds': 0,
        })
    if exploit_depth:
        scan_opts['no_early_stop'] = True
        lean.update({'sqli_extract_max': 8, 'oob_max_findings': 8, 'max_findings_per_family': None})
    parallel_scan._merge_custom_budget(scan_opts, lean)

    async with db_pool.acquire() as conn:
        update_result = await conn.execute(
            """
            UPDATE scans SET status='running', started_at=$1, current_phase='asm_exploit'
            WHERE id=$2 AND status <> 'cancelled'
            """,
            now, uuid.UUID(scan_id),
        )
    if update_result.endswith("0"):
        print(f"[asm {job_id[:8]}] Coverage batch cancelled before start; releasing claimed endpoints", flush=True)
        try:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """UPDATE target_endpoints
                       SET test_status='untested', last_attempt_status='cancelled',
                           lease_owner=NULL, lease_expires_at=NULL, updated_at=NOW()
                       WHERE id = ANY($1::uuid[]) AND test_status='in_progress'""",
                    endpoint_ids,
                )
        except Exception:
            pass
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
        r.hset(
            f"job:{job_id}",
            mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
        )
        r.expire(f"job:{job_id}", 86400)
        if parent_id:
            try:
                async with db_pool.acquire() as conn:
                    await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)
            except Exception as e:
                print(f"[asm {job_id[:8]}] merge reconcile error after cancelled batch start: {e}", flush=True)
        return
    r.hset(f"job:{job_id}", mapping={'status': 'running', 'scan_id': scan_id, 'started_at': now.isoformat(), 'heartbeat': now.isoformat()})

    stop_heartbeat = threading.Event()
    hb = threading.Thread(target=send_heartbeats, args=(job_id, stop_heartbeat), name=f"heartbeat-{job_id[:8]}", daemon=True)
    hb.start()
    error = None
    try:
        try:
            result = await run_scan(target, scan_opts, scan_id=scan_id, job_id=job_id)
        except Exception as e:
            result = {'target': target, 'error': str(e), 'result': {'score': None, 'grade': None}, 'findings': []}
        findings = result.get('findings', []) or []
        error = result.get('error')
        meta = result.get('scan_metadata') if isinstance(result.get('scan_metadata'), dict) else {}
        partial = bool(meta.get('partial') or meta.get('timed_out'))
        score = result.get('result', {}).get('score')
        grade = result.get('result', {}).get('grade')
        filepath = save_result_file(result, job_id)
        completed_at = utc_now()
        duration = int((completed_at - now).total_seconds())
        saved = 0
        if target_id and findings and not error and not parent_id:
            try:
                saved = await save_findings(scan_id, target_id, findings)
            except Exception as e:
                print(f"[asm {job_id[:8]}] save_findings error: {e}", flush=True)
        if not error:
            try:
                async with db_pool.acquire() as conn:
                    telemetry_present = _active_endpoint_telemetry_present(result)
                    attempts = _active_endpoint_attempts_from_report(result)
                    if telemetry_present:
                        recorded = {'completed_ids': [], 'partial_ids': [], 'error_ids': []}
                        if attempts:
                            recorded = await _record_endpoint_telemetry_attempts(
                                conn,
                                target_id=target_id,
                                attempts=attempts,
                                scan_id=scan_id,
                                parent_scan_id=parent_id,
                                campaign_id=campaign_id,
                                worker_id=worker_id,
                                auth_state=auth_state,
                                check_family=check_family,
                                started_at=now,
                                completed_at=completed_at,
                                source='dynamic_full_coverage_batch' if coverage_dynamic_worker else 'asm_exploit_batch',
                            )
                        completed_ids = list(dict.fromkeys(recorded['completed_ids']))
                        incomplete_ids = list(dict.fromkeys(recorded['partial_ids'] + recorded['error_ids']))
                        accounted = {str(eid) for eid in completed_ids + incomplete_ids}
                        missing_ids = [eid for eid in endpoint_ids if str(eid) not in accounted]
                        if completed_ids:
                            await asm_inventory.mark_tested(
                                conn,
                                completed_ids,
                                verdict=('findings' if findings else 'clean'),
                            )
                        if missing_ids:
                            incomplete_ids.extend(missing_ids)
                            await asm_inventory.record_endpoint_attempts(
                                conn,
                                missing_ids,
                                scan_id=scan_id,
                                parent_scan_id=parent_id,
                                campaign_id=campaign_id,
                                worker_id=worker_id,
                                auth_state=auth_state,
                                check_family=check_family,
                                started_at=now,
                                completed_at=completed_at,
                                status='partial',
                                attempted_params_count=0,
                                completed_params_count=0,
                                error_summary='not_reported_by_scanner_telemetry',
                                scanner_telemetry_json={
                                    "claimed_endpoints": len(endpoint_ids),
                                    "per_endpoint_telemetry": True,
                                    "missing_from_telemetry": True,
                                },
                            )
                        incomplete_ids = list(dict.fromkeys(incomplete_ids))
                        if incomplete_ids:
                            verdict = 'partial_findings' if findings else ('partial_timeout' if meta.get('timed_out') else 'partial')
                            await asm_inventory.mark_partial(conn, incomplete_ids, verdict=verdict)
                    elif partial:
                        verdict = 'partial_findings' if findings else ('partial_timeout' if meta.get('timed_out') else 'partial')
                        await asm_inventory.mark_partial(conn, endpoint_ids, verdict=verdict)
                        await asm_inventory.record_endpoint_attempts(
                            conn,
                            endpoint_ids,
                            scan_id=scan_id,
                            parent_scan_id=parent_id,
                            campaign_id=campaign_id,
                            worker_id=worker_id,
                            auth_state=auth_state,
                            check_family=check_family,
                            started_at=now,
                            completed_at=completed_at,
                            status='timeout' if meta.get('timed_out') else 'partial',
                            attempted_params_count=0,
                            completed_params_count=0,
                            error_summary=verdict,
                            scanner_telemetry_json={
                                "claimed_endpoints": len(endpoint_ids),
                                "findings_count": len(findings),
                                "per_endpoint_telemetry": False,
                                "partial": True,
                                "timed_out": bool(meta.get('timed_out')),
                            },
                        )
                    else:
                        verdict = 'partial_findings' if findings else 'missing_endpoint_telemetry'
                        await asm_inventory.mark_partial(conn, endpoint_ids, verdict=verdict)
                        await asm_inventory.record_endpoint_attempts(
                            conn,
                            endpoint_ids,
                            scan_id=scan_id,
                            parent_scan_id=parent_id,
                            campaign_id=campaign_id,
                            worker_id=worker_id,
                            auth_state=auth_state,
                            check_family=check_family,
                            started_at=now,
                            completed_at=completed_at,
                            status='partial',
                            attempted_params_count=0,
                            completed_params_count=0,
                            error_summary='completed_without_endpoint_telemetry',
                            scanner_telemetry_json={
                                "claimed_endpoints": len(endpoint_ids),
                                "findings_count": len(findings),
                                "per_endpoint_telemetry": False,
                                "completed_without_endpoint_telemetry": True,
                            },
                        )
                    if finish_campaign_on_complete:
                        await asm_inventory.finish_campaign(conn, campaign_id, status='completed')
                    wl = (result.get('active_checks') or {}).get('active_worklist')
                    if wl:  # keep inventory fresh with anything new this run surfaced
                        await asm_inventory.upsert_endpoints(conn, target_id, wl, source='asm', auth_state=auth_state)
            except Exception as e:
                print(f"[asm {job_id[:8]}] inventory stamp error: {e}", flush=True)
        else:
            try:
                async with db_pool.acquire() as conn:
                    await asm_inventory.record_endpoint_attempts(
                        conn,
                        endpoint_ids,
                        scan_id=scan_id,
                        parent_scan_id=parent_id,
                        campaign_id=campaign_id,
                        worker_id=worker_id,
                        auth_state=auth_state,
                        check_family=check_family,
                        started_at=now,
                        completed_at=completed_at,
                        status='error',
                        attempted_params_count=0,
                        completed_params_count=0,
                        error_summary=str(error)[:1000],
                        scanner_telemetry_json={
                            "claimed_endpoints": len(endpoint_ids),
                            "per_endpoint_telemetry": False,
                        },
                    )
                    if finish_campaign_on_complete:
                        await asm_inventory.finish_campaign(conn, campaign_id, status='failed')
            except Exception as e:
                print(f"[asm {job_id[:8]}] attempt-ledger error stamp failed: {e}", flush=True)
        terminal_phase = 'failed' if error else ('partial' if partial else 'completed')
        final_status = 'failed' if error else 'completed'
        async with db_pool.acquire() as conn:
            current = await conn.fetchrow("SELECT status FROM scans WHERE id = $1", uuid.UUID(scan_id))
            if current and current['status'] in ('failed', 'cancelled'):
                final_status = current['status']
                terminal_phase = current['status']
            else:
                await conn.execute(
                    """UPDATE scans SET status=$1, result=$2, score=$3, grade=$4, findings_count=$5,
                           completed_at=$6, duration_seconds=$7, progress=100, current_phase=$8,
                           error_message=$10 WHERE id=$9""",
                    final_status, json.dumps(result), score, grade, len(findings),
                    completed_at, duration, terminal_phase, uuid.UUID(scan_id),
                    (error if error else None),
                )
        r.hset(f"job:{job_id}", mapping={
            'status': final_status, 'result_path': filepath,
            'completed_at': completed_at.isoformat(), 'progress': '100',
            'current_phase': terminal_phase,
        })
        r.expire(f"job:{job_id}", 86400)
        print(
            f"[asm {job_id[:8]}] done | tested {len(endpoints)} | auth_state {auth_state} | "
            f"findings {len(findings)} (saved {saved}) | partial {partial} | error {bool(error)}",
            flush=True,
        )
    finally:
        stop_heartbeat.set()
        hb.join(timeout=max(1.0, HEARTBEAT_INTERVAL_SECONDS / 2))
        # Release any endpoints still 'in_progress' (error/crash) back to 'untested' to retry later.
        try:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """UPDATE target_endpoints
                       SET test_status='untested', last_attempt_status='failed',
                           lease_owner=NULL, lease_expires_at=NULL, updated_at=NOW()
                       WHERE id = ANY($1::uuid[]) AND test_status='in_progress'""",
                    endpoint_ids,
                )
        except Exception:
            pass
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")


async def process_job(job_data: dict):
    """Route job to appropriate handler."""
    job_type = job_data.get('type', 'scan')

    if job_type == 'discovery':
        await process_discovery_job(job_data)
    elif job_type == 'finding_retest':
        await process_finding_retest_job(job_data)
    elif job_type == parallel_scan.PLAN_JOB_TYPE:
        await process_scan_plan_job(job_data)
    elif job_type == parallel_scan.SHARD_JOB_TYPE:
        await process_scan_shard_job(job_data)
    elif job_type == parallel_scan.MERGE_JOB_TYPE:
        await process_scan_merge_job(job_data)
    elif job_type == asm_inventory.EXPLOIT_BATCH_JOB_TYPE:
        await process_exploit_batch_job(job_data)
    else:
        await process_scan_job(job_data)


async def async_main():
    """Async main worker loop - uses single event loop for database pool."""
    print("Initializing worker...", flush=True)

    # Initialize database pool (bound to this event loop)
    await init_db()

    r = get_redis()
    queue_keys = [QUEUE_NAME] if RETEST_QUEUE_NAME == QUEUE_NAME else [QUEUE_NAME, RETEST_QUEUE_NAME]
    print(
        f"Worker started, listening on queues: {', '.join(queue_keys)} "
        f"(retest max parallel: {RETEST_MAX_PARALLEL})",
        flush=True,
    )

    loop = asyncio.get_event_loop()
    last_stale_check_monotonic = 0.0

    try:
        while True:
            try:
                now_mono = loop.time()
                if (
                    RETEST_STALE_CHECK_INTERVAL_SECONDS > 0
                    and now_mono - last_stale_check_monotonic >= RETEST_STALE_CHECK_INTERVAL_SECONDS
                ):
                    try:
                        await reap_stale_retests()
                        await requeue_circuit_recovered_retests()
                    except Exception as stale_err:
                        print(f"[watchdog] stale retest sweep error: {stale_err}", flush=True)
                    finally:
                        last_stale_check_monotonic = now_mono

                # Use run_in_executor for blocking Redis pop
                result = await loop.run_in_executor(None, lambda: r.blpop(queue_keys, timeout=30))
                if result is None:
                    continue  # Timeout, continue polling

                _, job_json = result
                job_data = json.loads(job_json)
                await process_job(job_data)
            except asyncio.CancelledError:
                # Graceful shutdown requested (SIGTERM/SIGINT)
                print("Worker received shutdown signal, exiting...", flush=True)
                raise
            except Exception as e:
                print(f"Error processing job: {e}", flush=True)
                import traceback
                traceback.print_exc()
    except asyncio.CancelledError:
        # Clean shutdown
        pass
    finally:
        # Close database pool
        if db_pool:
            await db_pool.close()
        print("Worker shutdown complete", flush=True)


def main():
    """Entry point - runs async main in single event loop."""
    # Run blocking preflight subprocesses synchronously before entering the
    # event loop so they cannot stall asyncio tasks or healthchecks.
    run_worker_preflight()
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
