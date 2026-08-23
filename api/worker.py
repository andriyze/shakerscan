#!/usr/bin/env python3
"""
ShakerScan Worker - Open Source Edition
Redis-based job worker with PostgreSQL persistence.
"""

import asyncio
import copy
import functools
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import uuid
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Mapping

import asyncpg
import redis

try:
    from release_identity import build_fingerprint as release_build_fingerprint
    from release_identity import published_scanner_version
except ModuleNotFoundError:
    from scanner.release_identity import build_fingerprint as release_build_fingerprint
    from scanner.release_identity import published_scanner_version

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
from runtime.json_fields import json_array_field, json_object_field
import parallel_scan
import asm_inventory
import family_proof
import agent_tools
from capabilities.network import (
    CapabilityInputError,
    NetworkExecutionAdapter,
    network_capability_adapter,
)
from capabilities.browser import BrowserCapabilityInputError, browser_capability_adapter
from capabilities.http import execute_bound_http_request
from capabilities.auth import establish_target_bound_http_session
from capabilities.authz import (
    authz_route_inventory_digest,
    verify_target_bound_object_authorization,
)
from capabilities.dns import inspect_dns_posture
from capabilities.inline import (
    AuthSessionExecutionAdapter,
    AuthzVerificationExecutionAdapter,
    DnsInspectionExecutionAdapter,
    HttpRequestExecutionAdapter,
    TlsInspectionExecutionAdapter,
)
from capabilities.scanner import ScannerExecutionAdapter
from capabilities.scan import DeterministicScanExecutionAdapter
from capabilities.tls import inspect_tls_origin
from capabilities.replay import ReplayExecutionAdapter
from hunt.capability_reservations import (
    DURABLE_BROWSER_HUNT_CAPABILITIES,
    DURABLE_SCANNER_HUNT_CAPABILITIES,
    DURABLE_WORKER_HUNT_CAPABILITIES,
    hunt_capability_action_digest,
    hunt_capability_lease_seconds,
    terminalize_hunt_capability,
)
from hunt.capability_executor import CapabilityExecutionContext, CapabilityExecutor
from runtime.budget_reservations import DurableBudgetReservation
from runtime.budgets import BudgetExceeded
from runtime.capability_settlement import terminalize_capability_reservation
from runtime.receipts import CapabilityReceipt
from runtime.credential_resolver import (
    CredentialResolutionError,
    WorkerCredentialResolver,
    validate_worker_credential_authority,
)
from runtime.credential_refs import (
    CredentialReferenceError,
    select_hunt_principal_reference,
)
from runtime.models import PreparedExecution, ScanPolicy, TargetBinding
from runtime.request_collection_store import (
    RequestCollectionContractError,
    RequestCollectionSelection,
    request_collection_selection_digest,
)
from runtime.scan_credentials import (
    SCAN_CREDENTIAL_CAPABILITY,
    ScanCredentialError,
    bind_resolved_scan_credential,
    bind_scan_session_headers,
    resolve_scan_http_principal,
    resolve_scan_interactive_credential,
)
from scan.collection_replay import (
    EXECUTABLE_REPLAY_POLICIES,
    ScanCollectionReplayContractError,
    merge_scan_budget_usage,
    remaining_scan_replay_capacity,
    scan_replay_authorization,
    scan_replay_ledger_limits,
    scan_replay_runtime_http_ceiling,
    scan_replay_selector,
)
from scan.capability_execution import (
    ScanCapabilityContractError,
    fit_prepared_scan_capability,
    prepare_scan_external_capability,
    prepare_scan_inline_capability,
    scan_content_discovery_capability_allocation,
    scan_dns_posture_capability_allocation,
    scan_http_baseline_capability_allocation,
    scan_budget_ledger_limits,
    scan_capability_action_digest,
    scan_external_execution_target,
    scan_network_capability_allocation,
    scan_parameterized_execution_candidates,
    scan_sqli_verification_capability_allocation,
    scan_template_capability_allocation,
    scan_tls_capability_allocation,
    scan_web_crawl_capability_allocation,
    scan_web_probe_capability_allocation,
    scan_xss_verification_capability_allocation,
    prepare_scan_process_capability,
)
from scan.worker_dispatch import (
    execution_result_metadata,
    is_deterministic_dast,
    prepare_worker_dispatch,
)
from scan.authorization import (
    ActionAuthorityDecision,
    revalidate_scan_action_authority,
)
from scan.executor import build_native_scan_execution
from scan.stages import (
    ScanStageCancelled,
    ScanStageContext,
    ScanStageRunResult,
    execute_scan_stage_graph,
)
from scan.stage_store import PostgresScanStageCheckpointStore
from scan.surface_manifest import build_scan_surface_manifest
from scan.placement_transport import write_private_placement_bundle
from scan.jobs import (
    CanonicalScanJob,
    CanonicalScanJobError,
    SCAN_JOB_SCHEMA,
    ScanShardAuthority,
    admitted_credential_profile_ids,
    admitted_request_collection_job_refs,
    derive_scan_shard_budget,
    scan_job_options_digest,
)
from scan.job_runtime import (
    CanonicalScanJobMaterializationError,
    materialize_canonical_scan_job,
)
from runtime.pinned_http_replay import PinnedAiohttpReplayTransport
from runtime.request_replay_executor import (
    ReplayExecutionError,
    replay_reservation_budget,
)
from runtime.reservation_recovery import recover_stale_reservations
from runtime.reservation_store import (
    PostgresBudgetReservationStore,
    ReservationConflict,
    ReservationStoreError,
)
from pinned_socks_proxy import PinnedSocksProxy
import investigation_candidates
from worker_queue_policy import base_worker_queue_keys, worker_role
from model_intake_admissions import persist_from_result as persist_model_intake_admission
from job_queue import (
    DEFAULT_WORKER_TOOL_COMMANDS,
    QueueLease,
    acknowledge_lease,
    enqueue_job,
    heartbeat_lease,
    lease_job,
    placement_from_payload,
    qualified_route_queues,
    worker_matches_placement,
)
try:
    from scanner_tools.attempt_telemetry import (
        endpoint_attempt_schema_from_report,
        normalize_endpoint_attempt,
    )
    from scanner_tools.build_fingerprint import hash_source_files, runtime_file_map
    from scanner_tools.device_web import run_pinned_device_web_scan
    from scanner_tools.request_collections import RequestSelector, select_requests
    from scanner_tools.request_replay import (
        ReplayAuthorization,
        RequestReplayError,
        bind_replay_credential_headers,
        build_selected_replay_plan,
    )
    from scanner_tools import device_advisories
    from scanner_tools.common import run_streaming
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:
    from scanner.scanner_tools.attempt_telemetry import (
        endpoint_attempt_schema_from_report,
        normalize_endpoint_attempt,
    )
    from scanner.scanner_tools.build_fingerprint import hash_source_files, runtime_file_map
    from scanner.scanner_tools.device_web import run_pinned_device_web_scan
    from scanner.scanner_tools.request_collections import RequestSelector, select_requests
    from scanner.scanner_tools.request_replay import (
        ReplayAuthorization,
        RequestReplayError,
        bind_replay_credential_headers,
        build_selected_replay_plan,
    )
    from scanner.scanner_tools import device_advisories
    from scanner.scanner_tools.common import run_streaming
    from scanner.scanner_tools.url_redaction import redact_url
from evidence_storage import serialize_evidence_content, store_evidence_content
from artifact_storage import (
    ArtifactStorageError,
    guess_content_type as artifact_content_type,
    object_key as artifact_object_key,
    remote_required as artifact_remote_required,
    store_bytes as store_artifact_bytes,
    store_json as store_artifact_json,
    upsert_manifest as upsert_artifact_manifest,
)
from secret_store import decrypt_secret
try:
    from redaction import redact_text
except ModuleNotFoundError:
    from scanner.redaction import redact_text
try:
    from action_scope import evaluate_runtime_destination_scope
except ImportError:
    from api.action_scope import evaluate_runtime_destination_scope

try:
    from constants import resolve_scan_budget, resolve_or_consume_budget
except ImportError:
    from scanner.constants import resolve_scan_budget, resolve_or_consume_budget
try:
    from findings import templated_finding_identity as _templated_finding_identity
except ModuleNotFoundError as exc:
    if exc.name != "findings":
        raise
    from scanner.findings import templated_finding_identity as _templated_finding_identity

# Configuration
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379')
DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@localhost:5432/scanner')
RESULTS_DIR = Path(os.environ.get('RESULTS_DIR', '/results'))
QUEUE_NAME = 'scan_jobs'
DEVICE_QUEUE_NAME = os.environ.get("DEVICE_QUEUE_NAME", "device_scan_jobs")
DEVICE_ONLY_WORKER = str(os.environ.get("DEVICE_ONLY_WORKER", "false")).strip().lower() in {"1", "true", "yes", "on"}
AGENT_TOOL_ONLY_WORKER = str(os.environ.get("AGENT_TOOL_ONLY_WORKER", "false")).strip().lower() in {"1", "true", "yes", "on"}
WORKER_BUILD_REGISTRY_KEY = worker_role(
    device_only=DEVICE_ONLY_WORKER,
    agent_tool_only=AGENT_TOOL_ONLY_WORKER,
)[1]
RETEST_QUEUE_NAME = os.environ.get("RETEST_QUEUE_NAME", "retest_jobs")
BROKER_INGEST_QUEUE_NAME = os.environ.get("BROKER_INGEST_QUEUE_NAME", "broker_ingest_jobs")
AGENT_TOOL_QUEUE_NAME = os.environ.get("AGENT_TOOL_QUEUE_NAME", "agent_tool_jobs")
AI_GATE_RUN_KINDS = {"ai_api", "ai_rag", "ai_trace", "ai_mcp", "ai_widget"}
MODEL_INTAKE_RUN_KINDS = {"model_intake"}
ASM_RECON_RUN_KINDS = {"asm_recon"}
ASM_BATCH_RUN_KINDS = {"asm_batch", "asm_dynamic_batch"}
SCANNER_PATH = '/app/scanner.py'
SCAN_LOG_TAIL = int(os.environ.get('SCAN_LOG_TAIL', '200'))
SCAN_LOG_TTL_SECONDS = int(os.environ.get('SCAN_LOG_TTL_SECONDS', '86400'))
HEARTBEAT_INTERVAL_SECONDS = int(os.environ.get('HEARTBEAT_INTERVAL_SECONDS', '30'))
WORKER_QUEUE_BLOCK_SECONDS = max(1, int(os.environ.get("WORKER_QUEUE_BLOCK_SECONDS", "30")))
QUEUE_VISIBILITY_TIMEOUT_SECONDS = max(
    60,
    int(os.environ.get("SHAKERSCAN_QUEUE_VISIBILITY_TIMEOUT_SECONDS", "300")),
)
QUEUE_LEASE_HEARTBEAT_SECONDS = max(
    5,
    min(
        QUEUE_VISIBILITY_TIMEOUT_SECONDS // 3,
        int(os.environ.get("SHAKERSCAN_QUEUE_LEASE_HEARTBEAT_SECONDS", "30")),
    ),
)
QUEUE_MAX_DELIVERY_ATTEMPTS = max(
    1,
    int(os.environ.get("SHAKERSCAN_QUEUE_MAX_DELIVERY_ATTEMPTS", "5")),
)
QUEUE_LEASE_HEARTBEAT_FAILURE_LIMIT = max(
    1,
    int(os.environ.get("SHAKERSCAN_QUEUE_LEASE_HEARTBEAT_FAILURE_LIMIT", "3")),
)
ARTIFACT_CHECKPOINT_INTERVAL_SECONDS = max(
    2,
    int(os.environ.get("ARTIFACT_CHECKPOINT_INTERVAL_SECONDS", "15")),
)
ARTIFACT_REFERENCED_FILE_MAX_BYTES = max(
    1024,
    int(os.environ.get("ARTIFACT_REFERENCED_FILE_MAX_BYTES", str(25 * 1024 * 1024))),
)
ARTIFACT_REFERENCED_FILE_MAX_COUNT = max(
    1,
    int(os.environ.get("ARTIFACT_REFERENCED_FILE_MAX_COUNT", "50")),
)
WORKER_REDIS_SOCKET_TIMEOUT_SECONDS = max(
    WORKER_QUEUE_BLOCK_SECONDS + 5,
    int(os.environ.get("WORKER_REDIS_SOCKET_TIMEOUT_SECONDS", "35")),
)
TOOL_RECEIPT_ADAPTER_VERSION = "2026-07-05.v1"
DEVICE_SSH_AUTH_COOLDOWN_SECONDS = max(60, int(os.environ.get("DEVICE_SSH_AUTH_COOLDOWN_SECONDS", "1800")))
DEVICE_SSH_AUTH_DAILY_FAILURE_CAP = max(1, int(os.environ.get("DEVICE_SSH_AUTH_DAILY_FAILURE_CAP", "3")))

# Maximum allowed duration per scan type (minutes) - worker-side safety net
MAX_SCAN_DURATION = {
    'quick': 15,
    'standard': 45,
    'deep': 120,
    'full': 600,        # 10 hours
    'aggressive': 600,  # 10 hours
    'smart': 360,
    'device_probe': 5,
}
VALID_DAST_SCAN_TYPES = {"quick", "standard", "deep", "full", "aggressive", "smart"}
DEVICE_RUN_KINDS = {"device_posture", "device_probe", "device_web_dast"}
ACTIVE_ENFORCED_SCAN_TYPES = {"smart", "full", "aggressive"}
SCANNER_AUTH_CONFIG_KEYS = {
    "api_token",
    "auth_cookies",
    "auth_header",
    "auth_headers_json",
    "auth_scenario_json",
    "login_url",
    "login_username",
    "login_password",
    "login_extra_fields",
    "auto_auth",
    "oauth_client_id",
    "oauth_client_secret",
    "oauth_token_url",
    "oauth_scope",
    "oauth_username",
    "oauth_password",
    "user2_cookies",
    "user2_header",
    "user2_login_url",
    "user2_login_username",
    "user2_login_password",
}

FOCUSED_MERGE_FAMILY_RULES = {
    "sqli": {
        "tools": {"smart_sqli", "sqlmap", "sqli", "nosql_injection", "nosql"},
        "cwes": {"CWE-89", "CWE-943"},
        "title_markers": ("sql injection", "nosql", "injection"),
    },
    "xss": {
        "tools": {"active_xss", "dom_xss", "xss", "dalfox"},
        "cwes": {"CWE-79"},
        "title_markers": ("xss", "cross-site scripting", "script execution"),
    },
    "auth": {
        "tools": {"smart_auth", "auth_access"},
        "cwes": {"CWE-287", "CWE-306"},
        "title_markers": ("authentication", "authorization", "access control"),
    },
    "bola": {
        "tools": {"smart_bola", "smart_authz"},
        "cwes": {"CWE-639", "CWE-862", "CWE-863"},
        "title_markers": ("bola", "idor", "object authorization", "object level authorization"),
    },
}


def utc_now() -> datetime:
    """Return UTC as a naive datetime to match existing DB timestamp columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def _naive_utc_timestamp(value: Any) -> datetime | None:
    """Normalize PostgreSQL TIMESTAMPTZ values to the worker's naive-UTC clock."""
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _scanner_auth_config_from_options(options: dict[str, Any]) -> dict[str, Any]:
    """Extract DAST auth material for scanner subprocess file handoff."""
    if not isinstance(options, dict):
        return {}
    config: dict[str, Any] = {}
    for key in sorted(SCANNER_AUTH_CONFIG_KEYS):
        value = options.get(key)
        if value is None:
            continue
        if isinstance(value, str) and not value:
            continue
        config[key] = value
    return config


def _write_scanner_auth_config_file(config: dict[str, Any]) -> str | None:
    if not config:
        return None
    fd, path = tempfile.mkstemp(prefix="shakerscan-auth-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(config, f, sort_keys=True, separators=(",", ":"))
        os.chmod(path, 0o600)
        return path
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


_RECEIPT_SENSITIVE_KEYS = {
    "authorization",
    "authorization_header",
    "auth_header",
    "bearer_token",
    "cookie",
    "cookies",
    "credential",
    "password",
    "private_key",
    "secret",
    "signature",
    "token",
}


def _redact_receipt_value(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            out[key] = "***" if normalized in _RECEIPT_SENSITIVE_KEYS and nested not in (None, "", [], {}) else _redact_receipt_value(nested)
        return out
    if isinstance(value, list):
        return [_redact_receipt_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_receipt_value(item) for item in value]
    if isinstance(value, str):
        redacted = re.sub(r"(://)[^/\s@]+@", r"\1***@", value)
        redacted = re.sub(r"(?i)(bearer|token|secret|password|signature|api[_-]?key)=([^&\s]+)", r"\1=***", redacted)
        redacted = re.sub(r"(?i)(authorization:\s*bearer\s+)[^\s,;]+", r"\1***", redacted)
        redacted = re.sub(r"(?i)\b(secret|token|password|api[_-]?key)[-_a-z0-9]*\b", "***", redacted)
        return redacted
    return value


def _tool_receipt_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


async def _acquire_evidence_blob_lock(conn, content: Any) -> str | None:
    """Serialize writers with retention GC for the same content-addressed blob."""
    _raw, content_sha256, _size = serialize_evidence_content(content)
    if content_sha256:
        await conn.fetchval(
            "SELECT pg_advisory_lock(hashtextextended($1, 0))",
            f"evidence-blob:{content_sha256}",
        )
    return content_sha256


async def _release_evidence_blob_lock(conn, content_sha256: str | None) -> None:
    if not content_sha256:
        return
    try:
        await conn.fetchval(
            "SELECT pg_advisory_unlock(hashtextextended($1, 0))",
            f"evidence-blob:{content_sha256}",
        )
    except Exception:
        # A broken/closed connection releases session advisory locks itself.
        pass


async def _acquire_evidence_identity_lock(conn, finding_id: Any, object_type: str) -> str | None:
    """Serialize a finding/object upsert with retention intent for that exact row."""
    if not finding_id or not object_type:
        return None
    key = f"evidence-row:{finding_id}:{object_type}"
    await conn.fetchval("SELECT pg_advisory_lock(hashtextextended($1, 0))", key)
    return key


async def _release_evidence_identity_lock(conn, key: str | None) -> None:
    if not key:
        return
    try:
        await conn.fetchval("SELECT pg_advisory_unlock(hashtextextended($1, 0))", key)
    except Exception:
        pass


async def _persist_tool_output_artifact(
    conn,
    *,
    scan_id: str,
    tool_name: str,
    command_hash: str,
    stream_name: str,
    artifact: Any,
) -> str | None:
    if not isinstance(artifact, dict) or not artifact.get("content"):
        return None
    locked_sha: str | None = None
    try:
        content = _redact_receipt_value({
            "tool_name": tool_name,
            "command_hash": command_hash,
            "stream": stream_name,
            "content": artifact.get("content"),
            "original_length": artifact.get("original_length"),
            "redacted_length": artifact.get("redacted_length"),
            "captured_length": artifact.get("captured_length"),
            "truncated": bool(artifact.get("truncated")),
            "source_content_sha256": artifact.get("content_sha256"),
        })
        locked_sha = await _acquire_evidence_blob_lock(conn, content)
        stored = store_evidence_content(content, results_dir=RESULTS_DIR)
        row = await conn.fetchrow(
            """
            INSERT INTO evidence_objects (
                scan_id, finding_id, object_type, content_sha256, size_bytes,
                storage_uri, redaction_profile, retention_class, content
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            RETURNING id
            """,
            uuid.UUID(str(scan_id)),
            None,
            f"tool_{stream_name}_artifact"[:64],
            stored["content_sha256"],
            stored["size_bytes"],
            stored["storage_uri"],
            "subprocess_output_redact_v1",
            "standard",
            stored["content"],
        )
        return str(row["id"]) if row and row["id"] else None
    except Exception as exc:
        print(f"[tool-receipt] output artifact persist failed for {tool_name}/{stream_name}: {type(exc).__name__}: {exc}", flush=True)
        return None
    finally:
        await _release_evidence_blob_lock(conn, locked_sha)


def _internal_executor_receipt_spec(options: dict[str, Any]) -> dict[str, str] | None:
    run_kind = str((options or {}).get("run_kind") or "").strip()
    if run_kind == "device_probe":
        return {
            "tool_name": "device_service_state_verifier",
            "parser_status_key": "device_probe",
            "parser": "device-probe-v1",
            "proof_contract": "fixed-device-single-service-state",
        }
    if run_kind in AI_GATE_RUN_KINDS:
        return {
            "tool_name": "ai_gate_probe_executor",
            "parser_status_key": "ai_gate",
            "parser": "ai-gate-transcript-v1",
            "proof_contract": "deterministic-or-judge-evidence",
        }
    if run_kind in MODEL_INTAKE_RUN_KINDS:
        return {
            "tool_name": "model_intake_signature_verifier",
            "parser_status_key": "model_intake",
            "parser": "model-intake-summary-v1",
            "proof_contract": "cryptographic-signature-verification",
        }
    if run_kind in ASM_RECON_RUN_KINDS:
        return {
            "tool_name": "asm_recon_executor",
            "parser_status_key": "discovery",
            "parser": "asm-recon-summary-v1",
            "proof_contract": "endpoint-inventory-evidence",
        }
    return None


async def _record_internal_executor_tool_receipt(
    conn,
    *,
    scan_id: str,
    job_id: str | None,
    target: str,
    target_id: str | None,
    ai_target_id: str | None,
    options: dict[str, Any],
    result: dict[str, Any],
    started_at: datetime,
    completed_at: datetime,
    duration_seconds: int,
    error: Any,
) -> str | None:
    """Best-effort receipt emission for built-in product executors.

    This records execution metadata only. It never promotes findings, updates
    proof state, or changes the scan terminal status.
    """
    spec = _internal_executor_receipt_spec(options)
    if not spec:
        return None
    run_kind = str((options or {}).get("run_kind") or "")
    product_payload = result.get(spec["parser_status_key"]) if isinstance(result, dict) else None
    parser_status = "parsed" if isinstance(product_payload, dict) and product_payload else ("failed" if error else "partial")
    status = "failed" if error else "success"
    redacted_argv = [
        spec["tool_name"],
        "--run-kind",
        run_kind,
        "--scan-id",
        str(scan_id),
    ]
    target_scope = _redact_receipt_value({
        "scan_id": str(scan_id),
        "job_id": str(job_id or ""),
        "target_id": str(target_id or ""),
        "ai_target_id": str(ai_target_id or ""),
        "target": target,
        "run_kind": run_kind,
    })
    command_hash = _tool_receipt_hash({
        "tool_name": spec["tool_name"],
        "redacted_argv": redacted_argv,
        "target_scope": target_scope,
    })
    metadata = _redact_receipt_value({
        "executor": "worker_internal",
        "parser": spec["parser"],
        "proof_contract": spec["proof_contract"],
        "scan_type": (options or {}).get("scan_type"),
        "duration_seconds": duration_seconds,
        "finding_count": len(result.get("findings") or []) if isinstance(result.get("findings"), list) else 0,
        "error": str(error)[:500] if error else None,
    })
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO tool_receipts (
                tool_name, tool_version, adapter_version, command_hash, redacted_argv,
                worker_build, container_image, target_scope, scope_receipt_id,
                approval_receipt_id, policy_profile_id, status, parser_status,
                exit_code, timed_out, started_at, finished_at, stdout_evidence_object_id,
                stderr_evidence_object_id, parsed_evidence_instance_ids, redaction_summary,
                metadata_json, created_by
            ) VALUES (
                $1,$2,$3,$4,$5::jsonb,
                $6,$7,$8::jsonb,$9,
                $10,$11,$12,$13,
                $14,$15,$16,$17,$18,
                $19,$20::jsonb,$21,
                $22::jsonb,$23
            )
            RETURNING id
            """,
            spec["tool_name"],
            "internal",
            TOOL_RECEIPT_ADAPTER_VERSION,
            command_hash,
            json.dumps(redacted_argv),
            os.environ.get("BUILD_FINGERPRINT"),
            os.environ.get("WORKER_IMAGE"),
            json.dumps(target_scope),
            None,
            None,
            None,
            status,
            parser_status,
            1 if error else 0,
            False,
            started_at,
            completed_at,
            None,
            None,
            json.dumps([]),
            "worker internal executor receipt; sensitive target/options fields redacted",
            json.dumps(metadata),
            "worker",
        )
    except Exception as exc:
        print(f"[{str(job_id or scan_id)[:8]}] tool receipt insert error: {exc}", flush=True)
        return None
    receipt_id = str(row["id"]) if row and row["id"] else None
    if receipt_id:
        receipt_ids = result.setdefault("tool_receipt_ids", [])
        if isinstance(receipt_ids, list) and receipt_id not in receipt_ids:
            receipt_ids.append(receipt_id)
        result.setdefault("metadata", {})
        if isinstance(result.get("metadata"), dict):
            result["metadata"].setdefault("tool_receipt_ids", list(receipt_ids) if isinstance(receipt_ids, list) else [receipt_id])
        scan_metadata = result.setdefault("scan_metadata", {})
        if isinstance(scan_metadata, dict):
            scan_receipts = scan_metadata.setdefault("tool_receipt_ids", [])
            if isinstance(scan_receipts, list) and receipt_id not in scan_receipts:
                scan_receipts.append(receipt_id)
    return receipt_id


def _truthy_module_output(value: Any) -> bool:
    if isinstance(value, dict):
        return any(v not in (None, "", [], {}) for v in value.values())
    if isinstance(value, list):
        return bool(value)
    return value not in (None, "", [], {})


def _subprocess_parser_error_reason(tool_name: str, receipt: dict[str, Any]) -> str | None:
    """Conservatively classify known parser/output-format failures from subprocess previews."""
    tool = str(tool_name or "").strip().lower()
    parser_backed_tools = {
        "httpx", "katana", "subfinder", "ffuf", "nuclei", "dalfox",
        "sqlmap", "nmap", "sslyze", "testssl", "playwright",
    }
    if tool not in parser_backed_tools:
        return None
    if str(receipt.get("status") or "").strip() == "timeout" or receipt.get("timed_out"):
        return None
    combined = " ".join(
        str(receipt.get(key) or "")
        for key in ("stderr_preview", "stdout_preview")
    ).lower()
    if not combined:
        return None
    parser_markers = (
        "json: cannot unmarshal",
        "invalid character",
        "unexpected end of json input",
        "failed to parse json",
        "failed parsing json",
        "json parse error",
        "parse error",
        "could not parse",
        "cannot parse",
        "malformed json",
        "invalid json",
        "unmarshal type error",
    )
    for marker in parser_markers:
        if marker in combined:
            return marker
    return None


def _external_dast_tool_specs(result: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
    run_kind = str((options or {}).get("run_kind") or "").strip()
    if run_kind in AI_GATE_RUN_KINDS | MODEL_INTAKE_RUN_KINDS:
        return []
    specs: list[dict[str, Any]] = []

    discovery = result.get("discovery") if isinstance(result.get("discovery"), dict) else {}
    exposures = discovery.get("exposures") if isinstance(discovery.get("exposures"), dict) else {}
    if "httpx" in discovery:
        httpx_rows = discovery.get("httpx") if isinstance(discovery.get("httpx"), list) else []
        specs.append({
            "tool_name": "httpx",
            "parser": "httpx-json-summary-v1",
            "proof_contract": "http-observation",
            "status": "success" if httpx_rows else "recorded",
            "parser_status": "parsed" if httpx_rows else "partial",
            "summary": {
                "rows_count": len(httpx_rows),
                "status_codes": sorted({
                    str(row.get("status_code"))
                    for row in httpx_rows
                    if isinstance(row, dict) and row.get("status_code") is not None
                })[:20],
                "tech_count": sum(
                    len(row.get("tech") or [])
                    for row in httpx_rows
                    if isinstance(row, dict) and isinstance(row.get("tech"), list)
                ),
            },
        })

    if "katana_sample" in discovery or "smart_discovery" in discovery:
        katana_sample = discovery.get("katana_sample") if isinstance(discovery.get("katana_sample"), list) else []
        smart_discovery = discovery.get("smart_discovery") if isinstance(discovery.get("smart_discovery"), dict) else {}
        smart_url_count = int(smart_discovery.get("total_urls_discovered") or 0) if smart_discovery else 0
        zero_rediscovery = bool((options or {}).get("zero_rediscovery") or (options or {}).get("zero_rediscovery_scope"))
        has_katana_output = bool(katana_sample)
        specs.append({
            "tool_name": "katana",
            "parser": "katana-jsonl-summary-v1",
            "proof_contract": "crawl-observation",
            "status": "skipped" if zero_rediscovery else "success" if has_katana_output else "recorded",
            "parser_status": "not_applicable" if zero_rediscovery else "parsed" if has_katana_output else "partial",
            "summary": {
                "sample_count": len(katana_sample),
                "smart_discovery_total_urls": smart_url_count,
                "aggregate_discovery_only": bool(smart_url_count and not has_katana_output),
                "zero_rediscovery": zero_rediscovery,
            },
        })

    browser_crawl = discovery.get("browser_crawl") if isinstance(discovery.get("browser_crawl"), dict) else {}
    browser_api_endpoints = discovery.get("browser_api_endpoints") if isinstance(discovery.get("browser_api_endpoints"), list) else []
    try:
        browser_max_pages = int((options or {}).get("browser_max_pages") or 1)
    except (TypeError, ValueError):
        browser_max_pages = 1
    browser_disabled = bool((options or {}).get("no_browser")) or browser_max_pages == 0
    if "browser_api_endpoints" in discovery or "browser_crawl" in discovery or browser_disabled:
        pages_visited = int(browser_crawl.get("pages_visited") or 0) if browser_crawl else 0
        has_browser_output = bool(browser_api_endpoints or pages_visited)
        specs.append({
            "tool_name": "playwright",
            "parser": "playwright-proof-summary-v1",
            "proof_contract": "browser-observation",
            "status": "skipped" if browser_disabled else "success" if has_browser_output else "recorded",
            "parser_status": "not_applicable" if browser_disabled else "parsed" if has_browser_output else "partial",
            "summary": {
                "browser_api_endpoint_count": len(browser_api_endpoints),
                "pages_visited": pages_visited,
                "browser_disabled": browser_disabled,
            },
        })

    smart_discovery = discovery.get("smart_discovery") if isinstance(discovery.get("smart_discovery"), dict) else {}
    deep_discovery = discovery.get("deep_discovery") if isinstance(discovery.get("deep_discovery"), dict) else {}
    discovery_summary = discovery.get("summary") if isinstance(discovery.get("summary"), dict) else {}
    ffuf_disabled = bool((options or {}).get("disable_ffuf") or discovery_summary.get("spa_catch_all"))
    recursive_count = int(smart_discovery.get("total_recursive_paths") or 0) if smart_discovery else 0
    deep_count = len(deep_discovery.get("directories") or deep_discovery.get("paths") or []) if deep_discovery else 0
    ffuf_output = discovery.get("ffuf") if isinstance(discovery.get("ffuf"), (list, dict)) else None
    ffuf_count = len(ffuf_output) if isinstance(ffuf_output, list) else int(ffuf_output.get("count") or len(ffuf_output.get("results") or [])) if isinstance(ffuf_output, dict) else 0
    if smart_discovery or deep_discovery or ffuf_disabled:
        specs.append({
            "tool_name": "ffuf",
            "parser": "ffuf-json-summary-v1",
            "proof_contract": "content-discovery-observation",
            "status": "skipped" if ffuf_disabled else "success" if ffuf_count else "recorded",
            "parser_status": "not_applicable" if ffuf_disabled else "parsed" if ffuf_count else "partial",
            "summary": {
                "ffuf_result_count": ffuf_count,
                "recursive_paths": recursive_count,
                "deep_discovery_paths": deep_count,
                "aggregate_discovery_only": bool((recursive_count or deep_count) and not ffuf_count),
                "ffuf_disabled": ffuf_disabled,
            },
        })

    if (options or {}).get("subfinder") or result.get("subdomain_count") is not None or result.get("by_source") is not None:
        by_source = result.get("by_source") if isinstance(result.get("by_source"), dict) else {}
        subfinder_rows = by_source.get("subfinder") if isinstance(by_source.get("subfinder"), list) else []
        subdomain_count = int(result.get("subdomain_count") or len(result.get("subdomains") or []))
        input_payload = result.get("input") if isinstance(result.get("input"), dict) else {}
        source_payload = input_payload.get("sources") if isinstance(input_payload.get("sources"), dict) else {}
        subfinder_enabled = bool(source_payload.get("subfinder", (options or {}).get("subfinder")))
        specs.append({
            "tool_name": "subfinder",
            "parser": "subfinder-lines-summary-v1",
            "proof_contract": "passive-discovery",
            "status": "skipped" if not subfinder_enabled else "success" if subfinder_rows else "recorded",
            "parser_status": "not_applicable" if not subfinder_enabled else "parsed" if subfinder_rows else "partial",
            "summary": {
                "subdomains_count": subdomain_count,
                "subfinder_rows_count": len(subfinder_rows),
                "subfinder_enabled": subfinder_enabled,
                "aggregate_discovery_only": bool(subdomain_count and not subfinder_rows),
            },
        })

    nuclei = discovery.get("nuclei") if isinstance(discovery.get("nuclei"), dict) else exposures.get("nuclei")
    if isinstance(nuclei, dict) and _truthy_module_output(nuclei):
        completed = nuclei.get("scan_completed")
        errors = nuclei.get("errors") if isinstance(nuclei.get("errors"), list) else []
        specs.append({
            "tool_name": "nuclei",
            "parser": "nuclei-json-summary-v1",
            "proof_contract": "template-match-evidence",
            # Honesty: only an explicit completion is 'success'. Unknown completion
            # (scan_completed None) must never be stamped success — that would be a
            # phantom-tool provenance the no-phantom gate exists to prevent.
            "status": "success" if completed is True else "failed" if (completed is False or errors) else "recorded",
            "parser_status": "parsed" if completed is True else "failed" if errors else "partial",
            "summary": {
                "scan_completed": completed,
                "templates_used": nuclei.get("templates_used"),
                "vulnerabilities_count": len(nuclei.get("vulnerabilities") or []),
                "errors_count": len(errors),
            },
        })

    active = result.get("active_checks") if isinstance(result.get("active_checks"), dict) else {}
    for tool_name, parser in (("dalfox", "dalfox-active-summary-v1"), ("sqlmap", "sqlmap-active-summary-v1")):
        rows = active.get(tool_name) if isinstance(active.get(tool_name), list) else []
        errors = active.get(f"{tool_name}_errors") if isinstance(active.get(f"{tool_name}_errors"), list) else []
        if rows or errors:
            specs.append({
                "tool_name": tool_name,
                "parser": parser,
                "proof_contract": "active-replay-evidence",
                "status": "success" if rows else "failed",
                "parser_status": "parsed" if rows else "failed",
                "summary": {
                    "results_count": len(rows),
                    "errors_count": len(errors),
                    "endpoints_tested": active.get("tested_endpoints") or active.get(f"{tool_name}_endpoints_tested"),
                },
            })

    tls = result.get("tls") if isinstance(result.get("tls"), dict) else {}
    for tool_name, parser, payload_key in (
        ("nmap", "nmap-tls-summary-v1", "nmap"),
        ("sslyze", "sslyze-summary-v1", "sslyze"),
        ("testssl", "testssl-summary-v1", "testssl"),
    ):
        payload = tls.get(payload_key) if isinstance(tls.get(payload_key), dict) else {}
        if not _truthy_module_output(payload):
            continue
        completed = payload.get("scan_completed")
        raw_present = bool(payload.get("raw") or payload.get("raw_present"))
        has_structured = any(payload.get(key) for key in ("tls_versions", "cipher_suites", "vulnerabilities", "weak_indicators"))
        specs.append({
            "tool_name": tool_name,
            "parser": parser,
            "proof_contract": "tls-network-observation",
            # Honesty: success requires genuine completion or real parsed structured
            # data. raw-present alone is NOT success — `raw` also holds stderr/timeout
            # text, and an explicit completed=False (e.g. an nmap timeout) is a failure.
            "status": "success" if (completed is True or has_structured) else "failed" if completed is False else "recorded",
            "parser_status": "parsed" if has_structured else "partial" if raw_present else "failed",
            "summary": {
                "scan_completed": completed,
                "raw_present": raw_present,
                "vulnerabilities_count": len(payload.get("vulnerabilities") or []),
            },
        })
    scan_metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    subprocess_receipts = scan_metadata.get("subprocess_receipts") if isinstance(scan_metadata.get("subprocess_receipts"), list) else []
    known_subprocess_tools = {
        "curl", "dig", "host", "nslookup", "delv",
        "httpx", "katana", "subfinder", "ffuf", "nuclei", "dalfox",
        "sqlmap", "sqlmap.py", "nmap", "naabu", "sslyze", "testssl", "testssl.sh",
        "playwright",
    }
    for item in subprocess_receipts[:200]:
        if not isinstance(item, dict):
            continue
        tool_name = str(item.get("tool_name") or "").strip()
        if not tool_name:
            continue
        # Basename first: in the deployed image tools run by absolute path
        # (e.g. /opt/tools/nuclei), so a bare-name membership check would drop every
        # real per-subprocess receipt and leave only the synthetic summary receipt.
        tool_base = os.path.basename(tool_name)
        normalized_tool = "sqlmap" if tool_base in ("sqlmap.py", "sqlmap") else "testssl" if tool_base in ("testssl.sh", "testssl") else tool_base
        if normalized_tool not in known_subprocess_tools:
            continue
        redacted_argv = item.get("redacted_argv") if isinstance(item.get("redacted_argv"), list) else [normalized_tool]
        parser_error_reason = _subprocess_parser_error_reason(normalized_tool, item)
        status = "parser_error" if parser_error_reason else item.get("status") or "recorded"
        parser_status = "failed" if parser_error_reason else item.get("parser_status") or "not_applicable"
        specs.append({
            "tool_name": normalized_tool,
            "tool_version": "scanner-subprocess",
            "parser": "scanner-subprocess-outcome-v1",
            "proof_contract": "subprocess-exit-evidence",
            "status": status,
            "parser_status": parser_status,
            "exit_code": item.get("exit_code"),
            "timed_out": bool(item.get("timed_out")),
            "redacted_argv": redacted_argv,
            "command_hash": item.get("command_hash"),
            "stdout_artifact": item.get("stdout_artifact") if isinstance(item.get("stdout_artifact"), dict) else None,
            "stderr_artifact": item.get("stderr_artifact") if isinstance(item.get("stderr_artifact"), dict) else None,
            "summary": {
                "exact_subprocess": True,
                "timeout_seconds": item.get("timeout_seconds"),
                "duration_ms": item.get("duration_ms"),
                "stdout_length": item.get("stdout_length"),
                "stderr_length": item.get("stderr_length"),
                "stdout_preview": item.get("stdout_preview"),
                "stderr_preview": item.get("stderr_preview"),
                "stdout_artifact_available": isinstance(item.get("stdout_artifact"), dict),
                "stderr_artifact_available": isinstance(item.get("stderr_artifact"), dict),
                "parser_error_reason": parser_error_reason,
            },
        })
    return specs


def _coerce_tool_receipt_status(status: Any) -> str:
    value = str(status or "").strip()
    return value if value in {"success", "failed", "timeout", "skipped", "waived", "parser_error", "recorded"} else "recorded"


def _coerce_tool_receipt_parser_status(parser_status: Any, status: Any = None) -> str:
    value = str(parser_status or "").strip()
    if value == "skipped":
        return "not_applicable"
    if value in {"not_run", "parsed", "partial", "failed", "not_applicable"}:
        return value
    if str(status or "").strip() == "skipped":
        return "not_applicable"
    return "partial"


async def _record_external_dast_tool_receipts(
    conn,
    *,
    scan_id: str,
    job_id: str | None,
    target: str,
    target_id: str | None,
    options: dict[str, Any],
    result: dict[str, Any],
    started_at: datetime,
    completed_at: datetime,
    duration_seconds: int,
) -> list[str]:
    specs = _external_dast_tool_specs(result, options)
    if not specs:
        return []
    receipt_ids: list[str] = []
    target_scope = _redact_receipt_value({
        "scan_id": str(scan_id),
        "job_id": str(job_id or ""),
        "target_id": str(target_id or ""),
        "target": target,
        "scan_type": (options or {}).get("scan_type"),
    })
    for spec in specs:
        safe_status = _coerce_tool_receipt_status(spec.get("status"))
        safe_parser_status = _coerce_tool_receipt_parser_status(spec.get("parser_status"), safe_status)
        redacted_argv = spec.get("redacted_argv") if isinstance(spec.get("redacted_argv"), list) else [
            spec["tool_name"], "--scan-id", str(scan_id), "--target", str(target)
        ]
        redacted_argv = _redact_receipt_value(redacted_argv)
        command_hash = str(spec.get("command_hash") or "").strip() or _tool_receipt_hash({
            "tool_name": spec["tool_name"],
            "redacted_argv": redacted_argv,
            "target_scope": target_scope,
        })
        stdout_evidence_object_id = await _persist_tool_output_artifact(
            conn,
            scan_id=str(scan_id),
            tool_name=str(spec["tool_name"]),
            command_hash=command_hash,
            stream_name="stdout",
            artifact=spec.get("stdout_artifact"),
        )
        stderr_evidence_object_id = await _persist_tool_output_artifact(
            conn,
            scan_id=str(scan_id),
            tool_name=str(spec["tool_name"]),
            command_hash=command_hash,
            stream_name="stderr",
            artifact=spec.get("stderr_artifact"),
        )
        try:
            exit_code = int(spec.get("exit_code")) if spec.get("exit_code") is not None else 0 if safe_status == "success" else 124 if safe_status == "timeout" else 1
        except (TypeError, ValueError):
            exit_code = 0 if safe_status == "success" else 124 if safe_status == "timeout" else 1
        timed_out = bool(spec.get("timed_out") or safe_status == "timeout" or exit_code == 124)
        metadata = _redact_receipt_value({
            "executor": "scanner_dast_module",
            "parser": spec["parser"],
            "proof_contract": spec["proof_contract"],
            "duration_seconds": duration_seconds,
            "summary": spec.get("summary") or {},
        })
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO tool_receipts (
                    tool_name, tool_version, adapter_version, command_hash, redacted_argv,
                    worker_build, container_image, target_scope, scope_receipt_id,
                    approval_receipt_id, policy_profile_id, status, parser_status,
                    exit_code, timed_out, started_at, finished_at, stdout_evidence_object_id,
                    stderr_evidence_object_id, parsed_evidence_instance_ids, redaction_summary,
                    metadata_json, created_by
                ) VALUES (
                    $1,$2,$3,$4,$5::jsonb,
                    $6,$7,$8::jsonb,$9,
                    $10,$11,$12,$13,
                    $14,$15,$16,$17,$18,
                    $19,$20::jsonb,$21,
                    $22::jsonb,$23
                )
                RETURNING id
                """,
                spec["tool_name"],
                spec.get("tool_version") or "scanner-output",
                TOOL_RECEIPT_ADAPTER_VERSION,
                command_hash,
                json.dumps(redacted_argv),
                os.environ.get("BUILD_FINGERPRINT"),
                os.environ.get("WORKER_IMAGE"),
                json.dumps(target_scope),
                None,
                None,
                None,
                safe_status,
                safe_parser_status,
                exit_code,
                timed_out,
                started_at,
                completed_at,
                uuid.UUID(stdout_evidence_object_id) if stdout_evidence_object_id else None,
                uuid.UUID(stderr_evidence_object_id) if stderr_evidence_object_id else None,
                json.dumps([]),
                "scanner module receipt from parsed DAST result; sensitive target/options fields redacted",
                json.dumps(metadata),
                "worker",
            )
        except Exception as exc:
            print(f"[{str(job_id or scan_id)[:8]}] external tool receipt insert error: {exc}", flush=True)
            continue
        receipt_id = str(row["id"]) if row and row["id"] else None
        if receipt_id:
            receipt_ids.append(receipt_id)
    if receipt_ids:
        existing = result.setdefault("tool_receipt_ids", [])
        if isinstance(existing, list):
            for receipt_id in receipt_ids:
                if receipt_id not in existing:
                    existing.append(receipt_id)
        result.setdefault("metadata", {})
        if isinstance(result.get("metadata"), dict):
            result["metadata"].setdefault("tool_receipt_ids", list(existing) if isinstance(existing, list) else receipt_ids)
    return receipt_ids


async def _record_asm_executor_tool_receipt(
    conn,
    *,
    scan_id: str,
    job_id: str | None,
    target: str,
    target_id: str | None,
    parent_scan_id: str | None,
    campaign_id: str | None,
    options: dict[str, Any],
    result: dict[str, Any],
    action: str,
    status: str,
    parser_status: str,
    started_at: datetime,
    completed_at: datetime,
    duration_seconds: int,
    endpoint_ids: list[Any] | None = None,
    auth_state: str | None = None,
    check_family: str | None = None,
    endpoint_filter: str | None = None,
    error: Any = None,
    timed_out: bool = False,
    summary: dict[str, Any] | None = None,
) -> str | None:
    """Best-effort receipt for Continuous ASM executor work.

    This records executor outcome only; it does not change findings, endpoint
    verdicts, campaigns, or scan terminal state.
    """
    action_name = str(action or "batch").strip().lower()
    tool_name = "asm_recon_executor" if action_name == "recon" else "asm_endpoint_batch_executor"
    parser = "asm-recon-summary-v1" if action_name == "recon" else "asm-endpoint-batch-summary-v1"
    proof_contract = "endpoint-inventory-evidence" if action_name == "recon" else "endpoint-attempt-ledger"
    safe_status = status if status in {"success", "failed", "timeout", "skipped", "waived", "parser_error", "recorded"} else "recorded"
    safe_parser_status = parser_status if parser_status in {"not_run", "parsed", "partial", "failed", "not_applicable"} else "partial"
    endpoint_ids = endpoint_ids or []
    target_scope = _redact_receipt_value({
        "scan_id": str(scan_id),
        "job_id": str(job_id or ""),
        "target_id": str(target_id or ""),
        "parent_scan_id": str(parent_scan_id or ""),
        "campaign_id": str(campaign_id or ""),
        "target": target,
        "action": action_name,
        "auth_state": auth_state,
        "check_family": check_family or "all",
        "endpoint_filter": endpoint_filter,
        "endpoint_count": len(endpoint_ids),
    })
    redacted_argv = _redact_receipt_value([
        tool_name,
        "--action",
        action_name,
        "--scan-id",
        str(scan_id),
        "--target",
        str(target),
    ])
    command_hash = _tool_receipt_hash({
        "tool_name": tool_name,
        "redacted_argv": redacted_argv,
        "target_scope": target_scope,
    })
    metadata = _redact_receipt_value({
        "executor": "continuous_asm",
        "parser": parser,
        "proof_contract": proof_contract,
        "duration_seconds": duration_seconds,
        "endpoint_count": len(endpoint_ids),
        "auth_state": auth_state,
        "check_family": check_family or "all",
        "endpoint_filter": endpoint_filter,
        "scan_type": (options or {}).get("scan_type"),
        "coverage_dynamic_worker": bool((options or {}).get("coverage_dynamic_worker")),
        "partial": bool((result.get("scan_metadata") or {}).get("partial")) if isinstance(result, dict) else False,
        "timed_out": bool(timed_out),
        "error": str(error)[:500] if error else None,
        "summary": summary or {},
    })
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO tool_receipts (
                tool_name, tool_version, adapter_version, command_hash, redacted_argv,
                worker_build, container_image, target_scope, scope_receipt_id,
                approval_receipt_id, policy_profile_id, status, parser_status,
                exit_code, timed_out, started_at, finished_at, stdout_evidence_object_id,
                stderr_evidence_object_id, parsed_evidence_instance_ids, redaction_summary,
                metadata_json, created_by
            ) VALUES (
                $1,$2,$3,$4,$5::jsonb,
                $6,$7,$8::jsonb,$9,
                $10,$11,$12,$13,
                $14,$15,$16,$17,$18,
                $19,$20::jsonb,$21,
                $22::jsonb,$23
            )
            RETURNING id
            """,
            tool_name,
            "internal",
            TOOL_RECEIPT_ADAPTER_VERSION,
            command_hash,
            json.dumps(redacted_argv),
            os.environ.get("BUILD_FINGERPRINT"),
            os.environ.get("WORKER_IMAGE"),
            json.dumps(target_scope),
            (options or {}).get("scope_receipt_id"),
            _optional_uuid((options or {}).get("approval_receipt_id")),
            None,
            safe_status,
            safe_parser_status,
            0 if safe_status == "success" else 124 if safe_status == "timeout" else 1,
            bool(timed_out or safe_status == "timeout"),
            started_at,
            completed_at,
            None,
            None,
            json.dumps([]),
            "continuous ASM executor receipt; sensitive target/options fields redacted",
            json.dumps(metadata),
            "worker",
        )
    except Exception as exc:
        print(f"[{str(job_id or scan_id)[:8]}] ASM tool receipt insert error: {exc}", flush=True)
        return None
    receipt_id = str(row["id"]) if row and row["id"] else None
    if receipt_id and isinstance(result, dict):
        receipt_ids = result.setdefault("tool_receipt_ids", [])
        if isinstance(receipt_ids, list) and receipt_id not in receipt_ids:
            receipt_ids.append(receipt_id)
        result.setdefault("metadata", {})
        if isinstance(result.get("metadata"), dict):
            result["metadata"].setdefault("tool_receipt_ids", list(receipt_ids) if isinstance(receipt_ids, list) else [receipt_id])
        scan_metadata = result.setdefault("scan_metadata", {})
        if isinstance(scan_metadata, dict):
            scan_receipts = scan_metadata.setdefault("tool_receipt_ids", [])
            if isinstance(scan_receipts, list) and receipt_id not in scan_receipts:
                scan_receipts.append(receipt_id)
            scan_metadata.setdefault("asm_executor_receipt_id", receipt_id)
    return receipt_id


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
_reservation_sweep_interval = int(
    os.environ.get("BUDGET_RESERVATION_SWEEP_INTERVAL_SECONDS", "30")
)
BUDGET_RESERVATION_SWEEP_INTERVAL_SECONDS = (
    0 if _reservation_sweep_interval <= 0 else max(10, _reservation_sweep_interval)
)
BUDGET_RESERVATION_SWEEP_BATCH_SIZE = max(
    1, min(1000, int(os.environ.get("BUDGET_RESERVATION_SWEEP_BATCH_SIZE", "100")))
)
AI_SETTINGS_KEY = os.environ.get("AI_SETTINGS_KEY", "settings:ai")
PARALLEL_SHARD_MAX_PER_PARENT = max(1, int(os.environ.get("PARALLEL_SHARD_MAX_PER_PARENT", "4")))
PARALLEL_SHARD_CONCURRENCY_HARD_MAX = max(
    PARALLEL_SHARD_MAX_PER_PARENT,
    int(os.environ.get("PARALLEL_SHARD_CONCURRENCY_HARD_MAX", "64")),
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
# Verification Depth plan (B): stop auto-retesting a finding that has already been
# retested this many times without being proven, so a stubbornly-inconclusive finding
# can't consume the bounded retest budget every scan forever. Manual retests are
# unaffected; this only governs the automatic policy hook.
AUTO_RETEST_MAX_ATTEMPTS = int(os.environ.get("AUTO_RETEST_MAX_ATTEMPTS", "3"))

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
    forbidden_signer_variables = (
        "MODEL_INTAKE_ADMISSION_SIGNING_KEY_PEM",
        "MODEL_INTAKE_CONTROL_PLANE_SIGNING_KEY_PEM",
        "MODEL_INTAKE_SIGNER_AWS_KMS_KEY_ID",
    )
    if any(os.environ.get(name) for name in forbidden_signer_variables):
        raise RuntimeError(
            "worker preflight failed: admission signing material must not be present in an evidence-producing worker"
        )
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
    return redis.from_url(
        REDIS_URL,
        socket_timeout=WORKER_REDIS_SOCKET_TIMEOUT_SECONDS,
        socket_connect_timeout=10,
    )


def _published_scanner_version() -> str | None:
    """Development build label published by the API from its live checkout.

    Official images ignore this fallback in favor of their baked release manifest.
    """
    try:
        v = get_redis().get("shakerscan:scanner_version")
        if v:
            return v.decode() if isinstance(v, (bytes, bytearray)) else str(v)
    except Exception:
        pass
    return None


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


_MANAGED_SCAN_AUTH_OPTION_KEYS = {
    "user1": {"authorization_header": "auth_header", "cookie": "auth_cookies"},
    "user2": {"authorization_header": "user2_header", "cookie": "user2_cookies"},
}


async def _hydrate_managed_scan_credentials(options: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Resolve target-bound managed credentials in worker memory only."""
    hydrated = dict(options or {})
    raw_refs = hydrated.pop("managed_credential_profiles", None)
    if not isinstance(raw_refs, list) or not raw_refs:
        return hydrated

    refs = [dict(item) for item in raw_refs if isinstance(item, dict)][:2]
    states = [str(item.get("auth_state") or "") for item in refs]
    profile_ids = [str(item.get("profile_id") or "") for item in refs]
    if len(states) != len(set(states)) or not all(state in _MANAGED_SCAN_AUTH_OPTION_KEYS for state in states):
        raise ValueError("invalid managed credential profile references")
    if len(profile_ids) != len(set(profile_ids)):
        raise ValueError("user1 and user2 managed credential profiles must be distinct")
    try:
        profile_uuids = [uuid.UUID(value) for value in profile_ids]
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise ValueError("invalid managed credential profile id") from exc

    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT cp.id, cp.auth_kind, cp.secret_value
            FROM scans s
            JOIN target_credential_profiles cp ON cp.target_id = s.target_id
            WHERE s.id = $1
              AND cp.id = ANY($2::uuid[])
              AND cp.is_active = true
              AND (cp.expires_at IS NULL OR cp.expires_at > NOW())
            """,
            scan_uuid,
            profile_uuids,
        )
    profiles = {str(row["id"]): dict(row) for row in rows}
    resolved: list[dict[str, str]] = []
    for ref in refs:
        auth_state = str(ref.get("auth_state"))
        profile_id = str(ref.get("profile_id"))
        row = profiles.get(profile_id)
        if row is None:
            raise ValueError(f"managed credential profile unavailable for {auth_state}")
        auth_kind = str(row.get("auth_kind") or "")
        expected_key = _MANAGED_SCAN_AUTH_OPTION_KEYS[auth_state].get(auth_kind)
        if not expected_key or str(ref.get("option_key") or "") != expected_key:
            raise ValueError(f"managed credential profile kind mismatch for {auth_state}")
        secret = str(decrypt_secret(row.get("secret_value")) or "")
        if not secret or secret.startswith("enc:fernet:") or "\r" in secret or "\n" in secret:
            raise ValueError(f"managed credential profile could not be decrypted for {auth_state}")
        if not hydrated.get(expected_key):
            hydrated[expected_key] = secret
        resolved.append({"auth_state": auth_state, "profile_id": profile_id, "option_key": expected_key})
    hydrated["resolved_credential_profiles"] = resolved
    return hydrated


async def _hydrate_generic_scan_credentials(
    options: dict[str, Any], scan_id: str,
) -> dict[str, Any]:
    """Resolve admitted generic profiles after worker-side target/approval validation."""
    hydrated = dict(options or {})
    raw_refs = hydrated.pop("credential_profile_refs", None)
    if not isinstance(raw_refs, list) or not raw_refs:
        return hydrated
    if (
        hydrated.get("managed_credential_profiles") not in (None, "", [], {})
        or hydrated.get("authentication") not in (None, "", [], {})
        or any(hydrated.get(key) not in (None, "", [], {}) for key in SCANNER_AUTH_CONFIG_KEYS)
    ):
        raise ScanCredentialError(
            "generic Scan credential references cannot be combined with another authentication path"
        )
    refs = [dict(item) for item in raw_refs if isinstance(item, Mapping)]
    if len(refs) != len(raw_refs) or not 1 <= len(refs) <= 2:
        raise ScanCredentialError("generic Scan credential references are invalid")
    profile_ids = [str(item.get("profile_id") or "") for item in refs]
    lanes = [str(item.get("scan_lane") or "") for item in refs]
    if len(profile_ids) != len(set(profile_ids)) or len(lanes) != len(set(lanes)):
        raise ScanCredentialError("generic Scan credential references are ambiguous")
    if any(lane not in {"primary", "secondary"} for lane in lanes):
        raise ScanCredentialError("generic Scan credential lane is invalid")
    try:
        scan_uuid = uuid.UUID(str(scan_id))
        for profile_id in profile_ids:
            uuid.UUID(profile_id)
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCredentialError("generic Scan credential reference UUID is invalid") from exc

    target_kind = str(hydrated.pop("credential_target_kind", "") or "").strip().lower()
    action_name = str(hydrated.pop("credential_action_name", "") or "").strip()
    if target_kind not in {"web", "api"} or not action_name:
        raise ScanCredentialError("generic Scan credential authority is incomplete")

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT s.target_id, s.target_url, t.root_domain
               FROM scans s JOIN targets t ON t.id=s.target_id
               WHERE s.id=$1""",
            scan_uuid,
        )
        if not row:
            raise ScanCredentialError("generic Scan credential target is unavailable")
        target_url = str(row["target_url"] or "")
        parsed = urllib.parse.urlsplit(target_url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ScanCredentialError("generic Scan credential target URL is invalid")
        origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        guard = (
            dict(hydrated.get("runtime_scope_guard") or {})
            if isinstance(hydrated.get("runtime_scope_guard"), Mapping) else {}
        )
        roots = tuple(
            str(item).strip().lower().rstrip(".")
            for item in guard.get("allowed_root_domains") or ()
            if str(item).strip()
        ) or (str(row["root_domain"] or parsed.hostname).lower().rstrip("."),)
        target = TargetBinding(
            target_id=str(row["target_id"]),
            target_kind=target_kind,
            canonical_host=parsed.hostname,
            allowed_origins=(origin,),
            allowed_root_domains=roots,
            environment=str(guard.get("environment") or "unknown"),
            scope_receipt_id=str(hydrated.get("scope_receipt_id") or "") or None,
        )
        authority = await validate_worker_credential_authority(
            conn,
            owner_kind="scan",
            owner_id=scan_id,
            target=target,
            approval_receipt_id=hydrated.get("approval_receipt_id"),
            scope_receipt_id=hydrated.get("scope_receipt_id"),
            action_name=action_name,
        )
        resolver = WorkerCredentialResolver()
        resolved_refs: list[dict[str, Any]] = []
        for ref in refs:
            try:
                expected_version = int(ref.get("profile_version") or 0)
            except (TypeError, ValueError) as exc:
                raise ScanCredentialError(
                    "generic Scan credential profile version is invalid"
                ) from exc
            if expected_version < 1:
                raise ScanCredentialError("generic Scan credential profile version is invalid")
            async with resolver.resolve(
                conn,
                profile_id=ref["profile_id"],
                target=target,
                capability=SCAN_CREDENTIAL_CAPABILITY,
                authority=authority,
            ) as resolved:
                profile = resolved.profile
                if (
                    profile.current_version != expected_version
                    or profile.auth_kind != str(ref.get("auth_kind") or "")
                    or profile.principal_slot != str(ref.get("principal_slot") or "")
                    or profile.target_kind != target_kind
                ):
                    raise ScanCredentialError(
                        "generic Scan credential changed after admission"
                    )
                hydrated = bind_resolved_scan_credential(
                    hydrated, resolved, scan_lane=str(ref["scan_lane"]),
                )
                resolved_refs.append({
                    **resolved.receipt_metadata(),
                    "scan_lane": str(ref["scan_lane"]),
                })
    hydrated["resolved_credential_profiles"] = resolved_refs
    return hydrated


async def _hydrate_device_scan_credentials(options: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Resolve device-bound credentials in worker memory without persisting secrets."""
    hydrated = dict(options or {})
    raw_refs = hydrated.get("device_credential_profiles")
    if not isinstance(raw_refs, list) or not raw_refs:
        return hydrated
    if str(hydrated.get("safety_profile") or "") != "authenticated_active":
        raise ValueError("device credentials require safety_profile=authenticated_active")
    refs = [dict(item) for item in raw_refs if isinstance(item, dict)][:2]
    roles = [str(item.get("role") or "") for item in refs]
    if len(roles) != len(set(roles)) or not all(role in {"ssh", "web"} for role in roles):
        raise ValueError("invalid device credential profile references")
    try:
        profile_ids = [uuid.UUID(str(item.get("profile_id") or "")) for item in refs]
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise ValueError("invalid device credential profile id") from exc
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT cp.id, cp.auth_kind, cp.username, cp.secret_value,
                      cp.login_path, cp.port
               FROM scans s
               JOIN device_credential_profiles cp ON cp.device_target_id=s.device_target_id
               WHERE s.id=$1 AND cp.id=ANY($2::uuid[]) AND cp.is_active=true
                 AND (cp.expires_at IS NULL OR cp.expires_at > NOW())""",
            scan_uuid,
            profile_ids,
        )
        attempt_rows = await conn.fetch(
            """WITH latest_success AS (
                   SELECT credential_profile_id, MAX(attempted_at) AS succeeded_at
                   FROM device_credential_attempts
                   WHERE credential_profile_id=ANY($1::uuid[]) AND outcome='succeeded'
                   GROUP BY credential_profile_id
               )
               SELECT a.credential_profile_id,
                      COUNT(*) FILTER (WHERE a.outcome IN ('rejected','error')) AS failure_count,
                      MAX(a.attempted_at) FILTER (WHERE a.outcome IN ('rejected','error')) AS last_failure_at
               FROM device_credential_attempts a
               LEFT JOIN latest_success s ON s.credential_profile_id=a.credential_profile_id
               WHERE a.credential_profile_id=ANY($1::uuid[])
                 AND a.attempted_at >= NOW() - INTERVAL '24 hours'
                 AND (s.succeeded_at IS NULL OR a.attempted_at > s.succeeded_at)
               GROUP BY a.credential_profile_id""",
            profile_ids,
        )
    by_id = {str(row["id"]): dict(row) for row in rows}
    attempts_by_id = {str(row["credential_profile_id"]): dict(row) for row in attempt_rows}
    resolved: list[dict[str, Any]] = []
    for ref in refs:
        role = str(ref["role"])
        profile_id = str(ref["profile_id"])
        row = by_id.get(profile_id)
        if row is None:
            raise ValueError(f"device {role} credential profile is unavailable")
        auth_kind = str(row.get("auth_kind") or "")
        if (role == "ssh") != auth_kind.startswith("ssh_"):
            raise ValueError(f"device {role} credential profile kind mismatch")
        if role == "ssh":
            attempt_state = attempts_by_id.get(profile_id, {})
            failure_count = int(attempt_state.get("failure_count") or 0)
            last_failure_at = attempt_state.get("last_failure_at")
            if failure_count >= DEVICE_SSH_AUTH_DAILY_FAILURE_CAP:
                raise ValueError("device SSH credential daily authentication failure cap is active")
            if last_failure_at:
                now = utc_now()
                if last_failure_at.tzinfo is None:
                    now = datetime.now()
                if (now - last_failure_at).total_seconds() < DEVICE_SSH_AUTH_COOLDOWN_SECONDS:
                    raise ValueError("device SSH credential authentication cooldown is active")
        raw_secret = str(decrypt_secret(row.get("secret_value")) or "")
        if not raw_secret or raw_secret.startswith("enc:fernet:"):
            raise ValueError(f"device {role} credential profile could not be decrypted")
        try:
            secret_payload = json.loads(raw_secret)
        except json.JSONDecodeError as exc:
            raise ValueError(f"device {role} credential profile has an invalid secret payload") from exc
        secret = str(secret_payload.get("secret") or "")
        secondary_secret = str(secret_payload.get("secondary_secret") or "") or None
        if not secret or (role == "web" and ("\r" in secret or "\n" in secret)):
            raise ValueError(f"device {role} credential profile is invalid")
        resolved.append({
            "role": role,
            "profile_id": profile_id,
            "auth_kind": auth_kind,
            "username": str(row.get("username") or "") or None,
            "secret": secret,
            "secondary_secret": secondary_secret,
            "login_path": str(row.get("login_path") or "") or None,
            "port": int(row["port"]) if row.get("port") is not None else None,
        })
    hydrated["_resolved_device_credentials"] = resolved
    return hydrated


async def _hydrate_device_request_collections(options: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Resolve encrypted device-bound request documents only in worker memory."""
    hydrated = dict(options or {})
    refs = [dict(item) for item in hydrated.get("device_request_collections") or [] if isinstance(item, dict)][:8]
    if not refs:
        return hydrated
    if not hydrated.get("confirm_request_replay") or not hydrated.get("include_web_dast"):
        raise ValueError("imported device requests require confirmed Web DAST execution")
    try:
        collection_ids = [uuid.UUID(str(item.get("collection_id") or "")) for item in refs]
        scan_uuid = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise ValueError("invalid device request collection reference") from exc
    if len(collection_ids) != len(set(collection_ids)):
        raise ValueError("duplicate device request collection reference")
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            """SELECT c.id, c.name, c.document_sha256, c.encrypted_payload
               FROM scans s
               JOIN device_request_collections c ON c.device_target_id=s.device_target_id
               WHERE s.id=$1 AND c.id=ANY($2::uuid[]) AND c.is_active=true""",
            scan_uuid, collection_ids,
        )
    by_id = {str(row["id"]): dict(row) for row in rows}
    resolved: list[dict[str, Any]] = []
    total_bytes = 0
    for ref in refs:
        collection_id = str(ref.get("collection_id") or "")
        row = by_id.get(collection_id)
        if row is None:
            raise ValueError("device request collection is unavailable")
        raw = str(decrypt_secret(row.get("encrypted_payload")) or "")
        if not raw or raw.startswith("enc:fernet:"):
            raise ValueError("device request collection could not be decrypted")
        total_bytes += len(raw.encode("utf-8"))
        if total_bytes > 7 * 1024 * 1024:
            raise ValueError("selected device request collections exceed the execution size limit")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("device request collection has an invalid encrypted payload") from exc
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()
        expected = str(ref.get("document_sha256") or row.get("document_sha256") or "")
        if digest != expected or digest != str(row.get("document_sha256") or ""):
            raise ValueError("device request collection integrity check failed")
        resolved.append({
            "collection_id": collection_id,
            "name": str(row.get("name") or ref.get("name") or "Imported requests"),
            "document_sha256": digest,
            "payload": payload,
        })
    hydrated["_resolved_device_request_collections"] = resolved
    return hydrated


async def _persist_device_credential_attempts(result: dict[str, Any], scan_id: str) -> None:
    """Persist bounded authentication outcomes without retaining any credential value."""
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    attempts: dict[str, str] = {}
    for service in posture.get("services") or []:
        ssh = service.get("ssh") if isinstance(service, dict) and isinstance(service.get("ssh"), dict) else {}
        profile_id = str(ssh.get("credential_profile_id") or "")
        if not profile_id or not ssh.get("authentication_attempted"):
            continue
        attempts[profile_id] = (
            "succeeded" if ssh.get("authentication_succeeded")
            else "rejected" if "rejected" in str(ssh.get("authentication_error") or "")
            else "error"
        )
    children = posture.get("web_dast_children") if isinstance(posture.get("web_dast_children"), dict) else {}
    for child in children.get("children") or []:
        if not isinstance(child, dict) or not child.get("credentials_attempted"):
            continue
        profile_id = str(child.get("credential_profile_id") or "")
        if profile_id:
            attempts[profile_id] = "succeeded" if child.get("authenticated") else "rejected"
    if not attempts:
        return
    try:
        scan_uuid = uuid.UUID(str(scan_id))
        profile_ids = [uuid.UUID(profile_id) for profile_id in attempts]
    except ValueError:
        return
    async with db_pool.acquire() as conn:
        device_target_id = await conn.fetchval("SELECT device_target_id FROM scans WHERE id=$1", scan_uuid)
        if not device_target_id:
            return
        for profile_id in profile_ids:
            await conn.execute(
                """INSERT INTO device_credential_attempts (
                       device_target_id, credential_profile_id, scan_id, outcome
                   ) SELECT $1,$2,$3,$4
                     WHERE EXISTS (
                       SELECT 1 FROM device_credential_profiles
                       WHERE id=$2 AND device_target_id=$1
                     )
                   ON CONFLICT (scan_id, credential_profile_id) DO UPDATE
                   SET outcome=EXCLUDED.outcome, attempted_at=NOW()""",
                device_target_id, profile_id, scan_uuid, attempts[str(profile_id)],
            )


AI_GATE_CREDENTIAL_CAPABILITY = "ai_gate.scan"


def _ai_gate_runtime_credential(resolved: Any) -> dict[str, Any]:
    kind = resolved.profile.auth_kind
    if kind == "query_parameter":
        material = resolved.query_parameter()
        return {
            "auth_kind": "query_param",
            "header_name": material.name,
            "secret": material.value,
            "metadata_json": {"param_name": material.name},
        }
    material = resolved.immediate_http()
    if kind == "authorization_header":
        return {
            "auth_kind": "custom_header",
            "header_name": "Authorization",
            "secret": material.secret,
            "metadata_json": {},
        }
    if kind == "bearer_token":
        return {
            "auth_kind": "bearer",
            "header_name": "Authorization",
            "secret": material.secret,
            "metadata_json": {},
        }
    if kind == "api_key_header":
        return {
            "auth_kind": "api_key_header",
            "header_name": material.header_name,
            "secret": material.secret,
            "metadata_json": {},
        }
    if kind == "cookie":
        return {
            "auth_kind": "cookie",
            "header_name": "Cookie",
            "secret": material.secret,
            "metadata_json": {},
        }
    if kind == "basic_auth":
        return {
            "auth_kind": "basic_auth",
            "header_name": "Authorization",
            "secret": f"{material.username or ''}:{material.secret or ''}",
            "metadata_json": {},
        }
    if kind == "custom_headers":
        return {
            "auth_kind": "multi_header",
            "header_name": None,
            "secret": None,
            "metadata_json": {
                "headers": [
                    {"name": name, "value": value}
                    for name, value in sorted(material.custom_headers.items())
                ],
            },
        }
    raise CredentialResolutionError(
        "AI Gate credential authentication kind is not executable"
    )


def _validate_ai_gate_resolved_ref(resolved: Any, ref: Mapping[str, Any]) -> None:
    try:
        expected_version = int(ref.get("profile_version") or 0)
    except (TypeError, ValueError) as exc:
        raise CredentialResolutionError(
            "AI Gate credential profile version is invalid"
        ) from exc
    if (
        expected_version < 1
        or resolved.profile.current_version != expected_version
        or resolved.profile.auth_kind != str(ref.get("auth_kind") or "")
        or resolved.profile.principal_slot != str(ref.get("principal_slot") or "")
        or str(ref.get("source") or "") != "credential_profiles"
    ):
        raise CredentialResolutionError(
            "AI Gate credential changed after admission"
        )


def _ai_gate_target_binding(
    hydrated: Mapping[str, Any],
    ai_target: Mapping[str, Any],
    target_id: str,
) -> TargetBinding:
    endpoint_url = str(ai_target.get("endpoint_url") or "")
    parsed = urllib.parse.urlsplit(endpoint_url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise CredentialResolutionError("AI Gate target URL is invalid")
    guard = (
        dict(hydrated.get("runtime_scope_guard") or {})
        if isinstance(hydrated.get("runtime_scope_guard"), Mapping)
        else {}
    )
    roots = tuple(
        str(item).strip().lower().rstrip(".")
        for item in guard.get("allowed_root_domains") or ()
        if str(item).strip()
    ) or (parsed.hostname.lower().rstrip("."),)
    origins = tuple(
        str(item).strip().lower().rstrip("/")
        for item in guard.get("allowed_origins") or ()
        if str(item).strip()
    ) or (f"{parsed.scheme.lower()}://{parsed.netloc.lower()}",)
    addresses = tuple(
        str(item).strip()
        for item in guard.get("allowed_addresses") or ()
        if str(item).strip()
    )
    return TargetBinding(
        target_id=target_id,
        target_kind="api",
        canonical_host=parsed.hostname,
        allowed_origins=origins,
        allowed_addresses=addresses,
        allowed_root_domains=roots,
        environment=str(guard.get("environment") or "unknown"),
        scope_receipt_id=str(hydrated.get("scope_receipt_id") or "") or None,
    )


@asynccontextmanager
async def _hydrate_ai_gate_options(
    options: dict[str, Any], scan_id: str,
):
    hydrated = dict(options)
    ai_target = dict(hydrated.get("ai_target") or {})
    if not ai_target:
        yield hydrated
        return
    target_id = str(ai_target.get("id") or hydrated.get("ai_target_id") or "")
    try:
        uuid.UUID(target_id)
        uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise CredentialResolutionError("AI Gate credential authority is invalid") from exc

    default_ref = ai_target.pop("credential_profile_ref", None)
    legacy_ref = ai_target.pop("credential_ref", None)
    principal_refs = ai_target.pop("principal_refs", [])
    if legacy_ref and isinstance(legacy_ref, Mapping) and legacy_ref.get("configured"):
        raise CredentialResolutionError(
            "legacy AI Gate credential references are no longer executable"
        )
    if not isinstance(principal_refs, list) or any(
        not isinstance(item, Mapping) for item in principal_refs
    ):
        raise CredentialResolutionError("AI Gate principal references are invalid")
    has_credentials = isinstance(default_ref, Mapping) or any(
        isinstance(item.get("credential_profile_ref"), Mapping)
        for item in principal_refs
    )
    if any(
        item.get("credential_configured")
        and not isinstance(item.get("credential_profile_ref"), Mapping)
        for item in principal_refs
    ):
        raise CredentialResolutionError(
            "legacy AI Gate principal credentials are no longer executable"
        )

    ai_target["credential"] = {
        "auth_kind": "none", "header_name": None, "secret": None, "metadata_json": {},
    }
    ai_target["principals"] = [
        {
            "id": str(item.get("id") or ""),
            "label": item.get("label"),
            "role": item.get("role") or "attacker",
            "tenant_id": item.get("tenant_id"),
            "metadata_json": dict(item.get("metadata_json") or {}),
            "credential": {
                "auth_kind": "none", "header_name": None, "secret": None,
                "metadata_json": {},
            },
        }
        for item in principal_refs
    ]
    hydrated["ai_target"] = ai_target
    action_name = str(hydrated.pop("credential_action_name", "") or "").strip()

    resolver = WorkerCredentialResolver()
    try:
        async with AsyncExitStack() as stack:
            if has_credentials:
                if db_pool is None or not action_name:
                    raise CredentialResolutionError(
                        "AI Gate credential authority is incomplete"
                    )
                target = _ai_gate_target_binding(hydrated, ai_target, target_id)
                conn = await stack.enter_async_context(db_pool.acquire())
                authority = await validate_worker_credential_authority(
                    conn,
                    owner_kind="scan",
                    owner_id=scan_id,
                    target=target,
                    approval_receipt_id=hydrated.get("approval_receipt_id"),
                    scope_receipt_id=hydrated.get("scope_receipt_id"),
                    action_name=action_name,
                )
                if isinstance(default_ref, Mapping):
                    resolved = await stack.enter_async_context(resolver.resolve(
                        conn,
                        profile_id=default_ref.get("profile_id"),
                        target=target,
                        capability=AI_GATE_CREDENTIAL_CAPABILITY,
                        authority=authority,
                    ))
                    _validate_ai_gate_resolved_ref(resolved, default_ref)
                    ai_target["credential"] = _ai_gate_runtime_credential(resolved)
                for index, item in enumerate(principal_refs):
                    profile_ref = item.get("credential_profile_ref")
                    if not isinstance(profile_ref, Mapping):
                        continue
                    resolved = await stack.enter_async_context(resolver.resolve(
                        conn,
                        profile_id=profile_ref.get("profile_id"),
                        target=target,
                        capability=AI_GATE_CREDENTIAL_CAPABILITY,
                        authority=authority,
                    ))
                    _validate_ai_gate_resolved_ref(resolved, profile_ref)
                    ai_target["principals"][index]["credential"] = (
                        _ai_gate_runtime_credential(resolved)
                    )

            ai_runtime = _load_runtime_ai_settings()
            if ai_runtime.get("ai_url") and ai_runtime.get("ai_api_key"):
                hydrated.setdefault("ai_url", ai_runtime.get("ai_url"))
                hydrated.setdefault("ai_api_key", ai_runtime.get("ai_api_key"))
                hydrated.setdefault(
                    "ai_model", ai_runtime.get("ai_model") or "gpt-4o-mini"
                )
                hydrated.setdefault(
                    "ai_model_fallback",
                    ai_runtime.get("ai_model_fallback") or "",
                )
            yield hydrated
    finally:
        ai_target.pop("credential", None)
        for principal in ai_target.get("principals") or []:
            if isinstance(principal, dict):
                principal.pop("credential", None)


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
    if str(os.environ.get("SHAKERSCAN_BROKER_LEASE") or "").strip().lower() in {"1", "true", "yes", "on"}:
        return (RESULTS_DIR / f"{scan_id}_cancel").exists()
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


def _descendant_process_group_ids(root_pid: int, proc_root: str = "/proc") -> set[int]:
    """Best-effort PGIDs of all live descendants of ``root_pid`` (Linux ``/proc``); empty set on any
    failure, including non-Linux hosts that have no ``/proc``.

    Scanner tools run in their OWN session (scanner_tools/common.py starts each with
    ``start_new_session=True`` so the in-scanner cooperative watcher can reap grandchildren), which
    places them OUTSIDE scanner.py's process group. The force-kill backstop must therefore reach those
    separate groups explicitly. Callers enumerate BEFORE killing the scanner so the process tree is
    still intact — once the parent is reaped its descendants reparent to init and the link is lost.
    """
    try:
        children: dict[int, list[int]] = {}
        pid_pgid: dict[int, int] = {}
        for entry in os.listdir(proc_root):
            if not entry.isdigit():
                continue
            try:
                with open(os.path.join(proc_root, entry, "stat"), "r") as handle:
                    # "pid (comm) state ppid pgrp ..." — comm may contain spaces/parens, so split
                    # after the final ") " to reach the fixed positional fields.
                    after = handle.read().rsplit(") ", 1)[1].split()
                ppid = int(after[1])
                pgrp = int(after[2])
            except (OSError, ValueError, IndexError):
                continue
            pid = int(entry)
            children.setdefault(ppid, []).append(pid)
            pid_pgid[pid] = pgrp
    except OSError:
        return set()

    pgids: set[int] = set()
    seen: set[int] = set()
    stack = list(children.get(root_pid, []))
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        if pid in pid_pgid:
            pgids.add(pid_pgid[pid])
        stack.extend(children.get(pid, []))
    return pgids


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
            # Reach tool subprocesses that run in their OWN session (outside scanner.py's group) so a
            # starved-event-loop cancellation cannot orphan them. Enumerate descendant groups while the
            # tree is still intact, then SIGKILL them and the scanner's own group. Best-effort: the
            # descendant sweep is a no-op where /proc is unavailable, leaving prior behavior unchanged.
            for descendant_pgid in _descendant_process_group_ids(pid):
                try:
                    os.killpg(descendant_pgid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
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


# High-signal scanner stderr lines to mirror to the worker's stdout (so
# `docker compose logs worker -f` shows live scan progress). The full stderr is
# still buffered to Redis (the /scans/{id}/logs API) and dumped on completion;
# this only adds REAL-TIME visibility for the lines that matter when debugging a
# scan: phase markers, discovery/ingestion, the endpoint-scoped detectors, and
# errors. Set SHAKERSCAN_STREAM_SCANNER_LOGS=1 to mirror EVERY stderr line.
_SCANNER_LOG_FORWARD_RE = re.compile(
    r"\[(scanner|smart|discovery|bola|asm|nuclei)\]"
    r"|from OpenAPI|Auto-discovered OpenAPI|data_exposure|webhook_checks"
    r"|\bERROR\b|Traceback|\bWARN(?:ING)?\b|timed out|Exceeded max"
    r"|signature[- ]?bypass|exposure finding",
    re.IGNORECASE,
)
_STREAM_ALL_SCANNER_LOGS = str(os.environ.get("SHAKERSCAN_STREAM_SCANNER_LOGS", "")).strip().lower() in {"1", "true", "yes", "on"}

# --- Memory-aware scan admission control -----------------------------------
# Bound how many memory-heavy scanner subprocesses run AT ONCE across the whole
# fleet, so scaling to a large worker count (good for queue throughput) cannot
# OOM the Docker VM. Idle workers are cheap (~37MB); the real cost is concurrent
# ACTIVE scans (2-4GB each). A lease-based Redis semaphore caps concurrency to a
# value the API derives from Docker RAM and publishes to MAX_ACTIVE_SCANS_KEY.
# Standalone installs retain the historical best-effort fallback. Joined fleet
# nodes fail closed when Redis cannot authorize a slot or when the bounded wait
# expires; a remote node must never turn a control-plane partition into uncapped
# target pressure or memory use. Lease expiry frees a crashed holder's slot.
ACTIVE_SCAN_SLOTS_KEY = "shakerscan:active_scan_slots"
MAX_ACTIVE_SCANS_KEY = "shakerscan:max_active_scans"
_SCAN_SLOT_TTL_SECONDS = max(300, int(os.environ.get("SHAKERSCAN_SCAN_SLOT_TTL_SECONDS", "5400")))
_SCAN_SLOT_MAX_WAIT_SECONDS = max(0, int(os.environ.get("SHAKERSCAN_SCAN_SLOT_MAX_WAIT_SECONDS", "1800")))
_SCAN_SLOT_POLL_SECONDS = 3.0
_SCAN_SLOT_LUA = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, tonumber(ARGV[1]))
if redis.call('ZCARD', KEYS[1]) < tonumber(ARGV[3]) then
  redis.call('ZADD', KEYS[1], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[4])
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]) + 600)
  return 1
end
return 0
"""


class FleetAdmissionUnavailable(RuntimeError):
    """The control plane could not authorize a fleet worker to start a scan."""


def _fleet_limits_required() -> bool:
    explicit = str(os.environ.get("SHAKERSCAN_ENFORCE_FLEET_LIMITS") or "").strip().lower()
    if explicit:
        return explicit in {"1", "true", "yes", "on"}
    return bool(str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip())


def _max_active_scans(r) -> int:
    """Fleet-wide concurrent active-scan cap (published by the API from Docker RAM)."""
    try:
        v = r.get(MAX_ACTIVE_SCANS_KEY)
        if v:
            return max(1, int(v))
    except Exception:
        pass
    # Fallback when the API hasn't published the cap yet (fresh/headless start).
    # The API's authoritative value is RAM-derived (_compute_max_active_scans) and
    # is published within ~120s of startup. Until then, prefer an explicit override,
    # else use a CPU-count proxy (~1-2 cores per active scan) instead of a flat 10
    # so a fresh start doesn't underuse the fleet. The published RAM-derived value
    # supersedes this on the next poll.
    try:
        env = os.environ.get("SHAKERSCAN_MAX_ACTIVE_SCANS")
        if env:
            return max(1, int(env))
    except (TypeError, ValueError):
        pass
    return max(1, min(32, os.cpu_count() or 10))


def _take_scan_slot(r, slot_id: str) -> bool:
    """Atomically take an active-scan slot if under the cap."""
    try:
        got = r.eval(
            _SCAN_SLOT_LUA, 1, ACTIVE_SCAN_SLOTS_KEY,
            time.time(), _SCAN_SLOT_TTL_SECONDS, _max_active_scans(r), slot_id,
        )
        return bool(got)
    except Exception as exc:
        if _fleet_limits_required():
            raise FleetAdmissionUnavailable(
                "fleet active-scan admission is unavailable"
            ) from exc
        return True


def _release_scan_slot(r, slot_id: str) -> None:
    try:
        r.zrem(ACTIVE_SCAN_SLOTS_KEY, slot_id)
    except Exception:
        pass


async def _await_scan_slot(job_id: str | None, scan_id: str | None) -> tuple[Any, str | None, bool]:
    """Wait (bounded, heartbeating) for a fleet-wide active-scan slot.

    Returns (redis_or_None, slot_id_or_None, held). Standalone mode keeps the
    compatibility fail-open posture; joined fleet nodes require authorization."""
    if str(os.environ.get("SHAKERSCAN_BROKER_LEASE") or "").strip().lower() in {"1", "true", "yes", "on"}:
        # The HTTPS broker authorizes global admission before issuing the lease.
        return None, None, False
    try:
        r = get_redis()
    except Exception as exc:
        if _fleet_limits_required():
            raise FleetAdmissionUnavailable(
                "fleet active-scan admission cannot reach Redis"
            ) from exc
        return None, None, False
    slot_id = f"{job_id or scan_id or 'scan'}:{uuid.uuid4().hex[:8]}"
    deadline = time.time() + _SCAN_SLOT_MAX_WAIT_SECONDS
    waited = False
    while True:
        if _take_scan_slot(r, slot_id):
            if waited:
                print(f"[{(job_id or scan_id or '')[:8]}] acquired active-scan slot", file=sys.stderr, flush=True)
            return r, slot_id, True
        if time.time() >= deadline:
            if _fleet_limits_required():
                raise FleetAdmissionUnavailable(
                    f"fleet active-scan admission timed out after {_SCAN_SLOT_MAX_WAIT_SECONDS}s"
                )
            print(
                f"[{(job_id or scan_id or '')[:8]}] active-scan slot wait exceeded "
                f"({_SCAN_SLOT_MAX_WAIT_SECONDS}s); proceeding (best-effort throttle)",
                file=sys.stderr, flush=True,
            )
            return r, slot_id, False
        waited = True
        # Heartbeat so the stale-scan checker doesn't reap the job while it waits.
        if job_id:
            try:
                r.hset(f"job:{job_id}", 'heartbeat', utc_now_iso())
            except Exception:
                pass
        await asyncio.sleep(_SCAN_SLOT_POLL_SECONDS)


def _effective_request_budget_mode(options: dict[str, Any] | None) -> str:
    """Resolve request metering without removing the operator's explicit off switch.

    Fleet nodes turn the compatibility default into enforcement so independently
    scheduled workers share the domain budget. An explicit ``off`` remains off,
    preserving operator control for authorized local labs and other intentional
    high-throughput targets.
    """
    raw = str(
        (options or {}).get("request_budget_mode")
        or os.environ.get("SHAKERSCAN_REQUEST_BUDGET_MODE")
        or "compatibility"
    ).strip().lower()
    if raw not in {"off", "compatibility", "enforce"}:
        raw = "compatibility"
    if raw == "compatibility" and _fleet_limits_required():
        return "enforce"
    return raw


_SCANNER_MAIN_MARKERS = ('if __name__ == "__main__"', "if __name__ == '__main__'")
_scanner_preflight_cache: dict[str, tuple[tuple[int, float], str | None]] = {}


def _finalize_deterministic_scan_result(
    result: Any,
    admission: Any,
    scan_id: str | None,
) -> Any:
    """Attach canonical authority evidence and remove completed recovery state."""
    metadata = execution_result_metadata(admission) if admission is not None else None
    if metadata is not None and isinstance(result, dict):
        result = dict(result)
        result["scan_execution"] = metadata
    if isinstance(result, dict) and scan_id:
        sidecar = RESULTS_DIR / f"{scan_id}_checkpoint.json.endpoint-manifest.json"
        try:
            sidecar.unlink(missing_ok=True)
        except OSError:
            # Artifact cleanup must never replace an otherwise valid result.
            pass
    return result


def _scanner_preflight(scanner_path: str) -> str | None:
    """Return a clear error if the scanner entrypoint is missing / stale / truncated
    (e.g. macOS single-file bind-mount inode-pinning), else None. Turns the silent
    'Scanner produced no output (exit code 0)' failure — caused by a truncated
    scanner.py losing its `if __name__ == "__main__"` block — into a diagnosable
    error before we even spawn the subprocess. Cached by (size, mtime)."""
    try:
        st = os.stat(scanner_path)
    except OSError:
        # A missing path is handled by the normal subprocess spawn (and keeps unit
        # tests that mock the subprocess working); we only guard against a
        # PRESENT-but-stale/truncated entrypoint, which is the silent-failure mode.
        return None
    key = (st.st_size, st.st_mtime)
    cached = _scanner_preflight_cache.get(scanner_path)
    if cached and cached[0] == key:
        return cached[1]
    err: str | None = None
    try:
        with open(scanner_path, "r", errors="replace") as fh:
            src = fh.read()
    except OSError:
        return None
    if not src or not any(m in src for m in _SCANNER_MAIN_MARKERS):
        lines = src.count("\n") + 1 if src else 0
        err = (f"scanner entrypoint {scanner_path} is missing its __main__ block "
               f"({len(src)} bytes / {lines} lines) — almost certainly a stale/truncated "
               f"bind mount. Restart this worker to re-sync the source mount.")
    else:
        try:
            compile(src, scanner_path, "exec")
        except SyntaxError as e:
            err = (f"scanner entrypoint {scanner_path} has a syntax error at line "
                   f"{e.lineno} — likely a stale/truncated bind mount; restart this worker.")
    _scanner_preflight_cache[scanner_path] = (key, err)
    return err


def _resolve_deep_intent_exploit_level(scan_type: str, options: dict[str, Any]) -> str | None:
    """Return the CLI exploit level for an explicit deep-intent scan, else None.

    ``exploit_depth`` is the operator's explicit deep-intent option (the same
    signal used for retest gating). On smart/full scans it unlocks the
    aggressive proof-of-exploit profile by passing ``--exploit-level
    aggressive`` to the scanner (the scanner maps that flag to
    ``resolve_scan_poe_config``). Aggressive scan types already set it via
    ``--aggressive``. Public-only scans must never get it.
    """
    normalized = (scan_type or "").strip().lower()
    if normalized not in {"smart", "full"}:
        return None
    if not options.get("exploit_depth"):
        return None
    if options.get("public"):
        return None
    return "aggressive"


async def run_scan(
    target: str,
    options: dict,
    scan_id: str | None = None,
    job_id: str | None = None,
    progress_callback: Any = None,
    persist_checkpoint_artifacts: bool = True,
    canonical_runtime_budget: Mapping[str, int] | None = None,
    canonical_placed_capabilities: Mapping[str, Any] | None = None,
) -> dict:
    """Execute scanner and return results."""
    scan_admission = None
    native_scan_execution = None
    if is_deterministic_dast(options):
        options, scan_admission = prepare_worker_dispatch(options)
        if not scan_admission.canonical and os.getenv(
            "SHAKERSCAN_DISABLE_LEGACY_SCAN_EXECUTION", ""
        ).strip().lower() in {"1", "true", "yes", "on"}:
            raise ValueError(
                "legacy deterministic Scan execution is disabled; submit a "
                "canonical V2 plan"
            )
        if scan_admission.canonical and scan_admission.plan is not None:
            native_scan_execution = build_native_scan_execution(
                scan_admission.plan, options,
            )
            if canonical_runtime_budget is not None:
                native_scan_execution = native_scan_execution.with_runtime_budget(
                    canonical_runtime_budget
                )
            options = native_scan_execution.normalize_options(options)
            options["resolved_budget"] = resolve_scan_budget(
                "standard",
                scan_admission.plan.budget_profile,
                options.get("custom_budget")
                if isinstance(options.get("custom_budget"), dict) else None,
            )
        elif canonical_runtime_budget is not None:
            raise ValueError(
                "canonical runtime budget requires canonical Scan authority"
            )
    elif canonical_runtime_budget is not None:
        raise ValueError(
            "canonical runtime budget is valid only for deterministic Scan"
        )
    if canonical_placed_capabilities is not None and native_scan_execution is None:
        raise ValueError(
            "canonical placed capabilities require canonical Scan authority"
        )

    if options.get("run_kind") == "device_probe":
        if scan_id:
            await update_scan_progress(scan_id, "device_service_probe", 20, job_id=job_id)
        try:
            from scanner_tools.device_probe import run_device_service_probe
        except ImportError:
            from scanner.scanner_tools.device_probe import run_device_service_probe
        if str(os.environ.get("DEVICE_POSTURE_ENABLED", "true")).strip().lower() in {"0", "false", "no", "off"}:
            raise ValueError("connected-device posture is disabled on this worker")
        probe_options = dict(options or {})
        probe_options["_cancel_check"] = lambda: asyncio.to_thread(_scan_cancel_requested, scan_id)
        result = await run_device_service_probe(target, probe_options)
        if scan_id:
            await update_scan_progress(scan_id, "device_service_verdict", 90, job_id=job_id)
        return _strip_null_bytes(result) if isinstance(result, dict) else result

    if options.get("run_kind") == "device_posture":
        if scan_id:
            await update_scan_progress(scan_id, "device_inventory", 10, job_id=job_id)
        try:
            from scanner_tools.device_posture import run_device_posture_scan
        except ImportError:
            from scanner.scanner_tools.device_posture import run_device_posture_scan
        if str(os.environ.get("DEVICE_POSTURE_ENABLED", "true")).strip().lower() in {"0", "false", "no", "off"}:
            raise ValueError("connected-device posture is disabled on this worker")
        device_options = dict(options or {})
        device_options["_cancel_check"] = lambda: asyncio.to_thread(_scan_cancel_requested, scan_id)

        async def _device_progress(event: dict[str, Any]) -> None:
            if not scan_id:
                return
            phase = str(event.get("phase") or "device_inventory")
            try:
                progress = max(10, min(89, int(event.get("progress") or 10)))
            except (TypeError, ValueError):
                progress = 10
            await update_scan_progress(scan_id, phase, progress, job_id=job_id)
            _append_device_activity(
                scan_id, kind="phase", phase=phase, progress=progress,
                details=event.get("details") if isinstance(event.get("details"), dict) else None,
            )

        device_options["_progress_callback"] = _device_progress
        result = await run_device_posture_scan(target, device_options)
        if scan_id:
            await update_scan_progress(scan_id, "device_policy", 90, job_id=job_id)
        # Device protocol metadata is untrusted binary-adjacent input too. SSDP
        # banners and mDNS TXT records commonly contain padding NULs, which
        # PostgreSQL JSONB cannot store. Keep the same persistence boundary used
        # by ordinary DAST results instead of returning before it.
        return _strip_null_bytes(result) if isinstance(result, dict) else result

    if options.get("run_kind") in MODEL_INTAKE_RUN_KINDS:
        if scan_id:
            await update_scan_progress(scan_id, "model_intake", 15, job_id=job_id)
        try:
            from scanner_tools.model_intake import run_model_intake_scan
        except ImportError:
            from scanner.scanner_tools.model_intake import run_model_intake_scan

        intake_options = dict(options or {})
        if scan_id:
            intake_options.setdefault("scan_id", scan_id)
            intake_options.setdefault("quarantine_dir", str(RESULTS_DIR / "model-intake-quarantine"))

        async def _record_model_intake_event(event: dict[str, Any]) -> None:
            if not scan_id or not isinstance(event, dict):
                return
            line = str(event.get("line") or "").strip()
            if not line.startswith("[model-intake]") or len(line) > 1000:
                return

            def _write_log_line() -> None:
                redis_client = get_redis()
                log_key = f"scan:{scan_id}:logs"
                redis_client.rpush(log_key, line)
                redis_client.ltrim(log_key, -SCAN_LOG_TAIL, -1)
                redis_client.expire(log_key, SCAN_LOG_TTL_SECONDS)

            try:
                await asyncio.to_thread(_write_log_line)
            except Exception as exc:
                print(f"[model-intake] live log write failed: {type(exc).__name__}", flush=True)
            print(f"[{(job_id or scan_id)[:8]}] {line}", flush=True)
            try:
                progress = max(15, min(95, int(event.get("progress") or 15)))
            except (TypeError, ValueError):
                progress = 15
            phase = re.sub(r"[^a-z0-9_]+", "_", str(event.get("phase") or "model_intake").lower())[:64]
            await update_scan_progress(scan_id, phase or "model_intake", progress, job_id=job_id)

        result = await run_model_intake_scan(
            target,
            intake_options,
            event_callback=_record_model_intake_event,
        )
        if scan_id:
            await update_scan_progress(scan_id, "model_intake_finalize", 95, job_id=job_id)
        return result

    if options.get("run_kind") in AI_GATE_RUN_KINDS:
        if scan_id:
            await update_scan_progress(scan_id, "ai_gate", 15, job_id=job_id)
        from ai_gate_scan import run_ai_target_scan

        if not scan_id:
            raise CredentialResolutionError("AI Gate scan identity is unavailable")
        async with _hydrate_ai_gate_options(options, scan_id) as hydrated_options:
            result = await run_ai_target_scan(target, hydrated_options)
        if scan_id:
            await update_scan_progress(scan_id, "ai_gate_finalize", 95, job_id=job_id)
        return result

    cmd = ['python3', SCANNER_PATH, target]

    if native_scan_execution is not None:
        cmd.append('--canonical-scan')

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

    if native_scan_execution is not None:
        pass
    elif scan_type == 'smart':
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

    # Explicit deep intent (exploit_depth) on smart/full scans unlocks the
    # aggressive proof-of-exploit profile via --exploit-level. The API never
    # passes --exploit-level itself, so without this the deep-intent signal
    # (the same option that gates retest depth) silently kept safe proofs.
    # Public scans must never get it; public+active scan types are already
    # rejected above, and the guard here is defense in depth.
    deep_intent_exploit_level = (
        _resolve_deep_intent_exploit_level(scan_type, options)
        if native_scan_execution is None else None
    )
    if deep_intent_exploit_level:
        cmd.extend(['--exploit-level', deep_intent_exploit_level])

    # Additional flags (can be combined with scan types)
    # Pass --active when explicitly requested (even with explicit scan_type)
    # Note: full/aggressive/smart already include active tests, so skip for those
    if (
        native_scan_execution is None
        and options.get('active')
        and scan_type not in ['full', 'aggressive', 'smart']
    ):
        cmd.append('--active')

    # Note: public is not allowed for smart/full/aggressive (validated above)
    if native_scan_execution is None and options.get('public'):
        cmd.append('--public')
    check_family = options.get('asm_check_family') or options.get('check_family')
    if native_scan_execution is None and check_family:
        cmd.extend(['--check-family', str(check_family)])
    if native_scan_execution is None and options.get('xss'):
        cmd.append('--xss')
    if native_scan_execution is None and options.get('sqli'):
        cmd.append('--sqli')
    if native_scan_execution is None and options.get('deep_domxss'):
        cmd.append('--deep-domxss')
    if (
        native_scan_execution is None
        and options.get('nuclei')
        and scan_type not in ['full', 'aggressive', 'deep']
    ):
        cmd.append('--nuclei')
    if native_scan_execution is None and options.get('enhanced_dns'):
        cmd.append('--enhanced-dns')
    if native_scan_execution is None and options.get('subfinder'):
        cmd.append('--subfinder')
    if native_scan_execution is None and options.get('network_discovery'):
        cmd.append('--network-discovery')

    # Client-Side Security
    if native_scan_execution is None and options.get('js_dependency_scanning'):
        cmd.append('--js-dependency-scanning')
    if native_scan_execution is None and options.get('js_secret_scanning'):
        cmd.append('--js-secret-scanning')
    if native_scan_execution is None and options.get('grpc_discovery'):
        cmd.append('--grpc-discovery')
    if native_scan_execution is None and options.get('json_link_following'):
        cmd.append('--json-link-following')
    if native_scan_execution is None and options.get('options_method_discovery'):
        cmd.append('--options-method-discovery')
    if options.get('include_partial_attack_chains'):
        cmd.append('--include-partial-attack-chains')
    if native_scan_execution is None and options.get('skip_global_checks'):
        cmd.append('--skip-global-checks')
    if native_scan_execution is None and options.get('focused_endpoints_only'):
        cmd.append('--focused-endpoints-only')
    if native_scan_execution is None and options.get('zero_rediscovery'):
        cmd.append('--zero-rediscovery')
    if native_scan_execution is None and (
        options.get('parallel_discovery') or options.get('discovery_manifest_only')
    ):
        cmd.append('--discovery-manifest-only')

    # Smart scan tuning options
    if native_scan_execution is None and options.get('no_early_stop'):
        cmd.append('--no-early-stop')
    if native_scan_execution is None and options.get('thorough_params'):
        cmd.append('--thorough-params')
    if native_scan_execution is None and options.get('oob_callback_url'):
        cmd.extend(['--oob-callback-url', options['oob_callback_url']])
    if native_scan_execution is None and options.get('budget_profile'):
        cmd.extend(['--budget-profile', str(options['budget_profile'])])

    custom_budget = options.get("custom_budget")
    if native_scan_execution is None and isinstance(custom_budget, dict):
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
            "request_max": "--budget-request-max",
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
    if native_scan_execution is None and options.get('smart_bola_max_endpoints'):
        cmd.extend(['--smart-bola-max-endpoints', str(options['smart_bola_max_endpoints'])])
    if native_scan_execution is None and options.get('dom_xss_max_files'):
        cmd.extend(['--dom-xss-max-files', str(options['dom_xss_max_files'])])
    if native_scan_execution is None and options.get('sqli_extract_max'):
        cmd.extend(['--sqli-extract-max', str(options['sqli_extract_max'])])
    # oob_max_findings (prefer new name, fall back to deprecated oob_max_payloads)
    oob_max = options.get('oob_max_findings')
    if oob_max is None:
        oob_max = options.get('oob_max_payloads')
    if native_scan_execution is None and oob_max is not None:
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
    scan_ai_enabled = bool(
        ai_scan_classify_enabled and native_scan_execution is None
    )

    if scan_ai_enabled and ai_url and ai_api_key and model:
        cmd.append('--ai')
        cmd.extend(['--ai-url', ai_url])
        cmd.extend(['--model', model])
        if ai_fallback_model:
            cmd.extend(['--ai-fallback-model', str(ai_fallback_model)])
        cmd.extend(['--ai-mask-host', ai_mask_host])

    # Authentication options
    # Canonical credentials are resolved and consumed only by worker-owned,
    # target-bound capabilities. The final scan.execute subprocess assembles
    # placed evidence and must never receive reusable secret material or gain
    # authority to perform its own login flow.
    scanner_auth_config_file = (
        None
        if native_scan_execution is not None
        else _write_scanner_auth_config_file(
            _scanner_auth_config_from_options(options)
        )
    )
    if scanner_auth_config_file:
        cmd.extend(['--auth-config-file', scanner_auth_config_file])

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
    scan_env.pop("SHAKERSCAN_CANONICAL_PLACEMENTS_FILE", None)
    scan_env.pop("SHAKERSCAN_CANONICAL_PLACEMENTS_SHA256", None)
    canonical_placement_bundle = None
    placement_payload = None
    if native_scan_execution is not None:
        native_payload = native_scan_execution.payload()
        scan_env["SHAKERSCAN_CANONICAL_REPORT_ONLY"] = "true"
        scan_env["SHAKERSCAN_CANONICAL_SCAN_EXECUTION"] = json.dumps(
            native_payload,
            sort_keys=True,
            separators=(",", ":"),
        )
        if canonical_placed_capabilities is not None:
            if (
                len(canonical_placed_capabilities) > 16
                or any(
                    not isinstance(summary, Mapping)
                    for summary in canonical_placed_capabilities.values()
                )
            ):
                raise ValueError(
                    "canonical placed capabilities are invalid"
                )
            placement_payload = {
                "schema_version": "canonical-scan-placements/v1",
                "execution_plan_digest": native_payload[
                    "execution_plan_digest"
                ],
                "target_binding_digest": native_payload[
                    "target_binding_digest"
                ],
                "capabilities": {
                    str(name): dict(summary)
                    for name, summary in canonical_placed_capabilities.items()
                },
            }
    if scan_ai_enabled and ai_api_key:
        scan_env["AI_API_KEY"] = ai_api_key
    # Stamp the real deployed commit (published by the API from the live checkout)
    # so scan results record the running build, not the stale baked SCANNER_VERSION.
    _real_version = _published_scanner_version()
    if _real_version:
        scan_env["SCANNER_VERSION"] = _real_version
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
    request_budget_mode = _effective_request_budget_mode(options)
    scan_env["SHAKERSCAN_REQUEST_BUDGET_MODE"] = request_budget_mode
    resolved_request_budget = resolve_or_consume_budget(
        scan_type or "standard",
        options=options,
        budget_profile=options.get("budget_profile"),
        custom_budget=custom_budget if isinstance(custom_budget, dict) else None,
    )
    scan_env["SHAKERSCAN_REQUEST_BUDGET_LIMIT"] = (
        "0" if native_scan_execution is not None
        else str(max(0, int(resolved_request_budget.get("request_max") or 0)))
    )
    if native_scan_execution is not None:
        scan_env["SHAKERSCAN_REQUEST_BUDGET_RESERVED"] = "0"
    elif options.get("request_budget_reserved") is not None:
        scan_env["SHAKERSCAN_REQUEST_BUDGET_RESERVED"] = str(
            max(0, int(options.get("request_budget_reserved") or 0))
        )
    if options.get("request_budget_domain"):
        scan_env["SHAKERSCAN_REQUEST_BUDGET_DOMAIN"] = str(options["request_budget_domain"])
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

    if placement_payload is not None:
        canonical_placement_bundle = write_private_placement_bundle(
            placement_payload,
        )
        scan_env.update(canonical_placement_bundle.environment())

    # Preflight the scanner entrypoint: a stale/truncated bind mount (the macOS
    # single-file-mount inode-pinning) silently yields no output + exit 0. Fail
    # loudly with a diagnosable error instead of spawning a doomed subprocess.
    _pf_err = _scanner_preflight(SCANNER_PATH)
    if _pf_err:
        print(f"[worker] SCANNER PREFLIGHT FAILED: {_pf_err}", file=sys.stderr, flush=True)
        if scanner_auth_config_file:
            try:
                os.unlink(scanner_auth_config_file)
            except OSError:
                pass
        if canonical_placement_bundle is not None:
            canonical_placement_bundle.cleanup()
        return _finalize_deterministic_scan_result({
            "target": target,
            "error": _pf_err,
            "findings": [],
            "result": {"score": None, "grade": None},
            "scan_metadata": {"status": "failed", "preflight_failed": True},
        }, scan_admission, scan_id)

    # Memory-aware admission control: wait (bounded, heartbeating) for a fleet-wide
    # active-scan slot before launching the heavy scanner subprocess, so a large
    # worker fleet can't run too many scans at once and OOM the Docker VM.
    try:
        _slot_r, _slot_id, _slot_held = await _await_scan_slot(job_id, scan_id)
    except FleetAdmissionUnavailable as exc:
        if scanner_auth_config_file:
            try:
                os.unlink(scanner_auth_config_file)
            except OSError:
                pass
        if canonical_placement_bundle is not None:
            canonical_placement_bundle.cleanup()
        return _finalize_deterministic_scan_result({
            "target": target,
            "error": str(exc),
            "findings": [],
            "result": {"score": None, "grade": None},
            "scan_metadata": {
                "status": "failed",
                "admission_control_failed": True,
                "retryable": True,
            },
        }, scan_admission, scan_id)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=scan_env,
            **_scanner_process_kwargs(),
        )
    except Exception:
        if scanner_auth_config_file:
            try:
                os.unlink(scanner_auth_config_file)
            except OSError:
                pass
        if canonical_placement_bundle is not None:
            canonical_placement_bundle.cleanup()
        raise

    timeout_reason: str | None = None
    cancel_reason: str | None = None
    if native_scan_execution is not None:
        native_payload = native_scan_execution.payload()
        max_duration_seconds = max(
            1,
            min(
                int(native_payload["execution_budget"]["max_duration_seconds"]),
                int(native_payload["runtime_budget"]["tool_wall_seconds"]),
            ),
        )
    else:
        max_duration_seconds = DEFAULT_MAX_DURATION_MINUTES * 60
    override_minutes = os.environ.get("SCAN_MAX_DURATION_MINUTES")
    if override_minutes:
        try:
            configured_seconds = max(60, int(override_minutes) * 60)
            max_duration_seconds = (
                min(max_duration_seconds, configured_seconds)
                if native_scan_execution is not None else configured_seconds
            )
        except Exception:
            if native_scan_execution is None:
                max_duration_seconds = DEFAULT_MAX_DURATION_MINUTES * 60
    elif native_scan_execution is None:
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
            max_duration_seconds = 60 * int(
                resolved_budget.get("max_duration_minutes")
                or MAX_SCAN_DURATION.get(scan_type, DEFAULT_MAX_DURATION_MINUTES)
            )

    async def _watchdog_timeout() -> None:
        nonlocal timeout_reason
        if max_duration_seconds <= 0:
            return
        await asyncio.sleep(max_duration_seconds)
        if proc.returncode is None:
            timeout_reason = (
                "Exceeded max duration "
                f"({max_duration_seconds}s for "
                f"{'canonical' if native_scan_execution is not None else scan_type or 'standard'} scan)"
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

    checkpoint_signature: tuple[int, int] | None = None

    async def _upload_checkpoint_if_changed(*, force: bool = False) -> bool:
        nonlocal checkpoint_signature
        if not persist_checkpoint_artifacts or not checkpoint_file or not scan_id:
            return False
        try:
            stat = await asyncio.to_thread(checkpoint_file.stat)
        except OSError:
            return False
        signature = (int(stat.st_mtime_ns), int(stat.st_size))
        if not force and signature == checkpoint_signature:
            return False
        raw = await asyncio.to_thread(checkpoint_file.read_bytes)
        # Atomic scanner writes mean a visible checkpoint should always be valid
        # JSON. Validate before replacing the last known-good remote copy.
        await asyncio.to_thread(json.loads, raw.decode("utf-8"))
        await persist_scan_artifact_bytes(
            raw,
            scan_id=scan_id,
            artifact_type="checkpoint",
            filename="checkpoint.json",
            content_type="application/json",
            metadata={"job_id": job_id, "live_mirror": True},
        )
        checkpoint_signature = signature
        return True

    async def _mirror_checkpoint() -> None:
        while proc.returncode is None:
            await asyncio.sleep(ARTIFACT_CHECKPOINT_INTERVAL_SECONDS)
            try:
                await _upload_checkpoint_if_changed()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                # Keep scanning and retry the latest atomic checkpoint. The
                # final upload below is authoritative and fails closed on fleet
                # nodes if the object plane never recovers.
                print(
                    f"[{(job_id or scan_id)[:8]}] checkpoint mirror retry: "
                    f"{type(exc).__name__}: {exc}",
                    flush=True,
                )

    checkpoint_task = asyncio.create_task(_mirror_checkpoint())

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

        # Live-mirror high-signal lines to stdout so `docker compose logs worker`
        # shows scan progress in real time (otherwise stderr is only dumped once
        # the scan finishes — invisible while a long scan runs).
        if _STREAM_ALL_SCANNER_LOGS or _SCANNER_LOG_FORWARD_RE.search(text):
            _jid = (job_id or scan_id or "")[:8]
            print(f"[scan {_jid}] {text}", flush=True)

        if log_key:
            try:
                r = get_redis()
                r.rpush(log_key, text)
                r.ltrim(log_key, -SCAN_LOG_TAIL, -1)
                r.expire(log_key, SCAN_LOG_TTL_SECONDS)
            except Exception:
                pass

        progress = _parse_progress(text)
        if progress_callback is not None:
            callback_result = progress_callback({
                "line": text,
                "phase": progress[0] if progress else None,
                "progress": progress[1] if progress else None,
            })
            if asyncio.iscoroutine(callback_result):
                await callback_result
        if progress and scan_id:
            phase, pct = progress
            last_phase, last_pct = last_progress
            if phase != last_phase or pct != last_pct:
                if str(os.environ.get("SHAKERSCAN_BROKER_LEASE") or "").strip().lower() not in {"1", "true", "yes", "on"}:
                    await update_scan_progress(scan_id, phase, pct, job_id=job_id)
                last_progress = (phase, pct)
            elif job_id and str(os.environ.get("SHAKERSCAN_BROKER_LEASE") or "").strip().lower() not in {"1", "true", "yes", "on"}:
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

    try:
        await proc.wait()
    except asyncio.CancelledError:
        # Queue fencing, worker shutdown, and operator cancellation must not
        # leave scanner.py or its independently-sessioned tool descendants
        # running after this coroutine loses authority.
        await asyncio.to_thread(
            _signal_scanner_cancel_file,
            str(cancel_file) if cancel_file else None,
        )
        await asyncio.shield(_terminate_scanner_process(proc))
        if _slot_held and _slot_r is not None:
            _release_scan_slot(_slot_r, _slot_id)
            _slot_held = False
        for task in (watchdog_task, cancel_task, checkpoint_task, stdout_task, stderr_task):
            task.cancel()
        await asyncio.gather(
            watchdog_task,
            cancel_task,
            checkpoint_task,
            stdout_task,
            stderr_task,
            return_exceptions=True,
        )
        if scanner_auth_config_file:
            try:
                os.unlink(scanner_auth_config_file)
            except OSError:
                pass
        if canonical_placement_bundle is not None:
            canonical_placement_bundle.cleanup()
        raise
    # Scanner subprocess (the memory hog) has exited — free the active-scan slot
    # immediately so a waiting worker can start; the rest of run_scan is light.
    if _slot_held and _slot_r is not None:
        _release_scan_slot(_slot_r, _slot_id)
        _slot_held = False
    for task in (watchdog_task, cancel_task, checkpoint_task):
        task.cancel()
        try:
            await task
        except BaseException:
            pass  # CancelledError is BaseException in Python 3.8+
    await stdout_task
    await stderr_task
    if scanner_auth_config_file:
        try:
            os.unlink(scanner_auth_config_file)
        except OSError:
            pass
    if canonical_placement_bundle is not None:
        canonical_placement_bundle.cleanup()

    stdout_text = b"".join(stdout_chunks).decode(errors="replace") if stdout_chunks else ""
    stderr_text = "\n".join(stderr_lines)

    if checkpoint_file and checkpoint_file.exists():
        try:
            await _upload_checkpoint_if_changed(force=True)
        except Exception as exc:
            if artifact_remote_required():
                raise
            print(
                f"[{(job_id or scan_id)[:8]}] local checkpoint artifact unavailable: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

    if scan_id and (cancel_reason or timeout_reason or proc.returncode not in (0, None)):
        diagnostics = {
            "scan_id": scan_id,
            "job_id": job_id,
            "exit_code": proc.returncode,
            "cancel_reason": cancel_reason,
            "timeout_reason": timeout_reason,
            "masked_command": " ".join(cmd_masked),
            "stdout_len": len(stdout_text),
            "stderr_len": len(stderr_text),
            "stderr_tail": redact_text(stderr_text[-20000:]),
            "recorded_at": utc_now_iso(),
        }
        try:
            await persist_scan_artifact_bytes(
                json.dumps(diagnostics, sort_keys=True, default=str, indent=2).encode("utf-8"),
                scan_id=scan_id,
                artifact_type="diagnostic",
                filename="scanner-exit.json",
                content_type="application/json",
                metadata={"job_id": job_id, "terminal": True},
            )
        except Exception as exc:
            if artifact_remote_required():
                raise
            print(
                f"[{(job_id or scan_id)[:8]}] local diagnostic artifact unavailable: "
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

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
                    partial = (
                        _strip_null_bytes(partial)
                        if isinstance(partial, dict)
                        else partial
                    )
                    return _finalize_deterministic_scan_result(
                        partial, scan_admission, scan_id,
                    )
            except Exception:
                pass
        # Always surface a non-empty error: the caller marks a scan failed only
        # when result["error"] is truthy. A crashed/silent scanner (no JSON, no
        # stderr, no timeout) must not be mislabeled "completed".
        return _finalize_deterministic_scan_result({
            'error': (
                cancel_reason
                or timeout_reason
                or stderr_text
                or f"Scanner produced no output (exit code {proc.returncode})"
            ),
            'target': target,
            'exit_code': proc.returncode,
            # Persist enough to diagnose a silent no-output failure after the fact
            # (the failing runtime is usually gone by the time it's noticed): the
            # masked command, output sizes, and a head of whatever did come back.
            'failure_diagnostics': {
                'masked_command': ' '.join(cmd_masked),
                'stdout_len': len(stdout_text or ''),
                'stderr_len': len(stderr_text or ''),
                'stdout_head': (stdout_text or '')[:1000],
                'scanner_version': os.environ.get('SCANNER_VERSION') or os.environ.get('GIT_COMMIT') or 'dev',
            },
        }, scan_admission, scan_id)

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

    # Strip NUL bytes from the whole result before any caller persists it: the report
    # is written to the scans.result JSONB column (and findings rows), and PostgreSQL
    # cannot store \x00 (asyncpg UntranslatableCharacterError). NUL reaches the report
    # via harvested binary content (e.g. the %2500 file-bypass). Doing it here covers
    # every caller (standalone/shard/ASM-batch/recon) in one place.
    if isinstance(result, dict):
        result = _strip_null_bytes(result)
    return _finalize_deterministic_scan_result(
        result, scan_admission, scan_id,
    )


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

    Endpoint findings get a TEMPLATED, id/payload-insensitive identity so one
    BOLA route reported per object id (/orders/1../orders/46) and one SQLi param
    reported per payload variant collapse to a single DB row instead of dozens
    (docs proposed-next-steps §5). Non-endpoint findings (TLS, headers, DNS,
    config) keep the stable scanner ID so distinct config issues never merge.
    """
    # Templated identity for endpoint findings — primary count-explosion fix.
    try:
        templated = _templated_finding_identity(finding)
    except Exception:
        templated = None
    if templated:
        return "t:" + hashlib.sha256(templated.encode()).hexdigest()[:16]

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


def _finding_proof_rank(finding: dict[str, Any]) -> int:
    if not isinstance(finding, dict):
        return 0
    try:
        _status, verdict, _confidence = _scan_time_verification_fields(finding)
    except Exception:
        verdict = None
    if verdict == "exploited":
        return 2
    if verdict == "likely_vulnerable" or finding.get("suspected") or finding.get("needs_verification"):
        return 1
    return 0


def _finding_strength(finding: dict[str, Any]) -> tuple[int, int, float, int]:
    if not isinstance(finding, dict):
        return (0, 0, 0.0, 0)
    severity_rank = SEVERITY_ORDER.get(str(finding.get("severity") or "").lower(), 0)
    try:
        confidence = float(finding.get("confidence") or finding.get("ai_confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    evidence_size = len(json.dumps(finding.get("evidence") or {}, sort_keys=True, default=str))
    return (_finding_proof_rank(finding), severity_rank, confidence, evidence_size)


def _finding_merge_instance(finding: dict[str, Any]) -> dict[str, Any]:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return {
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "tool": finding.get("tool"),
        "url": finding.get("url") or evidence.get("url") or evidence.get("endpoint") or evidence.get("target"),
        "method": finding.get("method") or evidence.get("method"),
        "parameter": (
            finding.get("parameter")
            or finding.get("param")
            or evidence.get("parameter")
            or evidence.get("param")
        ),
        "cwe": finding.get("cwe"),
        "verified": finding.get("verified") is True,
    }


def _finding_duplicate_count(finding: dict[str, Any]) -> int:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    dedup = finding.get("deduplication") if isinstance(finding.get("deduplication"), dict) else {}
    for value in (dedup.get("original_count"), evidence.get("duplicate_count")):
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            pass
    return 1


def _merge_parent_duplicate_finding(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Merge duplicate parent findings without losing proof/evidence.

    Count collapse should make one product finding, not discard the stronger shard's
    proof or the concrete URLs/payloads that explain the collapsed instances.
    """
    if _finding_strength(incoming) > _finding_strength(existing):
        primary = copy.deepcopy(incoming)
    else:
        primary = copy.deepcopy(existing)

    evidence = primary.get("evidence") if isinstance(primary.get("evidence"), dict) else {}
    evidence = copy.deepcopy(evidence)

    def add_unique(key: str, value: Any) -> None:
        if value in (None, "", []):
            return
        items = evidence.setdefault(key, [])
        if not isinstance(items, list):
            items = [items]
            evidence[key] = items
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item not in (None, "") and item not in items:
                items.append(item)

    for source in (existing, incoming):
        ev = source.get("evidence") if isinstance(source.get("evidence"), dict) else {}
        add_unique("all_urls", source.get("url") or ev.get("url") or ev.get("endpoint") or ev.get("target"))
        add_unique("all_payloads", ev.get("payload") or ev.get("payloads") or ev.get("attack_payload"))

    instances = evidence.setdefault("merged_instances", [])
    if not isinstance(instances, list):
        instances = []
        evidence["merged_instances"] = instances
    for source in (existing, incoming):
        instance = _finding_merge_instance(source)
        if instance not in instances:
            instances.append(instance)
    if len(instances) > 25:
        evidence["merged_instances"] = instances[:25]

    total_count = _finding_duplicate_count(existing) + _finding_duplicate_count(incoming)
    evidence["duplicate_count"] = total_count
    primary["evidence"] = evidence
    dedup = primary.setdefault("deduplication", {})
    if isinstance(dedup, dict):
        dedup["consolidated"] = True
        dedup["original_count"] = total_count
        tools = {
            str(source.get("tool"))
            for source in (existing, incoming)
            if source.get("tool")
        }
        existing_tools = dedup.get("tools_involved")
        if isinstance(existing_tools, list):
            tools.update(str(tool) for tool in existing_tools if tool)
        dedup["tools_involved"] = sorted(tools)
    return primary


def _add_parent_union_finding(union: dict[str, dict], fingerprint: str, finding: dict[str, Any]) -> None:
    if fingerprint in union:
        union[fingerprint] = _merge_parent_duplicate_finding(union[fingerprint], finding)
    else:
        union[fingerprint] = finding


def _strip_null_bytes(value):
    """Recursively remove NUL (\\x00) from strings. PostgreSQL text/JSONB cannot
    store \\u0000 — asyncpg raises UntranslatableCharacterError, which crashed
    finding persistence and left the scan stuck mid-finalize (until the stale
    checker reaped it, discarding ALL results). NUL bytes reach findings via binary
    content harvested through the encoded-null-byte file-exposure bypass and other
    raw response captures. Stripping at the DB-write boundary fixes it universally."""
    if isinstance(value, str):
        return value.replace("\x00", "") if "\x00" in value else value
    if isinstance(value, dict):
        return {k: _strip_null_bytes(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_null_bytes(v) for v in value]
    return value


async def _persist_evidence_object(conn, scan_uuid, finding_id, finding: dict, evidence_redacted,
                                   *, tool_override: str | None = None) -> None:
    """Best-effort: persist a finding's (already null-stripped + redacted) evidence as
    a first-class durable evidence_object. NEVER raises — an evidence-object write must
    not fail or roll back the scan; findings.evidence stays the back-compat source of
    truth. Large payloads are content-addressed under RESULTS_DIR/evidence-objects."""
    if not finding_id:
        return
    locked_sha: str | None = None
    identity_lock: str | None = None
    try:
        content = evidence_redacted if evidence_redacted else None
        tool = tool_override or finding.get("tool")
        object_type = (f"{tool}_evidence" if tool else "finding_evidence")[:64]
        # Lock the stable row identity before checking pending state. Otherwise a
        # retention intent can land between the check and a different-content
        # upsert, making the conditional UPSERT a silent no-op after a new blob
        # was already written.
        identity_lock = await _acquire_evidence_identity_lock(conn, finding_id, object_type)
        pending_preview = await conn.fetchval(
            """
            SELECT retention_delete_preview_id
            FROM evidence_objects
            WHERE finding_id=$1 AND object_type=$2
              AND retention_delete_pending_at IS NOT NULL
            """,
            finding_id,
            object_type,
        )
        if pending_preview:
            return
        locked_sha = await _acquire_evidence_blob_lock(conn, content)
        stored = store_evidence_content(content, results_dir=RESULTS_DIR)
        retention = "sensitive" if (
            finding.get("request") or finding.get("response")
            or tool in ("ai_gate", "ai_session", "model_intake")
        ) else "standard"
        await conn.execute("""
            INSERT INTO evidence_objects
                (scan_id, finding_id, object_type, content_sha256, size_bytes,
                 storage_uri, redaction_profile, retention_class, content)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
            ON CONFLICT (finding_id, object_type) DO UPDATE SET
                content_sha256=EXCLUDED.content_sha256, size_bytes=EXCLUDED.size_bytes,
                storage_uri=EXCLUDED.storage_uri, content=EXCLUDED.content,
                retention_class=EXCLUDED.retention_class, created_at=NOW()
            WHERE evidence_objects.retention_delete_pending_at IS NULL
        """, scan_uuid, finding_id, object_type,
             stored["content_sha256"], stored["size_bytes"], stored["storage_uri"],
             "redact_sensitive_v1", retention, stored["content"])
    except Exception as e:
        print(f"[evidence] persist failed for finding {finding_id}: {type(e).__name__}: {e}", flush=True)
    finally:
        await _release_evidence_blob_lock(conn, locked_sha)
        await _release_evidence_identity_lock(conn, identity_lock)


def build_application_graph(result: dict) -> tuple[dict, dict]:
    """Pure transform: scan result -> (nodes, edges) for the first-class application
    graph. nodes: node_key -> {node_type,label,attributes}; edges: (src,dst,type) ->
    attributes. Producer/consumer/object/auth-boundary structure comes from the BOLA
    resource_map (found recursively, wherever it lands in the report); route nodes
    also come from discovery so the graph has context even without a dual-user pass."""
    nodes: dict = {}
    edges: dict = {}
    if not isinstance(result, dict):
        return nodes, edges

    def add_route(method_path, attrs=None):
        mp = str(method_path or "").strip()
        if not mp:
            return None
        key = f"route:{mp}"
        node = nodes.setdefault(key, {"node_type": "route", "label": mp, "attributes": {}})
        if attrs:
            node["attributes"].update({k: v for k, v in attrs.items() if v is not None})
        return key

    def add_object(obj_key, attrs=None):
        ok = str(obj_key or "object_id").strip() or "object_id"
        key = f"object:{ok}"
        node = nodes.setdefault(key, {"node_type": "object", "label": ok, "attributes": {}})
        if attrs:
            node["attributes"].update({k: v for k, v in attrs.items() if v is not None})
        return key

    resource_maps: list = []

    def _walk(o, depth=0):
        if depth > 30:
            return
        if isinstance(o, dict):
            if o.get("producer_endpoint") and o.get("consumer_candidates") is not None:
                resource_maps.append(o)
            for v in o.values():
                _walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o[:4096]:
                _walk(v, depth + 1)

    _walk(result)

    for rm in resource_maps:
        producer = add_route(rm.get("producer_endpoint"), {"role": "producer"})
        if not producer:
            continue
        sensitive = rm.get("sensitive_fields") or []
        obj = add_object(rm.get("object_id_key"),
                         {"location": rm.get("object_id_location"), "sensitive_fields": sensitive})
        edges[(producer, obj, "produces")] = {"source_principal": rm.get("source_principal")}
        for cons in (rm.get("consumer_candidates") or [])[:50]:
            c = add_route(cons, {"role": "consumer"})
            if not c:
                continue
            edges[(obj, c, "consumed_by")] = {}
            edges[(producer, c, "auth_boundary")] = {
                "object_id_key": str(rm.get("object_id_key") or ""),
                "source_principal": rm.get("source_principal"),
                "excluded_principal": rm.get("excluded_from_principal"),
                "sensitive_fields": sensitive,
            }

    # Focused authenticated preflights also emit a versioned endpoint-attempt
    # ledger. A producer may have no consumer candidates (for example both
    # principals can list the same collection), but a successful response from
    # two distinct principals is still an observed auth boundary. Keep this
    # separate from vulnerability proof: graph edges are context/leads, never
    # findings. Unknown telemetry schemas are rejected by the normalizer.
    for attempt in _active_endpoint_attempts_from_report(result):
        source_principal = str(attempt.get("source_principal") or "").strip()
        attacker_principal = str(attempt.get("attacker_principal") or "").strip()
        if not source_principal or not attacker_principal or source_principal == attacker_principal:
            continue
        try:
            owner_status = int(attempt.get("owner_status") or 0)
        except (TypeError, ValueError):
            owner_status = 0
        attacker_status_raw = (
            attempt.get("attacker_status")
            if attempt.get("attacker_status") is not None
            else attempt.get("attacker_listing_status")
        )
        try:
            attacker_status = int(attacker_status_raw or 0)
        except (TypeError, ValueError):
            attacker_status = 0
        # Do not turn guessed/404 producer paths into graph structure.  The owner
        # route must have produced a real response and the second-principal request
        # must have completed, regardless of whether it was allowed or denied.
        if not (200 <= owner_status < 400) or attacker_status <= 0:
            continue
        producer_label = str(attempt.get("producer_endpoint") or "").strip()
        consumer_label = str(attempt.get("consumer_endpoint") or "").strip()
        producer = add_route(producer_label, {"role": "producer", "observed": True})
        consumer = add_route(consumer_label, {"role": "consumer", "observed": True})
        if not producer or not consumer:
            continue
        sensitive = attempt.get("property_names_tested") or attempt.get("sensitive_fields") or []
        if not isinstance(sensitive, list):
            sensitive = []
        object_id_key = str(attempt.get("object_id_key") or "").strip()
        try:
            resource_ids_found = max(0, int(attempt.get("resource_ids_found") or 0))
        except (TypeError, ValueError):
            resource_ids_found = 0
        # Producer discovery does not always know the response field name.  Use a
        # route-scoped key only when resource identifiers were actually parsed so
        # unrelated collections are not collapsed into one generic object node.
        if not object_id_key and resource_ids_found:
            object_id_key = f"resource_id@{producer_label}"
        if object_id_key:
            obj = add_object(object_id_key, {
                "location": attempt.get("object_id_location"),
                "resource_ids_found": resource_ids_found,
                "sensitive_fields": sensitive,
            })
            edges[(producer, obj, "produces")] = {
                "source_principal": source_principal,
                "observation": "authenticated_endpoint_attempt",
            }
            edges[(obj, consumer, "consumed_by")] = {
                "observation": "authenticated_endpoint_attempt",
            }
        edges[(producer, consumer, "auth_boundary")] = {
            "object_id_key": object_id_key,
            "source_principal": source_principal,
            "excluded_principal": attacker_principal,
            "sensitive_fields": sensitive,
            "owner_status": owner_status,
            "attacker_status": attacker_status,
            "proof_type": attempt.get("proof_type"),
            "observation": "two_principal_route_comparison",
        }

    disc = result.get("discovery") if isinstance(result.get("discovery"), dict) else {}
    for ep in (disc.get("browser_api_endpoints") or [])[:500]:
        url = ep.get("url") if isinstance(ep, dict) else ep
        add_route(url, {"discovered": True})

    return nodes, edges


async def persist_application_graph(target_id: str, scan_id: str, result: dict) -> dict:
    """Best-effort: persist the application graph for a scan. Never raises (a graph
    write must not fail the scan)."""
    try:
        nodes, edges = build_application_graph(result)
        if not nodes:
            return {}
        tgt = uuid.UUID(target_id)
        sid = uuid.UUID(scan_id)
        async with db_pool.acquire() as conn:
            for key, n in nodes.items():
                await conn.execute("""
                    INSERT INTO application_graph_nodes
                        (target_id, node_type, node_key, label, attributes, scan_id, last_seen_at)
                    VALUES ($1,$2,$3,$4,$5,$6,NOW())
                    ON CONFLICT (target_id, node_type, node_key) DO UPDATE SET
                        label=EXCLUDED.label, attributes=EXCLUDED.attributes,
                        scan_id=EXCLUDED.scan_id, last_seen_at=NOW()
                """, tgt, n["node_type"], key, n["label"], json.dumps(n["attributes"]), sid)
            for (src, dst, etype), attrs in edges.items():
                await conn.execute("""
                    INSERT INTO application_graph_edges
                        (target_id, src_key, dst_key, edge_type, attributes, scan_id, last_seen_at)
                    VALUES ($1,$2,$3,$4,$5,$6,NOW())
                    ON CONFLICT (target_id, src_key, dst_key, edge_type) DO UPDATE SET
                        attributes=EXCLUDED.attributes, scan_id=EXCLUDED.scan_id, last_seen_at=NOW()
                """, tgt, src, dst, etype, json.dumps(attrs), sid)
        return {"nodes": len(nodes), "edges": len(edges)}
    except Exception as e:
        print(f"[graph] persist failed: {type(e).__name__}: {e}", flush=True)
        return {}


async def save_findings(scan_id: str, target_id: str, findings: list) -> int:
    """Save findings to database with deduplication. Returns count of saved findings."""
    if not findings:
        return 0

    saved = 0
    target_uuid = uuid.UUID(target_id)
    scan_uuid = uuid.UUID(scan_id)

    async with db_pool.acquire() as conn:
        for finding in findings:
            # PostgreSQL cannot store NUL bytes; strip them from every string field
            # before any INSERT/UPDATE so binary/bypass content can't crash persistence.
            finding = _strip_null_bytes(finding)
            fingerprint = generate_finding_fingerprint(finding)
            evidence_with_triage = _redact_finding_evidence(_build_evidence_with_triage(finding))
            evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
            ai_recommendations_json = json.dumps(finding.get('ai_recommendations')) if finding.get('ai_recommendations') else None
            ai_classification_source = finding.get('ai_classification_source')
            finding_tool = finding.get('tool')
            finding_source = finding.get('source') or ('model_intake' if finding_tool == 'model_intake' else None)
            scan_verification_status, scan_verification_verdict, scan_verification_confidence = _scan_time_verification_fields(finding)
            evidence_finding_id = None

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
                    evidence_finding_id = existing['id']
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
                        evidence_finding_id = result

            # Persist evidence as a first-class durable object — dedented to the loop
            # body so it runs AFTER the per-finding transaction commits. A Postgres
            # error inside a transaction poisons it even when caught, so the evidence
            # write must be outside (and best-effort) to never roll the finding back.
            await _persist_evidence_object(conn, scan_uuid, evidence_finding_id, finding, evidence_with_triage)

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
            evidence_with_triage = _redact_finding_evidence(_build_evidence_with_triage(finding))
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
                await _persist_evidence_object(conn, scan_uuid, existing['id'], finding,
                                               evidence_with_triage, tool_override='ai_gate')
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
                await _persist_evidence_object(conn, scan_uuid, result, finding,
                                               evidence_with_triage, tool_override='ai_gate')

    return saved


async def save_device_findings(
    scan_id: str,
    device_target_id: str,
    findings: list,
    *,
    resolve_posture_missing: bool = False,
    resolve_web_missing: bool = False,
) -> int:
    """Persist findings in the device namespace without touching Web DAST targets."""
    scan_uuid = uuid.UUID(scan_id)
    device_uuid = uuid.UUID(device_target_id)
    saved = 0
    seen_posture_fingerprints: list[str] = []
    seen_web_fingerprints: list[str] = []
    async with db_pool.acquire() as conn, conn.transaction():
        for finding in findings:
            fingerprint = str(finding.get("fingerprint") or generate_finding_fingerprint(finding))
            if str(finding.get("tool") or "") in {"device_policy", "device_ssh", "device_posture"}:
                seen_posture_fingerprints.append(fingerprint)
            else:
                seen_web_fingerprints.append(fingerprint)
            evidence_with_triage = _redact_finding_evidence(_build_evidence_with_triage(finding))
            evidence_json = json.dumps(evidence_with_triage) if evidence_with_triage else None
            recommendations = finding.get("ai_recommendations") or finding.get("recommendations")
            recommendation_json = json.dumps(recommendations) if recommendations else None
            finding_id = await conn.fetchval(
                """
                INSERT INTO findings (
                    scan_id, target_id, ai_target_id, device_target_id, fingerprint,
                    title, description, severity, cvss_score, tool, cwe, cwe_name,
                    owasp, url, evidence, ai_verdict, ai_confidence, ai_rationale,
                    ai_recommendations, ai_classification_source, source
                ) VALUES ($1,NULL,NULL,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'device')
                ON CONFLICT (device_target_id, fingerprint) WHERE device_target_id IS NOT NULL
                DO UPDATE SET
                    status=CASE WHEN findings.status='resolved' THEN 'active' ELSE findings.status END,
                    resolved_at=CASE WHEN findings.status='resolved' THEN NULL ELSE findings.resolved_at END,
                    resurfaced_count=findings.resurfaced_count + CASE WHEN findings.status='resolved' THEN 1 ELSE 0 END,
                    last_seen_at=NOW(), scan_id=EXCLUDED.scan_id, title=EXCLUDED.title,
                    description=EXCLUDED.description, severity=EXCLUDED.severity,
                    cvss_score=EXCLUDED.cvss_score, tool=EXCLUDED.tool, cwe=EXCLUDED.cwe,
                    cwe_name=EXCLUDED.cwe_name, owasp=EXCLUDED.owasp, url=EXCLUDED.url,
                    evidence=EXCLUDED.evidence, ai_verdict=EXCLUDED.ai_verdict,
                    ai_confidence=EXCLUDED.ai_confidence, ai_rationale=EXCLUDED.ai_rationale,
                    ai_recommendations=EXCLUDED.ai_recommendations,
                    ai_classification_source=EXCLUDED.ai_classification_source,
                    source='device', updated_at=NOW()
                RETURNING id
                """,
                scan_uuid, device_uuid, fingerprint,
                finding.get("title"), finding.get("description"), finding.get("severity", "info"),
                finding.get("cvss_score"), finding.get("tool") or "device_posture", finding.get("cwe"),
                finding.get("cwe_name"), finding.get("owasp"), finding.get("url"), evidence_json,
                finding.get("ai_verdict"), finding.get("ai_confidence"), finding.get("ai_rationale"),
                recommendation_json, finding.get("ai_classification_source"),
            )
            if finding_id:
                saved += 1
                await _persist_evidence_object(
                    conn, scan_uuid, finding_id, finding, evidence_with_triage,
                    tool_override=finding.get("tool") or "device_posture",
                )
                candidate_id = str(
                    (finding.get("evidence") or {}).get("candidate_id")
                    if isinstance(finding.get("evidence"), dict) else ""
                ).strip()
                proof = finding.get("proof_contract_v2") if isinstance(finding.get("proof_contract_v2"), dict) else {}
                if candidate_id and proof and str(finding.get("tool") or "") == "device_candidate_verifier":
                    try:
                        candidate_uuid = uuid.UUID(candidate_id)
                    except ValueError:
                        candidate_uuid = None
                    if candidate_uuid:
                        verification_id = await conn.fetchval(
                            """INSERT INTO finding_verifications (
                                   finding_id, candidate_id, scan_id, device_target_id,
                                   requested_by, status, result_status, verdict, verdict_reason,
                                   finding_type, target_url, original_url, proof, confidence,
                                   verification_mode, contract_id, contract_version, proof_basis,
                                   started_at, completed_at, updated_at
                               ) VALUES (
                                   $1,$2,$3,$4,'device_candidate_verifier','completed','success',
                                   'verified','Server-owned proof contract satisfied',
                                   $10,$5,$5,$6::jsonb,1.00,
                                   'deterministic',$7,$8,$9,NOW(),NOW(),NOW()
                               ) RETURNING id""",
                            finding_id, candidate_uuid, scan_uuid, device_uuid,
                            str(finding.get("url") or f"device://{device_target_id}"),
                            json.dumps(proof), proof.get("contract_id"), proof.get("contract_version"),
                            proof.get("proof_basis"), str(proof.get("family") or "device_candidate"),
                        )
                        proof_hash = hashlib.sha256(
                            json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()
                        ).hexdigest()
                        await conn.execute(
                            """INSERT INTO evidence_instances (
                                   finding_id, candidate_id, scan_id, device_target_id,
                                   proof_observation, hash, proof_state, evidence_strength,
                                   contract_id, contract_version, proof_basis, created_by
                               ) VALUES (
                                   $1,$2,$3,$4,$5::jsonb,$6,'verified','reproduced',$7,$8,$9,
                                   'device_candidate_verifier'
                               )""",
                            finding_id, candidate_uuid, scan_uuid, device_uuid, json.dumps(proof),
                            proof_hash, proof.get("contract_id"), proof.get("contract_version"),
                            proof.get("proof_basis"),
                        )
                        await conn.execute(
                            """UPDATE investigation_candidates
                               SET status='verified', latest_verification_id=$2,
                                   verification_context=verification_context ||
                                       jsonb_build_object('finding_id',$3::text),
                                   updated_at=NOW()
                               WHERE id=$1 AND plane='device' AND device_target_id=$4""",
                            candidate_uuid, verification_id, str(finding_id), device_uuid,
                        )
                        await conn.execute(
                            """UPDATE findings
                               SET last_verification_status='completed',
                                   last_verification_verdict='verified', updated_at=NOW()
                               WHERE id=$1""",
                            finding_id,
                        )
        if resolve_posture_missing:
            await conn.execute(
                """
                UPDATE findings
                SET status='resolved', resolved_at=NOW(), updated_at=NOW()
                WHERE device_target_id=$1 AND source='device' AND status='active'
                  AND tool IN ('device_policy','device_ssh','device_posture')
                  AND NOT (fingerprint = ANY($2::text[]))
                """,
                device_uuid,
                seen_posture_fingerprints,
            )
        if resolve_web_missing:
            await conn.execute(
                """
                UPDATE findings
                SET status='resolved', resolved_at=NOW(), updated_at=NOW()
                WHERE device_target_id=$1 AND source='device' AND status='active'
                  AND tool NOT IN ('device_policy','device_ssh','device_posture')
                  AND NOT (fingerprint = ANY($2::text[]))
                """,
                device_uuid,
                seen_web_fingerprints,
            )
    return saved


async def prepare_device_candidate_probe_result(
    *, result: dict[str, Any], options: dict[str, Any], device_target_id: str, target: str,
) -> dict[str, Any] | None:
    """Evaluate a device service candidate through a server-owned proof contract.

    The candidate's title, severity, and rationale are not used as proof. A verified finding is
    materialized only from the typed probe result plus the persisted device policy disposition.
    """
    candidate_id = str((options or {}).get("candidate_id") or "").strip()
    if not candidate_id or str((options or {}).get("proof_contract_id") or "") != "device.service_exposure":
        return None
    try:
        candidate_uuid = uuid.UUID(candidate_id)
        device_uuid = uuid.UUID(device_target_id)
    except ValueError:
        return None
    probe = result.get("device_probe") if isinstance(result.get("device_probe"), dict) else {}
    observation = probe.get("observation") if isinstance(probe.get("observation"), dict) else {}
    verification = probe.get("verification") if isinstance(probe.get("verification"), dict) else {}
    safety = probe.get("safety") if isinstance(probe.get("safety"), dict) else {}
    transport = str(probe.get("transport") or "").lower()
    try:
        port = int(probe.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    async with db_pool.acquire() as conn:
        candidate = await conn.fetchrow(
            """SELECT id, canonical_locus, verifier_contract_id
               FROM investigation_candidates
               WHERE id=$1 AND plane='device' AND device_target_id=$2""",
            candidate_uuid, device_uuid,
        )
        service = await conn.fetchrow(
            """SELECT state, service_name, product, version, cpe,
                      policy_disposition, policy_reason
               FROM device_services
               WHERE device_target_id=$1 AND transport=$2 AND port=$3""",
            device_uuid, transport, port,
        )
    if not candidate or str(candidate["verifier_contract_id"] or "") != "device.service_exposure":
        return None
    locus = parse_json_field(candidate["canonical_locus"]) or {}
    locus_matches = str(locus.get("transport") or "").lower() == transport and int(locus.get("port") or 0) == port
    policy_disposition = str(service["policy_disposition"] or "") if service else ""
    protocol_handshake = bool(
        locus_matches
        and observation.get("complete") is True
        and str(observation.get("state") or "") == "open"
        and str(verification.get("verdict") or "") == "satisfied"
    )
    evidence = {
        "protocol_handshake": protocol_handshake,
        "policy_denied": policy_disposition == "deny",
        "recent_observation": bool(probe),
        "service_closed": str(observation.get("state") or "") == "closed",
        "policy_allowed": policy_disposition == "allow",
        "health_degraded": bool(safety.get("halted")),
        "reexecuted_at_handoff": bool(probe),
    }
    proof = family_proof.build_proof_contract_result(
        "device_service_exposure",
        evidence,
        contract_id="device.service_exposure",
        contract_version="1.0.0",
        verifier_build=str(_worker_build_fingerprint() or "unknown"),
        subject={
            "device_target_id": device_target_id,
            "transport": transport,
            "port": port,
        },
        observations=[{
            "state": observation.get("state"),
            "complete": observation.get("complete"),
            "service_name": service["service_name"] if service else None,
            "policy_disposition": policy_disposition or None,
        }],
        controls=[{
            "health_halted": bool(safety.get("halted")),
            "locus_matches": locus_matches,
        }],
        proof_basis="protocol_handshake",
    )
    promotable, gate_reason = family_proof.proof_contract_promotion_gate(proof)
    settlement = {
        "candidate_id": candidate_id,
        "status": "verified" if promotable else (
            "refuted" if proof["verdict"] == "refuted" else "inconclusive"
        ),
        "proof": proof,
        "gate_reason": gate_reason,
    }
    result["candidate_verification"] = settlement
    if promotable:
        title = "Policy-denied connected-device service is exposed"
        finding = {
            "type": "Device service policy violation",
            "title": title,
            "severity": "high",
            "description": (
                f"A deterministic {transport.upper()} probe confirmed port {port} open, and the "
                "effective connected-device policy denies that service."
            ),
            "recommendation": "Disable the service or restrict it to the explicitly approved management segment.",
            "url": f"{transport}://{target}:{port}",
            "tool": "device_candidate_verifier",
            "source": "device",
            "cwe": "CWE-284",
            "verified": True,
            "proof_state": "verified",
            "proof_contract_v2": proof,
            "evidence": {
                "candidate_id": candidate_id,
                "transport": transport,
                "port": port,
                "observed_state": observation.get("state"),
                "policy_disposition": policy_disposition,
                "policy_reason": str(service["policy_reason"] or "")[:1000] if service else None,
                "proof_contract_v2": proof,
            },
        }
        finding["fingerprint"] = hashlib.sha256(
            json.dumps([title, device_target_id, transport, port], separators=(",", ":")).encode()
        ).hexdigest()
        result.setdefault("findings", []).append(finding)
    return settlement


async def prepare_device_candidate_posture_result(
    *, result: dict[str, Any], options: dict[str, Any], device_target_id: str, target: str,
) -> dict[str, Any] | None:
    """Evaluate TLS, imported-request auth, or SSH candidates from one fresh posture run."""
    candidate_id = str((options or {}).get("candidate_id") or "").strip()
    contract_id = str((options or {}).get("proof_contract_id") or "").strip()
    contract_families = {
        "device.tls": "device_tls",
        "device.auth_bypass": "device_auth_bypass",
        "device.ssh_posture": "device_ssh_posture",
    }
    family = contract_families.get(contract_id)
    if not candidate_id or not family:
        return None
    try:
        candidate_uuid = uuid.UUID(candidate_id)
        device_uuid = uuid.UUID(device_target_id)
    except ValueError:
        return None
    async with db_pool.acquire() as conn:
        candidate = await conn.fetchrow(
            """SELECT canonical_locus, verifier_contract_id
               FROM investigation_candidates
               WHERE id=$1 AND plane='device' AND device_target_id=$2""",
            candidate_uuid, device_uuid,
        )
    if not candidate or str(candidate["verifier_contract_id"] or "") != contract_id:
        return None
    locus = parse_json_field(candidate["canonical_locus"]) or {}
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    observations: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {"reexecuted_at_handoff": True}
    subject: dict[str, Any] = {"device_target_id": device_target_id}
    title = "Connected-device candidate was deterministically verified"
    description = "A fresh connected-device posture run satisfied the registered proof contract."
    severity = "medium"
    recommendation = "Review and remediate the verified connected-device control failure."
    url = f"device://{device_target_id}"
    proof_basis = "device_posture_observation"

    if family == "device_tls":
        children = ((posture.get("web_dast_children") or {}).get("children") or [])
        expected_port = int(locus.get("port") or 0)
        expected_scheme = str(locus.get("scheme") or "https").lower()
        selected = None
        for child in children:
            if not isinstance(child, dict):
                continue
            parsed = urllib.parse.urlsplit(str(child.get("origin") or ""))
            child_port = int(parsed.port or (443 if parsed.scheme == "https" else 80))
            if parsed.scheme == expected_scheme and (not expected_port or child_port == expected_port):
                selected = child
                break
        assessment = selected.get("tls_assessment") if isinstance(selected, dict) and isinstance(selected.get("tls_assessment"), dict) else {}
        origin = str((selected or {}).get("origin") or "")
        evidence.update({
            "strict_handshake_failed": bool(assessment) and assessment.get("trusted") is False,
            "endpoint_identity_bound": bool(selected and origin),
            "recent_observation": bool(selected),
            "strict_handshake_succeeded": assessment.get("trusted") is True,
        })
        subject.update({"origin": origin or None, "port": expected_port or None})
        observations.append({"origin": origin or None, **assessment})
        controls.append({"locus_matches": bool(selected), "pinned_destination": True})
        title = "Device HTTPS identity verification failed"
        description = "A fresh strict TLS handshake failed for the exact device HTTPS origin."
        recommendation = "Install or pin a certificate trusted for the device hostname."
        url = origin or url
        proof_basis = "strict_tls_handshake"
    elif family == "device_auth_bypass":
        collection_id = str(locus.get("collection_id") or "")
        request_id = str(locus.get("request_id") or "")
        selected_finding = None
        for finding in result.get("findings") or []:
            if not isinstance(finding, dict) or str(finding.get("tool") or "") != "device_request_dast":
                continue
            finding_evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            if collection_id and str(finding_evidence.get("collection_id") or "") != collection_id:
                continue
            if request_id and str(finding_evidence.get("request_id") or "") != request_id:
                continue
            if finding_evidence.get("response_match") is True:
                selected_finding = finding
                break
        auth_evidence = selected_finding.get("evidence") if isinstance(selected_finding, dict) and isinstance(selected_finding.get("evidence"), dict) else {}
        evidence.update({
            "protected_resource_established": bool(
                selected_finding
                and 200 <= int(auth_evidence.get("authenticated_status") or 0) < 300
                and collection_id
                and request_id
            ),
            "anonymous_semantic_equivalence": bool(
                auth_evidence.get("response_match")
                and auth_evidence.get("authenticated_body_sha256")
                == auth_evidence.get("anonymous_body_sha256")
            ),
            "negative_control": bool(auth_evidence.get("negative_control_differs")),
            "anonymous_access_denied": int(auth_evidence.get("anonymous_status") or 0) in {401, 403},
            "generic_response_shell": bool(auth_evidence.get("generic_response_shell")),
        })
        url = str((selected_finding or {}).get("url") or url)
        subject.update({"collection_id": collection_id or None, "request_id": request_id or None, "url": url})
        observations.append({key: auth_evidence.get(key) for key in (
            "authenticated_status", "anonymous_status", "response_match",
            "negative_control_status", "negative_control_differs",
        )})
        controls.append({"exact_collection_bound": bool(collection_id), "exact_request_bound": bool(request_id)})
        title = "Device API authentication bypass reproduced"
        description = "A bound imported authenticated request returned the same semantic response anonymously, while a negative route control differed."
        recommendation = "Require authentication and authorization for the exact device API operation."
        proof_basis = "authenticated_anonymous_negative_control"
    else:
        expected_port = int(locus.get("port") or 0)
        service = next((
            item for item in posture.get("services") or []
            if isinstance(item, dict)
            and str(item.get("transport") or "") == "tcp"
            and int(item.get("port") or 0) == expected_port
        ), None)
        ssh = service.get("ssh") if isinstance(service, dict) and isinstance(service.get("ssh"), dict) else {}
        host_key = ssh.get("host_key") if isinstance(ssh.get("host_key"), dict) else {}
        actual_key = str(host_key.get("fingerprint_sha256") or "")
        expected_key = str(
            (options.get("expected_ssh_host_keys") or {}).get(str(expected_port)) or ""
        )
        weak_algorithms = list(ssh.get("weak_algorithms") or [])
        policy_disposition = str((service or {}).get("policy_disposition") or "")
        policy_reason = str((service or {}).get("policy_reason") or "")
        violation = bool(
            policy_disposition == "deny"
            or (policy_disposition == "require" and weak_algorithms)
            or (weak_algorithms and "weak" in policy_reason.lower())
        )
        evidence.update({
            "pinned_host_key": bool(expected_key and actual_key == expected_key),
            "negotiated_posture": bool(ssh.get("scan_completed") and ssh.get("negotiated_algorithms")),
            "policy_violation": violation,
            "policy_requirements_satisfied": bool(ssh.get("scan_completed") and not violation),
            "host_key_changed": bool(expected_key and actual_key and actual_key != expected_key),
        })
        subject.update({"transport": "tcp", "port": expected_port, "host_key_fingerprint": actual_key or None})
        observations.append({
            "host_key_fingerprint": actual_key or None,
            "negotiated_algorithms": ssh.get("negotiated_algorithms") or {},
            "weak_algorithms": weak_algorithms,
            "policy_disposition": policy_disposition or None,
        })
        controls.append({"expected_host_key_fingerprint": expected_key or None, "policy_reason": policy_reason[:500]})
        title = "Device SSH cryptographic posture violates policy"
        description = "A fresh, host-key-pinned SSH negotiation reproduced a policy violation."
        recommendation = "Disable the policy-violating SSH algorithms and preserve the pinned host identity."
        url = f"ssh://{target}:{expected_port}"
        proof_basis = "pinned_ssh_negotiation"

    proof = family_proof.build_proof_contract_result(
        family,
        evidence,
        contract_id=contract_id,
        contract_version="1.0.0",
        verifier_build=str(_worker_build_fingerprint() or "unknown"),
        subject=subject,
        observations=observations,
        controls=controls,
        proof_basis=proof_basis,
    )
    promotable, gate_reason = family_proof.proof_contract_promotion_gate(proof)
    settlement = {
        "candidate_id": candidate_id,
        "status": "verified" if promotable else (
            "refuted" if proof["verdict"] == "refuted" else "inconclusive"
        ),
        "proof": proof,
        "gate_reason": gate_reason,
    }
    result["candidate_verification"] = settlement
    if promotable:
        finding = {
            "type": title,
            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "url": url,
            "tool": "device_candidate_verifier",
            "source": "device",
            "cwe": family_proof.FAMILY_CONTRACTS[family]["cwe"],
            "verified": True,
            "proof_state": "verified",
            "proof_contract_v2": proof,
            "evidence": {"candidate_id": candidate_id, "proof_contract_v2": proof},
        }
        finding["fingerprint"] = hashlib.sha256(
            json.dumps([title, device_target_id, subject], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result.setdefault("findings", []).append(finding)
    return settlement


async def persist_device_candidate_settlement(
    conn: Any,
    *,
    scan_id: str,
    device_target_id: str,
    settlement: dict[str, Any],
) -> uuid.UUID | None:
    """Persist every non-promoted device verifier outcome, including refutation and faults.

    Promoted outcomes are finalized by ``save_device_findings`` so their verification and evidence
    can reference the newly materialized finding. Everything else still gets a durable verification
    record and, when present, an immutable proof observation.
    """
    candidate_text = str(settlement.get("candidate_id") or "").strip()
    if not candidate_text:
        return None
    try:
        candidate_id = uuid.UUID(candidate_text)
        device_id = uuid.UUID(device_target_id)
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return None
    status = str(settlement.get("status") or "inconclusive")
    if status == "verified":
        await conn.execute(
            """UPDATE investigation_candidates
               SET status='verifying', verification_context=verification_context ||
                   jsonb_build_object('scan_id',$2::text,'proof',$3::jsonb,'gate_reason',$4::text),
                   updated_at=NOW()
               WHERE id=$1 AND status IN ('verification_queued','verifying','inconclusive')""",
            candidate_id, str(scan_uuid), json.dumps(settlement.get("proof") or {}),
            settlement.get("gate_reason"),
        )
        return None
    proof = settlement.get("proof") if isinstance(settlement.get("proof"), dict) else {}
    contract_id = str(
        proof.get("contract_id") or settlement.get("proof_contract_id") or "device.unknown"
    )
    verdict = str(proof.get("verdict") or status)
    result_status = "refuted" if status == "refuted" else "inconclusive"
    verification_id = await conn.fetchval(
        """INSERT INTO finding_verifications (
               finding_id, candidate_id, scan_id, device_target_id, requested_by,
               status, result_status, verdict, verdict_reason, finding_type,
               target_url, original_url, proof, verification_mode, contract_id,
               contract_version, proof_basis, started_at, completed_at, updated_at
           ) VALUES (
               NULL,$1,$2,$3,'device_candidate_verifier','completed',$4,$5,$6,$7,$8,$8,
               $9::jsonb,'deterministic',$10,$11,$12,NOW(),NOW(),NOW()
           ) RETURNING id""",
        candidate_id, scan_uuid, device_id, result_status, verdict,
        str(settlement.get("gate_reason") or settlement.get("error") or "Verifier did not promote")[:1000],
        str(proof.get("family") or "device_candidate"), f"device://{device_target_id}",
        json.dumps(proof), contract_id,
        str(proof.get("contract_version") or "1.0.0"),
        str(proof.get("proof_basis") or "device_verifier_outcome"),
    )
    if proof:
        proof_hash = hashlib.sha256(
            json.dumps(proof, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()
        await conn.execute(
            """INSERT INTO evidence_instances (
                   candidate_id, scan_id, device_target_id, proof_observation, hash,
                   proof_state, evidence_strength, contract_id, contract_version,
                   proof_basis, created_by
               ) VALUES ($1,$2,$3,$4::jsonb,$5,$6,'signal',$7,$8,$9,
                         'device_candidate_verifier')""",
            candidate_id, scan_uuid, device_id, json.dumps(proof), proof_hash,
            status if status in {"refuted", "inconclusive"} else "inconclusive",
            contract_id, str(proof.get("contract_version") or "1.0.0"),
            str(proof.get("proof_basis") or "device_verifier_outcome"),
        )
    await conn.execute(
        """UPDATE investigation_candidates
           SET status=$2, latest_verification_id=$3,
               verification_context=verification_context || jsonb_build_object(
                   'scan_id',$4::text,'proof',$5::jsonb,'gate_reason',$6::text
               ), updated_at=NOW()
           WHERE id=$1""",
        candidate_id,
        status if status in {"refuted", "inconclusive", "blocked"} else "inconclusive",
        verification_id, str(scan_uuid), json.dumps(proof),
        settlement.get("gate_reason") or settlement.get("error"),
    )
    return verification_id


def _authenticated_device_package_identities(posture: dict[str, Any]) -> list[dict[str, Any]]:
    """Build authoritative identity records from any credentialed SSH package inventory.

    These are synthetic, service-shaped identities the advisory correlator can iterate
    alongside network-fingerprinted services. They are never persisted into the device
    service inventory; they exist only to make an advisory match from authenticated
    package evidence reachable (the authoritative tier that promotion requires).
    """
    identities: list[dict[str, Any]] = []
    for service in posture.get("services") or []:
        if not isinstance(service, dict):
            continue
        ssh = service.get("ssh") if isinstance(service.get("ssh"), dict) else {}
        host_review = ssh.get("host_review") if isinstance(ssh.get("host_review"), dict) else {}
        if not host_review:
            continue
        for record in device_advisories.parse_authenticated_package_inventory(host_review):
            identities.append({
                "transport": "authenticated_package",
                "port": 0,
                "service_name": record["package"],
                "product": record["product"],
                "version": record["version"],
                "cpe": record["cpe"],
                "identity_evidence_tier": record["identity_evidence_tier"],
                "_advisory_identity_source": "authenticated_package",
            })
    return identities


async def correlate_device_advisory_lifecycle(
    *, result: dict[str, Any], device_target_id: str,
) -> dict[str, Any]:
    """Create advisory candidates on every posture scan and promote exact pinned matches only."""
    snapshot = device_advisories.load_verified_snapshot(
        os.environ.get("DEVICE_INTEL_DB_PATH"),
        os.environ.get("DEVICE_INTEL_DB_SHA256"),
    )
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    summary = {
        "status": snapshot.get("status"),
        "snapshot_sha256": snapshot.get("snapshot_sha256"),
        "snapshot_generated_at": snapshot.get("generated_at"),
        "services_evaluated": 0,
        "candidates": 0,
        "exact_matches": 0,
        "resolved_stale_matches": 0,
        "runtime_egress": False,
    }
    posture["advisory_correlation"] = summary
    result["device_posture"] = posture
    if snapshot.get("status") != "available":
        return summary
    records = snapshot.get("advisories") or []
    device_uuid = uuid.UUID(device_target_id)
    findings = result.setdefault("findings", [])
    evaluated_loci: set[tuple[str, int]] = set()
    current_candidate_ids: set[uuid.UUID] = set()
    summary["authenticated_packages_evaluated"] = 0
    identity_sources = list(posture.get("services") or []) + _authenticated_device_package_identities(posture)
    async with db_pool.acquire() as conn:
        for service in identity_sources:
            if not isinstance(service, dict):
                continue
            cpe = str(service.get("cpe") or "").strip()
            product = str(service.get("product") or service.get("service_name") or "").strip()
            version = str(service.get("version") or "").strip()
            if not cpe and not product:
                continue
            identity_provenance = device_advisories.identity_evidence_tier(service)
            try:
                evaluated_loci.add((
                    str(service.get("transport") or "tcp").lower(),
                    int(service.get("port") or 0),
                ))
            except (TypeError, ValueError):
                continue
            summary["services_evaluated"] += 1
            if service.get("_advisory_identity_source") == "authenticated_package":
                summary["authenticated_packages_evaluated"] += 1
            matches = device_advisories.match_advisories(
                records, cpe=cpe or None, product=product or None, version=version or None,
                identity_evidence_tier=identity_provenance["tier"],
                limit=50,
            )
            for match in matches:
                advisory_id = str(match.get("advisory_id") or "unknown")
                candidate = investigation_candidates.normalize_candidate(
                    plane="device",
                    device_target_id=device_target_id,
                    family="device_firmware_advisory",
                    locus={
                        "transport": service.get("transport"),
                        "port": service.get("port"),
                        "service_name": service.get("service_name"),
                        "advisory_id": advisory_id,
                        "cpe": cpe,
                        "version": version,
                    },
                    title=str(match.get("title") or advisory_id or "Firmware advisory candidate"),
                    claim=(
                        f"Offline advisory {advisory_id} matched {cpe or product} "
                        f"version {version or 'unknown'}."
                    ),
                    severity=str(match.get("severity") or "info").lower(),
                    evidence_refs=[],
                    source_kind="automatic_device_advisory_correlation",
                )
                advisory_context = {
                    "snapshot_sha256": str(snapshot.get("snapshot_sha256") or ""),
                    "advisory": match,
                    "service": {
                        "transport": service.get("transport"), "port": service.get("port"),
                        "service_name": service.get("service_name"), "product": product,
                        "version": version, "cpe": cpe,
                        "identity_evidence_tier": identity_provenance["tier"],
                        "authoritative_product_identity": identity_provenance["authoritative"],
                    },
                }
                candidate_record = await investigation_candidates.upsert_candidate(
                    conn, candidate, created_by="device_advisory_correlation",
                    observation_context=advisory_context,
                )
                current_candidate_ids.add(uuid.UUID(candidate_record["id"]))
                summary["candidates"] += 1
                await conn.execute(
                    """UPDATE investigation_candidates
                       SET verification_context=verification_context || jsonb_build_object(
                           'snapshot_sha256',$2::text,'advisory',$3::jsonb,
                           'service',$4::jsonb
                       ), updated_at=NOW()
                       WHERE id=$1 AND status NOT IN ('verified','refuted','expired')""",
                    uuid.UUID(candidate_record["id"]),
                    str(snapshot.get("snapshot_sha256") or ""),
                    json.dumps(match),
                    json.dumps(advisory_context["service"]),
                )
                if not match.get("promotable"):
                    continue
                proof = family_proof.build_proof_contract_result(
                    "device_firmware_advisory",
                    {
                        "exact_product_identity": bool(cpe and match.get("match_type") == "exact_cpe_version_range"),
                        "authoritative_product_identity": identity_provenance["authoritative"],
                        "version_in_affected_range": match.get("version_evaluation") == "affected",
                        "advisory_snapshot_verified": True,
                        "version_outside_affected_range": False,
                        "heuristic_product_match": match.get("match_type") == "heuristic_product",
                        # The current scan is fresh, but only authoritative inventory can satisfy
                        # the product-identity reproduction required for a verified advisory.
                        "reexecuted_at_handoff": identity_provenance["authoritative"],
                    },
                    contract_id="device.firmware_advisory",
                    contract_version="1.0.0",
                    verifier_build=str(_worker_build_fingerprint() or "unknown"),
                    subject={
                        "device_target_id": device_target_id,
                        "advisory_id": advisory_id,
                        "cpe": cpe,
                        "version": version,
                        "transport": str(service.get("transport") or "tcp"),
                        "port": int(service.get("port") or 0),
                    },
                    observations=[match],
                    controls=[{
                        "snapshot_sha256": snapshot.get("snapshot_sha256"),
                        "runtime_egress": False,
                        "identity_evidence_tier": identity_provenance["tier"],
                    }],
                    proof_basis="authoritative_inventory_plus_hash_pinned_offline_advisory",
                )
                promotable, _gate_reason = family_proof.proof_contract_promotion_gate(proof)
                if not promotable:
                    continue
                summary["exact_matches"] += 1
                severity = str(match.get("severity") or "medium").lower()
                if severity not in {"critical", "high", "medium", "low", "info"}:
                    severity = "medium"
                title = f"Affected connected-device software: {advisory_id}"
                finding = {
                    "type": "Device firmware advisory",
                    "title": title,
                    "severity": severity,
                    "description": (
                        f"The authoritatively observed software identity and version matched the affected range in the "
                        f"hash-pinned offline advisory snapshot for {advisory_id}."
                    ),
                    "recommendation": "Apply the vendor-fixed firmware or isolate the affected service until remediation.",
                    "url": str(match.get("reference") or f"device://{device_target_id}"),
                    "tool": "device_candidate_verifier",
                    "source": "device",
                    "cwe": "CWE-1104",
                    "verified": True,
                    "proof_state": "verified",
                    "proof_contract_v2": proof,
                    "evidence": {
                        "candidate_id": candidate_record["id"],
                        "advisory_id": advisory_id,
                        "snapshot_sha256": snapshot.get("snapshot_sha256"),
                        "proof_contract_v2": proof,
                    },
                }
                finding["fingerprint"] = hashlib.sha256(
                    f"device-advisory|{device_target_id}|{advisory_id}|{cpe}|{version}".encode()
                ).hexdigest()
                findings.append(finding)
        # Re-evaluate prior verified advisory candidates only when their exact service locus was
        # observed in this run. If the pinned snapshot no longer matches that observed service
        # (fixed version, withdrawn record, or changed identity), retire the candidate and resolve
        # its generated finding. An unscanned or silent port is never treated as remediation.
        prior_verified = await conn.fetch(
            """SELECT id, canonical_locus
               FROM investigation_candidates
               WHERE plane='device' AND device_target_id=$1
                 AND family='device_firmware_advisory' AND status='verified'""",
            device_uuid,
        )
        for prior in prior_verified:
            prior_id = prior["id"]
            if prior_id in current_candidate_ids:
                continue
            prior_locus = parse_json_field(prior["canonical_locus"]) or {}
            try:
                prior_key = (
                    str(prior_locus.get("transport") or "tcp").lower(),
                    int(prior_locus.get("port") or 0),
                )
            except (TypeError, ValueError):
                continue
            if prior_key not in evaluated_loci:
                continue
            await conn.execute(
                """UPDATE investigation_candidates
                   SET status='refuted', verification_context=verification_context ||
                       jsonb_build_object(
                           'lifecycle_reason','no_longer_matches_pinned_snapshot',
                           'snapshot_sha256',$2::text,
                           'reevaluated_at',NOW()::text
                       ), updated_at=NOW()
                   WHERE id=$1""",
                prior_id, str(snapshot.get("snapshot_sha256") or ""),
            )
            resolved = await conn.fetchval(
                """WITH changed AS (
                       UPDATE findings
                       SET status='resolved', resolved_at=NOW(), updated_at=NOW(),
                           notes=concat_ws(E'\n',NULLIF(notes,''),
                               'Resolved automatically: the observed service no longer matches the pinned advisory snapshot.')
                       WHERE device_target_id=$1 AND status='active'
                         AND evidence->>'candidate_id'=$2::text
                       RETURNING id
                   ) SELECT COUNT(*) FROM changed""",
                device_uuid, prior_id,
            )
            summary["resolved_stale_matches"] += int(resolved or 0)
    return summary


async def persist_device_inventory(scan_id: str, device_target_id: str, result: dict[str, Any]) -> None:
    """Upsert device identity, confirmed services, and inconclusive observations."""
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    identity = posture.get("identity") if isinstance(posture.get("identity"), dict) else {}
    services = posture.get("services") if isinstance(posture.get("services"), list) else []
    observations = (
        posture.get("inconclusive_observations")
        if isinstance(posture.get("inconclusive_observations"), list)
        else []
    )
    completeness = posture.get("completeness") if isinstance(posture.get("completeness"), dict) else {}
    device_uuid = uuid.UUID(device_target_id)
    scan_uuid = uuid.UUID(scan_id)
    addresses = [item for item in identity.get("addresses") or [] if isinstance(item, dict)]
    hostnames = [str(item) for item in identity.get("hostnames") or [] if str(item).strip()]
    mac = next((str(item.get("address")) for item in addresses if item.get("type") == "mac" and item.get("address")), None)
    vendor = next((str(item.get("vendor")) for item in addresses if item.get("vendor")), None)
    device_metadata = identity.get("device_metadata") if isinstance(identity.get("device_metadata"), dict) else {}
    descriptor_manufacturer = str(device_metadata.get("manufacturer") or "").strip() or None
    descriptor_model = str(device_metadata.get("model_name") or device_metadata.get("model_number") or "").strip() or None
    descriptor_udn = str(device_metadata.get("udn") or "").strip() or None
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            current = await conn.fetchrow("SELECT primary_locator, stable_identity FROM device_targets WHERE id=$1 FOR UPDATE", device_uuid)
            if not current:
                return
            locator = str(current["primary_locator"])
            locator_type = "hostname"
            try:
                ipaddress.ip_address(locator)
                locator_type = "ip"
            except ValueError:
                pass
            interface_id = await conn.fetchval(
                """
                INSERT INTO device_interfaces (
                    device_target_id, interface_type, locator_type, locator, mac_address, hostname, last_seen_at, metadata_json
                ) VALUES ($1,'network',$2,$3,$4,$5,NOW(),$6)
                ON CONFLICT (device_target_id, interface_type, locator_type, locator) DO UPDATE SET
                    mac_address=COALESCE(EXCLUDED.mac_address, device_interfaces.mac_address),
                    hostname=COALESCE(EXCLUDED.hostname, device_interfaces.hostname),
                    last_seen_at=NOW(), metadata_json=EXCLUDED.metadata_json
                RETURNING id
                """,
                device_uuid, locator_type, locator, mac, hostnames[0] if hostnames else None,
                json.dumps({"addresses": addresses, "os_matches": identity.get("os_matches") or []}),
            )
            if completeness.get("complete") and completeness.get("tcp_scope") == "all_65535":
                await conn.execute(
                    "UPDATE device_services SET state='not_observed' WHERE device_target_id=$1 AND transport='tcp'",
                    device_uuid,
                )
            udp_ports_requested = [int(port) for port in completeness.get("udp_ports_requested") or []]
            if completeness.get("udp_discovery_complete") and udp_ports_requested:
                await conn.execute(
                    """UPDATE device_services SET state='not_observed'
                       WHERE device_target_id=$1 AND transport='udp' AND port=ANY($2::integer[])""",
                    device_uuid,
                    udp_ports_requested,
                )
            for service in [*services, *observations]:
                if not isinstance(service, dict):
                    continue
                await conn.execute(
                    """
                    INSERT INTO device_services (
                        device_target_id, scan_id, interface_id, transport, port, state,
                        service_name, product, version, cpe, encrypted, web_origin,
                        policy_disposition, policy_reason, last_seen_at, metadata_json
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),$15)
                    ON CONFLICT (device_target_id, transport, port) DO UPDATE SET
                        scan_id=EXCLUDED.scan_id, interface_id=EXCLUDED.interface_id,
                        state=EXCLUDED.state, service_name=EXCLUDED.service_name,
                        product=EXCLUDED.product, version=EXCLUDED.version, cpe=EXCLUDED.cpe,
                        encrypted=EXCLUDED.encrypted, web_origin=EXCLUDED.web_origin,
                        policy_disposition=EXCLUDED.policy_disposition,
                        policy_reason=EXCLUDED.policy_reason, last_seen_at=NOW(),
                        metadata_json=EXCLUDED.metadata_json
                    """,
                    device_uuid, scan_uuid, interface_id, str(service.get("transport") or "tcp"),
                    int(service.get("port")), str(service.get("state") or "open"),
                    str(service.get("service_name") or "unknown"), service.get("product"),
                    service.get("version"), service.get("cpe"), service.get("encrypted"),
                    service.get("web_origin"), service.get("policy_disposition"),
                    service.get("policy_reason"), json.dumps({
                        key: value for key, value in service.items()
                        if key not in {"transport", "port", "state", "service_name", "product", "version", "cpe", "encrypted", "web_origin", "policy_disposition", "policy_reason"}
                    }),
                )
            stable_identity = current["stable_identity"] or (f"mac:{mac.lower()}" if mac else f"upnp:{descriptor_udn}" if descriptor_udn else None)
            identity_confidence = "high" if mac else "medium" if addresses else "low"
            await conn.execute(
                """UPDATE device_targets SET
                       stable_identity=COALESCE(stable_identity,$1),
                       identity_confidence=CASE
                           WHEN identity_confidence='verified' THEN identity_confidence
                           WHEN $2='high' THEN 'high'
                           WHEN identity_confidence='low' THEN $2
                           ELSE identity_confidence END,
                       manufacturer=COALESCE(manufacturer,$3),
                       model=COALESCE(model,$5), updated_at=NOW()
                   WHERE id=$4""",
                stable_identity, identity_confidence, descriptor_manufacturer or vendor, device_uuid, descriptor_model,
            )


def _hypothesis_dedupe_part(value: Any, *, lower: bool = False) -> str | None:
    if value is None:
        return None
    text = re.sub(r"\s+", " ", str(value).strip()).replace("|", "%7C")
    if not text:
        return None
    return text.lower().replace(" ", "_") if lower else text


def _product_signal_hypothesis_key(family: str, dimensions: dict[str, Any]) -> str:
    # scan_id is deliberately NOT part of the identity: the same unexplained finding from every
    # recurring scan must endorse/reopen the one canonical lead, not mint a scan-specific copy.
    # scan_id lives in the endorsement + dedupe_dimensions as provenance instead.
    ordered = (
        "product",
        "target_id",
        "ai_target_id",
        "artifact",
        "finding_id",
        "probe_family",
        "type",
    )
    parts = [f"family={family}"]
    for key in ordered:
        value = _hypothesis_dedupe_part(dimensions.get(key), lower=key in {"product", "probe_family", "type"})
        if value:
            parts.append(f"{key}={value}")
    return "hypothesis:v1|" + "|".join(parts)


def _severity_to_confidence(severity: Any, fallback: float = 0.62) -> float:
    rank = {"critical": 0.82, "high": 0.74, "medium": 0.62, "low": 0.45, "info": 0.35}
    return rank.get(str(severity or "").strip().lower(), fallback)


def _hypothesis_severity(value: Any, default: str = "medium") -> str:
    severity = str(value or "").strip().lower()
    return severity if severity in {"critical", "high", "medium", "low", "info"} else default


def _float_between_0_1(value: Any, fallback: float) -> float:
    try:
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return fallback


def _ai_gate_signal_hypotheses(
    scan_id: str,
    ai_target_id: str | None,
    result: dict[str, Any],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    hypotheses: list[dict[str, Any]] = []
    ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    for finding in findings[:50]:
        if not isinstance(finding, dict):
            continue
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        ai_verdict = str(finding.get("ai_verdict") or "").strip().lower()
        source = str(finding.get("ai_classification_source") or "").strip().lower()
        confidence = _float_between_0_1(
            finding.get("ai_confidence", finding.get("confidence")),
            _severity_to_confidence(finding.get("severity"), 0.6),
        )
        weak_or_semantic = (
            ai_verdict == "needs_review"
            or source == "semantic_judge"
            or isinstance(evidence.get("semantic_result"), dict)
            or bool(evidence.get("semantic_judge_error"))
            or confidence < 0.75
        )
        if not weak_or_semantic:
            continue
        finding_id = str(finding.get("id") or finding.get("title") or "").strip()
        probe_family = str(evidence.get("probe_family") or evidence.get("strategy_id") or finding.get("type") or "ai_gate").strip()
        family = f"ai_gate_{probe_family.lower().replace(' ', '_')}"[:80]
        dims = {
            "product": "ai_gate",
            "scan_id": scan_id,
            "ai_target_id": ai_target_id,
            "finding_id": finding_id,
            "probe_family": probe_family,
            "type": finding.get("type") or finding.get("category"),
        }
        hypotheses.append({
            "source": "ai_gate",
            "family": family or "ai_gate",
            "cwe": finding.get("cwe"),
            "title": f"AI Gate follow-up lead: {finding.get('title') or probe_family}",
            "description": (
                "AI Gate produced a semantic, needs-review, or lower-confidence signal. "
                "Treat it as a replayable hypothesis until focused AI Gate evidence confirms it."
            ),
            "severity_guess": _hypothesis_severity(finding.get("severity")),
            "confidence": confidence,
            "dedupe_key": _product_signal_hypothesis_key(family or "ai_gate", dims),
            "next_test_action": {
                "command": "ai_gate.replay_probe",
                "parameters": {
                    "scan_id": scan_id,
                    "ai_target_id": ai_target_id,
                    "source_finding_id": finding_id or None,
                    "probe_family": probe_family,
                },
            },
            "endorsement": {
                "source": "ai_gate",
                "scan_id": scan_id,
                "ai_target_id": ai_target_id,
                "finding_id": finding_id or None,
                "ai_verdict": ai_verdict or None,
                "ai_classification_source": source or None,
                "confidence": confidence,
            },
            "metadata_json": {
                "dedupe_dimensions": dims,
                "product": "ai_gate",
                "probe_pack": options.get("ai_probe_pack") or ai_gate.get("probe_pack"),
                "scan_profile": options.get("ai_scan_profile") or ai_gate.get("scan_profile"),
            },
            "created_by": "worker",
        })
    return hypotheses


MODEL_INTAKE_HYPOTHESIS_MARKERS = (
    "signature",
    "trust",
    "metadata",
    "governance",
    "approval",
    "license",
    "sbom",
    "malware",
    "eval",
    "provenance",
    "model_card",
)


SCANNER_SIGNAL_FAMILY_MARKERS = (
    ("bola", ("bola", "idor", "broken object", "object level", "cwe-639", "cwe-566")),
    ("auth", ("auth", "authorization", "authentication", "access control", "bfla", "bopla", "jwt", "cwe-287", "cwe-862", "cwe-863")),
    ("sqli", ("sqli", "sql injection", "nosql", "injection", "cwe-89", "cwe-943")),
    ("xss", ("xss", "cross-site scripting", "script injection", "cwe-79")),
    ("ssrf", ("ssrf", "server-side request", "cwe-918")),
    ("lfi", ("lfi", "rfi", "path traversal", "file inclusion", "directory traversal", "cwe-22", "cwe-98")),
    ("open_redirect", ("open redirect", "redirect", "cwe-601")),
)


def _scanner_signal_family(finding: dict[str, Any]) -> str:
    haystack = " ".join(
        str(finding.get(key) or "")
        for key in ("type", "category", "title", "description", "tool", "cwe", "cwe_name", "owasp")
    ).lower()
    for family, markers in SCANNER_SIGNAL_FAMILY_MARKERS:
        if any(marker in haystack for marker in markers):
            return family
    raw = str(finding.get("type") or finding.get("category") or finding.get("tool") or "scanner").strip().lower()
    family = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    return family[:80] or "scanner"


def _scanner_finding_is_verified(finding: dict[str, Any]) -> bool:
    try:
        _status, verdict, _confidence = _scan_time_verification_fields(finding)
    except Exception:
        verdict = None
    explicit = str(
        finding.get("proof_state")
        or finding.get("verification_verdict")
        or finding.get("last_verification_verdict")
        or ""
    ).strip().lower()
    return verdict == "exploited" or explicit in {"verified", "exploited"}


def _scanner_finding_needs_hypothesis(finding: dict[str, Any]) -> bool:
    if not isinstance(finding, dict) or _scanner_finding_is_verified(finding):
        return False
    severity = _hypothesis_severity(finding.get("severity"), "info")
    if severity not in {"critical", "high", "medium"}:
        return False
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    confidence = _float_between_0_1(
        finding.get("confidence", finding.get("ai_confidence")),
        _severity_to_confidence(severity, 0.58),
    )
    proof_state = str(finding.get("proof_state") or evidence.get("proof_state") or "").strip().lower()
    confidence_tier = str(finding.get("confidence_tier") or evidence.get("confidence_tier") or "").strip().lower()
    return (
        bool(finding.get("suspected") or finding.get("needs_verification") or evidence.get("needs_verification"))
        or proof_state in {"suspected", "unverified", "inconclusive", "needs_review"}
        or confidence_tier in {"low", "uncertain", "medium", "suspected"}
        or confidence < 0.85
        or _scan_time_verification_fields_dict(finding) is None
    )


def _scanner_signal_hypotheses(
    scan_id: str,
    target_id: str | None,
    target: str | None,
    result: dict[str, Any],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    if not target_id:
        return []
    hypotheses: list[dict[str, Any]] = []
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    for finding in findings[:100]:
        if not isinstance(finding, dict) or not _scanner_finding_needs_hypothesis(finding):
            continue
        family = _scanner_signal_family(finding)
        scanner_finding_id = str(finding.get("id") or "").strip()
        finding_fingerprint = str(generate_finding_fingerprint(finding) or scanner_finding_id).strip()
        confidence = _float_between_0_1(
            finding.get("confidence", finding.get("ai_confidence")),
            min(_severity_to_confidence(finding.get("severity"), 0.58), 0.82),
        )
        dims = {
            "product": "scanner_signal",
            "scan_id": scan_id,
            "target_id": target_id,
            "finding_id": finding_fingerprint,
            "type": finding.get("type") or finding.get("category") or finding.get("tool"),
        }
        hypotheses.append({
            "target_id": target_id,
            "source": "scanner_signal",
            "family": family,
            "cwe": finding.get("cwe"),
            "title": f"Scanner follow-up lead: {finding.get('title') or scanner_finding_id or family}",
            "description": (
                "A scanner finding is high enough impact to investigate but does not carry hard runtime proof. "
                "Treat it as a hypothesis until deterministic retest or focused family evidence confirms it."
            ),
            "severity_guess": _hypothesis_severity(finding.get("severity")),
            "confidence": confidence,
            "dedupe_key": _product_signal_hypothesis_key(family, dims),
            "next_test_action": {
                "command": "finding.retest",
                "parameters": {
                    "finding_id": finding_fingerprint or None,
                    "mode": "deterministic",
                    "target_id": target_id,
                    "target": target,
                    "scan_id": scan_id,
                    "finding_type": finding.get("type") or finding.get("category"),
                    "check_family": family,
                },
            },
            "endorsement": {
                "source": "scanner_signal",
                "scan_id": scan_id,
                "target_id": target_id,
                "finding_id": finding_fingerprint or None,
                "scanner_finding_id": scanner_finding_id or None,
                "tool": finding.get("tool"),
                "severity": finding.get("severity"),
                "confidence": confidence,
            },
            "metadata_json": {
                "dedupe_dimensions": dims,
                "product": "scanner_signal",
                "runtime_proof_required": True,
                "scan_type": (options or {}).get("scan_type"),
                "url": finding.get("url"),
                "finding_fingerprint": finding_fingerprint or None,
                "scanner_finding_id": scanner_finding_id or None,
                "proof_state": finding.get("proof_state"),
                "confidence_tier": finding.get("confidence_tier"),
            },
            "created_by": "worker",
        })
    return hypotheses


def _model_intake_signal_hypotheses(
    scan_id: str,
    target_id: str | None,
    target: str | None,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    hypotheses: list[dict[str, Any]] = []
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
    summary = model_intake.get("summary") if isinstance(model_intake.get("summary"), dict) else {}
    artifact_ref = summary.get("artifact_ref") or target
    for finding in findings[:50]:
        if not isinstance(finding, dict):
            continue
        finding_id = str(finding.get("id") or "").strip()
        haystack = f"{finding_id} {finding.get('title') or ''}".lower()
        if not any(marker in haystack for marker in MODEL_INTAKE_HYPOTHESIS_MARKERS):
            continue
        dims = {
            "product": "model_intake",
            "scan_id": scan_id,
            "target_id": target_id,
            "artifact": artifact_ref,
            "finding_id": finding_id,
            "type": finding.get("type") or finding_id,
        }
        hypotheses.append({
            "target_id": target_id,
            "source": "model_intake",
            "family": "model_intake_trust",
            "cwe": finding.get("cwe"),
            "title": f"Model Intake trust lead: {finding.get('title') or finding_id}",
            "description": (
                "Model Intake produced a metadata, governance, or trust-control signal. "
                "Treat it as a remediation hypothesis until checksum/signature/trust evidence confirms it."
            ),
            "severity_guess": _hypothesis_severity(finding.get("severity")),
            "confidence": _severity_to_confidence(finding.get("severity"), 0.65),
            "dedupe_key": _product_signal_hypothesis_key("model_intake_trust", dims),
            "next_test_action": {
                "command": "model_intake.trust_preview",
                "parameters": {
                    "artifact_url": artifact_ref,
                    "scan_id": scan_id,
                },
            },
            "endorsement": {
                "source": "model_intake",
                "scan_id": scan_id,
                "target_id": target_id,
                "finding_id": finding_id or None,
                "signature_status": summary.get("signature_verification_status"),
                "checksum_status": summary.get("checksum_status"),
            },
            "metadata_json": {
                "dedupe_dimensions": dims,
                "product": "model_intake",
                "summary": {
                    "signature_verification_status": summary.get("signature_verification_status"),
                    "checksum_status": summary.get("checksum_status"),
                    "format_posture": summary.get("format_posture"),
                },
            },
            "created_by": "worker",
        })
    return hypotheses


def _product_signal_hypotheses(
    scan_id: str,
    target_id: str | None,
    ai_target_id: str | None,
    target: str | None,
    result: dict[str, Any],
    options: dict[str, Any],
) -> list[dict[str, Any]]:
    run_kind = str((options or {}).get("run_kind") or "")
    if run_kind in AI_GATE_RUN_KINDS or isinstance((result or {}).get("ai_gate"), dict):
        return _ai_gate_signal_hypotheses(scan_id, ai_target_id, result, options)
    if run_kind in MODEL_INTAKE_RUN_KINDS or isinstance((result or {}).get("model_intake"), dict):
        return _model_intake_signal_hypotheses(scan_id, target_id, target, result)
    return _scanner_signal_hypotheses(scan_id, target_id, target, result or {}, options or {})


async def persist_product_signal_hypotheses(
    scan_id: str,
    target_id: str | None,
    ai_target_id: str | None,
    target: str | None,
    result: dict[str, Any],
    options: dict[str, Any],
) -> int:
    hypotheses = _product_signal_hypotheses(scan_id, target_id, ai_target_id, target, result, options)
    if not hypotheses:
        return 0
    inserted = 0
    async with db_pool.acquire() as conn:
        for payload in hypotheses:
            target_uuid = uuid.UUID(payload["target_id"]) if payload.get("target_id") else None
            # The scanner lead's next_test_action carries a finding FINGERPRINT, but the research
            # controller's finding.retest requires a canonical DB finding UUID (findings were just
            # persisted above). Resolve fingerprint -> UUID by (target_id, fingerprint) so the
            # suggested retest is runnable instead of failing finding_id_must_be_uuid.
            action = payload.get("next_test_action")
            if isinstance(action, dict) and target_uuid is not None and isinstance(action.get("parameters"), dict):
                params = action["parameters"]
                fid = str(params.get("finding_id") or "").strip()
                if fid:
                    # A scanner fingerprint may itself be UUID-shaped without being findings.id.
                    # Resolve the canonical row by fingerprint first; only accept a UUID as a DB id
                    # when a target-bound row with that exact id exists.
                    row = await conn.fetchrow(
                        "SELECT id FROM findings WHERE target_id=$1 AND fingerprint=$2 "
                        "ORDER BY last_seen_at DESC NULLS LAST LIMIT 1",
                        target_uuid, fid,
                    )
                    if not row:
                        try:
                            finding_uuid = uuid.UUID(fid)
                        except ValueError:
                            finding_uuid = None
                        if finding_uuid:
                            row = await conn.fetchrow(
                                "SELECT id FROM findings WHERE target_id=$1 AND id=$2",
                                target_uuid, finding_uuid,
                            )
                    params["finding_id"] = str(row["id"]) if row else None
            endorsement = {
                **(payload.get("endorsement") or {}),
                "recorded_at": utc_now_iso(),
            }
            await conn.fetchrow(
                """
                INSERT INTO hypotheses (
                    target_id, source, family, cwe, title, description,
                    severity_guess, confidence, dedupe_key, next_test_action,
                    endorsements, metadata_json, created_by
                ) VALUES (
                    $1,$2,$3,$4,$5,$6,
                    $7,$8,$9,$10::jsonb,
                    jsonb_build_array($11::jsonb),$12::jsonb,$13
                )
                ON CONFLICT (COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid), family, dedupe_key)
                DO UPDATE SET
                    confidence = GREATEST(hypotheses.confidence, EXCLUDED.confidence),
                    next_test_action = COALESCE(EXCLUDED.next_test_action, hypotheses.next_test_action),
                    endorsements = hypotheses.endorsements || EXCLUDED.endorsements,
                    metadata_json = hypotheses.metadata_json || EXCLUDED.metadata_json,
                    version = hypotheses.version + 1,
                    updated_at = NOW()
                RETURNING id
                """,
                target_uuid,
                payload["source"],
                payload["family"],
                payload.get("cwe"),
                payload.get("title"),
                payload.get("description"),
                payload.get("severity_guess"),
                float(payload.get("confidence") or 0),
                payload["dedupe_key"],
                json.dumps(payload.get("next_test_action") or {}),
                json.dumps(endorsement),
                json.dumps(payload.get("metadata_json") or {}),
                payload.get("created_by") or "worker",
            )
            inserted += 1
    return inserted


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


def _url_origin(url: str) -> tuple[str, str, int] | None:
    """Return a normalized HTTP origin for strict source-scan inheritance."""
    try:
        parsed = urllib.parse.urlparse(str(url or "").strip())
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        scheme = parsed.scheme.lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        return scheme, parsed.hostname.lower().rstrip("."), port
    except (TypeError, ValueError):
        return None


def _internal_retest_scope_authorized(verification: dict, target_url: str) -> bool:
    """Inherit bounded private-target authorization from the source scan.

    A finding cannot authorize its own destination. The source scan must target
    the exact origin and carry either a lab-scoped runtime guard or explicit
    deep intent on an active scan type.
    """
    source_target = str(verification.get("source_scan_target_url") or "").strip()
    if not source_target or _url_origin(source_target) != _url_origin(target_url):
        return False

    options = parse_json_field(verification.get("source_scan_options"))
    guard = options.get("runtime_scope_guard")
    if isinstance(guard, dict):
        environment = str(guard.get("environment") or "production").strip().lower()
        if environment in {"development", "dev", "preview", "staging", "lab", "test"}:
            scope = evaluate_runtime_destination_scope(guard, target_url)
            if scope.get("status") in {"allowed", "degraded"}:
                return True
        return False

    scan_type = str(
        verification.get("source_scan_type") or options.get("scan_type") or ""
    ).strip().lower()
    return scan_type in {"smart", "full", "aggressive"} and options.get("exploit_depth") is True


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
    internal_target_authorized: bool = False,
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

    if _is_internal_target(target_url) and not internal_target_authorized:
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

    # Verification Depth plan (C): AI never PROVES a finding — only the deterministic
    # provers can set 'exploited' (verified). An AI "exploited" verdict raises
    # suspicion but is not deterministic proof, so map it to 'likely_vulnerable'
    # (suspected, high-confidence) instead of 'exploited'. This keeps the verified
    # tier trustworthy: a finding is verified iff a deterministic prover confirmed it.
    if ai_verdict == "exploited":
        ai_verdict = "likely_vulnerable"
        ai_result = {**ai_result, "verdict": "likely_vulnerable"}

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


def _parallel_shard_concurrency_limit(r=None, options: dict[str, Any] | None = None) -> int:
    raw = None
    if isinstance(options, dict):
        if options.get("shard_concurrency") is not None:
            raw = options.get("shard_concurrency")
        elif options.get("parallel_shard_concurrency") is not None:
            raw = options.get("parallel_shard_concurrency")
    if raw is None:
        # No explicit per-scan override: let a single parent fill the fleet rather
        # than capping it at the legacy flat 4. The fleet-wide active-scan semaphore
        # (_await_scan_slot / _max_active_scans) still arbitrates total concurrent
        # scanner subprocesses across all parents, so this is bounded by real RAM-
        # derived fleet capacity. PARALLEL_SHARD_MAX_PER_PARENT is now just a floor.
        fleet = 0
        if r is not None:
            try:
                fleet = _max_active_scans(r)
            except Exception:
                fleet = 0
        raw = max(PARALLEL_SHARD_MAX_PER_PARENT, fleet)
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        limit = PARALLEL_SHARD_MAX_PER_PARENT
    return max(1, min(PARALLEL_SHARD_CONCURRENCY_HARD_MAX, limit))


_PARALLEL_SHARD_SLOT_ACQUIRE_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local expires_at = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local key_ttl = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
if redis.call('ZSCORE', key, member) then
  redis.call('ZADD', key, expires_at, member)
  redis.call('EXPIRE', key, key_ttl)
  return 1
end
if redis.call('ZCARD', key) >= limit then
  return 0
end
redis.call('ZADD', key, expires_at, member)
redis.call('EXPIRE', key, key_ttl)
return 1
"""

_PARALLEL_SHARD_SLOT_REFRESH_LUA = """
local key = KEYS[1]
local member = ARGV[1]
local expires_at = tonumber(ARGV[2])
local key_ttl = tonumber(ARGV[3])
if not redis.call('ZSCORE', key, member) then
  return 0
end
redis.call('ZADD', key, expires_at, member)
redis.call('EXPIRE', key, key_ttl)
return 1
"""


def _prepare_parallel_shard_slot_key(r, key: str) -> None:
    """Remove the legacy integer semaphore before using the leased ZSET."""
    kind = r.type(key)
    if isinstance(kind, bytes):
        kind = kind.decode("utf-8", errors="replace")
    if str(kind or "none") not in {"none", "zset"}:
        r.delete(key)


def _try_acquire_parallel_shard_slot(
    r,
    parent_id: str | None,
    options: dict[str, Any] | None = None,
    *,
    slot_id: str | None,
) -> tuple[bool, int]:
    if not parent_id:
        return True, 0
    member = str(slot_id or "").strip()
    if not member:
        raise ValueError("parallel shard slot_id is required")
    limit = _parallel_shard_concurrency_limit(r, options)
    key = _parallel_shard_slot_key(parent_id)
    _prepare_parallel_shard_slot_key(r, key)
    now = time.time()
    acquired = r.eval(
        _PARALLEL_SHARD_SLOT_ACQUIRE_LUA,
        1,
        key,
        now,
        now + PARALLEL_SHARD_SLOT_TTL_SECONDS,
        limit,
        member,
        PARALLEL_SHARD_SLOT_TTL_SECONDS + 600,
    )
    return bool(acquired), limit


def _refresh_parallel_shard_slot(r, parent_id: str | None, slot_id: str | None) -> bool:
    if not parent_id or not slot_id:
        return False
    key = _parallel_shard_slot_key(parent_id)
    _prepare_parallel_shard_slot_key(r, key)
    return bool(r.eval(
        _PARALLEL_SHARD_SLOT_REFRESH_LUA,
        1,
        key,
        str(slot_id),
        time.time() + PARALLEL_SHARD_SLOT_TTL_SECONDS,
        PARALLEL_SHARD_SLOT_TTL_SECONDS + 600,
    ))


def _release_parallel_shard_slot(r, parent_id: str | None, slot_id: str | None) -> None:
    if not parent_id or not slot_id:
        return
    key = _parallel_shard_slot_key(parent_id)
    try:
        _prepare_parallel_shard_slot_key(r, key)
        r.zrem(key, str(slot_id))
        if int(r.zcard(key) or 0) <= 0:
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


def _standalone_scan_rate_reservation_amount(options: dict[str, Any] | None) -> int:
    """Estimate active endpoint budget before a standalone scanner subprocess runs.

    ASM and dynamic coverage batches already know their endpoint IDs before
    execution. Standalone smart/full/aggressive scans discover active work
    inside the scanner process, so reserve the resolved active endpoint budget
    up front instead of fail-opening unlimited discovered requests.
    """
    opts = options or {}
    request_budget_mode = _effective_request_budget_mode(opts)
    if request_budget_mode == "enforce":
        custom_budget = opts.get("custom_budget") if isinstance(opts.get("custom_budget"), dict) else {}
        try:
            resolved = resolve_or_consume_budget(
                str(opts.get("scan_type") or "standard"),
                options=opts,
                budget_profile=opts.get("budget_profile"),
                custom_budget=custom_budget,
            )
            return max(0, int(resolved.get("request_max") or 0))
        except Exception:
            return 0
    known = _known_endpoint_count(opts)
    if known > 0:
        return known

    scan_type = str(opts.get("scan_type") or "standard").strip().lower()
    active_requested = bool(
        opts.get("active")
        or opts.get("sqli")
        or opts.get("xss")
        or opts.get("check_family")
        or opts.get("asm_check_family")
        or scan_type in ACTIVE_ENFORCED_SCAN_TYPES
    )
    if not active_requested:
        return 0

    custom_budget = opts.get("custom_budget") if isinstance(opts.get("custom_budget"), dict) else {}
    profile = opts.get("budget_profile")
    if opts.get("thorough_params") and not profile and not custom_budget:
        profile = "thorough"
    try:
        # Consume the stamped budget contract (docs §4) so the active-endpoint cap
        # matches what the scan was planned with, not a re-derived value.
        resolved = resolve_or_consume_budget(
            scan_type, options=opts, budget_profile=profile, custom_budget=custom_budget
        )
    except Exception:
        resolved = {}
    try:
        return max(0, int(resolved.get("active_max_endpoints") or 0))
    except (TypeError, ValueError):
        return 0


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
    canonical_queue = isinstance(job_data.get("_canonical_queue_payload"), Mapping)
    wait_cycles = int((
        _redis_scalar_text(r.hget(f"job:{job_id}", "domain_rate_wait_cycles"))
        if canonical_queue else job_data.get("domain_rate_wait_cycles") or 0
    ) or 0) + 1
    requeued = _safe_requeue_payload(job_data)
    if not canonical_queue:
        requeued["domain_rate_wait_cycles"] = wait_cycles
        requeued["last_domain_rate_wait_at"] = utc_now_iso()
    enqueue_job(r, QUEUE_NAME, requeued)
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
        "nosqli": "prove_nosqli",
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
            prove_nosqli,
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
    internal_target_authorized = _internal_retest_scope_authorized(verification, test_url)

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
        "prove_nosqli": prove_nosqli,
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
            internal_target_authorized=internal_target_authorized,
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
            internal_target_authorized=internal_target_authorized,
        )
    else:
        result_status, verdict, verdict_reason = classify_retest_outcome(
            proof=proof_data, proven=still_vulnerable, confidence=confidence, inputs=inputs,
            internal_target_authorized=internal_target_authorized,
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
                    candidate_uuid = uuid.UUID(str(job_data.get("candidate_id")))
                except Exception:
                    candidate_uuid = None
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
                    if candidate_uuid is not None:
                        await conn.execute(
                            """UPDATE investigation_candidates
                               SET status='inconclusive',
                                   verification_context=verification_context || jsonb_build_object(
                                       'error','retest_slot_exhausted',
                                       'verification_id',$2::text
                                   ), updated_at=NOW()
                               WHERE id=$1""",
                            candidate_uuid, uuid.UUID(verification_id),
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
            submitted_at=str(job_data["submitted_at"]),
            trigger=trigger,
            attempt=attempt,
            finding_id=str(job_data.get("finding_id") or "") or None,
            candidate_id=str(job_data.get("candidate_id") or "") or None,
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
        enqueue_job(r, RETEST_QUEUE_NAME, requeued_payload)
        r.expire(retest_key, 86400)
        await asyncio.sleep(backoff_seconds)
        return

    try:
        async with db_pool.acquire() as conn:
            verification = await conn.fetchrow("""
                SELECT fv.*,
                       COALESCE(f.title, c.title) AS title,
                       COALESCE(f.tool, 'investigation_candidate') AS tool,
                       COALESCE(f.evidence, c.verification_context) AS evidence,
                       COALESCE(f.url, fv.original_url, fv.target_url) AS finding_url,
                       COALESCE(f.severity, c.claimed_severity) AS severity,
                       c.family AS candidate_family,
                       c.canonical_locus AS candidate_locus,
                       s.target_url as source_scan_target_url,
                       s.options as source_scan_options,
                       s.scan_type as source_scan_type
                FROM finding_verifications fv
                LEFT JOIN findings f ON fv.finding_id = f.id
                LEFT JOIN investigation_candidates c ON fv.candidate_id = c.id
                LEFT JOIN scans s ON fv.scan_id = s.id
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

            claimed = await conn.fetchrow("""
                UPDATE finding_verifications
                SET status = 'running',
                    started_at = NOW(),
                    attempt_count = GREATEST(COALESCE(attempt_count, 0), $2),
                    updated_at = NOW()
                WHERE id = $1 AND status = 'queued'
                RETURNING id
            """, verification["id"], attempt)
            if not claimed:
                current_status = await conn.fetchval(
                    "SELECT status FROM finding_verifications WHERE id=$1",
                    verification["id"],
                )
                if str(current_status or "") == "cancelled":
                    r.hset(retest_key, mapping={
                        "status": "cancelled",
                        "verification_id": verification_id,
                        "finding_id": str(verification["finding_id"]),
                    })
                    r.expire(retest_key, 86400)
                    print(f"[retest:{job_id[:8]}] Retest cancelled before execution", flush=True)
                    return
                r.hset(retest_key, mapping={
                    "status": str(current_status or "ignored"),
                    "verification_id": verification_id,
                    "note": "duplicate_or_nonqueued_retest_job",
                })
                r.expire(retest_key, 86400)
                return

            r.hset(retest_key, mapping={
                "status": "running",
                "verification_id": verification_id,
                "started_at": now.isoformat(),
                "attempt": str(attempt),
            })

            await conn.execute("""
                UPDATE findings
                SET last_verification_status = 'running',
                    last_verification_verdict = NULL,
                    updated_at = NOW()
                WHERE id = $1
            """, verification["finding_id"])
            if verification.get("candidate_id"):
                await conn.execute(
                    """UPDATE investigation_candidates
                       SET status='verifying', latest_verification_id=$2, updated_at=NOW()
                       WHERE id=$1""",
                    verification["candidate_id"], verification["id"],
                )

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
            if not finding_severity and verification.get("finding_id"):
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

            if (
                verification.get("candidate_id")
                and not verification.get("finding_id")
                and str(result.get("verdict") or "").lower() == "exploited"
            ):
                candidate_context = parse_json_field(verification.get("evidence")) or {}
                candidate_locus = parse_json_field(verification.get("candidate_locus")) or {}
                finding_url = str(
                    verification.get("original_url")
                    or verification.get("target_url")
                    or verification.get("finding_url")
                    or ""
                )
                family_name = str(
                    verification.get("candidate_family")
                    or verification.get("finding_type")
                    or "verified_candidate"
                )
                fingerprint = hashlib.sha256(json.dumps({
                    "target_id": str(verification.get("target_id") or ""),
                    "family": family_name,
                    "locus": candidate_locus,
                    "source": "deep_hunt_candidate_retest",
                }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                finding_id = await conn.fetchval(
                    """INSERT INTO findings (
                           target_id, fingerprint, title, description, severity, tool, cwe,
                           url, evidence, notes, source, status,
                           last_verification_status, last_verification_verdict,
                           last_verification_confidence, last_verified_at, verification_count
                       ) VALUES ($1,$2,$3,$4,$5,'autonomous_workflow',$6,$7,$8::jsonb,
                                 'Created only after deterministic candidate verification.',
                                 'autonomous','active','completed','exploited',$9,NOW(),1)
                       ON CONFLICT (target_id, fingerprint) WHERE target_id IS NOT NULL
                       DO UPDATE SET status='active', resolved_at=NULL, last_seen_at=NOW(),
                           evidence=EXCLUDED.evidence, tool='autonomous_workflow',
                           last_verification_status='completed',
                           last_verification_verdict='exploited',
                           last_verification_confidence=EXCLUDED.last_verification_confidence,
                           last_verified_at=NOW(), updated_at=NOW()
                       RETURNING id""",
                    verification.get("target_id"), fingerprint,
                    str(verification.get("title") or "Verified Deep Hunt candidate")[:300],
                    str(candidate_context.get("proof") or verification.get("title") or "Verified candidate")[:8000],
                    finding_severity if finding_severity in SEVERITY_ORDER else "high",
                    str(candidate_context.get("cwe") or "")[:32] or None,
                    finding_url,
                    json.dumps({
                        "candidate_id": str(verification.get("candidate_id")),
                        "family": family_name,
                        "canonical_locus": candidate_locus,
                        "deterministic_retest": _redact_finding_evidence(result.get("proof") or {}),
                    }),
                    result.get("confidence"),
                )
                await conn.execute(
                    "UPDATE finding_verifications SET finding_id=$2 WHERE id=$1",
                    verification["id"], finding_id,
                )
                verification = dict(verification)
                verification["finding_id"] = finding_id

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
            # Link Deep Hunt's durable candidate to the existing deterministic retest record.
            # The retest verdict, never the model claim, owns the candidate lifecycle.
            candidate = await conn.fetchrow(
                """SELECT id, verifier_contract_id
                   FROM investigation_candidates
                   WHERE plane='web' AND (
                         id=$2::uuid
                         OR verification_context->>'finding_id'=$1::text
                   )
                   ORDER BY last_seen_at DESC, id DESC LIMIT 1""",
                verification["finding_id"], verification.get("candidate_id"),
            )
            if candidate:
                final_candidate_verdict = str(result.get("verdict") or "").lower()
                candidate_status = (
                    "verified" if final_candidate_verdict == "exploited"
                    else "refuted" if final_candidate_verdict in {"false_positive", "likely_fixed"}
                    else "inconclusive"
                )
                proof_basis = str(
                    (result.get("proof") or {}).get("evidence_type")
                    if isinstance(result.get("proof"), dict) else ""
                ) or str(result.get("verification_mode") or "deterministic_retest")
                await conn.execute(
                    """UPDATE finding_verifications
                       SET candidate_id=$2, contract_id=COALESCE(contract_id,$3),
                           contract_version=COALESCE(contract_version,'deterministic-retest/v1'),
                           proof_basis=COALESCE(proof_basis,$4)
                       WHERE id=$1""",
                    verification["id"], candidate["id"], candidate["verifier_contract_id"], proof_basis,
                )
                proof_observation = _redact_finding_evidence(result.get("proof") or {})
                proof_hash = hashlib.sha256(
                    json.dumps(proof_observation, sort_keys=True, separators=(",", ":"), default=str).encode()
                ).hexdigest()
                await conn.execute(
                    """INSERT INTO evidence_instances (
                           finding_id, candidate_id, scan_id, target_id, proof_observation,
                           hash, proof_state, evidence_strength, contract_id, contract_version,
                           proof_basis, created_by
                       ) VALUES (
                           $1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,'deterministic-retest/v1',$10,
                           'deep_hunt_candidate_retest'
                       )""",
                    verification["finding_id"], candidate["id"], verification["scan_id"],
                    verification["target_id"], json.dumps(proof_observation), proof_hash,
                    "verified" if candidate_status == "verified" else candidate_status,
                    "reproduced" if candidate_status == "verified" else "signal",
                    candidate["verifier_contract_id"], proof_basis,
                )
                await conn.execute(
                    """UPDATE investigation_candidates
                       SET status=$2, latest_verification_id=$3,
                           verification_context=verification_context || jsonb_build_object(
                               'verdict',$4::text,'verified_at',$5::text
                           ), updated_at=NOW()
                       WHERE id=$1""",
                    candidate["id"], candidate_status, verification["id"],
                    final_candidate_verdict or "inconclusive", completed_at.isoformat(),
                )
            campaign_status = (
                'completed'
                if result.get("verdict") == "exploited" or result.get("status") == "completed"
                else 'failed'
            )
            await asm_inventory.finish_campaign(
                conn,
                str(_row_get(verification, "campaign_id")) if _row_get(verification, "campaign_id") else None,
                status=campaign_status,
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
    except Exception as exc:
        candidate_value = job_data.get("candidate_id")
        if candidate_value:
            try:
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        """UPDATE investigation_candidates
                           SET status='inconclusive',
                               verification_context=verification_context || jsonb_build_object(
                                   'error',$2::text,'verification_id',$3::text
                               ), updated_at=NOW()
                           WHERE id=$1""",
                        uuid.UUID(str(candidate_value)),
                        f"worker_error:{type(exc).__name__}"[:160],
                        verification_id,
                    )
            except Exception:
                pass
        raise
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

        # The auto-retest budget is bounded, so spend it on findings that still need
        # PROOF (suspected/unverified), highest severity first — not on findings the
        # scan already proved ('exploited'). This directly lifts the verified ratio:
        # the budget targets the suspected High/Critical wall instead of re-confirming
        # already-verified findings. (Verification Depth plan, workstream B.)
        rows = await conn.fetch("""
            SELECT f.*, t.url as target_url
            FROM findings f
            LEFT JOIN targets t ON f.target_id = t.id
            WHERE f.scan_id = $1 AND f.status = 'active'
            ORDER BY
                CASE WHEN f.last_verification_verdict = 'exploited' THEN 1 ELSE 0 END,
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
            # Already proven by the scan — don't spend a retest slot re-confirming it.
            if str(finding.get("last_verification_verdict") or "") == "exploited":
                skipped += 1
                continue
            # Attempt ceiling: a finding retested AUTO_RETEST_MAX_ATTEMPTS times without
            # proof won't be auto-retested again (it surfaces as stuck in /asm/gaps).
            if int(finding.get("verification_count") or 0) >= AUTO_RETEST_MAX_ATTEMPTS:
                skipped += 1
                continue
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
            enqueue_job(r, RETEST_QUEUE_NAME, job_payload)
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
            SELECT id, finding_id, candidate_id, job_id, attempt_count
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
            candidate_id = row["candidate_id"]
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
                    submitted_at=now.isoformat(),
                    trigger="stale_watchdog_requeue",
                    attempt=next_attempt,
                    finding_id=str(finding_id) if finding_id else None,
                    candidate_id=str(candidate_id) if candidate_id else None,
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

                    enqueue_job(r, RETEST_QUEUE_NAME, payload)
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
                SELECT fv.id, fv.finding_id, fv.candidate_id, fv.retry_class, fv.attempt_count
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
                finding_id = str(row["finding_id"]) if row["finding_id"] else None
                candidate_id = str(row["candidate_id"]) if row["candidate_id"] else None
                job_id = f"circuit-recovery-{uuid.uuid4().hex[:12]}"
                now_iso = utc_now_iso()
                payload = build_retest_job_payload(
                    job_id=job_id,
                    verification_id=verification_id,
                    submitted_at=now_iso,
                    trigger="circuit_recovery",
                    attempt=int(row["attempt_count"] or 0) + 1,
                    finding_id=finding_id,
                    candidate_id=candidate_id,
                )
                enqueue_job(r, RETEST_QUEUE_NAME, payload)
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


async def persist_scan_artifact_bytes(
    data: bytes,
    *,
    scan_id: str,
    artifact_type: str,
    filename: str,
    parent_scan_id: str | None = None,
    shard_index: int | None = None,
    content_type: str = "application/octet-stream",
    metadata: dict[str, Any] | None = None,
    executing_node_id: str | None = None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Upload bytes and commit the matching manifest as one worker contract."""
    if (parent_scan_id is None and shard_index is None) or executing_node_id is None:
        try:
            if conn is not None:
                lineage = await conn.fetchrow(
                    "SELECT parent_scan_id, shard_index, executing_node_id FROM scans WHERE id=$1",
                    uuid.UUID(scan_id),
                )
            else:
                async with db_pool.acquire() as lineage_conn:
                    lineage = await lineage_conn.fetchrow(
                        "SELECT parent_scan_id, shard_index, executing_node_id FROM scans WHERE id=$1",
                        uuid.UUID(scan_id),
                    )
            if lineage:
                parent_scan_id = str(lineage["parent_scan_id"]) if lineage["parent_scan_id"] else None
                shard_index = lineage["shard_index"]
                executing_node_id = str(lineage.get("executing_node_id") or "") or None
        except Exception:
            if artifact_remote_required():
                raise

    key = artifact_object_key(
        scan_id=scan_id,
        artifact_type=artifact_type,
        shard_index=shard_index,
        filename=filename,
    )
    descriptor = await asyncio.to_thread(
        store_artifact_bytes,
        data,
        results_dir=RESULTS_DIR,
        scan_id=scan_id,
        artifact_type=artifact_type,
        shard_index=shard_index,
        filename=filename,
        content_type=content_type,
    )

    async def record(active_conn):
        return await upsert_artifact_manifest(
            active_conn,
            scan_id=scan_id,
            parent_scan_id=parent_scan_id,
            shard_index=shard_index,
            artifact_type=artifact_type,
            artifact_key=key,
            descriptor=descriptor,
            metadata=metadata,
            executing_node_id=executing_node_id,
        )

    if conn is not None:
        row = await record(conn)
    else:
        async with db_pool.acquire() as artifact_conn:
            row = await record(artifact_conn)
    return {**descriptor, "manifest": row}


def _referenced_artifact_path(key: str, value: Any) -> Path | None:
    if not isinstance(value, str) or not value.startswith("/"):
        return None
    lowered = str(key or "").lower()
    if "screenshot" not in lowered and not lowered.endswith(("_path", "_file")):
        return None
    candidate = Path(value)
    if candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file():
        return None
    allowed = False
    for root in (RESULTS_DIR, Path(tempfile.gettempdir())):
        try:
            resolved.relative_to(root.resolve())
            allowed = True
            break
        except (OSError, ValueError):
            continue
    if not allowed:
        return None
    try:
        size = resolved.stat().st_size
    except OSError:
        return None
    if size < 0 or size > ARTIFACT_REFERENCED_FILE_MAX_BYTES:
        return None
    return resolved


async def centralize_referenced_artifacts(
    value: Any,
    *,
    scan_id: str,
    parent_scan_id: str | None = None,
    shard_index: int | None = None,
) -> int:
    """Replace bounded worker-local result paths with API-proxied references."""
    references: list[tuple[Any, Any, str, Path]] = []

    def collect(current: Any) -> None:
        if len(references) >= ARTIFACT_REFERENCED_FILE_MAX_COUNT:
            return
        if isinstance(current, dict):
            for key, item in list(current.items()):
                path = _referenced_artifact_path(str(key), item)
                if path is not None:
                    references.append((current, key, str(key), path))
                else:
                    collect(item)
        elif isinstance(current, list):
            for index, item in enumerate(list(current)):
                path = _referenced_artifact_path("artifact_file", item)
                if path is not None:
                    references.append((current, index, "artifact_file", path))
                else:
                    collect(item)

    collect(value)
    uploaded: dict[str, str] = {}
    for container, key, source_key, path in references:
        cache_key = str(path)
        download_url = uploaded.get(cache_key)
        if download_url is None:
            artifact_type = "screenshot" if "screenshot" in source_key.lower() else "attachment"
            try:
                persisted = await persist_scan_artifact_bytes(
                    await asyncio.to_thread(path.read_bytes),
                    scan_id=scan_id,
                    parent_scan_id=parent_scan_id,
                    shard_index=shard_index,
                    artifact_type=artifact_type,
                    filename=path.name,
                    content_type=artifact_content_type(path.name),
                    metadata={"source_key": source_key, "source_filename": path.name},
                )
            except Exception:
                if artifact_remote_required():
                    raise
                continue
            artifact_id = str((persisted.get("manifest") or {}).get("id") or "")
            if not artifact_id:
                raise ArtifactStorageError("referenced artifact manifest has no id")
            download_url = f"/scans/{scan_id}/artifacts/{artifact_id}"
            uploaded[cache_key] = download_url
        container[key] = download_url
    return len(uploaded)


async def persist_result_artifact(
    result: dict,
    job_id: str,
    scan_id: str,
    *,
    parent_scan_id: str | None = None,
    shard_index: int | None = None,
    conn: Any | None = None,
) -> str:
    """Persist the compatibility result file and centralized artifact.

    A joined fleet node fails the job lease if either the object upload or its
    durable manifest cannot be committed. Standalone mode keeps the historical
    local result path and treats a manifest failure as degraded compatibility.
    """
    executing_node_id: str | None = None
    try:
        if conn is not None:
            lineage = await conn.fetchrow(
                "SELECT parent_scan_id, shard_index, executing_node_id FROM scans WHERE id=$1",
                uuid.UUID(scan_id),
            )
        else:
            async with db_pool.acquire() as lineage_conn:
                lineage = await lineage_conn.fetchrow(
                    "SELECT parent_scan_id, shard_index, executing_node_id FROM scans WHERE id=$1",
                    uuid.UUID(scan_id),
                )
        if lineage:
            parent_scan_id = parent_scan_id or (
                str(lineage["parent_scan_id"]) if lineage["parent_scan_id"] else None
            )
            shard_index = shard_index if shard_index is not None else lineage["shard_index"]
            executing_node_id = str(lineage.get("executing_node_id") or "") or None
    except Exception:
        if artifact_remote_required():
            raise

    await centralize_referenced_artifacts(
        result,
        scan_id=scan_id,
        parent_scan_id=parent_scan_id,
        shard_index=shard_index,
    )
    local_result_path = save_result_file(result, job_id)
    artifact_key = artifact_object_key(
        scan_id=scan_id,
        artifact_type="result",
        shard_index=shard_index,
        filename="result.json",
    )
    try:
        descriptor = await asyncio.to_thread(
            store_artifact_json,
            result,
            results_dir=RESULTS_DIR,
            scan_id=scan_id,
            artifact_type="result",
            shard_index=shard_index,
            filename="result.json",
        )
        async def record(active_conn):
            await upsert_artifact_manifest(
                active_conn,
                scan_id=scan_id,
                parent_scan_id=parent_scan_id,
                shard_index=shard_index,
                artifact_type="result",
                artifact_key=artifact_key,
                descriptor=descriptor,
                metadata={"job_id": job_id, "canonical": True},
                executing_node_id=executing_node_id,
            )
        if conn is not None:
            await record(conn)
        else:
            async with db_pool.acquire() as acquired_conn:
                await record(acquired_conn)
        return str(descriptor["storage_uri"])
    except Exception as exc:
        if artifact_remote_required():
            if isinstance(exc, ArtifactStorageError):
                raise
            raise ArtifactStorageError(
                f"artifact manifest persistence failed ({type(exc).__name__})"
            ) from exc
        print(
            f"[{job_id[:8]}] artifact manifest degraded to local result: "
            f"{type(exc).__name__}: {exc}",
            flush=True,
        )
        return local_result_path


def send_heartbeats(
    job_id: str,
    stop_event: threading.Event,
    parent_id: str | None = None,
    shard_slot_id: str | None = None,
):
    """Send periodic heartbeats from a dedicated thread.

    This avoids heartbeat starvation when the asyncio event loop is busy with
    synchronous CPU/JSON work.
    """
    # Dedicated client with socket timeouts so a stalled connection cannot block
    # the hset forever — otherwise the heartbeat silently stops and the stale-scan
    # checker reaps a still-running scan, discarding all its findings (observed on
    # long finalize/verification phases of large scans). Reconnect on failure.
    def _hb_client():
        try:
            return redis.from_url(REDIS_URL, socket_timeout=10, socket_connect_timeout=10)
        except Exception:
            return None
    r = _hb_client()
    while not stop_event.is_set():
        try:
            if r is None:
                r = _hb_client()
            if r is not None:
                r.hset(f"job:{job_id}", 'heartbeat', utc_now_iso())
                if parent_id and shard_slot_id:
                    _refresh_parallel_shard_slot(r, parent_id, shard_slot_id)
                _write_worker_build_report(r)
        except Exception as e:
            print(f"[{job_id[:8]}] Heartbeat error (reconnecting): {e}", flush=True)
            r = None  # force reconnect next tick instead of reusing a wedged socket
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


_DEVICE_ACTIVITY_MESSAGES = {
    "device_inventory": "Starting device reachability and inventory checks",
    "device_tcp_discovery": "Scanning the requested TCP port scope",
    "tcp_priority_discovery": "Checking common and device-specific TCP ports",
    "device_service_fingerprinting": "Fingerprinting confirmed listening services",
    "device_udp_discovery": "Checking curated UDP services",
    "device_protocol_discovery": "Testing device protocols such as SSDP and mDNS",
    "device_web_discovery": "Detecting HTTP and HTTPS on confirmed ports",
    "device_application_discovery": "Identifying device platforms and testing known APIs",
    "device_ssh_posture": "Reviewing SSH posture on confirmed SSH services",
    "device_policy": "Evaluating device policy and evidence completeness",
    "device_web_dast": "Testing discovered web and API interfaces",
    "completed": "Connected-device scan completed",
    "failed": "Connected-device scan failed",
}


def _append_device_activity(
    scan_id: str,
    *,
    kind: str,
    phase: str,
    message: str | None = None,
    progress: int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist bounded, secret-free device events for the user-facing live feed."""
    safe_details = {}
    for key, value in (details or {}).items():
        if key in {
            "confirmed_services", "web_origins", "origin", "status", "error_type",
            "executed_requests", "skipped_requests", "findings_count", "collection_count",
            "platforms", "api_endpoints", "auth_boundaries", "available_control_families",
        }:
            safe_details[str(key)] = value
    event = {
        "timestamp": utc_now_iso(),
        "kind": str(kind)[:80],
        "phase": str(phase)[:120],
        "message": str(message or _DEVICE_ACTIVITY_MESSAGES.get(phase) or phase.replace("_", " ").capitalize())[:500],
        "progress": max(0, min(100, int(progress))) if progress is not None else None,
        "details": safe_details,
    }
    try:
        redis_client = get_redis()
        key = f"scan:{scan_id}:device_activity"
        redis_client.rpush(key, json.dumps(event, separators=(",", ":"), default=str))
        redis_client.ltrim(key, -250, -1)
        redis_client.expire(key, SCAN_LOG_TTL_SECONDS)
    except Exception:
        pass


def _runtime_scope_guard_applies(options: dict[str, Any]) -> bool:
    guard = (options or {}).get("runtime_scope_guard")
    return isinstance(guard, dict) and bool(guard.get("requires_runtime_destination_check"))


def _runtime_destination_records(result: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
    run_kind = str((options or {}).get("run_kind") or "").strip()
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        label: str,
        url: Any,
        final_url: Any = None,
        *,
        source: str | None = None,
        redirect_urls: Any = None,
        resolved_ips: Any = None,
        resolved_host: Any = None,
    ) -> None:
        raw_url = str(url or "").strip()
        raw_final = str(final_url or raw_url).strip()
        if not raw_url and not raw_final:
            return
        key = (label, raw_url, raw_final)
        if key in seen:
            return
        seen.add(key)
        record: dict[str, Any] = {"label": label, "url": raw_url or raw_final}
        if raw_final:
            record["final_url"] = raw_final
        if source:
            record["source"] = source
        if isinstance(redirect_urls, (list, tuple)):
            record["redirect_urls"] = [str(item) for item in redirect_urls if str(item or "").strip()]
        if isinstance(resolved_ips, (list, tuple)):
            record["resolved_ips"] = [str(item) for item in resolved_ips if str(item or "").strip()]
        elif str(resolved_ips or "").strip():
            record["resolved_ips"] = [str(resolved_ips).strip()]
        if str(resolved_host or "").strip():
            record["resolved_host"] = str(resolved_host).strip()
        records.append(record)

    if run_kind in {"device_posture", "device_probe"}:
        posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
        probe = result.get("device_probe") if isinstance(result.get("device_probe"), dict) else {}
        locator = str(result.get("target") or "").strip()
        resolved = str(result.get("resolved_target") or posture.get("resolved_target") or "").strip()
        if locator:
            formatted = f"[{locator}]" if ":" in locator and not locator.startswith("[") else locator
            port = probe.get("port") if probe else None
            destination_url = f"http://{formatted}{f':{int(port)}' if port else ''}/"
            add(
                "device_target",
                destination_url,
                source=run_kind,
                resolved_ips=[resolved] if resolved else None,
                resolved_host=locator,
            )
        for item in posture.get("runtime_destinations") or ():
            if isinstance(item, dict):
                add(
                    str(item.get("label") or "device_web_child"),
                    item.get("url"),
                    item.get("final_url"),
                    source=item.get("source") or "device_web_dast",
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        return records

    if run_kind in AI_GATE_RUN_KINDS:
        ai_gate = result.get("ai_gate") if isinstance(result.get("ai_gate"), dict) else {}
        for item in ai_gate.get("runtime_destinations") or ():
            if isinstance(item, dict):
                add(
                    str(item.get("label") or "ai_gate"),
                    item.get("url"),
                    item.get("final_url"),
                    source=item.get("source"),
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        return records

    if run_kind in MODEL_INTAKE_RUN_KINDS:
        model_intake = result.get("model_intake") if isinstance(result.get("model_intake"), dict) else {}
        for item in model_intake.get("runtime_destinations") or ():
            if isinstance(item, dict):
                add(
                    str(item.get("label") or "model_intake"),
                    item.get("url"),
                    item.get("final_url"),
                    source=item.get("source"),
                    redirect_urls=item.get("redirect_urls") or item.get("redirect_chain"),
                    resolved_ips=item.get("resolved_ips") or item.get("remote_ip"),
                    resolved_host=item.get("resolved_host"),
                )
        return records

    http = result.get("http") if isinstance(result.get("http"), dict) else {}
    final_url = str(http.get("final_url") or "").strip()
    final_host = urllib.parse.urlparse(final_url).hostname if final_url else None
    add(
        "dast_http",
        http.get("request_url") or final_url,
        final_url,
        source="http_observation",
        redirect_urls=http.get("redirect_chain"),
        resolved_ips=http.get("remote_ip"),
        resolved_host=final_host,
    )
    return records


def _evaluate_runtime_destination_records(
    records: list[dict[str, Any]],
    options: dict[str, Any],
) -> dict[str, Any]:
    if not records:
        return evaluate_runtime_destination_scope((options or {}).get("runtime_scope_guard"), None)

    checks: list[dict[str, Any]] = []
    blocked_by: list[str] = []
    warnings: list[str] = []
    all_resolution_observations: list[dict[str, Any]] = []
    for record in records:
        resolved_ips = record.get("resolved_ips") if isinstance(record.get("resolved_ips"), list) else []
        resolved_host = str(record.get("resolved_host") or "").strip()
        if resolved_host and resolved_ips:
            observation = {"host": resolved_host, "ips": resolved_ips}
            if observation not in all_resolution_observations:
                all_resolution_observations.append(observation)
    for record in records:
        url = str(record.get("url") or "").strip()
        final_url = str(record.get("final_url") or url).strip()
        redirects = record.get("redirect_urls") if isinstance(record.get("redirect_urls"), list) else []
        if url and final_url and final_url != url and final_url not in redirects:
            redirects = [*redirects, final_url]
        check = evaluate_runtime_destination_scope(
            (options or {}).get("runtime_scope_guard"),
            url or final_url,
            redirect_urls=redirects or None,
            resolution_observations=all_resolution_observations,
        )
        check["label"] = record.get("label")
        check["source"] = record.get("source")
        check["url"] = url or final_url
        check["final_url"] = final_url or url
        checks.append(check)
        if check.get("status") == "blocked":
            for reason in check.get("blocked_by") or ():
                if reason not in blocked_by:
                    blocked_by.append(reason)
        for warning in check.get("warnings") or ():
            if warning not in warnings:
                warnings.append(warning)

    first = checks[0] if checks else {}
    return {
        "verdict": "blocked" if blocked_by else ("degraded" if warnings else "allowed"),
        "status": "blocked" if blocked_by else ("degraded" if warnings else "allowed"),
        "blocked_by": blocked_by,
        "warnings": warnings,
        "checks": checks,
        "destinations": records,
        "runtime_scope_guard_present": True,
        "scope_receipt_id": first.get("scope_receipt_id") or ((options or {}).get("runtime_scope_guard") or {}).get("scope_receipt_id"),
    }


def _apply_runtime_scope_guard_to_result(result: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    """Fail closed when a guarded scan cannot prove touched runtime destinations are in scope."""
    if not isinstance(result, dict) or result.get("error") or not _runtime_scope_guard_applies(options):
        return result
    check = _evaluate_runtime_destination_records(_runtime_destination_records(result, options), options)
    metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    metadata["runtime_scope_check"] = check
    result["scan_metadata"] = metadata
    if check.get("status") == "allowed":
        return result
    if check.get("status") == "degraded":
        metadata["runtime_scope_degraded"] = True
        metadata["runtime_scope_degraded_reason"] = ",".join(
            str(item) for item in check.get("warnings") or [] if str(item).strip()
        ) or "runtime_scope_degraded"
        return result

    blocked_by = check.get("blocked_by") if isinstance(check.get("blocked_by"), list) else []
    reason = ",".join(str(item) for item in blocked_by if str(item).strip()) or "runtime_scope_blocked"
    metadata["status"] = "failed"
    metadata["runtime_scope_blocked"] = True
    metadata["runtime_scope_block_reason"] = reason
    result["error"] = f"Runtime destination failed scope re-check: {reason}"
    result["findings"] = []
    if not isinstance(result.get("result"), dict):
        result["result"] = {}
    result["result"]["score"] = None
    result["result"]["grade"] = None
    return result


def _optional_uuid(value: Any) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


async def _record_runtime_scope_command_result(
    conn,
    *,
    scan_id: str | None,
    campaign_id: str | None,
    target: str | None,
    options: dict[str, Any],
    runtime_scope_check: dict[str, Any],
) -> str | None:
    status = "degraded" if runtime_scope_check.get("status") == "degraded" else "blocked"
    reasons = runtime_scope_check.get("warnings") if status == "degraded" else runtime_scope_check.get("blocked_by")
    reasons = reasons if isinstance(reasons, list) else []
    default_reason = "runtime_scope_degraded" if status == "degraded" else "runtime_scope_blocked"
    reason = ",".join(str(item) for item in reasons if str(item).strip()) or default_reason
    try:
        row = await conn.fetchrow(
            """
            INSERT INTO command_results (
                command, status, dry_run, risk_tier, operation_plan_id,
                scope_receipt_id, approval_receipt_id, campaign_id, scan_id,
                finding_ids, hypothesis_ids, evidence_object_ids, tool_receipt_ids,
                blocked_by, next_action, operator_message, result_json, created_by
            ) VALUES (
                $1,$2,$3,$4,$5,
                $6,$7,$8,$9,
                $10::jsonb,$11::jsonb,$12::jsonb,$13::jsonb,
                $14::jsonb,$15,$16,$17::jsonb,$18
            )
            RETURNING id
            """,
            "scan.runtime_scope_check",
            status,
            False,
            str((options or {}).get("risk_tier") or "active"),
            _optional_uuid((options or {}).get("operation_plan_id")),
            (options or {}).get("scope_receipt_id"),
            _optional_uuid((options or {}).get("approval_receipt_id")),
            _optional_uuid(campaign_id or (options or {}).get("campaign_id")),
            _optional_uuid(scan_id),
            json.dumps([]),
            json.dumps([]),
            json.dumps([]),
            json.dumps([]),
            json.dumps(reasons or [default_reason]),
            f"/scans/{scan_id}" if scan_id else None,
            (
                f"Degraded scan at runtime: destination DNS evidence was incomplete ({reason})"
                if status == "degraded"
                else f"Blocked scan at runtime: actual destination failed scope re-check ({reason})"
            ),
            json.dumps({
                "target": target,
                "runtime_scope_check": runtime_scope_check,
            }),
            "worker",
        )
        return str(row["id"]) if row and row.get("id") else None
    except Exception as exc:
        print(f"[worker] runtime scope command_result insert failed: {exc}", flush=True)
        return None


async def _record_runtime_scope_block_command_result(conn, **kwargs) -> str | None:
    """Backward-compatible wrapper for callers/tests using the phase-1 name."""
    return await _record_runtime_scope_command_result(conn, **kwargs)


def _failure_result_for_scan_error(result: dict[str, Any], error: Any, diag: Any) -> dict[str, Any]:
    metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
    metadata.setdefault("status", "failed")
    if diag is not None:
        metadata["failure_diagnostics"] = diag
    return {
        "error": error,
        "failure_diagnostics": diag,
        "tool_receipt_ids": result.get("tool_receipt_ids", []),
        "scan_metadata": metadata,
    }


def _unexpected_scan_exception_result(target: str, exc: Exception) -> dict[str, Any]:
    """Turn an unhandled scanner exception into a durable terminal failure.

    Letting the exception escape leaves the already-claimed scan in ``running``;
    a redelivered queue message then refuses the running row and acknowledges it.
    Preserve bounded diagnostics so the ordinary failure-finalization path can
    mark both PostgreSQL and Redis terminal instead.
    """
    error_type = type(exc).__name__
    message = str(exc).replace("\x00", "")[:1000]
    error = f"{error_type}: {message}" if message else error_type
    return {
        "target": target,
        "error": error,
        "result": {"score": None, "grade": None},
        "findings": [],
        "failure_diagnostics": {
            "failure_type": "unhandled_scan_exception",
            "exception_type": error_type,
        },
    }


_QUEUE_HANDOFF_CONFIRMATION_KEY = "queue_handoff_confirmed"
QUEUE_HANDOFF_CONFIRM_RECHECKS = 5
QUEUE_HANDOFF_CONFIRM_RECHECK_SECONDS = 0.1


def _queue_handoff_confirmation_marker(row: Any) -> bool | None:
    raw_options = _row_get(row, "options")
    options = parse_json_field(raw_options) if raw_options is not None else {}
    if not isinstance(options, dict) or _QUEUE_HANDOFF_CONFIRMATION_KEY not in options:
        return None
    return options.get(_QUEUE_HANDOFF_CONFIRMATION_KEY) is True


async def _confirmed_scan_handoff_status(scan_id: str) -> str:
    """Wait briefly for a two-phase queue handoff, then fail it closed.

    Legacy scans have no marker and remain claimable. Two-phase enqueue paths persist
    ``false`` before enqueue and flip it to ``true`` only after Redis acknowledges.
    """
    scan_uuid = uuid.UUID(str(scan_id))
    row = None
    for attempt in range(QUEUE_HANDOFF_CONFIRM_RECHECKS + 1):
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status, options, campaign_id FROM scans WHERE id=$1",
                scan_uuid,
            )
        if not row:
            return "missing"
        status = str(_row_get(row, "status") or "missing")
        marker = _queue_handoff_confirmation_marker(row)
        if marker is not False or status not in {"pending", "queued"}:
            return status
        if attempt < QUEUE_HANDOFF_CONFIRM_RECHECKS:
            await asyncio.sleep(QUEUE_HANDOFF_CONFIRM_RECHECK_SECONDS)

    async with db_pool.acquire() as conn:
        failed = await conn.fetchrow(
            """
            UPDATE scans
            SET status='failed', progress=100, current_phase='queue_failed',
                error_message='Queue handoff confirmation was not persisted before the worker deadline; active work was not started.',
                completed_at=NOW()
            WHERE id=$1 AND status IN ('pending','queued')
              AND options->>'queue_handoff_confirmed'='false'
            RETURNING status, campaign_id
            """,
            scan_uuid,
        )
        if failed:
            campaign_id = _row_get(failed, "campaign_id")
            if campaign_id:
                await conn.execute(
                    """
                    UPDATE scan_campaigns campaign
                    SET status='failed', completed_at=COALESCE(completed_at, NOW()), updated_at=NOW()
                    WHERE campaign.id=$1 AND campaign.status='active'
                      AND EXISTS (
                          SELECT 1 FROM scans owner
                          WHERE owner.id=$2 AND owner.campaign_id=campaign.id
                            AND owner.status='failed'
                      )
                      AND NOT EXISTS (
                          SELECT 1 FROM scans other
                          WHERE other.campaign_id=campaign.id AND other.id<>$2
                      )
                    """,
                    campaign_id,
                    scan_uuid,
                )
            return "failed"
        latest = await conn.fetchval("SELECT status FROM scans WHERE id=$1", scan_uuid)
        return str(latest or "missing")


async def _load_broker_result(job_data: dict[str, Any], scan_id: str) -> dict[str, Any]:
    """Claim an immutable HTTPS-broker result for normal control-plane ingestion."""
    try:
        result_id = uuid.UUID(str(job_data.get("_broker_result_id") or ""))
        lease_id = uuid.UUID(str(job_data.get("_broker_lease_id") or ""))
        expected_scan_id = uuid.UUID(str(scan_id))
    except ValueError as exc:
        raise RuntimeError("invalid broker result identity") from exc
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT r.result, r.result_sha256, l.scan_id, l.status
                FROM broker_job_results r
                JOIN broker_job_leases l ON l.id = r.lease_id
                WHERE r.id=$1 AND l.id=$2
                FOR UPDATE OF l
                """,
                result_id,
                lease_id,
            )
            if not row or row["scan_id"] != expected_scan_id:
                raise RuntimeError("broker result is not bound to this scan")
            if str(row["status"]) not in {"submitted", "ingesting", "completed", "failed"}:
                raise RuntimeError(f"broker result lease is {row['status']}")
            raw_result = row["result"]
            result = json.loads(raw_result) if isinstance(raw_result, str) else dict(raw_result or {})
            encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(encoded).hexdigest() != str(row["result_sha256"]):
                raise RuntimeError("broker result hash verification failed")
            await conn.execute(
                "UPDATE broker_job_leases SET status='ingesting' WHERE id=$1 AND status='submitted'",
                lease_id,
            )
    return result


async def _finish_broker_result_ingest(job_data: dict[str, Any]) -> None:
    raw_lease_id = str(job_data.get("_broker_lease_id") or "").strip()
    raw_result_id = str(job_data.get("_broker_result_id") or "").strip()
    if not raw_lease_id or not raw_result_id:
        return
    try:
        lease_id = uuid.UUID(raw_lease_id)
        result_id = uuid.UUID(raw_result_id)
    except ValueError:
        return
    async with db_pool.acquire() as conn:
        scan_status = await conn.fetchval(
            "SELECT status FROM scans WHERE id=(SELECT scan_id FROM broker_job_leases WHERE id=$1)",
            lease_id,
        )
        terminal = "failed" if str(scan_status) == "failed" else "cancelled" if str(scan_status) == "cancelled" else "completed"
        await conn.execute(
            """
            UPDATE broker_job_leases
            SET status=$2, completed_at=NOW()
            WHERE id=$1 AND status IN ('submitted','ingesting')
            """,
            lease_id,
            terminal,
        )
        await conn.execute(
            "UPDATE broker_job_results SET ingested_at=NOW() WHERE id=$1",
            result_id,
        )


def _device_score_with_web_findings(result: dict[str, Any]) -> None:
    findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    reachability = posture.get("reachability") if isinstance(posture.get("reachability"), dict) else {}
    completeness = posture.get("completeness") if isinstance(posture.get("completeness"), dict) else {}
    children = posture.get("web_dast_children") if isinstance(posture.get("web_dast_children"), dict) else {}
    # Older stored results predate the reachability receipt. Preserve their
    # existing post-processing semantics, but fail closed whenever a current
    # scan explicitly records that online status was not proven.
    if reachability and reachability.get("status") != "online":
        result.setdefault("result", {})["score"] = None
        result["result"]["grade"] = None
        decision = posture.get("decision") if isinstance(posture.get("decision"), dict) else {}
        decision["decision"] = "needs_review"
        decision["rationale"] = str(
            reachability.get("reason")
            or "Device reachability was not positively confirmed; no posture score was issued."
        )
        posture["decision"] = decision
        result["device_posture"] = posture
        return
    weights = {"critical": 30, "high": 18, "medium": 8, "low": 3, "info": 0}
    score = max(0, 100 - sum(weights.get(str(item.get("severity") or "info").lower(), 0) for item in findings if isinstance(item, dict)))
    execution_incomplete = not bool(completeness.get("execution_complete", completeness.get("complete", False)))
    incomplete = (
        not bool(completeness.get("complete", False))
        or bool(completeness.get("web_probe_truncated", False))
        or int(children.get("failed") or 0) > 0
        or int(children.get("truncated") or 0) > 0
    )
    if execution_incomplete:
        score = min(score, 69)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    result.setdefault("result", {})["score"] = score
    result["result"]["grade"] = grade
    blocking = []
    review = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        disposition = str(evidence.get("disposition") or "").lower()
        severity = str(item.get("severity") or "info").lower()
        tool = str(item.get("tool") or "")
        if disposition in {"deny", "require"} or (
            tool != "device_policy" and severity in {"critical", "high"}
        ):
            blocking.append(item)
        elif severity != "info" or disposition == "review":
            review.append(item)
    decision = posture.get("decision") if isinstance(posture.get("decision"), dict) else {}
    if blocking:
        decision["decision"] = "block"
        decision["rationale"] = f"{len(blocking)} blocking connected-device finding(s) require remediation."
    elif incomplete:
        decision["decision"] = "needs_review"
        decision["rationale"] = "One or more required device or web-origin checks were incomplete."
    elif review:
        decision["decision"] = "needs_review"
        decision["rationale"] = f"{len(review)} confirmed connected-device finding(s) require review."
    else:
        decision["decision"] = "allow"
        decision["rationale"] = "Device services and discovered web origins conform to policy."
    posture["decision"] = decision
    result["device_posture"] = posture


async def run_device_web_children(
    *,
    parent_scan_id: str,
    device_target_id: str,
    parent_job_id: str,
    parent_options: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    """Run bounded device-owned web and imported-request checks without creating Web targets."""
    posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
    origins = posture.get("web_origins") if isinstance(posture.get("web_origins"), list) else []
    limit = max(0, min(int(parent_options.get("max_web_origins") or 0), 32))
    enabled = bool(parent_options.get("include_web_dast")) and limit > 0
    selected = [origin for origin in origins if isinstance(origin, dict) and origin.get("origin")][:limit] if enabled else []
    request_collections = [
        dict(item) for item in parent_options.get("_resolved_device_request_collections", [])
        if isinstance(item, dict)
    ][:8]
    child_summary = {
        "enabled": enabled,
        "requested": len(selected),
        "completed": 0,
        "failed": 0,
        "truncated": max(0, len(origins) - len(selected)) if enabled else 0,
        "scan_type": str(parent_options.get("web_scan_type") or "standard"),
        "children": [],
    }
    if not selected:
        posture["web_dast_children"] = child_summary
        posture["imported_request_assessment"] = {
            "collections": [
                {
                    "collection_id": str(item.get("collection_id") or ""),
                    "name": str(item.get("name") or "Imported requests"),
                    "document_sha256": str(item.get("document_sha256") or ""),
                }
                for item in request_collections
            ],
            "executed": 0,
            "skipped": 0,
            "findings_count": 0,
            "reason": "no_discovered_web_origin" if request_collections else None,
            "allow_state_changing_requests": bool(parent_options.get("allow_state_changing_requests")),
            "allow_untrusted_tls_credentials": bool(parent_options.get("allow_untrusted_tls_credentials")),
        }
        result["device_posture"] = posture
        _device_score_with_web_findings(result)
        return result

    web_scan_type = str(parent_options.get("web_scan_type") or "standard").lower()
    if web_scan_type not in {"quick", "standard", "deep"}:
        web_scan_type = "standard"
    await update_scan_progress(parent_scan_id, "device_web_dast", 92, job_id=parent_job_id)
    _append_device_activity(
        parent_scan_id,
        kind="web",
        phase="device_web_dast",
        progress=92,
        message=f"Testing {len(selected)} discovered web interface(s)",
        details={"web_origins": len(selected), "collection_count": len(request_collections)},
    )
    merged_findings = result.get("findings") if isinstance(result.get("findings"), list) else []
    web_credentials = [
        dict(item) for item in parent_options.get("_resolved_device_credentials", [])
        if isinstance(item, dict) and item.get("role") == "web"
    ]

    for index, origin_info in enumerate(selected, start=1):
        if _scan_cancel_requested(parent_scan_id):
            child_summary["cancelled"] = True
            child_summary["truncated"] += len(selected) - index + 1
            break
        origin = str(origin_info["origin"])
        _append_device_activity(
            parent_scan_id,
            kind="web_origin",
            phase="device_web_dast",
            progress=min(98, 92 + int((index - 1) / max(1, len(selected)) * 6)),
            message="Running bounded web and imported-request checks",
            details={"origin": origin},
        )
        origin_port = int(origin_info.get("port") or urllib.parse.urlsplit(origin).port or 0)
        web_credential = next((
            item for item in web_credentials
            if item.get("port") is None or int(item.get("port")) == origin_port
        ), None)
        child_scan_id, child_job_id = str(uuid.uuid4()), str(uuid.uuid4())
        child_options = {
            "scan_type": web_scan_type,
            "run_kind": "device_web_dast",
            "active": False,
            "xss": False,
            "sqli": False,
            "subfinder": False,
            "enhanced_dns": False,
            "device_parent_scan_id": parent_scan_id,
            "device_target_id": device_target_id,
            "device_origin": origin_info,
            "device_credential_profile_ref": (
                {
                    "profile_id": str(web_credential.get("profile_id") or ""),
                    "auth_kind": str(web_credential.get("auth_kind") or ""),
                }
                if web_credential else None
            ),
            "device_request_collection_refs": [
                {
                    "collection_id": str(item.get("collection_id") or ""),
                    "name": str(item.get("name") or "Imported requests"),
                    "document_sha256": str(item.get("document_sha256") or ""),
                }
                for item in request_collections
            ],
            "allow_state_changing_requests": bool(parent_options.get("allow_state_changing_requests")),
            "request_budget_mode": "enforce",
            "custom_budget": {
                "max_duration_minutes": 20 if web_scan_type == "deep" else 10,
                "max_urls": 250,
                # Deep child scans may replay up to 2000 imported requests
                # (IMPORTED_REQUEST_LIMITS["deep"]); the budget must not silently
                # cap the scanner-side limit below it.
                "request_max": 3000 if web_scan_type == "deep" else 750,
                "active_max_endpoints": 0,
            },
        }
        for guard_key in (
            "runtime_scope_guard",
            "scope_receipt_id",
            "approval_receipt_id",
            "risk_tier",
            "operation_plan_id",
        ):
            if parent_options.get(guard_key) is not None:
                child_options[guard_key] = copy.deepcopy(parent_options[guard_key])
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO scans (
                    id, target_id, ai_target_id, device_target_id, target_url, job_id,
                    status, started_at, options, scan_type, run_kind, subject_ref,
                    parent_scan_id, scan_role, progress, current_phase
                ) VALUES ($1,NULL,NULL,$2,$3,$4,'running',NOW(),$5,$6,'device_web_dast',$7,$8,'device_web_origin',5,'starting')
                """,
                uuid.UUID(child_scan_id), uuid.UUID(device_target_id), origin, child_job_id,
                json.dumps(child_options), web_scan_type,
                f"device_target:{device_target_id}:web_origin:{hashlib.sha256(origin.encode()).hexdigest()[:20]}",
                uuid.UUID(parent_scan_id),
            )
        child_job_key = f"job:{child_job_id}"
        child_heartbeat_stop = threading.Event()
        get_redis().hset(child_job_key, mapping={
            "status": "running",
            "scan_id": child_scan_id,
            "target": origin,
            "started_at": utc_now_iso(),
            "heartbeat": utc_now_iso(),
        })
        child_heartbeat_thread = threading.Thread(
            target=send_heartbeats,
            args=(child_job_id, child_heartbeat_stop),
            daemon=True,
        )
        child_heartbeat_thread.start()
        started = utc_now()
        try:
            child_result = await run_pinned_device_web_scan(
                origin_info,
                profile=web_scan_type,
                credential=web_credential,
                request_collections=request_collections,
                allow_state_changing_requests=bool(parent_options.get("allow_state_changing_requests")),
                allow_untrusted_tls_credentials=bool(parent_options.get("allow_untrusted_tls_credentials")),
                default_origin=index == 1,
                cancel_check=lambda: asyncio.to_thread(_scan_cancel_requested, parent_scan_id),
                request_budget=int(child_options["custom_budget"]["request_max"]),
            )
            child_result = _apply_runtime_scope_guard_to_result(child_result, child_options)
            child_error = child_result.get("error") if isinstance(child_result, dict) else "invalid child result"
        except Exception as exc:
            child_result = _unexpected_scan_exception_result(origin, exc)
            child_error = str(child_result.get("error") or exc)
        finally:
            child_heartbeat_stop.set()
            child_heartbeat_thread.join(timeout=2)
        completed = utc_now()
        duration = int((completed - started).total_seconds())
        child_findings = child_result.get("findings") if isinstance(child_result.get("findings"), list) else []
        child_http = child_result.get("http") if isinstance(child_result.get("http"), dict) else {}
        child_runtime_destination = {
            "label": f"device_web_child_{index}",
            "url": str(child_http.get("request_url") or origin),
            "final_url": str(child_http.get("final_url") or origin),
            "redirect_chain": list(child_http.get("redirect_chain") or []),
            "remote_ip": child_http.get("remote_ip") or origin_info.get("connect_address"),
            "resolved_host": urllib.parse.urlsplit(origin).hostname,
            "source": "device_web_dast",
        }
        child_score = (child_result.get("result") or {}).get("score") if isinstance(child_result.get("result"), dict) else None
        child_grade = (child_result.get("result") or {}).get("grade") if isinstance(child_result.get("result"), dict) else None
        async with db_pool.acquire() as conn:
            child_updated = await conn.fetchval(
                """UPDATE scans SET status=$1, result=$2, score=$3, grade=$4,
                       findings_count=$5, error_message=$6, completed_at=$7,
                       duration_seconds=$8, progress=100, current_phase=$1
                   WHERE id=$9 AND status NOT IN ('cancelled','failed')
                   RETURNING id""",
                "failed" if child_error else "completed", json.dumps(child_result), child_score,
                child_grade, len(child_findings), str(child_error)[:2000] if child_error else None,
                completed, duration, uuid.UUID(child_scan_id),
            )
        if not child_updated:
            child_error = "Cancelled by user"
            child_findings = []
            child_score = None
            child_grade = None
        await persist_result_artifact(child_result, child_job_id, child_scan_id)
        child_entry = {
            "scan_id": child_scan_id,
            "origin": origin,
            "status": "cancelled" if not child_updated else "failed" if child_error else "completed",
            "score": child_score,
            "grade": child_grade,
            "findings_count": len(child_findings),
            "error": str(child_error)[:500] if child_error else None,
            "credential_profile_id": str(web_credential.get("profile_id") or "") if web_credential else None,
            "credentials_attempted": bool((child_result.get("device_web") or {}).get("credentials_attempted")),
            "authenticated": bool((child_result.get("device_web") or {}).get("authentication_succeeded")),
            "tls_assessment": {
                key: value
                for key, value in (((child_result.get("device_web") or {}).get("tls_assessment") or {}).items())
                if key in {"trusted", "verification_error", "verification_code", "protocol", "cipher"}
            },
            "imported_requests": {
                key: value
                for key, value in (((child_result.get("device_web") or {}).get("imported_requests") or {}).items())
                if key in {"executed", "skipped", "skipped_actionable", "routed_elsewhere", "findings_count", "cancelled", "profile", "request_limit"}
            },
            "runtime_destination": child_runtime_destination,
        }
        child_summary["children"].append(child_entry)
        get_redis().hset(child_job_key, mapping={
            "status": child_entry["status"],
            "progress": "100",
            "current_phase": child_entry["status"],
            "completed_at": completed.isoformat(),
        })
        get_redis().expire(child_job_key, 86400)
        if not child_updated:
            child_summary["cancelled"] = True
            child_summary["truncated"] += len(selected) - index
            break
        if child_error:
            child_summary["failed"] += 1
            _append_device_activity(
                parent_scan_id,
                kind="warning",
                phase="device_web_dast",
                message="A discovered web interface check failed",
                details={"origin": origin, "status": child_entry["status"], "error_type": child_entry.get("error")},
            )
        else:
            child_summary["completed"] += 1
            imported_activity = child_entry.get("imported_requests") or {}
            _append_device_activity(
                parent_scan_id,
                kind="web_result",
                phase="device_web_dast",
                message="Completed web and API checks for a discovered interface",
                details={
                    "origin": origin,
                    "status": child_entry["status"],
                    "executed_requests": int(imported_activity.get("executed") or 0),
                    "skipped_requests": int(imported_activity.get("skipped") or 0),
                    "findings_count": len(child_findings),
                },
            )
            for finding in child_findings:
                if not isinstance(finding, dict):
                    continue
                merged = dict(finding)
                original_fingerprint = str(merged.get("fingerprint") or generate_finding_fingerprint(merged))
                merged["fingerprint"] = hashlib.sha256(f"device-web|{origin}|{original_fingerprint}".encode()).hexdigest()
                merged["source"] = "device"
                merged["tool"] = str(merged.get("tool") or "web_dast")
                evidence = merged.get("evidence") if isinstance(merged.get("evidence"), dict) else {"original": merged.get("evidence")}
                evidence["device_web_dast"] = {
                    "parent_scan_id": parent_scan_id,
                    "child_scan_id": child_scan_id,
                    "origin": origin,
                    "connect_address": origin_info.get("connect_address"),
                    "host_header": origin_info.get("host_header"),
                    "sni": origin_info.get("sni"),
                }
                merged["evidence"] = evidence
                merged_findings.append(merged)
        await update_scan_progress(
            parent_scan_id,
            "device_web_dast",
            min(98, 92 + int(index / max(1, len(selected)) * 6)),
            job_id=parent_job_id,
        )

    result["findings"] = merged_findings
    posture["runtime_destinations"] = [
        item for item in posture.get("runtime_destinations") or []
        if isinstance(item, dict)
    ] + [
        child.get("runtime_destination")
        for child in child_summary.get("children") or []
        if isinstance(child, dict) and isinstance(child.get("runtime_destination"), dict)
    ]
    posture["web_dast_children"] = child_summary
    posture["imported_request_assessment"] = {
        "collections": [
            {
                "collection_id": str(item.get("collection_id") or ""),
                "name": str(item.get("name") or "Imported requests"),
                "document_sha256": str(item.get("document_sha256") or ""),
            }
            for item in request_collections
        ],
        "executed": sum(int((child.get("imported_requests") or {}).get("executed") or 0) for child in child_summary.get("children") or []),
        "skipped": sum(int((child.get("imported_requests") or {}).get("skipped_actionable") or 0) for child in child_summary.get("children") or []),
        "routed_elsewhere": sum(int((child.get("imported_requests") or {}).get("routed_elsewhere") or 0) for child in child_summary.get("children") or []),
        "findings_count": sum(int((child.get("imported_requests") or {}).get("findings_count") or 0) for child in child_summary.get("children") or []),
        "allow_state_changing_requests": bool(parent_options.get("allow_state_changing_requests")),
    }
    metadata = result.setdefault("scan_metadata", {})
    metadata["credentials_attempted"] = bool(metadata.get("credentials_attempted")) or any(
        bool(child.get("credentials_attempted"))
        for child in child_summary.get("children") or []
        if isinstance(child, dict)
    )
    if parent_options.get("allow_state_changing_requests"):
        metadata["active_testing"] = True
        metadata["state_changing_requests_authorized"] = True
    result["device_posture"] = posture
    _device_score_with_web_findings(result)
    return result


def _scan_replay_receipt_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Keep Scan results bounded while the complete receipt remains durable."""
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": receipt.get("receipt_hash"),
        "status": receipt.get("status"),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "input_digest": receipt.get("input_digest"),
        "budget_reservation_id": receipt.get("budget_reservation_id"),
        "budget_reservation_state": receipt.get("budget_reservation_state"),
        "budget_reserved": dict(receipt.get("budget_reserved") or {}),
        "budget_consumed": dict(receipt.get("budget_consumed") or {}),
        "observation_count": len(receipt.get("observations") or []),
        "errors": list(receipt.get("errors") or [])[:50],
    }


def _scan_capability_receipt_reference(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Expose one bounded pointer while the complete receipt stays durable."""
    return {
        "receipt_id": receipt.get("receipt_id"),
        "receipt_hash": receipt.get("receipt_hash"),
        "status": receipt.get("status"),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "input_digest": receipt.get("input_digest"),
        "budget_reservation_id": receipt.get("budget_reservation_id"),
        "budget_reservation_state": receipt.get("budget_reservation_state"),
        "budget_reserved": dict(receipt.get("budget_reserved") or {}),
        "budget_consumed": dict(receipt.get("budget_consumed") or {}),
        "observation_count": len(receipt.get("observations") or []),
        "errors": list(receipt.get("errors") or [])[:20],
    }


def _scan_subdomain_summary_from_stored(
    stored: Any,
    *,
    root_domain: str,
    idempotent_redelivery: bool = False,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping) and item.get("kind") == "subdomain"
    ]
    return {
        "schema_version": "canonical-scan-subdomain-discovery/v1",
        "enabled": True,
        "status": status,
        "root_domain": root_domain,
        "observations": observations[:5000],
        "observation_count": len(observations),
        "observations_truncated": len(observations) > 5000,
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": stored.record.terminal,
        "idempotent_redelivery": bool(idempotent_redelivery),
        "network_binding": "root_domain_target_binding",
        "automatically_scanned_discovered_hosts": False,
    }


def _skipped_scan_subdomain_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-subdomain-discovery/v1",
        "enabled": False,
        "status": "skipped",
        "reason": reason,
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "durable_budget_settled": True,
        "network_binding": "root_domain_target_binding",
        "automatically_scanned_discovered_hosts": False,
    }


async def _reuse_placed_scan_subdomain_discovery(
    *,
    parent_scan_id: str,
    source_scan_id: str,
    expected_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Reuse a placed discovery receipt without repeating target traffic."""
    try:
        parent_uuid = uuid.UUID(str(parent_scan_id))
        source_uuid = uuid.UUID(str(source_scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCapabilityContractError(
            "placed subdomain discovery identity is invalid"
        ) from exc
    receipt_ref = (
        dict(expected_summary.get("receipt") or {})
        if isinstance(expected_summary.get("receipt"), Mapping) else {}
    )
    reservation_id = str(
        receipt_ref.get("budget_reservation_id") or ""
    ).strip()
    receipt_hash = str(receipt_ref.get("receipt_hash") or "").strip().lower()
    receiptless_failure = bool(
        expected_summary.get("schema_version")
        == "canonical-scan-subdomain-discovery/v1"
        and expected_summary.get("enabled") is True
        and str(expected_summary.get("status") or "") in {"failed", "blocked"}
        and not expected_summary.get("observations")
        and int(expected_summary.get("observation_count") or 0) == 0
        and expected_summary.get("durable_budget_settled") is False
    )
    if (
        (not reservation_id or not re.fullmatch(r"[0-9a-f]{64}", receipt_hash))
        and not receiptless_failure
    ):
        raise ScanCapabilityContractError(
            "placed subdomain discovery has no durable receipt"
        )
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT status, result
            FROM scans
            WHERE id=$1 AND parent_scan_id=$2 AND scan_role=$3
              AND status IN ('completed','failed')
            """,
            source_uuid,
            parent_uuid,
            parallel_scan.PARALLEL_DISCOVERY_ROLE,
        )
        if not row:
            raise ScanCapabilityContractError(
                "placed subdomain discovery is unavailable"
            )
        source_result = _as_report_dict(row.get("result")) or {}
        durable_summary = source_result.get("subdomain_discovery")
        if (
            not isinstance(durable_summary, Mapping)
            or dict(durable_summary) != dict(expected_summary)
        ):
            raise ScanCapabilityContractError(
                "placed subdomain discovery summary changed before reuse"
            )
        if receiptless_failure:
            reused = dict(expected_summary)
            reused["idempotent_redelivery"] = True
            reused["reused_from_placed_discovery"] = True
            reused["source_scan_id"] = str(source_uuid)
            return reused
        stored = await PostgresBudgetReservationStore().load(
            conn, reservation_id, for_update=False,
        )
    if (
        stored is None
        or stored.record.owner_kind != "scan"
        or stored.record.owner_id != str(source_uuid)
        or stored.record.capability_name != "subdomains.discover"
        or not stored.record.terminal
        or not stored.receipt
        or str(stored.receipt.get("receipt_hash") or "").lower() != receipt_hash
        or str(stored.receipt.get("receipt_id") or "")
        != str(receipt_ref.get("receipt_id") or "")
        or str(stored.receipt.get("budget_reservation_state") or "")
        != stored.record.status
    ):
        raise ScanCapabilityContractError(
            "placed subdomain discovery receipt is not trustworthy"
        )
    reused = dict(expected_summary)
    reused["idempotent_redelivery"] = True
    reused["reused_from_placed_discovery"] = True
    reused["source_scan_id"] = str(source_uuid)
    return reused


async def _execute_reserved_scan_capability(
    *,
    admission: Any,
    execution: Any,
    scan_id: str,
    job_id: str,
    capability_name: str,
    capability_args: Mapping[str, Any],
    action_id: str,
    target_binding: TargetBinding | None = None,
    reservation_limits: Mapping[str, int] | None = None,
    scan_runner: Callable[[Mapping[str, int]], Awaitable[Mapping[str, Any]]] | None = None,
    scan_result_holder: dict[str, Any] | None = None,
    scanner_process_payload: Mapping[str, Any] | None = None,
    scanner_process_runner: Callable[..., Awaitable[Mapping[str, Any]]] | None = None,
    scanner_result_holder: dict[str, Any] | None = None,
    inline_operation: Callable[[], Awaitable[Mapping[str, Any]]] | None = None,
    canonical_action: Any | None = None,
) -> tuple[Any, bool]:
    """Reserve, execute, and reconcile one target-bound Scan capability."""
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCapabilityContractError(
            "Scan capability owner ID is invalid"
        ) from exc
    if not admission.canonical or admission.plan is None:
        raise ScanCapabilityContractError(
            "Scan capability execution requires canonical authority"
        )

    base_target = execution.target_binding
    target = target_binding or base_target
    if target_binding is not None and (
        target.target_id != base_target.target_id
        or target.target_kind != base_target.target_kind
        or target.canonical_host != base_target.canonical_host
        or target.allowed_origins != base_target.allowed_origins
        or target.allowed_root_domains != base_target.allowed_root_domains
        or target.environment != base_target.environment
        or target.scope_receipt_id != base_target.scope_receipt_id
        or not set(target.allowed_addresses).issubset(
            base_target.allowed_addresses
        )
    ):
        raise ScanCapabilityContractError(
            "Scan capability target must be an exact-address subset of its binding"
        )
    if canonical_action is not None:
        if (
            str(getattr(canonical_action, "action_id", "")) != action_id
            or str(getattr(canonical_action, "capability_name", ""))
            != capability_name
            or str(getattr(canonical_action, "target_binding_digest", ""))
            != target.digest
        ):
            raise ScanCapabilityContractError(
                "canonical Scan action differs from capability dispatch authority"
            )
    policy = admission.plan.policy
    deterministic_process = scan_runner is not None
    external_process = (
        scanner_process_payload is not None
        or scanner_process_runner is not None
    )
    internal_inline = inline_operation is not None
    if external_process and (
        scanner_process_payload is None or scanner_process_runner is None
    ):
        raise ScanCapabilityContractError(
            "external Scan process requires payload and runner"
        )
    if sum((deterministic_process, external_process, internal_inline)) > 1:
        raise ScanCapabilityContractError(
            "Scan capability cannot use multiple execution adapters"
        )
    if deterministic_process and capability_name != "scan.execute":
        raise ScanCapabilityContractError(
            "deterministic Scan runner requires scan.execute"
        )
    if internal_inline and capability_name not in {
        "auth.session.establish", "authz.verify", "dns.inspect", "http.request",
        "tls.inspect",
    }:
        raise ScanCapabilityContractError(
            "unsupported inline Scan capability adapter"
        )
    adapter = None
    prepared: PreparedExecution | None = None
    runtime_budget: dict[str, int] | None = None
    specification = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
    if internal_inline:
        prepared = prepare_scan_inline_capability(
            specification=specification,
            target=target,
            args=dict(capability_args),
            policy=policy,
        )
    elif external_process:
        prepared = prepare_scan_external_capability(
            specification=specification,
            target=target,
            args=dict(capability_args),
            policy=policy,
        )
    elif not deterministic_process:
        adapter = network_capability_adapter(capability_name)
        prepared = adapter.prepare(
            target=target,
            args=dict(capability_args),
            policy=policy,
        )
    effective_budget = execution.payload()["execution_budget"]
    limits = scan_budget_ledger_limits(
        effective_budget,
        allow_zero=execution.shard_authority is not None,
    )
    request_limits = dict(limits)
    if canonical_action is not None:
        reservation_limits = dict(canonical_action.requested_budget)
    if reservation_limits is not None:
        for raw_name, raw_amount in reservation_limits.items():
            name = str(raw_name or "").strip()
            if name not in request_limits:
                raise ScanCapabilityContractError(
                    f"unknown Scan capability reservation dimension: {name}"
                )
            amount = int(raw_amount)
            if amount <= 0:
                raise ScanCapabilityContractError(
                    f"Scan capability reservation limit must be positive: {name}"
                )
            request_limits[name] = min(request_limits[name], amount)
    if prepared is not None:
        prepared = fit_prepared_scan_capability(
            prepared, ledger_limits=request_limits,
        )
    worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"
    action_digest = ""
    requested_budget: dict[str, int] = {}
    lease_seconds = 90
    store = PostgresBudgetReservationStore()
    persisted = None

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            locked = await conn.fetchrow(
                "SELECT status, policy_json, budget_json, budget_used_json "
                "FROM scans WHERE id=$1 FOR UPDATE",
                scan_uuid,
            )
            if not locked or str(locked["status"] or "") != "running":
                raise ScanCapabilityContractError(
                    "Scan stopped before capability admission"
                )
            canonical_plan = admission.plan.canonical_dict()
            if (
                _worker_json_object(locked["policy_json"])
                != canonical_plan["policy"]
                or _worker_json_object(locked["budget_json"])
                != canonical_plan["budget"]
            ):
                raise ScanCapabilityContractError(
                    "persisted Scan authority changed before capability execution"
                )
            if canonical_action is not None:
                authority_decision = await revalidate_scan_action_authority(
                    conn,
                    action=canonical_action,
                    target_binding=target,
                    scope_receipt_id=(
                        target.scope_receipt_id or policy.scope_receipt_id
                    ),
                    approval_receipt_id=policy.approval_receipt_id,
                )
                if authority_decision is not ActionAuthorityDecision.ALLOWED:
                    raise ScanCapabilityContractError(
                        "Scan action authority rejected at dispatch: "
                        f"{authority_decision.value}"
                    )
            current_used = _worker_json_object(locked["budget_used_json"])
            current_ledger = {
                name: int(current_used.get(name) or 0) for name in limits
            }
            if deterministic_process:
                existing = await store.load_by_action(
                    conn,
                    owner_kind="scan",
                    owner_id=scan_id,
                    action_id=action_id,
                    for_update=True,
                )
                if existing is not None:
                    if existing.record.terminal:
                        existing_receipt = dict(existing.receipt or {})
                        redacted = _worker_json_object(
                            existing_receipt.get("redacted_execution")
                        )
                        receipt_input = _worker_json_object(
                            redacted.get("input")
                        )
                        if (
                            existing.record.capability_name != "scan.execute"
                            or existing_receipt.get("capability_name")
                            != "scan.execute"
                            or str(existing_receipt.get("scan_id") or "")
                            != str(scan_id)
                            or str(existing_receipt.get("target_id") or "")
                            != str(target.target_id)
                            or receipt_input.get("execution_plan_digest")
                            != admission.plan.digest
                            or receipt_input.get("target_binding_digest")
                            != target.digest
                            or dict(existing_receipt.get("budget_reserved") or {})
                            != dict(existing.record.requested)
                            or str(existing_receipt.get("receipt_hash") or "")
                            != str(existing.record.execution_receipt_hash or "")
                        ):
                            raise ReservationConflict(
                                "deterministic Scan terminal receipt is not trustworthy"
                            )
                        return existing, True
                    raise ReservationConflict(
                        "deterministic Scan already has an active reservation"
                    )
                prepared, runtime_budget = prepare_scan_process_capability(
                    execution_plan_digest=admission.plan.digest,
                    target=target,
                    stage_rows=execution.stage_rows(),
                    ledger_limits=limits,
                    consumed=current_ledger,
                    allow_state_changing_http=bool(
                        policy.active_testing
                        and policy.allow_state_changing_http
                    ),
                )
            if prepared is None:
                raise ScanCapabilityContractError(
                    "Scan capability preparation failed"
                )
            action_digest = scan_capability_action_digest(
                scan_id=scan_id,
                execution_plan_digest=admission.plan.digest,
                target=target,
                prepared=prepared,
            )
            requested_budget = dict(prepared.estimated_budget)
            if canonical_action is not None:
                expected_adapter = str(
                    canonical_action.placement.get("adapter_name") or ""
                )
                expected_version = str(
                    canonical_action.placement.get("adapter_version") or ""
                )
                if (
                    prepared.adapter_name != expected_adapter
                    or prepared.adapter_version != expected_version
                    or requested_budget != dict(canonical_action.requested_budget)
                ):
                    raise ScanCapabilityContractError(
                        "prepared capability differs from canonical Scan action"
                    )
                action_digest = str(canonical_action.action_digest)
            lease_seconds = max(
                90,
                min(
                    3_600,
                    int(requested_budget.get("tool_wall_seconds") or 1) + 30,
                ),
            )
            requested = DurableBudgetReservation.request(
                owner_kind="scan",
                owner_id=scan_id,
                capability_name=prepared.capability_name,
                amounts=requested_budget,
                reservation_id=str(uuid.uuid4()),
            )
            stored = await store.create_requested(
                conn,
                action_id=action_id,
                action_digest=action_digest,
                record=requested,
            )
            if stored.record.terminal:
                return stored, True
            if stored.record.status != "requested":
                raise ReservationConflict(
                    "Scan capability already has an active reservation"
                )
            try:
                reserved, held_ledger = stored.record.reserve_against(
                    limits=limits,
                    consumed=current_ledger,
                    lease_seconds=lease_seconds,
                )
            except BudgetExceeded as exc:
                finished_at = datetime.now(timezone.utc)
                zero_actual = {name: 0 for name in requested_budget}
                blocked_receipt = CapabilityReceipt(
                    receipt_id=str(uuid.uuid4()),
                    capability_name=prepared.capability_name,
                    adapter_name=prepared.adapter_name,
                    adapter_version=prepared.adapter_version,
                    target_id=target.target_id,
                    scan_id=scan_id,
                    worker_id=worker_id,
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                    status="blocked",
                    input_digest=action_digest,
                    parser_version=prepared.parser_version,
                    started_at=finished_at.isoformat(),
                    finished_at=finished_at.isoformat(),
                    redacted_execution=dict(prepared.redacted_execution),
                    budget_reservation_id=stored.record.reservation_id,
                    budget_reservation_state="failed",
                    budget_reserved=requested_budget,
                    budget_consumed=zero_actual,
                    observations=(),
                    errors=(
                        "budget_exhausted:"
                        + next(iter(exc.shortages), "unknown"),
                    ),
                )
                failed = stored.record.fail(
                    reason="budget_exhausted_before_execution",
                    actual=zero_actual,
                    execution_receipt_hash=blocked_receipt.receipt_hash,
                    execution_may_have_started=False,
                    now=finished_at,
                )
                blocked = await store.persist_terminal(
                    conn,
                    previous=stored,
                    terminal=failed,
                    ledger_after_settlement=current_ledger,
                    receipt=blocked_receipt,
                )
                return blocked, False
            persisted = await store.persist_transition(
                conn,
                previous=stored,
                current=reserved,
                ledger_after_hold=held_ledger,
            )
            current_used.update(held_ledger)
            await conn.execute(
                "UPDATE scans SET budget_used_json=$2 WHERE id=$1",
                scan_uuid,
                json.dumps(current_used),
            )

    async with db_pool.acquire() as conn:
        async with conn.transaction():
            owner = await conn.fetchrow(
                "SELECT status FROM scans WHERE id=$1 FOR UPDATE", scan_uuid,
            )
            if not owner or str(owner["status"] or "") != "running":
                raise ScanCapabilityContractError(
                    "Scan stopped before capability dispatch"
                )
            latest = await store.load(
                conn, persisted.record.reservation_id, for_update=True,
            )
            if (
                latest is None
                or latest.record.state_digest != persisted.record.state_digest
                or latest.action_digest != action_digest
            ):
                raise ReservationConflict(
                    "Scan capability reservation changed before dispatch"
                )
            running = latest.record.start(
                worker_id=worker_id, lease_seconds=lease_seconds,
            )
            persisted = await store.persist_transition(
                conn, previous=latest, current=running,
            )

    async def heartbeat_reservation() -> None:
        nonlocal persisted
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                owner = await conn.fetchrow(
                    "SELECT status FROM scans WHERE id=$1 FOR UPDATE", scan_uuid,
                )
                if not owner or str(owner["status"] or "") != "running":
                    raise ReservationStoreError(
                        "Scan stopped during capability execution"
                    )
                latest = await store.load(
                    conn, persisted.record.reservation_id, for_update=True,
                )
                if (
                    latest is None
                    or latest.record.state_digest != persisted.record.state_digest
                    or latest.record.worker_id != worker_id
                ):
                    raise ReservationConflict(
                        "Scan capability reservation changed before heartbeat"
                    )
                heartbeat = latest.record.heartbeat(
                    worker_id=worker_id, lease_seconds=lease_seconds,
                )
                persisted = await store.persist_transition(
                    conn, previous=latest, current=heartbeat,
                )

    if prepared is None:
        raise ScanCapabilityContractError("Scan capability preparation was lost")
    executable_adapter: Any
    if deterministic_process:
        if runtime_budget is None or scan_runner is None:
            raise ScanCapabilityContractError(
                "deterministic Scan runtime budget is unavailable"
            )

        async def execute_scan_process() -> Mapping[str, Any]:
            return await scan_runner(runtime_budget)

        executable_adapter = DeterministicScanExecutionAdapter(
            specification=agent_tools.CAPABILITY_REGISTRY.require(
                capability_name
            ),
            scan_runner=execute_scan_process,
            requested_budget=persisted.record.requested,
            redacted_execution=prepared.redacted_execution,
        )
    elif external_process:
        executable_adapter = ScannerExecutionAdapter(
            specification=specification,
            process_payload=dict(scanner_process_payload or {}),
            process_runner=scanner_process_runner,
            requested_budget=persisted.record.requested,
            redacted_execution=prepared.redacted_execution,
        )
    elif internal_inline:
        if inline_operation is None:
            raise ScanCapabilityContractError(
                "inline Scan capability operation is unavailable"
            )
        inline_adapter = (
            AuthSessionExecutionAdapter
            if capability_name == "auth.session.establish"
            else AuthzVerificationExecutionAdapter
            if capability_name == "authz.verify"
            else HttpRequestExecutionAdapter
            if capability_name == "http.request"
            else DnsInspectionExecutionAdapter
            if capability_name == "dns.inspect"
            else TlsInspectionExecutionAdapter
        )
        executable_adapter = inline_adapter(
            specification=specification,
            operation=inline_operation,
            requested_budget=persisted.record.requested,
            redacted_execution=prepared.redacted_execution,
        )
    else:
        if adapter is None:
            raise ScanCapabilityContractError(
                "network Scan capability adapter is unavailable"
            )
        executable_adapter = NetworkExecutionAdapter(
            prepared=prepared,
            parser=adapter,
            command_runner=run_streaming,
            max_stdout_bytes=_AGENT_TOOL_OUTPUT_BYTES,
            max_stderr_bytes=min(_AGENT_TOOL_OUTPUT_BYTES, 20_000),
        )

    started_at = persisted.record.started_at or datetime.now(timezone.utc)
    execution_result = await CapabilityExecutor().execute(
        CapabilityExecutionContext(
            specification=agent_tools.CAPABILITY_REGISTRY.require(
                capability_name
            ),
            target=target,
            requested_budget=persisted.record.requested,
            adapter_managed_cancellation=(
                deterministic_process or external_process
            ),
        ),
        executable_adapter,
        heartbeat=heartbeat_reservation,
        cancelled=lambda: _scan_cancel_requested(scan_id),
    )
    if (
        deterministic_process
        and scan_result_holder is not None
        and isinstance(executable_adapter.scan_result, Mapping)
    ):
        scan_result_holder["result"] = dict(executable_adapter.scan_result)
    if (
        external_process
        and scanner_result_holder is not None
        and isinstance(executable_adapter.process_result, Mapping)
    ):
        scanner_result_holder["result"] = dict(
            executable_adapter.process_result
        )
    action_status = (
        "completed" if execution_result.status == "success"
        else "partial" if execution_result.status == "partial"
        else "cancelled" if execution_result.status == "cancelled"
        else "blocked" if execution_result.status == "blocked"
        else "failed"
    )
    observations = [dict(item) for item in execution_result.observations]
    errors = [str(item) for item in execution_result.errors]
    finished_at = datetime.now(timezone.utc)
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            locked = await conn.fetchrow(
                "SELECT budget_used_json FROM scans WHERE id=$1 FOR UPDATE",
                scan_uuid,
            )
            if not locked:
                raise ReservationStoreError(
                    "Scan disappeared during capability settlement"
                )
            latest = await store.load(
                conn, persisted.record.reservation_id, for_update=True,
            )
            if (
                latest is None
                or latest.record.state_digest != persisted.record.state_digest
                or latest.record.status != "running"
                or latest.record.worker_id != worker_id
            ):
                raise ReservationConflict(
                    "Scan capability reservation changed before settlement"
                )
            terminal, receipt = terminalize_capability_reservation(
                latest.record,
                action_digest=action_digest,
                capability_name=prepared.capability_name,
                adapter_name=prepared.adapter_name,
                adapter_version=prepared.adapter_version,
                parser_version=execution_result.parser_version,
                target_id=target.target_id,
                target_kind=target.target_kind,
                capability_input=execution_result.redacted_execution,
                action_status=action_status,
                actual_budget=execution_result.actual_budget,
                worker_id=worker_id,
                started_at=started_at.isoformat(),
                finished_at=finished_at.isoformat(),
                receipt_id=str(uuid.uuid4()),
                scope_receipt_id=target.scope_receipt_id,
                approval_receipt_id=policy.approval_receipt_id,
                result={
                    "ok": execution_result.status == "success",
                    "error": errors[0] if errors else None,
                    "receipt_errors": errors,
                    "timed_out": execution_result.timed_out,
                    "execution_started": execution_result.execution_started,
                    "receipt_observations": observations[:5000],
                },
            )
            current_used = _worker_json_object(locked["budget_used_json"])
            current_ledger = {
                name: int(current_used.get(name) or 0) for name in limits
            }
            reconciled = terminal.reconcile_consumed(current_ledger)
            persisted = await store.persist_terminal(
                conn,
                previous=latest,
                terminal=terminal,
                ledger_after_settlement=reconciled,
                receipt=receipt,
            )
            current_used.update(reconciled)
            await conn.execute(
                "UPDATE scans SET budget_used_json=$2 WHERE id=$1",
                scan_uuid,
                json.dumps(current_used),
            )
    return persisted, False


def _deterministic_scan_reservation_summary(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    return {
        "schema_version": "deterministic-scan-execution-receipt/v1",
        "capability_name": "scan.execute",
        "status": str(receipt.get("status") or "failed"),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


def _deterministic_scan_terminal_failure_result(
    *,
    target: str,
    stored: Any,
    summary: Mapping[str, Any],
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    errors = [str(item) for item in receipt.get("errors") or [] if str(item)]
    reason = (
        errors[0]
        if errors else stored.record.failure_reason
        or "deterministic_scan_execution_not_recoverable"
    )
    return {
        "target": target,
        "error": str(reason)[:1000],
        "result": {"score": None, "grade": None},
        "findings": [],
        "coverage": {
            "status": "failed",
            "reasons": ["deterministic_scan_execution_not_replayed"],
        },
        "scan_metadata": {
            "status": "failed",
            "deterministic_scan_redelivery_blocked": True,
        },
        "deterministic_scan_execution": dict(summary),
    }


def _skipped_scan_auth_session_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-auth-session-execution/v1",
        "capability_name": "auth.session.establish",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
        "worker_private_session_available": False,
    }


def _blocked_scan_auth_session_summary(reason: str) -> dict[str, Any]:
    summary = _skipped_scan_auth_session_summary(reason)
    summary.update({
        "enabled": True,
        "status": "blocked",
        "durable_budget_settled": False,
        "errors": [str(reason)[:200]],
    })
    return summary


def _scan_auth_session_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
    private_session_available: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "credential_session"
    ][:1]
    reason = None
    if status == "success" and not private_session_available:
        status = "failed"
        reason = "worker_private_session_unavailable_after_redelivery"
    return {
        "schema_version": "canonical-scan-auth-session-execution/v1",
        "capability_name": "auth.session.establish",
        "enabled": True,
        "status": status,
        "reason": reason,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
        "worker_private_session_available": bool(private_session_available),
    }


async def _execute_scan_auth_session_capability(
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    private_session_holder: dict[str, Any],
    lane: str = "primary",
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Establish one interactive identity lane under Scan authority."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_auth_session_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_auth_session_summary("discovery_manifest_only")
    credential = resolve_scan_interactive_credential(options, lane=lane)
    if credential is None:
        return _skipped_scan_auth_session_summary(f"no_interactive_{lane}")
    if not admission.plan.policy.approval_receipt_id:
        return _blocked_scan_auth_session_summary("credential_approval_missing")

    target = execution.target_binding
    request_limit = 2 if credential.auth_kind == "form_login" else 1

    async def establish_session() -> Mapping[str, Any]:
        session = await establish_target_bound_http_session(
            credential.session_credential(), target=target,
        )
        private_session_holder["session"] = session
        return session.execution_result()

    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="auth.session.establish",
        capability_args=credential.capability_args(),
        action_id=(
            canonical_action.action_id if canonical_action is not None
            else f"resolve_inputs.auth.session.establish.{lane}"
        ),
        target_binding=target,
        reservation_limits={
            "http_requests": request_limit,
            "tool_wall_seconds": 30,
        },
        inline_operation=establish_session,
        canonical_action=canonical_action,
    )
    session = private_session_holder.get("session")
    private_available = bool(
        session is not None
        and session.established
        and session.headers()
    )
    return _scan_auth_session_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
        private_session_available=private_available,
    )


def _skipped_scan_template_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-template-execution/v1",
        "capability_name": "templates.scan",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _skipped_scan_tls_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-tls-inspection-execution/v1",
        "capability_name": "tls.inspect",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _skipped_scan_dns_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-dns-inspection-execution/v1",
        "capability_name": "dns.inspect",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


_SCAN_BASELINE_RESPONSE_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "feature-policy",
    "x-xss-protection",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "server",
    "x-powered-by",
    "via",
    "alt-svc",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "cf-ray",
    "cf-cache-status",
    "x-amz-request-id",
    "x-vercel-id",
]


def _skipped_scan_http_baseline_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-http-baseline-execution/v1",
        "capability_name": "http.request",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_http_baseline_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "http_observation"
    ][:1]
    return {
        "schema_version": "canonical-scan-http-baseline-execution/v1",
        "capability_name": "http.request",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


def _skipped_scan_http_redirect_summary(reason: str) -> dict[str, Any]:
    summary = _skipped_scan_http_baseline_summary(reason)
    summary["schema_version"] = "canonical-scan-http-redirect-execution/v1"
    return summary


def _scan_http_redirect_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    summary = _scan_http_baseline_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )
    summary["schema_version"] = "canonical-scan-http-redirect-execution/v1"
    return summary


def _skipped_scan_security_txt_summary(reason: str) -> dict[str, Any]:
    summary = _skipped_scan_http_baseline_summary(reason)
    summary["schema_version"] = "canonical-scan-security-txt-execution/v1"
    return summary


def _scan_security_txt_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    summary = _scan_http_baseline_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )
    summary["schema_version"] = "canonical-scan-security-txt-execution/v1"
    return summary


async def _run_scan_http_baseline_operation(
    *,
    origin: str,
    capability_args: Mapping[str, Any],
    target: TargetBinding,
    timeout_seconds: int,
    allow_bound_origin_redirects: bool = False,
    trusted_headers: Mapping[str, Any] | None = None,
    principal_slot: str = "anonymous",
) -> dict[str, Any]:
    """Execute the shared adapter and retain only public header evidence."""
    result = dict(await execute_bound_http_request(
        origin,
        capability_args,
        target=target,
        allow_write=False,
        selected_headers=_SCAN_BASELINE_RESPONSE_HEADERS,
        timeout_seconds=timeout_seconds,
        allow_bound_origin_redirects=allow_bound_origin_redirects,
        trusted_headers=trusted_headers,
        principal_slot=principal_slot,
    ))
    request = (
        dict(result.get("request") or {})
        if isinstance(result.get("request"), Mapping) else {}
    )
    if request.get("path"):
        request["path"] = redact_url(str(request["path"]))
    result["request"] = request
    response = (
        dict(result.get("response") or {})
        if isinstance(result.get("response"), Mapping) else {}
    )
    selected = (
        dict(response.get("selected_headers") or {})
        if isinstance(response.get("selected_headers"), Mapping) else {}
    )
    response["selected_headers"] = {
        str(name).lower()[:120]: redact_text(str(value))[:2_000]
        for name, value in selected.items()
        if str(name).lower() in _SCAN_BASELINE_RESPONSE_HEADERS
    }
    response["body_sample"] = ""
    response["selected_json"] = {}
    if response.get("final_url"):
        response["final_url"] = redact_url(str(response["final_url"]))
    if response.get("location"):
        response["location"] = redact_url(str(response["location"]))
    result["response"] = response
    chain = []
    for item in result.get("redirect_chain") or []:
        if not isinstance(item, Mapping):
            continue
        row = dict(item)
        if row.get("location"):
            row["location"] = redact_url(str(row["location"]))
        chain.append(row)
    if "redirect_chain" in result:
        result["redirect_chain"] = chain
    return result


async def _run_scan_security_txt_operation(
    *,
    origin: str,
    capability_args: Mapping[str, Any],
    target: TargetBinding,
    timeout_seconds: int,
) -> dict[str, Any]:
    """Fetch RFC 9116 policy and retain only bounded public evidence."""
    result = dict(await execute_bound_http_request(
        origin,
        capability_args,
        target=target,
        allow_write=False,
        timeout_seconds=timeout_seconds,
    ))
    request = (
        dict(result.get("request") or {})
        if isinstance(result.get("request"), Mapping) else {}
    )
    result["request"] = request
    response = (
        dict(result.get("response") or {})
        if isinstance(result.get("response"), Mapping) else {}
    )
    body = str(response.get("body_sample") or "").strip()
    directive_markers = (
        "contact:", "expires:", "acknowledgments:", "encryption:",
        "preferred-languages:", "policy:", "hiring:", "canonical:",
    )
    present = (
        response.get("status") == 200
        and bool(body)
        and any(marker in body.lower() for marker in directive_markers)
    )
    policy_url = urllib.parse.urljoin(
        origin.rstrip("/") + "/", "/.well-known/security.txt",
    )
    response["security_txt"] = {
        "present": bool(present),
        "url": redact_url(policy_url),
        "sample": redact_text(body)[:500] if present else None,
    }
    response["body_sample"] = ""
    response["selected_json"] = {}
    response["selected_headers"] = {}
    if response.get("final_url"):
        response["final_url"] = redact_url(str(response["final_url"]))
    if response.get("location"):
        response["location"] = redact_url(str(response["location"]))
    result["response"] = response
    chain = []
    for item in result.get("redirect_chain") or []:
        if not isinstance(item, Mapping):
            continue
        row = dict(item)
        if row.get("location"):
            row["location"] = redact_url(str(row["location"]))
        chain.append(row)
    if "redirect_chain" in result:
        result["redirect_chain"] = chain
    return result


async def _execute_scan_http_baseline_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run the public base-header request outside the report monolith."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_http_baseline_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_http_baseline_summary("discovery_manifest_only")
    allocation = scan_http_baseline_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_http_baseline_summary(
            "insufficient_stage_budget"
        )
    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed = urllib.parse.urlsplit(execution_target)
    origin = urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, "", "", "",
    ))
    path = urllib.parse.urlunsplit((
        "", "", parsed.path or "/", parsed.query, "",
    ))
    capability_args = {
        "method": "HEAD",
        "path": path,
        "follow_redirects": True,
    }
    principal = resolve_scan_http_principal(options, lane="primary")
    capability_args.update(principal.capability_args())
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="http.request",
        capability_args=capability_args,
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.http.request"),
        target_binding=target,
        reservation_limits=allocation,
        inline_operation=lambda: _run_scan_http_baseline_operation(
            origin=origin,
            capability_args=capability_args,
            target=target,
            timeout_seconds=int(allocation["tool_wall_seconds"]),
            trusted_headers=principal.headers(),
            principal_slot=(
                "primary" if principal.authenticated else "anonymous"
            ),
        ),
        canonical_action=canonical_action,
    )
    return _scan_http_baseline_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


async def _execute_scan_http_redirect_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Probe HTTP downgrade posture only when that origin is explicitly bound."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_http_redirect_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_http_redirect_summary("discovery_manifest_only")
    parsed_target = urllib.parse.urlsplit(str(target_url or ""))
    if parsed_target.scheme.lower() != "https":
        return _skipped_scan_http_redirect_summary("target_is_http")
    target = execution.target_binding
    http_origins = [
        str(origin)
        for origin in target.allowed_origins
        if urllib.parse.urlsplit(str(origin)).scheme.lower() == "http"
        and urllib.parse.urlsplit(str(origin)).hostname == target.canonical_host
    ]
    if not http_origins:
        return _skipped_scan_http_redirect_summary("http_origin_not_bound")
    allocation = scan_http_baseline_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_http_redirect_summary(
            "insufficient_stage_budget"
        )
    origin = http_origins[0]
    capability_args = {
        "method": "HEAD",
        "path": "/",
        "follow_redirects": True,
    }
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="http.request",
        capability_args=capability_args,
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.http_redirect"),
        target_binding=target,
        reservation_limits=allocation,
        inline_operation=lambda: _run_scan_http_baseline_operation(
            origin=origin,
            capability_args=capability_args,
            target=target,
            timeout_seconds=int(allocation["tool_wall_seconds"]),
            allow_bound_origin_redirects=True,
        ),
        canonical_action=canonical_action,
    )
    return _scan_http_redirect_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


async def _execute_scan_security_txt_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run the fixed RFC 9116 request outside the report monolith."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_security_txt_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_security_txt_summary("discovery_manifest_only")
    allocation = scan_http_baseline_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_security_txt_summary("insufficient_stage_budget")
    target = execution.target_binding
    execution_target = scan_external_execution_target(target_url, target=target)
    parsed = urllib.parse.urlsplit(execution_target)
    origin = urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, "", "", "",
    ))
    capability_args = {
        "method": "GET",
        "path": "/.well-known/security.txt",
        "follow_redirects": True,
    }
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="http.request",
        capability_args=capability_args,
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.security_txt"),
        target_binding=target,
        reservation_limits=allocation,
        inline_operation=lambda: _run_scan_security_txt_operation(
            origin=origin,
            capability_args=capability_args,
            target=target,
            timeout_seconds=int(allocation["tool_wall_seconds"]),
        ),
        canonical_action=canonical_action,
    )
    return _scan_security_txt_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _scan_dns_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "dns_posture"
    ][:1]
    return {
        "schema_version": "canonical-scan-dns-inspection-execution/v1",
        "capability_name": "dns.inspect",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_dns_capability(
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run the fixed DNS posture plan outside the report monolith."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_dns_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_dns_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_dns_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_dns_summary("assigned_endpoint_scope")
    allocation = scan_dns_posture_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_dns_summary("insufficient_stage_budget")
    target = execution.target_binding
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="dns.inspect",
        capability_args={},
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.dns.inspect"),
        target_binding=target,
        reservation_limits=allocation,
        inline_operation=lambda: inspect_dns_posture(
            target,
            timeout_seconds=int(allocation["tool_wall_seconds"]),
        ),
        canonical_action=canonical_action,
    )
    return _scan_dns_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _scan_tls_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "tls_protocol"
    ][:1]
    return {
        "schema_version": "canonical-scan-tls-inspection-execution/v1",
        "capability_name": "tls.inspect",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_tls_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run one canonical TLS handshake outside the report monolith."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_tls_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    if execution.discovery_manifest_only:
        return _skipped_scan_tls_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_tls_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_tls_summary("assigned_endpoint_scope")
    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed = urllib.parse.urlsplit(execution_target)
    origin = urllib.parse.urlunsplit((
        parsed.scheme, parsed.netloc, "", "", "",
    ))
    if parsed.scheme.lower() != "https":
        return _skipped_scan_tls_summary("non_https")
    allocation = scan_tls_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_tls_summary("insufficient_stage_budget")
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="tls.inspect",
        capability_args={"origin": origin},
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.tls.inspect"),
        target_binding=target,
        reservation_limits=allocation,
        inline_operation=lambda: inspect_tls_origin(
            origin,
            target=target,
            timeout_seconds=int(allocation["tool_wall_seconds"]),
        ),
        canonical_action=canonical_action,
    )
    return _scan_tls_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _scan_template_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "template_match"
    ][:200]
    return {
        "schema_version": "canonical-scan-template-execution/v1",
        "capability_name": "templates.scan",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


def _skipped_scan_web_probe_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-web-probe-execution/v1",
        "capability_name": "web.probe",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_web_probe_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "http_fingerprint"
    ][:50]
    return {
        "schema_version": "canonical-scan-web-probe-execution/v1",
        "capability_name": "web.probe",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_web_probe_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run the canonical passive HTTP fingerprint outside the monolith."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_web_probe_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_web_probe_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_web_probe_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_web_probe_summary("assigned_endpoint_scope")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "recon" in exclude:
        return _skipped_scan_web_probe_summary("policy_excluded")
    if include and "recon" not in include:
        return _skipped_scan_web_probe_summary("policy_not_included")
    allocation = scan_web_probe_capability_allocation(
        execution.payload()["execution_budget"],
        preserve_http_requests=2 if policy.active_testing else 1,
        preserve_tool_wall_seconds=2 if policy.active_testing else 1,
    )
    if allocation is None:
        return _skipped_scan_web_probe_summary("insufficient_stage_budget")

    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="web.probe",
        capability_args=principal.capability_args(),
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_recon.web.probe"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:web.probe",
            "tool_name": "httpx",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_web_probe_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _skipped_scan_web_crawl_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-web-crawl-execution/v1",
        "capability_name": "web.crawl",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_web_crawl_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "discovered_route"
    ][:200]
    return {
        "schema_version": "canonical-scan-web-crawl-execution/v1",
        "capability_name": "web.crawl",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_web_crawl_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run canonical Katana once under active Scan authority."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_web_crawl_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_web_crawl_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_web_crawl_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_web_crawl_summary("assigned_endpoint_scope")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "recon" in exclude:
        return _skipped_scan_web_crawl_summary("policy_excluded")
    if include and "recon" not in include:
        return _skipped_scan_web_crawl_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_web_crawl_summary("active_testing_not_authorized")
    if not policy.approval_receipt_id:
        return _skipped_scan_web_crawl_summary("active_approval_missing")
    allocation = scan_web_crawl_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_web_crawl_summary("insufficient_stage_budget")

    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="web.crawl",
        capability_args=principal.capability_args(),
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_recon.web.crawl"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:web.crawl",
            "tool_name": "katana",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_web_crawl_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _skipped_scan_content_discovery_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-content-discovery-execution/v1",
        "capability_name": "web.content_discover",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_content_discovery_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and str(item.get("kind") or "") == "content_discovery"
    ][:200]
    return {
        "schema_version": "canonical-scan-content-discovery-execution/v1",
        "capability_name": "web.content_discover",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_content_discovery_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run canonical FFUF once with a bundled fixed wordlist."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_content_discovery_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_content_discovery_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_content_discovery_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_content_discovery_summary("assigned_endpoint_scope")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "recon" in exclude:
        return _skipped_scan_content_discovery_summary("policy_excluded")
    if include and "recon" not in include:
        return _skipped_scan_content_discovery_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_content_discovery_summary(
            "active_testing_not_authorized"
        )
    if not policy.approval_receipt_id:
        return _skipped_scan_content_discovery_summary("active_approval_missing")
    allocation = scan_content_discovery_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_content_discovery_summary(
            "insufficient_stage_budget"
        )

    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="web.content_discover",
        capability_args={
            "wordlist": "common", **principal.capability_args(),
        },
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_recon.web.content_discover"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:web.content_discover",
            "tool_name": "ffuf",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {"wordlist": "common"},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_content_discovery_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _skipped_scan_xss_verification_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-xss-verification-execution/v1",
        "capability_name": "xss.verify",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_xss_verification_summary_from_stored(
    stored: Any,
    *,
    target_url: str,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    public_target = agent_tools._public_observed_url(target_url)
    observations = []
    for item in receipt.get("observations") or []:
        if not isinstance(item, Mapping) or item.get("kind") != "xss_alert":
            continue
        observation = dict(item)
        observation["url"] = observation.get("url") or public_target
        observations.append(observation)
        if len(observations) >= 100:
            break
    return {
        "schema_version": "canonical-scan-xss-verification-execution/v1",
        "capability_name": "xss.verify",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_xss_verification_capability(
    target_url: str | None,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run one candidate-bound Dalfox proof contract under Scan authority."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_xss_verification_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_xss_verification_summary(
            "discovery_manifest_only"
        )
    if execution.focused_family and execution.focused_family != "xss":
        return _skipped_scan_xss_verification_summary("focused_other_family")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "xss" in exclude:
        return _skipped_scan_xss_verification_summary("policy_excluded")
    if include and "xss" not in include:
        return _skipped_scan_xss_verification_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_xss_verification_summary(
            "active_testing_not_authorized"
        )
    if not policy.approval_receipt_id:
        return _skipped_scan_xss_verification_summary(
            "active_approval_missing"
        )
    if not target_url:
        return _skipped_scan_xss_verification_summary(
            "no_parameterized_candidate"
        )
    allocation = scan_xss_verification_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_xss_verification_summary(
            "insufficient_fixed_profile_budget"
        )

    target = execution.target_binding
    execution_target = scan_external_execution_target(target_url, target=target)
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    candidate_digest = hashlib.sha256(execution_target.encode()).hexdigest()[:16]
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="xss.verify",
        capability_args={
            "severity": "high", **principal.capability_args(),
        },
        action_id=(canonical_action.action_id if canonical_action is not None
                   else f"deterministic_verify.xss.{candidate_digest}"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:xss.verify:{candidate_digest}",
            "tool_name": "dalfox",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {"severity": "high"},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_xss_verification_summary_from_stored(
        stored,
        target_url=execution_target,
        idempotent_redelivery=idempotent_redelivery,
    )


def _skipped_scan_sqli_verification_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-sqli-verification-execution/v1",
        "capability_name": "sqli.verify",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _skipped_scan_authz_verification_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-authz-verification-execution/v1",
        "capability_name": "authz.verify",
        "enabled": False,
        "status": "skipped",
        "reason": str(reason)[:200],
        "observations": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "receipt": {},
        "durable_budget_settled": True,
        "idempotent_redelivery": False,
    }


def _scan_authz_verification_summary_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
        and item.get("kind") == "authz_differential"
        and item.get("proof_state") in {"verified", "inconclusive"}
    ][:1]
    return {
        "schema_version": "canonical-scan-authz-verification-execution/v1",
        "capability_name": "authz.verify",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


def _scan_authz_route_inventory(
    options: Mapping[str, Any],
    *,
    crawl_observations: Any = None,
    content_observations: Any = None,
) -> list[str]:
    routes: list[str] = []
    for item in options.get("custom_endpoints") or []:
        if isinstance(item, str) and item.strip():
            routes.append(item.strip())
    for observations in (crawl_observations, content_observations):
        for item in observations or []:
            if not isinstance(item, Mapping) or not item.get("url"):
                continue
            method = str(item.get("method") or "GET").upper()
            if method == "GET":
                routes.append(str(item["url"]))
    return list(dict.fromkeys(routes))[:50]


async def _execute_scan_authz_verification_capability(
    target_url: str,
    routes: list[str],
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run one proof-gated read-only BOLA differential under Scan authority."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_authz_verification_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_authz_verification_summary(
            "discovery_manifest_only"
        )
    if execution.focused_family and execution.focused_family != "bola":
        return _skipped_scan_authz_verification_summary(
            "focused_other_family"
        )
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "bola" in exclude or "access_control" in exclude:
        return _skipped_scan_authz_verification_summary("policy_excluded")
    if include and not ({"bola", "access_control"} & include):
        return _skipped_scan_authz_verification_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_authz_verification_summary(
            "active_testing_not_authorized"
        )
    if not policy.approval_receipt_id:
        return _skipped_scan_authz_verification_summary(
            "active_approval_missing"
        )
    primary = resolve_scan_http_principal(options, lane="primary")
    secondary = resolve_scan_http_principal(options, lane="secondary")
    if not primary.authenticated or not secondary.authenticated:
        return _skipped_scan_authz_verification_summary(
            "two_authenticated_principals_required"
        )
    if not routes:
        return _skipped_scan_authz_verification_summary(
            "no_authz_route_candidates"
        )
    budget = execution.payload()["execution_budget"]
    if (
        int(budget.get("max_http_requests") or 0) < 4
        or int(budget.get("max_tool_wall_seconds") or 0) < 45
    ):
        return _skipped_scan_authz_verification_summary(
            "insufficient_stage_budget"
        )
    route_digest = authz_route_inventory_digest(routes)
    target = execution.target_binding

    async def verify() -> Mapping[str, Any]:
        return await verify_target_bound_object_authorization(
            target_url,
            routes,
            target=target,
            primary_headers=primary.headers(),
            secondary_headers=secondary.headers(),
        )

    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="authz.verify",
        capability_args={
            "primary_binding_digest": str(primary.binding_digest),
            "secondary_binding_digest": str(secondary.binding_digest),
            "route_inventory_digest": route_digest,
            "route_count": len(routes),
        },
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "verify_candidates.authz.verify"),
        target_binding=target,
        reservation_limits={
            "http_requests": 4,
            "tool_wall_seconds": min(
                60, int(budget["max_tool_wall_seconds"]),
            ),
        },
        inline_operation=verify,
        canonical_action=canonical_action,
    )
    return _scan_authz_verification_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


def _canonical_candidate_verification_summary(
    xss: Mapping[str, Any],
    sqli: Mapping[str, Any],
    authz: Mapping[str, Any] | None = None,
    *,
    candidate_count: int,
) -> dict[str, Any]:
    """Evaluate canonical active observations without sending more traffic.

    Dalfox's browser/alert proof may satisfy the deterministic XSS contract.
    SQLMap output remains a suspected candidate until the separate payload and
    control differential exists; a tool label alone can never promote it.
    """
    xss_observations = [
        dict(item)
        for item in xss.get("observations") or []
        if isinstance(item, Mapping) and item.get("kind") == "xss_alert"
    ]
    sqli_observations = [
        dict(item)
        for item in sqli.get("observations") or []
        if isinstance(item, Mapping)
        and item.get("kind") in {"sqli_finding", "sqli_dbms_fingerprint"}
    ]
    verified_xss = sum(
        1 for item in xss_observations
        if str(item.get("proof_state") or "") == "verified"
    )
    suspected_sqli = sum(
        1 for item in sqli_observations
        if item.get("kind") == "sqli_finding"
    )
    authz_observations = [
        dict(item)
        for item in (authz or {}).get("observations") or []
        if isinstance(item, Mapping)
        and item.get("kind") == "authz_differential"
    ]
    verified_authz = sum(
        1 for item in authz_observations
        if item.get("proof_state") == "verified"
    )
    return {
        "schema_version": "canonical-candidate-verification/v1",
        "candidate_count": max(0, int(candidate_count)),
        "finding_promotion_authority": "deterministic_proof_contracts_only",
        "xss": {
            "contract": "browser_or_alert_execution_proof",
            "observation_count": len(xss_observations),
            "verified_count": verified_xss,
            "candidate_count": max(0, len(xss_observations) - verified_xss),
        },
        "sqli": {
            "contract": "payload_control_differential",
            "observation_count": len(sqli_observations),
            "verified_count": 0,
            "suspected_count": suspected_sqli,
            "promotion_blocked_reason": (
                "deterministic_differential_missing" if suspected_sqli else None
            ),
        },
        "authz": {
            "contract": "cross_principal_ownership_differential",
            "observation_count": len(authz_observations),
            "verified_count": verified_authz,
            "inconclusive_count": max(
                0, len(authz_observations) - verified_authz,
            ),
        },
    }


def _scan_sqli_verification_summary_from_stored(
    stored: Any,
    *,
    target_url: str,
    idempotent_redelivery: bool,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    public_target = agent_tools._public_observed_url(target_url)
    observations = []
    for item in receipt.get("observations") or []:
        if (
            not isinstance(item, Mapping)
            or item.get("kind") not in {
                "sqli_finding", "sqli_dbms_fingerprint",
            }
        ):
            continue
        observation = dict(item)
        observation["url"] = public_target
        observation["method"] = "GET"
        observations.append(observation)
        if len(observations) >= 100:
            break
    return {
        "schema_version": "canonical-scan-sqli-verification-execution/v1",
        "capability_name": "sqli.verify",
        "enabled": True,
        "status": status,
        "reason": None,
        "observations": observations,
        "observation_count": len(observations),
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": bool(stored.record.terminal),
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


async def _execute_scan_sqli_verification_capability(
    target_url: str | None,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run one candidate-bound SQLMap contract under Scan authority."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_sqli_verification_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_sqli_verification_summary(
            "discovery_manifest_only"
        )
    if execution.focused_family and execution.focused_family != "sqli":
        return _skipped_scan_sqli_verification_summary("focused_other_family")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "sqli" in exclude:
        return _skipped_scan_sqli_verification_summary("policy_excluded")
    if include and "sqli" not in include:
        return _skipped_scan_sqli_verification_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_sqli_verification_summary(
            "active_testing_not_authorized"
        )
    if not policy.approval_receipt_id:
        return _skipped_scan_sqli_verification_summary(
            "active_approval_missing"
        )
    if not target_url:
        return _skipped_scan_sqli_verification_summary(
            "no_parameterized_candidate"
        )
    allocation = scan_sqli_verification_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_sqli_verification_summary(
            "insufficient_fixed_profile_budget"
        )

    target = execution.target_binding
    execution_target = scan_external_execution_target(target_url, target=target)
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    candidate_digest = hashlib.sha256(execution_target.encode()).hexdigest()[:16]
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="sqli.verify",
        capability_args=principal.capability_args(),
        action_id=(canonical_action.action_id if canonical_action is not None
                   else f"deterministic_verify.sqli.{candidate_digest}"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:sqli.verify:{candidate_digest}",
            "tool_name": "sqlmap",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_sqli_verification_summary_from_stored(
        stored,
        target_url=execution_target,
        idempotent_redelivery=idempotent_redelivery,
    )


async def _execute_scan_template_capability(
    target_url: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run canonical Nuclei once, outside the compatibility scanner process."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_template_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if execution.discovery_manifest_only:
        return _skipped_scan_template_summary("discovery_manifest_only")
    if execution.skip_global_checks:
        return _skipped_scan_template_summary("global_checks_skipped")
    if execution.focused_endpoints_only or execution.zero_rediscovery:
        return _skipped_scan_template_summary("assigned_endpoint_scope")
    if execution.focused_family and execution.focused_family != "nuclei":
        return _skipped_scan_template_summary("focused_other_family")
    include = set(policy.include_families)
    exclude = set(policy.exclude_families)
    if "nuclei" in exclude:
        return _skipped_scan_template_summary("policy_excluded")
    if include and "nuclei" not in include:
        return _skipped_scan_template_summary("policy_not_included")
    if not policy.active_testing:
        return _skipped_scan_template_summary("active_testing_not_authorized")
    if not policy.approval_receipt_id:
        return _skipped_scan_template_summary("active_approval_missing")
    allocation = scan_template_capability_allocation(
        execution.payload()["execution_budget"]
    )
    if allocation is None:
        return _skipped_scan_template_summary(
            "insufficient_fixed_profile_budget"
        )

    target = execution.target_binding
    execution_target = scan_external_execution_target(
        target_url, target=target,
    )
    parsed_target = urllib.parse.urlsplit(execution_target)
    registered_target = urllib.parse.urlunsplit((
        parsed_target.scheme, parsed_target.netloc, "", "", "",
    ))
    authorized_addresses = list(target.allowed_addresses)
    pinned_address = agent_tools.validate_pinned_scanner_address(
        authorized_addresses[0], authorized_addresses,
    )
    principal = resolve_scan_http_principal(options, lane="primary")
    stored, idempotent_redelivery = await _execute_reserved_scan_capability(
        admission=admission,
        execution=execution,
        scan_id=scan_id,
        job_id=job_id,
        capability_name="templates.scan",
        capability_args=principal.capability_args(),
        action_id=(canonical_action.action_id if canonical_action is not None
                   else "deterministic_baseline.templates.scan"),
        target_binding=target,
        reservation_limits=allocation,
        scanner_process_payload={
            "job_id": f"{job_id}:templates.scan",
            "tool_name": "nuclei",
            "execution_target": execution_target,
            "registered_target": registered_target,
            "scanner_options": {},
            "trusted_headers": principal.headers(),
            "timeout_ms": int(allocation["tool_wall_seconds"]) * 1_000,
            "pinned_address": pinned_address,
            "authorized_addresses": authorized_addresses,
            # Scan does not grant an additional OOB destination. Nuclei's fixed
            # template therefore retains -no-interactsh for this capability.
            "oob_interactsh_server": None,
            "oob_interactsh_token": None,
        },
        scanner_process_runner=_execute_agent_scanner_process,
        canonical_action=canonical_action,
    )
    return _scan_template_summary_from_stored(
        stored,
        idempotent_redelivery=idempotent_redelivery,
    )


async def _execute_reserved_deterministic_scan(
    target: str,
    options: Mapping[str, Any],
    *,
    scan_id: str,
    job_id: str,
    runtime_request_grant: int | None = None,
    collection_replay_result_holder: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run canonical DAST through the executable fixed-stage worker graph."""
    normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return await run_scan(
            target, dict(options), scan_id=scan_id, job_id=job_id,
        )
    execution = build_native_scan_execution(admission.plan, normalized)
    context = ScanStageContext(
        execution=execution,
        target_url=target,
        options=normalized,
        scan_id=scan_id,
        job_id=job_id,
    )
    effective_options = dict(normalized)
    composite_options = dict(normalized)
    primary_principal = resolve_scan_http_principal(
        effective_options, lane="primary",
    )
    secondary_principal = resolve_scan_http_principal(
        effective_options, lane="secondary",
    )

    def stage_capabilities(
        output: Mapping[str, Any],
        *,
        capability_names: tuple[str, ...],
        adapter: str = "native_worker",
    ) -> ScanStageRunResult:
        summaries = [
            value for value in output.values() if isinstance(value, Mapping)
        ]
        statuses = {
            str(item.get("status") or "").strip().lower()
            for item in summaries
        }
        if "cancelled" in statuses:
            status, reason = "cancelled", "capability_cancelled"
        elif statuses & {"failed", "blocked", "partial"}:
            status, reason = "partial", "capability_partial_or_failed"
        else:
            status, reason = "completed", None
        return ScanStageRunResult(
            output=output,
            status=status,
            reason=reason,
            adapter=adapter,
            capability_names=capability_names,
        )

    async def bind_target_stage(_context: ScanStageContext) -> ScanStageRunResult:
        return ScanStageRunResult(output={
            "target_binding_digest": execution.target_binding.digest,
            "scope_receipt_bound": bool(execution.target_binding.scope_receipt_id),
            "origin_count": len(execution.target_binding.allowed_origins),
            "address_count": len(execution.target_binding.allowed_addresses),
        })

    async def resolve_inputs_stage(_context: ScanStageContext) -> ScanStageRunResult:
        nonlocal effective_options, primary_principal, secondary_principal

        def count_rows(name: str) -> int:
            value = effective_options.get(name)
            return len(value) if isinstance(value, (list, tuple)) else 0

        primary_session_holder: dict[str, Any] = {}
        primary_session_summary = await _execute_scan_auth_session_capability(
            effective_options,
            scan_id=scan_id,
            job_id=job_id,
            private_session_holder=primary_session_holder,
            lane="primary",
        )
        primary_session = primary_session_holder.get("session")
        if (
            primary_session is not None
            and primary_session.established
            and primary_session.headers()
        ):
            effective_options = bind_scan_session_headers(
                effective_options, primary_session.headers(), lane="primary",
            )
            primary_principal = resolve_scan_http_principal(
                effective_options, lane="primary",
            )
        secondary_session_holder: dict[str, Any] = {}
        if (
            primary_session_summary.get("enabled")
            and primary_session_summary.get("status") != "success"
        ):
            secondary_session_summary = _skipped_scan_auth_session_summary(
                "primary_session_failed"
            )
        else:
            secondary_session_summary = await _execute_scan_auth_session_capability(
                effective_options,
                scan_id=scan_id,
                job_id=job_id,
                private_session_holder=secondary_session_holder,
                lane="secondary",
            )
        secondary_session = secondary_session_holder.get("session")
        if (
            secondary_session is not None
            and secondary_session.established
            and secondary_session.headers()
        ):
            effective_options = bind_scan_session_headers(
                effective_options, secondary_session.headers(), lane="secondary",
            )
            secondary_principal = resolve_scan_http_principal(
                effective_options, lane="secondary",
            )
        output = {
            "credential_profile_reference_count": count_rows(
                "credential_profile_refs"
            ),
            "request_collection_reference_count": count_rows(
                "request_collections"
            ),
            "custom_endpoint_count": count_rows("custom_endpoints"),
            "collection_replay_scheduled": bool(
                effective_options.get("request_collections")
            ),
            "secret_values_exposed": False,
            "primary_principal": primary_principal.public_dict(),
            "secondary_principal": secondary_principal.public_dict(),
            "auth.session.establish": primary_session_summary,
            "auth.session.establish.secondary": secondary_session_summary,
        }
        failed_session = next((
            summary for summary in (
                primary_session_summary, secondary_session_summary,
            )
            if summary.get("enabled") and summary.get("status") != "success"
        ), None)
        if failed_session is not None:
            return ScanStageRunResult(
                output=output,
                status="failed",
                reason="credential_session_establishment_failed",
                adapter="native_worker.auth_session",
                capability_names=("auth.session.establish",),
            )
        return ScanStageRunResult(
            output=output,
            adapter="native_worker.auth_session",
            capability_names=("auth.session.establish",),
        )

    async def discover_surface_stage(
        _context: ScanStageContext,
    ) -> ScanStageRunResult:
        nonlocal effective_options, composite_options
        replay_capability_names = _scan_request_collection_capability_names(
            effective_options
        )
        if effective_options.get("request_collections"):
            collection_replay_summary = await _execute_scan_request_collections(
                effective_options,
                scan_id,
                job_id=job_id,
                runtime_request_grant=runtime_request_grant,
                trusted_primary_headers=primary_principal.headers(),
            )
        else:
            collection_replay_summary = (
                _empty_scan_request_collection_replay_summary()
            )
        if collection_replay_result_holder is not None:
            collection_replay_result_holder.clear()
            collection_replay_result_holder.update(collection_replay_summary)
        if collection_replay_summary.get("cancelled"):
            return stage_capabilities(
                {"collections.replay": collection_replay_summary},
                capability_names=replay_capability_names,
            )
        effective_options = _apply_scan_collection_replay_remaining_budget(
            effective_options, collection_replay_summary,
        )
        composite_options = _apply_scan_collection_replay_remaining_budget(
            composite_options, collection_replay_summary,
        )
        subdomains = await _execute_scan_subdomain_discovery(
            effective_options, scan_id, job_id=job_id,
        )
        if str(subdomains.get("status") or "").strip().lower() == "cancelled":
            return stage_capabilities(
                {
                    "collections.replay": collection_replay_summary,
                    "subdomains.discover": subdomains,
                },
                capability_names=(
                    *replay_capability_names, "subdomains.discover",
                ),
            )
        probe = await _execute_scan_web_probe_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        crawl = await _execute_scan_web_crawl_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        content = await _execute_scan_content_discovery_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        endpoint_manifest = build_scan_surface_manifest(
            target_url=target,
            target=execution.target_binding,
            options=effective_options,
            collection_replay=collection_replay_summary,
            subdomains=subdomains,
            probe=probe,
            crawl=crawl,
            content=content,
            max_endpoints=admission.plan.budget.max_endpoints,
        )
        output: dict[str, Any] = {
            "collections.replay": collection_replay_summary,
            "subdomains.discover": subdomains,
            "web.probe": probe,
            "web.crawl": crawl,
            "web.content_discover": content,
            "endpoint_manifest": endpoint_manifest,
        }
        capability_names = [
            *replay_capability_names,
            "subdomains.discover", "web.probe", "web.crawl",
            "web.content_discover",
        ]
        return stage_capabilities(
            output, capability_names=tuple(capability_names),
        )

    async def discover_network_stage(
        _context: ScanStageContext,
    ) -> ScanStageRunResult:
        network_discovery_summary = await _execute_scan_network_discovery(
            effective_options, scan_id, job_id=job_id,
        )
        return stage_capabilities(
            {"network.discovery": dict(network_discovery_summary)},
            capability_names=("ports.discover", "service.fingerprint"),
        )

    async def deterministic_baseline_stage(
        _context: ScanStageContext,
    ) -> ScanStageRunResult:
        http_baseline = await _execute_scan_http_baseline_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        http_redirect = await _execute_scan_http_redirect_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        security_txt = await _execute_scan_security_txt_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        dns = await _execute_scan_dns_capability(
            effective_options, scan_id=scan_id, job_id=job_id,
        )
        tls = await _execute_scan_tls_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        template = await _execute_scan_template_capability(
            target, effective_options, scan_id=scan_id, job_id=job_id,
        )
        return stage_capabilities(
            {
                "http.request": http_baseline,
                "http.request.scheme_redirect": http_redirect,
                "http.request.security_txt": security_txt,
                "dns.inspect": dns,
                "tls.inspect": tls,
                "templates.scan": template,
            },
            capability_names=(
                "http.request", "tls.inspect", "templates.scan",
            ),
        )

    async def deterministic_active_stage(
        stage_context: ScanStageContext,
    ) -> ScanStageRunResult:
        surface = stage_context.output("discover_surface")
        crawl = surface.get("web.crawl")
        candidates = scan_parameterized_execution_candidates(
            target,
            target=execution.target_binding,
            options=effective_options,
            crawl_observations=(
                crawl.get("observations") if isinstance(crawl, Mapping) else None
            ),
        )
        candidate = candidates[0] if candidates else None
        xss = await _execute_scan_xss_verification_capability(
            candidate, effective_options, scan_id=scan_id, job_id=job_id,
        )
        sqli = await _execute_scan_sqli_verification_capability(
            candidate, effective_options, scan_id=scan_id, job_id=job_id,
        )
        content = surface.get("web.content_discover")
        authz_routes = _scan_authz_route_inventory(
            effective_options,
            crawl_observations=(
                crawl.get("observations") if isinstance(crawl, Mapping) else None
            ),
            content_observations=(
                content.get("observations")
                if isinstance(content, Mapping) else None
            ),
        )
        authz = await _execute_scan_authz_verification_capability(
            target,
            authz_routes,
            effective_options,
            scan_id=scan_id,
            job_id=job_id,
        )
        return stage_capabilities(
            {
                "xss.verify": xss,
                "sqli.verify": sqli,
                "authz.verify": authz,
                "candidate_count": len(candidates),
            },
            capability_names=("xss.verify", "sqli.verify", "authz.verify"),
        )

    async def verify_candidates_stage(
        stage_context: ScanStageContext,
    ) -> ScanStageRunResult:
        active = stage_context.output("deterministic_active")
        if not active:
            return ScanStageRunResult(
                output={
                    "proof_contracts": _canonical_candidate_verification_summary(
                        {}, {}, candidate_count=0,
                    ),
                },
                status="skipped",
                reason="active_stage_disabled",
                adapter="native_worker.proof_contracts",
            )
        xss = (
            dict(active.get("xss.verify") or {})
            if isinstance(active.get("xss.verify"), Mapping)
            else {}
        )
        sqli = (
            dict(active.get("sqli.verify") or {})
            if isinstance(active.get("sqli.verify"), Mapping)
            else {}
        )
        authz = (
            dict(active.get("authz.verify") or {})
            if isinstance(active.get("authz.verify"), Mapping)
            else {}
        )
        return ScanStageRunResult(
            output={
                "proof_contracts": _canonical_candidate_verification_summary(
                    xss,
                    sqli,
                    authz,
                    candidate_count=int(active.get("candidate_count") or 0),
                ),
            },
            adapter="native_worker.proof_contracts",
        )

    async def finalize_evidence_stage(
        stage_context: ScanStageContext,
    ) -> ScanStageRunResult:
        inputs = stage_context.output("resolve_inputs")
        surface = stage_context.output("discover_surface")
        network = stage_context.output("discover_network")
        baseline = stage_context.output("deterministic_baseline")
        active = stage_context.output("deterministic_active")
        verification = stage_context.output("verify_candidates")
        placed_capabilities = {
            "auth.session.establish": inputs.get("auth.session.establish")
            or _skipped_scan_auth_session_summary("stage_disabled"),
            "auth.session.establish.secondary": inputs.get(
                "auth.session.establish.secondary"
            ) or _skipped_scan_auth_session_summary("stage_disabled"),
            "web.probe": surface.get("web.probe")
            or _skipped_scan_web_probe_summary("stage_disabled"),
            "web.crawl": surface.get("web.crawl")
            or _skipped_scan_web_crawl_summary("stage_disabled"),
            "web.content_discover": surface.get("web.content_discover")
            or _skipped_scan_content_discovery_summary("stage_disabled"),
            "http.request": baseline.get("http.request")
            or _skipped_scan_http_baseline_summary("stage_disabled"),
            "http.request.scheme_redirect": baseline.get(
                "http.request.scheme_redirect"
            ) or _skipped_scan_http_redirect_summary("stage_disabled"),
            "http.request.security_txt": baseline.get(
                "http.request.security_txt"
            ) or _skipped_scan_security_txt_summary("stage_disabled"),
            "dns.inspect": baseline.get("dns.inspect")
            or _skipped_scan_dns_summary("stage_disabled"),
            "tls.inspect": baseline.get("tls.inspect")
            or _skipped_scan_tls_summary("stage_disabled"),
            "templates.scan": baseline.get("templates.scan")
            or _skipped_scan_template_summary("stage_disabled"),
            "xss.verify": active.get("xss.verify")
            or _skipped_scan_xss_verification_summary("stage_disabled"),
            "sqli.verify": active.get("sqli.verify")
            or _skipped_scan_sqli_verification_summary("stage_disabled"),
            "authz.verify": active.get("authz.verify")
            or _skipped_scan_authz_verification_summary("stage_disabled"),
        }
        collection_replay = surface.get("collections.replay")
        if isinstance(collection_replay, Mapping):
            for capability_name in _scan_request_collection_capability_names(
                effective_options
            ):
                placed_capabilities[capability_name] = dict(collection_replay)
        result_holder: dict[str, Any] = {}

        async def scan_runner(
            runtime_budget: Mapping[str, int],
        ) -> Mapping[str, Any]:
            report_placements = {
                name: summary
                for name, summary in placed_capabilities.items()
                if not name.startswith("auth.session.establish")
                and not name.startswith("collections.replay")
            }
            return await run_scan(
                target,
                dict(composite_options),
                scan_id=scan_id,
                job_id=job_id,
                canonical_runtime_budget=runtime_budget,
                canonical_placed_capabilities=report_placements,
            )

        stored, idempotent_redelivery = await _execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id=scan_id,
            job_id=job_id,
            capability_name="scan.execute",
            capability_args={},
            action_id="deterministic_scan.execute",
            scan_runner=scan_runner,
            scan_result_holder=result_holder,
        )
        summary = _deterministic_scan_reservation_summary(
            stored,
            idempotent_redelivery=idempotent_redelivery,
        )
        if isinstance(result_holder.get("result"), Mapping):
            result = dict(result_holder["result"])
        elif idempotent_redelivery:
            async with db_pool.acquire() as conn:
                durable_result = await conn.fetchval(
                    "SELECT result FROM scans WHERE id=$1",
                    uuid.UUID(str(scan_id)),
                )
            result = _as_report_dict(durable_result) or {}
            if not result:
                result = _deterministic_scan_terminal_failure_result(
                    target=target, stored=stored, summary=summary,
                )
        else:
            result = _deterministic_scan_terminal_failure_result(
                target=target, stored=stored, summary=summary,
            )
        result["canonical_candidate_verification"] = dict(
            verification.get("proof_contracts") or {}
        )
        authentication = primary_principal.public_dict()
        authentication["session_establishment"] = dict(
            inputs.get("auth.session.establish") or {}
        )
        authentication["secondary_session_establishment"] = dict(
            inputs.get("auth.session.establish.secondary") or {}
        )
        authenticated_candidates = {
            "web.probe": surface.get("web.probe"),
            "web.crawl": surface.get("web.crawl"),
            "web.content_discover": surface.get("web.content_discover"),
            "http.request": baseline.get("http.request"),
            "templates.scan": baseline.get("templates.scan"),
            "xss.verify": active.get("xss.verify"),
            "sqli.verify": active.get("sqli.verify"),
            "authz.verify": active.get("authz.verify"),
        }
        for capability_name in _scan_request_collection_capability_names(
            effective_options
        ):
            authenticated_candidates[capability_name] = collection_replay
        authentication["applied_capabilities"] = (
            sorted(
                capability_name
                for capability_name, capability_summary
                in authenticated_candidates.items()
                if isinstance(capability_summary, Mapping)
                and str(capability_summary.get("status") or "")
                in {"success", "partial"}
            )
            if primary_principal.authenticated else []
        )
        authentication["secondary_principal"] = (
            secondary_principal.public_dict()
        )
        result["canonical_authentication"] = authentication
        result = _attach_scan_subdomain_summary(
            result,
            surface.get("subdomains.discover")
            if isinstance(surface.get("subdomains.discover"), Mapping)
            else None,
        )
        result = _attach_scan_network_summary(
            result,
            network.get("network.discovery")
            if isinstance(network.get("network.discovery"), Mapping)
            else None,
        )
        result["request_collection_replay"] = (
            dict(collection_replay)
            if isinstance(collection_replay, Mapping)
            else _empty_scan_request_collection_replay_summary()
        )
        endpoint_manifest = surface.get("endpoint_manifest")
        if isinstance(endpoint_manifest, Mapping):
            discovery = (
                dict(result.get("discovery") or {})
                if isinstance(result.get("discovery"), Mapping) else {}
            )
            discovery["endpoint_manifest"] = dict(endpoint_manifest)
            result["discovery"] = discovery
            metadata = (
                dict(result.get("scan_metadata") or {})
                if isinstance(result.get("scan_metadata"), Mapping) else {}
            )
            manifest_digest = hashlib.sha256(
                json.dumps(
                    endpoint_manifest,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            metadata["endpoint_manifest"] = {
                "schema_version": str(
                    endpoint_manifest.get("schema_version") or ""
                ),
                "status": str(endpoint_manifest.get("status") or "partial"),
                "endpoint_count": int(
                    endpoint_manifest.get("endpoint_count") or 0
                ),
                "digest": manifest_digest,
            }
            metadata["endpoint_manifest_digest"] = manifest_digest
            result["scan_metadata"] = metadata
            if str(endpoint_manifest.get("status") or "") == "partial":
                coverage = (
                    dict(result.get("coverage") or {})
                    if isinstance(result.get("coverage"), Mapping) else {}
                )
                if str(coverage.get("status") or "") not in {
                    "failed", "cancelled",
                }:
                    coverage["status"] = "partial"
                reasons = [str(item) for item in coverage.get("reasons") or []]
                if "canonical_surface_manifest_partial" not in reasons:
                    reasons.append("canonical_surface_manifest_partial")
                coverage["reasons"] = reasons
                result["coverage"] = coverage
        status = "partial" if (
            result.get("error") or summary.get("partial") or summary.get("timed_out")
        ) else "completed"
        return ScanStageRunResult(
            output={
                "report": result,
                "reservation_summary": summary,
                "placed_capabilities": placed_capabilities,
            },
            status=status,
            reason=("composite_scanner_partial" if status == "partial" else None),
            adapter="scanner.dast.composite_finalize",
            capability_names=("scan.execute",),
        )

    try:
        checkpoint_store = PostgresScanStageCheckpointStore()
        checkpoint_worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"

        async def persist_stage_checkpoint(
            stage_row: Mapping[str, Any], history_digest: str,
        ) -> None:
            async with db_pool.acquire() as conn:
                await checkpoint_store.persist(
                    conn,
                    scan_id=scan_id,
                    job_id=job_id,
                    execution_plan_digest=execution.execution_plan.digest,
                    target_binding_digest=execution.target_binding.digest,
                    history_digest=history_digest,
                    stage_row=stage_row,
                    worker_id=checkpoint_worker_id,
                )

        stage_execution = await execute_scan_stage_graph(
            context,
            {
                "bind_target": bind_target_stage,
                "resolve_inputs": resolve_inputs_stage,
                "discover_surface": discover_surface_stage,
                "discover_network": discover_network_stage,
                "deterministic_baseline": deterministic_baseline_stage,
                "deterministic_active": deterministic_active_stage,
                "verify_candidates": verify_candidates_stage,
                "finalize_evidence": finalize_evidence_stage,
            },
            cancel_requested=lambda: _scan_cancel_requested(scan_id),
            checkpoint=persist_stage_checkpoint,
        )
    except ScanStageCancelled as exc:
        raise ValueError("Cancelled by user") from exc

    final_output = context.output("finalize_evidence")
    result = dict(final_output["report"])
    summary = dict(final_output["reservation_summary"])
    placed_capabilities = dict(final_output["placed_capabilities"])
    canonical_capabilities = result.setdefault(
        "canonical_capabilities", {}
    )
    if isinstance(canonical_capabilities, dict):
        canonical_capabilities.update(placed_capabilities)
    result["deterministic_scan_execution"] = summary
    result["canonical_stage_execution"] = stage_execution
    return result


async def _execute_scan_subdomain_discovery(
    options: Mapping[str, Any],
    scan_id: str,
    *,
    job_id: str,
    canonical_action: Any | None = None,
) -> dict[str, Any]:
    """Run policy-enabled Scan subdomain discovery through the canonical executor."""
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCapabilityContractError(
            "Scan subdomain discovery owner ID is invalid"
        ) from exc

    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_subdomain_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if not policy.subdomain_discovery:
        return _skipped_scan_subdomain_summary("policy_disabled")
    if (
        execution.shard_authority is not None
        and not execution.shard_authority.parallel_discovery
    ):
        return _skipped_scan_subdomain_summary("assigned_endpoint_shard")
    if execution.zero_rediscovery and not execution.discovery_manifest_only:
        return _skipped_scan_subdomain_summary("rediscovery_disabled")
    placed_summary = options.get("canonical_subdomain_discovery")
    placed_source_scan_id = str(
        options.get("canonical_subdomain_discovery_source_scan_id") or ""
    ).strip()
    if isinstance(placed_summary, Mapping) or placed_source_scan_id:
        if not isinstance(placed_summary, Mapping) or not placed_source_scan_id:
            raise ScanCapabilityContractError(
                "placed subdomain discovery reference is incomplete"
            )
        return await _reuse_placed_scan_subdomain_discovery(
            parent_scan_id=scan_id,
            source_scan_id=placed_source_scan_id,
            expected_summary=placed_summary,
        )

    target = execution.target_binding
    root_domain = str(
        target.allowed_root_domains[0]
        if target.allowed_root_domains else target.canonical_host or ""
    ).lower().rstrip(".")
    stored, idempotent_redelivery = (
        await _execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id=scan_id,
            job_id=job_id,
            capability_name="subdomains.discover",
            capability_args={"root_domain": root_domain},
            action_id=(canonical_action.action_id if canonical_action is not None
                       else "discover_surface.subdomains"),
            canonical_action=canonical_action,
        )
    )
    return _scan_subdomain_summary_from_stored(
        stored,
        root_domain=root_domain,
        idempotent_redelivery=idempotent_redelivery,
    )


def _scan_network_action_from_stored(
    stored: Any,
    *,
    idempotent_redelivery: bool = False,
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    receipt_status = str(receipt.get("status") or "failed").strip().lower()
    status = {
        "succeeded": "success",
        "success": "success",
        "partial": "partial",
        "blocked": "blocked",
        "cancelled": "cancelled",
    }.get(receipt_status, "failed")
    observations = [
        dict(item)
        for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
    ]
    return {
        "capability_name": stored.record.capability_name,
        "status": status,
        "observations": observations[:5000],
        "observation_count": len(observations),
        "observations_truncated": len(observations) > 5000,
        "partial": bool(receipt.get("partial")),
        "timed_out": bool(receipt.get("timed_out")),
        "errors": list(receipt.get("errors") or [])[:20],
        "budget_consumed": dict(stored.record.actual),
        "receipt": _scan_capability_receipt_reference(receipt),
        "durable_budget_settled": stored.record.terminal,
        "idempotent_redelivery": bool(idempotent_redelivery),
    }


def _skipped_scan_network_summary(reason: str) -> dict[str, Any]:
    return {
        "schema_version": "canonical-scan-network-discovery/v1",
        "enabled": False,
        "status": "skipped",
        "reason": reason,
        "actions": [],
        "observations": [],
        "open_ports": [],
        "services": [],
        "observation_count": 0,
        "partial": False,
        "timed_out": False,
        "errors": [],
        "budget_consumed": {},
        "durable_budget_settled": True,
        "network_binding": "exact_address_subset",
    }


def _scan_network_summary_from_actions(
    actions: list[Mapping[str, Any]],
    *,
    addresses: tuple[str, ...],
) -> dict[str, Any]:
    normalized = [dict(action) for action in actions]
    observations = [
        dict(item)
        for action in normalized
        for item in action.get("observations") or []
        if isinstance(item, Mapping)
    ]
    open_ports: list[dict[str, Any]] = []
    seen_open_ports: set[tuple[str, int, str]] = set()
    for item in observations:
        if item.get("kind") != "open_port":
            continue
        identity = (
            str(item.get("address") or ""),
            int(item.get("port") or 0),
            str(item.get("transport") or "tcp"),
        )
        if identity not in seen_open_ports:
            seen_open_ports.add(identity)
            open_ports.append(item)
    services = [
        item for item in observations if item.get("kind") == "service"
    ]
    statuses = {
        str(action.get("status") or "failed").strip().lower()
        for action in normalized
        if action.get("status") != "skipped"
    }
    if "cancelled" in statuses:
        status = "cancelled"
    elif statuses & {"failed", "blocked", "partial"}:
        status = "partial" if observations else (
            "blocked" if statuses == {"blocked"} else "failed"
        )
    else:
        status = "success"
    consumed: dict[str, int] = {}
    for action in normalized:
        for name, amount in dict(action.get("budget_consumed") or {}).items():
            consumed[str(name)] = consumed.get(str(name), 0) + int(amount)
    errors = [
        str(error)
        for action in normalized
        for error in action.get("errors") or []
    ][:20]
    return {
        "schema_version": "canonical-scan-network-discovery/v1",
        "enabled": True,
        "status": status,
        "addresses": list(addresses),
        "actions": normalized,
        "observations": observations[:5000],
        "open_ports": open_ports[:5000],
        "services": services[:5000],
        "observation_count": len(observations),
        "observations_truncated": len(observations) > 5000,
        "partial": status == "partial",
        "timed_out": any(bool(action.get("timed_out")) for action in normalized),
        "errors": errors,
        "budget_consumed": consumed,
        "durable_budget_settled": all(
            bool(action.get("durable_budget_settled"))
            for action in normalized
            if action.get("status") != "skipped"
        ),
        "network_binding": "exact_address_subset",
    }


async def _reuse_placed_scan_network_discovery(
    *,
    parent_scan_id: str,
    source_scan_id: str,
    expected_summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify every placed network receipt before reusing its observations."""
    try:
        parent_uuid = uuid.UUID(str(parent_scan_id))
        source_uuid = uuid.UUID(str(source_scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCapabilityContractError(
            "placed network discovery identity is invalid"
        ) from exc
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT status, result
            FROM scans
            WHERE id=$1 AND parent_scan_id=$2 AND scan_role=$3
              AND status IN ('completed','failed')
            """,
            source_uuid,
            parent_uuid,
            parallel_scan.PARALLEL_DISCOVERY_ROLE,
        )
        if not row:
            raise ScanCapabilityContractError(
                "placed network discovery is unavailable"
            )
        source_result = _as_report_dict(row.get("result")) or {}
        durable_summary = source_result.get("network_discovery")
        if (
            not isinstance(durable_summary, Mapping)
            or dict(durable_summary) != dict(expected_summary)
        ):
            raise ScanCapabilityContractError(
                "placed network discovery summary changed before reuse"
            )
        actions = expected_summary.get("actions")
        receiptless_failure = bool(
            expected_summary.get("schema_version")
            == "canonical-scan-network-discovery/v1"
            and expected_summary.get("enabled") is True
            and isinstance(actions, list)
            and not actions
            and str(expected_summary.get("status") or "")
            in {"failed", "blocked"}
            and not expected_summary.get("observations")
            and int(expected_summary.get("observation_count") or 0) == 0
            and expected_summary.get("durable_budget_settled") is False
        )
        if receiptless_failure:
            reused = dict(expected_summary)
            reused["idempotent_redelivery"] = True
            reused["reused_from_placed_discovery"] = True
            reused["source_scan_id"] = str(source_uuid)
            return reused
        if not isinstance(actions, list) or not actions:
            raise ScanCapabilityContractError(
                "placed network discovery has no durable actions"
            )
        verified_capabilities: set[str] = set()
        for action in actions:
            if not isinstance(action, Mapping) or action.get("status") == "skipped":
                continue
            capability_name = str(action.get("capability_name") or "").strip()
            receipt_ref = (
                dict(action.get("receipt") or {})
                if isinstance(action.get("receipt"), Mapping) else {}
            )
            reservation_id = str(
                receipt_ref.get("budget_reservation_id") or ""
            ).strip()
            receipt_hash = str(
                receipt_ref.get("receipt_hash") or ""
            ).strip().lower()
            if (
                capability_name not in {"ports.discover", "service.fingerprint"}
                or not reservation_id
                or not re.fullmatch(r"[0-9a-f]{64}", receipt_hash)
            ):
                raise ScanCapabilityContractError(
                    "placed network discovery action has no durable receipt"
                )
            stored = await PostgresBudgetReservationStore().load(
                conn, reservation_id, for_update=False,
            )
            if (
                stored is None
                or stored.record.owner_kind != "scan"
                or stored.record.owner_id != str(source_uuid)
                or stored.record.capability_name != capability_name
                or not stored.record.terminal
                or not stored.receipt
                or str(stored.receipt.get("receipt_hash") or "").lower()
                != receipt_hash
                or str(stored.receipt.get("receipt_id") or "")
                != str(receipt_ref.get("receipt_id") or "")
                or str(stored.receipt.get("budget_reservation_state") or "")
                != stored.record.status
            ):
                raise ScanCapabilityContractError(
                    "placed network discovery receipt is not trustworthy"
                )
            verified_capabilities.add(capability_name)
    if "ports.discover" not in verified_capabilities:
        raise ScanCapabilityContractError(
            "placed network discovery has no port-discovery receipt"
        )
    reused = dict(expected_summary)
    reused["idempotent_redelivery"] = True
    reused["reused_from_placed_discovery"] = True
    reused["source_scan_id"] = str(source_uuid)
    return reused


async def _execute_scan_network_discovery(
    options: Mapping[str, Any],
    scan_id: str,
    *,
    job_id: str,
) -> dict[str, Any]:
    """Run approved Scan port and service discovery as canonical capabilities."""
    _normalized, admission = prepare_worker_dispatch(options)
    if not admission.canonical or admission.plan is None:
        return _skipped_scan_network_summary("legacy_scan")
    execution = build_native_scan_execution(admission.plan, options)
    policy = admission.plan.policy
    if not policy.network_discovery:
        return _skipped_scan_network_summary("policy_disabled")
    if (
        execution.shard_authority is not None
        and not execution.shard_authority.parallel_discovery
    ):
        return _skipped_scan_network_summary("assigned_endpoint_shard")
    if execution.skip_global_checks and not execution.discovery_manifest_only:
        return _skipped_scan_network_summary("global_checks_skipped")
    if execution.zero_rediscovery and not execution.discovery_manifest_only:
        return _skipped_scan_network_summary("rediscovery_disabled")
    placed_summary = options.get("canonical_network_discovery")
    placed_source_scan_id = str(
        options.get("canonical_network_discovery_source_scan_id") or ""
    ).strip()
    if isinstance(placed_summary, Mapping) or placed_source_scan_id:
        if not isinstance(placed_summary, Mapping) or not placed_source_scan_id:
            raise ScanCapabilityContractError(
                "placed network discovery reference is incomplete"
            )
        return await _reuse_placed_scan_network_discovery(
            parent_scan_id=scan_id,
            source_scan_id=placed_source_scan_id,
            expected_summary=placed_summary,
        )

    budget = execution.payload()["execution_budget"]
    target = execution.target_binding
    allocation = scan_network_capability_allocation(
        budget,
        available_address_count=len(target.allowed_addresses),
        reserved_tcp_ports=(
            1 if any(
                str(origin).lower().startswith("https://")
                for origin in target.allowed_origins
            ) else 0
        ),
    )
    addresses = tuple(
        target.allowed_addresses[:int(allocation["address_count"])]
    )
    bounded_target = TargetBinding(
        target_id=target.target_id,
        target_kind=target.target_kind,
        canonical_host=target.canonical_host,
        allowed_origins=target.allowed_origins,
        allowed_addresses=addresses,
        allowed_root_domains=target.allowed_root_domains,
        environment=target.environment,
        scope_receipt_id=target.scope_receipt_id,
    )
    port_stored, port_redelivery = (
        await _execute_reserved_scan_capability(
            admission=admission,
            execution=execution,
            scan_id=scan_id,
            job_id=job_id,
            capability_name="ports.discover",
            capability_args={"ports": list(allocation["ports"])},
            action_id="discover_network.ports",
            target_binding=bounded_target,
            reservation_limits=allocation["port_discovery_limits"],
        )
    )
    port_action = _scan_network_action_from_stored(
        port_stored, idempotent_redelivery=port_redelivery,
    )
    actions: list[Mapping[str, Any]] = [port_action]
    open_ports = sorted({
        int(item["port"])
        for item in port_action["observations"]
        if item.get("kind") == "open_port" and item.get("port")
    })
    fingerprint_limits = allocation.get("fingerprint_limits")
    if (
        open_ports
        and isinstance(fingerprint_limits, Mapping)
        and port_action["status"] in {"success", "partial"}
    ):
        fingerprint_stored, fingerprint_redelivery = (
            await _execute_reserved_scan_capability(
                admission=admission,
                execution=execution,
                scan_id=scan_id,
                job_id=job_id,
                capability_name="service.fingerprint",
                capability_args={
                    "ports": open_ports,
                    "profile": "version_light",
                },
                action_id="discover_network.services",
                target_binding=bounded_target,
                reservation_limits=fingerprint_limits,
            )
        )
        actions.append(_scan_network_action_from_stored(
            fingerprint_stored,
            idempotent_redelivery=fingerprint_redelivery,
        ))
    else:
        actions.append({
            "capability_name": "service.fingerprint",
            "status": "skipped",
            "reason": (
                "no_open_ports" if not open_ports
                else "insufficient_scan_budget"
                if not isinstance(fingerprint_limits, Mapping)
                else "port_discovery_not_usable"
            ),
            "observations": [],
            "observation_count": 0,
            "partial": False,
            "timed_out": False,
            "errors": [],
            "budget_consumed": {},
            "durable_budget_settled": True,
            "idempotent_redelivery": False,
        })
    return _scan_network_summary_from_actions(
        actions, addresses=addresses,
    )


def _attach_scan_network_summary(
    result: dict[str, Any], summary: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(summary, Mapping):
        return result
    public_summary = dict(summary)
    result["network_discovery"] = public_summary
    metadata = result.setdefault("scan_metadata", {})
    if isinstance(metadata, dict):
        metadata["network_discovery"] = {
            "status": public_summary.get("status"),
            "observation_count": int(
                public_summary.get("observation_count") or 0
            ),
            "partial": bool(public_summary.get("partial")),
            "timed_out": bool(public_summary.get("timed_out")),
            "budget_consumed": dict(
                public_summary.get("budget_consumed") or {}
            ),
            "durable_budget_settled": bool(
                public_summary.get("durable_budget_settled")
            ),
        }
    status = str(public_summary.get("status") or "").strip().lower()
    if status in {"blocked", "failed", "partial"}:
        coverage = (
            dict(result.get("coverage") or {})
            if isinstance(result.get("coverage"), Mapping) else {}
        )
        if str(coverage.get("status") or "") not in {"failed", "cancelled"}:
            coverage["status"] = "partial"
        reasons = [str(item) for item in coverage.get("reasons") or []]
        reason = f"network_discovery_{status}"
        if reason not in reasons:
            reasons.append(reason)
        coverage["reasons"] = reasons
        result["coverage"] = coverage
    return result


def _attach_scan_subdomain_summary(
    result: dict[str, Any], summary: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(summary, Mapping):
        return result
    public_summary = dict(summary)
    result["subdomain_discovery"] = public_summary
    metadata = result.setdefault("scan_metadata", {})
    if isinstance(metadata, dict):
        metadata["subdomain_discovery"] = {
            "status": public_summary.get("status"),
            "observation_count": int(
                public_summary.get("observation_count") or 0
            ),
            "partial": bool(public_summary.get("partial")),
            "timed_out": bool(public_summary.get("timed_out")),
            "budget_consumed": dict(
                public_summary.get("budget_consumed") or {}
            ),
            "durable_budget_settled": bool(
                public_summary.get("durable_budget_settled")
            ),
        }
    status = str(public_summary.get("status") or "").strip().lower()
    if status in {"blocked", "failed", "partial"}:
        coverage = (
            dict(result.get("coverage") or {})
            if isinstance(result.get("coverage"), Mapping) else {}
        )
        if str(coverage.get("status") or "") not in {"failed", "cancelled"}:
            coverage["status"] = "partial"
        reasons = [str(item) for item in coverage.get("reasons") or []]
        reason = f"subdomain_discovery_{status}"
        if reason not in reasons:
            reasons.append(reason)
        coverage["reasons"] = reasons
        result["coverage"] = coverage
    return result


def _empty_scan_request_collection_replay_summary() -> dict[str, Any]:
    return {
        "schema_version": "scan-request-collection-replay/v1",
        "attached_collections": 0,
        "executable_collections": 0,
        "discovery_only_collections": 0,
        "collections": [],
        "replayed": 0,
        "observation_count": 0,
        "status": "skipped",
        "cancelled": False,
        "observations": [],
        "budget_consumed": {},
        "partial": False,
        "secret_values_visible": False,
        "durable_budget_settled": True,
        "network_binding": "runtime_target_binding",
    }


def _scan_request_collection_capability_names(
    options: Mapping[str, Any],
) -> tuple[str, ...]:
    names: list[str] = []
    for item in options.get("request_collections") or ():
        if not isinstance(item, Mapping):
            continue
        replay_policy = str(item.get("replay_policy") or "").strip().lower()
        name = {
            "safe_reads": "collections.replay_safe",
            "confirmed_active": "collections.replay_active",
        }.get(replay_policy)
        if name and name not in names:
            names.append(name)
    return tuple(names)


async def _bind_scan_replay_primary_credential(
    conn: Any,
    *,
    plan: Any,
    target: TargetBinding,
    scan_id: str,
    options: Mapping[str, Any],
    trusted_primary_headers: Mapping[str, str] | None = None,
) -> tuple[Any, dict[str, Any] | None]:
    """Independently resolve the Scan primary identity into one exact replay plan."""
    refs = [
        dict(item)
        for item in options.get("credential_profile_refs") or []
        if isinstance(item, Mapping)
    ]
    primary = next(
        (item for item in refs if str(item.get("scan_lane") or "") == "primary"),
        None,
    )
    if primary is None:
        return plan, None
    try:
        expected_version = int(primary.get("profile_version") or 0)
        profile_id = str(uuid.UUID(str(primary.get("profile_id") or "")))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ReplayExecutionError(
            "Scan replay credential reference is invalid"
        ) from exc
    if expected_version < 1:
        raise ReplayExecutionError("Scan replay credential version is invalid")
    action_name = str(options.get("credential_action_name") or "").strip()
    authority = await validate_worker_credential_authority(
        conn,
        owner_kind="scan",
        owner_id=scan_id,
        target=target,
        approval_receipt_id=options.get("approval_receipt_id"),
        scope_receipt_id=options.get("scope_receipt_id"),
        action_name=action_name,
    )
    async with WorkerCredentialResolver().resolve(
        conn,
        profile_id=profile_id,
        target=target,
        capability=SCAN_CREDENTIAL_CAPABILITY,
        authority=authority,
    ) as resolved:
        if (
            resolved.profile.current_version != expected_version
            or resolved.profile.auth_kind != str(primary.get("auth_kind") or "")
            or resolved.profile.principal_slot
            != str(primary.get("principal_slot") or "")
            or resolved.profile.target_kind != target.target_kind
        ):
            raise ReplayExecutionError(
                "Scan replay credential changed after admission"
            )
        try:
            headers = resolved.http_headers().as_dict()
        except CredentialResolutionError as exc:
            if (
                resolved.profile.auth_kind not in {
                    "form_login", "oauth_client_credentials", "oauth_password",
                }
                or not trusted_primary_headers
            ):
                raise ReplayExecutionError(
                    "exact collection replay requires an established primary session"
                ) from exc
            headers = dict(trusted_primary_headers)
        bound = bind_replay_credential_headers(
            plan, headers, auth_kind=resolved.profile.auth_kind,
        )
        receipt_context = {
            "principal_profile_ref": resolved.profile.profile_id,
            "principal_profile_version": resolved.profile.current_version,
            "principal_slot": resolved.profile.principal_slot,
        }
    return bound, receipt_context


async def _execute_scan_request_collections(
    options: Mapping[str, Any], scan_id: str, *, job_id: str,
    runtime_request_grant: int | None = None,
    trusted_primary_headers: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Execute saved Scan selections through the canonical exact replay executor."""
    try:
        scan_uuid = uuid.UUID(str(scan_id))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ScanCollectionReplayContractError("Scan replay owner ID is invalid") from exc

    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """SELECT s.id, s.target_id, s.target_url, s.status, s.options,
                      s.policy_json, s.budget_json, s.budget_used_json,
                      t.root_domain
               FROM scans s JOIN targets t ON t.id=s.target_id
               WHERE s.id=$1""",
            scan_uuid,
        )
    if not row:
        raise ScanCollectionReplayContractError("Scan replay owner is unavailable")
    persisted_options = _worker_json_object(row["options"])
    refs = [
        dict(item)
        for item in persisted_options.get("request_collections") or []
        if isinstance(item, Mapping)
    ]
    executable = [
        item
        for item in refs
        if str(item.get("replay_policy") or "").strip().lower()
        in EXECUTABLE_REPLAY_POLICIES
    ]
    summary = _empty_scan_request_collection_replay_summary()
    summary.update({
        "attached_collections": len(refs),
        "executable_collections": len(executable),
        "discovery_only_collections": len(refs) - len(executable),
    })
    if not executable:
        return summary
    summary["status"] = "success"
    if str(row["status"] or "") != "running":
        raise ScanCollectionReplayContractError("Scan is no longer executable")

    scan_policy = _worker_json_object(row["policy_json"])
    if not scan_policy:
        scan_policy = _worker_json_object(persisted_options.get("scan_policy"))
    budget = _worker_json_object(row["budget_json"])
    limits = scan_replay_ledger_limits(budget)
    runtime_budget_options = dict(persisted_options)
    if runtime_request_grant is not None:
        runtime_budget_options["request_budget_mode"] = "enforce"
        runtime_budget_options["request_budget_reserved"] = runtime_request_grant
    runtime_http_ceiling = scan_replay_runtime_http_ceiling(
        runtime_budget_options, budget,
    )
    guard = _worker_json_object(persisted_options.get("runtime_scope_guard"))
    target_id = str(row["target_id"] or "")
    parsed_target = urllib.parse.urlsplit(str(row["target_url"] or ""))
    canonical_host = str(parsed_target.hostname or "").strip().lower().rstrip(".")
    target_kind = str(guard.get("target_kind") or executable[0].get("target_kind") or "")
    if (
        str(guard.get("target_id") or "") != target_id
        or str(guard.get("canonical_host") or "").lower().rstrip(".") != canonical_host
        or target_kind not in {"web", "api"}
    ):
        raise ScanCollectionReplayContractError(
            "Scan replay runtime target binding is incomplete"
        )
    allowed_addresses = tuple(
        str(item) for item in guard.get("allowed_addresses") or () if str(item)
    )
    guard_origins = tuple(
        str(item) for item in guard.get("allowed_origins") or () if str(item)
    )
    if not allowed_addresses or not guard_origins:
        raise ScanCollectionReplayContractError(
            "Scan replay requires frozen origins and target addresses"
        )
    roots = tuple(
        str(item).strip().lower().rstrip(".")
        for item in guard.get("allowed_root_domains") or ()
        if str(item).strip()
    ) or (str(row["root_domain"] or canonical_host).lower().rstrip("."),)
    store = PostgresBudgetReservationStore()
    worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"

    for ref in executable:
        try:
            collection_id = str(uuid.UUID(str(ref.get("collection_id") or "")))
            binding_id = str(uuid.UUID(str(ref.get("binding_id") or "")))
            selection_id = str(uuid.UUID(str(ref.get("selection_id") or "")))
        except (TypeError, ValueError, AttributeError) as exc:
            raise ScanCollectionReplayContractError(
                "Scan replay requires a saved collection selection"
            ) from exc
        replay_policy = str(ref.get("replay_policy") or "").strip().lower()
        replay_capability_name = (
            "collections.replay_active"
            if replay_policy == "confirmed_active"
            else "collections.replay_safe"
        )
        expected_payload_sha256 = str(ref.get("payload_sha256") or "").lower()
        expected_selection_digest = str(ref.get("selection_digest") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_payload_sha256):
            raise ScanCollectionReplayContractError(
                "Scan replay collection digest is invalid"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", expected_selection_digest):
            raise ScanCollectionReplayContractError(
                "Scan replay selection digest is invalid"
            )
        expected_environment_id = str(ref.get("environment_id") or "").strip() or None
        if expected_environment_id:
            expected_environment_id = str(uuid.UUID(expected_environment_id))
        expected_environment_sha256 = str(
            ref.get("environment_sha256") or ""
        ).lower() or None
        if expected_environment_sha256 and not re.fullmatch(
            r"[0-9a-f]{64}", expected_environment_sha256
        ):
            raise ScanCollectionReplayContractError(
                "Scan replay environment digest is invalid"
            )
        queued_origins = tuple(
            str(item) for item in ref.get("allowed_origins") or () if str(item)
        )
        if (
            str(ref.get("target_id") or "") != target_id
            or str(ref.get("target_kind") or "") != target_kind
            or not queued_origins
            or any(origin not in guard_origins for origin in queued_origins)
        ):
            raise ScanCollectionReplayContractError(
                "Scan replay selection exceeds the frozen target binding"
            )

        async with db_pool.acquire() as conn:
            async with conn.transaction():
                collection = await conn.fetchrow(
                    """SELECT c.id, c.encrypted_payload, c.payload_sha256,
                              b.id AS binding_id, b.allowed_origins, b.environment_id,
                              e.encrypted_payload AS encrypted_environment,
                              e.payload_sha256 AS environment_sha256,
                              s.id AS selection_id, s.replay_policy, s.selector_json,
                              s.selection_digest
                       FROM request_collections c
                       JOIN request_collection_bindings b
                         ON b.id=$2 AND b.collection_id=c.id AND b.is_active=true
                       JOIN request_collection_selections s
                         ON s.id=$3 AND s.collection_id=c.id
                        AND s.binding_id=b.id AND s.is_active=true
                       LEFT JOIN request_collection_environments e
                         ON e.id=b.environment_id AND e.collection_id=c.id
                        AND e.is_active=true
                       WHERE c.id=$1 AND c.target_id=$4 AND c.is_active=true
                         AND b.target_id=$4 AND b.target_kind=$5
                       FOR UPDATE OF c, b, s""",
                    uuid.UUID(collection_id), uuid.UUID(binding_id),
                    uuid.UUID(selection_id), row["target_id"], target_kind,
                )
        if not collection:
            raise ScanCollectionReplayContractError(
                "Scan request collection selection is unavailable or target-mismatched"
            )
        stored_origins = tuple(
            str(item) for item in _worker_json_array(collection["allowed_origins"])
            if str(item)
        )
        stored_environment_id = (
            str(collection["environment_id"])
            if collection["environment_id"] else None
        )
        stored_environment_sha256 = (
            str(collection["environment_sha256"] or "").lower() or None
        )
        if str(collection["payload_sha256"] or "").lower() != expected_payload_sha256:
            raise ScanCollectionReplayContractError(
                "Scan request collection payload changed after admission"
            )
        if stored_origins != queued_origins:
            raise ScanCollectionReplayContractError(
                "Scan request collection origin binding changed after admission"
            )
        if stored_environment_id != expected_environment_id:
            raise ScanCollectionReplayContractError(
                "Scan request collection environment binding changed after admission"
            )
        if stored_environment_sha256 != expected_environment_sha256:
            raise ScanCollectionReplayContractError(
                "Scan request collection environment changed after admission"
            )
        if str(collection["replay_policy"] or "") != replay_policy:
            raise ScanCollectionReplayContractError(
                "Scan request collection replay policy changed after admission"
            )
        stored_selection = RequestCollectionSelection.from_mapping(
            _worker_json_object(collection["selector_json"])
        )
        recomputed_selection_digest = request_collection_selection_digest(
            collection_id=collection_id,
            payload_sha256=expected_payload_sha256,
            binding_id=binding_id,
            allowed_origins=stored_origins,
            selector=stored_selection,
            replay_policy=replay_policy,
            environment_sha256=stored_environment_sha256,
        )
        if (
            str(collection["selection_digest"] or "").lower()
            != expected_selection_digest
            or recomputed_selection_digest != expected_selection_digest
        ):
            raise ScanCollectionReplayContractError(
                "Scan request collection selection changed after admission"
            )

        raw_payload = str(decrypt_secret(collection["encrypted_payload"]) or "")
        if not raw_payload or raw_payload.startswith("enc:fernet:"):
            raise ScanCollectionReplayContractError(
                "Scan request collection could not be decrypted on the worker"
            )
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ScanCollectionReplayContractError(
                "Scan request collection payload is invalid"
            ) from exc
        if not isinstance(payload, Mapping):
            raise ScanCollectionReplayContractError(
                "Scan request collection payload is not an object"
            )
        payload_digest = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        if payload_digest != expected_payload_sha256:
            raise ScanCollectionReplayContractError(
                "Scan request collection failed its worker integrity check"
            )
        if expected_environment_id:
            raw_environment = str(
                decrypt_secret(collection["encrypted_environment"]) or ""
            )
            if not raw_environment or raw_environment.startswith("enc:fernet:"):
                raise ScanCollectionReplayContractError(
                    "Scan request collection environment could not be decrypted on the worker"
                )
            try:
                environment = json.loads(raw_environment)
            except json.JSONDecodeError as exc:
                raise ScanCollectionReplayContractError(
                    "Scan request collection environment payload is invalid"
                ) from exc
            if not isinstance(environment, Mapping):
                raise ScanCollectionReplayContractError(
                    "Scan request collection environment payload is not an object"
                )
            environment_digest = hashlib.sha256(json.dumps(
                environment, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")).hexdigest()
            if environment_digest != expected_environment_sha256:
                raise ScanCollectionReplayContractError(
                    "Scan request collection environment failed its integrity check"
                )
            payload = {**dict(payload), "environment": dict(environment)}

        async with db_pool.acquire() as conn:
            current_used = _worker_json_object(await conn.fetchval(
                "SELECT budget_used_json FROM scans WHERE id=$1", scan_uuid,
            ))
        consumed = {key: int(current_used.get(key) or 0) for key in limits}
        capacity = remaining_scan_replay_capacity(
            limits=limits,
            consumed=consumed,
            runtime_http_ceiling=runtime_http_ceiling,
        )
        if capacity.http_requests < 1 or capacity.tool_wall_seconds < 1:
            raise ScanCollectionReplayContractError(
                "Scan budget leaves no capacity for exact collection replay"
            )
        wall_reservation = min(300, capacity.tool_wall_seconds)
        runtime_limit = min(capacity.http_requests, wall_reservation * 10)
        runtime_selector = scan_replay_selector(
            stored_selection, replay_policy, runtime_limit=runtime_limit,
        )
        selected = select_requests(payload, runtime_selector)
        if not selected:
            summary["collections"].append({
                "collection_id": collection_id,
                "selection_id": selection_id,
                "capability_name": replay_capability_name,
                "replay_policy": replay_policy,
                "status": "skipped",
                "reason": "saved_selection_resolved_to_no_requests",
                "secret_values_visible": False,
            })
            continue
        target_binding = TargetBinding(
            target_id=target_id,
            target_kind=target_kind,
            canonical_host=canonical_host,
            allowed_origins=stored_origins,
            allowed_addresses=allowed_addresses,
            allowed_root_domains=roots,
            environment=str(guard.get("environment") or "unknown"),
            scope_receipt_id=str(persisted_options.get("scope_receipt_id") or "") or None,
        )
        authorization = scan_replay_authorization(
            replay_policy,
            scan_policy,
            approval_receipt_id=persisted_options.get("approval_receipt_id"),
        )
        plan = build_selected_replay_plan(
            payload,
            runtime_selector,
            allowed_origins=target_binding.allowed_origins,
            default_origin=(
                target_binding.allowed_origins[0]
                if target_binding.allowed_origins else None
            ),
            authorization=authorization,
        )
        async with db_pool.acquire() as conn:
            plan, receipt_context = await _bind_scan_replay_primary_credential(
                conn,
                plan=plan,
                target=target_binding,
                scan_id=scan_id,
                options=persisted_options,
                trusted_primary_headers=trusted_primary_headers,
            )

        additional_budget = {"tool_wall_seconds": wall_reservation}
        requested_budget = replay_reservation_budget(plan, additional_budget)
        reservation_id = str(uuid.uuid4())
        action_id = f"collection_replay:{selection_id}"
        requested = DurableBudgetReservation.request(
            owner_kind="scan",
            owner_id=scan_id,
            capability_name="collections.replay",
            amounts=requested_budget,
            reservation_id=reservation_id,
        )
        persisted = None
        held_ledger: dict[str, int] = {}
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT status, budget_json, budget_used_json FROM scans "
                    "WHERE id=$1 FOR UPDATE",
                    scan_uuid,
                )
                if not locked or str(locked["status"] or "") != "running":
                    raise ReplayExecutionError(
                        "Scan stopped before collection replay admission"
                    )
                stored = await store.create_requested(
                    conn,
                    action_id=action_id,
                    action_digest=plan.input_digest,
                    record=requested,
                )
                if stored.record.terminal:
                    if stored.record.status != "committed" or not stored.receipt:
                        raise ReplayExecutionError(
                            "previous Scan collection replay is terminal without success"
                        )
                    public_receipt = dict(stored.receipt)
                    observations = list(public_receipt.get("observations") or [])
                    summary["collections"].append({
                        "collection_id": collection_id,
                        "selection_id": selection_id,
                        "capability_name": replay_capability_name,
                        "replay_policy": replay_policy,
                        "status": "succeeded",
                        "replayed": int(stored.record.actual.get("http_requests") or 0),
                        "idempotent_redelivery": True,
                        "receipt": _scan_replay_receipt_reference(public_receipt),
                        "secret_values_visible": False,
                    })
                    summary["replayed"] += int(
                        stored.record.actual.get("http_requests") or 0
                    )
                    summary["observation_count"] += len(observations)
                    remaining_observation_slots = max(
                        0, 500 - len(summary["observations"])
                    )
                    summary["observations"].extend(
                        observations[:remaining_observation_slots]
                    )
                    summary["budget_consumed"] = merge_scan_budget_usage(
                        summary["budget_consumed"], stored.record.actual,
                    )
                    continue
                if stored.record.status != "requested":
                    raise ReservationConflict(
                        "Scan collection replay already has an active durable reservation"
                    )
                current_used = _worker_json_object(locked["budget_used_json"])
                current_consumed = {
                    key: int(current_used.get(key) or 0) for key in limits
                }
                try:
                    reserved, held_ledger = stored.record.reserve_against(
                        limits=limits,
                        consumed=current_consumed,
                        lease_seconds=max(90, wall_reservation + 10),
                    )
                except BudgetExceeded as exc:
                    released = stored.record.release(
                        proof_not_started=True,
                        reason="budget_exhausted_before_execution",
                    )
                    await store.persist_terminal(
                        conn,
                        previous=stored,
                        terminal=released,
                        ledger_after_settlement=current_consumed,
                        receipt=None,
                    )
                    dimension = next(iter(exc.shortages), "unknown")
                    raise ScanCollectionReplayContractError(
                        f"Scan collection replay budget exhausted: {dimension}"
                    ) from exc
                persisted = await store.persist_transition(
                    conn,
                    previous=stored,
                    current=reserved,
                    ledger_after_hold=held_ledger,
                )
                current_used.update(held_ledger)
                await conn.execute(
                    "UPDATE scans SET budget_used_json=$2 WHERE id=$1",
                    scan_uuid, json.dumps(current_used),
                )

        settled_ledger = dict(held_ledger)

        async def persist_runtime_transition(
            current: DurableBudgetReservation, _ledger: Mapping[str, int],
        ) -> None:
            nonlocal persisted
            if persisted is None:
                raise ReservationStoreError(
                    "Scan replay reservation persistence was not initialized"
                )
            async with db_pool.acquire() as conn:
                async with conn.transaction():
                    owner = await conn.fetchrow(
                        "SELECT status FROM scans WHERE id=$1 FOR UPDATE", scan_uuid,
                    )
                    if not owner or str(owner["status"] or "") != "running":
                        raise ReplayExecutionError(
                            "Scan stopped before the next collection replay request"
                        )
                    latest = await store.load(
                        conn, persisted.record.reservation_id, for_update=True,
                    )
                    if (
                        latest is None
                        or latest.record.state_digest != persisted.record.state_digest
                    ):
                        raise ReservationConflict(
                            "Scan replay reservation changed before worker transition"
                        )
                    persisted = await store.persist_transition(
                        conn, previous=latest, current=current,
                    )

        async def persist_runtime_settlement(
            terminal: DurableBudgetReservation,
            receipt: Any,
            _ledger: Mapping[str, int],
        ) -> None:
            nonlocal persisted, settled_ledger
            if persisted is None:
                raise ReservationStoreError(
                    "Scan replay reservation persistence was not initialized"
                )
            async with db_pool.acquire() as conn:
                async with conn.transaction():
                    locked = await conn.fetchrow(
                        "SELECT budget_json, budget_used_json FROM scans "
                        "WHERE id=$1 FOR UPDATE",
                        scan_uuid,
                    )
                    if not locked:
                        raise ReservationStoreError(
                            "Scan disappeared during collection replay settlement"
                        )
                    latest = await store.load(
                        conn, persisted.record.reservation_id, for_update=True,
                    )
                    if (
                        latest is None
                        or latest.record.state_digest != persisted.record.state_digest
                    ):
                        raise ReservationConflict(
                            "Scan replay reservation changed before settlement"
                        )
                    current_used = _worker_json_object(locked["budget_used_json"])
                    current_ledger = {
                        key: int(current_used.get(key) or 0) for key in limits
                    }
                    settled_ledger = terminal.reconcile_consumed(current_ledger)
                    persisted = await store.persist_terminal(
                        conn,
                        previous=latest,
                        terminal=terminal,
                        ledger_after_settlement=settled_ledger,
                        receipt=receipt,
                    )
                    current_used.update(settled_ledger)
                    await conn.execute(
                        "UPDATE scans SET budget_used_json=$2 WHERE id=$1",
                        scan_uuid, json.dumps(current_used),
                    )

        replay_spec = agent_tools.CAPABILITY_REGISTRY.require(
            replay_capability_name
        )
        replay_adapter = ReplayExecutionAdapter(
            specification=replay_spec,
            execution_kwargs={
                "plan": plan,
                "target": target_binding,
                "owner_kind": "scan",
                "owner_id": scan_id,
                "worker_id": worker_id,
                "limits": limits,
                "consumed": held_ledger,
                "transport": PinnedAiohttpReplayTransport(),
                "timeout_seconds": max(
                    0.1,
                    min(
                        30.0,
                        float(wall_reservation) / len(plan.requests),
                    ),
                ),
                "reservation_id": persisted.record.reservation_id,
                "lease_seconds": max(90, wall_reservation + 10),
                "on_reservation": persist_runtime_transition,
                "on_settlement": persist_runtime_settlement,
                "require_durable_persistence": True,
                "additional_budget": additional_budget,
                "initial_reservation": persisted.record,
                "receipt_context": receipt_context,
            },
        )
        execution = await CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=replay_spec,
                target=target_binding,
                requested_budget=persisted.record.requested,
                adapter_managed_cancellation=True,
            ),
            replay_adapter,
            heartbeat=lambda: asyncio.sleep(0),
            cancelled=lambda: _scan_cancel_requested(scan_id),
        )
        outcome = replay_adapter.outcome
        if outcome is None:
            raise ReplayExecutionError(
                execution.errors[0]
                if execution.errors
                else "replay capability failed before durable settlement"
            )
        public_receipt = outcome.receipt.public_dict()
        observations = list(public_receipt.get("observations") or [])
        item_status = (
            "succeeded" if outcome.reservation.status == "committed"
            and outcome.status == "succeeded" else outcome.status
        )
        summary["collections"].append({
            "collection_id": collection_id,
            "selection_id": selection_id,
            "capability_name": replay_capability_name,
            "replay_policy": replay_policy,
            "status": item_status,
            "partial": bool(outcome.receipt.partial),
            "replayed": int(outcome.reservation.actual.get("http_requests") or 0),
            "safe_methods_only": runtime_selector.safe_methods_only,
            "runtime_limit": runtime_selector.limit,
            "selection_truncated_by_budget": (
                runtime_selector.limit < stored_selection.max_requests
            ),
            "receipt": _scan_replay_receipt_reference(public_receipt),
            "secret_values_visible": False,
        })
        summary["partial"] = bool(
            summary["partial"] or outcome.receipt.partial
        )
        summary["replayed"] += int(
            outcome.reservation.actual.get("http_requests") or 0
        )
        summary["observation_count"] += len(observations)
        remaining_observation_slots = max(0, 500 - len(summary["observations"]))
        summary["observations"].extend(
            observations[:remaining_observation_slots]
        )
        summary["budget_consumed"] = merge_scan_budget_usage(
            summary["budget_consumed"], outcome.reservation.actual,
        )
        if outcome.status == "cancelled":
            summary["status"] = "cancelled"
            summary["cancelled"] = True
            return summary
        if outcome.reservation.status != "committed":
            raise ScanCollectionReplayContractError(
                "Scan collection replay failed before producing a trusted terminal result: "
                f"{outcome.reservation.failure_reason or 'executor_failed'}"
            )

    summary["observations_truncated"] = (
        summary["observation_count"] > len(summary["observations"])
    )
    if summary["partial"]:
        summary["status"] = "partial"
    return summary


def _apply_scan_collection_replay_remaining_budget(
    options: Mapping[str, Any], summary: Mapping[str, Any],
) -> dict[str, Any]:
    """Prevent the compatibility scanner from reusing exact replay request budget."""
    adjusted = dict(options or {})
    consumed = _worker_json_object(summary.get("budget_consumed"))
    http_used = max(0, int(consumed.get("http_requests") or 0))
    writes_used = max(0, int(consumed.get("state_changing_requests") or 0))
    custom = dict(adjusted.get("custom_budget") or {})
    try:
        current_request_max = int(custom.get("request_max") or 0)
    except (TypeError, ValueError):
        current_request_max = 0
    if current_request_max > 0 and http_used:
        custom["request_max"] = max(1, current_request_max - http_used)
    try:
        current_active_max = int(custom.get("active_max_endpoints") or 0)
    except (TypeError, ValueError):
        current_active_max = 0
    if current_active_max > 0 and writes_used:
        custom["active_max_endpoints"] = max(1, current_active_max - writes_used)
    adjusted["custom_budget"] = custom
    adjusted["request_collection_replay_consumed"] = {
        "http_requests": http_used,
        "state_changing_requests": writes_used,
        "secret_values_visible": False,
    }
    return adjusted


async def process_scan_job(job_data: dict):
    """Process a scan job."""
    job_id = job_data.get('job_id', 'unknown')
    scan_id = job_data.get('scan_id')
    target = job_data.get('target')
    options = job_data.get('options', {})
    if job_data.get("asm_recon"):
        options = dict(options or {})
        options.setdefault("run_kind", "asm_recon")
    campaign_id = job_data.get('campaign_id')

    print(f"[{job_id[:8]}] Starting scan: {target}", flush=True)
    print(f"[{job_id[:8]}] Options keys: {list(options.keys())}", flush=True)
    print(f"[{job_id[:8]}] auth_header present: {bool(options.get('auth_header'))}", flush=True)
    print(f"[{job_id[:8]}] custom_endpoints: {len(options.get('custom_endpoints') or [])} endpoints", flush=True)

    r = get_redis()
    now = utc_now()
    if job_data.get("_broker_lease_id"):
        try:
            async with db_pool.acquire() as conn:
                leased_at = await conn.fetchval(
                    "SELECT created_at FROM broker_job_leases WHERE id=$1",
                    uuid.UUID(str(job_data["_broker_lease_id"])),
                )
            normalized_lease_time = _naive_utc_timestamp(leased_at)
            if normalized_lease_time:
                now = normalized_lease_time
        except (ValueError, TypeError):
            pass

    current_status = await _confirmed_scan_handoff_status(scan_id)
    broker_ingest = bool(job_data.get("_broker_result_id"))
    if current_status not in ({'pending', 'queued', 'running'} if broker_ingest else {'pending', 'queued'}):
        print(f"[{job_id[:8]}] Scan is {current_status}; queued worker job skipped", flush=True)
        r.hset(
            f"job:{job_id}",
            mapping={
                'status': current_status,
                'progress': '100' if current_status in {'completed', 'cancelled', 'failed'} else '0',
                'current_phase': current_status,
            },
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
    r.delete(f"scan:{scan_id}:device_activity")

    # Update database
    target_id = None
    ai_target_id = None
    device_target_id = None
    async with db_pool.acquire() as conn:
        update_result = await conn.execute("""
            UPDATE scans SET status = 'running', started_at = $1
            WHERE id = $2
              AND (status IN ('pending', 'queued') OR ($3::boolean AND status='running'))
        """, now, uuid.UUID(scan_id), broker_ingest)
        if update_result.endswith("0"):
            latest_status = await conn.fetchval(
                "SELECT status FROM scans WHERE id=$1",
                uuid.UUID(scan_id),
            )
            latest_status = str(latest_status or 'not_claimable')
            print(f"[{job_id[:8]}] Scan became {latest_status} before worker claim; skipping", flush=True)
            r.hset(
                f"job:{job_id}",
                mapping={
                    'status': latest_status,
                    'progress': '100' if latest_status in {'completed', 'cancelled', 'failed'} else '0',
                    'current_phase': latest_status,
                },
            )
            r.expire(f"job:{job_id}", 86400)
            return

        # Get target references
        row = await conn.fetchrow("SELECT target_id, ai_target_id, device_target_id FROM scans WHERE id = $1", uuid.UUID(scan_id))
        if row:
            target_id = str(row['target_id']) if row['target_id'] else None
            ai_target_id = str(row['ai_target_id']) if row['ai_target_id'] else None
            device_target_id = str(row['device_target_id']) if row['device_target_id'] else None

    # A broker ingest job carries immutable output from execution that already
    # happened on the remote node. It must not reserve execution budget again:
    # doing so can strand a submitted result behind its own still-live broker
    # reservation and can requeue trusted ingestion as executable work.
    reserve_amount = 0 if broker_ingest else _standalone_scan_rate_reservation_amount(options)
    runtime_request_grant: int | None = None
    enforcing_request_budget = _effective_request_budget_mode(options) == "enforce"
    if reserve_amount > 0 and target_id:
        try:
            async with db_pool.acquire() as conn:
                rate = await _reserve_target_domain_endpoint_budget(
                    conn,
                    r,
                    target_id=target_id,
                    amount=reserve_amount,
                    already_reserved=int(job_data.get('domain_rate_reserved') or 0),
                    all_or_nothing=False,
                )
        except Exception as exc:
            rate = {"granted": 0, "limited": True, "requested": reserve_amount, "reason": str(exc)}
        granted = max(0, int(rate.get("granted") or 0))
        if granted <= 0 and rate.get("limited"):
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """UPDATE scans
                       SET status='queued', current_phase='waiting_for_domain_rate',
                           progress=5, started_at=NULL
                       WHERE id=$1 AND status <> 'cancelled'""",
                    uuid.UUID(scan_id),
                )
            await _requeue_for_domain_rate(
                r,
                job_data,
                job_id=job_id,
                scan_id=scan_id,
                log_prefix=job_id[:8],
                rate=rate,
            )
            return
        if 0 < granted < reserve_amount:
            options = dict(options or {})
            budget = dict(options.get("custom_budget") or {})
            if enforcing_request_budget:
                budget["request_max"] = granted
            else:
                budget["active_max_endpoints"] = granted
            options["custom_budget"] = budget
            options[
                "domain_rate_request_grant"
                if enforcing_request_budget
                else "domain_rate_active_endpoint_grant"
            ] = granted
            print(
                f"[{job_id[:8]}] domain rate limited standalone scan "
                f"{'request' if enforcing_request_budget else 'active endpoint'} budget "
                f"to {granted}/{reserve_amount} for {rate.get('root_domain') or 'unknown'}",
                flush=True,
            )
        if granted > 0:
            options = dict(options or {})
            options["request_budget_reserved"] = granted
            if enforcing_request_budget:
                runtime_request_grant = granted
            if rate.get("root_domain"):
                options["request_budget_domain"] = str(rate["root_domain"])

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

    collection_replay_summary: dict[str, Any] = {}
    try:
        try:
            if job_data.get("_broker_result_id"):
                result = await _load_broker_result(job_data, scan_id)
            else:
                options = await _hydrate_generic_scan_credentials(options, scan_id)
                options = await _hydrate_managed_scan_credentials(options, scan_id)
                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    options = await _hydrate_device_scan_credentials(options, scan_id)
                    options = await _hydrate_device_request_collections(options, scan_id)
                if is_deterministic_dast(options):
                    result = await _execute_reserved_deterministic_scan(
                        target,
                        options,
                        scan_id=scan_id,
                        job_id=job_id,
                        runtime_request_grant=runtime_request_grant,
                        collection_replay_result_holder=collection_replay_summary,
                    )
                else:
                    result = await run_scan(
                        target, options, scan_id=scan_id, job_id=job_id,
                    )
                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    posture_result = result.get("device_posture") if isinstance(result, dict) and isinstance(result.get("device_posture"), dict) else {}
                    _append_device_activity(
                        scan_id,
                        kind="inventory",
                        phase="device_inventory_complete",
                        message="Device inventory completed; preparing web and API checks",
                        progress=91,
                        details={
                            "confirmed_services": len(posture_result.get("services") or []),
                            "web_origins": len(posture_result.get("web_origins") or []),
                        },
                    )
                    result = await run_device_web_children(
                        parent_scan_id=scan_id,
                        device_target_id=device_target_id,
                        parent_job_id=job_id,
                        parent_options=options,
                        result=result,
                    )
                    if (options or {}).get("candidate_id"):
                        try:
                            await prepare_device_candidate_posture_result(
                                result=result,
                                options=options,
                                device_target_id=device_target_id,
                                target=str(target or ""),
                            )
                        except Exception as candidate_error:
                            result["candidate_verification"] = {
                                "candidate_id": str((options or {}).get("candidate_id") or "") or None,
                                "status": "inconclusive",
                                "error": f"candidate_verifier_fault:{type(candidate_error).__name__}",
                            }
                    try:
                        await correlate_device_advisory_lifecycle(
                            result=result,
                            device_target_id=device_target_id,
                        )
                    except Exception as advisory_error:
                        posture_result = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
                        posture_result["advisory_correlation"] = {
                            "status": "error",
                            "error": f"advisory_correlation_fault:{type(advisory_error).__name__}",
                            "runtime_egress": False,
                        }
                        result["device_posture"] = posture_result
        except ValueError as e:
            # Validation errors (e.g., incompatible options like public+smart)
            result = {
                'target': target,
                'error': str(e),
                'result': {'score': None, 'grade': None},
                'findings': []
            }
            print(f"[{job_id[:8]}] Validation error: {e}", flush=True)
        except Exception as e:
            result = _unexpected_scan_exception_result(str(target or ""), e)
            print(f"[{job_id[:8]}] Unexpected scan failure: {result['error']}", flush=True)

        if collection_replay_summary:
            result["request_collection_replay"] = collection_replay_summary
        result['job_id'] = job_id
        result['scan_id'] = scan_id
        result = _apply_runtime_scope_guard_to_result(result, options)
        if device_target_id and (options or {}).get("run_kind") == "device_posture":
            await _persist_device_credential_attempts(result, scan_id)
        if device_target_id and (options or {}).get("run_kind") == "device_probe" and not result.get("error"):
            try:
                await prepare_device_candidate_probe_result(
                    result=result,
                    options=options,
                    device_target_id=device_target_id,
                    target=str(target or ""),
                )
            except Exception as candidate_error:
                result["candidate_verification"] = {
                    "candidate_id": str((options or {}).get("candidate_id") or "") or None,
                    "status": "inconclusive",
                    "error": f"candidate_verifier_fault:{type(candidate_error).__name__}",
                }

        # Extract results (run_scan already strips NUL bytes from the whole result so
        # the scans.result write and findings rows can't crash on \x00; save_findings
        # strips again as a defense-in-depth guard for findings from other sources.)
        score = result.get('result', {}).get('score')
        grade = result.get('result', {}).get('grade')
        findings = result.get('findings', [])
        error = result.get('error')
        result_coverage = result.get("coverage") if isinstance(result.get("coverage"), dict) else {}
        if not result_coverage:
            smart_coverage = result.get("smart_coverage") if isinstance(result.get("smart_coverage"), dict) else {}
            quality_metrics = result.get("quality_metrics") if isinstance(result.get("quality_metrics"), dict) else {}
            coverage_status = str(
                options.get("coverage_status") or smart_coverage.get("status")
                or quality_metrics.get("coverage_status") or ("failed" if error else "complete")
            )
            result_coverage = {
                "status": coverage_status,
                "reasons": list(options.get("coverage_reasons") or []),
            }
        coverage_status = str(result_coverage.get("status") or ("failed" if error else "complete"))
        scan_metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
        scanner_budget_used = (
            scan_metadata.get("budget_used")
            if isinstance(scan_metadata.get("budget_used"), dict) else {}
        )
        # Durable replay settlement is authoritative even when a later collection
        # contract fails before the helper can return its summary.  Reload it so the
        # legacy terminal Scan update can never erase a held or settled reservation.
        async with db_pool.acquire() as conn:
            replay_budget_used = _worker_json_object(await conn.fetchval(
                "SELECT budget_used_json FROM scans WHERE id=$1", uuid.UUID(scan_id),
            ))
        budget_used = merge_scan_budget_usage(
            replay_budget_used, scanner_budget_used,
        )
        if budget_used:
            scan_metadata["budget_used"] = budget_used
            result["scan_metadata"] = scan_metadata

        # Save an early artifact before DB finalization so runtime failures still
        # leave diagnostics. A later write refreshes it with receipt ids.
        filepath = await persist_result_artifact(result, job_id, scan_id)

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
            if current and current['status'] in ('failed', 'cancelled', 'cancelling'):
                terminal_status = 'cancelled' if current['status'] == 'cancelling' else current['status']
                if current['status'] == 'cancelling':
                    await conn.execute(
                        """UPDATE scans SET status='cancelled', completed_at=$2, progress=100,
                                  current_phase='cancelled', error_message='Cancelled by user'
                           WHERE id=$1 AND status='cancelling'""",
                        uuid.UUID(scan_id), completed_at,
                    )
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
                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    _append_device_activity(
                        scan_id,
                        kind="error" if terminal_status == "failed" else "cancelled",
                        phase=terminal_status,
                        message=(
                            "Device scan failed before its late result could be accepted"
                            if terminal_status == "failed"
                            else "Device scan cancelled"
                        ),
                        progress=100,
                        details={"status": terminal_status},
                    )
                return

            await _record_internal_executor_tool_receipt(
                conn,
                scan_id=scan_id,
                job_id=job_id,
                target=target,
                target_id=target_id,
                ai_target_id=ai_target_id,
                options=options,
                result=result,
                started_at=now,
                completed_at=completed_at,
                duration_seconds=duration,
                error=error,
            )
            if target_id:
                await _record_external_dast_tool_receipts(
                    conn,
                    scan_id=scan_id,
                    job_id=job_id,
                    target=target,
                    target_id=target_id,
                    options=options,
                    result=result,
                    started_at=now,
                    completed_at=completed_at,
                    duration_seconds=duration,
                )

            if error:
                # A no-output (exit-0, no JSON) failure must not be a bare 'failed'
                # row with nothing to debug. Surface the structured failure
                # diagnostics (masked command, stdout/stderr sizes, scanner version)
                # both in error_message and persisted result so the shard is
                # diagnosable after the runtime is gone.
                diag = result.get('failure_diagnostics') if isinstance(result, dict) else None
                error_detail = str(error)
                if isinstance(diag, dict):
                    error_detail = (
                        f"{error} | scanner_version={diag.get('scanner_version')} "
                        f"stdout_len={diag.get('stdout_len')} stderr_len={diag.get('stderr_len')}"
                    )
                metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
                runtime_check = metadata.get("runtime_scope_check") if isinstance(metadata, dict) else None
                if metadata.get("runtime_scope_blocked") and isinstance(runtime_check, dict):
                    command_result_id = await _record_runtime_scope_block_command_result(
                        conn,
                        scan_id=scan_id,
                        campaign_id=campaign_id,
                        target=target,
                        options=options,
                        runtime_scope_check=runtime_check,
                    )
                    if command_result_id:
                        metadata["runtime_scope_command_result_id"] = command_result_id
                        result["scan_metadata"] = metadata
                failure_result = _failure_result_for_scan_error(result, error, diag)
                await conn.execute("""
                    UPDATE scans SET
                        status = 'failed',
                        error_message = $1,
                        result = $2,
                        completed_at = $3,
                        duration_seconds = $4,
                        progress = 100,
                        current_phase = 'failed', coverage_status=$5, coverage_json=$6,
                        budget_used_json=$7
                    WHERE id = $8
                """, error_detail[:2000], json.dumps(failure_result), completed_at, duration,
                     coverage_status, json.dumps(result_coverage), json.dumps(budget_used),
                     uuid.UUID(scan_id))
                candidate_id = str((options or {}).get("candidate_id") or "")
                if candidate_id:
                    try:
                        await persist_device_candidate_settlement(
                            conn,
                            scan_id=scan_id,
                            device_target_id=device_target_id,
                            settlement={
                                "candidate_id": candidate_id,
                                "status": "inconclusive",
                                "proof_contract_id": str((options or {}).get("proof_contract_id") or "device.unknown"),
                                "error": "probe_failed",
                            },
                        )
                    except (ValueError, asyncpg.PostgresError) as candidate_error:
                        print(
                            f"[{job_id[:8]}] device candidate settlement failed: "
                            f"{type(candidate_error).__name__}: {candidate_error}",
                            flush=True,
                        )
                await asm_inventory.finish_campaign(conn, campaign_id, status='failed')
            else:
                metadata = result.get("scan_metadata") if isinstance(result.get("scan_metadata"), dict) else {}
                runtime_check = metadata.get("runtime_scope_check") if isinstance(metadata, dict) else None
                if metadata.get("runtime_scope_degraded") and isinstance(runtime_check, dict):
                    command_result_id = await _record_runtime_scope_command_result(
                        conn,
                        scan_id=scan_id,
                        campaign_id=campaign_id,
                        target=target,
                        options=options,
                        runtime_scope_check=runtime_check,
                    )
                    if command_result_id:
                        metadata["runtime_scope_command_result_id"] = command_result_id
                        result["scan_metadata"] = metadata
                await conn.execute("""
                    UPDATE scans SET
                        status = 'completed',
                        result = $1,
                        score = $2,
                        grade = $3,
                        findings_count = $4,
                        completed_at = $5,
                        duration_seconds = $6,
                        progress = 100,
                        current_phase = 'completed',
                        coverage_status = $7, coverage_json = $8, budget_used_json = $9
                    WHERE id = $10
                """, json.dumps(result), score, grade, len(findings),
                     completed_at, duration, coverage_status, json.dumps(result_coverage),
                     json.dumps(budget_used), uuid.UUID(scan_id))
                candidate_settlement = result.get("candidate_verification") if isinstance(result.get("candidate_verification"), dict) else {}
                candidate_id = str(candidate_settlement.get("candidate_id") or "")
                if candidate_id:
                    try:
                        await persist_device_candidate_settlement(
                            conn,
                            scan_id=scan_id,
                            device_target_id=device_target_id,
                            settlement=candidate_settlement,
                        )
                    except (ValueError, asyncpg.PostgresError) as candidate_error:
                        print(
                            f"[{job_id[:8]}] device candidate settlement failed: "
                            f"{type(candidate_error).__name__}: {candidate_error}",
                            flush=True,
                        )
                if (options or {}).get("run_kind") in MODEL_INTAKE_RUN_KINDS:
                    try:
                        admission = await persist_model_intake_admission(
                            conn,
                            scan_id=scan_id,
                            target_id=target_id,
                            result=result,
                            reassessment_days=int((options or {}).get("admission_reassessment_days") or 30),
                        )
                        if admission:
                            print(
                                f"[{job_id[:8]}] Model admission {admission.get('id')} registered as {admission.get('status')}",
                                flush=True,
                            )
                    except Exception as admission_error:
                        # Deployment verification requires a durable active row,
                        # so registration failure is fail-closed even though the
                        # historical scan itself remains available.
                        print(f"[{job_id[:8]}] Model admission registration failed: {admission_error}", flush=True)
                await asm_inventory.finish_campaign(conn, campaign_id, status='completed')
                if ai_target_id:
                    await conn.execute("""
                        UPDATE ai_targets SET
                            last_scan_id = $1,
                            last_scanned_at = $2,
                            updated_at = NOW()
                        WHERE id = $3
                    """, uuid.UUID(scan_id), completed_at, uuid.UUID(ai_target_id))
                if device_target_id and (options or {}).get("run_kind") == "device_posture":
                    await conn.execute("""
                        UPDATE device_targets SET
                            last_scan_id=$1, last_scanned_at=$2, last_score=$3,
                            last_grade=$4, updated_at=NOW()
                        WHERE id=$5
                    """, uuid.UUID(scan_id), completed_at, score, grade, uuid.UUID(device_target_id))

        # Save to file after best-effort receipt emission so the file mirrors
        # the persisted scan result's receipt ids.
        filepath = await persist_result_artifact(result, job_id, scan_id)

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
        elif device_target_id and (options or {}).get("run_kind") in {"device_posture", "device_probe"} and findings:
            try:
                posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
                completeness = posture.get("completeness") if isinstance(posture.get("completeness"), dict) else {}
                web_children = posture.get("web_dast_children") if isinstance(posture.get("web_dast_children"), dict) else {}
                resolve_posture_missing = bool(
                    completeness.get("complete")
                    and completeness.get("tcp_scope") == "all_65535"
                )
                resolve_web_missing = bool(
                    resolve_posture_missing
                    and not completeness.get("web_probe_truncated")
                    and (options or {}).get("include_web_dast")
                    and web_children.get("enabled")
                    and int(web_children.get("failed") or 0) == 0
                    and int(web_children.get("truncated") or 0) == 0
                    and int(web_children.get("completed") or 0) == int(web_children.get("requested") or 0)
                )
                saved_count = await save_device_findings(
                    scan_id,
                    device_target_id,
                    findings,
                    resolve_posture_missing=resolve_posture_missing,
                    resolve_web_missing=resolve_web_missing,
                )
            except Exception as e:
                print(f"[{job_id[:8]}] save_device_findings error: {e}", flush=True)

        if device_target_id and not error and (options or {}).get("run_kind") == "device_posture":
            try:
                await persist_device_inventory(scan_id, device_target_id, result)
                async with db_pool.acquire() as conn:
                    await conn.execute("""
                        UPDATE device_targets SET active_findings_count=(
                            SELECT COUNT(*) FROM findings
                            WHERE device_target_id=$1 AND status='active'
                        ), updated_at=NOW() WHERE id=$1
                    """, uuid.UUID(device_target_id))
            except Exception as e:
                print(f"[{job_id[:8]}] persist_device_inventory error: {e}", flush=True)

        if not error and (ai_target_id or target_id or (options or {}).get("run_kind") in MODEL_INTAKE_RUN_KINDS):
            try:
                n = await persist_product_signal_hypotheses(
                    scan_id,
                    target_id,
                    ai_target_id,
                    target,
                    result,
                    options,
                )
                if n:
                    print(f"[{job_id[:8]}] product hypotheses: upserted {n} signal leads", flush=True)
            except Exception as e:
                print(f"[{job_id[:8]}] product hypotheses error: {e}", flush=True)

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
                            conn, target_id, worklist, source='scan', auth_state=auth_state,
                            scan_id=scan_id,
                        )
                    print(f"[{job_id[:8]}] ASM inventory: upserted {n} endpoints", flush=True)

                # Focused BOLA/auth preflights can intentionally skip discovery and
                # therefore have no active_worklist.  Persist their versioned,
                # response-backed endpoint attempts under each principal actually
                # observed so campaign readiness and later ASM work can reuse them.
                telemetry_worklists = _authenticated_endpoint_worklists_from_report(result)
                if telemetry_worklists:
                    counts: dict[str, int] = {}
                    async with db_pool.acquire() as conn:
                        for auth_state, endpoints in telemetry_worklists.items():
                            counts[auth_state] = await asm_inventory.upsert_endpoints(
                                conn,
                                target_id,
                                endpoints,
                                source='scan_telemetry',
                                auth_state=auth_state,
                                scan_id=scan_id,
                            )
                    print(
                        f"[{job_id[:8]}] ASM authenticated telemetry inventory: "
                        + ", ".join(f"{state}={count}" for state, count in sorted(counts.items())),
                        flush=True,
                    )
            except Exception as e:
                print(f"[{job_id[:8]}] ASM inventory error: {e}", flush=True)

        # Persist the first-class application graph (routes, objects, producer/
        # consumer links, auth boundaries, sensitive fields). Best-effort.
        if target_id and not error:
            try:
                g = await persist_application_graph(target_id, scan_id, result)
                if g:
                    print(f"[{job_id[:8]}] application graph: {g.get('nodes', 0)} nodes, "
                          f"{g.get('edges', 0)} edges", flush=True)
            except Exception as e:
                print(f"[{job_id[:8]}] application graph error: {e}", flush=True)

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

        if device_target_id and (options or {}).get("run_kind") == "device_posture":
            final_posture = result.get("device_posture") if isinstance(result.get("device_posture"), dict) else {}
            imported = final_posture.get("imported_request_assessment") if isinstance(final_posture.get("imported_request_assessment"), dict) else {}
            _append_device_activity(
                scan_id,
                kind="error" if error else "complete",
                phase=status,
                message="Device scan failed" if error else "Device scan completed",
                progress=100,
                details={
                    "status": status,
                    "confirmed_services": len(final_posture.get("services") or []),
                    "web_origins": len(final_posture.get("web_origins") or []),
                    "executed_requests": int(imported.get("executed") or 0),
                    "skipped_requests": int(imported.get("skipped") or 0),
                    "findings_count": len(findings),
                    "error_type": str(error)[:100] if error else None,
                },
            )

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
                        ON CONFLICT (canonical_key) DO NOTHING
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
# See docs/dast-asm-architecture.md and api/parallel_scan.py.
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


def _asm_scan_options_for_auth_state(
    options: dict[str, Any],
    auth_state: Any,
    *,
    check_family: str | None = None,
) -> dict[str, Any] | None:
    """Scope scan options to the auth identity claimed from ASM inventory.

    Returning None means the endpoint was discovered under an auth state that
    the current target options can no longer reproduce; testing it anonymously
    would corrupt coverage and BOLA/IDOR results.
    """
    state = asm_inventory.normalize_auth_state(auth_state)
    base = dict(options or {})
    if asm_inventory.normalize_auth_state(base.get("auth_state")) == state:
        if state == "anonymous":
            return parallel_scan._apply_auth_state(base, state)
        if (
            any(base.get(k) for k in parallel_scan._PRIMARY_AUTH_KEYS)
            or parallel_scan._managed_auth_refs(base, "user1")
        ):
            return base
    if state not in parallel_scan.available_auth_states(base):
        return None
    if state == "user1" and asm_inventory.normalize_check_family(check_family) == "bola":
        # BOLA is a cross-principal check. A user1-scoped inventory batch still
        # needs the secondary identity so the scanner can compare user1 vs user2.
        scoped = dict(base)
        scoped["auth_state"] = state
        return scoped
    return parallel_scan._apply_auth_state(base, state)


def _active_endpoint_attempts_from_report(report: dict | None) -> list[dict[str, Any]]:
    active = (report or {}).get('active_checks') if isinstance(report, dict) else None
    schema_version = endpoint_attempt_schema_from_report(report)
    attempts = active.get('endpoint_attempts') if isinstance(active, dict) else None
    if not isinstance(attempts, list):
        return []
    out: list[dict[str, Any]] = []
    for attempt in attempts:
        normalized = normalize_endpoint_attempt(attempt, schema_version=schema_version)
        if normalized:
            out.append(normalized)
    return out


def _authenticated_endpoint_worklists_from_report(
    report: dict | None,
) -> dict[str, list[str]]:
    """Return response-backed endpoint worklists for explicitly observed principals.

    This is deliberately conservative: only declared endpoint-attempt telemetry,
    distinct source/attacker principals, and a successful response for that exact
    principal are accepted.  A completed 404/405 guess must never become durable
    authenticated coverage.
    """
    grouped: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}

    def add(state_value: Any, status_value: Any, endpoint: str) -> None:
        state = asm_inventory.normalize_auth_state(state_value)
        if state == "anonymous":
            return
        try:
            status_code = int(status_value or 0)
        except (TypeError, ValueError):
            return
        if not 200 <= status_code < 400:
            return
        state_seen = seen.setdefault(state, set())
        if endpoint in state_seen:
            return
        state_seen.add(endpoint)
        grouped.setdefault(state, []).append(endpoint)

    for attempt in _active_endpoint_attempts_from_report(report):
        if str(attempt.get("status") or "").lower() not in {"completed", "partial"}:
            continue
        endpoint = str(attempt.get("custom_endpoint") or "").strip()
        source_principal = str(attempt.get("source_principal") or "").strip()
        attacker_principal = str(attempt.get("attacker_principal") or "").strip()
        if (
            not endpoint
            or not source_principal
            or not attacker_principal
            or source_principal == attacker_principal
        ):
            continue
        add(source_principal, attempt.get("owner_status"), endpoint)
        add(
            attacker_principal,
            attempt.get("attacker_status")
            if attempt.get("attacker_status") is not None
            else attempt.get("attacker_listing_status"),
            endpoint,
        )
    return grouped


def _active_endpoint_telemetry_present(report: dict | None) -> bool:
    active = (report or {}).get('active_checks') if isinstance(report, dict) else None
    if not isinstance(active, dict):
        return False
    if endpoint_attempt_schema_from_report(report) is None:
        return False
    return bool(active.get('per_endpoint_telemetry')) or isinstance(active.get('endpoint_attempts'), list)


def _ledger_status_from_endpoint_attempt(attempt: dict[str, Any]) -> tuple[str, str | None]:
    status = str(attempt.get('status') or '').strip().lower()
    reason = attempt.get('budget_exhausted_reason') or attempt.get('skip_reason')
    if status == 'completed':
        return 'completed', None
    if reason in {'time_budget', 'time_budget_exhausted'}:
        return 'timeout', str(reason)
    if reason in {'auth_missing', 'auth_failed'}:
        return str(reason), str(reason)
    if reason == 'rate_limited':
        return 'rate_limited', 'rate_limited'
    if status == 'cancelled' or reason == 'cancelled' or attempt.get('cancelled'):
        return 'partial', 'cancelled'
    if status == 'failed':
        return 'error', str(attempt.get('error_summary') or reason or 'failed')
    if status == 'blocked':
        return 'partial', str(reason or 'blocked')
    if status == 'skipped':
        return 'partial', str(reason or 'skipped')
    if status in {'partial', 'started'}:
        return 'partial', str(reason or 'partial')
    return 'partial', str(reason or status or 'partial')


def _apply_campaign_coverage_rollup(
    merged: dict[str, Any],
    campaign_coverage: dict[str, Any],
    worklist_meta: dict[str, Any] | None = None,
) -> bool:
    """Overlay parent smart coverage with campaign attempt-ledger facts."""
    if not isinstance(campaign_coverage, dict) or int(campaign_coverage.get('attempted') or 0) <= 0:
        return False
    agg_cov = dict(merged.get('smart_coverage') or {})
    assignment_rollup = agg_cov.get('endpoints')
    if assignment_rollup:
        agg_cov['endpoint_assignment_rollup'] = assignment_rollup
    agg_cov['endpoints'] = campaign_coverage
    agg_cov['coverage_basis'] = 'attempt_ledger'
    # Carry the worklist-truncation facts so a capped worklist is not presented as
    # full coverage (endpoints beyond the cap were discovered but never tested).
    if isinstance(worklist_meta, dict) and worklist_meta.get('truncated'):
        agg_cov['worklist_truncated'] = True
        agg_cov['worklist_raw_discovered'] = worklist_meta.get('raw_discovered')
        agg_cov['worklist_tested_cap'] = worklist_meta.get('cap')
    merged['smart_coverage'] = agg_cov
    return True


def _merge_finding_matches_family(finding: dict[str, Any], family: str | None) -> bool:
    rules = FOCUSED_MERGE_FAMILY_RULES.get(str(family or ""))
    if not rules or not isinstance(finding, dict):
        return False
    tool = str(finding.get("tool") or "").lower()
    cwe = str(finding.get("cwe") or "").upper()
    title = str(finding.get("title") or "").lower()
    type_name = str(finding.get("type") or "").lower()
    return (
        tool in rules["tools"]
        or cwe in rules["cwes"]
        or any(marker in title for marker in rules["title_markers"])
        or any(marker in type_name for marker in rules["title_markers"])
    )


def _focused_family_from_parent_options(parent_options: dict[str, Any]) -> str | None:
    raw_families = parent_options.get("coverage_check_families")
    if isinstance(raw_families, list):
        families = [
            asm_inventory.normalize_check_family(f)
            for f in raw_families
            if asm_inventory.normalize_check_family(f) != "all"
        ]
        if len(set(families)) == 1:
            return families[0]
    for key in ("check_family", "asm_check_family", "coverage_attempt_family"):
        family = asm_inventory.normalize_check_family(parent_options.get(key))
        if family and family != "all":
            return family
    return None


def _recompute_focused_parent_result(
    merged: dict[str, Any],
    union_findings: list[dict[str, Any]],
    family: str | None,
) -> tuple[int | None, str | None]:
    """Rebuild focused-family parent grade from the merged finding set."""
    family = asm_inventory.normalize_check_family(family)
    if not family or family == "all":
        return None, None
    result = merged.setdefault("result", {})
    if not isinstance(result, dict):
        result = {}
        merged["result"] = result

    focused_findings = [
        f for f in union_findings
        if isinstance(f, dict) and _merge_finding_matches_family(f, family)
    ]
    severity_counts = {
        "critical": sum(1 for f in focused_findings if str(f.get("severity") or "").lower() == "critical"),
        "high": sum(1 for f in focused_findings if str(f.get("severity") or "").lower() == "high"),
        "medium": sum(1 for f in focused_findings if str(f.get("severity") or "").lower() == "medium"),
        "low": sum(1 for f in focused_findings if str(f.get("severity") or "").lower() == "low"),
    }
    score = 100
    score -= min(severity_counts["critical"] * 15, 45)
    score -= min(severity_counts["high"] * 10, 30)
    score -= min(severity_counts["medium"] * 4, 20)
    score -= min(severity_counts["low"] * 1, 10)
    score = max(0, min(100, score))
    max_severity = "info"
    for sev in ("critical", "high", "medium", "low"):
        if severity_counts[sev]:
            max_severity = sev
            break
    if max_severity == "critical":
        grade = "D" if score >= 55 else "F"
    elif max_severity == "high":
        grade = "C" if score >= 70 else "D" if score >= 55 else "F"
    else:
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 55 else "F"

    notes: list[str] = []
    if severity_counts["critical"]:
        max_cvss = max([float(f.get("cvss_score") or 0) for f in focused_findings] or [0])
        notes.append(
            f"{severity_counts['critical']} critical vulnerability(ies) found "
            f"(max CVSS: {max_cvss:g}, penalty: -{min(severity_counts['critical'] * 15, 45)})."
        )
    if severity_counts["high"]:
        notes.append(
            f"{severity_counts['high']} high severity issue(s) found "
            f"(penalty: -{min(severity_counts['high'] * 10, 30)})."
        )
    if severity_counts["medium"]:
        notes.append(
            f"{severity_counts['medium']} medium severity issue(s) found "
            f"(penalty: -{min(severity_counts['medium'] * 4, 20)})."
        )

    result.update({
        "score": score,
        "grade": grade,
        "notes": notes,
        "summary": (
            f"Focused {family.upper()} Scan Grade: {grade} "
            f"({score}/100) - {len(focused_findings)} in-scope issue(s) found"
        ),
        "focused_active_scope": True,
        "focused_family": family,
        "focused_context_findings": max(0, len(union_findings) - len(focused_findings)),
        "grade_reliable": True,
    })
    for stale_key in ("grade_warning", "coverage_issues", "original_grade"):
        result.pop(stale_key, None)
    return score, grade


def _parallel_result_is_partial(result: dict[str, Any] | None) -> bool:
    if not isinstance(result, dict):
        return True
    meta = result.get('scan_metadata') if isinstance(result.get('scan_metadata'), dict) else {}
    if any(meta.get(key) is True for key in ('partial', 'degraded', 'timed_out', 'cancelled')):
        return True
    result_block = result.get('result') if isinstance(result.get('result'), dict) else {}
    if result_block.get('grade_reliable') is False:
        return True
    coverage = result.get('smart_coverage') if isinstance(result.get('smart_coverage'), dict) else {}
    status = str(coverage.get('status') or '').strip().lower()
    if status in {'partial', 'incomplete', 'failed', 'timed_out', 'cancelled'}:
        return True
    return False


def _mark_parallel_parent_degraded(
    merged: dict[str, Any],
    *,
    failed_count: int,
    total_count: int,
    cancelled_count: int = 0,
    partial_count: int = 0,
) -> bool:
    """Mark a merged parent incomplete when any required shard is not complete."""
    incomplete_count = max(0, failed_count) + max(0, cancelled_count) + max(0, partial_count)
    if incomplete_count <= 0 or total_count <= 0:
        return False
    completed_count = max(0, total_count - incomplete_count)
    details = ", ".join(
        item for item in (
            f"{failed_count} failed" if failed_count else "",
            f"{cancelled_count} cancelled" if cancelled_count else "",
            f"{partial_count} partial" if partial_count else "",
        ) if item
    )
    if completed_count:
        reason = (
            f"Parallel scan has incomplete execution ({details}; {incomplete_count}/{total_count} shard(s)); "
            "grade is not reliable for full shard coverage"
        )
    else:
        reason = (
            f"Parallel scan has no fully completed shard ({details}); "
            "grade is not reliable"
        )

    parallel = merged.setdefault("parallel", {})
    if isinstance(parallel, dict):
        parallel["degraded"] = True
        parallel["degrade_reason"] = reason

    meta = merged.setdefault("scan_metadata", {})
    if isinstance(meta, dict):
        meta["partial"] = True
        meta["degraded"] = True
        meta["grade_reliable"] = False
        meta["parallel_shards_failed"] = failed_count
        meta["parallel_shards_cancelled"] = cancelled_count
        meta["parallel_shards_partial"] = partial_count
        meta["parallel_shards_total"] = total_count

    result = merged.setdefault("result", {})
    if isinstance(result, dict):
        result["grade_reliable"] = False
        result["degraded"] = True
        result["grade_warning"] = reason
        issues = result.get("coverage_issues")
        if not isinstance(issues, list):
            issues = [str(issues)] if issues else []
        if reason not in issues:
            issues.append(reason)
        result["coverage_issues"] = issues
        grade = result.get("grade")
        if grade is not None:
            grade_text = str(grade)
            if not grade_text.endswith("*"):
                result.setdefault("original_grade", grade_text)
                result["grade"] = f"{grade_text}*"
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


def _canonical_parent_scan_job(value: Any) -> CanonicalScanJob | None:
    if not isinstance(value, Mapping):
        return None
    try:
        return (
            CanonicalScanJob.from_queue_payload(value)
            if any(key in value for key in ("type", "placement", "attempt", "plan_version"))
            else CanonicalScanJob.from_payload(value)
        )
    except CanonicalScanJobError as exc:
        raise ExecutionScopeError(
            f"parallel orchestration lost canonical Scan authority: {exc}"
        ) from exc


def _canonicalize_shard_options(
    parent_job: CanonicalScanJob, options: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep planner specialization while restoring immutable parent authority fields."""
    child_options = dict(options)
    for key in ("scan_type", "quick", "thorough"):
        child_options.pop(key, None)
    child_options.update(parent_job.execution_plan.option_metadata())
    active = parent_job.execution_plan.policy.active_testing
    child_options.update({
        "active": active,
        "network_discovery": parent_job.execution_plan.policy.network_discovery,
        "subfinder": parent_job.execution_plan.policy.subdomain_discovery,
    })
    return child_options


def _canonical_shard_job(
    parent_job: CanonicalScanJob,
    *,
    child_id: str,
    child_job_id: str,
    child_options: Mapping[str, Any],
    shard_label: str,
    shard_index: int,
    shard_count: int,
    parallel_discovery: bool = False,
    parallel_worker_count: int = 0,
) -> tuple[CanonicalScanJob, dict[str, Any], dict[str, Any]]:
    """Freeze one private child row and its secret-free canonical queue envelope."""
    options = _canonicalize_shard_options(parent_job, child_options)
    options["queue_handoff_confirmed"] = False
    authority = ScanShardAuthority(
        parent_scan_id=parent_job.scan_id,
        parent_execution_plan_digest=parent_job.execution_plan.digest,
        options_digest=scan_job_options_digest(options),
        shard_index=shard_index,
        shard_count=shard_count,
        shard_label=shard_label,
        parallel_discovery=parallel_discovery,
        sub_budget=derive_scan_shard_budget(options, parent_job.execution_plan.budget),
    )
    options["canonical_shard_authority"] = authority.payload()
    collections = options.get("request_collections")
    credentials = options.get("credential_profile_refs")
    child_job = CanonicalScanJob.create(
        job_id=child_job_id,
        scan_id=child_id,
        target=parent_job.target,
        execution_plan=parent_job.execution_plan,
        request_collections=admitted_request_collection_job_refs(
            [dict(item) for item in collections if isinstance(item, Mapping)]
            if isinstance(collections, list) else []
        ),
        credential_profile_ids=admitted_credential_profile_ids(
            [dict(item) for item in credentials if isinstance(item, Mapping)]
            if isinstance(credentials, list) else []
        ),
        endpoint_manifest_id=(
            str(options.get("endpoint_manifest_id") or "")
            or parent_job.endpoint_manifest_id
        ),
        shard=authority,
    )
    placement = options.get("placement")
    queue_payload = child_job.queue_payload(
        placement=placement if isinstance(placement, Mapping) else None,
    )
    queue_payload.update({
        "type": parallel_scan.SHARD_JOB_TYPE,
        "attempt": 1,
        "plan_version": parallel_scan.PLAN_VERSION,
    })
    if parallel_worker_count:
        queue_payload["parallel_worker_count"] = min(
            max(1, int(parallel_worker_count)),
            parent_job.execution_plan.budget.max_workers,
        )
    CanonicalScanJob.from_queue_payload(queue_payload)
    return child_job, options, queue_payload


def _enqueue_parallel_discovery_continuation(
    redis_client,
    *,
    parent_id: str,
    parent_job_id: str,
    discovery_scan_id: str,
    target: str,
    options: dict[str, Any],
    parallel_worker_count: int = 0,
    parent_queue_payload: Mapping[str, Any] | None = None,
) -> bool:
    """Wake the local planner exactly once after placed discovery is durable."""
    guard = parallel_scan.discovery_continue_guard_key(parent_id)
    claimed = redis_client.set(guard, "1", nx=True, ex=86400)
    if not claimed:
        return False
    parent_job = _canonical_parent_scan_job(parent_queue_payload)
    if parent_job is not None:
        payload = parent_job.payload()
        payload.update({
            'type': parallel_scan.PLAN_JOB_TYPE,
            'plan_stage': 'fanout',
            'discovery_scan_id': discovery_scan_id,
            'parallel_worker_count': min(
                max(0, int(parallel_worker_count or 0)),
                parent_job.execution_plan.budget.max_workers,
            ),
            'placement': {'node_scope': 'local'},
            'attempt': 1,
            'plan_version': parallel_scan.PLAN_VERSION,
        })
        CanonicalScanJob.from_queue_payload(payload)
    else:
        payload = {
            'type': parallel_scan.PLAN_JOB_TYPE,
            'job_id': parent_job_id,
            'scan_id': parent_id,
            'target': target,
            'options': options,
            'plan_stage': 'fanout',
            'discovery_scan_id': discovery_scan_id,
            'parallel_worker_count': int(parallel_worker_count or 0),
            'placement': {'node_scope': 'local'},
            'attempt': 1,
            'plan_version': parallel_scan.PLAN_VERSION,
            'submitted_at': utc_now_iso(),
        }
    try:
        enqueue_job(redis_client, QUEUE_NAME, payload)
    except Exception:
        redis_client.delete(guard)
        raise
    return True


async def process_scan_plan_job(job_data: dict):
    """Plan stage: decompose a parent scan into shard jobs (or fall back to a
    standalone scan when there is nothing to parallelize)."""
    parent_id = job_data.get('scan_id')
    parent_job_id = job_data.get('job_id', 'unknown')
    target = job_data.get('target')
    options = job_data.get('options', {}) or {}
    canonical_parent_job = _canonical_parent_scan_job(
        job_data.get("_canonical_queue_payload")
    )
    scan_type = (
        "scan"
        if canonical_parent_job is not None
        else (options.get('scan_type') or 'standard').strip().lower() or 'standard'
    )
    active_testing = (
        canonical_parent_job.execution_plan.policy.active_testing
        if canonical_parent_job is not None
        else None
    )

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

    # Count the plan/discovery stage as a running job. This stage runs the discover-once
    # recon (coverage) and the fan-out planning before any shard exists; without marking
    # the job running here, queue "running" shows 0 during a parent's discovery phase and
    # only starts counting once shards spawn. Marked completed after fan-out (below), or
    # re-enqueued as a standalone scan in the not-worth-parallelizing branch.
    r.hset(
        f"job:{parent_job_id}",
        mapping={
            'status': 'running',
            'started_at': now.isoformat(),
            'heartbeat': now.isoformat(),
            'current_phase': 'planning',
        },
    )
    r.expire(f"job:{parent_job_id}", 86400)

    requested_strategy = parallel_scan.resolve_auto_strategy(
        options,
        scan_type,
        options.get('shard_strategy') or 'auto',
        active_testing=active_testing,
    )
    plan_stage = str(job_data.get('plan_stage') or 'start')
    canonical_subdomain_discovery = bool(
        canonical_parent_job is not None
        and canonical_parent_job.execution_plan.policy.subdomain_discovery
    )
    canonical_network_discovery = bool(
        canonical_parent_job is not None
        and canonical_parent_job.execution_plan.policy.network_discovery
    )
    needs_placed_discovery = bool(
        (
            requested_strategy in {'coverage', 'coverage_family'}
            and not options.get('custom_endpoints')
        )
        or canonical_subdomain_discovery
        or canonical_network_discovery
    )

    # Discovery is executable target traffic, so it must honor the user's
    # placement. Create one ordinary shard job first; its durable result then
    # wakes a local-only continuation that performs pure planning and fan-out.
    # Canonical subdomain and network discovery use this stage even when endpoint
    # planning already has a custom worklist, preventing every endpoint shard
    # from repeating the same root-domain or address-bound capabilities.
    if (
        needs_placed_discovery
        and plan_stage == 'start'
    ):
        async with db_pool.acquire() as conn:
            existing_discovery = await conn.fetchrow(
                """
                SELECT id, job_id, status FROM scans
                WHERE parent_scan_id=$1 AND scan_role=$2
                ORDER BY created_at DESC LIMIT 1
                """,
                uuid.UUID(parent_id), parallel_scan.PARALLEL_DISCOVERY_ROLE,
            )
        if existing_discovery:
            existing_status = str(existing_discovery.get('status') or '')
            if existing_status in {'completed', 'failed'}:
                _enqueue_parallel_discovery_continuation(
                    r,
                    parent_id=parent_id,
                    parent_job_id=parent_job_id,
                    discovery_scan_id=str(existing_discovery['id']),
                    target=target_url,
                    options=options,
                    parallel_worker_count=int(job_data.get('parallel_worker_count') or 0),
                    parent_queue_payload=job_data.get("_canonical_queue_payload"),
                )
            print(
                f"[{parent_id[:8]}] discovery stage already {existing_status or 'present'}; duplicate plan skipped",
                flush=True,
            )
            return
        discovery_id = str(uuid.uuid4())
        discovery_job_id = str(uuid.uuid4())
        discovery_opts = parallel_scan._base_child_options(options)
        discovery_opts['parallel_discovery'] = True
        discovery_opts['parallel_stage'] = 'discovery'
        discovery_opts['skip_global_checks'] = True
        discovery_opts.pop('custom_endpoints', None)
        for key in (
            'check_family', 'asm_check_family', 'coverage_attempt_family',
            'coverage_family_aware', 'sqli', 'xss',
        ):
            discovery_opts.pop(key, None)
        parallel_scan._merge_custom_budget(
            discovery_opts, dict(parallel_scan.RECON_DISCOVERY_BUDGET)
        )
        if canonical_parent_job is not None:
            discovery_job, discovery_opts, discovery_payload = _canonical_shard_job(
                canonical_parent_job,
                child_id=discovery_id,
                child_job_id=discovery_job_id,
                child_options=discovery_opts,
                shard_label='discovery',
                shard_index=-1,
                shard_count=0,
                parallel_discovery=True,
                parallel_worker_count=int(job_data.get('parallel_worker_count') or 0),
            )
            discovery_generation = 'v2'
            discovery_policy = canonical_parent_job.execution_plan.canonical_dict()['policy']
            discovery_budget = canonical_parent_job.execution_plan.canonical_dict()['budget']
            discovery_job_payload = discovery_job.payload()
            discovery_job_digest = discovery_job.payload_digest
        else:
            discovery_opts['scan_type'] = 'smart'
            discovery_opts['queue_handoff_confirmed'] = False
            discovery_payload = {
                'type': parallel_scan.SHARD_JOB_TYPE,
                'job_id': discovery_job_id,
                'scan_id': discovery_id,
                'parent_scan_id': parent_id,
                'target_id': target_id,
                'target': target_url,
                'options': discovery_opts,
                'parallel_discovery': True,
                'parent_job_id': parent_job_id,
                'parent_options': options,
                'parallel_worker_count': int(job_data.get('parallel_worker_count') or 0),
                'shard_label': 'discovery',
                'shard_index': -1,
                'shard_count': 0,
                'attempt': 1,
                'plan_version': parallel_scan.PLAN_VERSION,
                'submitted_at': utc_now_iso(),
            }
            discovery_generation = 'legacy'
            discovery_policy = {}
            discovery_budget = {}
            discovery_job_payload = {}
            discovery_job_digest = None
        parent_options = dict(options)
        parent_options['parallel_strategy'] = requested_strategy
        parent_options['parallel_stage'] = 'discovery'
        parent_options[parallel_scan.PARALLEL_FANOUT_COMPLETE_KEY] = False
        parent_options[parallel_scan.PARALLEL_EXPECTED_SHARDS_KEY] = 0
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                updated = await conn.execute(
                    """
                    UPDATE scans SET status='running', started_at=COALESCE(started_at, $1),
                        current_phase='parallel_discovery', progress=GREATEST(progress, 2),
                        options=$2
                    WHERE id=$3 AND status <> 'cancelled'
                    """,
                    now, json.dumps(parent_options), uuid.UUID(parent_id),
                )
                if updated.endswith('0'):
                    return
                await conn.execute(
                    """
                    INSERT INTO scans (
                        id, target_id, target_url, job_id, status, options, scan_type,
                        parent_scan_id, scan_role, shard_index, scan_generation,
                        policy_json, budget_json, scan_job_payload, scan_job_digest
                    ) VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8,-1,$9,$10,$11,$12,$13)
                    """,
                    uuid.UUID(discovery_id),
                    uuid.UUID(target_id) if target_id else None,
                    target_url,
                    discovery_job_id,
                    json.dumps(discovery_opts),
                    scan_type,
                    uuid.UUID(parent_id),
                    parallel_scan.PARALLEL_DISCOVERY_ROLE,
                    discovery_generation,
                    json.dumps(discovery_policy),
                    json.dumps(discovery_budget),
                    json.dumps(discovery_job_payload),
                    discovery_job_digest,
                )
        try:
            enqueue_job(r, QUEUE_NAME, discovery_payload)
        except Exception as exc:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE scans SET status='failed', progress=100,
                        current_phase='queue_handoff_failed', completed_at=NOW(),
                        error_message=$2
                    WHERE id=$1
                    """,
                    uuid.UUID(discovery_id),
                    f"Parallel discovery queue handoff failed: {exc}"[:1000],
                )
            raise
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE scans SET status='queued',
                    options=jsonb_set(options, '{queue_handoff_confirmed}', 'true'::jsonb, true)
                WHERE id=$1 AND status='pending'
                """,
                uuid.UUID(discovery_id),
            )
        r.hset(
            f"job:{discovery_job_id}",
            mapping={'status': 'queued', 'target': target_url, 'current_phase': 'discovery'},
        )
        r.hset(
            f"job:{parent_job_id}",
            mapping={'status': 'running', 'progress': '2', 'current_phase': 'parallel_discovery'},
        )
        print(
            f"[{parent_id[:8]}] queued placed discovery stage {discovery_id[:8]}",
            flush=True,
        )
        return

    coverage_auth_states: list[str] = []
    coverage_allocation = 'static'
    harvested: list[str] = []
    harvest_meta: dict[str, Any] | None = None
    discovery_degraded_reason: str | None = None
    precreated_campaign_id: str | None = None
    discovery_scan_id = str(job_data.get('discovery_scan_id') or '').strip()
    discovery = None
    recon_result: dict[str, Any] = {}
    placed_subdomain_summary: dict[str, Any] | None = None
    placed_network_summary: dict[str, Any] | None = None
    if discovery_scan_id:
        async with db_pool.acquire() as conn:
            discovery = await conn.fetchrow(
                """
                SELECT id, status, result, error_message
                FROM scans
                WHERE id=$1 AND parent_scan_id=$2 AND scan_role=$3
                """,
                uuid.UUID(discovery_scan_id),
                uuid.UUID(parent_id),
                parallel_scan.PARALLEL_DISCOVERY_ROLE,
            )
        if not discovery or str(discovery.get('status') or '') not in {
            'completed', 'failed'
        }:
            print(
                f"[{parent_id[:8]}] discovery continuation arrived before terminal result",
                flush=True,
            )
            return
        recon_result = _as_report_dict(discovery.get('result')) or {}
        raw_subdomain_summary = recon_result.get('subdomain_discovery')
        if isinstance(raw_subdomain_summary, Mapping):
            placed_subdomain_summary = dict(raw_subdomain_summary)
        elif canonical_subdomain_discovery:
            placed_subdomain_summary = {
                "schema_version": "canonical-scan-subdomain-discovery/v1",
                "enabled": True,
                "status": "failed",
                "root_domain": (
                    canonical_parent_job.target.allowed_root_domains[0]
                    if canonical_parent_job.target.allowed_root_domains else None
                ),
                "observations": [],
                "observation_count": 0,
                "partial": False,
                "timed_out": False,
                "errors": [str(
                    discovery.get('error_message')
                    or "placed discovery returned no canonical subdomain receipt"
                )[:500]],
                "budget_consumed": {},
                "durable_budget_settled": False,
                "network_binding": "root_domain_target_binding",
                "automatically_scanned_discovered_hosts": False,
            }
        raw_network_summary = recon_result.get('network_discovery')
        if isinstance(raw_network_summary, Mapping):
            placed_network_summary = dict(raw_network_summary)
        elif canonical_network_discovery:
            placed_network_summary = {
                "schema_version": "canonical-scan-network-discovery/v1",
                "enabled": True,
                "status": "failed",
                "addresses": [],
                "actions": [],
                "observations": [],
                "open_ports": [],
                "services": [],
                "observation_count": 0,
                "partial": False,
                "timed_out": False,
                "errors": [str(
                    discovery.get('error_message')
                    or "placed discovery returned no canonical network receipts"
                )[:500]],
                "budget_consumed": {},
                "durable_budget_settled": False,
                "network_binding": "exact_address_subset",
            }
    if requested_strategy in {'coverage', 'coverage_family'}:
        # The placed discovery shard already executed target traffic. This
        # continuation only reads its durable result and plans self-contained
        # endpoint shards on the control plane.
        if discovery_scan_id:
            discovery_status = str(discovery.get('status') or '')
            if discovery_status == 'failed' and (
                str(options.get('scan_generation') or 'legacy') != 'v2' or not target_url
            ):
                discovery_error = str(
                    discovery.get('error_message')
                    or 'Parallel endpoint discovery failed before producing a durable worklist'
                )[:1000]
                parent_error = f"Parallel discovery failed: {discovery_error}"[:1000]
                failure_result = {
                    'technical_outcome': 'INCOMPLETE',
                    'error': parent_error,
                    'parallel': {
                        'strategy': requested_strategy,
                        'stage': 'discovery',
                        'degraded': True,
                        'discovery_scan_id': discovery_scan_id,
                    },
                }
                async with db_pool.acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE scans SET status='failed', progress=100,
                            current_phase='parallel_discovery_failed', completed_at=NOW(),
                            error_message=$2, result=$3
                        WHERE id=$1 AND status <> 'cancelled'
                        """,
                        uuid.UUID(parent_id), parent_error, json.dumps(failure_result),
                    )
                r.hset(
                    f"job:{parent_job_id}",
                    mapping={
                        'status': 'failed',
                        'progress': '100',
                        'current_phase': 'parallel_discovery_failed',
                        'error': parent_error,
                    },
                )
                r.expire(f"job:{parent_job_id}", 86400)
                print(f"[{parent_id[:8]}] {parent_error}", flush=True)
                return
            if discovery_status == 'failed':
                # A failed producer may still have durable, trustworthy partial output. Harvest it
                # and continue; coverage truth is reported separately from the parent run status.
                discovery_degraded_reason = str(
                    discovery.get('error_message') or recon_result.get('error')
                    or 'parallel discovery producer failed after partial output'
                )[:1000]
        else:
            # Explicit endpoint scope can fan out immediately without target
            # discovery. This is the lowest-latency parallel path.
            recon_result = {}
        recon_opts = parallel_scan._base_child_options(options)
        try:
            harvest_limit = int(
                ((options.get('custom_budget') or {}).get('active_worklist_max'))
                or parallel_scan.COVERAGE_WORKLIST_MAX
            )
        except (TypeError, ValueError):
            harvest_limit = parallel_scan.COVERAGE_WORKLIST_MAX
        harvested, harvest_meta = parallel_scan.harvest_endpoints_with_meta(
            recon_result, max_endpoints=harvest_limit
        )
        # Surface the worklist cap so "Full Coverage" never reports ~100% over a
        # silently truncated surface: endpoints beyond the cap were discovered but
        # will not be tested. (Recorded on parent_options where it is built below.)
        if harvest_meta['truncated']:
            print(f"[{parent_id[:8]}] coverage: WORKLIST TRUNCATED — discovered "
                  f"{harvest_meta['raw_discovered']} endpoints, testing only "
                  f"{harvest_meta['cap']} (cap). Raise custom_budget.active_worklist_max "
                  f"for full coverage.", flush=True)
        _raw_harvested = len(harvested)
        harvested = parallel_scan._normalize_endpoint_list(
            list(options.get('custom_endpoints') or []) + harvested
        )
        print(f"[{parent_id[:8]}] coverage: harvested {len(harvested)} endpoints from recon "
              f"({_raw_harvested} discovered)", flush=True)
        requested_allocation = parallel_scan.coverage_allocation_mode(options)
        if requested_allocation == 'dynamic':
            print(
                f"[{parent_id[:8]}] coverage: database-pull allocation replaced by "
                "self-contained shards for broker/fleet correctness",
                flush=True,
            )
        coverage_allocation = 'static'
        coverage_auth_states = (
            parallel_scan.available_auth_states(options)
            if options.get('auth_state_shards')
            else [asm_inventory.auth_state_from_options(options)]
        )
        # Continuous ASM: the recon worklist is the richest endpoint source —
        # persist the whole thing into the per-target inventory (docs §16).
        if target_id and harvested:
            try:
                async with db_pool.acquire() as conn:
                    upsert_states = coverage_auth_states
                    n = 0
                    for auth_state in upsert_states:
                        n += await asm_inventory.upsert_endpoints(
                            conn,
                            target_id,
                            harvested,
                            source='coverage_discovery',
                            auth_state=auth_state,
                            campaign_id=None,
                            scan_id=parent_id,
                        )
                print(
                    f"[{parent_id[:8]}] ASM inventory: upserted {n} endpoint/auth rows from recon",
                    flush=True,
                )
            except Exception as e:
                print(f"[{parent_id[:8]}] ASM inventory error: {e}", flush=True)
        if requested_strategy == 'coverage_family':
            plan = parallel_scan.plan_coverage_family_shards(options, harvested)
        else:
            plan = parallel_scan.plan_coverage_shards(options, harvested)
        plan = parallel_scan.with_coverage_backbone(plan, options)
    else:
        plan = parallel_scan.plan_shards(
            options,
            scan_type=scan_type,
            active_testing=active_testing,
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
        if canonical_parent_job is not None:
            single_opts = _canonicalize_shard_options(
                canonical_parent_job, single_opts,
            )
        if placed_subdomain_summary is not None:
            single_opts['canonical_subdomain_discovery'] = (
                placed_subdomain_summary
            )
            single_opts['canonical_subdomain_discovery_source_scan_id'] = (
                discovery_scan_id
            )
        if placed_network_summary is not None:
            single_opts['canonical_network_discovery'] = placed_network_summary
            single_opts['canonical_network_discovery_source_scan_id'] = (
                discovery_scan_id
            )
        async with db_pool.acquire() as conn:
            await conn.execute(
                "UPDATE scans SET scan_role = 'standalone', options = $1 WHERE id = $2",
                json.dumps(single_opts), uuid.UUID(parent_id),
            )
        canonical_source = job_data.get("_canonical_queue_payload")
        if isinstance(canonical_source, Mapping):
            try:
                parent_job = CanonicalScanJob.from_queue_payload(canonical_source)
                standalone_payload = parent_job.queue_payload(
                    placement=(
                        single_opts.get("placement")
                        if isinstance(single_opts.get("placement"), Mapping) else None
                    ),
                )
            except CanonicalScanJobError as exc:
                raise ExecutionScopeError(
                    f"parallel fallback lost canonical Scan authority: {exc}"
                ) from exc
        else:
            standalone_payload = {
                'job_id': parent_job_id,
                'scan_id': parent_id,
                'target': target_url,
                'options': single_opts,
                'submitted_at': utc_now_iso(),
            }
        enqueue_job(r, QUEUE_NAME, standalone_payload)
        return

    # Mark parent running and fan out child shard rows + jobs. Record the
    # resolved strategy on the parent options so the merge can report it.
    parent_options = dict(options)
    parent_options['parallel_strategy'] = plan.strategy
    if placed_subdomain_summary is not None:
        parent_options['canonical_subdomain_discovery'] = placed_subdomain_summary
        parent_options['canonical_subdomain_discovery_source_scan_id'] = (
            discovery_scan_id
        )
        if str(placed_subdomain_summary.get('status') or '') in {
            'blocked', 'failed', 'partial'
        }:
            parent_options['coverage_status'] = 'partial'
            coverage_reasons = [
                str(item) for item in parent_options.get('coverage_reasons') or []
            ]
            subdomain_reason = (
                "subdomain_discovery_"
                + str(placed_subdomain_summary.get('status') or 'failed')
            )
            if subdomain_reason not in coverage_reasons:
                coverage_reasons.append(subdomain_reason)
            parent_options['coverage_reasons'] = coverage_reasons
    if placed_network_summary is not None:
        parent_options['canonical_network_discovery'] = placed_network_summary
        parent_options['canonical_network_discovery_source_scan_id'] = (
            discovery_scan_id
        )
        if str(placed_network_summary.get('status') or '') in {
            'blocked', 'failed', 'partial'
        }:
            parent_options['coverage_status'] = 'partial'
            coverage_reasons = [
                str(item) for item in parent_options.get('coverage_reasons') or []
            ]
            network_reason = (
                "network_discovery_"
                + str(placed_network_summary.get('status') or 'failed')
            )
            if network_reason not in coverage_reasons:
                coverage_reasons.append(network_reason)
            parent_options['coverage_reasons'] = coverage_reasons
    if plan.strategy in {'coverage', 'coverage_family'}:
        parent_options['coverage_allocation'] = coverage_allocation
        if discovery_degraded_reason:
            parent_options['coverage_status'] = 'partial'
            coverage_reasons = [
                str(item) for item in parent_options.get('coverage_reasons') or []
            ]
            if discovery_degraded_reason not in coverage_reasons:
                coverage_reasons.append(discovery_degraded_reason)
            parent_options['coverage_reasons'] = coverage_reasons
        if harvest_meta is not None:
            # Surface the worklist cap so "Full Coverage" never reports ~100% over a
            # silently truncated surface (endpoints beyond the cap were discovered
            # but will not be tested).
            parent_options['coverage_worklist_raw_discovered'] = harvest_meta['raw_discovered']
            parent_options['coverage_worklist_cap'] = harvest_meta['cap']
            parent_options['coverage_worklist_truncated'] = harvest_meta['truncated']
        if harvested and coverage_auth_states:
            planned_families = {
                asm_inventory.normalize_check_family(s.options.get('coverage_attempt_family') or 'all')
                for s in plan.shards if not s.options.get('parallel_backbone')
            } if plan.strategy == 'coverage_family' else {'all'}
            parent_options['coverage_check_families'] = sorted(planned_families)
            family_multiplier = max(1, len(planned_families))
            parent_options['coverage_expected_attempts'] = len(harvested) * max(1, len(coverage_auth_states)) * family_multiplier
    campaign_id = None
    parent_options['parallel_stage'] = 'fanout'
    parent_options['parallel_fanout_started_at'] = utc_now_iso()
    parent_options[parallel_scan.PARALLEL_FANOUT_COMPLETE_KEY] = False
    parent_options[parallel_scan.PARALLEL_EXPECTED_SHARDS_KEY] = plan.shard_count
    planned_request_budget = 0
    backbone_request_budget = 0
    for planned_shard in plan.shards:
        resolved = planned_shard.options.get('resolved_budget')
        if not isinstance(resolved, dict):
            resolved = resolve_scan_budget(
                planned_shard.options.get('scan_type') or scan_type,
                planned_shard.options.get('budget_profile'),
                planned_shard.options.get('custom_budget')
                if isinstance(planned_shard.options.get('custom_budget'), dict) else None,
            )
        try:
            request_budget = max(0, int(resolved.get('request_max') or 0))
        except (TypeError, ValueError):
            request_budget = 0
        planned_request_budget += request_budget
        if planned_shard.options.get('parallel_backbone'):
            backbone_request_budget += request_budget
    parent_options['parallel_planned_request_budget'] = planned_request_budget
    parent_options['parallel_backbone_request_budget'] = backbone_request_budget
    child_jobs: list[
        tuple[str, str, dict[str, Any], dict[str, Any], CanonicalScanJob | None, int]
    ] = []
    for shard in plan.shards:
        child_id = str(uuid.uuid4())
        child_job_id = str(uuid.uuid4())
        child_options = dict(shard.options)
        if canonical_parent_job is not None:
            child_job, child_options, payload = _canonical_shard_job(
                canonical_parent_job,
                child_id=child_id,
                child_job_id=child_job_id,
                child_options=child_options,
                shard_label=shard.label,
                shard_index=shard.index,
                shard_count=plan.shard_count,
                parallel_worker_count=int(job_data.get('parallel_worker_count') or 0),
            )
        else:
            child_job = None
            child_options['queue_handoff_confirmed'] = False
            payload = {
                'type': parallel_scan.SHARD_JOB_TYPE,
                'job_id': child_job_id,
                'scan_id': child_id,
                'parent_scan_id': parent_id,
                'campaign_id': None,
                'target_id': target_id,
                'target': target_url,
                'options': child_options,
                'shard_label': shard.label,
                'shard_index': shard.index,
                'shard_count': plan.shard_count,
                'attempt': 1,
                'plan_version': parallel_scan.PLAN_VERSION,
                'submitted_at': utc_now_iso(),
            }
        child_jobs.append((
            child_id, child_job_id, child_options, payload, child_job, shard.index,
        ))

    # Publish barrier part 1: make the complete expected child set durable in one
    # transaction before any worker can observe a queue message.
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            update_result = await conn.execute("""
                UPDATE scans SET status='running', started_at=COALESCE(started_at, $1),
                    current_phase=$2, progress=GREATEST(progress, 20), shard_count=$3,
                    options=$4
                WHERE id=$5 AND status <> 'cancelled'
            """, now, f'fanout:{plan.strategy}', plan.shard_count,
                 json.dumps(parent_options), uuid.UUID(parent_id))
            if update_result.endswith("0"):
                print(f"[{parent_id[:8]}] parent scan cancelled before fan-out; plan job skipped", flush=True)
                r.hset(
                    f"job:{parent_job_id}",
                    mapping={'status': 'cancelled', 'progress': '100', 'current_phase': 'cancelled'},
                )
                r.expire(f"job:{parent_job_id}", 86400)
                return
            for child_id, child_job_id, child_options, payload, child_job, shard_index in child_jobs:
                child_plan = child_job.execution_plan.canonical_dict() if child_job else None
                await conn.execute("""
                    INSERT INTO scans (id, target_id, target_url, job_id, status, options,
                                       scan_type, parent_scan_id, scan_role, shard_index, shard_count,
                                       scan_generation, policy_json, budget_json,
                                       scan_job_payload, scan_job_digest)
                    VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,'shard',$8,$9,$10,$11,$12,$13,$14)
                """, uuid.UUID(child_id),
                     uuid.UUID(target_id) if target_id else None,
                     target_url, child_job_id, json.dumps(child_options), scan_type,
                     uuid.UUID(parent_id), shard_index, plan.shard_count,
                     'v2' if child_job else 'legacy',
                     json.dumps(child_plan['policy'] if child_plan else {}),
                     json.dumps(child_plan['budget'] if child_plan else {}),
                     json.dumps(child_job.payload() if child_job else {}),
                     child_job.payload_digest if child_job else None)

    r.set(parallel_scan.shards_remaining_key(parent_id), plan.shard_count, ex=86400)
    enqueue_failures = 0
    for child_id, child_job_id, child_options, payload, _child_job, _shard_index in child_jobs:
        try:
            enqueue_job(r, QUEUE_NAME, payload)
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE scans SET status='queued',
                        options=jsonb_set(options, '{queue_handoff_confirmed}', 'true'::jsonb, true)
                    WHERE id=$1 AND status='pending'
                    """,
                    uuid.UUID(child_id),
                )
            r.hset(f"job:{child_job_id}", mapping={'status': 'queued', 'target': target_url})
        except Exception as exc:
            enqueue_failures += 1
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """
                    UPDATE scans SET status='failed', progress=100,
                        current_phase='queue_handoff_failed', completed_at=NOW(),
                        error_message=$2
                    WHERE id=$1 AND status='pending'
                    """,
                    uuid.UUID(child_id),
                    f"Shard queue handoff failed: {exc}"[:1000],
                )

    # Publish barrier part 2: only now may reconciliation observe a complete
    # fan-out. Fast children cannot merge a prefix of the planned set.
    parent_options['parallel_stage'] = 'execution'
    parent_options[parallel_scan.PARALLEL_FANOUT_COMPLETE_KEY] = True
    async with db_pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE scans SET current_phase=$2, progress=GREATEST(progress, 20), options=$3
            WHERE id=$1 AND status <> 'cancelled'
            """,
            uuid.UUID(parent_id), f'sharded:{plan.strategy}', json.dumps(parent_options),
        )
        await parallel_scan.reconcile_parallel_parent(conn, parent_id, r, QUEUE_NAME)

    print(
        f"[{parent_id[:8]}] fanned out {plan.shard_count} '{plan.strategy}' shards "
        f"(allocation=self-contained, queue_failures={enqueue_failures})",
        flush=True,
    )
    # Planning is done and the shards are enqueued: free the plan job so it no longer
    # counts as running while the shards (and later the merge job) do the work.
    r.hset(
        f"job:{parent_job_id}",
        mapping={'status': 'completed', 'progress': '100', 'current_phase': 'fanned_out'},
    )
    r.expire(f"job:{parent_job_id}", 86400)


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
    broker_ingest = bool(job_data.get("_broker_result_id"))
    parallel_discovery = bool(
        job_data.get('parallel_discovery') or options.get('parallel_discovery')
    )
    label = job_data.get('shard_label', 'shard')
    idx = job_data.get('shard_index')
    total = job_data.get('shard_count')

    r = get_redis()
    now = utc_now()
    if job_data.get("_broker_lease_id"):
        try:
            async with db_pool.acquire() as conn:
                leased_at = await conn.fetchval(
                    "SELECT created_at FROM broker_job_leases WHERE id=$1",
                    uuid.UUID(str(job_data["_broker_lease_id"])),
                )
            normalized_lease_time = _naive_utc_timestamp(leased_at)
            if normalized_lease_time:
                now = normalized_lease_time
        except (ValueError, TypeError):
            pass
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

    # Broker result ingestion is persistence/verification work on the control
    # plane, not a second shard execution. The remote execution already held the
    # broker admission slot and its request-budget reservation. Claiming either
    # a local shard slot or domain budget here can deadlock an already-submitted
    # result and incorrectly requeue it onto an executable queue.
    if broker_ingest:
        slot_acquired = False
        shard_limit = _parallel_shard_concurrency_limit(r, options)
    else:
        slot_acquired, shard_limit = _try_acquire_parallel_shard_slot(
            r, parent_id, options, slot_id=job_id
        )
    if not broker_ingest and not slot_acquired:
        canonical_queue = isinstance(job_data.get("_canonical_queue_payload"), Mapping)
        wait_cycles = int((
            _redis_scalar_text(r.hget(f"job:{job_id}", "shard_slot_wait_cycles"))
            if canonical_queue else job_data.get('shard_slot_wait_cycles') or 0
        ) or 0) + 1
        requeued = _safe_requeue_payload(job_data)
        if not canonical_queue:
            requeued['shard_slot_wait_cycles'] = wait_cycles
            requeued['last_shard_slot_wait_at'] = utc_now_iso()
        enqueue_job(r, QUEUE_NAME, requeued)
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

    endpoint_count = 0 if broker_ingest else _known_endpoint_count(options)
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
            _release_parallel_shard_slot(r, parent_id, job_id)
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
        _release_parallel_shard_slot(r, parent_id, job_id)
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
        target=send_heartbeats, args=(job_id, stop_heartbeat, parent_id, job_id),
        name=f"heartbeat-{job_id[:8]}", daemon=True,
    )
    heartbeat_thread.start()
    try:
        try:
            if job_data.get("_broker_result_id"):
                result = await _load_broker_result(job_data, scan_id)
            else:
                options = await _hydrate_generic_scan_credentials(options, scan_id)
                options = await _hydrate_managed_scan_credentials(options, scan_id)
                result = await _execute_reserved_deterministic_scan(
                    target,
                    options,
                    scan_id=scan_id,
                    job_id=job_id,
                )
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
        partial = bool(
            not error and not parallel_discovery and _parallel_result_is_partial(result)
        )
        filepath = await persist_result_artifact(
            result,
            job_id,
            scan_id,
            parent_scan_id=parent_id,
            shard_index=idx,
        )
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
                        duration_seconds = $6, progress = 100, current_phase = $7
                    WHERE id = $8
                """, json.dumps(result), score, grade, len(findings),
                     completed_at, duration, 'partial' if partial else 'completed',
                     uuid.UUID(scan_id))

        final_status = 'failed' if error else 'completed'
        final_phase = 'failed' if error else ('partial' if partial else 'completed')
        if current and current['status'] in ('failed', 'cancelled'):
            final_status = current['status']
            final_phase = current['status']
        r.hset(f"job:{job_id}", mapping={
            'status': final_status,
            'result_path': filepath,
            'completed_at': completed_at.isoformat(),
            'progress': '100',
            'current_phase': final_phase,
        })
        r.expire(f"job:{job_id}", 86400)
        print(f"[{job_id[:8]}] Shard '{label}' done | findings: {len(findings)} | error: {bool(error)}", flush=True)
    finally:
        stop_heartbeat.set()
        heartbeat_thread.join(timeout=max(1.0, HEARTBEAT_INTERVAL_SECONDS / 2))
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id, job_id)
        # Discovery wakes a local-only continuation. Normal shards enter the
        # all-terminal barrier. Both paths are idempotent under redelivery.
        if parallel_discovery and parent_id:
            try:
                parent_queue_payload = None
                continuation_parent_job_id = str(
                    job_data.get('parent_job_id') or parent_id
                )
                continuation_target = target
                continuation_options = dict(job_data.get('parent_options') or {})
                if isinstance(job_data.get("_canonical_queue_payload"), Mapping):
                    async with db_pool.acquire() as conn:
                        parent_row = await conn.fetchrow(
                            """
                            SELECT job_id, target_url, options, scan_job_payload
                            FROM scans WHERE id=$1
                            """,
                            uuid.UUID(parent_id),
                        )
                    if not parent_row:
                        raise ExecutionScopeError(
                            "canonical discovery parent disappeared before continuation"
                        )
                    parent_queue_payload = _as_report_dict(
                        parent_row.get('scan_job_payload')
                    )
                    continuation_parent_job_id = str(
                        parent_row.get('job_id') or parent_id
                    )
                    continuation_target = str(parent_row.get('target_url') or target)
                    continuation_options = _as_report_dict(parent_row.get('options')) or {}
                continued = _enqueue_parallel_discovery_continuation(
                    r,
                    parent_id=parent_id,
                    parent_job_id=continuation_parent_job_id,
                    discovery_scan_id=scan_id,
                    target=continuation_target,
                    options=continuation_options,
                    parallel_worker_count=int(job_data.get('parallel_worker_count') or 0),
                    parent_queue_payload=parent_queue_payload,
                )
                if continued:
                    print(
                        f"[{job_id[:8]}] discovery durable -> enqueued fan-out continuation",
                        flush=True,
                    )
            except Exception as e:
                print(f"[{job_id[:8]}] discovery continuation enqueue error: {e}", flush=True)
        elif parent_id:
            # Barrier + merge trigger. The DB all-terminal check in
            # reconcile_parallel_parent is the source of truth.
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
                   options, started_at, completed_at, campaign_id, error_message,
                   current_phase, executing_node_id, worker_id
            FROM scans
            WHERE parent_scan_id = $1 AND scan_role='shard'
            ORDER BY shard_index
        """, uuid.UUID(parent_id))

    target_id = str(parent['target_id']) if parent['target_id'] else None
    target_url = parent['target_url']
    parent_job_id = parent['job_id'] or parent_id
    campaign_id = str(parent['campaign_id']) if parent['campaign_id'] else None
    parent_options = _as_report_dict(parent['options']) or {}

    # Aggregate findings (union, deduped by canonical fingerprint) and pick the
    # richest completed child report as the base skeleton for the merged report.
    union: dict[str, dict] = {}
    base_result = None
    base_section_count = -1
    shard_summaries = []
    shard_coverage_records: list[dict] = []
    shard_execution_evidence: list[dict[str, Any]] = []
    shard_worklists_by_auth: dict[str, list] = {}  # ASM: union per auth identity
    min_score = None
    min_score_grade = None
    for ch in children:
        cres = _as_report_dict(ch['result'])
        status = ch['status']
        child_options = _as_report_dict(ch['options']) or {}
        child_partial = bool(
            str(ch.get('current_phase') or '') == 'partial'
            or (status == 'completed' and _parallel_result_is_partial(cres))
        )
        sc = cres.get('smart_coverage') if isinstance(cres, dict) else None
        shard_coverage_records.append({
            'status': status,
            'options': child_options,
            'smart_coverage': sc if isinstance(sc, dict) else {},
            'partial': child_partial,
        })
        shard_summaries.append({
            'scan_id': str(ch['id']),
            'shard_index': ch['shard_index'],
            'status': status,
            'score': ch['score'],
            'grade': ch['grade'],
            'findings_count': ch['findings_count'],
            'partial': child_partial,
            'stage': child_options.get('parallel_stage'),
            'node_id': str(ch.get('executing_node_id')) if ch.get('executing_node_id') else None,
            'worker_id': ch.get('worker_id'),
            'started_at': ch.get('started_at').isoformat() if ch.get('started_at') else None,
            'completed_at': ch.get('completed_at').isoformat() if ch.get('completed_at') else None,
            'error': ch.get('error_message'),
        })
        if status == 'completed' and ch['score'] is not None:
            if min_score is None or ch['score'] < min_score:
                min_score = ch['score']
                min_score_grade = ch['grade']
        if not cres:
            continue
        shard_execution_evidence.append({
            'scan_id': str(ch['id']),
            'shard_index': ch['shard_index'],
            'stage': child_options.get('parallel_stage'),
            'checks_skipped': cres.get('checks_skipped')
                if isinstance(cres.get('checks_skipped'), list)
                else ((_as_report_dict(cres.get('scan_metadata')) or {}).get('checks_skipped') or []),
            'scanner_execution_receipts': cres.get('scanner_execution_receipts')
                if isinstance(cres.get('scanner_execution_receipts'), list)
                else [],
        })
        wl = (cres.get('active_checks') or {}).get('active_worklist')
        if wl:
            auth_state = asm_inventory.auth_state_from_options(child_options)
            shard_worklists_by_auth.setdefault(auth_state, []).extend(wl)
        if status == 'completed' and child_options.get('parallel_backbone'):
            # The backbone carries the complete single-Smart report contract.
            # Endpoint shards enrich it; they must never replace its browser,
            # posture, discovery, and execution-receipt sections.
            base_section_count = 10**9
            base_result = cres
        elif status == 'completed':
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
            _add_parent_union_finding(union, fp, f)

    # Union the coverage recon pass's findings (browser/DOM-XSS + global checks the
    # zero-rediscovery shards don't run, already verified by the recon's own smart
    # verification phase). Without this, parallel coverage misses whole classes a
    # single scan finds (DOM-XSS, /metrics exposure, BFLA).
    try:
        _recon_raw = r.get(f"coverage:recon_findings:{parent_id}")
        if _recon_raw:
            _recon_findings = json.loads(_recon_raw) or []
            for f in _recon_findings:
                fp = parallel_scan.finding_merge_key(f)
                if not fp:
                    try:
                        fp = generate_finding_fingerprint(f)
                    except Exception:
                        fp = json.dumps(f, sort_keys=True, default=str)[:256]
                _add_parent_union_finding(union, fp, f)
            r.delete(f"coverage:recon_findings:{parent_id}")
            print(f"[merge {parent_id[:8]}] unioned {len(_recon_findings)} recon findings", flush=True)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] recon-findings union error: {e}", flush=True)

    union_findings = list(union.values())
    try:
        from findings import apply_dast_precision_policy
        host = urllib.parse.urlparse(target_url or "").hostname
        union_findings = apply_dast_precision_policy(union_findings, target_host=host or None)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] precision policy skipped: {e}", flush=True)

    # Build merged report.
    merged = copy.deepcopy(base_result) if base_result else {'target': target_url, 'result': {}, 'findings': []}
    merged['findings'] = union_findings
    if not isinstance(merged.get('result'), dict):
        merged['result'] = {}

    # Recompute the parent score/grade from the FINAL union (shards + recon findings)
    # rather than copying the worst shard's score. The union strictly contains more
    # findings than any single shard, so a worst-shard grade can be optimistic and
    # ignores recon-only verified SQLi/DOM-XSS. Floor at the worst shard so the parent
    # is never graded better than any shard.
    agg_score = min_score
    agg_grade = min_score_grade
    _graded_block = None
    try:
        from grading import grade as _grade_report
        _graded = _grade_report(merged)
        _gs = _graded.get('score')
        if _gs is not None and (min_score is None or _gs <= min_score):
            agg_score = _gs
            agg_grade = _graded.get('grade')
            _graded_block = _graded
    except Exception as e:
        print(f"[merge {parent_id[:8]}] parent grade recompute skipped: {e}", flush=True)
    if agg_score is None:
        agg_score = merged['result'].get('score')
        agg_grade = merged['result'].get('grade')
    if agg_score is not None:
        merged['result']['score'] = agg_score
    if agg_grade is not None:
        merged['result']['grade'] = agg_grade
    # Apply the recomputed human-readable summary/notes/remediation so the result
    # SUMMARY block matches the union grade (it was showing the stale shard summary,
    # e.g. top-level F/32 but result.summary still "D (58/100) - 19 issues").
    if _graded_block is not None:
        for _k in ("summary", "notes", "remediation", "cvss_metrics", "compliance"):
            if _graded_block.get(_k) is not None:
                merged["result"][_k] = _graded_block[_k]

    # Recompute the verification/triage summary from the final union so the parent's
    # counts reflect recon + every shard, not a single shard's stale view.
    try:
        from findings import summarize_verification
        merged['verification_summary'] = summarize_verification(union_findings)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] verification summary recompute skipped: {e}", flush=True)

    # Recompute the triage block from the union too — the base-shard triage often
    # showed confirmed.count=0 even when recon contributed verified Critical/High.
    try:
        def _u_sev(f):
            return str(f.get("severity") or "").lower()
        _confirmed = [f for f in union_findings if isinstance(f, dict) and f.get("verified") is True]
        _suspected_high = [
            f for f in union_findings
            if isinstance(f, dict) and not f.get("verified") and _u_sev(f) in ("critical", "high")
        ]
        _needs_review = [
            f for f in union_findings
            if isinstance(f, dict) and f.get("confidence_tier") in ("low", "uncertain")
        ]
        _ai_fp = [f for f in union_findings if isinstance(f, dict) and f.get("ai_verdict") == "false_positive"]
        _verif_skipped = [f for f in union_findings if isinstance(f, dict) and f.get("verification_skipped")]
        merged["triage"] = {
            "confirmed": {"count": len(_confirmed), "sample": _confirmed[:5]},
            "suspected_high": {"count": len(_suspected_high), "sample": _suspected_high[:5]},
            "needs_review": {"count": len(_needs_review), "sample": _needs_review[:5]},
            "ai_false_positive": {"count": len(_ai_fp), "sample": _ai_fp[:5]},
            "verification_skipped": {"count": len(_verif_skipped), "sample": _verif_skipped[:5]},
        }
    except Exception as e:
        print(f"[merge {parent_id[:8]}] triage recompute skipped: {e}", flush=True)

    # Recompute quality_metrics from the union too. This block was previously the
    # ONLY report section left stale after merge: base_result was deep-copied with
    # its single-shard quality_metrics while merged['findings'] grew to the union,
    # so total_findings / severity_distribution disagreed with findings[] and every
    # other recomputed block (docs proposed-next-steps §2). Same helper as the
    # single-scan path, so the numbers are identical for an identical finding set.
    try:
        from findings import compute_quality_metrics
        _base_qm = merged.get('quality_metrics') if isinstance(merged.get('quality_metrics'), dict) else {}
        _cov_status = _base_qm.get('coverage_status')
        if not _cov_status:
            _cov_status = (merged.get('smart_coverage') or {}).get('status') or 'complete'
        _checks_skipped = merged.get('checks_skipped')
        if not isinstance(_checks_skipped, list):
            _meta = merged.get('scan_metadata') if isinstance(merged.get('scan_metadata'), dict) else {}
            _checks_skipped = _meta.get('checks_skipped') if isinstance(_meta.get('checks_skipped'), list) else []
        _ai_enabled = bool((_base_qm.get('ai_validation') or {}).get('enabled'))
        merged['quality_metrics'] = compute_quality_metrics(
            union_findings,
            coverage_status=_cov_status,
            checks_skipped=_checks_skipped,
            ai_enabled=_ai_enabled,
        )
    except Exception as e:
        print(f"[merge {parent_id[:8]}] quality_metrics recompute skipped: {e}", flush=True)

    focused_family = _focused_family_from_parent_options(parent_options)
    focused_score, focused_grade = _recompute_focused_parent_result(
        merged,
        union_findings,
        focused_family,
    )
    if focused_score is not None:
        agg_score = focused_score
    if focused_grade is not None:
        agg_grade = focused_grade

    # Recompute attack chains over the full union (they need every finding).
    # attack_chains is a TOP-LEVEL report section, not part of the grade block.
    try:
        from scanner_tools.attack_chains import analyze_attack_chains
        include_partial = bool(parent_options.get('include_partial_attack_chains'))
        merged['attack_chains'] = analyze_attack_chains(union_findings, include_partial)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] attack-chain recompute skipped: {e}", flush=True)

    completed_n = sum(1 for c in children if c['status'] == 'completed')
    failed_n = sum(1 for c in children if c['status'] == 'failed')
    cancelled_n = sum(1 for c in children if c['status'] == 'cancelled')
    partial_n = sum(
        1 for c in children
        if c['status'] == 'completed' and (
            str(c.get('current_phase') or '') == 'partial'
            or _parallel_result_is_partial(_as_report_dict(c.get('result')))
        )
    )
    strategy = parent_options.get('parallel_strategy')
    merged['parallel'] = {
        'strategy': strategy,
        'planned_request_budget': parent_options.get('parallel_planned_request_budget'),
        'backbone_request_budget': parent_options.get('parallel_backbone_request_budget'),
        'shards': shard_summaries,
        # Keep every child's execution proof without replacing the backbone's
        # top-level report contract. This makes the merged report auditable while
        # preserving the normal single-scan sections consumers already expect.
        'execution_evidence_by_shard': shard_execution_evidence,
        'shards_total': len(children),
        'shards_completed': completed_n,
        'shards_failed': failed_n,
        'shards_cancelled': cancelled_n,
        'shards_partial': partial_n,
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

    merged_subdomain_discovery = parent_options.get(
        'canonical_subdomain_discovery'
    )
    merged = _attach_scan_subdomain_summary(
        merged,
        (
            merged_subdomain_discovery
            if isinstance(merged_subdomain_discovery, Mapping) else None
        ),
    )
    merged_network_discovery = parent_options.get(
        'canonical_network_discovery'
    )
    merged = _attach_scan_network_summary(
        merged,
        (
            merged_network_discovery
            if isinstance(merged_network_discovery, Mapping) else None
        ),
    )

    if _mark_parallel_parent_degraded(
        merged,
        failed_count=failed_n,
        cancelled_count=cancelled_n,
        partial_count=partial_n,
        total_count=len(children),
    ):
        if isinstance(merged.get('result'), dict):
            agg_grade = merged['result'].get('grade', agg_grade)
            agg_score = merged['result'].get('score', agg_score)
    technically_incomplete = bool(failed_n or cancelled_n or partial_n)
    merged['technical_outcome'] = 'INCOMPLETE' if technically_incomplete else 'COMPLETE'

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

    # Invariant harness over the final merged report (docs §1): run it after
    # shard counts, coverage aggregation, target correction, and partial-result
    # markers are applied so trust gates see the same report users receive.
    try:
        from findings import check_report_invariants
        _violations = check_report_invariants(merged)
        merged['invariant_violations'] = _violations
        if _violations:
            print(f"[merge {parent_id[:8]}] REPORT INVARIANT VIOLATIONS: {_violations}", flush=True)
    except Exception as e:
        print(f"[merge {parent_id[:8]}] invariant check skipped: {e}", flush=True)

    filepath = await persist_result_artifact(merged, parent_job_id, parent_id)

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

    # When every shard failed, summarize the first shard's error onto the parent so
    # the scan detail page shows WHY it failed instead of a bare 'failed' row with an
    # empty error_message.
    parent_error_message = None
    if parent_status == 'failed':
        failed_children = [c for c in children if c['status'] == 'failed']
        first = failed_children[0] if failed_children else None
        if first is not None:
            shard_err = first.get('error_message')
            if not shard_err:
                res = first.get('result')
                if isinstance(res, str):
                    try:
                        res = json.loads(res)
                    except Exception:
                        res = None
                if isinstance(res, dict):
                    shard_err = res.get('error')
            parent_error_message = (
                f"All {failed_n} shard(s) failed; merge had no completed shard. "
                f"First failure (shard {first.get('shard_index')}): "
                f"{shard_err or 'no diagnostics recorded'}"
            )[:2000]

    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE scans SET status = $1, result = $2, score = $3, grade = $4,
                findings_count = $5, completed_at = $6, duration_seconds = $7,
                progress = 100, current_phase = $8, error_message = $9
            WHERE id = $10
        """, parent_status, json.dumps(merged), agg_score, agg_grade,
             len(union_findings), completed_at, duration,
             ('completed_partial' if technically_incomplete else 'completed')
             if parent_status == 'completed' else 'failed',
             parent_error_message,
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
                        conn, target_id, worklist, source='scan', auth_state=auth_state,
                        scan_id=parent_id,
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
                worklist_meta = {
                    'truncated': bool(parent_options.get('coverage_worklist_truncated')),
                    'raw_discovered': parent_options.get('coverage_worklist_raw_discovered'),
                    'cap': parent_options.get('coverage_worklist_cap'),
                }
                if _apply_campaign_coverage_rollup(merged, campaign_coverage, worklist_meta):
                    filepath = await persist_result_artifact(
                        merged,
                        parent_job_id,
                        parent_id,
                        conn=conn,
                    )
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
    worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"
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
        slot_acquired, shard_limit = _try_acquire_parallel_shard_slot(
            r, parent_id, options, slot_id=job_id
        )
        if not slot_acquired:
            canonical_queue = isinstance(job_data.get("_canonical_queue_payload"), Mapping)
            wait_cycles = int((
                _redis_scalar_text(r.hget(f"job:{job_id}", "shard_slot_wait_cycles"))
                if canonical_queue else job_data.get('shard_slot_wait_cycles') or 0
            ) or 0) + 1
            requeued = _safe_requeue_payload(job_data)
            if not canonical_queue:
                requeued['shard_slot_wait_cycles'] = wait_cycles
                requeued['last_shard_slot_wait_at'] = utc_now_iso()
            enqueue_job(r, QUEUE_NAME, requeued)
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

    handoff_status = await _confirmed_scan_handoff_status(scan_id)
    if handoff_status not in {'pending', 'queued'}:
        print(
            f"[asm {job_id[:8]}] scan is {handoff_status}; queued worker job skipped",
            flush=True,
        )
        r.hset(
            f"job:{job_id}",
            mapping={
                'status': handoff_status,
                'scan_id': scan_id or '',
                'progress': '100' if handoff_status in {'completed', 'cancelled', 'failed'} else '0',
                'current_phase': handoff_status,
            },
        )
        r.expire(f"job:{job_id}", 86400)
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id, job_id)
        return

    # Claim the durable scan row before leasing endpoints. This makes a failed or
    # cancelled row authoritative even when Redis accepted the enqueue but the API lost
    # the response and marked its pending handoff failed.
    async with db_pool.acquire() as conn:
        scan_claim = await conn.execute(
            """
            UPDATE scans SET status='running', started_at=COALESCE(started_at, $1),
                current_phase='asm_claiming'
            WHERE id=$2 AND status IN ('pending', 'queued')
            """,
            now,
            uuid.UUID(scan_id),
        )
        if scan_claim.endswith("0"):
            current_status = await conn.fetchval(
                "SELECT status FROM scans WHERE id=$1",
                uuid.UUID(scan_id),
            )
        else:
            current_status = "running"
    if scan_claim.endswith("0"):
        current_status = str(current_status or "not_claimable")
        print(
            f"[asm {job_id[:8]}] scan is {current_status}; queued worker job skipped",
            flush=True,
        )
        r.hset(
            f"job:{job_id}",
            mapping={
                'status': current_status,
                'scan_id': scan_id or '',
                'progress': '100' if current_status in {'completed', 'cancelled', 'failed'} else '0',
                'current_phase': current_status,
            },
        )
        r.expire(f"job:{job_id}", 86400)
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id, job_id)
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
                auth_state=options.get('auth_state'),
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
            _release_parallel_shard_slot(r, parent_id, job_id)
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
            _release_parallel_shard_slot(r, parent_id, job_id)
            slot_acquired = False
        async with db_pool.acquire() as conn:
            released_claim = await conn.execute(
                """
                UPDATE scans
                SET status='pending', started_at=NULL, current_phase='waiting_for_domain_rate'
                WHERE id=$1 AND status='running'
                """,
                uuid.UUID(scan_id),
            )
        if released_claim.endswith("0"):
            # Cancellation or another terminal transition won the race. Do not put
            # a terminal scan back on the queue merely because its rate slot closed.
            current_status = str(current_status or "not_claimable")
            print(
                f"[asm {job_id[:8]}] scan became terminal before domain-rate requeue; skipping",
                flush=True,
            )
            return
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
    scoped_opts = _asm_scan_options_for_auth_state(options, auth_state, check_family=check_family)
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
        filepath = await persist_result_artifact(
            result,
            job_id,
            scan_id,
            parent_scan_id=parent_id,
            shard_index=job_data.get('shard_index'),
        )
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
                await _record_asm_executor_tool_receipt(
                    conn,
                    scan_id=scan_id,
                    job_id=job_id,
                    target=target,
                    target_id=target_id,
                    parent_scan_id=parent_id,
                    campaign_id=campaign_id,
                    options=options,
                    result=result,
                    action="batch",
                    status="skipped",
                    parser_status="not_applicable",
                    started_at=now,
                    completed_at=completed_at,
                    duration_seconds=0,
                    endpoint_ids=endpoint_ids,
                    auth_state=auth_state,
                    check_family=check_family,
                    endpoint_filter=endpoint_filter,
                    summary={
                        "claimed_endpoints": len(endpoint_ids),
                        "skip_reason": "auth_missing",
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
        filepath = await persist_result_artifact(
            result,
            job_id,
            scan_id,
            parent_scan_id=parent_id,
            shard_index=job_data.get('shard_index'),
        )
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
            _release_parallel_shard_slot(r, parent_id, job_id)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")
        return

    scan_opts = scoped_opts
    scan_opts['run_kind'] = 'asm_dynamic_batch' if coverage_dynamic_worker else 'asm_batch'
    scan_opts['scan_type'] = scan_opts.get('scan_type') or 'smart'
    scan_opts['parallel'] = False
    for k in ('shard_strategy', 'shards', 'auth_state_shards'):
        scan_opts.pop(k, None)
    scan_opts['custom_endpoints'] = endpoints
    if coverage_dynamic_worker:
        scan_opts['focused_endpoints_only'] = True
        scan_opts['zero_rediscovery'] = True
        # Honor the planner's per-shard designation: exactly one coverage shard
        # per auth state runs host-wide global/posture checks
        # (skip_global_checks=False); the rest skip them so we don't re-emit the
        # same CSP/TLS/DNS findings per shard. Default to skipping when the
        # planner didn't say.
        scan_opts['skip_global_checks'] = bool(options.get('skip_global_checks', True))
    # Honor the planner's per-shard active budget when it set one; otherwise size it
    # with the SAME realistic per-endpoint cost as the coverage planner
    # (_coverage_active_seconds: ~20-32s/endpoint). The old hardcoded 8s/endpoint
    # re-clamped a shard planned at e.g. 1120s down to 320s, stopping SQLi after a
    # couple of endpoints — the dynamic pull-worker / ASM batch path was silently
    # overriding the planner.
    _planned_secs = (options.get('custom_budget') or {}).get('active_max_seconds')
    if isinstance(_planned_secs, (int, float)) and _planned_secs > 0:
        _active_secs = int(_planned_secs)
    else:
        _active_secs = parallel_scan._coverage_active_seconds(
            {**options, 'exploit_depth': exploit_depth}, len(endpoints)
        )
    lean = {
        'max_urls': 200, 'browser_max_pages': 5, 'browser_max_depth': 1,
        'param_discovery_url_limit': 0, 'param_discovery_max_params': 0,
        'nuclei_max_targets': 50,
        'active_max_endpoints': len(endpoints),
        'active_max_seconds': _active_secs,
        # Bound the WHOLE batch so a hang on a slow/remote endpoint can't tie up
        # the claimed in_progress endpoints for hours (the target's default smart
        # max_duration is 600 min). This watchdog must comfortably EXCEED the
        # active budget, not sit ~5 min above it: auth/setup/report overhead plus
        # CPU/IO/target contention when many batches run concurrently push real
        # wall-clock well past active_max_seconds, and a too-tight cap kills the
        # batch mid-active-scan — losing every finding for the claimed endpoints.
        # Give ~2x the active budget plus fixed overhead (more under exploit depth).
        'max_duration_minutes': max(
            15, min(90, (_active_secs // 60) * 2 + (20 if exploit_depth else 10))
        ),
    }
    if coverage_dynamic_worker:
        lean.update({
            'browser_max_pages': 0,
            'api_probe_limit': 0,
            'nuclei_max_targets': 0,
            'phase4_max_seconds': 0,
        })
        if check_family == 'bola':
            # Dynamic workers normally disable Phase 4 to keep SQLi/XSS lanes
            # lean. BOLA/IDOR is implemented in Phase 4, so a focused BOLA lane
            # must preserve a bounded Phase 4 window or it never executes.
            lean['phase4_max_seconds'] = parallel_scan.BOLA_DYNAMIC_PHASE4_SECONDS
    if exploit_depth:
        scan_opts['no_early_stop'] = True
        lean.update({'sqli_extract_max': 8, 'oob_max_findings': 8, 'max_findings_per_family': None})
    parallel_scan._merge_custom_budget(scan_opts, lean)

    async with db_pool.acquire() as conn:
        update_result = await conn.execute(
            """
            UPDATE scans SET status='running', started_at=COALESCE(started_at, $1),
                current_phase='asm_exploit'
            WHERE id=$2 AND status='running'
            """,
            now, uuid.UUID(scan_id),
        )
    if update_result.endswith("0"):
        print(f"[asm {job_id[:8]}] Coverage batch cancelled before start; releasing claimed endpoints", flush=True)
        completed_at = utc_now()
        cancelled_result = {
            "target": target,
            "findings": [],
            "result": {"score": None, "grade": None},
            "scan_metadata": {
                "asm_cancelled_before_start": True,
                "claimed_endpoints": len(endpoint_ids),
            },
        }
        try:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    """UPDATE target_endpoints
                       SET test_status='untested', last_attempt_status='cancelled',
                           lease_owner=NULL, lease_expires_at=NULL, updated_at=NOW()
                       WHERE id = ANY($1::uuid[]) AND test_status='in_progress'""",
                    endpoint_ids,
                )
                await _record_asm_executor_tool_receipt(
                    conn,
                    scan_id=scan_id,
                    job_id=job_id,
                    target=target,
                    target_id=target_id,
                    parent_scan_id=parent_id,
                    campaign_id=campaign_id,
                    options=scan_opts,
                    result=cancelled_result,
                    action="batch",
                    status="skipped",
                    parser_status="not_run",
                    started_at=now,
                    completed_at=completed_at,
                    duration_seconds=int((completed_at - now).total_seconds()),
                    endpoint_ids=endpoint_ids,
                    auth_state=auth_state,
                    check_family=check_family,
                    endpoint_filter=endpoint_filter,
                    summary={
                        "claimed_endpoints": len(endpoint_ids),
                        "skip_reason": "cancelled_before_start",
                    },
                )
        except Exception:
            pass
        if slot_acquired:
            _release_parallel_shard_slot(r, parent_id, job_id)
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
    hb = threading.Thread(
        target=send_heartbeats,
        args=(job_id, stop_heartbeat, parent_id, job_id),
        name=f"heartbeat-{job_id[:8]}",
        daemon=True,
    )
    hb.start()
    error = None
    try:
        try:
            scan_opts = await _hydrate_generic_scan_credentials(scan_opts, scan_id)
            scan_opts = await _hydrate_managed_scan_credentials(scan_opts, scan_id)
            result = await _execute_reserved_deterministic_scan(
                target, scan_opts, scan_id=scan_id, job_id=job_id,
            )
        except Exception as e:
            result = {'target': target, 'error': str(e), 'result': {'score': None, 'grade': None}, 'findings': []}
        findings = result.get('findings', []) or []
        error = result.get('error')
        meta = result.get('scan_metadata') if isinstance(result.get('scan_metadata'), dict) else {}
        partial = bool(meta.get('partial') or meta.get('timed_out'))
        score = result.get('result', {}).get('score')
        grade = result.get('result', {}).get('grade')
        completed_at = utc_now()
        duration = int((completed_at - now).total_seconds())
        telemetry_present = _active_endpoint_telemetry_present(result)
        attempts = _active_endpoint_attempts_from_report(result) if telemetry_present else []
        if error:
            receipt_status = "failed"
            receipt_parser_status = "failed"
        elif meta.get('timed_out'):
            receipt_status = "timeout"
            receipt_parser_status = "partial"
        elif partial:
            receipt_status = "recorded"
            receipt_parser_status = "partial"
        elif telemetry_present:
            receipt_status = "success"
            receipt_parser_status = "parsed"
        else:
            receipt_status = "recorded"
            receipt_parser_status = "partial"
        try:
            async with db_pool.acquire() as conn:
                await _record_asm_executor_tool_receipt(
                    conn,
                    scan_id=scan_id,
                    job_id=job_id,
                    target=target,
                    target_id=target_id,
                    parent_scan_id=parent_id,
                    campaign_id=campaign_id,
                    options=scan_opts,
                    result=result,
                    action="batch",
                    status=receipt_status,
                    parser_status=receipt_parser_status,
                    started_at=now,
                    completed_at=completed_at,
                    duration_seconds=duration,
                    endpoint_ids=endpoint_ids,
                    auth_state=auth_state,
                    check_family=check_family,
                    endpoint_filter=endpoint_filter,
                    error=error,
                    timed_out=bool(meta.get('timed_out')),
                    summary={
                        "claimed_endpoints": len(endpoint_ids),
                        "assigned_endpoints": len(endpoints),
                        "attempts_reported": len(attempts),
                        "findings_count": len(findings),
                        "telemetry_present": telemetry_present,
                        "partial": partial,
                    },
                )
        except Exception as e:
            print(f"[asm {job_id[:8]}] ASM receipt record error: {e}", flush=True)
        filepath = await persist_result_artifact(
            result,
            job_id,
            scan_id,
            parent_scan_id=parent_id,
            shard_index=job_data.get('shard_index'),
        )
        saved = 0
        if target_id and findings and not error and not parent_id:
            try:
                saved = await save_findings(scan_id, target_id, findings)
            except Exception as e:
                print(f"[asm {job_id[:8]}] save_findings error: {e}", flush=True)
        if not error:
            try:
                async with db_pool.acquire() as conn:
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
                        await asm_inventory.upsert_endpoints(
                            conn, target_id, wl, source='asm', auth_state=auth_state,
                            scan_id=scan_id,
                        )
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
            _release_parallel_shard_slot(r, parent_id, job_id)
        await _reconcile_parallel_child_completion(parent_id, r, f"asm {job_id[:8]}")


STALE_REQUEUE_FAIL_AFTER_SECONDS = int(os.environ.get('SHAKERSCAN_STALE_FAIL_AFTER_SECONDS') or 180)
STALE_JOB_MAX_REQUEUE_HARD_CAP = 500  # backstop against a pathological tight loop


class ExecutionScopeError(RuntimeError):
    """Queued work no longer matches the control plane's durable scan scope."""


def _safe_requeue_payload(job_data: Mapping[str, Any]) -> dict[str, Any]:
    """Return the original secret-free canonical envelope after materialization."""
    canonical = job_data.get("_canonical_queue_payload")
    if isinstance(canonical, Mapping):
        return dict(canonical)
    return dict(job_data)


def _redis_scalar_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


async def _resolve_scan_job_target_addresses(target_url: str) -> tuple[str, ...]:
    parsed = urllib.parse.urlsplit(str(target_url or ""))
    hostname = str(parsed.hostname or "").strip().rstrip(".")
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        raise CanonicalScanJobMaterializationError(
            "persisted Scan target URL has no resolvable HTTP(S) host"
        )
    try:
        return (str(ipaddress.ip_address(hostname)),)
    except ValueError:
        pass
    port = int(parsed.port or (443 if parsed.scheme.lower() == "https" else 80))
    try:
        records = await asyncio.get_running_loop().getaddrinfo(
            hostname, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise CanonicalScanJobMaterializationError(
            "runtime DNS resolution failed for scan-job/v2"
        ) from exc
    addresses: list[str] = []
    for record in records:
        try:
            address = str(ipaddress.ip_address(str(record[4][0]).split("%", 1)[0]))
        except (IndexError, ValueError):
            continue
        if address not in addresses:
            addresses.append(address)
        if len(addresses) >= 16:
            break
    if not addresses:
        raise CanonicalScanJobMaterializationError(
            "runtime DNS returned no usable address for scan-job/v2"
        )
    return tuple(addresses)


async def _materialize_scan_job_v2(queue_payload: Mapping[str, Any]) -> dict[str, Any]:
    """Load private Scan inputs only after proving the canonical Redis envelope."""
    scan_id = str(queue_payload.get("scan_id") or "").strip()
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError as exc:
        raise CanonicalScanJobMaterializationError(
            "queued scan-job/v2 has an invalid Scan identity"
        ) from exc
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT target_id, target_url, job_id, options, scan_generation,
                   policy_json, budget_json, scan_job_payload, scan_job_digest,
                   parent_scan_id, scan_role, shard_index, shard_count
            FROM scans
            WHERE id=$1
            """,
            scan_uuid,
        )
    if not row:
        raise CanonicalScanJobMaterializationError(
            "queued scan-job/v2 has no durable Scan record"
        )
    addresses = await _resolve_scan_job_target_addresses(str(row["target_url"] or ""))
    return materialize_canonical_scan_job(
        queue_payload, row, resolved_addresses=addresses,
    )


def _execution_target_key(value: Any) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return raw
    try:
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return raw
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return raw
    host = hostname.lower().rstrip(".")
    host_authority = f"[{host}]" if ":" in host else host
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    authority = host_authority if port in {None, default_port} else f"{host_authority}:{port}"
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, parsed.query, ""))


def _execution_target_authority(value: Any, *, default_scheme: str = "https") -> tuple[str, int] | None:
    raw = str(value or "").strip()
    parsed = urllib.parse.urlsplit(raw if "://" in raw else f"{default_scheme}://{raw}")
    try:
        host = str(parsed.hostname or "").lower().rstrip(".")
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError:
        return None
    return (host, int(port)) if host else None


async def _revalidate_job_execution_scope(job_data: dict[str, Any]) -> bool:
    """Re-derive target/terminal scope immediately before worker execution.

    This does not classify public versus private targets: operators retain full
    freedom to scan authorized local labs. It fences stale or tampered queue
    payloads against the durable scan row and cancelled parent state.
    """
    raw_scan_id = str(job_data.get("scan_id") or "").strip()
    if not raw_scan_id:
        return True
    try:
        scan_id = uuid.UUID(raw_scan_id)
    except ValueError as exc:
        raise ExecutionScopeError("queued work has an invalid scan identity") from exc
    async with db_pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT child.target_url, child.status, parent.status AS parent_status
            FROM scans child
            LEFT JOIN scans parent ON parent.id=child.parent_scan_id
            WHERE child.id=$1
            """,
            scan_id,
        )
    if not row:
        raise ExecutionScopeError("queued work has no durable scan record")
    if str(row.get("status") or "") in {"completed", "failed", "cancelled"}:
        return False
    if str(row.get("parent_status") or "") == "cancelled":
        return False
    queued_target = str(job_data.get("target") or "").strip()
    durable_target = str(row.get("target_url") or "").strip()
    if durable_target and not queued_target:
        raise ExecutionScopeError("queued work is missing its durable scan target")
    if queued_target and _execution_target_key(queued_target) != _execution_target_key(durable_target):
        options = job_data.get("options") if isinstance(job_data.get("options"), Mapping) else {}
        inferred_match = bool(
            options.get("target_scheme_inferred")
            and _execution_target_authority(queued_target)
            == _execution_target_authority(durable_target)
        )
        if not inferred_match:
            raise ExecutionScopeError("queued target does not match the durable scan target")
    return True


async def _fail_execution_scope(job_data: dict[str, Any], message: str) -> None:
    raw_scan_id = str(job_data.get("scan_id") or "").strip()
    job_id = str(job_data.get("job_id") or "").strip()
    try:
        scan_id = uuid.UUID(raw_scan_id)
    except ValueError:
        scan_id = None
    if scan_id:
        async with db_pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE scans
                SET status='failed', progress=100, current_phase='scope_revalidation_failed',
                    error_message=$2, completed_at=NOW()
                WHERE id=$1 AND status NOT IN ('completed','failed','cancelled')
                """,
                scan_id,
                message[:500],
            )
    if job_id:
        try:
            get_redis().hset(
                f"job:{job_id}",
                mapping={"status": "failed", "current_phase": "scope_revalidation_failed", "error": message[:500]},
            )
        except Exception:
            pass


async def _refuse_stale_job_if_needed(job_data: dict) -> bool:
    """Fail-closed worker freshness. If a job was submitted with
    require_current_workers (or SHAKERSCAN_WORKER_FAIL_CLOSED) and THIS worker's
    build fingerprint does not match the submit-time expected one, do NOT run stale
    code — running it silently corrupts results (the worker-skew class). Requeue so
    a current worker takes it; if no current worker accepts it within the stale
    fail-closed window, fail the scan rather than loop. Returns True if refused."""
    options = job_data.get('options') if isinstance(job_data.get('options'), dict) else {}
    expected_fp = options.get('expected_build_fingerprint_at_submit')
    require_current = bool(options.get('require_current_workers')) or \
        str(os.environ.get('SHAKERSCAN_WORKER_FAIL_CLOSED') or '').strip().lower() in ('1', 'true', 'yes')
    if not (expected_fp and require_current):
        return False
    worker_fp = _worker_build_fingerprint()
    # Fail CLOSED: only a worker that can PROVE it is current (fingerprint present
    # AND equal to the submit-time expected one) may run. An unknown fingerprint
    # (None) is NOT provably current, so it must be refused — treating "unknown" as
    # "safe to run" was a fail-OPEN bug.
    if worker_fp is not None and worker_fp == expected_fp:
        return False

    job_id = str(job_data.get('job_id') or 'unknown')
    scan_id = job_data.get('scan_id')
    source_queue = str(
        job_data.get("_base_queue_name")
        or (RETEST_QUEUE_NAME if job_data.get('type') == 'finding_retest' else QUEUE_NAME)
    )
    # Time-based, not count-based: a current worker in a MIXED fleet picks up the
    # requeued job within seconds, so the window never elapses. Only when NO current
    # worker takes it for the whole window (the fleet is uniformly stale, e.g. a
    # half-finished deploy) do we fail closed. A bounce count alone would false-fail
    # a job that merely got picked up by stale workers a few times.
    now = time.time()
    canonical_queue = isinstance(job_data.get("_canonical_queue_payload"), Mapping)
    if canonical_queue:
        redis_client = get_redis()
        first_stale = float(_redis_scalar_text(
            redis_client.hget(f"job:{job_id}", "first_stale_requeue_at")
        ) or 0) or now
        attempts = int(_redis_scalar_text(
            redis_client.hget(f"job:{job_id}", "stale_requeue_attempts")
        ) or 0) + 1
    else:
        first_stale = float(job_data.get('first_stale_requeue_at') or 0) or now
        attempts = int(job_data.get('stale_requeue_attempts') or 0) + 1
    if (now - first_stale) < STALE_REQUEUE_FAIL_AFTER_SECONDS and attempts <= STALE_JOB_MAX_REQUEUE_HARD_CAP:
        if canonical_queue:
            get_redis().hset(
                f"job:{job_id}",
                mapping={
                    "first_stale_requeue_at": first_stale,
                    "stale_requeue_attempts": attempts,
                },
            )
        else:
            job_data['first_stale_requeue_at'] = first_stale
            job_data['stale_requeue_attempts'] = attempts
        enqueue_job(get_redis(), source_queue, _safe_requeue_payload(job_data))
        print(f"[{job_id[:8]}] REFUSED stale build (worker {worker_fp} != submit {expected_fp}); "
              f"requeued for a current worker (attempt {attempts}, {now - first_stale:.0f}s waiting)", flush=True)
        await asyncio.sleep(2)
        return True

    msg = (f"No current-build worker available for {STALE_REQUEUE_FAIL_AFTER_SECONDS}s "
           f"(require_current_workers): worker build {worker_fp} != submit-time expected {expected_fp}. "
           "Restart ALL workers to deploy current code.")
    if scan_id:
        try:
            async with db_pool.acquire() as conn:
                await conn.execute(
                    "UPDATE scans SET status='failed', error_message=$2, completed_at=NOW() "
                    "WHERE id=$1 AND status NOT IN ('completed','cancelled')",
                    uuid.UUID(scan_id), msg[:500])
        except Exception as e:
            print(f"[{job_id[:8]}] stale-fail DB update error: {e}", flush=True)
    get_redis().hset(f"job:{job_id}", mapping={'status': 'failed', 'current_phase': 'build_stale'})
    print(f"[{job_id[:8]}] FAILED build-stale: no current worker for "
          f"{STALE_REQUEUE_FAIL_AFTER_SECONDS}s ({attempts} bounces)", flush=True)
    return True


async def _attribute_job_execution(job_data: dict[str, Any]) -> None:
    """Stamp the durable scan row before dispatch so every phase has host/node provenance."""
    scan_id = str(job_data.get("scan_id") or "").strip()
    if not scan_id:
        return
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        return
    worker_id = _worker_runtime_identity()
    raw_node_id = str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip()
    try:
        node_uuid = uuid.UUID(raw_node_id) if raw_node_id else None
    except ValueError as exc:
        raise RuntimeError("SHAKERSCAN_NODE_ID is not a UUID") from exc
    async with db_pool.acquire() as conn:
        node = None
        if node_uuid is not None:
            node = await conn.fetchrow(
                """
                SELECT id, name, region, egress_ip, labels, build_fingerprint,
                       worker_image_digest, active_worker_image_digest, agent_version,
                       desired_state_version, applied_state_version, last_error,
                       rollout_in_progress, status, drain
                FROM nodes WHERE id=$1
                """,
                node_uuid,
            )
            node_current = bool(
                node
                and str(node.get("status") or "") == "healthy"
                and not bool(node.get("drain"))
                and not bool(node.get("rollout_in_progress"))
                and not node.get("last_error")
                and int(node.get("applied_state_version") or 0) >= int(node.get("desired_state_version") or 1)
                and str(node.get("active_worker_image_digest") or "")
                == str(node.get("worker_image_digest") or "")
            )
            if not node_current:
                raise RuntimeError("fleet node is missing or disabled, or is not current; refusing job execution")
        labels = parse_json_field(node.get("labels")) if node else {}
        labels = labels if isinstance(labels, dict) else {}
        execution_context = {
            "node_id": str(node_uuid) if node_uuid else None,
            "node_name": str(node.get("name") or "") if node else None,
            "worker_id": worker_id,
            "worker_build_fingerprint": _worker_build_fingerprint(),
            "worker_image_digest": (
                str(node.get("active_worker_image_digest") or "") if node
                else str(os.environ.get("FLEET_WORKER_IMAGE_DIGEST") or "")
            ) or None,
            "node_build_fingerprint": str(node.get("build_fingerprint") or "") if node else None,
            "node_agent_version": str(node.get("agent_version") or "") if node else None,
            "region": str(node.get("region") or "") if node else None,
            "egress_ip": str(node.get("egress_ip") or "") if node else None,
            "transport": str(labels.get("transport") or "standalone"),
            "credential_scope": "overlay_shared_store" if node else "standalone_local",
        }
        row = await conn.fetchrow(
            """
            UPDATE scans
            SET worker_id = $2,
                executing_node_id = COALESCE($3, executing_node_id),
                execution_context = $4::jsonb
            WHERE id = $1
            RETURNING id
            """,
            scan_uuid,
            worker_id,
            node_uuid,
            json.dumps(execution_context, sort_keys=True, separators=(",", ":")),
        )
    if node_uuid is not None and not row:
        raise RuntimeError("fleet node is missing or disabled; refusing job execution")


async def _fleet_node_accepts_work() -> bool:
    """Fail closed while a joined node is draining, rolling, disabled, or unreachable."""
    raw_node_id = str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip()
    if not raw_node_id:
        return True
    try:
        node_id = uuid.UUID(raw_node_id)
    except ValueError:
        return False
    try:
        async with db_pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT status, drain, rollout_in_progress, desired_state_version,
                       applied_state_version, worker_image_digest,
                       active_worker_image_digest, last_error, last_heartbeat_at,
                       last_heartbeat_at >= NOW() - ($2::int * INTERVAL '1 second') AS heartbeat_current
                FROM nodes WHERE id=$1
                """,
                node_id,
                max(60, int(os.environ.get("FLEET_HEARTBEAT_TIMEOUT_SECONDS") or 300)),
            )
    except Exception as exc:
        print(f"[fleet] cannot authorize node scheduling: {exc}", flush=True)
        return False
    return bool(
        row
        and str(row.get("status") or "") == "healthy"
        and not bool(row.get("drain"))
        and not bool(row.get("rollout_in_progress"))
        and bool(row.get("heartbeat_current"))
        and not row.get("last_error")
        and int(row.get("applied_state_version") or 0) >= int(row.get("desired_state_version") or 1)
        and str(row.get("active_worker_image_digest") or "")
        == str(row.get("worker_image_digest") or "")
    )


def _fleet_busy_marker(job_data: dict[str, Any]) -> Path | None:
    """Publish host-visible job occupancy so the node agent can drain safely."""
    if not str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip():
        return None
    container_id = str(os.environ.get("HOSTNAME") or "").strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", container_id):
        raise RuntimeError("fleet worker hostname cannot be used for a busy marker")
    directory = RESULTS_DIR / ".fleet-busy"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = directory / f"{container_id}.json"
    temporary = directory / f".{container_id}.{os.getpid()}.tmp"
    payload = {
        "node_id": str(os.environ.get("SHAKERSCAN_NODE_ID") or ""),
        "container_id": container_id,
        "job_id": str(job_data.get("job_id") or ""),
        "scan_id": str(job_data.get("scan_id") or ""),
        "started_at": utc_now_iso(),
    }
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(marker)
    return marker


def _clear_fleet_busy_marker(marker: Path | None) -> None:
    if marker is None:
        return
    try:
        marker.unlink(missing_ok=True)
    except OSError as exc:
        print(f"[fleet] busy marker cleanup failed: {exc}", flush=True)


_AGENT_TOOL_OUTPUT_BYTES = max(
    4_096, min(200_000, int(os.environ.get("SHAKERSCAN_AGENT_TOOL_OUTPUT_BYTES", "80000")))
)
_AGENT_TOOL_RESULT_TTL_SECONDS = max(
    60, min(86_400, int(os.environ.get("SHAKERSCAN_AGENT_TOOL_RESULT_TTL_SECONDS", "3600")))
)


def _terminate_agent_tool_process_group(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        proc.kill()


async def _read_agent_tool_streams(
    proc: asyncio.subprocess.Process,
    *,
    max_bytes: int,
    overflow: asyncio.Event,
) -> tuple[bytes, bytes]:
    """Drain both pipes while retaining at most ``max_bytes`` in aggregate."""
    lock = asyncio.Lock()
    retained = 0

    async def read_one(stream: asyncio.StreamReader | None) -> bytes:
        nonlocal retained
        if stream is None:
            return b""
        chunks: list[bytes] = []
        while True:
            chunk = await stream.read(8192)
            if not chunk:
                break
            async with lock:
                remaining = max(0, max_bytes - retained)
                if remaining:
                    kept = chunk[:remaining]
                    chunks.append(kept)
                    retained += len(kept)
                if len(chunk) > remaining:
                    overflow.set()
        return b"".join(chunks)

    stdout_task = asyncio.create_task(read_one(proc.stdout))
    stderr_task = asyncio.create_task(read_one(proc.stderr))
    return tuple(await asyncio.gather(stdout_task, stderr_task))  # type: ignore[return-value]


def _agent_scanner_request_settlement(
    scanner_name: str, stdout: str, stderr: bytes | str | None,
) -> dict[str, Any]:
    """Settle scanner traffic without exposing diagnostic stderr to the planner."""
    normalized = str(scanner_name or "").strip().lower()
    settlement_input = str(stdout or "")
    if normalized == "nuclei" and stderr:
        diagnostics = (
            stderr.decode("utf-8", "replace")
            if isinstance(stderr, bytes)
            else str(stderr)
        )
        settlement_input = f"{settlement_input}\n{diagnostics}"
    return agent_tools.scanner_request_settlement(normalized, settlement_input)


def _materialize_bounded_ffuf_wordlist(
    *, options: Mapping[str, Any], reservation: Mapping[str, Any], scratch_dir: str,
) -> tuple[str, int]:
    """Create the exact owner-only wordlist whose entries equal FFUF's wire ceiling."""
    try:
        request_limit = max(0, int(reservation.get("http_requests") or 0))
    except (TypeError, ValueError) as exc:
        raise agent_tools.AgentToolError("ffuf request reservation is invalid") from exc
    if request_limit < 1:
        raise agent_tools.AgentToolError("ffuf has no reserved requests")
    source = Path(agent_tools.scanner_ffuf_wordlist_source(options))
    selected: list[str] = []
    seen: set[str] = set()
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise agent_tools.AgentToolError("ffuf bundled wordlist is unavailable") from exc
    for raw in lines:
        entry = raw.strip()
        if (
            not entry
            or entry.startswith("#")
            or len(entry.encode("utf-8")) > 512
            or any(character in entry for character in "\x00\r\n")
            or entry in seen
        ):
            continue
        seen.add(entry)
        selected.append(entry)
        if len(selected) >= request_limit:
            break
    if not selected:
        raise agent_tools.AgentToolError("ffuf bundled wordlist has no safe entries")
    destination = Path(scratch_dir) / "bounded-wordlist.txt"
    descriptor = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(selected) + "\n")
    return str(destination), len(selected)


async def _execute_agent_scanner_process(
    job_data: Mapping[str, Any],
    *,
    heartbeat: Callable[[], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Run one fixed-template scanner and return a bounded typed result."""
    job_id = str(job_data.get("job_id") or "").strip()
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    started_at = datetime.now(timezone.utc)
    monotonic_started = time.monotonic()
    proc: asyncio.subprocess.Process | None = None
    status = "failed"
    error: str | None = None
    stdout = ""
    err: bytes = b""
    returncode: int | None = None
    scratch_dir: str | None = None
    pinned_proxy: PinnedSocksProxy | None = None
    read_streams: asyncio.Task[tuple[bytes, bytes]] | None = None
    process_started = False
    execution_uncertain = False
    process_enforcement: dict[str, Any] = {}
    name = str(job_data.get("tool_name") or "").strip().lower()
    execution_target = str(job_data.get("execution_target") or "")
    registered_target = str(job_data.get("registered_target") or "")
    cancelled = (
        job_data.get("_cancelled")
        if callable(job_data.get("_cancelled")) else None
    )
    try:
        if not job_id:
            raise agent_tools.AgentToolError("scanner job requires an identity")
        name, _ignored, options = agent_tools.coerce_run_tool({
            "name": job_data.get("tool_name"),
            "target": execution_target,
            "options": job_data.get("scanner_options"),
        })
        execution_target = agent_tools.validate_scanner_execution_target(
            registered_target,
            execution_target,
        )
        pinned_address = agent_tools.validate_pinned_scanner_address(
            job_data.get("pinned_address"),
            job_data.get("authorized_addresses"),
        )
        parsed_execution = urllib.parse.urlsplit(execution_target)
        target_port = parsed_execution.port or (
            443 if parsed_execution.scheme.lower() == "https" else 80
        )
        reserved_budget = (
            dict(job_data.get("_reserved_budget") or {})
            if isinstance(job_data.get("_reserved_budget"), Mapping)
            else {}
        )
        if not reserved_budget:
            raise agent_tools.AgentToolError(
                "scanner process requires its durable reserved budget"
            )
        connection_ceiling = max(
            1,
            int(reserved_budget.get("http_requests") or 0),
            int(reserved_budget.get("tcp_ports_attempted") or 0),
        )
        pinned_proxy = await PinnedSocksProxy(
            hostname=str(parsed_execution.hostname or ""),
            pinned_address=pinned_address,
            port=target_port,
            max_connections=connection_ceiling,
        ).start()
        runtime_paths: dict[str, Any] = {}
        if name in {"ffuf", "sqlmap"}:
            scratch_dir = tempfile.mkdtemp(
                prefix=f"shakerscan-{name}-{job_id[:8]}-"
            )
            os.chmod(scratch_dir, 0o700)
        if name == "ffuf":
            wordlist_path, word_count = _materialize_bounded_ffuf_wordlist(
                options=options,
                reservation=reserved_budget,
                scratch_dir=str(scratch_dir),
            )
            runtime_paths.update({
                "ffuf_wordlist": wordlist_path,
                "ffuf_word_count": word_count,
            })
        if name == "sqlmap":
            runtime_paths["sqlmap_output_dir"] = str(scratch_dir)
        process_plan = agent_tools.build_enforced_scanner_plan(
            name,
            execution_target,
            options,
            reserved_budget=reserved_budget,
            pinned_address=pinned_address,
            pinned_proxy_url=pinned_proxy.proxy_url,
            oob_interactsh_server=job_data.get("oob_interactsh_server"),
            oob_interactsh_token=job_data.get("oob_interactsh_token"),
            trusted_headers=job_data.get("trusted_headers"),
            runtime_paths=runtime_paths,
        )
        binary = process_plan.binary
        argv = list(process_plan.argv)
        process_enforcement = process_plan.enforcement_receipt()
        requested_timeout = int(job_data.get("timeout_ms") or process_plan.timeout_ms)
        timeout_ms = max(1_000, min(process_plan.timeout_ms, requested_timeout))
        process_environment = dict(os.environ)
        process_environment.update(dict(process_plan.env))
        proc = await asyncio.create_subprocess_exec(
            binary,
            *argv,
            env=process_environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        process_started = True
        overflow = asyncio.Event()
        read_streams = asyncio.create_task(
            _read_agent_tool_streams(
                proc,
                max_bytes=_AGENT_TOOL_OUTPUT_BYTES,
                overflow=overflow,
            )
        )
        wait_process = asyncio.create_task(proc.wait())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_ms / 1000.0
        next_heartbeat = loop.time() + 15.0
        while not wait_process.done():
            if (
                (cancelled is not None and cancelled())
                or redis_client.exists(cancel_key)
            ):
                status, error = "cancelled", "cancelled"
                _terminate_agent_tool_process_group(proc)
                break
            if overflow.is_set():
                status, error = "failed", "output_limit_exceeded"
                _terminate_agent_tool_process_group(proc)
                break
            proxy_limit = getattr(pinned_proxy, "limit_exceeded", None)
            if proxy_limit is not None and proxy_limit.is_set():
                status, error = "failed", "connection_limit_exceeded"
                _terminate_agent_tool_process_group(proc)
                break
            if loop.time() >= deadline:
                status, error = "timeout", "timeout"
                _terminate_agent_tool_process_group(proc)
                break
            if heartbeat is not None and loop.time() >= next_heartbeat:
                await heartbeat()
                next_heartbeat = loop.time() + 15.0
            await asyncio.sleep(0.05)
        await wait_process
        out, err = await read_streams
        returncode = proc.returncode
        stdout = (out or b"").decode("utf-8", "replace")
        pinned_url, _pinned_host, _pinned_header = agent_tools._pinned_scanner_url(
            execution_target,
            pinned_address,
        )
        original_origin = urllib.parse.urlunsplit(
            (*urllib.parse.urlsplit(execution_target)[:2], "", "", "")
        )
        pinned_origin = urllib.parse.urlunsplit(
            (*urllib.parse.urlsplit(pinned_url)[:2], "", "", "")
        )
        stdout = stdout.replace(pinned_origin, original_origin)
        if overflow.is_set() and status not in {"cancelled", "timeout"}:
            status, error = "failed", "output_limit_exceeded"
        if status not in {"cancelled", "timeout"}:
            if error == "output_limit_exceeded":
                status = "failed"
            elif returncode not in (0, None) and not stdout.strip():
                status = "failed"
                error = (
                    redact_text((err or b"").decode("utf-8", "replace")[:300])
                    or f"exit_{returncode}"
                )
            else:
                status = "success"
    except FileNotFoundError:
        error = "scanner_not_available"
    except (agent_tools.AgentToolError, KeyError, TypeError, ValueError) as exc:
        error = f"contract:{str(exc)[:240]}"
    except asyncio.CancelledError:
        if proc is not None and proc.returncode is None:
            _terminate_agent_tool_process_group(proc)
            await proc.wait()
        if read_streams is not None:
            await asyncio.gather(read_streams, return_exceptions=True)
        raise
    except (ReservationConflict, ReservationStoreError):
        if proc is not None and proc.returncode is None:
            _terminate_agent_tool_process_group(proc)
            await proc.wait()
        if read_streams is not None:
            await asyncio.gather(read_streams, return_exceptions=True)
        raise
    except Exception as exc:  # noqa: BLE001 - caller charges uncertain execution fully
        if proc is not None and proc.returncode is None:
            _terminate_agent_tool_process_group(proc)
            await proc.wait()
        if read_streams is not None:
            await asyncio.gather(read_streams, return_exceptions=True)
        error = f"worker_fault:{type(exc).__name__}"
        execution_uncertain = process_started
    finally:
        if pinned_proxy is not None:
            await pinned_proxy.close()
        if scratch_dir:
            shutil.rmtree(scratch_dir, ignore_errors=True)

    typed_output = agent_tools.parse_scanner_output(
        name,
        stdout,
        allowed_host=(
            urllib.parse.urlsplit(registered_target).hostname
            if name == "katana"
            else None
        ),
    )
    settlement = _agent_scanner_request_settlement(name, stdout, err)
    if status in {"failed", "cancelled"} and not stdout.strip():
        if error == "scanner_not_available" or str(error or "").startswith("contract:"):
            settlement = {
                "mode": "exact",
                "actual": 0,
                "observed_minimum": 0,
                "source": "not_executed",
            }
    safe_lines = [
        json.dumps(record, sort_keys=True, separators=(",", ":"))[:1200]
        for record in list(typed_output.get("records") or [])[:60]
        if isinstance(record, dict)
    ]
    record_count = int(typed_output.get("record_count") or 0)
    finished_at = datetime.now(timezone.utc)
    network_telemetry = {
        "connections_attempted": (
            int(getattr(pinned_proxy, "connection_attempts", 0))
            if pinned_proxy is not None else 0
        ),
        "connections_opened": (
            int(getattr(pinned_proxy, "connections_opened", 0))
            if pinned_proxy is not None else 0
        ),
        "connections_rejected": (
            int(getattr(pinned_proxy, "connections_rejected", 0))
            if pinned_proxy is not None else 0
        ),
        "bytes_to_target": (
            int(getattr(pinned_proxy, "bytes_to_target", 0))
            if pinned_proxy is not None else 0
        ),
        "bytes_from_target": (
            int(getattr(pinned_proxy, "bytes_from_target", 0))
            if pinned_proxy is not None else 0
        ),
        "targets": 1 if process_started else 0,
    }
    return {
        "job_id": job_id,
        "status": status,
        "error": error,
        "returncode": returncode,
        "started_at": started_at.isoformat(),
        "finished_at": finished_at.isoformat(),
        "elapsed_seconds": max(0, int(time.monotonic() - monotonic_started + 0.999)),
        "partial": status == "timeout" and record_count > 0,
        "timed_out": status == "timeout",
        "output_lines": safe_lines,
        "line_count": record_count,
        "typed_output": typed_output,
        "settlement": settlement,
        "process_enforcement": process_enforcement,
        "network_telemetry": network_telemetry,
        "execution_uncertain": execution_uncertain,
        "network_binding": "hostname_preserving_pinned_socks5",
    }


async def process_agent_scanner_tool_job(job_data: dict[str, Any]) -> None:
    """Execute a legacy fixed-template scanner job outside the API process."""
    job_id = str(job_data.get("job_id") or "").strip()
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    result = await _execute_agent_scanner_process(job_data)
    if job_id:
        redis_client.set(
            result_key,
            json.dumps(result, default=str, separators=(",", ":")),
            ex=_AGENT_TOOL_RESULT_TTL_SECONDS,
        )
        redis_client.hset(
            f"job:{job_id}",
            mapping={
                "status": str(result.get("status") or "failed"),
                "current_phase": "agent_tool_complete",
                "error": str(result.get("error") or ""),
            },
        )
        redis_client.expire(f"job:{job_id}", _AGENT_TOOL_RESULT_TTL_SECONDS)
        redis_client.delete(cancel_key)


def _worker_hunt_ledger_limits(budget: Mapping[str, Any]) -> dict[str, int]:
    return {
        "agent_actions": int(budget.get("max_capability_calls") or 0),
        "active_actions": int(budget.get("max_active_actions") or 0),
        "http_requests": int(budget.get("max_http_requests") or 0),
        "tcp_ports_attempted": int(budget.get("max_tcp_ports") or 0),
        "browser_actions": int(budget.get("max_browser_actions") or 0),
        "state_changing_requests": int(budget.get("max_state_changing_requests") or 0),
        "tool_wall_seconds": int(budget.get("max_duration_seconds") or 0),
        "device_fragility_points": int(budget.get("max_device_fragility_points") or 0),
        "hosts_attempted": int(budget.get("max_hosts") or 0),
        "udp_ports_attempted": int(budget.get("max_udp_ports") or 0),
        "oob_interactions": int(budget.get("max_oob_interactions") or 0),
    }


def _worker_json_object(value: Any) -> dict[str, Any]:
    return json_object_field(value)


def _worker_json_array(value: Any) -> list[Any]:
    return json_array_field(value)


def _worker_terminal_replay_result(stored: Any, *, job_id: str) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    return {
        "job_id": job_id,
        "status": "success" if stored.record.status == "committed" else "failed",
        "error": stored.record.failure_reason,
        "replayed": int(stored.record.actual.get("http_requests") or 0),
        "budget_consumed": dict(stored.record.actual),
        "used_after_reconciliation": dict(stored.ledger_after_settlement or {}),
        "reservation_id": stored.record.reservation_id,
        "receipt": receipt,
        "observations": list(receipt.get("observations") or []),
        "durable_budget_settled": True,
        "idempotent_redelivery": True,
    }


async def process_request_collection_replay_job(job_data: dict[str, Any]) -> None:
    """Decrypt and execute one exact collection selection on the assigned worker.

    The queue contains only opaque IDs, a selector, and the collection digest observed
    by the control plane.  The worker reloads every authority object from PostgreSQL,
    creates the exact plan in private memory, and holds the Hunt ledger before sending
    any target bytes.
    """
    job_id = str(job_data.get("job_id") or "").strip()
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    store = PostgresBudgetReservationStore()
    credential_stack = AsyncExitStack()
    receipt_context: dict[str, Any] | None = None
    result: dict[str, Any] = {
        "job_id": job_id,
        "status": "failed",
        "error": "worker_fault",
        "durable_budget_settled": False,
    }
    try:
        if not job_id:
            raise ReplayExecutionError("replay job requires an identity")
        hunt_id = str(uuid.UUID(str(job_data.get("hunt_id") or "")))
        action_id = str(uuid.UUID(str(job_data.get("action_id") or "")))
        collection_id = str(uuid.UUID(str(job_data.get("collection_id") or "")))
        binding_id = str(uuid.UUID(str(job_data.get("binding_id") or "")))
        selection_id = str(uuid.UUID(str(job_data.get("selection_id") or "")))
        reservation_id = str(uuid.UUID(str(job_data.get("reservation_id") or "")))
        expected_payload_sha256 = str(job_data.get("expected_payload_sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_payload_sha256):
            raise ReplayExecutionError("replay job collection digest is invalid")
        expected_selection_digest = str(job_data.get("selection_digest") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_selection_digest):
            raise ReplayExecutionError("replay job selection digest is invalid")
        expected_environment_id = str(job_data.get("environment_id") or "").strip() or None
        if expected_environment_id:
            expected_environment_id = str(uuid.UUID(expected_environment_id))
        expected_environment_sha256 = str(
            job_data.get("expected_environment_sha256") or ""
        ).lower() or None
        if expected_environment_sha256 and not re.fullmatch(
            r"[0-9a-f]{64}", expected_environment_sha256
        ):
            raise ReplayExecutionError("replay job environment digest is invalid")
        replay_policy = str(job_data.get("replay_policy") or "").strip()
        if replay_policy not in {"safe_reads", "confirmed_active"}:
            raise ReplayExecutionError("replay job policy is not executable")
        queued_allowed_origins = tuple(
            str(item) for item in job_data.get("allowed_origins") or () if str(item)
        )
        if not queued_allowed_origins:
            raise ReplayExecutionError("replay job has no exact origin binding")
        selector_raw = _worker_json_object(job_data.get("selector"))
        selector = RequestSelector(
            request_ids=tuple(str(item) for item in selector_raw.get("request_ids") or ()),
            methods=tuple(str(item) for item in selector_raw.get("methods") or ()),
            path_regex=str(selector_raw.get("path_regex") or "") or None,
            safe_methods_only=True,
            limit=max(1, min(int(selector_raw.get("limit") or 25), 25)),
        )
        credential_profile_id = str(job_data.get("credential_profile_id") or "").strip()
        principal_slot = str(job_data.get("principal_slot") or "").strip().lower()
        raw_expected_profile_version = job_data.get("expected_profile_version")
        if credential_profile_id or principal_slot or raw_expected_profile_version is not None:
            try:
                credential_profile_id = str(uuid.UUID(credential_profile_id))
                expected_profile_version = int(raw_expected_profile_version)
            except (TypeError, ValueError, AttributeError) as exc:
                raise ReplayExecutionError("managed principal queue binding is invalid") from exc
            if principal_slot not in {"primary", "secondary", "service"}:
                raise ReplayExecutionError("managed principal queue slot is invalid")
            if expected_profile_version < 1:
                raise ReplayExecutionError("managed principal queue version is invalid")
        else:
            expected_profile_version = None

        async with db_pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", uuid.UUID(hunt_id),
                )
                if not run:
                    raise ReplayExecutionError("replay Hunt does not exist")
                if str(run["target_kind"]) not in {"web", "api"} or not run["target_id"]:
                    raise ReplayExecutionError("collection replay requires a web or API Hunt")
                action = await conn.fetchrow(
                    """SELECT id, capability_name, status FROM hunt_actions
                       WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                    uuid.UUID(action_id), uuid.UUID(hunt_id),
                )
                if not action or str(action["capability_name"]) != "collections.replay_safe":
                    raise ReplayExecutionError("replay action identity is not valid")
                collection = await conn.fetchrow(
                    """SELECT c.id, c.encrypted_payload, c.payload_sha256,
                              b.id AS binding_id, b.allowed_origins, b.environment_id,
                              e.encrypted_payload AS encrypted_environment,
                              e.payload_sha256 AS environment_sha256,
                              s.id AS selection_id, s.replay_policy, s.selector_json,
                              s.selection_digest
                       FROM request_collections c
                       JOIN request_collection_bindings b
                         ON b.id=$2 AND b.collection_id=c.id AND b.is_active=true
                       JOIN request_collection_selections s
                         ON s.id=$3 AND s.collection_id=c.id
                        AND s.binding_id=b.id AND s.is_active=true
                       LEFT JOIN request_collection_environments e
                         ON e.id=b.environment_id AND e.collection_id=c.id
                        AND e.is_active=true
                       WHERE c.id=$1 AND c.target_id=$4 AND c.is_active=true
                         AND b.target_id=$4 AND b.target_kind=$5
                       FOR UPDATE OF c, b, s""",
                    uuid.UUID(collection_id), uuid.UUID(binding_id),
                    uuid.UUID(selection_id), run["target_id"], str(run["target_kind"]),
                )
                if not collection:
                    raise ReplayExecutionError(
                        "request collection selection is unavailable or bound to another target"
                    )
                if str(collection["payload_sha256"] or "").lower() != expected_payload_sha256:
                    raise ReplayExecutionError("request collection changed after action admission")
                stored_origins = tuple(
                    str(item) for item in _worker_json_array(collection["allowed_origins"])
                    if str(item)
                )
                if stored_origins != queued_allowed_origins:
                    raise ReplayExecutionError("request collection origin binding changed")
                stored_environment_id = (
                    str(collection["environment_id"])
                    if collection["environment_id"] else None
                )
                stored_environment_sha256 = (
                    str(collection["environment_sha256"] or "").lower() or None
                )
                if (
                    stored_environment_id != expected_environment_id
                    or stored_environment_sha256 != expected_environment_sha256
                ):
                    raise ReplayExecutionError("request collection environment binding changed")
                if str(collection["replay_policy"] or "") != replay_policy:
                    raise ReplayExecutionError("request collection replay policy changed")
                stored_selection = RequestCollectionSelection.from_mapping(
                    _worker_json_object(collection["selector_json"])
                )
                recomputed_selection_digest = request_collection_selection_digest(
                    collection_id=collection_id,
                    payload_sha256=expected_payload_sha256,
                    binding_id=binding_id,
                    allowed_origins=stored_origins,
                    selector=stored_selection,
                    replay_policy=replay_policy,
                    environment_sha256=stored_environment_sha256,
                )
                if (
                    str(collection["selection_digest"] or "").lower()
                    != expected_selection_digest
                    or recomputed_selection_digest != expected_selection_digest
                ):
                    raise ReplayExecutionError("request collection selection changed")
                context = _worker_json_object(run["context_pack"])
                hunt_policy = _worker_json_object(run["policy_json"])
                existing_reservation = await store.load(
                    conn, reservation_id, for_update=True,
                )
                if existing_reservation is not None:
                    if (
                        existing_reservation.action_id != action_id
                        or existing_reservation.record.owner_kind != "hunt"
                        or existing_reservation.record.owner_id != hunt_id
                        or existing_reservation.record.capability_name != "collections.replay"
                    ):
                        raise ReservationConflict(
                            "replay reservation identity does not match the queued action"
                        )
                    if existing_reservation.record.terminal:
                        result = _worker_terminal_replay_result(
                            existing_reservation, job_id=job_id,
                        )
                        return

        raw_payload = str(decrypt_secret(collection["encrypted_payload"]) or "")
        if not raw_payload or raw_payload.startswith("enc:fernet:"):
            raise ReplayExecutionError("request collection could not be decrypted on the worker")
        try:
            payload = json.loads(raw_payload)
        except json.JSONDecodeError as exc:
            raise ReplayExecutionError("request collection payload is invalid") from exc
        if not isinstance(payload, Mapping):
            raise ReplayExecutionError("request collection payload is not an object")
        payload_digest = hashlib.sha256(
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        if payload_digest != expected_payload_sha256:
            raise ReplayExecutionError("decrypted request collection failed its integrity check")
        if expected_environment_id:
            raw_environment = str(
                decrypt_secret(collection["encrypted_environment"]) or ""
            )
            if not raw_environment or raw_environment.startswith("enc:fernet:"):
                raise ReplayExecutionError(
                    "request collection environment could not be decrypted on the worker"
                )
            try:
                environment = json.loads(raw_environment)
            except json.JSONDecodeError as exc:
                raise ReplayExecutionError(
                    "request collection environment payload is invalid"
                ) from exc
            if not isinstance(environment, Mapping):
                raise ReplayExecutionError(
                    "request collection environment payload is not an object"
                )
            environment_digest = hashlib.sha256(
                json.dumps(
                    environment,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            ).hexdigest()
            if environment_digest != expected_environment_sha256:
                raise ReplayExecutionError(
                    "decrypted request collection environment failed its integrity check"
                )
            payload = {**dict(payload), "environment": dict(environment)}

        target_context = (
            dict(context.get("target") or {})
            if isinstance(context.get("target"), Mapping) else {}
        )
        origins = tuple(str(item) for item in target_context.get("origins") or () if str(item))
        target_url = str(target_context.get("url") or "")
        parsed_target = urllib.parse.urlsplit(target_url)
        hunt_origins = tuple(
            str(item) for item in origins if str(item)
        )
        if any(origin not in hunt_origins for origin in queued_allowed_origins):
            raise ReplayExecutionError(
                "request collection binding exceeds the Hunt target origins"
            )
        target = TargetBinding(
            target_id=str(run["target_id"]),
            target_kind=str(run["target_kind"]),
            canonical_host=parsed_target.hostname,
            allowed_origins=queued_allowed_origins,
            allowed_addresses=tuple(
                str(item) for item in context.get("authorized_target_addresses") or () if str(item)
            ),
            allowed_root_domains=(
                str(target_context.get("root_domain") or parsed_target.hostname or "")
                .lower().rstrip("."),
            ),
            environment=str(target_context.get("environment") or "unknown"),
            scope_receipt_id=str(hunt_policy.get("scope_receipt_id") or "") or None,
        )
        stored_runtime_selector = RequestSelector(
            request_ids=stored_selection.request_ids,
            folders=stored_selection.folders,
            methods=stored_selection.methods,
            path_regex=stored_selection.path_regex,
            tags=stored_selection.tags,
            safe_methods_only=True,
            limit=min(stored_selection.max_requests, 2_000),
        )
        allowed_request_ids = {
            str(item.get("id") or "")
            for item in select_requests(payload, stored_runtime_selector)
            if item.get("id")
        }
        queued_request_ids = set(selector.request_ids)
        if not queued_request_ids or not queued_request_ids.issubset(allowed_request_ids):
            raise ReplayExecutionError(
                "queued replay requests exceed the saved collection selection"
            )
        plan = build_selected_replay_plan(
            payload,
            selector,
            allowed_origins=target.allowed_origins,
            default_origin=(target.allowed_origins[0] if target.allowed_origins else None),
            authorization=ReplayAuthorization(),
        )
        if credential_profile_id:
            context_ref = select_hunt_principal_reference(context, principal_slot)
            if context_ref is None or context_ref["profile_id"] != credential_profile_id:
                raise ReplayExecutionError("managed principal queue reference changed")
            if context_ref["profile_version"] != expected_profile_version:
                raise ReplayExecutionError("managed principal context version changed")
            async with db_pool.acquire() as conn:
                authority = await validate_worker_credential_authority(
                    conn,
                    owner_kind="hunt",
                    owner_id=hunt_id,
                    target=target,
                    approval_receipt_id=hunt_policy.get("approval_receipt_id"),
                    scope_receipt_id=hunt_policy.get("scope_receipt_id"),
                    action_name="hunt.capability:collections.replay_safe",
                )
                resolved = await credential_stack.enter_async_context(
                    WorkerCredentialResolver().resolve(
                        conn,
                        profile_id=credential_profile_id,
                        target=target,
                        capability="request.replay",
                        authority=authority,
                    )
                )
            if (
                resolved.profile.current_version != expected_profile_version
                or resolved.profile.principal_slot != principal_slot
            ):
                raise ReplayExecutionError("managed principal profile changed after admission")
            plan = bind_replay_credential_headers(
                plan,
                resolved.http_headers().as_dict(),
                auth_kind=resolved.profile.auth_kind,
            )
            receipt_context = {
                "principal_profile_ref": resolved.profile.profile_id,
                "principal_profile_version": resolved.profile.current_version,
                "principal_slot": resolved.profile.principal_slot,
            }
        additional_budget = {
            "agent_actions": 1,
            "tool_wall_seconds": max(
                1, min(int(job_data.get("tool_wall_seconds") or 60), 300),
            ),
        }
        requested_budget = replay_reservation_budget(plan, additional_budget)
        requested = DurableBudgetReservation.request(
            owner_kind="hunt",
            owner_id=hunt_id,
            capability_name="collections.replay",
            amounts=requested_budget,
            reservation_id=reservation_id,
        )

        persisted = None
        held_ledger: dict[str, int] = {}
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", uuid.UUID(hunt_id),
                )
                if not locked or str(locked["status"]) not in {"active", "awaiting_planner"}:
                    raise ReplayExecutionError("Hunt is no longer executable")
                stored = await store.create_requested(
                    conn,
                    action_id=action_id,
                    action_digest=plan.input_digest,
                    record=requested,
                )
                if stored.record.terminal:
                    result = _worker_terminal_replay_result(stored, job_id=job_id)
                    return
                if stored.record.status != "requested":
                    raise ReservationConflict(
                        "replay action already has an active durable reservation"
                    )
                budget = _worker_json_object(locked["budget_json"])
                limits = _worker_hunt_ledger_limits(budget)
                used = _worker_json_object(locked["budget_used_json"])
                consumed = {key: int(used.get(key) or 0) for key in limits}
                try:
                    reserved, held_ledger = stored.record.reserve_against(
                        limits=limits,
                        consumed=consumed,
                        lease_seconds=max(90, additional_budget["tool_wall_seconds"] + 10),
                    )
                except BudgetExceeded as exc:
                    released = stored.record.release(
                        proof_not_started=True,
                        reason="budget_exhausted_before_execution",
                    )
                    await store.persist_terminal(
                        conn,
                        previous=stored,
                        terminal=released,
                        ledger_after_settlement=consumed,
                        receipt=None,
                    )
                    dimension = next(iter(exc.shortages), "unknown")
                    await conn.execute(
                        """UPDATE hunt_runs SET status='budget_exhausted', stop_reason=$2,
                                  updated_at=NOW() WHERE id=$1""",
                        uuid.UUID(hunt_id), f"budget_exhausted:{dimension}",
                    )
                    await conn.execute(
                        """UPDATE hunt_actions SET status='failed', completed_at=NOW(),
                                  result_summary=$2 WHERE id=$1""",
                        uuid.UUID(action_id), json.dumps({"error": f"budget_exhausted:{dimension}"}),
                    )
                    result = {
                        "job_id": job_id,
                        "status": "failed",
                        "error": f"budget_exhausted:{dimension}",
                        "reservation_id": reservation_id,
                        "budget_consumed": {},
                        "durable_budget_settled": True,
                    }
                    return
                persisted = await store.persist_transition(
                    conn,
                    previous=stored,
                    current=reserved,
                    ledger_after_hold=held_ledger,
                )
                used.update(held_ledger)
                await conn.execute(
                    """UPDATE hunt_runs SET budget_used_json=$2, status='active',
                              updated_at=NOW() WHERE id=$1""",
                    uuid.UUID(hunt_id), json.dumps(used),
                )
                await conn.execute(
                    "UPDATE hunt_actions SET status='running' WHERE id=$1",
                    uuid.UUID(action_id),
                )

        settled_ledger = dict(held_ledger)

        async def persist_runtime_transition(
            current: DurableBudgetReservation, _ledger: Mapping[str, int],
        ) -> None:
            nonlocal persisted
            if persisted is None:
                raise ReservationStoreError("replay reservation persistence was not initialized")
            async with db_pool.acquire() as conn:
                async with conn.transaction():
                    owner = await conn.fetchrow(
                        "SELECT id, status FROM hunt_runs WHERE id=$1 FOR UPDATE",
                        uuid.UUID(hunt_id),
                    )
                    if not owner or str(owner["status"]) not in {
                        "active", "awaiting_planner", "budget_exhausted"
                    }:
                        raise ReplayExecutionError("Hunt stopped before the next replay request")
                    latest = await store.load(
                        conn, reservation_id, for_update=True,
                    )
                    if latest is None or latest.record.state_digest != persisted.record.state_digest:
                        raise ReservationConflict("replay reservation changed before worker transition")
                    persisted = await store.persist_transition(
                        conn, previous=latest, current=current,
                    )

        async def persist_runtime_settlement(
            terminal: DurableBudgetReservation,
            receipt: Any,
            _ledger: Mapping[str, int],
        ) -> None:
            nonlocal persisted, settled_ledger
            if persisted is None:
                raise ReservationStoreError("replay reservation persistence was not initialized")
            async with db_pool.acquire() as conn:
                async with conn.transaction():
                    locked = await conn.fetchrow(
                        "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", uuid.UUID(hunt_id),
                    )
                    if not locked:
                        raise ReservationStoreError("replay Hunt disappeared during settlement")
                    latest = await store.load(conn, reservation_id, for_update=True)
                    if latest is None or latest.record.state_digest != persisted.record.state_digest:
                        raise ReservationConflict("replay reservation changed before settlement")
                    current_used = _worker_json_object(locked["budget_used_json"])
                    current_ledger = {
                        key: int(current_used.get(key) or 0)
                        for key in _worker_hunt_ledger_limits(
                            _worker_json_object(locked["budget_json"])
                        )
                    }
                    settled_ledger = terminal.reconcile_consumed(current_ledger)
                    persisted = await store.persist_terminal(
                        conn,
                        previous=latest,
                        terminal=terminal,
                        ledger_after_settlement=settled_ledger,
                        receipt=receipt,
                    )
                    current_used.update(settled_ledger)
                    await conn.execute(
                        "UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1",
                        uuid.UUID(hunt_id), json.dumps(current_used),
                    )
                    await conn.execute(
                        """UPDATE hunt_actions SET status=$2, result_summary=$3,
                                  completed_at=NOW() WHERE id=$1""",
                        uuid.UUID(action_id),
                        (
                            "completed"
                            if terminal.status == "committed"
                            else "cancelled"
                            if receipt.status == "cancelled"
                            else "failed"
                        ),
                        json.dumps({
                            "reservation_id": reservation_id,
                            "receipt_hash": receipt.receipt_hash,
                            "status": receipt.status,
                        }),
                    )

        worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"
        replay_spec = agent_tools.CAPABILITY_REGISTRY.require(
            "collections.replay_safe"
        )
        replay_adapter = ReplayExecutionAdapter(
            specification=replay_spec,
            execution_kwargs={
                "plan": plan,
                "target": target,
                "owner_kind": "hunt",
                "owner_id": hunt_id,
                "worker_id": worker_id,
                "limits": _worker_hunt_ledger_limits(
                    _worker_json_object(run["budget_json"])
                ),
                "consumed": held_ledger,
                "transport": PinnedAiohttpReplayTransport(),
                "timeout_seconds": max(
                    0.1,
                    min(
                        30.0,
                        float(additional_budget["tool_wall_seconds"])
                        / len(plan.requests),
                    ),
                ),
                "reservation_id": reservation_id,
                "lease_seconds": max(
                    90, additional_budget["tool_wall_seconds"] + 10
                ),
                "on_reservation": persist_runtime_transition,
                "on_settlement": persist_runtime_settlement,
                "require_durable_persistence": True,
                "additional_budget": additional_budget,
                "initial_reservation": (
                    persisted.record if persisted is not None else None
                ),
                "receipt_context": receipt_context,
            },
        )
        execution = await CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=replay_spec,
                target=target,
                requested_budget=persisted.record.requested,
                adapter_managed_cancellation=True,
            ),
            replay_adapter,
            heartbeat=lambda: asyncio.sleep(0),
            cancelled=lambda: bool(redis_client.exists(cancel_key)),
        )
        outcome = replay_adapter.outcome
        if outcome is None:
            raise ReplayExecutionError(
                execution.errors[0]
                if execution.errors
                else "replay capability failed before durable settlement"
            )
        public_receipt = outcome.receipt.public_dict()
        result = {
            "job_id": job_id,
            "status": execution.status,
            "error": None if outcome.reservation.status == "committed" else outcome.reservation.failure_reason,
            "ok": execution.status == "success",
            "partial": execution.partial,
            "replayed": int(outcome.reservation.actual.get("http_requests") or 0),
            "observations": [dict(item) for item in execution.observations],
            "budget_consumed": dict(execution.actual_budget),
            "used_after_reconciliation": settled_ledger,
            "reservation_id": reservation_id,
            "receipt": public_receipt,
            "safe_methods_only": True,
            "secret_values_visible": False,
            "durable_budget_settled": True,
            "network_binding": "runtime_target_binding",
        }
    except asyncio.CancelledError:
        raise
    except (
        ReplayExecutionError,
        RequestReplayError,
        RequestCollectionContractError,
        CredentialReferenceError,
        CredentialResolutionError,
        ReservationConflict,
        ReservationStoreError,
        ValueError,
        TypeError,
        KeyError,
    ) as exc:
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"contract:{str(exc)[:240]}",
            "durable_budget_settled": False,
        }
    except Exception as exc:  # noqa: BLE001 - publish a bounded operational result
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"worker_fault:{type(exc).__name__}",
            "durable_budget_settled": False,
        }
    finally:
        try:
            await credential_stack.aclose()
        except Exception:  # noqa: BLE001 - cleanup must not suppress durable replay results
            pass
        if job_id:
            redis_client.set(
                result_key,
                json.dumps(result, default=str, separators=(",", ":")),
                ex=_AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.hset(
                f"job:{job_id}",
                mapping={
                    "status": str(result.get("status") or "failed"),
                    "current_phase": "request_collection_replay_complete",
                    "error": str(result.get("error") or ""),
                },
            )
            redis_client.expire(f"job:{job_id}", _AGENT_TOOL_RESULT_TTL_SECONDS)
            redis_client.delete(cancel_key)


def _worker_terminal_network_result(
    stored: Any,
    *,
    job_id: str,
    network_binding: str = "runtime_target_binding",
) -> dict[str, Any]:
    receipt = dict(stored.receipt or {})
    partial = bool(receipt.get("partial"))
    receipt_status = str(receipt.get("status") or "").strip().lower()
    status = (
        "partial" if stored.record.status == "committed" and partial
        else "success" if stored.record.status == "committed"
        else "cancelled" if receipt_status == "cancelled"
        else "blocked" if receipt_status == "blocked"
        else "failed"
    )
    observations = [
        dict(item) for item in receipt.get("observations") or []
        if isinstance(item, Mapping)
    ]
    return {
        "job_id": job_id,
        "status": status,
        "ok": status == "success",
        "error": stored.record.failure_reason,
        "partial": partial,
        "timed_out": bool(receipt.get("timed_out")),
        "typed_output": {
            "parser": receipt.get("parser_version"),
            "parser_status": "partial" if partial else "parsed" if status == "success" else "failed",
            "records": observations,
            "record_count": len(observations),
            "errors": list(receipt.get("errors") or []),
        },
        "budget_consumed": dict(stored.record.actual),
        "used_after_reconciliation": dict(stored.ledger_after_settlement or {}),
        "reservation_id": stored.record.reservation_id,
        "budget_reservation_id": stored.record.reservation_id,
        "budget_reservation_state": stored.record.status,
        "receipt_id": str(receipt.get("receipt_id") or "") or None,
        "receipt": receipt,
        "durable_budget_settled": True,
        "idempotent_redelivery": True,
        "network_binding": network_binding,
    }


async def _record_hunt_network_tool_receipt(
    conn: Any,
    *,
    receipt_id: uuid.UUID,
    hunt_id: uuid.UUID,
    action_id: uuid.UUID,
    reservation_id: str,
    action_digest: str,
    target: TargetBinding,
    policy: ScanPolicy,
    prepared: Any,
    status: str,
    partial: bool,
    timed_out: bool,
    parser_errors: list[str],
    record_count: int,
    reserved: Mapping[str, int],
    actual: Mapping[str, int],
    used_after: Mapping[str, int],
    started_at: datetime,
    finished_at: datetime,
) -> None:
    redacted_argv = _redact_receipt_value([
        {
            "adapter": prepared.adapter_name,
            "execution": dict(prepared.redacted_execution),
        }
    ])
    target_scope = _redact_receipt_value({
        "hunt_id": str(hunt_id),
        "hunt_action_id": str(action_id),
        "target_id": target.target_id,
        "target_kind": target.target_kind,
        "runtime_target_binding": True,
    })
    command_hash = _tool_receipt_hash({
        "capability_name": prepared.capability_name,
        "action_digest": action_digest,
        "redacted_argv": redacted_argv,
        "target_scope": target_scope,
    })
    tool_status = (
        "timeout" if timed_out
        else "success" if status in {"success", "partial"}
        else "failed"
    )
    parser_status = "partial" if partial else "parsed" if status == "success" else "failed"
    await conn.execute(
        """
        INSERT INTO tool_receipts (
            id, tool_name, tool_version, adapter_version, command_hash, redacted_argv,
            worker_build, container_image, target_scope, scope_receipt_id,
            approval_receipt_id, status, parser_status, exit_code, timed_out,
            started_at, finished_at, parsed_evidence_instance_ids, redaction_summary,
            metadata_json, created_by, capability_name, adapter_name, budget_json,
            partial, hunt_id
        ) VALUES (
            $1,$2,$3,$4,$5,$6::jsonb,
            $7,$8,$9::jsonb,$10,
            $11,$12,$13,$14,$15,
            $16,$17,$18::jsonb,$19,
            $20::jsonb,$21,$22,$23,$24::jsonb,
            $25,$26
        )
        """,
        receipt_id,
        prepared.adapter_name,
        prepared.adapter_version,
        prepared.adapter_version,
        command_hash,
        json.dumps(redacted_argv),
        os.environ.get("BUILD_FINGERPRINT"),
        os.environ.get("WORKER_IMAGE"),
        json.dumps(target_scope),
        target.scope_receipt_id,
        _optional_uuid(policy.approval_receipt_id),
        tool_status,
        parser_status,
        0 if status in {"success", "partial"} else 124 if timed_out else 1,
        timed_out,
        started_at,
        finished_at,
        json.dumps([]),
        "canonical Hunt capability; target and arguments are server-owned and redacted",
        json.dumps(_redact_receipt_value({
            "hunt_action_id": str(action_id),
            "durable_budget_reservation_id": reservation_id,
            "action_digest": action_digest,
            "record_count": max(0, int(record_count)),
            "parser_errors": parser_errors[:20],
        })),
        "worker:hunt_v2",
        prepared.capability_name,
        prepared.adapter_name,
        json.dumps({
            "reserved": dict(reserved),
            "actual": dict(actual),
            "used_after_reconciliation": dict(used_after),
        }),
        partial,
        hunt_id,
    )


def _worker_scanner_execution_target(
    registered_target: str,
    capability_input: Mapping[str, Any],
) -> str:
    path = str(capability_input.get("path") or "").strip()
    if not path:
        candidate = registered_target
    else:
        if not path.startswith("/") or path.startswith("//"):
            raise agent_tools.AgentToolError(
                "scanner path must be an absolute same-origin path starting with /"
            )
        candidate = urllib.parse.urljoin(registered_target, path)
        if (
            urllib.parse.urlsplit(candidate)[:2]
            != urllib.parse.urlsplit(registered_target)[:2]
        ):
            raise agent_tools.AgentToolError(
                "scanner path escapes the persisted Hunt target origin"
            )
    return agent_tools.validate_scanner_execution_target(
        registered_target,
        candidate,
    )


async def process_canonical_scanner_capability_job(
    job_data: dict[str, Any],
) -> None:
    """Execute a canonical external Hunt scanner under its durable reservation."""
    job_id = str(job_data.get("job_id") or "").strip()
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    store = PostgresBudgetReservationStore()
    result: dict[str, Any] = {
        "job_id": job_id,
        "status": "failed",
        "error": "worker_fault",
        "durable_budget_settled": False,
    }
    publish_result = True
    persisted = None
    try:
        if not job_id:
            raise agent_tools.AgentToolError("scanner capability job requires an identity")
        hunt_id = uuid.UUID(str(job_data.get("hunt_id") or ""))
        action_id = uuid.UUID(str(job_data.get("action_id") or ""))
        reservation_id = str(
            uuid.UUID(str(job_data.get("budget_reservation_id") or ""))
        )
        queued_action_digest = str(job_data.get("action_digest") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", queued_action_digest):
            raise agent_tools.AgentToolError(
                "scanner capability action digest is invalid"
            )
        capability_name = str(
            job_data.get("capability_name") or ""
        ).strip().lower()
        if capability_name not in DURABLE_SCANNER_HUNT_CAPABILITIES:
            raise agent_tools.AgentToolError(
                "capability is not a durable external scanner action"
            )
        capability_input = dict(job_data.get("capability_input") or {})
        spec = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
        if not spec.legacy_tool_name or not spec.binary:
            raise agent_tools.AgentToolError(
                "canonical scanner capability has no fixed-template adapter"
            )
        worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"

        async with db_pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE",
                    hunt_id,
                )
                if not run:
                    raise agent_tools.AgentToolError("scanner Hunt does not exist")
                action = await conn.fetchrow(
                    """SELECT id, capability_name, status FROM hunt_actions
                       WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                    action_id,
                    hunt_id,
                )
                if (
                    not action
                    or str(action["capability_name"]) != capability_name
                ):
                    raise agent_tools.AgentToolError(
                        "scanner action identity is invalid"
                    )
                stored = await store.load(conn, reservation_id, for_update=True)
                if (
                    stored is None
                    or stored.action_id != str(action_id)
                    or stored.record.owner_kind != "hunt"
                    or stored.record.owner_id != str(hunt_id)
                    or stored.record.capability_name != capability_name
                ):
                    raise ReservationConflict(
                        "scanner reservation identity does not match the queued action"
                    )
                if stored.action_digest != queued_action_digest:
                    raise ReservationConflict(
                        "scanner reservation action digest does not match the queue"
                    )
                if stored.record.terminal:
                    result = _worker_terminal_network_result(
                        stored,
                        job_id=job_id,
                        network_binding="hostname_preserving_pinned_socks5",
                    )
                    return
                if stored.record.status == "running":
                    publish_result = False
                    result = {
                        "job_id": job_id,
                        "status": "running",
                        "error": "idempotent_redelivery_running",
                        "budget_reservation_id": reservation_id,
                        "durable_budget_settled": False,
                        "idempotent_redelivery": True,
                    }
                    return
                if (
                    stored.record.status != "reserved"
                    or str(action["status"]) != "reserved"
                ):
                    raise ReservationConflict(
                        "scanner action is not dispatchable"
                    )
                if str(run["status"]) not in {
                    "active",
                    "awaiting_planner",
                    "budget_exhausted",
                }:
                    raise agent_tools.AgentToolError(
                        "Hunt is no longer executable"
                    )

                context = _worker_json_object(run["context_pack"])
                hunt_policy = _worker_json_object(run["policy_json"])
                allowed = {
                    str(item)
                    for item in hunt_policy.get("allowed_capabilities") or []
                }
                if capability_name not in allowed:
                    raise agent_tools.AgentToolError(
                        "scanner capability is outside the persisted Hunt allowlist"
                    )
                if spec.requires_active_approval and not (
                    hunt_policy.get("active_testing")
                    and hunt_policy.get("approval_receipt_id")
                ):
                    raise agent_tools.AgentToolError(
                        "scanner capability no longer has active approval"
                    )
                target_context = (
                    dict(context.get("target") or {})
                    if isinstance(context.get("target"), Mapping)
                    else {}
                )
                registered_target = str(target_context.get("url") or "")
                execution_target = _worker_scanner_execution_target(
                    registered_target,
                    capability_input,
                )
                authorized_addresses = [
                    str(item)
                    for item in context.get("authorized_target_addresses") or []
                    if str(item)
                ][:16]
                if not authorized_addresses:
                    raise agent_tools.AgentToolError(
                        "Hunt has no frozen target resolution set"
                    )
                pinned_address = agent_tools.validate_pinned_scanner_address(
                    authorized_addresses[0],
                    authorized_addresses,
                )
                target = TargetBinding(
                    target_id=str(run["target_id"]),
                    target_kind=str(run["target_kind"]),
                    canonical_host=urllib.parse.urlsplit(
                        registered_target
                    ).hostname,
                    allowed_origins=tuple(target_context.get("origins") or ()),
                    allowed_addresses=tuple(authorized_addresses),
                    environment=str(
                        target_context.get("environment") or "unknown"
                    ),
                    scope_receipt_id=str(
                        hunt_policy.get("scope_receipt_id") or ""
                    ) or None,
                )
                policy = ScanPolicy(
                    active_testing=bool(hunt_policy.get("active_testing")),
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=hunt_policy.get(
                        "approval_receipt_id"
                    ),
                )
                limits = _worker_hunt_ledger_limits(
                    _worker_json_object(run["budget_json"])
                )
                requested_budget = {
                    key: int(value)
                    for key, value in spec.budget_cost.items()
                    if key in limits
                }
                requested_budget["agent_actions"] = 1
                if spec.requires_active_approval:
                    requested_budget["active_actions"] = 1
                recomputed_digest = hunt_capability_action_digest(
                    hunt_id=hunt_id,
                    action_id=action_id,
                    capability_name=capability_name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["target_id"],
                    capability_input=capability_input,
                    requested_budget=requested_budget,
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                )
                if (
                    recomputed_digest != queued_action_digest
                    or stored.action_digest != queued_action_digest
                    or dict(stored.record.requested) != requested_budget
                ):
                    raise ReservationConflict(
                        "scanner queue payload does not match its durable action"
                    )
                lease_seconds = hunt_capability_lease_seconds(
                    requested_budget
                )
                running = stored.record.start(
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )
                persisted = await store.persist_transition(
                    conn,
                    previous=stored,
                    current=running,
                )
                updated = await conn.execute(
                    """UPDATE hunt_actions SET status='running', started_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$2 AND status='reserved'""",
                    action_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "scanner action changed before worker dispatch"
                    )

        async def heartbeat_reservation() -> None:
            nonlocal persisted
            if persisted is None:
                raise ReservationStoreError(
                    "scanner reservation persistence was not initialized"
                )
            async with db_pool.acquire() as heartbeat_conn:
                async with heartbeat_conn.transaction():
                    owner = await heartbeat_conn.fetchrow(
                        "SELECT status FROM hunt_runs WHERE id=$1 FOR UPDATE",
                        hunt_id,
                    )
                    if not owner or str(owner["status"]) not in {
                        "active",
                        "awaiting_planner",
                        "budget_exhausted",
                    }:
                        raise ReservationStoreError(
                            "Hunt stopped during scanner execution"
                        )
                    latest = await store.load(
                        heartbeat_conn,
                        reservation_id,
                        for_update=True,
                    )
                    if (
                        latest is None
                        or latest.record.state_digest
                        != persisted.record.state_digest
                        or latest.record.worker_id != worker_id
                    ):
                        raise ReservationConflict(
                            "scanner reservation changed before heartbeat"
                        )
                    heartbeat_record = latest.record.heartbeat(
                        worker_id=worker_id,
                        lease_seconds=lease_seconds,
                    )
                    persisted = await store.persist_transition(
                        heartbeat_conn,
                        previous=latest,
                        current=heartbeat_record,
                    )

        oob_server, oob_token = agent_tools.resolve_hunt_interactsh_config(
            allow_active=bool(policy.active_testing),
        )
        receipt_properties = dict(
            spec.input_schema.get("properties") or {}
        )
        receipt_input = {
            key: value
            for key, value in capability_input.items()
            if key in receipt_properties
        }
        if receipt_input.get("path"):
            receipt_input["path"] = str(
                receipt_input["path"]
            ).split("?", 1)[0]
        safe_path = urllib.parse.urlsplit(execution_target).path or "/"
        scanner_adapter = ScannerExecutionAdapter(
            specification=spec,
            process_payload={
                "job_id": job_id,
                "tool_name": spec.legacy_tool_name,
                "execution_target": execution_target,
                "registered_target": registered_target,
                "scanner_options": capability_input,
                "timeout_ms": int(spec.default_timeout_ms),
                "pinned_address": pinned_address,
                "authorized_addresses": authorized_addresses,
                "oob_interactsh_server": oob_server,
                "oob_interactsh_token": oob_token,
            },
            process_runner=_execute_agent_scanner_process,
            requested_budget=persisted.record.requested,
            redacted_execution={
                **receipt_input,
                "path": safe_path,
            },
        )
        execution = await CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=spec,
                target=target,
                requested_budget=persisted.record.requested,
            ),
            scanner_adapter,
            heartbeat=heartbeat_reservation,
            cancelled=lambda: bool(redis_client.exists(cancel_key)),
        )
        process_result = scanner_adapter.process_result
        typed_output = (
            dict(process_result.get("typed_output") or {})
            if isinstance(process_result.get("typed_output"), Mapping)
            else {}
        )
        observations = [dict(item) for item in execution.observations]
        parser_errors = [
            str(item) for item in typed_output.get("errors") or ()
        ][:20]
        status = execution.status
        is_partial = execution.partial
        error = (
            str(process_result.get("error") or "").strip()
            or (execution.errors[0] if execution.errors else None)
        )
        action_status = (
            "completed"
            if status == "success"
            else "partial"
            if is_partial
            else "cancelled"
            if status == "cancelled"
            else "failed"
        )
        actual = dict(execution.actual_budget)

        started_at = str(
            process_result.get("started_at")
            or persisted.record.started_at.isoformat()
        )
        finished_at = str(
            process_result.get("finished_at")
            or datetime.now(timezone.utc).isoformat()
        )
        receipt_id = uuid.uuid4()
        prepared_receipt = SimpleNamespace(
            capability_name=capability_name,
            adapter_name=str(spec.adapter),
            adapter_version=str(spec.adapter_version),
            redacted_execution=dict(execution.redacted_execution),
        )
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE",
                    hunt_id,
                )
                if not locked:
                    raise ReservationStoreError(
                        "scanner Hunt disappeared during settlement"
                    )
                latest = await store.load(
                    conn,
                    reservation_id,
                    for_update=True,
                )
                if (
                    latest is None
                    or persisted is None
                    or latest.record.state_digest
                    != persisted.record.state_digest
                    or latest.record.status != "running"
                    or latest.record.worker_id != worker_id
                ):
                    raise ReservationConflict(
                        "scanner reservation changed before settlement"
                    )
                current_used = _worker_json_object(
                    locked["budget_used_json"]
                )
                current_ledger = {
                    key: int(current_used.get(key) or 0)
                    for key in _worker_hunt_ledger_limits(
                        _worker_json_object(locked["budget_json"])
                    )
                }
                terminal, capability_receipt = terminalize_hunt_capability(
                    latest.record,
                    action_digest=queued_action_digest,
                    capability_name=capability_name,
                    adapter_name=str(spec.adapter),
                    adapter_version=str(spec.adapter_version),
                    parser_version=execution.parser_version,
                    target_id=target.target_id,
                    target_kind=target.target_kind,
                    capability_input=execution.redacted_execution,
                    action_status=action_status,
                    actual_budget=actual,
                    worker_id=worker_id,
                    started_at=started_at,
                    finished_at=finished_at,
                    receipt_id=str(receipt_id),
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                    result={
                        "ok": status == "success",
                        "error": error,
                        "timed_out": execution.timed_out,
                        "receipt_observations": observations,
                    },
                )
                reconciled = terminal.reconcile_consumed(current_ledger)
                await _record_hunt_network_tool_receipt(
                    conn,
                    receipt_id=receipt_id,
                    hunt_id=hunt_id,
                    action_id=action_id,
                    reservation_id=reservation_id,
                    action_digest=queued_action_digest,
                    target=target,
                    policy=policy,
                    prepared=prepared_receipt,
                    status=("partial" if is_partial else status),
                    partial=is_partial,
                    timed_out=bool(process_result.get("timed_out")),
                    parser_errors=parser_errors,
                    record_count=len(observations),
                    reserved=latest.record.requested,
                    actual=actual,
                    used_after=reconciled,
                    started_at=datetime.fromisoformat(
                        started_at.replace("Z", "+00:00")
                    ),
                    finished_at=datetime.fromisoformat(
                        finished_at.replace("Z", "+00:00")
                    ),
                )
                persisted = await store.persist_terminal(
                    conn,
                    previous=latest,
                    terminal=terminal,
                    ledger_after_settlement=reconciled,
                    receipt=capability_receipt,
                )
                current_used.update(reconciled)
                await conn.execute(
                    "UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1",
                    hunt_id,
                    json.dumps(current_used),
                )
                action_result = {
                    "status": status,
                    "error": error,
                    "record_count": len(observations),
                    "parser_errors": parser_errors,
                    "budget_reservation_id": reservation_id,
                    "budget_reservation_state": terminal.status,
                    "receipt_id": str(receipt_id),
                }
                updated = await conn.execute(
                    """UPDATE hunt_actions
                       SET status=$2, result_summary=$3, receipt_id=$4,
                           completed_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$5 AND status='running'""",
                    action_id,
                    action_status,
                    json.dumps(action_result),
                    receipt_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "scanner action changed before settlement"
                    )
        result = {
            **process_result,
            "status": status,
            "error": error,
            "ok": status == "success",
            "partial": is_partial,
            "typed_output": typed_output,
            "budget_consumed": dict(terminal.actual),
            "used_after_reconciliation": dict(reconciled),
            "reservation_id": reservation_id,
            "budget_reservation_id": reservation_id,
            "budget_reservation_state": terminal.status,
            "receipt_id": str(receipt_id),
            "receipt": capability_receipt.public_dict(),
            "durable_budget_settled": True,
        }
    except asyncio.CancelledError:
        raise
    except (
        agent_tools.AgentToolError,
        ReservationConflict,
        ReservationStoreError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"contract:{str(exc)[:240]}",
            "durable_budget_settled": False,
        }
    except Exception as exc:  # noqa: BLE001 - stale running work is recovered fail closed
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"worker_fault:{type(exc).__name__}",
            "durable_budget_settled": False,
        }
    finally:
        if job_id and publish_result:
            redis_client.set(
                result_key,
                json.dumps(result, default=str, separators=(",", ":")),
                ex=_AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.hset(
                f"job:{job_id}",
                mapping={
                    "status": str(result.get("status") or "failed"),
                    "current_phase": "canonical_scanner_capability_complete",
                    "error": str(result.get("error") or ""),
                },
            )
            redis_client.expire(
                f"job:{job_id}",
                _AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.delete(cancel_key)


async def process_canonical_browser_capability_job(job_data: dict[str, Any]) -> None:
    """Execute one target-bound browser action under its durable Hunt hold."""
    job_id = str(job_data.get("job_id") or "").strip()
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    store = PostgresBudgetReservationStore()
    result: dict[str, Any] = {
        "job_id": job_id,
        "status": "failed",
        "error": "worker_fault",
        "durable_budget_settled": False,
    }
    publish_result = True
    persisted = None
    prepared = None
    try:
        if not job_id:
            raise BrowserCapabilityInputError(
                "browser capability job requires an identity"
            )
        hunt_id = uuid.UUID(str(job_data.get("hunt_id") or ""))
        action_id = uuid.UUID(str(job_data.get("action_id") or ""))
        reservation_id = str(uuid.UUID(
            str(job_data.get("budget_reservation_id") or "")
        ))
        queued_action_digest = str(
            job_data.get("action_digest") or ""
        ).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", queued_action_digest):
            raise BrowserCapabilityInputError(
                "browser capability action digest is invalid"
            )
        capability_name = str(
            job_data.get("capability_name") or ""
        ).strip().lower()
        if capability_name not in DURABLE_BROWSER_HUNT_CAPABILITIES:
            raise BrowserCapabilityInputError(
                "capability is not a durable browser action"
            )
        capability_input = dict(job_data.get("capability_input") or {})
        worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"

        async with db_pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id,
                )
                if not run:
                    raise BrowserCapabilityInputError(
                        "browser Hunt does not exist"
                    )
                action = await conn.fetchrow(
                    """SELECT id, capability_name, status FROM hunt_actions
                       WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                    action_id,
                    hunt_id,
                )
                if (
                    not action
                    or str(action["capability_name"]) != capability_name
                ):
                    raise BrowserCapabilityInputError(
                        "browser action identity is invalid"
                    )
                stored = await store.load(conn, reservation_id, for_update=True)
                if (
                    stored is None
                    or stored.action_id != str(action_id)
                    or stored.record.owner_kind != "hunt"
                    or stored.record.owner_id != str(hunt_id)
                    or stored.record.capability_name != capability_name
                ):
                    raise ReservationConflict(
                        "browser reservation identity does not match the queued action"
                    )
                if stored.action_digest != queued_action_digest:
                    raise ReservationConflict(
                        "browser reservation action digest does not match the queue"
                    )
                if stored.record.terminal:
                    result = _worker_terminal_network_result(
                        stored,
                        job_id=job_id,
                        network_binding="playwright_host_resolver_and_route_guard",
                    )
                    return
                if stored.record.status == "running":
                    publish_result = False
                    result = {
                        "job_id": job_id,
                        "status": "running",
                        "error": "idempotent_redelivery_running",
                        "budget_reservation_id": reservation_id,
                        "durable_budget_settled": False,
                        "idempotent_redelivery": True,
                    }
                    return
                if (
                    stored.record.status != "reserved"
                    or str(action["status"]) != "reserved"
                ):
                    raise ReservationConflict(
                        "browser action is not dispatchable"
                    )
                if str(run["status"]) not in {
                    "active", "awaiting_planner", "budget_exhausted",
                }:
                    raise BrowserCapabilityInputError(
                        "Hunt is no longer executable"
                    )

                context = _worker_json_object(run["context_pack"])
                hunt_policy = _worker_json_object(run["policy_json"])
                allowed = {
                    str(item)
                    for item in hunt_policy.get("allowed_capabilities") or []
                }
                if capability_name not in allowed:
                    raise BrowserCapabilityInputError(
                        "browser capability is outside the persisted Hunt allowlist"
                    )
                target_context = (
                    dict(context.get("target") or {})
                    if isinstance(context.get("target"), Mapping)
                    else {}
                )
                target_url = str(target_context.get("url") or "")
                parsed_target = urllib.parse.urlsplit(target_url)
                root_domain = str(
                    target_context.get("root_domain")
                    or parsed_target.hostname
                    or ""
                ).lower().rstrip(".")
                target = TargetBinding(
                    target_id=str(run["target_id"]),
                    target_kind=str(run["target_kind"]),
                    canonical_host=parsed_target.hostname,
                    allowed_origins=tuple(target_context.get("origins") or ()),
                    allowed_addresses=tuple(
                        str(item)
                        for item in context.get(
                            "authorized_target_addresses"
                        ) or ()
                        if str(item)
                    ),
                    allowed_root_domains=(root_domain,) if root_domain else (),
                    environment=str(
                        target_context.get("environment") or "unknown"
                    ),
                    scope_receipt_id=str(
                        hunt_policy.get("scope_receipt_id") or ""
                    ) or None,
                )
                policy = ScanPolicy(
                    active_testing=bool(hunt_policy.get("active_testing")),
                    allow_state_changing_http=False,
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=hunt_policy.get(
                        "approval_receipt_id"
                    ),
                )
                browser_adapter = browser_capability_adapter(capability_name)
                prepared = browser_adapter.prepare(
                    target=target,
                    base_url=target_url,
                    args=capability_input,
                )
                expected_input_digest = str(
                    job_data.get("expected_input_digest") or ""
                ).lower()
                if prepared.input_digest != expected_input_digest:
                    raise BrowserCapabilityInputError(
                        "control-plane and worker browser input digests differ"
                    )
                expected_budget = {
                    str(key): int(value)
                    for key, value in dict(
                        job_data.get("expected_budget") or {}
                    ).items()
                }
                if dict(prepared.estimated_budget) != expected_budget:
                    raise BrowserCapabilityInputError(
                        "control-plane and worker browser budget estimates differ"
                    )
                limits = _worker_hunt_ledger_limits(
                    _worker_json_object(run["budget_json"])
                )
                requested_budget = {
                    key: int(value)
                    for key, value in prepared.estimated_budget.items()
                    if key in limits
                }
                requested_budget["agent_actions"] = 1
                spec = agent_tools.CAPABILITY_REGISTRY.require(capability_name)
                if spec.requires_active_approval:
                    requested_budget["active_actions"] = 1
                recomputed_digest = hunt_capability_action_digest(
                    hunt_id=hunt_id,
                    action_id=action_id,
                    capability_name=capability_name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["target_id"],
                    capability_input=capability_input,
                    requested_budget=requested_budget,
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                )
                if (
                    recomputed_digest != queued_action_digest
                    or stored.action_digest != queued_action_digest
                    or dict(stored.record.requested) != requested_budget
                ):
                    raise ReservationConflict(
                        "browser queue payload does not match its durable action"
                    )
                lease_seconds = hunt_capability_lease_seconds(
                    requested_budget
                )
                running = stored.record.start(
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )
                persisted = await store.persist_transition(
                    conn,
                    previous=stored,
                    current=running,
                )
                updated = await conn.execute(
                    """UPDATE hunt_actions SET status='running', started_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$2 AND status='reserved'""",
                    action_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "browser action changed before worker dispatch"
                    )

        async def heartbeat_reservation() -> None:
            nonlocal persisted
            if persisted is None:
                raise ReservationStoreError(
                    "browser reservation persistence was not initialized"
                )
            async with db_pool.acquire() as heartbeat_conn:
                async with heartbeat_conn.transaction():
                    owner = await heartbeat_conn.fetchrow(
                        "SELECT status FROM hunt_runs WHERE id=$1 FOR UPDATE",
                        hunt_id,
                    )
                    if not owner or str(owner["status"]) not in {
                        "active", "awaiting_planner", "budget_exhausted",
                    }:
                        raise ReservationStoreError(
                            "Hunt stopped during browser execution"
                        )
                    latest = await store.load(
                        heartbeat_conn,
                        reservation_id,
                        for_update=True,
                    )
                    if (
                        latest is None
                        or latest.record.state_digest
                        != persisted.record.state_digest
                        or latest.record.worker_id != worker_id
                    ):
                        raise ReservationConflict(
                            "browser reservation changed before heartbeat"
                        )
                    heartbeat = latest.record.heartbeat(
                        worker_id=worker_id,
                        lease_seconds=lease_seconds,
                    )
                    persisted = await store.persist_transition(
                        heartbeat_conn,
                        previous=latest,
                        current=heartbeat,
                    )

        executor = CapabilityExecutor()
        execution = await executor.execute(
            CapabilityExecutionContext(
                specification=spec,
                target=target,
                requested_budget=persisted.record.requested,
            ),
            browser_adapter(prepared),
            heartbeat=heartbeat_reservation,
            cancelled=lambda: bool(redis_client.exists(cancel_key)),
        )
        started_at = persisted.record.started_at or datetime.now(timezone.utc)
        finished_at = datetime.now(timezone.utc)
        action_status = (
            "completed" if execution.status == "success"
            else "partial" if execution.status == "partial"
            else "blocked" if execution.status == "blocked"
            else "cancelled" if execution.status == "cancelled"
            else "failed"
        )
        receipt_id = uuid.uuid4()
        observations = [
            dict(item) for item in execution.observations
        ][:5000]
        parser_errors = [str(item) for item in execution.errors][:20]
        receipt_input = dict(execution.redacted_execution)
        receipt_result = {
            "ok": execution.status == "success",
            "error": parser_errors[0] if parser_errors else None,
            "timed_out": execution.timed_out,
            "receipt_observations": observations,
        }
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id,
                )
                if not locked:
                    raise ReservationStoreError(
                        "browser Hunt disappeared during settlement"
                    )
                latest = await store.load(
                    conn, reservation_id, for_update=True,
                )
                if (
                    latest is None
                    or persisted is None
                    or latest.record.state_digest
                    != persisted.record.state_digest
                    or latest.record.status != "running"
                    or latest.record.worker_id != worker_id
                ):
                    raise ReservationConflict(
                        "browser reservation changed before settlement"
                    )
                current_used = _worker_json_object(
                    locked["budget_used_json"]
                )
                current_ledger = {
                    key: int(current_used.get(key) or 0)
                    for key in _worker_hunt_ledger_limits(
                        _worker_json_object(locked["budget_json"])
                    )
                }
                terminal, capability_receipt = terminalize_hunt_capability(
                    latest.record,
                    action_digest=queued_action_digest,
                    capability_name=prepared.capability_name,
                    adapter_name=prepared.adapter_name,
                    adapter_version=prepared.adapter_version,
                    parser_version=execution.parser_version,
                    target_id=target.target_id,
                    target_kind=target.target_kind,
                    capability_input=receipt_input,
                    action_status=action_status,
                    actual_budget=execution.actual_budget,
                    worker_id=worker_id,
                    started_at=started_at.isoformat(),
                    finished_at=finished_at.isoformat(),
                    receipt_id=str(receipt_id),
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                    result=receipt_result,
                )
                reconciled = terminal.reconcile_consumed(current_ledger)
                await _record_hunt_network_tool_receipt(
                    conn,
                    receipt_id=receipt_id,
                    hunt_id=hunt_id,
                    action_id=action_id,
                    reservation_id=reservation_id,
                    action_digest=queued_action_digest,
                    target=target,
                    policy=policy,
                    prepared=prepared,
                    status=execution.status,
                    partial=execution.partial,
                    timed_out=execution.timed_out,
                    parser_errors=parser_errors,
                    record_count=len(observations),
                    reserved=latest.record.requested,
                    actual=execution.actual_budget,
                    used_after=reconciled,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                persisted = await store.persist_terminal(
                    conn,
                    previous=latest,
                    terminal=terminal,
                    ledger_after_settlement=reconciled,
                    receipt=capability_receipt,
                )
                current_used.update(reconciled)
                await conn.execute(
                    "UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() "
                    "WHERE id=$1",
                    hunt_id,
                    json.dumps(current_used),
                )
                action_result = {
                    "status": execution.status,
                    "error": parser_errors[0] if parser_errors else None,
                    "record_count": len(observations),
                    "parser_errors": parser_errors,
                    "budget_reservation_id": reservation_id,
                    "budget_reservation_state": terminal.status,
                    "receipt_id": str(receipt_id),
                }
                updated = await conn.execute(
                    """UPDATE hunt_actions
                       SET status=$2, result_summary=$3, receipt_id=$4,
                           completed_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$5 AND status='running'""",
                    action_id,
                    action_status,
                    json.dumps(action_result),
                    receipt_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "browser action changed before settlement"
                    )
        result = {
            "job_id": job_id,
            "status": execution.status,
            "ok": execution.status == "success",
            "error": parser_errors[0] if parser_errors else None,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "partial": execution.partial,
            "timed_out": execution.timed_out,
            "typed_output": {
                "parser": execution.parser_version,
                "parser_status": (
                    "partial" if execution.partial
                    else "parsed" if execution.status == "success"
                    else "failed"
                ),
                "records": observations,
                "record_count": len(observations),
                "errors": parser_errors,
            },
            "budget_consumed": dict(terminal.actual),
            "used_after_reconciliation": dict(reconciled),
            "execution": dict(execution.redacted_execution),
            "input_digest": prepared.input_digest,
            "reservation_id": reservation_id,
            "budget_reservation_id": reservation_id,
            "budget_reservation_state": terminal.status,
            "receipt_id": str(receipt_id),
            "receipt": capability_receipt.public_dict(),
            "durable_budget_settled": True,
            "network_binding": "playwright_host_resolver_and_route_guard",
        }
    except asyncio.CancelledError:
        raise
    except (
        BrowserCapabilityInputError,
        ReservationConflict,
        ReservationStoreError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"contract:{str(exc)[:240]}",
            "durable_budget_settled": False,
        }
    except Exception as exc:  # noqa: BLE001 - stale running work recovers fail closed
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"worker_fault:{type(exc).__name__}",
            "durable_budget_settled": False,
        }
    finally:
        if job_id and publish_result:
            redis_client.set(
                result_key,
                json.dumps(result, default=str, separators=(",", ":")),
                ex=_AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.hset(
                f"job:{job_id}",
                mapping={
                    "status": str(result.get("status") or "failed"),
                    "current_phase": "canonical_browser_capability_complete",
                    "error": str(result.get("error") or ""),
                },
            )
            redis_client.expire(
                f"job:{job_id}", _AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.delete(cancel_key)


async def process_canonical_network_capability_job(job_data: dict[str, Any]) -> None:
    """Execute one canonical network action under its durable Hunt reservation."""
    job_id = str(job_data.get("job_id") or "").strip()
    result_key = f"agent_tool_result:{job_id}"
    cancel_key = f"agent_tool_cancel:{job_id}"
    redis_client = get_redis()
    store = PostgresBudgetReservationStore()
    result: dict[str, Any] = {
        "job_id": job_id,
        "status": "failed",
        "error": "worker_fault",
        "durable_budget_settled": False,
    }
    publish_result = True
    persisted = None
    prepared = None
    try:
        if not job_id:
            raise CapabilityInputError("capability job requires an identity")
        hunt_id = uuid.UUID(str(job_data.get("hunt_id") or ""))
        action_id = uuid.UUID(str(job_data.get("action_id") or ""))
        reservation_id = str(uuid.UUID(str(job_data.get("budget_reservation_id") or "")))
        queued_action_digest = str(job_data.get("action_digest") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", queued_action_digest):
            raise CapabilityInputError("capability action digest is invalid")
        capability_name = str(job_data.get("capability_name") or "").strip().lower()
        if capability_name not in DURABLE_WORKER_HUNT_CAPABILITIES:
            raise CapabilityInputError("capability is not a durable network action")
        capability_input = dict(job_data.get("capability_input") or {})
        worker_id = _worker_runtime_identity() or f"worker:{job_id[:8]}"

        async with db_pool.acquire() as conn:
            async with conn.transaction():
                run = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id,
                )
                if not run:
                    raise CapabilityInputError("network Hunt does not exist")
                action = await conn.fetchrow(
                    """SELECT id, capability_name, status FROM hunt_actions
                       WHERE id=$1 AND hunt_run_id=$2 FOR UPDATE""",
                    action_id,
                    hunt_id,
                )
                if not action or str(action["capability_name"]) != capability_name:
                    raise CapabilityInputError("network action identity is invalid")
                stored = await store.load(conn, reservation_id, for_update=True)
                if (
                    stored is None
                    or stored.action_id != str(action_id)
                    or stored.record.owner_kind != "hunt"
                    or stored.record.owner_id != str(hunt_id)
                    or stored.record.capability_name != capability_name
                ):
                    raise ReservationConflict(
                        "network reservation identity does not match the queued action"
                    )
                if stored.action_digest != queued_action_digest:
                    raise ReservationConflict(
                        "network reservation action digest does not match the queue"
                    )
                if stored.record.terminal:
                    result = _worker_terminal_network_result(stored, job_id=job_id)
                    return
                if stored.record.status == "running":
                    publish_result = False
                    result = {
                        "job_id": job_id,
                        "status": "running",
                        "error": "idempotent_redelivery_running",
                        "budget_reservation_id": reservation_id,
                        "durable_budget_settled": False,
                        "idempotent_redelivery": True,
                    }
                    return
                if stored.record.status != "reserved" or str(action["status"]) != "reserved":
                    raise ReservationConflict("network action is not dispatchable")
                if str(run["status"]) not in {
                    "active", "awaiting_planner", "budget_exhausted"
                }:
                    raise CapabilityInputError("Hunt is no longer executable")

                context = _worker_json_object(run["context_pack"])
                hunt_policy = _worker_json_object(run["policy_json"])
                allowed = {
                    str(item) for item in hunt_policy.get("allowed_capabilities") or []
                }
                if capability_name not in allowed:
                    raise CapabilityInputError(
                        "network capability is outside the persisted Hunt allowlist"
                    )
                target_context = (
                    dict(context.get("target") or {})
                    if isinstance(context.get("target"), Mapping) else {}
                )
                target_url = str(target_context.get("url") or "")
                parsed_target = urllib.parse.urlsplit(target_url)
                root_domain = str(
                    target_context.get("root_domain") or parsed_target.hostname or ""
                ).lower().rstrip(".")
                target = TargetBinding(
                    target_id=str(run["target_id"]),
                    target_kind=str(run["target_kind"]),
                    canonical_host=parsed_target.hostname,
                    allowed_origins=tuple(target_context.get("origins") or ()),
                    allowed_addresses=tuple(
                        str(item) for item in context.get("authorized_target_addresses") or ()
                        if str(item)
                    ),
                    allowed_root_domains=(root_domain,) if root_domain else (),
                    environment=str(target_context.get("environment") or "unknown"),
                    scope_receipt_id=str(hunt_policy.get("scope_receipt_id") or "") or None,
                )
                policy = ScanPolicy(
                    active_testing=bool(hunt_policy.get("active_testing")),
                    network_discovery=bool(hunt_policy.get("network_discovery")),
                    subdomain_discovery=capability_name == "subdomains.discover",
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=hunt_policy.get("approval_receipt_id"),
                )
                adapter = network_capability_adapter(capability_name)
                prepared = adapter.prepare(
                    target=target,
                    args=capability_input,
                    policy=policy,
                )
                expected_input_digest = str(
                    job_data.get("expected_input_digest") or ""
                ).lower()
                if prepared.input_digest != expected_input_digest:
                    raise CapabilityInputError(
                        "control-plane and worker capability input digests differ"
                    )
                expected_budget = {
                    str(key): int(value)
                    for key, value in dict(job_data.get("expected_budget") or {}).items()
                }
                if dict(prepared.estimated_budget) != expected_budget:
                    raise CapabilityInputError(
                        "control-plane and worker budget estimates differ"
                    )
                limits = _worker_hunt_ledger_limits(
                    _worker_json_object(run["budget_json"])
                )
                requested_budget = {
                    key: int(value)
                    for key, value in prepared.estimated_budget.items()
                    if key in limits
                }
                requested_budget["agent_actions"] = 1
                if agent_tools.CAPABILITY_REGISTRY.require(
                    capability_name
                ).requires_active_approval:
                    requested_budget["active_actions"] = 1
                recomputed_digest = hunt_capability_action_digest(
                    hunt_id=hunt_id,
                    action_id=action_id,
                    capability_name=capability_name,
                    target_kind=str(run["target_kind"]),
                    target_id=run["target_id"],
                    capability_input=capability_input,
                    requested_budget=requested_budget,
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                )
                if (
                    recomputed_digest != queued_action_digest
                    or stored.action_digest != queued_action_digest
                    or dict(stored.record.requested) != requested_budget
                ):
                    raise ReservationConflict(
                        "network queue payload does not match its durable action"
                    )
                lease_seconds = hunt_capability_lease_seconds(requested_budget)
                running = stored.record.start(
                    worker_id=worker_id,
                    lease_seconds=lease_seconds,
                )
                persisted = await store.persist_transition(
                    conn,
                    previous=stored,
                    current=running,
                )
                updated = await conn.execute(
                    """UPDATE hunt_actions SET status='running', started_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$2 AND status='reserved'""",
                    action_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "network action changed before worker dispatch"
                    )

        async def heartbeat_reservation() -> None:
            nonlocal persisted
            if persisted is None:
                raise ReservationStoreError(
                    "network reservation persistence was not initialized"
                )
            async with db_pool.acquire() as heartbeat_conn:
                async with heartbeat_conn.transaction():
                    owner = await heartbeat_conn.fetchrow(
                        "SELECT status FROM hunt_runs WHERE id=$1 FOR UPDATE",
                        hunt_id,
                    )
                    if not owner or str(owner["status"]) not in {
                        "active", "awaiting_planner", "budget_exhausted"
                    }:
                        raise ReservationStoreError(
                            "Hunt stopped during network execution"
                        )
                    latest = await store.load(
                        heartbeat_conn,
                        reservation_id,
                        for_update=True,
                    )
                    if (
                        latest is None
                        or latest.record.state_digest != persisted.record.state_digest
                        or latest.record.worker_id != worker_id
                    ):
                        raise ReservationConflict(
                            "network reservation changed before heartbeat"
                        )
                    heartbeat = latest.record.heartbeat(
                        worker_id=worker_id,
                        lease_seconds=lease_seconds,
                    )
                    persisted = await store.persist_transition(
                        heartbeat_conn,
                        previous=latest,
                        current=heartbeat,
                    )

        started_at = persisted.record.started_at or datetime.now(timezone.utc)
        execution = await CapabilityExecutor().execute(
            CapabilityExecutionContext(
                specification=agent_tools.CAPABILITY_REGISTRY.require(
                    capability_name
                ),
                target=target,
                requested_budget=persisted.record.requested,
            ),
            NetworkExecutionAdapter(
                prepared=prepared,
                parser=adapter,
                command_runner=run_streaming,
                max_stdout_bytes=_AGENT_TOOL_OUTPUT_BYTES,
                max_stderr_bytes=min(_AGENT_TOOL_OUTPUT_BYTES, 20_000),
            ),
            heartbeat=heartbeat_reservation,
            cancelled=lambda: bool(redis_client.exists(cancel_key)),
        )
        status = execution.status
        observations = [dict(item) for item in execution.observations]
        parser_errors = [str(item) for item in execution.errors]
        partial = execution.partial
        timed_out = execution.timed_out
        actual = dict(execution.actual_budget)
        error = (
            parser_errors[0]
            if parser_errors and status in {"failed", "cancelled"}
            else None
        )
        finished_at = datetime.now(timezone.utc)
        action_status = (
            "completed" if status == "success"
            else "partial" if status == "partial"
            else "cancelled" if status == "cancelled"
            else "failed"
        )
        receipt_id = uuid.uuid4()
        receipt_result = {
            "ok": status == "success",
            "error": error,
            "timed_out": timed_out,
            "receipt_observations": observations[:5000],
        }
        async with db_pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", hunt_id,
                )
                if not locked:
                    raise ReservationStoreError(
                        "network Hunt disappeared during settlement"
                    )
                latest = await store.load(conn, reservation_id, for_update=True)
                if (
                    latest is None
                    or persisted is None
                    or latest.record.state_digest != persisted.record.state_digest
                    or latest.record.status != "running"
                    or latest.record.worker_id != worker_id
                ):
                    raise ReservationConflict(
                        "network reservation changed before settlement"
                    )
                current_used = _worker_json_object(locked["budget_used_json"])
                current_ledger = {
                    key: int(current_used.get(key) or 0)
                    for key in _worker_hunt_ledger_limits(
                        _worker_json_object(locked["budget_json"])
                    )
                }
                terminal, capability_receipt = terminalize_hunt_capability(
                    latest.record,
                    action_digest=queued_action_digest,
                    capability_name=prepared.capability_name,
                    adapter_name=prepared.adapter_name,
                    adapter_version=prepared.adapter_version,
                    parser_version=execution.parser_version,
                    target_id=target.target_id,
                    target_kind=target.target_kind,
                    capability_input=execution.redacted_execution,
                    action_status=action_status,
                    actual_budget=actual,
                    worker_id=worker_id,
                    started_at=started_at.isoformat(),
                    finished_at=finished_at.isoformat(),
                    receipt_id=str(receipt_id),
                    scope_receipt_id=target.scope_receipt_id,
                    approval_receipt_id=policy.approval_receipt_id,
                    result=receipt_result,
                )
                reconciled = terminal.reconcile_consumed(current_ledger)
                await _record_hunt_network_tool_receipt(
                    conn,
                    receipt_id=receipt_id,
                    hunt_id=hunt_id,
                    action_id=action_id,
                    reservation_id=reservation_id,
                    action_digest=queued_action_digest,
                    target=target,
                    policy=policy,
                    prepared=prepared,
                    status=status,
                    partial=action_status == "partial",
                    timed_out=timed_out,
                    parser_errors=parser_errors,
                    record_count=len(observations),
                    reserved=latest.record.requested,
                    actual=actual,
                    used_after=reconciled,
                    started_at=started_at,
                    finished_at=finished_at,
                )
                persisted = await store.persist_terminal(
                    conn,
                    previous=latest,
                    terminal=terminal,
                    ledger_after_settlement=reconciled,
                    receipt=capability_receipt,
                )
                current_used.update(reconciled)
                await conn.execute(
                    "UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1",
                    hunt_id,
                    json.dumps(current_used),
                )
                action_result = {
                    "status": status,
                    "error": error,
                    "record_count": len(observations),
                    "parser_errors": parser_errors[:20],
                    "budget_reservation_id": reservation_id,
                    "budget_reservation_state": terminal.status,
                    "receipt_id": str(receipt_id),
                }
                updated = await conn.execute(
                    """UPDATE hunt_actions
                       SET status=$2, result_summary=$3, receipt_id=$4,
                           completed_at=NOW()
                       WHERE id=$1 AND hunt_run_id=$5 AND status='running'""",
                    action_id,
                    action_status,
                    json.dumps(action_result),
                    receipt_id,
                    hunt_id,
                )
                if not str(updated).endswith(" 1"):
                    raise ReservationConflict(
                        "network action changed before settlement"
                    )
        public_receipt = capability_receipt.public_dict()
        result = {
            "job_id": job_id,
            "status": status,
            "ok": status == "success",
            "error": error,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "partial": action_status == "partial",
            "timed_out": timed_out,
            "typed_output": {
                "parser": execution.parser_version,
                "parser_status": (
                    "partial" if action_status == "partial"
                    else "parsed" if status == "success" else "failed"
                ),
                "records": observations[:5000],
                "record_count": len(observations),
                "errors": parser_errors[:20],
            },
            "budget_consumed": dict(terminal.actual),
            "used_after_reconciliation": dict(reconciled),
            "execution": dict(execution.redacted_execution),
            "input_digest": prepared.input_digest,
            "reservation_id": reservation_id,
            "budget_reservation_id": reservation_id,
            "budget_reservation_state": terminal.status,
            "receipt_id": str(receipt_id),
            "receipt": public_receipt,
            "durable_budget_settled": True,
            "network_binding": "runtime_target_binding",
        }
    except asyncio.CancelledError:
        raise
    except (
        CapabilityInputError,
        ReservationConflict,
        ReservationStoreError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"contract:{str(exc)[:240]}",
            "durable_budget_settled": False,
        }
    except Exception as exc:  # noqa: BLE001 - leave running work to the fail-closed sweeper
        result = {
            "job_id": job_id,
            "status": "failed",
            "error": f"worker_fault:{type(exc).__name__}",
            "durable_budget_settled": False,
        }
    finally:
        if job_id and publish_result:
            redis_client.set(
                result_key,
                json.dumps(result, default=str, separators=(",", ":")),
                ex=_AGENT_TOOL_RESULT_TTL_SECONDS,
            )
            redis_client.hset(
                f"job:{job_id}",
                mapping={
                    "status": str(result.get("status") or "failed"),
                    "current_phase": "canonical_capability_complete",
                    "error": str(result.get("error") or ""),
                },
            )
            redis_client.expire(f"job:{job_id}", _AGENT_TOOL_RESULT_TTL_SECONDS)
            redis_client.delete(cancel_key)


async def process_job(job_data: dict):
    """Route job to appropriate handler."""
    if job_data.get("schema_version") == SCAN_JOB_SCHEMA:
        canonical_payload = dict(job_data)
        try:
            job_data = await _materialize_scan_job_v2(canonical_payload)
        except CanonicalScanJobMaterializationError as exc:
            await _fail_execution_scope(canonical_payload, str(exc))
            print(f"[scan-job/v2] refused queued work: {exc}", flush=True)
            return
    if str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip():
        try:
            if not await _revalidate_job_execution_scope(job_data):
                print("[scope] terminal or parent-cancelled queued work skipped", flush=True)
                return
        except ExecutionScopeError as exc:
            await _fail_execution_scope(job_data, str(exc))
            print(f"[scope] refused queued work: {exc}", flush=True)
            return
    if not await _fleet_node_accepts_work():
        source_queue = str(
            job_data.get("_base_queue_name")
            or (RETEST_QUEUE_NAME if job_data.get('type') == 'finding_retest' else QUEUE_NAME)
        )
        enqueue_job(get_redis(), source_queue, _safe_requeue_payload(job_data))
        print("[fleet] node is draining or unavailable; requeued leased work", flush=True)
        await asyncio.sleep(1)
        return
    placement = placement_from_payload(job_data)
    if placement and not worker_matches_placement(_worker_placement_labels(), placement):
        source_queue = str(
            job_data.get("_base_queue_name")
            or (RETEST_QUEUE_NAME if job_data.get('type') == 'finding_retest' else QUEUE_NAME)
        )
        enqueue_job(get_redis(), source_queue, _safe_requeue_payload(job_data))
        print(
            f"[fleet] placement changed after lease; requeued for {placement}",
            flush=True,
        )
        await asyncio.sleep(1)
        return
    # Fail-closed: refuse to run a scan on a build-stale worker (see helper).
    if await _refuse_stale_job_if_needed(job_data):
        return
    try:
        if not job_data.get("_broker_result_id"):
            await _attribute_job_execution(job_data)
    except RuntimeError as exc:
        # A node can be revoked between lease and dispatch. Preserve the user's
        # work while the control-plane reconciler removes that peer.
        source_queue = str(
            job_data.get("_base_queue_name")
            or (RETEST_QUEUE_NAME if job_data.get('type') == 'finding_retest' else QUEUE_NAME)
        )
        enqueue_job(get_redis(), source_queue, _safe_requeue_payload(job_data))
        print(f"[fleet] refused job on this node and requeued it: {exc}", flush=True)
        await asyncio.sleep(2)
        return
    job_type = job_data.get('type', 'scan')

    if job_type == 'discovery':
        await process_discovery_job(job_data)
    elif job_type == 'agent_scanner_tool':
        await process_agent_scanner_tool_job(job_data)
    elif job_type == 'canonical_scanner_capability':
        await process_canonical_scanner_capability_job(job_data)
    elif job_type == 'request_collection_replay':
        await process_request_collection_replay_job(job_data)
    elif job_type == 'canonical_browser_capability':
        await process_canonical_browser_capability_job(job_data)
    elif job_type == 'canonical_network_capability':
        await process_canonical_network_capability_job(job_data)
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
    await _finish_broker_result_ingest(job_data)


def _mark_worker_processing_lease(
    r,
    job_data: dict[str, Any],
    source_queue: str,
    lease: QueueLease | None = None,
) -> None:
    """Stamp a short-lived proof that this worker leased the job from Redis.

    The Stream message remains pending before the durable DB row is claimed.
    The API orphan reconciler accepts this lease timestamp only for a brief grace
    window, so a worker crash cannot leave a stale ``status=queued`` hash looking
    like durable work for the hash's full one-day TTL.
    """
    job_id = str(job_data.get("job_id") or "").strip()
    if not job_id:
        return
    is_retest = source_queue == RETEST_QUEUE_NAME or job_data.get("type") == "finding_retest"
    key = f"retest_job:{job_id}" if is_retest else f"job:{job_id}"
    mapping = {
        "processing_lease_at": utc_now_iso(),
        "processing_queue": source_queue,
    }
    if lease is not None:
        mapping.update({
            "queue_message_id": lease.message_id or "legacy-list",
            "queue_delivery_attempts": str(lease.delivery_attempts),
            "queue_reclaimed": "true" if lease.reclaimed else "false",
            "queue_consumer": _worker_runtime_identity(),
        })
    r.hset(key, mapping=mapping)
    r.expire(key, 86400)


async def _fail_exhausted_queue_delivery(job_data: dict[str, Any], attempts: int) -> None:
    job_id = str(job_data.get("job_id") or "unknown")
    message = f"Queue delivery exhausted after {attempts} attempts"
    scan_id = str(job_data.get("scan_id") or "").strip()
    verification_id = str(job_data.get("verification_id") or "").strip()
    async with db_pool.acquire() as conn:
        if scan_id:
            try:
                await conn.execute(
                    """
                    UPDATE scans
                    SET status='failed', progress=100, current_phase='queue_delivery_failed',
                        error_message=$2, completed_at=NOW()
                    WHERE id=$1 AND status NOT IN ('completed','failed','cancelled')
                    """,
                    uuid.UUID(scan_id),
                    message,
                )
            except ValueError:
                pass
        if verification_id:
            try:
                await conn.execute(
                    """
                    UPDATE finding_verifications
                    SET status='failed', result_status='error', verdict='error',
                        error_message=$2, completed_at=NOW(), retryable=false,
                        attempts_exhausted=true
                    WHERE id=$1 AND status IN ('queued','running')
                    """,
                    uuid.UUID(verification_id),
                    message,
                )
            except ValueError:
                pass
    key = f"retest_job:{job_id}" if job_data.get("type") == "finding_retest" else f"job:{job_id}"
    redis_client = get_redis()
    redis_client.hset(key, mapping={
        "status": "failed",
        "current_phase": "queue_delivery_failed",
        "error": message,
        "delivery_attempts": str(attempts),
    })
    redis_client.expire(key, 86400)
    _release_parallel_shard_slot(
        redis_client,
        str(job_data.get("parent_scan_id") or "") or None,
        job_id,
    )


async def _guard_queue_lease(
    redis_client: Any,
    lease: QueueLease,
    consumer_name: str,
    work_task: asyncio.Task,
) -> None:
    """Keep Stream ownership alive and stop execution if fencing authority is lost."""
    if lease.legacy:
        return
    loop = asyncio.get_running_loop()
    failures = 0
    while not work_task.done():
        await asyncio.sleep(QUEUE_LEASE_HEARTBEAT_SECONDS)
        if work_task.done():
            return
        try:
            owned = await loop.run_in_executor(
                None,
                lambda: heartbeat_lease(redis_client, lease, consumer_name),
            )
            if not owned:
                print(
                    f"[queue] lease {lease.message_id} is no longer owned; cancelling stale execution",
                    flush=True,
                )
                work_task.cancel()
                return
            failures = 0
        except Exception as exc:
            failures += 1
            print(
                f"[queue] lease heartbeat failed ({failures}/{QUEUE_LEASE_HEARTBEAT_FAILURE_LIMIT}): {exc}",
                flush=True,
            )
            if failures >= QUEUE_LEASE_HEARTBEAT_FAILURE_LIMIT:
                print("[queue] fencing authority unavailable; cancelling execution fail-closed", flush=True)
                work_task.cancel()
                return


async def _run_job_under_lease(redis_client: Any, lease: QueueLease, job_data: dict[str, Any]) -> None:
    consumer_name = _worker_runtime_identity()
    if lease.delivery_attempts > QUEUE_MAX_DELIVERY_ATTEMPTS:
        await _fail_exhausted_queue_delivery(job_data, lease.delivery_attempts)
        if not lease.legacy:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: acknowledge_lease(redis_client, lease))
        return

    marker: Path | None = None
    try:
        marker = _fleet_busy_marker(job_data)
        if lease.legacy:
            await process_job(job_data)
            return

        work_task = asyncio.create_task(process_job(job_data))
        guard_task = asyncio.create_task(_guard_queue_lease(redis_client, lease, consumer_name, work_task))
        try:
            await work_task
            loop = asyncio.get_running_loop()
            acknowledged = await loop.run_in_executor(
                None,
                lambda: acknowledge_lease(redis_client, lease),
            )
            if not acknowledged:
                raise RuntimeError(f"completed queue message {lease.message_id} was not acknowledged")
        finally:
            guard_task.cancel()
            await asyncio.gather(guard_task, return_exceptions=True)
    finally:
        _clear_fleet_busy_marker(marker)


async def sweep_stale_budget_reservations() -> dict[str, int]:
    """Recover expired durable holds without allowing uncertain traffic refunds."""
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            events = await recover_stale_reservations(
                conn,
                now=datetime.now(timezone.utc),
                limit=BUDGET_RESERVATION_SWEEP_BATCH_SIZE,
            )
    summary = {
        "recovered": len(events),
        "released": sum(event.terminal_status == "released" for event in events),
        "failed_uncertain": sum(event.execution_uncertain for event in events),
    }
    if events:
        print(
            "[watchdog] stale budget reservations recovered: "
            f"released={summary['released']}, "
            f"failed_uncertain={summary['failed_uncertain']}",
            flush=True,
        )
    return summary


async def async_main():
    """Async main worker loop - uses single event loop for database pool."""
    print("Initializing worker...", flush=True)

    # Initialize database pool (bound to this event loop)
    await init_db()

    r = get_redis()
    device_queue_enabled = str(os.environ.get("DEVICE_SCAN_WORKER_ENABLED", "false")).strip().lower() in {"1", "true", "yes", "on"}
    base_queue_keys = base_worker_queue_keys(
        device_only=DEVICE_ONLY_WORKER,
        agent_tool_only=AGENT_TOOL_ONLY_WORKER,
        device_queue_enabled=device_queue_enabled,
        scan_queue=QUEUE_NAME,
        retest_queue=RETEST_QUEUE_NAME,
        broker_queue=BROKER_INGEST_QUEUE_NAME,
        device_queue=DEVICE_QUEUE_NAME,
        agent_tool_queue=AGENT_TOOL_QUEUE_NAME,
    )
    queue_keys = list(base_queue_keys)
    print(
        f"Worker started, listening on queues: {', '.join(queue_keys)} "
        f"(retest max parallel: {RETEST_MAX_PARALLEL})",
        flush=True,
    )

    loop = asyncio.get_event_loop()
    last_stale_check_monotonic = 0.0
    last_reservation_sweep_monotonic = 0.0

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

                if (
                    BUDGET_RESERVATION_SWEEP_INTERVAL_SECONDS > 0
                    and now_mono - last_reservation_sweep_monotonic
                    >= BUDGET_RESERVATION_SWEEP_INTERVAL_SECONDS
                ):
                    try:
                        await sweep_stale_budget_reservations()
                    except Exception as reservation_err:
                        print(
                            f"[watchdog] stale budget reservation sweep error: {reservation_err}",
                            flush=True,
                        )
                    finally:
                        last_reservation_sweep_monotonic = now_mono

                if not await _fleet_node_accepts_work():
                    await asyncio.sleep(min(5, WORKER_QUEUE_BLOCK_SECONDS))
                    continue

                # Lease a Stream message. Legacy list entries are drained only
                # as an upgrade bridge; all new work is explicitly acked.
                queue_keys = [
                    *base_queue_keys,
                    *qualified_route_queues(
                        r,
                        base_queue_keys,
                        worker_labels=_worker_placement_labels(),
                    ),
                ]
                consumer_name = _worker_runtime_identity()
                lease = await loop.run_in_executor(
                    None,
                    lambda: lease_job(
                        r,
                        queue_keys,
                        consumer_name=consumer_name,
                        block_ms=WORKER_QUEUE_BLOCK_SECONDS * 1000,
                        visibility_timeout_ms=QUEUE_VISIBILITY_TIMEOUT_SECONDS * 1000,
                    ),
                )
                if lease is None:
                    # Re-report build identity while idle so the per-worker version
                    # label converges to the API-published commit after a deploy (the
                    # startup report can run before the API publishes). build_current
                    # already uses the source fingerprint; this just freshens the label.
                    try:
                        report_worker_build_fingerprint()
                    except Exception:
                        pass
                    continue  # Timeout, continue polling

                source_queue = lease.queue_name
                try:
                    job_data = json.loads(lease.payload)
                    if not isinstance(job_data, dict):
                        raise ValueError("queue payload is not an object")
                except (TypeError, ValueError, json.JSONDecodeError) as payload_error:
                    print(f"[queue] discarding malformed message {lease.message_id}: {payload_error}", flush=True)
                    if not lease.legacy:
                        await loop.run_in_executor(None, lambda: acknowledge_lease(r, lease))
                    continue
                try:
                    _mark_worker_processing_lease(r, job_data, source_queue, lease)
                except Exception as lease_err:
                    # This marker is recovery metadata, never authority to run.
                    # The durable DB claim in each handler remains authoritative.
                    print(f"[worker] processing lease metadata error: {lease_err}", flush=True)
                await _run_job_under_lease(r, lease, job_data)
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
        # A clean container replacement should disappear from lightweight fleet identity
        # immediately. Crash/kill remnants still age out server-side, while graceful rebuilds do
        # not leave a transient false mismatch in the sidebar.
        try:
            r.hdel(WORKER_BUILD_REGISTRY_KEY, _worker_build_hostname())
        except Exception:
            pass
        # Close database pool
        if db_pool:
            await db_pool.close()
        print("Worker shutdown complete", flush=True)


@functools.lru_cache(maxsize=1)
def _worker_build_fingerprint() -> str | None:
    """Source-tree checksum of this worker's runtime (keyed by basename so it
    matches the API's host-checkout fingerprint when the code is current)."""
    return release_build_fingerprint(hash_source_files(runtime_file_map(), require_all=True))


def _worker_runtime_identity() -> str:
    import socket as _socket
    configured = str(os.environ.get("WORKER_ID") or "").strip()
    hostname = str(os.environ.get("HOSTNAME") or _socket.gethostname() or "").strip()
    if configured and hostname and hostname not in configured:
        return f"{configured}:{hostname[:12]}"
    return configured or hostname


@functools.lru_cache(maxsize=1)
def _worker_placement_labels() -> dict[str, Any]:
    raw = str(os.environ.get("SHAKERSCAN_NODE_LABELS_JSON") or "").strip()
    try:
        labels = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        labels = {}
    if not isinstance(labels, dict):
        labels = {}
    labels = dict(labels)
    node_id = str(os.environ.get("SHAKERSCAN_NODE_ID") or "").strip().lower()
    # The control plane is a real execution location even though it is not an
    # enrolled remote node. A stable reserved identity lets users explicitly
    # keep a scan local while preserving the same routed-queue machinery and
    # failover between all local worker replicas.
    labels["node_id"] = node_id or "local"
    labels.setdefault("transport", "fleet" if node_id else "local")
    labels.setdefault("node_scope", "remote" if node_id else "local")
    detected_tools = {
        tool for tool, command in DEFAULT_WORKER_TOOL_COMMANDS.items() if shutil.which(command)
    }
    configured_tools = labels.get("tools") or labels.get("capabilities") or []
    if isinstance(configured_tools, str):
        configured_tools = [configured_tools]
    labels["tools"] = sorted(
        detected_tools
        | {str(item).strip().lower() for item in configured_tools if str(item).strip()}
    )
    configured_tiers = labels.get("scan_tiers") or list(VALID_DAST_SCAN_TYPES)
    if isinstance(configured_tiers, str):
        configured_tiers = [configured_tiers]
    labels["scan_tiers"] = sorted(
        {str(item).strip().lower() for item in configured_tiers if str(item).strip()}
    )
    return labels


def _worker_build_hostname() -> str:
    return _worker_runtime_identity()


def _worker_build_report_payload() -> tuple[str, str]:
    hostname = _worker_build_hostname()
    tool_commands = dict(DEFAULT_WORKER_TOOL_COMMANDS)
    if AGENT_TOOL_ONLY_WORKER:
        tool_commands.update({
            str(spec.legacy_tool_name): str(spec.binary or spec.legacy_tool_name)
            for spec in agent_tools.CAPABILITY_REGISTRY.external_tools()
            if spec.legacy_tool_name
        })
    payload = json.dumps({
        "build_fingerprint": _worker_build_fingerprint(),
        "scanner_version": published_scanner_version(_published_scanner_version()),
        "node_id": os.environ.get("SHAKERSCAN_NODE_ID") or os.environ.get("FLEET_NODE_ID") or None,
        "worker_kind": worker_role(
            device_only=DEVICE_ONLY_WORKER,
            agent_tool_only=AGENT_TOOL_ONLY_WORKER,
        )[0],
        "tools": sorted(
            tool for tool, command in tool_commands.items() if shutil.which(command)
        ),
        "reported_at": utc_now_iso(),
    })
    return hostname, payload


def _write_worker_build_report(redis_client) -> str:
    hostname, payload = _worker_build_report_payload()
    redis_client.hset(WORKER_BUILD_REGISTRY_KEY, hostname, payload)
    return hostname


def report_worker_build_fingerprint() -> None:
    """Register build identity in the product-specific worker registry.

    Device-only workers deliberately never enter the Web DAST registry, so adding
    connected-device capacity cannot make the ordinary fleet look larger, stale,
    or partially reported.
    """
    try:
        hostname = _write_worker_build_report(get_redis())
        print(f"[worker] registered build fingerprint for {hostname}", flush=True)
    except Exception as e:
        print(f"[worker] build fingerprint report failed: {e}", file=sys.stderr, flush=True)


def main():
    """Entry point - runs async main in single event loop."""
    # Run blocking preflight subprocesses synchronously before entering the
    # event loop so they cannot stall asyncio tasks or healthchecks.
    run_worker_preflight()
    report_worker_build_fingerprint()
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
