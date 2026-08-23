#!/usr/bin/env python3
"""Outbound-only HTTPS broker worker.

This runtime deliberately has no Redis or PostgreSQL connection configuration.
Canonical Scan work executes the same immutable action graph as local placement;
the control plane owns durable action leases and receipt settlement over HTTPS.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import mimetypes
import os
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Mapping

from fleet_tls import FleetTLSConfigurationError, create_fleet_ssl_context, normalize_tls_ca_state
from runtime.models import ScanPolicy, TargetBinding
from scan.action_adapter import DatabaseNeutralScanActionDispatcher
from scan.action_plan import ScanActionPlan, ScanActionPlanError
from scan.broker_backend import (
    BrokerActionHTTPError,
    BrokerScanExecutionBackend,
)
from scan.orchestrator import ScanOrchestrator
from scan.migration import require_legacy_scan_execution_window
from scan.worker_action_executor import ReceiptScanActionExecutor
from worker import (
    RESULTS_DIR,
    _clear_fleet_busy_marker,
    _execute_agent_scanner_process,
    _fleet_busy_marker,
    _scan_cancel_requested,
    _signal_scanner_cancel_file,
    run_scan,
)


class BrokerWorkerError(RuntimeError):
    pass


class BrokerHTTPError(BrokerWorkerError):
    """An authenticated broker response whose status controls retry posture."""

    def __init__(self, status_code: int, detail: str = "") -> None:
        self.status_code = int(status_code)
        super().__init__(f"broker returned HTTP {self.status_code}: {detail[:300]}")


_SCAN_RUNTIME_BUDGET_DIMENSIONS = frozenset({
    "http_requests",
    "state_changing_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "hosts_attempted",
    "tool_wall_seconds",
})


def _broker_scan_action_plan(
    job: dict[str, Any], lease: dict[str, Any],
) -> tuple[ScanActionPlan, str] | None:
    """Validate the complete immutable plan issued to this broker worker."""
    options = job.get("options") if isinstance(job.get("options"), dict) else {}
    execution_digest = str(options.get("scan_execution_plan_digest") or "").lower()
    raw_plan = lease.get("scan_action_plan")
    worker_id = str(lease.get("action_worker_id") or "").strip()
    if not execution_digest:
        if raw_plan is not None or worker_id:
            raise BrokerWorkerError(
                "non-canonical broker job carried Scan action authority"
            )
        return None
    if lease.get("scan_execution") is not None:
        raise BrokerWorkerError(
            "canonical broker Scan carried deprecated monolithic authority"
        )
    if not isinstance(raw_plan, dict) or not worker_id.startswith("broker:"):
        raise BrokerWorkerError(
            "canonical broker Scan is missing immutable action authority"
        )
    try:
        plan = ScanActionPlan.from_dict(raw_plan)
    except (ScanActionPlanError, TypeError, ValueError) as exc:
        raise BrokerWorkerError("canonical broker Scan action plan is invalid") from exc
    target_binding = options.get("_canonical_target_binding")
    if not isinstance(target_binding, dict):
        raise BrokerWorkerError(
            "canonical broker Scan target binding is unavailable"
        )
    try:
        target = TargetBinding(
            target_id=str(target_binding.get("target_id") or ""),
            target_kind=str(target_binding.get("target_kind") or ""),
            canonical_host=target_binding.get("canonical_host"),
            allowed_origins=tuple(target_binding.get("allowed_origins") or ()),
            allowed_addresses=tuple(target_binding.get("allowed_addresses") or ()),
            allowed_root_domains=tuple(
                target_binding.get("allowed_root_domains") or ()
            ),
            environment=str(target_binding.get("environment") or "unknown"),
            scope_receipt_id=(
                str(target_binding.get("scope_receipt_id") or "") or None
            ),
        )
    except (TypeError, ValueError) as exc:
        raise BrokerWorkerError(
            "canonical broker Scan target binding is invalid"
        ) from exc
    if (
        plan.scan_id != str(job.get("scan_id") or "")
        or plan.execution_plan_digest != execution_digest
        or plan.target_binding_digest != target.digest
    ):
        raise BrokerWorkerError(
            "canonical broker Scan action authority does not match the job"
        )
    return plan, worker_id


def _broker_scan_runtime_budget(
    job: dict[str, Any], lease: dict[str, Any],
) -> dict[str, int] | None:
    """Validate the control-plane hold before a canonical broker Scan starts."""
    options = job.get("options") if isinstance(job.get("options"), dict) else {}
    plan_digest = str(options.get("scan_execution_plan_digest") or "").lower()
    raw = lease.get("scan_execution")
    if not plan_digest:
        if raw is not None:
            raise BrokerWorkerError(
                "non-canonical broker job carried Scan execution authority"
            )
        return None
    if not isinstance(raw, dict):
        raise BrokerWorkerError(
            "canonical broker Scan is missing durable execution authority"
        )
    if (
        raw.get("schema_version")
        != "broker-scan-execution-reservation/v1"
        or raw.get("action_id") != "deterministic_scan.execute"
        or str(raw.get("execution_plan_digest") or "").lower() != plan_digest
    ):
        raise BrokerWorkerError("broker Scan execution authority is invalid")
    for name in ("reservation_id",):
        try:
            uuid.UUID(str(raw.get(name) or ""))
        except ValueError as exc:
            raise BrokerWorkerError(
                f"broker Scan execution {name} is invalid"
            ) from exc
    for name in ("action_digest", "target_binding_digest"):
        value = str(raw.get(name) or "").lower()
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise BrokerWorkerError(
                f"broker Scan execution {name} is invalid"
            )
    target_binding = options.get("_canonical_target_binding")
    if not isinstance(target_binding, dict):
        raise BrokerWorkerError(
            "canonical broker Scan target binding is unavailable"
        )
    target_digest = hashlib.sha256(json.dumps(
        target_binding,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    if target_digest != str(raw.get("target_binding_digest") or "").lower():
        raise BrokerWorkerError(
            "broker Scan execution target binding does not match the job"
        )
    runtime = raw.get("runtime_budget")
    requested = raw.get("requested_budget")
    if (
        not isinstance(runtime, dict)
        or set(runtime) != _SCAN_RUNTIME_BUDGET_DIMENSIONS
        or not isinstance(requested, dict)
        or not set(requested).issubset(_SCAN_RUNTIME_BUDGET_DIMENSIONS)
    ):
        raise BrokerWorkerError("broker Scan execution budget is invalid")
    normalized: dict[str, int] = {}
    normalized_requested: dict[str, int] = {}
    for name, amount in runtime.items():
        if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
            raise BrokerWorkerError(
                f"broker Scan runtime budget {name} is invalid"
            )
        normalized[name] = amount
    for name, amount in requested.items():
        if isinstance(amount, bool) or not isinstance(amount, int) or amount <= 0:
            raise BrokerWorkerError(
                f"broker Scan requested budget {name} is invalid"
            )
        normalized_requested[name] = amount
    expected_requested = {
        name: amount
        for name, amount in normalized.items()
        if amount > 0
    }
    if normalized_requested != expected_requested:
        raise BrokerWorkerError(
            "broker Scan runtime budget does not match its durable hold"
        )
    if any(
        normalized[name] <= 0
        for name in ("http_requests", "hosts_attempted", "tool_wall_seconds")
    ):
        raise BrokerWorkerError(
            "broker Scan durable hold lacks mandatory execution capacity"
        )
    if normalized["state_changing_requests"] > normalized["http_requests"]:
        raise BrokerWorkerError(
            "broker Scan mutation budget exceeds HTTP authority"
        )
    return normalized


def _heartbeat_failure_is_terminal(exc: Exception) -> bool:
    """Fail closed immediately only when the control plane rejected authority.

    Rate limits, server failures, and transport errors are retried within the
    lease grace window. Authentication/conflict/not-found responses mean this
    worker no longer owns the lease and must stop immediately.
    """
    if not isinstance(exc, BrokerHTTPError):
        return False
    return exc.status_code not in {408, 425, 429, 500, 502, 503, 504}


def _heartbeat_lease_until_done(
    state: dict[str, Any],
    *,
    node_id: str,
    lease_id: str,
    lease_token: str,
    scan_id: str,
    heartbeat_interval: float,
    done: threading.Event,
    live: dict[str, Any],
    live_lock: threading.Lock,
    lease_failed: list[str],
    failure_grace_seconds: float | None = None,
    request_timeout: int = 15,
) -> None:
    """Keep broker ownership alive independently of scanner event-loop health.

    Several scanners legitimately perform long blocking parser or subprocess work.
    An asyncio heartbeat task on the same loop can therefore be starved long enough
    for both the queue lease and the API stale-scan watchdog to expire.  The ordinary
    worker already uses a dedicated heartbeat thread for this reason; broker workers
    need the same failure posture.
    """
    grace = max(heartbeat_interval * 2, float(failure_grace_seconds or 0))
    last_success = time.monotonic()
    wait_seconds = heartbeat_interval
    while not done.wait(wait_seconds):
        with live_lock:
            log_lines = list(live.get("log_lines") or [])
            live["log_lines"] = []
            phase = live.get("phase")
            progress = live.get("progress")
        try:
            response = api_request(
                state,
                "POST",
                f"/fleet/broker/nodes/{node_id}/leases/{lease_id}/heartbeat",
                {
                    "lease_token": lease_token,
                    "phase": phase,
                    "progress": progress,
                    "log_lines": log_lines,
                },
                timeout=max(1, int(request_timeout)),
            )
            if done.is_set():
                return
            last_success = time.monotonic()
            wait_seconds = heartbeat_interval
            if response and response.get("cancel_requested"):
                _signal_scanner_cancel_file(str(RESULTS_DIR / f"{scan_id}_cancel"))
        except Exception as exc:
            if done.is_set():
                return
            # Do not discard buffered logs just because this delivery attempt
            # failed; resend them on the next successful heartbeat.
            if log_lines:
                with live_lock:
                    pending = list(live.get("log_lines") or [])
                    live["log_lines"] = (log_lines + pending)[-20:]
            terminal = _heartbeat_failure_is_terminal(exc)
            grace_expired = (time.monotonic() - last_success) >= grace
            if terminal or grace_expired:
                posture = "terminal" if terminal else "retry grace exhausted"
                lease_failed.append(f"{posture}: {exc}")
                _signal_scanner_cancel_file(str(RESULTS_DIR / f"{scan_id}_cancel"))
                return
            # Retry transient failures well before the lease deadline instead
            # of sleeping a complete heartbeat interval again.
            wait_seconds = max(0.01, min(5.0, heartbeat_interval / 3))


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise BrokerWorkerError(f"broker state file does not exist: {path}")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise BrokerWorkerError(f"broker state file must be owner-only (mode 0600), found {mode:04o}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BrokerWorkerError(f"cannot read broker state: {exc}") from exc
    required = ("node_id", "node_credential", "control_plane_url")
    missing = [key for key in required if not str(state.get(key) or "").strip()]
    if missing:
        raise BrokerWorkerError(f"broker state is missing: {', '.join(missing)}")
    parsed = urllib.parse.urlparse(str(state["control_plane_url"]))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BrokerWorkerError("control_plane_url must be HTTPS without embedded credentials")
    try:
        normalize_tls_ca_state(state)
    except FleetTLSConfigurationError as exc:
        raise BrokerWorkerError(str(exc)) from exc
    return state


def _ssl_context(state: dict[str, Any]) -> ssl.SSLContext:
    try:
        return create_fleet_ssl_context(state)
    except FleetTLSConfigurationError as exc:
        raise BrokerWorkerError(str(exc)) from exc


def api_request(
    state: dict[str, Any],
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    allow_empty: bool = False,
    timeout: int = 40,
) -> dict[str, Any] | None:
    url = f"{str(state['control_plane_url']).rstrip('/')}{path}"
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {state['node_credential']}",
            "User-Agent": "ShakerScan-Broker-Worker/1",
        },
    )
    context = _ssl_context(state)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            if response.status == 204 and allow_empty:
                return None
            result = json.load(response)
            if not isinstance(result, dict):
                raise BrokerWorkerError("broker returned a non-object response")
            return result
    except urllib.error.HTTPError as exc:
        if exc.code == 204 and allow_empty:
            return None
        detail = ""
        try:
            detail = str(json.load(exc).get("detail") or "")
        except Exception:
            pass
        raise BrokerHTTPError(exc.code, detail) from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise BrokerWorkerError(f"broker request failed: {exc}") from exc


def upload_artifact(
    state: dict[str, Any],
    *,
    lease_id: str,
    lease_token: str,
    path: Path,
    artifact_type: str,
) -> dict[str, Any]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    filename = f"{digest[:12]}-{path.name}"[:180]
    query = urllib.parse.urlencode({"artifact_type": artifact_type, "filename": filename})
    url = (
        f"{str(state['control_plane_url']).rstrip('/')}/fleet/broker/nodes/{state['node_id']}"
        f"/leases/{lease_id}/artifacts?{query}"
    )
    request = urllib.request.Request(
        url,
        data=raw,
        method="PUT",
        headers={
            "Accept": "application/json",
            "Content-Type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "Authorization": f"Bearer {state['node_credential']}",
            "X-ShakerScan-Lease-Token": lease_token,
            "User-Agent": "ShakerScan-Broker-Worker/1",
        },
    )
    context = _ssl_context(state)
    try:
        with urllib.request.urlopen(request, timeout=120, context=context) as response:
            result = json.load(response)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise BrokerWorkerError(f"artifact upload failed: {exc}") from exc
    if not isinstance(result, dict) or result.get("content_sha256") != digest or not result.get("url"):
        raise BrokerWorkerError("artifact upload receipt failed hash verification")
    return result


async def centralize_result_artifacts(
    state: dict[str, Any],
    *,
    lease_id: str,
    lease_token: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    root = RESULTS_DIR.resolve()
    uploaded: dict[str, str] = {}
    count = 0

    async def rewrite(value: Any) -> Any:
        nonlocal count
        if isinstance(value, dict):
            return {str(key): await rewrite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [await rewrite(item) for item in value]
        if not isinstance(value, str) or not value.startswith("/"):
            return value
        try:
            candidate = Path(value)
            if candidate.is_symlink():
                return value
            path = candidate.resolve(strict=True)
            path.relative_to(root)
        except (OSError, ValueError):
            return value
        if not path.is_file():
            return value
        cache_key = str(path)
        if cache_key in uploaded:
            return uploaded[cache_key]
        if count >= 64:
            raise BrokerWorkerError("broker result references more than 64 local artifacts")
        count += 1
        artifact_type = "screenshot" if (mimetypes.guess_type(path.name)[0] or "").startswith("image/") else "attachment"
        receipt = await asyncio.to_thread(
            upload_artifact,
            state,
            lease_id=lease_id,
            lease_token=lease_token,
            path=path,
            artifact_type=artifact_type,
        )
        uploaded[cache_key] = str(receipt["url"])
        return uploaded[cache_key]

    return await rewrite(result)


def _broker_target_binding(options: Mapping[str, Any]) -> TargetBinding:
    raw = options.get("_canonical_target_binding")
    if not isinstance(raw, Mapping):
        raise BrokerWorkerError("canonical broker target binding is unavailable")
    try:
        return TargetBinding(
            target_id=str(raw.get("target_id") or ""),
            target_kind=str(raw.get("target_kind") or ""),
            canonical_host=raw.get("canonical_host"),
            allowed_origins=tuple(raw.get("allowed_origins") or ()),
            allowed_addresses=tuple(raw.get("allowed_addresses") or ()),
            allowed_root_domains=tuple(raw.get("allowed_root_domains") or ()),
            environment=str(raw.get("environment") or "unknown"),
            scope_receipt_id=str(raw.get("scope_receipt_id") or "") or None,
        )
    except (TypeError, ValueError) as exc:
        raise BrokerWorkerError("canonical broker target binding is invalid") from exc


async def _execute_broker_action_plan(
    state: dict[str, Any],
    lease: dict[str, Any],
    job: dict[str, Any],
    *,
    plan: ScanActionPlan,
    worker_id: str,
) -> dict[str, Any]:
    """Run the shared ScanOrchestrator over the HTTPS action backend."""
    node_id = str(state["node_id"])
    lease_id = str(lease.get("lease_id") or "")
    lease_token = str(lease.get("lease_token") or "")
    scan_id = str(job.get("scan_id") or "")
    options = dict(job.get("options") or {})
    target = _broker_target_binding(options)
    raw_execution_plan = options.get("scan_execution_plan")
    if not isinstance(raw_execution_plan, Mapping) or not isinstance(
        raw_execution_plan.get("policy"), Mapping,
    ):
        raise BrokerWorkerError("canonical broker Scan policy is unavailable")
    raw_policy = dict(raw_execution_plan["policy"])
    raw_policy["include_families"] = tuple(raw_policy.get("include_families") or ())
    raw_policy["exclude_families"] = tuple(raw_policy.get("exclude_families") or ())
    try:
        policy = ScanPolicy(**raw_policy)
    except (TypeError, ValueError) as exc:
        raise BrokerWorkerError("canonical broker Scan policy is invalid") from exc

    async def request(
        method: str, path: str, payload: Mapping[str, Any] | None,
    ) -> Mapping[str, Any] | None:
        try:
            return await asyncio.to_thread(
                api_request,
                state,
                method,
                path,
                dict(payload) if payload is not None else None,
                timeout=120,
            )
        except BrokerHTTPError as exc:
            raise BrokerActionHTTPError(exc.status_code, str(exc)) from exc

    base_path = f"/fleet/broker/nodes/{node_id}/leases/{lease_id}"
    backend = BrokerScanExecutionBackend(
        plan=plan,
        worker_id=worker_id,
        job_lease_token=lease_token,
        base_path=base_path,
        request=request,
    )
    dispatcher = DatabaseNeutralScanActionDispatcher(
        target_url=str(job.get("target") or ""),
        options=options,
        target=target,
        policy=policy,
        scan_id=scan_id,
        job_id=str(job.get("job_id") or ""),
        worker_id=worker_id,
        plan=plan,
        backend=backend,
        process_runner=_execute_agent_scanner_process,
        cancelled=lambda: _scan_cancel_requested(scan_id),
    )
    executor = ReceiptScanActionExecutor(
        scan_id=scan_id,
        target_id=target.target_id,
        worker_id=worker_id,
        dispatcher=dispatcher,
        scope_receipt_id=target.scope_receipt_id,
        approval_receipt_id=dispatcher.policy.approval_receipt_id,
    )
    orchestration = await ScanOrchestrator(
        backend=backend,
        executor=executor,
    ).run(plan)
    if not any(action.action_id == "finalize.report" for action in plan.actions):
        if any(
            result.status.value == "cancelled"
            for result in orchestration.action_results.values()
        ):
            raise BrokerWorkerError("broker Scan was cancelled during discovery")
        allocation_digest = str(
            options.get("scan_continuation_allocation_digest") or ""
        ).strip()
        if len(allocation_digest) != 64:
            raise BrokerWorkerError(
                "active broker Scan has no continuation allocation"
            )
        response = await request(
            "POST",
            f"{base_path}/continuation",
            {
                "job_lease_token": lease_token,
                "worker_id": worker_id,
                "plan_digest": plan.plan_digest,
                "allocation_digest": allocation_digest,
            },
        )
        if not isinstance(response, Mapping) or not isinstance(
            response.get("plan"), Mapping,
        ):
            raise BrokerWorkerError(
                "broker continuation returned no immutable action plan"
            )
        try:
            plan = ScanActionPlan.from_dict(response["plan"])
        except (TypeError, ValueError) as exc:
            raise BrokerWorkerError(
                "broker continuation action plan is invalid"
            ) from exc
        if (
            plan.scan_id != scan_id
            or plan.actions[-1].action_id != "finalize.report"
            or str(response.get("allocation_digest") or "")
            != allocation_digest
        ):
            raise BrokerWorkerError(
                "broker continuation changed Scan authority"
            )
        continuation_options = response.get("options")
        if isinstance(continuation_options, Mapping):
            options.update(dict(continuation_options))
        backend = BrokerScanExecutionBackend(
            plan=plan,
            worker_id=worker_id,
            job_lease_token=lease_token,
            base_path=base_path,
            request=request,
        )
        dispatcher = DatabaseNeutralScanActionDispatcher(
            target_url=str(job.get("target") or ""),
            options=options,
            target=target,
            policy=policy,
            scan_id=scan_id,
            job_id=str(job.get("job_id") or ""),
            worker_id=worker_id,
            plan=plan,
            backend=backend,
            process_runner=_execute_agent_scanner_process,
            cancelled=lambda: _scan_cancel_requested(scan_id),
        )
        executor = ReceiptScanActionExecutor(
            scan_id=scan_id,
            target_id=target.target_id,
            worker_id=worker_id,
            dispatcher=dispatcher,
            scope_receipt_id=target.scope_receipt_id,
            approval_receipt_id=dispatcher.policy.approval_receipt_id,
        )
        orchestration = await ScanOrchestrator(
            backend=backend,
            executor=executor,
        ).run(plan)
    final = orchestration.action_results.get("finalize.report")
    if final is None or final.observation_manifest_ref is None:
        raise BrokerWorkerError("broker Scan finalizer produced no report")
    observations = await backend.load_observations("finalize.report")
    if (
        not observations
        or observations[0].get("kind") != "scan_report"
        or not isinstance(observations[0].get("report"), Mapping)
    ):
        raise BrokerWorkerError("broker Scan final report observation is invalid")
    report = dict(observations[0]["report"])
    report.setdefault("canonical_action_execution", {})["status_matrix"] = dict(
        orchestration.status_matrix
    )
    return report


async def execute_lease(state: dict[str, Any], lease: dict[str, Any]) -> None:
    job = lease.get("job") if isinstance(lease.get("job"), dict) else {}
    if job.get("_broker_result_id"):
        raise BrokerWorkerError("trusted broker-result ingestion cannot execute on a fleet node")
    target = str(job.get("target") or "").strip()
    scan_id = str(job.get("scan_id") or "").strip()
    job_id = str(job.get("job_id") or "").strip()
    if not target or not scan_id or not job_id:
        raise BrokerWorkerError("broker lease is missing executable scan fields")
    canonical_action_authority = _broker_scan_action_plan(job, lease)
    node_id = str(state["node_id"])
    lease_id = str(lease.get("lease_id") or "")
    lease_token = str(lease.get("lease_token") or "")
    heartbeat_interval = max(5, int(lease.get("heartbeat_interval_seconds") or 30))
    heartbeat_request_timeout = max(5, min(15, heartbeat_interval))
    lease_failed: list[str] = []
    done = threading.Event()
    live: dict[str, Any] = {"phase": "broker_execution", "progress": 5, "log_lines": []}
    live_lock = threading.Lock()

    def progress_callback(event: dict[str, Any]) -> None:
        with live_lock:
            if event.get("phase") is not None:
                live["phase"] = str(event["phase"])
            if event.get("progress") is not None:
                live["progress"] = int(event["progress"])
            line = str(event.get("line") or "")
            if line:
                lines = live.setdefault("log_lines", [])
                lines.append(line[:2000])
                del lines[:-20]

    heartbeat_thread = threading.Thread(
        target=_heartbeat_lease_until_done,
        kwargs={
            "state": state,
            "node_id": node_id,
            "lease_id": lease_id,
            "lease_token": lease_token,
            "scan_id": scan_id,
            "heartbeat_interval": heartbeat_interval,
            "done": done,
            "live": live,
            "live_lock": live_lock,
            "lease_failed": lease_failed,
            "failure_grace_seconds": heartbeat_interval * 2,
            "request_timeout": heartbeat_request_timeout,
        },
        name=f"broker-heartbeat-{scan_id[:8]}",
        daemon=True,
    )
    heartbeat_thread.start()
    busy_marker = _fleet_busy_marker(job)
    try:
        try:
            if canonical_action_authority is not None:
                action_plan, action_worker_id = canonical_action_authority
                result = await _execute_broker_action_plan(
                    state,
                    lease,
                    job,
                    plan=action_plan,
                    worker_id=action_worker_id,
                )
            else:
                require_legacy_scan_execution_window()
                result = await run_scan(
                    target,
                    dict(job.get("options") or {}),
                    scan_id=scan_id,
                    job_id=job_id,
                    progress_callback=progress_callback,
                    persist_checkpoint_artifacts=False,
                )
        except Exception as exc:
            result = {
                "target": target,
                "error": f"broker execution failed: {type(exc).__name__}: {str(exc)[:1000]}",
                "result": {"score": None, "grade": None},
                "findings": [],
                "scan_metadata": {"broker_execution_failed": True, "retryable": True},
            }
        if lease_failed:
            raise BrokerWorkerError(f"lease authority lost during execution: {lease_failed[-1]}")
        result["job_id"] = job_id
        result["scan_id"] = scan_id
        result = await centralize_result_artifacts(
            state,
            lease_id=lease_id,
            lease_token=lease_token,
            result=result,
        )
        broker_artifacts: list[dict[str, Any]] = []
        checkpoint = RESULTS_DIR / f"{scan_id}_checkpoint.json"
        if (
            canonical_action_authority is None
            and checkpoint.is_file()
            and not checkpoint.is_symlink()
        ):
            receipt = await asyncio.to_thread(
                upload_artifact,
                state,
                lease_id=lease_id,
                lease_token=lease_token,
                path=checkpoint,
                artifact_type="checkpoint",
            )
            broker_artifacts.append({"type": "checkpoint", **receipt})
        if result.get("error") or result.get("failure_diagnostics"):
            diagnostic_path = RESULTS_DIR / f"{scan_id}_broker_diagnostic.json"
            diagnostic_path.write_text(
                json.dumps({
                    "scan_id": scan_id,
                    "job_id": job_id,
                    "error": result.get("error"),
                    "failure_diagnostics": result.get("failure_diagnostics"),
                }, sort_keys=True, default=str),
                encoding="utf-8",
            )
            try:
                receipt = await asyncio.to_thread(
                    upload_artifact,
                    state,
                    lease_id=lease_id,
                    lease_token=lease_token,
                    path=diagnostic_path,
                    artifact_type="diagnostic",
                )
                broker_artifacts.append({"type": "diagnostic", **receipt})
            finally:
                diagnostic_path.unlink(missing_ok=True)
        if broker_artifacts:
            result["broker_artifacts"] = broker_artifacts
        await asyncio.to_thread(
            api_request,
            state,
            "POST",
            f"/fleet/broker/nodes/{node_id}/leases/{lease_id}/result",
            {"lease_token": lease_token, "result": result},
            timeout=120,
        )
    finally:
        done.set()
        heartbeat_thread.join(timeout=heartbeat_request_timeout + 2)
        _clear_fleet_busy_marker(busy_marker)


async def run_forever(state: dict[str, Any], worker_id: str) -> None:
    node_id = str(state["node_id"])
    backoff = 5
    while True:
        try:
            lease = await asyncio.to_thread(
                api_request,
                state,
                "POST",
                f"/fleet/broker/nodes/{node_id}/lease",
                {"worker_id": worker_id, "wait_seconds": 20},
                allow_empty=True,
                timeout=40,
            )
            if lease is None:
                backoff = 5
                continue
            await execute_lease(state, lease)
            backoff = 5
        except Exception as exc:
            # Never print lease payloads or state: both may contain target credentials.
            print(f"[broker-worker] {exc}", file=sys.stderr, flush=True)
            await asyncio.sleep(backoff)
            backoff = min(60, backoff * 2)


def worker_runtime_identity(configured: str | None = None) -> str:
    """Return a lease identity that names one physical worker container."""
    base = str(configured or os.environ.get("WORKER_ID") or "broker-worker").strip()
    hostname = str(os.environ.get("HOSTNAME") or socket.gethostname() or "").strip()
    short_hostname = hostname[:12]
    if base and short_hostname and short_hostname not in base:
        return f"{base}:{short_hostname}"
    return base or hostname or "broker-worker"


def main() -> int:
    parser = argparse.ArgumentParser(description="ShakerScan outbound-only HTTPS broker worker")
    parser.add_argument("--state", default=os.environ.get("FLEET_BROKER_STATE_PATH", "/run/shakerscan-fleet/broker-state.json"))
    parser.add_argument("--worker-id", default=os.environ.get("WORKER_ID") or os.environ.get("HOSTNAME") or "broker-worker")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    worker_id = worker_runtime_identity(args.worker_id)
    os.environ["SHAKERSCAN_BROKER_LEASE"] = "1"
    os.environ["ARTIFACT_STORAGE_REQUIRED"] = "false"
    state = load_state(Path(args.state))
    os.environ["SHAKERSCAN_NODE_ID"] = str(state["node_id"])
    if args.once:
        lease = api_request(
            state,
            "POST",
            f"/fleet/broker/nodes/{state['node_id']}/lease",
            {"worker_id": worker_id, "wait_seconds": 0},
            allow_empty=True,
        )
        if lease:
            asyncio.run(execute_lease(state, lease))
        return 0
    asyncio.run(run_forever(state, worker_id))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
