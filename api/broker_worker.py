#!/usr/bin/env python3
"""Outbound-only HTTPS broker worker.

This runtime deliberately has no Redis or PostgreSQL connection configuration.
It receives one node/job-scoped lease, executes the existing scanner subprocess,
heartbeats ownership, and submits an immutable result for control-plane ingestion.
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
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from fleet_tls import FleetTLSConfigurationError, create_fleet_ssl_context, normalize_tls_ca_state
from worker import (
    RESULTS_DIR,
    _clear_fleet_busy_marker,
    _fleet_busy_marker,
    _signal_scanner_cancel_file,
    run_scan,
)


class BrokerWorkerError(RuntimeError):
    pass


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
        raise BrokerWorkerError(f"broker returned HTTP {exc.code}: {detail[:300]}") from exc
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


async def execute_lease(state: dict[str, Any], lease: dict[str, Any]) -> None:
    job = lease.get("job") if isinstance(lease.get("job"), dict) else {}
    if job.get("_broker_result_id"):
        raise BrokerWorkerError("trusted broker-result ingestion cannot execute on a fleet node")
    target = str(job.get("target") or "").strip()
    scan_id = str(job.get("scan_id") or "").strip()
    job_id = str(job.get("job_id") or "").strip()
    if not target or not scan_id or not job_id:
        raise BrokerWorkerError("broker lease is missing executable scan fields")
    node_id = str(state["node_id"])
    lease_id = str(lease.get("lease_id") or "")
    lease_token = str(lease.get("lease_token") or "")
    heartbeat_interval = max(5, int(lease.get("heartbeat_interval_seconds") or 30))
    lease_failed: list[str] = []
    done = asyncio.Event()
    live: dict[str, Any] = {"phase": "broker_execution", "progress": 5, "log_lines": []}

    def progress_callback(event: dict[str, Any]) -> None:
        if event.get("phase") is not None:
            live["phase"] = str(event["phase"])
        if event.get("progress") is not None:
            live["progress"] = int(event["progress"])
        line = str(event.get("line") or "")
        if line:
            lines = live.setdefault("log_lines", [])
            lines.append(line[:2000])
            del lines[:-20]

    async def heartbeat() -> None:
        while not done.is_set():
            try:
                await asyncio.wait_for(done.wait(), timeout=heartbeat_interval)
                return
            except asyncio.TimeoutError:
                pass
            try:
                log_lines = list(live.get("log_lines") or [])
                live["log_lines"] = []
                response = await asyncio.to_thread(
                    api_request,
                    state,
                    "POST",
                    f"/fleet/broker/nodes/{node_id}/leases/{lease_id}/heartbeat",
                    {
                        "lease_token": lease_token,
                        "phase": live.get("phase"),
                        "progress": live.get("progress"),
                        "log_lines": log_lines,
                    },
                )
                if response and response.get("cancel_requested"):
                    _signal_scanner_cancel_file(str(RESULTS_DIR / f"{scan_id}_cancel"))
            except Exception as exc:
                lease_failed.append(str(exc))
                _signal_scanner_cancel_file(str(RESULTS_DIR / f"{scan_id}_cancel"))
                return

    heartbeat_task = asyncio.create_task(heartbeat())
    busy_marker = _fleet_busy_marker(job)
    try:
        try:
            result = await run_scan(
                target,
                dict(job.get("options") or {}),
                scan_id=scan_id,
                job_id=job_id,
                progress_callback=progress_callback,
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
        if checkpoint.is_file() and not checkpoint.is_symlink():
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
        await asyncio.gather(heartbeat_task, return_exceptions=True)
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
