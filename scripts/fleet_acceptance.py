#!/usr/bin/env python3
"""Reproducible multi-node fleet acceptance and lease-failure probe.

Run this from the control plane after at least two physical worker nodes have
joined. The scan is passive ``standard`` work, but the operator must still pass
``--authorized`` because it sends traffic to the supplied target.

The emitted JSON is content-free acceptance evidence: target URLs, credentials,
scan bodies, findings, and artifact bytes are never written to the receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TERMINAL_SCAN_STATUSES = {"completed", "failed", "cancelled"}


class AcceptanceError(RuntimeError):
    pass


class ApiClient:
    def __init__(self, base_url: str, operator_token: str = "") -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise AcceptanceError("--api-url must be an HTTP(S) URL")
        self.base_url = base_url.rstrip("/")
        self.operator_token = operator_token.strip()

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout: int = 60,
    ) -> dict[str, Any]:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.operator_token:
            headers["Authorization"] = f"Bearer {self.operator_token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            method=method,
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = str(json.load(exc).get("detail") or "")
            except Exception:
                pass
            raise AcceptanceError(f"{method} {path} returned HTTP {exc.code}: {detail[:400]}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise AcceptanceError(f"{method} {path} failed: {exc}") from exc
        if not isinstance(result, dict):
            raise AcceptanceError(f"{method} {path} returned a non-object response")
        return result


def _check(checks: list[dict[str, Any]], name: str, passed: bool, detail: str, **evidence: Any) -> bool:
    item = {"name": name, "pass": bool(passed), "detail": detail}
    if evidence:
        item["evidence"] = evidence
    checks.append(item)
    marker = "ok" if passed else "FAIL"
    print(f"[{marker}] {name}: {detail}", flush=True)
    return bool(passed)


def _target_hash(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def _safe_parallel_endpoints(target: str, count: int) -> list[str]:
    parsed = urllib.parse.urlsplit(target)
    origin = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
    paths = [
        "/",
        "/robots.txt",
        "/favicon.ico",
        "/sitemap.xml",
        "/.well-known/security.txt",
        "/?shakerscan_fleet_acceptance=1",
        "/nonexistent-shakerscan-fleet-a",
        "/nonexistent-shakerscan-fleet-b",
        "/nonexistent-shakerscan-fleet-c",
        "/nonexistent-shakerscan-fleet-d",
        "/nonexistent-shakerscan-fleet-e",
        "/nonexistent-shakerscan-fleet-f",
    ]
    return [urllib.parse.urljoin(f"{origin}/", path.lstrip("/")) for path in paths[:count]]


def _select_nodes(payload: dict[str, Any], requested: list[str]) -> list[dict[str, Any]]:
    nodes = [item for item in payload.get("nodes") or [] if isinstance(item, dict)]
    if requested:
        wanted = set(requested)
        nodes = [item for item in nodes if str(item.get("id") or "") in wanted]
        missing = wanted - {str(item.get("id") or "") for item in nodes}
        if missing:
            raise AcceptanceError(f"requested fleet nodes were not found: {', '.join(sorted(missing))}")
    return [item for item in nodes if str(item.get("status") or "") != "disabled"]


def _probe_public_data_stores(host: str, timeout: float = 2.0) -> dict[str, bool]:
    results: dict[str, bool] = {}
    for port in (6379, 5432):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                results[str(port)] = False
        except OSError:
            results[str(port)] = True
    return results


def _lease_failure_probe(redis_url: str) -> dict[str, Any]:
    try:
        import redis
    except ImportError as exc:
        raise AcceptanceError("redis package is required for --redis-url lease probing") from exc
    sys.path.insert(0, str(ROOT / "api"))
    try:
        from job_queue import acknowledge_lease, enqueue_job, heartbeat_lease, lease_job, stream_key
    finally:
        sys.path.pop(0)
    client = redis.from_url(redis_url, socket_connect_timeout=5, socket_timeout=5)
    queue = f"fleet_acceptance:{uuid.uuid4().hex}"
    try:
        message_id = enqueue_job(client, queue, {"kind": "fleet_acceptance", "nonce": uuid.uuid4().hex})
        first = lease_job(
            client,
            [queue],
            consumer_name="acceptance-dead-consumer",
            block_ms=10,
            visibility_timeout_ms=50,
        )
        if not first or first.message_id != message_id:
            raise AcceptanceError("lease probe could not acquire its first delivery")
        time.sleep(0.08)
        reclaimed = lease_job(
            client,
            [queue],
            consumer_name="acceptance-recovery-consumer",
            block_ms=10,
            visibility_timeout_ms=50,
        )
        if not reclaimed or reclaimed.message_id != message_id or not reclaimed.reclaimed:
            raise AcceptanceError("lease probe did not reclaim the abandoned delivery")
        heartbeat_ok = heartbeat_lease(client, reclaimed, "acceptance-recovery-consumer")
        first_ack = acknowledge_lease(client, reclaimed)
        duplicate_ack = acknowledge_lease(client, reclaimed)
        return {
            "reclaimed": True,
            "delivery_attempts": reclaimed.delivery_attempts,
            "heartbeat_ok": heartbeat_ok,
            "first_ack": first_ack,
            "duplicate_ack": duplicate_ack,
        }
    finally:
        try:
            client.delete(queue, stream_key(queue))
        except Exception:
            pass


def _poll_scan(client: ApiClient, scan_id: str, timeout_seconds: int, poll_seconds: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        scan = client.request("GET", f"/scans/{scan_id}")
        status = str(scan.get("status") or "")
        print(
            f"[wait] scan {scan_id[:8]} status={status} progress={scan.get('progress', 0)} phase={scan.get('current_phase')}",
            flush=True,
        )
        if status in TERMINAL_SCAN_STATUSES:
            return scan
        time.sleep(max(1.0, poll_seconds))
    raise AcceptanceError(f"scan {scan_id} did not finish within {timeout_seconds}s")


def _inject_physical_worker_loss(
    client: ApiClient,
    parent_scan_id: str,
    *,
    node_id: str,
    ssh_target: str,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Kill the exact Docker worker executing a child shard on a physical node."""
    try:
        uuid.UUID(node_id)
    except ValueError as exc:
        raise AcceptanceError("--fault-node-id must be a UUID") from exc
    if (
        not ssh_target
        or ssh_target.startswith("-")
        or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@:-" for ch in ssh_target)
    ):
        raise AcceptanceError("--fault-node-ssh must be a plain [user@]host without shell syntax")
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        for shard in _all_shards(client, parent_scan_id):
            if str(shard.get("status") or "") != "running" or str(shard.get("executing_node_id") or "") != node_id:
                continue
            context = shard.get("execution_context") if isinstance(shard.get("execution_context"), dict) else {}
            worker_id = str(context.get("worker_id") or shard.get("worker_id") or "")
            container_id = worker_id.rsplit(":", 1)[-1].lower()
            if len(container_id) < 12 or any(ch not in "0123456789abcdef" for ch in container_id):
                raise AcceptanceError("running shard did not expose a Docker container worker identity")
            client.request("PATCH", f"/fleet/nodes/{node_id}/state", {"drain": True})
            result = subprocess.run(
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", "ConnectTimeout=10",
                    ssh_target,
                    "docker", "kill", container_id,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if result.returncode != 0:
                try:
                    client.request("PATCH", f"/fleet/nodes/{node_id}/state", {"drain": False})
                except AcceptanceError:
                    pass
                raise AcceptanceError(f"physical worker kill failed: {result.stderr.strip()[:300]}")
            print(f"[fault] killed worker {container_id} for shard {str(shard['id'])[:8]} on node {node_id[:8]}", flush=True)
            return {
                "node_id": node_id,
                "scan_id": str(shard["id"]),
                "container_id": container_id,
                "worker_id": worker_id,
                "node_drained": True,
                "fault": "docker_kill",
            }
        time.sleep(1.0)
    raise AcceptanceError("no running shard appeared on the selected fault node before timeout")


def _all_shards(client: ApiClient, parent_scan_id: str) -> list[dict[str, Any]]:
    payload = client.request("GET", f"/scans/{parent_scan_id}")
    return [
        row for row in payload.get("shards") or [] if isinstance(row, dict)
    ]


def _evaluate_scan(
    client: ApiClient,
    scan_id: str,
    parent: dict[str, Any],
    checks: list[dict[str, Any]],
    fault: dict[str, Any] | None = None,
) -> None:
    shards = _all_shards(client, scan_id)
    node_ids = sorted({str(row.get("executing_node_id") or "") for row in shards if row.get("executing_node_id")})
    _check(checks, "parallel_parent_completed", parent.get("status") == "completed", str(parent.get("status")))
    _check(checks, "parallel_shards_created", len(shards) >= 2, f"{len(shards)} shard rows")
    _check(
        checks,
        "cross_node_shard_execution",
        len(node_ids) >= 2,
        f"{len(node_ids)} distinct executing nodes",
        node_ids=node_ids,
    )
    terminal = all(str(row.get("status") or "") in TERMINAL_SCAN_STATUSES for row in shards)
    _check(checks, "shards_terminal", bool(shards) and terminal, "all child rows reached terminal state")
    context_ok = bool(shards) and all(
        isinstance(row.get("execution_context"), dict)
        and row["execution_context"].get("credential_scope")
        and row["execution_context"].get("worker_id")
        for row in shards
    )
    _check(checks, "execution_context_snapshotted", context_ok, "worker/node execution context is durable")

    fingerprints: list[str] = []
    for shard in shards:
        detail = client.request("GET", f"/scans/{shard['id']}")
        fingerprints.extend(
            str(item.get("fingerprint") or "")
            for item in detail.get("findings") or []
            if isinstance(item, dict) and item.get("fingerprint")
        )
    _check(
        checks,
        "concurrent_findings_deduplicated",
        len(fingerprints) == len(set(fingerprints)),
        f"{len(fingerprints)} persisted child finding fingerprints are unique",
    )

    result = client.request("GET", f"/scans/{scan_id}/result")
    _check(checks, "single_logical_report", isinstance(result, dict) and bool(result), "parent result is readable")
    artifact_payload = client.request("GET", f"/scans/{scan_id}/artifacts?limit=500")
    artifacts = [item for item in artifact_payload.get("artifacts") or [] if isinstance(item, dict)]
    available = [item for item in artifacts if item.get("status") == "available"]
    hashes_ok = bool(available) and all(
        len(str(item.get("content_sha256") or "")) == 64 and int(item.get("size_bytes") or 0) > 0
        for item in available
    )
    _check(
        checks,
        "central_artifact_manifests",
        hashes_ok,
        f"{len(available)} available hash-addressed artifacts",
        artifact_count=len(available),
    )
    if fault:
        delivery = client.request("GET", f"/scans/{fault['scan_id']}/queue-delivery")
        recovered = (
            int(delivery.get("delivery_attempts") or 0) >= 2
            and bool(delivery.get("reclaimed"))
            and str(delivery.get("status") or "") in TERMINAL_SCAN_STATUSES
            and str(delivery.get("executing_node_id") or "")
            and str(delivery.get("executing_node_id") or "") != str(fault["node_id"])
        )
        _check(
            checks,
            "physical_worker_loss_recovered",
            recovered,
            "killed physical worker lease was reclaimed and completed",
            scan_id=fault["scan_id"],
            node_id=fault["node_id"],
            recovered_node_id=delivery.get("executing_node_id"),
            delivery_attempts=int(delivery.get("delivery_attempts") or 0),
            reclaimed=bool(delivery.get("reclaimed")),
        )


def run(args: argparse.Namespace) -> dict[str, Any]:
    client = ApiClient(args.api_url, args.operator_token or os.environ.get("SHAKERSCAN_FLEET_OPERATOR_TOKEN", ""))
    checks: list[dict[str, Any]] = []
    health = client.request("GET", "/health")
    _check(checks, "control_plane_health", health.get("status") == "healthy", str(health.get("status")))
    fleet = client.request("GET", "/fleet/nodes")
    nodes = _select_nodes(fleet, args.node_id)
    healthy = [node for node in nodes if node.get("status") == "healthy"]
    _check(checks, "two_healthy_nodes", len(healthy) >= 2, f"{len(healthy)} healthy selected nodes")
    heartbeat_ok = len(healthy) >= 2 and all(
        node.get("last_heartbeat_at") and isinstance(node.get("capacity"), dict) and node["capacity"].get("cpu_count")
        for node in healthy
    )
    _check(checks, "heartbeat_and_capacity", heartbeat_ok, "selected nodes report heartbeat and CPU capacity")
    uniform = len(healthy) >= 2 and all(
        node.get("state_current") and node.get("image_current") and int(node.get("active_worker_count") or 0) > 0
        for node in healthy
    )
    _check(checks, "current_worker_fleet", uniform, "selected nodes are current and have active workers")
    worker_only = all(str((node.get("labels") or {}).get("transport") or "") in {"overlay", "broker"} for node in healthy)
    _check(checks, "worker_transport_labeled", bool(healthy) and worker_only, "nodes identify overlay or broker transport")

    storage = client.request("GET", "/artifacts/storage/health?probe=true")
    _check(checks, "artifact_store_write_probe", storage.get("status") == "ok", str(storage.get("status")))

    public_host = args.public_host or urllib.parse.urlsplit(args.api_url).hostname or ""
    try:
        is_loopback = ipaddress.ip_address(public_host).is_loopback
    except ValueError:
        is_loopback = public_host.lower() == "localhost"
    if not is_loopback:
        port_results = _probe_public_data_stores(public_host)
        _check(
            checks,
            "public_data_stores_closed",
            all(port_results.values()),
            "Redis 6379 and PostgreSQL 5432 reject public TCP connections",
            ports=port_results,
        )
    elif not args.preflight_only:
        _check(checks, "public_data_stores_closed", False, "provide --public-host for an external isolation probe")

    if args.redis_url:
        lease = _lease_failure_probe(args.redis_url)
        lease_ok = (
            lease.get("reclaimed")
            and int(lease.get("delivery_attempts") or 0) >= 2
            and lease.get("heartbeat_ok")
            and lease.get("first_ack")
            and not lease.get("duplicate_ack")
        )
        _check(
            checks,
            "lease_reclaim_and_duplicate_completion",
            bool(lease_ok),
            "abandoned lease reclaimed; completion acknowledged once",
            **lease,
        )
    elif not args.preflight_only:
        _check(checks, "lease_reclaim_and_duplicate_completion", False, "provide --redis-url on the control plane")

    scan_id = None
    physical_fault: dict[str, Any] | None = None
    if not args.preflight_only:
        if not args.target or not args.authorized:
            raise AcceptanceError("full acceptance requires --target and --authorized")
        shard_count = max(4, min(12, len(healthy) * 3))
        submitted = client.request(
            "POST",
            "/scans",
            {
                "target": args.target,
                "options": {
                    "scan_type": "standard",
                    "parallel": True,
                    "shards": shard_count,
                    "shard_strategy": "scope",
                    "custom_endpoints": _safe_parallel_endpoints(args.target, shard_count),
                    "request_budget_mode": args.request_budget_mode,
                    "require_current_workers": True,
                },
            },
            timeout=60,
        )
        scan_id = str(submitted.get("scan_id") or "")
        if not scan_id or not submitted.get("parallel"):
            raise AcceptanceError("control plane did not create a parallel acceptance scan")
        print(f"[queued] fleet acceptance scan {scan_id}", flush=True)
        if not args.fault_node_ssh:
            _check(
                checks,
                "physical_worker_loss_recovered",
                False,
                "provide --fault-node-ssh and --fault-node-id for the physical failure gate",
            )
        else:
            fault_node_id = args.fault_node_id or str(healthy[0].get("id") or "")
            try:
                physical_fault = _inject_physical_worker_loss(
                    client,
                    scan_id,
                    node_id=fault_node_id,
                    ssh_target=args.fault_node_ssh,
                    timeout_seconds=min(args.timeout, 600),
                )
                parent = _poll_scan(client, scan_id, args.timeout, args.poll_seconds)
                _evaluate_scan(client, scan_id, parent, checks, physical_fault)
            finally:
                if physical_fault and physical_fault.get("node_drained"):
                    client.request("PATCH", f"/fleet/nodes/{fault_node_id}/state", {"drain": False})
        if not physical_fault:
            parent = _poll_scan(client, scan_id, args.timeout, args.poll_seconds)
            _evaluate_scan(client, scan_id, parent, checks)

    receipt: dict[str, Any] = {
        "schema_version": "shakerscan_fleet_acceptance_v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "api_origin": urllib.parse.urlunsplit((*urllib.parse.urlsplit(args.api_url)[:2], "", "", "")),
        "selected_node_ids": sorted(str(node.get("id") or "") for node in nodes),
        "scan_id": scan_id,
        "target_sha256": _target_hash(args.target) if args.target else None,
        "physical_fault": physical_fault,
        "preflight_only": bool(args.preflight_only),
        "checks": checks,
        "passed": all(item["pass"] for item in checks),
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    receipt["receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate a physical ShakerScan multi-node fleet")
    parser.add_argument("--api-url", default="http://127.0.0.1:8080")
    parser.add_argument("--operator-token", default="")
    parser.add_argument("--node-id", action="append", default=[], help="limit acceptance to this node UUID (repeatable)")
    parser.add_argument("--public-host", help="public control-plane host from which 6379/5432 must be closed")
    parser.add_argument("--redis-url", help="control-plane Redis URL used only for an isolated lease-reclaim probe")
    parser.add_argument("--target", help="authorized passive web target for the cross-node scan")
    parser.add_argument("--authorized", action="store_true", help="confirm authorization to scan --target")
    parser.add_argument("--request-budget-mode", choices=["enforce", "off"], default="enforce")
    parser.add_argument("--fault-node-id", help="node UUID whose active worker will be killed during the scan")
    parser.add_argument("--fault-node-ssh", help="SSH [user@]host for --fault-node-id (BatchMode required)")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output", type=Path, default=Path("results/fleet-acceptance.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        receipt = run(args)
    except AcceptanceError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(args.output)
    print(f"[receipt] {args.output} sha256={receipt['receipt_sha256']}", flush=True)
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
