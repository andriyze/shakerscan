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
import re
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


TERMINAL_SCAN_STATUSES = {"completed", "failed", "cancelled"}
LOCAL_WORKER_IMAGE_RE = re.compile(r"^shakerscan-fleet-local:[a-z0-9][a-z0-9_.-]{0,127}$")


class AcceptanceError(RuntimeError):
    pass


def _local_operator_token() -> str:
    """Load the generated runtime token without exposing it in process arguments."""
    explicit = os.environ.get("SHAKERSCAN_FLEET_OPERATOR_TOKEN") or os.environ.get("FLEET_OPERATOR_TOKEN")
    if explicit:
        return explicit.strip()
    dotenv = Path(__file__).resolve().parents[1] / ".env"
    try:
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            if line.startswith("FLEET_OPERATOR_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _local_api_url() -> str:
    """Resolve the host-published API used by the default acceptance command."""
    dotenv = Path(__file__).resolve().parents[1] / ".env"
    values: dict[str, str] = {}
    try:
        for line in dotenv.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.lstrip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    host = str(values.get("SHAKERSCAN_BIND_HOST") or "").strip()
    if host in {"", "0.0.0.0", "::"}:
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise AcceptanceError("SHAKERSCAN_BIND_HOST is not a safe IP address or hostname")
        formatted_host = host
    else:
        formatted_host = f"[{address}]" if address.version == 6 else str(address)
    raw_port = str(values.get("SHAKERSCAN_API_PORT") or "8080").strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise AcceptanceError("SHAKERSCAN_API_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise AcceptanceError("SHAKERSCAN_API_PORT must be between 1 and 65535")
    return f"http://{formatted_host}:{port}"


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


def _validate_external_acceptance_target(target: str, api_url: str, public_host: str | None) -> None:
    """Refuse to use the Fleet control plane itself as a scan target."""
    parsed_target = urllib.parse.urlsplit(target)
    if parsed_target.scheme not in {"http", "https"}:
        raise AcceptanceError("--target must be an HTTP(S) URL with a hostname")

    def canonical_host(value: str) -> str:
        host = str(value or "").strip().lower().rstrip(".")
        if host == "localhost":
            return "loopback"
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return host
        return "loopback" if address.is_loopback else str(address)

    target_host = canonical_host(parsed_target.hostname or "")
    api_host = canonical_host(urllib.parse.urlsplit(api_url).hostname or "")
    public_name = str(public_host or "").strip()
    if "://" in public_name:
        public_name = urllib.parse.urlsplit(public_name).hostname or ""
    else:
        public_name = public_name.split(":", 1)[0]
    public_name = canonical_host(public_name)
    if not target_host:
        raise AcceptanceError("--target must be an HTTP(S) URL with a hostname")
    protected_hosts = {host for host in (api_host, public_name) if host}
    if target_host in protected_hosts:
        raise AcceptanceError(
            "--target must be a separate authorized test application, not the Fleet control plane"
        )


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


def _acceptance_request_max(shard_count: int) -> int:
    """Return a bounded parent budget for the transport acceptance scan.

    The acceptance target is deliberately limited to one known endpoint per
    shard. Reusing the ordinary ``standard`` ceiling (currently 1,866
    requests) can consume the default 1,000-request hourly domain reservation
    before every shard obtains a lease, leaving a fresh acceptance run waiting
    on its own conservative reservations. Keep the safety gate enabled while
    giving each shard enough room for the passive scanner setup around its one
    assigned URL.
    """
    count = max(1, min(12, int(shard_count or 1)))
    return min(900, count * 100)


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


def _selected_worker_build_mode(
    nodes: list[dict[str, Any]], *, allow_local_build: bool
) -> tuple[bool, str, list[str]]:
    """Validate one unambiguous worker-image mode for an acceptance receipt."""
    local_nodes = [node for node in nodes if bool(node.get("local_build_active"))]
    active_images = sorted({
        str(node.get("active_worker_image_digest") or "").strip()
        for node in nodes
        if node.get("active_worker_image_digest")
    })
    if local_nodes:
        valid = (
            allow_local_build
            and len(local_nodes) == len(nodes)
            and len(active_images) == 1
            and bool(LOCAL_WORKER_IMAGE_RE.fullmatch(active_images[0]))
        )
        return valid, "local-build-development", active_images
    return all(bool(node.get("image_current")) for node in nodes), "digest-pinned", active_images


def _evaluate_scan(
    client: ApiClient,
    scan_id: str,
    parent: dict[str, Any],
    checks: list[dict[str, Any]],
    fault: dict[str, Any] | None = None,
) -> None:
    shards = _all_shards(client, scan_id)
    node_ids = sorted({str(row.get("executing_node_id") or "") for row in shards if row.get("executing_node_id")})
    if fault:
        recovered_shard = next(
            (row for row in shards if str(row.get("id") or "") == str(fault.get("scan_id") or "")),
            None,
        )
        recovered_node_id = str((recovered_shard or {}).get("executing_node_id") or "")
        fault_node_id = str(fault.get("node_id") or "")
        if recovered_node_id and fault_node_id and recovered_node_id != fault_node_id:
            node_ids = sorted(set(node_ids) | {fault_node_id})
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
    client = ApiClient(args.api_url, args.operator_token or _local_operator_token())
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
    build_mode_ok, build_mode, active_images = _selected_worker_build_mode(
        healthy,
        allow_local_build=bool(getattr(args, "allow_local_build", False)),
    )
    uniform = len(healthy) >= 2 and build_mode_ok and all(
        node.get("state_current") and int(node.get("active_worker_count") or 0) > 0
        for node in healthy
    )
    _check(checks, "current_worker_fleet", uniform, "selected nodes are current and have active workers")
    _check(
        checks,
        "uniform_worker_build_mode",
        build_mode_ok,
        (
            "selected nodes use one acknowledged local development image"
            if build_mode == "local-build-development"
            else "selected nodes use their desired digest-pinned images"
        ),
        build_mode=build_mode,
        active_worker_images=active_images,
    )
    worker_only = all(str((node.get("labels") or {}).get("transport") or "") in {"overlay", "broker"} for node in healthy)
    _check(checks, "worker_transport_labeled", bool(healthy) and worker_only, "nodes identify overlay or broker transport")
    selected_transports = {
        str((node.get("labels") or {}).get("transport") or "").strip().lower()
        for node in healthy
    }
    shared_transport = next(iter(selected_transports)) if len(selected_transports) == 1 else ""
    _check(
        checks,
        "uniform_worker_transport",
        shared_transport in {"overlay", "broker"},
        f"selected nodes use one remote worker transport ({shared_transport or 'mixed/unknown'})",
    )

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

    lease = client.request("POST", "/fleet/acceptance/lease-probe", {})
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

    scan_id = None
    physical_fault: dict[str, Any] | None = None
    if not args.preflight_only:
        if not args.target or not args.authorized:
            raise AcceptanceError("full acceptance requires --target and --authorized")
        _validate_external_acceptance_target(args.target, args.api_url, args.public_host)
        shard_count = max(4, min(12, len(healthy) * 3))
        acceptance_request_max = _acceptance_request_max(shard_count)
        submitted = client.request(
            "POST",
            "/scans",
            {
                "target": args.target,
                "options": {
                    "scan_type": args.scan_type,
                    "parallel": True,
                    "shards": shard_count,
                    "shard_strategy": "scope",
                    "custom_endpoints": _safe_parallel_endpoints(args.target, shard_count),
                    "custom_budget": {"request_max": acceptance_request_max},
                    "request_budget_mode": args.request_budget_mode,
                    "require_current_workers": True,
                    # Keep the physical proof on the selected fleet transport. Without
                    # this constraint a control-plane-local worker could execute a
                    # shard and make a nominal cross-node result misleading.
                    "placement": {"node_scope": "remote"},
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
        "scan_type": args.scan_type,
        "request_budget_mode": args.request_budget_mode,
        "request_budget_max": (
            _acceptance_request_max(max(4, min(12, len(healthy) * 3)))
            if not args.preflight_only
            else None
        ),
        "physical_fault": physical_fault,
        "preflight_only": bool(args.preflight_only),
        "build_mode": build_mode,
        "allow_local_build": bool(getattr(args, "allow_local_build", False)),
        "checks": checks,
        "passed": all(item["pass"] for item in checks),
    }
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    receipt["receipt_sha256"] = hashlib.sha256(canonical).hexdigest()
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate a physical ShakerScan multi-node fleet")
    parser.add_argument("--api-url", default=_local_api_url())
    parser.add_argument("--operator-token", default="")
    parser.add_argument("--node-id", action="append", default=[], help="limit acceptance to this node UUID (repeatable)")
    parser.add_argument("--public-host", help="public control-plane host from which 6379/5432 must be closed")
    parser.add_argument(
        "--redis-url",
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--target", help="authorized passive web target for the cross-node scan")
    parser.add_argument("--authorized", action="store_true", help="confirm authorization to scan --target")
    parser.add_argument(
        "--scan-type",
        choices=["quick", "standard"],
        default="standard",
        help="passive acceptance scan depth (default: standard)",
    )
    parser.add_argument("--request-budget-mode", choices=["enforce", "off"], default="enforce")
    parser.add_argument("--fault-node-id", help="node UUID whose active worker will be killed during the scan")
    parser.add_argument("--fault-node-ssh", help="SSH [user@]host for --fault-node-id (BatchMode required)")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument(
        "--allow-local-build",
        action="store_true",
        help=(
            "allow one uniform shakerscan-fleet-local image for development acceptance; "
            "the receipt is not production release evidence"
        ),
    )
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
