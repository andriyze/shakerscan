#!/usr/bin/env python3
"""Host-local fleet agent for owned ShakerScan worker nodes.

The agent has two narrow responsibilities: reconcile this node's desired worker
count through the local Docker socket and report authenticated health to the
control plane. It never receives scan credentials through its API responses and
it never exposes an inbound management listener.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


AGENT_VERSION = "1"
DOCKER_SOCKET = "/var/run/docker.sock"


class AgentError(RuntimeError):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 30.0):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


class DockerClient:
    def __init__(self, socket_path: str = DOCKER_SOCKET):
        self.socket_path = socket_path

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        connection = UnixHTTPConnection(self.socket_path)
        encoded = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        headers = {"Content-Type": "application/json"} if encoded is not None else {}
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            data = response.read()
            parsed: Any = {}
            if data:
                try:
                    parsed = json.loads(data)
                except json.JSONDecodeError:
                    parsed = {"message": data.decode("utf-8", errors="replace")[:1000]}
            return response.status, parsed
        finally:
            connection.close()


def load_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise AgentError(f"fleet state file does not exist: {path}")
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise AgentError(f"fleet state file must be owner-only (mode 0600), found {mode:04o}")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AgentError(f"cannot read fleet state: {exc}") from exc
    required = (
        "node_id",
        "node_credential",
        "control_plane_overlay_url",
        "ca_cert_path",
        "worker_image_digest",
    )
    missing = [key for key in required if not str(state.get(key) or "").strip()]
    if missing:
        raise AgentError(f"fleet state is missing: {', '.join(missing)}")
    endpoint = urllib.parse.urlparse(str(state["control_plane_overlay_url"]))
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise AgentError("control_plane_overlay_url must be an HTTPS URL without embedded credentials")
    image_name, separator, digest = str(state["worker_image_digest"]).rpartition("@sha256:")
    if not separator or not image_name or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
        raise AgentError("worker_image_digest must be digest-pinned")
    return state


def _ssl_context(state: dict[str, Any]) -> ssl.SSLContext:
    ca_path = Path(str(state["ca_cert_path"]))
    if not ca_path.is_file():
        raise AgentError(f"fleet CA certificate does not exist: {ca_path}")
    return ssl.create_default_context(cafile=str(ca_path))


def api_request(
    state: dict[str, Any], method: str, path: str, payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    base = str(state["control_plane_overlay_url"]).rstrip("/")
    url = f"{base}{path}"
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {state['node_credential']}",
            "User-Agent": f"ShakerScan-Fleet-Agent/{AGENT_VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=_ssl_context(state)) as response:
            result = json.load(response)
            if not isinstance(result, dict):
                raise AgentError("control plane returned a non-object response")
            return result
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = str(json.load(exc).get("detail") or "")
        except Exception:
            pass
        raise AgentError(f"control plane returned HTTP {exc.code}: {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise AgentError(f"control plane request failed: {exc}") from exc


def _worker_filters(node_id: str) -> str:
    raw = json.dumps(
        {
            "label": [
                "com.docker.compose.service=worker",
                f"com.shakerscan.node_id={node_id}",
            ]
        },
        separators=(",", ":"),
    )
    return urllib.parse.quote(raw)


def worker_containers(client: DockerClient, node_id: str) -> list[dict[str, Any]]:
    status, payload = client.request("GET", f"/containers/json?all=true&filters={_worker_filters(node_id)}")
    if status != 200 or not isinstance(payload, list):
        raise AgentError(f"Docker worker listing failed with status {status}")
    return payload


def _safe_host_config(inspect: dict[str, Any]) -> dict[str, Any]:
    source = inspect.get("HostConfig") if isinstance(inspect.get("HostConfig"), dict) else {}
    allowed = (
        "Binds",
        "NetworkMode",
        "RestartPolicy",
        "Memory",
        "NanoCpus",
        "CpuShares",
        "Init",
        "ShmSize",
        "CapDrop",
        "SecurityOpt",
    )
    return {key: source[key] for key in allowed if key in source and source[key] is not None}


def _container_number(container: dict[str, Any]) -> int:
    labels = container.get("Labels") if isinstance(container.get("Labels"), dict) else {}
    try:
        return int(labels.get("com.docker.compose.container-number") or 0)
    except (TypeError, ValueError):
        return 0


def _clone_worker(client: DockerClient, template: dict[str, Any], number: int, node_id: str) -> None:
    template_id = str(template.get("Id") or "")
    status, inspect = client.request("GET", f"/containers/{template_id}/json")
    if status != 200 or not isinstance(inspect, dict):
        raise AgentError(f"Docker worker inspection failed with status {status}")
    config = inspect.get("Config") if isinstance(inspect.get("Config"), dict) else {}
    labels = dict(config.get("Labels") or {})
    labels.update(
        {
            "com.docker.compose.service": "worker",
            "com.docker.compose.oneoff": "False",
            "com.docker.compose.container-number": str(number),
            "com.shakerscan.node_id": node_id,
            "com.shakerscan.fleet_managed": "true",
        }
    )
    project = labels.get("com.docker.compose.project") or f"shakerscan-fleet-{node_id[:8]}"
    name = f"{project}-worker-{number}"
    body = {
        "Image": config.get("Image"),
        "Cmd": config.get("Cmd") or ["python3", "/app/worker.py"],
        "Env": config.get("Env") or [],
        "Labels": labels,
        "WorkingDir": config.get("WorkingDir") or "",
        "HostConfig": _safe_host_config(inspect),
    }
    if not body["Image"]:
        raise AgentError("worker template has no image")
    status, created = client.request("POST", f"/containers/create?name={urllib.parse.quote(name)}", body)
    if status != 201 or not isinstance(created, dict) or not created.get("Id"):
        message = created.get("message") if isinstance(created, dict) else ""
        raise AgentError(f"Docker worker create failed with status {status}: {message}")
    status, _ = client.request("POST", f"/containers/{created['Id']}/start")
    if status not in {204, 304}:
        client.request("DELETE", f"/containers/{created['Id']}?force=true")
        raise AgentError(f"Docker worker start failed with status {status}")


def reconcile_workers(client: DockerClient, *, node_id: str, desired_count: int) -> int:
    desired = max(0, min(128, int(desired_count)))
    containers = sorted(worker_containers(client, node_id), key=_container_number)
    running = [item for item in containers if item.get("State") == "running"]
    stopped = [item for item in containers if item.get("State") != "running"]

    if len(running) > desired:
        for item in reversed(running[desired:]):
            status, _ = client.request("POST", f"/containers/{item['Id']}/stop?t=30")
            if status not in {204, 304}:
                raise AgentError(f"Docker worker stop failed with status {status}")
        return desired

    needed = desired - len(running)
    for item in list(stopped):
        if needed <= 0:
            break
        status, _ = client.request("POST", f"/containers/{item['Id']}/start")
        if status not in {204, 304}:
            raise AgentError(f"Docker worker restart failed with status {status}")
        running.append(item)
        needed -= 1

    if needed > 0:
        templates = running or stopped
        if not templates:
            raise AgentError("no worker template exists; start the worker-only Compose project first")
        next_number = max((_container_number(item) for item in containers), default=0) + 1
        for offset in range(needed):
            _clone_worker(client, templates[0], next_number + offset, node_id)
    return desired


def host_capacity() -> dict[str, Any]:
    memory_bytes = None
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                memory_bytes = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError, IndexError):
        pass
    result: dict[str, Any] = {"cpu_count": os.cpu_count() or 1}
    if memory_bytes is not None:
        result["memory_bytes"] = memory_bytes
    try:
        stat = os.statvfs("/results")
        result["results_free_bytes"] = stat.f_bavail * stat.f_frsize
    except OSError:
        pass
    return result


def run_once(state: dict[str, Any], client: DockerClient) -> dict[str, Any]:
    node_id = str(state["node_id"])
    desired_state = api_request(state, "GET", f"/fleet/nodes/{node_id}/state")
    desired = 0 if desired_state.get("drain") else int(desired_state.get("desired_worker_count") or 0)
    desired_version = int(desired_state.get("desired_state_version") or 1)
    previously_applied_version = int(desired_state.get("applied_state_version") or 0)
    error: Exception | None = None
    try:
        reconcile_workers(client, node_id=node_id, desired_count=desired)
    except Exception as exc:
        error = exc
    try:
        containers = worker_containers(client, node_id)
        active = sum(1 for item in containers if item.get("State") == "running")
    except Exception:
        active = 0
    result = api_request(
        state,
        "POST",
        f"/fleet/nodes/{node_id}/heartbeat",
        {
            "active_worker_count": active,
            "capacity": host_capacity(),
            "build_fingerprint": state.get("build_fingerprint"),
            "active_worker_image_digest": state.get("worker_image_digest"),
            "agent_version": AGENT_VERSION,
            "applied_state_version": desired_version if error is None else previously_applied_version,
            "last_error": str(error)[:2000] if error is not None else None,
        },
    )
    if error is not None:
        raise AgentError(str(error)) from error
    return result


def run_forever(state_path: Path, interval_seconds: int) -> None:
    client = DockerClient()
    backoff = max(5, interval_seconds)
    while True:
        state = load_state(state_path)
        try:
            run_once(state, client)
            backoff = max(5, interval_seconds)
        except Exception as exc:
            # Never print the state or request payload; both contain the node credential.
            print(f"[fleet-agent] reconcile failed: {exc}", flush=True)
            backoff = min(max(10, backoff * 2), 300)
        time.sleep(backoff)


def main() -> int:
    parser = argparse.ArgumentParser(description="ShakerScan owned-fleet node agent")
    parser.add_argument("--state", default=os.environ.get("FLEET_STATE_PATH", "/run/shakerscan-fleet/state.json"))
    parser.add_argument("--interval", type=int, default=int(os.environ.get("FLEET_AGENT_INTERVAL_SECONDS", "30")))
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    state_path = Path(args.state)
    if args.once:
        result = run_once(load_state(state_path), DockerClient())
        print(json.dumps({"node_id": result.get("id"), "status": result.get("status")}, sort_keys=True))
        return 0
    run_forever(state_path, max(5, min(args.interval, 300)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
