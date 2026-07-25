#!/usr/bin/env python3
"""Host-side owned-fleet provisioning for ShakerScan.

This is intentionally a small Linux/WireGuard provisioner, not a general cloud
orchestrator. It keeps private material on the host, performs every privileged
change through explicit commands, and can reconcile repeatedly without rotating
the fleet identity.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Iterable


INTERFACE_NAME = "shakerscan"
DEFAULT_OVERLAY = "10.77.0.0/24"
DEFAULT_WG_PORT = 51820
DEFAULT_TLS_PORT = 8443
MAX_HTTP_BODY = 2 * 1024 * 1024
DIGEST_IMAGE_RE = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
URL_SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


class FleetCLIError(RuntimeError):
    pass


def fleet_operator_token(env: dict[str, str]) -> str:
    """Return the persisted operator token, creating a strong one when absent."""
    current = str(env.get("FLEET_OPERATOR_TOKEN") or "").strip()
    return current if len(current) >= 32 else secrets.token_urlsafe(48)


def fleet_datastore_credentials(env: dict[str, str]) -> dict[str, str]:
    """Return strong URL-safe credentials, preserving strong operator values."""
    current_postgres = str(env.get("POSTGRES_PASSWORD") or "").strip()
    current_redis = str(env.get("REDIS_PASSWORD") or "").strip()
    for key, current in (("POSTGRES_PASSWORD", current_postgres), ("REDIS_PASSWORD", current_redis)):
        if len(current) >= 32 and not URL_SAFE_SECRET_RE.fullmatch(current):
            raise FleetCLIError(f"{key} must use URL-safe unreserved characters for fleet mode")
    postgres_password = current_postgres if len(current_postgres) >= 32 else secrets.token_hex(32)
    redis_password = current_redis if len(current_redis) >= 32 else secrets.token_hex(32)
    return {
        "POSTGRES_PASSWORD": postgres_password,
        "REDIS_PASSWORD": redis_password,
    }


def rotate_postgres_password_if_running(password: str) -> None:
    """Rotate an initialized Compose role; new volumes consume the env directly."""
    compose = _docker_compose_command()
    running = _run([*compose, "ps", "-q", "postgres"], check=False)
    if running.returncode == 0 and running.stdout.strip():
        # fleet-generated passwords are hex, so the fixed SQL literal cannot be
        # escaped into another statement. The secret travels on stdin, not argv.
        _run(
            [*compose, "exec", "-T", "postgres", "psql", "-U", "scanner", "-d", "scanner", "-v", "ON_ERROR_STOP=1"],
            input_text=f"ALTER ROLE scanner PASSWORD '{password}';\n",
        )


@dataclass(frozen=True)
class RuntimePaths:
    root: Path

    @property
    def fleet(self) -> Path:
        return self.root / ".shakerscan-fleet"

    @property
    def control(self) -> Path:
        return self.fleet / "control"

    @property
    def node(self) -> Path:
        return self.fleet / "node"

    @property
    def dotenv(self) -> Path:
        return self.root / ".env"

    @property
    def worker_compose(self) -> Path:
        return self.root / "docker-compose.worker.yml"

    @property
    def broker_worker_compose(self) -> Path:
        return self.root / "docker-compose.broker-worker.yml"


def _run(
    argv: list[str],
    *,
    input_text: str | None = None,
    privileged: bool = False,
    check: bool = True,
    capture: bool = True,
) -> subprocess.CompletedProcess[str]:
    command = list(argv)
    if privileged and os.geteuid() != 0:
        if not shutil.which("sudo"):
            raise FleetCLIError(f"root authority is required to run: {' '.join(argv)}")
        command = ["sudo", *command]
    try:
        return subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=capture,
            check=check,
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()[-1000:]
        raise FleetCLIError(f"command failed ({' '.join(argv)}): {detail}") from exc
    except OSError as exc:
        raise FleetCLIError(f"cannot execute {argv[0]}: {exc}") from exc


def _require_linux() -> None:
    if sys.platform != "linux":
        raise FleetCLIError("built-in WireGuard fleet provisioning currently requires Linux")


def _require_commands(names: Iterable[str]) -> None:
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise FleetCLIError(
            "missing host dependencies: "
            + ", ".join(missing)
            + " (install wireguard-tools, iproute2, openssl, curl, and Docker Compose)"
        )


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def atomic_write(path: Path, content: str, mode: int) -> None:
    _ensure_private_dir(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    temp_path = Path(temp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        path.chmod(mode)
    finally:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass


def parse_duration(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smhd]?)", str(value or "").strip().lower())
    if not match:
        raise FleetCLIError("duration must look like 30m, 24h, or 7d")
    multiplier = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    seconds = int(match.group(1)) * multiplier
    if not 60 <= seconds <= 604_800:
        raise FleetCLIError("duration must be between 60 seconds and 7 days")
    return seconds


def validate_digest_image(value: str) -> str:
    candidate = str(value or "").strip()
    if not DIGEST_IMAGE_RE.fullmatch(candidate):
        raise FleetCLIError("worker image must be pinned as repository@sha256:<64 hex characters>")
    return candidate


def validate_https_url(value: str) -> str:
    candidate = str(value or "").strip().rstrip("/")
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise FleetCLIError("control-plane URL must be HTTPS and must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise FleetCLIError("control-plane URL must not contain a path, query, or fragment")
    return candidate


def validate_endpoint(value: str) -> tuple[str, int]:
    candidate = str(value or "").strip()
    if not candidate:
        raise FleetCLIError("WireGuard endpoint is required (for example fleet.example.com:51820)")
    parsed = urllib.parse.urlparse(f"//{candidate}")
    if not parsed.hostname or parsed.username or parsed.password or parsed.path not in {"", "/"}:
        raise FleetCLIError("WireGuard endpoint must be host:port")
    try:
        port = parsed.port
    except ValueError as exc:
        raise FleetCLIError("WireGuard endpoint has an invalid port") from exc
    if port is None or not 1 <= port <= 65535:
        raise FleetCLIError("WireGuard endpoint must include a port")
    host = parsed.hostname
    return (f"[{host}]:{port}" if ":" in host else f"{host}:{port}", port)


def parse_overlay(value: str) -> tuple[IPv4Network, IPv4Address]:
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise FleetCLIError("overlay must be a canonical IPv4 CIDR") from exc
    if not isinstance(network, IPv4Network) or network.num_addresses < 4 or network.num_addresses > 65_536:
        raise FleetCLIError("overlay must be an IPv4 network containing 4 to 65536 addresses")
    control_ip = next(network.hosts())
    return network, control_ip


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if ENV_KEY_RE.fullmatch(key.strip()):
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def update_dotenv(path: Path, updates: dict[str, str]) -> None:
    for key, value in updates.items():
        if not ENV_KEY_RE.fullmatch(key) or "\n" in value or "\r" in value:
            raise FleetCLIError(f"unsafe environment assignment for {key!r}")
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    remaining = dict(updates)
    output: list[str] = []
    for line in existing:
        if "=" in line:
            key = line.split("=", 1)[0].strip()
            if key in remaining:
                output.append(f"{key}={remaining.pop(key)}")
                continue
        output.append(line)
    if output and output[-1] != "":
        output.append("")
    output.extend(f"{key}={value}" for key, value in remaining.items())
    atomic_write(path, "\n".join(output).rstrip() + "\n", 0o600)


def api_json(
    base_url: str,
    method: str,
    path: str,
    *,
    payload: dict[str, Any] | None = None,
    bearer: str | None = None,
    ca_file: Path | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, method=method, data=data, headers=headers)
    context = ssl.create_default_context(cafile=str(ca_file)) if ca_file else ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            raw = response.read(MAX_HTTP_BODY + 1)
            if len(raw) > MAX_HTTP_BODY:
                raise FleetCLIError("control plane response exceeded 2 MiB")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise FleetCLIError("control plane returned a non-object response")
            return result
    except urllib.error.HTTPError as exc:
        raw = exc.read(64 * 1024)
        try:
            detail = json.loads(raw).get("detail")
        except Exception:
            detail = raw.decode("utf-8", errors="replace")[:500]
        raise FleetCLIError(f"control plane returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, json.JSONDecodeError) as exc:
        raise FleetCLIError(f"control plane request failed: {exc}") from exc


def generate_wireguard_keypair(private_path: Path, public_path: Path) -> tuple[str, str]:
    if private_path.exists() and public_path.exists():
        private = private_path.read_text(encoding="utf-8").strip()
        public = public_path.read_text(encoding="utf-8").strip()
    else:
        private = _run(["wg", "genkey"]).stdout.strip()
        public = _run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
        atomic_write(private_path, private + "\n", 0o600)
        atomic_write(public_path, public + "\n", 0o644)
    for label, value in (("private", private), ("public", public)):
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as exc:
            raise FleetCLIError(f"stored WireGuard {label} key is invalid") from exc
        if len(decoded) != 32:
            raise FleetCLIError(f"stored WireGuard {label} key is invalid")
    return private, public


def generate_control_certificates(control_dir: Path, control_ip: str) -> None:
    ca_key = control_dir / "ca.key"
    ca_cert = control_dir / "ca.crt"
    server_key = control_dir / "server.key"
    server_cert = control_dir / "server.crt"
    if all(path.exists() for path in (ca_key, ca_cert, server_key, server_cert)):
        verify = _run(["openssl", "x509", "-in", str(server_cert), "-noout", "-checkend", "86400"], check=False)
        if verify.returncode != 0:
            raise FleetCLIError("fleet TLS certificate expires within 24 hours; rotate it before continuing")
        return
    with tempfile.TemporaryDirectory(prefix="shakerscan-fleet-cert-") as temp:
        temp_dir = Path(temp)
        csr = temp_dir / "server.csr"
        extensions = temp_dir / "server.ext"
        atomic_write(
            extensions,
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage=serverAuth\nsubjectAltName=IP:{control_ip}\n",
            0o600,
        )
        _run([
            "openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
            "-subj", "/CN=ShakerScan Fleet CA", "-keyout", str(ca_key), "-out", str(ca_cert),
        ])
        _run([
            "openssl", "req", "-newkey", "rsa:3072", "-nodes", "-sha256",
            "-subj", f"/CN={control_ip}", "-keyout", str(server_key), "-out", str(csr),
        ])
        _run([
            "openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
            "-CAcreateserial", "-days", "825", "-sha256", "-extfile", str(extensions), "-out", str(server_cert),
        ])
    ca_key.chmod(0o600)
    server_key.chmod(0o600)
    ca_cert.chmod(0o644)
    server_cert.chmod(0o644)


def render_control_wireguard(
    *, private_key: str, control_ip: str, prefix_length: int, listen_port: int, peers: list[dict[str, str]]
) -> str:
    lines = [
        "# Managed by ShakerScan. Re-run `shakerscan fleet reconcile` after manual database repair.",
        "[Interface]",
        f"Address = {control_ip}/{prefix_length}",
        f"ListenPort = {listen_port}",
        f"PrivateKey = {private_key}",
        "SaveConfig = false",
    ]
    for peer in sorted(peers, key=lambda item: item["overlay_ip"]):
        lines.extend([
            "",
            f"# node_id={peer['node_id']}",
            "[Peer]",
            f"PublicKey = {peer['public_key']}",
            f"AllowedIPs = {peer['overlay_ip']}/32",
        ])
    return "\n".join(lines) + "\n"


def render_worker_wireguard(
    *, private_key: str, peer_ip: str, overlay_cidr: str, control_public_key: str, endpoint: str
) -> str:
    network = ip_network(overlay_cidr, strict=True)
    address = ip_address(peer_ip)
    if address not in network or address in {network.network_address, network.broadcast_address}:
        raise FleetCLIError("control plane assigned an invalid WireGuard peer address")
    return (
        "# Managed by ShakerScan.\n"
        "[Interface]\n"
        f"Address = {address}/{network.prefixlen}\n"
        f"PrivateKey = {private_key}\n"
        "SaveConfig = false\n\n"
        "[Peer]\n"
        f"PublicKey = {control_public_key}\n"
        f"Endpoint = {endpoint}\n"
        f"AllowedIPs = {network}\n"
        "PersistentKeepalive = 25\n"
    )


def install_wireguard(config_path: Path) -> None:
    _run(["install", "-d", "-m", "700", "/etc/wireguard"], privileged=True, capture=False)
    _run(
        ["install", "-m", "600", str(config_path), f"/etc/wireguard/{INTERFACE_NAME}.conf"],
        privileged=True,
        capture=False,
    )
    exists = _run(["ip", "link", "show", INTERFACE_NAME], check=False)
    if exists.returncode == 0:
        stripped = _run(["wg-quick", "strip", f"/etc/wireguard/{INTERFACE_NAME}.conf"], privileged=True).stdout
        _run(["wg", "syncconf", INTERFACE_NAME, "/dev/stdin"], input_text=stripped, privileged=True, capture=False)
    else:
        _run(["wg-quick", "up", INTERFACE_NAME], privileged=True, capture=False)


def _docker_compose_command() -> list[str]:
    if shutil.which("docker") and _run(["docker", "compose", "version"], check=False).returncode == 0:
        return ["docker", "compose"]
    if shutil.which("docker-compose"):
        return ["docker-compose"]
    raise FleetCLIError("Docker Compose is required")


def _discover_digest_image(env: dict[str, str]) -> str:
    explicit = env.get("FLEET_WORKER_IMAGE_DIGEST", "")
    if explicit:
        return validate_digest_image(explicit)
    repository = env.get("SCANNER_IMAGE_REPO", "shakerscan/shakerscan-scanner")
    tag = env.get("SCANNER_IMAGE_TAG", "latest")
    inspected = _run(["docker", "image", "inspect", f"{repository}:{tag}", "--format", "{{json .RepoDigests}}"], check=False)
    if inspected.returncode == 0:
        try:
            digests = json.loads(inspected.stdout)
        except json.JSONDecodeError:
            digests = []
        for digest in digests or []:
            if DIGEST_IMAGE_RE.fullmatch(str(digest)):
                return str(digest)
    raise FleetCLIError("cannot derive a pinned worker image; pass --worker-image repository@sha256:...")


def _connection_bundle(control_ip: str, env: dict[str, str]) -> dict[str, Any]:
    worker_environment: dict[str, str] = {}
    evidence_keys = (
        "EVIDENCE_STORAGE_BACKEND",
        "EVIDENCE_S3_ENDPOINT_URL",
        "EVIDENCE_S3_BUCKET",
        "EVIDENCE_S3_REGION",
        "EVIDENCE_S3_ACCESS_KEY_ID",
        "EVIDENCE_S3_SECRET_ACCESS_KEY",
        "EVIDENCE_S3_SESSION_TOKEN",
        "EVIDENCE_S3_FORCE_PATH_STYLE",
        "ARTIFACT_STORAGE_BACKEND",
        "ARTIFACT_S3_ENDPOINT_URL",
        "ARTIFACT_S3_BUCKET",
        "ARTIFACT_S3_REGION",
        "ARTIFACT_S3_ACCESS_KEY_ID",
        "ARTIFACT_S3_SECRET_ACCESS_KEY",
        "ARTIFACT_S3_SESSION_TOKEN",
        "ARTIFACT_S3_FORCE_PATH_STYLE",
        "ARTIFACT_S3_PREFIX",
        "ARTIFACT_RETENTION_DAYS",
        "ARTIFACT_RETENTION_RESULT_DAYS",
        "ARTIFACT_RETENTION_CHECKPOINT_DAYS",
        "ARTIFACT_RETENTION_DIAGNOSTIC_DAYS",
        "ARTIFACT_RETENTION_SCREENSHOT_DAYS",
        "ARTIFACT_RETENTION_ATTACHMENT_DAYS",
    )
    for key in evidence_keys:
        if env.get(key):
            worker_environment[key] = env[key]
    redis_password = urllib.parse.quote(str(env.get("REDIS_PASSWORD") or ""), safe="")
    postgres_password = urllib.parse.quote(str(env.get("POSTGRES_PASSWORD") or ""), safe="")
    if not redis_password or not postgres_password:
        raise FleetCLIError("fleet datastore credentials are missing")
    return {
        "redis_url": f"redis://:{redis_password}@{control_ip}:6379",
        "database_url": f"postgresql://scanner:{postgres_password}@{control_ip}:5432/scanner",
        "worker_environment": worker_environment,
    }


def _fleet_artifact_environment(control_ip: str, env: dict[str, str]) -> tuple[dict[str, str], bool]:
    """Resolve external S3 settings or provision the bundled private MinIO."""
    backend = str(
        env.get("ARTIFACT_STORAGE_BACKEND")
        or env.get("EVIDENCE_STORAGE_BACKEND")
        or ""
    ).strip().lower()
    bucket = str(env.get("ARTIFACT_S3_BUCKET") or env.get("EVIDENCE_S3_BUCKET") or "").strip()
    access_key = str(
        env.get("ARTIFACT_S3_ACCESS_KEY_ID")
        or env.get("EVIDENCE_S3_ACCESS_KEY_ID")
        or env.get("AWS_ACCESS_KEY_ID")
        or ""
    ).strip()
    secret_key = str(
        env.get("ARTIFACT_S3_SECRET_ACCESS_KEY")
        or env.get("EVIDENCE_S3_SECRET_ACCESS_KEY")
        or env.get("AWS_SECRET_ACCESS_KEY")
        or ""
    )
    if backend in {"s3", "minio", "s3-compatible", "s3_compatible"} and bucket and access_key and secret_key:
        return {"ARTIFACT_STORAGE_REQUIRED": "true"}, False

    minio_user = str(env.get("MINIO_ROOT_USER") or f"ss-{secrets.token_hex(8)}")
    minio_password = str(env.get("MINIO_ROOT_PASSWORD") or secrets.token_urlsafe(36))
    minio_bucket = str(env.get("EVIDENCE_S3_BUCKET") or "shakerscan-artifacts")
    endpoint = f"http://{control_ip}:9000"
    return {
        "MINIO_ROOT_USER": minio_user,
        "MINIO_ROOT_PASSWORD": minio_password,
        "EVIDENCE_STORAGE_BACKEND": "s3",
        "EVIDENCE_S3_ENDPOINT_URL": endpoint,
        "EVIDENCE_S3_BUCKET": minio_bucket,
        "EVIDENCE_S3_REGION": "us-east-1",
        "EVIDENCE_S3_ACCESS_KEY_ID": minio_user,
        "EVIDENCE_S3_SECRET_ACCESS_KEY": minio_password,
        "EVIDENCE_S3_FORCE_PATH_STYLE": "true",
        "ARTIFACT_STORAGE_BACKEND": "s3",
        "ARTIFACT_STORAGE_REQUIRED": "true",
        "ARTIFACT_S3_PREFIX": "scan-artifacts",
    }, True


def _install_reconcile_timer(paths: RuntimePaths) -> None:
    if not shutil.which("systemctl") or not Path("/run/systemd/system").is_dir():
        raise FleetCLIError("fleet control mode requires systemd for automatic WireGuard peer reconciliation")
    python = shutil.which("python3") or sys.executable
    script = Path(__file__).resolve()
    service = paths.control / "shakerscan-fleet-reconcile.service"
    timer = paths.control / "shakerscan-fleet-reconcile.timer"
    quoted_python = str(python).replace('"', '\\"')
    quoted_script = str(script).replace('"', '\\"')
    quoted_runtime = str(paths.root).replace('"', '\\"')
    atomic_write(
        service,
        "[Unit]\nDescription=Reconcile ShakerScan WireGuard fleet peers\nAfter=network-online.target\n\n"
        "[Service]\nType=oneshot\n"
        f'ExecStart="{quoted_python}" "{quoted_script}" --runtime "{quoted_runtime}" reconcile\n'
        "NoNewPrivileges=true\nPrivateTmp=true\nProtectHome=read-only\nProtectSystem=strict\n"
        f'ReadWritePaths="{quoted_runtime}/.shakerscan-fleet/control" /etc/wireguard\n',
        0o644,
    )
    atomic_write(
        timer,
        "[Unit]\nDescription=Continuously reconcile ShakerScan WireGuard fleet peers\n\n"
        "[Timer]\nOnBootSec=10s\nOnUnitActiveSec=10s\nAccuracySec=1s\nPersistent=true\n\n"
        "[Install]\nWantedBy=timers.target\n",
        0o644,
    )
    for source in (service, timer):
        _run(["install", "-m", "644", str(source), f"/etc/systemd/system/{source.name}"], privileged=True, capture=False)
    _run(["systemctl", "daemon-reload"], privileged=True, capture=False)
    _run(["systemctl", "enable", "--now", timer.name], privileged=True, capture=False)


def command_init(paths: RuntimePaths, args: argparse.Namespace) -> None:
    _require_linux()
    if getattr(args, "network", "wireguard") == "broker":
        _require_commands(("docker",))
        _docker_compose_command()
        public_url = validate_https_url(args.public_url)
        if not 1 <= args.workers <= 128:
            raise FleetCLIError("--workers must be between 1 and 128")
        if not args.skip_public_check:
            health = api_json(public_url, "GET", "/health", timeout=10)
            if health.get("status") != "healthy":
                raise FleetCLIError("public HTTPS API did not report healthy")
        env = load_dotenv(paths.dotenv)
        if env.get("FLEET_ALLOW_INSECURE_ENROLLMENT", "").lower() in {"1", "true", "yes", "on"}:
            raise FleetCLIError("production fleet init refuses FLEET_ALLOW_INSECURE_ENROLLMENT")
        worker_image = validate_digest_image(args.worker_image) if args.worker_image else _discover_digest_image(env)
        operator_token = fleet_operator_token(env)
        profiles = {item.strip() for item in env.get("COMPOSE_PROFILES", "").split(",") if item.strip()}
        artifact_updates, bundled_minio = _fleet_artifact_environment("127.0.0.1", env)
        if bundled_minio:
            profiles.add("artifacts")
        update_dotenv(paths.dotenv, {
            "COMPOSE_PROFILES": ",".join(sorted(profiles)),
            "FLEET_NETWORK_BACKEND": "broker",
            "FLEET_WORKER_IMAGE_DIGEST": worker_image,
            "FLEET_DESIRED_WORKER_COUNT": str(args.workers),
            "FLEET_PUBLIC_URL": public_url,
            "FLEET_ALLOW_INSECURE_ENROLLMENT": "false",
            "FLEET_OPERATOR_TOKEN": operator_token,
            **artifact_updates,
        })
        scanner = paths.root / "scanner.sh"
        if not scanner.is_file():
            raise FleetCLIError("scanner.sh is missing from the runtime")
        _run([str(scanner), "restart"], capture=False)
        health = api_json(public_url, "GET", "/health", timeout=30)
        if health.get("status") != "healthy":
            raise FleetCLIError("public HTTPS broker API did not report healthy after restart")
        artifact_health = api_json(
            "http://127.0.0.1:8080",
            "GET",
            "/artifacts/storage/health?probe=true",
            timeout=15,
        )
        if artifact_health.get("status") != "ok":
            raise FleetCLIError("artifact store write probe did not pass")
        print(f"HTTPS broker control plane initialized: {public_url}")
        print("Next: shakerscan fleet join-token --ttl 24h --transport broker")
        return
    _require_commands(("wg", "wg-quick", "ip", "openssl", "docker"))
    _docker_compose_command()
    network, control_ip = parse_overlay(args.overlay)
    if not args.endpoint:
        raise FleetCLIError("--endpoint is required for WireGuard fleet init")
    endpoint, listen_port = validate_endpoint(args.endpoint)
    if listen_port != args.listen_port:
        raise FleetCLIError("--endpoint port and --listen-port must match")
    public_url = validate_https_url(args.public_url)
    if not 1 <= args.tls_port <= 65535:
        raise FleetCLIError("--tls-port must be between 1 and 65535")
    if not 1 <= args.workers <= 128:
        raise FleetCLIError("--workers must be between 1 and 128")
    if not args.skip_public_check:
        health = api_json(public_url, "GET", "/health", timeout=10)
        if health.get("status") != "healthy":
            raise FleetCLIError("public HTTPS API did not report healthy")
    env = load_dotenv(paths.dotenv)
    if env.get("FLEET_OVERLAY_CIDR") and env["FLEET_OVERLAY_CIDR"] != str(network):
        raise FleetCLIError("refusing to change the overlay CIDR of an existing fleet identity")
    if env.get("FLEET_ALLOW_INSECURE_ENROLLMENT", "").lower() in {"1", "true", "yes", "on"}:
        raise FleetCLIError("production fleet init refuses FLEET_ALLOW_INSECURE_ENROLLMENT")
    worker_image = validate_digest_image(args.worker_image) if args.worker_image else _discover_digest_image(env)
    operator_token = fleet_operator_token(env)
    datastore_updates = fleet_datastore_credentials(env)
    _ensure_private_dir(paths.control)
    private_key, public_key = generate_wireguard_keypair(
        paths.control / "wireguard.key", paths.control / "wireguard.pub"
    )
    generate_control_certificates(paths.control, str(control_ip))
    wg_config = render_control_wireguard(
        private_key=private_key,
        control_ip=str(control_ip),
        prefix_length=network.prefixlen,
        listen_port=args.listen_port,
        peers=[],
    )
    atomic_write(paths.control / f"{INTERFACE_NAME}.conf", wg_config, 0o600)
    profiles = {item.strip() for item in env.get("COMPOSE_PROFILES", "").split(",") if item.strip()}
    profiles.add("fleet")
    artifact_updates, bundled_minio = _fleet_artifact_environment(str(control_ip), env)
    if bundled_minio:
        profiles.add("artifacts")
    effective_env = {**env, **artifact_updates, **datastore_updates}
    bundle = _connection_bundle(str(control_ip), effective_env)
    atomic_write(
        paths.control / "connection-bundle.json",
        json.dumps(bundle, separators=(",", ":"), sort_keys=True) + "\n",
        0o600,
    )
    updates = {
        "COMPOSE_PROFILES": ",".join(sorted(profiles)),
        "SHAKERSCAN_DATA_BIND_HOST": str(control_ip),
        "FLEET_NETWORK_BACKEND": "wireguard",
        "FLEET_INTERFACE": INTERFACE_NAME,
        "FLEET_OVERLAY_CIDR": str(network),
        "FLEET_CONTROL_PLANE_OVERLAY_URL": f"https://{control_ip}:{args.tls_port}",
        "FLEET_WIREGUARD_PUBLIC_KEY": public_key,
        "FLEET_WIREGUARD_ENDPOINT": endpoint,
        "FLEET_WORKER_IMAGE_DIGEST": worker_image,
        "FLEET_DESIRED_WORKER_COUNT": str(args.workers),
        "FLEET_TLS_PORT": str(args.tls_port),
        "FLEET_PUBLIC_URL": public_url,
        "FLEET_ALLOW_INSECURE_ENROLLMENT": "false",
        "FLEET_OPERATOR_TOKEN": operator_token,
        "FLEET_CONNECTION_BUNDLE_PATH": "/run/shakerscan-fleet/control/connection-bundle.json",
        "FLEET_CONNECTION_BUNDLE_JSON": "",
        **datastore_updates,
        **artifact_updates,
    }
    update_dotenv(paths.dotenv, updates)
    install_wireguard(paths.control / f"{INTERFACE_NAME}.conf")
    if args.no_reconcile_service:
        print("Automatic peer reconciliation skipped; run `shakerscan fleet reconcile` after each join")
    else:
        _install_reconcile_timer(paths)
    scanner = paths.root / "scanner.sh"
    if not scanner.is_file():
        raise FleetCLIError("scanner.sh is missing from the runtime")
    if datastore_updates["POSTGRES_PASSWORD"] != str(env.get("POSTGRES_PASSWORD") or "").strip():
        rotate_postgres_password_if_running(datastore_updates["POSTGRES_PASSWORD"])
    _run([str(scanner), "restart"], capture=False)
    deadline = time.monotonic() + 90
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = api_json(
                f"https://{control_ip}:{args.tls_port}",
                "GET",
                "/health",
                ca_file=paths.control / "ca.crt",
                timeout=5,
            )
            if result.get("status") == "healthy":
                artifact_health = api_json(
                    f"https://{control_ip}:{args.tls_port}",
                    "GET",
                    "/artifacts/storage/health?probe=true",
                    ca_file=paths.control / "ca.crt",
                    timeout=10,
                )
                if artifact_health.get("status") != "ok":
                    raise FleetCLIError("artifact store write probe did not pass")
                print(f"Fleet control plane initialized on {network}")
                print(f"Private fleet API: https://{control_ip}:{args.tls_port}")
                print(f"Public enrollment API: {public_url}")
                print(f"Ensure inbound UDP {args.listen_port} reaches this host")
                print("Next: shakerscan fleet join-token --ttl 24h")
                return
        except FleetCLIError as exc:
            last_error = exc
        time.sleep(2)
    raise FleetCLIError(f"fleet TLS edge did not become healthy: {last_error}")


def command_join_token(paths: RuntimePaths, args: argparse.Namespace) -> None:
    ttl_seconds = parse_duration(args.ttl)
    env = load_dotenv(paths.dotenv)
    public_url = validate_https_url(args.public_url or env.get("FLEET_PUBLIC_URL", ""))
    result = api_json(
        args.local_api.rstrip("/"),
        "POST",
        "/fleet/join-tokens",
        payload={"role": "worker", "ttl_seconds": ttl_seconds},
        bearer=env.get("FLEET_OPERATOR_TOKEN"),
    )
    token = str(result.get("token") or "")
    if not token.startswith("ssj_"):
        raise FleetCLIError("control plane did not return a join token")
    print("Single-use join token created. Run on the worker VPS:")
    transport_flag = " --transport broker" if getattr(args, "transport", "overlay") == "broker" else ""
    print(f"shakerscan join {public_url} --token {token}{transport_flag}")
    print(f"Expires: {result.get('expires_at')}")


def _read_node_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FleetCLIError("node state does not exist")
    if path.stat().st_mode & 0o077:
        raise FleetCLIError("node state must be owner-only (0600)")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FleetCLIError(f"cannot read node state: {exc}") from exc
    if not isinstance(state, dict):
        raise FleetCLIError("node state is invalid")
    return state


def _validated_join_response(result: dict[str, Any]) -> dict[str, Any]:
    required = (
        "node_id",
        "node_credential",
        "control_plane_overlay_url",
        "wireguard_overlay_cidr",
        "wireguard_peer_ip",
        "wireguard_control_plane_public_key",
        "wireguard_control_plane_endpoint",
        "worker_image_digest",
        "fleet_ca_certificate_pem",
    )
    missing = [key for key in required if not str(result.get(key) or "").strip()]
    if missing:
        raise FleetCLIError("enrollment response is missing: " + ", ".join(missing))
    try:
        result["node_id"] = str(uuid.UUID(str(result["node_id"])))
    except ValueError as exc:
        raise FleetCLIError("enrollment response contains an invalid node ID") from exc
    validate_https_url(str(result["control_plane_overlay_url"]))
    validate_digest_image(str(result["worker_image_digest"]))
    validate_endpoint(str(result["wireguard_control_plane_endpoint"]))
    network, _ = parse_overlay(str(result["wireguard_overlay_cidr"]))
    try:
        peer_ip = ip_address(str(result["wireguard_peer_ip"]))
    except ValueError as exc:
        raise FleetCLIError("enrollment response contains an invalid peer address") from exc
    if peer_ip not in network:
        raise FleetCLIError("enrollment peer address is outside the overlay")
    for key in ("wireguard_control_plane_public_key",):
        try:
            decoded = base64.b64decode(str(result[key]), validate=True)
        except Exception as exc:
            raise FleetCLIError("enrollment response contains an invalid WireGuard key") from exc
        if len(decoded) != 32:
            raise FleetCLIError("enrollment response contains an invalid WireGuard key")
    certificate = str(result["fleet_ca_certificate_pem"])
    if "-----BEGIN CERTIFICATE-----" not in certificate or len(certificate) > 64 * 1024:
        raise FleetCLIError("enrollment response contains an invalid fleet CA")
    return result


def _validated_broker_join_response(result: dict[str, Any]) -> dict[str, Any]:
    required = ("node_id", "node_credential", "worker_image_digest")
    missing = [key for key in required if not str(result.get(key) or "").strip()]
    if missing:
        raise FleetCLIError("broker enrollment response is missing: " + ", ".join(missing))
    try:
        result["node_id"] = str(uuid.UUID(str(result["node_id"])))
    except ValueError as exc:
        raise FleetCLIError("broker enrollment response contains an invalid node ID") from exc
    validate_digest_image(str(result["worker_image_digest"]))
    if str(result.get("transport") or "") != "broker":
        raise FleetCLIError("control plane did not enroll a broker node")
    return result


def _write_worker_environment(
    path: Path,
    bundle: dict[str, Any],
    *,
    labels: dict[str, Any] | None = None,
) -> None:
    redis_url = str(bundle.get("redis_url") or "").strip()
    database_url = str(bundle.get("database_url") or "").strip()
    if not redis_url.startswith("redis://") or not database_url.startswith(("postgresql://", "postgres://")):
        raise FleetCLIError("connection bundle is missing private Redis/Postgres URLs")
    values = {
        "REDIS_URL": redis_url,
        "DATABASE_URL": database_url,
        "RESULTS_DIR": "/results",
    }
    if labels:
        encoded_labels = json.dumps(labels, sort_keys=True, separators=(",", ":"))
        if len(encoded_labels.encode("utf-8")) > 8192:
            raise FleetCLIError("node labels exceed 8192 bytes")
        values["SHAKERSCAN_NODE_LABELS_JSON"] = encoded_labels
    extra = bundle.get("worker_environment") or {}
    if not isinstance(extra, dict):
        raise FleetCLIError("connection bundle worker_environment must be an object")
    for key, value in extra.items():
        if not ENV_KEY_RE.fullmatch(str(key)) or any(ch in str(value) for ch in "\r\n"):
            raise FleetCLIError("connection bundle contains an unsafe worker environment entry")
        values[str(key)] = str(value)
    atomic_write(path, "".join(f"{key}={value}\n" for key, value in sorted(values.items())), 0o600)


def _worker_compose_env(paths: RuntimePaths, response: dict[str, Any]) -> dict[str, str]:
    return {
        "FLEET_COMPOSE_PROJECT_NAME": f"shakerscan-fleet-{str(response['node_id'])[:8]}",
        "FLEET_NODE_ID": str(response["node_id"]),
        "FLEET_WORKER_IMAGE": str(response["worker_image_digest"]),
        "FLEET_WORKER_ENV_FILE": str(paths.node / "worker.env"),
        "FLEET_RUNTIME_DIR": str(paths.node),
        "FLEET_RESULTS_DIR": str(paths.root / "results"),
    }


def _write_compose_env(path: Path, values: dict[str, str]) -> None:
    for value in values.values():
        if any(ch in value for ch in "\r\n"):
            raise FleetCLIError("unsafe Compose environment value")
    atomic_write(path, "".join(f"{key}={value}\n" for key, value in sorted(values.items())), 0o600)


def _start_worker_runtime(paths: RuntimePaths, response: dict[str, Any]) -> None:
    if not paths.worker_compose.is_file():
        raise FleetCLIError("docker-compose.worker.yml is missing from the runtime")
    compose = _docker_compose_command()
    compose_env = paths.node / "compose.env"
    _write_compose_env(compose_env, _worker_compose_env(paths, response))
    image = validate_digest_image(str(response["worker_image_digest"]))
    _run(["docker", "pull", image], capture=False)
    _run(
        [*compose, "--env-file", str(compose_env), "-f", str(paths.worker_compose), "up", "-d"],
        capture=False,
    )


def _start_broker_runtime(paths: RuntimePaths, response: dict[str, Any]) -> None:
    if not paths.broker_worker_compose.is_file():
        raise FleetCLIError("docker-compose.broker-worker.yml is missing from the runtime")
    compose = _docker_compose_command()
    compose_env = paths.node / "compose.env"
    _write_compose_env(compose_env, _worker_compose_env(paths, response))
    image = validate_digest_image(str(response["worker_image_digest"]))
    _run(["docker", "pull", image], capture=False)
    _run(
        [*compose, "--env-file", str(compose_env), "-f", str(paths.broker_worker_compose), "up", "-d"],
        capture=False,
    )


def command_join(paths: RuntimePaths, args: argparse.Namespace) -> None:
    _require_linux()
    transport = str(getattr(args, "transport", "overlay") or "overlay")
    _require_commands(("docker",) if transport == "broker" else ("wg", "wg-quick", "ip", "docker"))
    _docker_compose_command()
    public_url = validate_https_url(args.control_plane_url)
    _ensure_private_dir(paths.node)
    state_path = paths.node / "state.json"
    if state_path.exists():
        state = _read_node_state(state_path)
        if str(state.get("enrollment_url") or "") != public_url:
            raise FleetCLIError("this host is already joined to a different control plane")
        state_transport = str(state.get("transport") or "overlay")
        if state_transport != transport:
            raise FleetCLIError(f"this host is already joined with {state_transport} transport")
        response = (
            _validated_broker_join_response(dict(state["bootstrap"]))
            if transport == "broker"
            else _validated_join_response(dict(state["bootstrap"]))
        )
        if transport == "broker":
            _start_broker_runtime(paths, response)
            print(f"HTTPS broker node {response['node_id']} resumed")
            return
        install_wireguard(paths.node / f"{INTERFACE_NAME}.conf")
        if not (paths.node / "worker.env").exists():
            raise FleetCLIError("existing node state has no worker environment; rotate/reset the node on the control plane")
        bootstrap_labels = response.get("labels") if isinstance(response.get("labels"), dict) else {}
        if bootstrap_labels:
            update_dotenv(
                paths.node / "worker.env",
                {
                    "SHAKERSCAN_NODE_LABELS_JSON": json.dumps(
                        bootstrap_labels,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                },
            )
        _start_worker_runtime(paths, response)
        print(f"Fleet node {response['node_id']} resumed")
        return
    if not args.token or not str(args.token).startswith("ssj_"):
        raise FleetCLIError("--token must contain the single-use ssj_ join token")
    private_key = public_key = None
    if transport == "overlay":
        private_key, public_key = generate_wireguard_keypair(
            paths.node / "wireguard.key", paths.node / "wireguard.pub"
        )
    hostname = socket.gethostname()[:255]
    labels: dict[str, Any] = {}
    labels["transport"] = transport
    if getattr(args, "region", None):
        labels["region"] = args.region
    for key, value in (
        ("egress_group", getattr(args, "egress_group", None)),
        ("network", getattr(args, "network_label", None)),
        ("data_residency", getattr(args, "data_residency", None)),
    ):
        if value:
            labels[key] = str(value).strip()
    capabilities = [str(item).strip().lower() for item in (getattr(args, "capability", None) or []) if str(item).strip()]
    if capabilities:
        labels["tools"] = sorted(set(capabilities))
    scan_tiers = [str(item).strip().lower() for item in (getattr(args, "scan_tier", None) or []) if str(item).strip()]
    if scan_tiers:
        labels["scan_tiers"] = sorted(set(scan_tiers))
    for raw_label in getattr(args, "label", None) or []:
        key, separator, value = str(raw_label).partition("=")
        key = key.strip().lower()
        value = value.strip()
        if not separator or not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", key) or not value:
            raise FleetCLIError("--label must use key=value with a safe lowercase key")
        if key in {"node_id"}:
            raise FleetCLIError("node_id is assigned by the control plane")
        labels[key] = value[:256]
    payload = {
        "token": args.token,
        "name": args.name or hostname,
        "hostname": hostname,
        "region": args.region,
        "transport": transport,
        "wireguard_public_key": public_key,
        "labels": labels,
        "capacity": {"cpu_count": os.cpu_count() or 1},
    }
    raw_response = api_json(public_url, "POST", "/fleet/nodes/join", payload=payload, timeout=30)
    response = (
        _validated_broker_join_response(raw_response)
        if transport == "broker"
        else _validated_join_response(raw_response)
    )
    if transport == "broker":
        bootstrap_state = {
            "node_id": response["node_id"],
            "node_credential": response["node_credential"],
            "control_plane_url": public_url,
            "worker_image_digest": response["worker_image_digest"],
            "transport": "broker",
            "enrollment_url": public_url,
            "bootstrap": response,
        }
        atomic_write(state_path, json.dumps(bootstrap_state, sort_keys=True, indent=2) + "\n", 0o600)
        _start_broker_runtime(paths, response)
        print(f"Joined fleet as outbound-only HTTPS broker node {response['node_id']}")
        print("No Redis or PostgreSQL credentials were installed")
        return
    ca_path = paths.node / "ca.crt"
    atomic_write(ca_path, str(response["fleet_ca_certificate_pem"]), 0o644)
    wireguard = render_worker_wireguard(
        private_key=private_key,
        peer_ip=str(response["wireguard_peer_ip"]),
        overlay_cidr=str(response["wireguard_overlay_cidr"]),
        control_public_key=str(response["wireguard_control_plane_public_key"]),
        endpoint=str(response["wireguard_control_plane_endpoint"]),
    )
    wg_path = paths.node / f"{INTERFACE_NAME}.conf"
    atomic_write(wg_path, wireguard, 0o600)
    bootstrap_state = {
        "node_id": response["node_id"],
        "node_credential": response["node_credential"],
        "control_plane_overlay_url": response["control_plane_overlay_url"],
        "ca_cert_path": "/run/shakerscan-fleet/ca.crt",
        "worker_image_digest": response["worker_image_digest"],
        "transport": "overlay",
        "enrollment_url": public_url,
        "bootstrap": response,
    }
    atomic_write(state_path, json.dumps(bootstrap_state, sort_keys=True, indent=2) + "\n", 0o600)
    install_wireguard(wg_path)
    overlay_url = str(response["control_plane_overlay_url"])
    deadline = time.monotonic() + args.overlay_timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            health = api_json(overlay_url, "GET", "/health", ca_file=ca_path, timeout=5)
            if health.get("status") == "healthy":
                break
        except FleetCLIError as exc:
            last_error = exc
        time.sleep(2)
    else:
        raise FleetCLIError(f"WireGuard overlay did not become ready: {last_error}")
    bundle_response = api_json(
        overlay_url,
        "POST",
        f"/fleet/nodes/{response['node_id']}/connection-bundle",
        bearer=str(response["node_credential"]),
        ca_file=ca_path,
        timeout=30,
    )
    bundle = bundle_response.get("bundle")
    if not isinstance(bundle, dict) or not bundle_response.get("delivered_once"):
        raise FleetCLIError("control plane returned an invalid one-time connection bundle")
    _write_worker_environment(
        paths.node / "worker.env",
        bundle,
        labels=response.get("labels") if isinstance(response.get("labels"), dict) else labels,
    )
    _start_worker_runtime(paths, response)
    print(f"Joined fleet as node {response['node_id']}")
    print(f"Overlay address: {response['wireguard_peer_ip']}")
    print("Worker-only runtime and node agent started")


def _control_config(paths: RuntimePaths) -> dict[str, Any]:
    env = load_dotenv(paths.dotenv)
    network, control_ip = parse_overlay(env.get("FLEET_OVERLAY_CIDR", ""))
    endpoint, listen_port = validate_endpoint(env.get("FLEET_WIREGUARD_ENDPOINT", ""))
    del endpoint
    private = (paths.control / "wireguard.key").read_text(encoding="utf-8").strip()
    return {
        "network": network,
        "control_ip": control_ip,
        "listen_port": listen_port,
        "private_key": private,
    }


def command_reconcile(paths: RuntimePaths, args: argparse.Namespace) -> None:
    _require_linux()
    _require_commands(("wg", "wg-quick", "ip"))
    config = _control_config(paths)
    env = load_dotenv(paths.dotenv)
    result = api_json(
        args.local_api.rstrip("/"),
        "GET",
        "/fleet/nodes",
        bearer=env.get("FLEET_OPERATOR_TOKEN"),
    )
    rows = result.get("nodes")
    if not isinstance(rows, list):
        raise FleetCLIError("fleet node list response is invalid")
    peers: list[dict[str, str]] = []
    for row in rows:
        if not isinstance(row, dict) or row.get("status") == "disabled" or row.get("role") != "worker":
            continue
        public_key = str(row.get("wireguard_public_key") or "").strip()
        overlay_ip = str(row.get("overlay_ip") or "").split("/", 1)[0]
        try:
            decoded = base64.b64decode(public_key, validate=True)
            address = ip_address(overlay_ip)
        except Exception as exc:
            raise FleetCLIError(f"node {row.get('id')} has invalid WireGuard identity") from exc
        if len(decoded) != 32 or address not in config["network"] or address == config["control_ip"]:
            raise FleetCLIError(f"node {row.get('id')} has invalid WireGuard identity")
        peers.append({
            "node_id": str(uuid.UUID(str(row.get("id")))),
            "public_key": public_key,
            "overlay_ip": str(address),
        })
    rendered = render_control_wireguard(
        private_key=config["private_key"],
        control_ip=str(config["control_ip"]),
        prefix_length=config["network"].prefixlen,
        listen_port=config["listen_port"],
        peers=peers,
    )
    path = paths.control / f"{INTERFACE_NAME}.conf"
    atomic_write(path, rendered, 0o600)
    install_wireguard(path)
    if not args.quiet:
        print(f"Reconciled {len(peers)} WireGuard worker peer(s)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ShakerScan owned-fleet host provisioning")
    parser.add_argument("--runtime", default=str(Path(__file__).resolve().parents[1]))
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="initialize a WireGuard or HTTPS-broker fleet control plane")
    init.add_argument("--network", choices=["wireguard", "broker"], default="wireguard")
    init.add_argument("--overlay", default=DEFAULT_OVERLAY)
    init.add_argument("--endpoint", help="public WireGuard endpoint host:port (required for wireguard)")
    init.add_argument("--listen-port", type=int, default=DEFAULT_WG_PORT)
    init.add_argument("--tls-port", type=int, default=DEFAULT_TLS_PORT)
    init.add_argument("--public-url", required=True, help="existing HTTPS URL used before overlay setup")
    init.add_argument(
        "--skip-public-check",
        action="store_true",
        help="allow split-horizon/hairpin-limited DNS after manually verifying the public HTTPS URL",
    )
    init.add_argument("--worker-image", help="digest-pinned scanner image")
    init.add_argument("--workers", type=int, default=1)
    init.add_argument(
        "--no-reconcile-service",
        action="store_true",
        help="skip systemd timer installation and reconcile peers manually",
    )

    token = subparsers.add_parser("join-token", help="mint a single-use worker join command")
    token.add_argument("--role", choices=["worker"], default="worker")
    token.add_argument("--transport", choices=["overlay", "broker"], default="overlay")
    token.add_argument("--ttl", default="24h")
    token.add_argument("--public-url")
    token.add_argument("--local-api", default="http://127.0.0.1:8080")

    join = subparsers.add_parser("join", help="join this Linux host as a worker node")
    join.add_argument("control_plane_url")
    join.add_argument("--token")
    join.add_argument("--name")
    join.add_argument("--transport", choices=["overlay", "broker"], default="overlay")
    join.add_argument("--region")
    join.add_argument("--egress-group")
    join.add_argument("--network", dest="network_label")
    join.add_argument("--data-residency")
    join.add_argument("--capability", action="append", default=[])
    join.add_argument(
        "--scan-tier",
        action="append",
        choices=["quick", "standard", "deep", "full", "aggressive", "smart"],
        default=[],
    )
    join.add_argument("--label", action="append", default=[])
    join.add_argument("--overlay-timeout", type=int, default=90)

    reconcile = subparsers.add_parser("reconcile", help="apply registered WireGuard peers locally")
    reconcile.add_argument("--local-api", default="http://127.0.0.1:8080")
    reconcile.add_argument("--quiet", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = RuntimePaths(Path(args.runtime).expanduser().resolve())
    try:
        if args.command == "init":
            command_init(paths, args)
        elif args.command == "join-token":
            command_join_token(paths, args)
        elif args.command == "join":
            command_join(paths, args)
        elif args.command == "reconcile":
            command_reconcile(paths, args)
        else:
            parser.error("unknown command")
    except FleetCLIError as exc:
        print(f"fleet error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
