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
from typing import Any, Callable, Iterable


INTERFACE_NAME = "shakerscan"
DEFAULT_OVERLAY = "10.77.0.0/24"
DEFAULT_WG_PORT = 51820
DEFAULT_TLS_PORT = 8443
MAX_HTTP_BODY = 2 * 1024 * 1024
CADDY_PROFILE = "fleet-gateway"
DIGEST_IMAGE_RE = re.compile(r"^\S+@sha256:[0-9a-fA-F]{64}$")
IMAGE_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:~-]*$")
ENV_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
URL_SAFE_SECRET_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
LOCAL_WORKER_IMAGE_RE = re.compile(r"^shakerscan-fleet-local:[a-z0-9][a-z0-9_.-]{0,127}$")
LOCAL_BUILD_RECOMMENDED_FREE_BYTES = 12 * 1024**3


class FleetCLIError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str
    detail: str
    hint: str = ""


@dataclass(frozen=True)
class FileSnapshot:
    existed: bool
    content: bytes = b""
    mode: int = 0o600


def _run_check(
    checks: list[PreflightCheck],
    name: str,
    action: Callable[[], Any],
    *,
    success: str,
    hint: str,
) -> Any | None:
    try:
        result = action()
    except (FleetCLIError, OSError, ValueError) as exc:
        checks.append(PreflightCheck(name, "fail", str(exc), hint))
        return None
    checks.append(PreflightCheck(name, "pass", success))
    return result


def _print_preflight(checks: Iterable[PreflightCheck]) -> None:
    print("Fleet preflight")
    for check in checks:
        marker = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}.get(check.status, check.status.upper())
        print(f"  [{marker}] {check.name}: {check.detail}")
        if check.hint and check.status != "pass":
            print(f"         Fix: {check.hint}")


def _require_preflight(checks: list[PreflightCheck]) -> None:
    failures = [check for check in checks if check.status == "fail"]
    _print_preflight(checks)
    if failures:
        raise FleetCLIError(f"preflight failed ({len(failures)} check{'s' if len(failures) != 1 else ''})")


def fleet_operator_token(env: dict[str, str]) -> str:
    """Return the persisted operator token, creating a strong one when absent."""
    current = str(env.get("FLEET_OPERATOR_TOKEN") or "").strip()
    return current if len(current) >= 32 else secrets.token_urlsafe(48)


def fleet_gateway_proxy_secret(env: dict[str, str]) -> str:
    """Return an internal Caddy-to-API trust secret safe for an HTTP header."""
    current = str(env.get("FLEET_GATEWAY_PROXY_SECRET") or "").strip()
    if current:
        if len(current) < 32 or not URL_SAFE_SECRET_RE.fullmatch(current):
            raise FleetCLIError(
                "FLEET_GATEWAY_PROXY_SECRET must contain at least 32 URL-safe unreserved characters"
            )
        return current
    return secrets.token_urlsafe(48)


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
        # Generated passwords are hex; preserved operator values pass the
        # URL_SAFE_SECRET_RE guard above. Neither form can escape this literal.
        # The secret travels on stdin, not argv.
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

    @property
    def gateway_config(self) -> Path:
        return self.control / "Caddyfile"


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


def _snapshot_file(path: Path) -> FileSnapshot:
    if not path.exists():
        return FileSnapshot(False)
    return FileSnapshot(True, path.read_bytes(), path.stat().st_mode & 0o777)


def _restore_file(path: Path, snapshot: FileSnapshot) -> None:
    if snapshot.existed:
        atomic_write(path, snapshot.content.decode("utf-8"), snapshot.mode)
    else:
        path.unlink(missing_ok=True)


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


def validate_ca_certificate_path(value: str | None) -> Path | None:
    raw_path = str(value or "").strip()
    if not raw_path:
        return None
    ca_path = Path(raw_path).expanduser().resolve()
    try:
        certificate = ca_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FleetCLIError(f"enrollment CA certificate cannot be read: {ca_path}") from exc
    if "-----BEGIN CERTIFICATE-----" not in certificate or len(certificate.encode("utf-8")) > 64 * 1024:
        raise FleetCLIError("enrollment CA certificate must be a PEM certificate no larger than 64 KiB")
    return ca_path


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


def runtime_image_env(values: dict[str, str]) -> dict[str, str]:
    """Overlay launcher-selected image settings on persisted fleet state.

    ``scanner.sh`` selects the installed release tag in the process environment.
    Fleet preflight previously read only ``.env``, so a fresh curl installation
    silently fell back to the mutable ``latest`` worker tag.
    """
    merged = dict(values)
    for key in ("SCANNER_IMAGE_REPO", "SCANNER_IMAGE_TAG", "FLEET_WORKER_IMAGE_DIGEST"):
        value = str(os.environ.get(key) or "").strip()
        if value:
            merged[key] = value
    return merged


def local_api_url(paths: RuntimePaths, explicit: str | None = None) -> str:
    """Resolve the host-published API origin for control-plane CLI commands.

    Remote mode intentionally binds Docker to the host's Tailscale address, so
    loopback is not always reachable even when the CLI runs on that same host.
    An explicit ``--local-api`` remains authoritative; otherwise use the
    persisted bind address and API port written by ``scanner.sh``.
    """
    if explicit:
        return str(explicit).strip().rstrip("/")
    env = load_dotenv(paths.dotenv)
    host = str(env.get("SHAKERSCAN_BIND_HOST") or "").strip()
    if host in {"", "0.0.0.0", "::"}:
        host = "127.0.0.1"
    try:
        address = ip_address(host)
    except ValueError:
        if host != "localhost" and not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            raise FleetCLIError("SHAKERSCAN_BIND_HOST is not a safe IP address or hostname")
        formatted_host = host
    else:
        formatted_host = f"[{address}]" if address.version == 6 else str(address)
    raw_port = str(env.get("SHAKERSCAN_API_PORT") or "8080").strip()
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise FleetCLIError("SHAKERSCAN_API_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise FleetCLIError("SHAKERSCAN_API_PORT must be between 1 and 65535")
    return f"http://{formatted_host}:{port}"


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
        reason = getattr(exc, "reason", exc)
        tls_failure = isinstance(reason, (ssl.SSLCertVerificationError, ssl.CertificateError)) or (
            "CERTIFICATE_VERIFY_FAILED" in str(exc).upper()
        )
        if tls_failure:
            if ca_file is None:
                raise FleetCLIError(
                    "control-plane TLS verification failed; if this endpoint uses a private CA, "
                    "pass --ca-cert /path/to/ca.pem (certificate and hostname verification cannot be disabled)"
                ) from exc
            raise FleetCLIError(
                f"control-plane TLS verification failed with the supplied CA {ca_file}; "
                "verify the CA chain and that the certificate hostname matches the control-plane URL"
            ) from exc
        raise FleetCLIError(f"control plane request failed: {exc}") from exc


def http_response(
    base_url: str,
    method: str,
    path: str,
    *,
    ca_file: Path | None = None,
    timeout: float = 10.0,
) -> tuple[int, bytes]:
    """Return a bounded response status/body, including deliberate HTTP errors."""
    request = urllib.request.Request(f"{base_url.rstrip('/')}{path}", method=method)
    context = ssl.create_default_context(cafile=str(ca_file)) if ca_file else ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return int(response.status), response.read(64 * 1024)
    except urllib.error.HTTPError as exc:
        return int(exc.code), exc.read(64 * 1024)
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as exc:
        raise FleetCLIError(f"public gateway request failed: {exc}") from exc


def http_status(
    base_url: str,
    method: str,
    path: str,
    *,
    ca_file: Path | None = None,
    timeout: float = 10.0,
) -> int:
    return http_response(base_url, method, path, ca_file=ca_file, timeout=timeout)[0]


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


def _image_repository(reference: str) -> str:
    candidate = reference.split("@", 1)[0]
    slash = candidate.rfind("/")
    colon = candidate.rfind(":")
    if colon > slash:
        candidate = candidate[:colon]
    if not candidate:
        raise FleetCLIError("worker image repository is empty")
    return candidate


def resolve_worker_image(value: str | None, env: dict[str, str]) -> tuple[str, str | None]:
    """Return a pinned image and the mutable source reference, when resolved."""
    raw = str(value or "").strip()
    if not raw:
        if str(env.get("FLEET_WORKER_IMAGE_DIGEST") or "").strip():
            return _discover_digest_image(env), None
        try:
            return _discover_digest_image(env), None
        except FleetCLIError:
            repository = env.get("SCANNER_IMAGE_REPO", "shakerscan/shakerscan-scanner")
            tag = env.get("SCANNER_IMAGE_TAG", "latest")
            raw = f"{repository}:{tag}"
    if DIGEST_IMAGE_RE.fullmatch(raw):
        return validate_digest_image(raw), None
    if not IMAGE_REFERENCE_RE.fullmatch(raw) or "@" in raw:
        raise FleetCLIError(
            "worker image must be a safe registry tag or repository@sha256:<64 hex characters>"
        )

    inspected = _run(
        ["docker", "buildx", "imagetools", "inspect", raw],
        check=False,
    )
    if inspected.returncode == 0:
        match = re.search(r"(?m)^Digest:\s*(sha256:[0-9a-fA-F]{64})\s*$", inspected.stdout or "")
        if match:
            return f"{_image_repository(raw)}@{match.group(1).lower()}", raw

    # Older Docker installations may not have buildx. Pulling is a safe
    # compatibility fallback; RepoDigests is still immutable once persisted.
    pulled = _run(["docker", "pull", raw], check=False, capture=False)
    if pulled.returncode == 0:
        local = _run(
            ["docker", "image", "inspect", raw, "--format", "{{json .RepoDigests}}"],
            check=False,
        )
        if local.returncode == 0:
            try:
                digests = json.loads(local.stdout)
            except json.JSONDecodeError:
                digests = []
            repository = _image_repository(raw)
            for digest in digests or []:
                digest_text = str(digest)
                if DIGEST_IMAGE_RE.fullmatch(digest_text):
                    _repo, _separator, sha = digest_text.rpartition("@sha256:")
                    return f"{repository}@sha256:{sha.lower()}", raw
    raise FleetCLIError(
        f"could not resolve worker image tag {raw!r} to an immutable digest; "
        "authenticate to the registry or pass repository@sha256:<digest>"
    )


def _listening_port(protocol: str, port: int) -> bool:
    flag = "-ltn" if protocol == "tcp" else "-lun"
    result = _run(["ss", "-H", flag], check=False)
    if result.returncode != 0:
        raise FleetCLIError(f"could not inspect local {protocol.upper()} listeners with ss")
    return bool(re.search(rf"(?:\]:|:){port}\b", result.stdout or ""))


def _overlay_route_conflicts(network: IPv4Network) -> list[str]:
    result = _run(["ip", "-json", "route", "show", "table", "all"], check=False)
    if result.returncode != 0:
        raise FleetCLIError("could not inspect local routes with ip")
    try:
        routes = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise FleetCLIError("ip returned invalid route data") from exc
    conflicts: list[str] = []
    for route in routes if isinstance(routes, list) else []:
        if not isinstance(route, dict) or route.get("dev") == INTERFACE_NAME:
            continue
        destination = str(route.get("dst") or "")
        if not destination or destination == "default":
            continue
        try:
            existing = ip_network(destination, strict=False)
        except ValueError:
            continue
        if isinstance(existing, IPv4Network) and existing.overlaps(network):
            conflicts.append(f"{existing} via {route.get('dev') or route.get('gateway') or 'unknown'}")
    return sorted(set(conflicts))


def _assert_port_available(protocol: str, port: int, *, existing_fleet: bool) -> None:
    if _listening_port(protocol, port) and not existing_fleet:
        raise FleetCLIError(f"{protocol.upper()} port {port} is already in use")


def _assert_overlay_available(network: IPv4Network, *, existing_fleet: bool) -> None:
    conflicts = _overlay_route_conflicts(network)
    if conflicts and not existing_fleet:
        raise FleetCLIError(
            f"overlay {network} overlaps existing route{'s' if len(conflicts) != 1 else ''}: "
            + ", ".join(conflicts[:4])
        )


def _resolved_public_addresses(public_url: str) -> list[str]:
    parsed = urllib.parse.urlparse(public_url)
    if parsed.port not in {None, 443}:
        raise FleetCLIError("managed HTTPS requires the standard public HTTPS port 443")
    hostname = str(parsed.hostname or "")
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        raise FleetCLIError("managed public HTTPS requires a DNS hostname, not an IP address")
    try:
        answers = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise FleetCLIError(f"DNS does not resolve {hostname}: {exc}") from exc
    addresses = sorted({str(answer[4][0]) for answer in answers if answer[4]})
    if not addresses:
        raise FleetCLIError(f"DNS returned no addresses for {hostname}")
    if not any(ip_address(address).is_global for address in addresses):
        raise FleetCLIError(
            f"managed public HTTPS requires a publicly routable DNS address; {hostname} resolves to "
            + ", ".join(addresses)
        )
    return addresses


def render_managed_caddyfile(public_url: str, proxy_secret: str) -> str:
    """Render the narrow public ingress used by HTTPS-broker workers."""
    validated = validate_https_url(public_url)
    hostname = str(urllib.parse.urlparse(validated).hostname or "")
    if len(proxy_secret) < 32 or not URL_SAFE_SECRET_RE.fullmatch(proxy_secret):
        raise FleetCLIError("managed gateway proxy secret is invalid")
    return f"""# Managed by ShakerScan. Local UI and operator APIs are intentionally not public.
{hostname} {{
    encode zstd gzip

    @health {{
        method GET
        path /health
    }}
    handle @health {{
        rewrite * /fleet/public-health
        reverse_proxy api:8080 {{
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-For {{remote_host}}
            header_up X-ShakerScan-Gateway-Secret {proxy_secret}
        }}
    }}

    @join {{
        method POST
        path /fleet/nodes/join
    }}
    handle @join {{
        reverse_proxy api:8080 {{
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-For {{remote_host}}
            header_up X-ShakerScan-Gateway-Secret {proxy_secret}
        }}
    }}

    @node_state {{
        method GET
        path_regexp node_state ^/fleet/nodes/[0-9a-fA-F-]+/state$
    }}
    handle @node_state {{
        reverse_proxy api:8080 {{
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-For {{remote_host}}
            header_up X-ShakerScan-Gateway-Secret {proxy_secret}
        }}
    }}

    @node_heartbeat {{
        method POST
        path_regexp node_heartbeat ^/fleet/nodes/[0-9a-fA-F-]+/heartbeat$
    }}
    handle @node_heartbeat {{
        reverse_proxy api:8080 {{
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-For {{remote_host}}
            header_up X-ShakerScan-Gateway-Secret {proxy_secret}
        }}
    }}

    @broker path /fleet/broker/*
    handle @broker {{
        reverse_proxy api:8080 {{
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-For {{remote_host}}
            header_up X-ShakerScan-Gateway-Secret {proxy_secret}
        }}
    }}

    handle {{
        respond "Not found" 404
    }}
}}
"""


def _managed_gateway_state_present(paths: RuntimePaths, env: dict[str, str]) -> bool:
    """Recognize current and pre-proxy-secret managed gateway installations."""
    profiles = {item.strip() for item in env.get("COMPOSE_PROFILES", "").split(",")}
    if CADDY_PROFILE in profiles:
        return True
    try:
        first_line = paths.gateway_config.read_text(encoding="utf-8").splitlines()[0]
    except (FileNotFoundError, IndexError, OSError, UnicodeError):
        return False
    return first_line.strip() == "# Managed by ShakerScan. Local UI and operator APIs are intentionally not public."


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


def _fleet_artifact_environment(artifact_host: str, env: dict[str, str]) -> tuple[dict[str, str], bool]:
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
    profiles = {item.strip() for item in env.get("COMPOSE_PROFILES", "").split(",")}
    configured_minio_user = str(env.get("MINIO_ROOT_USER") or "")
    configured_minio_password = str(env.get("MINIO_ROOT_PASSWORD") or "")
    bundled_minio = bool(
        "artifacts" in profiles
        and configured_minio_user
        and configured_minio_password
        and access_key == configured_minio_user
        and secret_key == configured_minio_password
    )
    if (
        not bundled_minio
        and backend in {"s3", "minio", "s3-compatible", "s3_compatible"}
        and bucket
        and access_key
        and secret_key
    ):
        return {"ARTIFACT_STORAGE_REQUIRED": "true"}, False

    minio_user = configured_minio_user or f"ss-{secrets.token_hex(8)}"
    minio_password = configured_minio_password or secrets.token_urlsafe(36)
    minio_bucket = str(env.get("EVIDENCE_S3_BUCKET") or "shakerscan-artifacts")
    endpoint = f"http://{artifact_host}:9000"
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


def _validated_range(value: int, label: str, minimum: int, maximum: int) -> int:
    if not minimum <= value <= maximum:
        raise FleetCLIError(f"{label} must be between {minimum} and {maximum}")
    return value


def run_init_preflight(paths: RuntimePaths, args: argparse.Namespace) -> dict[str, Any]:
    """Validate a fleet conversion completely before any durable mutation."""
    checks: list[PreflightCheck] = []
    network_mode = str(getattr(args, "network", "wireguard") or "wireguard")
    env = runtime_image_env(load_dotenv(paths.dotenv))

    _run_check(
        checks,
        "Linux host",
        _require_linux,
        success="supported",
        hint="Run fleet provisioning on a Linux control-plane host.",
    )
    required_commands = ("docker", "ss") if network_mode == "broker" else (
        "wg", "wg-quick", "ip", "ss", "openssl", "docker"
    )
    _run_check(
        checks,
        "Host dependencies",
        lambda: _require_commands(required_commands),
        success="all required commands are installed",
        hint="Install Docker; WireGuard mode also needs wireguard-tools and iproute2.",
    )
    _run_check(
        checks,
        "Docker Compose",
        _docker_compose_command,
        success="available",
        hint="Install the Docker Compose plugin and ensure the Docker daemon is running.",
    )
    public_url = _run_check(
        checks,
        "Public HTTPS URL",
        lambda: validate_https_url(args.public_url),
        success="URL syntax is valid",
        hint="Use a stable origin such as https://scanner.example.com with no path or credentials.",
    )
    enrollment_ca = _run_check(
        checks,
        "Enrollment CA",
        lambda: validate_ca_certificate_path(getattr(args, "ca_cert", None)),
        success="system trust or supplied PEM is usable",
        hint="Pass a readable PEM CA with --ca-cert when the public URL uses private PKI.",
    )
    requested_https_mode = str(getattr(args, "https_mode", "auto") or "auto")
    existing_managed_gateway = _managed_gateway_state_present(paths, env)
    https_mode = "external"
    external_boundary_verified = False
    if requested_https_mode == "managed" and network_mode != "broker":
        checks.append(PreflightCheck(
            "Managed HTTPS",
            "fail",
            "the built-in public gateway is currently supported for broker fleets",
            "Use --network broker, or configure external HTTPS for WireGuard enrollment.",
        ))
    if getattr(args, "skip_public_check", False) and requested_https_mode == "managed":
        checks.append(PreflightCheck(
            "Managed HTTPS",
            "fail",
            "--skip-public-check cannot verify certificate provisioning",
            "Remove --skip-public-check when ShakerScan manages HTTPS.",
        ))
    if public_url and getattr(args, "skip_public_check", False):
        checks.append(PreflightCheck(
            "Public API reachability",
            "warn",
            "skipped by operator for a split-horizon/hairpin limitation",
            "Verify the public HTTPS endpoint from a worker before issuing a join token.",
        ))
    elif public_url and network_mode == "broker" and (
        requested_https_mode == "managed" or (requested_https_mode == "auto" and existing_managed_gateway)
    ):
        https_mode = "managed"
        checks.append(PreflightCheck(
            "Public API reachability",
            "warn",
            "will be verified after the managed HTTPS gateway obtains its certificate",
        ))
    elif public_url and network_mode == "broker" and requested_https_mode == "auto":
        try:
            _require_healthy_api(public_url, enrollment_ca)
        except FleetCLIError as exc:
            https_mode = "managed"
            checks.append(PreflightCheck(
                "Public API reachability",
                "warn",
                f"not ready yet ({exc}); the managed HTTPS gateway will be provisioned",
            ))
        else:
            try:
                _require_public_fleet_auth_boundary(public_url, enrollment_ca)
            except FleetCLIError as exc:
                https_mode = "managed"
                checks.append(PreflightCheck(
                    "Public API reachability",
                    "warn",
                    "HTTPS is reachable but its fleet trust boundary is not ready; "
                    "the managed gateway will be provisioned",
                ))
                checks.append(PreflightCheck(
                    "Existing HTTPS authentication boundary",
                    "warn",
                    str(exc),
                    "ShakerScan will replace this incomplete path with its restricted managed gateway.",
                ))
            else:
                external_boundary_verified = True
                checks.append(PreflightCheck(
                    "Public API reachability",
                    "pass",
                    "healthy existing API and certificate chain verified",
                ))
                checks.append(PreflightCheck(
                    "Broker HTTPS authentication boundary",
                    "pass",
                    "protected node route reaches HTTPS enforcement and requires authentication",
                ))
    elif public_url:
        _run_check(
            checks,
            "Public API reachability",
            lambda: _require_healthy_api(public_url, enrollment_ca),
            success="healthy API and certificate chain verified",
            hint="Fix DNS/HTTPS/firewall access; for private PKI, pass --ca-cert.",
        )

    if (
        public_url
        and network_mode == "broker"
        and https_mode == "external"
        and not external_boundary_verified
        and not getattr(args, "skip_public_check", False)
    ):
        _run_check(
            checks,
            "Broker HTTPS authentication boundary",
            lambda: _require_public_fleet_auth_boundary(public_url, enrollment_ca),
            success="protected node route reaches HTTPS enforcement and requires authentication",
            hint=(
                "Configure the reverse proxy to publish the documented fleet worker routes and preserve "
                "the verified HTTPS scheme."
            ),
        )

    if public_url and https_mode == "managed":
        if enrollment_ca is not None:
            checks.append(PreflightCheck(
                "Managed HTTPS trust",
                "fail",
                "--ca-cert selects private PKI but the managed gateway obtains a public certificate",
                "Remove --ca-cert, or use --https-mode external for a private-CA reverse proxy.",
            ))
        addresses = _run_check(
            checks,
            "Public DNS",
            lambda: _resolved_public_addresses(public_url),
            success="hostname resolves and is eligible for public certificate issuance",
            hint="Create an A/AAAA record pointing the hostname at this VPS and wait for DNS propagation.",
        )
        if addresses:
            checks.append(PreflightCheck("Public DNS answers", "pass", ", ".join(addresses)))
        _run_check(
            checks,
            "HTTP port 80",
            lambda: _assert_port_available("tcp", 80, existing_fleet=existing_managed_gateway),
            success="available for ACME validation and HTTPS redirects",
            hint="Stop the service using TCP 80 or select --https-mode external and configure that proxy.",
        )
        _run_check(
            checks,
            "HTTPS port 443",
            lambda: _assert_port_available("tcp", 443, existing_fleet=existing_managed_gateway),
            success="available for fleet traffic",
            hint="Stop the service using TCP 443 or select --https-mode external and configure that proxy.",
        )

    image_result = _run_check(
        checks,
        "Worker image",
        lambda: resolve_worker_image(getattr(args, "worker_image", None), env),
        success="resolved to an immutable digest",
        hint="Authenticate to the registry or provide repository@sha256:<digest>.",
    )
    _run_check(
        checks,
        "Worker count",
        lambda: _validated_range(int(args.workers), "--workers", 1, 128),
        success="within supported range",
        hint="Choose between 1 and 128 initial workers.",
    )
    if env.get("FLEET_ALLOW_INSECURE_ENROLLMENT", "").lower() in {"1", "true", "yes", "on"}:
        checks.append(PreflightCheck(
            "Enrollment policy",
            "fail",
            "FLEET_ALLOW_INSECURE_ENROLLMENT is enabled",
            "Remove the insecure override before production fleet initialization.",
        ))
    else:
        checks.append(PreflightCheck("Enrollment policy", "pass", "secure enrollment is enforced"))

    prepared: dict[str, Any] = {
        "env": env,
        "public_url": public_url,
        "enrollment_ca": enrollment_ca,
        "worker_image": image_result[0] if image_result else None,
        "worker_image_source": image_result[1] if image_result else None,
        "https_mode": https_mode,
    }
    if network_mode == "wireguard":
        overlay = _run_check(
            checks,
            "Overlay CIDR",
            lambda: parse_overlay(args.overlay),
            success="canonical private route is valid",
            hint="Choose a canonical unused IPv4 CIDR, for example 10.77.0.0/24.",
        )
        endpoint_result = _run_check(
            checks,
            "WireGuard endpoint",
            lambda: validate_endpoint(args.endpoint),
            success="host and port are valid",
            hint="Pass --endpoint with the externally reachable host:port.",
        )
        _run_check(
            checks,
            "Private TLS port",
            lambda: _validated_range(int(args.tls_port), "--tls-port", 1, 65535),
            success="valid",
            hint="Choose an unused TCP port between 1 and 65535.",
        )
        if endpoint_result and endpoint_result[1] != args.listen_port:
            checks.append(PreflightCheck(
                "WireGuard listen port",
                "fail",
                "--endpoint port and --listen-port do not match",
                "Use the same UDP port in --endpoint and --listen-port.",
            ))
        else:
            checks.append(PreflightCheck("WireGuard listen port", "pass", "endpoint and listener agree"))

        existing_overlay = str(env.get("FLEET_OVERLAY_CIDR") or "")
        if overlay and existing_overlay and existing_overlay != str(overlay[0]):
            checks.append(PreflightCheck(
                "Existing fleet identity",
                "fail",
                f"existing overlay is {existing_overlay}, requested overlay is {overlay[0]}",
                "Keep the existing overlay or perform a documented fleet reset/migration.",
            ))
        else:
            checks.append(PreflightCheck("Existing fleet identity", "pass", "no incompatible overlay change"))
        existing_fleet = bool(existing_overlay and overlay and existing_overlay == str(overlay[0]))
        if overlay:
            _run_check(
                checks,
                "Overlay route collision",
                lambda: _assert_overlay_available(overlay[0], existing_fleet=existing_fleet),
                success="no conflicting local route",
                hint="Choose a different --overlay CIDR or remove the conflicting local route.",
            )
        if endpoint_result:
            _run_check(
                checks,
                "WireGuard UDP port",
                lambda: _assert_port_available("udp", endpoint_result[1], existing_fleet=existing_fleet),
                success="available",
                hint="Choose another --listen-port/--endpoint port or stop the conflicting listener.",
            )
        _run_check(
            checks,
            "Private TLS TCP port",
            lambda: _assert_port_available("tcp", int(args.tls_port), existing_fleet=existing_fleet),
            success="available",
            hint="Choose another --tls-port or stop the conflicting listener.",
        )
        has_systemd = bool(shutil.which("systemctl") and Path("/run/systemd/system").is_dir())
        if has_systemd:
            checks.append(PreflightCheck("Peer reconciliation", "pass", "systemd timer can be installed"))
        elif getattr(args, "no_reconcile_service", False):
            checks.append(PreflightCheck(
                "Peer reconciliation",
                "warn",
                "automatic systemd reconciliation is unavailable",
                "Run shakerscan fleet reconcile after joins/revocations; Fleet UI will flag pending peers.",
            ))
        else:
            checks.append(PreflightCheck(
                "Peer reconciliation",
                "fail",
                "systemd is unavailable",
                "Use a systemd host or explicitly accept manual reconciliation with --no-reconcile-service.",
            ))
        prepared.update({
            "overlay": overlay,
            "endpoint": endpoint_result,
        })

    _require_preflight(checks)
    if prepared.get("worker_image_source"):
        print(
            f"Pinned worker image: {prepared['worker_image_source']} -> {prepared['worker_image']}"
        )
    return prepared


def _require_healthy_api(public_url: str, ca_file: Path | None) -> None:
    health = api_json(public_url, "GET", "/health", ca_file=ca_file, timeout=10)
    if health.get("status") != "healthy":
        raise FleetCLIError("public HTTPS API did not report healthy")


def _require_public_fleet_auth_boundary(public_url: str, ca_file: Path | None) -> None:
    probe_node = "00000000-0000-0000-0000-000000000000"
    status, body = http_response(
        public_url,
        "GET",
        f"/fleet/nodes/{probe_node}/state",
        ca_file=ca_file,
    )
    try:
        detail = str(json.loads(body or b"{}").get("detail") or "")
    except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
        detail = ""
    if status != 401 or detail != "node bearer credential is required":
        raise FleetCLIError(
            f"protected fleet route returned HTTP {status} without the expected ShakerScan node-auth response"
        )


def _wait_for_healthy_api(public_url: str, ca_file: Path | None, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            _require_healthy_api(public_url, ca_file)
            return
        except FleetCLIError as exc:
            last_error = exc
            time.sleep(2)
    raise FleetCLIError(f"public HTTPS did not become healthy within {int(timeout)}s: {last_error}")


def _wait_for_artifact_store(paths: RuntimePaths, timeout: float = 120.0) -> None:
    """Wait for the configured artifact plane to accept a real write probe.

    The API can become healthy a moment before the bundled MinIO initializer
    creates its bucket. Treat that bounded startup window like the public API
    readiness window instead of rolling a valid fleet conversion back on the
    first transient NoSuchBucket/HTTP 503 response. External S3 endpoints get
    the same bounded retry and still fail closed when the deadline expires.
    """
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            result = api_json(
                local_api_url(paths),
                "GET",
                "/artifacts/storage/health?probe=true",
                timeout=15,
            )
            if result.get("status") == "ok":
                return
            last_error = FleetCLIError(
                "artifact store probe returned "
                f"status={result.get('status')!r}, backend={result.get('backend')!r}, "
                f"error={result.get('error')!r}"
            )
        except FleetCLIError as exc:
            last_error = exc
        time.sleep(2)
    raise FleetCLIError(
        f"artifact store did not become writable within {int(timeout)}s: {last_error}"
    )


def _verify_managed_gateway_isolation(public_url: str, ca_file: Path | None) -> None:
    _require_public_fleet_auth_boundary(public_url, ca_file)
    for path in ("/", "/targets", "/fleet/nodes", "/docs"):
        status = http_status(public_url, "GET", path, ca_file=ca_file)
        if status != 404:
            raise FleetCLIError(
                f"managed HTTPS route isolation failed: GET {path} returned {status}, expected 404"
            )


def command_preflight(paths: RuntimePaths, args: argparse.Namespace) -> None:
    run_init_preflight(paths, args)
    print("Preflight passed. No fleet state was changed.")


def _backup_standalone_if_running(paths: RuntimePaths, env: dict[str, str]) -> None:
    """Create a recoverable snapshot before the first standalone-to-fleet conversion."""
    if str(env.get("FLEET_NETWORK_BACKEND") or "").strip():
        return
    compose = _docker_compose_command()
    postgres = _run([*compose, "ps", "-q", "postgres"], check=False)
    if postgres.returncode != 0 or not (postgres.stdout or "").strip():
        return
    scanner = paths.root / "scanner.sh"
    if not scanner.is_file():
        raise FleetCLIError("scanner.sh is missing; cannot create the required pre-conversion backup")
    print("Existing standalone control plane detected; creating a pre-conversion backup...")
    _run([str(scanner), "backup"], capture=False)


def command_init(paths: RuntimePaths, args: argparse.Namespace) -> None:
    prepared = run_init_preflight(paths, args)
    enrollment_ca = prepared["enrollment_ca"]
    if getattr(args, "network", "wireguard") == "broker":
        public_url = prepared["public_url"]
        env = prepared["env"]
        worker_image = prepared["worker_image"]
        https_mode = prepared["https_mode"]
        scanner = paths.root / "scanner.sh"
        if not scanner.is_file():
            raise FleetCLIError("scanner.sh is missing from the runtime")
        _backup_standalone_if_running(paths, env)
        dotenv_snapshot = _snapshot_file(paths.dotenv)
        gateway_snapshot = _snapshot_file(paths.gateway_config)
        operator_token = fleet_operator_token(env)
        profiles = {item.strip() for item in env.get("COMPOSE_PROFILES", "").split(",") if item.strip()}
        # Broker control-plane services share the Compose network. Loopback here
        # would point each API/worker container at itself, not bundled MinIO.
        artifact_updates, bundled_minio = _fleet_artifact_environment("minio", env)
        if bundled_minio:
            profiles.add("artifacts")
        if https_mode == "managed":
            profiles.add(CADDY_PROFILE)
        gateway_secret = (
            fleet_gateway_proxy_secret(env)
            if https_mode == "managed"
            else str(env.get("FLEET_GATEWAY_PROXY_SECRET") or "").strip()
        )
        try:
            if https_mode == "managed":
                atomic_write(
                    paths.gateway_config,
                    render_managed_caddyfile(public_url, gateway_secret),
                    0o600,
                )
            update_dotenv(paths.dotenv, {
                "COMPOSE_PROFILES": ",".join(sorted(profiles)),
                "FLEET_NETWORK_BACKEND": "broker",
                "FLEET_HTTPS_MODE": https_mode,
                "FLEET_WORKER_IMAGE_DIGEST": worker_image,
                "FLEET_DESIRED_WORKER_COUNT": str(args.workers),
                "FLEET_PUBLIC_URL": public_url,
                "FLEET_ALLOW_INSECURE_ENROLLMENT": "false",
                "FLEET_OPERATOR_TOKEN": operator_token,
                "FLEET_GATEWAY_PROXY_SECRET": gateway_secret,
                **artifact_updates,
            })
            _run([str(scanner), "restart"], capture=False)
            _wait_for_healthy_api(public_url, enrollment_ca)
            if https_mode == "managed":
                _verify_managed_gateway_isolation(public_url, enrollment_ca)
            else:
                _require_public_fleet_auth_boundary(public_url, enrollment_ca)
            _wait_for_artifact_store(paths)
        except Exception as exc:
            print("Fleet initialization failed; restoring the previous runtime configuration...", file=sys.stderr)
            stop_error: Exception | None = None
            try:
                _run([str(scanner), "stop"], check=False, capture=False)
            except Exception as rollback_stop_exc:
                stop_error = rollback_stop_exc
            try:
                _restore_file(paths.dotenv, dotenv_snapshot)
                _restore_file(paths.gateway_config, gateway_snapshot)
            except Exception as restore_exc:
                raise FleetCLIError(
                    f"broker initialization failed ({exc}) and automatic configuration restore failed: "
                    f"{restore_exc}"
                ) from exc
            try:
                _run([str(scanner), "restart"], capture=False)
            except FleetCLIError as rollback_exc:
                raise FleetCLIError(
                    f"broker initialization failed ({exc}); configuration was restored but restart failed: "
                    f"{rollback_exc}"
                ) from exc
            if stop_error:
                raise FleetCLIError(
                    f"broker initialization failed and configuration was restored; the failed stack could not "
                    f"be stopped cleanly before restart ({stop_error}): {exc}"
                ) from exc
            raise FleetCLIError(
                f"broker initialization failed and was rolled back to the previous configuration: {exc}"
            ) from exc
        print(f"HTTPS broker control plane initialized: {public_url}")
        if https_mode == "managed":
            print("HTTPS certificate and restricted fleet gateway are managed by ShakerScan")
        print("Next: shakerscan fleet join-token --ttl 24h --transport broker")
        return
    network, control_ip = prepared["overlay"]
    endpoint, listen_port = prepared["endpoint"]
    public_url = prepared["public_url"]
    env = prepared["env"]
    worker_image = prepared["worker_image"]
    _backup_standalone_if_running(paths, env)
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
        "FLEET_RECONCILE_MODE": "manual" if args.no_reconcile_service else "systemd",
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
        local_api_url(paths, getattr(args, "local_api", None)),
        "POST",
        "/fleet/join-tokens",
        payload={
            "role": args.role,
            "transport": args.transport,
            "ttl_seconds": ttl_seconds,
            "max_uses": args.max_uses,
        },
        bearer=env.get("FLEET_OPERATOR_TOKEN"),
    )
    token = str(result.get("token") or "")
    if not token.startswith("ssj_"):
        raise FleetCLIError("control plane did not return a join token")
    token_id = str(result.get("token_id") or "")
    try:
        uuid.UUID(token_id)
    except ValueError as exc:
        raise FleetCLIError("control plane did not return a join token identity") from exc
    max_uses = int(result.get("max_uses") or 1)
    if max_uses == 1:
        print("Single-use join token created. Run on the worker VPS:")
    else:
        print(f"Bounded multi-use join token created for up to {max_uses} workers.")
        print("Run the same command on each intended worker VPS:")
    transport_flag = " --transport broker" if getattr(args, "transport", "overlay") == "broker" else ""
    print(f"shakerscan join {public_url} --token {token}{transport_flag}")
    print(f"Expires: {result.get('expires_at')}")
    print(f"Token ID: {token_id}")
    print(f"Revoke remaining uses: shakerscan fleet revoke-join-token {token_id}")
    if max_uses > 1:
        print(
            "Security: share only with the intended workers, revoke it after enrollment, "
            "and never store it in source control or chat history."
        )
    if (
        getattr(args, "transport", "overlay") == "overlay"
        and env.get("FLEET_RECONCILE_MODE") == "manual"
    ):
        print(
            "Manual reconciliation is enabled: after starting join on the worker, run "
            "`shakerscan fleet reconcile` on this control plane."
        )


def command_revoke_join_token(paths: RuntimePaths, args: argparse.Namespace) -> None:
    env = load_dotenv(paths.dotenv)
    try:
        token_id = str(uuid.UUID(str(args.token_id)))
    except ValueError as exc:
        raise FleetCLIError("join token ID must be a UUID") from exc
    result = api_json(
        local_api_url(paths, getattr(args, "local_api", None)),
        "DELETE",
        f"/fleet/join-tokens/{token_id}",
        bearer=env.get("FLEET_OPERATOR_TOKEN"),
    )
    if result.get("revoked") is not True:
        raise FleetCLIError("control plane did not confirm join token revocation")
    print(f"Join token {token_id} revoked; no remaining uses can enroll.")


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


def _worker_compose_env(
    paths: RuntimePaths,
    response: dict[str, Any],
    *,
    runtime_image: str | None = None,
) -> dict[str, str]:
    expected_image = str(response["worker_image_digest"])
    selected_image = str(runtime_image or expected_image)
    sandbox_uid, sandbox_gid = _sandbox_runtime_identity(
        paths.root / "results" / "model-intake-sandbox"
    )
    return {
        "FLEET_COMPOSE_PROJECT_NAME": f"shakerscan-fleet-{str(response['node_id'])[:8]}",
        "FLEET_NODE_ID": str(response["node_id"]),
        "FLEET_WORKER_IMAGE": selected_image,
        "FLEET_EXPECTED_WORKER_IMAGE_DIGEST": expected_image,
        "FLEET_WORKER_ENV_FILE": str(paths.node / "worker.env"),
        "FLEET_RUNTIME_DIR": str(paths.node),
        "FLEET_RESULTS_DIR": str(paths.root / "results"),
        "MODEL_INTAKE_SANDBOX_UID": str(sandbox_uid),
        "MODEL_INTAKE_SANDBOX_GID": str(sandbox_gid),
    }


def _sandbox_runtime_identity(queue_path: Path | None = None) -> tuple[int, int]:
    """Return the durable bind owner and matching non-root container identity.

    Preserve an existing non-root owner across launcher-user changes. Older
    root-run installations commonly own this queue as UID 10001; changing the
    desired identity to the next operator's UID makes otherwise safe upgrades
    impossible without weakening the private 0700 boundary.
    """
    if queue_path is not None and queue_path.exists() and not queue_path.is_symlink():
        current = queue_path.stat()
        if current.st_uid != 0:
            return current.st_uid, current.st_gid
    uid = os.geteuid()
    gid = os.getegid()
    return (10001, 10001) if uid == 0 else (uid, gid)


def _set_sandbox_queue_owner(path: Path, uid: int, gid: int) -> None:
    """Set the private queue owner when the launcher has host root authority."""
    if os.geteuid() == 0:
        os.chown(path, uid, gid)


def _prepare_worker_result_directories(paths: RuntimePaths) -> None:
    """Create bind-mount directories before Docker can create them as root.

    The isolated Model Intake service runs as an unprivileged identity that
    owns its private queue. On a fresh worker, Compose would otherwise create
    the bind path as root:root/0755. Making the queue world-writable solves the
    availability problem but lets another local host account forge or disrupt
    sandbox evidence, so Fleet establishes an explicit owner and mode 0700.
    """
    directories = (
        (paths.root / "results", 0o755),
        (paths.root / "results" / "model-intake-quarantine", 0o755),
        (paths.root / "results" / "model-intake-sandbox", 0o700),
    )
    sandbox_path = paths.root / "results" / "model-intake-sandbox"
    sandbox_uid, sandbox_gid = _sandbox_runtime_identity(sandbox_path)
    for path, mode in directories:
        if path.is_symlink():
            raise FleetCLIError(f"worker result directory must not be a symlink: {path}")
        try:
            path.mkdir(parents=True, exist_ok=True, mode=mode)
            if path == sandbox_path:
                _set_sandbox_queue_owner(path, sandbox_uid, sandbox_gid)
            path.chmod(mode)
        except OSError as exc:
            raise FleetCLIError(f"could not prepare worker result directory {path}: {exc}") from exc
        actual_mode = path.stat().st_mode & 0o777
        if actual_mode != mode:
            raise FleetCLIError(
                f"worker result directory {path} has mode {actual_mode:o}; "
                f"mode {mode:o} is required for the isolated scanner service"
            )
    sandbox_stat = sandbox_path.stat()
    if sandbox_stat.st_uid != sandbox_uid or sandbox_stat.st_gid != sandbox_gid:
        raise FleetCLIError(
            f"worker sandbox queue {sandbox_path} must be owned by "
            f"{sandbox_uid}:{sandbox_gid}; found {sandbox_stat.st_uid}:{sandbox_stat.st_gid}. "
            "For a legacy root-owned queue, run the explicit host migration: "
            "sudo shakerscan fleet repair-permissions --confirm"
        )


def command_repair_permissions(paths: RuntimePaths, args: argparse.Namespace) -> None:
    """Migrate legacy root/world-writable fleet queues to the private runtime UID."""
    _require_linux()
    if os.geteuid() != 0:
        raise FleetCLIError("repair-permissions requires host root; rerun with sudo")
    if not args.confirm:
        raise FleetCLIError("repair-permissions requires --confirm after reviewing the target path")
    results = paths.root / "results"
    sandbox = results / "model-intake-sandbox"
    for path in (results, sandbox):
        if path.is_symlink():
            raise FleetCLIError(f"worker result directory must not be a symlink: {path}")
    results.mkdir(parents=True, exist_ok=True, mode=0o755)
    sandbox.mkdir(parents=True, exist_ok=True, mode=0o700)
    sandbox.chmod(0o700)
    os.chown(sandbox, 10001, 10001)
    print(f"Repaired private sandbox queue {sandbox} (owner 10001:10001, mode 0700)")


def _write_compose_env(path: Path, values: dict[str, str]) -> None:
    for value in values.values():
        if any(ch in value for ch in "\r\n"):
            raise FleetCLIError("unsafe Compose environment value")
    atomic_write(path, "".join(f"{key}={value}\n" for key, value in sorted(values.items())), 0o600)


def _persist_worker_runtime_template(paths: RuntimePaths, response: dict[str, Any]) -> None:
    """Freeze the safe Compose worker shape for recovery after total container loss."""
    state_path = paths.node / "state.json"
    if not state_path.is_file():
        return
    state = _read_node_state(state_path)
    project = f"shakerscan-fleet-{str(response['node_id'])[:8]}"
    listed = _run(
        [
            "docker",
            "ps",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            "label=com.docker.compose.service=worker",
            "--format",
            "{{.ID}}",
        ],
    )
    container_ids = [line.strip() for line in str(listed.stdout or "").splitlines() if line.strip()]
    if not container_ids:
        raise FleetCLIError(
            "expected at least one running Compose worker while capturing recovery state"
        )
    inspected = _run(["docker", "inspect", *container_ids])
    try:
        payload = json.loads(str(inspected.stdout or ""))
        if not isinstance(payload, list) or len(payload) != len(container_ids):
            raise ValueError("incomplete Docker inspection response")

        allowed_images = {str(response["worker_image_digest"])}
        runtime_override = str(state.get("runtime_image_override") or "").strip()
        if runtime_override:
            allowed_images.add(runtime_override)

        candidates: list[tuple[int, dict[str, Any]]] = []
        for inspected_item in payload:
            inspected_config = inspected_item["Config"]
            labels = inspected_config.get("Labels") or {}
            if (
                labels.get("com.docker.compose.project") != project
                or labels.get("com.docker.compose.service") != "worker"
                or labels.get("com.shakerscan.node_id") != str(response["node_id"])
                or labels.get("com.shakerscan.fleet_managed") != "true"
            ):
                raise ValueError("worker identity does not match the enrolled node")
            # Old and new digests legitimately coexist during a rolling update.
            # Ignore non-current images and capture a matching live template;
            # fail only when no enrolled/current candidate remains.
            if str(inspected_config.get("Image") or "") not in allowed_images:
                continue
            number = str(labels.get("com.docker.compose.container-number") or "")
            candidates.append((int(number) if number.isdigit() else 2**31 - 1, inspected_item))

        if not candidates:
            raise ValueError("no current enrolled worker image is available for recovery capture")

        # The node agent may already have scaled beyond the Compose seed worker,
        # or Compose may leave an exited replacement behind during a rebuild.
        # Every live candidate was identity/image checked above; choose the
        # lowest stable Compose ordinal as the recovery template source.
        item = min(candidates, key=lambda candidate: candidate[0])[1]
        config = item["Config"]
        host_config = item["HostConfig"]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError, ValueError) as exc:
        raise FleetCLIError("could not capture the Compose worker recovery state") from exc
    allowed_host_keys = (
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
    template = {
        "Config": {
            "Image": config.get("Image"),
            "Cmd": config.get("Cmd"),
            "Env": config.get("Env") or [],
            "Labels": config.get("Labels") or {},
            "WorkingDir": config.get("WorkingDir") or "",
        },
        "HostConfig": {
            key: host_config[key]
            for key in allowed_host_keys
            if key in host_config and host_config[key] is not None
        },
    }
    state["worker_runtime_template"] = template
    atomic_write(state_path, json.dumps(state, sort_keys=True, indent=2) + "\n", 0o600)


def _start_worker_runtime(paths: RuntimePaths, response: dict[str, Any]) -> None:
    if not paths.worker_compose.is_file():
        raise FleetCLIError("docker-compose.worker.yml is missing from the runtime")
    _prepare_worker_result_directories(paths)
    compose = _docker_compose_command()
    compose_env = paths.node / "compose.env"
    compose_values = _worker_compose_env(paths, response)
    _write_compose_env(compose_env, compose_values)
    image = validate_digest_image(str(response["worker_image_digest"]))
    _run(["docker", "pull", image], capture=False)
    _run(
        [
            *compose,
            "--project-name",
            compose_values["FLEET_COMPOSE_PROJECT_NAME"],
            "--env-file",
            str(compose_env),
            "-f",
            str(paths.worker_compose),
            "up",
            "-d",
        ],
        capture=False,
    )
    _persist_worker_runtime_template(paths, response)


def _build_local_broker_worker_image(paths: RuntimePaths) -> str:
    """Build the broker worker from this checkout without registry distribution."""
    dockerfile = paths.root / "scanner" / "Dockerfile"
    if not dockerfile.is_file() or not (paths.root / "api" / "broker_worker.py").is_file():
        raise FleetCLIError("--local-build requires a full ShakerScan source checkout")
    revision = (
        _run(
            ["git", "-C", str(paths.root), "rev-parse", "HEAD"],
            check=False,
        )
        if shutil.which("git")
        else None
    )
    source_revision = (
        str(revision.stdout or "").strip().lower()
        if revision is not None
        else ""
    )
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source_revision):
        source_revision = "unknown"
    suffix = source_revision[:12]
    if source_revision == "unknown":
        suffix = "dev"
    image = f"shakerscan-fleet-local:{suffix}"
    # Commit-tagged development images are deliberately immutable, but keeping
    # every old tag eventually fills small worker VPS disks. Remove only this
    # product's unused local-build tags; Docker refuses tags still backing a
    # running container. Preserve the image we are about to rebuild/reuse.
    _prune_obsolete_local_broker_images(keep_image=image)
    free_bytes = shutil.disk_usage(paths.root).free
    if free_bytes < LOCAL_BUILD_RECOMMENDED_FREE_BYTES:
        free_gib = free_bytes / 1024**3
        recommended_gib = LOCAL_BUILD_RECOMMENDED_FREE_BYTES / 1024**3
        print(
            f"Warning: local worker builds recommend {recommended_gib:.0f} GiB free after "
            f"old-image cleanup ({free_gib:.1f} GiB available). The build will continue; "
            "if it runs out of space, remove Docker build cache or expand the worker disk."
        )
    _run(
        [
            "docker", "build",
            "--build-arg", f"SCANNER_VERSION={suffix}",
            "--build-arg", f"SCANNER_SOURCE_REVISION={source_revision}",
            "--tag", image,
            "--file", str(dockerfile),
            str(paths.root),
        ],
        capture=False,
    )
    return image


def _prune_obsolete_local_broker_images(*, keep_image: str) -> list[str]:
    """Remove unused commit-tagged fleet development images, never volumes/data."""
    if not LOCAL_WORKER_IMAGE_RE.fullmatch(keep_image):
        raise FleetCLIError("local broker worker image reference is invalid")
    listed = _run(
        [
            "docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}",
            "--filter", "reference=shakerscan-fleet-local:*",
        ],
        check=False,
    )
    if listed.returncode != 0:
        return []
    removed: list[str] = []
    for candidate in sorted(set(str(listed.stdout or "").splitlines())):
        candidate = candidate.strip()
        if candidate == keep_image or not LOCAL_WORKER_IMAGE_RE.fullmatch(candidate):
            continue
        result = _run(["docker", "image", "rm", candidate], check=False)
        if result.returncode == 0:
            removed.append(candidate)
    return removed


def _start_broker_runtime(
    paths: RuntimePaths,
    response: dict[str, Any],
    *,
    runtime_image: str | None = None,
) -> None:
    if not paths.broker_worker_compose.is_file():
        raise FleetCLIError("docker-compose.broker-worker.yml is missing from the runtime")
    if runtime_image is not None and not LOCAL_WORKER_IMAGE_RE.fullmatch(runtime_image):
        raise FleetCLIError("local broker worker image reference is invalid")
    _prepare_worker_result_directories(paths)
    _stop_standalone_runtime_for_worker(paths)
    compose = _docker_compose_command()
    compose_env = paths.node / "compose.env"
    expected_image = validate_digest_image(str(response["worker_image_digest"]))
    compose_values = _worker_compose_env(paths, response, runtime_image=runtime_image)
    _write_compose_env(compose_env, compose_values)
    if runtime_image is None:
        _run(["docker", "pull", expected_image], capture=False)
    _run(
        [
            *compose,
            "--project-name",
            compose_values["FLEET_COMPOSE_PROJECT_NAME"],
            "--env-file",
            str(compose_env),
            "-f",
            str(paths.broker_worker_compose),
            "up",
            "-d",
        ],
        capture=False,
    )
    _persist_worker_runtime_template(paths, response)
    if runtime_image is not None:
        removed = _prune_obsolete_local_broker_images(keep_image=runtime_image)
        if removed:
            print(f"Removed {len(removed)} obsolete local fleet image tag(s)")


def _stop_standalone_runtime_for_worker(paths: RuntimePaths) -> None:
    """Retire only this runtime's standalone project before worker-only startup."""
    env = load_dotenv(paths.dotenv)
    if str(os.environ.get("FLEET_NETWORK_BACKEND") or env.get("FLEET_NETWORK_BACKEND") or "").strip():
        raise FleetCLIError("a fleet control plane cannot also join as a worker node")
    project = str(os.environ.get("COMPOSE_PROJECT_NAME") or env.get("COMPOSE_PROJECT_NAME") or "shakerscan")
    project = project.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", project):
        raise FleetCLIError("COMPOSE_PROJECT_NAME is invalid for worker-only conversion")
    running = _run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.ID}}",
        ],
        check=False,
    )
    if running.returncode != 0:
        raise FleetCLIError("could not inspect the standalone Docker Compose project")
    if not (running.stdout or "").strip():
        return
    compose_file = paths.root / "docker-compose.release.yml"
    if not compose_file.is_file():
        compose_file = paths.root / "docker-compose.yml"
    if not compose_file.is_file():
        raise FleetCLIError("standalone services are running but no Compose file is available to stop them")
    compose = _docker_compose_command()
    command = [
        *compose,
        "--project-name",
        project,
        "--project-directory",
        str(paths.root),
    ]
    if paths.dotenv.is_file():
        command.extend(["--env-file", str(paths.dotenv)])
    command.extend(["-f", str(compose_file), "down", "--remove-orphans"])
    print("Stopping standalone ShakerScan services for worker-only Fleet mode (data volumes are preserved)...")
    _run(command, capture=False)


def run_join_preflight(
    paths: RuntimePaths,
    args: argparse.Namespace,
    *,
    transport: str,
    public_url: str,
    enrollment_ca: Path | None,
) -> None:
    checks: list[PreflightCheck] = []
    _run_check(
        checks,
        "Linux host",
        _require_linux,
        success="supported",
        hint="Run fleet workers on Linux.",
    )
    required = ("docker",) if transport == "broker" else ("wg", "wg-quick", "ip", "docker")
    _run_check(
        checks,
        "Worker dependencies",
        lambda: _require_commands(required),
        success="installed",
        hint="Install Docker; WireGuard workers also need wireguard-tools and iproute2.",
    )
    _run_check(
        checks,
        "Docker Compose",
        _docker_compose_command,
        success="available",
        hint="Install the Docker Compose plugin and start Docker.",
    )
    if getattr(args, "local_build", False):
        if transport != "broker":
            checks.append(PreflightCheck(
                "Local worker build",
                "fail",
                "--local-build is currently supported only by the HTTPS broker transport",
                "Use --transport broker for source-checkout testing.",
            ))
        elif not (paths.root / "scanner" / "Dockerfile").is_file() or not (
            paths.root / "api" / "broker_worker.py"
        ).is_file():
            checks.append(PreflightCheck(
                "Local worker build",
                "fail",
                "the runtime is not a full ShakerScan source checkout",
                "Clone the repository on this worker before using --local-build.",
            ))
        else:
            checks.append(PreflightCheck(
                "Local worker build",
                "pass",
                "worker image will be built from this checkout without a registry pull",
            ))
    token = str(getattr(args, "token", "") or "")
    if token.startswith("ssj_"):
        checks.append(PreflightCheck("Join token", "pass", "format is valid"))
    else:
        checks.append(PreflightCheck(
            "Join token",
            "fail",
            "missing or malformed enrollment token",
            "Create a fresh token with shakerscan fleet join-token.",
        ))
    _run_check(
        checks,
        "Control-plane HTTPS",
        lambda: _require_healthy_api(public_url, enrollment_ca),
        success="reachable with a verified certificate",
        hint="Fix DNS/firewall access; for a private CA, pass --ca-cert /path/to/ca.pem.",
    )
    _require_preflight(checks)


def _wireguard_handshake_age() -> int:
    result = _run(
        ["wg", "show", INTERFACE_NAME, "latest-handshakes"],
        check=False,
        privileged=True,
    )
    if result.returncode != 0:
        raise FleetCLIError("could not inspect the WireGuard handshake")
    epochs: list[int] = []
    for line in (result.stdout or "").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit() and int(fields[1]) > 0:
            epochs.append(int(fields[1]))
    if not epochs:
        raise FleetCLIError("WireGuard has not completed a handshake")
    return max(0, int(time.time()) - max(epochs))


def _wireguard_failure_diagnostics(endpoint: str) -> str:
    details = [f"endpoint={endpoint}"]
    try:
        details.append(f"latest_handshake_age={_wireguard_handshake_age()}s")
    except FleetCLIError as exc:
        details.append(str(exc))
    interface = _run(["ip", "-brief", "address", "show", INTERFACE_NAME], check=False, privileged=True)
    if interface.returncode == 0 and (interface.stdout or "").strip():
        details.append((interface.stdout or "").strip())
    return "; ".join(details)


def command_join(paths: RuntimePaths, args: argparse.Namespace) -> None:
    transport = str(getattr(args, "transport", "overlay") or "overlay")
    public_url = validate_https_url(args.control_plane_url)
    enrollment_ca = validate_ca_certificate_path(getattr(args, "ca_cert", None))
    state_path = paths.node / "state.json"
    if not state_path.exists():
        run_join_preflight(
            paths,
            args,
            transport=transport,
            public_url=public_url,
            enrollment_ca=enrollment_ca,
        )
    else:
        _require_linux()
        _require_commands(("docker",) if transport == "broker" else ("wg", "wg-quick", "ip", "docker"))
        _docker_compose_command()
    _ensure_private_dir(paths.node)
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
            runtime_image = str(state.get("runtime_image_override") or "").strip() or None
            if getattr(args, "local_build", False):
                runtime_image = _build_local_broker_worker_image(paths)
                state["runtime_image_override"] = runtime_image
            resume_ca = enrollment_ca
            if resume_ca is None and str(state.get("tls_ca_mode") or "") == "file":
                resume_ca = paths.node / "ca.crt"
                if not resume_ca.is_file():
                    raise FleetCLIError("existing broker node state requires its persisted enrollment CA")
            desired_state = api_json(
                public_url,
                "GET",
                f"/fleet/nodes/{response['node_id']}/state",
                bearer=str(response["node_credential"]),
                ca_file=resume_ca,
            )
            desired_image = validate_digest_image(str(desired_state.get("worker_image_digest") or ""))
            enrolled_image = validate_digest_image(
                str(state.get("worker_image_digest") or response["worker_image_digest"])
            )
            response["worker_image_digest"] = desired_image
            state["bootstrap"] = response
            if runtime_image and not getattr(args, "local_build", False) and (
                desired_image != enrolled_image or bool(desired_state.get("rollout_in_progress"))
            ):
                runtime_image = None
                state.pop("runtime_image_override", None)
                print("Control-plane rollout superseded the local worker build override")
            atomic_write(state_path, json.dumps(state, sort_keys=True, indent=2) + "\n", 0o600)
            _start_broker_runtime(paths, response, runtime_image=runtime_image)
            print(f"HTTPS broker node {response['node_id']} resumed")
            if runtime_image:
                print(f"Local worker build active: {runtime_image} (registry pull skipped)")
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
        raise FleetCLIError("--token must contain the ssj_ enrollment token")
    runtime_image = (
        _build_local_broker_worker_image(paths)
        if transport == "broker" and getattr(args, "local_build", False)
        else None
    )
    private_key = public_key = None
    if transport == "overlay":
        private_key, public_key = generate_wireguard_keypair(
            paths.node / "wireguard.key", paths.node / "wireguard.pub"
        )
    hostname = socket.gethostname()[:255]
    labels: dict[str, Any] = {}
    labels["transport"] = transport
    if runtime_image:
        labels["runtime_mode"] = "local-build"
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
    raw_response = api_json(
        public_url,
        "POST",
        "/fleet/nodes/join",
        payload=payload,
        ca_file=enrollment_ca,
        timeout=30,
    )
    response = (
        _validated_broker_join_response(raw_response)
        if transport == "broker"
        else _validated_join_response(raw_response)
    )
    if transport == "broker":
        ca_path = paths.node / "ca.crt"
        if enrollment_ca is not None:
            atomic_write(ca_path, enrollment_ca.read_text(encoding="utf-8"), 0o644)
        bootstrap_state = {
            "node_id": response["node_id"],
            "node_credential": response["node_credential"],
            "control_plane_url": public_url,
            "worker_image_digest": response["worker_image_digest"],
            "tls_ca_mode": "file" if enrollment_ca is not None else "system",
            "transport": "broker",
            "enrollment_url": public_url,
            "bootstrap": response,
        }
        if runtime_image:
            bootstrap_state["runtime_image_override"] = runtime_image
        if enrollment_ca is not None:
            bootstrap_state["ca_cert_path"] = "/run/shakerscan-fleet/ca.crt"
        atomic_write(state_path, json.dumps(bootstrap_state, sort_keys=True, indent=2) + "\n", 0o600)
        _start_broker_runtime(paths, response, runtime_image=runtime_image)
        print(f"Joined fleet as outbound-only HTTPS broker node {response['node_id']}")
        if runtime_image:
            print(f"Local worker build active: {runtime_image} (registry pull skipped)")
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
        "tls_ca_mode": "file",
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
        diagnostics = _wireguard_failure_diagnostics(
            str(response["wireguard_control_plane_endpoint"])
        )
        raise FleetCLIError(
            "WireGuard overlay did not become ready. Confirm the control-plane peer was reconciled "
            f"and inbound UDP reaches it ({diagnostics}). Last HTTPS error: {last_error}"
        )
    handshake_age = _wireguard_handshake_age()
    if handshake_age > max(120, int(args.overlay_timeout) + 30):
        raise FleetCLIError(
            f"WireGuard overlay health succeeded but the latest handshake is stale ({handshake_age}s); "
            "check for an overlapping route before starting workers"
        )
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
        local_api_url(paths, getattr(args, "local_api", None)),
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
    init.add_argument(
        "--public-url",
        required=True,
        help="public HTTPS hostname; broker mode provisions HTTPS automatically when needed",
    )
    init.add_argument(
        "--https-mode",
        choices=["auto", "managed", "external"],
        default="auto",
        help="reuse working HTTPS or provision it automatically (default: auto)",
    )
    init.add_argument(
        "--ca-cert",
        help="PEM CA certificate for a private-CA public URL (system CA store is the default)",
    )
    init.add_argument(
        "--skip-public-check",
        action="store_true",
        help="allow split-horizon/hairpin-limited DNS after manually verifying the public HTTPS URL",
    )
    init.add_argument(
        "--worker-image",
        help="scanner image tag or digest (tags are resolved and persisted by immutable digest)",
    )
    init.add_argument("--workers", type=int, default=1)
    init.add_argument(
        "--no-reconcile-service",
        action="store_true",
        help="skip systemd timer installation and reconcile peers manually",
    )

    preflight = subparsers.add_parser(
        "preflight",
        help="check a planned fleet initialization without changing fleet state",
    )
    preflight.add_argument("--network", choices=["wireguard", "broker"], default="wireguard")
    preflight.add_argument("--overlay", default=DEFAULT_OVERLAY)
    preflight.add_argument("--endpoint", help="public WireGuard endpoint host:port")
    preflight.add_argument("--listen-port", type=int, default=DEFAULT_WG_PORT)
    preflight.add_argument("--tls-port", type=int, default=DEFAULT_TLS_PORT)
    preflight.add_argument("--public-url", required=True)
    preflight.add_argument("--https-mode", choices=["auto", "managed", "external"], default="auto")
    preflight.add_argument("--ca-cert")
    preflight.add_argument("--skip-public-check", action="store_true")
    preflight.add_argument("--worker-image", help="registry tag or digest-pinned scanner image")
    preflight.add_argument("--workers", type=int, default=1)
    preflight.add_argument("--no-reconcile-service", action="store_true")

    token = subparsers.add_parser("join-token", help="mint a bounded worker join command")
    token.add_argument("--role", choices=["worker"], default="worker")
    token.add_argument("--transport", choices=["overlay", "broker"], default="overlay")
    token.add_argument("--ttl", default="24h")
    token.add_argument(
        "--max-uses",
        type=int,
        default=1,
        choices=range(1, 129),
        metavar="N",
        help="maximum workers that may enroll with this token (default: 1)",
    )
    token.add_argument("--public-url")
    token.add_argument("--local-api", help="override the host-published control-plane API origin")

    revoke_token = subparsers.add_parser(
        "revoke-join-token",
        help="revoke the remaining uses of a join token",
    )
    revoke_token.add_argument("token_id")
    revoke_token.add_argument("--local-api", help="override the host-published control-plane API origin")

    join = subparsers.add_parser("join", help="join this Linux host as a worker node")
    join.add_argument("control_plane_url")
    join.add_argument("--token")
    join.add_argument(
        "--ca-cert",
        help="PEM CA certificate for a private-CA enrollment URL (system CA store is the default)",
    )
    join.add_argument("--name")
    join.add_argument("--transport", choices=["overlay", "broker"], default="overlay")
    join.add_argument(
        "--local-build",
        action="store_true",
        help="broker development only: build the worker from this checkout and skip the registry pull",
    )
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
    reconcile.add_argument("--local-api", help="override the host-published control-plane API origin")
    reconcile.add_argument("--quiet", action="store_true")
    repair = subparsers.add_parser(
        "repair-permissions",
        help="migrate a legacy root-owned Model Intake sandbox queue",
    )
    repair.add_argument(
        "--confirm",
        action="store_true",
        help="confirm changing only the private sandbox queue owner/mode",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    paths = RuntimePaths(Path(args.runtime).expanduser().resolve())
    try:
        if args.command == "init":
            command_init(paths, args)
        elif args.command == "preflight":
            command_preflight(paths, args)
        elif args.command == "join-token":
            command_join_token(paths, args)
        elif args.command == "revoke-join-token":
            command_revoke_join_token(paths, args)
        elif args.command == "join":
            command_join(paths, args)
        elif args.command == "reconcile":
            command_reconcile(paths, args)
        elif args.command == "repair-permissions":
            command_repair_permissions(paths, args)
        else:
            parser.error("unknown command")
    except FleetCLIError as exc:
        print(f"fleet error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
