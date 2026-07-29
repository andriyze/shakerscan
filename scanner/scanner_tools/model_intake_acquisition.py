"""SSRF-resistant HTTP acquisition for untrusted model-intake references.

The downloader resolves and validates every destination before opening a socket,
then connects to the validated address directly. Redirects are handled manually
so each hop receives the same validation and cross-origin credentials are not
forwarded.
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import ssl
import urllib.parse
from typing import Any


DEFAULT_REDIRECT_LIMIT = 5
DEFAULT_ALLOWED_PORTS = {443}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
SENSITIVE_REDIRECT_HEADERS = {"authorization", "cookie", "proxy-authorization"}


class AcquisitionPolicyError(ValueError):
    """Raised before an unsafe model-intake network connection is opened."""


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _string_tokens(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw = value
    else:
        raw = str(value).split(",")
    return [str(item).strip().lower().rstrip(".") for item in raw if str(item).strip()]


def acquisition_policy(options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the explicit acquisition exceptions configured for one intake."""
    options = options or {}
    allowed_hosts = _string_tokens(
        options.get("allowed_acquisition_hosts")
        or options.get("allowed_hosts")
        or os.getenv("MODEL_INTAKE_ALLOWED_HOSTS")
    )
    raw_ports = options.get("allowed_acquisition_ports") or os.getenv("MODEL_INTAKE_ALLOWED_PORTS")
    allowed_ports: set[int] = set(DEFAULT_ALLOWED_PORTS)
    for token in _string_tokens(raw_ports):
        try:
            port = int(token)
        except ValueError as exc:
            raise AcquisitionPolicyError(f"Invalid allowed acquisition port: {token}") from exc
        if not 1 <= port <= 65535:
            raise AcquisitionPolicyError(f"Allowed acquisition port is out of range: {port}")
        allowed_ports.add(port)

    allow_insecure_http = _boolish(
        options.get("allow_insecure_http") or os.getenv("MODEL_INTAKE_ALLOW_INSECURE_HTTP")
    )
    if allow_insecure_http:
        allowed_ports.add(80)

    return {
        "allow_insecure_http": allow_insecure_http,
        "allow_private_networks": _boolish(
            options.get("allow_private_networks") or os.getenv("MODEL_INTAKE_ALLOW_PRIVATE_NETWORKS")
        ),
        "allowed_hosts": allowed_hosts,
        "allowed_ports": sorted(allowed_ports),
        "max_redirects": min(
            DEFAULT_REDIRECT_LIMIT,
            max(0, int(options.get("max_acquisition_redirects") or DEFAULT_REDIRECT_LIMIT)),
        ),
    }


def _canonical_hostname(hostname: str) -> str:
    host = str(hostname or "").strip().rstrip(".")
    if not host or any(ord(char) < 33 or ord(char) == 127 for char in host):
        raise AcquisitionPolicyError("Artifact URL hostname is missing or contains control characters")
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise AcquisitionPolicyError("Artifact URL hostname is not valid IDNA") from exc


def _host_allowed(host: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    for raw_pattern in patterns:
        pattern = _canonical_hostname(raw_pattern.removeprefix("*."))
        if raw_pattern.startswith("*."):
            if host.endswith(f".{pattern}") and host != pattern:
                return True
        elif host == pattern:
            return True
    return False


def _blocked_ip_reason(value: str) -> str | None:
    ip = ipaddress.ip_address(value)
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if not ip.is_global:
        return "non_global"
    return None


def _resolve_host(host: str, port: int) -> list[str]:
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise AcquisitionPolicyError(f"Artifact hostname DNS resolution failed: {exc}") from exc
    addresses: list[str] = []
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        try:
            normalized = str(ipaddress.ip_address(str(sockaddr[0])))
        except ValueError as exc:
            raise AcquisitionPolicyError("Artifact hostname resolved to an invalid IP address") from exc
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise AcquisitionPolicyError("Artifact hostname did not resolve to an IP address")
    return addresses


def validate_url_destination(url: str, policy: dict[str, Any] | None = None) -> dict[str, Any]:
    """Validate one URL and resolve all addresses before any network connection."""
    policy = policy or acquisition_policy()
    parsed = urllib.parse.urlsplit(str(url or ""))
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise AcquisitionPolicyError(f"Unsupported acquisition URL scheme: {scheme or 'missing'}")
    if scheme == "http" and not policy.get("allow_insecure_http"):
        raise AcquisitionPolicyError("Plain HTTP acquisition is disabled; use HTTPS or an explicit development exception")
    if parsed.username is not None or parsed.password is not None:
        raise AcquisitionPolicyError("Artifact URLs must not contain embedded credentials")
    if not parsed.hostname:
        raise AcquisitionPolicyError("Artifact URL must include a hostname")
    host = _canonical_hostname(parsed.hostname)
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise AcquisitionPolicyError("Artifact URL port is invalid") from exc
    allowed_ports = {int(item) for item in policy.get("allowed_ports") or DEFAULT_ALLOWED_PORTS}
    if port not in allowed_ports:
        raise AcquisitionPolicyError(f"Artifact URL port {port} is not allowed by acquisition policy")
    if not _host_allowed(host, list(policy.get("allowed_hosts") or [])):
        raise AcquisitionPolicyError("Artifact URL hostname is not in the acquisition allowlist")

    addresses = _resolve_host(host, port)
    if not policy.get("allow_private_networks"):
        blocked = [
            {"ip": address, "reason": _blocked_ip_reason(address)}
            for address in addresses
            if _blocked_ip_reason(address)
        ]
        if blocked:
            reasons = ",".join(sorted({str(item["reason"]) for item in blocked}))
            raise AcquisitionPolicyError(
                f"Artifact hostname resolves to a blocked network range: {reasons}"
            )

    default_port = 443 if scheme == "https" else 80
    host_header = f"[{host}]" if ":" in host else host
    if port != default_port:
        host_header = f"{host_header}:{port}"
    return {
        "url": urllib.parse.urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, "")),
        "scheme": scheme,
        "host": host,
        "host_header": host_header,
        "port": port,
        "addresses": addresses,
    }


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, connect_ip: str, port: int, timeout: int):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_ip, self.port),
            timeout=self.timeout,
            source_address=self.source_address,
        )
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def _request_target(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    path = urllib.parse.quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        path = f"{path}?{urllib.parse.quote(parsed.query, safe='=&%:@!$\'()*+,;/?-._~')}"
    return path


def _request_once(
    destination: dict[str, Any],
    headers: dict[str, str],
    max_bytes: int,
    timeout_seconds: int,
) -> tuple[bytes, dict[str, Any]]:
    connect_ip = str(destination["addresses"][0])
    if destination["scheme"] == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(
            str(destination["host"]), connect_ip, int(destination["port"]), timeout_seconds
        )
    else:
        connection = http.client.HTTPConnection(connect_ip, int(destination["port"]), timeout=timeout_seconds)
    request_headers = {**headers, "Host": str(destination["host_header"]), "Accept-Encoding": "identity"}
    try:
        connection.request("GET", _request_target(str(destination["url"])), headers=request_headers)
        response = connection.getresponse()
        response_headers = {key: value for key, value in response.getheaders()}
        data = response.read(max_bytes + 1)
        return data, {
            "status": response.status,
            "reason": response.reason,
            "headers": response_headers,
            "remote_ip": connect_ip,
            "resolved_ips": list(destination["addresses"]),
        }
    finally:
        connection.close()


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    return scheme, _canonical_hostname(parsed.hostname or ""), parsed.port or (443 if scheme == "https" else 80)


def download_http(
    url: str,
    max_bytes: int,
    timeout_seconds: int,
    headers: dict[str, str] | None = None,
    policy: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Download a bounded prefix through a pre-connect, redirect-safe policy."""
    if max_bytes < 1:
        raise AcquisitionPolicyError("Acquisition byte limit must be positive")
    effective_policy = policy or acquisition_policy()
    current_url = str(url or "").strip()
    current_headers = {
        "User-Agent": "ShakerScan-ModelIntake/2.0",
        "Range": f"bytes=0-{max_bytes - 1}",
        **(headers or {}),
    }
    redirect_chain: list[str] = []
    resolution_chain: list[dict[str, Any]] = []
    max_redirects = int(effective_policy.get("max_redirects", DEFAULT_REDIRECT_LIMIT))

    for hop in range(max_redirects + 1):
        destination = validate_url_destination(current_url, effective_policy)
        resolution_chain.append({
            "url": current_url,
            "host": destination["host"],
            "port": destination["port"],
            "ips": list(destination["addresses"]),
        })
        data, response_meta = _request_once(destination, current_headers, max_bytes, timeout_seconds)
        status = int(response_meta["status"])
        response_headers = response_meta["headers"]
        location = response_headers.get("Location") or response_headers.get("location")
        if status in REDIRECT_STATUSES and location:
            if hop >= max_redirects:
                raise AcquisitionPolicyError(f"Artifact redirect limit exceeded ({max_redirects})")
            next_url = urllib.parse.urljoin(current_url, location)
            # Validate before preserving or dropping credentials and before the next
            # loop can open a socket. Cross-origin secrets never follow redirects.
            validate_url_destination(next_url, effective_policy)
            if _origin(next_url) != _origin(current_url):
                current_headers = {
                    key: value
                    for key, value in current_headers.items()
                    if key.lower() not in SENSITIVE_REDIRECT_HEADERS
                }
            redirect_chain.append(next_url)
            current_url = next_url
            continue

        content_range = response_headers.get("Content-Range") or response_headers.get("content-range")
        content_length = response_headers.get("Content-Length") or response_headers.get("content-length")
        try:
            declared_length = int(content_length) if content_length is not None else None
        except ValueError:
            declared_length = None
        truncated = len(data) > max_bytes or (declared_length is not None and declared_length > max_bytes)
        if status == 206:
            truncated = True
        return data[:max_bytes], {
            "source": "http",
            "requested_url": url,
            "final_url": current_url,
            "redirected": bool(redirect_chain),
            "redirect_chain": redirect_chain,
            "resolution_chain": resolution_chain,
            "remote_ip": response_meta.get("remote_ip"),
            "status": status,
            "content_type": response_headers.get("Content-Type") or response_headers.get("content-type"),
            "content_length": content_length,
            "content_range": content_range,
            "range_requested": f"bytes=0-{max_bytes - 1}",
            "range_satisfied": status == 206 and bool(content_range),
            "bytes_observed": min(len(data), max_bytes),
            "truncated": truncated,
            "acquisition_policy": {
                "https_required": not bool(effective_policy.get("allow_insecure_http")),
                "private_networks_blocked": not bool(effective_policy.get("allow_private_networks")),
                "host_allowlist_enforced": bool(effective_policy.get("allowed_hosts")),
                "redirect_limit": max_redirects,
                "dns_pinned": True,
            },
        }

    raise AcquisitionPolicyError("Artifact acquisition ended without a response")
