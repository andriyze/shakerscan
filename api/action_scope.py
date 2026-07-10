"""Central scope guard for future state-changing actions.

The guard is deliberately deterministic and side-effect free. API handlers can
persist the returned receipt, but validation itself does not perform network
requests or follow redirects.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
import urllib.parse
from typing import Any


SAFE_LAB_ENVIRONMENTS = {"development", "dev", "preview", "staging", "lab", "test"}
ALLOWED_SCHEMES = {"http", "https"}
CIDR_RE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?![\w:])")


@dataclass(frozen=True)
class ScopeCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class ScopeReceipt:
    receipt_id: str
    input_scope: dict[str, Any]
    normalized_scope: dict[str, Any]
    verdict: str
    checks: tuple[ScopeCheck, ...]
    blocked_by: tuple[str, ...]
    warnings: tuple[str, ...]
    environment: str
    allowed_hosts: tuple[str, ...]
    allowed_root_domains: tuple[str, ...]
    redirect_destinations: tuple[dict[str, Any], ...]


def _add_check(checks: list[ScopeCheck], name: str, status: str, message: str) -> None:
    checks.append(ScopeCheck(name=name, status=status, message=message))


def _canonical_host(value: str | None) -> str:
    host = str(value or "").strip().strip("[]").lower()
    if host.endswith("."):
        host = host[:-1]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _host_matches(host: str, allowed_hosts: tuple[str, ...], allowed_root_domains: tuple[str, ...]) -> bool:
    if host in allowed_hosts:
        return True
    return any(host == root or host.endswith(f".{root}") for root in allowed_root_domains)


def _ip_scope_block_reason(host: str, environment: str) -> str | None:
    lowered = host.lower().strip("[]")
    if lowered in {"localhost", "localhost.localdomain"}:
        return "loopback_or_private_range"
    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return None
    if environment in SAFE_LAB_ENVIRONMENTS:
        return None
    if (
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return "loopback_or_private_range"
    return None


def _cidr_block_reasons(raw: str) -> list[str]:
    reasons: list[str] = []
    for match in CIDR_RE.findall(raw):
        try:
            network = ipaddress.ip_network(match, strict=False)
        except ValueError:
            continue
        if (network.version == 4 and network.prefixlen <= 24) or (network.version == 6 and network.prefixlen <= 64):
            reasons.append("broad_cidr")
    return reasons


def _parse_absolute_http_url(raw_url: str) -> urllib.parse.ParseResult | None:
    try:
        parsed = urllib.parse.urlparse(raw_url)
    except Exception:
        return None
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.netloc:
        return None
    return parsed


def _receipt_id(input_payload: dict[str, Any], verdict: str, blocked_by: tuple[str, ...]) -> str:
    material = {
        "input_scope": input_payload,
        "verdict": verdict,
        "blocked_by": list(blocked_by),
    }
    digest = hashlib.sha256(repr(material).encode("utf-8")).hexdigest()
    return digest[:32]


def evaluate_scope(
    raw_url: str,
    *,
    allowed_hosts: list[str] | tuple[str, ...] | None = None,
    allowed_root_domains: list[str] | tuple[str, ...] | None = None,
    environment: str = "production",
    redirect_urls: list[str] | tuple[str, ...] | None = None,
    target_id: str | None = None,
) -> ScopeReceipt:
    checks: list[ScopeCheck] = []
    blocked: list[str] = []
    warnings: list[str] = []

    raw = str(raw_url or "").strip()
    env = str(environment or "production").strip().lower()
    allow_hosts = tuple(_canonical_host(item) for item in (allowed_hosts or ()) if str(item or "").strip())
    allow_roots = tuple(_canonical_host(item) for item in (allowed_root_domains or ()) if str(item or "").strip())

    input_scope = {
        "url": raw,
        "target_id": target_id,
    }

    for reason in _cidr_block_reasons(raw):
        blocked.append(reason)
        _add_check(checks, reason, "blocked", "Broad CIDR scope is not allowed in command receipts.")

    if not raw:
        blocked.append("malformed_url")
        _add_check(checks, "malformed_url", "blocked", "URL is required.")
        normalized = {}
    elif raw.startswith("//"):
        blocked.append("scheme_relative_url")
        _add_check(checks, "scheme_relative_url", "blocked", "Scheme-relative URLs are rejected.")
        normalized = {}
    else:
        parsed = _parse_absolute_http_url(raw)
        if parsed is None:
            blocked.append("malformed_url")
            _add_check(checks, "malformed_url", "blocked", "URL must be an absolute http(s) URL.")
            normalized = {}
        else:
            host_raw = parsed.hostname or ""
            host = _canonical_host(host_raw)
            normalized = {
                "scheme": parsed.scheme.lower(),
                "host": host,
                "port": parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                "path": parsed.path or "/",
            }
            _add_check(checks, "malformed_url", "passed", "URL parsed as absolute http(s).")

            if parsed.username or parsed.password or "@" in parsed.netloc.split("@", 1)[0]:
                blocked.append("userinfo")
                _add_check(checks, "userinfo", "blocked", "Userinfo in URLs is rejected.")
            else:
                _add_check(checks, "userinfo", "passed", "No URL userinfo present.")

            if host_raw.endswith("."):
                blocked.append("trailing_dot_host")
                _add_check(checks, "trailing_dot_host", "blocked", "Trailing-dot hostnames are rejected.")
            else:
                _add_check(checks, "trailing_dot_host", "passed", "No trailing-dot hostname.")

            if host_raw and (host_raw.lower() != host or host.startswith("xn--") or ".xn--" in host):
                blocked.append("unicode_or_punycode_confusion")
                _add_check(checks, "unicode_or_punycode_confusion", "blocked", "Unicode/punycode hostnames require explicit review.")
            else:
                _add_check(checks, "unicode_or_punycode_confusion", "passed", "Hostname is plain ASCII.")

            ip_reason = _ip_scope_block_reason(host, env)
            if ip_reason:
                blocked.append(ip_reason)
                _add_check(checks, ip_reason, "blocked", "Loopback/private/reserved network targets require lab policy.")
            else:
                _add_check(checks, "loopback_or_private_range", "passed", "No blocked private network scope.")

            if allow_hosts or allow_roots:
                if not _host_matches(host, allow_hosts, allow_roots):
                    blocked.append("host_out_of_allowed_scope")
                    _add_check(checks, "host_out_of_allowed_scope", "blocked", "Host is outside the provided allowed scope.")
                else:
                    _add_check(checks, "host_out_of_allowed_scope", "passed", "Host matches allowed scope.")
            else:
                warnings.append("no_allowed_scope_supplied")
                _add_check(checks, "host_out_of_allowed_scope", "warning", "No allowed_hosts or allowed_root_domains were supplied.")

    redirect_results: list[dict[str, Any]] = []
    base_host = str(normalized.get("host") or "") if "normalized" in locals() else ""
    for destination in redirect_urls or ():
        dest_raw = str(destination or "").strip()
        dest_parsed = _parse_absolute_http_url(dest_raw)
        if dest_parsed is None:
            blocked.append("redirect_out_of_scope")
            redirect_results.append({"url": dest_raw, "verdict": "blocked", "reason": "malformed_redirect_url"})
            continue
        dest_host = _canonical_host(dest_parsed.hostname or "")
        if allow_hosts or allow_roots:
            dest_allowed = _host_matches(dest_host, allow_hosts, allow_roots)
        else:
            dest_allowed = bool(base_host and dest_host == base_host)
        if not dest_allowed:
            blocked.append("redirect_out_of_scope")
            redirect_results.append({"url": dest_raw, "host": dest_host, "verdict": "blocked", "reason": "redirect_out_of_scope"})
        else:
            redirect_results.append({"url": dest_raw, "host": dest_host, "verdict": "allowed"})
    if redirect_results:
        if any(item["verdict"] == "blocked" for item in redirect_results):
            _add_check(checks, "redirect_out_of_scope", "blocked", "One or more redirect destinations leave allowed scope.")
        else:
            _add_check(checks, "redirect_out_of_scope", "passed", "Redirect destinations remain in scope.")
    else:
        _add_check(checks, "redirect_out_of_scope", "not_checked", "No redirect destinations supplied.")

    unique_blocked = tuple(dict.fromkeys(blocked))
    unique_warnings = tuple(dict.fromkeys(warnings))
    if unique_blocked:
        verdict = "blocked"
    elif unique_warnings:
        verdict = "needs_approval"
    else:
        verdict = "allowed"

    return ScopeReceipt(
        receipt_id=_receipt_id(input_scope, verdict, unique_blocked),
        input_scope=input_scope,
        normalized_scope=normalized if "normalized" in locals() else {},
        verdict=verdict,
        checks=tuple(checks),
        blocked_by=unique_blocked,
        warnings=unique_warnings,
        environment=env,
        allowed_hosts=allow_hosts,
        allowed_root_domains=allow_roots,
        redirect_destinations=tuple(redirect_results),
    )


def receipt_to_dict(receipt: ScopeReceipt) -> dict[str, Any]:
    return {
        "receipt_id": receipt.receipt_id,
        "input_scope": receipt.input_scope,
        "normalized_scope": receipt.normalized_scope,
        "verdict": receipt.verdict,
        "checks": [check.__dict__ for check in receipt.checks],
        "blocked_by": list(receipt.blocked_by),
        "warnings": list(receipt.warnings),
        "environment": receipt.environment,
        "allowed_hosts": list(receipt.allowed_hosts),
        "allowed_root_domains": list(receipt.allowed_root_domains),
        "redirect_destinations": list(receipt.redirect_destinations),
    }


def _decode_json_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, (bytes, bytearray)):
        value = value.decode()
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return value
    return value


def runtime_scope_guard_from_scope(scope: dict[str, Any]) -> dict[str, Any]:
    """Build the non-secret scope contract queued workers must re-check."""
    normalized = _decode_json_value(scope.get("normalized_scope")) or {}
    allowed_hosts = _decode_json_value(scope.get("allowed_hosts")) or []
    allowed_roots = _decode_json_value(scope.get("allowed_root_domains")) or []
    if not isinstance(allowed_hosts, list):
        allowed_hosts = []
    if not isinstance(allowed_roots, list):
        allowed_roots = []
    normalized_host = normalized.get("host") if isinstance(normalized, dict) else None
    if normalized_host and not allowed_hosts:
        allowed_hosts = [normalized_host]

    guard = {
        "scope_receipt_id": str(scope.get("id") or ""),
        "environment": str(scope.get("environment") or "production").strip().lower() or "production",
        "allowed_hosts": [str(item) for item in allowed_hosts if str(item or "").strip()],
        "allowed_root_domains": [str(item) for item in allowed_roots if str(item or "").strip()],
        "normalized_scope": normalized if isinstance(normalized, dict) else {},
        "requires_runtime_destination_check": True,
        "requires_runtime_dns_check": True,
    }
    if scope.get("target_id"):
        guard["target_id"] = str(scope.get("target_id"))
    return guard


def _evaluate_runtime_dns_observations(
    urls: tuple[str, ...],
    observations: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None,
    *,
    environment: str,
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    expected_hosts: list[str] = []
    for url in urls:
        parsed = _parse_absolute_http_url(str(url or "").strip())
        host = _canonical_host(parsed.hostname or "") if parsed else ""
        if host and host not in expected_hosts:
            expected_hosts.append(host)

    observations_by_host: dict[str, list[str]] = {}
    for observation in observations or ():
        if not isinstance(observation, dict):
            continue
        host = _canonical_host(observation.get("host"))
        raw_ips = observation.get("ips")
        if not isinstance(raw_ips, (list, tuple)):
            raw_ips = [observation.get("ip")] if observation.get("ip") else []
        ips = [str(item).strip() for item in raw_ips if str(item or "").strip()]
        if host and ips:
            observations_by_host.setdefault(host, []).extend(ips)

    results: list[dict[str, Any]] = []
    blocked: list[str] = []
    warnings: list[str] = []
    for host in expected_hosts:
        try:
            ipaddress.ip_address(host)
            continue
        except ValueError:
            pass
        ips = list(dict.fromkeys(observations_by_host.get(host, [])))
        if not ips:
            blocked.append("runtime_dns_unverified")
            results.append({"host": host, "ips": [], "verdict": "blocked", "reason": "runtime_dns_unverified"})
            continue
        result: dict[str, Any] = {"host": host, "ips": ips, "verdict": "allowed"}
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                blocked.append("runtime_dns_invalid")
                result.update({"verdict": "blocked", "reason": "runtime_dns_invalid"})
                continue
            if _ip_scope_block_reason(ip, environment):
                blocked.append("runtime_dns_private_range")
                result.update({"verdict": "blocked", "reason": "runtime_dns_private_range"})
        results.append(result)
    return results, list(dict.fromkeys(blocked)), list(dict.fromkeys(warnings))


def evaluate_runtime_destination_scope(
    runtime_scope_guard: dict[str, Any] | None,
    destination_url: str | None,
    *,
    redirect_urls: list[str] | tuple[str, ...] | None = None,
    resolution_observations: list[dict[str, Any]] | tuple[dict[str, Any], ...] | None = None,
) -> dict[str, Any]:
    """Re-check actual network destinations against an approval scope guard.

    Network-following workers should call this with the post-resolution or
    post-redirect destination they actually touched. Missing guard/destination
    fails closed so unknown runtime scope cannot be treated as in-scope.
    """
    if not isinstance(runtime_scope_guard, dict) or not runtime_scope_guard:
        return {
            "verdict": "blocked",
            "status": "blocked",
            "blocked_by": ["runtime_scope_guard_missing"],
            "warnings": [],
            "checks": [],
            "redirect_destinations": [],
            "runtime_scope_guard_present": False,
        }
    raw_destination = str(destination_url or "").strip()
    if not raw_destination:
        return {
            "verdict": "blocked",
            "status": "blocked",
            "blocked_by": ["runtime_destination_unverified"],
            "warnings": [],
            "checks": [],
            "redirect_destinations": [],
            "runtime_scope_guard_present": True,
            "scope_receipt_id": runtime_scope_guard.get("scope_receipt_id"),
        }

    normalized = (
        runtime_scope_guard.get("normalized_scope")
        if isinstance(runtime_scope_guard.get("normalized_scope"), dict)
        else {}
    )
    allowed_hosts = (
        runtime_scope_guard.get("allowed_hosts")
        if isinstance(runtime_scope_guard.get("allowed_hosts"), list)
        else []
    )
    allowed_roots = (
        runtime_scope_guard.get("allowed_root_domains")
        if isinstance(runtime_scope_guard.get("allowed_root_domains"), list)
        else []
    )
    if not allowed_hosts and normalized.get("host"):
        allowed_hosts = [normalized["host"]]

    receipt = evaluate_scope(
        raw_destination,
        allowed_hosts=allowed_hosts,
        allowed_root_domains=allowed_roots,
        environment=str(runtime_scope_guard.get("environment") or "production"),
        redirect_urls=redirect_urls,
        target_id=str(runtime_scope_guard.get("target_id") or "") or None,
    )
    payload = receipt_to_dict(receipt)
    dns_results: list[dict[str, Any]] = []
    dns_blocked: list[str] = []
    dns_warnings: list[str] = []
    if runtime_scope_guard.get("requires_runtime_dns_check"):
        dns_results, dns_blocked, dns_warnings = _evaluate_runtime_dns_observations(
            (raw_destination, *(str(item or "") for item in (redirect_urls or ()))),
            resolution_observations,
            environment=str(runtime_scope_guard.get("environment") or "production"),
        )
        if dns_blocked:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "blocked",
                "message": "A runtime hostname resolution was missing, invalid, or outside the permitted network scope.",
            })
        elif dns_warnings:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "degraded",
                "message": "One or more runtime hostname resolutions were not observed.",
            })
        else:
            payload.setdefault("checks", []).append({
                "name": "runtime_dns_resolution",
                "status": "passed",
                "message": "Observed runtime hostname resolutions remained in policy.",
            })
    payload["resolution_observations"] = dns_results
    payload["blocked_by"] = list(dict.fromkeys([*(payload.get("blocked_by") or []), *dns_blocked]))
    payload["warnings"] = list(dict.fromkeys([*(payload.get("warnings") or []), *dns_warnings]))
    if payload["blocked_by"]:
        payload["verdict"] = "blocked"
        payload["status"] = "blocked"
    elif payload["warnings"]:
        payload["verdict"] = "degraded"
        payload["status"] = "degraded"
    else:
        payload["verdict"] = "allowed"
        payload["status"] = "allowed"
    if payload["status"] == "blocked" and not payload.get("blocked_by"):
        payload["blocked_by"] = ["runtime_destination_unverified"]
    payload["runtime_scope_guard_present"] = True
    payload["scope_receipt_id"] = runtime_scope_guard.get("scope_receipt_id")
    return payload
