#!/usr/bin/env python3
import argparse
import asyncio
import base64
import faulthandler
import fnmatch
import hashlib
import hmac
import json
import logging
import os
import re
import shlex
import signal
import socket
import ssl
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from typing import Any

from scanner_tools.common import is_in_scope_url, run
try:
    from constants import resolve_scan_budget
except ImportError:
    from scanner.constants import resolve_scan_budget
from scanner_tools.coverage_tracker import CoverageTracker
from scanner_tools.har_discovery import (
    extract_discovery_from_har,
    get_testable_endpoints,
    get_bola_candidates,
    HARDiscoveryResult,
)
from scanner_tools.signal_types import Signal, SignalSet
from scanner_tools.verification_phase import verify_high_severity_findings
try:
    from scanner_tools.attack_chains import analyze_attack_chains
except ImportError:
    analyze_attack_chains = None

REPORT_SCHEMA_VERSION = "2026-01-28"
SCANNER_VERSION = os.environ.get("SCANNER_VERSION") or os.environ.get("GIT_COMMIT") or "dev"
CHECKPOINT_FILE = os.environ.get("SCAN_CHECKPOINT_FILE")

# Enable stack dumps on SIGUSR1/SIGUSR2 for debugging hangs (best-effort).
if os.environ.get("SCAN_FAULTHANDLER", "1") != "0":
    try:
        sig_usr1 = getattr(signal, "SIGUSR1", None)
        if sig_usr1 is not None:
            faulthandler.register(sig_usr1, all_threads=True, chain=False)
        sig_usr2 = getattr(signal, "SIGUSR2", None)
        if sig_usr2 is not None:
            faulthandler.register(sig_usr2, all_threads=True, chain=False)
    except Exception:
        pass

# Global reference to current report for checkpoint saving
_current_report: dict | None = None


def save_checkpoint(report: dict, phase: str) -> None:
    """Save current report state to checkpoint file for recovery."""
    global _current_report
    _current_report = report

    if not CHECKPOINT_FILE:
        return

    try:
        checkpoint_data = {
            "phase": phase,
            "timestamp": datetime.now(UTC).isoformat(),
            "partial": True,
            "report": report
        }
        # Write atomically using temp file + rename
        temp_file = CHECKPOINT_FILE + ".tmp"
        with open(temp_file, "w") as f:
            json.dump(checkpoint_data, f)
        os.replace(temp_file, CHECKPOINT_FILE)
    except Exception as e:
        print(f"[checkpoint] Failed to save checkpoint: {e}", file=sys.stderr)


def emit_progress(phase: str, pct: int, message: str | None = None) -> None:
    try:
        pct_int = int(pct)
    except Exception:
        pct_int = 0
    pct_int = max(0, min(100, pct_int))
    parts = [f"[progress] phase={phase}", f"pct={pct_int}"]
    if message:
        safe_message = " ".join(str(message).split())
        parts.append(f"message={safe_message}")
    print(" ".join(parts), file=sys.stderr, flush=True)


def _normalize_port_entry(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, int):
        return {"port": entry, "protocol": "tcp", "state": "open"}
    if not isinstance(entry, dict):
        return None
    port = entry.get("port")
    if port is None:
        return None
    normalized = dict(entry)
    if "protocol" not in normalized and "transport" in normalized:
        normalized["protocol"] = normalized.get("transport")
    normalized.setdefault("protocol", "tcp")
    normalized.setdefault("state", "open")
    return normalized


def _merge_port_list(primary: list[Any] | None, secondary: list[Any] | None) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen = set()
    for source in (primary or []):
        norm = _normalize_port_entry(source)
        if not norm:
            continue
        key = (norm.get("port"), norm.get("protocol"), norm.get("state"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(norm)
    for source in (secondary or []):
        norm = _normalize_port_entry(source)
        if not norm:
            continue
        key = (norm.get("port"), norm.get("protocol"), norm.get("state"))
        if key in seen:
            continue
        seen.add(key)
        merged.append(norm)
    return merged


def _merge_port_scan_results(primary: dict[str, Any] | None, secondary: dict[str, Any] | None) -> dict[str, Any]:
    primary = primary or {}
    secondary = secondary or {}

    merged = {
        "open_ports": _merge_port_list(primary.get("open_ports"), secondary.get("open_ports")),
        "services": primary.get("services") or secondary.get("services") or [],
        "os_detection": primary.get("os_detection") or secondary.get("os_detection") or {},
        "vulnerabilities": primary.get("vulnerabilities") or secondary.get("vulnerabilities") or [],
        "scan_completed": primary.get("scan_completed") if primary.get("scan_completed") is not None else secondary.get("scan_completed"),
    }
    if primary.get("errors") or secondary.get("errors"):
        merged["errors"] = primary.get("errors") or secondary.get("errors")

    return merged

# Architecture modules: Import from new modular structure
# These modules extract common functionality for better maintainability
# Support both package import (from scanner.scanner) and script import (python3 scanner.py)
try:
    from .constants import NUCLEI_PROMOTE_TEMPLATES, SMART_SCAN_BUDGETS
    from .grading import grade
    from .findings import (
        normalize_finding,
        deduplicate_findings,
        apply_dast_precision_policy,
        now_utc_iso,
    )
    from .signals import extract_signals_from_nuclei
    from .reporting import (
        emit_config_findings,
        _reproCurlHost,
        _reproCurlCors,
        _reproDig,
        _reproDelv,
        _reproTLS,
        _ai_safe_commands_for_finding,
        _ai_rule_verdict,
        _mask_text_host,
        _redact_sensitive,
        _redact_body_value,
        _redact_body_structure,
        _redact_body_for_report,
        _mask_structure,
        _generate_fallback_executive_summary,
        HONEYPOT_TEST_DOMAINS,
    )
except ImportError:
    try:
        from scanner.constants import NUCLEI_PROMOTE_TEMPLATES, SMART_SCAN_BUDGETS
        from scanner.grading import grade
        from scanner.findings import (
            normalize_finding,
            deduplicate_findings,
            apply_dast_precision_policy,
            now_utc_iso,
        )
        from scanner.signals import extract_signals_from_nuclei
        from scanner.reporting import (
            emit_config_findings,
            _reproCurlHost,
            _reproCurlCors,
            _reproDig,
            _reproDelv,
            _reproTLS,
            _ai_safe_commands_for_finding,
            _ai_rule_verdict,
            _mask_text_host,
            _redact_sensitive,
            _redact_body_value,
            _redact_body_structure,
            _redact_body_for_report,
            _mask_structure,
            _generate_fallback_executive_summary,
            HONEYPOT_TEST_DOMAINS,
        )
    except ImportError:
        from constants import NUCLEI_PROMOTE_TEMPLATES, SMART_SCAN_BUDGETS
        from grading import grade
        from findings import (
            normalize_finding,
            deduplicate_findings,
            apply_dast_precision_policy,
            now_utc_iso,
        )
        from signals import extract_signals_from_nuclei
        from reporting import (
            emit_config_findings,
            _reproCurlHost,
            _reproCurlCors,
            _reproDig,
            _reproDelv,
            _reproTLS,
            _ai_safe_commands_for_finding,
            _ai_rule_verdict,
            _mask_text_host,
            _redact_sensitive,
            _redact_body_value,
            _redact_body_structure,
            _redact_body_for_report,
            _mask_structure,
            _generate_fallback_executive_summary,
            HONEYPOT_TEST_DOMAINS,
        )

# Alias for backward compatibility (inline code used different name)
NUCLEI_PROMOTE_INFO_TEMPLATES = NUCLEI_PROMOTE_TEMPLATES

# Set global socket timeout to prevent DNS hangs (critical fix for scanner.py)
socket.setdefaulttimeout(10)

# Configurable DNS resolvers (can be set via environment variable for enterprise deployments)
# Set SCANNER_DNS_RESOLVERS="internal.dns.local,backup.dns.local" to use custom resolvers
DNS_RESOLVERS = os.environ.get("SCANNER_DNS_RESOLVERS", "1.1.1.1,8.8.8.8").split(",")

# Playwright (headless browser) - optional import
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    print("Warning: Playwright not installed. Browser-based features disabled.", file=sys.stderr)

# JWT library - optional import for JWT vulnerability testing
try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    print("Warning: PyJWT not installed. JWT vulnerability testing limited.", file=sys.stderr)

# ---------- utility functions ----------

def normalize_host(target: str) -> tuple[str,int,str]:
    """Enhanced host normalization with protocol auto-detection"""
    try:
        # If no scheme provided, we'll auto-detect
        if "://" not in target:
            # Try to detect the correct protocol
            return auto_detect_protocol(target)
        else:
            parsed = urllib.parse.urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            scheme = parsed.scheme
            return host, port, scheme
    except Exception:
        # Fallback: try auto-detection
        return auto_detect_protocol(target)

def auto_detect_protocol(target: str) -> tuple[str, int, str]:
    """Auto-detect whether to use HTTP or HTTPS"""
    import socket

    # Extract host and potential port
    if ":" in target and not target.startswith("["):
        parts = target.rsplit(":", 1)
        if parts[1].isdigit():
            host = parts[0]
            port = int(parts[1])
        else:
            host = target
            port = None
    else:
        host = target
        port = None

    # Common HTTPS ports
    https_ports = [443, 8443, 9443]
    # Common HTTP ports
    http_ports = [80, 8080, 8000, 3000, 5000]

    # If port is specified, make educated guess
    if port:
        if port in https_ports:
            return host, port, "https"
        elif port in http_ports:
            return host, port, "http"

    # Try HTTPS first (port 443)
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(3)
        test_sock.connect((host, 443))
        # Try SSL handshake
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(test_sock, server_hostname=host) as ssock:
            ssock.getpeercert()
        return host, 443, "https"
    except Exception:
        pass

    # Try HTTP (port 80)
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(3)
        test_sock.connect((host, 80))
        test_sock.close()
        return host, 80, "http"
    except Exception:
        pass

    # Try alternative ports
    for test_port in [8080, 8443, 8000]:
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect((host, test_port))
            test_sock.close()
            # Guess based on port number
            if test_port == 8443:
                return host, test_port, "https"
            else:
                return host, test_port, "http"
        except Exception:
            continue

    # Default fallback
    return host, port or 443, "https"

MANUAL_ENDPOINT_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}


def _split_endpoint_params(raw: str) -> list[str]:
    return [p.strip() for p in raw.split(",") if p.strip()]


def _coerce_param_value(raw: str) -> Any:
    if raw is None:
        return ""
    cleaned = raw.strip()
    if cleaned == "":
        return ""
    lowered = cleaned.lower()
    if lowered in ("true", "false", "null"):
        try:
            return json.loads(lowered)
        except json.JSONDecodeError:
            return cleaned
    # JSON literals
    if cleaned.startswith("{") or cleaned.startswith("["):
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return cleaned
    # Numbers
    if re.fullmatch(r"-?\d+", cleaned):
        try:
            return int(cleaned)
        except ValueError:
            return cleaned
    if re.fullmatch(r"-?\d+\.\d+", cleaned):
        try:
            return float(cleaned)
        except ValueError:
            return cleaned
    return cleaned


def _parse_param_pairs(raw: str) -> dict[str, Any]:
    if not raw:
        return {}
    normalized = raw.replace("&", ",")
    pairs = {}
    for chunk in normalized.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "=" in chunk:
            key, value = chunk.split("=", 1)
        elif ":" in chunk:
            key, value = chunk.split(":", 1)
        else:
            continue
        key = key.strip()
        if not key:
            continue
        pairs[key] = _coerce_param_value(value)
    return pairs


def _flatten_json_keys(obj: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                keys.extend(_flatten_json_keys(value, full_key))
            elif isinstance(value, list):
                keys.append(full_key)
                if value and isinstance(value[0], dict):
                    keys.extend(_flatten_json_keys(value[0], full_key))
            else:
                keys.append(full_key)
    elif isinstance(obj, list):
        if obj and isinstance(obj[0], dict):
            keys.extend(_flatten_json_keys(obj[0], prefix))
    return keys


def _flatten_json_defaults(obj: Any, prefix: str = "") -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                defaults.update(_flatten_json_defaults(value, full_key))
            elif isinstance(value, list):
                defaults[full_key] = value
            else:
                defaults[full_key] = value
    return defaults


def parse_manual_endpoints(raw_lines: list[str]) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for raw in raw_lines:
        if not raw:
            continue
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        if not parts:
            continue

        method = "GET"
        idx = 0
        first = parts[0].upper()
        if first in MANUAL_ENDPOINT_METHODS:
            method = first
            idx = 1
        if idx >= len(parts):
            continue

        url = parts[idx]
        params_spec = " ".join(parts[idx + 1:]).strip() if len(parts) > idx + 1 else ""

        endpoint: dict[str, Any] = {"url": url, "method": method, "source": "manual"}
        params: list[str] = []

        if params_spec:
            spec_lower = params_spec.lower()
            if spec_lower.startswith("json:"):
                body_raw = params_spec[5:].strip()
                try:
                    body_obj = json.loads(body_raw)
                except json.JSONDecodeError:
                    body_obj = None
                if isinstance(body_obj, dict):
                    endpoint["body_template"] = body_obj
                    endpoint["body_param_defaults"] = _flatten_json_defaults(body_obj)
                    params = _flatten_json_keys(body_obj)
                    endpoint["content_type"] = "application/json"
                else:
                    params = _split_endpoint_params(params_spec)
            elif spec_lower.startswith("form:"):
                body_raw = params_spec[5:].strip()
                form_defaults = dict(urllib.parse.parse_qsl(body_raw, keep_blank_values=True))
                endpoint["body_param_defaults"] = form_defaults
                params = list(form_defaults.keys())
                endpoint["content_type"] = "application/x-www-form-urlencoded"
            elif spec_lower.startswith("query:") or spec_lower.startswith("params:"):
                query_raw = params_spec.split(":", 1)[1].strip()
                query_defaults = _parse_param_pairs(query_raw)
                endpoint["param_defaults"] = query_defaults
                params = list(query_defaults.keys())
            elif "=" in params_spec or ":" in params_spec:
                defaults = _parse_param_pairs(params_spec)
                params = list(defaults.keys())
                if method in ("POST", "PUT", "PATCH"):
                    endpoint["body_param_defaults"] = defaults
                    endpoint["content_type"] = "application/json"
                else:
                    endpoint["param_defaults"] = defaults
            else:
                params = _split_endpoint_params(params_spec)
        else:
            parsed = urllib.parse.urlparse(url)
            params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

        if method in ("POST", "PUT", "PATCH"):
            if params:
                endpoint["body_params"] = params
                endpoint["body_required_params"] = params
                endpoint.setdefault("content_type", "application/json")
        else:
            if params:
                endpoint["params"] = params
        endpoints.append(endpoint)
    return endpoints


def normalize_manual_endpoints(base_url: str, manual_endpoints: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for endpoint in manual_endpoints or []:
        raw_url = str(endpoint.get("url") or "").strip()
        if not raw_url:
            continue
        url = raw_url
        if not raw_url.startswith(("http://", "https://")):
            url = urllib.parse.urljoin(base_url, raw_url)

        method = (endpoint.get("method") or "GET").upper()
        params = endpoint.get("params") or []
        param_defaults = endpoint.get("param_defaults") or endpoint.get("query_param_defaults") or {}

        if method == "GET" and not params:
            if param_defaults:
                params = list(param_defaults.keys())
            else:
                parsed = urllib.parse.urlparse(url)
                params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())

        normalized_ep = dict(endpoint)
        normalized_ep["url"] = url
        normalized_ep["method"] = method
        if method == "GET":
            if params:
                normalized_ep["params"] = params
            if param_defaults:
                normalized_ep["param_defaults"] = param_defaults
        elif method in ("POST", "PUT", "PATCH"):
            body_params = normalized_ep.get("body_params") or []
            body_defaults = normalized_ep.get("body_param_defaults") or {}
            body_template = normalized_ep.get("body_template")
            if not body_params:
                if body_defaults:
                    body_params = list(body_defaults.keys())
                elif isinstance(body_template, dict):
                    body_params = _flatten_json_keys(body_template)
            if body_params:
                normalized_ep["body_params"] = body_params
                normalized_ep["body_required_params"] = normalized_ep.get("body_required_params") or body_params
            if body_defaults:
                normalized_ep["body_param_defaults"] = body_defaults
            if body_template:
                normalized_ep["body_template"] = body_template
            if body_params and not normalized_ep.get("content_type"):
                normalized_ep["content_type"] = "application/json"
        normalized.append(normalized_ep)
    return normalized


SCOPE_RULE_TYPES = {"path", "subdomain", "domain", "method", "header", "parameter"}


def parse_scope_rules_json(raw: str | None, label: str) -> list[dict[str, str]]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except Exception as e:
        print(f"[scope] Invalid {label} rules JSON, ignoring: {e}", file=sys.stderr)
        return []
    if not isinstance(parsed, list):
        print(f"[scope] {label} rules must be a JSON array, ignoring.", file=sys.stderr)
        return []

    rules: list[dict[str, str]] = []
    seen = set()
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            continue
        rule_type = str(item.get("type") or "").strip().lower()
        url_path = str(item.get("url_path") or item.get("value") or "").strip()
        if rule_type not in SCOPE_RULE_TYPES or not url_path:
            continue
        key = (rule_type, url_path.lower())
        if key in seen:
            continue
        seen.add(key)
        rules.append({
            "type": rule_type,
            "url_path": url_path,
            "description": str(item.get("description") or f"{label}_{idx}").strip(),
        })
    return rules


def _endpoint_param_names(endpoint: dict[str, Any]) -> list[str]:
    names: set[str] = set()
    for key in ("params", "body_params"):
        values = endpoint.get(key) or []
        if isinstance(values, list):
            for value in values:
                if value:
                    names.add(str(value))
    for key in ("param_defaults", "body_param_defaults"):
        values = endpoint.get(key) or {}
        if isinstance(values, dict):
            for value in values.keys():
                if value:
                    names.add(str(value))
    return sorted(names)


def _rule_matches(
    rule: dict[str, str],
    *,
    url: str,
    method: str | None = None,
    param_names: list[str] | None = None,
    header_names: list[str] | None = None,
) -> bool:
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
    except Exception:
        host = ""
        path = "/"
    rule_type = rule.get("type")
    value = str(rule.get("url_path") or "").strip()
    value_l = value.lower()

    if rule_type == "path":
        if fnmatch.fnmatch(path, value) or fnmatch.fnmatch(path, value_l):
            return True
        return value in path
    if rule_type == "subdomain":
        if not host:
            return False
        if fnmatch.fnmatch(host, f"{value_l}.*"):
            return True
        return host.startswith(f"{value_l}.")
    if rule_type == "domain":
        if not host:
            return False
        return host == value_l or host.endswith(f".{value_l}")
    if rule_type == "method":
        return bool(method and method.upper() == value.upper())
    if rule_type == "parameter":
        return any(str(p).lower() == value_l for p in (param_names or []))
    if rule_type == "header":
        return any(str(h).lower() == value_l for h in (header_names or []))
    return False


def apply_scope_rules_to_manual_endpoints(
    endpoints: list[dict[str, Any]],
    focus_rules: list[dict[str, str]],
    avoid_rules: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if not endpoints:
        return [], {"kept": 0, "dropped": 0}

    scoped: list[dict[str, Any]] = []
    dropped = 0
    for endpoint in endpoints:
        url = str(endpoint.get("url") or "")
        method = str(endpoint.get("method") or "GET")
        param_names = _endpoint_param_names(endpoint)

        if any(_rule_matches(rule, url=url, method=method, param_names=param_names) for rule in avoid_rules):
            dropped += 1
            continue

        if focus_rules and not any(
            _rule_matches(rule, url=url, method=method, param_names=param_names)
            for rule in focus_rules
        ):
            dropped += 1
            continue
        scoped.append(endpoint)

    return scoped, {"kept": len(scoped), "dropped": dropped}


def apply_scope_rules_to_urls(
    urls: list[str],
    focus_rules: list[dict[str, str]],
    avoid_rules: list[dict[str, str]],
) -> tuple[list[str], dict[str, int]]:
    if not urls:
        return [], {"kept": 0, "dropped": 0}

    focus_url_rules = [r for r in focus_rules if r.get("type") in {"path", "subdomain", "domain"}]
    avoid_url_rules = [r for r in avoid_rules if r.get("type") in {"path", "subdomain", "domain"}]

    scoped: list[str] = []
    dropped = 0
    for url in urls:
        if any(_rule_matches(rule, url=url) for rule in avoid_url_rules):
            dropped += 1
            continue

        if focus_url_rules and not any(_rule_matches(rule, url=url) for rule in focus_url_rules):
            dropped += 1
            continue
        scoped.append(url)
    return scoped, {"kept": len(scoped), "dropped": dropped}


def _generate_totp(secret: str, digits: int = 6, interval_seconds: int = 30) -> str:
    cleaned = re.sub(r"\s+", "", str(secret or "").upper())
    if not cleaned:
        raise ValueError("empty TOTP secret")
    pad_len = (-len(cleaned)) % 8
    key = base64.b32decode(cleaned + ("=" * pad_len), casefold=True)
    counter = int(time.time() // interval_seconds)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (
        ((digest[offset] & 0x7F) << 24)
        | ((digest[offset + 1] & 0xFF) << 16)
        | ((digest[offset + 2] & 0xFF) << 8)
        | (digest[offset + 3] & 0xFF)
    )
    return f"{code_int % (10 ** digits):0{digits}d}"


def parse_auth_scenario_json(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except Exception as e:
        print(f"[auth_scenario] Invalid JSON, ignoring: {e}", file=sys.stderr)
        return None
    if not isinstance(parsed, dict):
        print("[auth_scenario] Expected JSON object, ignoring.", file=sys.stderr)
        return None

    scenario: dict[str, Any] = {}
    for key in ("login_type", "login_url", "auth_header", "auth_cookies"):
        value = parsed.get(key)
        if isinstance(value, str) and value.strip():
            scenario[key] = value.strip()

    credentials = parsed.get("credentials")
    if isinstance(credentials, dict):
        normalized_credentials: dict[str, str] = {}
        for key in ("username", "password", "totp_secret"):
            value = credentials.get(key)
            if isinstance(value, str) and value.strip():
                normalized_credentials[key] = value.strip()
        if normalized_credentials:
            scenario["credentials"] = normalized_credentials

    success_condition = parsed.get("success_condition")
    if isinstance(success_condition, dict):
        cond_type = str(success_condition.get("type") or "").strip().lower()
        cond_value = str(success_condition.get("value") or "").strip()
        if cond_type and cond_value:
            scenario["success_condition"] = {"type": cond_type, "value": cond_value}

    login_flow = parsed.get("login_flow")
    if isinstance(login_flow, list):
        flow_steps = [str(step).strip() for step in login_flow if str(step).strip()]
        if flow_steps:
            scenario["login_flow"] = flow_steps[:20]

    extra_fields = parsed.get("extra_fields")
    if isinstance(extra_fields, dict):
        normalized_extra_fields: dict[str, str] = {}
        for key, value in extra_fields.items():
            k = str(key).strip()
            if not k:
                continue
            normalized_extra_fields[k] = str(value)
        if normalized_extra_fields:
            scenario["extra_fields"] = normalized_extra_fields

    return scenario or None


def _apply_auth_placeholders(value: str | None, *, totp_code: str | None = None) -> str | None:
    """Render lightweight auth placeholders used by auth_scenario_json."""
    if value is None:
        return None
    rendered = str(value)
    if totp_code:
        rendered = rendered.replace("{{TOTP}}", totp_code).replace("${TOTP}", totp_code)
    return rendered

# ---------- DNS ----------

async def dns_fallback_query(host: str, qtype: str) -> str:
    """Fallback DNS query using multiple methods"""
    # Get configured resolvers (first two for primary/fallback)
    primary_resolver = DNS_RESOLVERS[0] if DNS_RESOLVERS else "1.1.1.1"
    fallback_resolver = DNS_RESOLVERS[1] if len(DNS_RESOLVERS) > 1 else "8.8.8.8"

    # Method 1: Try dig first (already done in resolve_dns)

    # Method 2: Try nslookup as fallback
    if qtype == "A":
        out, err, rc = await run(["nslookup", "-type=A", host, primary_resolver], timeout=5)
        if rc == 0 and out:
            lines = out.split('\n')
            addresses = []
            in_answer = False
            for line in lines:
                if 'answer:' in line.lower():
                    in_answer = True
                elif in_answer and 'address:' in line.lower():
                    addr = line.split(':', 1)[1].strip()
                    if addr and addr != primary_resolver:
                        addresses.append(addr)
            if addresses:
                return '\n'.join(addresses)

    # Method 3: Try host command with fallback resolver
    if qtype == "A":
        out, err, rc = await run(["host", "-t", "A", host, fallback_resolver], timeout=5)
        if rc == 0 and out:
            addresses = []
            for line in out.split('\n'):
                if 'has address' in line:
                    addr = line.split('has address')[1].strip()
                    if addr:
                        addresses.append(addr)
            if addresses:
                return '\n'.join(addresses)

    # Method 4: Python socket as last resort (only for A records)
    if qtype == "A":
        try:
            import socket
            result = socket.gethostbyname(host)
            if result:
                return result
        except Exception:
            pass

    return ""

async def resolve_dns(host: str) -> dict[str, Any]:
    res = {"A": [], "AAAA": [], "CNAME": None, "MX": [], "TXT": []}
    async def q(qtype):
        # Use optimized dig flags: +tries=1 +time=2 to reduce timeout attempts
        out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", host, qtype], retry=2)
        # If dig fails, try fallback methods
        if (rc != 0 or not out) and qtype == "A":
            out = await dns_fallback_query(host, qtype)
            rc = 0 if out else 1
        return qtype, out, rc
    tasks = [q(t) for t in ["A","AAAA","CNAME","MX","TXT"]]
    done = await asyncio.gather(*tasks, return_exceptions=True)
    for result in done:
        # Skip failed queries gracefully (graceful degradation)
        if isinstance(result, Exception):
            continue
        qtype, out, rc = result
        if rc != 0 or not out: continue
        # Filter out DNS error messages and comment lines
        lines = [l.strip() for l in out.splitlines()
                if l.strip() and not l.startswith(';;') and 'communications error' not in l]
        if qtype == "CNAME":
            # Only set CNAME if we have valid data
            if lines and not any('error' in l.lower() for l in lines):
                res["CNAME"] = lines[0].rstrip(".")
        elif qtype == "MX":
            for l in lines:
                parts = l.split()
                if len(parts) >= 2:
                    try:
                        priority = int(parts[0])
                        res["MX"].append({"priority": priority, "host": parts[1].rstrip(".")})
                    except ValueError:
                        # Skip malformed MX records
                        continue
        elif qtype in ["A","AAAA"]:
            # Filter out any non-IP addresses
            if qtype == "A":
                res[qtype] = [l for l in lines if re.match(r'^\d+\.\d+\.\d+\.\d+$', l)]
            else:  # AAAA
                res[qtype] = [l for l in lines if ':' in l]
        elif qtype == "TXT":
            res["TXT"] = [l.strip('"') for l in lines]
    return res

async def fetch_caa(domain: str) -> dict[str, Any]:
    """Fetch CAA records if present."""
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", domain, "CAA"], timeout=8)
    records = []
    if rc == 0 and out:
        for l in out.splitlines():
            l = l.strip()
            if l and not l.startswith(";;"):
                records.append(l)
    return {"records": records}

async def fetch_mta_sts(domain: str) -> dict[str, Any]:
    """Check MTA-STS DNS TXT and policy file."""
    txt_name = f"_mta-sts.{domain}"
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", txt_name, "TXT"], timeout=8)
    record = None
    if rc == 0 and out:
        for l in out.splitlines():
            s = l.strip().strip('"')
            if s.lower().startswith("v=stsv1"):
                record = s
                break
    # Fetch policy file (best-effort)
    policy_url = f"https://{domain}/.well-known/mta-sts.txt"
    pol_out, _, pol_rc = await run(["curl", "-sS", "-L", "-k", "--max-time", "6", policy_url], timeout=8)
    body = (pol_out or "").strip()
    # RFC 8461 policy must contain version: STSv1
    policy_present = (pol_rc == 0 and body and ("version:" in body.lower()) and ("stsv1" in body.lower()))
    return {"record": record, "policy_url": policy_url, "policy_present": policy_present, "policy_sample": (body[:400] if policy_present else None)}

async def fetch_tls_rpt(domain: str) -> dict[str, Any]:
    """Check SMTP TLS reporting (TLS-RPT) TXT record."""
    name = f"_smtp._tls.{domain}"
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", name, "TXT"], timeout=8)
    record = None
    rua = None
    if rc == 0 and out:
        for l in out.splitlines():
            s = l.strip().strip('"')
            if s.lower().startswith("v=tlsrptv1"):
                record = s
                m = re.search(r"rua=mailto:([^;\s,]+)", s, re.I)
                if m:
                    rua = m.group(1)
                break
    return {"record": record, "rua": rua}

def detect_spf(txt_records: list[str]) -> str | None:
    for t in txt_records:
        if t.lower().startswith("v=spf1"):
            return t
    return None

async def subfinder_scan(domain: str) -> dict[str, Any]:
    return await _subfinder_scan_mod(domain)

async def fetch_dmarc(domain: str) -> dict[str, Any]:
    d = f"_dmarc.{domain}"
    out, err, rc = await run(["dig", "+short", "+tries=1", "+time=2", d, "TXT"])
    # Filter out error messages and comment lines
    recs = [l.strip().strip('"') for l in out.splitlines()
            if l.strip() and not l.startswith(';;') and 'communications error' not in l] if (rc==0 and out) else []
    dmarc = " ".join(recs) if recs else None
    fields = {}
    if dmarc:
        for k in ["p","sp","adkim","aspf","pct","rua","ruf","fo"]:
            m = re.search(rf"\b{k}\s*=\s*([^;,\s]+)", dmarc, re.I)
            if m: fields[k] = m.group(1)
    return {"record": dmarc, "fields": fields}

async def check_dnssec(domain: str) -> dict[str, Any]:
    # Use external DNSSEC-validating resolver (Cloudflare) instead of Docker internal DNS
    # Docker internal DNS (127.0.0.11) doesn't validate DNSSEC properly
    resolver = "@1.1.1.1"
    # Add explicit timeout to prevent hanging on slow DNSSEC validation chains
    out, err, rc = await run(["delv", resolver, domain, "A"], timeout=30)
    status = "unknown"
    if rc == 0 and out:
        if re.search(r"\bsecure\b", out, re.I):
            status = "secure"
        elif re.search(r"\bvalidation failure\b|\bBOGUS\b", out, re.I):
            status = "bogus"
        else:
            status = "insecure"
    elif err and "timed out" in err.lower():
        status = "timeout"
    alg = None
    trace_out, _, _ = await run(["delv", resolver, "+rtrace", domain, "A"], timeout=30)
    if trace_out:
        m = re.search(r"algorithm\s+([A-Z0-9-]+)", trace_out, re.I)
        if m: alg = m.group(1).upper()
    return {"status": status, "algorithm": alg, "raw": (out or err)[:2000]}

# moved to scanner_tools.discovery

# (moved) check_subdomain_takeover is now implemented in scanner_tools.active_checks

async def check_exposed_files(base_url: str, quick_mode: bool = False) -> dict:
    return await _check_exposed_files_mod(base_url, quick_mode=quick_mode)


async def nmap_full_scan(
    host: str,
    quick_mode: bool = False,
    top_ports: int | None = None,
    scripts: bool = False,
) -> dict[str, Any]:
    return await _nmap_full_scan_mod(host, quick_mode, top_ports=top_ports, scripts=scripts)

# ---------- Complete Mode Functions ----------

async def comprehensive_port_scan(host: str, max_ports: int = 1000) -> dict[str, Any]:
    return await _comprehensive_port_scan_mod(host, max_ports)

async def deep_discovery_scan(base_url: str) -> dict[str, Any]:
    return await _deep_discovery_scan_mod(base_url)

async def advanced_vuln_tests(
    base_url: str,
    exploit_level: str = "safe",
    candidates: list[dict[str, Any]] | None = None,
    auth_session: Any | None = None,
) -> dict[str, Any]:
    return await _advanced_vuln_tests_mod(
        base_url,
        exploit_level=exploit_level,
        candidates=candidates,
        auth_session=auth_session,
    )

# ---------- Nuclei vulnerability scanning ----------

async def nuclei_scan(
    url: str,
    quick_mode: bool = False,
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    return await _nuclei_scan_mod(
        url,
        quick_mode,
        targets=targets,
        auth_session=auth_session,
        max_targets=max_targets,
    )


async def nuclei_comprehensive_scan(
    url: str,
    rate_limit: int = 5,
    timeout_per_request: int = 15,
    scan_tier: str = "safe",
    targets: list[str] | None = None,
    auth_session: Any | None = None,
    max_targets: int | None = None
) -> dict[str, Any]:
    return await _nuclei_comprehensive_scan_mod(
        url,
        rate_limit,
        timeout_per_request,
        scan_tier,
        targets=targets,
        auth_session=auth_session,
        max_targets=max_targets,
    )


async def detect_cloud_services(host: str, headers: dict[str, list[str]]) -> dict[str, Any]:
    return await _detect_cloud_services_mod(host, headers)


async def detect_waf(url: str, headers: dict[str, list[str]]) -> dict[str, Any]:
    return await _detect_waf_mod(url, headers)


# ---------- API Security Testing ----------

async def api_security_test(url: str) -> dict[str, Any]:
    return await _api_security_test_mod(url)

# ---------- Subdomain Takeover Detection ----------

async def subdomain_takeover_check(host: str) -> dict[str, Any]:
    return await _subdomain_takeover_check_mod(host)

# ---------- Advanced Vulnerability Detection ----------

async def nosql_injection_test(url: str) -> dict[str, Any]:
    return await _nosql_injection_test_mod(url)

async def ldap_injection_test(
    url: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    param_defaults: dict[str, Any] | None = None,
    max_params: int = 5,
    max_payloads: int = 6,
) -> dict[str, Any]:
    return await _ldap_injection_test_mod(
        url,
        params_to_test=params_to_test,
        auth_session=auth_session,
        param_defaults=param_defaults,
        max_params=max_params,
        max_payloads=max_payloads,
    )

async def xxe_injection_test(url: str) -> dict[str, Any]:
    return await _xxe_injection_test_mod(url)

async def ssti_test(
    url: str,
    params_to_test: list[str] | None = None,
    auth_session: Any | None = None,
    param_defaults: dict[str, Any] | None = None,
    max_params: int = 5,
    max_payloads: int = 6,
) -> dict[str, Any]:
    return await _ssti_test_mod(
        url,
        params_to_test=params_to_test,
        auth_session=auth_session,
        param_defaults=param_defaults,
        max_params=max_params,
        max_payloads=max_payloads,
    )

async def jwt_vulnerability_test(url: str, sample_token: str | None = None) -> dict[str, Any]:
    return await _jwt_vulnerability_test_mod(url, sample_token)

async def oauth_vulnerability_test(url: str) -> dict[str, Any]:
    return await _oauth_vulnerability_test_mod(url)

async def session_vulnerability_test(url: str) -> dict[str, Any]:
    return await _session_vulnerability_test_mod(url)

async def timing_attack_test(url: str) -> dict[str, Any]:
    return await _timing_attack_test_mod(url)

async def http_smuggling_test(url: str) -> dict[str, Any]:
    return await _http_smuggling_test_mod(url)

async def graphql_vulnerability_test(url: str) -> dict[str, Any]:
    return await _graphql_vulnerability_test_mod(url)

async def cache_poisoning_test(url: str) -> dict[str, Any]:
    return await _cache_poisoning_test_mod(url)

# ---------- Active checks (dalfox/sqlmap, optional) ----------

async def dalfox_one(
    url: str,
    quick_mode: bool = False,
    auth_session: Any | None = None,
    deep_domxss: bool | None = None
) -> list[dict]:
    return await _dalfox_one_mod(url, quick_mode, auth_session=auth_session, deep_domxss=deep_domxss)

async def sqlmap_test(url: str, quick_mode: bool = False, aggressive: bool = False, **kwargs) -> dict:
    return await _sqlmap_test_mod(url, quick_mode, aggressive=aggressive, **kwargs)

# ---------- Reporting ----------





def assess_scan_completeness(
    report: dict[str, Any],
    *,
    public_only: bool = False,
    active_checks_requested: bool = False,
    js_dependency_scanning: bool = False,
    js_secret_scanning: bool = False,
) -> dict[str, Any]:
    """
    Assess scan completeness to determine if grade should be published.

    Required modules (must complete for valid grade):
    - TLS: Either sslyze OR testssl must complete successfully
    - HTTP: Must have valid HTTP response (status code present)
    - DNS: Basic DNS resolution must work (A records present)

    Optional modules (tracked but don't block grade):
    - Nuclei vulnerability scanning
    - Active checks (dalfox, sqlmap)
    - JS dependency/secret scanning
    - Port scanning (nmap)

    Returns dict with:
    - status: "complete" | "partial" | "failed"
    - grade_reliable: bool - whether grade should be trusted
    - modules: dict of module completion status
    - issues: list of completion issues
    """
    modules = {}
    issues = []

    # --- Required Modules ---

    # TLS: Check sslyze OR testssl OR nmap ciphers completed
    tls = report.get("tls", {})
    sslyze = tls.get("sslyze", {}) or {}
    testssl = tls.get("testssl", {}) or {}
    nmap_tls = tls.get("nmap", {}) or {}
    cipher_suites = tls.get("cipher_suites") or {}

    sslyze_completed = bool(
        sslyze.get("scan_completed")
        or sslyze.get("tls_versions")
        or sslyze.get("cipher_suites")
        or sslyze.get("certificate_chain")
    )
    testssl_completed = bool(
        testssl.get("scan_completed")
        or testssl.get("raw_present")
        or testssl.get("supports_tls13") is not None
    )
    nmap_tls_completed = bool(
        nmap_tls.get("scan_completed")
        or nmap_tls.get("raw")
        or (nmap_tls.get("ciphers_by_protocol") or {})
    )
    cipher_suites_present = bool(cipher_suites)

    tls_completed = sslyze_completed or testssl_completed or nmap_tls_completed or cipher_suites_present
    modules["tls"] = {
        "completed": tls_completed,
        "required": True,
        "details": {
            "sslyze": sslyze_completed,
            "testssl": testssl_completed,
            "nmap_ciphers": nmap_tls_completed,
            "cipher_suites": cipher_suites_present,
        }
    }
    if not tls_completed:
        issues.append("TLS scanning incomplete - no TLS tool (sslyze/testssl/nmap) completed successfully")

    # HTTP: Check we got a valid response
    http = report.get("http", {})
    http_status = http.get("status", "")
    http_completed = bool(http_status and ("200" in str(http_status) or "301" in str(http_status) or
                                           "302" in str(http_status) or "403" in str(http_status) or
                                           "404" in str(http_status)))
    # Also accept any numeric status
    if not http_completed and http_status:
        try:
            status_code = int(str(http_status).split()[-1]) if http_status else 0
            http_completed = 100 <= status_code < 600
        except (ValueError, IndexError):
            pass

    modules["http"] = {
        "completed": http_completed,
        "required": True,
        "details": {"status": http_status, "source": http.get("source")}
    }
    if not http_completed:
        issues.append(f"HTTP check incomplete - no valid response received (status: {http_status})")

    # DNS: Check we got A/AAAA records (basic connectivity)
    dns = report.get("dns", {})
    dns_a_records = dns.get("a") or []
    dns_aaaa_records = dns.get("aaaa") or []
    dns_completed = len(dns_a_records) > 0 or len(dns_aaaa_records) > 0
    modules["dns"] = {
        "completed": dns_completed,
        "required": True,
        "details": {
            "a_records": len(dns_a_records),
            "aaaa_records": len(dns_aaaa_records),
            "has_spf": bool(dns.get("spf")),
            "has_dmarc": bool(dns.get("dmarc", {}).get("record"))
        }
    }
    if not dns_completed:
        issues.append("DNS resolution failed - no A/AAAA records found")

    # --- Optional Modules ---

    # Nuclei (if results present)
    discovery = report.get("discovery", {})
    nuclei_expected = not public_only
    nuclei_data = discovery.get("nuclei") or discovery.get("exposures", {}).get("nuclei")
    if nuclei_expected and isinstance(nuclei_data, dict) and nuclei_data:
        scan_completed = nuclei_data.get("scan_completed")
        if scan_completed is None:
            scan_completed = bool(
                nuclei_data.get("vulnerabilities")
                or nuclei_data.get("info")
                or nuclei_data.get("by_category")
                or nuclei_data.get("statistics")
                or nuclei_data.get("errors")
                or nuclei_data.get("templates_used") is not None
            )
        findings_count = 0
        vulnerabilities = nuclei_data.get("vulnerabilities")
        if isinstance(vulnerabilities, dict):
            findings_count = sum(len(v) for v in vulnerabilities.values())
        elif isinstance(vulnerabilities, list):
            findings_count = len(vulnerabilities)
        else:
            by_category = nuclei_data.get("by_category") or {}
            if isinstance(by_category, dict):
                findings_count = sum(len(v) for v in by_category.values())
        modules["nuclei"] = {
            "completed": scan_completed,
            "required": False,
            "expected": True,
            "details": {
                "findings_count": findings_count,
                "scan_completed": scan_completed,
            }
        }
        if not scan_completed:
            issues.append("Nuclei vulnerability scan did not complete")
    elif nuclei_expected:
        modules["nuclei"] = {
            "completed": False,
            "required": False,
            "expected": True,
            "details": {"reason": "missing results"}
        }
        issues.append("Nuclei vulnerability scan missing from report")

    # JS Dependencies (if results present)
    js_deps_expected = js_dependency_scanning and not public_only
    js_deps = report.get("js_dependencies")
    if js_deps_expected and isinstance(js_deps, dict):
        js_deps_attempted = any(
            key in js_deps for key in ("detection_sources", "cdn_detected", "cwe", "owasp", "recommendation", "severity")
        )
        js_deps_completed = bool(js_deps.get("scan_completed")) or js_deps_attempted
        modules["js_dependencies"] = {
            "completed": js_deps_completed,
            "required": False,
            "expected": True,
            "details": {
                "total_js_files": js_deps.get("total_js_files"),
                "libraries_scanned": js_deps.get("libraries_scanned"),
                "vulnerabilities": len(js_deps.get("vulnerable_libraries", []) or []),
            }
        }
        if not js_deps_completed:
            issues.append("JS dependency scanning did not complete")
    elif js_deps_expected:
        modules["js_dependencies"] = {
            "completed": False,
            "required": False,
            "expected": True,
            "details": {"reason": "missing results"}
        }
        issues.append("JS dependency scanning missing from report")

    # JS Secrets (if results present)
    js_secrets_expected = js_secret_scanning and not public_only
    js_secrets = report.get("js_secrets")
    if js_secrets_expected and isinstance(js_secrets, dict):
        js_secrets_attempted = any(
            key in js_secrets for key in ("cwe", "owasp", "recommendation", "severity")
        )
        js_secrets_completed = bool(js_secrets.get("scan_completed")) or js_secrets_attempted
        modules["js_secrets"] = {
            "completed": js_secrets_completed,
            "required": False,
            "expected": True,
            "details": {"files_scanned": js_secrets.get("files_scanned")}
        }
        if not js_secrets_completed:
            issues.append("JS secret scanning did not complete")
    elif js_secrets_expected:
        modules["js_secrets"] = {
            "completed": False,
            "required": False,
            "expected": True,
            "details": {"reason": "missing results"}
        }
        issues.append("JS secret scanning missing from report")

    # Active checks
    if active_checks_requested and not public_only:
        active_results = report.get("active_checks") or {}
        dalfox_results = active_results.get("dalfox") or []
        sqlmap_results = active_results.get("sqlmap") or []
        dalfox_errors = active_results.get("dalfox_errors") or []
        sqlmap_errors = active_results.get("sqlmap_errors") or []

        def _has_findings(value: Any) -> bool:
            if isinstance(value, list):
                return len(value) > 0
            if isinstance(value, dict):
                if value.get("findings"):
                    return True
                vulns = value.get("vulnerabilities_found")
                return isinstance(vulns, int) and vulns > 0
            return False

        smart_attempted = False
        smart_attempted = smart_attempted or _has_findings(active_results.get("smart_sqli"))
        smart_attempted = smart_attempted or _has_findings(active_results.get("smart_xss"))
        smart_attempted = smart_attempted or _has_findings(active_results.get("nosql_injection"))
        smart_attempted = smart_attempted or _has_findings(active_results.get("dom_xss"))
        smart_attempted = smart_attempted or _has_findings(active_results.get("smart_bola"))
        smart_attempted = smart_attempted or (active_results.get("smart_total_endpoints_tested") or 0) > 0
        smart_attempted = smart_attempted or (active_results.get("get_endpoints_tested") or 0) > 0
        smart_attempted = smart_attempted or (active_results.get("post_endpoints_tested") or 0) > 0
        smart_attempted = smart_attempted or (active_results.get("xss_get_endpoints_tested") or 0) > 0
        smart_attempted = smart_attempted or (active_results.get("xss_post_endpoints_tested") or 0) > 0
        smart_attempted = smart_attempted or (active_results.get("smart_reflections_found") or 0) > 0

        attempted = bool(dalfox_results or sqlmap_results or dalfox_errors or sqlmap_errors or smart_attempted)

        modules["active_checks"] = {
            "completed": attempted,
            "required": False,
            "expected": True,
            "details": {
                "dalfox_results": len(dalfox_results),
                "sqlmap_results": len(sqlmap_results),
                "dalfox_errors": len(dalfox_errors),
                "sqlmap_errors": len(sqlmap_errors),
                "smart_total_endpoints_tested": active_results.get("smart_total_endpoints_tested") or 0,
                "smart_get_endpoints_tested": active_results.get("get_endpoints_tested") or 0,
                "smart_post_endpoints_tested": active_results.get("post_endpoints_tested") or 0,
                "smart_xss_get_endpoints_tested": active_results.get("xss_get_endpoints_tested") or 0,
                "smart_xss_post_endpoints_tested": active_results.get("xss_post_endpoints_tested") or 0,
                "smart_reflections_found": active_results.get("smart_reflections_found") or 0,
            }
        }
        if not attempted:
            issues.append("Active checks requested but no results or errors recorded")
    elif active_checks_requested and public_only:
        modules["active_checks"] = {
            "completed": False,
            "required": False,
            "expected": False,
            "details": {"reason": "skipped in public-only mode"}
        }

    # --- Calculate Overall Status ---

    required_modules = [m for m in modules.values() if m.get("required")]
    optional_modules = [m for m in modules.values() if not m.get("required") and m.get("expected", True)]

    required_completed = sum(1 for m in required_modules if m["completed"])
    required_total = len(required_modules)
    optional_completed = sum(1 for m in optional_modules if m["completed"])
    optional_total = len(optional_modules)

    all_required_complete = required_completed == required_total

    if all_required_complete and (optional_total == 0 or optional_completed == optional_total):
        status = "complete"
    elif all_required_complete:
        status = "partial"  # Required OK but some optional failed
    else:
        status = "failed"  # Required modules failed

    return {
        "status": status,
        "grade_reliable": all_required_complete,
        "required_completed": f"{required_completed}/{required_total}",
        "optional_completed": f"{optional_completed}/{optional_total}" if optional_total > 0 else "N/A",
        "modules": modules,
        "issues": issues
    }


# ARCHITECTURE NOTE: This function is now available from scanner.grading module.
# To migrate: replace calls to grade() with _grade_imported() or import directly.
# The inline version is kept for backward compatibility during migration.
try:
    # Import modular implementations
    from scanner_tools.access_control_checks import (
        check_forced_browsing as _check_forced_browsing_mod,
        format_findings_for_scanner as _format_forced_browsing_findings_mod,
        smart_bola_test as _smart_bola_test_mod,
        # Enhanced BOLA testing
        check_bola_multi_user as _check_bola_multi_user_mod,
        check_bola_enumeration as _check_bola_enumeration_mod,
    )
    from scanner_tools.race_condition_tests import (
        run_race_condition_tests as _run_race_condition_tests_mod,
        identify_race_prone_endpoints as _identify_race_prone_endpoints_mod,
    )
    from scanner_tools.active_checks import (
        advanced_vuln_tests as _advanced_vuln_tests_mod,
        cache_poisoning_test as _cache_poisoning_test_mod,
        check_exposed_files as _check_exposed_files_mod,
        check_subdomain_takeover as _check_subdomain_takeover_mod,
        blind_ssrf_test as _blind_ssrf_test_mod,
        custom_sqli_test as _custom_sqli_test_mod,
        custom_xss_test as _custom_xss_test_mod,
        dalfox_one as _dalfox_one_mod,
        detect_dbms as _detect_dbms_mod,
        graphql_vulnerability_test as _graphql_vulnerability_test_mod,
        http_smuggling_test as _http_smuggling_test_mod,
        jwt_vulnerability_test as _jwt_vulnerability_test_mod,
        ldap_injection_test as _ldap_injection_test_mod,
        ldap_injection_test_json_body as _ldap_injection_test_json_body_mod,
        nosql_injection_test as _nosql_injection_test_mod,
        nosql_injection_test_json_body as _nosql_injection_test_json_body_mod,
        oauth_vulnerability_test as _oauth_vulnerability_test_mod,
        run_smart_active_tests as _run_smart_active_tests_mod,
        session_vulnerability_test as _session_vulnerability_test_mod,
        smart_sqli_test as _smart_sqli_test_mod,
        smart_xss_test as _smart_xss_test_mod,
        dom_xss_analysis as _dom_xss_analysis_mod,
        sqli_data_extraction as _sqli_data_extraction_mod,
        oob_sqli_test as _oob_sqli_test_mod,
        sqlmap_test as _sqlmap_test_mod,
        sqlmap_test_context as _sqlmap_test_context_mod,
        sqlmap_replay_request as _sqlmap_replay_request_mod,
        ssti_test as _ssti_test_mod,
        ssrf_injection_test_json_body as _ssrf_injection_test_json_body_mod,
        stored_xss_workflow as _stored_xss_workflow_mod,
        subdomain_takeover_check as _subdomain_takeover_check_mod,
        timing_attack_test as _timing_attack_test_mod,
        xpath_injection_test as _xpath_injection_test_mod,
        xpath_injection_test_json_body as _xpath_injection_test_json_body_mod,
        xxe_injection_test as _xxe_injection_test_mod,
        xxe_injection_test_json_body as _xxe_injection_test_json_body_mod,
        # Enhanced security tests
        jwt_comprehensive_test as _jwt_comprehensive_test_mod,
        jwt_algorithm_confusion_test as _jwt_algorithm_confusion_test_mod,
        jwt_kid_injection_test as _jwt_kid_injection_test_mod,
        jwt_claim_manipulation_test as _jwt_claim_manipulation_test_mod,
        graphql_comprehensive_test as _graphql_comprehensive_test_mod,
        graphql_batch_attack_test as _graphql_batch_attack_test_mod,
        graphql_depth_attack_test as _graphql_depth_attack_test_mod,
        graphql_alias_idor_test as _graphql_alias_idor_test_mod,
        graphql_field_suggestion_test as _graphql_field_suggestion_test_mod,
    )
    from scanner_tools.ai_classifier import (
        AIClassificationResult as _AIClassificationResult_mod,
        calculate_hybrid_confidence as _calculate_hybrid_confidence_mod,
        call_ai_provider as _call_ai_provider_mod,
        classify_findings_batch as _classify_findings_batch_mod,
        generate_executive_summary as _generate_executive_summary_mod,
    )
    from scanner_tools.asn_discovery import (
        check_asn_discovery as _check_asn_discovery_mod,
    )
    from scanner_tools.auth_session import (
        AuthSession as _AuthSession_mod,
        create_authenticated_session as _create_authenticated_session_mod,
        parse_cookie_string as _parse_cookie_string_mod,
    )
    from scanner_tools.api_auth import (
        api_login as _api_login_mod,
    )
    from scanner_tools.brand_protection import (
        check_brand_protection as _check_brand_protection_mod,
        check_typosquatting as _check_typosquatting_mod,
    )
    from scanner_tools.breach_check import (
        breach_assessment as _breach_assessment_mod,
        check_domain_breaches as _check_domain_breaches_mod,
        generate_breach_findings as _generate_breach_findings_mod,
    )
    from scanner_tools.client_side import (
        detect_server_versions as _detect_server_versions_mod,
        test_client_side_vulns as _test_client_side_vulns_mod,
        test_js_dependencies as _test_js_dependencies_mod,
        test_js_secrets as _test_js_secrets_mod,
    )
    from scanner_tools.compliance_mapper import (
        generate_compliance_report as _generate_compliance_report_mod,
    )
    from scanner_tools.critical_checks import (
        test_2fa_bypass as _test_2fa_bypass_mod,
        test_account_enumeration as _test_account_enumeration_mod,
        test_bruteforce_protection as _test_bruteforce_protection_mod,
        test_csrf as _test_csrf_mod,
        test_default_credentials as _test_default_credentials_mod,
        test_deserialization as _test_deserialization_mod,
        test_http_methods as _test_http_methods_mod,
        test_idor_bola as _test_idor_bola_mod,
        test_password_policy as _test_password_policy_mod,
        test_password_reset as _test_password_reset_mod,
        test_path_traversal as _test_path_traversal_mod,
        test_rate_limiting as _test_rate_limiting_mod,
        test_session_management as _test_session_management_mod,
    )
    from scanner_tools.credential_check import (
        test_default_credentials as _test_default_credentials_aggressive_mod,
    )
    from scanner_tools.ct_monitor import (
        check_certificate_transparency as _check_ct_transparency_mod,
    )
    from scanner_tools.discovery import (
        analyze_js_bundles as _analyze_js_bundles_mod,
        api_security_test as _api_security_test_mod,
        browser_crawl_fallback as _browser_crawl_fallback_mod,
        calculate_adaptive_depth as _calculate_adaptive_depth_mod,
        check_cors as _check_cors_mod,
        deep_discovery_scan as _deep_discovery_scan_mod,
        detect_cloud_services as _detect_cloud_services_mod,
        detect_waf as _detect_waf_mod,
        discover_allowed_methods as _discover_allowed_methods_mod,
        discover_openapi_schema as _discover_openapi_schema_mod,
        enumerate_virtual_hosts as _enumerate_virtual_hosts_mod,
        enhanced_tech_fingerprinting as _enhanced_tech_fingerprinting_mod,
        enhanced_url_discovery as _enhanced_url_discovery_mod,
        extract_openapi_endpoints as _extract_openapi_endpoints_mod,
        fetch_openapi_schema as _fetch_openapi_schema_mod,
        fetch_sitemap_urls as _fetch_sitemap_urls_mod,
        follow_json_links as _follow_json_links_mod,
        katana_crawl as _katana_crawl_mod,
        pd_httpx_probe as _pd_httpx_probe_mod,
        recursive_directory_discovery as _recursive_directory_discovery_mod,
        schemathesis_run as _schemathesis_run_mod,
        smart_discovery as _smart_discovery_mod,
    )
    from scanner_tools.grpc_discovery import (
        grpc_reflection_discovery as _grpc_reflection_discovery_mod,
    )
    from scanner_tools.dns_enhanced import (
        check_dangling_dns as _check_dangling_dns_mod,
        check_enhanced_dns as _check_enhanced_dns_mod,
        enumerate_dkim_selectors as _enumerate_dkim_selectors_mod,
        test_zone_transfer as _test_zone_transfer_mod,
        validate_spf_record as _validate_spf_record_mod,
    )
    from scanner_tools.domain_intel import (
        check_domain_intelligence as _check_domain_intelligence_mod,
    )
    from scanner_tools.finding_validator import (
        CONFIDENCE_THRESHOLDS as _CONFIDENCE_THRESHOLDS_mod,
        ValidationPipelineConfig as _ValidationPipelineConfig_mod,
        ValidationResult as _ValidationResult_mod,
        apply_validation_to_finding as _apply_validation_to_finding_mod,
        should_report_finding as _should_report_finding_mod,
        validate_finding as _validate_finding_mod,
        validate_findings_pipeline as _validate_findings_pipeline_mod,
    )
    from scanner_tools.form_login import (
        detect_login_form as _detect_login_form_mod,
        form_login as _form_login_mod,
        test_form_login as _test_form_login_mod,
    )
    from scanner_tools.http_scanner import (
        analyze_cookies as _analyze_cookies_mod,
        analyze_csp as _analyze_csp_mod,
        browser_fetch as _browser_fetch_mod,
        curl_headers as _curl_headers_mod,
        fetch_security_txt as _fetch_security_txt_mod,
        parse_security_headers as _parse_security_headers_mod,
        supports_http2 as _supports_http2_mod,
        supports_http3 as _supports_http3_mod,
        # Enhanced security tests
        detect_rate_limits as _detect_rate_limits_mod,
        detect_rate_limits_per_endpoint as _detect_rate_limits_per_endpoint_mod,
        test_verb_tampering as _test_verb_tampering_mod,
        test_verb_tampering_authenticated as _test_verb_tampering_authenticated_mod,
        interactive_browser_crawl as _interactive_browser_crawl_mod,
    )
    from scanner_tools.infrastructure_checks import (
        test_backup_files as _test_backup_files_mod,
        test_cicd_exposure as _test_cicd_exposure_mod,
        test_cloud_buckets as _test_cloud_buckets_mod,
        test_cloud_metadata_ssrf as _test_cloud_metadata_ssrf_mod,
        test_container_registry_exposure as _test_container_registry_exposure_mod,
        test_directory_listing as _test_directory_listing_mod,
        test_kubernetes_exposure as _test_kubernetes_exposure_mod,
        test_package_exposure as _test_package_exposure_mod,
        test_terraform_state as _test_terraform_state_mod,
    )
    from scanner_tools.ip_reputation import (
        check_dnsbl as _check_dnsbl_mod,
        check_ip_reputation as _check_ip_reputation_mod,
    )
    from scanner_tools.network_services import (
        check_network_services as _check_network_services_mod,
    )
    from scanner_tools.nmap import (
        comprehensive_port_scan as _comprehensive_port_scan_mod,
        nmap_ciphers as _nmap_ciphers_mod,
        nmap_full_scan as _nmap_full_scan_mod,
    )
    from scanner_tools.nuclei import (
        nuclei_comprehensive_scan as _nuclei_comprehensive_scan_mod,
        nuclei_scan as _nuclei_scan_mod,
        staged_nuclei_scan as _staged_nuclei_scan_mod,
    )
    from scanner_tools.oauth_auth import (
        OAuthSession as _OAuthSession_mod,
        oauth_authenticate as _oauth_authenticate_mod,
        oauth_refresh_token as _oauth_refresh_token_mod,
        oidc_discover as _oidc_discover_mod,
        parse_jwt_claims as _parse_jwt_claims_mod,
    )
    from scanner_tools.phase4_checks import (
        test_api_security as _test_api_security_mod,
        test_business_logic as _test_business_logic_mod,
        test_file_upload as _test_file_upload_mod,
        test_host_header_injection as _test_host_header_injection_mod,
        test_open_redirect as _test_open_redirect_mod,
    )
    from scanner_tools.remediation_kb import (
        get_code_example as _get_code_example_mod,
        get_remediation_for_finding as _get_remediation_for_finding_mod,
    )
    from scanner_tools.sarif_output import (
        convert_to_sarif as _convert_to_sarif_mod,
        create_baseline as _create_baseline_mod,
        filter_by_baseline as _filter_by_baseline_mod,
        load_baseline as _load_baseline_mod,
        quality_gate_check as _quality_gate_check_mod,
        save_baseline as _save_baseline_mod,
        write_sarif_file as _write_sarif_file_mod,
    )
    from scanner_tools.smtp_scanner import (
        check_smtp_security as _check_smtp_security_mod,
    )
    from scanner_tools.ssh_scanner import (
        ssh_auth_methods as _ssh_auth_methods_mod,
    )
    from scanner_tools.subfinder import subfinder_scan as _subfinder_scan_mod
    from scanner_tools.subdomain_discovery import (
        discover_subdomains as _discover_subdomains_mod,
        quick_subdomain_scan as _quick_subdomain_scan_mod,
        comprehensive_subdomain_scan as _comprehensive_subdomain_scan_mod,
    )
    from scanner_tools.gungnir import (
        gungnir_scan as _gungnir_scan_mod,
        check_gungnir_available as _check_gungnir_available_mod,
    )
    from scanner_tools.tech_discovery import (
        discover_technologies as _discover_technologies_mod,
    )
    from scanner_tools.tls_scanner import (
        build_crypto_inventory as _build_crypto_inventory_mod,
        days_until as _days_until_mod,
        openssl_ocsp as _openssl_ocsp_mod,
        parse_openssl_cert as _parse_openssl_cert_mod,
        sslyze_scan as _sslyze_scan_mod,
        testssl as _testssl_mod,
        tlsx_probe as _tlsx_probe_mod,
    )
    from scanner_tools.vendor_risk import (
        generate_vendor_findings as _generate_vendor_findings_mod,
        vendor_risk_assessment as _vendor_risk_assessment_mod,
    )
    from scanner_tools.websocket_security import (
        probe_websocket_endpoints as _probe_websocket_endpoints_mod,
        run_websocket_security_tests as _run_websocket_security_tests_mod,
    )

    # Reassign names used throughout this module to the modular versions
    nmap_ciphers = _nmap_ciphers_mod
    nmap_full_scan = _nmap_full_scan_mod
    comprehensive_port_scan = _comprehensive_port_scan_mod
    nuclei_scan = _nuclei_scan_mod
    nuclei_comprehensive_scan = _nuclei_comprehensive_scan_mod
    staged_nuclei_scan = _staged_nuclei_scan_mod
    subfinder_scan = _subfinder_scan_mod
    discover_subdomains = _discover_subdomains_mod
    quick_subdomain_scan = _quick_subdomain_scan_mod
    comprehensive_subdomain_scan = _comprehensive_subdomain_scan_mod
    gungnir_scan = _gungnir_scan_mod
    check_gungnir_available = _check_gungnir_available_mod
    tlsx_probe = _tlsx_probe_mod
    openssl_ocsp = _openssl_ocsp_mod
    testssl = _testssl_mod
    sslyze_scan = _sslyze_scan_mod
    parse_openssl_cert = _parse_openssl_cert_mod
    days_until = _days_until_mod
    curl_headers = _curl_headers_mod
    supports_http2 = _supports_http2_mod
    supports_http3 = _supports_http3_mod
    parse_security_headers = _parse_security_headers_mod
    analyze_csp = _analyze_csp_mod
    analyze_cookies = _analyze_cookies_mod
    fetch_security_txt = _fetch_security_txt_mod
    browser_fetch = _browser_fetch_mod
    enhanced_tech_fingerprinting = _enhanced_tech_fingerprinting_mod
    fetch_sitemap_urls = _fetch_sitemap_urls_mod
    browser_crawl_fallback = _browser_crawl_fallback_mod
    pd_httpx_probe = _pd_httpx_probe_mod
    enhanced_url_discovery = _enhanced_url_discovery_mod
    katana_crawl = _katana_crawl_mod
    deep_discovery_scan = _deep_discovery_scan_mod
    smart_discovery = _smart_discovery_mod
    calculate_adaptive_depth = _calculate_adaptive_depth_mod
    recursive_directory_discovery = _recursive_directory_discovery_mod
    analyze_js_bundles = _analyze_js_bundles_mod
    schemathesis_run = _schemathesis_run_mod
    follow_json_links = _follow_json_links_mod
    discover_allowed_methods = _discover_allowed_methods_mod
    discover_openapi_schema = _discover_openapi_schema_mod
    extract_openapi_endpoints = _extract_openapi_endpoints_mod
    fetch_openapi_schema = _fetch_openapi_schema_mod
    detect_cloud_services = _detect_cloud_services_mod
    detect_waf = _detect_waf_mod
    enumerate_virtual_hosts = _enumerate_virtual_hosts_mod
    api_security_test = _api_security_test_mod
    check_cors = _check_cors_mod
    check_subdomain_takeover = _check_subdomain_takeover_mod
    check_exposed_files = _check_exposed_files_mod
    grpc_reflection_discovery = _grpc_reflection_discovery_mod
    advanced_vuln_tests = _advanced_vuln_tests_mod
    dalfox_one = _dalfox_one_mod
    sqlmap_test = _sqlmap_test_mod
    sqlmap_test_context = _sqlmap_test_context_mod
    sqlmap_replay_request = _sqlmap_replay_request_mod
    custom_sqli_test = _custom_sqli_test_mod
    custom_xss_test = _custom_xss_test_mod
    blind_ssrf_test = _blind_ssrf_test_mod
    # Smart active checks (DBMS-aware, context-aware)
    detect_dbms = _detect_dbms_mod
    smart_sqli_test = _smart_sqli_test_mod
    smart_xss_test = _smart_xss_test_mod
    dom_xss_analysis = _dom_xss_analysis_mod
    sqli_data_extraction = _sqli_data_extraction_mod
    oob_sqli_test = _oob_sqli_test_mod
    run_smart_active_tests = _run_smart_active_tests_mod
    subdomain_takeover_check = _subdomain_takeover_check_mod
    nosql_injection_test = _nosql_injection_test_mod
    nosql_injection_test_json_body = _nosql_injection_test_json_body_mod
    ldap_injection_test = _ldap_injection_test_mod
    ldap_injection_test_json_body = _ldap_injection_test_json_body_mod
    xpath_injection_test = _xpath_injection_test_mod
    xpath_injection_test_json_body = _xpath_injection_test_json_body_mod
    xxe_injection_test = _xxe_injection_test_mod
    xxe_injection_test_json_body = _xxe_injection_test_json_body_mod
    ssti_test = _ssti_test_mod
    ssrf_injection_test_json_body = _ssrf_injection_test_json_body_mod
    stored_xss_workflow = _stored_xss_workflow_mod
    jwt_vulnerability_test = _jwt_vulnerability_test_mod
    oauth_vulnerability_test = _oauth_vulnerability_test_mod
    session_vulnerability_test = _session_vulnerability_test_mod
    timing_attack_test = _timing_attack_test_mod
    http_smuggling_test = _http_smuggling_test_mod
    graphql_vulnerability_test = _graphql_vulnerability_test_mod
    cache_poisoning_test = _cache_poisoning_test_mod
    test_csrf = _test_csrf_mod
    test_idor_bola = _test_idor_bola_mod
    test_path_traversal = _test_path_traversal_mod
    test_default_credentials = _test_default_credentials_mod
    test_default_credentials_aggressive = _test_default_credentials_aggressive_mod
    test_deserialization = _test_deserialization_mod
    test_rate_limiting = _test_rate_limiting_mod
    test_2fa_bypass = _test_2fa_bypass_mod
    test_account_enumeration = _test_account_enumeration_mod
    test_bruteforce_protection = _test_bruteforce_protection_mod
    test_http_methods = _test_http_methods_mod
    test_password_policy = _test_password_policy_mod
    test_password_reset = _test_password_reset_mod
    test_session_management = _test_session_management_mod
    test_js_dependencies = _test_js_dependencies_mod
    test_js_secrets = _test_js_secrets_mod
    detect_server_versions = _detect_server_versions_mod
    test_client_side_vulns = _test_client_side_vulns_mod
    discover_technologies = _discover_technologies_mod
    test_cicd_exposure = _test_cicd_exposure_mod
    test_package_exposure = _test_package_exposure_mod
    test_cloud_buckets = _test_cloud_buckets_mod
    test_backup_files = _test_backup_files_mod
    test_directory_listing = _test_directory_listing_mod
    # New cloud security checks
    test_cloud_metadata_ssrf = _test_cloud_metadata_ssrf_mod
    test_kubernetes_exposure = _test_kubernetes_exposure_mod
    test_terraform_state = _test_terraform_state_mod
    test_container_registry_exposure = _test_container_registry_exposure_mod
    # IP Reputation & Brand Protection
    check_ip_reputation = _check_ip_reputation_mod
    check_dnsbl = _check_dnsbl_mod
    check_typosquatting = _check_typosquatting_mod
    check_brand_protection = _check_brand_protection_mod
    # Enhanced DNS checks
    enumerate_dkim_selectors = _enumerate_dkim_selectors_mod
    validate_spf_record = _validate_spf_record_mod
    test_zone_transfer = _test_zone_transfer_mod
    check_dangling_dns = _check_dangling_dns_mod
    check_enhanced_dns = _check_enhanced_dns_mod
    # Domain Intelligence
    check_domain_intelligence = _check_domain_intelligence_mod
    # CT Monitoring
    check_certificate_transparency = _check_ct_transparency_mod
    build_crypto_inventory = _build_crypto_inventory_mod
    # SMTP Security
    check_smtp_security = _check_smtp_security_mod
    # ASN Discovery
    check_asn_discovery = _check_asn_discovery_mod
    # Compliance Mapper
    generate_compliance_report = _generate_compliance_report_mod
    # Network Services
    check_network_services = _check_network_services_mod
    # Auth Session
    AuthSession = _AuthSession_mod
    parse_cookie_string = _parse_cookie_string_mod
    create_authenticated_session = _create_authenticated_session_mod
    api_login = _api_login_mod
    # Form Login
    form_login = _form_login_mod
    detect_login_form = _detect_login_form_mod
    test_form_login = _test_form_login_mod
    # OAuth/OIDC
    oauth_authenticate = _oauth_authenticate_mod
    oauth_refresh_token = _oauth_refresh_token_mod
    oidc_discover = _oidc_discover_mod
    OAuthSession = _OAuthSession_mod
    parse_jwt_claims = _parse_jwt_claims_mod
    # Breach Check
    breach_assessment = _breach_assessment_mod
    check_domain_breaches = _check_domain_breaches_mod
    generate_breach_findings = _generate_breach_findings_mod
    # SARIF Output
    convert_to_sarif = _convert_to_sarif_mod
    quality_gate_check = _quality_gate_check_mod
    write_sarif_file = _write_sarif_file_mod
    create_baseline = _create_baseline_mod
    load_baseline = _load_baseline_mod
    save_baseline = _save_baseline_mod
    filter_by_baseline = _filter_by_baseline_mod
    # Vendor Risk
    vendor_risk_assessment = _vendor_risk_assessment_mod
    generate_vendor_findings = _generate_vendor_findings_mod
    # WebSocket security
    probe_websocket_endpoints = _probe_websocket_endpoints_mod
    run_websocket_security_tests = _run_websocket_security_tests_mod
    # Phase 4 checks
    test_file_upload = _test_file_upload_mod
    test_open_redirect = _test_open_redirect_mod
    test_host_header_injection = _test_host_header_injection_mod
    test_business_logic = _test_business_logic_mod
    test_api_security = _test_api_security_mod
    # Access control checks
    check_forced_browsing = _check_forced_browsing_mod
    format_forced_browsing_findings = _format_forced_browsing_findings_mod
    smart_bola_test = _smart_bola_test_mod
    check_bola_multi_user = _check_bola_multi_user_mod
    check_bola_enumeration = _check_bola_enumeration_mod
    # Race condition testing
    run_race_condition_tests = _run_race_condition_tests_mod
    identify_race_prone_endpoints = _identify_race_prone_endpoints_mod
    # Rate limiting and verb tampering
    detect_rate_limits = _detect_rate_limits_mod
    detect_rate_limits_per_endpoint = _detect_rate_limits_per_endpoint_mod
    test_verb_tampering = _test_verb_tampering_mod
    test_verb_tampering_authenticated = _test_verb_tampering_authenticated_mod
    interactive_browser_crawl = _interactive_browser_crawl_mod
    # Enhanced JWT and GraphQL tests
    jwt_comprehensive_test = _jwt_comprehensive_test_mod
    jwt_algorithm_confusion_test = _jwt_algorithm_confusion_test_mod
    jwt_kid_injection_test = _jwt_kid_injection_test_mod
    jwt_claim_manipulation_test = _jwt_claim_manipulation_test_mod
    graphql_comprehensive_test = _graphql_comprehensive_test_mod
    graphql_batch_attack_test = _graphql_batch_attack_test_mod
    graphql_depth_attack_test = _graphql_depth_attack_test_mod
    graphql_alias_idor_test = _graphql_alias_idor_test_mod
    graphql_field_suggestion_test = _graphql_field_suggestion_test_mod
    # SSH checks
    ssh_auth_methods = _ssh_auth_methods_mod
    # AI Classifier
    call_ai_provider = _call_ai_provider_mod
    classify_findings_batch = _classify_findings_batch_mod
    generate_executive_summary_ai = _generate_executive_summary_mod
    calculate_hybrid_confidence = _calculate_hybrid_confidence_mod
    AIClassificationResult = _AIClassificationResult_mod
    # Remediation KB
    get_remediation_for_finding = _get_remediation_for_finding_mod
    get_code_example = _get_code_example_mod
    # Finding Validator
    validate_finding = _validate_finding_mod
    apply_validation_to_finding = _apply_validation_to_finding_mod
    should_report_finding = _should_report_finding_mod
    ValidationResult = _ValidationResult_mod
    CONFIDENCE_THRESHOLDS = _CONFIDENCE_THRESHOLDS_mod
    validate_findings_pipeline = _validate_findings_pipeline_mod
    ValidationPipelineConfig = _ValidationPipelineConfig_mod
except Exception as e:
    # If modular imports fail, log the error and provide fallback stubs
    print(f"WARNING: Failed to import modular tools: {e}", file=sys.stderr)
    import traceback
    traceback.print_exc()

    # Provide fallback stub functions for critical tools that may not have been imported
    async def _fallback_tlsx_probe(host: str, port: int):
        """Fallback tlsx_probe when modular import fails."""
        return {"endpoints": [], "certificate": {}}

    def _fallback_build_crypto_inventory(*args, **kwargs):
        return {"protocols": {"observed": [], "legacy": []}, "pqc_readiness": {"status": "unknown", "blockers": []}}

    async def _fallback_check_forced_browsing(*args, **kwargs):
        return {"vulnerable": False, "findings": [], "summary": {}}

    def _fallback_format_forced_browsing_findings(*args, **kwargs):
        return []

    async def _fallback_ssh_auth_methods(*args, **kwargs):
        return {"password_auth_enabled": False, "auth_methods": [], "findings": [], "scan_completed": False}

    # Ensure critical functions are defined even if import failed
    tlsx_probe = _fallback_tlsx_probe
    build_crypto_inventory = _fallback_build_crypto_inventory
    check_forced_browsing = _fallback_check_forced_browsing
    format_forced_browsing_findings = _fallback_format_forced_browsing_findings
    ssh_auth_methods = _fallback_ssh_auth_methods

    # AI classifier fallbacks
    async def _fallback_classify_findings_batch(*args, **kwargs):
        return {}, "AI classifier module not available", None

    async def _fallback_generate_executive_summary(*args, **kwargs):
        return None, "AI classifier module not available", None

    def _fallback_calculate_hybrid_confidence(h_verdict, h_conf, h_rationale, ai_result):
        return h_verdict, h_conf, h_rationale

    def _fallback_get_remediation_for_finding(finding):
        return None

    def _fallback_get_code_example(remediation, framework=None):
        return None

    classify_findings_batch = _fallback_classify_findings_batch
    generate_executive_summary_ai = _fallback_generate_executive_summary
    calculate_hybrid_confidence = _fallback_calculate_hybrid_confidence
    get_remediation_for_finding = _fallback_get_remediation_for_finding
    get_code_example = _fallback_get_code_example


def _get_validator_type(finding: dict) -> str:
    """
    Determine which validator type applies to a finding for stats tracking.
    """
    title_lower = finding.get("title", "").lower()
    tool = finding.get("tool", "").lower()

    if "xss" in title_lower or "cross-site scripting" in title_lower or tool == "dalfox":
        return "xss"
    if ("sql" in title_lower and "inject" in title_lower) or tool == "sqlmap":
        return "sqli"
    if "ssrf" in title_lower or "server-side request" in title_lower:
        return "ssrf"
    if "xxe" in title_lower or "xml external" in title_lower:
        return "xxe"
    if any(x in title_lower for x in ["path traversal", "lfi", "local file", "directory traversal", "../"]):
        return "path_traversal"
    if "open redirect" in title_lower or "url redirect" in title_lower:
        return "open_redirect"
    if any(x in title_lower for x in ["command injection", "rce", "remote code", "os command"]):
        return "command_injection"
    if "subdomain takeover" in title_lower or "takeover" in title_lower:
        return "subdomain_takeover"
    if "cors" in title_lower:
        return "cors"
    if "jwt" in title_lower or "json web token" in title_lower:
        return "jwt"
    if "csrf" in title_lower or "cross-site request forgery" in title_lower:
        return "csrf"
    if "idor" in title_lower or "insecure direct object" in title_lower or "bola" in title_lower:
        return "idor"
    if any(x in title_lower for x in ["file upload", "upload vuln", "unrestricted upload"]):
        return "file_upload"
    if any(x in title_lower for x in ["deserialization", "deserialize", "pickle", "unserialize"]):
        return "deserialization"
    return "other"


try:
    from scanner_tools.report_gating import finding_has_verification_evidence
except Exception:
    def finding_has_verification_evidence(finding: dict[str, Any]) -> bool:
        """Fallback report gating helper when modular import is unavailable."""
        if not isinstance(finding, dict):
            return False
        if finding.get("verified") is True:
            return True
        validation = finding.get("validation")
        if isinstance(validation, dict):
            if validation.get("verified") is True:
                return True
            if validation.get("poe_proven") is True:
                return True
        verdict = str(
            finding.get("verification_verdict")
            or finding.get("last_verification_verdict")
            or ""
        ).strip().lower()
        if verdict in {"exploited", "likely_vulnerable"}:
            return True
        result_status = str(finding.get("result_status") or "").strip().lower()
        if result_status in {"still_vulnerable", "verified_vulnerable"}:
            return True
        poe = finding.get("poe")
        if isinstance(poe, dict) and poe.get("proven") is True:
            return True
        poe_result = finding.get("poe_result")
        if isinstance(poe_result, dict) and poe_result.get("proven") is True:
            return True
        return False


# ---------- Scan orchestration ----------

async def build_report(target: str,
                       dkim_selectors: list[str] | None=None,
                       openapi_url: str | None=None,
                       api_token: str | None=None,
                       manual_endpoints: list[dict[str, Any]] | None=None,
                       active_checks: bool=False,
                       active_xss: bool=True,
                       active_sqli: bool=True,
                       deep_domxss: bool | None = None,
                       max_active: int=10,
                       quick_mode: bool=False,
                       no_browser: bool=False,
                       public_only: bool=False,
                       complete_mode: bool=False,
                       max_ports: int=1000,
                       deep_discovery: bool=False,
                       exploit_level: str="safe",
                       complete_tier: str="safe",
                       csrf_testing: bool=False,
                       idor_testing: bool=False,
                       path_traversal_testing: bool=False,
                       default_creds_testing: bool=False,
                       deserialization_testing: bool=False,
                       rate_limiting_testing: bool=False,
                       twofa_bypass_testing: bool=False,
                       password_reset_testing: bool=False,
                       session_mgmt_testing: bool=False,
                       js_dependency_scanning: bool=False,
                       js_secret_scanning: bool=False,
                       cicd_exposure_testing: bool=False,
                       package_exposure_testing: bool=False,
                       cloud_bucket_testing: bool=False,
                       backup_file_testing: bool=False,
                       # Phase 4 checks
                       file_upload_testing: bool=False,
                       open_redirect_testing: bool=False,
                       host_header_testing: bool=False,
                       business_logic_testing: bool=False,
                       api_security_testing: bool=False,
                       # WebSocket security
                       websocket_testing: bool=False,
                       # Access control checks
                       forced_browsing_testing: bool=False,
                       mass_assignment_testing: bool=False,
                       bola_testing: bool=False,
                       # SSH checks
                       ssh_testing: bool=False,
                       ssh_port: int=22,
                       # New: IP Reputation & Threat Intelligence
                       ip_reputation: bool=False,
                       abuseipdb_key: str | None=None,
                       virustotal_key: str | None=None,
                       # New: Brand Protection & Typosquatting
                       typosquatting: bool=False,
                       max_typo_checks: int=100,
                       # New: Enhanced DNS Security
                       enhanced_dns: bool=False,
                       dkim_enumeration: bool=False,
                       zone_transfer_test: bool=False,
                       # New: Domain Intelligence
                       domain_intelligence: bool=False,
                       # New: CT Monitoring
                       ct_monitoring: bool=False,
                       # New: SMTP Security
                       smtp_security: bool=False,
                       # New: ASN Discovery
                       asn_discovery: bool=False,
                       # New: Compliance Report
                       compliance_report: bool=False,
                       # New: Network Services
                       network_services: bool=False,
                       # New: Authenticated Scanning
                       auth_cookies: str | None=None,
                       auth_header: str | None=None,
                       auth_headers_json: str | None=None,
                       auth_scenario_json: str | None=None,
                       # New: Form-Based Login
                       login_url: str | None=None,
                       login_username: str | None=None,
                       login_password: str | None=None,
                       login_extra_fields: str | None=None,
                       # New: Automated API Login
                       auto_auth: bool=False,
                       # New: OAuth 2.0/OIDC Authentication
                       oauth_client_id: str | None=None,
                       oauth_client_secret: str | None=None,
                       oauth_token_url: str | None=None,
                       oauth_scope: str | None=None,
                       oauth_username: str | None=None,
                       oauth_password: str | None=None,
                       # User2 credentials for BOLA comparison
                       user2_cookies: str | None=None,
                       user2_header: str | None=None,
                       user2_login_username: str | None=None,
                       user2_login_password: str | None=None,
                       # New: Breach Monitoring
                       breach_check: bool=False,
                       hibp_api_key: str | None=None,
                       github_token: str | None=None,
                       # New: Vendor/Third-Party Risk
                       vendor_risk: bool=False,
                       # New: Cloud Security Enhancements
                       cloud_ssrf: bool=False,
                       kubernetes_exposure: bool=False,
                       terraform_exposure: bool=False,
                       registry_exposure: bool=False,
                       # AI-powered finding validation
                       ai_validation: bool=False,
                       ai_url: str | None=None,
                       ai_api_key: str | None=None,
                       ai_model: str="gpt-4o-mini",
                       include_partial_attack_chains: bool=False,
                       # Discovery enhancements
                       grpc_discovery: bool=False,
                       json_link_following: bool=False,
                       options_method_discovery: bool=False,
                       focus_rules_json: str | None=None,
                       avoid_rules_json: str | None=None,
                       verified_findings_only: bool | None=None,
                       # Smart scan mode
                       smart_mode: bool=False,
                       # Smart scan tuning
                       no_early_stop: bool=False,
                       thorough_params: bool=False,
                       oob_callback_url: str | None=None,
                       budget_profile: str | None=None,
                       custom_budget: dict[str, Any] | None=None,
                       # Safety/performance limits
                       smart_bola_max_endpoints: int=SMART_SCAN_BUDGETS.smart_bola_max_endpoints,
                       dom_xss_max_files: int=SMART_SCAN_BUDGETS.dom_xss_max_files,
                       sqli_extract_max: int=SMART_SCAN_BUDGETS.sqli_extract_max,
                       oob_max_findings: int=SMART_SCAN_BUDGETS.oob_max_findings,
                       # Active enforcement metadata
                       active_enforced: bool=False) -> dict[str, Any]:

    # Warning if conflicting flags are used (only for non-enforced scan types)
    if public_only and active_checks and not active_enforced:
        print("Warning: --active flag ignored when --public is set (public mode disables active scans)", file=sys.stderr)

    host, port, scheme = normalize_host(target)
    base_url = f"{scheme}://{host}"
    if port and port not in [80, 443]:
        base_url = f"{scheme}://{host}:{port}"

    focus_rules = parse_scope_rules_json(focus_rules_json, "focus")
    avoid_rules = parse_scope_rules_json(avoid_rules_json, "avoid")
    budget_scan_type = (
        "smart" if smart_mode
        else complete_tier if complete_mode and complete_tier in {"full", "aggressive"}
        else "deep" if complete_mode
        else "quick" if quick_mode
        else "standard"
    )
    effective_budget_profile = budget_profile
    if thorough_params and not effective_budget_profile and not custom_budget:
        effective_budget_profile = "thorough"
    scan_budget = resolve_scan_budget(budget_scan_type, effective_budget_profile, custom_budget)
    if scan_budget.get("active_max_endpoints"):
        max_active = int(scan_budget["active_max_endpoints"])
    smart_bola_max_endpoints = int(scan_budget.get("smart_bola_max_endpoints") or smart_bola_max_endpoints)
    dom_xss_max_files = int(scan_budget.get("dom_xss_max_files") or dom_xss_max_files)
    sqli_extract_max = int(scan_budget.get("sqli_extract_max") or sqli_extract_max)
    oob_max_findings = int(scan_budget.get("oob_max_findings") or oob_max_findings)
    # Runtime AI controls are injected by worker env and should drive scan behavior.
    scan_ai_classification_enabled = _is_truthy_env(
        os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED"),
        default=ai_validation,
    )
    pipeline_ai_enabled = bool(ai_validation and ai_api_key and scan_ai_classification_enabled)
    verify_min_severity = _normalize_ai_classification_min_severity(
        os.environ.get("VERIFICATION_MIN_SEVERITY") or os.environ.get("AI_VERIFY_MIN_SEVERITY"),
        default="high",
    )
    # Smart scans default to discovery-first reporting unless proof-gating is
    # explicitly enabled via PROOF_REQUIRED_FOR_SMART / --verified-findings-only.
    if verified_findings_only is None and smart_mode:
        _proof_required = os.environ.get("PROOF_REQUIRED_FOR_SMART", "false").strip().lower()
        verified_findings_only = _proof_required in {"1", "true", "yes", "on"}
    elif verified_findings_only is None:
        verified_findings_only = False
    scope_stats = {
        "focus_rule_count": len(focus_rules),
        "avoid_rule_count": len(avoid_rules),
        "manual_endpoints_dropped": 0,
        "discovered_urls_dropped": 0,
    }
    auth_scenario = parse_auth_scenario_json(auth_scenario_json)
    auth_scenario_info: dict[str, Any] | None = None
    auth_scenario_totp: str | None = None
    if auth_scenario:
        credentials = auth_scenario.get("credentials") if isinstance(auth_scenario.get("credentials"), dict) else {}
        totp_secret = str((credentials or {}).get("totp_secret") or "").strip()
        if totp_secret:
            try:
                auth_scenario_totp = _generate_totp(totp_secret)
            except Exception as e:
                print(f"[auth_scenario] Failed to generate TOTP code: {e}", file=sys.stderr)

        # Scenario config acts as fallback defaults; explicit scan options win.
        if not login_url and auth_scenario.get("login_url"):
            login_url = _apply_auth_placeholders(str(auth_scenario.get("login_url")), totp_code=auth_scenario_totp)
        if not auth_header and auth_scenario.get("auth_header"):
            auth_header = _apply_auth_placeholders(str(auth_scenario.get("auth_header")), totp_code=auth_scenario_totp)
        if not auth_cookies and auth_scenario.get("auth_cookies"):
            auth_cookies = _apply_auth_placeholders(str(auth_scenario.get("auth_cookies")), totp_code=auth_scenario_totp)
        if not login_username and (credentials or {}).get("username"):
            login_username = _apply_auth_placeholders(str((credentials or {}).get("username")), totp_code=auth_scenario_totp)
        if not login_password and (credentials or {}).get("password"):
            login_password = _apply_auth_placeholders(str((credentials or {}).get("password")), totp_code=auth_scenario_totp)

        auth_scenario_info = {
            "configured": True,
            "login_type": auth_scenario.get("login_type"),
            "has_login_flow": bool(auth_scenario.get("login_flow")),
            "has_success_condition": bool(auth_scenario.get("success_condition")),
            "has_totp_secret": bool(totp_secret),
            "extra_fields_count": len(auth_scenario.get("extra_fields") or {}),
        }
        print("[auth_scenario] Loaded scenario config", file=sys.stderr)
    if focus_rules or avoid_rules:
        print(
            f"[scope] Loaded rules: focus={len(focus_rules)} avoid={len(avoid_rules)}",
            file=sys.stderr,
        )

    # Initialize coverage tracker for smart scans
    coverage_tracker = CoverageTracker() if smart_mode else None

    # Seed URLs derived from target path (improves discovery when target is a subpath or static asset)
    seed_entry_urls: list[str] = []
    seed_js_urls: list[str] = []
    try:
        target_str = target if isinstance(target, str) else (target.get("url") if isinstance(target, dict) else "")
        if target_str and "://" in target_str:
            parsed_target = urllib.parse.urlparse(target_str)
            target_path = parsed_target.path or "/"
            static_exts = {
                ".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg",
                ".svg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot",
            }
            target_ext = os.path.splitext(target_path.lower())[1]
            if target_path and target_path != "/":
                if target_ext in static_exts:
                    if target_ext in (".js", ".mjs"):
                        seed_js_urls.append(target_str)
                    parent = target_path.rsplit("/", 1)[0] or "/"
                    seed_entry_urls.append(urllib.parse.urljoin(base_url + "/", parent.lstrip("/") + "/"))
                else:
                    seed_entry_urls.append(urllib.parse.urljoin(base_url + "/", target_path.lstrip("/")))
                if parsed_target.query and target_ext not in static_exts:
                    seed_entry_urls.append(target_str)
    except Exception:
        pass

    if seed_entry_urls:
        seed_entry_urls = list(dict.fromkeys(seed_entry_urls))
        print(f"[scanner] Entry seed URLs derived from target: {seed_entry_urls[:3]}...", file=sys.stderr)

    manual_endpoints_norm = normalize_manual_endpoints(base_url, manual_endpoints)
    if manual_endpoints_norm and (focus_rules or avoid_rules):
        manual_endpoints_norm, manual_scope = apply_scope_rules_to_manual_endpoints(
            manual_endpoints_norm,
            focus_rules=focus_rules,
            avoid_rules=avoid_rules,
        )
        scope_stats["manual_endpoints_dropped"] = manual_scope["dropped"]
        print(
            f"[scope] Manual endpoints kept={manual_scope['kept']} dropped={manual_scope['dropped']}",
            file=sys.stderr,
        )
    if manual_endpoints_norm:
        print(f"[DEBUG] Normalized {len(manual_endpoints_norm)} manual endpoints:", file=sys.stderr)
        for i, ep in enumerate(manual_endpoints_norm[:5]):
            print(
                f"[DEBUG]   {i}: method={ep.get('method')} url={ep.get('url')} "
                f"params={ep.get('params')} body_params={ep.get('body_params')} "
                f"param_defaults={ep.get('param_defaults')} body_defaults={ep.get('body_param_defaults')} "
                f"content_type={ep.get('content_type')}",
                file=sys.stderr
            )

    # Initialize scan session ID early for consistent reporting.
    import uuid as _uuid
    scan_session_id = str(_uuid.uuid4())
    emit_progress("init", 5, "initializing scan")

    # Pre-scan connectivity validation
    pre_scan_issues = []
    pre_scan_validation_result = None
    try:
        from scanner_tools.health_check import pre_scan_validation
        pre_scan_validation_result = await pre_scan_validation(target)
        if not pre_scan_validation_result["can_proceed"]:
            logging.warning(f"Pre-scan validation failed for {target}: {pre_scan_validation_result['warnings']}")
            pre_scan_issues = pre_scan_validation_result["warnings"]

            connectivity = pre_scan_validation_result.get("connectivity") or {}
            details = connectivity.get("details") or {}
            ip_addresses = details.get("ip_addresses") or []
            a_records = [ip for ip in ip_addresses if ":" not in ip]
            aaaa_records = [ip for ip in ip_addresses if ":" in ip]

            http_status_code = details.get("http_status")
            http_status_line = f"HTTP/? {http_status_code}" if http_status_code else "HTTP/? 0"
            http_url = details.get("http_url") or base_url
            security_txt_url = http_url.rstrip("/") + "/.well-known/security.txt"

            empty_headers: dict[str, list[str]] = {}
            sec_headers = parse_security_headers(empty_headers)
            csp_eval = analyze_csp(None)
            cookies = analyze_cookies(empty_headers)

            scan_mode_label = "smart" if smart_mode else ("complete" if complete_mode else ("quick" if quick_mode else "standard"))
            report: dict[str, Any] = {
                "schema_version": REPORT_SCHEMA_VERSION,
                "scanner_version": SCANNER_VERSION,
                "input": {"target": target, "normalized_host": host, "port": port, "scheme": scheme},
                "scan_mode": scan_mode_label,
                "scan_config": {
                    "active_enforced": active_enforced,
                    "active_checks": active_checks,
                    "smart_mode": smart_mode,
                    "no_early_stop": no_early_stop,
                    "thorough_params": thorough_params,
                    "budget_profile": scan_budget.get("budget_profile"),
                    "resolved_budget": scan_budget,
                    "verified_findings_only": verified_findings_only,
                    "focus_rules": len(focus_rules),
                    "avoid_rules": len(avoid_rules),
                    "auth_scenario": bool(auth_scenario),
                },
                "timestamp_utc": now_utc_iso(),
                "dns": {
                    "a": a_records,
                    "aaaa": aaaa_records,
                    "cname": None,
                    "mx": [],
                    "txt_sample": [],
                    "spf": None,
                    "dmarc": {},
                    "dnssec": {},
                    "dkim": {},
                    "caa": {},
                    "mta_sts": {},
                    "tls_rpt": {},
                },
                "tls": {
                    "endpoints": [],
                    "certificate": {},
                    "ocsp": {"stapled": False},
                    "nmap": {},
                    "testssl": {},
                    "sslyze": {},
                    "cipher_suites": {},
                },
                "http": {
                    "source": "pre_scan",
                    "status": http_status_line,
                    "final_url": http_url,
                    "headers": empty_headers,
                    "security_headers": sec_headers,
                    "csp_evaluation": csp_eval,
                    "cookies": cookies,
                    "http2": None,
                    "http3": None,
                    "http3_advertised": False,
                    "scheme_redirect": "n/a",
                    "security_txt": {"present": False, "url": security_txt_url, "sample": None},
                    "evidence": {"screenshot": None, "page_title": None},
                },
                "discovery": {
                    "summary": {
                        "total_urls": 0,
                        "browser_endpoints": 0,
                        "manual_endpoints": 0,
                        "methods_used": [],
                        "warnings": ["Target unreachable during pre-scan validation."],
                    }
                },
                "network_scan": {},
                "findings": [],
                "connectivity": connectivity,
            }

            coverage = assess_scan_completeness(
                report,
                public_only=public_only,
                active_checks_requested=active_checks,
                js_dependency_scanning=js_dependency_scanning,
                js_secret_scanning=js_secret_scanning,
            )
            if pre_scan_issues:
                for issue in pre_scan_issues:
                    labeled = f"Pre-scan: {issue}"
                    if labeled not in coverage["issues"]:
                        coverage["issues"].append(labeled)
            report["coverage"] = coverage

            grade_result = grade(report)
            if not coverage["grade_reliable"]:
                grade_result["grade_reliable"] = False
                grade_result["grade_warning"] = "Grade may be inaccurate - required scan modules did not complete"
                grade_result["coverage_issues"] = coverage["issues"]
                grade_result["original_grade"] = grade_result["grade"]
                grade_result["grade"] = grade_result["grade"] + "*"
                grade_result["summary"] = f"[INCOMPLETE] {grade_result['summary']}"
            else:
                grade_result["grade_reliable"] = True
            report["result"] = grade_result

            checks_skipped = []
            if active_checks and public_only:
                checks_skipped.append({
                    "check": "active_checks",
                    "reason": "Active scans disabled in public-only mode"
                })
            if js_dependency_scanning and public_only:
                checks_skipped.append({
                    "check": "js_dependency_scanning",
                    "reason": "JS scanning disabled in public-only mode"
                })
            if js_secret_scanning and public_only:
                checks_skipped.append({
                    "check": "js_secret_scanning",
                    "reason": "JS secret scanning disabled in public-only mode"
                })

            report["scan_metadata"] = {
                "scan_id": scan_session_id,
                "target": target,
                "completed_at": now_utc_iso(),
                "scan_mode": scan_mode_label,
                "coverage_status": coverage["status"],
                "schema_version": REPORT_SCHEMA_VERSION,
                "scanner_version": SCANNER_VERSION,
                "options": {
                    "public_only": public_only,
                    "active_checks_requested": active_checks,
                    "ai_validation_enabled": pipeline_ai_enabled,
                    "ai_scan_classification_enabled": scan_ai_classification_enabled,
                    "ai_verify_min_severity": verify_min_severity,
                },
                "checks_skipped": checks_skipped,
                "pre_scan_warnings": pre_scan_issues if pre_scan_issues else None,
            }

            emit_progress("pre_scan_failed", 100, "target unreachable")
            return report
        else:
            logging.info(f"Pre-scan validation passed for {target}")
    except Exception as e:
        logging.warning(f"Pre-scan validation error: {e}")

    emit_progress("pre_scan", 10, "validation passed")

    # Initialize scan-scoped PoE session to ensure request counts are isolated per scan
    # This prevents cross-scan throttling issues in long-lived worker processes
    try:
        from scanner_tools.proof_of_exploit import end_scan_session, reset_request_counts, start_scan_session
        start_scan_session(scan_session_id)
    except ImportError:
        # PoE module not available - continue without session management
        pass

    # Create authenticated session if credentials provided
    auth_session = None
    auth_config = {}
    if auth_cookies or auth_header or auth_headers_json:
        auth_cookies_dict = {}
        auth_headers_dict = {}

        # Parse cookies
        if auth_cookies:
            auth_cookies_dict = parse_cookie_string(auth_cookies)

        # Parse auth header
        if auth_header:
            auth_headers_dict["Authorization"] = auth_header

        # Parse JSON headers
        if auth_headers_json:
            try:
                extra_headers = json.loads(auth_headers_json)
                if isinstance(extra_headers, dict):
                    auth_headers_dict.update(extra_headers)
            except json.JSONDecodeError:
                print("Warning: Invalid JSON in --auth-headers-json, ignoring", file=sys.stderr)

        if auth_cookies_dict or auth_headers_dict:
            auth_session = AuthSession(
                cookies=auth_cookies_dict,
                headers=auth_headers_dict,
                base_url=base_url
            )
            auth_config = {
                "enabled": True,
                "cookies_count": len(auth_cookies_dict),
                "headers_count": len(auth_headers_dict),
                "cookie_names": list(auth_cookies_dict.keys()),
                "header_names": list(auth_headers_dict.keys())
            }

    # Form-based login authentication (takes priority over cookie/header auth)
    login_result_info = None
    extra_fields: dict[str, Any] | None = {}

    if login_extra_fields:
        try:
            parsed_extra = json.loads(login_extra_fields)
            if isinstance(parsed_extra, dict):
                extra_fields.update(parsed_extra)
            else:
                print("Warning: --login-extra-fields must be a JSON object, ignoring", file=sys.stderr)
        except json.JSONDecodeError:
            print("Warning: Invalid JSON in --login-extra-fields, ignoring", file=sys.stderr)

    scenario_extra_fields = auth_scenario.get("extra_fields") if isinstance(auth_scenario, dict) else None
    if isinstance(scenario_extra_fields, dict):
        for key, value in scenario_extra_fields.items():
            field_name = str(key).strip()
            if not field_name:
                continue
            if field_name not in extra_fields:
                extra_fields[field_name] = _apply_auth_placeholders(
                    str(value),
                    totp_code=auth_scenario_totp,
                )

    if extra_fields:
        if auth_scenario_totp:
            for key, value in list(extra_fields.items()):
                if isinstance(value, str):
                    extra_fields[key] = _apply_auth_placeholders(value, totp_code=auth_scenario_totp)
    else:
        extra_fields = None

    if login_username and login_password:
        try:
            # Perform form-based login
            login_result = await form_login(
                base_url=base_url,
                username=login_username,
                password=login_password,
                login_url=login_url,
                extra_fields=extra_fields
            )

            login_result_info = {
                "attempted": True,
                "success": login_result.success,
                "login_url": login_result.login_url,
                "attempts": login_result.attempts,
                "error": login_result.error
            }

            if login_result.success and login_result.session:
                # Use the authenticated session from form login
                auth_session = login_result.session
                auth_config = {
                    "enabled": True,
                    "method": "form_login",
                    "login_url": login_result.login_url,
                    "cookies_count": len(login_result.cookies),
                    "cookie_names": list(login_result.cookies.keys()),
                    "redirect_url": login_result.redirect_url
                }
                if login_result.form_used:
                    login_result_info["form_details"] = {
                        "username_field": login_result.form_used.username_field,
                        "password_field": login_result.form_used.password_field,
                        "csrf_field": login_result.form_used.csrf_field,
                        "confidence": login_result.form_used.confidence
                    }
            else:
                print(f"Warning: Form login failed: {login_result.error}", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Form login error: {e}", file=sys.stderr)
            login_result_info = {
                "attempted": True,
                "success": False,
                "error": str(e)
            }

    # OAuth 2.0/OIDC authentication (takes priority if form login didn't succeed)
    oauth_result_info = None
    oauth_refresh_token_value: str | None = None
    if oauth_client_id and (not auth_session or not login_result_info or not login_result_info.get("success")):
        try:
            # Perform OAuth authentication
            oauth_result = await oauth_authenticate(
                base_url=base_url,
                client_id=oauth_client_id,
                client_secret=oauth_client_secret,
                username=oauth_username,
                password=oauth_password,
                token_url=oauth_token_url,
                scope=oauth_scope
            )

            oauth_result_info = {
                "attempted": True,
                "success": oauth_result.success,
                "error": oauth_result.error,
                "error_description": oauth_result.error_description
            }

            if oauth_result.success and oauth_result.session:
                auth_session = oauth_result.session
                auth_config = {
                    "enabled": True,
                    "method": "oauth",
                    "token_type": oauth_result.token.token_type if oauth_result.token else "Bearer",
                    "has_refresh_token": bool(oauth_result.token and oauth_result.token.refresh_token),
                    "scope": oauth_result.token.scope if oauth_result.token else None,
                }
                if oauth_result.token and oauth_result.token.refresh_token:
                    oauth_refresh_token_value = oauth_result.token.refresh_token
                if oauth_result.token and oauth_result.token.expires_at:
                    oauth_result_info["expires_at"] = oauth_result.token.expires_at.isoformat()
                if oauth_result.jwt_claims:
                    # Include safe JWT claims
                    safe_claims = {}
                    for key in ["sub", "aud", "iss", "exp", "iat", "scope", "azp"]:
                        if key in oauth_result.jwt_claims:
                            safe_claims[key] = oauth_result.jwt_claims[key]
                    oauth_result_info["jwt_claims"] = safe_claims
                if oauth_result.oidc_config:
                    oauth_result_info["oidc_issuer"] = oauth_result.oidc_config.issuer
            else:
                print(f"Warning: OAuth authentication failed: {oauth_result.error}", file=sys.stderr)

        except Exception as e:
            print(f"Warning: OAuth authentication error: {e}", file=sys.stderr)
            oauth_result_info = {
                "attempted": True,
                "success": False,
                "error": str(e)
            }

    # Automated API login for JSON endpoints (optional)
    api_login_info = None
    if auto_auth and login_username and login_password and not auth_session:
        try:
            api_login_result = await api_login(
                base_url=base_url,
                username=login_username,
                password=login_password,
                login_url=login_url,
                extra_fields=extra_fields,
            )

            api_login_info = {
                "attempted": True,
                "success": api_login_result.success,
                "login_url": api_login_result.login_url,
                "method": api_login_result.method,
                "attempts": api_login_result.attempts,
                "error": api_login_result.error,
            }

            if api_login_result.success and api_login_result.session:
                auth_session = api_login_result.session
                auth_config = {
                    "enabled": True,
                    "method": "api_login",
                    "login_url": api_login_result.login_url,
                    "token_type": api_login_result.token_type or "Bearer",
                    "token_key": api_login_result.token_key,
                    "cookies_count": len(api_login_result.cookies),
                    "cookie_names": list(api_login_result.cookies.keys()),
                    "headers_count": len(api_login_result.headers),
                    "header_names": list(api_login_result.headers.keys()),
                }
        except Exception as e:
            print(f"Warning: API login error: {e}", file=sys.stderr)
            api_login_info = {
                "attempted": True,
                "success": False,
                "error": str(e)
            }

    # Create second user session for BOLA comparison (if credentials provided)
    user2_session = None

    if user2_cookies or user2_header:
        # Create user2 session from cookies/headers
        user2_cookies_dict = {}
        user2_headers_dict = {}

        if user2_cookies:
            user2_cookies_dict = parse_cookie_string(user2_cookies)
        if user2_header:
            user2_headers_dict["Authorization"] = user2_header

        if user2_cookies_dict or user2_headers_dict:
            user2_session = AuthSession(
                cookies=user2_cookies_dict,
                headers=user2_headers_dict,
                base_url=base_url
            )
            if auth_config:
                auth_config["user2_enabled"] = True
                auth_config["user2_method"] = "cookies/headers"

    elif user2_login_username and user2_login_password and login_url:
        # Perform form login for user2
        try:
            login_result_user2 = await form_login(
                base_url=base_url,
                username=user2_login_username,
                password=user2_login_password,
                login_url=login_url,
                extra_fields=extra_fields,
            )
            if login_result_user2.success and login_result_user2.session:
                user2_session = login_result_user2.session
                if auth_config:
                    auth_config["user2_enabled"] = True
                    auth_config["user2_method"] = "form_login"
        except Exception as e:
            print(f"Warning: User2 form login failed: {e}", file=sys.stderr)

    # Configure auth refresh callback for long-running scans
    if auth_session and auth_config:
        if auth_config.get("method") == "form_login" and login_username and login_password:
            async def _refresh_form_login():
                result = await form_login(
                    base_url=base_url,
                    username=login_username,
                    password=login_password,
                    login_url=login_url,
                    extra_fields=extra_fields,
                )
                return result.session if result and result.success else None

            auth_session.set_refresh_callback(_refresh_form_login, cooldown_seconds=90, max_failures=3)
            auth_config["refresh_method"] = "form_login"

        elif auth_config.get("method") == "api_login" and login_username and login_password:
            async def _refresh_api_login():
                result = await api_login(
                    base_url=base_url,
                    username=login_username,
                    password=login_password,
                    login_url=login_url,
                    extra_fields=extra_fields,
                )
                return result.session if result and result.success else None

            auth_session.set_refresh_callback(_refresh_api_login, cooldown_seconds=90, max_failures=3)
            auth_config["refresh_method"] = "api_login"

        elif auth_config.get("method") == "oauth" and oauth_client_id:
            async def _refresh_oauth():
                nonlocal oauth_refresh_token_value
                if oauth_refresh_token_value and oauth_token_url:
                    refreshed = await oauth_refresh_token(
                        token_url=oauth_token_url,
                        refresh_token=oauth_refresh_token_value,
                        client_id=oauth_client_id,
                        client_secret=oauth_client_secret,
                    )
                    if refreshed.success and refreshed.session:
                        if refreshed.token and refreshed.token.refresh_token:
                            oauth_refresh_token_value = refreshed.token.refresh_token
                        return refreshed.session
                if oauth_username and oauth_password:
                    refreshed = await oauth_authenticate(
                        base_url=base_url,
                        client_id=oauth_client_id,
                        client_secret=oauth_client_secret,
                        username=oauth_username,
                        password=oauth_password,
                        token_url=oauth_token_url,
                        scope=oauth_scope,
                    )
                    if refreshed.success and refreshed.session:
                        return refreshed.session
                return None

            auth_session.set_refresh_callback(_refresh_oauth, cooldown_seconds=120, max_failures=2)
            auth_config["refresh_method"] = "oauth"

    # P0-3 FIX: Periodic auth refresh background task for long-running scans
    # This ensures auth tokens don't expire during 1-2+ hour scans
    auth_refresh_task = None
    if auth_session:
        async def periodic_auth_refresh(session, interval_minutes: int = 15):
            """Background task that periodically refreshes auth to prevent token expiration."""
            refresh_count = 0
            while True:
                try:
                    await asyncio.sleep(interval_minutes * 60)
                    if session:
                        refreshed = await session.refresh_if_needed(force=False)
                        refresh_count += 1
                        if refreshed:
                            print(f"[scanner] Auth token refreshed (refresh #{refresh_count})", file=sys.stderr)
                        else:
                            print(f"[scanner] Auth check #{refresh_count} - token still valid", file=sys.stderr)
                except asyncio.CancelledError:
                    print(f"[scanner] Auth refresh task cancelled after {refresh_count} refreshes", file=sys.stderr)
                    break
                except Exception as e:
                    print(f"[scanner] Auth refresh error: {e}", file=sys.stderr)
                    # Continue trying even after errors

        # Start background refresh task - will be cancelled at scan end
        auth_refresh_task = asyncio.create_task(periodic_auth_refresh(auth_session, interval_minutes=15))
        print(f"[scanner] Started background auth refresh (every 15 min)", file=sys.stderr)

    # parallel tasks (infra)
    dns_task    = asyncio.create_task(resolve_dns(host))
    dmarc_task  = asyncio.create_task(fetch_dmarc(host))
    dnssec_task = asyncio.create_task(check_dnssec(host))
    tlsx_task   = asyncio.create_task(tlsx_probe(host, port))
    ocsp_task   = asyncio.create_task(openssl_ocsp(host, port))

    # Skip slow TLS scans in public+quick mode for speed
    if public_only and quick_mode:
        # Basic TLS info only - skip deep cipher analysis
        async def dummy_nmap(): return {"raw": "", "weak_indicators": [], "ciphers_by_protocol": {}}
        async def dummy_testssl(): return {"supports_tls13": None, "issues": [], "raw_present": False}
        async def dummy_sslyze(): return {"certificate_chain": [], "cipher_suites": {}, "vulnerabilities": [], "tls_versions": {}, "ocsp_stapling": False, "session_resumption": {}, "scan_completed": False}
        nmap_task   = asyncio.create_task(dummy_nmap())
        testssl_task= asyncio.create_task(dummy_testssl())
        sslyze_task = asyncio.create_task(dummy_sslyze())
    else:
        nmap_task   = asyncio.create_task(nmap_ciphers(host, port))
        testssl_task= asyncio.create_task(testssl(host, port))
        sslyze_task = asyncio.create_task(sslyze_scan(host, port))
    head_task   = asyncio.create_task(curl_headers(base_url))
    # Check HTTP->HTTPS redirect explicitly when scanning HTTPS
    http_redirect_task = None
    if scheme == "https":
        http_redirect_task = asyncio.create_task(curl_headers(f"http://{host}"))
    h2_task     = asyncio.create_task(supports_http2(base_url))
    h3_task     = asyncio.create_task(supports_http3(base_url))
    sec_txt_task= asyncio.create_task(fetch_security_txt(base_url))

    # Email/DNS security extras (best-effort)
    caa_task    = asyncio.create_task(fetch_caa(host))
    mta_task    = asyncio.create_task(fetch_mta_sts(host))
    tlsrpt_task = asyncio.create_task(fetch_tls_rpt(host))

    # New: IP Reputation & Threat Intelligence (opt-in)
    if ip_reputation and not public_only:
        # Get API keys from environment if not provided
        abuseipdb_api_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")
        virustotal_api_key = virustotal_key or os.environ.get("VIRUSTOTAL_API_KEY")
        ip_rep_task = asyncio.create_task(check_ip_reputation(
            "", # Will be set after DNS resolution
            abuseipdb_key=abuseipdb_api_key,
            virustotal_key=virustotal_api_key
        ))
    else:
        async def dummy_ip_rep(): return {"ip": "", "reputation_score": 100, "risk_level": "low", "blacklisted": False, "blacklists": [], "threat_indicators": []}
        ip_rep_task = asyncio.create_task(dummy_ip_rep())

    # New: Brand Protection & Typosquatting (opt-in)
    if typosquatting and not public_only:
        typosquat_task = asyncio.create_task(check_typosquatting(host, max_checks=max_typo_checks, safe_mode=True))
    else:
        async def dummy_typosquat(): return {"original_domain": host, "checked": 0, "suspicious_domains": [], "high_risk_count": 0}
        typosquat_task = asyncio.create_task(dummy_typosquat())

    # New: Enhanced DNS Security (opt-in)
    if enhanced_dns or dkim_enumeration:
        dkim_task = asyncio.create_task(enumerate_dkim_selectors(host, safe_mode=True))
    else:
        async def dummy_dkim(): return {"domain": host, "selectors_found": [], "total_checked": 0, "dkim_configured": False}
        dkim_task = asyncio.create_task(dummy_dkim())

    if enhanced_dns or zone_transfer_test:
        zone_transfer_task = asyncio.create_task(test_zone_transfer(host))
    else:
        async def dummy_zone(): return {"domain": host, "vulnerable": None, "status": "not_tested", "nameservers_tested": 0, "vulnerable_nameservers": []}
        zone_transfer_task = asyncio.create_task(dummy_zone())

    # New: Domain Intelligence (opt-in)
    if domain_intelligence:
        domain_intel_task = asyncio.create_task(check_domain_intelligence(host, timeout=30, safe_mode=True))
    else:
        async def dummy_domain_intel(): return {"domain": host, "whois": None, "overall_risk": "unknown", "findings": [], "recommendations": []}
        domain_intel_task = asyncio.create_task(dummy_domain_intel())

    # New: CT Monitoring (opt-in)
    if ct_monitoring:
        ct_monitor_task = asyncio.create_task(check_certificate_transparency(host, timeout=30, safe_mode=True))
    else:
        async def dummy_ct(): return {"domain": host, "certificates_found": 0, "overall_risk": "unknown", "findings": [], "recommendations": []}
        ct_monitor_task = asyncio.create_task(dummy_ct())

    # New: SMTP Security (opt-in)
    if smtp_security:
        smtp_security_task = asyncio.create_task(check_smtp_security(host, timeout=30, safe_mode=True))
    else:
        async def dummy_smtp(): return {"domain": host, "mx_analysis": None, "smtp_hosts": {}, "overall_assessment": {"grade": "N/A", "risk_level": "unknown"}, "findings": []}
        smtp_security_task = asyncio.create_task(dummy_smtp())

    # New: ASN Discovery (opt-in)
    if asn_discovery:
        asn_discovery_task = asyncio.create_task(check_asn_discovery(host, timeout=60, safe_mode=True))
    else:
        async def dummy_asn(): return {"domain": host, "resolved_ips": {}, "asn_info": [], "hosting_providers": [], "overall_assessment": {"risk_level": "unknown"}, "findings": []}
        asn_discovery_task = asyncio.create_task(dummy_asn())

    # New: Network Services (opt-in)
    if network_services and not public_only:
        network_services_task = asyncio.create_task(check_network_services(host, timeout=120, safe_mode=True))
    else:
        async def dummy_network_services(): return {"host": host, "vpn_endpoints": [], "remote_desktop": {}, "iot_protocols": [], "industrial_protocols": [], "database_exposure": [], "overall_risk": "unknown", "findings": []}
        network_services_task = asyncio.create_task(dummy_network_services())

    # New: Cloud Security Enhancements (opt-in)
    if cloud_ssrf and not public_only:
        cloud_ssrf_task = asyncio.create_task(test_cloud_metadata_ssrf(base_url, discovered_urls=[], safe_mode=True))
    else:
        async def dummy_ssrf(): return {"vulnerable": False, "ssrf_findings": [], "tested_parameters": 0}
        cloud_ssrf_task = asyncio.create_task(dummy_ssrf())

    if kubernetes_exposure and not public_only:
        k8s_task = asyncio.create_task(test_kubernetes_exposure(host, safe_mode=True))
    else:
        async def dummy_k8s(): return {"vulnerable": False, "exposed_endpoints": [], "ports_tested": []}
        k8s_task = asyncio.create_task(dummy_k8s())

    if terraform_exposure and not public_only:
        tf_task = asyncio.create_task(test_terraform_state(base_url, safe_mode=True))
    else:
        async def dummy_tf(): return {"vulnerable": False, "exposed_files": [], "total_tested": 0}
        tf_task = asyncio.create_task(dummy_tf())

    if registry_exposure and not public_only:
        registry_task = asyncio.create_task(test_container_registry_exposure(base_url, safe_mode=True))
    else:
        async def dummy_registry(): return {"vulnerable": False, "registry_type": None, "catalog_accessible": False, "repositories": []}
        registry_task = asyncio.create_task(dummy_registry())

    # New: Breach Monitoring (opt-in)
    if breach_check:
        # Get API keys from environment if not provided
        actual_hibp_key = hibp_api_key or os.environ.get("HIBP_API_KEY")
        actual_github_token = github_token or os.environ.get("GITHUB_TOKEN")
        breach_check_task = asyncio.create_task(breach_assessment(
            domain=host,
            hibp_api_key=actual_hibp_key,
            github_token=actual_github_token,
            check_github=bool(actual_github_token)
        ))
    else:
        async def dummy_breach():
            from scanner_tools.breach_check import BreachCheckResult
            return BreachCheckResult(domain=host)
        breach_check_task = asyncio.create_task(dummy_breach())

    # New: Vendor/Third-Party Risk (opt-in)
    if vendor_risk:
        vendor_risk_task = asyncio.create_task(vendor_risk_assessment(
            base_url=base_url,
            page_content=None,  # Will be populated later after browser fetch
            check_security=not quick_mode,  # Skip security checks in quick mode
            max_resources=30 if quick_mode else 50
        ))
    else:
        async def dummy_vendor():
            from scanner_tools.vendor_risk import VendorRiskResult
            return VendorRiskResult(
                target=base_url,
                assessed_at="",
                total_third_parties=0,
                third_party_domains=[],
                resources=[],
                risk_score=0,
                risk_level="unknown",
                findings=[],
                summary={}
            )
        vendor_risk_task = asyncio.create_task(dummy_vendor())

    # discovery + browser
    httpx_task  = asyncio.create_task(pd_httpx_probe(host, port))

    # Skip katana crawling in public+quick mode (it can be slow)
    # Determine discovery scan type based on mode
    if smart_mode:
        discovery_scan_type = "smart"
    elif quick_mode:
        discovery_scan_type = "quick"
    elif complete_mode:
        # Map complete_tier to discovery scan type
        if complete_tier == "aggressive":
            discovery_scan_type = "aggressive"
        elif complete_tier == "full":
            discovery_scan_type = "full"
        else:
            discovery_scan_type = "deep"
    else:
        discovery_scan_type = "standard"

    if public_only and quick_mode:
        async def dummy_katana(): return []
        katana_task = asyncio.create_task(dummy_katana())
    elif smart_mode:
        # Smart mode: Use recursive discovery
        # Note: signals=None because discovery runs before nuclei; nuclei signals are used
        # later in run_smart_active_tests for adaptive XSS/SQLi testing
        katana_task = asyncio.create_task(smart_discovery(base_url, signals=None, scan_type="smart", budget=scan_budget))
    else:
        katana_task = asyncio.create_task(katana_crawl(base_url, scan_type=discovery_scan_type, budget=scan_budget))

    if auth_session:
        await auth_session.refresh_if_needed()

    browser_crawl_limits = {
        "quick": {"max_pages": 3, "max_depth": 1},
        "standard": {"max_pages": 6, "max_depth": 2},
        "deep": {"max_pages": 12, "max_depth": 2},
        "full": {"max_pages": 20, "max_depth": 3},
        "aggressive": {"max_pages": 30, "max_depth": 3},
        "smart": {"max_pages": 30, "max_depth": 4},
    }
    crawl_limits = browser_crawl_limits.get(discovery_scan_type, {"max_pages": 6, "max_depth": 2})
    crawl_limits = {
        "max_pages": int(scan_budget.get("browser_max_pages") if scan_budget.get("browser_max_pages") is not None else crawl_limits["max_pages"]),
        "max_depth": int(scan_budget.get("browser_max_depth") if scan_budget.get("browser_max_depth") is not None else crawl_limits["max_depth"]),
    }
    enable_browser_crawl = smart_mode or complete_mode or bool(auth_session)

    # For smart mode: Quick JS route discovery to seed browser crawl
    # This helps SPAs by finding routes before the browser crawl starts
    browser_seed_urls: list[str] = list(seed_entry_urls)
    if smart_mode and not no_browser:
        try:
            import re
            import httpx as _httpx

            print(f"[smart] Quick JS route discovery for browser crawl seeding", file=sys.stderr)
            async with _httpx.AsyncClient(verify=False, timeout=15.0, follow_redirects=True) as client:
                candidate_urls = [base_url]
                if seed_entry_urls:
                    candidate_urls.extend(seed_entry_urls)
                candidate_urls = list(dict.fromkeys(candidate_urls))

                seed_base_url = base_url
                html = ""
                for candidate in candidate_urls:
                    try:
                        resp = await client.get(candidate)
                    except Exception:
                        continue
                    candidate_html = resp.text or ""
                    content_type = (resp.headers.get("content-type") or "").lower()
                    if candidate_html and (
                        "text/html" in content_type
                        or "<html" in candidate_html.lower()
                        or "<script" in candidate_html.lower()
                    ):
                        seed_base_url = candidate
                        html = candidate_html
                        break
                    if not html:
                        seed_base_url = candidate
                        html = candidate_html

                # Extract script URLs from HTML
                script_urls: list[str] = []
                script_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
                for match in re.finditer(script_pattern, html, re.IGNORECASE):
                    src = match.group(1)
                    if src and not src.startswith("data:"):
                        if src.startswith("//"):
                            src = "https:" + src
                        elif not src.startswith("http"):
                            src = urllib.parse.urljoin(seed_base_url, src)
                        script_urls.append(src)

                # Quick JS analysis for routes (limit to 5 scripts)
                route_patterns = [
                    r'''["'](/[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+){0,3})["']''',  # Path strings
                    r'''path:\s*["']([^"']+)["']''',  # path: '/route'
                    r'''to:\s*["']([^"']+)["']''',  # to: '/route'
                ]

                # Hash route patterns for SPAs using hash-based routing
                hash_route_patterns = [
                    r'''["'](#/[^"']+)["']''',           # "#/search" or "#/page"
                    r'''["'](#!/[^"']+)["']''',          # "#!/page" hashbang
                    r'''location\.hash\s*=\s*["']#?(/[^"']+)["']''',  # location.hash = '#/route'
                ]

                # Detect SPA frameworks from HTML (use specific patterns to avoid false positives)
                # Case-insensitive patterns (framework-specific attributes)
                spa_patterns_ci = [
                    r'ng-app\s*=', r'ng-controller\s*=', r'\[ng-',  # AngularJS directives
                    r'v-bind:', r'v-on:', r'v-model\s*=',           # Vue.js directives
                    r':click\s*=', r'@click\s*=',                   # Vue.js shorthand
                ]
                # Case-sensitive patterns (JS globals, specific markers)
                spa_indicators_cs = [
                    "__NEXT_DATA__",                       # Next.js hydration
                    "__NUXT__",                            # Nuxt.js
                    "data-reactroot", "_reactRootContainer",  # React specific
                    "data-v-",                             # Vue.js scoped styles (hash suffix)
                ]
                html_lower = html.lower()
                is_spa = (
                    any(re.search(pat, html_lower) for pat in spa_patterns_ci) or
                    any(ind in html for ind in spa_indicators_cs)
                )

                for js_url in script_urls[:5]:
                    try:
                        js_resp = await client.get(js_url)
                        js_content = js_resp.text or ""
                        if len(js_content) > 500000:  # Skip very large bundles (>500KB)
                            continue
                        if len(js_content) < 1000:  # Skip tiny files (likely not app bundles)
                            continue

                        # Extract standard routes
                        for pattern in route_patterns:
                            for match in re.finditer(pattern, js_content):
                                route = match.group(1)
                                if route and route.startswith("/") and len(route) > 1:
                                    # Filter out static assets and common non-routes
                                    if not any(route.endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".svg", ".ico"]):
                                        browser_seed_urls.append(route)

                        # Extract hash routes for SPAs
                        for pattern in hash_route_patterns:
                            for match in re.finditer(pattern, js_content):
                                route = match.group(1)
                                if route:
                                    # Keep hash prefix for browser seed URLs
                                    if not route.startswith("#"):
                                        route = "#" + route
                                    browser_seed_urls.append(route)
                    except Exception:
                        continue

                # For detected SPAs, add common hash route patterns as candidates
                if is_spa:
                    common_hash_routes = [
                        "#/search?q=test",
                        "#!/search?q=test",
                        "#/login",
                        "#/home",
                    ]
                    browser_seed_urls.extend(common_hash_routes)

                # Deduplicate and limit
                browser_seed_urls = list(dict.fromkeys(browser_seed_urls))[:25]  # Increased limit for hash routes
                if browser_seed_urls:
                    print(f"[smart] Found {len(browser_seed_urls)} routes to seed browser crawl: {browser_seed_urls[:5]}...", file=sys.stderr)
        except Exception as e:
            print(f"[smart] Quick JS route discovery failed: {e}", file=sys.stderr)
            browser_seed_urls = []

    browser_task= asyncio.create_task(browser_fetch(
        base_url,
        "/tmp",
        no_browser,
        auth_session=auth_session,
        crawl=enable_browser_crawl,
        max_pages=crawl_limits["max_pages"],
        max_depth=crawl_limits["max_depth"],
        seed_urls=browser_seed_urls if browser_seed_urls else None,
    ))

    # Additional security checks
    if not public_only:
        cors_task = asyncio.create_task(check_cors(base_url))
        takeover_task = asyncio.create_task(check_subdomain_takeover(host))
        exposed_task = asyncio.create_task(check_exposed_files(base_url, quick_mode=quick_mode))
        # Delay nuclei start until discovery yields target URLs and auth context
        nuclei_task = None

        # Nmap strategy:
        # - quick: very light (top 33)
        # - smart: light (top 33)
        # - complete (deep/full/aggressive): top 1000 + scripts only if exploit_level aggressive
        # - standard: no nmap unless grpc_discovery is requested
        nmap_kwargs: dict[str, Any] | None = None
        if quick_mode:
            nmap_kwargs = {"quick_mode": True}
        elif smart_mode:
            nmap_kwargs = {"top_ports": 33, "scripts": False}
        elif complete_mode:
            nmap_kwargs = {"top_ports": 1000, "scripts": exploit_level == "aggressive"}
        elif grpc_discovery:
            nmap_kwargs = {"top_ports": 200, "scripts": False}

        if nmap_kwargs:
            nmap_full_task = asyncio.create_task(nmap_full_scan(host, **nmap_kwargs))
        else:
            async def dummy_nmap_full(): return {"open_ports": [], "services": [], "os_detection": {}, "vulnerabilities": [], "scan_completed": False, "skipped": True, "reason": "nmap_disabled_for_profile"}
            nmap_full_task = asyncio.create_task(dummy_nmap_full())
    else:
        # Create dummy tasks that return empty results for public-only mode
        async def dummy_cors(): return {"vulnerable": False, "issues": []}
        async def dummy_takeover(): return {"vulnerable": False, "cname": None, "issues": []}
        async def dummy_exposed(): return {"exposed_files": []}
        async def dummy_nuclei(): return {"vulnerabilities": [], "info": [], "scan_completed": False, "templates_used": 0}
        async def dummy_nmap_full(): return {"open_ports": [], "services": [], "os_detection": {}, "vulnerabilities": [], "scan_completed": False}
        cors_task = asyncio.create_task(dummy_cors())
        takeover_task = asyncio.create_task(dummy_takeover())
        exposed_task = asyncio.create_task(dummy_exposed())
        nuclei_task = asyncio.create_task(dummy_nuclei())
        nmap_full_task = asyncio.create_task(dummy_nmap_full())

    # Complete mode specific tasks
    if complete_mode and not public_only and not smart_mode:
        comprehensive_port_task = asyncio.create_task(comprehensive_port_scan(host, max_ports))
        deep_discovery_task = asyncio.create_task(deep_discovery_scan(base_url) if deep_discovery else asyncio.sleep(0))
    else:
        async def dummy_comprehensive(): return {"scan_type": "standard", "open_ports": [], "services": [], "vulnerabilities": [], "scan_completed": False}
        async def dummy_deep(): return {"directories": [], "files": [], "parameters": [], "scan_completed": False}
        comprehensive_port_task = asyncio.create_task(dummy_comprehensive())
        deep_discovery_task = asyncio.create_task(dummy_deep())

    # Advanced vuln tests are deferred until discovery is available
    advanced_vuln_task = None
    schemathesis_task = None
    schemathesis_schema_url: str | None = None

    # New advanced vulnerability checks (smart/full/aggressive only)
    advanced_scan = smart_mode or (complete_mode and complete_tier in ("full", "aggressive"))
    if advanced_scan and not public_only:
        nosql_task = asyncio.create_task(nosql_injection_test(base_url))
        ldap_task = asyncio.create_task(ldap_injection_test(base_url))
        xpath_task = asyncio.create_task(xpath_injection_test(base_url))
        ssti_task = asyncio.create_task(ssti_test(base_url))
        smuggling_task = asyncio.create_task(http_smuggling_test(base_url))
        jwt_task = asyncio.create_task(jwt_vulnerability_test(base_url))
        oauth_task = asyncio.create_task(oauth_vulnerability_test(base_url))
        session_task = asyncio.create_task(session_vulnerability_test(base_url))
        timing_task = asyncio.create_task(timing_attack_test(base_url))
        graphql_task = asyncio.create_task(graphql_vulnerability_test(base_url))
        cache_poison_task = asyncio.create_task(cache_poisoning_test(base_url))
        # Enhanced security tests (new)
        jwt_comprehensive_task = asyncio.create_task(jwt_comprehensive_test(base_url, None, auth_session))
        graphql_comprehensive_task = asyncio.create_task(graphql_comprehensive_test(base_url, None, auth_session))
        verb_tampering_task = asyncio.create_task(test_verb_tampering(base_url))
        rate_limit_task = asyncio.create_task(detect_rate_limits(base_url))
    else:
        # Create dummy tasks that return empty results for public-only mode
        async def dummy_nosql(): return {"vulnerable": False, "payloads_tested": [], "evidence": []}
        async def dummy_ldap(): return {"vulnerable": False, "payloads_tested": [], "evidence": []}
        async def dummy_xpath(): return {"vulnerable": False, "payloads_tested": [], "evidence": []}
        async def dummy_ssti(): return {"vulnerable": False, "payloads_tested": [], "evidence": []}
        async def dummy_smuggling(): return {"vulnerable": False, "technique": None, "evidence": []}
        async def dummy_jwt(): return {"vulnerable": False, "issues": [], "evidence": []}
        async def dummy_oauth(): return {"vulnerable": False, "issues": [], "evidence": []}
        async def dummy_session(): return {"vulnerable": False, "issues": [], "evidence": []}
        async def dummy_timing(): return {"vulnerable": False, "evidence": []}
        async def dummy_graphql(): return {"vulnerable": False, "issues": [], "evidence": []}
        async def dummy_cache_poison(): return {"vulnerable": False, "issues": [], "evidence": []}
        async def dummy_jwt_comprehensive(): return {"vulnerable": False, "algorithm_confusion": {}, "kid_injection": {}, "claim_manipulation": {}, "findings": []}
        async def dummy_graphql_comprehensive(): return {"vulnerable": False, "batch_attacks": {}, "depth_attacks": {}, "alias_idor": {}, "field_suggestions": {}, "findings": []}
        async def dummy_verb_tampering(): return {"vulnerable": False, "method_overrides": [], "findings": []}
        async def dummy_rate_limit(): return {"rate_limited": False, "headers": {}, "limits": {}, "findings": []}
        nosql_task = asyncio.create_task(dummy_nosql())
        ldap_task = asyncio.create_task(dummy_ldap())
        xpath_task = asyncio.create_task(dummy_xpath())
        ssti_task = asyncio.create_task(dummy_ssti())
        smuggling_task = asyncio.create_task(dummy_smuggling())
        jwt_task = asyncio.create_task(dummy_jwt())
        oauth_task = asyncio.create_task(dummy_oauth())
        session_task = asyncio.create_task(dummy_session())
        timing_task = asyncio.create_task(dummy_timing())
        graphql_task = asyncio.create_task(dummy_graphql())
        cache_poison_task = asyncio.create_task(dummy_cache_poison())
        jwt_comprehensive_task = asyncio.create_task(dummy_jwt_comprehensive())
        graphql_comprehensive_task = asyncio.create_task(dummy_graphql_comprehensive())
        verb_tampering_task = asyncio.create_task(dummy_verb_tampering())
        rate_limit_task = asyncio.create_task(dummy_rate_limit())

    # Enhanced security checks (will be run after headers are available)
    if not public_only:
        api_sec_task = asyncio.create_task(api_security_test(base_url))
        subdomain_takeover_task = asyncio.create_task(subdomain_takeover_check(host))
        xxe_task = asyncio.create_task(xxe_injection_test(base_url))
    else:
        # Create dummy tasks that return empty results for public-only mode
        async def dummy_api_sec(): return {"api_type": "unknown", "vulnerabilities": [], "endpoints_discovered": [], "authentication": {"required": False, "methods": []}}
        async def dummy_subdomain_takeover(): return {"vulnerable": False, "dangling_cnames": [], "vulnerable_services": [], "evidence": []}
        async def dummy_xxe(): return {"vulnerable": False, "payloads_tested": [], "evidence": []}
        api_sec_task = asyncio.create_task(dummy_api_sec())
        subdomain_takeover_task = asyncio.create_task(dummy_subdomain_takeover())
        xxe_task = asyncio.create_task(dummy_xxe())

    # Phase 1/2 Critical Checks - MOVED to after crawling completes (see below)
    # These checks need discovered_urls from katana crawling to be effective

    # Phase 3a Client-Side Security Checks (opt-in, disabled by default)
    # Note: js_deps_task is created AFTER browser_res is available to pass browser_versions
    # Placeholder task created here, real task created after browser_res is awaited
    js_deps_task = None  # Will be set after browser_res is available

    # Note: js_secrets_task is created AFTER crawl_urls is available (like js_deps_task)
    js_secrets_task = None  # Will be set after crawl_urls is available

    # Phase 3b Infrastructure & Configuration Leak Checks (opt-in, disabled by default)
    if cicd_exposure_testing and not public_only:
        cicd_task = asyncio.create_task(test_cicd_exposure(base_url, safe_mode=True))
    else:
        async def dummy_cicd(): return {"vulnerable": False, "exposed_files": [], "total_files_tested": 0}
        cicd_task = asyncio.create_task(dummy_cicd())

    if package_exposure_testing and not public_only:
        package_task = asyncio.create_task(test_package_exposure(base_url, safe_mode=True))
    else:
        async def dummy_package(): return {"vulnerable": False, "exposed_files": [], "total_files_tested": 0}
        package_task = asyncio.create_task(dummy_package())

    if cloud_bucket_testing and not public_only:
        cloud_bucket_task = asyncio.create_task(test_cloud_buckets(base_url, safe_mode=True))
    else:
        async def dummy_cloud_bucket(): return {"vulnerable": False, "public_buckets": [], "total_buckets_tested": 0}
        cloud_bucket_task = asyncio.create_task(dummy_cloud_bucket())

    if backup_file_testing and not public_only:
        backup_file_task = asyncio.create_task(test_backup_files(base_url, safe_mode=True))
    else:
        async def dummy_backup_file(): return {"vulnerable": False, "exposed_backups": [], "total_files_tested": 0}
        backup_file_task = asyncio.create_task(dummy_backup_file())

    # Phase 4 Checks - will be created AFTER crawling completes (see below)
    # These checks need discovered_urls from katana crawling to be effective

    # wait for tasks
    dns = await dns_task
    dmarc = await dmarc_task
    dnssec = await dnssec_task
    tlsx_data = await tlsx_task
    ocsp = await ocsp_task
    nmap_ = await nmap_task
    testssl_ = await testssl_task
    sslyze_ = await sslyze_task
    headers_main = await head_task
    http2 = await h2_task
    http3 = await h3_task
    sec_txt = await sec_txt_task

    emit_progress("baseline", 20, "dns/tls/http complete")

    # Virtual host enumeration (post-DNS, safe)
    if not public_only and dns.get("A"):
        vhost_task = asyncio.create_task(enumerate_virtual_hosts(base_url, host, dns.get("A")))
    else:
        async def dummy_vhost(): return {"hosts_tested": 0, "potential_vhosts": [], "baseline": {}}
        vhost_task = asyncio.create_task(dummy_vhost())

    httpx_meta = await httpx_task
    katana_result = await katana_task
    browser_fetch_error = None
    try:
        browser_res = await browser_task
    except Exception as e:
        browser_fetch_error = str(e)
        print(f"[scanner] Browser fetch failed: {e}, continuing without browser data", file=sys.stderr)
        # Set browser_res to None on error - downstream code checks `if browser_res` before using
        browser_res = None

    emit_progress("discovery", 30, "crawling and discovery")

    # HAR-First Discovery: Extract endpoints and parameters from browser network capture
    # This is the primary discovery source in smart mode
    har_discovery_result: HARDiscoveryResult | None = None
    if smart_mode and browser_res:
        captured_requests = browser_res.get("captured_requests", [])
        websocket_endpoints = browser_res.get("websocket_endpoints", [])
        if captured_requests:
            har_discovery_result = extract_discovery_from_har(
                captured_requests=captured_requests,
                websocket_endpoints=websocket_endpoints,
                base_url=base_url,
            )
            print(
                f"[scanner] HAR discovery: {len(har_discovery_result.endpoints)} endpoints, "
                f"{len(har_discovery_result.parameters)} parameters, "
                f"{har_discovery_result.api_requests} API calls",
                file=sys.stderr
            )
            # Track discovery coverage
            if coverage_tracker and har_discovery_result:
                coverage_tracker.record_discovery_source("har_network_capture")
                for endpoint in har_discovery_result.endpoints:
                    coverage_tracker.record_endpoint_discovered(endpoint.method)
                for param in har_discovery_result.parameters:
                    coverage_tracker.record_param_discovered(param.location)

    # Extract prioritized endpoints from HAR discovery for active testing
    har_test_targets: list[dict] = []
    if har_discovery_result and har_discovery_result.endpoints:
        har_test_targets = get_testable_endpoints(har_discovery_result, max_endpoints=50)
        if har_test_targets:
            print(f"[scanner] HAR discovery: {len(har_test_targets)} prioritized endpoints for active testing", file=sys.stderr)

    # Smart mode: Collect early tech detection hints for staged nuclei
    early_techs: list[str] = []
    if smart_mode:
        for item in httpx_meta:
            if isinstance(item, dict):
                for key in ["tech", "technologies", "webserver", "cdn"]:
                    val = item.get(key)
                    if val:
                        if isinstance(val, list):
                            early_techs.extend(val)
                        else:
                            early_techs.append(str(val))
        if browser_res:
            early_techs.extend(browser_res.get("tech_stack", []))
        early_techs = list(set(t for t in early_techs if t))

    # Handle smart_discovery returning dict vs katana returning list
    if isinstance(katana_result, dict):
        # smart_discovery result
        crawl_urls = katana_result.get("all_urls", [])
        smart_discovery_data = katana_result  # Store for later use
    else:
        # katana_crawl result (list)
        crawl_urls = katana_result
        smart_discovery_data = None

    if seed_entry_urls:
        existing_urls = set(crawl_urls)
        added_seeds = 0
        for seed_url in seed_entry_urls:
            if seed_url and seed_url not in existing_urls:
                crawl_urls.append(seed_url)
                existing_urls.add(seed_url)
                added_seeds += 1
        if added_seeds > 0:
            print(f"[scanner] Added {added_seeds} entry seed URLs to discovery pool (total: {len(crawl_urls)})", file=sys.stderr)

    # Merge API endpoints discovered via Playwright network capture into crawl_urls
    browser_api_endpoints = browser_res.get("api_endpoints", []) if browser_res else []
    if browser_api_endpoints:
        browser_api_endpoints = [
            ep for ep in browser_api_endpoints
            if is_in_scope_url(ep.get("url", ""), base_url)
        ]
    if browser_api_endpoints:
        existing_urls = set(crawl_urls)
        added_count = 0
        for endpoint in browser_api_endpoints:
            ep_url = endpoint.get("url", "")
            if ep_url and ep_url not in existing_urls:
                crawl_urls.append(ep_url)
                existing_urls.add(ep_url)
                added_count += 1
        if added_count > 0:
            print(f"[scanner] Added {added_count} browser-captured API endpoints to discovery pool (total: {len(crawl_urls)})", file=sys.stderr)

    browser_page_urls = browser_res.get("page_urls", []) if browser_res else []
    if browser_page_urls:
        browser_page_urls = [
            u for u in browser_page_urls
            if is_in_scope_url(u, base_url)
        ]
    if browser_page_urls:
        existing_urls = set(crawl_urls)
        added_pages = 0
        for page_url in browser_page_urls:
            if page_url and page_url not in existing_urls:
                crawl_urls.append(page_url)
                existing_urls.add(page_url)
                added_pages += 1
        if added_pages > 0:
            print(f"[scanner] Added {added_pages} browser-crawled pages to discovery pool (total: {len(crawl_urls)})", file=sys.stderr)

    # Add HAR-prioritized endpoints to crawl_urls for active testing
    if har_test_targets:
        existing_urls = set(crawl_urls)
        har_added = 0
        for target in har_test_targets:
            target_url = target.get("url", "")
            if target_url and target_url not in existing_urls:
                crawl_urls.append(target_url)
                existing_urls.add(target_url)
                har_added += 1
        if har_added > 0:
            print(f"[scanner] Added {har_added} HAR-prioritized endpoints to discovery pool (total: {len(crawl_urls)})", file=sys.stderr)

    manual_urls = [ep.get("url") for ep in manual_endpoints_norm if ep.get("url")] if manual_endpoints_norm else []
    if manual_urls:
        existing_urls = set(crawl_urls)
        added_manual = 0
        for ep_url in manual_urls:
            if ep_url and ep_url not in existing_urls:
                crawl_urls.append(ep_url)
                existing_urls.add(ep_url)
                added_manual += 1
        if added_manual > 0:
            print(f"[scanner] Added {added_manual} manual endpoints to discovery pool (total: {len(crawl_urls)})", file=sys.stderr)

    # Smart mode: Analyze JS bundles for hidden API endpoints
    # Skip if discovery already did JS parsing (smart/full/aggressive profiles have js_parsing=True)
    js_bundle_analysis = None
    discovery_config = smart_discovery_data.get("config", {}) if isinstance(smart_discovery_data, dict) else {}
    js_already_analyzed = discovery_config.get("js_parsing", False)
    if js_already_analyzed:
        js_bundle_analysis = smart_discovery_data.get("js_bundle_analysis") if smart_discovery_data else None
        if not js_bundle_analysis:
            js_bundle_analysis = {"source": "discovery_phase", "js_parsing_enabled": True}
    elif smart_mode:
        js_urls = [u for u in crawl_urls if u.endswith(".js") or ".js?" in u]
        if seed_js_urls:
            for js_url in seed_js_urls:
                if js_url and js_url not in js_urls:
                    js_urls.append(js_url)
        if js_urls:
            print(f"[scanner] Smart mode: Analyzing {len(js_urls)} JS bundles for hidden endpoints", file=sys.stderr)
            js_bundle_analysis = await analyze_js_bundles(base_url, js_urls)

            # Add discovered API endpoints to crawl pool
            if js_bundle_analysis.get("api_endpoints"):
                existing_urls = set(crawl_urls)
                added_from_js = 0
                for endpoint in js_bundle_analysis["api_endpoints"]:
                    # Convert relative paths to full URLs
                    if endpoint.startswith("/"):
                        full_url = f"{base_url.rstrip('/')}{endpoint}"
                    else:
                        full_url = endpoint
                    if full_url not in existing_urls:
                        crawl_urls.append(full_url)
                        existing_urls.add(full_url)
                        added_from_js += 1
                if added_from_js > 0:
                    print(f"[scanner] Added {added_from_js} hidden API endpoints from JS bundles", file=sys.stderr)

    json_link_results = None
    if json_link_following and not public_only:
        json_seed_limit = discovery_config.get("json_link_seed_limit", 60)
        json_total_limit = discovery_config.get("json_link_total_limit", 200)
        json_depth = discovery_config.get("json_link_depth", 2)

        json_seed_urls = list(crawl_urls)
        json_seed_urls.extend([e.get("url") if isinstance(e, dict) else e for e in browser_api_endpoints])
        json_seed_urls.extend(manual_urls)
        json_link_results = await follow_json_links(
            base_url=base_url,
            seed_urls=json_seed_urls,
            auth_session=auth_session,
            max_seeds=json_seed_limit,
            max_total=json_total_limit,
            max_depth=json_depth,
        )

        json_links = json_link_results.get("links", []) if json_link_results else []
        if json_links:
            existing_urls = set(crawl_urls)
            added_json_links = 0
            for link in json_links:
                if link and link not in existing_urls:
                    crawl_urls.append(link)
                    existing_urls.add(link)
                    added_json_links += 1
            if added_json_links > 0:
                print(f"[scanner] Added {added_json_links} JSON-linked endpoints to discovery pool", file=sys.stderr)
            if smart_discovery_data and isinstance(smart_discovery_data, dict):
                api_list = smart_discovery_data.get("api_endpoints", []) or []
                all_list = smart_discovery_data.get("all_urls", []) or []
                smart_discovery_data["api_endpoints"] = list(set(api_list + json_links))
                smart_discovery_data["all_urls"] = list(set(all_list + json_links))

    if crawl_urls and (focus_rules or avoid_rules):
        crawl_urls, discovered_scope = apply_scope_rules_to_urls(
            crawl_urls,
            focus_rules=focus_rules,
            avoid_rules=avoid_rules,
        )
        scope_stats["discovered_urls_dropped"] = discovered_scope["dropped"]
        print(
            f"[scope] Discovered URLs kept={discovered_scope['kept']} dropped={discovered_scope['dropped']}",
            file=sys.stderr,
        )

    options_method_results = None
    if options_method_discovery and not public_only:
        options_limit = discovery_config.get("options_method_limit", 150)
        options_method_results = await discover_allowed_methods(
            base_url=base_url,
            urls=crawl_urls,
            auth_session=auth_session,
            max_urls=options_limit,
        )

    # Deferred advanced vulnerability tests (full/aggressive only, requires parameterized endpoints)
    if advanced_vuln_task is None:
        def _build_adv_candidates() -> list[dict[str, Any]]:
            ssrf_params = {
                "url", "uri", "path", "dest", "destination", "redirect", "next",
                "callback", "return", "continue", "image", "file", "host", "domain", "link", "ref", "target",
            }
            cmd_params = {
                "cmd", "exec", "command", "shell", "ping", "host", "ip", "query",
            }
            candidates: list[dict[str, Any]] = []
            seen_keys: set[tuple[str, str, str]] = set()

            def _add_candidate(url: str, param: str, kind: str) -> None:
                key = (url, param, kind)
                if key in seen_keys:
                    return
                seen_keys.add(key)
                candidates.append({"url": url, "param": param, "type": kind})

            def _url_with_params(url: str, params: list[str]) -> str:
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.urlencode({p: "test" for p in params})
                return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", query, ""))

            def _consume_url(url: str, params_override: list[str] | None = None) -> None:
                if not url:
                    return
                if params_override is None:
                    parsed = urllib.parse.urlparse(url)
                    params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
                else:
                    params = params_override
                    url = _url_with_params(url, params)
                for param in params:
                    param_lower = param.lower()
                    if param_lower in ssrf_params:
                        _add_candidate(url, param, "ssrf")
                    if param_lower in cmd_params:
                        _add_candidate(url, param, "cmd")

            # Use real discovered URLs with params
            for url in crawl_urls:
                if "?" in url:
                    _consume_url(url)

            # Manual endpoints (GET only)
            for ep in manual_endpoints_norm or []:
                if ep.get("method", "GET").upper() != "GET":
                    continue
                params = ep.get("params") or []
                if params:
                    _consume_url(ep.get("url", ""), params_override=params)

            # Smart discovery inferred params (if available)
            if smart_discovery_data and isinstance(smart_discovery_data, dict):
                for entry in smart_discovery_data.get("endpoints_with_params", []) or []:
                    if isinstance(entry, dict):
                        url = entry.get("url")
                        params = entry.get("params") or []
                        if url and params:
                            _consume_url(url, params_override=params[:5])

            return candidates[:40]  # Cap candidates to avoid excessive probing

        run_adv = (
            complete_mode and not public_only and not smart_mode
            and complete_tier in ("full", "aggressive")
            and exploit_level != "safe"
        )
        if run_adv:
            adv_candidates = _build_adv_candidates()
            if adv_candidates:
                advanced_vuln_task = asyncio.create_task(
                    advanced_vuln_tests(
                        base_url,
                        exploit_level=exploit_level,
                        candidates=adv_candidates,
                        auth_session=auth_session,
                    )
                )
            else:
                async def dummy_advanced(): return {"ssrf": {"tested": False}, "xxe": {"tested": False}, "command_injection": {"tested": False}, "scan_completed": False, "skipped": True, "reason": "no_parameterized_endpoints"}
                advanced_vuln_task = asyncio.create_task(dummy_advanced())
        else:
            async def dummy_advanced(): return {"ssrf": {"tested": False}, "xxe": {"tested": False}, "command_injection": {"tested": False}, "scan_completed": False, "skipped": True, "reason": "profile_not_enabled"}
            advanced_vuln_task = asyncio.create_task(dummy_advanced())

    # Record discovery coverage
    if coverage_tracker:
        # Record discovered endpoints
        for url in crawl_urls:
            coverage_tracker.record_endpoint_discovered("GET")
        # Record browser-captured endpoints (may have POST/PUT methods)
        for ep in browser_api_endpoints:
            if isinstance(ep, dict):
                coverage_tracker.record_endpoint_discovered(ep.get("method", "GET"))
        # Record discovery sources
        if crawl_urls:
            coverage_tracker.record_discovery_source("url_crawl")
        if browser_api_endpoints:
            coverage_tracker.record_discovery_source("browser_api_capture")
        if manual_endpoints_norm:
            coverage_tracker.record_discovery_source("manual_endpoints")
        if js_bundle_analysis and js_bundle_analysis.get("api_endpoints"):
            coverage_tracker.record_discovery_source("js_bundle_analysis")
        if json_link_results and json_link_results.get("links"):
            coverage_tracker.record_discovery_source("json_link_following")
        if options_method_results:
            coverage_tracker.record_discovery_source("options_method_discovery")
        # Record auth state
        if auth_session:
            coverage_tracker.record_auth_state("user1")
        else:
            coverage_tracker.record_auth_state("anonymous")
        if user2_session:
            coverage_tracker.record_auth_state("user2")

    # Start nuclei once discovery has populated targets and auth is ready
    if nuclei_task is None and not public_only:
        nuclei_target_limits = {
            "quick": 120,
            "standard": 400,
            "deep": 800,
            "full": 1200,
            "aggressive": 1800,
            "smart": 1000,
        }
        nuclei_target_limit = int(scan_budget.get("nuclei_max_targets") or nuclei_target_limits.get(discovery_scan_type, 400))

        if auth_session:
            await auth_session.refresh_if_needed()

        if smart_mode:
            print(
                f"[scanner] Smart mode: Starting staged nuclei with {len(early_techs)} detected technologies"
                f"{' (early stopping disabled)' if no_early_stop else ''}",
                file=sys.stderr,
            )
            nuclei_task = asyncio.create_task(staged_nuclei_scan(
                base_url,
                detected_tech=early_techs,
                early_stopping=bool(scan_budget.get("nuclei_early_stop", True)) and not no_early_stop,
                targets=crawl_urls,
                auth_session=auth_session,
                max_targets=nuclei_target_limit,
            ))
        elif complete_mode:
            nuclei_task = asyncio.create_task(nuclei_comprehensive_scan(
                base_url,
                rate_limit=5,
                timeout_per_request=15,
                scan_tier=complete_tier,
                targets=crawl_urls,
                auth_session=auth_session,
                max_targets=nuclei_target_limit,
            ))
        else:
            nuclei_task = asyncio.create_task(nuclei_scan(
                base_url,
                quick_mode=quick_mode,
                targets=crawl_urls,
                auth_session=auth_session,
                max_targets=nuclei_target_limit,
            ))

    # WebSocket endpoint discovery and testing
    browser_ws_endpoints = browser_res.get("websocket_endpoints", []) if browser_res else []
    if websocket_testing and not public_only:
        # Probe for additional WebSocket endpoints
        probed_ws_endpoints = await probe_websocket_endpoints(base_url)
        all_ws_endpoints = list(set(browser_ws_endpoints + probed_ws_endpoints))
        if all_ws_endpoints:
            print(f"[scanner] Found {len(all_ws_endpoints)} WebSocket endpoints for testing", file=sys.stderr)
        ws_task = asyncio.create_task(run_websocket_security_tests(all_ws_endpoints, safe_mode=True))
    else:
        all_ws_endpoints = browser_ws_endpoints
        async def dummy_ws(): return {"endpoints_tested": 0, "vulnerabilities": [], "endpoints": []}
        ws_task = asyncio.create_task(dummy_ws())

    cors_results = await cors_task
    takeover_results = await takeover_task
    exposed_results = await exposed_task
    nuclei_results = await nuclei_task
    nmap_full_results = await nmap_full_task

    grpc_results = None
    if grpc_discovery and not public_only:
        grpc_ports = set()
        common_grpc_ports = {50051, 50052, 50053, 6565, 7000, 7001, 8085}
        for entry in nmap_full_results.get("open_ports", []) or []:
            port = entry.get("port")
            service = str(entry.get("service", "")).lower()
            if isinstance(port, int) and (port in common_grpc_ports or "grpc" in service):
                grpc_ports.add(port)
        for entry in nmap_full_results.get("services", []) or []:
            port = entry.get("port")
            name = str(entry.get("name", "")).lower()
            product = str(entry.get("product", "")).lower()
            extra = str(entry.get("extrainfo", "")).lower()
            if isinstance(port, int) and ("grpc" in name or "grpc" in product or "grpc" in extra):
                grpc_ports.add(port)

        # If comprehensive port scan already completed, include those ports as candidates
        try:
            if comprehensive_port_task and comprehensive_port_task.done():
                comp_res = comprehensive_port_task.result()
                for entry in comp_res.get("open_ports", []) or []:
                    port = entry.get("port")
                    if isinstance(port, int):
                        grpc_ports.add(port)
        except Exception:
            pass

        if grpc_ports:
            grpc_results = await grpc_reflection_discovery(host, sorted(grpc_ports))
        else:
            grpc_results = {
                "available": True,
                "reflection_supported": False,
                "targets": [],
                "services": [],
                "methods": [],
                "errors": ["no grpc port candidates"],
            }

    # Extract signals from nuclei for smart mode phase coordination
    nuclei_signals = extract_signals_from_nuclei(nuclei_results) if smart_mode else {}

    # Adaptive smart discovery refinement using nuclei signals (post-nuclei)
    # Skip when SPA catch-all detected — recursive fuzzing on SPA sites produces false paths
    if smart_mode and smart_discovery_data and nuclei_signals and not smart_discovery_data.get("spa_catch_all"):
        try:
            signals_used = smart_discovery_data.get("signals_used")
            if not signals_used:
                # Build directories from existing discovery results
                all_urls = smart_discovery_data.get("all_urls", []) or []
                api_endpoints = smart_discovery_data.get("api_endpoints", []) or []
                directories = [u for u in all_urls if u.endswith("/")]

                api_bases = set()
                for endpoint in api_endpoints:
                    parsed = urllib.parse.urlparse(endpoint)
                    path_parts = parsed.path.split("/")
                    if len(path_parts) >= 2:
                        api_base = "/".join(path_parts[:3]) + "/"
                        if api_base != "/":
                            api_bases.add(api_base)

                directories.extend(list(api_bases))
                if not directories:
                    directories = [
                        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
                        "/v1/", "/v2/", "/v3/", "/rest/", "/rest/v1/", "/rest/v2/",
                    ]
                directories = list(set(directories))

                adaptive_depth, adaptive_paths = calculate_adaptive_depth(nuclei_signals, base_depth=3)
                refined = await recursive_directory_discovery(
                    base_url,
                    directories,
                    signals=nuclei_signals,
                    max_depth=adaptive_depth,
                    max_paths_per_level=adaptive_paths,
                )

                new_paths = refined.get("paths", []) or []
                added_urls = 0
                if new_paths:
                    new_urls = [urllib.parse.urljoin(base_url, p) for p in new_paths]
                    existing_urls = set(all_urls)
                    # Cap additions to avoid runaway growth
                    config = smart_discovery_data.get("config", {}) or {}
                    max_urls = config.get("max_urls", 1000)
                    remaining = max(0, max_urls - len(all_urls))
                    new_urls = [u for u in new_urls if u not in existing_urls]
                    if remaining:
                        new_urls = new_urls[:remaining]
                    else:
                        new_urls = []

                    if new_urls:
                        added_urls = len(new_urls)
                        all_urls = list(set(all_urls + new_urls))
                        smart_discovery_data["all_urls"] = all_urls
                        existing_recursive = smart_discovery_data.get("recursive_paths", []) or []
                        smart_discovery_data["recursive_paths"] = list(set(existing_recursive + new_urls))
                        # Add to crawl pool for later active testing
                        crawl_set = set(crawl_urls)
                        for u in new_urls:
                            if u not in crawl_set:
                                crawl_urls.append(u)
                                crawl_set.add(u)

                smart_discovery_data["signals_used"] = (
                    nuclei_signals.to_dict() if hasattr(nuclei_signals, "to_dict") else nuclei_signals
                )
                stats = smart_discovery_data.get("stats", {}) or {}
                stats["adaptive_refinement"] = {
                    "added_urls": added_urls,
                    "adaptive_depth": adaptive_depth,
                    "paths_per_level": adaptive_paths,
                }
                smart_discovery_data["stats"] = stats
        except Exception as e:
            print(f"[smart] Adaptive discovery refinement failed: {e}", file=sys.stderr)

    if coverage_tracker and isinstance(nuclei_results, dict):
        templates_run = 0
        templates_matched = 0
        stats = nuclei_results.get("statistics")
        if isinstance(stats, dict):
            templates_run = stats.get("templates_executed") or stats.get("templates_loaded") or 0
        if not templates_run:
            templates_run = nuclei_results.get("templates_executed") or nuclei_results.get("templates_used") or 0
        templates_matched = nuclei_results.get("templates_matched", 0) or 0
        if not templates_matched:
            vulns = nuclei_results.get("vulnerabilities")
            if isinstance(vulns, dict):
                templates_matched += sum(len(v) for v in vulns.values() if isinstance(v, list))
            elif isinstance(vulns, list):
                templates_matched += len(vulns)
            info = nuclei_results.get("info")
            if isinstance(info, list):
                templates_matched += len(info)
        if templates_run == 0 and templates_matched:
            templates_run = templates_matched
        if templates_run or templates_matched:
            coverage_tracker.record_templates(run=templates_run, matched=templates_matched)

    # Await new vulnerability tests
    nosql_results = await nosql_task
    ldap_results = await ldap_task
    xpath_results = await xpath_task
    ssti_results = await ssti_task
    smuggling_results = await smuggling_task
    jwt_results = await jwt_task
    oauth_results = await oauth_task
    session_results = await session_task
    timing_results = await timing_task
    graphql_results = await graphql_task
    cache_poison_results = await cache_poison_task
    # Enhanced security tests (new)
    jwt_comprehensive_results = await jwt_comprehensive_task
    graphql_comprehensive_results = await graphql_comprehensive_task
    verb_tampering_results = await verb_tampering_task
    rate_limit_results = await rate_limit_task

    # Await enhanced security tests
    api_sec_results = await api_sec_task
    subdomain_takeover_results = await subdomain_takeover_task
    xxe_results = await xxe_task
    ws_results = await ws_task
    vhost_results = await vhost_task

    # Phase 1 Critical Checks - Create tasks NOW with discovered URLs from crawling
    if csrf_testing and not public_only:
        csrf_task = asyncio.create_task(test_csrf(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
    else:
        async def dummy_csrf(): return {"vulnerable": False, "forms_without_tokens": [], "tested_forms": 0}
        csrf_task = asyncio.create_task(dummy_csrf())

    if idor_testing and not public_only:
        idor_task = asyncio.create_task(test_idor_bola(crawl_urls, base_url=base_url, auth_session=auth_session))
    else:
        async def dummy_idor(): return {"vulnerable": False, "vulnerable_endpoints": [], "tested_endpoints": 0}
        idor_task = asyncio.create_task(dummy_idor())

    if path_traversal_testing and not public_only:
        path_traversal_task = asyncio.create_task(test_path_traversal(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
    else:
        async def dummy_path_traversal(): return {"vulnerable": False, "vulnerable_parameters": [], "payloads_tested": 0}
        path_traversal_task = asyncio.create_task(dummy_path_traversal())

    if default_creds_testing and not public_only:
        # Use aggressive credential checker for full/aggressive scans
        if exploit_level in ("aggressive", "moderate"):
            # Note: all_techs computed later; pass empty list for now (generic credential testing)
            default_creds_task = asyncio.create_task(test_default_credentials_aggressive(
                base_url,
                detected_tech=[],
                max_attempts=20 if exploit_level == "aggressive" else 10,
                delay_ms=300 if exploit_level == "aggressive" else 500
            ))
        else:
            default_creds_task = asyncio.create_task(test_default_credentials(base_url, login_endpoints=crawl_urls, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_default_creds(): return {"vulnerable": False, "vulnerable_endpoints": [], "tested_endpoints": 0}
        default_creds_task = asyncio.create_task(dummy_default_creds())

    if deserialization_testing and not public_only:
        deserialization_task = asyncio.create_task(test_deserialization(base_url, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_deserialization(): return {"vulnerable": False, "vulnerable_endpoints": [], "tested_types": 0}
        deserialization_task = asyncio.create_task(dummy_deserialization())

    # Phase 2 Access Control & Auth Checks
    if rate_limiting_testing and not public_only:
        rate_limiting_task = asyncio.create_task(test_rate_limiting(base_url, requests_per_second=20, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_rate_limiting(): return {"vulnerable": False, "vulnerable_endpoints": [], "tested_endpoints": 0}
        rate_limiting_task = asyncio.create_task(dummy_rate_limiting())

    if twofa_bypass_testing and not public_only:
        twofa_bypass_task = asyncio.create_task(test_2fa_bypass(base_url, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_twofa_bypass(): return {"vulnerable": False, "bypass_methods_detected": [], "tested_methods": 0}
        twofa_bypass_task = asyncio.create_task(dummy_twofa_bypass())

    if password_reset_testing and not public_only:
        password_reset_task = asyncio.create_task(test_password_reset(base_url, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_password_reset(): return {"vulnerable": False, "vulnerabilities_found": [], "tested_checks": 0}
        password_reset_task = asyncio.create_task(dummy_password_reset())

    if session_mgmt_testing and not public_only:
        session_mgmt_task = asyncio.create_task(test_session_management(base_url, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_session_mgmt(): return {"vulnerable": False, "issues_found": [], "tested_checks": 0}
        session_mgmt_task = asyncio.create_task(dummy_session_mgmt())

    # Additional auth policy checks (lightweight)
    if rate_limiting_testing and not public_only:
        password_policy_task = asyncio.create_task(test_password_policy(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
        account_enum_task = asyncio.create_task(test_account_enumeration(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
        bruteforce_task = asyncio.create_task(test_bruteforce_protection(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
        http_methods_task = asyncio.create_task(test_http_methods(base_url, discovered_urls=crawl_urls, auth_session=auth_session))
    else:
        async def dummy_password_policy(): return {"vulnerable": False, "issues": [], "tested_endpoints": 0}
        async def dummy_account_enum(): return {"vulnerable": False, "issues": [], "tested_endpoints": 0}
        async def dummy_bruteforce(): return {"vulnerable": False, "issues": [], "protections_detected": [], "tested_endpoints": 0}
        async def dummy_http_methods(): return {"vulnerable": False, "allowed_methods": [], "risky_methods": [], "trace_enabled": False}
        password_policy_task = asyncio.create_task(dummy_password_policy())
        account_enum_task = asyncio.create_task(dummy_account_enum())
        bruteforce_task = asyncio.create_task(dummy_bruteforce())
        http_methods_task = asyncio.create_task(dummy_http_methods())

    # Await Phase 1/2 Critical Checks (run in parallel with Phase 3/4)
    csrf_results = await csrf_task
    idor_results = await idor_task
    path_traversal_results = await path_traversal_task
    default_creds_results = await default_creds_task
    deserialization_results = await deserialization_task
    rate_limiting_results = await rate_limiting_task
    twofa_bypass_results = await twofa_bypass_task
    password_reset_results = await password_reset_task
    session_mgmt_results = await session_mgmt_task
    password_policy_results = await password_policy_task
    account_enum_results = await account_enum_task
    bruteforce_results = await bruteforce_task
    http_methods_results = await http_methods_task

    emit_progress("phase_1_2", 55, "critical and auth checks complete")

    # Phase 3a Client-Side Security Checks - Create js_deps_task NOW with browser versions
    # (Moved here so we have access to browser_res.get("browser_versions"))
    # Determine headers early for response_headers parameter
    early_headers = browser_res.get("headers", {}) if browser_res and browser_res.get("headers") else headers_main.get("headers", {})
    if js_dependency_scanning and not public_only:
        browser_versions = browser_res.get("browser_versions", {}) if browser_res else {}
        js_deps_task = asyncio.create_task(test_js_dependencies(
            base_url,
            discovered_urls=crawl_urls,
            safe_mode=True,
            browser_versions=browser_versions,
            response_headers=early_headers,
        ))
    else:
        async def dummy_js_deps(): return {"vulnerable": False, "vulnerable_libraries": [], "libraries_scanned": 0, "total_js_files": 0, "framework_detection": {}}
        js_deps_task = asyncio.create_task(dummy_js_deps())

    # Create js_secrets_task now that crawl_urls is available
    if js_secret_scanning and not public_only:
        js_secrets_task = asyncio.create_task(test_js_secrets(base_url, discovered_urls=crawl_urls, safe_mode=True))
    else:
        async def dummy_js_secrets(): return {"vulnerable": False, "secrets_found": [], "files_scanned": 0}
        js_secrets_task = asyncio.create_task(dummy_js_secrets())

    # Additional client-side heuristics (postMessage/prototype pollution)
    if (js_dependency_scanning or js_secret_scanning) and not public_only:
        client_side_task = asyncio.create_task(test_client_side_vulns(base_url, discovered_urls=crawl_urls, safe_mode=True))
    else:
        async def dummy_client_side(): return {"vulnerable": False, "findings": [], "files_scanned": 0}
        client_side_task = asyncio.create_task(dummy_client_side())

    # Directory listing exposure (uses discovered URLs)
    if backup_file_testing and not public_only:
        directory_listing_task = asyncio.create_task(test_directory_listing(base_url, discovered_urls=crawl_urls, safe_mode=True))
    else:
        async def dummy_directory_listing(): return {"vulnerable": False, "exposed_directories": [], "directories_tested": 0}
        directory_listing_task = asyncio.create_task(dummy_directory_listing())

    # Await Phase 3a Client-Side Security Checks
    js_deps_results = await js_deps_task
    js_secrets_results = await js_secrets_task
    client_side_results = await client_side_task
    directory_listing_results = await directory_listing_task

    # Await Phase 3b Infrastructure & Configuration Leak Checks
    cicd_results = await cicd_task
    package_results = await package_task
    cloud_bucket_results = await cloud_bucket_task
    backup_file_results = await backup_file_task

    emit_progress("phase_3", 70, "client and infrastructure checks complete")

    # Phase 4 Checks (P1 Priority) - Run AFTER crawling so discovered_urls is available
    # This ensures Phase 4 checks can scan all discovered forms, endpoints, and URLs
    emit_progress("phase_4", 72, "starting phase 4 checks")
    forced_browsing_max_seconds = None
    if smart_mode:
        try:
            forced_browsing_max_seconds = int(os.environ.get("SCAN_FORCED_BROWSING_MAX_SECONDS", "90"))
        except Exception:
            forced_browsing_max_seconds = 90

    if file_upload_testing and not public_only:
        file_upload_task = asyncio.create_task(test_file_upload(base_url, discovered_urls=crawl_urls, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_file_upload(): return {"vulnerable": False, "upload_endpoints": [], "tested_endpoints": 0}
        file_upload_task = asyncio.create_task(dummy_file_upload())

    if open_redirect_testing and not public_only:
        open_redirect_task = asyncio.create_task(test_open_redirect(base_url, discovered_urls=crawl_urls, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_open_redirect(): return {"vulnerable": False, "redirect_params_found": [], "confirmed_redirects": []}
        open_redirect_task = asyncio.create_task(dummy_open_redirect())

    if host_header_testing and not public_only:
        host_header_task = asyncio.create_task(test_host_header_injection(base_url, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_host_header(): return {"vulnerable": False, "header_reflection": [], "password_reset_endpoints": []}
        host_header_task = asyncio.create_task(dummy_host_header())

    if business_logic_testing and not public_only:
        business_logic_task = asyncio.create_task(test_business_logic(base_url, discovered_urls=crawl_urls, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_business_logic(): return {"potential_issues": [], "price_fields": [], "quantity_fields": []}
        business_logic_task = asyncio.create_task(dummy_business_logic())

    if api_security_testing and not public_only:
        api_security_p4_task = asyncio.create_task(test_api_security(base_url, discovered_urls=crawl_urls, auth_session=auth_session, safe_mode=True))
    else:
        async def dummy_api_security_p4(): return {"vulnerable": False, "mass_assignment_risks": [], "bfla_endpoints": []}
        api_security_p4_task = asyncio.create_task(dummy_api_security_p4())

    # Access Control Checks - Forced Browsing (can run in parallel with Phase 4)
    if forced_browsing_testing and not public_only:
        forced_browsing_task = asyncio.create_task(check_forced_browsing(
            base_url,
            max_concurrent=10,
            max_total_time=forced_browsing_max_seconds,
        ))
    else:
        async def dummy_forced_browsing(): return {"vulnerable": False, "findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "info": 0}, "paths_tested": 0}
        forced_browsing_task = asyncio.create_task(dummy_forced_browsing())

    # Mass Assignment Check (requires auth for best results)
    if mass_assignment_testing and not public_only:
        from scanner_tools.access_control_checks import check_mass_assignment
        mass_assignment_task = asyncio.create_task(check_mass_assignment(base_url, auth_session=auth_session))
    else:
        async def dummy_mass_assignment(): return {"vulnerable": False, "findings": [], "endpoints_tested": 0, "parameters_tested": 0}
        mass_assignment_task = asyncio.create_task(dummy_mass_assignment())

    # BOLA/IDOR Check (requires auth for best results, user2_session enables true multi-user comparison)
    if bola_testing and not public_only:
        from scanner_tools.access_control_checks import check_bola
        bola_task = asyncio.create_task(check_bola(base_url, user1_session=auth_session, user2_session=user2_session))
    else:
        async def dummy_bola(): return {"vulnerable": False, "findings": [], "endpoints_tested": 0, "access_violations": 0}
        bola_task = asyncio.create_task(dummy_bola())

    # Race Condition Testing (smart/full/aggressive only)
    if advanced_scan and not public_only:
        # Identify race-prone endpoints from discovered endpoints
        race_endpoints = []
        if har_discovery_result and har_discovery_result.endpoints:
            def _race_endpoint_from_har(ep: Any) -> dict[str, Any]:
                if isinstance(ep, dict):
                    url = ep.get("url", "")
                    method = ep.get("method", "GET")
                    query_params = ep.get("query_params") or {}
                    body_params = ep.get("body_params") or {}
                else:
                    url = getattr(ep, "url", "")
                    method = getattr(ep, "method", "GET")
                    query_params = getattr(ep, "query_params", {}) or {}
                    body_params = getattr(ep, "body_params", {}) or {}

                params: list[dict[str, str]] = []
                if isinstance(query_params, dict):
                    params.extend({"name": k} for k in query_params.keys())
                elif isinstance(query_params, list):
                    params.extend({"name": k} for k in query_params if isinstance(k, str))

                if isinstance(body_params, dict):
                    params.extend({"name": k} for k in body_params.keys())
                elif isinstance(body_params, list):
                    if body_params and isinstance(body_params[0], dict):
                        params.extend({"name": k} for k in body_params[0].keys())
                    elif body_params and all(isinstance(item, str) for item in body_params):
                        params.extend({"name": k} for k in body_params)

                return {"url": url, "method": method, "params": params}

            race_endpoints = identify_race_prone_endpoints(
                [_race_endpoint_from_har(ep) for ep in har_discovery_result.endpoints]
            )
        race_condition_task = asyncio.create_task(
            run_race_condition_tests(race_endpoints, auth_session=auth_session, concurrent_requests=10)
        )
    else:
        async def dummy_race(): return {"tested_endpoints": 0, "vulnerable_endpoints": 0, "findings": [], "results": []}
        race_condition_task = asyncio.create_task(dummy_race())

    # SSH checks
    if ssh_testing and not public_only:
        ssh_task = asyncio.create_task(ssh_auth_methods(host, ssh_port))
    else:
        async def dummy_ssh(): return {"password_auth_enabled": False, "auth_methods": [], "findings": [], "scan_completed": False}
        ssh_task = asyncio.create_task(dummy_ssh())

    # Phase 4 watchdog for smart scans (prevents hangs from non-cancellable awaits)
    phase4_deadline = None
    if smart_mode:
        try:
            phase4_max_seconds = int(os.environ.get("SCAN_PHASE4_MAX_SECONDS", "360"))
        except Exception:
            phase4_max_seconds = 360
        phase4_max_seconds = max(30, phase4_max_seconds)
        phase4_deadline = time.monotonic() + phase4_max_seconds
        print(f"[phase_4] Enforcing max duration {phase4_max_seconds}s for smart scan", file=sys.stderr, flush=True)
    phase4_trace = os.environ.get("SCAN_PHASE4_TRACE")
    phase4_logs_env = os.environ.get("SCAN_PHASE4_LOGS")
    if phase4_logs_env is None:
        phase4_logs = bool(smart_mode)
    else:
        phase4_logs = phase4_logs_env.strip().lower() in ("1", "true", "yes", "on")
    try:
        phase4_cancel_grace = float(os.environ.get("SCAN_PHASE4_CANCEL_GRACE", "1"))
    except Exception:
        phase4_cancel_grace = 1.0
    if phase4_cancel_grace < 0:
        phase4_cancel_grace = 0.0

    def _phase4_log(event: str, **fields: Any) -> None:
        if not phase4_logs:
            return
        parts = [f"[phase_4] event={event}"]
        for key, value in fields.items():
            if value is None:
                continue
            text = str(value)
            if " " in text:
                text = text.replace(" ", "_")
            parts.append(f"{key}={text}")
        print(" ".join(parts), file=sys.stderr, flush=True)

    _phase4_log(
        "start",
        smart=int(bool(smart_mode)),
        public=int(bool(public_only)),
        deadline=f"{phase4_max_seconds}s" if phase4_deadline else "none",
    )

    def _phase4_timeout(requested: int, name: str) -> int:
        if phase4_deadline is None:
            return requested
        remaining = phase4_deadline - time.monotonic()
        if remaining <= 0:
            print(f"[phase_4] Deadline exceeded; skipping {name}", file=sys.stderr)
            return 0
        return int(min(requested, remaining))

    def _attach_task_suppressor(task: asyncio.Task, name: str) -> None:
        def _done_callback(t: asyncio.Task) -> None:
            try:
                exc = t.exception()
                if exc:
                    print(f"[{name}] Task error after timeout: {exc}", file=sys.stderr)
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        try:
            task.add_done_callback(_done_callback)
        except Exception:
            pass

    def _cancel_task(task: asyncio.Task | None, name: str) -> None:
        if task is None or task.done():
            return
        try:
            task.cancel()
        except Exception:
            pass
        _attach_task_suppressor(task, name)

    async def _drain_task(task: asyncio.Task | None, name: str) -> None:
        if task is None or task.done() or phase4_cancel_grace <= 0:
            return
        try:
            await asyncio.wait_for(task, timeout=phase4_cancel_grace)
        except asyncio.CancelledError:
            pass
        except asyncio.TimeoutError:
            _phase4_log("cancel_grace_timeout", task=name, grace=f"{phase4_cancel_grace:.1f}s")
        except Exception as e:
            print(f"[{name}] Cancel cleanup error: {e}", file=sys.stderr)

    # Helper for timeout with default
    async def await_with_timeout(task, timeout_sec, default, name):
        if timeout_sec <= 0:
            _phase4_log("skip", task=name, reason="deadline")
            print(f"[{name}] Skipped (deadline exceeded), using defaults", file=sys.stderr)
            _cancel_task(task, name)
            await _drain_task(task, name)
            return default
        start_ts = time.monotonic()
        try:
            _phase4_log("await", task=name, timeout=f"{timeout_sec}s")
            done, pending = await asyncio.wait({task}, timeout=timeout_sec)
            if task in done:
                try:
                    result = task.result()
                    if phase4_trace:
                        elapsed = time.monotonic() - start_ts
                        print(f"[phase_4] {name} completed in {elapsed:.2f}s", file=sys.stderr)
                    else:
                        elapsed = time.monotonic() - start_ts
                        _phase4_log("done", task=name, elapsed=f"{elapsed:.2f}s")
                    return result
                except asyncio.CancelledError:
                    elapsed = time.monotonic() - start_ts
                    _phase4_log("cancelled", task=name, elapsed=f"{elapsed:.2f}s")
                    print(f"[{name}] Cancelled, using defaults", file=sys.stderr)
                except Exception as e:
                    elapsed = time.monotonic() - start_ts
                    _phase4_log("error", task=name, elapsed=f"{elapsed:.2f}s", err=type(e).__name__)
                    print(f"[{name}] Failed: {e}, using defaults", file=sys.stderr)
                if phase4_trace:
                    elapsed = time.monotonic() - start_ts
                    print(f"[phase_4] {name} error after {elapsed:.2f}s", file=sys.stderr)
                return default
            if phase4_trace:
                elapsed = time.monotonic() - start_ts
                print(f"[phase_4] {name} timed out after {elapsed:.2f}s (limit {timeout_sec}s)", file=sys.stderr)
            else:
                elapsed = time.monotonic() - start_ts
                _phase4_log("timeout", task=name, elapsed=f"{elapsed:.2f}s", timeout=f"{timeout_sec}s")
                print(f"[{name}] Timed out after {timeout_sec}s, using defaults", file=sys.stderr)
            _cancel_task(task, name)
            await _drain_task(task, name)
            return default
        except Exception as e:
            elapsed = time.monotonic() - start_ts
            _phase4_log("error", task=name, elapsed=f"{elapsed:.2f}s", err=type(e).__name__)
            print(f"[{name}] Timeout handler error: {e}, using defaults", file=sys.stderr)
            _cancel_task(task, name)
            await _drain_task(task, name)
            return default

    # Await Phase 4 Checks with timeouts
    file_upload_results = await await_with_timeout(file_upload_task, _phase4_timeout(90, "file_upload"), {"vulnerable": False, "upload_endpoints": [], "tested_endpoints": 0}, "file_upload")
    open_redirect_results = await await_with_timeout(open_redirect_task, _phase4_timeout(60, "open_redirect"), {"vulnerable": False, "redirect_params_found": [], "confirmed_redirects": []}, "open_redirect")
    host_header_results = await await_with_timeout(host_header_task, _phase4_timeout(60, "host_header"), {"vulnerable": False, "header_reflection": [], "password_reset_endpoints": []}, "host_header")
    business_logic_results = await await_with_timeout(business_logic_task, _phase4_timeout(90, "business_logic"), {"potential_issues": [], "price_fields": [], "quantity_fields": []}, "business_logic")
    api_security_p4_results = await await_with_timeout(api_security_p4_task, _phase4_timeout(90, "api_security_p4"), {"vulnerable": False, "mass_assignment_risks": [], "bfla_endpoints": []}, "api_security_p4")
    forced_browsing_results = await await_with_timeout(forced_browsing_task, _phase4_timeout(180, "forced_browsing"), {"vulnerable": False, "findings": [], "summary": {"critical": 0, "high": 0, "medium": 0, "info": 0}, "paths_tested": 0}, "forced_browsing")
    mass_assignment_results = await await_with_timeout(mass_assignment_task, _phase4_timeout(60, "mass_assignment"), {"vulnerable": False, "findings": [], "endpoints_tested": 0, "parameters_tested": 0}, "mass_assignment")
    bola_results = await await_with_timeout(bola_task, _phase4_timeout(120, "bola"), {"vulnerable": False, "findings": [], "endpoints_tested": 0, "access_violations": 0}, "bola")
    ssh_results = await await_with_timeout(ssh_task, _phase4_timeout(30, "ssh"), {"password_auth_enabled": False, "auth_methods": [], "findings": [], "scan_completed": False}, "ssh")
    race_condition_results = await await_with_timeout(race_condition_task, _phase4_timeout(90, "race_condition"), {"tested_endpoints": 0, "vulnerable_endpoints": 0, "findings": [], "results": []}, "race_condition")

    # Await new security enhancement tasks with timeouts (IP Reputation, Brand Protection, Enhanced DNS, Domain Intel, CT Monitor, Cloud Security)
    typosquat_results = await await_with_timeout(typosquat_task, _phase4_timeout(60, "typosquat"), {"similar_domains": [], "risk_domains": []}, "typosquat")
    dkim_enum_results = await await_with_timeout(dkim_task, _phase4_timeout(30, "dkim"), {"selectors_found": [], "dkim_records": []}, "dkim")
    zone_transfer_results = await await_with_timeout(zone_transfer_task, _phase4_timeout(30, "zone_transfer"), {"vulnerable": False, "records": []}, "zone_transfer")
    domain_intel_results = await await_with_timeout(domain_intel_task, _phase4_timeout(60, "domain_intel"), {}, "domain_intel")
    ct_monitor_results = await await_with_timeout(ct_monitor_task, _phase4_timeout(60, "ct_monitor"), {"certificates": [], "subdomains": []}, "ct_monitor")
    smtp_security_results = await await_with_timeout(smtp_security_task, _phase4_timeout(60, "smtp_security"), {"open_relay": False, "starttls": False, "findings": []}, "smtp_security")
    asn_discovery_results = await await_with_timeout(asn_discovery_task, _phase4_timeout(30, "asn_discovery"), {"asn": None, "ranges": []}, "asn_discovery")
    network_services_results = await await_with_timeout(network_services_task, _phase4_timeout(120, "network_services"), {"services": [], "findings": []}, "network_services")
    cloud_ssrf_results = await await_with_timeout(cloud_ssrf_task, _phase4_timeout(90, "cloud_ssrf"), {"vulnerable": False, "findings": []}, "cloud_ssrf")
    k8s_results = await await_with_timeout(k8s_task, _phase4_timeout(60, "k8s"), {"exposed": False, "findings": []}, "k8s")
    tf_results = await await_with_timeout(tf_task, _phase4_timeout(30, "tf"), {"exposed": False, "findings": []}, "tf")

    emit_progress("phase_4", 85, "priority and enhancement checks complete")
    registry_results = await await_with_timeout(registry_task, _phase4_timeout(60, "registry"), {"registrar": None, "creation_date": None, "expiration_date": None}, "registry")
    breach_check_results = await await_with_timeout(breach_check_task, _phase4_timeout(60, "breach_check"), {"breaches": [], "exposed_emails": []}, "breach_check")
    vendor_risk_results = await await_with_timeout(vendor_risk_task, _phase4_timeout(60, "vendor_risk"), {"risk_score": None, "vendors": []}, "vendor_risk")

    # IP Reputation: Now run with actual resolved IP (after DNS resolution)
    # Re-create IP reputation task with actual IP if enabled
    if ip_reputation and not public_only and dns.get("A"):
        primary_ip = dns["A"][0] if isinstance(dns.get("A"), list) and dns.get("A") else None
        if primary_ip:
            abuseipdb_api_key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY")
            virustotal_api_key = virustotal_key or os.environ.get("VIRUSTOTAL_API_KEY")
            ip_rep_task_actual = asyncio.create_task(check_ip_reputation(
                primary_ip,
                abuseipdb_key=abuseipdb_api_key,
                virustotal_key=virustotal_api_key
            ))
            ip_rep_results = await await_with_timeout(
                ip_rep_task_actual,
                _phase4_timeout(60, "ip_reputation"),
                {"abuse_score": None, "malicious": False, "reports": []},
                "ip_reputation"
            )
        else:
            ip_rep_results = await await_with_timeout(ip_rep_task, _phase4_timeout(60, "ip_rep"), {"abuse_score": None, "malicious": False, "reports": []}, "ip_rep")
    else:
        ip_rep_results = await await_with_timeout(ip_rep_task, _phase4_timeout(60, "ip_rep"), {"abuse_score": None, "malicious": False, "reports": []}, "ip_rep")

    # Await complete mode tasks with timeouts
    comprehensive_port_results = await await_with_timeout(comprehensive_port_task, _phase4_timeout(300, "comprehensive_port"), {"ports": [], "services": []}, "comprehensive_port")
    deep_discovery_results = await await_with_timeout(deep_discovery_task, _phase4_timeout(180, "deep_discovery"), {"paths": [], "endpoints": []}, "deep_discovery")
    advanced_vuln_results = await await_with_timeout(advanced_vuln_task, _phase4_timeout(180, "advanced_vuln"), {"findings": [], "vulnerabilities": []}, "advanced_vuln")

    # Optional DKIM selectors
    dkim = None
    if dkim_selectors:
        dkim = {}
        tasks = []
        for s in dkim_selectors:
            name = f"{s}._domainkey.{host}"
            tasks.append(asyncio.create_task(run(["dig","+short","+tries=1","+time=2",name,"TXT"])))
        done = await asyncio.gather(*tasks, return_exceptions=True)
        for s, result in zip(dkim_selectors, done, strict=False):
            name = f"{s}._domainkey.{host}"
            # Skip failed lookups gracefully (graceful degradation)
            if isinstance(result, Exception):
                dkim[name] = {"present": False, "raw": None, "error": str(result)}
                continue
            out, err, rc = result
            dkim[name] = {"present": rc==0 and bool(out.strip()), "raw": out.strip() if out else None}

    # Choose header source: prefer browser if it returned a non-error status (<= 399)
    use_browser = False
    try:
        br_status_code = int(browser_res["status"].split()[-1]) if browser_res and browser_res.get("status") else 0
        curl_status_code = int((headers_main["status"].split()[1]) if headers_main.get("status") else 0)
        # prefer browser if 2xx/3xx, or curl got a 403/401 from CDN
        if 200 <= br_status_code < 400 or (br_status_code and br_status_code != 0 and curl_status_code in (401,403)):
            use_browser = True
    except Exception:
        pass

    chosen_headers = browser_res["headers"] if use_browser and browser_res else headers_main["headers"]
    sec_headers = parse_security_headers(chosen_headers)
    csp_eval = analyze_csp(sec_headers.get("csp"))
    cookies = analyze_cookies(chosen_headers)

    # Cloud service detection
    cloud_services = await detect_cloud_services(host, chosen_headers)

    # WAF detection (needs headers)
    waf_results = await detect_waf(base_url, chosen_headers)

    # Server version detection (nginx, Apache, Node.js, PHP, etc.)
    server_versions = detect_server_versions(chosen_headers)

    final_url = headers_main["final_url"]
    scheme_redirect = None
    if base_url.startswith("http://"):
        # We started with HTTP; treat HTTPS result as redirect
        scheme_redirect = "to_https" if final_url.startswith("https://") else "none"
    elif base_url.startswith("https://"):
        # If we started with HTTPS, probe HTTP explicitly to avoid penalizing 'n/a'
        scheme_redirect = "n/a"
        if http_redirect_task is not None:
            try:
                http_probe = await http_redirect_task
                http_final = (http_probe.get("final_url") or "").lower()
                http_status = (http_probe.get("status") or "")
                if http_final.startswith("https://"):
                    scheme_redirect = "to_https"
                elif http_status and " 200" in http_status:
                    scheme_redirect = "none"
                else:
                    scheme_redirect = "n/a"
            except Exception:
                scheme_redirect = "n/a"
    else:
        scheme_redirect = "n/a"

    # --- Certificate fallback merge ---
    cert = tlsx_data["certificate"] or {}
    if not cert or not cert.get("not_after"):
        openssl_cert = parse_openssl_cert(ocsp.get("raw"))
        for k, v in openssl_cert.items():
            if k not in cert or cert.get(k) in (None, "", [], {}):
                cert[k] = v
    cert["days_remaining"] = days_until(cert.get("not_after"))

    # Discovery summary - combine tech detection from multiple sources
    httpx_techs = []
    for r in httpx_meta:
        tech_field = r.get("tech", [])
        if isinstance(tech_field, list):
            httpx_techs.extend(tech_field)
        elif isinstance(tech_field, str):
            httpx_techs.extend([t.strip() for t in tech_field.split(",") if t.strip()])
    httpx_techs = sorted(set(httpx_techs))
    browser_techs = browser_res.get("tech_stack", []) if browser_res else []

    # Enhanced technology fingerprinting
    # Get page content for fingerprinting
    page_content = None
    if browser_res and browser_res.get("status"):
        content_out, _, _ = await run(["curl", "-sS", "-L", "-k", "--max-time", "10", base_url])
        page_content = content_out[:50000] if content_out else None

    tech_fingerprint = await enhanced_tech_fingerprinting(base_url, chosen_headers, page_content)

    # Merge browser-detected versions into tech_fingerprint
    browser_versions = browser_res.get("browser_versions", {}) if browser_res else {}
    if browser_versions:
        for tech in tech_fingerprint["technologies"]:
            if tech["name"] == "Next.js" and not tech.get("version"):
                if browser_versions.get("nextjs"):
                    tech["version"] = browser_versions["nextjs"]
                    tech["detection_method"] = "browser_js"
            elif tech["name"] == "React" and not tech.get("version"):
                if browser_versions.get("react"):
                    tech["version"] = browser_versions["react"]
                    tech["detection_method"] = "browser_js"

    enhanced_techs = [t["name"] for t in tech_fingerprint["technologies"]]
    all_techs = sorted(set(httpx_techs + browser_techs + enhanced_techs))

    # Run unified tech discovery engine
    # Get status code from browser if available, otherwise from curl headers
    effective_status_code = 0  # Default to 0 (unknown) rather than None
    if browser_res and browser_res.get("status_code"):
        effective_status_code = browser_res.get("status_code")
    elif headers_main.get("status"):
        try:
            effective_status_code = int(headers_main["status"].split()[1])
        except (ValueError, IndexError):
            pass

    tech_discovery_result = await discover_technologies(
        url=base_url,
        browser_res=browser_res or {},  # Pass empty dict instead of None
        headers=chosen_headers,
        html_content=page_content,
        dns_result=dns,
        tls_result=tlsx_data,
        httpx_techs=httpx_techs,
        server_versions=server_versions,
        status_code=effective_status_code
    )

    # Update all_techs with discoveries from new engine
    engine_techs = [item["name"] for item in tech_discovery_result.get("items", [])]
    all_techs = sorted(set(all_techs + engine_techs))

    discovery = {
        "httpx": httpx_meta[:50],
        "katana_sample": crawl_urls[:100],
        "browser_api_endpoints": browser_api_endpoints[:50],  # API endpoints captured via Playwright
        "websocket_endpoints": all_ws_endpoints[:20],  # WebSocket endpoints discovered
        "scope": scope_stats,
        "tech_stack_guess": all_techs,
        "tech_fingerprint": tech_fingerprint,
        "tech": tech_discovery_result,  # New structured tech discovery with evidence
        "server_versions": server_versions,
        "cors": cors_results,
        "subdomain_takeover": takeover_results,
        "exposed_files": exposed_results,
        "nuclei": nuclei_results,
        "cloud_services": cloud_services,
        "network_scan": nmap_full_results,
        "waf_detection": waf_results,
        "api_security": api_sec_results,
        "subdomain_takeover_advanced": subdomain_takeover_results,
        "xxe_injection": xxe_results,
        "websocket_security": ws_results,
        "virtual_hosts": vhost_results,
    }
    browser_crawl_stats = browser_res.get("crawl_stats") if browser_res else None
    if browser_crawl_stats:
        discovery["browser_crawl"] = {
            "pages_visited": browser_crawl_stats.get("pages_visited", 0),
            "depth_reached": browser_crawl_stats.get("depth_reached", 0),
            "sample_pages": (browser_res.get("page_urls", []) or [])[:20],
        }

    if json_link_results:
        discovery["json_link_following"] = json_link_results
    if options_method_results:
        discovery["options_methods"] = options_method_results
    if grpc_results:
        discovery["grpc_reflection"] = grpc_results

    # Add complete mode results if available (skip for smart mode to avoid duplicating smart discovery)
    if complete_mode and not smart_mode:
        discovery["complete_ports"] = comprehensive_port_results
        discovery["deep_discovery"] = deep_discovery_results
        discovery["advanced_vulns"] = advanced_vuln_results

    # Add smart mode results if available
    if smart_mode:
        if smart_discovery_data:
            # Helper to redact query params from URLs (avoid leaking tokens/PII)
            def redact_url(url: str) -> str:
                if "?" not in url:
                    return url
                base, _ = url.split("?", 1)
                return base + "?<redacted>"

            # Cap lists to avoid bloating report size
            max_urls_in_report = 200
            max_endpoints_in_report = 100

            raw_all_urls = smart_discovery_data.get("all_urls", []) or []
            raw_api_endpoints = smart_discovery_data.get("api_endpoints", []) or []
            raw_recursive = smart_discovery_data.get("recursive_paths", []) or []
            raw_probed = smart_discovery_data.get("probed_endpoints", []) or []
            raw_with_params = smart_discovery_data.get("endpoints_with_params", []) or []

            discovery["smart_discovery"] = {
                "stats": smart_discovery_data.get("stats", {}),
                "total_urls_discovered": len(raw_all_urls),
                "total_api_endpoints": len(raw_api_endpoints),
                "total_recursive_paths": len(raw_recursive),
                "total_probed_endpoints": len(raw_probed),
                "total_endpoints_with_params": len(raw_with_params),
                # Capped and redacted samples
                "all_urls_sample": [redact_url(u) for u in raw_all_urls[:max_urls_in_report]],
                "api_endpoints_sample": [redact_url(u) for u in raw_api_endpoints[:max_endpoints_in_report]],
                "recursive_paths_sample": [redact_url(u) for u in raw_recursive[:max_urls_in_report]],
                "probed_endpoints_sample": [
                    {"path": p.get("path", ""), "status": p.get("status"), "params": p.get("params", [])}
                    for p in raw_probed[:max_endpoints_in_report]
                ],
            }
        if js_bundle_analysis:
            discovery["js_bundle_analysis"] = js_bundle_analysis
        # HAR-first discovery results
        if har_discovery_result:
            discovery["har_discovery"] = har_discovery_result.to_dict()
            # Add BOLA candidates for targeted testing
            bola_candidates = get_bola_candidates(har_discovery_result)
            if bola_candidates:
                discovery["bola_candidates"] = bola_candidates[:20]
        if nuclei_signals:
            # Serialize SignalSet to dict for JSON output
            discovery["nuclei_signals"] = nuclei_signals.to_dict() if hasattr(nuclei_signals, "to_dict") else nuclei_signals

    # Discovery summary with warnings for API-only targets
    discovery_summary: dict[str, Any] = {
        "total_urls": len(crawl_urls),
        "browser_endpoints": len(browser_api_endpoints),
        "manual_endpoints": len(manual_endpoints_norm) if manual_endpoints_norm else 0,
        "methods_used": [],
        "warnings": [],
    }

    if crawl_urls:
        discovery_summary["methods_used"].append("url_crawl")
    if browser_api_endpoints:
        discovery_summary["methods_used"].append("browser_api_capture")
    if manual_endpoints_norm:
        discovery_summary["methods_used"].append("manual_endpoints")
    if smart_discovery_data and smart_discovery_data.get("api_endpoints"):
        discovery_summary["methods_used"].append("api_wordlist_probe")
    if json_link_results and json_link_results.get("links"):
        discovery_summary["methods_used"].append("json_link_following")
        discovery_summary["json_links"] = len(json_link_results.get("links", []))
    if options_method_results and options_method_results.get("methods_by_url"):
        discovery_summary["methods_used"].append("options_method_discovery")
        discovery_summary["options_methods"] = len(options_method_results.get("methods_by_url", {}))
    if browser_crawl_stats and browser_crawl_stats.get("pages_visited", 0) > 1:
        discovery_summary["methods_used"].append("browser_crawl")
        discovery_summary["browser_crawl_pages"] = browser_crawl_stats.get("pages_visited", 0)
        discovery_summary["browser_crawl_depth"] = browser_crawl_stats.get("depth_reached", 0)
    if grpc_results and grpc_results.get("services"):
        discovery_summary["methods_used"].append("grpc_reflection")
        discovery_summary["grpc_services"] = len(grpc_results.get("services", []))

    # Warn if no endpoints were discovered
    if not crawl_urls and not browser_api_endpoints and not manual_endpoints_norm:
        discovery_summary["warnings"].append(
            "No endpoints discovered. For API-only targets, use custom_endpoints option "
            "or ensure OpenAPI spec is available at standard paths."
        )

    if smart_discovery_data and smart_discovery_data.get("spa_catch_all"):
        discovery_summary["spa_catch_all"] = True
        discovery_summary["warnings"].append(
            "SPA catch-all routing detected. Directory fuzzing and POST inference were skipped "
            "to avoid false positives. Only real URLs from crawl/JS parsing are included."
        )

    discovery["summary"] = discovery_summary
    emit_progress("discovery_complete", 40, "discovery summary ready")

    # Base report
    report = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "input": {"target": target, "normalized_host": host, "port": port, "scheme": scheme},
        "scan_mode": "smart" if smart_mode else ("complete" if complete_mode else ("quick" if quick_mode else "standard")),
        "scan_config": {
            "active_enforced": active_enforced,
            "active_checks": active_checks,
            "smart_mode": smart_mode,
            "no_early_stop": no_early_stop,
            "thorough_params": thorough_params,
            "budget_profile": scan_budget.get("budget_profile"),
            "resolved_budget": scan_budget,
            "include_partial_attack_chains": include_partial_attack_chains,
            "verified_findings_only": verified_findings_only,
            "focus_rules": len(focus_rules),
            "avoid_rules": len(avoid_rules),
            "auth_scenario": bool(auth_scenario),
        },
        "timestamp_utc": now_utc_iso(),
        "dns": {
            "a": dns.get("A"), "aaaa": dns.get("AAAA"), "cname": dns.get("CNAME"), "mx": dns.get("MX"),
            "txt_sample": (dns.get("TXT") or [])[:5],
            "spf": detect_spf(dns.get("TXT",[])),
            "dmarc": dmarc,
            "dnssec": dnssec,
            "dkim": dkim,
            "caa": await caa_task,
            "mta_sts": await mta_task,
            "tls_rpt": await tlsrpt_task
        },
        "tls": {
            "endpoints": tlsx_data["endpoints"],
            "certificate": cert,
            "ocsp": ocsp,
            "nmap": nmap_,
            "testssl": testssl_,
            "sslyze": sslyze_,
            "cipher_suites": sslyze_.get("cipher_suites") if sslyze_.get("cipher_suites") else nmap_.get("ciphers_by_protocol", {}),
        },
        "http": {
            "source": "browser" if use_browser else "curl",
            "status": browser_res["status"] if use_browser and browser_res else headers_main["status"],
            "final_url": final_url,
            "headers": chosen_headers,
            "security_headers": sec_headers,
            "csp_evaluation": csp_eval,
            "cookies": cookies,
            "http2": http2,
            "http3": http3,
            "http3_advertised": bool((headers_main or {}).get("advertises_h3")),
            "scheme_redirect": scheme_redirect,
            "security_txt": sec_txt,
            "evidence": {"screenshot": browser_res.get("screenshot_path") if browser_res else None, "page_title": browser_res.get("title") if browser_res else None},
            "browser_fetch_error": browser_fetch_error,
        },
        "discovery": discovery,
        "findings": []
    }
    report["tls"]["crypto_inventory"] = build_crypto_inventory(report["tls"], host, port)

    # Save initial checkpoint with baseline data
    save_checkpoint(report, "baseline")

    # Canonical network scan output (merge standard and complete port scans)
    merged_network_scan = _merge_port_scan_results(
        discovery.get("network_scan"),
        discovery.get("complete_ports"),
    )
    report["network_scan"] = merged_network_scan
    report["discovery"]["network_scan"] = merged_network_scan

    report["auth_checks"] = {
        "password_policy": password_policy_results,
        "account_enumeration": account_enum_results,
        "bruteforce_protection": bruteforce_results,
        "http_methods": http_methods_results,
    }

    # Add authenticated scanning config if enabled
    if auth_config or auth_scenario_info:
        report["authenticated_scan"] = auth_config or {"enabled": False}
        if auth_scenario_info:
            report["authenticated_scan"]["scenario"] = auth_scenario_info
            if isinstance(auth_scenario, dict) and auth_scenario.get("success_condition"):
                report["authenticated_scan"]["scenario"]["success_condition"] = auth_scenario.get("success_condition")
        # Add session validation stats if session was created
        if auth_session:
            report["authenticated_scan"]["session_stats"] = auth_session.get_stats()
        # Add form login result if attempted
        if login_result_info:
            report["authenticated_scan"]["form_login"] = login_result_info
        # Add OAuth result if attempted
        if oauth_result_info:
            report["authenticated_scan"]["oauth"] = oauth_result_info
        if api_login_info:
            report["authenticated_scan"]["api_login"] = api_login_info

    # Add Phase 3a: Client-Side Security results (if executed)
    if js_deps_results is not None:
        report["js_dependencies"] = js_deps_results
        # Add detected framework versions to tech_fingerprint for visibility
        framework_det = js_deps_results.get("framework_detection", {})
        if framework_det:
            # Add to discovery tech list if detected with version
            if framework_det.get("react", {}).get("version"):
                react_info = framework_det["react"]
                report["discovery"]["tech_fingerprint"]["technologies"].append({
                    "name": "React",
                    "version": react_info["version"],
                    "detection_method": react_info.get("detection_method"),
                    "confidence": react_info.get("confidence")
                })
            if framework_det.get("nextjs", {}).get("version"):
                next_info = framework_det["nextjs"]
                report["discovery"]["tech_fingerprint"]["technologies"].append({
                    "name": "Next.js",
                    "version": next_info["version"],
                    "detection_method": next_info.get("detection_method"),
                    "confidence": next_info.get("confidence")
                })
    if js_secrets_results is not None:
        report["js_secrets"] = js_secrets_results
    if client_side_results is not None:
        report["client_side_vulns"] = client_side_results

    # Add Phase 3b: Infrastructure & Configuration Leak results (if executed)
    if cicd_results is not None:
        report["cicd_exposure"] = cicd_results
    if package_results is not None:
        report["package_exposure"] = package_results
    if cloud_bucket_results is not None:
        report["cloud_buckets"] = cloud_bucket_results
    if backup_file_results is not None:
        report["backup_files"] = backup_file_results
    if directory_listing_results is not None:
        report["directory_listing"] = directory_listing_results

    # Add new security enhancement results (IP Reputation, Brand Protection, Domain Intel, Enhanced DNS, Cloud Security)
    if ip_rep_results is not None and ip_rep_results.get("ip"):
        report["ip_reputation"] = ip_rep_results
    if typosquat_results is not None and typosquat_results.get("checked", 0) > 0:
        report["brand_protection"] = typosquat_results
    if domain_intel_results is not None and domain_intel_results.get("whois"):
        report["domain_intelligence"] = domain_intel_results
    if ct_monitor_results is not None and ct_monitor_results.get("certificates_found", 0) > 0:
        report["certificate_transparency"] = ct_monitor_results
    if smtp_security_results is not None and smtp_security_results.get("smtp_hosts"):
        report["smtp_security"] = smtp_security_results
    if asn_discovery_results is not None and asn_discovery_results.get("asn_info"):
        report["asn_discovery"] = asn_discovery_results
    if network_services_results is not None and (network_services_results.get("vpn_endpoints") or network_services_results.get("remote_desktop") or network_services_results.get("database_exposure")):
        report["network_services"] = network_services_results

    # Add enhanced DNS results to DNS section
    if dkim_enum_results is not None and dkim_enum_results.get("selectors_found"):
        report["dns"]["dkim_enumeration"] = dkim_enum_results
    if zone_transfer_results is not None:
        report["dns"]["zone_transfer"] = zone_transfer_results

    # Add cloud security enhancement results
    if cloud_ssrf_results is not None and cloud_ssrf_results.get("tested_parameters", 0) > 0:
        report["cloud_ssrf"] = cloud_ssrf_results
    if k8s_results is not None:
        report["kubernetes_exposure"] = k8s_results
    if tf_results is not None and tf_results.get("total_tested", 0) > 0:
        report["terraform_exposure"] = tf_results
    if registry_results is not None:
        report["container_registry"] = registry_results

    # Add breach monitoring results
    if breach_check and breach_check_results is not None:
        report["breach_monitoring"] = {
            "domain": breach_check_results.domain,
            "breaches_found": breach_check_results.breaches_found,
            "breaches": [
                {
                    "name": b.name,
                    "title": b.title,
                    "breach_date": b.breach_date,
                    "records_exposed": b.pwn_count,
                    "data_types": b.data_classes,
                    "is_verified": b.is_verified,
                }
                for b in breach_check_results.breaches
            ],
            "emails_discovered": len(breach_check_results.emails_discovered),
            "credential_leaks_found": len(breach_check_results.credential_leaks),
            "github_leaks_found": len(breach_check_results.github_leaks),
            "risk_score": breach_check_results.risk_score,
            "risk_level": breach_check_results.risk_level,
            "checked_at": breach_check_results.checked_at,
        }

        # Add breach findings to main findings list
        breach_findings = generate_breach_findings(breach_check_results)
        for finding in breach_findings:
            report["findings"].append(finding)

    # Add vendor risk results
    if vendor_risk and vendor_risk_results is not None and vendor_risk_results.total_third_parties > 0:
        report["vendor_risk"] = {
            "target": vendor_risk_results.target,
            "assessed_at": vendor_risk_results.assessed_at,
            "total_third_parties": vendor_risk_results.total_third_parties,
            "third_party_domains": vendor_risk_results.third_party_domains[:20],  # Limit to 20
            "risk_score": vendor_risk_results.risk_score,
            "risk_level": vendor_risk_results.risk_level,
            "summary": vendor_risk_results.summary,
            "resources": [
                {
                    "url": r.url,
                    "domain": r.domain,
                    "type": r.resource_type,
                    "provider": r.provider,
                    "category": r.category,
                    "trust_level": r.trust_level,
                    "security_score": r.security_score,
                    "risk_factors": r.risk_factors[:3] if r.risk_factors else [],
                }
                for r in vendor_risk_results.resources[:20]  # Limit to 20 resources
            ]
        }

        # Add vendor risk findings to main findings list
        for finding in vendor_risk_results.findings:
            report["findings"].append(finding)

    # Add findings from security checks

    # Process SSLyze findings
    if sslyze_.get("scan_completed"):
        for vuln in sslyze_.get("vulnerabilities", []):
            severity = vuln.get("severity", "medium")
            cve = vuln.get("cve", "CWE-310")  # Cryptographic Issues

            if vuln["type"] == "heartbleed":
                title = "Heartbleed Vulnerability (CVE-2014-0160)"
            elif vuln["type"] == "robot":
                title = f"ROBOT Attack Vulnerability: {vuln.get('details', '')}"
            elif vuln["type"] == "ccs_injection":
                title = "OpenSSL CCS Injection (CVE-2014-0224)"
            elif vuln["type"] == "crime":
                title = f"CRIME Attack: {vuln.get('details', '')}"
            elif vuln["type"] == "weak_cipher":
                title = f"Weak Cipher Suite: {vuln.get('details', '')}"
            else:
                title = f"TLS Vulnerability: {vuln['type']}"

            report["findings"].append(normalize_finding(
                "sslyze",
                title,
                severity,
                {
                    "type": vuln["type"],
                    "details": vuln.get("details", ""),
                    "protocol": vuln.get("protocol", "")
                },
                cve
            ))

    # Prepare open ports set for correlating with network findings
    open_ports_set = set()
    try:
        for p in nmap_full_results.get("open_ports", []):
            if isinstance(p, dict) and isinstance(p.get("port"), int):
                open_ports_set.add(p["port"])
    except Exception:
        pass
    try:
        for p in comprehensive_port_results.get("open_ports", []):
            if isinstance(p, dict) and isinstance(p.get("port"), int):
                open_ports_set.add(p["port"])
    except Exception:
        pass

    # Process Nuclei findings
    if nuclei_results.get("scan_completed"):
        # Check if CAA records actually exist (to filter false positive CAA findings from Nuclei)
        caa_records_exist = bool(report.get("dns", {}).get("caa", {}).get("records", []))

        # Track seen template_ids to deduplicate nuclei findings
        # This prevents multiple RDAP/WHOIS or other duplicate findings from the same template
        seen_nuclei_templates = set()

        # Handle comprehensive scan format (with categorized vulnerabilities)
        if "vulnerabilities" in nuclei_results and isinstance(nuclei_results["vulnerabilities"], dict):
            # Comprehensive scan format
            for severity_level, vulns in nuclei_results["vulnerabilities"].items():
                for vuln in vulns:
                    # Skip CAA-related Nuclei findings if no CAA records actually exist
                    # (Nuclei's caa-fingerprint template can match on DNS response structure even without CAA records)
                    template_id = str(vuln.get("template_id", "")).lower()
                    if "caa" in template_id and not caa_records_exist:
                        continue

                    # Skip Nuclei CSP findings when internal CSP evaluator gave A or A+ grade
                    # Our internal evaluator is more nuanced than Nuclei's generic templates
                    if "csp" in template_id:
                        internal_csp_grade = report.get("http", {}).get("csp_evaluation", {}).get("grade", "")
                        if internal_csp_grade in ("A", "A+"):
                            continue

                    # Deduplicate nuclei findings by template_id + severity
                    # Prevents multiple identical findings from same template (e.g., HTTP Missing Security Headers 11x)
                    dedup_key = f"{template_id}:{severity_level}" if template_id else None
                    if dedup_key:
                        if dedup_key in seen_nuclei_templates:
                            continue
                        seen_nuclei_templates.add(dedup_key)

                    # Use CWE IDs from Nuclei if available
                    cwe_ids = vuln.get("cwe_ids", [])
                    cwe = cwe_ids[0] if cwe_ids else "CWE-16"  # Default to Configuration

                    title = vuln.get("name", vuln.get("template_id", "Unknown Vulnerability"))
                    tags = [str(t).lower() for t in vuln.get("tags", [])]

                    # Handle info-level nuclei findings
                    # High-value templates are promoted to low severity findings
                    # Others go to discovery.nuclei_recon to avoid cluttering findings[]
                    if severity_level == "info":
                        # Check if this is a high-value template that should be promoted
                        should_promote = any(pt in template_id for pt in NUCLEI_PROMOTE_INFO_TEMPLATES)
                        if should_promote:
                            # Promote to low severity for security posture visibility
                            severity_level = "low"
                        else:
                            # Move to nuclei_recon (tech detection, waf-detect, cdn-detect, etc.)
                            if "nuclei_recon" not in report.get("discovery", {}):
                                report["discovery"]["nuclei_recon"] = []
                            report["discovery"]["nuclei_recon"].append({
                                "template_id": vuln.get("template_id"),
                                "name": title,
                                "matched_at": vuln.get("matched_at"),
                                "description": vuln.get("description"),
                                "tags": tags,
                            })
                            continue  # Don't add to findings[]

                    # Mark network findings where the referenced port wasn't confirmed open
                    evidence_extra = {}
                    if "network" in tags:
                        m = re.search(r":(\d{1,5})(?:/|$)", str(vuln.get("matched_at", "")))
                        if m:
                            port = int(m.group(1))
                            if port not in open_ports_set:
                                evidence_extra["port_unverified"] = True
                                evidence_extra["unverified_port"] = port
                    report["findings"].append(normalize_finding(
                        "nuclei",
                        title,
                        severity_level,
                        {
                            "template_id": vuln.get("template_id"),
                            "matched_at": vuln.get("matched_at"),
                            "description": vuln.get("description"),
                            "tags": vuln.get("tags", []),
                            "cvss_score": vuln.get("cvss_score", 0),
                            "remediation": vuln.get("remediation", ""),
                            **evidence_extra
                        },
                        cwe
                    ))
        else:
            # Standard scan format (backward compatibility)
            for vuln in nuclei_results.get("vulnerabilities", []):
                # Skip CAA-related Nuclei findings if no CAA records actually exist
                template_id = str(vuln.get("template_id", "")).lower()
                if "caa" in template_id and not caa_records_exist:
                    continue

                # Skip Nuclei CSP findings when internal CSP evaluator gave A or A+ grade
                if "csp" in template_id:
                    internal_csp_grade = report.get("http", {}).get("csp_evaluation", {}).get("grade", "")
                    if internal_csp_grade in ("A", "A+"):
                        continue

                # Map Nuclei severity to our severity scale
                severity_map = {
                    "critical": "critical",
                    "high": "high",
                    "medium": "medium",
                    "low": "low",
                    "info": "info"
                }
                severity = severity_map.get(vuln["severity"].lower(), "medium")

                # Deduplicate nuclei findings by template_id + severity
                # Prevents multiple identical findings from same template (e.g., HTTP Missing Security Headers 11x)
                dedup_key = f"{template_id}:{severity}" if template_id else None
                if dedup_key:
                    if dedup_key in seen_nuclei_templates:
                        continue
                    seen_nuclei_templates.add(dedup_key)

                # Use CWE IDs from Nuclei if available
                cwe_ids = vuln.get("cwe_ids", [])
                cwe = cwe_ids[0] if cwe_ids else "CWE-16"  # Default to Configuration

                title = vuln.get("name", vuln.get("template_id", "Unknown Vulnerability"))
                tags = [str(t).lower() for t in vuln.get("tags", [])]

                # Handle info-level nuclei findings
                # High-value templates are promoted to low severity findings
                # Others go to discovery.nuclei_recon to avoid cluttering findings[]
                if severity == "info":
                    # Check if this is a high-value template that should be promoted
                    should_promote = any(pt in template_id for pt in NUCLEI_PROMOTE_INFO_TEMPLATES)
                    if should_promote:
                        # Promote to low severity for security posture visibility
                        severity = "low"
                    else:
                        # Move to nuclei_recon (tech detection, waf-detect, cdn-detect, etc.)
                        if "nuclei_recon" not in report.get("discovery", {}):
                            report["discovery"]["nuclei_recon"] = []
                        report["discovery"]["nuclei_recon"].append({
                            "template_id": vuln.get("template_id"),
                            "name": title,
                            "matched_at": vuln.get("matched_at"),
                            "description": vuln.get("description"),
                            "tags": tags,
                        })
                        continue  # Don't add to findings[]

                # Mark network findings with unverified ports
                evidence_extra = {}
                if "network" in tags:
                    m = re.search(r":(\d{1,5})(?:/|$)", str(vuln.get("matched_at", "")))
                    if m:
                        port = int(m.group(1))
                        if port not in open_ports_set:
                            evidence_extra["port_unverified"] = True
                            evidence_extra["unverified_port"] = port
                report["findings"].append(normalize_finding(
                    "nuclei",
                    title,
                    severity,
                {
                    "template_id": vuln.get("template_id"),
                    "description": vuln.get("description"),
                    **evidence_extra,
                    "matched_at": vuln.get("matched_at"),
                    "tags": vuln.get("tags", []),
                    "reference": vuln.get("reference", []),
                    "cvss_score": vuln.get("cvss_score", 0),
                    "cvss_metrics": vuln.get("cvss_metrics", "")
                },
                cwe
            ))

    if cors_results.get("vulnerable"):
        # FIX: Deduplicate CORS issues and consolidate into a single finding
        # Previous code created one finding per issue, causing duplicates like
        # "Wildcard CORS" appearing 4 times in the same scan
        unique_issues = sorted(set(cors_results.get("issues", [])))
        if unique_issues:
            # Create a single consolidated finding with all unique issues
            if len(unique_issues) == 1:
                title = f"CORS Misconfiguration: {unique_issues[0]}"
            else:
                title = f"CORS Misconfiguration: {unique_issues[0]} (+{len(unique_issues) - 1} more)"
            report["findings"].append(normalize_finding(
                "cors_check", title, "high",
                {
                    "issues": unique_issues,
                    "occurrences": len(cors_results.get("issues", [])),
                    "details": cors_results
                }, "CWE-942"
            ))

    if takeover_results.get("vulnerable"):
        for issue in takeover_results.get("issues", []):
            report["findings"].append(normalize_finding(
                "subdomain_takeover", f"Subdomain Takeover: {issue}", "critical",
                {"cname": takeover_results.get("cname"), "issue": issue}, "CWE-284"
            ))

    if exposed_results.get("exposed_files"):
        critical_key_markers = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "privatekey", "private.key", "ssl.key", "cert.key", "certificate.key", ".pem"]
        high_markers = [".git/", ".git\\", ".git", ".env", "wp-config.php", "database.sql", "backup.sql", "dump.sql", "database.yml", "database.yaml", "db.yml", "db.yaml"]
        for file_info in exposed_results["exposed_files"][:5]:  # Limit to top 5
            path_raw = file_info.get("path") or "?"
            path_l = path_raw.lower()
            confidence = (file_info.get("confidence") or "low").lower()
            # Severity mapping
            if any(m in path_l for m in critical_key_markers):
                severity = "critical" if confidence in ("high", "medium") else "high"
            elif any(m in path_l for m in high_markers):
                severity = "high" if confidence != "low" else "medium"
            else:
                severity = "medium" if confidence != "low" else "low"

            # Per-finding remediation suggestions
            remediation: list[str] = []
            if any(m in path_l for m in ["id_rsa", "server.key", "private.key", ".pem", "certificate.key", "cert.key", "privkey.pem", "key.pem"]):
                remediation = [
                    "Remove private key from web root; ensure keys live outside document root.",
                    "Rotate the keypair and revoke any certificates referencing the leaked key.",
                    "Add web server rule to deny access to key files (e.g., location ~* \\.(key|pem)$ { deny all; }).",
                ]
            elif ".git" in path_l:
                remediation = [
                    "Block access to /.git in the web server (deny all).",
                    "Redeploy from a clean build artifact; avoid deploying the .git directory.",
                    "Rotate any credentials accidentally committed; review history for secrets.",
                ]
            elif ".env" in path_l:
                remediation = [
                    "Move secrets to environment/secret manager; remove .env from web root.",
                    "Rotate any exposed API keys/passwords.",
                    "Add deny rules for .env files.",
                ]
            elif any(m in path_l for m in ["wp-config.php", "configuration.php", "localsettings.php"]):
                remediation = [
                    "Ensure PHP is executed and not served as source; deny direct access to config files.",
                    "Move sensitive app configs outside document root where possible.",
                ]
            elif any(m in path_l for m in [".sql", "backup.sql", "dump.sql", "database.sql"]):
                remediation = [
                    "Remove SQL dumps from web root; store offline/encrypted.",
                    "Rotate database passwords and audit for unauthorized access.",
                ]
            elif any(m in path_l for m in ["database.yml", "database.yaml", "db.yml", "db.yaml"]):
                remediation = [
                    "Remove application DB config from web root and move to environment/secret manager.",
                    "Rotate DB credentials and restrict DB network exposure to trusted hosts only.",
                    "Add deny rules for database config files (e.g., location ~* (database|db)\\.(ya?ml)$ { deny all; }).",
                ]

            # Manual verify commands embedded in evidence (safe)
            url = file_info.get("url", urllib.parse.urljoin(base_url + "/", (file_info.get("path") or "").lstrip("/")))
            verify_cmds = [
                f"curl -sI {shlex.quote(url)}",
                f"curl -sL {shlex.quote(url)} | sed -n '1,40p'",
            ]
            if ".git" in path_l:
                base = base_url.rstrip("/")
                verify_cmds.extend([f"curl -sL {shlex.quote(base)}/.git/HEAD", f"curl -sL {shlex.quote(base)}/.git/config"])
            if any(m in path_l for m in ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "server.key", "private.key", ".pem"]):
                verify_cmds.append(f"curl -sL {shlex.quote(url)} | grep -E 'BEGIN (OPENSSH|RSA|DSA|EC) PRIVATE KEY' -m1")
            if any(m in path_l for m in ["database.yml", "database.yaml", "db.yml", "db.yaml"]):
                verify_cmds.append(f"curl -sL {shlex.quote(url)} | grep -Ei '(^|[:\"'\\s])(password|username|adapter|database)[:=]' -m1")

            title = f"Exposed file: {path_raw} (confidence: {confidence})"
            evidence = {
                "path": path_raw,
                "url": url,
                "confidence": confidence,
                "content_type": file_info.get("content_type", "unknown"),
                "size": file_info.get("size", file_info.get("content_length", 0)),
                "markers": file_info.get("markers"),
                "preview_first_line": file_info.get("preview_first_line"),
                "preview_hash16": file_info.get("preview_hash16"),
                "has_html": file_info.get("has_html"),
                "subentries": file_info.get("subentries"),
                "verify_commands": verify_cmds,
                "remediation": remediation,
            }
            report["findings"].append(normalize_finding(
                "exposed_files", title, severity, evidence, "CWE-200"
            ))

    # Add findings from new vulnerability tests
    if nosql_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "nosql_injection", "NoSQL Injection Vulnerability", "critical",
            {"evidence": nosql_results["evidence"], "payloads_tested": len(nosql_results["payloads_tested"])},
            "CWE-89"
        ))

    if ldap_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "ldap_injection", "LDAP Injection Vulnerability", "high",
            {"evidence": ldap_results["evidence"], "payloads_tested": len(ldap_results["payloads_tested"])},
            "CWE-90"
        ))

    if xpath_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "xpath_injection", "XPath Injection Vulnerability", "high",
            {"evidence": xpath_results["evidence"], "payloads_tested": len(xpath_results["payloads_tested"])},
            "CWE-91"
        ))

    if ssti_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "ssti", "Server-Side Template Injection", "critical",
            {"evidence": ssti_results["evidence"], "payloads_tested": len(ssti_results["payloads_tested"])},
            "CWE-1336"
        ))

    if smuggling_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "http_smuggling", f"HTTP Request Smuggling ({smuggling_results['technique']})", "high",
            {"technique": smuggling_results["technique"], "evidence": smuggling_results["evidence"]},
            "CWE-444"
        ))

    if jwt_results.get("vulnerable"):
        for issue in jwt_results.get("issues", []):
            severity = "critical" if issue == "none_algorithm" else "high"
            report["findings"].append(normalize_finding(
                "jwt_vulnerability", f"JWT Vulnerability: {issue}", severity,
                {"issue": issue, "evidence": jwt_results["evidence"]},
                "CWE-347"
            ))

    if oauth_results.get("vulnerable"):
        issue_severity = {
            "open_redirect": "medium",
            "issuer_insecure": "high",
            "id_token_alg_none": "high",
            "jwks_symmetric_key": "high",
            "jwks_alg_none": "high",
            "jwks_weak_rsa": "high",
            "implicit_flow_enabled": "medium",
            "ropc_enabled": "medium",
            "pkce_s256_missing": "medium",
            "token_endpoint_auth_none": "low",
        }
        issue_cwe = {
            "open_redirect": "CWE-601",
            "issuer_insecure": "CWE-319",
            "id_token_alg_none": "CWE-347",
            "jwks_symmetric_key": "CWE-347",
            "jwks_alg_none": "CWE-347",
            "jwks_weak_rsa": "CWE-326",
            "implicit_flow_enabled": "CWE-287",
            "ropc_enabled": "CWE-287",
            "pkce_s256_missing": "CWE-287",
            "token_endpoint_auth_none": "CWE-287",
        }
        for issue in oauth_results.get("issues", []):
            issue_evidence = [e for e in oauth_results.get("evidence", []) if e.get("type") == issue]
            report["findings"].append(normalize_finding(
                "oauth_vulnerability", f"OAuth/OIDC Issue: {issue}", issue_severity.get(issue, "medium"),
                {"issue": issue, "evidence": issue_evidence or oauth_results.get("evidence", [])},
                issue_cwe.get(issue, "CWE-863")
            ))

    if session_results.get("vulnerable"):
        for issue in session_results.get("issues", []):
            report["findings"].append(normalize_finding(
                "session_vulnerability", f"Session Management Issue: {issue}", "medium",
                {"issue": issue, "evidence": session_results["evidence"]},
                "CWE-384"
            ))

    if timing_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "timing_attack", "Timing Attack Vulnerability", "medium",
            {"evidence": timing_results["evidence"]},
            "CWE-208"
        ))

    if graphql_results.get("vulnerable"):
        for issue in graphql_results.get("issues", []):
            severity = "high" if "introspection" in issue else "medium"
            report["findings"].append(normalize_finding(
                "graphql_vulnerability", f"GraphQL Vulnerability: {issue}", severity,
                {"issue": issue, "evidence": graphql_results["evidence"]},
                "CWE-200"
            ))

    if cache_poison_results.get("vulnerable"):
        evidence_list = cache_poison_results.get("evidence", [])
        affected_headers = [e.get("header", "unknown") for e in evidence_list]

        # Check if any evidence is actually cacheable - if not, downgrade severity
        any_cacheable = any(e.get("cacheable", False) for e in evidence_list)

        if any_cacheable:
            # Actually exploitable - high severity
            severity = "high"
            title = f"Cache Poisoning via header injection ({len(evidence_list)} header(s) affected)"
        else:
            # Header reflection exists but response not cached - info only
            severity = "info"
            title = f"Header Reflection Detected (not cacheable - {len(evidence_list)} header(s))"

        report["findings"].append(normalize_finding(
            "cache_poisoning",
            title,
            severity,
            {
                "affected_headers": affected_headers,
                "details": evidence_list,
                "cacheable": any_cacheable,
                "recommendation": "Configure your reverse proxy/CDN to strip or ignore untrusted headers like X-Forwarded-Host, X-Forwarded-Scheme, X-HTTP-Method-Override"
            },
            "CWE-444"
        ))

    # Enhanced JWT security findings
    if jwt_comprehensive_results.get("vulnerable") or jwt_comprehensive_results.get("findings"):
        for finding in jwt_comprehensive_results.get("findings", []):
            severity = finding.get("severity", "high")
            report["findings"].append(normalize_finding(
                f"jwt_{finding.get('type', 'vulnerability')}",
                finding.get("title", "JWT Security Vulnerability"),
                severity,
                {
                    "type": finding.get("type"),
                    "evidence": finding.get("evidence", []),
                    "recommendation": finding.get("recommendation", "Review JWT implementation")
                },
                finding.get("cwe", "CWE-287")
            ))
        # Handle specific algorithm confusion findings
        if jwt_comprehensive_results.get("algorithm_confusion", {}).get("vulnerable"):
            report["findings"].append(normalize_finding(
                "jwt_algorithm_confusion",
                "JWT Algorithm Confusion Attack (RS256 to HS256)",
                "critical",
                {
                    "technique": "Algorithm substitution from RS256 to HS256",
                    "evidence": jwt_comprehensive_results["algorithm_confusion"].get("evidence", []),
                    "recommendation": "Explicitly verify the algorithm in JWT tokens server-side; never rely on the alg header"
                },
                "CWE-327"
            ))
        # Handle KID injection findings
        if jwt_comprehensive_results.get("kid_injection", {}).get("vulnerable"):
            report["findings"].append(normalize_finding(
                "jwt_kid_injection",
                "JWT Key ID (kid) Injection",
                "critical",
                {
                    "technique": "Path traversal or SQL injection via kid header",
                    "evidence": jwt_comprehensive_results["kid_injection"].get("evidence", []),
                    "recommendation": "Sanitize and validate the kid claim; use an allowlist of valid key IDs"
                },
                "CWE-94"
            ))

    # Enhanced GraphQL security findings
    if graphql_comprehensive_results.get("vulnerable") or graphql_comprehensive_results.get("findings"):
        for finding in graphql_comprehensive_results.get("findings", []):
            severity = finding.get("severity", "medium")
            report["findings"].append(normalize_finding(
                f"graphql_{finding.get('type', 'vulnerability')}",
                finding.get("title", "GraphQL Security Vulnerability"),
                severity,
                {
                    "type": finding.get("type"),
                    "evidence": finding.get("evidence", []),
                    "recommendation": finding.get("recommendation", "Review GraphQL security configuration")
                },
                finding.get("cwe", "CWE-400")
            ))
        # Handle batch attack findings
        if graphql_comprehensive_results.get("batch_attacks", {}).get("vulnerable"):
            report["findings"].append(normalize_finding(
                "graphql_batch_attack",
                "GraphQL Batching Attack Possible",
                "medium",
                {
                    "technique": "Array or alias-based batch queries",
                    "evidence": graphql_comprehensive_results["batch_attacks"].get("evidence", []),
                    "recommendation": "Implement query cost analysis and rate limiting for GraphQL"
                },
                "CWE-770"
            ))
        # Handle depth attack findings
        if graphql_comprehensive_results.get("depth_attacks", {}).get("vulnerable"):
            report["findings"].append(normalize_finding(
                "graphql_depth_attack",
                "GraphQL Query Depth Limit Bypass",
                "medium",
                {
                    "max_depth_reached": graphql_comprehensive_results["depth_attacks"].get("max_depth", 0),
                    "evidence": graphql_comprehensive_results["depth_attacks"].get("evidence", []),
                    "recommendation": "Implement query depth limiting in GraphQL server"
                },
                "CWE-400"
            ))

    # HTTP Verb Tampering findings
    if verb_tampering_results.get("vulnerable") or verb_tampering_results.get("findings"):
        for finding in verb_tampering_results.get("findings", []):
            severity = finding.get("severity", "medium")
            report["findings"].append(normalize_finding(
                "http_verb_tampering",
                finding.get("title", "HTTP Method/Verb Tampering"),
                severity,
                {
                    "method": finding.get("method"),
                    "bypass_technique": finding.get("technique"),
                    "evidence": finding.get("evidence", []),
                    "recommendation": "Ensure consistent authorization checks across all HTTP methods"
                },
                "CWE-650"
            ))

    # Rate Limit Detection findings (informational)
    if rate_limit_results.get("rate_limited") is False and rate_limit_results.get("tested"):
        # No rate limiting detected - potential issue
        report["findings"].append(normalize_finding(
            "missing_rate_limit",
            "No Rate Limiting Detected",
            "low",
            {
                "requests_sent": rate_limit_results.get("requests_sent", 0),
                "all_succeeded": rate_limit_results.get("all_succeeded", True),
                "recommendation": "Implement rate limiting to prevent brute force and denial of service attacks"
            },
            "CWE-770"
        ))
    elif rate_limit_results.get("rate_limited") and rate_limit_results.get("limits"):
        # Rate limiting detected - include info
        report["result"]["rate_limiting"] = {
            "detected": True,
            "limits": rate_limit_results.get("limits", {}),
            "headers": rate_limit_results.get("headers", {})
        }

    # Add findings from enhanced security checks
    if waf_results.get("waf_detected"):
        waf_info = f"WAF Detected: {', '.join(waf_results['waf_products'])}"
        report["findings"].append(normalize_finding(
            "waf_detection", waf_info, "info",
            {
                "products": waf_results["waf_products"],
                "confidence": waf_results["confidence"],
                "blocked_details": waf_results.get("blocked_details", []),
                "bypass_techniques": waf_results["bypass_techniques"]
            },
            "CWE-693"
        ))
    elif waf_results.get("input_validation_detected"):
        # Only report input validation as low severity info
        report["findings"].append(normalize_finding(
            "input_validation",
            "Input validation detected (attack payloads blocked)",
            "info",
            {
                "blocked_payloads": waf_results["blocked_payloads"],
                "blocked_details": waf_results.get("blocked_details", []),
                "confidence": waf_results["confidence"],
                "note": "Standard input validation detected, no specific WAF identified"
            },
            "CWE-20"  # Improper Input Validation
        ))

    if api_sec_results.get("vulnerabilities"):
        for vuln in api_sec_results["vulnerabilities"]:
            evidence = {
                "type": vuln["type"],
                "endpoint": vuln.get("endpoint", "unknown"),
                "api_type": api_sec_results.get("api_type", "unknown")
            }
            for key in (
                "url",
                "verified",
                "sensitive_markers",
                "response_hash16",
                "response_sample",
            ):
                if key in vuln:
                    evidence[key] = vuln[key]
            # Include headers if present (for auth bypass findings)
            if "headers" in vuln:
                evidence["headers"] = vuln["headers"]
            elif "header" in vuln:
                evidence["header"] = vuln["header"]

            report["findings"].append(normalize_finding(
                "api_security", vuln["description"], vuln["severity"],
                evidence,
                "CWE-209" if "introspection" in vuln["type"] else "CWE-287"
            ))

    if subdomain_takeover_results.get("vulnerable"):
        for evidence in subdomain_takeover_results["evidence"]:
            severity = "critical" if evidence.get("type") != "dead_nameserver" else "high"
            report["findings"].append(normalize_finding(
                "subdomain_takeover_advanced",
                f"Subdomain Takeover: {evidence.get('service', evidence.get('type', 'unknown'))}",
                severity,
                evidence,
                "CWE-284"
            ))

    if xxe_results.get("vulnerable"):
        for evidence in xxe_results["evidence"]:
            report["findings"].append(normalize_finding(
                "xxe_injection",
                f"XXE Injection: {evidence['type']}",
                "critical" if "file" in evidence.get("response_snippet", "") else "high",
                evidence,
                "CWE-611"
            ))

    # Phase 1 Critical Checks Findings
    if csrf_results.get("vulnerable"):
        # CSRF findings - high severity
        if csrf_results.get("forms_without_tokens"):
            report["findings"].append(normalize_finding(
                "csrf_testing",
                f"CSRF protection missing on {len(csrf_results['forms_without_tokens'])} form(s)",
                "high",
                {
                    "forms_without_tokens": csrf_results["forms_without_tokens"][:5],  # Limit to 5 for report size
                    "tested_forms": csrf_results["tested_forms"],
                    "total_vulnerable": len(csrf_results["forms_without_tokens"])
                },
                "CWE-352"
            ))

        # SameSite cookie issues - medium severity
        if csrf_results.get("missing_samesite"):
            report["findings"].append(normalize_finding(
                "csrf_testing",
                f"Missing SameSite cookie attribute on {len(csrf_results['missing_samesite'])} cookie(s)",
                "medium",
                {
                    "missing_samesite": csrf_results["missing_samesite"][:5],
                    "total_cookies": len(csrf_results["missing_samesite"])
                },
                "CWE-352"
            ))

    if idor_results.get("vulnerable"):
        # IDOR/BOLA findings - critical severity
        for vuln_endpoint in idor_results.get("vulnerable_endpoints", []):
            report["findings"].append(normalize_finding(
                "idor_bola",
                f"IDOR/BOLA: {vuln_endpoint.get('description', 'Sequential ID accessible')}",
                "critical",
                vuln_endpoint,
                "CWE-639"
            ))

    if path_traversal_results.get("vulnerable"):
        # Path Traversal findings - critical severity
        for vuln_param in path_traversal_results.get("vulnerable_parameters", []):
            report["findings"].append(normalize_finding(
                "path_traversal",
                f"Path Traversal in parameter '{vuln_param.get('parameter')}'",
                "critical",
                vuln_param,
                "CWE-22"
            ))

    if default_creds_results.get("vulnerable"):
        # Default Credentials findings - critical severity
        for vuln_endpoint in default_creds_results.get("vulnerable_endpoints", []):
            report["findings"].append(normalize_finding(
                "default_credentials",
                f"Default credentials detected on {vuln_endpoint.get('endpoint')} (username: {vuln_endpoint.get('username')})",
                "critical",
                {
                    "endpoint": vuln_endpoint.get("endpoint"),
                    "username": vuln_endpoint.get("username"),
                    "credential_hash": vuln_endpoint.get("credential_hash"),
                    "auth_method": vuln_endpoint.get("auth_method"),
                    "warning": default_creds_results.get("warning")
                },
                "CWE-798"
            ))

    if deserialization_results.get("vulnerable"):
        # Deserialization findings - critical severity
        for vuln_endpoint in deserialization_results.get("vulnerable_endpoints", []):
            report["findings"].append(normalize_finding(
                "deserialization",
                f"Insecure Deserialization detected ({vuln_endpoint.get('type')})",
                "critical",
                vuln_endpoint,
                "CWE-502"
            ))

    # Phase 2 Access Control & Auth Findings
    if rate_limiting_results.get("vulnerable"):
        # Rate limiting findings - low severity
        for vuln_endpoint in rate_limiting_results.get("vulnerable_endpoints", []):
            report["findings"].append(normalize_finding(
                "rate_limiting",
                f"No rate limiting detected on {vuln_endpoint.get('endpoint')}",
                "low",
                vuln_endpoint,
                "CWE-307"
            ))

    if twofa_bypass_results.get("vulnerable"):
        # 2FA bypass findings - critical severity
        for bypass_method in twofa_bypass_results.get("bypass_methods_detected", []):
            report["findings"].append(normalize_finding(
                "2fa_bypass",
                f"2FA bypass possible via {bypass_method.get('method')}",
                "critical",
                bypass_method,
                "CWE-287"
            ))

    if password_reset_results.get("vulnerable"):
        # Password reset findings - critical/high severity
        for vuln in password_reset_results.get("vulnerabilities_found", []):
            severity = "critical" if vuln.get("type") in ["token_disclosure", "host_header_injection"] else "high"
            report["findings"].append(normalize_finding(
                "password_reset",
                f"Password reset vulnerability: {vuln.get('description')}",
                severity,
                vuln,
                "CWE-640"
            ))

    if session_mgmt_results.get("vulnerable"):
        # Session management findings - medium/high severity
        for issue in session_mgmt_results.get("issues_found", []):
            severity = issue.get("severity", "medium")
            report["findings"].append(normalize_finding(
                "session_management",
                f"Session management issue: {issue.get('type')}",
                severity,
                issue,
                "CWE-384" if issue.get("type") == "session_in_url" else "CWE-614"
            ))

    if password_policy_results.get("vulnerable"):
        for issue in password_policy_results.get("issues", []):
            report["findings"].append(normalize_finding(
                "password_policy",
                f"Weak password policy: {issue.get('detail', 'weak constraints')}",
                issue.get("severity", "medium"),
                issue,
                "CWE-521"
            ))

    if account_enum_results.get("vulnerable"):
        for issue in account_enum_results.get("issues", []):
            severity = issue.get("severity", "medium")
            report["findings"].append(normalize_finding(
                "account_enumeration",
                f"Account enumeration risk: {issue.get('type')}",
                severity,
                issue,
                "CWE-204"
            ))

    if bruteforce_results.get("vulnerable"):
        for issue in bruteforce_results.get("issues", []):
            report["findings"].append(normalize_finding(
                "bruteforce_protection",
                f"Brute-force protection missing: {issue.get('endpoint')}",
                issue.get("severity", "low"),
                issue,
                "CWE-307"
            ))

    if http_methods_results.get("vulnerable"):
        if http_methods_results.get("trace_enabled"):
            report["findings"].append(normalize_finding(
                "http_methods",
                "HTTP TRACE method enabled",
                "high",
                http_methods_results.get("trace_evidence", {}),
                "CWE-200"
            ))
        for risky in http_methods_results.get("risky_methods", []):
            report["findings"].append(normalize_finding(
                "http_methods",
                f"Risky HTTP methods advertised: {', '.join(risky.get('methods', []))}",
                "medium",
                risky,
                "CWE-650"
            ))

    # Phase 3a Client-Side Security Findings
    if js_deps_results.get("vulnerable"):
        # JavaScript dependency vulnerabilities - severity depends on CVE
        for lib in js_deps_results.get("vulnerable_libraries", []):
            for vuln in lib.get("vulnerabilities", []):
                report["findings"].append(normalize_finding(
                    "js_dependency",
                    f"Vulnerable JavaScript Library: {lib['library']} {lib['version']} ({vuln['cve']})",
                    vuln["severity"],
                    {
                        "library": lib["library"],
                        "version": lib["version"],
                        "url": lib["url"],
                        "cve": vuln["cve"],
                        "summary": vuln["summary"],
                        "fixed_in": vuln["fixed_in"]
                    },
                    "CWE-829"
                ))

    if js_secrets_results.get("vulnerable"):
        # Hardcoded secrets in JavaScript - critical severity
        for secret in js_secrets_results.get("secrets_found", []):
            report["findings"].append(normalize_finding(
                "js_secret",
                f"Hardcoded Secret in JavaScript: {secret['description']}",
                secret["severity"],
                {
                    "type": secret["type"],
                    "description": secret["description"],
                    "file": secret["file"],
                    "value_preview": secret["value_preview"],
                    "line_number": secret.get("line_number"),
                    "context": secret.get("context"),
                    "risk": secret["risk"]
                },
                "CWE-798"
            ))

    if client_side_results.get("vulnerable"):
        for finding in client_side_results.get("findings", []):
            severity = finding.get("severity", "low")
            title = "Client-Side Issue"
            if finding.get("type") == "postmessage_origin_check_missing":
                title = "postMessage handler without origin validation"
            elif finding.get("type") == "prototype_pollution_sink":
                title = "Potential prototype pollution sink"
            report["findings"].append(normalize_finding(
                "client_side",
                title,
                severity,
                {
                    "type": finding.get("type"),
                    "file": finding.get("file"),
                    "line_number": finding.get("line_number"),
                    "evidence": finding.get("evidence"),
                },
                "CWE-345" if finding.get("type") == "postmessage_origin_check_missing" else "CWE-1321"
            ))

    # Phase 3b Infrastructure & Configuration Leak Findings
    if cicd_results.get("vulnerable"):
        # CI/CD file exposure - high severity
        for exposed_file in cicd_results.get("exposed_files", []):
            severity = "critical" if exposed_file.get("secrets_found") else "high"
            report["findings"].append(normalize_finding(
                "cicd_exposure",
                f"Exposed CI/CD Configuration File: {exposed_file['file']}",
                severity,
                {
                    "file": exposed_file["file"],
                    "url": exposed_file["url"],
                    "size_bytes": exposed_file["size_bytes"],
                    "secrets_found": exposed_file.get("secrets_found", []),
                    "preview": exposed_file.get("preview", "")
                },
                "CWE-540"
            ))

    if package_results.get("vulnerable"):
        # Package manager file exposure - medium severity
        for exposed_file in package_results.get("exposed_files", []):
            report["findings"].append(normalize_finding(
                "package_exposure",
                f"Exposed Package Manager File: {exposed_file['file']}",
                "medium",
                {
                    "file": exposed_file["file"],
                    "url": exposed_file["url"],
                    "size_bytes": exposed_file["size_bytes"]
                },
                "CWE-219"
            ))

    if cloud_bucket_results.get("vulnerable"):
        # Public cloud storage buckets - critical severity
        for bucket in cloud_bucket_results.get("public_buckets", []):
            report["findings"].append(normalize_finding(
                "cloud_bucket",
                f"Publicly Accessible Cloud Storage Bucket: {bucket['bucket_name']} ({bucket['provider']})",
                "critical",
                {
                    "provider": bucket["provider"],
                    "bucket_name": bucket["bucket_name"],
                    "url": bucket["url"],
                    "readable": bucket.get("readable", False),
                    "sample_files": bucket.get("sample_files", [])
                },
                "CWE-552"
            ))

    if backup_file_results.get("vulnerable"):
        # Exposed backup files - critical severity
        for backup_file in backup_file_results.get("exposed_backups", []):
            report["findings"].append(normalize_finding(
                "backup_file",
                f"Exposed Backup File: {backup_file['file']}",
                "critical",
                {
                    "file": backup_file["file"],
                    "url": backup_file["url"],
                    "size_bytes": backup_file["size_bytes"],
                    "size_human": backup_file["size_human"]
                },
                "CWE-219"
            ))

    if directory_listing_results.get("vulnerable"):
        for directory in directory_listing_results.get("exposed_directories", []):
            report["findings"].append(normalize_finding(
                "directory_listing",
                f"Directory listing enabled: {directory.get('directory')}",
                "medium",
                {
                    "directory": directory.get("directory"),
                    "url": directory.get("url"),
                    "content_preview": directory.get("content_preview"),
                },
                "CWE-548"
            ))

    # New Security Enhancement Findings (IP Reputation, Brand Protection, Enhanced DNS, Cloud Security)

    # IP Reputation findings
    if ip_rep_results.get("blacklisted"):
        for bl in ip_rep_results.get("blacklists", []):
            report["findings"].append(normalize_finding(
                "ip_reputation",
                f"IP Blacklisted: {bl.get('list', 'Unknown blacklist')}",
                "high",
                {
                    "ip": ip_rep_results.get("ip"),
                    "blacklist": bl.get("list"),
                    "response_code": bl.get("response_code"),
                    "meaning": bl.get("meaning")
                },
                "CWE-400"  # Uncontrolled Resource Consumption
            ))
    if ip_rep_results.get("threat_indicators"):
        for indicator in ip_rep_results.get("threat_indicators", []):
            report["findings"].append(normalize_finding(
                "ip_reputation",
                f"Threat Intelligence: {indicator.get('type', 'Unknown threat')}",
                indicator.get("severity", "medium"),
                {
                    "ip": ip_rep_results.get("ip"),
                    "indicator_type": indicator.get("type"),
                    "source": indicator.get("source"),
                    "details": indicator.get("details")
                },
                "CWE-693"  # Protection Mechanism Failure
            ))

    # Brand Protection / Typosquatting findings
    # NOTE: Downgraded to "info" - these are speculative findings (domain exists,
    # but may be legitimate). The domain owner can investigate if needed.
    if typosquat_results.get("high_risk_count", 0) > 0:
        for domain in typosquat_results.get("suspicious_domains", []):
            if domain.get("risk_score", 0) >= 75:
                report["findings"].append(normalize_finding(
                    "typosquatting",
                    f"High-Risk Typosquatting Domain: {domain.get('domain', 'Unknown')}",
                    "info",  # Downgraded from medium - speculative, not a confirmed vulnerability
                    {
                        "original_domain": typosquat_results.get("original_domain"),
                        "typosquat_domain": domain.get("domain"),
                        "permutation_type": domain.get("permutation_type"),
                        "risk_score": domain.get("risk_score"),
                        "has_mx": domain.get("has_mx", False),
                        "ip": domain.get("ip")
                    },
                    "CWE-451"  # User Interface (UI) Misrepresentation
                ))

    # Domain Intelligence findings
    if domain_intel_results.get("findings"):
        for finding in domain_intel_results.get("findings", []):
            if finding.get("severity") not in ["info"]:  # Skip info-level findings
                report["findings"].append(normalize_finding(
                    "domain_intelligence",
                    finding.get("title", "Domain Intelligence Issue"),
                    finding.get("severity", "medium"),
                    {
                        "domain": domain_intel_results.get("domain"),
                        "description": finding.get("description"),
                        "age_days": domain_intel_results.get("age_analysis", {}).get("age_days"),
                        "days_until_expiry": domain_intel_results.get("expiration_analysis", {}).get("days_until_expiry"),
                        "registrar": domain_intel_results.get("whois", {}).get("registrar"),
                        "creation_date": domain_intel_results.get("whois", {}).get("creation_date"),
                        "expiration_date": domain_intel_results.get("whois", {}).get("expiration_date"),
                    },
                    finding.get("cwe", "CWE-200")  # Information Exposure
                ))

    # CT Monitoring findings
    if ct_monitor_results.get("findings"):
        for finding in ct_monitor_results.get("findings", []):
            if finding.get("severity") not in ["info"]:  # Skip info-level findings
                report["findings"].append(normalize_finding(
                    "ct_monitor",
                    finding.get("title", "Certificate Transparency Issue"),
                    finding.get("severity", "medium"),
                    {
                        "domain": ct_monitor_results.get("domain"),
                        "description": finding.get("description"),
                        "certificates_found": ct_monitor_results.get("certificates_found"),
                        "ca_diversity": ct_monitor_results.get("ca_diversity", {}).get("unique_cas"),
                        "suspicious_count": len(ct_monitor_results.get("suspicious_certificates", [])),
                    },
                    finding.get("cwe", "CWE-295")  # Certificate Validation
                ))

    # SMTP Security findings
    if smtp_security_results.get("findings"):
        for finding in smtp_security_results.get("findings", []):
            if finding.get("severity") not in ["info"]:  # Skip info-level findings
                report["findings"].append(normalize_finding(
                    "smtp_scanner",
                    finding.get("title", "SMTP Security Issue"),
                    finding.get("severity", "medium"),
                    {
                        "domain": smtp_security_results.get("domain"),
                        "description": finding.get("description"),
                        "remediation": finding.get("remediation"),
                        "evidence": finding.get("evidence", {}),
                    },
                    finding.get("cwe", "CWE-319")  # Cleartext Transmission
                ))

    # ASN Discovery findings
    if asn_discovery_results.get("findings"):
        for finding in asn_discovery_results.get("findings", []):
            if finding.get("severity") not in ["info"]:  # Skip info-level findings
                report["findings"].append(normalize_finding(
                    "asn_discovery",
                    finding.get("title", "ASN Discovery Issue"),
                    finding.get("severity", "low"),
                    {
                        "domain": asn_discovery_results.get("domain"),
                        "description": finding.get("description"),
                        "remediation": finding.get("remediation"),
                        "evidence": finding.get("evidence", {}),
                    },
                    finding.get("cwe", "CWE-693")  # Protection Mechanism Failure
                ))

    # Network Services findings
    if network_services_results.get("findings"):
        for finding in network_services_results.get("findings", []):
            if finding.get("severity") not in ["info"]:  # Skip info-level findings
                report["findings"].append(normalize_finding(
                    "network_services",
                    finding.get("title", "Network Service Exposure"),
                    finding.get("severity", "medium"),
                    {
                        "host": network_services_results.get("host"),
                        "description": finding.get("description"),
                        "remediation": finding.get("remediation"),
                        "evidence": finding.get("evidence", {}),
                    },
                    finding.get("cwe", "CWE-200")  # Information Exposure
                ))

    # Enhanced DNS findings
    if zone_transfer_results.get("vulnerable"):
        for ns in zone_transfer_results.get("vulnerable_nameservers", []):
            report["findings"].append(normalize_finding(
                "zone_transfer",
                f"DNS Zone Transfer Allowed: {ns.get('nameserver', 'Unknown NS')}",
                "high",
                {
                    "domain": zone_transfer_results.get("domain"),
                    "nameserver": ns.get("nameserver"),
                    "records_exposed": ns.get("records_exposed", 0)
                },
                "CWE-200"  # Information Exposure
            ))

    # Cloud Security Enhancement findings

    # Cloud Metadata SSRF findings
    if cloud_ssrf_results.get("vulnerable"):
        for finding in cloud_ssrf_results.get("ssrf_findings", []):
            report["findings"].append(normalize_finding(
                "cloud_ssrf",
                f"Cloud Metadata SSRF: {finding.get('cloud_provider', 'Unknown provider')}",
                "critical",
                {
                    "url": finding.get("url"),
                    "parameter": finding.get("parameter"),
                    "cloud_provider": finding.get("cloud_provider"),
                    "metadata_type": finding.get("metadata_type"),
                    "sensitive_data_exposed": finding.get("sensitive_data_exposed", False)
                },
                "CWE-918"  # Server-Side Request Forgery
            ))

    # Kubernetes Exposure findings
    if k8s_results.get("vulnerable"):
        for endpoint in k8s_results.get("exposed_endpoints", []):
            report["findings"].append(normalize_finding(
                "kubernetes_exposure",
                f"Kubernetes API Exposed: {endpoint.get('path', 'Unknown endpoint')}",
                "critical",
                {
                    "url": endpoint.get("url"),
                    "path": endpoint.get("path"),
                    "port": endpoint.get("port"),
                    "api_version": endpoint.get("api_version"),
                    "resources_exposed": endpoint.get("resources_exposed", [])
                },
                "CWE-284"  # Improper Access Control
            ))

    # Terraform State Exposure findings
    if tf_results.get("vulnerable"):
        for tf_file in tf_results.get("exposed_files", []):
            report["findings"].append(normalize_finding(
                "terraform_exposure",
                f"Terraform State Exposed: {tf_file.get('path', 'terraform.tfstate')}",
                "critical",
                {
                    "url": tf_file.get("url"),
                    "path": tf_file.get("path"),
                    "size_bytes": tf_file.get("size_bytes"),
                    "contains_secrets": tf_file.get("contains_secrets", False),
                    "secret_types": tf_file.get("secret_types", [])
                },
                "CWE-540"  # Information Exposure Through Source Code
            ))

    # Container Registry Exposure findings
    if registry_results.get("vulnerable"):
        report["findings"].append(normalize_finding(
            "container_registry",
            f"Container Registry Exposed: {registry_results.get('registry_type', 'Unknown registry')}",
            "high",
            {
                "registry_type": registry_results.get("registry_type"),
                "catalog_accessible": registry_results.get("catalog_accessible", False),
                "repositories_count": len(registry_results.get("repositories", [])),
                "repositories_sample": registry_results.get("repositories", [])[:5]
            },
            "CWE-284"  # Improper Access Control
        ))

    # Phase 4 P1 Priority Checks Findings
    if file_upload_results.get("vulnerable"):
        # File upload vulnerabilities - high severity
        for endpoint in file_upload_results.get("upload_endpoints", []):
            if endpoint.get("vulnerable"):
                report["findings"].append(normalize_finding(
                    "file_upload",
                    f"File Upload Vulnerability: {endpoint.get('issue', 'Unrestricted file upload')}",
                    "high",
                    {
                        "url": endpoint.get("url"),
                        "form_action": endpoint.get("form_action"),
                        "accept_attribute": endpoint.get("accept"),
                        "issue": endpoint.get("issue")
                    },
                    "CWE-434"
                ))

    if open_redirect_results.get("vulnerable"):
        # Open redirect vulnerabilities - medium severity
        for redirect in open_redirect_results.get("confirmed_redirects", []):
            report["findings"].append(normalize_finding(
                "open_redirect",
                f"Open Redirect: {redirect.get('param', 'URL redirect parameter')}",
                "medium",
                {
                    "url": redirect.get("url"),
                    "param": redirect.get("param"),
                    "redirect_to": redirect.get("redirect_to"),
                    "type": redirect.get("type", "server")
                },
                "CWE-601"
            ))
        for js_redirect in open_redirect_results.get("javascript_redirects", []):
            report["findings"].append(normalize_finding(
                "open_redirect",
                f"JavaScript Open Redirect: {js_redirect.get('pattern', 'window.location manipulation')}",
                "medium",
                {
                    "url": js_redirect.get("url"),
                    "pattern": js_redirect.get("pattern"),
                    "type": "javascript"
                },
                "CWE-601"
            ))

    if host_header_results.get("vulnerable"):
        # Host header injection - high severity
        for reflection in host_header_results.get("header_reflection", []):
            report["findings"].append(normalize_finding(
                "host_header_injection",
                f"Host Header Injection: {reflection.get('header', 'X-Forwarded-Host')} reflected",
                "high",
                {
                    "url": reflection.get("url"),
                    "header": reflection.get("header"),
                    "reflected_in": reflection.get("reflected_in"),
                    "cache_poisoning_risk": reflection.get("cache_poisoning_risk", False)
                },
                "CWE-644"
            ))

    if business_logic_results.get("potential_issues"):
        # Business logic vulnerabilities - medium/high severity
        for issue in business_logic_results.get("potential_issues", []):
            severity = issue.get("severity", "medium")
            report["findings"].append(normalize_finding(
                "business_logic",
                f"Business Logic Issue: {issue.get('type', 'Potential manipulation')}",
                severity,
                {
                    "type": issue.get("type"),
                    "url": issue.get("url"),
                    "field": issue.get("field"),
                    "description": issue.get("description")
                },
                "CWE-840"
            ))

    if api_security_p4_results.get("vulnerable"):
        # API security / mass assignment - high/critical severity
        for risk in api_security_p4_results.get("mass_assignment_risks", []):
            report["findings"].append(normalize_finding(
                "mass_assignment",
                f"Mass Assignment Risk: {risk.get('field', 'sensitive field')} modifiable",
                "high",
                {
                    "url": risk.get("url"),
                    "field": risk.get("field"),
                    "field_type": risk.get("field_type")
                },
                "CWE-915"
            ))
        for endpoint in api_security_p4_results.get("bfla_endpoints", []):
            if endpoint.get("accessible"):
                severity = "critical" if "admin" in endpoint.get("path", "").lower() else "high"
                report["findings"].append(normalize_finding(
                    "bfla",
                    f"Broken Function Level Authorization: {endpoint.get('path')} accessible",
                    severity,
                    {
                        "url": endpoint.get("url"),
                        "path": endpoint.get("path"),
                        "status_code": endpoint.get("status_code")
                    },
                    "CWE-285"
                ))

    # Add web vulnerability check results to report
    report["file_upload"] = file_upload_results
    report["open_redirect"] = open_redirect_results
    report["host_header_injection"] = host_header_results
    report["business_logic"] = business_logic_results
    report["api_security_web"] = api_security_p4_results

    # Access Control - Forced Browsing Findings
    if forced_browsing_results.get("vulnerable"):
        # Add findings for accessible privileged endpoints
        for fb_finding in forced_browsing_results.get("findings", []):
            if fb_finding.get("severity") in ["critical", "high", "medium"]:
                severity = fb_finding.get("severity", "medium")
                path = fb_finding.get("path", "")
                status = fb_finding.get("status_code", "unknown")
                category = fb_finding.get("category", "unknown")

                # Map category to readable name
                category_names = {
                    "admin_panels": "Admin Panel",
                    "api_endpoints": "API Endpoint",
                    "management_consoles": "Management Console",
                    "debug_dev": "Debug/Development Endpoint",
                    "sensitive_files": "Sensitive File",
                    "backup_files": "Backup File",
                    "user_management": "User Management Endpoint",
                    "logs_monitoring": "Log/Monitoring Endpoint",
                }
                category_name = category_names.get(category, category.replace("_", " ").title())

                report["findings"].append(normalize_finding(
                    "forced_browsing",
                    f"Accessible {category_name}: {path}",
                    severity,
                    {
                        "url": fb_finding.get("url"),
                        "path": path,
                        "status_code": status,
                        "category": category,
                        "content_type": fb_finding.get("content_type"),
                        "content_length": fb_finding.get("content_length"),
                        "accessible": fb_finding.get("accessible", False),
                        "verified": bool(
                            fb_finding.get("accessible")
                            and not fb_finding.get("false_positive_detected")
                            and not fb_finding.get("content_validation_failed")
                        ),
                        "validation_reason": (
                            fb_finding.get("validation_reason")
                            or "Forced browsing content validation accepted this response"
                        ),
                    },
                    "CWE-425"  # Direct Request (Forced Browsing)
                ))

    # Mass Assignment Findings
    if mass_assignment_results.get("vulnerable"):
        for ma_finding in mass_assignment_results.get("findings", []):
            report["findings"].append(normalize_finding(
                "mass_assignment",
                ma_finding.get("title", "Mass Assignment Vulnerability"),
                ma_finding.get("severity", "high"),
                ma_finding.get("evidence", {}),
                "CWE-915"  # Mass Assignment
            ))

    # BOLA/IDOR Findings
    if bola_results.get("vulnerable"):
        for bola_finding in bola_results.get("findings", []):
            report["findings"].append(normalize_finding(
                "bola_idor",
                bola_finding.get("title", "Broken Object Level Authorization"),
                bola_finding.get("severity", "critical"),
                bola_finding.get("evidence", {}),
                "CWE-639"  # BOLA/IDOR
            ))

    # Race Condition Findings
    if race_condition_results.get("vulnerable_endpoints", 0) > 0:
        for race_finding in race_condition_results.get("findings", []):
            severity = race_finding.get("severity", "high")
            report["findings"].append(normalize_finding(
                "race_condition",
                race_finding.get("type", "Race Condition Vulnerability"),
                severity,
                {
                    "endpoint": race_finding.get("endpoint"),
                    "method": race_finding.get("method"),
                    "evidence": race_finding.get("evidence"),
                    "confidence": race_finding.get("confidence"),
                    "details": race_finding.get("details", {}),
                    "recommendation": "Implement proper synchronization mechanisms such as database transactions, optimistic locking, or mutex/semaphores"
                },
                race_finding.get("cwe", "CWE-362")
            ))

    # Add access control results to report
    report["access_control"] = {
        "forced_browsing": forced_browsing_results,
        "mass_assignment": mass_assignment_results,
        "bola": bola_results,
        "race_conditions": race_condition_results,
    }

    # Add SSH scan results to report and process findings
    if ssh_results.get("scan_completed"):
        report["ssh"] = ssh_results
        # Process SSH findings
        for ssh_finding in ssh_results.get("findings", []):
            report["findings"].append(normalize_finding(
                "ssh_scanner",
                ssh_finding.get("title", "SSH Configuration Issue"),
                ssh_finding.get("severity", "medium"),
                ssh_finding.get("evidence", {}),
                ssh_finding.get("cwe", "CWE-287")
            ))

    # Optional: API testing (explicit or smart-discovered OpenAPI)
    if schemathesis_task:
        api_rep = await schemathesis_task
        report["api"] = {
            "openapi": schemathesis_schema_url,
            "schemathesis": api_rep,
            "source": "auto_discovery",
        }
    elif openapi_url:
        api_rep = await schemathesis_run(openapi_url, api_token, base_url=None, auth_session=auth_session)
        report["api"] = {"openapi": openapi_url, "schemathesis": api_rep, "source": "explicit"}

    if isinstance(report.get("api"), dict):
        api_rep = report["api"].get("schemathesis")
        # Normalize simple high level finding if errors present
        if isinstance(api_rep, dict) and api_rep.get("errors"):
            report["findings"].append(normalize_finding(
                "schemathesis", "OpenAPI test errors", "medium", {"errors": api_rep.get("errors")}
            ))

    # Optional: active checks (sampled outside of smart/complete mode)
    if active_checks and not public_only:
        dalfox_deep_domxss = deep_domxss
        if dalfox_deep_domxss is None and (exploit_level == "aggressive" or complete_tier == "aggressive"):
            dalfox_deep_domxss = True
        if auth_session:
            await auth_session.refresh_if_needed()
        # Reuse already-discovered URLs from main discovery phase (avoid duplicate katana call)
        discovery_data = report.get("discovery", {})
        # browser_api_endpoints may contain dicts with "url" key or strings
        browser_endpoints = discovery_data.get("browser_api_endpoints", [])
        browser_urls = [e.get("url") if isinstance(e, dict) else e for e in browser_endpoints]
        discovery_urls = crawl_urls if (smart_mode or complete_mode) else crawl_urls[:100]
        all_discovered = [u for u in (discovery_urls + browser_urls + manual_urls) if u and isinstance(u, str)]

        # Filter out documentation/non-functional endpoints (these don't have vulnerabilities)
        doc_patterns = [
            'swagger', 'openapi', 'api-docs', 'redoc', 'swagger-ui',
            '/docs', '/schema', '/schemas',
            'openapi.json', 'swagger.json', 'openapi.yaml', 'swagger.yaml'
        ]
        def is_documentation_url(url: str) -> bool:
            url_lower = url.lower()
            return any(p in url_lower for p in doc_patterns)

        # Filter out external URLs and documentation
        functional_urls = [
            u for u in all_discovered
            if is_in_scope_url(u, base_url) and not is_documentation_url(u)
        ]

        # Build URL categories from functional endpoints only
        parameterized_urls = [u for u in functional_urls if "?" in u]

        # API endpoints - exclude documentation
        api_endpoints = [u for u in functional_urls
                        if any(p in u for p in ["/api/", "/rest/", "/v1/", "/v2/", "/graphql"])]

        # High-value targets for injection testing
        search_urls = [u for u in functional_urls if "search" in u.lower()]
        login_urls = [u for u in functional_urls if any(f in u.lower() for f in ["login", "signin", "auth", "user"])]
        product_urls = [u for u in functional_urls if any(f in u.lower() for f in ["product", "item", "order", "cart"])]
        form_urls = [u for u in functional_urls if any(f in u.lower() for f in ["register", "signup", "contact", "feedback", "comment"])]

        # Smart parameter generation based on endpoint type
        def add_smart_params(url: str) -> list[str]:
            """Generate test URLs with appropriate parameters based on endpoint type."""
            if "?" in url:
                return [url]  # Already has params

            url_lower = url.lower()
            results = []

            # Search endpoints - use q= parameter (most common for SQLi/XSS)
            if "search" in url_lower:
                results.append(f"{url}?q=test")
                results.append(f"{url}?q=1")
                results.append(f"{url}?query=test")
            # Product/item endpoints - use id= parameter
            elif any(p in url_lower for p in ["product", "item", "order"]):
                results.append(f"{url}?id=1")
                results.append(f"{url}?id=test")
            # User/login endpoints - use common auth params
            elif any(p in url_lower for p in ["user", "login", "auth"]):
                results.append(f"{url}?id=1")
                results.append(f"{url}?username=test")
                results.append(f"{url}?email=test@test.com")
            # Feedback/comment endpoints - common XSS targets
            elif any(p in url_lower for p in ["feedback", "comment", "review"]):
                results.append(f"{url}?comment=test")
                results.append(f"{url}?message=test")
            # Generic API endpoints
            else:
                results.append(f"{url}?id=1")
                results.append(f"{url}?q=test")

            return results

        # Prioritize URLs for testing - HIGH VALUE TARGETS FIRST
        candidates = []

        # HIGHEST priority: Search endpoints (most likely SQLi/XSS)
        for url in search_urls[:max_active//3]:
            candidates.extend(add_smart_params(url))

        # HIGH priority: Login/user endpoints (auth bypass, SQLi)
        for url in login_urls[:max_active//4]:
            candidates.extend(add_smart_params(url))

        # HIGH priority: Product/data endpoints (SQLi, IDOR)
        for url in product_urls[:max_active//4]:
            candidates.extend(add_smart_params(url))

        # MEDIUM priority: URLs with existing parameters
        candidates.extend(parameterized_urls[:max_active//3])

        # MEDIUM priority: Other API endpoints
        for api_url in api_endpoints[:max_active//3]:
            candidates.extend(add_smart_params(api_url))

        # LOWER priority: Form URLs (registration, contact)
        for form_url in form_urls[:max_active//4]:
            candidates.extend(add_smart_params(form_url))

        # Track discovered URLs before adding synthetic (discovered wins over synthetic)
        discovered_urls = set(candidates)

        # If still need more URLs, create synthetic high-value endpoints
        synthetic_skipped_reason = None
        api_hint = (
            any("/api/" in u or "/rest/" in u or "/graphql" in u for u in functional_urls)
            or bool(har_test_targets)
            or bool(browser_api_endpoints)
            or bool(manual_endpoints_norm)
        )
        if len(candidates) < max_active:
            if api_hint or thorough_params:
                synthetic_endpoints = [
                    # High-value injection targets
                    "/rest/products/search", "/api/products/search", "/search",
                    "/rest/user/login", "/api/user/login", "/api/login",
                    "/api/users", "/rest/users", "/api/user",
                    "/api/products", "/rest/products",
                    "/api/feedbacks", "/rest/feedbacks",
                    "/api/orders", "/rest/orders",
                    # Common vulnerable endpoints
                    "/api/data", "/rest/data",
                    "/admin", "/api/admin",
                ]
                for endpoint in synthetic_endpoints:
                    test_url = urllib.parse.urljoin(base_url, endpoint)
                    synthetic_params = add_smart_params(test_url)
                    candidates.extend(synthetic_params)
                    if len(candidates) >= max_active * 2:  # Generate more, will dedupe
                        break
            else:
                synthetic_skipped_reason = "Skipped synthetic endpoints (no API hints detected; enable --thorough-params to force)"

        # de-dup and cap; mark as synthetic only if not already discovered
        seen = set()
        cand = []
        cand_synthetic = set()
        for u in candidates:
            if u not in seen:
                seen.add(u)
                cand.append(u)
                if u not in discovered_urls:
                    cand_synthetic.add(u)
            if len(cand) >= max_active:
                break

        run_xss = bool(active_xss)
        run_sqli = bool(active_sqli)
        active_block = {
            "targets": cand,
            "dalfox": [],
            "sqlmap": [],
            "custom_sqli": [],
            "custom_xss": [],
            "filters": {"xss": run_xss, "sqli": run_sqli},
        }
        if synthetic_skipped_reason:
            active_block.setdefault("warnings", []).append(synthetic_skipped_reason)
        if cand_synthetic:
            active_block["synthetic_targets_count"] = len(cand_synthetic)
            active_block["synthetic_targets_sample"] = list(cand_synthetic)[:10]

        # Smart mode: Use DBMS-aware and context-aware active tests
        if smart_mode:
            try:
                # P1-2 FIX: Early DBMS detection for smarter SQLi testing
                # Detect DBMS before building test plan to use DBMS-specific payloads
                early_dbms = None
                if run_sqli and cand:
                    try:
                        # ARCHITECTURE FIX: Intelligent URL selection for DBMS fingerprinting
                        # Prioritize HAR-discovered endpoints (real DB interaction) over arbitrary URLs
                        db_param_patterns = ["id", "user", "query", "search", "filter", "sort", "order", "page", "limit"]

                        def score_url_for_dbms(url: str, is_har: bool = False) -> int:
                            """Score URL for DBMS probing priority (higher = better)."""
                            score = 0
                            url_lower = url.lower()
                            if is_har:
                                score += 100  # HAR-discovered = highest priority
                            if any(f"{p}=" in url_lower for p in db_param_patterns):
                                score += 50  # Has DB-like parameters
                            if "/api/" in url_lower or "/rest/" in url_lower:
                                score += 30  # API endpoint
                            if "?" in url:
                                score += 10  # Has parameters
                            return score

                        # Collect candidate URLs with scores
                        scored_urls = []
                        # Add HAR endpoints with high priority
                        if har_test_targets:
                            for target in har_test_targets[:10]:
                                url = target.get("url", "")
                                if url and "?" in url:
                                    scored_urls.append((score_url_for_dbms(url, is_har=True), url))
                        # Add discovered URLs
                        for u in cand:
                            if "?" in u:
                                scored_urls.append((score_url_for_dbms(u), u))

                        # Sort by score (highest first), take top 5
                        scored_urls.sort(key=lambda x: x[0], reverse=True)
                        param_urls = [url for _, url in scored_urls[:5]]

                        for probe_url in param_urls:
                            dbms_result = await detect_dbms(probe_url)
                            if dbms_result.get("dbms") and dbms_result.get("confidence", 0) > 0.5:
                                early_dbms = dbms_result["dbms"]
                                print(
                                    f"[smart] Early DBMS detection: {early_dbms} "
                                    f"(confidence: {dbms_result.get('confidence', 0):.0%})",
                                    file=sys.stderr
                                )
                                break
                    except Exception as e:
                        print(f"[smart] Early DBMS detection failed: {e}", file=sys.stderr)

                # Build endpoints dict for smart testing (GET params from discovered URLs)
                endpoints = []
                endpoint_index = {}

                def _dedupe_list(items):
                    seen_items = set()
                    deduped = []
                    for item in items or []:
                        if item not in seen_items:
                            seen_items.add(item)
                            deduped.append(item)
                    return deduped

                def _normalize_endpoint_url(url: str) -> str:
                    parsed = urllib.parse.urlparse(url)
                    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))

                def _normalize_allowed_methods(methods):
                    allowed = []
                    for raw in methods or []:
                        if not raw:
                            continue
                        method = str(raw).strip().upper()
                        if not method or method in allowed:
                            continue
                        allowed.append(method)
                    return allowed

                options_methods_by_url: dict[str, list[str]] = {}
                if options_method_results and options_method_results.get("methods_by_url"):
                    for opt_url, methods in (options_method_results.get("methods_by_url") or {}).items():
                        if not opt_url or not methods:
                            continue
                        normalized = _normalize_endpoint_url(opt_url)
                        filtered = [
                            m for m in _normalize_allowed_methods(methods)
                            if m in ("GET", "POST", "PUT", "PATCH", "DELETE")
                        ]
                        if filtered:
                            options_methods_by_url[normalized] = filtered
                debug_endpoint_discovery = os.environ.get("SCANNER_DEBUG_ENDPOINTS", "").lower() in ("1", "true", "yes")
                if debug_endpoint_discovery and options_methods_by_url:
                    print(
                        f"[DEBUG OPTIONS] methods_by_url={len(options_methods_by_url)}",
                        file=sys.stderr
                    )
                    for i, (opt_url, methods) in enumerate(list(options_methods_by_url.items())[:5]):
                        print(
                            f"[DEBUG OPTIONS]   {i}: {opt_url} -> {methods}",
                            file=sys.stderr
                        )

                # Source priority for endpoint testing (lower = higher priority)
                # Real discovered endpoints should be tested before synthetic/inferred
                _SOURCE_PRIORITY = {
                    "har_discovery": 1,  # Actually observed in browser network
                    "manual": 2,         # User-specified endpoints
                    "openapi": 3,        # From OpenAPI/Swagger spec
                    "form": 4,           # Discovered from HTML forms
                    "common": 5,         # Well-known endpoints like /rest/user/login
                    "options": 6,        # Discovered via OPTIONS method
                    "inferred": 7,       # Synthetic endpoints guessed from patterns
                }
                _DEFAULT_SOURCE_PRIORITY = 6

                def _merge_endpoint(new_ep):
                    url = new_ep.get("url")
                    if not url:
                        return False
                    method = (new_ep.get("method") or "GET").upper()
                    new_ep["method"] = method
                    normalized_url = _normalize_endpoint_url(url)
                    if normalized_url in options_methods_by_url:
                        allowed = _dedupe_list(
                            (new_ep.get("allowed_methods") or []) + options_methods_by_url[normalized_url]
                        )
                        if allowed:
                            new_ep["allowed_methods"] = allowed
                    key = (url, method)
                    existing = endpoint_index.get(key)
                    if not existing:
                        endpoints.append(new_ep)
                        endpoint_index[key] = new_ep
                        return True
                    for list_key in ("params", "body_params", "body_required_params"):
                        if new_ep.get(list_key):
                            existing[list_key] = _dedupe_list(
                                (existing.get(list_key) or []) + list(new_ep.get(list_key))
                            )
                    if new_ep.get("body_param_defaults"):
                        defaults = dict(existing.get("body_param_defaults") or {})
                        defaults.update(new_ep.get("body_param_defaults") or {})
                        existing["body_param_defaults"] = defaults
                    if new_ep.get("param_defaults"):
                        defaults = dict(existing.get("param_defaults") or {})
                        defaults.update(new_ep.get("param_defaults") or {})
                        existing["param_defaults"] = defaults
                    if new_ep.get("body_template") and not existing.get("body_template"):
                        existing["body_template"] = new_ep.get("body_template")
                    if new_ep.get("content_type") and not existing.get("content_type"):
                        existing["content_type"] = new_ep["content_type"]
                    if new_ep.get("allowed_methods"):
                        existing["allowed_methods"] = _dedupe_list(
                            (existing.get("allowed_methods") or []) + list(new_ep.get("allowed_methods"))
                        )
                    # Keep the highest-priority source (lower number = higher priority)
                    new_source = new_ep.get("source", "")
                    existing_source = existing.get("source", "")
                    new_priority = _SOURCE_PRIORITY.get(new_source, _DEFAULT_SOURCE_PRIORITY)
                    existing_priority = _SOURCE_PRIORITY.get(existing_source, _DEFAULT_SOURCE_PRIORITY)
                    if new_priority < existing_priority:
                        existing["source"] = new_source
                    return False

                manual_get_count = 0
                manual_post_count = 0
                if manual_endpoints_norm:
                    for ep in manual_endpoints_norm:
                        if not isinstance(ep, dict):
                            continue
                        ep_url = ep.get("url")
                        if not ep_url:
                            continue
                        method = (ep.get("method") or "GET").upper()
                        if method == "GET":
                            params = ep.get("params") or []
                            param_defaults = ep.get("param_defaults") or {}
                            if not params and param_defaults:
                                params = list(param_defaults.keys())
                            if params and _merge_endpoint({
                                "url": ep_url,
                                "method": "GET",
                                "params": params,
                                "param_defaults": param_defaults,
                                "source": "manual",
                            }):
                                manual_get_count += 1
                        elif method in ("POST", "PUT", "PATCH"):
                            body_params = ep.get("body_params") or ep.get("params") or []
                            if body_params and _merge_endpoint({
                                "url": ep_url,
                                "method": method,
                                "body_params": body_params,
                                "body_required_params": ep.get("body_required_params") or body_params,
                                "body_param_defaults": ep.get("body_param_defaults") or {},
                                "body_template": ep.get("body_template"),
                                "content_type": ep.get("content_type") or "application/json",
                                "source": "manual",
                            }):
                                manual_post_count += 1
                if manual_get_count or manual_post_count:
                    print(
                        f"[scanner] Added {manual_get_count} GET and {manual_post_count} POST manual endpoints to smart testing",
                        file=sys.stderr
                    )

                for u in cand:
                    parsed = urllib.parse.urlparse(u)
                    params = list(urllib.parse.parse_qs(parsed.query, keep_blank_values=True).keys())
                    # Real discovered endpoints get har_discovery priority; synthetic fallbacks get inferred
                    source = "inferred" if u in cand_synthetic else "har_discovery"
                    _merge_endpoint({"url": u, "method": "GET", "params": params, "source": source})

                # Add inferred parameter endpoints from smart discovery (even if no query string)
                if smart_discovery_data:
                    for endpoint in smart_discovery_data.get("endpoints_with_params", []) or []:
                        if not isinstance(endpoint, dict):
                            continue
                        ep_url = endpoint.get("url")
                        params = endpoint.get("params") or []
                        if ep_url and params:
                            _merge_endpoint({"url": ep_url, "method": "GET", "params": params, "source": "har_discovery"})
                    for ep_url, params in (smart_discovery_data.get("discovered_params") or {}).items():
                        if ep_url and params:
                            _merge_endpoint({"url": ep_url, "method": "GET", "params": params, "source": "har_discovery"})

                # Add form-discovered endpoints (POST/GET) from discovery
                def _is_token_param(name: str) -> bool:
                    name_l = name.lower()
                    return any(
                        token in name_l for token in
                        ("csrf", "xsrf", "authenticity", "nonce", "token", "_token", "__requestverificationtoken")
                    )

                def _iter_form_inputs(raw_inputs):
                    if isinstance(raw_inputs, dict):
                        for key, value in raw_inputs.items():
                            if isinstance(value, dict):
                                item = {"name": key, **value}
                            else:
                                item = {"name": key, "value": value}
                            yield item
                    elif isinstance(raw_inputs, list):
                        for item in raw_inputs:
                            yield item
                    elif isinstance(raw_inputs, str):
                        yield raw_inputs

                def _normalize_form_url(form: dict) -> str | None:
                    action = (
                        form.get("action")
                        or form.get("form_action")
                        or form.get("endpoint")
                        or form.get("url")
                        or form.get("target")
                    )
                    page_url = (
                        form.get("page")
                        or form.get("page_url")
                        or form.get("source")
                        or form.get("referrer")
                    )
                    action = str(action or "").strip()
                    if not action or action == "#":
                        action = str(page_url or base_url).strip()
                    if action.startswith("javascript:") or action.startswith("mailto:"):
                        return None
                    if page_url and not str(page_url).startswith(("http://", "https://")):
                        page_url = urllib.parse.urljoin(base_url, str(page_url))
                    return urllib.parse.urljoin(page_url or base_url, action)

                def _form_content_type(form: dict) -> str:
                    enctype = (form.get("enctype") or form.get("enc_type") or form.get("content_type") or "").lower()
                    if "multipart/form-data" in enctype:
                        return "multipart/form-data"
                    if "application/json" in enctype:
                        return "application/json"
                    if "text/plain" in enctype:
                        return "text/plain"
                    return "application/x-www-form-urlencoded"

                def _extract_form_fields(form: dict) -> tuple[list[str], list[str], dict[str, Any]]:
                    raw_inputs = (
                        form.get("inputs")
                        or form.get("fields")
                        or form.get("params")
                        or form.get("form_fields")
                        or form.get("input")
                        or []
                    )
                    body_params = []
                    required_params = []
                    defaults: dict[str, Any] = {}
                    for item in _iter_form_inputs(raw_inputs):
                        name = None
                        input_type = ""
                        required = False
                        value = None
                        if isinstance(item, str):
                            name = item
                        elif isinstance(item, dict):
                            name = item.get("name") or item.get("id") or item.get("key")
                            input_type = (item.get("type") or item.get("input_type") or "").lower()
                            required = bool(item.get("required") or item.get("is_required"))
                            value = item.get("value") if item.get("value") is not None else item.get("default")
                        if not name:
                            continue
                        if input_type in ("submit", "button", "reset", "image"):
                            continue
                        if input_type == "file":
                            continue
                        if value not in (None, ""):
                            defaults[name] = value
                        if _is_token_param(name):
                            continue
                        body_params.append(name)
                        if required:
                            required_params.append(name)
                    if not body_params and defaults:
                        body_params = list(defaults.keys())
                    return _dedupe_list(body_params), _dedupe_list(required_params), defaults

                if smart_discovery_data:
                    forms = smart_discovery_data.get("forms", []) or []
                    form_post_count = 0
                    form_get_count = 0
                    for form in forms:
                        if not isinstance(form, dict):
                            continue
                        form_url = _normalize_form_url(form)
                        if not form_url:
                            continue
                        method = (form.get("method") or form.get("http_method") or form.get("form_method") or "POST").upper()
                        params, required_params, defaults = _extract_form_fields(form)
                        if not params:
                            continue
                        if method == "GET":
                            _merge_endpoint({"url": form_url, "method": "GET", "params": params, "source": "form"})
                            form_get_count += 1
                        elif method in ("POST", "PUT", "PATCH"):
                            _merge_endpoint({
                                "url": form_url,
                                "method": method,
                                "body_params": params,
                                "body_required_params": required_params,
                                "body_param_defaults": defaults,
                                "content_type": _form_content_type(form),
                                "source": "form",
                            })
                            form_post_count += 1
                    if form_post_count or form_get_count:
                        print(
                            f"[scanner] Added {form_get_count} GET and {form_post_count} POST endpoints from form discovery",
                            file=sys.stderr
                        )

                # Discover OpenAPI/Swagger schema endpoints for smart testing
                try:
                    openapi_sources = []
                    if openapi_url:
                        explicit_schema = await fetch_openapi_schema(openapi_url, auth_session=auth_session)
                        if explicit_schema:
                            openapi_sources.append(explicit_schema)
                    auto_schema = await discover_openapi_schema(base_url, auth_session=auth_session)
                    if auto_schema:
                        openapi_sources.append(auto_schema)

                    if openapi_sources:
                        import re as path_re
                        post_count = 0
                        get_count = 0
                        seen_specs = set()
                        for schema in openapi_sources:
                            schema_url = schema.get("url")
                            if schema_url in seen_specs:
                                continue
                            seen_specs.add(schema_url)
                            for ep in schema.get("endpoints", []) or []:
                                method = ep.get("method")
                                path = ep.get("path", "")
                                if not method or not path:
                                    continue
                                if "{" in path:
                                    path = path_re.sub(r'\{[^}]+\}', '1', path)
                                full_url = urllib.parse.urljoin(base_url, path)
                                if method in ("POST", "PUT", "PATCH") and ep.get("body_params"):
                                    if _merge_endpoint({
                                        "url": full_url,
                                        "method": method,
                                        "body_params": ep["body_params"],
                                        "body_required_params": ep.get("body_required_params", []),
                                        "body_param_defaults": ep.get("body_param_defaults", {}),
                                        "content_type": ep.get("content_type", "application/json"),
                                        "source": "openapi",
                                    }):
                                        post_count += 1
                                elif method in ("GET", "DELETE", "HEAD", "OPTIONS") and ep.get("query_params"):
                                    if _merge_endpoint({
                                        "url": full_url,
                                        "method": method,
                                        "params": ep.get("query_params", []),
                                        "source": "openapi",
                                    }):
                                        get_count += 1
                        if post_count or get_count:
                            print(f"[scanner] Added {get_count} GET and {post_count} POST endpoints from OpenAPI", file=sys.stderr)

                        # Smart mode: optionally kick off Schemathesis when OpenAPI is found
                        if schemathesis_task is None and not public_only:
                            schema_url = openapi_url
                            if not schema_url:
                                for schema in openapi_sources:
                                    candidate_url = schema.get("url")
                                    if candidate_url:
                                        schema_url = candidate_url
                                        break
                            if schema_url:
                                schemathesis_schema_url = schema_url
                                schemathesis_task = asyncio.create_task(
                                    schemathesis_run(
                                        schema_url,
                                        api_token,
                                        base_url=base_url,
                                        auth_session=auth_session,
                                    )
                                )
                except Exception as e:
                    print(f"[scanner] OpenAPI discovery failed: {e}", file=sys.stderr)

                # Infer POST endpoints from discovered URLs (katana crawl results)
                # This converts API paths like /api/auth/login, /workshop/api/shop/apply_coupon
                # into POST endpoint candidates with inferred body parameters
                # Skip when SPA catch-all detected — discovered URLs are phantom paths
                _skip_post_inference = smart_discovery_data and smart_discovery_data.get("spa_catch_all")
                if _skip_post_inference:
                    print("[scanner] POST inference: skipped (SPA catch-all detected)", file=sys.stderr)
                try:
                    # Patterns that suggest POST/mutation operations
                    POST_INDICATORS = [
                        "login", "signin", "signup", "register", "auth",
                        "create", "add", "new", "insert",
                        "update", "edit", "modify", "change",
                        "delete", "remove",
                        "submit", "send", "post",
                        "apply", "validate", "verify", "confirm",
                        "checkout", "payment", "pay", "purchase", "order",
                        "upload", "import",
                        "reset", "forgot", "recover",
                        "contact", "feedback", "comment", "review",
                        "subscribe", "unsubscribe",
                        "coupon", "discount", "promo",
                    ]

                    # Parameter inference based on path segments
                    PATH_TO_PARAMS = {
                        "login": ["email", "username", "password"],
                        "signin": ["email", "username", "password"],
                        "signup": ["email", "username", "password", "name"],
                        "register": ["email", "username", "password", "name"],
                        "auth": ["email", "username", "password", "token"],
                        "search": ["query", "q", "term", "keyword"],
                        "order": ["product_id", "quantity", "id"],
                        "checkout": ["cart_id", "payment_method", "address"],
                        "payment": ["amount", "card", "token"],
                        "coupon": ["coupon_code", "code", "coupon"],
                        "apply": ["code", "id", "value"],
                        "validate": ["code", "token", "value"],
                        "verify": ["code", "token", "otp"],
                        "reset": ["email", "token", "password"],
                        "forgot": ["email"],
                        "contact": ["email", "message", "name", "subject"],
                        "feedback": ["message", "rating", "comment"],
                        "comment": ["content", "text", "message", "post_id"],
                        "review": ["rating", "comment", "product_id"],
                        "upload": ["file", "name"],
                        "user": ["id", "email", "username"],
                        "product": ["id", "name", "price"],
                        "shop": ["id", "product_id", "quantity"],
                    }

                    # Collect all discovered URLs from crawl
                    all_discovered_urls = []
                    if not _skip_post_inference:
                        if crawl_urls:
                            all_discovered_urls.extend(crawl_urls)
                        if smart_discovery_data:
                            all_discovered_urls.extend(smart_discovery_data.get("api_endpoints", []))

                    print(f"[scanner] POST inference: {len(all_discovered_urls)} URLs to analyze (crawl_urls={len(crawl_urls) if crawl_urls else 0})", file=sys.stderr)

                    inferred_post_count = 0
                    seen_post_urls = set()

                    for disc_url in all_discovered_urls:
                        if not isinstance(disc_url, str):
                            continue
                        parsed = urllib.parse.urlparse(disc_url)
                        path_lower = parsed.path.lower()

                        # Build canonical URL without query params
                        base_post_url = urllib.parse.urljoin(base_url, parsed.path.rstrip("/"))
                        if base_post_url in seen_post_urls:
                            continue

                        # Check if path suggests a POST operation
                        is_post_candidate = False
                        matched_params = []
                        indicators_in_path = {ind for ind in POST_INDICATORS if ind in path_lower}
                        primary_indicator = None
                        matched_indicators: set[str] = set()

                        for indicator in POST_INDICATORS:
                            if indicator in indicators_in_path:
                                is_post_candidate = True
                                primary_indicator = indicator
                                matched_indicators.add(indicator)
                                if indicator in PATH_TO_PARAMS:
                                    matched_params.extend(PATH_TO_PARAMS[indicator])
                                break

                        # Also check individual path segments for substring matches
                        # e.g., "apply_coupon" should match "coupon" in PATH_TO_PARAMS
                        segments = [s for s in parsed.path.split("/") if s]
                        for segment in segments:
                            seg_lower = segment.lower()
                            # Only enrich params for explicit indicator tokens (conservative)
                            tokens = [t for t in re.split(r"[^a-z0-9]+", seg_lower) if t]
                            for token in tokens:
                                if token == primary_indicator:
                                    continue
                                if token in indicators_in_path and token in PATH_TO_PARAMS:
                                    matched_indicators.add(token)
                                    matched_params.extend(PATH_TO_PARAMS[token])

                        if is_post_candidate and matched_params:
                            seen_post_urls.add(base_post_url)
                            # Deduplicate params while preserving order
                            unique_params = list(dict.fromkeys(matched_params))
                            if _merge_endpoint({
                                "url": base_post_url,
                                "method": "POST",
                                "body_params": unique_params[:8],
                                "body_required_params": unique_params[:3],
                                "body_param_defaults": {},
                                "content_type": "application/json",
                                "source": "inferred",
                            }):
                                inferred_post_count += 1
                                if os.environ.get("SHAKERSCAN_DEBUG_POST_INFER") == "1":
                                    print(
                                        f"[scanner][debug] POST infer url={base_post_url} path={parsed.path} "
                                        f"indicators={sorted(matched_indicators)} params={unique_params[:8]}",
                                        file=sys.stderr
                                    )

                    if inferred_post_count > 0:
                        print(f"[scanner] Inferred {inferred_post_count} POST endpoints from discovered URLs", file=sys.stderr)
                except Exception as e:
                    print(f"[scanner] POST endpoint inference failed: {e}", file=sys.stderr)

                # Add common POST endpoint patterns for apps without OpenAPI
                # Enabled in complete_mode (full/aggressive) and smart_mode since these
                # are active scan types that should test POST body injection
                if complete_mode or smart_mode:
                    COMMON_POST_ENDPOINTS = [
                        ("/api/auth/login", ["email", "username", "password"]),
                        ("/api/login", ["email", "username", "password"]),
                        ("/api/v1/login", ["email", "username", "password"]),
                        ("/api/v2/user/login", ["email", "password"]),
                        ("/api/search", ["query", "q", "term"]),
                        ("/rest/user/login", ["email", "password"]),
                        # Read-only endpoints safe to probe
                        ("/api/users", ["id"]),
                        ("/api/user", ["id"]),
                        ("/api/products", ["id", "category"]),
                    ]
                    added_common = 0
                    for path, params in COMMON_POST_ENDPOINTS:
                        full_url = urllib.parse.urljoin(base_url, path)
                        if _merge_endpoint({
                            "url": full_url,
                            "method": "POST",
                            "body_params": params,
                            "body_required_params": params,
                            "body_param_defaults": {},
                            "content_type": "application/json",
                            "source": "common",
                        }):
                            added_common += 1
                    if added_common > 0:
                        print(f"[scanner] Added {added_common} common POST endpoints (active scan mode)", file=sys.stderr)

                # OPTIONS-based method discovery expansion
                if options_method_results and options_method_results.get("methods_by_url"):
                    def _infer_params_from_path(path: str, method: str) -> list[str]:
                        path_lower = path.lower()
                        if method in ("POST", "PUT", "PATCH"):
                            if any(k in path_lower for k in ["login", "signin", "auth"]):
                                return ["username", "email", "password"]
                            if any(k in path_lower for k in ["register", "signup"]):
                                return ["email", "username", "password", "name"]
                            if any(k in path_lower for k in ["search", "query"]):
                                return ["q", "query"]
                            if any(k in path_lower for k in ["order", "cart", "checkout"]):
                                return ["id", "product_id", "quantity"]
                            return ["id", "name"]
                        if "search" in path_lower or "query" in path_lower:
                            return ["q", "query"]
                        if any(k in path_lower for k in ["user", "account", "profile"]):
                            return ["id", "user", "email"]
                        return ["id"]

                    def _find_params_for_url(url: str) -> list[str]:
                        target_norm = _normalize_endpoint_url(url)
                        for ep in endpoints:
                            if _normalize_endpoint_url(ep.get("url", "")) == target_norm:
                                if ep.get("params"):
                                    return list(ep.get("params") or [])
                                if ep.get("body_params"):
                                    return list(ep.get("body_params") or [])
                        return []

                    options_added = 0
                    for opt_url, methods in (options_method_results.get("methods_by_url") or {}).items():
                        if not opt_url or not methods:
                            continue
                        parsed = urllib.parse.urlparse(opt_url)
                        for method in methods:
                            method_u = method.upper()
                            if method_u not in ("GET", "POST", "PUT", "PATCH"):
                                continue
                            params = _find_params_for_url(opt_url)
                            if not params:
                                params = _infer_params_from_path(parsed.path or "/", method_u)
                            if method_u == "GET":
                                if _merge_endpoint({"url": opt_url, "method": "GET", "params": params, "source": "options"}):
                                    options_added += 1
                            else:
                                if _merge_endpoint({
                                    "url": opt_url,
                                    "method": method_u,
                                    "body_params": params,
                                    "body_required_params": params[:3],
                                    "body_param_defaults": {},
                                    "content_type": "application/json",
                                    "source": "options",
                                }):
                                    options_added += 1

                    if options_added > 0:
                        print(f"[scanner] Added {options_added} endpoints from OPTIONS method discovery", file=sys.stderr)

                # Add HAR-discovered endpoints with method/body params preserved
                if har_test_targets:
                    har_get_count = 0
                    har_post_count = 0
                    for har_target in har_test_targets:
                        har_url = har_target.get("url")
                        if not har_url:
                            continue
                        har_method = (har_target.get("method") or "GET").upper()
                        har_params = har_target.get("params", {})
                        har_param_values = har_target.get("param_values", {})
                        har_content_type = har_target.get("content_type") or "application/json"
                        har_body_template = har_target.get("body_template")

                        if har_method == "GET":
                            # params.query is now a list of param names from get_testable_endpoints
                            query_params = har_params.get("query", [])
                            query_defaults = har_param_values.get("query", {})
                            if query_params and _merge_endpoint({
                                "url": har_url,
                                "method": "GET",
                                "params": query_params,
                                "param_defaults": query_defaults,
                                "source": "har_discovery",
                            }):
                                har_get_count += 1
                        elif har_method in ("POST", "PUT", "PATCH"):
                            # params.body is now a list of param names from get_testable_endpoints
                            body_params = har_params.get("body", [])
                            body_defaults = har_param_values.get("body", {})
                            if body_params and _merge_endpoint({
                                "url": har_url,
                                "method": har_method,
                                "body_params": body_params,
                                "body_required_params": body_params[:5] if len(body_params) > 5 else body_params,
                                "body_param_defaults": body_defaults,
                                "content_type": har_content_type,
                                "body_template": har_body_template,
                                "source": "har_discovery",
                            }):
                                har_post_count += 1

                    if har_get_count or har_post_count:
                        print(f"[scanner] Added {har_get_count} GET and {har_post_count} POST endpoints from HAR discovery", file=sys.stderr)

                if endpoints:
                    get_count = sum(1 for ep in endpoints if (ep.get("method") or "GET").upper() == "GET")
                    post_count = sum(1 for ep in endpoints if (ep.get("method") or "GET").upper() in ("POST", "PUT", "PATCH"))
                    allowed_count = sum(1 for ep in endpoints if ep.get("allowed_methods"))
                    if debug_endpoint_discovery:
                        print(
                            f"[DEBUG SMART] endpoints={len(endpoints)} get={get_count} post={post_count} "
                            f"allowed_methods={allowed_count}",
                            file=sys.stderr
                        )
                    if debug_endpoint_discovery and allowed_count:
                        for i, ep in enumerate([e for e in endpoints if e.get("allowed_methods")][:5]):
                            print(
                                f"[DEBUG SMART]   {i}: {ep.get('method')} {ep.get('url')} "
                                f"allowed={ep.get('allowed_methods')}",
                                file=sys.stderr
                            )

                # Get tech stack from discovery for DBMS hints
                tech_stack = smart_discovery_data.get("tech_stack_guess", []) if smart_discovery_data else []

                # Prioritize endpoints: high-signal params and sensitive API paths first,
                # then real discovered endpoints before synthetic/inferred.
                def _endpoint_priority(ep: dict) -> tuple[int, int, int, int, str]:
                    """Return a stable sort key where lower values are tested first."""
                    source = ep.get("source", "")
                    source_priority = _SOURCE_PRIORITY.get(source, _DEFAULT_SOURCE_PRIORITY)
                    method = (ep.get("method") or "GET").upper()
                    url_s = ep.get("url", "")
                    path_l = urllib.parse.urlparse(url_s).path.lower()
                    param_names = [
                        str(p).lower()
                        for p in ((ep.get("params") or []) + (ep.get("body_params") or []))
                    ]
                    high_signal_tokens = (
                        "id", "user", "uid", "account", "token", "file", "path", "url",
                        "redirect", "next", "q", "query", "search", "filter", "name",
                        "email", "password",
                    )
                    sensitive_path_tokens = (
                        "/api/", "login", "auth", "upload", "logs", "admin", "users",
                        "orders", "payment", "checkout", "debug",
                    )
                    param_score = sum(
                        1
                        for p in param_names
                        if any(tok == p or tok in p for tok in high_signal_tokens)
                    )
                    path_score = sum(1 for tok in sensitive_path_tokens if tok in path_l)
                    post_bonus = 1 if method in ("POST", "PUT", "PATCH") else 0
                    # Negative scores sort before lower-risk endpoints.
                    return (-param_score, -path_score, -post_bonus, source_priority, url_s)

                endpoints = sorted(endpoints, key=_endpoint_priority)

                # Log prioritization stats
                source_counts = {}
                for ep in endpoints[:100]:  # Sample first 100
                    src = ep.get("source", "unknown")
                    source_counts[src] = source_counts.get(src, 0) + 1
                if source_counts:
                    print(f"[scanner] Endpoint prioritization (first 100): {source_counts}", file=sys.stderr)

                # Run smart active tests with DBMS detection and context-aware payloads
                if auth_session:
                    try:
                        await auth_session.refresh_if_needed()
                    except Exception as e:
                        print(f"[scanner] Auth refresh before smart active tests failed: {e}", file=sys.stderr)

                smart_results = await run_smart_active_tests(
                    url=base_url,
                    endpoints=endpoints,
                    tech_stack=tech_stack,
                    dbms=early_dbms,  # P1-2 FIX: Use early-detected DBMS instead of auto-detect
                    signals=nuclei_signals,  # Pass signals from nuclei findings
                    auth_session=auth_session,  # Pass auth session for authenticated testing
                    run_xss=run_xss,
                    run_sqli=run_sqli,
                    thorough_params=thorough_params,  # Test more params if --thorough-params flag is set
                    active_max_seconds=scan_budget.get("active_max_seconds"),
                    active_max_endpoints=scan_budget.get("active_max_endpoints"),
                    active_params_per_endpoint=scan_budget.get("active_params_per_endpoint"),
                    max_findings_per_family=scan_budget.get("max_findings_per_family"),
                )

                smart_sqli_findings = []
                smart_xss_findings = []

                if run_sqli:
                    smart_sqli_findings = smart_results.get("sqli", {}).get("findings", [])
                    active_block["smart_sqli"] = smart_sqli_findings
                    active_block["get_endpoints_tested"] = smart_results.get("sqli", {}).get("get_endpoints_tested", 0)
                    active_block["post_endpoints_tested"] = smart_results.get("sqli", {}).get("post_endpoints_tested", 0)
                    active_block["smart_total_endpoints_tested"] = smart_results.get("total_endpoints_tested", 0)

                    # Process smart SQLi results
                    if smart_sqli_findings:
                        for f in smart_sqli_findings:
                            method = f.get("method", "GET")
                            title = f"SQL Injection ({f.get('dbms', 'unknown')} - {f.get('technique', 'unknown')})"
                            if method != "GET":
                                title = f"{method} {title}"  # e.g., "POST SQL Injection (...)"
                            evidence_dict = {
                                "type": f.get("type", "SQLi"),
                                "url": f.get("url"),
                                "method": method,
                                "param": f.get("param"),
                                "payload": f.get("payload"),
                                "technique": f.get("technique"),
                                "evidence": f.get("evidence"),
                                "dbms": f.get("dbms"),
                            }
                            if f.get("request_headers"):
                                evidence_dict["request_headers"] = f.get("request_headers")
                            # Include content_type and body for POST verification
                            if f.get("content_type"):
                                evidence_dict["content_type"] = f.get("content_type")
                            if f.get("body"):
                                evidence_dict["body"] = f.get("body")
                            report["findings"].append(normalize_finding(
                                "smart_sqli",
                                title,
                                f.get("severity", "critical"),
                                evidence_dict,
                                "CWE-89"
                            ))

                    # Store DBMS detection info
                    if smart_results.get("dbms_detected"):
                        active_block["dbms_detected"] = smart_results["dbms_detected"]

                    # SQLi Data Extraction - chain from confirmed SQLi to extract actual data
                    # This provides proof of exploitation and upgrades severity
                    if smart_sqli_findings:
                        extraction_results = []
                        for sqli_finding in smart_sqli_findings[:sqli_extract_max]:
                            try:
                                extraction = await sqli_data_extraction(
                                    sqli_finding=sqli_finding,
                                    auth_session=auth_session,
                                    max_extractions=5
                                )
                                if extraction.get("extraction_successful"):
                                    extraction_results.append({
                                        "url": sqli_finding.get("url"),
                                        "param": sqli_finding.get("param"),
                                        **extraction
                                    })
                                    # Update the finding with extraction evidence
                                    sqli_finding["extraction_evidence"] = extraction.get("evidence", [])
                                    sqli_finding["extracted_data"] = extraction.get("extracted_data", {})
                                    # Severity upgrade is automatic (already critical, but add flag)
                                    sqli_finding["proof_of_exploitation"] = True
                                    print(f"[scanner] SQLi data extraction successful for {sqli_finding.get('url')}", file=sys.stderr)
                            except Exception as e:
                                print(f"[scanner] SQLi extraction error: {e}", file=sys.stderr)

                        if extraction_results:
                            active_block["sqli_extraction"] = extraction_results

                    # OOB SQLi Test - for blind SQLi detection via external callbacks
                    # Requires a callback URL (e.g., Burp Collaborator) for verification
                    oob_results = []
                    if oob_callback_url and smart_sqli_findings:
                        for sqli_finding in smart_sqli_findings[:oob_max_findings]:
                            try:
                                oob_result = await oob_sqli_test(
                                    url=sqli_finding.get("url", ""),
                                    param=sqli_finding.get("param", ""),
                                    dbms=sqli_finding.get("dbms"),
                                    callback_url=oob_callback_url,
                                    auth_session=auth_session
                                )
                                if oob_result.get("payloads_sent"):
                                    oob_results.append({
                                        "url": sqli_finding.get("url"),
                                        "param": sqli_finding.get("param"),
                                        **oob_result
                                    })
                            except Exception as e:
                                print(f"[scanner] OOB SQLi test error: {e}", file=sys.stderr)

                    if oob_results:
                        active_block["oob_sqli"] = oob_results
                        # Add a finding that requires callback verification
                        report["findings"].append(normalize_finding(
                            "oob_sqli",
                            "Potential Out-of-Band SQL Injection (requires callback verification)",
                            "medium",  # Medium until callback confirms
                            {
                                "payloads_sent": len(oob_results),
                                "callback_url": oob_callback_url,
                                "note": "Check callback server for DNS/HTTP requests to confirm exploitation",
                                "endpoints_tested": [r.get("url") for r in oob_results],
                            },
                            "CWE-89"
                        ))

                # Parameter-aware auxiliary injection tests + blind SSRF (OOB)
                try:
                    def _coerce_param_list(raw: Any) -> list[str]:
                        if isinstance(raw, dict):
                            return [str(k) for k in raw.keys() if k]
                        if isinstance(raw, (list, tuple, set)):
                            return [str(v) for v in raw if v]
                        if isinstance(raw, str):
                            return [raw] if raw else []
                        return []

                    def _build_query_url(test_url: str, defaults: dict[str, Any] | None) -> str:
                        parsed = urllib.parse.urlparse(test_url)
                        query_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
                        if defaults:
                            for name, value in defaults.items():
                                if name not in query_params:
                                    query_params[name] = str(value)
                        if not query_params:
                            return test_url
                        new_query = urllib.parse.urlencode(query_params, doseq=True)
                        return urllib.parse.urlunparse(parsed._replace(query=new_query))

                    auxiliary_injection_enabled = not (run_sqli and not run_xss)
                    if not auxiliary_injection_enabled:
                        active_block["auxiliary_injection_skipped"] = "sql_tests_only"
                        print("[active] Skipping auxiliary injection probes for SQLi-only scan", file=sys.stderr)

                    param_endpoints = []
                    if auxiliary_injection_enabled:
                        param_endpoints = [
                            ep for ep in endpoints
                            if (ep.get("method") or "GET").upper() == "GET"
                            and _coerce_param_list(ep.get("params") or ep.get("query_params"))
                        ]
                        param_endpoints = param_endpoints[: (8 if thorough_params else 4)]

                    ssrf_param_keywords = {
                        "url", "uri", "path", "dest", "redirect", "link", "proxy",
                        "domain", "host", "site", "html", "val", "feed", "dir",
                        "page", "callback", "webhook", "target", "src", "file",
                        "reference", "ref", "fetch", "request", "load", "data",
                        "image", "img", "pdf", "document", "download", "resource",
                    }
                    xxe_param_keywords = {"xml", "xxe", "file", "doc", "data", "payload", "content"}

                    if param_endpoints:
                        ldap_param = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}
                        xpath_param = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}
                        ssti_param = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}

                        ssti_param_hints = {"template", "view", "render", "page", "tpl"}

                        for ep in param_endpoints:
                            params = _coerce_param_list(ep.get("params") or ep.get("query_params"))
                            if not params:
                                continue
                            defaults = ep.get("param_defaults") or ep.get("query_param_defaults") or {}
                            test_url = _build_query_url(ep.get("url", ""), defaults)
                            if not test_url:
                                continue

                            ldap_res = await ldap_injection_test(
                                test_url,
                                params_to_test=params,
                                auth_session=auth_session,
                                param_defaults=defaults,
                                max_params=3,
                                max_payloads=6,
                            )
                            if ldap_res.get("vulnerable"):
                                ldap_param["vulnerable"] = True
                                ldap_param["evidence"].extend(ldap_res.get("evidence", []))
                                ldap_param["payloads_tested"].update(ldap_res.get("payloads_tested", []))
                                ldap_param["tested_params"].update(ldap_res.get("tested_params", []))

                            xpath_res = await xpath_injection_test(
                                test_url,
                                params_to_test=params,
                                auth_session=auth_session,
                                param_defaults=defaults,
                                max_params=3,
                                max_payloads=6,
                            )
                            if xpath_res.get("vulnerable"):
                                xpath_param["vulnerable"] = True
                                xpath_param["evidence"].extend(xpath_res.get("evidence", []))
                                xpath_param["payloads_tested"].update(xpath_res.get("payloads_tested", []))
                                xpath_param["tested_params"].update(xpath_res.get("tested_params", []))

                            if any(p.lower() in ssti_param_hints for p in params):
                                ssti_res = await ssti_test(
                                    test_url,
                                    params_to_test=params,
                                    auth_session=auth_session,
                                    param_defaults=defaults,
                                    max_params=3,
                                    max_payloads=6,
                                )
                                if ssti_res.get("vulnerable"):
                                    ssti_param["vulnerable"] = True
                                    ssti_param["evidence"].extend(ssti_res.get("evidence", []))
                                    ssti_param["payloads_tested"].update(ssti_res.get("payloads_tested", []))
                                    ssti_param["tested_params"].update(ssti_res.get("tested_params", []))

                        if ldap_param["vulnerable"]:
                            active_block["ldap_param"] = {
                                "payloads_tested": sorted(ldap_param["payloads_tested"]),
                                "tested_params": sorted(ldap_param["tested_params"]),
                                "evidence": ldap_param["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "ldap_injection",
                                "LDAP Injection (parameter-aware)",
                                "high",
                                {
                                    "evidence": ldap_param["evidence"][:10],
                                    "payloads_tested": len(ldap_param["payloads_tested"]),
                                    "tested_params": sorted(ldap_param["tested_params"]),
                                },
                                "CWE-90"
                            ))

                        if xpath_param["vulnerable"]:
                            active_block["xpath_param"] = {
                                "payloads_tested": sorted(xpath_param["payloads_tested"]),
                                "tested_params": sorted(xpath_param["tested_params"]),
                                "evidence": xpath_param["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "xpath_injection",
                                "XPath Injection (parameter-aware)",
                                "high",
                                {
                                    "evidence": xpath_param["evidence"][:10],
                                    "payloads_tested": len(xpath_param["payloads_tested"]),
                                    "tested_params": sorted(xpath_param["tested_params"]),
                                },
                                "CWE-91"
                            ))

                        if ssti_param["vulnerable"]:
                            active_block["ssti_param"] = {
                                "payloads_tested": sorted(ssti_param["payloads_tested"]),
                                "tested_params": sorted(ssti_param["tested_params"]),
                                "evidence": ssti_param["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "ssti",
                                "Server-Side Template Injection (parameter-aware)",
                                "critical",
                                {
                                    "evidence": ssti_param["evidence"][:10],
                                    "payloads_tested": len(ssti_param["payloads_tested"]),
                                    "tested_params": sorted(ssti_param["tested_params"]),
                                },
                                "CWE-1336"
                            ))

                    # Parameter-aware POST/JSON injection tests
                    post_json_endpoints = []
                    if auxiliary_injection_enabled:
                        post_json_endpoints = [
                            ep for ep in endpoints
                            if (ep.get("method") or "GET").upper() in ("POST", "PUT", "PATCH")
                            and _coerce_param_list(ep.get("body_params") or ep.get("params"))
                            and ("json" in (ep.get("content_type") or "application/json").lower())
                        ]
                        post_json_endpoints = post_json_endpoints[: (6 if thorough_params else 3)]

                    if post_json_endpoints:
                        ldap_post = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}
                        xpath_post = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}
                        ssrf_post = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}
                        xxe_post = {"vulnerable": False, "payloads_tested": set(), "tested_params": set(), "evidence": []}

                        for ep in post_json_endpoints:
                            params = _coerce_param_list(ep.get("body_params") or ep.get("params"))
                            if not params:
                                continue
                            defaults = ep.get("body_param_defaults") or {}
                            method = (ep.get("method") or "POST").upper()
                            content_type = ep.get("content_type") or "application/json"
                            url = ep.get("url") or ""
                            if not url:
                                continue

                            ldap_res = await ldap_injection_test_json_body(
                                url=url,
                                method=method,
                                params=params,
                                auth_session=auth_session,
                                body_template=ep.get("body_template"),
                                body_param_defaults=defaults,
                                content_type=content_type,
                                max_params=3,
                                max_payloads=5,
                            )
                            if ldap_res.get("vulnerable"):
                                ldap_post["vulnerable"] = True
                                ldap_post["evidence"].extend(ldap_res.get("findings", []))
                                ldap_post["payloads_tested"].update(ldap_res.get("payloads_tested", []))
                                ldap_post["tested_params"].update(ldap_res.get("tested_params", []))

                            xpath_res = await xpath_injection_test_json_body(
                                url=url,
                                method=method,
                                params=params,
                                auth_session=auth_session,
                                body_template=ep.get("body_template"),
                                body_param_defaults=defaults,
                                content_type=content_type,
                                max_params=3,
                                max_payloads=5,
                            )
                            if xpath_res.get("vulnerable"):
                                xpath_post["vulnerable"] = True
                                xpath_post["evidence"].extend(xpath_res.get("findings", []))
                                xpath_post["payloads_tested"].update(xpath_res.get("payloads_tested", []))
                                xpath_post["tested_params"].update(xpath_res.get("tested_params", []))

                            ssrf_params = [p for p in params if p.lower() in ssrf_param_keywords]
                            if ssrf_params or thorough_params:
                                ssrf_res = await ssrf_injection_test_json_body(
                                    url=url,
                                    method=method,
                                    params=ssrf_params or params[:2],
                                    auth_session=auth_session,
                                    body_template=ep.get("body_template"),
                                    body_param_defaults=defaults,
                                    content_type=content_type,
                                    max_params=2,
                                    max_payloads=3,
                                )
                                if ssrf_res.get("vulnerable"):
                                    ssrf_post["vulnerable"] = True
                                    ssrf_post["evidence"].extend(ssrf_res.get("findings", []))
                                    ssrf_post["payloads_tested"].update(ssrf_res.get("payloads_tested", []))
                                    ssrf_post["tested_params"].update(ssrf_res.get("tested_params", []))

                            xxe_params = [p for p in params if any(k in p.lower() for k in xxe_param_keywords)]
                            if xxe_params or thorough_params:
                                xxe_res = await xxe_injection_test_json_body(
                                    url=url,
                                    method=method,
                                    params=xxe_params or params[:2],
                                    auth_session=auth_session,
                                    body_template=ep.get("body_template"),
                                    body_param_defaults=defaults,
                                    content_type=content_type,
                                    max_params=2,
                                    max_payloads=2,
                                )
                                if xxe_res.get("vulnerable"):
                                    xxe_post["vulnerable"] = True
                                    xxe_post["evidence"].extend(xxe_res.get("findings", []))
                                    xxe_post["payloads_tested"].update(xxe_res.get("payloads_tested", []))
                                    xxe_post["tested_params"].update(xxe_res.get("tested_params", []))

                        if ldap_post["vulnerable"]:
                            active_block["ldap_json"] = {
                                "payloads_tested": sorted(ldap_post["payloads_tested"]),
                                "tested_params": sorted(ldap_post["tested_params"]),
                                "evidence": ldap_post["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "ldap_injection",
                                "LDAP Injection (JSON body)",
                                "high",
                                {
                                    "evidence": ldap_post["evidence"][:10],
                                    "payloads_tested": len(ldap_post["payloads_tested"]),
                                    "tested_params": sorted(ldap_post["tested_params"]),
                                },
                                "CWE-90"
                            ))

                        if xpath_post["vulnerable"]:
                            active_block["xpath_json"] = {
                                "payloads_tested": sorted(xpath_post["payloads_tested"]),
                                "tested_params": sorted(xpath_post["tested_params"]),
                                "evidence": xpath_post["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "xpath_injection",
                                "XPath Injection (JSON body)",
                                "high",
                                {
                                    "evidence": xpath_post["evidence"][:10],
                                    "payloads_tested": len(xpath_post["payloads_tested"]),
                                    "tested_params": sorted(xpath_post["tested_params"]),
                                },
                                "CWE-91"
                            ))

                        if ssrf_post["vulnerable"]:
                            active_block["ssrf_json"] = {
                                "payloads_tested": sorted(ssrf_post["payloads_tested"]),
                                "tested_params": sorted(ssrf_post["tested_params"]),
                                "evidence": ssrf_post["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "ssrf",
                                "SSRF (JSON body)",
                                "high",
                                {
                                    "evidence": ssrf_post["evidence"][:10],
                                    "payloads_tested": len(ssrf_post["payloads_tested"]),
                                    "tested_params": sorted(ssrf_post["tested_params"]),
                                },
                                "CWE-918"
                            ))

                        if xxe_post["vulnerable"]:
                            active_block["xxe_json"] = {
                                "payloads_tested": sorted(xxe_post["payloads_tested"]),
                                "tested_params": sorted(xxe_post["tested_params"]),
                                "evidence": xxe_post["evidence"][:10],
                            }
                            report["findings"].append(normalize_finding(
                                "xxe_injection",
                                "XXE (JSON body)",
                                "high",
                                {
                                    "evidence": xxe_post["evidence"][:10],
                                    "payloads_tested": len(xxe_post["payloads_tested"]),
                                    "tested_params": sorted(xxe_post["tested_params"]),
                                },
                                "CWE-611"
                            ))

                    # Blind SSRF (OOB) for smart mode when callback is provided
                    if oob_callback_url:
                        ssrf_results = []
                        ssrf_candidates = param_endpoints[:5] if param_endpoints else []
                        for ep in ssrf_candidates:
                            params = _coerce_param_list(ep.get("params") or ep.get("query_params"))
                            if not params:
                                continue
                            ssrf_params = [p for p in params if p.lower() in ssrf_param_keywords]
                            if not ssrf_params and not thorough_params:
                                continue
                            if not ssrf_params:
                                ssrf_params = params[:2]
                            defaults = ep.get("param_defaults") or ep.get("query_param_defaults") or {}
                            test_url = _build_query_url(ep.get("url", ""), defaults)
                            if not test_url:
                                continue
                            ssrf_res = await blind_ssrf_test(
                                test_url,
                                callback_domain=oob_callback_url,
                                params_to_test=ssrf_params,
                                auth_session=auth_session,
                            )
                            if ssrf_res.get("payloads_injected"):
                                ssrf_results.append({
                                    "url": test_url,
                                    "params": ssrf_params,
                                    **ssrf_res,
                                })

                        if ssrf_results:
                            active_block["blind_ssrf"] = ssrf_results
                            report["findings"].append(normalize_finding(
                                "blind_ssrf",
                                "Potential Blind SSRF (OOB callbacks sent)",
                                "medium",
                                {
                                    "callback_domain": oob_callback_url,
                                    "payloads_sent": sum(r.get("payloads_injected", 0) for r in ssrf_results),
                                    "endpoints_tested": [r.get("url") for r in ssrf_results],
                                    "note": "Check your callback server for DNS/HTTP hits to confirm SSRF.",
                                },
                                "CWE-918"
                            ))

                    # Stored XSS workflow
                    try:
                        stored_urls = []
                        if smart_discovery_data and isinstance(smart_discovery_data, dict):
                            stored_urls.extend(smart_discovery_data.get("all_urls", []) or [])
                        stored_urls.extend(crawl_urls or [])
                        if browser_api_endpoints:
                            for ep in browser_api_endpoints:
                                if isinstance(ep, dict) and ep.get("url"):
                                    stored_urls.append(ep["url"])
                                elif isinstance(ep, str):
                                    stored_urls.append(ep)
                        stored_urls = list({u for u in stored_urls if isinstance(u, str)})

                        stored_res = await stored_xss_workflow(
                            base_url=base_url,
                            endpoints=endpoints,
                            discovered_urls=stored_urls,
                            auth_session=auth_session,
                            max_forms=8 if thorough_params else 5,
                            max_pages=25 if thorough_params else 12,
                        )
                        active_block["stored_xss"] = stored_res
                        if stored_res.get("vulnerable"):
                            for finding in stored_res.get("findings", [])[:5]:
                                report["findings"].append(normalize_finding(
                                    "stored_xss",
                                    "Stored XSS (workflow)",
                                    finding.get("severity", "high"),
                                    {
                                        "injection_url": finding.get("injection_url"),
                                        "stored_url": finding.get("stored_url"),
                                        "param": finding.get("param"),
                                        "payload": finding.get("payload"),
                                        "payload_reflected": finding.get("payload_reflected"),
                                        "snippet": finding.get("snippet"),
                                        "method": finding.get("method"),
                                    },
                                    "CWE-79"
                                ))
                    except Exception as e:
                        active_block["stored_xss_error"] = str(e)
                except Exception as e:
                    active_block["param_injection_error"] = str(e)

                if run_xss:
                    all_xss_findings = smart_results.get("xss", {}).get("findings", [])
                    # Filter out hash-route DOM XSS (tracked separately in active_block["hash_route_dom_xss"])
                    smart_xss_findings = [f for f in all_xss_findings if f.get("subtype") != "dom_xss_hash_route"]
                    active_block["smart_xss"] = smart_xss_findings
                    active_block["smart_reflections_found"] = smart_results.get("xss", {}).get("reflections_found", 0)
                    active_block["xss_get_endpoints_tested"] = smart_results.get("xss", {}).get("get_endpoints_tested", 0)
                    active_block["xss_post_endpoints_tested"] = smart_results.get("xss", {}).get("post_endpoints_tested", 0)

                    # Process smart XSS results (hash-route DOM XSS handled separately below)
                    for f in smart_xss_findings:
                        report["findings"].append(normalize_finding(
                            "smart_xss",
                            f"Cross-Site Scripting ({f.get('context', 'unknown')})",
                            f.get("severity", "high"),
                            {
                                "type": f.get("type", "XSS"),
                                "url": f.get("url"),
                                "param": f.get("param"),
                                "payload": f.get("payload"),
                                "evidence": f.get("evidence"),
                                "context": f.get("context"),
                            },
                            "CWE-79"
                        ))

                # Hash-route DOM XSS always reported (runs unconditionally in smart scans)
                hash_route_dom_xss = smart_results.get("hash_route_dom_xss", {})
                hash_route_findings = hash_route_dom_xss.get("findings", [])
                if hash_route_findings:
                    active_block["hash_route_dom_xss"] = hash_route_findings
                    active_block["hash_route_endpoints_tested"] = hash_route_dom_xss.get("endpoints_tested", 0)
                    for f in hash_route_findings:
                        report["findings"].append(normalize_finding(
                            "hash_route_dom_xss",
                            f"DOM XSS in Hash Route ({f.get('technique', 'unknown')})",
                            f.get("severity", "high"),
                            {
                                "type": "DOM XSS",
                                "url": f.get("url"),
                                "param": f.get("param"),
                                "payload": f.get("payload"),
                                "evidence": f.get("evidence"),
                                "verified": f.get("verified", False),
                            },
                            "CWE-79"
                        ))

                # Record coverage for smart active tests
                if coverage_tracker:
                    sqli_stats = smart_results.get("sqli", {})
                    xss_stats = smart_results.get("xss", {})
                    total_endpoints = (
                        sqli_stats.get("endpoints_tested", 0) +
                        xss_stats.get("endpoints_tested", 0)
                    )
                    total_params = (
                        sqli_stats.get("params_tested", 0) +
                        xss_stats.get("params_tested", 0)
                    )
                    if total_endpoints > 0:
                        coverage_tracker.record_endpoint_tested(count=total_endpoints)
                    if total_params > 0:
                        coverage_tracker.record_param_tested(count=total_params)

                if run_sqli:
                    # Heuristic sqlmap verification on high-signal endpoints
                    try:
                        sqlmap_candidates: list[dict[str, Any]] = []
                        seen_keys: set[tuple[str, str]] = set()
                        endpoint_lookup = {
                            (e.get("url"), e.get("method", "GET").upper()): e for e in endpoints
                        }

                        # PRIORITY: Always include manual/custom endpoints for SQLmap testing
                        if manual_endpoints_norm:
                            for ep in manual_endpoints_norm:
                                if not isinstance(ep, dict):
                                    continue
                                ep_url = ep.get("url")
                                if not ep_url:
                                    continue
                                method = (ep.get("method") or "GET").upper()
                                key = (ep_url, method)
                                if key in seen_keys:
                                    continue
                                # Build endpoint dict with params
                                sqlmap_ep = {
                                    "url": ep_url,
                                    "method": method,
                                    "source": "manual",
                                }
                                if method == "GET":
                                    sqlmap_ep["params"] = ep.get("params") or []
                                else:
                                    sqlmap_ep["body_params"] = ep.get("body_params") or ep.get("params") or []
                                    sqlmap_ep["content_type"] = ep.get("content_type") or "application/json"
                                sqlmap_candidates.append({"endpoint": sqlmap_ep, "param": None, "reason": "manual_endpoint"})
                                seen_keys.add(key)
                            if sqlmap_candidates:
                                print(
                                    f"[sqlmap] Added {len(sqlmap_candidates)} manual endpoints for SQLmap testing",
                                    file=sys.stderr
                                )

                        if smart_sqli_findings:
                            max_sqlmap = 2 if quick_mode else 5
                            for f in smart_sqli_findings:
                                key = (f.get("url"), f.get("method", "GET").upper())
                                if key in seen_keys:
                                    continue
                                endpoint = endpoint_lookup.get(key, {"url": f.get("url"), "method": f.get("method", "GET")})
                                sqlmap_candidates.append({"endpoint": endpoint, "param": f.get("param"), "reason": "smart_sqli"})
                                seen_keys.add(key)
                                if len(sqlmap_candidates) >= max_sqlmap:
                                    break
                        elif nuclei_signals and (nuclei_signals.get("sql_errors") or nuclei_signals.get("auth_issues")):
                            sql_priority_params = ["id", "user", "uid", "account", "login", "query", "search", "filter"]

                            def score_endpoint(ep: dict[str, Any]) -> int:
                                params = (ep.get("params", []) or []) + (ep.get("body_params", []) or [])
                                return sum(1 for p in params if any(sp in p.lower() for sp in sql_priority_params))

                            prioritized = sorted(endpoints, key=score_endpoint, reverse=True)
                            limit = 2 if quick_mode else 5
                            for ep in prioritized:
                                if not (ep.get("params") or ep.get("body_params")):
                                    continue
                                key = (ep.get("url"), ep.get("method", "GET").upper())
                                if key in seen_keys:
                                    continue
                                sqlmap_candidates.append({"endpoint": ep, "param": None, "reason": "signals"})
                                seen_keys.add(key)
                                if len(sqlmap_candidates) >= limit:
                                    break

                        # Add a small set of POST/PUT/PATCH endpoints for sqlmap coverage
                        if len(sqlmap_candidates) < (2 if quick_mode else 4):
                            post_endpoints = [
                                ep for ep in endpoints
                                if ep.get("method", "GET").upper() in ("POST", "PUT", "PATCH")
                                and ep.get("body_params")
                            ]

                            def score_post(ep: dict[str, Any]) -> int:
                                params = ep.get("body_params", []) or []
                                score = len(params)
                                path = str(ep.get("url", "")).lower()
                                if any(k in path for k in ["login", "auth", "search", "filter", "query"]):
                                    score += 3
                                return score

                            post_endpoints = sorted(post_endpoints, key=score_post, reverse=True)
                            extra_limit = 1 if quick_mode else 2
                            for ep in post_endpoints:
                                if extra_limit <= 0:
                                    break
                                key = (ep.get("url"), ep.get("method", "GET").upper())
                                if key in seen_keys:
                                    continue
                                sqlmap_candidates.append({"endpoint": ep, "param": None, "reason": "post_coverage"})
                                seen_keys.add(key)
                                extra_limit -= 1

                        # Build index of captured Playwright requests for SQLmap replay
                        # This allows us to use real headers/CSRF/body from browser traffic
                        debug_sqlmap = os.environ.get("SCANNER_DEBUG_SQLMAP", "").lower() in ("1", "true", "yes")
                        captured_index: dict[tuple[str, str, tuple[str, ...]], dict[str, Any]] = {}
                        if browser_res:
                            captured_requests = browser_res.get("captured_requests", [])
                            target_host = urllib.parse.urlparse(base_url).netloc

                            def _is_better_capture(new_req: dict[str, Any], old_req: dict[str, Any]) -> bool:
                                """Prefer authenticated, successful, with body."""
                                new_score = (
                                    new_req.get("has_auth", False),
                                    200 <= (new_req.get("status") or 0) < 400,
                                    bool(new_req.get("post_data")),
                                )
                                old_score = (
                                    old_req.get("has_auth", False),
                                    200 <= (old_req.get("status") or 0) < 400,
                                    bool(old_req.get("post_data")),
                                )
                                return new_score > old_score

                            for cap_req in captured_requests:
                                cap_url = cap_req.get("url", "")
                                cap_parsed = urllib.parse.urlparse(cap_url)

                                # Skip: different host
                                if cap_parsed.netloc != target_host:
                                    continue
                                # Skip: not an API call
                                if not cap_req.get("is_api_call"):
                                    continue
                                # Skip: multipart (file uploads)
                                if "multipart/form-data" in cap_req.get("content_type", ""):
                                    continue
                                # Skip: huge bodies
                                if cap_req.get("post_data") and len(cap_req.get("post_data", "")) > 50000:
                                    continue

                                # Build normalized key: (method, path, sorted_query_param_names)
                                cap_method = cap_req.get("method", "GET").upper()
                                cap_path = cap_parsed.path.rstrip("/") or "/"
                                cap_query_params = tuple(sorted(urllib.parse.parse_qs(cap_parsed.query, keep_blank_values=True).keys()))
                                cap_key = (cap_method, cap_path, cap_query_params)

                                # Keep best capture for each key
                                existing = captured_index.get(cap_key)
                                if existing is None or _is_better_capture(cap_req, existing):
                                    captured_index[cap_key] = cap_req

                            if debug_sqlmap and captured_index:
                                print(f"[DEBUG SQLMAP] indexed {len(captured_index)} captured requests for replay", file=sys.stderr)

                        if sqlmap_candidates:
                            if debug_sqlmap:
                                print(
                                    f"[DEBUG SQLMAP] candidates={len(sqlmap_candidates)}",
                                    file=sys.stderr
                                )
                                for i, candidate in enumerate(sqlmap_candidates[:5]):
                                    ep = candidate.get("endpoint", {}) or {}
                                    print(
                                        f"[DEBUG SQLMAP]   {i}: {ep.get('method', 'GET')} "
                                        f"{ep.get('url')} param={candidate.get('param')} "
                                        f"reason={candidate.get('reason')}",
                                        file=sys.stderr,
                                    )
                            # Only use aggressive SQLmap for aggressive exploit level
                            aggressive_sqlmap = exploit_level == "aggressive"
                            # Get detected DBMS from smart_sqli for DBMS-aware SQLmap tuning
                            detected_dbms = active_block.get("dbms_detected")

                            # Build tasks with replay matching
                            tasks: list[asyncio.Task[dict[str, Any]]] = []
                            replay_flags: list[bool] = []  # Track which candidates use replay
                            emit_progress(
                                "active_sqlmap",
                                90,
                                f"starting SQLMap verification on {len(sqlmap_candidates)} candidates",
                            )

                            for c in sqlmap_candidates:
                                ep = c["endpoint"]
                                ep_url = ep.get("url", "")
                                ep_method = ep.get("method", "GET").upper()
                                ep_parsed = urllib.parse.urlparse(ep_url)
                                ep_path = ep_parsed.path.rstrip("/") or "/"
                                ep_query_params = tuple(sorted(urllib.parse.parse_qs(ep_parsed.query, keep_blank_values=True).keys()))

                                # Build match key
                                match_key = (ep_method, ep_path, ep_query_params)
                                matched_capture = captured_index.get(match_key)

                                # Use replay if we have a match AND:
                                # - GET: always (preserves real headers/CSRF cookies)
                                # - POST/PUT/PATCH: only if captured request has body
                                use_replay = (
                                    matched_capture is not None
                                    and (
                                        ep_method == "GET"  # GET: replay for headers even without body
                                        or matched_capture.get("post_data")  # Non-GET: require body
                                    )
                                )

                                if use_replay:
                                    if debug_sqlmap:
                                        print(
                                            f"[DEBUG SQLMAP] using replay for {ep_method} {ep_path}",
                                            file=sys.stderr,
                                        )
                                    tasks.append(
                                        asyncio.create_task(
                                            sqlmap_replay_request(
                                                matched_capture,
                                                auth_session=auth_session,
                                                quick_mode=quick_mode,
                                                aggressive=aggressive_sqlmap,
                                                param=c.get("param"),
                                                dbms=detected_dbms,
                                            )
                                        )
                                    )
                                    replay_flags.append(True)
                                else:
                                    tasks.append(
                                        asyncio.create_task(
                                            sqlmap_test_context(
                                                ep,
                                                quick_mode=quick_mode,
                                                aggressive=aggressive_sqlmap,
                                                auth_session=auth_session,
                                                param=c.get("param"),
                                                dbms=detected_dbms,
                                            )
                                        )
                                    )
                                    replay_flags.append(False)

                            sqlmap_results = await asyncio.gather(*tasks, return_exceptions=True)
                            emit_progress("active_sqlmap", 91, "SQLMap verification complete")

                            for candidate, srep, used_replay in zip(sqlmap_candidates, sqlmap_results, replay_flags):
                                if isinstance(srep, Exception):
                                    active_block.setdefault("sqlmap_errors", []).append({
                                        "url": candidate["endpoint"].get("url"),
                                        "error": str(srep),
                                    })
                                    continue

                                # Handle None result (replay failed to write request file)
                                if srep is None:
                                    active_block.setdefault("sqlmap_errors", []).append({
                                        "url": candidate["endpoint"].get("url"),
                                        "error": "replay request file write failed",
                                    })
                                    continue

                                if srep.get("skipped"):
                                    # Enhanced skip reason logging
                                    skip_entry = {
                                        "url": srep.get("url"),
                                        "method": srep.get("method"),
                                        "param": srep.get("param"),
                                        "skip_reason": srep.get("skip_reason") or srep.get("error"),
                                        "skip_details": srep.get("skip_details"),
                                        "candidate_reason": candidate.get("reason"),
                                        "replay": used_replay,
                                    }
                                    active_block.setdefault("sqlmap_skipped", []).append(skip_entry)
                                    continue

                                # Add replay traceability
                                result_entry = {
                                    **srep,
                                    "reason": candidate.get("reason"),
                                    "replay": used_replay,
                                }
                                if used_replay:
                                    result_entry["replay_source"] = "playwright"
                                active_block["sqlmap"].append(result_entry)
                                if srep.get("vulnerable") or srep.get("summary") == "possible SQLi":
                                    method = srep.get("method", "GET")
                                    title = "Potential SQL injection"
                                    if method != "GET":
                                        title = f"{method} {title}"
                                    report["findings"].append(normalize_finding(
                                        "sqlmap", title, "high",
                                        {"url": srep.get("url"), "summary": srep.get("summary"), "param": srep.get("param")}
                                    ))
                    except Exception as e:
                        active_block.setdefault("sqlmap_errors", []).append({"error": str(e)})

                # NoSQL Injection testing for JSON body endpoints
                # NoSQL is an injection attack and should run when SQLi testing is enabled
                if run_sqli:
                    try:
                        debug_nosql = os.environ.get("SCANNER_DEBUG_NOSQL", "").lower() in ("1", "true", "yes")
                        post_endpoints = [ep for ep in endpoints if ep.get("method") in ("POST", "PUT", "PATCH")]
                        if debug_nosql:
                            print(f"[DEBUG NoSQL] Total POST endpoints: {len(post_endpoints)}", file=sys.stderr)
                            for i, ep in enumerate(post_endpoints[:5]):
                                print(f"[DEBUG NoSQL]   {i}: {ep.get('url')} body_params={ep.get('body_params')} content_type={ep.get('content_type')}", file=sys.stderr)

                        nosql_candidates = [
                            ep for ep in endpoints
                            if ep.get("method") in ("POST", "PUT", "PATCH")
                            and ep.get("body_params")
                            and (
                                not ep.get("allowed_methods")
                                or ep.get("method", "").upper() in [m.upper() for m in ep.get("allowed_methods", [])]
                            )
                            # Test if content_type is JSON or not specified (assume JSON for API endpoints)
                            and (not ep.get("content_type") or "json" in ep.get("content_type", "").lower())
                        ]
                        if debug_nosql:
                            print(f"[DEBUG NoSQL] NoSQL candidates after filter: {len(nosql_candidates)}", file=sys.stderr)
                            for i, ep in enumerate(nosql_candidates[:5]):
                                print(f"[DEBUG NoSQL]   candidate {i}: {ep.get('url')} params={ep.get('body_params')}", file=sys.stderr)

                        if nosql_candidates:
                            active_block["nosql_injection"] = []
                            nosql_limit = 3 if quick_mode else 8
                            emit_progress(
                                "active_nosql",
                                91,
                                f"starting NoSQL JSON body checks on {min(len(nosql_candidates), nosql_limit)} candidates",
                            )
                            for ep in nosql_candidates[:nosql_limit]:
                                nosql_result = await nosql_injection_test_json_body(
                                    url=ep["url"],
                                    method=ep["method"],
                                    params=ep.get("body_params", []),
                                    auth_session=auth_session,
                                    body_template=ep.get("body_template"),
                                    body_param_defaults=ep.get("body_param_defaults") or {},
                                )
                                if nosql_result.get("vulnerable"):
                                    active_block["nosql_injection"].append(nosql_result)
                                    for finding in nosql_result.get("findings", []):
                                        report["findings"].append(normalize_finding(
                                            "nosql_injection",
                                            f"NoSQL Injection in {finding.get('parameter', 'unknown')}",
                                            "high",
                                            {
                                                "url": nosql_result.get("url"),
                                                "method": nosql_result.get("method"),
                                                "parameter": finding.get("parameter"),
                                                "payload": finding.get("payload"),
                                                "evidence_type": finding.get("evidence_type"),
                                                "response_snippet": finding.get("response_snippet", "")[:200],
                                            },
                                            "CWE-943"
                                        ))
                            emit_progress("active_nosql", 91, "NoSQL JSON body checks complete")
                    except Exception as e:
                        active_block.setdefault("nosql_errors", []).append({"error": str(e)})

            except Exception as e:
                active_block["smart_error"] = str(e)
                # Smart mode failed - will fall back to legacy checks below

        # Track if smart mode ran successfully (no error)
        smart_succeeded = smart_mode and "smart_error" not in active_block

        # DOM XSS Analysis - run in smart mode after smart active tests
        # Analyzes JavaScript files for source-to-sink flows that could lead to DOM-based XSS
        # Note: Always runs in smart mode regardless of --xss/--sqli filters (smart-mode feature)
        if smart_mode and smart_succeeded:
            try:
                # Get JS URLs from discovery data or crawl results (optional - function can self-discover)
                js_urls_for_dom_xss = []
                if smart_discovery_data:
                    js_urls_for_dom_xss = [
                        u for u in smart_discovery_data.get("all_urls", [])
                        if u and (u.endswith(".js") or ".js?" in u)
                    ]
                if not js_urls_for_dom_xss and crawl_urls:
                    js_urls_for_dom_xss = [
                        u for u in crawl_urls
                        if u and (u.endswith(".js") or ".js?" in u)
                    ]
                if seed_js_urls:
                    js_urls_for_dom_xss.extend([u for u in seed_js_urls if u])
                if js_urls_for_dom_xss:
                    js_urls_for_dom_xss = list(dict.fromkeys(js_urls_for_dom_xss))

                # Always run DOM XSS analysis - function will self-discover JS if none provided
                if js_urls_for_dom_xss:
                    print(f"[scanner] Smart mode: Running DOM XSS analysis on {min(len(js_urls_for_dom_xss), dom_xss_max_files)} JS files (max: {dom_xss_max_files})", file=sys.stderr)
                else:
                    print(f"[scanner] Smart mode: Running DOM XSS analysis (self-discovering JS files, max: {dom_xss_max_files})", file=sys.stderr)
                emit_progress("active_dom_analysis", 91, "starting DOM XSS static analysis")

                dom_xss_results = await dom_xss_analysis(
                    url=base_url,
                    js_urls=js_urls_for_dom_xss[:dom_xss_max_files] if js_urls_for_dom_xss else None,
                    auth_session=auth_session,
                    max_files=dom_xss_max_files
                )

                active_block["dom_xss"] = dom_xss_results
                emit_progress("active_dom_analysis", 91, "DOM XSS static analysis complete")

                # Add normalized findings for DOM XSS vulnerabilities
                if dom_xss_results.get("findings"):
                    for f in dom_xss_results["findings"]:
                        # Only report findings with source nearby (higher confidence)
                        if f.get("source_nearby"):
                            severity = f.get("severity", "medium")
                            report["findings"].append(normalize_finding(
                                "dom_xss",
                                f"DOM-Based XSS ({f.get('sink_type', 'unknown sink')})",
                                severity,
                                {
                                    "file": f.get("file"),
                                    "line": f.get("line"),
                                    "snippet": f.get("snippet"),
                                    "sink_type": f.get("sink_type"),
                                    "source_pattern": f.get("source_pattern"),
                                    "source_nearby": f.get("source_nearby"),  # Include for validation
                                    "evidence": f.get("evidence"),
                                    "confidence": f.get("confidence", 0.7),
                                },
                                "CWE-79"
                            ))
                    print(f"[scanner] DOM XSS analysis: found {len(dom_xss_results['findings'])} potential vulnerabilities", file=sys.stderr)
            except Exception as e:
                active_block["dom_xss_error"] = str(e)
                print(f"[scanner] DOM XSS analysis error: {e}", file=sys.stderr)

        # Smart BOLA Testing - run in smart mode to detect authorization issues
        # Requires discovered URLs with ID patterns; user2_session enables cross-user comparison
        if smart_mode and smart_succeeded and not public_only:
            try:
                # Get discovered URLs from crawl + smart discovery + JS/HAR for BOLA pattern analysis
                bola_urls: list[str] = []
                bola_param_endpoints: list[dict[str, Any]] = []

                def _normalize_bola_url(raw_url: str) -> str | None:
                    if not raw_url or not isinstance(raw_url, str):
                        return None
                    u = raw_url.strip()
                    if not u:
                        return None
                    if u.startswith("//"):
                        u = "https:" + u
                    if u.startswith("/"):
                        u = urllib.parse.urljoin(base_url, u)
                    if not u.startswith("http"):
                        u = urllib.parse.urljoin(base_url + "/", u)
                    return u

                def _add_bola_urls(urls: list[str] | None) -> None:
                    if not urls:
                        return
                    for u in urls:
                        normalized = _normalize_bola_url(u)
                        if normalized:
                            bola_urls.append(normalized)

                if smart_discovery_data:
                    _add_bola_urls(smart_discovery_data.get("all_urls", []))
                    _add_bola_urls(smart_discovery_data.get("api_endpoints", []))
                    _add_bola_urls(smart_discovery_data.get("parameterized_urls", []))
                    _add_bola_urls(smart_discovery_data.get("recursive_paths", []))
                    bola_param_endpoints.extend(smart_discovery_data.get("endpoints_with_params", []) or [])

                if crawl_urls:
                    _add_bola_urls(crawl_urls)

                if browser_api_endpoints:
                    _add_bola_urls(browser_api_endpoints)

                if js_bundle_analysis and isinstance(js_bundle_analysis, dict):
                    _add_bola_urls(js_bundle_analysis.get("api_endpoints", []))

                if har_discovery_result and getattr(har_discovery_result, "endpoints", None):
                    for ep in har_discovery_result.endpoints:
                        ep_url = getattr(ep, "url", None)
                        if ep_url:
                            _add_bola_urls([ep_url])
                        # Collect query param hints for synthesis
                        params: list[str] = []
                        query_params = getattr(ep, "query_params", None)
                        if isinstance(query_params, dict):
                            params = list(query_params.keys())
                        elif isinstance(query_params, list):
                            params = [p for p in query_params if isinstance(p, str)]
                        if params and ep_url:
                            bola_param_endpoints.append({"url": ep_url, "params": params})

                # Deduplicate and cap
                bola_urls = list(dict.fromkeys(bola_urls))[:500]

                if bola_urls:
                    print(f"[scanner] Smart mode: Running BOLA/IDOR testing on {len(bola_urls)} discovered URLs", file=sys.stderr)
                    if user2_session:
                        print("[scanner] Multi-user BOLA: user2_session provided - cross-user comparison enabled", file=sys.stderr)
                    else:
                        print("[scanner] Single-user BOLA: no user2_session - unauthenticated access testing only", file=sys.stderr)
                    emit_progress("active_bola", 91, f"starting BOLA/IDOR testing on {len(bola_urls)} URLs")

                    bola_results = await smart_bola_test(
                        base_url=base_url,
                        discovered_urls=bola_urls,
                        user1_session=auth_session,
                        user2_session=user2_session,  # Only runs cross-user tests if provided
                        param_endpoints=bola_param_endpoints,
                        max_endpoints=smart_bola_max_endpoints,
                        timeout=10
                    )

                    active_block["smart_bola"] = bola_results
                    emit_progress("active_bola", 91, "BOLA/IDOR testing complete")

                    # Add findings to report
                    if bola_results.get("findings"):
                        for f in bola_results["findings"]:
                            report["findings"].append(normalize_finding(
                                "smart_bola",
                                f.get("title", "BOLA/IDOR Vulnerability"),
                                f.get("severity", "high"),
                                {
                                    "url": f.get("evidence", {}).get("url"),
                                    "test_id": f.get("evidence", {}).get("test_id"),
                                    "pattern_type": f.get("evidence", {}).get("pattern_type"),
                                    "description": f.get("description"),
                                    "response_snippet": f.get("evidence", {}).get("response_snippet", "")[:300],
                                },
                                f.get("cwe", "CWE-639")
                            ))
                        print(f"[scanner] Smart BOLA: found {len(bola_results['findings'])} vulnerabilities", file=sys.stderr)
                    else:
                        print(f"[scanner] Smart BOLA: no vulnerabilities found (tested {bola_results.get('endpoints_analyzed', 0)} endpoints)", file=sys.stderr)
            except Exception as e:
                active_block["smart_bola_error"] = str(e)
                print(f"[scanner] Smart BOLA error: {e}", file=sys.stderr)

        # Run active checks with a global timeout (standard mode or smart fallback on error)
        async def run_active_checks():
            for u in cand:
                try:
                    # Run selected tools concurrently for each URL
                    tasks: dict[str, asyncio.Task] = {}
                    if run_xss:
                        tasks["dalfox"] = asyncio.create_task(
                            dalfox_one(u, quick_mode, auth_session=auth_session, deep_domxss=dalfox_deep_domxss)
                        )
                        tasks["custom_xss"] = asyncio.create_task(custom_xss_test(u, auth_session=auth_session))
                    if run_sqli:
                        tasks["sqlmap"] = asyncio.create_task(sqlmap_test(u, quick_mode, auth_session=auth_session))
                        tasks["custom_sqli"] = asyncio.create_task(custom_sqli_test(u))

                    if not tasks:
                        continue

                    # Wait for all with timeout
                    try:
                        per_url_timeout = 90 if quick_mode else 300  # 90s quick, 5min thorough
                        results = await asyncio.wait_for(
                            asyncio.gather(*tasks.values(), return_exceptions=True),
                            timeout=per_url_timeout
                        )
                    except TimeoutError:
                        continue

                    results_by_name = dict(zip(tasks.keys(), results))

                    # Process XSS results (dalfox_one returns dict with "findings" key)
                    if run_xss:
                        xss = results_by_name.get("dalfox")
                        if not isinstance(xss, Exception) and xss:
                            xss_findings = xss.get("findings", []) if isinstance(xss, dict) else xss
                            xss_completed = xss.get("scan_completed", True) if isinstance(xss, dict) else True
                            if xss_findings:
                                active_block["dalfox"].extend(xss_findings)
                                for f in xss_findings:
                                    # Dalfox uses "severity" field with values "High", "Medium", "Low" (capitalized)
                                    # XSS is ALWAYS at minimum medium severity (CVSS 6.1+) - never downgrade to low
                                    dalfox_sev = (f.get("severity") or "medium").lower()
                                    severity = "high" if dalfox_sev == "high" else "medium"
                                    report["findings"].append(normalize_finding(
                                        "dalfox", f.get("type","XSS"), severity,
                                        {"url": u, "detail": f}
                                    ))
                            # Track scan status
                            if not xss_completed and "dalfox_errors" not in active_block:
                                active_block["dalfox_errors"] = []
                            if not xss_completed:
                                active_block["dalfox_errors"].append({"url": u, "error": xss.get("error")})

                        custom_xss = results_by_name.get("custom_xss")
                        if not isinstance(custom_xss, Exception) and custom_xss:
                            if custom_xss.get("vulnerable"):
                                active_block["custom_xss"].extend(custom_xss.get("findings", []))
                                for f in custom_xss.get("findings", []):
                                    report["findings"].append(normalize_finding(
                                        "custom_xss",
                                        f"Cross-Site Scripting ({f.get('payload_type', 'unknown')})",
                                        f.get("severity", "medium"),
                                        {
                                            "url": f.get("url"),
                                            "parameter": f.get("parameter"),
                                            "payload": f.get("payload"),
                                            "evidence": f.get("evidence"),
                                            "context": f.get("context"),
                                        },
                                        "CWE-79"
                                    ))

                    # Process SQLi results (sqlmap_test returns dict with scan_completed flag)
                    if run_sqli:
                        srep = results_by_name.get("sqlmap")
                        if not isinstance(srep, Exception) and srep:
                            sql_completed = srep.get("scan_completed", True)
                            if srep.get("vulnerable") or srep.get("summary") == "possible SQLi":
                                active_block["sqlmap"].append({"url": u, **srep})
                                report["findings"].append(normalize_finding(
                                    "sqlmap", "Potential SQL injection", "high", {"url": u, "summary": srep.get("summary")}
                                ))
                            # Track scan status
                            if not sql_completed:
                                if "sqlmap_errors" not in active_block:
                                    active_block["sqlmap_errors"] = []
                                active_block["sqlmap_errors"].append({"url": u, "error": srep.get("error")})

                        custom_sql = results_by_name.get("custom_sqli")
                        if not isinstance(custom_sql, Exception) and custom_sql:
                            if custom_sql.get("vulnerable"):
                                active_block["custom_sqli"].extend(custom_sql.get("findings", []))
                                for f in custom_sql.get("findings", []):
                                    report["findings"].append(normalize_finding(
                                        "custom_sqli",
                                        f"SQL Injection ({f.get('payload_type', 'unknown')})",
                                        f.get("severity", "high"),
                                        {
                                            "url": f.get("url"),
                                            "parameter": f.get("parameter"),
                                            "payload": f.get("payload"),
                                            "evidence": f.get("evidence"),
                                        },
                                        "CWE-89"
                                    ))
                except Exception:
                    pass

        # Run legacy active checks if NOT in smart mode, OR if smart mode errored (fallback)
        if not smart_succeeded:
            try:
                total_timeout = 300 if quick_mode else 900  # 5min quick, 15min thorough
                await asyncio.wait_for(run_active_checks(), timeout=total_timeout)
            except TimeoutError:
                pass  # Continue with partial results
        report["active_checks"] = active_block
    elif active_checks and public_only:
        # Document that active checks were requested but skipped due to public_only mode
        report["active_checks"] = {
            "skipped": True,
            "reason": "Active scans disabled in public-only mode",
            "targets": [],
            "dalfox": [],
            "sqlmap": [],
            "custom_sqli": [],
            "custom_xss": []
        }

    # Emit configuration/metadata findings (CSP/Headers/Cookies/TLS/DNS/CORS/etc.)
    try:
        emit_config_findings(report)
    except Exception:
        # Do not fail the whole scan if emitter has a bug
        pass

    # =========================================================================
    # NOISE REDUCTION: Use unified validation pipeline with AI support
    # =========================================================================
    try:
        # Pre-filter: Remove findings marked for exclusion (e.g., noisy nuclei templates)
        excluded_count = 0
        findings_to_validate = []
        for finding in report.get("findings", []):
            if finding.get("excluded"):
                excluded_count += 1
                logging.debug(f"Excluded finding: {finding.get('title', 'Unknown')} - {finding.get('exclude_reason', 'No reason')}")
            else:
                findings_to_validate.append(finding)

        # Build response cache from findings evidence
        response_cache: dict[str, str] = {}
        for finding in findings_to_validate:
            evidence = finding.get("evidence", {})
            url = evidence.get("url", "")
            if url:
                response_body = evidence.get("response_body") or evidence.get("body") or evidence.get("content") or ""
                if response_body and url not in response_cache:
                    response_cache[url] = response_body

        # Configure validation pipeline
        # NOTE: Dedup disabled - let UI handle grouping/display of similar findings.
        # Backend dedup was removing legitimate findings due to fingerprint collisions
        # (e.g., all DNS policy findings got same fingerprint). Preserving all findings
        # gives users full visibility and allows UI to group as needed.
        pipeline_config = ValidationPipelineConfig(
            enable_heuristics=True,
            enable_poe=True,
            poe_safe_mode=True,
            enable_ai=pipeline_ai_enabled,
            ai_url=ai_url or os.environ.get("AI_URL", ""),
            ai_api_key=ai_api_key or os.environ.get("AI_API_KEY", ""),
            ai_model=ai_model,
            enable_dedup=False,  # Disabled - see comment above
            filter_low_confidence=True,
            min_confidence_to_report=0.35,
        )

        # Run the unified validation pipeline
        validated_findings, pipeline_stats = await validate_findings_pipeline(
            findings=findings_to_validate,
            response_cache=response_cache,
            config=pipeline_config,
        )

        # Mark high-severity findings with low/marginal confidence for manual verification
        # This catches findings like "Potential sensitive data exposed" with confidence 0.4
        needs_verification = []
        for finding in validated_findings:
            confidence = finding.get("confidence", 0.5)
            severity = finding.get("severity", "medium").lower()
            if severity in ("high", "critical") and confidence < 0.75:
                finding["needs_verification"] = True
                finding["verification_reason"] = f"Confidence {confidence:.0%} below 75% for {severity}-severity finding"
                needs_verification.append(finding)

        report["findings"] = apply_dast_precision_policy(validated_findings)

        # Apply targeted dedup (CORS from multiple tools, XXE grouping, etc.)
        # Note: This is separate from the pipeline dedup which was disabled due to fingerprint issues
        report["findings"] = apply_dast_precision_policy(deduplicate_findings(report["findings"]))

        # Build noise reduction stats from pipeline stats
        total_original = pipeline_stats.get("input_count", 0) + excluded_count
        total_removed = (
            excluded_count +
            pipeline_stats.get("deduplicated", 0) +
            pipeline_stats.get("filtered", 0)
        )
        report["noise_reduction_stats"] = {
            "original_count": total_original,
            "excluded_count": excluded_count,
            "deduplicated_count": pipeline_stats.get("deduplicated", 0),
            "filtered_count": pipeline_stats.get("filtered", 0),
            "reported_count": len(validated_findings),
            "needs_verification_count": len(needs_verification),
            "reduction_rate": round(total_removed / max(total_original, 1) * 100, 1),
            "pipeline_stats": {
                "heuristic_validated": pipeline_stats.get("heuristic_validated", 0),
                "poe_attempted": pipeline_stats.get("poe_attempted", 0),
                "poe_proven": pipeline_stats.get("poe_proven", 0),
                "ai_validated": pipeline_stats.get("ai_validated", 0),
                "ai_fp_detected": pipeline_stats.get("ai_fp_detected", 0),
            }
        }
    except NameError:
        # validate_findings_pipeline not available (module not imported)
        pass
    except Exception as e:
        logging.warning(f"Finding validation pipeline failed: {e}")
        import traceback
        traceback.print_exc()

    emit_progress("validation", 92, "finding validation complete")

    # Save checkpoint with all findings collected
    save_checkpoint(report, "findings_complete")

    # Assess scan completeness before grading
    coverage = assess_scan_completeness(
        report,
        public_only=public_only,
        active_checks_requested=active_checks,
        js_dependency_scanning=js_dependency_scanning,
        js_secret_scanning=js_secret_scanning,
    )
    report["coverage"] = coverage

    # =========================================================================
    # VERIFICATION PHASE: Verify findings at/above configured severity before grading
    # =========================================================================
    # Run verification BEFORE grading so downgraded severities are reflected
    # in the final grade. Only run in smart mode to avoid slowing down standard scans.
    if smart_mode:
        pre_verification_findings = report.get("findings", [])
        verify_min_rank = AI_CLASSIFICATION_SEVERITY_ORDER.get(
            verify_min_severity,
            AI_CLASSIFICATION_SEVERITY_ORDER["high"],
        )
        verifiable_count = sum(
            1
            for f in pre_verification_findings
            if AI_CLASSIFICATION_SEVERITY_ORDER.get(str(f.get("severity") or "").lower(), 0) >= verify_min_rank
        )
        verification_summary = {
            "enabled": True,
            "min_severity": verify_min_severity,
            "eligible_findings": verifiable_count,
            "attempted": 0,
            "verified": 0,
            "downgraded": 0,
            "skipped": 0,
            "error": None,
        }

        if verifiable_count > 0:
            print(
                f"[verification] Verifying {verifiable_count} findings (min severity: {verify_min_severity})...",
                file=sys.stderr,
            )
            try:
                verification_result = await verify_high_severity_findings(
                    findings=pre_verification_findings,
                    auth_session=auth_session,
                    verify_xss=True,
                    verify_sqli=True,
                    max_verification_attempts=3,
                    min_severity=verify_min_severity,
                    include_summary=True,
                )
                if isinstance(verification_result, tuple):
                    verified_findings, phase_summary = verification_result
                else:
                    verified_findings, phase_summary = verification_result, {}
                if isinstance(phase_summary, dict):
                    verification_summary.update(phase_summary)
                report["findings"] = verified_findings
            except Exception as e:
                print(f"[verification] Warning: Verification phase failed: {e}", file=sys.stderr)
                verification_summary["error"] = str(e)
                # Continue with unverified findings

        report["verification_phase"] = {"summary": verification_summary}

    if verified_findings_only:
        all_findings = report.get("findings") or []
        pre_filter_count = len(all_findings)
        verified = []
        unverified = []
        for f in all_findings:
            if isinstance(f, dict) and finding_has_verification_evidence(f):
                verified.append(f)
            else:
                unverified.append(f)
        report["findings"] = verified
        # Preserve unverified findings for audit/review (not graded, not in primary output)
        report["unverified_findings"] = unverified
        post_filter_count = len(verified)
        dropped_count = max(0, pre_filter_count - post_filter_count)
        report.setdefault("filters_applied", {})
        report["filters_applied"]["verified_findings_only"] = {
            "enabled": True,
            "kept": post_filter_count,
            "dropped": dropped_count,
        }
        print(
            f"[filters] verified_findings_only enabled: kept={post_filter_count} dropped={dropped_count}",
            file=sys.stderr,
        )

    # Attack chain analysis (optional)
    def _empty_attack_chains(error_message: str | None = None) -> dict[str, Any]:
        payload = {
            "chains": [],
            "partial_chains": [],
            "summary": {
                "total_chains": 0,
                "total_partial_chains": 0,
                "critical_chains": 0,
                "high_chains": 0,
                "chain_types": [],
                "partial_chain_types": [],
                "partial_chains_included": include_partial_attack_chains,
            },
        }
        if error_message:
            payload["error"] = error_message
        return payload

    # Save checkpoint before final analysis
    save_checkpoint(report, "pre_finalize")

    if report.get("findings"):
        report["findings"] = apply_dast_precision_policy(report["findings"])
        if analyze_attack_chains:
            try:
                report["attack_chains"] = analyze_attack_chains(
                    report["findings"],
                    include_partial_chains=include_partial_attack_chains,
                )
            except Exception as e:
                report["attack_chains"] = _empty_attack_chains(str(e))
        else:
            report["attack_chains"] = _empty_attack_chains("attack_chains module unavailable")

    if report.get("attack_chains"):
        emit_progress("attack_chains", 95, "attack chain analysis complete")

    # Calculate grade
    emit_progress("finalizing", 97, "grading report")
    grade_result = grade(report)
    await asyncio.sleep(0)  # yield to heartbeat

    # If required modules failed, mark grade as unreliable
    if not coverage["grade_reliable"]:
        grade_result["grade_reliable"] = False
        grade_result["grade_warning"] = "Grade may be inaccurate - required scan modules did not complete"
        grade_result["coverage_issues"] = coverage["issues"]
        # Optionally set grade to None or add indicator
        grade_result["original_grade"] = grade_result["grade"]
        grade_result["grade"] = grade_result["grade"] + "*"  # Mark with asterisk
        grade_result["summary"] = f"[INCOMPLETE] {grade_result['summary']}"
    else:
        grade_result["grade_reliable"] = True

    report["result"] = grade_result

    # Generate compliance report if requested
    if compliance_report and report.get("findings"):
        try:
            report["compliance"] = generate_compliance_report(
                findings=report["findings"],
                scan_results=report
            )
        except Exception as e:
            report["compliance"] = {"error": str(e)}
    await asyncio.sleep(0)  # yield to heartbeat

    # Add scan metadata (per SCANNER_REFERENCE.md spec)
    # Use the scan_session_id we created at the start for consistency
    # Enhanced metadata includes checks_skipped for transparency
    checks_skipped = []
    if active_checks and public_only:
        checks_skipped.append({
            "check": "active_checks",
            "reason": "Active scans disabled in public-only mode"
        })
    if js_dependency_scanning and public_only:
        checks_skipped.append({
            "check": "js_dependency_scanning",
            "reason": "JS scanning disabled in public-only mode"
        })
    if js_secret_scanning and public_only:
        checks_skipped.append({
            "check": "js_secret_scanning",
            "reason": "JS secret scanning disabled in public-only mode"
        })

    report["scan_metadata"] = {
        "scan_id": scan_session_id,
        "target": target,
        "completed_at": now_utc_iso(),
        "scan_mode": "smart" if smart_mode else ("complete" if complete_mode else ("quick" if quick_mode else "standard")),
        "coverage_status": coverage["status"],
        "schema_version": REPORT_SCHEMA_VERSION,
        "scanner_version": SCANNER_VERSION,
        "options": {
            "public_only": public_only,
            "active_checks_requested": active_checks,
            "ai_validation_enabled": pipeline_ai_enabled,
            "ai_scan_classification_enabled": scan_ai_classification_enabled,
            "ai_verify_min_severity": verify_min_severity,
            "include_partial_attack_chains": include_partial_attack_chains,
            "verified_findings_only": verified_findings_only,
            "focus_rules": len(focus_rules),
            "avoid_rules": len(avoid_rules),
            "auth_scenario": bool(auth_scenario),
        },
        "checks_skipped": checks_skipped,
        "pre_scan_warnings": pre_scan_issues if pre_scan_issues else None,
        "browser_fetch_error": browser_fetch_error,
    }

    # =========================================================================
    # SCAN QUALITY METRICS: Track signal quality and tool reliability
    # =========================================================================
    # Quality metrics help identify when scan results may be incomplete or
    # when findings may need additional validation.
    findings_list = report.get("findings", [])

    # Count findings by confidence tier
    confidence_distribution = {"verified": 0, "high": 0, "medium": 0, "low": 0, "uncertain": 0}
    for f in findings_list:
        tier = f.get("confidence_tier", "medium")
        if tier in confidence_distribution:
            confidence_distribution[tier] += 1

    # Count AI verdicts if present
    ai_verdicts = {"true_positive": 0, "false_positive": 0, "unclear": 0}
    for f in findings_list:
        verdict = f.get("ai_verdict", "")
        if verdict in ai_verdicts:
            ai_verdicts[verdict] += 1

    # Track which tools produced findings
    tools_with_findings = set()
    for f in findings_list:
        tool = f.get("tool", "")
        if tool:
            tools_with_findings.add(tool)

    # Severity distribution
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings_list:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Calculate quality score (0-100)
    # Higher score = more reliable scan results
    quality_score = 100

    # Penalize for tool failures
    if coverage["status"] != "complete":
        quality_score -= 20
    if checks_skipped:
        quality_score -= len(checks_skipped) * 5

    # Reward for AI validation
    if ai_verdicts["true_positive"] + ai_verdicts["false_positive"] > 0:
        quality_score += 10

    # Penalize for many uncertain or low-confidence findings
    total_findings = len(findings_list)
    if total_findings > 0:
        uncertain_ratio = confidence_distribution["uncertain"] / total_findings
        low_conf_ratio = (
            confidence_distribution["uncertain"] + confidence_distribution["low"]
        ) / total_findings
        if uncertain_ratio > 0.3:
            quality_score -= 15
        elif uncertain_ratio > 0.2:
            quality_score -= 10
        if low_conf_ratio > 0.5:
            quality_score -= 25
        elif low_conf_ratio > 0.3:
            quality_score -= 15

    # Reward for high-confidence findings
    if total_findings > 0:
        high_conf_ratio = (confidence_distribution["verified"] + confidence_distribution["high"]) / total_findings
        if high_conf_ratio > 0.7:
            quality_score += 10
        elif high_conf_ratio > 0.5:
            quality_score += 5

    confirmed_count = sum(1 for f in findings_list if f.get("verified") is True)
    suspected_high_count = sum(
        1
        for f in findings_list
        if f.get("severity") in ("high", "critical") and f.get("verified") is not True
    )
    needs_verification_count = sum(1 for f in findings_list if f.get("needs_verification"))
    if total_findings and confirmed_count == 0:
        quality_score -= 10
    if suspected_high_count:
        quality_score -= min(25, suspected_high_count * 8)
    if needs_verification_count:
        quality_score -= min(20, needs_verification_count * 3)

    quality_score = max(0, min(100, quality_score))

    # Quality grade
    if quality_score >= 90:
        quality_grade = "A"
    elif quality_score >= 80:
        quality_grade = "B"
    elif quality_score >= 70:
        quality_grade = "C"
    elif quality_score >= 60:
        quality_grade = "D"
    else:
        quality_grade = "F"

    report["quality_metrics"] = {
        "quality_score": quality_score,
        "quality_grade": quality_grade,
        "total_findings": total_findings,
        "severity_distribution": severity_counts,
        "confidence_distribution": confidence_distribution,
        "ai_validation": {
            "enabled": pipeline_ai_enabled,
            "verdicts": ai_verdicts,
        },
        "tools_with_findings": sorted(list(tools_with_findings)),
        "coverage_status": coverage["status"],
        "reliability_notes": [],
    }
    await asyncio.sleep(0)  # yield to heartbeat

    # Add reliability notes
    if coverage["status"] != "complete":
        report["quality_metrics"]["reliability_notes"].append(
            f"Some tools did not complete successfully (coverage: {coverage['status']})"
        )
    if confidence_distribution["uncertain"] > 0:
        report["quality_metrics"]["reliability_notes"].append(
            f"{confidence_distribution['uncertain']} finding(s) have uncertain confidence - manual review recommended"
        )
    if confidence_distribution["low"] > 0:
        report["quality_metrics"]["reliability_notes"].append(
            f"{confidence_distribution['low']} finding(s) have low confidence - validate before treating as exploitable"
        )
    if total_findings and confirmed_count == 0:
        report["quality_metrics"]["reliability_notes"].append(
            "No findings were confirmed by proof or verification"
        )
    if suspected_high_count:
        report["quality_metrics"]["reliability_notes"].append(
            f"{suspected_high_count} high/critical finding(s) are suspected, not confirmed"
        )
    if ai_verdicts["false_positive"] > 0:
        report["quality_metrics"]["reliability_notes"].append(
            f"{ai_verdicts['false_positive']} finding(s) marked as likely false positive by AI"
        )
    if checks_skipped:
        report["quality_metrics"]["reliability_notes"].append(
            f"{len(checks_skipped)} check(s) were skipped due to scan configuration"
        )

    # =========================================================================
    # TRIAGE: Separate confirmed vs suspected findings + coverage gaps
    # =========================================================================
    def _sample_findings(items: list[dict], limit: int = 5) -> list[dict[str, Any]]:
        sample = []
        for f in items[:limit]:
            sample.append({
                "id": f.get("id"),
                "title": f.get("title"),
                "severity": f.get("severity"),
                "tool": f.get("tool"),
                "url": f.get("url") or f.get("endpoint"),
            })
        return sample

    confirmed_findings = [f for f in findings_list if f.get("verified") is True]
    suspected_high = [
        f for f in findings_list
        if f.get("severity") in ("high", "critical") and not f.get("verified")
    ]
    needs_review = [
        f for f in findings_list
        if f.get("confidence_tier") in ("low", "uncertain")
    ]
    ai_false_positives = [f for f in findings_list if f.get("ai_verdict") == "false_positive"]
    verification_skipped = [f for f in findings_list if f.get("verification_skipped")]

    report["triage"] = {
        "confirmed": {
            "count": len(confirmed_findings),
            "sample": _sample_findings(confirmed_findings),
        },
        "suspected_high": {
            "count": len(suspected_high),
            "sample": _sample_findings(suspected_high),
        },
        "needs_review": {
            "count": len(needs_review),
            "sample": _sample_findings(needs_review),
        },
        "ai_false_positive": {
            "count": len(ai_false_positives),
            "sample": _sample_findings(ai_false_positives),
        },
        "verification_skipped": {
            "count": len(verification_skipped),
            "sample": _sample_findings(verification_skipped),
        },
    }
    await asyncio.sleep(0)  # yield to heartbeat

    coverage_gaps: list[str] = []
    if coverage.get("issues"):
        coverage_gaps.extend(coverage.get("issues") or [])

    smart_cov = report.get("smart_coverage")
    if not smart_cov and coverage_tracker:
        try:
            smart_cov = coverage_tracker.to_dict()
        except Exception:
            smart_cov = None
    smart_cov = smart_cov or {}
    endpoints_cov = smart_cov.get("endpoints") or {}
    if endpoints_cov.get("discovered") and endpoints_cov.get("coverage") is not None:
        if endpoints_cov.get("coverage", 1.0) < 0.3:
            coverage_gaps.append(
                f"Low endpoint coverage ({endpoints_cov.get('coverage'):.2f}) - increase crawl depth or authenticated coverage"
            )

    nuclei_cov = smart_cov.get("nuclei_templates") or {}
    if nuclei_cov.get("run") == 0 and not public_only:
        coverage_gaps.append("Nuclei templates not executed - check nuclei configuration or timeouts")

    auth_states = smart_cov.get("auth_states_tested") or []
    if auth_states == ["anonymous"]:
        coverage_gaps.append("Only anonymous auth state tested - authenticated coverage may be missing")

    report["coverage_gaps"] = {
        "count": len(coverage_gaps),
        "issues": coverage_gaps,
    }

    # Redact request bodies from findings before returning/saving reports.
    if report.get("findings"):
        for finding in report["findings"]:
            if "body" in finding:
                finding["body"] = _redact_body_for_report(
                    finding.get("body"),
                    finding.get("content_type"),
                )
    await asyncio.sleep(0)  # yield to heartbeat

    # Add smart coverage metrics without overwriting completeness coverage
    # report["coverage"] contains grade_reliable, issues, status from assess_scan_completeness
    # report["smart_coverage"] contains endpoints/params discovered/tested from CoverageTracker
    if coverage_tracker:
        report["smart_coverage"] = coverage_tracker.to_dict()

    # Cleanup PoE session to prevent memory leaks in long-lived workers
    try:
        from scanner_tools.proof_of_exploit import end_scan_session
        end_scan_session(scan_session_id)
    except (ImportError, NameError):
        pass

    # P0-3 FIX: Cancel background auth refresh task to prevent memory leaks
    if auth_refresh_task and not auth_refresh_task.done():
        auth_refresh_task.cancel()
        try:
            await auth_refresh_task
        except asyncio.CancelledError:
            pass  # Expected when cancelling

    return report

# ---------- AI review ----------
# Note: Config findings emitters and AI helpers moved to reporting.py module

AI_CLASSIFICATION_SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _is_truthy_env(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _normalize_ai_classification_min_severity(value: str | None, default: str = "high") -> str:
    severity = str(value or "").strip().lower()
    if severity not in AI_CLASSIFICATION_SEVERITY_ORDER:
        severity = str(default or "").strip().lower()
    if severity not in AI_CLASSIFICATION_SEVERITY_ORDER:
        severity = "high"
    return severity


async def ai_review_findings(
    report: dict[str, Any],
    model: str | None,
    ai_url: str | None,
    ai_api_key: str | None,
    exploit_level: str = "safe",
    public_only: bool = False,
    mask_host: str = "example.com",
    ai_fallback_model: str | None = None,
) -> dict[str, Any]:
    """Attach AI analysis per finding and aggregate logs.

    Uses external AI provider if configured for enhanced classification,
    combined with heuristic rules via hybrid confidence scoring.
    Also generates executive summary for non-technical stakeholders.

    Returns ai_logs summary structure.
    """
    # Be tolerant to partially formed reports
    host = (report.get("input", {}) or {}).get("normalized_host") or ""
    base_url = report.get("http", {}).get("final_url") or (f"https://{host}" if host else "https://example.com")
    http_status = report.get("http", {}).get("status")
    findings = report.get("findings", [])
    ai_scan_classification_enabled = _is_truthy_env(
        os.environ.get("AI_SCAN_CLASSIFICATION_ENABLED"),
        default=False,
    )
    ai_min_severity = _normalize_ai_classification_min_severity(
        os.environ.get("AI_CLASSIFY_MIN_SEVERITY"),
        default=os.environ.get("AI_VERIFY_MIN_SEVERITY", "high"),
    )
    min_rank = AI_CLASSIFICATION_SEVERITY_ORDER[ai_min_severity]
    ai_eligible_findings: list[dict[str, Any]] = []
    ai_skipped_due_to_severity_ids: set[str] = set()
    ai_skipped_due_to_disabled_ids: set[str] = set()
    for finding in findings:
        finding_id = finding.get("id")
        if not ai_scan_classification_enabled:
            if isinstance(finding_id, str) and finding_id:
                ai_skipped_due_to_disabled_ids.add(finding_id)
            continue
        finding_severity = str(finding.get("severity") or "").lower()
        finding_rank = AI_CLASSIFICATION_SEVERITY_ORDER.get(finding_severity, 0)
        if finding_rank >= min_rank:
            ai_eligible_findings.append(finding)
            continue
        if isinstance(finding_id, str) and finding_id:
            ai_skipped_due_to_severity_ids.add(finding_id)

    ai_logs: list[dict[str, Any]] = []
    tp = fp = unc = 0
    confs: list[float] = []

    # Build scan context for AI classification
    scan_context = {
        "host": host,
        "http": report.get("http", {}),
        "dns": report.get("dns", {}),
        "tls": report.get("tls", {}),
        "discovery": report.get("discovery", {}),
        "timestamp_utc": report.get("timestamp_utc")
    }

    # Try batch AI classification if provider available
    ai_results: dict[str, Any] = {}
    provider_used = False
    provider_status = None
    provider_attempted = False
    provider_error = None
    provider_latency_ms = None
    ai_meta: dict[str, Any] | None = None
    provider_models_used: list[str] = []
    provider_partial = False
    provider_finding_ids: set[str] = set()
    fallback_finding_ids: set[str] = set()
    classification_source_counts = {
        "provider": 0,
        "heuristic_fallback": 0,
        "heuristic_only": 0,
        "disabled": 0,
    }

    if ai_scan_classification_enabled and ai_url and ai_api_key and model and ai_eligible_findings:
        provider_attempted = True
        try:
            # Use the new classify_findings_batch function that actually parses AI responses
            ai_results, error, latency, ai_meta = await classify_findings_batch(
                ai_eligible_findings,
                scan_context,
                ai_url,
                ai_api_key,
                model,
                mask_host,
                fallback_models=ai_fallback_model,
            )
            provider_latency_ms = latency
            provider_used = bool(ai_meta.get("provider_used")) if isinstance(ai_meta, dict) else False
            if isinstance(ai_meta, dict):
                provider_models_used = [m for m in (ai_meta.get("used_models") or []) if isinstance(m, str)]
                provider_partial = bool(ai_meta.get("chunks_fallback", 0))
                provider_finding_ids = {str(fid) for fid in (ai_meta.get("provider_finding_ids") or []) if isinstance(fid, str)}
                fallback_finding_ids = {str(fid) for fid in (ai_meta.get("fallback_finding_ids") or []) if isinstance(fid, str)}
            if error:
                provider_error = error
            if provider_used:
                provider_status = 200
                if ai_meta:
                    report["ai_correlations"] = {
                        "cross_finding_correlations": ai_meta.get("cross_finding_correlations", []),
                        "overall_risk_assessment": ai_meta.get("overall_risk_assessment"),
                    }
        except Exception as e:
            provider_error = f"classification_error: {type(e).__name__}: {str(e)[:100]}"

    # Process each finding
    for f in findings:
        finding_id = f.get("id")

        # Build verification commands
        commands = _ai_safe_commands_for_finding(f, base_url, host)

        # Build plan (non-invasive)
        plan = {"steps": []}
        tool_l = (f.get("tool") or "").lower()
        title_l = (f.get("title") or "").lower()

        if "nosql" in title_l:
            plan["steps"].append({
                "type": "http_request",
                "request": {"url": base_url, "method": "POST", "headers": {"Content-Type": "application/json"}, "body": json.dumps({"$ne": "1"})},
                "expect": {"status_in": [200], "body_includes": ["id", "user", "success"], "header_contains": []}
            })

        if tool_l == "graphql_vulnerability" or "graphql" in title_l:
            ev = f.get("evidence") or {}
            endpoint = None
            if isinstance(ev.get("evidence"), list) and ev["evidence"]:
                if isinstance(ev["evidence"][0], dict):
                    endpoint = ev["evidence"][0].get("endpoint")
            ep = endpoint or "/graphql"
            plan["steps"].append({
                "type": "http_request",
                "request": {"url": urllib.parse.urljoin(base_url, ep), "method": "POST", "headers": {"Content-Type": "application/json"}, "body": json.dumps({"query": "{ __schema { types { name } } }"})},
                "expect": {"status_in": [200], "body_includes": ["__schema"], "header_contains": []}
            })

        if tool_l == "api_security" or any(k in title_l for k in ["openapi", "swagger", "api "]):
            plan["steps"].append({
                "type": "http_request",
                "request": {"url": urllib.parse.urljoin(base_url, "/openapi.json"), "method": "GET"},
                "expect": {"status_in": [200], "body_includes": ["paths"], "header_contains": ["application/json"]}
            })

        # Get heuristic verdict
        h_verdict, h_conf, h_rationale = _ai_rule_verdict(f, http_status, host)

        # Get AI result if available
        ai_result = ai_results.get(finding_id) if ai_results else None
        classification_source = "heuristic_only"
        if not ai_scan_classification_enabled:
            classification_source = "disabled"
        elif isinstance(finding_id, str) and finding_id in provider_finding_ids:
            classification_source = "provider"
        elif isinstance(finding_id, str) and finding_id in fallback_finding_ids:
            classification_source = "heuristic_fallback"
        elif isinstance(finding_id, str) and finding_id in ai_skipped_due_to_severity_ids:
            classification_source = "heuristic_only"
        elif ai_result and hasattr(ai_result, "classification_source"):
            classification_source = str(getattr(ai_result, "classification_source") or "heuristic_fallback")
        elif provider_attempted:
            classification_source = "heuristic_fallback"

        # Calculate hybrid confidence (combines heuristics + AI)
        if ai_result and hasattr(ai_result, 'verdict'):
            final_verdict, final_conf, final_rationale = calculate_hybrid_confidence(
                h_verdict, h_conf, h_rationale, ai_result
            )
        else:
            # AI not available - use heuristics with slight penalty
            final_verdict = h_verdict
            final_conf = max(0.4, h_conf * 0.9)
            final_rationale = h_rationale

        # Update counters
        if final_verdict == "true_positive":
            tp += 1
        elif final_verdict == "false_positive":
            fp += 1
        else:
            unc += 1
        confs.append(final_conf)

        # Get remediation from knowledge base
        kb_remediation = get_remediation_for_finding(f)

        # Build remediation object
        remediation_obj: dict[str, Any] = {}
        if kb_remediation:
            remediation_obj = {
                "title": kb_remediation.get("title"),
                "steps": kb_remediation.get("remediation_steps", []),
                "code_examples": kb_remediation.get("code_examples", {}),
                "documentation": kb_remediation.get("documentation_links", []),
                "effort": kb_remediation.get("effort"),
                "verification": kb_remediation.get("verification"),
            }

        # Merge AI remediation if available
        if ai_result and hasattr(ai_result, 'remediation') and ai_result.remediation:
            if "steps" not in remediation_obj or not remediation_obj["steps"]:
                remediation_obj["steps"] = ai_result.remediation
            else:
                remediation_obj["ai_suggestions"] = ai_result.remediation

        # Build AI recommendations
        ai_rec: dict[str, Any] = {
            "commands": commands,
            "plan": plan,
            "rationale": final_rationale,
        }
        if remediation_obj:
            ai_rec["remediation"] = remediation_obj

        # Add attack narrative if available from AI
        if ai_result and hasattr(ai_result, 'attack_narrative') and ai_result.attack_narrative:
            ai_rec["attack_narrative"] = ai_result.attack_narrative

        # Add AI verification steps if available
        if ai_result and hasattr(ai_result, 'verification_steps') and ai_result.verification_steps:
            ai_rec["ai_verification_steps"] = ai_result.verification_steps

        # Annotate finding only when scan-time AI classification is enabled.
        if ai_scan_classification_enabled:
            f["ai_verdict"] = final_verdict
            f["ai_confidence"] = round(final_conf, 2)
            f["ai_confidence_percent"] = int(round(final_conf * 100))
            f["ai_classification_source"] = classification_source
            f["ai_recommendations"] = ai_rec
        if classification_source in classification_source_counts:
            classification_source_counts[classification_source] += 1
        else:
            classification_source_counts["heuristic_only"] += 1

        # Per-finding log entry
        log_entry: dict[str, Any] = {
            "finding_id": finding_id,
            "title": f.get("title"),
            "verdict": final_verdict,
            "confidence": round(final_conf, 2),
            "confidence_percent": int(round(final_conf * 100)),
            "heuristic_verdict": h_verdict,
            "heuristic_confidence": round(h_conf, 2),
            "rationale": final_rationale,
            "commands": commands,
            "plan": plan,
            "classification_source": classification_source,
        }

        # Include AI verdict for comparison if available
        if ai_result and hasattr(ai_result, 'verdict') and classification_source == "provider":
            log_entry["ai_verdict_raw"] = ai_result.verdict
            log_entry["ai_confidence_raw"] = round(ai_result.confidence, 2) if hasattr(ai_result, 'confidence') else None
        elif ai_result and hasattr(ai_result, 'verdict'):
            log_entry["fallback_verdict_raw"] = ai_result.verdict
            log_entry["fallback_confidence_raw"] = round(ai_result.confidence, 2) if hasattr(ai_result, 'confidence') else None

        ai_logs.append(log_entry)

    # Generate executive summary if AI provider available
    executive_summary = None
    exec_summary_error = None
    if provider_used and findings:
        try:
            # Get real host from report to unmask in final output
            real_host = report.get("input", {}).get("normalized_host")
            exec_result, exec_error, exec_latency = await generate_executive_summary_ai(
                report,
                ai_url,
                ai_api_key,
                model,
                mask_host,
                real_host=real_host,
                fallback_models=ai_fallback_model,
            )
            if exec_error:
                exec_summary_error = exec_error
            else:
                executive_summary = exec_result
                # Add latency to total
                if exec_latency and provider_latency_ms:
                    provider_latency_ms += exec_latency
        except Exception as e:
            exec_summary_error = f"exec_summary_error: {type(e).__name__}"

    # Fallback: Generate template-based executive summary when AI fails or is unavailable
    if executive_summary is None and findings:
        executive_summary = _generate_fallback_executive_summary(report, findings, tp, fp, unc)

    cross_correlations = ai_meta.get("cross_finding_correlations", []) if ai_meta else []
    overall_risk_assessment = ai_meta.get("overall_risk_assessment") if ai_meta else None

    summary = {
        "counts": {"true_positive": tp, "false_positive": fp, "unclear": unc},
        "avg_confidence": round((sum(confs) / len(confs)) if confs else 0.0, 2),
        "model": model or os.environ.get("AI_MODEL"),
        "model_fallback": ai_fallback_model or os.environ.get("AI_FALLBACK_MODEL"),
        "provider_url": ai_url or os.environ.get("AI_URL"),
        "used_provider": provider_used,
        "provider_status": provider_status,
        "provider_attempted": provider_attempted,
        "provider_error": provider_error,
        "provider_latency_ms": provider_latency_ms,
        "provider_models_used": provider_models_used,
        "provider_partial": provider_partial,
        "classification_source_counts": classification_source_counts,
        "classification_enabled": ai_scan_classification_enabled,
        "classification_min_severity": ai_min_severity,
        "classification_eligible_findings": len(ai_eligible_findings),
        "classification_skipped_disabled": len(ai_skipped_due_to_disabled_ids),
        "classification_skipped_by_min_severity": len(ai_skipped_due_to_severity_ids),
        "masking": {"enabled": True, "replacement_host": mask_host},
        "executive_summary": executive_summary,
        "executive_summary_error": exec_summary_error,
        "cross_finding_correlations": cross_correlations,
        "overall_risk_assessment": overall_risk_assessment,
    }
    return {"summary": summary, "entries": ai_logs}

# ---------- CLI & API ----------

async def cli_main():
    ap = argparse.ArgumentParser(description="Site security scanner (DNS/TLS/Headers + Browser + Discovery; optional API & active checks).")
    ap.add_argument("target", nargs="?", help="Hostname or URL (e.g., example.com or https://example.com)")
    ap.add_argument("--dkim-selectors", help="Comma-separated DKIM selectors to check (e.g., default,google)")
    ap.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    ap.add_argument("--server", action="store_true", help="Run FastAPI server")
    ap.add_argument("--port", type=int, default=8080, help="Server port")

    # New options
    ap.add_argument("--openapi", help="OpenAPI/Swagger schema URL to test with Schemathesis")
    ap.add_argument("--api-token", help="Bearer token for API testing (Authorization header)")
    ap.add_argument("--endpoints", action="append", help="Manual endpoint (e.g., 'GET /api/v1/users id,email' or '/api/login')")
    ap.add_argument("--endpoints-file", help="File with manual endpoints (one per line, same format as --endpoints)")
    ap.add_argument("--active", action="store_true", help="Run active security checks (dalfox/sqlmap) on discovered/synthetic URLs")
    ap.add_argument("--xss", action="store_true", help="Run only XSS active checks (implies --active)")
    ap.add_argument("--sqli", action="store_true", help="Run only SQLi active checks (implies --active)")
    ap.add_argument("--deep-domxss", action="store_true", default=None, help="Enable dalfox deep DOM XSS (spawns headless browser; heavy)")
    ap.add_argument("--max-active", type=int, default=10, help="Max URLs for active checks (default 10)")
    ap.add_argument("--quick", action="store_true", help="Quick scan mode - faster but less thorough (affects active checks)")
    ap.add_argument("--no-browser", action="store_true", help="Disable browser-based scanning, use curl only (faster but less data)")
    ap.add_argument("--public", action="store_true", help="Public data collection only (no active scans)")
    ap.add_argument("--subfinder", action="store_true", help="Subdomain discovery mode - comprehensive CT log and passive enumeration")
    ap.add_argument("--subdomain-sources", default="all", help="Comma-separated subdomain sources: gungnir,subfinder,crtsh (default: all)")
    ap.add_argument("--subdomain-quick", action="store_true", help="Quick subdomain scan using Gungnir only (faster)")
    ap.add_argument("--nuclei", action="store_true", help="Nuclei scan mode - comprehensive vulnerability scan with all templates (10-30 min)")
    ap.add_argument("--complete", action="store_true", help="Complete scan mode - comprehensive security assessment (30-60 min)")
    ap.add_argument("--complete-tier", choices=["safe", "full", "aggressive"], default="safe",
                    help="Scan tier for complete mode: safe (30-45min), full (2-3hr), aggressive (3+hr)")
    ap.add_argument("--max-ports", type=int, default=1000, help="Max ports to scan in complete mode (default 1000)")
    ap.add_argument("--deep-discovery", action="store_true", help="Enable deep discovery with ffuf (complete mode)")
    ap.add_argument("--exploit-level", choices=["safe", "moderate", "aggressive"], default="safe", help="Exploit level for active tests")
    # AI-enabled review
    ap.add_argument("--ai", action="store_true", help="Enable AI-assisted verification of findings (non-invasive)")
    ap.add_argument("--model", help="AI model identifier (provider specific)")
    ap.add_argument("--ai-fallback-model", dest="ai_fallback_model", help="Comma-separated fallback AI model IDs")
    ap.add_argument("--ai-url", dest="ai_url", help="AI provider URL (HTTP endpoint)")
    ap.add_argument("--ai-api-key", dest="ai_api_key", help="AI provider API key")
    ap.add_argument("--ai-mask-host", dest="ai_mask_host", default="example.com", help="Replacement host sent to AI instead of the real target (default: example.com)")
    ap.add_argument("--include-partial-attack-chains", action="store_true", help="Include partial attack chains in report (analyst mode)")

    # ===========================================
    # Vulnerability Check Categories (opt-in)
    # ===========================================

    # Authentication & Access Control Vulnerabilities
    ap.add_argument("--csrf-testing", action="store_true", help="Test for CSRF vulnerabilities")
    ap.add_argument("--idor-testing", action="store_true", help="Test for IDOR/BOLA vulnerabilities")
    ap.add_argument("--default-creds-testing", action="store_true", help="Test for default credentials (safe mode)")
    ap.add_argument("--rate-limiting-testing", action="store_true", help="Test for missing rate limiting")
    ap.add_argument("--twofa-bypass-testing", action="store_true", help="Test for 2FA bypass vulnerabilities")
    ap.add_argument("--password-reset-testing", action="store_true", help="Test for password reset vulnerabilities")
    ap.add_argument("--session-mgmt-testing", action="store_true", help="Test for session management issues")

    # Injection & Input Validation Vulnerabilities
    ap.add_argument("--path-traversal-testing", action="store_true", help="Test for path traversal vulnerabilities")
    ap.add_argument("--deserialization-testing", action="store_true", help="Test for insecure deserialization (detection only)")

    # Web Application Vulnerabilities
    ap.add_argument("--file-upload-testing", action="store_true", help="Test for file upload vulnerabilities")
    ap.add_argument("--open-redirect-testing", action="store_true", help="Test for open redirect vulnerabilities")
    ap.add_argument("--host-header-testing", action="store_true", help="Test for host header injection")
    ap.add_argument("--business-logic-testing", action="store_true", help="Detect business logic vulnerability indicators")
    ap.add_argument("--api-security-testing", action="store_true", help="Test for API security issues (mass assignment, BFLA)")

    # WebSocket Security
    ap.add_argument("--websocket-testing", action="store_true", help="Test WebSocket endpoints for CSWSH, auth bypass, and other vulnerabilities")

    # Client-Side Exposure
    ap.add_argument("--js-dependency-scanning", action="store_true", help="Scan for vulnerable JavaScript dependencies (Retire.js methodology)")
    ap.add_argument("--js-secret-scanning", action="store_true", help="Scan for hardcoded secrets in JavaScript files")

    # Infrastructure Exposure
    ap.add_argument("--cicd-exposure", action="store_true", help="Test for exposed CI/CD configuration files")
    ap.add_argument("--package-exposure", action="store_true", help="Test for exposed package manager files")
    ap.add_argument("--cloud-bucket-testing", action="store_true", help="Test for publicly accessible cloud storage buckets")
    ap.add_argument("--backup-file-testing", action="store_true", help="Test for exposed backup files")

    # Access Control Checks
    ap.add_argument("--forced-browsing", action="store_true", help="Test for forced browsing/direct request vulnerabilities (privileged path enumeration)")
    ap.add_argument("--mass-assignment-testing", action="store_true", help="Test for mass assignment vulnerabilities (CWE-915, privilege escalation via parameters)")
    ap.add_argument("--bola-testing", action="store_true", help="Test for BOLA/IDOR vulnerabilities (API1:2023, broken object-level authorization)")

    # SSH Checks
    ap.add_argument("--ssh-testing", action="store_true", help="Test SSH configuration (password auth detection)")
    ap.add_argument("--ssh-port", type=int, default=22, help="SSH port to scan (default 22)")

    # New: IP Reputation & Threat Intelligence
    ap.add_argument("--ip-reputation", action="store_true", help="Check IP reputation against DNS blacklists and threat intelligence")
    ap.add_argument("--abuseipdb-key", type=str, help="AbuseIPDB API key for enhanced IP reputation (env: ABUSEIPDB_API_KEY)")
    ap.add_argument("--virustotal-key", type=str, help="VirusTotal API key for enhanced IP reputation (env: VIRUSTOTAL_API_KEY)")

    # New: Brand Protection & Typosquatting
    ap.add_argument("--typosquatting", action="store_true", help="Detect typosquatting/lookalike domains")
    ap.add_argument("--max-typo-checks", type=int, default=100, help="Maximum typosquatting permutations to check (default: 100)")

    # New: Enhanced DNS Security
    ap.add_argument("--enhanced-dns", action="store_true", help="Enable enhanced DNS checks (DKIM, SPF validation, zone transfer)")
    ap.add_argument("--dkim-enumeration", action="store_true", help="Enumerate DKIM selectors")
    ap.add_argument("--zone-transfer-test", action="store_true", help="Test for DNS zone transfer (AXFR) vulnerability")

    # New: Domain Intelligence
    ap.add_argument("--domain-intelligence", action="store_true", help="Enable domain intelligence (WHOIS, age, expiration, registrar reputation)")

    # New: CT Monitoring
    ap.add_argument("--ct-monitoring", action="store_true", help="Enable certificate transparency monitoring (CA diversity, suspicious certs)")

    # New: SMTP Security
    ap.add_argument("--smtp-security", action="store_true", help="Enable SMTP security testing (STARTTLS, open relay, banner analysis)")

    # New: ASN Discovery
    ap.add_argument("--asn-discovery", action="store_true", help="Enable ASN/IP discovery (hosting provider, geographic distribution, multi-homing)")

    # New: Compliance Report
    ap.add_argument("--compliance-report", action="store_true", help="Generate compliance report (PCI DSS, SOC 2, HIPAA, GDPR, CIS)")

    # New: Network Services
    ap.add_argument("--network-services", action="store_true", help="Enable network services detection (VPN, RDP, VNC, IoT, Industrial, databases)")

    # New: Authenticated Scanning
    ap.add_argument("--auth-cookies", type=str, help="Session cookies for authenticated scanning (e.g., 'session=abc; token=xyz')")
    ap.add_argument("--auth-header", type=str, help="Authorization header for authenticated scanning (e.g., 'Bearer token123')")
    ap.add_argument("--auth-headers-json", type=str, help="Custom auth headers as JSON (e.g., '{\"X-API-Key\": \"abc\"}')")
    ap.add_argument("--auth-scenario-json", type=str, help="Auth scenario DSL JSON (login flow, credentials, success condition)")

    # New: Form-Based Login
    ap.add_argument("--login-url", type=str, help="Login page URL for form-based authentication (auto-detected if not provided)")
    ap.add_argument("--login-username", type=str, help="Username for form-based login")
    ap.add_argument("--login-password", type=str, help="Password for form-based login")
    ap.add_argument("--login-extra-fields", type=str, help="Extra form fields as JSON (e.g., '{\"remember_me\": \"1\"}')")
    ap.add_argument("--auto-auth", action="store_true", help="Attempt API login with provided credentials (JSON/form endpoints)")

    # New: OAuth 2.0/OIDC Authentication
    ap.add_argument("--oauth-client-id", type=str, help="OAuth 2.0 client ID")
    ap.add_argument("--oauth-client-secret", type=str, help="OAuth 2.0 client secret")
    ap.add_argument("--oauth-token-url", type=str, help="OAuth token endpoint URL (auto-discovered via OIDC if not provided)")
    ap.add_argument("--oauth-scope", type=str, help="OAuth scopes (space-separated)")
    ap.add_argument("--oauth-username", type=str, help="Username for OAuth password grant flow")
    ap.add_argument("--oauth-password", type=str, help="Password for OAuth password grant flow")

    # New: Second User Auth (for BOLA/IDOR testing - compare access between users)
    ap.add_argument("--user2-cookies", type=str, help="Session cookies for second user (BOLA comparison)")
    ap.add_argument("--user2-header", type=str, help="Authorization header for second user (BOLA comparison)")
    ap.add_argument("--user2-login-username", type=str, help="Username for second user form login")
    ap.add_argument("--user2-login-password", type=str, help="Password for second user form login")

    # New: Breach Monitoring
    ap.add_argument("--breach-check", action="store_true", help="Check for credential breaches and leaks (HIBP, GitHub)")
    ap.add_argument("--hibp-api-key", type=str, help="HIBP API key for email breach lookups (env: HIBP_API_KEY)")
    ap.add_argument("--github-token", type=str, help="GitHub token for code search (env: GITHUB_TOKEN)")

    # New: SARIF Output (CI/CD Integration)
    ap.add_argument("--sarif", type=str, help="Output SARIF file for CI/CD integration (e.g., results.sarif)")
    ap.add_argument("--quality-gate", action="store_true", help="Enable quality gate (exit code 1 if critical/high findings)")
    ap.add_argument("--max-critical", type=int, default=0, help="Max critical findings before quality gate fails (default: 0)")
    ap.add_argument("--max-high", type=int, default=0, help="Max high findings before quality gate fails (default: 0)")
    ap.add_argument("--max-medium", type=int, default=-1, help="Max medium findings before quality gate fails (-1 = unlimited)")
    ap.add_argument("--fail-on-high", action="store_true", help="Fail quality gate on high severity findings (alias for --max-high 0)")

    # New: Baseline/Ignore Support
    ap.add_argument("--baseline", type=str, help="Baseline file to filter known issues (suppress matching findings)")
    ap.add_argument("--create-baseline", type=str, help="Create baseline file from scan results (save known issues)")
    ap.add_argument("--show-suppressed", action="store_true", help="Include suppressed findings in output (marked with suppressed=true)")

    # New: Vendor/Third-Party Risk
    ap.add_argument("--vendor-risk", action="store_true", help="Assess third-party/vendor supply chain risk (CDN, analytics, dependencies)")

    # New: Cloud Security Enhancements
    ap.add_argument("--cloud-ssrf", action="store_true", help="Test for SSRF vulnerabilities targeting cloud metadata")
    ap.add_argument("--kubernetes-exposure", action="store_true", help="Test for exposed Kubernetes API servers")
    ap.add_argument("--terraform-exposure", action="store_true", help="Test for exposed Terraform state files")
    ap.add_argument("--registry-exposure", action="store_true", help="Test for exposed container registries")

    # Health check
    ap.add_argument("--health-check", action="store_true", help="Run tool health check and exit (validate all scanner tools are available)")
    ap.add_argument("--grpc-discovery", action="store_true", help="Enable gRPC reflection discovery (requires grpcurl)")
    ap.add_argument("--json-link-following", action="store_true", help="Follow JSON/HATEOAS links to expand API endpoints")
    ap.add_argument("--options-method-discovery", action="store_true", help="Use HTTP OPTIONS to enumerate allowed methods")
    ap.add_argument("--focus-rules-json", type=str, help="JSON array of focus rules to constrain endpoint scope")
    ap.add_argument("--avoid-rules-json", type=str, help="JSON array of avoid rules to exclude endpoint scope")
    ap.add_argument("--verified-findings-only", dest="verified_findings_only", action="store_true", default=None,
                    help="Only keep findings with exploit verification evidence (default for smart scans)")
    ap.add_argument("--no-verified-findings-only", dest="verified_findings_only", action="store_false",
                    help="Keep all findings regardless of verification status")

    # Category convenience flags (enable groups of checks)
    ap.add_argument("--vuln-auth", action="store_true", help="Enable all auth/access checks (CSRF, IDOR, Rate Limiting, 2FA, Password Reset, Session, Default Creds)")
    ap.add_argument("--vuln-injection", action="store_true", help="Enable all injection checks (Path Traversal, Deserialization)")
    ap.add_argument("--vuln-web", action="store_true", help="Enable all web app checks (File Upload, Open Redirect, Host Header, Business Logic, API Security, Forced Browsing, Cloud SSRF)")
    ap.add_argument("--exposure-client", action="store_true", help="Enable client-side exposure checks (JS Dependencies, JS Secrets)")
    ap.add_argument("--exposure-infra", action="store_true", help="Enable infrastructure exposure checks (CI/CD, Packages, Cloud Buckets, Backups, SSH, SMTP, Network Services, K8s/Terraform/Registry)")
    ap.add_argument("--threat-intel", action="store_true", help="Enable threat intelligence checks (IP Reputation, Breach Check, Vendor Risk, Typosquatting, Domain Intel, CT Monitoring, ASN Discovery, Enhanced DNS)")

    # ===========================================
    # Scan Type Presets
    # ===========================================
    # These are convenience flags that set multiple options at once:
    # --quick: Fast passive scan (DNS, TLS, headers) - 1-2 min
    # --standard: Standard scan (+ tech detection, basic nuclei) - 5-10 min
    # --deep: Deep scan (+ full nuclei, port scan, JS scanning) - 30-60 min (alias for --complete)
    # --full: Full assessment (+ active XSS/SQLi, all security tests) - 1-2 hours
    # --aggressive: Maximum coverage (+ aggressive exploit level) - 2+ hours
    ap.add_argument("--full", action="store_true", help="Full assessment - ALL security tests including active XSS/SQLi (1-2 hours)")
    ap.add_argument("--aggressive", action="store_true", help="Aggressive mode - maximum coverage with aggressive testing (2+ hours)")
    ap.add_argument("--smart", action="store_true", help="Smart scan - adaptive scanning with staged templates, recursive discovery, and context-aware attacks")
    ap.add_argument("--standard", action="store_true", help="Standard scan - balanced passive coverage (5-10 min)")
    ap.add_argument("--deep", action="store_true", help="Deep scan - thorough passive assessment (30-60 min, alias for --complete)")
    # Smart scan tuning options
    ap.add_argument("--no-early-stop", action="store_true", help="Disable early stopping in smart scan (continue even after finding many vulns)")
    ap.add_argument("--thorough-params", action="store_true", help="Test more parameters (100 endpoints x 10 params vs default 50x5)")
    ap.add_argument("--oob-callback-url", dest="oob_callback_url", help="Out-of-band callback URL for blind SQLi verification (e.g., Burp Collaborator)")
    ap.add_argument("--budget-profile", choices=["fast", "balanced", "thorough", "exhaustive"], default=None,
                    help="Depth/time budget profile. Scan type selects checks; budget controls how hard they run.")
    ap.add_argument("--budget-max-duration-minutes", type=int, dest="budget_max_duration_minutes")
    ap.add_argument("--budget-discovery-depth", type=int, dest="budget_discovery_depth")
    ap.add_argument("--budget-max-urls", type=int, dest="budget_max_urls")
    ap.add_argument("--budget-browser-max-pages", type=int, dest="budget_browser_max_pages")
    ap.add_argument("--budget-browser-max-depth", type=int, dest="budget_browser_max_depth")
    ap.add_argument("--budget-api-probe-limit", type=int, dest="budget_api_probe_limit")
    ap.add_argument("--budget-nuclei-max-targets", type=int, dest="budget_nuclei_max_targets")
    ap.add_argument("--budget-disable-nuclei-early-stop", action="store_true", dest="budget_disable_nuclei_early_stop")
    ap.add_argument("--budget-active-max-seconds", type=int, dest="budget_active_max_seconds")
    ap.add_argument("--budget-active-max-endpoints", type=int, dest="budget_active_max_endpoints")
    ap.add_argument("--budget-active-params-per-endpoint", type=int, dest="budget_active_params_per_endpoint")
    ap.add_argument("--budget-max-findings-per-family", type=int, dest="budget_max_findings_per_family",
                    help="-1 disables the per-family active finding cap")
    # Safety/performance limits
    ap.add_argument(
        "--smart-bola-max-endpoints",
        type=int,
        default=None,
        dest="smart_bola_max_endpoints",
        help=f"Max endpoints for smart BOLA testing (default: {SMART_SCAN_BUDGETS.smart_bola_max_endpoints})",
    )
    ap.add_argument(
        "--dom-xss-max-files",
        type=int,
        default=None,
        dest="dom_xss_max_files",
        help=f"Max JS files for DOM XSS analysis (default: {SMART_SCAN_BUDGETS.dom_xss_max_files})",
    )
    ap.add_argument(
        "--sqli-extract-max",
        type=int,
        default=None,
        dest="sqli_extract_max",
        help=f"Max SQLi findings to attempt data extraction (default: {SMART_SCAN_BUDGETS.sqli_extract_max})",
    )
    ap.add_argument(
        "--oob-max-findings",
        type=int,
        default=None,
        dest="oob_max_findings",
        help=f"Max SQLi findings to test with OOB payloads (default: {SMART_SCAN_BUDGETS.oob_max_findings})",
    )
    # Deprecated alias for backward compatibility (hidden from help)
    ap.add_argument("--oob-max-payloads", type=int, default=None, dest="oob_max_payloads_deprecated", help=argparse.SUPPRESS)

    args = ap.parse_args()

    # Handle deprecated --oob-max-payloads alias (only if new flag not explicitly set)
    if args.oob_max_findings is None and args.oob_max_payloads_deprecated is not None:
        print("[scanner] Warning: --oob-max-payloads is deprecated, use --oob-max-findings instead", file=sys.stderr)
        args.oob_max_findings = args.oob_max_payloads_deprecated

    # Apply default if neither was set
    if args.oob_max_findings is None:
        args.oob_max_findings = SMART_SCAN_BUDGETS.oob_max_findings

    # Auto-enable AI when environment variables are set
    if not args.ai_url:
        args.ai_url = os.environ.get("AI_URL")
    if not args.ai_api_key:
        args.ai_api_key = os.environ.get("AI_API_KEY")
    if args.ai_url and args.ai_api_key:
        args.ai = True

    raw_endpoint_lines: list[str] = []
    if args.endpoints:
        for entry in args.endpoints:
            if not entry:
                continue
            if "," in entry and not any(ch.isspace() for ch in entry):
                raw_endpoint_lines.extend([p.strip() for p in entry.split(",") if p.strip()])
            else:
                raw_endpoint_lines.append(entry.strip())
    if args.endpoints_file:
        try:
            with open(args.endpoints_file, "r", encoding="utf-8", errors="ignore") as f:
                raw_endpoint_lines.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"Warning: Failed to read endpoints file: {e}", file=sys.stderr)
    manual_endpoints = parse_manual_endpoints(raw_endpoint_lines)

    # DEBUG: Log parsed manual endpoints
    if manual_endpoints:
        print(f"[DEBUG] Parsed {len(manual_endpoints)} manual endpoints:", file=sys.stderr)
        for i, ep in enumerate(manual_endpoints[:5]):
            print(f"[DEBUG]   {i}: method={ep.get('method')} url={ep.get('url')} body_params={ep.get('body_params')} body_template={ep.get('body_template')}", file=sys.stderr)

    # Handle --health-check flag
    if args.health_check:
        # json already imported at module level, sys already imported at module level
        from scanner_tools.health_check import full_health_check, log_health_check_results

        print("Running scanner tool health check...", file=sys.stderr)
        results = await full_health_check()
        log_health_check_results(results)
        print(json.dumps(results, indent=2))

        # Exit with appropriate code
        if results.get("overall_status") == "failed":
            sys.exit(1)
        sys.exit(0)

    if args.server:
        import uvicorn
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import JSONResponse

        app = FastAPI(title="ShakerScan", version="2.0 (playwright)")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/healthz")
        async def healthz():
            return {"ok": True, "time": now_utc_iso()}

        @app.get("/health-check")
        async def health_check_endpoint():
            """Full tool health check - validates all scanner tools are available."""
            from scanner_tools.health_check import full_health_check
            results = await full_health_check()
            return results

        @app.get("/scan")
        async def scan(target: str,
                       dkim_selectors: str | None = None,
                       openapi: str | None = None,
                       api_token: str | None = None,
                       active: bool = False,
                       xss: bool = False,
                       sqli: bool = False,
                       deep_domxss: bool | None = None,
                       max_active: int = 10,
                       quick: bool = False,
                       no_browser: bool = False,
                       public: bool = False,
                       subfinder: bool = False,
                       subdomain_sources: str = "all",
                       subdomain_quick: bool = False,
                       complete: bool = False,
                       complete_tier: str = "safe",
                       max_ports: int = 1000,
                       deep_discovery: bool = False,
                       exploit_level: str = "safe",
                       ai: bool = False,
                       model: str | None = None,
                       ai_fallback_model: str | None = Query(default=None, alias="ai-fallback-model"),
                       ai_url: str | None = Query(default=None, alias="ai-url"),
                       ai_api_key: str | None = Query(default=None, alias="ai-api-key"),
                       ai_mask_host: str | None = Query(default="example.com", alias="ai-mask-host"),
                       include_partial_attack_chains: bool = False,
                       # Phase 1 Critical Checks
                       csrf_testing: bool = False,
                       idor_testing: bool = False,
                       path_traversal_testing: bool = False,
                       default_creds_testing: bool = False,
                       deserialization_testing: bool = False,
                       # Phase 2 Access Control & Auth Checks
                       rate_limiting_testing: bool = False,
                       twofa_bypass_testing: bool = False,
                       password_reset_testing: bool = False,
                       session_mgmt_testing: bool = False,
                       # Phase 3a: Client-Side Security
                       js_dependency_scanning: bool = False,
                       js_secret_scanning: bool = False,
                       # Phase 3b: Infrastructure & Configuration Leaks
                       cicd_exposure: bool = False,
                       package_exposure: bool = False,
                       cloud_bucket_testing: bool = False,
                       backup_file_testing: bool = False,
                       # Phase 4: P1 Priority Checks
                       file_upload_testing: bool = False,
                       open_redirect_testing: bool = False,
                       host_header_testing: bool = False,
                       business_logic_testing: bool = False,
                       api_security_testing: bool = False,
                       # WebSocket Security
                       websocket_testing: bool = False,
                       # Access Control Checks
                       forced_browsing_testing: bool = False,
                       mass_assignment_testing: bool = False,
                       bola_testing: bool = False,
                       # SSH Checks
                       ssh_testing: bool = False,
                       ssh_port: int = 22,
                       # New Security Enhancement Checks
                       ip_reputation: bool = False,
                       abuseipdb_key: str | None = None,
                       virustotal_key: str | None = None,
                       typosquatting: bool = False,
                       max_typo_checks: int = 100,
                       enhanced_dns: bool = False,
                       dkim_enumeration: bool = False,
                       zone_transfer_test: bool = False,
                       domain_intelligence: bool = False,
                       ct_monitoring: bool = False,
                       smtp_security: bool = False,
                       asn_discovery: bool = False,
                       compliance_report: bool = False,
                       network_services: bool = False,
                       auth_cookies: str | None = None,
                       auth_header: str | None = None,
                       auth_headers_json: str | None = None,
                       auth_scenario_json: str | None = None,
                       login_url: str | None = None,
                       login_username: str | None = None,
                       login_password: str | None = None,
                       login_extra_fields: str | None = None,
                       oauth_client_id: str | None = None,
                       oauth_client_secret: str | None = None,
                       oauth_token_url: str | None = None,
                       oauth_scope: str | None = None,
                       oauth_username: str | None = None,
                       oauth_password: str | None = None,
                       breach_check: bool = False,
                       hibp_api_key: str | None = None,
                       github_token: str | None = None,
                       cloud_ssrf: bool = False,
                       kubernetes_exposure: bool = False,
                       terraform_exposure: bool = False,
                       registry_exposure: bool = False,
                       vendor_risk: bool = False,
                       # Category convenience flags
                       vuln_auth: bool = False,
                       vuln_injection: bool = False,
                       vuln_web: bool = False,
                       exposure_client: bool = False,
                       exposure_infra: bool = False,
                       threat_intel: bool = False,
                       focus_rules_json: str | None = None,
                       avoid_rules_json: str | None = None,
                       verified_findings_only: bool | None = None):
            if not target:
                raise HTTPException(status_code=400, detail="target required")

            # Auto-enable AI when environment variables are set
            if not ai_url:
                ai_url = os.environ.get("AI_URL")
            if not ai_api_key:
                ai_api_key = os.environ.get("AI_API_KEY")
            if ai_url and ai_api_key:
                ai = True

            # Handle subdomain discovery mode (enhanced with Gungnir CT log scanning)
            if subfinder:
                # Extract domain from target URL
                if target.startswith('http://') or target.startswith('https://'):
                    from urllib.parse import urlparse
                    parsed = urlparse(target)
                    domain = parsed.netloc
                else:
                    domain = target

                # Parse subdomain sources
                sources = subdomain_sources.lower().split(",")
                use_gungnir = "all" in sources or "gungnir" in sources
                use_subfinder_source = "all" in sources or "subfinder" in sources
                use_crtsh = "all" in sources or "crtsh" in sources

                # Quick mode uses Gungnir only
                if subdomain_quick:
                    subdomains = await quick_subdomain_scan(domain, timeout=60)
                    report = {
                        "input": {
                            "target": target,
                            "normalized_host": domain,
                            "scan_type": "subdomain_discovery",
                            "mode": "quick"
                        },
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "subdomains": subdomains,
                        "subdomain_count": len(subdomains),
                        "result": {
                            "scan_type": "subdomain_discovery",
                            "domain": domain,
                            "subdomains_found": len(subdomains),
                            "summary": f"Quick subdomain discovery: {len(subdomains)} subdomains discovered"
                        }
                    }
                else:
                    # Run comprehensive subdomain discovery with all sources
                    discovery_result = await discover_subdomains(
                        domain,
                        use_gungnir=use_gungnir,
                        use_subfinder=use_subfinder_source,
                        use_crtsh=use_crtsh,
                    )

                    # Create detailed report
                    report = {
                        "input": {
                            "target": target,
                            "normalized_host": domain,
                            "scan_type": "subdomain_discovery",
                            "sources": {
                                "gungnir": use_gungnir,
                                "subfinder": use_subfinder_source,
                                "crtsh": use_crtsh,
                            }
                        },
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "subdomains": discovery_result["subdomains"],
                        "subdomain_count": discovery_result["count"],
                        "by_source": discovery_result.get("by_source", {}),
                        "source_stats": discovery_result.get("source_stats", {}),
                        "recommendations": discovery_result.get("recommendations", []),
                        "error": discovery_result.get("error"),
                        "result": {
                            "scan_type": "subdomain_discovery",
                            "domain": domain,
                            "subdomains_found": discovery_result["count"],
                            "gungnir_exclusive": discovery_result.get("source_stats", {}).get("gungnir_exclusive", 0),
                            "summary": f"Comprehensive subdomain discovery: {discovery_result['count']} subdomains discovered"
                        }
                    }

                return JSONResponse(report)

            sels = [s.strip() for s in (dkim_selectors or "").split(",") if s.strip()] if dkim_selectors else None

            # Handle category convenience flags
            # Auth & Access Control checks
            if vuln_auth:
                csrf_testing = True
                idor_testing = True
                default_creds_testing = True
                rate_limiting_testing = True
                twofa_bypass_testing = True
                password_reset_testing = True
                session_mgmt_testing = True

            # Injection checks
            if vuln_injection:
                path_traversal_testing = True
                deserialization_testing = True

            # Web Application checks
            if vuln_web:
                file_upload_testing = True
                open_redirect_testing = True
                host_header_testing = True
                business_logic_testing = True
                api_security_testing = True

            # Client-Side Exposure checks
            if exposure_client:
                js_dependency_scanning = True
                js_secret_scanning = True

            # Infrastructure Exposure checks
            if exposure_infra:
                cicd_exposure = True
                package_exposure = True
                cloud_bucket_testing = True
                backup_file_testing = True

            # Threat Intelligence checks
            if threat_intel:
                ip_reputation = True
                breach_check = True
                vendor_risk = True

            # Active check filters
            if xss or sqli:
                active = True
            active_xss = xss or not (xss or sqli)
            active_sqli = sqli or not (xss or sqli)

            rep = await build_report(
                target, sels,
                openapi_url=openapi,
                api_token=api_token,
                active_checks=active,
                active_xss=active_xss,
                active_sqli=active_sqli,
                deep_domxss=deep_domxss,
                max_active=max_active,
                quick_mode=quick,
                no_browser=no_browser or quick,  # Quick mode skips browser for speed
                public_only=public,
                complete_mode=complete,
                max_ports=max_ports,
                deep_discovery=deep_discovery,
                exploit_level=exploit_level,
                complete_tier=complete_tier,
                # Phase 1 Critical Checks
                csrf_testing=csrf_testing,
                idor_testing=idor_testing,
                path_traversal_testing=path_traversal_testing,
                default_creds_testing=default_creds_testing,
                deserialization_testing=deserialization_testing,
                # Phase 2 Access Control & Auth
                rate_limiting_testing=rate_limiting_testing,
                twofa_bypass_testing=twofa_bypass_testing,
                password_reset_testing=password_reset_testing,
                session_mgmt_testing=session_mgmt_testing,
                # Phase 3a: Client-Side Security
                js_dependency_scanning=js_dependency_scanning,
                js_secret_scanning=js_secret_scanning,
                # Phase 3b: Infrastructure & Configuration Leaks
                cicd_exposure_testing=cicd_exposure,
                package_exposure_testing=package_exposure,
                cloud_bucket_testing=cloud_bucket_testing,
                backup_file_testing=backup_file_testing,
                # Phase 4: P1 Priority Checks
                file_upload_testing=file_upload_testing,
                open_redirect_testing=open_redirect_testing,
                host_header_testing=host_header_testing,
                business_logic_testing=business_logic_testing,
                api_security_testing=api_security_testing,
                # WebSocket Security
                websocket_testing=websocket_testing,
                # Access Control Checks
                forced_browsing_testing=forced_browsing_testing,
                mass_assignment_testing=mass_assignment_testing,
                bola_testing=bola_testing,
                # SSH Checks
                ssh_testing=ssh_testing,
                ssh_port=ssh_port,
                # New Security Enhancement Checks
                ip_reputation=ip_reputation,
                abuseipdb_key=abuseipdb_key,
                virustotal_key=virustotal_key,
                typosquatting=typosquatting,
                max_typo_checks=max_typo_checks,
                enhanced_dns=enhanced_dns,
                dkim_enumeration=dkim_enumeration,
                zone_transfer_test=zone_transfer_test,
                domain_intelligence=domain_intelligence,
                ct_monitoring=ct_monitoring,
                smtp_security=smtp_security,
                asn_discovery=asn_discovery,
                compliance_report=compliance_report,
                network_services=network_services,
                auth_cookies=auth_cookies,
                auth_header=auth_header,
                auth_headers_json=auth_headers_json,
                auth_scenario_json=auth_scenario_json,
                login_url=login_url,
                login_username=login_username,
                login_password=login_password,
                login_extra_fields=login_extra_fields,
                oauth_client_id=oauth_client_id,
                oauth_client_secret=oauth_client_secret,
                oauth_token_url=oauth_token_url,
                oauth_scope=oauth_scope,
                oauth_username=oauth_username,
                oauth_password=oauth_password,
                breach_check=breach_check,
                hibp_api_key=hibp_api_key,
                github_token=github_token,
                cloud_ssrf=cloud_ssrf,
                kubernetes_exposure=kubernetes_exposure,
                terraform_exposure=terraform_exposure,
                registry_exposure=registry_exposure,
                # AI-powered finding validation (integrated into pipeline)
                ai_validation=ai,
                ai_url=ai_url,
                ai_api_key=ai_api_key,
                ai_model=model or "gpt-4o-mini",
                include_partial_attack_chains=include_partial_attack_chains,
                focus_rules_json=focus_rules_json,
                avoid_rules_json=avoid_rules_json,
                verified_findings_only=verified_findings_only,
            )
            if ai:
                try:
                    rep["ai_logs"] = await ai_review_findings(
                        rep,
                        model,
                        ai_url,
                        ai_api_key,
                        exploit_level=exploit_level,
                        public_only=public,
                        mask_host=ai_mask_host or "example.com",
                        ai_fallback_model=ai_fallback_model,
                    )
                    # Recompute grade now that AI has set ai_verdict on findings
                    rep["result"] = grade(rep)
                except Exception as e:
                    rep.setdefault("ai_logs", {})
                    rep["ai_logs"]["error"] = f"ai_review_failed: {e}"
            return JSONResponse(rep)

        @app.post("/retest")
        async def retest_finding(
            target: str = Query(..., description="Target URL to retest"),
            finding_type: str = Query(..., description="Type of finding: xss, sqli, ssrf, path_traversal"),
            param: str | None = Query(None, description="Parameter name to test"),
            payload: str | None = Query(None, description="Original payload that triggered the finding"),
            original_url: str | None = Query(None, description="Original URL where finding was detected"),
        ):
            """
            Retest a specific finding to verify if it's still present (fixed or not).

            This endpoint allows security teams to verify remediation by retesting
            specific vulnerabilities that were previously found.

            Returns:
                - still_vulnerable: bool - whether the issue still exists
                - proof: dict - proof of exploitation details
                - confidence: float - confidence level (0-1)
            """
            from scanner_tools.proof_of_exploit import (
                ExploitProof,
                prove_path_traversal,
                prove_sqli,
                prove_ssrf,
                prove_xss,
            )

            result = {
                "target": target,
                "finding_type": finding_type,
                "still_vulnerable": False,
                "proof": None,
                "tested_at": now_utc_iso(),
            }

            try:
                test_url = original_url or target
                proof: ExploitProof = ExploitProof()

                if finding_type.lower() in ["xss", "cross-site-scripting"]:
                    proof = await prove_xss(test_url, param or "", "", payload)
                elif finding_type.lower() in ["sqli", "sql-injection", "sql_injection"]:
                    proof = await prove_sqli(test_url, param or "", "")
                elif finding_type.lower() in ["path_traversal", "lfi", "path-traversal"]:
                    proof = await prove_path_traversal(test_url, param or "", "")
                elif finding_type.lower() in ["ssrf", "server-side-request-forgery"]:
                    proof = await prove_ssrf(test_url, param or "", "")
                else:
                    return JSONResponse({
                        "error": f"Unknown finding type: {finding_type}",
                        "supported_types": ["xss", "sqli", "path_traversal", "ssrf"]
                    }, status_code=400)

                result["still_vulnerable"] = proof.proven
                result["proof"] = proof.to_dict()
                result["confidence"] = proof.confidence

                if proof.proven:
                    result["status"] = "STILL_VULNERABLE"
                    result["message"] = "The vulnerability is still present and exploitable."
                else:
                    result["status"] = "LIKELY_FIXED"
                    result["message"] = "The vulnerability could not be reproduced. It may be fixed."

            except Exception as e:
                result["error"] = str(e)
                result["status"] = "ERROR"

            return JSONResponse(result)

        @app.get("/retest/status")
        async def retest_status():
            """Check retest endpoint status and capabilities."""
            return {
                "available": True,
                "supported_finding_types": [
                    "xss", "sqli", "path_traversal", "ssrf"
                ],
                "description": "Retest specific findings to verify remediation"
            }

        # Run startup health check
        try:
            from scanner_tools.health_check import full_health_check, log_health_check_results
            logging.info("Running startup health check...")
            health_results = await full_health_check()
            log_health_check_results(health_results)
            if health_results.get("overall_status") == "failed":
                logging.error("CRITICAL: Required scanner tools are missing. Some scans may fail.")
        except Exception as e:
            logging.warning(f"Startup health check failed: {e}")

        config = uvicorn.Config(app, host="0.0.0.0", port=args.port, loop="asyncio")
        server = uvicorn.Server(config)
        await server.serve()
        return

    if not args.target:
        print("error: target is required (or use --server)", file=sys.stderr)
        sys.exit(2)

    # Handle subdomain discovery mode - runs in complete isolation
    if args.subfinder:
        # Extract domain from target URL
        target = args.target
        if target.startswith('http://') or target.startswith('https://'):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            domain = parsed.netloc
        else:
            domain = target

        # Parse subdomain sources
        sources = args.subdomain_sources.lower().split(",") if hasattr(args, 'subdomain_sources') else ["all"]
        use_gungnir = "all" in sources or "gungnir" in sources
        use_subfinder = "all" in sources or "subfinder" in sources
        use_crtsh = "all" in sources or "crtsh" in sources

        # Quick mode uses Gungnir only
        if hasattr(args, 'subdomain_quick') and args.subdomain_quick:
            subdomains = await quick_subdomain_scan(domain, timeout=60)
            report = {
                "input": {
                    "target": args.target,
                    "normalized_host": domain,
                    "scan_type": "subdomain_discovery",
                    "mode": "quick"
                },
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "subdomains": subdomains,
                "subdomain_count": len(subdomains),
                "result": {
                    "scan_type": "subdomain_discovery",
                    "domain": domain,
                    "subdomains_found": len(subdomains),
                    "summary": f"Quick subdomain discovery: {len(subdomains)} subdomains discovered"
                }
            }
        else:
            # Run comprehensive subdomain discovery with all sources
            discovery_result = await discover_subdomains(
                domain,
                use_gungnir=use_gungnir,
                use_subfinder=use_subfinder,
                use_crtsh=use_crtsh,
            )

            # Create detailed report
            report = {
                "input": {
                    "target": args.target,
                    "normalized_host": domain,
                    "scan_type": "subdomain_discovery",
                    "sources": {
                        "gungnir": use_gungnir,
                        "subfinder": use_subfinder,
                        "crtsh": use_crtsh,
                    }
                },
                "timestamp_utc": datetime.now(UTC).isoformat(),
                "subdomains": discovery_result["subdomains"],
                "subdomain_count": discovery_result["count"],
                "by_source": discovery_result.get("by_source", {}),
                "source_stats": discovery_result.get("source_stats", {}),
                "recommendations": discovery_result.get("recommendations", []),
                "error": discovery_result.get("error"),
                "result": {
                    "scan_type": "subdomain_discovery",
                    "domain": domain,
                    "subdomains_found": discovery_result["count"],
                    "gungnir_exclusive": discovery_result.get("source_stats", {}).get("gungnir_exclusive", 0),
                    "summary": f"Comprehensive subdomain discovery: {discovery_result['count']} subdomains discovered"
                }
            }

        print(json.dumps(report, indent=2 if args.pretty else None, separators=None if args.pretty else (",",":")))
        return  # Exit immediately - do not run any other scans

    # Handle nuclei-only mode - comprehensive vulnerability scanning
    if args.nuclei:
        # Normalize target URL
        target = args.target
        if not target.startswith('http://') and not target.startswith('https://'):
            # Try HTTPS first
            target = f"https://{target}"

        # Run comprehensive nuclei scan
        nuclei_result = await nuclei_comprehensive_scan(target, rate_limit=5, timeout_per_request=15)

        # Get summary with defaults if not available
        summary = nuclei_result.get("summary", {
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "cvss_max": 0,
            "cvss_avg": 0
        })

        # Create nuclei-focused report
        report = {
            "input": {
                "target": args.target,
                "normalized_url": target,
                "scan_type": "nuclei_comprehensive"
            },
            "timestamp_utc": datetime.now(UTC).isoformat(),
            "scan_type": "nuclei",
            "nuclei_results": nuclei_result,
            "result": {
                "scan_type": "nuclei",
                "total_findings": summary["total_findings"],
                "critical": summary["critical_count"],
                "high": summary["high_count"],
                "medium": summary["medium_count"],
                "low": summary["low_count"],
                "info": summary["info_count"],
                "cvss_max": summary["cvss_max"],
                "cvss_avg": summary["cvss_avg"],
                "summary": f"Nuclei scan completed: {summary['total_findings']} findings (Critical: {summary['critical_count']}, High: {summary['high_count']}, Medium: {summary['medium_count']})",
                "scan_completed": nuclei_result.get("scan_completed", False),
                "duration_seconds": nuclei_result.get("statistics", {}).get("duration_seconds", 0)
            }
        }
        print(json.dumps(report, indent=2 if args.pretty else None, separators=None if args.pretty else (",",":")))
        return  # Exit immediately - do not run any other scans

    selectors = [s.strip() for s in (args.dkim_selectors or "").split(",") if s.strip()] if args.dkim_selectors else None

    # ===========================================
    # Expand scan type presets (--full, --aggressive, --deep, --standard)
    # ===========================================
    # --deep is alias for --complete
    if args.deep:
        args.complete = True

    # --full enables everything except aggressive exploit level
    if args.full:
        args.complete = True
        args.active = True
        args.nuclei = True
        args.vuln_auth = True
        args.vuln_injection = True
        args.vuln_web = True
        args.exposure_client = True
        args.exposure_infra = True
        args.websocket_testing = True
        args.enhanced_dns = True
        args.complete_tier = "full"
        args.max_active = 30  # Test more URLs for XSS/SQLi

    # --aggressive enables everything with aggressive settings
    if args.aggressive:
        args.complete = True
        args.active = True
        args.nuclei = True
        args.vuln_auth = True
        args.vuln_injection = True
        args.vuln_web = True
        args.exposure_client = True
        args.exposure_infra = True
        args.threat_intel = True
        args.websocket_testing = True
        args.enhanced_dns = True
        args.deep_discovery = True
        args.exploit_level = "aggressive"
        args.complete_tier = "aggressive"
        args.max_ports = 65535
        args.max_active = 50  # Test even more URLs for XSS/SQLi

    # --standard enables basic checks beyond quick
    if args.standard:
        args.nuclei = True
        args.js_dependency_scanning = True

    # --smart enables adaptive intelligent scanning
    # Note: staged nuclei and recursive discovery are handled via smart_mode flag
    # and DISCOVERY_CONFIG["smart"] profile respectively
    if args.smart:
        args.smart_mode = True  # Flag for smart scan orchestration
        args.complete = True
        args.active = True
        args.nuclei = True
        args.vuln_auth = True
        args.vuln_injection = True
        args.vuln_web = True
        args.exposure_client = True
        args.js_dependency_scanning = True
        args.js_secret_scanning = True
        args.websocket_testing = True
        args.enhanced_dns = True
        args.deep_discovery = True
        args.auto_auth = True
        args.json_link_following = True
        args.options_method_discovery = True
        args.grpc_discovery = True
        args.max_active = 50

    # Enforce active checks for smart/full/aggressive scan types
    # These scan types require active testing - public-only mode is incompatible
    active_enforced_scan_type = None
    if args.smart:
        active_enforced_scan_type = "smart"
    elif args.aggressive:
        active_enforced_scan_type = "aggressive"
    elif args.full:
        active_enforced_scan_type = "full"

    if active_enforced_scan_type:
        if args.public:
            print(f"Error: --public is incompatible with --{active_enforced_scan_type} scan type.", file=sys.stderr)
            print(f"  {active_enforced_scan_type.capitalize()} scans require active testing (XSS/SQLi probes).", file=sys.stderr)
            print("  Use --deep for passive-only comprehensive scanning, or remove --public.", file=sys.stderr)
            sys.exit(1)
        # Force active=True (redundant since already set, but explicit for safety)
        args.active = True
        args.active_enforced = True  # Metadata flag for reporting
    else:
        args.active_enforced = False

    # Active check filters
    if args.xss or args.sqli:
        args.active = True

    # Handle category convenience flags
    # Authentication & Access Control checks (--vuln-auth)
    vuln_auth = args.vuln_auth
    csrf_testing = vuln_auth or args.csrf_testing
    idor_testing = vuln_auth or args.idor_testing
    default_creds_testing = vuln_auth or args.default_creds_testing
    rate_limiting_testing = vuln_auth or args.rate_limiting_testing
    twofa_bypass_testing = vuln_auth or args.twofa_bypass_testing
    password_reset_testing = vuln_auth or args.password_reset_testing
    session_mgmt_testing = vuln_auth or args.session_mgmt_testing

    # Injection & Input Validation checks (--vuln-injection)
    vuln_injection = args.vuln_injection
    path_traversal_testing = vuln_injection or args.path_traversal_testing
    deserialization_testing = vuln_injection or args.deserialization_testing

    # Web Application checks (--vuln-web)
    vuln_web = args.vuln_web
    file_upload_testing = vuln_web or args.file_upload_testing
    open_redirect_testing = vuln_web or args.open_redirect_testing
    host_header_testing = vuln_web or args.host_header_testing
    business_logic_testing = vuln_web or args.business_logic_testing
    api_security_testing = vuln_web or args.api_security_testing
    websocket_testing = args.websocket_testing
    forced_browsing_testing = vuln_web or args.forced_browsing
    cloud_ssrf = vuln_web or args.cloud_ssrf

    # Client-Side Exposure checks (--exposure-client)
    exposure_client = args.exposure_client
    js_dependency_scanning = exposure_client or args.js_dependency_scanning
    js_secret_scanning = exposure_client or args.js_secret_scanning

    # Infrastructure Exposure checks (--exposure-infra)
    exposure_infra = args.exposure_infra
    cicd_exposure = exposure_infra or args.cicd_exposure
    package_exposure = exposure_infra or args.package_exposure
    cloud_bucket_testing = exposure_infra or args.cloud_bucket_testing
    backup_file_testing = exposure_infra or args.backup_file_testing
    ssh_testing = exposure_infra or args.ssh_testing
    smtp_security = exposure_infra or args.smtp_security
    network_services = exposure_infra or args.network_services
    kubernetes_exposure = exposure_infra or args.kubernetes_exposure
    terraform_exposure = exposure_infra or args.terraform_exposure
    registry_exposure = exposure_infra or args.registry_exposure

    # Threat Intelligence checks (--threat-intel) - includes DNS intel
    threat_intel = args.threat_intel
    ip_reputation = threat_intel or args.ip_reputation
    breach_check = threat_intel or args.breach_check
    vendor_risk = threat_intel or args.vendor_risk
    typosquatting = threat_intel or args.typosquatting
    domain_intelligence = threat_intel or args.domain_intelligence
    ct_monitoring = threat_intel or args.ct_monitoring
    asn_discovery = threat_intel or args.asn_discovery
    enhanced_dns = threat_intel or args.enhanced_dns
    dkim_enumeration = threat_intel or args.dkim_enumeration
    zone_transfer_test = threat_intel or args.zone_transfer_test

    # Active check selection (defaults to both unless filtered)
    active_xss = args.xss or not (args.xss or args.sqli)
    active_sqli = args.sqli or not (args.xss or args.sqli)
    custom_budget = {
        key: value
        for key, value in {
            "max_duration_minutes": getattr(args, "budget_max_duration_minutes", None),
            "discovery_depth": getattr(args, "budget_discovery_depth", None),
            "max_urls": getattr(args, "budget_max_urls", None),
            "browser_max_pages": getattr(args, "budget_browser_max_pages", None),
            "browser_max_depth": getattr(args, "budget_browser_max_depth", None),
            "api_probe_limit": getattr(args, "budget_api_probe_limit", None),
            "nuclei_max_targets": getattr(args, "budget_nuclei_max_targets", None),
            "active_max_seconds": getattr(args, "budget_active_max_seconds", None),
            "active_max_endpoints": getattr(args, "budget_active_max_endpoints", None),
            "active_params_per_endpoint": getattr(args, "budget_active_params_per_endpoint", None),
            "max_findings_per_family": (
                None if getattr(args, "budget_max_findings_per_family", None) == -1
                else getattr(args, "budget_max_findings_per_family", None)
            ),
            "smart_bola_max_endpoints": getattr(args, "smart_bola_max_endpoints", None),
            "dom_xss_max_files": getattr(args, "dom_xss_max_files", None),
            "sqli_extract_max": getattr(args, "sqli_extract_max", None),
            "oob_max_findings": getattr(args, "oob_max_findings", None),
        }.items()
        if value is not None
    }
    if getattr(args, "budget_disable_nuclei_early_stop", False):
        custom_budget["nuclei_early_stop"] = False

    report = await build_report(
        args.target,
        selectors,
        openapi_url=args.openapi,
        api_token=args.api_token,
        manual_endpoints=manual_endpoints,
        active_checks=args.active,
        active_xss=active_xss,
        active_sqli=active_sqli,
        deep_domxss=args.deep_domxss,
        max_active=args.max_active,
        quick_mode=args.quick,
        no_browser=args.no_browser or args.quick,  # Quick mode skips browser for speed
        public_only=args.public,
        complete_mode=args.complete,
        max_ports=args.max_ports,
        deep_discovery=args.deep_discovery,
        exploit_level=args.exploit_level,
        complete_tier=args.complete_tier,
        # Phase 1 Critical Checks
        csrf_testing=csrf_testing,
        idor_testing=idor_testing,
        path_traversal_testing=path_traversal_testing,
        default_creds_testing=default_creds_testing,
        deserialization_testing=deserialization_testing,
        # Phase 2 Access Control & Auth
        rate_limiting_testing=rate_limiting_testing,
        twofa_bypass_testing=twofa_bypass_testing,
        password_reset_testing=password_reset_testing,
        session_mgmt_testing=session_mgmt_testing,
        # Phase 3a: Client-Side Security
        js_dependency_scanning=js_dependency_scanning,
        js_secret_scanning=js_secret_scanning,
        # Phase 3b: Infrastructure & Configuration Leaks
        cicd_exposure_testing=cicd_exposure,
        package_exposure_testing=package_exposure,
        cloud_bucket_testing=cloud_bucket_testing,
        backup_file_testing=backup_file_testing,
        # Phase 4: P1 Priority Checks
        file_upload_testing=file_upload_testing,
        open_redirect_testing=open_redirect_testing,
        host_header_testing=host_header_testing,
        business_logic_testing=business_logic_testing,
        api_security_testing=api_security_testing,
        # WebSocket Security
        websocket_testing=websocket_testing,
        # Access Control Checks
        forced_browsing_testing=forced_browsing_testing,
        mass_assignment_testing=args.mass_assignment_testing,
        bola_testing=args.bola_testing,
        # SSH Checks
        ssh_testing=ssh_testing,
        ssh_port=args.ssh_port,
        # Security Enhancement Checks (many now controlled by category flags)
        ip_reputation=ip_reputation,
        abuseipdb_key=args.abuseipdb_key,
        virustotal_key=args.virustotal_key,
        typosquatting=typosquatting,
        max_typo_checks=args.max_typo_checks,
        enhanced_dns=enhanced_dns,
        dkim_enumeration=dkim_enumeration,
        zone_transfer_test=zone_transfer_test,
        domain_intelligence=domain_intelligence,
        ct_monitoring=ct_monitoring,
        smtp_security=smtp_security,
        asn_discovery=asn_discovery,
        compliance_report=args.compliance_report,
        network_services=network_services,
        auth_cookies=args.auth_cookies,
        auth_header=args.auth_header,
        auth_headers_json=args.auth_headers_json,
        auth_scenario_json=args.auth_scenario_json,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
        login_extra_fields=args.login_extra_fields,
        auto_auth=args.auto_auth,
        oauth_client_id=args.oauth_client_id,
        oauth_client_secret=args.oauth_client_secret,
        oauth_token_url=args.oauth_token_url,
        oauth_scope=args.oauth_scope,
        oauth_username=args.oauth_username,
        oauth_password=args.oauth_password,
        user2_cookies=args.user2_cookies,
        user2_header=args.user2_header,
        user2_login_username=args.user2_login_username,
        user2_login_password=args.user2_login_password,
        breach_check=breach_check,
        hibp_api_key=args.hibp_api_key,
        github_token=args.github_token,
        vendor_risk=vendor_risk,
        cloud_ssrf=cloud_ssrf,
        kubernetes_exposure=kubernetes_exposure,
        terraform_exposure=terraform_exposure,
        registry_exposure=registry_exposure,
        # AI-powered finding validation (integrated into pipeline)
        ai_validation=args.ai,
        ai_url=args.ai_url,
        ai_api_key=args.ai_api_key,
        ai_model=args.model or "gpt-4o-mini",
        include_partial_attack_chains=args.include_partial_attack_chains,
        grpc_discovery=args.grpc_discovery,
        json_link_following=args.json_link_following,
        options_method_discovery=args.options_method_discovery,
        focus_rules_json=args.focus_rules_json,
        avoid_rules_json=args.avoid_rules_json,
        verified_findings_only=args.verified_findings_only,
        # Smart scan mode
        smart_mode=getattr(args, 'smart_mode', False),
        # Smart scan tuning
        no_early_stop=getattr(args, 'no_early_stop', False),
        thorough_params=getattr(args, 'thorough_params', False),
        oob_callback_url=getattr(args, 'oob_callback_url', None),
        budget_profile=getattr(args, 'budget_profile', None),
        custom_budget=custom_budget or None,
        # Safety/performance limits
        smart_bola_max_endpoints=getattr(args, 'smart_bola_max_endpoints', None) or SMART_SCAN_BUDGETS.smart_bola_max_endpoints,
        dom_xss_max_files=getattr(args, 'dom_xss_max_files', None) or SMART_SCAN_BUDGETS.dom_xss_max_files,
        sqli_extract_max=getattr(args, 'sqli_extract_max', None) or SMART_SCAN_BUDGETS.sqli_extract_max,
        oob_max_findings=getattr(args, 'oob_max_findings', None) or SMART_SCAN_BUDGETS.oob_max_findings,
        # Active enforcement metadata
        active_enforced=getattr(args, 'active_enforced', False),
    )
    # Optional AI review attachment (batch classification + executive summary)
    if args.ai:
        try:
            ai = await ai_review_findings(
                report,
                args.model,
                args.ai_url,
                args.ai_api_key,
                exploit_level=args.exploit_level,
                public_only=args.public,
                mask_host=args.ai_mask_host,
                ai_fallback_model=getattr(args, "ai_fallback_model", None),
            )
            report["ai_logs"] = ai
            # Surface AI errors in result.notes for visibility
            ai_summary = ai.get("summary", {})
            if ai_summary.get("provider_error"):
                error_msg = str(ai_summary["provider_error"])[:80]
                report["result"]["notes"].append(f"AI analysis incomplete: {error_msg}")
            if ai_summary.get("executive_summary_error"):
                report["result"]["notes"].append("AI executive summary unavailable.")

            # Recompute grade now that AI has set ai_verdict on findings
            # This ensures false positives identified by AI don't penalize the score
            grade_result = grade(report)
            # Preserve coverage reliability info from original assessment
            coverage = report.get("coverage", {})
            if not coverage.get("grade_reliable", True):
                grade_result["grade_reliable"] = False
                grade_result["grade_warning"] = "Grade may be inaccurate - required scan modules did not complete"
                grade_result["coverage_issues"] = coverage.get("issues", [])
                grade_result["original_grade"] = grade_result["grade"]
                grade_result["grade"] = grade_result["grade"] + "*"
                grade_result["summary"] = f"[INCOMPLETE] {grade_result['summary']}"
            else:
                grade_result["grade_reliable"] = True
            report["result"] = grade_result
        except Exception as e:
            report.setdefault("ai_logs", {})
            report["ai_logs"]["error"] = f"ai_review_failed: {e}"
            report["result"]["notes"].append(f"AI review failed: {str(e)[:50]}")

    # Baseline filtering (apply before SARIF/quality gate)
    if args.baseline:
        try:
            baseline_data = load_baseline(args.baseline)
            original_findings_count = len(report.get("findings", []))
            report = filter_by_baseline(report, baseline_data, include_suppressed=args.show_suppressed)
            new_findings_count = len(report.get("findings", []))
            report["baseline"]["file"] = args.baseline
            print(f"Baseline applied: {original_findings_count - new_findings_count} findings suppressed, {new_findings_count} new findings", file=sys.stderr)
        except FileNotFoundError:
            print(f"Warning: Baseline file not found: {args.baseline}", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Failed to apply baseline: {e}", file=sys.stderr)

    # Create baseline from current scan (before any filtering)
    if args.create_baseline:
        try:
            baseline_data = create_baseline(report)
            save_baseline(baseline_data, args.create_baseline)
            report["baseline_created"] = {
                "file": args.create_baseline,
                "findings_count": baseline_data["findings_count"]
            }
            print(f"Baseline created: {args.create_baseline} ({baseline_data['findings_count']} findings)", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Failed to create baseline: {e}", file=sys.stderr)

    # SARIF output for CI/CD integration
    exit_code = 0
    if args.sarif:
        try:
            sarif_report = convert_to_sarif(report)
            write_sarif_file(sarif_report, args.sarif)
            report["sarif_output"] = {"file": args.sarif, "status": "success"}
        except Exception as e:
            report["sarif_output"] = {"file": args.sarif, "status": "error", "error": str(e)}

    # Quality gate check
    if args.quality_gate or args.fail_on_high:
        try:
            sarif_for_gate = convert_to_sarif(report) if not args.sarif else sarif_report
            max_high = 0 if args.fail_on_high else args.max_high
            gate_result = quality_gate_check(
                sarif_for_gate,
                max_critical=args.max_critical,
                max_high=max_high,
                max_medium=args.max_medium
            )
            report["quality_gate"] = {
                "passed": gate_result["passed"],
                "counts": gate_result["counts"],
                "thresholds": {
                    "max_critical": args.max_critical,
                    "max_high": max_high,
                    "max_medium": args.max_medium
                }
            }
            exit_code = gate_result["exit_code"]
        except Exception as e:
            report["quality_gate"] = {"error": str(e), "passed": False}
            exit_code = 1

    print(json.dumps(report, indent=2 if args.pretty else None, separators=None if args.pretty else (",",":")))

    # Exit with quality gate code if enabled
    if exit_code != 0:
        sys.exit(exit_code)

def _run_cli_with_shutdown_guard() -> int:
    """Run cli_main with bounded shutdown to avoid hangs on pending tasks."""
    exit_code = 0
    executor_shutdown_timed_out = False
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(cli_main())
    except KeyboardInterrupt:
        exit_code = 0
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        print(f"[scanner] Unhandled error: {e}", file=sys.stderr)
        exit_code = 1
    finally:
        try:
            pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
        except Exception:
            pending = []
        if pending:
            for task in pending:
                try:
                    task.cancel()
                except Exception:
                    pass
            # Best-effort cancellation with a short grace period.
            try:
                grace = float(os.environ.get("SCAN_SHUTDOWN_GRACE_SECONDS", "2"))
            except Exception:
                grace = 2.0
            if grace > 0:
                try:
                    loop.run_until_complete(asyncio.wait(pending, timeout=grace))
                except Exception:
                    pass
        # Best-effort shutdown of default executor to avoid hanging on non-daemon threads.
        try:
            grace = float(os.environ.get("SCAN_SHUTDOWN_GRACE_SECONDS", "2"))
        except Exception:
            grace = 2.0
        if grace < 0:
            grace = 0
        try:
            shutdown_coro = loop.shutdown_default_executor()
        except Exception:
            shutdown_coro = None
        if shutdown_coro is not None:
            try:
                loop.run_until_complete(asyncio.wait_for(shutdown_coro, timeout=grace or 0.1))
            except Exception:
                executor_shutdown_timed_out = True
                try:
                    default_executor = getattr(loop, "_default_executor", None)
                    if default_executor:
                        default_executor.shutdown(wait=False, cancel_futures=True)
                except Exception:
                    pass
        # Shutdown async generators to properly clean up subprocess transports
        # before closing the event loop (prevents "Event loop is closed" errors
        # during garbage collection of BaseSubprocessTransport objects)
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        except Exception:
            pass
        try:
            loop.stop()
        except Exception:
            pass
        # Force garbage collection while loop is still technically available
        # to allow subprocess transport __del__ methods to run cleanly
        import gc
        gc.collect()
        try:
            loop.close()
        except Exception:
            pass
        try:
            asyncio.set_event_loop(None)
        except Exception:
            pass
    if executor_shutdown_timed_out and os.environ.get("SCAN_FORCE_EXIT_ON_SHUTDOWN_TIMEOUT", "1") != "0":
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        except Exception:
            pass
        os._exit(exit_code)
    return exit_code


if __name__ == "__main__":
    code = _run_cli_with_shutdown_guard()
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:
        pass
    sys.exit(code)
