"""Unauthenticated sensitive-data exposure detector.

Fetches discovered API endpoints WITHOUT credentials and flags responses that
leak secrets/credentials/PII (cloud keys, JWTs, API keys, private keys, tokens in
logs, tenant-scoped admin listings). This is the generic DAST capability for
"GET /api/<x> returns a token/key/PII to anyone" — the most common high-severity
exposure class. Designed to run over the active worklist so it rides existing
discovery (OpenAPI/crawl/HAR) instead of a fixed wordlist.
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any

import httpx

# High-confidence secret/credential VALUE patterns (match the leaked value, not
# just a key name, to keep false positives low). Each maps to a finding family +
# CWE so the report carries a precise, deterministic title.
SENSITIVE_VALUE_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key id exposed", "cloud_credential_exposure", "CWE-522"),
    (
        r"(?i)secret[_-]?access[_-]?key[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+]{20,}",
        "AWS secret access key exposed", "cloud_credential_exposure", "CWE-522",
    ),
    (
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}",
        "JWT / bearer token exposed in response", "secret_token_exposure", "CWE-522",
    ),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "Private key exposed in response", "private_key_exposure", "CWE-522"),
    (
        r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}",
        "Bearer token exposed in response/logs", "secret_token_exposure", "CWE-522",
    ),
    (
        r"(?i)(vault[_-]?token|service[_-]?token|client[_-]?secret|access[_-]?token|refresh[_-]?token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9._\-/+]{12,}",
        "Secret credential exposed in response", "secret_token_exposure", "CWE-522",
    ),
    (
        r"(?i)\"?api[_-]?key\"?\s*[:=]\s*[\"']?[A-Za-z0-9._\-]{10,}",
        "API key exposed in response", "api_key_exposure", "CWE-522",
    ),
    (
        r"(?i)\"key\"\s*:\s*\"[A-Z0-9_]*(KEY|CANARY|SECRET|TOKEN)[A-Z0-9_]*\"",
        "Secret key field exposed in API listing", "api_key_exposure", "CWE-522",
    ),
    (r"\b\d{3}-\d{2}-\d{4}\b", "Possible SSN / PII exposed in response", "pii_exposure", "CWE-359"),
    (
        r"mongodb(\+srv)?://[^\s\"']+|postgres(ql)?://[^\s\"']+|mysql://[^\s\"']+",
        "Database connection string exposed", "secret_token_exposure", "CWE-522",
    ),
    (
        r"(?i)\"security_posture\"\s*:\s*\"(vulnerable|hardened|insecure)\"",
        "Internal trace/audit metadata exposed without auth", "audit_trace_exposure", "CWE-200",
    ),
]

# Common reflective markers that should NOT alone trigger a finding (reduce FPs on
# pages that merely mention these words without a leaked value).
_MAX_BODY_BYTES = 200_000


_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")


def _get_method_url(spec: Any) -> str | None:
    """Return a GET-able URL/path from a plain URL, a "METHOD /path" worklist
    string, or an endpoint dict. Only GET/HEAD are probed (exposure is a read)."""
    if isinstance(spec, str):
        s = spec.strip()
        if not s:
            return None
        parts = s.split(None, 1)
        if len(parts) == 2 and parts[0].upper() in _METHODS:
            if parts[0].upper() not in ("GET", "HEAD"):
                return None
            return parts[1].split()[0] if parts[1].split() else None
        return s
    if isinstance(spec, dict):
        method = str(spec.get("method") or "GET").upper()
        if method not in ("GET", "HEAD", ""):
            return None
        return spec.get("url") or spec.get("path")
    return None


async def check_api_data_exposure(
    base_url: str,
    endpoints: list[Any],
    *,
    auth_session: Any | None = None,  # noqa: ARG001 — intentionally unauth; kept for call symmetry
    max_endpoints: int = 250,
    concurrency: int = 12,
    timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Probe discovered endpoints unauthenticated; flag sensitive-data exposure.

    The vulnerability class is *unauthenticated* exposure, so we deliberately send
    no credentials. Returns raw finding dicts (title/severity/cwe/evidence) for the
    caller to normalize.
    """
    base = base_url.rstrip("/")
    host = urllib.parse.urlparse(base).netloc

    # Normalize to absolute, in-scope, GET-able, deduped URLs.
    seen: set[str] = set()
    urls: list[str] = []
    for spec in endpoints or []:
        raw = _get_method_url(spec)
        if not raw or not isinstance(raw, str):
            continue
        raw = raw.strip()
        if not raw:
            continue
        full = raw if raw.startswith("http") else urllib.parse.urljoin(base + "/", raw.lstrip("/"))
        if urllib.parse.urlparse(full).netloc != host:
            continue
        if full in seen:
            continue
        seen.add(full)
        urls.append(full)
        if len(urls) >= max_endpoints:
            break

    if not urls:
        return []

    findings: list[dict[str, Any]] = []
    findings_by_family: set[tuple[str, str]] = set()  # (family, url) dedupe
    sem = asyncio.Semaphore(max(1, concurrency))

    async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:

        async def probe(url: str) -> None:
            async with sem:
                try:
                    resp = await client.get(url, headers={"Origin": "https://evil.example"})
                except Exception:
                    return
                if resp.status_code >= 400:
                    return
                ctype = resp.headers.get("content-type", "")
                # CORS misconfig: reflects an arbitrary origin (or "*") WITH
                # credentials -> any site can read this (authenticated) response.
                acao = (resp.headers.get("access-control-allow-origin") or "").strip()
                acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()
                if acac == "true" and acao and (acao == "*" or "evil.example" in acao):
                    ckey = ("cors_credentialed_exposure", url)
                    if ckey not in findings_by_family:
                        findings_by_family.add(ckey)
                        findings.append({
                            "title": f"CORS allows credentialed cross-origin reads: {urllib.parse.urlparse(url).path}",
                            "severity": "high",
                            "tool": "data_exposure",
                            "type": "CORS Misconfiguration",
                            "cwe": "CWE-942",
                            "url": url,
                            "evidence": {
                                "url": url,
                                "access_control_allow_origin": acao,
                                "access_control_allow_credentials": acac,
                                "finding_family": "cors_credentialed_exposure",
                                "cvss_score": 7.5,
                            },
                        })
                # Skip HTML pages (UI / API docs / SPA) for the secret-value
                # patterns: sample JWT/API-key text in documentation or example
                # payloads must not become a high-severity finding. The CORS check
                # above already ran regardless of content type.
                if "html" in ctype.lower() or re.match(
                    r"\s*(<!doctype html|<html\b)", resp.text[:256], re.IGNORECASE
                ):
                    return
                body = resp.text[:_MAX_BODY_BYTES]
                for pattern, title, family, cwe in SENSITIVE_VALUE_PATTERNS:
                    m = re.search(pattern, body)
                    if not m:
                        continue
                    key = (family, url)
                    if key in findings_by_family:
                        break
                    findings_by_family.add(key)
                    snippet = body[max(0, m.start() - 40): m.start() + 80]
                    findings.append({
                        "title": f"{title}: {urllib.parse.urlparse(url).path}",
                        "severity": "high",
                        "tool": "data_exposure",
                        "type": "Sensitive Data Exposure",
                        "cwe": cwe,
                        "url": url,
                        "evidence": {
                            "url": url,
                            "status_code": resp.status_code,
                            "content_type": ctype,
                            "finding_family": family,
                            "match_snippet": re.sub(r"\s+", " ", snippet).strip(),
                            "unauthenticated": True,
                            # Pin CVSS so normalize_finding keeps this in the high band.
                            "cvss_score": 7.5,
                        },
                    })
                    break  # one finding per endpoint

        await asyncio.gather(*(probe(u) for u in urls))

    return findings
