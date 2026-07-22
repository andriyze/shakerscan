"""Broken-authorization / approval-workflow bypass detector.

State-changing approval endpoints (wire transfers, refunds, KYC review, manager
delegation, vendor approval, impersonation) must enforce authorization and
multi-party control. This probes such endpoints UNAUTHENTICATED with a benign
payload; if the endpoint reports the action as approved/succeeded (instead of a
401/403/required-approver rejection) it is a critical broken-access-control flaw.

Active write probe (sends POSTs with benign, non-destructive data), so it only
runs under active scans, never public-only.
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any

import httpx

# Approval / privileged-workflow endpoint shapes.
_APPROVAL_PATH_RE = re.compile(
    r"(?i)/(approve|approval|review|delegate|impersonate|escalat|override|"
    r"authoriz|prior-auth|dual-control|sign-?off|release|disburse|payout)(/|$|\?|e\b|ion\b)"
)

# The action was accepted/performed (provider-agnostic + honey's deterministic echo).
_ACCEPTED_RE = re.compile(
    r"(?i)\"?(approved|authorized|succeeded|success|completed|released|disbursed|"
    r"impersonat\w*|delegated|overridden)\"?\s*[:=]\s*(true|\"?(ok|success|approved|completed)\"?)"
    r"|_bypass\b|dual.control|without.approval|callback_verified\"\s*:\s*false"
)
# Correct rejection of the unauthorized request.
_REJECTED_RE = re.compile(
    r"(?i)(unauthor|forbidden|denied|not\s+permitted|requires?\s+(approval|authentication|second|dual)"
    r"|missing\s+(approver|authorization)|insufficient\s+(privile|permission))"
)

_BENIGN = {
    "id": "shakerscan_probe",
    "amount": 1,
    "reason": "scanner-probe",
    "approve": True,
    "confirm": True,
}


def _candidate_paths(endpoints: list[Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for spec in endpoints or []:
        raw: str | None = None
        method: str | None = None
        if isinstance(spec, str):
            s = spec.strip()
            parts = s.split(None, 1)
            if len(parts) == 2 and parts[0].upper() in (
                    "POST", "PUT", "PATCH", "GET", "DELETE", "OPTIONS", "HEAD"):
                method = parts[0].upper()
                rest = parts[1].split()
                raw = rest[0] if rest else None
            else:
                raw = s  # plain URL, method unknown
        elif isinstance(spec, dict):
            raw = spec.get("url") or spec.get("path")
            method = str(spec["method"]).upper() if spec.get("method") else None
        # Only probe write-shaped endpoints; never POST to an explicitly read-only
        # route (GET/HEAD/DELETE/OPTIONS). Method-unknown candidates are gated by
        # the approval path shape below.
        if method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            continue
        if not raw or not isinstance(raw, str) or not _APPROVAL_PATH_RE.search(raw):
            continue
        key = raw.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(raw)
    return out


async def check_approval_authz_bypass(
    base_url: str,
    endpoints: list[Any],
    *,
    max_endpoints: int = 40,
    concurrency: int = 6,
    timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Probe approval endpoints unauthenticated; flag accepted state changes."""
    base = base_url.rstrip("/")
    host = urllib.parse.urlparse(base).netloc
    candidates = _candidate_paths(endpoints)[:max_endpoints]
    if not candidates:
        return []

    findings: list[dict[str, Any]] = []
    seen_urls: set[str] = set()
    sem = asyncio.Semaphore(max(1, concurrency))

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout) as client:

        async def probe(path: str) -> None:
            url = path if path.startswith("http") else urllib.parse.urljoin(base + "/", path.lstrip("/"))
            if urllib.parse.urlparse(url).netloc != host or url in seen_urls:
                return
            seen_urls.add(url)
            async with sem:
                try:
                    resp = await client.post(url, json=_BENIGN)
                except Exception:
                    return
            if resp.status_code >= 400:
                return
            body = resp.text[:8000]
            if _REJECTED_RE.search(body):
                return
            if not _ACCEPTED_RE.search(body):
                return
            findings.append({
                "title": f"Broken authorization / approval bypass: {urllib.parse.urlparse(url).path}",
                "severity": "critical",
                "tool": "approval_checks",
                "type": "Broken Access Control",
                "cwe": "CWE-862",
                "url": url,
                "evidence": {
                    "url": url,
                    "status_code": resp.status_code,
                    "finding_family": "approval_authz_bypass",
                    "note": "Privileged approval/workflow action accepted with no authentication or approver context.",
                    "response_snippet": re.sub(r"\s+", " ", body[:240]).strip(),
                    "cvss_score": 9.1,
                },
            })

        await asyncio.gather(*(probe(p) for p in candidates))

    return findings
