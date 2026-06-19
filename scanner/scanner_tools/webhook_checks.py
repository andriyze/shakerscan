"""Webhook signature-verification bypass detector.

A webhook receiver that processes an event with a missing/forged signature is a
critical integrity flaw (forged payment/CI/provisioning events). This probes
webhook-shaped endpoints with a benign event body and NO valid signature; if the
endpoint accepts and processes it (2xx + processed/ok markers, not a
401/403/400-invalid-signature rejection), it is flagged.

Active write probe (sends POSTs), so it only runs under active scans, never
public-only.
"""

from __future__ import annotations

import asyncio
import re
import urllib.parse
from typing import Any

import httpx

# Endpoint shapes that are webhook receivers.
_WEBHOOK_PATH_RE = re.compile(r"(?i)(/|\b)(webhooks?|hook|callback|events?/(stripe|github|gitlab|slack))(/|$|\?)")

# Acceptance markers in a webhook response body (provider-agnostic + honey's echo).
_ACCEPTED_MARKERS = re.compile(
    r"(?i)\"?(processed|received|ok|success|accepted|handled)\"?\s*[:=]\s*(true|\"?(ok|success|received|accepted)\"?)"
    r"|webhook_signature_bypass|webhook_replay|event_id"
)
# Signs the receiver correctly REJECTED the unsigned/forged request.
_REJECTED_MARKERS = re.compile(r"(?i)(invalid|missing|bad|unverified).{0,20}(signature|hmac|token)|signature.{0,20}(invalid|missing|required)")

_BENIGN_EVENT = {
    "id": "evt_shakerscan_probe",
    "type": "ping",
    "event": "ping",
    "action": "ping",
    "data": {"object": {"id": "obj_probe"}},
}


def _candidate_webhook_paths(endpoints: list[Any]) -> list[str]:
    paths: list[str] = []
    seen: set[str] = set()
    for spec in endpoints or []:
        raw: str | None = None
        if isinstance(spec, str):
            s = spec.strip()
            parts = s.split(None, 1)
            raw = parts[1].split()[0] if len(parts) == 2 and parts[0].upper() in (
                "POST", "PUT", "GET", "PATCH", "DELETE", "OPTIONS", "HEAD") else s
        elif isinstance(spec, dict):
            raw = spec.get("url") or spec.get("path")
        if not raw or not isinstance(raw, str):
            continue
        if not _WEBHOOK_PATH_RE.search(raw):
            continue
        key = raw.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        paths.append(raw)
    return paths


async def check_webhook_signature_bypass(
    base_url: str,
    endpoints: list[Any],
    *,
    max_endpoints: int = 40,
    concurrency: int = 8,
    timeout: float = 8.0,
) -> list[dict[str, Any]]:
    """Probe webhook endpoints with an unsigned benign event; flag acceptance."""
    base = base_url.rstrip("/")
    host = urllib.parse.urlparse(base).netloc
    candidates = _candidate_webhook_paths(endpoints)[:max_endpoints]
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
                    # No signature header at all — a secure receiver must reject.
                    resp = await client.post(url, json=_BENIGN_EVENT)
                except Exception:
                    return
            if resp.status_code >= 400:
                return  # correctly rejected (401/403/400)
            body = resp.text[:8000]
            if _REJECTED_MARKERS.search(body):
                return
            if not _ACCEPTED_MARKERS.search(body):
                return
            findings.append({
                "title": f"Webhook signature verification bypass: {urllib.parse.urlparse(url).path}",
                "severity": "critical",
                "tool": "webhook_checks",
                "type": "Webhook Signature Bypass",
                "cwe": "CWE-345",
                "url": url,
                "evidence": {
                    "url": url,
                    "status_code": resp.status_code,
                    "finding_family": "webhook_signature_bypass",
                    "note": "Endpoint processed an event sent with no valid signature.",
                    "response_snippet": re.sub(r"\s+", " ", body[:240]).strip(),
                    "cvss_score": 9.0,
                },
            })

        await asyncio.gather(*(probe(p) for p in candidates))

    return findings
