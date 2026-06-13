"""
Extended injection & integrity active checks for ShakerScan DAST.

Fills OWASP Top 10 gaps not handled elsewhere in the engine:
  - Server-Side Includes (SSI) injection            CWE-97   (A03)
  - Edge-Side Includes (ESI) injection              CWE-97   (A03)
  - Server-Side Prototype Pollution (Node/Express)  CWE-1321 (A08/A05)
  - CSV / Formula injection                         CWE-1236 (A03)
  - Remote File Inclusion (RFI)                      CWE-98   (A03)

Every check is differential and false-positive conservative: a finding is only
emitted when an injected payload produces an observable evaluation/inclusion
that a benign control payload does not. Functions reuse common.run (curl
subprocess) and return plain dicts; the orchestrator converts them to findings
via normalize_finding().
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import urllib.parse
from typing import Any

from .common import get_auth_curl_args, run

# curl -w sentinel: lets us read status + content-type without parsing the
# (multi-block, redirect-prone) raw header stream.
_META = "__SHAKER_META__"
_META_RE = re.compile(re.escape(_META) + r"(\d{1,3})\|([^|]*)" + re.escape(_META) + r"\s*$")

# Param names that commonly drive file/template inclusion (RFI candidates).
_INCLUDE_PARAMS = {
    "file", "page", "include", "inc", "template", "tpl", "path", "doc",
    "document", "lang", "language", "view", "content", "load", "read",
    "module", "conf", "url", "src", "source",
}


def _curl_cmd(
    url: str,
    auth_args: list[str],
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    timeout: int = 12,
) -> list[str]:
    # -k is intentional and matches every other scanner_tools probe: a DAST
    # engine must reach targets with self-signed/expired/invalid certs (the
    # misconfigured hosts we most need to test). Cert validity is assessed
    # separately by tls_scanner.py, never by failing an active probe.
    cmd = [
        "curl", "-sS", "-k", "--max-time", str(max(3, timeout - 2)),
        "-X", method,
        "-H", "User-Agent: Mozilla/5.0 (ShakerScan Security Scanner)",
        "-w", f"{_META}%{{http_code}}|%{{content_type}}{_META}",
    ]
    if content_type:
        cmd += ["-H", f"Content-Type: {content_type}"]
    if data is not None:
        cmd += ["--data-binary", data]
    cmd += auth_args
    cmd += [url]
    return cmd


def _parse_curl(out: str | None) -> tuple[int, str, str]:
    """Return (status, content_type, body) from a -w-annotated curl response."""
    if not out:
        return 0, "", ""
    m = _META_RE.search(out)
    if not m:
        return 0, "", out
    return int(m.group(1)), m.group(2).strip(), out[: m.start()]


async def _fetch(
    url: str,
    auth_args: list[str],
    method: str = "GET",
    data: str | None = None,
    content_type: str | None = None,
    timeout: int = 12,
) -> tuple[int, str, str]:
    out, _err, _rc = await run(
        _curl_cmd(url, auth_args, method, data, content_type, timeout),
        timeout=timeout + 3,
    )
    return _parse_curl(out)


def _set_query_param(url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _collect_param_targets(
    urls: list[str], limit: int
) -> list[tuple[str, str, str]]:
    """Flatten URLs into (url, param, current_value) tuples for query params."""
    targets: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for u in urls:
        try:
            parsed = urllib.parse.urlparse(u)
        except Exception:
            continue
        if not parsed.query:
            continue
        for param, values in urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True
        ).items():
            key = (f"{parsed.scheme}://{parsed.netloc}{parsed.path}", param)
            if key in seen:
                continue
            seen.add(key)
            targets.append((u, param, values[0] if values else ""))
            if len(targets) >= limit:
                return targets
    return targets


# ---------------------------------------------------------------------------
# SSI / ESI injection (CWE-97)
# ---------------------------------------------------------------------------

# Evaluated SSI #echo of DATE_LOCAL yields a date/time; match a few locale forms.
_DATE_EVAL_RE = re.compile(
    r"\d{1,2}[:/ -]\d{1,2}"               # 12:30, 06/12, 6-12
    r"|\b\d{4}\b"                          # a 4-digit year
    r"|(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)",
    re.IGNORECASE,
)


async def test_ssi_esi_injection(
    targets: list[tuple[str, str, str]],
    auth_args: list[str],
    max_endpoints: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for url, param, _cur in targets[:max_endpoints]:
        host = urllib.parse.urlparse(url).hostname or ""
        tok = secrets.token_hex(4).upper()

        # SSI: directive sits between two unique markers. We only flag when the
        # space between markers shows an evaluated date — tag-stripping alone
        # (which a sanitizer also does) is NOT enough.
        ssi_value = f"SS{tok}A<!--#echo var=\"DATE_LOCAL\"-->{tok}B"
        status, _ct, body = await _fetch(_set_query_param(url, param, ssi_value), auth_args)
        if body:
            m = re.search(re.escape(f"SS{tok}A") + r"(.*?)" + re.escape(f"{tok}B"), body, re.DOTALL)
            if m:
                between = m.group(1)
                if "<!--#echo" not in between and _DATE_EVAL_RE.search(between):
                    findings.append({
                        "category": "ssi_injection",
                        "title": "Server-Side Includes (SSI) Injection",
                        "severity": "high",
                        "cwe": "CWE-97",
                        "evidence": {
                            "type": "SSI Injection", "url": url, "param": param,
                            "payload": ssi_value, "evaluated_output": between[:120],
                            "note": "SSI #echo directive was evaluated server-side",
                        },
                    })
                    continue  # one class per param is enough

        # ESI: <esi:vars>$(HTTP_HOST)</esi:vars> expands to the request Host.
        if host:
            esi_value = f"ES{tok}A<esi:vars>$(HTTP_HOST)</esi:vars>{tok}B"
            status, _ct, body = await _fetch(_set_query_param(url, param, esi_value), auth_args)
            if body:
                m = re.search(re.escape(f"ES{tok}A") + r"(.*?)" + re.escape(f"{tok}B"), body, re.DOTALL)
                if m:
                    between = m.group(1)
                    if "<esi:" not in between and host in between:
                        findings.append({
                            "category": "esi_injection",
                            "title": "Edge-Side Includes (ESI) Injection",
                            "severity": "high",
                            "cwe": "CWE-97",
                            "evidence": {
                                "type": "ESI Injection", "url": url, "param": param,
                                "payload": esi_value, "evaluated_output": between[:120],
                                "note": "ESI <esi:vars> directive was evaluated server-side",
                            },
                        })
        await asyncio.sleep(0.03)
    return findings


# ---------------------------------------------------------------------------
# CSV / Formula injection (CWE-1236)
# ---------------------------------------------------------------------------

_CSV_CT_RE = re.compile(r"csv|excel|spreadsheet|ms-excel|vnd\.openxmlformats", re.IGNORECASE)


def _looks_like_csv(body: str) -> bool:
    lines = [ln for ln in body.splitlines() if ln.strip()][:10]
    if len(lines) < 2:
        return False
    commas = [ln.count(",") for ln in lines]
    return commas and min(commas) >= 1 and max(commas) - min(commas) <= 2


async def test_csv_formula_injection(
    targets: list[tuple[str, str, str]],
    auth_args: list[str],
    max_endpoints: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for url, param, _cur in targets[:max_endpoints]:
        tok = secrets.token_hex(4).upper()
        for lead in ("=", "+", "-", "@"):
            payload = f"{lead}SHK{tok}"
            status, ct, body = await _fetch(_set_query_param(url, param, payload), auth_args)
            if not body:
                continue
            is_csv = bool(_CSV_CT_RE.search(ct)) or _looks_like_csv(body)
            if not is_csv:
                continue
            # Flag only when the formula char survives unescaped at a cell start
            # (line start or after a comma) — a leading ' or HTML-escape is safe.
            cell_re = re.compile(r"(?:^|,)" + re.escape(payload), re.MULTILINE)
            if cell_re.search(body):
                findings.append({
                    "category": "csv_injection",
                    "title": "CSV / Formula Injection",
                    "severity": "medium",
                    "cwe": "CWE-1236",
                    "evidence": {
                        "type": "CSV Injection", "url": url, "param": param,
                        "payload": payload, "content_type": ct or "csv-like",
                        "note": "Formula-prefixed input reflected unescaped into a CSV/Excel cell",
                    },
                })
                break  # one lead char is enough to prove it
            await asyncio.sleep(0.02)
    return findings


# ---------------------------------------------------------------------------
# Remote File Inclusion (CWE-98) — self-referential differential
# ---------------------------------------------------------------------------

async def _origin_marker(base_url: str, auth_args: list[str]) -> tuple[str, str] | None:
    """Pick a same-origin resource + a distinctive token from its body."""
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for path in ("/robots.txt", "/sitemap.xml", "/"):
        status, _ct, body = await _fetch(origin + path, auth_args)
        if status != 200 or not body:
            continue
        for line in body.splitlines():
            line = line.strip()
            # need a stable, distinctive token unlikely to appear by chance
            if len(line) >= 14 and re.fullmatch(r"[\w :/.\-]+", line):
                return origin + path, line[:60]
    return None


async def test_rfi(
    base_url: str,
    targets: list[tuple[str, str, str]],
    auth_args: list[str],
    max_endpoints: int,
) -> list[dict[str, Any]]:
    include_targets = [t for t in targets if t[1].lower() in _INCLUDE_PARAMS]
    if not include_targets:
        return []
    marker = await _origin_marker(base_url, auth_args)
    if not marker:
        return []
    resource_url, token = marker
    parsed = urllib.parse.urlparse(resource_url)

    findings: list[dict[str, Any]] = []
    for url, param, _cur in include_targets[:max_endpoints]:
        tok = secrets.token_hex(4)
        # Baseline with a benign value must NOT already contain the token.
        _s, _c, base_body = await _fetch(_set_query_param(url, param, f"shk{tok}"), auth_args)
        if token in (base_body or ""):
            continue
        for payload in (
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            f"//{parsed.netloc}{parsed.path}",
        ):
            status, _ct, body = await _fetch(_set_query_param(url, param, payload), auth_args)
            if body and token in body:
                findings.append({
                    "category": "rfi",
                    "title": "Remote File Inclusion (RFI)",
                    "severity": "high",
                    "cwe": "CWE-98",
                    "evidence": {
                        "type": "RFI", "url": url, "param": param, "payload": payload,
                        "included_resource": resource_url, "marker": token,
                        "note": "Remote resource content was fetched and included in the response",
                    },
                })
                break
            await asyncio.sleep(0.03)
    return findings


# ---------------------------------------------------------------------------
# Server-Side Prototype Pollution (CWE-1321) — JSON-spaces oracle
# ---------------------------------------------------------------------------

_POLLUTE_INDENT = 7  # uncommon value, distinguishable from typical 2/4-space pretty print


def _json_indent(body: str) -> int | None:
    """Indent width of pretty-printed JSON; 0 if compact; None if not JSON."""
    try:
        json.loads(body)
    except Exception:
        return None
    for line in body.splitlines()[1:]:
        m = re.match(r"^( +)\S", line)
        if m:
            return len(m.group(1))
    return 0


async def test_prototype_pollution(
    base_url: str,
    json_endpoints: list[str],
    auth_args: list[str],
    max_endpoints: int,
) -> list[dict[str, Any]]:
    """Detect server-side prototype pollution via the Express json-spaces oracle.

    Pollutes Object.prototype['json spaces'] and observes whether an unrelated
    JSON response becomes indented, then reverts. This sends state-changing
    POST/PUT bodies, so callers must only invoke it on the non-safe (aggressive)
    tier — run_injection_extra_checks() gates it on safe_mode=False.
    """
    findings: list[dict[str, Any]] = []
    pollute_body = json.dumps({"__proto__": {"json spaces": _POLLUTE_INDENT}})
    revert_body = json.dumps({"__proto__": {"json spaces": 0}})

    for endpoint in json_endpoints[:max_endpoints]:
        # 1) baseline indent on a JSON GET response
        status, ct, body = await _fetch(endpoint, auth_args)
        if "json" not in ct.lower():
            continue
        base_indent = _json_indent(body)
        if base_indent is None or base_indent == _POLLUTE_INDENT:
            continue

        # 2) attempt pollution (POST then PUT) against the same endpoint
        polluted = False
        for method in ("POST", "PUT"):
            ps, _pc, _pb = await _fetch(
                endpoint, auth_args, method=method,
                data=pollute_body, content_type="application/json",
            )
            if ps and ps < 500:
                polluted = True
        if not polluted:
            continue

        # 3) re-measure: indentation flipping to our injected width confirms it
        await asyncio.sleep(0.05)
        _s2, ct2, body2 = await _fetch(endpoint, auth_args)
        new_indent = _json_indent(body2) if "json" in ct2.lower() else None

        # 4) always revert global state
        for method in ("POST", "PUT"):
            await _fetch(
                endpoint, auth_args, method=method,
                data=revert_body, content_type="application/json",
            )

        if new_indent == _POLLUTE_INDENT and base_indent != _POLLUTE_INDENT:
            findings.append({
                "category": "prototype_pollution",
                "title": "Server-Side Prototype Pollution",
                "severity": "high",
                "cwe": "CWE-1321",
                "evidence": {
                    "type": "Prototype Pollution", "url": endpoint,
                    "payload": pollute_body, "method": "POST/PUT",
                    "baseline_json_indent": base_indent, "polluted_json_indent": new_indent,
                    "note": "Object.prototype['json spaces'] pollution altered JSON serialization",
                },
            })
        await asyncio.sleep(0.03)
    return findings


# ---------------------------------------------------------------------------
# Orchestrator entry point
# ---------------------------------------------------------------------------

async def run_injection_extra_checks(
    url: str,
    discovered_urls: list[str] | None = None,
    auth_session: Any | None = None,
    safe_mode: bool = True,
    max_endpoints: int = 15,
) -> dict[str, Any]:
    """Run the extended injection/integrity checks.

    safe_mode (default True) runs only the GET-reflection probes (SSI/ESI, CSV).
    The state-changing prototype-pollution probe and the server-fetch-inducing RFI
    probe run only when safe_mode is False (the aggressive tier).

    Returns {"findings": [...normalized dicts...], "tested": {...}, "checks_run": [...]}.
    Each finding dict has category/title/severity/cwe/evidence for normalize_finding().
    """
    auth_args = get_auth_curl_args(auth_session)
    all_urls = [url] + list(discovered_urls or [])
    targets = _collect_param_targets(all_urls, limit=max_endpoints * 3)

    # JSON endpoints for prototype pollution: discovered URLs that look API-ish.
    json_endpoints = [
        u for u in all_urls
        if re.search(r"/(api|rest|graphql|v\d)/|\.json(\?|$)", u, re.IGNORECASE)
    ] or [url]

    findings: list[dict[str, Any]] = []
    checks_run: list[str] = []
    skipped_checks: list[dict[str, str]] = []

    if targets:
        # SSI/ESI/CSV are GET-only reflection probes (same risk profile as the
        # XSS/open-redirect active checks) and run in the default active bundle.
        checks_run += ["ssi_esi", "csv_formula"]
        coros = [
            test_ssi_esi_injection(targets, auth_args, max_endpoints),
            test_csv_formula_injection(targets, auth_args, max_endpoints),
        ]
        # RFI induces a server-side fetch (SSRF-like), so it is gated to the
        # non-safe (aggressive) tier, like the engine's SSRF/command-injection probes.
        if not safe_mode:
            checks_run.append("rfi")
            coros.append(test_rfi(url, targets, auth_args, max_endpoints))
        else:
            skipped_checks.append({
                "check": "rfi",
                "reason": "safe_mode_server_side_fetch",
            })
        for result in await asyncio.gather(*coros):
            findings += result

    # Prototype pollution sends state-changing POST/PUT bodies; restrict it to the
    # non-safe (aggressive) tier so default Phase 4 scans never mutate target state.
    if not safe_mode:
        checks_run.append("prototype_pollution")
        findings += await test_prototype_pollution(
            url, json_endpoints, auth_args, max_endpoints
        )
    else:
        skipped_checks.append({
            "check": "prototype_pollution",
            "reason": "safe_mode_state_changing_post_put",
        })

    return {
        "findings": findings,
        "tested": {"param_targets": len(targets), "json_endpoints": len(json_endpoints)},
        "checks_run": checks_run,
        "skipped_checks": skipped_checks,
        "safe_mode": safe_mode,
    }
