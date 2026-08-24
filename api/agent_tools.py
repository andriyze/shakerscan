"""Agent tool contracts + guards for the autonomous ReAct loop.

The bounded tools exposed to the Deep Hunt planner (documented in
docs/functionality-reference.md, section 11.6).
This module holds the **function-call schemas** (consumed by the text-contract renderer
in :mod:`agent_text_toolcalls`) and the **pure guards** — target-host origin/path validation,
request-header allowlisting (so the model can never inject an auth header — real auth
comes only from a server-resolved ``as_principal``), method classification, and result
shaping. The async execution (httpx, DB, tool_receipts, principal resolution) lives in
api.py, which owns those dependencies; this layer stays dependency-free and host-testable.

Containment is enforced in code, before every handler (borrow T3MP3ST ``execute()``):
scope (same target host) and approval (write methods are gated) are checked server-side, never
left to the model.
"""
from __future__ import annotations

import hashlib
import json
import ipaddress
import math
import os
import re
import urllib.parse
from typing import Any, Mapping, Optional

from runtime.capability_registry import CAPABILITY_REGISTRY
from scan.external_process import (
    EnforcedProcessPlan,
    ExternalProcessContractError,
    PROCESS_BUDGET_PROOF_SCHEMA,
)
from scan.work_manifests import (
    CANONICAL_PASSIVE_NUCLEI_TEMPLATES,
    canonical_passive_nuclei_request_upper_bound,
)

try:
    from scanner_tools.url_redaction import redact_url
except ModuleNotFoundError:  # package import in host-side tests
    from scanner.scanner_tools.url_redaction import redact_url

# Methods the model may request. Reads are read-only; writes are credential/active-gated.
READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})
WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ALL_METHODS: frozenset[str] = READ_METHODS | WRITE_METHODS

# Request headers the model may never set. Auth/identity headers come ONLY from a
# server-resolved principal (as_principal); a Host/CL/hop-by-hop header would break
# same-origin or smuggle. Anything matching a sensitive substring is also dropped.
_FORBIDDEN_HEADERS: frozenset[str] = frozenset(
    {
        "authorization", "cookie", "host", "content-length", "connection",
        "transfer-encoding", "proxy-authorization", "x-forwarded-for",
        "x-forwarded-host", "x-real-ip", "forwarded",
    }
)
_SENSITIVE_HEADER_SUBSTR: tuple[str, ...] = (
    "token", "secret", "auth", "session", "cookie", "password", "api-key", "apikey",
    "credential", "bearer",
)

# query_kb read-only surfaces (each maps to a bounded SELECT in api.py).
QUERY_KB_KINDS: frozenset[str] = frozenset(
    {
        "endpoints", "findings", "hypotheses", "principals",
        "graph_nodes", "graph_edges", "tool_receipts", "notes",
    }
)

NOTE_KINDS: frozenset[str] = frozenset({"hypothesis", "observation", "todo"})

AGENT_TOOL_NAMES: frozenset[str] = frozenset({"http_request", "query_kb", "diff", "note"})
# Includes run_tool (defined below); used by the loop's hallucinated-tool guard.
CALLABLE_TOOL_NAMES: frozenset[str] = AGENT_TOOL_NAMES | {"run_tool"}


# --------------------------------------------------------------------------------------
# Function-call schemas (shape expected by render_tool_contract / native tool APIs).
# The optional ``risk`` field is used by the server gate, ignored by the renderer.
# --------------------------------------------------------------------------------------

AGENT_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "http_request",
        "risk": "active",  # elevated to gated when the method is a write
        "description": (
            "Issue ONE HTTP request to an origin on the selected target host and get a structured "
            "response summary (status, headers, body sample, json keys, sha256, timing). "
            "Set as_principal to a configured principal slot (e.g. 'user1','user2','admin') "
            "to send it authenticated AS that server-managed identity — you never see the "
            "credential. Replay the same request as different principals to test access "
            "control. Reads (GET/HEAD/OPTIONS) run freely; writes (POST/PUT/PATCH/DELETE) "
            "are approval-gated. Set follow_redirects=true (reads only) to follow up to 3 "
            "same-origin redirects and receive the final response plus the chain. "
            "Returns a 'ref' you can pass to diff."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE"},
                "origin": {"type": "string", "description": "optional concrete http(s) origin on the selected target host, including port"},
                "path": {"type": "string", "description": "absolute path on that origin, must start with / (e.g. /rest/basket/1)"},
                "query": {"type": "object", "description": "optional query params {k:v}"},
                "json_body": {"type": "object", "description": "optional JSON request body"},
                "form_body": {"type": "object", "description": "optional form-encoded body"},
                "headers": {"type": "object", "description": "optional benign request headers (auth headers are forbidden — use as_principal)"},
                "as_principal": {"type": "string", "description": "optional principal slot to authenticate as; omit for anonymous"},
                "follow_redirects": {"type": "boolean", "description": "optional: follow up to 3 STRICT same-origin (scheme+host+port) redirects; read methods (GET/HEAD/OPTIONS) only. The response is the FINAL hop plus a redirect_chain of {status, location} hops"},
            },
            "required": ["method", "path"],
        },
    },
    {
        "name": "query_kb",
        "risk": "read_only",
        "description": (
            "Read the ShakerScan knowledge base for this target (read-only): "
            f"kind ∈ {sorted(QUERY_KB_KINDS)}. Use 'findings' to see what is ALREADY known "
            "(so you hunt NET-NEW), 'endpoints' for the live attack surface, 'principals' "
            "for available auth identities, 'graph_*' for the application graph, 'notes' for "
            "your own scratchpad."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "one of the allowed kinds"},
                "filter": {"type": "object", "description": "optional {method,path_contains,family,severity,limit}"},
            },
            "required": ["kind"],
        },
    },
    {
        "name": "diff",
        "risk": "read_only",
        "description": (
            "Compare two HTTP response summaries and get a structured differential "
            "(status/length/body change, json keys added/removed, selected-value and "
            "header changes, timing delta). Pass refs returned by http_request (e.g. "
            "'resp_1') or inline summary objects. Use it to prove BOLA (two principals get "
            "the same protected body -> comparison_equivalent) or a persisted state change."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "left": {"type": "string", "description": "ref (e.g. 'resp_1') or inline response summary"},
                "right": {"type": "string", "description": "ref (e.g. 'resp_2') or inline response summary"},
            },
            "required": ["left", "right"],
        },
    },
    {
        "name": "note",
        "risk": "read_only",
        "description": (
            "Record a hypothesis, observation, or TODO to your durable scratchpad (a tool "
            "receipt) so it survives across steps and is visible to the operator. kind ∈ "
            f"{sorted(NOTE_KINDS)}. (A note is scratchpad only — it does not itself seed the "
            "lead board or create a finding.)"
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "kind": {"type": "string", "description": "hypothesis|observation|todo"},
                "title": {"type": "string", "description": "short title"},
                "detail": {"type": "string", "description": "the note body"},
                "family": {"type": "string", "description": "optional vuln family for a hypothesis (bola,sqli,mass_assignment,...)"},
                "severity": {"type": "string", "description": "optional guessed severity"},
            },
            "required": ["kind", "title"],
        },
    },
]


# --------------------------------------------------------------------------------------
# run_tool — external scanners via hardcoded argv templates (port of T3MP3ST
# adapter-tools.ts ARG_TEMPLATES). The LLM picks tool + target ONLY; every flag is baked
# into build(); only regex-gated tunables are read by name. No arbitrary shell.
# --------------------------------------------------------------------------------------

_SEV_RE = re.compile(r"^(critical|high|medium|low|info)(,(critical|high|medium|low|info))*$")
_TAGS_RE = re.compile(r"^[a-z0-9][a-z0-9,\-]{0,80}$")
_CANONICAL_PASSIVE_NUCLEI_IDS = ",".join(sorted(
    row[0] for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES
))
# nmap -oN - human output: one row per scanned port, e.g. "8443/tcp open  https  nginx 1.25.3".
_NMAP_SERVICE_LINE_RE = re.compile(r"^(\d{1,5}/(?:tcp|udp))\s+(\S+)\s+(\S+)(?:\s+(.*\S))?\s*$")
_NUCLEI_FOCUSED_TAGS = "exposure,misconfig,auth-bypass,default-login"


def _tmpl_httpx(url: str, opts: dict[str, Any]) -> list[str]:
    # Passive fingerprint: exactly one URL, with fallback and redirects disabled.
    return ["-u", url, "-status-code", "-title", "-tech-detect", "-web-server",
            "-json", "-silent", "-timeout", "10", "-no-color", "-no-stdin",
            "-retries", "0", "-rate-limit", "1", "-threads", "1",
            "-no-fallback-scheme", "-disable-update-check"]


def _tmpl_nuclei(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded template scan. Severity + tags are the ONLY tunables, both regex-gated.
    severity = str(opts.get("severity") or "").strip().lower()
    if not _SEV_RE.match(severity):
        severity = "high,critical"
    args = ["-target", url, "-severity", severity, "-silent", "-jsonl",
            "-stats", "-stats-json", "-stats-interval", "5",
            "-timeout", "5", "-retries", "0", "-no-color", "-disable-update-check",
            "-disable-redirects", "-no-interactsh", "-type", "http"]
    args += ["-rate-limit", "10", "-bulk-size", "10", "-concurrency", "10"]
    template_ids = str(opts.get("template_ids") or "").strip().lower()
    if template_ids:
        if template_ids != _CANONICAL_PASSIVE_NUCLEI_IDS:
            raise AgentToolError("nuclei template allowlist is not canonical")
        args += ["-id", template_ids]
    tags = str(opts.get("tags") or "").strip().lower()
    if _TAGS_RE.match(tags):
        args += ["-tags", tags]
    elif not template_ids:
        # All High/Critical HTTP templates exceed the bounded agent turn on the
        # pinned bundle. The default remains useful but finite; callers may ask
        # for broader explicit tags and receive honestly labeled partial output
        # if the same hard wall is reached.
        args += ["-tags", _NUCLEI_FOCUSED_TAGS]
    return args


# Bundled small wordlists for content discovery. The model picks a NAME from this map (dict
# lookup, unknown -> common); it can NEVER pass an arbitrary path, so ffuf's -w is injection-proof.
_AGENT_FFUF_WORDLISTS: dict[str, str] = {
    "common": "/app/wordlists/common.txt",
    "api": "/app/wordlists/api-resources.txt",
    "admin": "/app/wordlists/admin-common.txt",
}


def _tmpl_katana(url: str, opts: dict[str, Any]) -> list[str]:
    # Same-origin crawl + JS endpoint extraction. Read-only (GET only; form auto-fill stays OFF),
    # bounded: depth 2, 30s wall cap, 5 req/s, field-scope fqdn (same HOST only — never crosses
    # origin), 8s per-request timeout, URL-only output. Katana's JSONL records embed raw
    # request/response bodies and can exhaust the worker output cap after only a few pages.
    # The compact stream is sufficient for route discovery and keeps planner evidence bounded.
    return ["-u", url, "-js-crawl", "-depth", "2", "-concurrency", "5",
            "-rate-limit", "5", "-crawl-duration", "30s", "-field-scope", "fqdn",
            "-timeout", "8", "-retry", "0", "-disable-redirects", "-silent"]


def _tmpl_dalfox(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded XSS scan of a single URL. GET-based: no data body, no blind callback, no headless,
    # no WAF evasion, no parameter mining beyond the URL itself. json output for the typed parser.
    severity = str(opts.get("severity") or "").strip().lower()
    severity_args: list[str] = []
    if severity == "low":
        severity_args = ["--only-poc", "g,r,v"]
    elif severity == "medium":
        severity_args = ["--only-poc", "r,v"]
    else:
        severity_args = ["--only-poc", "v"]
    return (["url", url, "--format", "jsonl", "--silence", "--no-color",
             "--timeout", "8", "--delay", "1000", "--worker", "3",
             "--skip-bav", "--skip-grepping", "--skip-headless",
             "--skip-mining-all"] + severity_args)


def _tmpl_sqlmap(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded single-URL SQLi test. Non-interactive (--batch), boolean/error/union plus
    # time-based techniques (the widened wall window + wire reservation bound the time-based
    # payloads), level/risk 2, no crawl, output to a scratch dir the worker owns (replaced
    # per-job by bind_scanner_runtime_paths); findings surface in stdout ("is vulnerable").
    return ["-u", url, "--batch", "--technique", "BEUT", "--level", "2", "--risk", "2",
            "--threads", "1", "--timeout", "8", "--retries", "0", "--delay", "1",
            "--flush-session", "--output-dir", "/tmp/shakerscan-sqlmap",
            "--smart", "--disable-coloring", "--answers", "redirect=N",
            "--user-agent", "shakerscan-sqlmap/1.0"]


def _tmpl_ffuf(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded content/dir discovery. Read-only (GET). One tunable: wordlist in {common,api,admin}
    # -> a small BUNDLED list (unknown/invalid -> common; no arbitrary path). Automatic
    # calibration stays off because it adds requests outside the exact wordlist count. The
    # authoritative worker replaces this source with an owner-only exact-size subset.
    wordlist = _AGENT_FFUF_WORDLISTS.get(
        str(opts.get("wordlist") or "").strip().lower(), _AGENT_FFUF_WORDLISTS["common"]
    )
    base = url.split("?", 1)[0].rstrip("/")
    return ["-u", f"{base}/FUZZ", "-w", wordlist,
            "-mc", "200,204,301,302,307,401,403,405",
            "-t", "5", "-rate", "5", "-timeout", "8", "-maxtime", "40", "-s", "-json"]


def _tmpl_nmap(url: str, opts: dict[str, Any]) -> list[str]:
    # Read-only single-port service/version probe of the host behind the target URL. nmap takes
    # no URL: host+port are extracted from it. Connect scan only (-sT — never raw SYN), NO NSE
    # scripts, no host discovery (-Pn), no file output (-oN - keeps it on stdout), 60s host
    # timeout. When pinning is active build_scanner_argv feeds this a URL whose hostname is the
    # pinned IP, so the positional host is address-frozen.
    parsed = urllib.parse.urlsplit(url)
    host = str(parsed.hostname or "")
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return ["-p", str(port), "-sV", "-sT", "--version-light", "--host-timeout", "60s",
            "--max-retries", "0", "-T3", "-Pn", "-oN", "-", host]


def _tmpl_naabu(url: str, opts: dict[str, Any]) -> list[str]:
    # Bounded top-100 TCP port sweep of the host behind the target URL. Connect scan
    # (-scan-type c — no raw SYN), rate 10 + 120s wall cap -> a 1200-request wire ceiling, JSON
    # lines on stdout for the typed parser. No full-range -p- sweep. Pinned IP substitution is
    # handled by build_scanner_argv exactly as for nmap.
    parsed = urllib.parse.urlsplit(url)
    host = str(parsed.hostname or "")
    return ["-host", host, "-top-ports", "100", "-Pn", "-scan-type", "c",
            "-rate", "10", "-c", "10", "-timeout", "1500ms", "-retries", "1",
            "-json", "-silent", "-no-color", "-disable-update-check", "-no-stdin",
            "-stats", "-stats-interval", "10"]


# Adapter builders remain implementation details here while the canonical registry owns names,
# risk, budgets, placement, schemas, evidence contracts, binaries, and timeouts.
_SCANNER_BUILDERS = {
    "httpx": _tmpl_httpx,
    "nuclei": _tmpl_nuclei,
    "katana": _tmpl_katana,
    "ffuf": _tmpl_ffuf,
    "dalfox": _tmpl_dalfox,
    "sqlmap": _tmpl_sqlmap,
    "nmap": _tmpl_nmap,
    "naabu": _tmpl_naabu,
}
SCANNER_ARG_TEMPLATES: dict[str, dict[str, Any]] = {
    spec.process_tool_name: spec.scanner_template(_SCANNER_BUILDERS[spec.process_tool_name])
    for spec in CAPABILITY_REGISTRY.process_tools()
    if spec.process_tool_name in _SCANNER_BUILDERS
}
RUN_TOOL_NAMES: frozenset[str] = frozenset(SCANNER_ARG_TEMPLATES)

RUN_TOOL_SCHEMA: dict[str, Any] = {
    "name": "run_tool",
    "risk": "active",
    "description": (
        "Run a bounded external scanner against a URL on the SELECTED TARGET HOST. You pick tool + target "
        f"only; all flags are fixed. Tools: {sorted(RUN_TOOL_NAMES)} — httpx = passive "
        "fingerprint; nuclei = bounded focused templates by default (options {severity,tags}; explicit broad tags may return partial evidence at the hard wall); katana = crawl + "
        "JS endpoint extraction (finds linked/JS-referenced routes); ffuf = content/dir "
        "discovery over a bundled wordlist (options {wordlist: common|api|admin} — finds "
        "UNLINKED paths); dalfox = XSS scan of one URL (options {severity}); sqlmap = "
        "bounded SQLi test of one URL (boolean/error/union/time-based techniques, level/risk 2); "
        "nmap = read-only service/version probe of the single port behind a target URL (no "
        "scripts); naabu = top-100 TCP port sweep of the target host. Use katana/ffuf/naabu to "
        "expand the surface, then attack params with dalfox/sqlmap or probe hits with "
        "http_request. Returns the scanner's output (bounded)."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "name": {
                "type": "string",
                "enum": sorted(RUN_TOOL_NAMES),
                "description": "httpx | nuclei | katana | ffuf | dalfox | sqlmap | nmap | naabu",
            },
            "target": {"type": "string", "description": "absolute path (/) on the chosen origin or an http(s) URL on the selected target host"},
            "options": {
                "type": "object",
                "description": (
                    "nuclei: {severity:'high,critical', tags:'cve,exposure'} (omit tags for the focused pack); "
                    "ffuf: {wordlist:'common'|'api'|'admin'}; "
                    "dalfox: {severity:'low'|'medium'|'high'}; other tools have no tunable options"
                ),
            },
        },
        "required": ["name", "target"],
    },
}


def tool_schemas(*, include_run_tool: bool = True) -> list[dict[str, Any]]:
    """Return the callable tool schemas (a copy). ``include_run_tool`` adds the
    argv-template scanner tool (slice 5)."""
    schemas = [dict(schema) for schema in AGENT_TOOL_SCHEMAS]
    if include_run_tool:
        schemas.append(dict(RUN_TOOL_SCHEMA))
    return schemas


def coerce_run_tool(args: dict[str, Any]) -> tuple[str, Any, dict[str, Any]]:
    name = str(args.get("name") or "").strip().lower()
    if name not in RUN_TOOL_NAMES:
        raise AgentToolError(f"unknown run_tool:{name} (allowed: {sorted(RUN_TOOL_NAMES)})")
    options = args.get("options") if isinstance(args.get("options"), dict) else {}
    return name, args.get("target"), options


def _pinned_scanner_url(url: str, pinned_address: str) -> tuple[str, str, str]:
    parsed = urllib.parse.urlsplit(url)
    try:
        address = str(ipaddress.ip_address(str(pinned_address or "").strip()))
    except ValueError as exc:
        raise AgentToolError("scanner pinned address must be an IP address") from exc
    hostname = str(parsed.hostname or "").rstrip(".")
    if not hostname:
        raise AgentToolError("scanner target is missing a hostname")
    port = parsed.port
    display_address = f"[{address}]" if ":" in address else address
    pinned_netloc = display_address + (f":{port}" if port is not None else "")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    host_display = f"[{hostname}]" if ":" in hostname else hostname
    host_header = host_display if port in (None, default_port) else f"{host_display}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme, pinned_netloc, parsed.path or "/", parsed.query, "")), hostname, host_header


# ProjectDiscovery's PUBLIC interactsh servers. A hunt runs against a customer target, so an
# OOB callback URL reveals target-identifying data to whoever operates the callback server.
# We therefore NEVER enable the public default; blind OOB detection is available only when an
# operator explicitly points ShakerScan at their OWN private interactsh server.
_PUBLIC_INTERACTSH_HOSTS = frozenset({
    "oast.fun", "oast.online", "oast.pro", "oast.live", "oast.site", "oast.me", "interact.sh",
})


def validate_private_interactsh_server(url: Any) -> str | None:
    """Return a normalized scheme://host[:port] only for a valid, non-public OOB server.

    Fail-closed: empty, malformed, non-http(s), or any ProjectDiscovery public server returns
    ``None`` (the caller then keeps ``-no-interactsh``). The path/query/fragment are dropped.
    """
    text = str(url or "").strip()
    if not text or any(ch in text for ch in " \t\r\n"):
        return None
    parsed = urllib.parse.urlsplit(text if "://" in text else "https://" + text)
    scheme = (parsed.scheme or "https").lower()
    if scheme not in {"http", "https"}:
        return None
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host:
        return None
    if any(host == pub or host.endswith("." + pub) for pub in _PUBLIC_INTERACTSH_HOSTS):
        return None
    authority = host
    if parsed.port:
        if not 1 <= int(parsed.port) <= 65535:
            return None
        authority = f"{host}:{int(parsed.port)}"
    return f"{scheme}://{authority}"


def resolve_hunt_interactsh_config(*, allow_active: bool) -> tuple[str | None, str | None]:
    """Resolve the operator-configured private OOB server for a gated hunt, or (None, None).

    Only a gated-execution (credential-tier approved) hunt may use OOB, and only when the
    operator has set ``SHAKERSCAN_HUNT_INTERACTSH_SERVER`` to their own private server. This is
    off by default, so no hunt gains external OOB egress without an explicit operator opt-in.
    """
    if not allow_active:
        return None, None
    server = validate_private_interactsh_server(os.environ.get("SHAKERSCAN_HUNT_INTERACTSH_SERVER"))
    if not server:
        return None, None
    token = str(os.environ.get("SHAKERSCAN_HUNT_INTERACTSH_TOKEN") or "").strip() or None
    if token and (any(ch in token for ch in "\r\n") or len(token) > 512):
        token = None
    return server, token


def _apply_nuclei_interactsh(argv: list[str], server: str | None, token: str | None) -> list[str]:
    """Enable nuclei OOB against a validated private server; otherwise leave argv unchanged.

    When enabled we also drop ``-proxy-internal`` so nuclei's interactsh client can reach the
    operator's private OOB server directly. Target scan traffic still rides ``-proxy`` (the pinned
    loopback SOCKS broker), so egress pinning of the actual scan is preserved.
    """
    validated = validate_private_interactsh_server(server)
    if not validated:
        return argv
    result = [flag for flag in argv if flag not in {"-no-interactsh", "-proxy-internal"}]
    result += ["-interactsh-server", validated]
    if token:
        result += ["-interactsh-token", token]
    return result


_TRUSTED_SCANNER_HEADER_NAME = re.compile(
    r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,120}$"
)
_RESERVED_TRUSTED_SCANNER_HEADERS = frozenset({
    "connection", "content-length", "host", "transfer-encoding",
})
_HTTP_HEADER_SCANNER_FLAGS: dict[str, str] = {
    "httpx": "-H",
    "nuclei": "-H",
    "katana": "-H",
    "ffuf": "-H",
    "dalfox": "--header",
}


def _trusted_scanner_header_args(
    name: str, trusted_headers: Mapping[str, Any] | None,
) -> list[str]:
    """Render worker-resolved headers for fixed HTTP adapters, never planner options."""
    if not trusted_headers:
        return []
    if not isinstance(trusted_headers, Mapping):
        raise AgentToolError("trusted scanner headers must be a mapping")
    rendered: list[tuple[str, str]] = []
    normalized_names: set[str] = set()
    for raw_name, raw_value in trusted_headers.items():
        header_name = str(raw_name or "").strip()
        header_value = str(raw_value or "")
        normalized_name = header_name.lower()
        if (
            not _TRUSTED_SCANNER_HEADER_NAME.fullmatch(header_name)
            or normalized_name in _RESERVED_TRUSTED_SCANNER_HEADERS
            or normalized_name in normalized_names
            or not header_value
            or not header_value.isascii()
            or len(header_value.encode("ascii")) > 8_192
            or any(ord(character) < 32 or ord(character) == 127
                   for character in header_value)
        ):
            raise AgentToolError("trusted scanner headers are invalid")
        normalized_names.add(normalized_name)
        rendered.append((header_name, header_value))
    rendered.sort(key=lambda item: item[0].lower())
    lines = [f"{header_name}: {header_value}" for header_name, header_value in rendered]
    if name == "sqlmap":
        return ["--headers", "\n".join(lines)]
    flag = _HTTP_HEADER_SCANNER_FLAGS.get(name)
    if not flag:
        raise AgentToolError(f"{name} does not accept HTTP credential headers")
    return [value for line in lines for value in (flag, line)]


def build_scanner_argv(
    name: str,
    url: str,
    options: dict[str, Any],
    *,
    pinned_address: str | None = None,
    pinned_proxy_url: str | None = None,
    oob_interactsh_server: str | None = None,
    oob_interactsh_token: str | None = None,
    trusted_headers: Mapping[str, Any] | None = None,
) -> tuple[str, list[str], int]:
    """Return (binary, argv, timeout_ms) for a scanner run. The binary name is NOT in argv
    (passed separately to the subprocess); every flag is hardcoded in the template."""
    template = SCANNER_ARG_TEMPLATES[name]
    execution_url = url
    pin_args: list[str] = []
    if name in ("nmap", "naabu") and pinned_address:
        # Host/port posture tools support neither SOCKS proxies nor Host/SNI overrides, so
        # pinning replaces the scan HOST with the pinned IP itself: the template extracts
        # host+port from this URL. The hostname is intentionally dropped (no SNI needed for
        # port/service posture); egress stays frozen to the authorized address. This branch
        # takes precedence over the SOCKS broker, which these tools cannot ride.
        execution_url, _hostname, _host_header = _pinned_scanner_url(url, pinned_address)
    elif pinned_proxy_url:
        if not re.fullmatch(r"socks5://127\.0\.0\.1:\d{1,5}", pinned_proxy_url):
            raise AgentToolError("scanner pinned proxy must be a loopback SOCKS5 URL")
        if name in ("nmap", "naabu"):
            raise AgentToolError(
                f"{name} cannot ride the SOCKS pinning broker without a pinned address to scan directly"
            )
        proxy_flags = {
            "httpx": ["-http-proxy", pinned_proxy_url],
            "nuclei": ["-proxy", pinned_proxy_url, "-proxy-internal"],
            "katana": ["-proxy", pinned_proxy_url],
            "ffuf": ["-x", pinned_proxy_url],
            "dalfox": ["--proxy", pinned_proxy_url],
            "sqlmap": [f"--proxy={pinned_proxy_url}"],
        }
        pin_args = proxy_flags[name]
    elif pinned_address:
        execution_url, hostname, host_header = _pinned_scanner_url(url, pinned_address)
        if name == "httpx":
            pin_args = ["-H", f"Host: {host_header}", "-sni-name", hostname]
        elif name == "nuclei":
            pin_args = ["-H", f"Host: {host_header}", "-sni", hostname]
        elif name == "katana":
            pin_args = ["-H", f"Host: {host_header}"]
        elif name == "ffuf":
            pin_args = ["-H", f"Host: {host_header}", "-sni", hostname]
        elif name == "dalfox":
            pin_args = ["--header", f"Host: {host_header}"]
        elif name == "sqlmap":
            pin_args = ["--host", host_header]
    argv = (
        template["build"](execution_url, options or {})
        + pin_args
        + _trusted_scanner_header_args(name, trusted_headers)
    )
    if name == "nuclei":
        argv = _apply_nuclei_interactsh(argv, oob_interactsh_server, oob_interactsh_token)
    return (
        template["binary"],
        argv,
        int(template["default_timeout_ms"]),
    )


def _replace_argv_value(argv: list[str], flag: str, value: Any) -> None:
    try:
        index = argv.index(flag)
        argv[index + 1] = str(value)
    except (ValueError, IndexError) as exc:
        raise AgentToolError(f"scanner command is missing required flag: {flag}") from exc


def scanner_ffuf_wordlist_source(options: Mapping[str, Any] | None = None) -> str:
    """Resolve one bundled FFUF source path; callers can never supply a filesystem path."""
    selected = str(dict(options or {}).get("wordlist") or "").strip().lower()
    return _AGENT_FFUF_WORDLISTS.get(selected, _AGENT_FFUF_WORDLISTS["common"])


def build_enforced_scanner_plan(
    name: str,
    url: str,
    options: dict[str, Any],
    *,
    reserved_budget: Mapping[str, Any],
    pinned_address: str | None = None,
    pinned_proxy_url: str | None = None,
    oob_interactsh_server: str | None = None,
    oob_interactsh_token: str | None = None,
    trusted_headers: Mapping[str, Any] | None = None,
    runtime_paths: Mapping[str, Any] | None = None,
) -> EnforcedProcessPlan:
    """Build and prove a command whose worst-case wire use fits ``reserved_budget``.

    This is the sole authoritative builder used by worker process creation. The
    older tuple builder remains a compatibility renderer for inspection/tests;
    it is not sufficient authority to launch a process.
    """
    scanner = str(name or "").strip().lower()
    reservation: dict[str, int] = {}
    for raw_name, raw_amount in dict(reserved_budget or {}).items():
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError) as exc:
            raise AgentToolError("scanner reservation must contain integers") from exc
        if amount > 0:
            reservation[str(raw_name)] = amount
    wall = int(reservation.get("tool_wall_seconds") or 0)
    if wall < 1:
        raise AgentToolError("scanner reservation has no wall-clock capacity")
    runtime = dict(runtime_paths or {})
    internal_options = dict(options or {})
    if scanner == "ffuf" and runtime.get("ffuf_wordlist"):
        internal_options["wordlist"] = "common"

    binary, argv, template_timeout_ms = build_scanner_argv(
        scanner,
        url,
        internal_options,
        pinned_address=pinned_address,
        pinned_proxy_url=pinned_proxy_url,
        # The executable contract is self-contained. OOB traffic cannot be
        # counted by the target-bound limiter, so it is always disabled here.
        oob_interactsh_server=None,
        oob_interactsh_token=None,
        trusted_headers=trusted_headers,
    )
    timeout_seconds = max(1, min(wall, int(math.ceil(template_timeout_ms / 1000))))
    timeout_ms = timeout_seconds * 1_000
    proof_inputs: dict[str, Any]

    if scanner == "httpx":
        if reservation.get("http_requests", 0) < 1:
            raise AgentToolError("httpx requires one reserved HTTP request")
        hard = {"http_requests": 1, "tool_wall_seconds": timeout_seconds}
        mode, method = "exact", "exact_request_count"
        proof_inputs = {
            "targets": 1, "redirects": 0, "fallbacks": 0, "retries": 0,
        }
    elif scanner == "katana":
        http = int(reservation.get("http_requests") or 0)
        duration = min(30, wall, max(0, http - 1))
        if duration < 1:
            raise AgentToolError("katana requires two reserved HTTP requests")
        _replace_argv_value(argv, "-rate-limit", 1)
        _replace_argv_value(argv, "-concurrency", 1)
        _replace_argv_value(argv, "-crawl-duration", f"{duration}s")
        timeout_seconds = duration
        timeout_ms = duration * 1_000
        # One initial token plus one token for each elapsed second.
        hard = {"http_requests": duration + 1, "tool_wall_seconds": duration}
        mode, method = "conservative", "rate_time_upper_bound"
        proof_inputs = {
            "rate_per_second": 1, "duration_seconds": duration,
            "startup_burst": 1, "redirects": 0, "form_fill": False,
            "depth": 2, "concurrency": 1,
        }
    elif scanner == "ffuf":
        wordlist_path = str(runtime.get("ffuf_wordlist") or "")
        try:
            entry_count = int(runtime.get("ffuf_word_count") or 0)
        except (TypeError, ValueError) as exc:
            raise AgentToolError("ffuf bounded wordlist count is invalid") from exc
        if (
            not wordlist_path
            or not os.path.isabs(wordlist_path)
            or entry_count < 1
            or entry_count > int(reservation.get("http_requests") or 0)
        ):
            raise AgentToolError("ffuf requires a bounded worker-owned wordlist")
        _replace_argv_value(argv, "-w", wordlist_path)
        # The wordlist, not rate*time, is the exact request ceiling.  Scale
        # throughput so the immutable list can finish inside the reservation;
        # forcing one request per second made the 108-entry bundled list time
        # out after only 39 requests despite a 75-second action hold.
        maxtime = wall
        usable_seconds = max(1, maxtime - 2)
        rate = max(1, int(math.ceil(entry_count / usable_seconds)))
        _replace_argv_value(argv, "-t", min(5, rate))
        _replace_argv_value(argv, "-rate", rate)
        _replace_argv_value(argv, "-maxtime", maxtime)
        timeout_seconds = maxtime
        timeout_ms = maxtime * 1_000
        hard = {"http_requests": entry_count, "tool_wall_seconds": maxtime}
        mode, method = "exact", "exact_wordlist"
        proof_inputs = {
            "entries": entry_count, "auto_calibration_requests": 0,
            "redirects": 0, "recursion": False,
            "threads": min(5, rate), "rate_per_second": rate,
        }
    elif scanner == "nuclei":
        http = int(reservation.get("http_requests") or 0)
        passive_cost = internal_options.get(
            "template_request_cost_upper_bound"
        )
        if passive_cost is not None:
            if (
                isinstance(passive_cost, bool)
                or not isinstance(passive_cost, int)
                or passive_cost != canonical_passive_nuclei_request_upper_bound()
                or internal_options.get("template_ids")
                != _CANONICAL_PASSIVE_NUCLEI_IDS
                or passive_cost > http
            ):
                raise AgentToolError(
                    "nuclei passive template request ceiling is not canonical"
                )
            _replace_argv_value(argv, "-rate-limit", min(10, passive_cost))
            _replace_argv_value(argv, "-bulk-size", 1)
            _replace_argv_value(argv, "-concurrency", 1)
            timeout_seconds, timeout_ms = wall, wall * 1_000
            hard = {
                "http_requests": passive_cost,
                "tool_wall_seconds": wall,
            }
            mode, method = "exact", "reviewed_template_allowlist"
            proof_inputs = {
                "profile": "passive_read_only",
                "template_count": len(CANONICAL_PASSIVE_NUCLEI_TEMPLATES),
                "template_request_upper_bound": passive_cost,
                "methods": ["GET"],
                "retries": 0,
                "redirects": 0,
                "public_oob": False,
            }
        elif http >= 4_000 and wall >= 300:
            hard = {"http_requests": 4_000, "tool_wall_seconds": 300}
            timeout_seconds, timeout_ms = 300, 300_000
            mode, method = "conservative", "fixed_conservative_profile"
            proof_inputs = {
                "profile": "full", "rate_per_second": 10,
                "duration_seconds": 300, "startup_and_engine_overhead": 1_000,
                "retries": 0, "redirects": 0, "public_oob": False,
            }
        else:
            duration = min(wall, max(0, http - 1))
            rate = (http - 1) // duration if duration else 0
            if duration < 1 or rate < 1:
                raise AgentToolError("nuclei reduced profile requires rate/time capacity")
            _replace_argv_value(argv, "-rate-limit", rate)
            _replace_argv_value(argv, "-bulk-size", 1)
            _replace_argv_value(argv, "-concurrency", 1)
            timeout_seconds, timeout_ms = duration, duration * 1_000
            hard = {
                "http_requests": rate * duration + 1,
                "tool_wall_seconds": duration,
            }
            mode, method = "conservative", "rate_time_upper_bound"
            proof_inputs = {
                "profile": "reduced", "rate_per_second": rate,
                "duration_seconds": duration, "startup_burst": 1,
                "bulk_size": 1, "concurrency": 1, "retries": 0,
                "redirects": 0, "public_oob": False,
            }
    elif scanner == "dalfox":
        http = int(reservation.get("http_requests") or 0)
        if http >= 400 and wall >= 120:
            hard = {"http_requests": 400, "tool_wall_seconds": 120}
            timeout_seconds, timeout_ms = 120, 120_000
            mode, method = "conservative", "fixed_conservative_profile"
            proof_inputs = {
                "profile": "full", "targets": 1, "workers": 3,
                "delay_ms": 1_000, "headless": False,
                "parameter_mining": False, "blind_oob": False,
            }
        else:
            duration = min(wall, max(0, http - 1))
            if duration < 1:
                raise AgentToolError("dalfox reduced profile requires rate/time capacity")
            _replace_argv_value(argv, "--worker", 1)
            _replace_argv_value(argv, "--delay", 1_000)
            timeout_seconds, timeout_ms = duration, duration * 1_000
            hard = {
                "http_requests": duration + 1,
                "tool_wall_seconds": duration,
            }
            mode, method = "conservative", "rate_time_upper_bound"
            proof_inputs = {
                "profile": "reduced", "targets": 1, "workers": 1,
                "delay_ms": 1_000, "startup_burst": 1,
                "headless": False, "parameter_mining": False,
                "blind_oob": False,
            }
    elif scanner == "sqlmap":
        sqlmap_output_dir = str(runtime.get("sqlmap_output_dir") or "")
        argv = bind_scanner_runtime_paths(
            "sqlmap", argv, scratch_dir=sqlmap_output_dir,
        )
        _replace_argv_value(argv, "--threads", 1)
        _replace_argv_value(argv, "--retries", 0)
        http = int(reservation.get("http_requests") or 0)
        if http >= 900 and wall >= 300:
            hard = {"http_requests": 900, "tool_wall_seconds": 300}
            timeout_seconds, timeout_ms = 300, 300_000
            mode, method = "conservative", "fixed_conservative_profile"
            techniques, profile = "BEUT", "full"
        else:
            duration = min(wall, max(0, http - 1))
            if duration < 1:
                raise AgentToolError("sqlmap reduced profile requires rate/time capacity")
            techniques = "BEU" if duration >= 60 else "BE"
            _replace_argv_value(argv, "--technique", techniques)
            _replace_argv_value(argv, "--level", 1)
            _replace_argv_value(argv, "--risk", 1)
            timeout_seconds, timeout_ms = duration, duration * 1_000
            hard = {
                "http_requests": duration + 1,
                "tool_wall_seconds": duration,
            }
            mode, method = "conservative", "rate_time_upper_bound"
            profile = "reduced"
        proof_inputs = {
            "profile": profile, "targets": 1, "candidate_requests": 1,
            "crawl_depth": 0, "retries": 0, "threads": 1,
            "delay_ms": 1_000, "startup_burst": 1,
            "techniques": techniques, "shell": False, "file_read": False,
            "dump": False,
        }
    elif scanner == "nmap":
        if reservation.get("tcp_ports_attempted", 0) < 1:
            raise AgentToolError("nmap requires one reserved TCP port")
        hard = {"tcp_ports_attempted": 1, "tool_wall_seconds": timeout_seconds}
        mode, method = "exact", "exact_port_set"
        proof_inputs = {"targets": 1, "ports": 1, "scripts": 0}
    elif scanner == "naabu":
        if reservation.get("tcp_ports_attempted", 0) < 200:
            raise AgentToolError("naabu top-100 profile requires 200 TCP-attempt units")
        hard = {"tcp_ports_attempted": 200, "tool_wall_seconds": timeout_seconds}
        mode, method = "conservative", "port_retry_upper_bound"
        proof_inputs = {"targets": 1, "ports": 100, "attempts_per_port": 2}
    else:
        raise AgentToolError(f"scanner has no wire-budget proof builder: {scanner}")

    proof = {
        "schema_version": PROCESS_BUDGET_PROOF_SCHEMA,
        "tool_name": scanner,
        "accounting_mode": mode,
        "method": method,
        "inputs": proof_inputs,
        "upper_bound": hard,
    }
    try:
        parser_version = str(CAPABILITY_REGISTRY.for_process_tool(scanner).output_schema)
    except KeyError:
        parser_version = "scanner-output/v1"
    try:
        plan = EnforcedProcessPlan(
            tool_name=scanner,
            binary=binary,
            argv=tuple(argv),
            env=(("NO_COLOR", "1"),),
            timeout_ms=timeout_ms,
            hard_budget=tuple(sorted(hard.items())),
            budget_proof=proof,
            parser_version=parser_version,
        )
        plan.validate_reservation(reservation)
    except ExternalProcessContractError as exc:
        raise AgentToolError(str(exc)) from exc
    return plan


def bind_scanner_runtime_paths(
    name: str,
    argv: list[str],
    *,
    scratch_dir: str | None,
) -> list[str]:
    """Bind worker-owned ephemeral paths after the fixed argv is constructed."""
    bound = list(argv)
    if name != "sqlmap":
        return bound
    if not scratch_dir or not os.path.isabs(scratch_dir):
        raise AgentToolError("sqlmap requires an absolute worker-owned scratch directory")
    try:
        output_index = bound.index("--output-dir") + 1
    except (ValueError, IndexError) as exc:
        raise AgentToolError("sqlmap output directory contract is missing") from exc
    bound[output_index] = scratch_dir
    return bound


def scanner_request_reservation(name: str, options: dict[str, Any] | None = None) -> int:
    """Return the fail-closed wire-request reservation for one external scanner invocation."""
    template = SCANNER_ARG_TEMPLATES.get(str(name or "").strip().lower())
    if not template:
        raise AgentToolError(f"unknown run_tool:{name}")
    return max(1, int(template.get("max_wire_requests") or 1))


def settle_scanner_wire_reservation(
    *, charged_total: int, reservation: int, accounting: str,
    actual: Any, budget_limit: int | None,
) -> dict[str, Any]:
    """Replace one reservation with an exact counter without hiding overruns."""
    before = max(0, int(charged_total))
    reserved = max(0, int(reservation))
    exact: int | None = None
    if str(accounting or "") == "exact" and actual is not None:
        try:
            exact = max(0, int(actual))
        except (TypeError, ValueError):
            exact = None
    charged = reserved if exact is None else exact
    total = max(0, before - reserved + charged)
    limit = None if budget_limit is None else max(0, int(budget_limit))
    return {
        "charged": charged,
        "charged_total": total,
        "actual": exact,
        "reservation_refund": max(0, reserved - charged),
        "reservation_overrun": max(0, charged - reserved),
        "budget_overrun": 0 if limit is None else max(0, total - limit),
        "settled": exact is not None,
    }


def request_budget_units(tool_name: str) -> int:
    """Return episode request units for one traffic-producing tool invocation.

    A bounded external scanner consumes one episode request unit regardless of how many
    requests it issues inside its fixed wire ceiling. Wire traffic is settled separately.
    """
    return 1 if str(tool_name or "").strip() in {"http_request", "run_tool"} else 0


def validate_scanner_execution_target(registered_target: str, execution_target: str) -> str:
    """Revalidate the worker-side scanner destination against the durable web target.

    The control plane resolves an allowed origin before enqueueing, but queue contents are
    untrusted at execution time.  Workers therefore independently require HTTP(S), a concrete
    hostname, and the exact selected target host.  Ports and paths may differ because Deep Hunt
    explicitly supports discovered origins on the same registered host.
    """
    try:
        registered = urllib.parse.urlsplit(str(registered_target or "").strip())
        execution = urllib.parse.urlsplit(str(execution_target or "").strip())
        registered_host = (registered.hostname or "").lower().rstrip(".")
        execution_host = (execution.hostname or "").lower().rstrip(".")
        # Accessing port also rejects malformed authorities such as ``host:bad``.
        _ = registered.port
        _ = execution.port
    except ValueError as exc:
        raise AgentToolError("scanner execution target has an invalid authority") from exc
    if registered.scheme.lower() not in {"http", "https"} or not registered_host:
        raise AgentToolError("registered scanner target must be an absolute HTTP(S) URL")
    if execution.scheme.lower() not in {"http", "https"} or not execution_host:
        raise AgentToolError("scanner execution target must be an absolute HTTP(S) URL")
    if execution.username or execution.password:
        raise AgentToolError("scanner execution target must not contain user information")
    if execution_host != registered_host:
        raise AgentToolError("scanner execution target must use the selected target host")
    return urllib.parse.urlunsplit(
        (execution.scheme.lower(), execution.netloc, execution.path or "/", execution.query, "")
    )


def validate_pinned_scanner_address(pinned_address: Any, authorized_addresses: Any) -> str:
    try:
        pinned = str(ipaddress.ip_address(str(pinned_address or "").strip()))
    except ValueError as exc:
        raise AgentToolError("scanner job has no valid pinned address") from exc
    authorized: set[str] = set()
    for raw in list(authorized_addresses or [])[:32]:
        try:
            authorized.add(str(ipaddress.ip_address(str(raw).strip())))
        except ValueError:
            continue
    if pinned not in authorized:
        raise AgentToolError("scanner pinned address is outside the authorized resolution set")
    return pinned


_REQUEST_COUNTER_KEYS: frozenset[str] = frozenset({
    "requests", "request_count", "requests_count", "requests_sent",
    "total_requests", "total_requests_sent", "http_requests",
})


def _explicit_request_counters(value: Any) -> list[int]:
    counters: list[int] = []
    if isinstance(value, dict):
        for raw_key, raw_value in value.items():
            key = str(raw_key or "").strip().lower().replace("-", "_")
            if key in _REQUEST_COUNTER_KEYS:
                number: int | None = None
                if isinstance(raw_value, (int, float)):
                    number = int(raw_value)
                elif isinstance(raw_value, str) and re.fullmatch(r"\d{1,18}", raw_value.strip()):
                    # Nuclei v3.11 serializes stats counters as JSON strings.
                    number = int(raw_value.strip())
                if number is not None and number >= 0:
                    counters.append(number)
            elif isinstance(raw_value, (dict, list)):
                counters.extend(_explicit_request_counters(raw_value))
    elif isinstance(value, list):
        for item in value:
            counters.extend(_explicit_request_counters(item))
    return counters


def scanner_request_settlement(name: str, stdout: str) -> dict[str, Any]:
    """Derive honest post-execution wire-request accounting from scanner output.

    An explicit scanner counter is exact and may refund a conservative reservation.  A successful
    ``httpx`` fingerprint is one request because redirects are not followed by its fixed template.
    Other result records are only a lower bound: a crawler/template engine can issue many requests
    that produce no record, so those observations must never be treated as exact or refunded.
    """
    scanner = str(name or "").strip().lower()
    text = str(stdout or "")
    decoded: list[Any] = []
    try:
        whole = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        whole = None
    if whole is not None:
        decoded.append(whole)
    else:
        for line in text.splitlines()[:1000]:
            try:
                decoded.append(json.loads(line))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
    counters = _explicit_request_counters(decoded)
    if counters:
        # Nested summaries sometimes repeat the same cumulative counter.  The maximum is the final
        # cumulative total and is safer than summing duplicate snapshots.
        actual = max(counters)
        return {
            "mode": "exact",
            "actual": actual,
            "observed_minimum": actual,
            "source": "scanner_counter",
        }
    typed = parse_scanner_output(scanner, text)
    observed = int(typed.get("record_count") or 0)
    if scanner == "httpx" and observed > 0:
        return {"mode": "exact", "actual": 1, "observed_minimum": 1, "source": "fixed_httpx_contract"}
    if observed > 0:
        return {
            "mode": "observed_lower_bound",
            "actual": None,
            "observed_minimum": observed,
            "source": "typed_result_records",
        }
    return {"mode": "unavailable", "actual": None, "observed_minimum": 0, "source": None}


def _public_observed_url(value: Any) -> str | None:
    """Retain route shape while removing secrets from untrusted scanner output."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return redact_url(text, max_length=2_000)
    except ValueError:
        return None


def parse_scanner_output(
    name: str, stdout: str, *, allowed_host: str | None = None,
) -> dict[str, Any]:
    """Parse bounded scanner output into records safe for hunt reasoning.

    Raw output remains receipt evidence; these records are observations, never finding proof.
    """
    scanner = str(name or "").strip().lower()
    decoded: list[dict[str, Any]] = []
    text = str(stdout or "")
    try:
        whole = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        whole = None
    if isinstance(whole, dict) and isinstance(whole.get("results"), list):
        decoded.extend(item for item in whole["results"] if isinstance(item, dict))
    elif isinstance(whole, list):
        decoded.extend(item for item in whole if isinstance(item, dict))
    elif isinstance(whole, dict):
        decoded.append(whole)
    else:
        for line in text.splitlines()[:500]:
            try:
                item = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(item, dict):
                decoded.append(item)
        if scanner == "katana" and not decoded:
            # Compact Katana mode emits one absolute URL per line. Preserve only URL-shaped
            # records; banners and diagnostics are not route observations.
            for line in text.splitlines()[:500]:
                candidate = line.strip()
                try:
                    parsed_candidate = urllib.parse.urlsplit(candidate)
                except ValueError:
                    continue
                if parsed_candidate.scheme in {"http", "https"} and parsed_candidate.hostname:
                    decoded.append({"url": candidate, "method": "GET"})

    records: list[dict[str, Any]] = []
    seen_katana_urls: set[str] = set()
    for item in decoded[:200]:
        if scanner == "nuclei":
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            template_id = str(item.get("template-id") or item.get("template_id") or "")[:200] or None
            matched_at = _public_observed_url(
                item.get("matched-at") or item.get("matched_at") or item.get("url")
            )
            # Stats/progress JSON is accounting evidence, not a template match.
            if not template_id and not matched_at:
                continue
            records.append({
                "kind": "template_match",
                "template_id": template_id,
                "name": str(info.get("name") or item.get("name") or "")[:300] or None,
                "severity": str(info.get("severity") or item.get("severity") or "").lower()[:20] or None,
                "matched_at": matched_at,
                "matcher_name": str(item.get("matcher-name") or item.get("matcher_name") or "")[:200] or None,
                "proof_state": "candidate",
            })
        elif scanner == "katana":
            request = item.get("request") if isinstance(item.get("request"), dict) else {}
            observed_url = _public_observed_url(
                item.get("url") or item.get("endpoint") or request.get("endpoint")
            )
            if not observed_url:
                continue
            if allowed_host:
                try:
                    observed_host = (urllib.parse.urlsplit(observed_url).hostname or "").lower().rstrip(".")
                except ValueError:
                    continue
                if observed_host != str(allowed_host).lower().rstrip("."):
                    continue
            if observed_url in seen_katana_urls:
                continue
            seen_katana_urls.add(observed_url)
            records.append({
                "kind": "discovered_route",
                "url": observed_url,
                "method": str(item.get("method") or request.get("method") or "GET").upper()[:16],
                "source": _public_observed_url(item.get("source") or item.get("from")),
            })
        elif scanner == "ffuf":
            records.append({
                "kind": "content_discovery",
                "url": _public_observed_url(item.get("url") or item.get("input", {}).get("FUZZ") if isinstance(item.get("input"), dict) else item.get("url")),
                "status": item.get("status"),
                "length": item.get("length"),
                "redirect_location": _public_observed_url(item.get("redirectlocation") or item.get("redirect_location")),
            })
        elif scanner == "httpx":
            technologies = item.get("tech") or item.get("technologies") or []
            records.append({
                "kind": "http_fingerprint",
                "url": _public_observed_url(item.get("url") or item.get("input")),
                "status": item.get("status_code") or item.get("status-code"),
                "title": str(item.get("title") or "")[:300] or None,
                "webserver": str(item.get("webserver") or item.get("web_server") or "")[:200] or None,
                "technologies": [str(value)[:100] for value in list(technologies or [])[:50]],
            })
        elif scanner == "dalfox":
            data = item.get("data") if isinstance(item.get("data"), dict) else item
            message = str(data.get("message") or data.get("poc") or "")[:500] or None
            record = {
                "kind": "xss_alert",
                "alert_type": str(data.get("type") or item.get("type") or "")[:40] or None,
                "url": _public_observed_url(data.get("address") or data.get("url") or data.get("target")),
                "param": str(data.get("param") or "")[:200] or None,
                # Payload text is receipt-side only; hunt reasoning gets its shape, not the body.
                "payload_sha256": hashlib.sha256(str(data.get("payload") or "").encode()).hexdigest() if data.get("payload") else None,
                "message": message,
                "proof_state": "verified" if str(data.get("type") or "").lower() == "v" else "candidate",
            }
            records.append(record)
        elif scanner == "naabu":
            # JSON lines: {"host":"10.0.0.4","port":8443,"protocol":"tcp"} (port may be a
            # string). Stats/banner lines carry no port and are dropped.
            text_port = str(item.get("port") or "").strip()
            if not text_port.isdigit():
                continue
            records.append({
                "kind": "open_port",
                "host": str(item.get("host") or item.get("ip") or "")[:200] or None,
                "port": int(text_port),
                "protocol": str(item.get("protocol") or "tcp")[:16],
                "proof_state": "candidate",
            })
    if scanner == "sqlmap":
        for line in text.splitlines()[:500]:
            line = line.strip()
            if "is vulnerable" in line:
                parameter_match = re.search(
                    r"(?:\b(GET|POST|PUT|PATCH|DELETE)\s+)?parameter\s+['\"]([^'\"]+)['\"]\s+is vulnerable",
                    line,
                    re.I,
                )
                records.append({
                    "kind": "sqli_finding",
                    "message": line.split("Do you want")[0].strip()[:500],
                    "param": parameter_match.group(2)[:200] if parameter_match else None,
                    "method": (
                        parameter_match.group(1).upper()
                        if parameter_match and parameter_match.group(1) else None
                    ),
                    "proof_state": "candidate",
                })
            elif line.startswith("[INFO] back-end DBMS:") or "back-end DBMS" in line:
                records.append({
                    "kind": "sqli_dbms_fingerprint",
                    "message": line[:300],
                    "proof_state": "candidate",
                })
    if scanner == "nmap":
        # -oN - human output; only "PORT STATE SERVICE [VERSION]" table rows are observations.
        for line in text.splitlines()[:500]:
            match = _NMAP_SERVICE_LINE_RE.match(line.strip())
            if not match:
                continue
            records.append({
                "kind": "port_service",
                "port": match.group(1),
                "state": match.group(2)[:32],
                "service": match.group(3)[:64],
                "version": (match.group(4) or "")[:200] or None,
                "proof_state": "candidate",
            })
    records = [record for record in records if any(value not in (None, "", [], {}) for key, value in record.items() if key != "kind")]
    return {
        "parser": f"{scanner}-typed-v1",
        "parser_status": "parsed" if records else ("partial" if decoded else "not_applicable"),
        "records": records[:200],
        "record_count": len(records),
    }


# --------------------------------------------------------------------------------------
# Pure guards (host-testable).
# --------------------------------------------------------------------------------------


class AgentToolError(ValueError):
    """Raised by a guard when a tool argument is unsafe or malformed. The loop feeds the
    message back to the model (error-recovery) rather than crashing."""


def coerce_method(method: Any) -> str:
    value = str(method or "GET").strip().upper()
    if value not in ALL_METHODS:
        raise AgentToolError(f"unsupported_method:{value} (allowed: {sorted(ALL_METHODS)})")
    return value


def is_write_method(method: str) -> bool:
    return method.strip().upper() in WRITE_METHODS


def validate_same_origin_path(path: Any) -> str:
    """A same-origin absolute path: starts with a single '/', no control chars, bounded.
    Rejects protocol-relative ('//host') and absolute URLs (SSRF)."""
    text = str(path or "")
    if not text.startswith("/") or text.startswith("//"):
        raise AgentToolError("path must be an absolute same-origin path starting with a single '/'")
    if len(text.encode("utf-8")) > 4000:
        raise AgentToolError("path exceeds size limit")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in text):
        raise AgentToolError("path contains control characters")
    return text


def filter_request_headers(headers: Any) -> dict[str, str]:
    """Drop any header the model must not set (auth/identity/hop-by-hop/sensitive). Real
    auth comes only from a server-resolved principal. Returns the surviving benign headers."""
    out: dict[str, str] = {}
    if not isinstance(headers, dict):
        return out
    for name, value in headers.items():
        lname = str(name).strip().lower()
        if not lname or lname in _FORBIDDEN_HEADERS:
            continue
        if any(sub in lname for sub in _SENSITIVE_HEADER_SUBSTR):
            continue
        sval = str(value)
        if not lname.isascii() or not sval.isascii():
            continue
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name + sval):
            continue
        if len(sval.encode("utf-8")) > 2000:
            continue
        out[str(name)] = sval
    return out


def normalize_principal_slot(value: Any) -> str:
    """A principal slot the model may request. 'anonymous' (or empty) means no auth."""
    slot = str(value or "").strip().lower()
    if slot in ("", "anonymous", "anon", "none"):
        return "anonymous"
    return slot


def coerce_query_kb(args: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    kind = str(args.get("kind") or "").strip().lower()
    if kind not in QUERY_KB_KINDS:
        raise AgentToolError(f"unknown query_kb kind:{kind} (allowed: {sorted(QUERY_KB_KINDS)})")
    flt = args.get("filter") if isinstance(args.get("filter"), dict) else {}
    return kind, flt


def coerce_note(args: dict[str, Any]) -> dict[str, Any]:
    kind = str(args.get("kind") or "observation").strip().lower()
    if kind not in NOTE_KINDS:
        raise AgentToolError(f"unknown note kind:{kind} (allowed: {sorted(NOTE_KINDS)})")
    title = str(args.get("title") or "").strip()
    if not title:
        raise AgentToolError("note requires a non-empty title")
    return {
        "kind": kind,
        "title": title[:200],
        "detail": str(args.get("detail") or "")[:4000],
        "family": (str(args.get("family")).strip().lower()[:80] if args.get("family") else None),
        "severity": (str(args.get("severity")).strip().lower()[:16] if args.get("severity") else None),
    }


def http_evidence_item(request_view: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """Shape an http_request result as a tool-provenance evidence item for the gate.
    ``type='response'`` is one of TOOL_EVIDENCE_KINDS, so this carries real provenance."""
    try:
        content = json.dumps({"request": request_view, "response": summary}, default=str)[:6000]
    except Exception:
        content = str(summary)[:6000]
    return {"type": "response", "content": content}


# --------------------------------------------------------------------------------------
# SUSPECTED -> VERIFIED bridge (Gap B): derive the concrete targets for a BOLA family_proof
# verification workflow from a suspected finding's route + each principal's captured object
# references. Pure/host-testable; the workflow assembly + dispatch (the moat) live in api.py.
# --------------------------------------------------------------------------------------

_ID_SEGMENT = re.compile(r"^(\d+|\{[^}]+\}|[0-9a-fA-F-]{8,})$")


def _bola_collection_and_segment(route: Any) -> tuple[Optional[str], str]:
    """Split a finding route into its collection route + the collection's last path segment,
    dropping a trailing object-id segment (numeric, uuid-ish, or ``{id}``)."""
    path = str(route or "").split("?", 1)[0].rstrip("/")
    parts = [p for p in path.split("/") if p]
    if not parts:
        return None, ""
    collection_parts = parts[:-1] if (len(parts) >= 2 and _ID_SEGMENT.match(parts[-1])) else parts
    if not collection_parts:
        return None, ""
    return "/" + "/".join(collection_parts), collection_parts[-1].lower()


def _singularize(segment: str) -> str:
    """Best-effort singular of a REST collection segment so a plural collection matches a singular
    captured-ref key (``products`` -> ``product`` so ``product_id`` matches). Conservative: keeps
    ``address`` (``ss``), ``basket`` (already singular)."""
    s = str(segment or "").lower()
    if s.endswith("ies") and len(s) > 3:
        return s[:-3] + "y"           # categories -> category
    if s.endswith("ses") and len(s) > 3:
        return s[:-2]                 # addresses -> address, statuses -> status
    if s.endswith("s") and not s.endswith("ss") and len(s) > 1:
        return s[:-1]                 # products -> product, baskets -> basket, users -> user
    return s


def _pick_object_ref(refs: Any, segment: str) -> tuple[Optional[str], Optional[str]]:
    """Choose a principal's own object reference for ``segment`` from its captured references, but
    ONLY when the ref key SEMANTICALLY matches the collection under test. Returns ``(key, value)`` —
    the ORIGINAL captured-ref key (to bind a server-resolved principal_variable) and its value.

    Zero-FP fail-closed: a captured ref is accepted only if its key is one of the collection's
    singular/plural forms (``{sing|plur}_id`` / ``{sing|plur}id`` / ``{sing|plur}``). There is NO
    generic ``object_id``/``id`` match and NO single-ref fallback — binding an UNRELATED ref (e.g.
    ``basket_id`` to a ``/api/Products`` route) fabricated the "owned object" premise the moat's
    ownership predicate trusts, which could false-VERIFY a BOLA on an auth-gated shared resource.
    No matching ref -> ``(None, None)`` -> the finding stays SUSPECTED (external-audit BUG 1)."""
    if not isinstance(refs, dict) or not refs:
        return None, None
    lower = {str(k).lower(): (k, v) for k, v in refs.items()}
    forms: list[str] = []
    for form in (_singularize(segment), str(segment or "").lower()):
        if form and form not in forms:
            forms.append(form)
    candidates = [c for form in forms for c in (f"{form}_id", f"{form}id", form)]
    for candidate in candidates:
        pair = lower.get(candidate)
        if pair is not None and str(pair[1]).strip():
            return str(pair[0]), str(pair[1]).strip()
    return None, None


def derive_bola_verification_targets(
    finding_route: Any, user1_refs: Any, user2_refs: Any
) -> Optional[dict[str, Any]]:
    """Return targets for a BOLA verification workflow, or ``None`` when the inputs cannot support
    a SOUND proof:
    ``{collection, owner_object_id, attacker_object_id, owner_ref_key, attacker_ref_key, ref_segment}``.

    The ``*_ref_key`` fields name each principal's captured-ref key so the workflow can bind a
    ``principal_variable`` that resolves the id server-side (a managed reference) — the only form the
    ownership predicate accepts. Requires two *distinct* owned object references (owner=user1,
    attacker=user2); equal or missing refs yield None (the finding stays SUSPECTED)."""
    collection, segment = _bola_collection_and_segment(finding_route)
    if not collection or collection == "/":
        return None
    owner_key, owner_value = _pick_object_ref(user1_refs, segment)
    attacker_key, attacker_value = _pick_object_ref(user2_refs, segment)
    if not owner_value or not attacker_value or owner_value == attacker_value:
        return None
    return {
        "collection": collection,
        "owner_object_id": owner_value,
        "attacker_object_id": attacker_value,
        "owner_ref_key": owner_key,
        "attacker_ref_key": attacker_key,
        "ref_segment": segment,
    }
