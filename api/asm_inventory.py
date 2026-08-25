"""Continuous ASM — persistent per-target endpoint inventory (docs §16).

Recon upserts the discovered endpoint worklist into the ``target_endpoints``
table; the exploitation pipeline pulls untested/stale endpoints, tests them, and
stamps results. Endpoint identity reuses the findings dedup pattern:
``UNIQUE(target_id, fingerprint)`` with an ``ON CONFLICT`` upsert.

The pure helpers (parse/normalize/fingerprint/priority) are unit-tested; the
async helpers take an asyncpg connection and do the DB work.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

try:
    from scanner_tools.attempt_telemetry import ENDPOINT_ATTEMPT_SCHEMA_V1
except ModuleNotFoundError:
    from scanner.scanner_tools.attempt_telemetry import ENDPOINT_ATTEMPT_SCHEMA_V1

# Job type for the async exploitation pipeline (routed in worker.process_job).
EXPLOIT_BATCH_JOB_TYPE = "exploit_batch"
# Scan roles created by the continuous dispatcher (docs §16 Phase 3).
ASM_BATCH_ROLE = "asm_batch"
ASM_RECON_ROLE = "asm_recon"

# Campaign modes. They are intentionally broader than the current dispatcher
# path so one-shot Full Coverage can move onto the same allocator later.
CAMPAIGN_FULL_COVERAGE = "full_coverage"
CAMPAIGN_CONTINUOUS_ASM = "continuous_asm"
CAMPAIGN_FOCUSED_FAMILY = "focused_family"
CAMPAIGN_FINDING_RETEST = "finding_retest"
CAMPAIGN_SURFACE_RECON = "surface_recon"

DEFAULT_LEASE_TTL_SECONDS = 3600
ASM_RATE_RESERVATION_TTL_SECONDS = 3600
ASM_RATE_RESERVE_LUA = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
local requested = tonumber(ARGV[1]) or 0
local cap = tonumber(ARGV[2]) or 0
local ttl = tonumber(ARGV[3]) or 3600
local all_or_nothing = tostring(ARGV[4] or '0')
if requested <= 0 then return 0 end
if cap <= 0 then return 0 end
if current >= cap then return 0 end
if all_or_nothing == '1' and current + requested > cap then
  return 0
end
local grant = requested
if current + grant > cap then
  grant = cap - current
end
redis.call('INCRBY', KEYS[1], grant)
redis.call('EXPIRE', KEYS[1], ttl)
return grant
"""

# HTTP methods we recognize as a leading token in a worklist entry.
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Path segments that are volatile resource identifiers — templated so
# /users/42 and /users/43 collapse to one inventory row.
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Path keywords that raise an endpoint's test priority (high-value surface).
_HIGH_VALUE = (
    "admin", "login", "signin", "auth", "oauth", "token", "session", "password",
    "reset", "register", "signup", "user", "account", "api", "rest", "graphql",
    "upload", "file", "payment", "checkout", "order", "basket", "cart", "config",
)

_AUTH_ROUTE_RE = re.compile(
    r"/(?:api|rest)?/?(?:v\d+(?:\.\d+)?/)?(?:user|users|auth|session|sessions|account|accounts)/(?:login|signin|authenticate|token|authentication)(?:/|$)"
)
_SEARCH_ROUTE_RE = re.compile(
    r"/(?:api|rest)?/?(?:v\d+(?:\.\d+)?/)?(?:products?/)?(?:search|query)(?:/|$)"
)
_MUTATION_RESOURCE_RE = re.compile(
    r"/(?:api|rest)?/?(?:v\d+(?:\.\d+)?/)?(?:basket|cart|order|orders|feedback|feedbacks|review|reviews|address|addresses|card|cards|coupon|payment)(?:/|$)"
)
_SPECULATIVE_VERSION_RE = re.compile(r"/(?:api|rest)/v\d+(?:\.\d+)?/(?:auth|oauth|signin|validate|coupon|payment|checkout)(?:/|$)")

_BOLA_RESOURCE_SQL_RE = (
    "/(user|users|account|accounts|profile|profiles|order|orders|invoice|invoices|"
    "document|documents|payment|payments|basket|baskets|cart|carts|address|addresses|"
    "addresss|vehicle|vehicles|service|services|report|reports|post|posts|comment|comments)"
)
_BOLA_COLLECTION_SQL_RE = (
    _BOLA_RESOURCE_SQL_RE
    + "(/(all|list|listing|recent|history|past|mine|my|owned|search|results))?/?$"
)
_BOLA_DETAIL_SQL_RE = _BOLA_RESOURCE_SQL_RE + "/([^/]*\\{[^/]+\\}|<[^/]+>|[0-9]+|[0-9a-fA-F-]{24,36})/?$"
_AUTH_FLOW_SQL_RE = (
    "/(auth|oauth|session|sessions|login|signin|signup|register|registration|"
    "password|reset-password|reset_password|change-password|change_password|token|tokens)(/|$)"
)

VALID_AUTH_STATES = frozenset({"anonymous", "user1", "user2"})
ATTEMPT_TERMINAL_STATUSES = (
    "completed",
    "partial",
    "timeout",
    "auth_missing",
    "auth_failed",
    "rate_limited",
    "error",
)
ATTEMPT_CLAIM_BLOCKING_STATUSES = ATTEMPT_TERMINAL_STATUSES + ("leased",)


API_ENDPOINT_FILTER_SQL = """(
    {alias}.path = '/api'
    OR {alias}.path LIKE '/api/%'
    OR {alias}.path = '/rest'
    OR {alias}.path LIKE '/rest/%'
    OR {alias}.path LIKE '/graphql%'
    OR {alias}.method <> 'GET'
    OR {alias}.param_location IN ('json', 'form')
    OR COALESCE({alias}.source, '') IN ('openapi', 'har')
)"""


def normalize_endpoint_filter(value: Any) -> str | None:
    raw = str(value or "").strip().lower()
    if raw in ("", "all", "none"):
        return None
    if raw in ("api", "apis", "api_endpoints", "api-only", "api_only"):
        return "api"
    raise ValueError(f"unsupported endpoint_filter '{raw}'; allowed values: api")


def _endpoint_filter_clause(alias: str, endpoint_filter: Any) -> str:
    normalized = normalize_endpoint_filter(endpoint_filter)
    if normalized == "api":
        return " AND " + API_ENDPOINT_FILTER_SQL.format(alias=alias)
    return ""


@dataclass(frozen=True)
class ParsedEndpoint:
    method: str
    path: str
    param_shape: str
    param_location: str
    replay_spec: str
    content_type: str | None = None


def normalize_auth_state(value: Any) -> str:
    state = str(value or "anonymous").strip().lower()
    return state if state in VALID_AUTH_STATES else "anonymous"


def normalize_check_family(value: Any) -> str:
    family = str(value or "all").strip().lower().replace("-", "_")
    return family if family and family not in {"*", "none", "null"} else "all"


def domain_rate_key(root_domain: str) -> str:
    normalized = str(root_domain or "").strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16]
    return f"asm:domain_rate:{digest}"


def reserved_domain_rate_count(redis_client: Any, root_domain: str) -> int:
    if not root_domain:
        return 0
    try:
        return max(0, int(redis_client.get(domain_rate_key(root_domain)) or 0))
    except Exception:
        return 0


def reserve_domain_rate(
    redis_client: Any,
    root_domain: str,
    cap: int,
    amount: int,
    *,
    ttl_seconds: int = ASM_RATE_RESERVATION_TTL_SECONDS,
    all_or_nothing: bool = False,
) -> int:
    """Reserve endpoint budget in Redis for a root domain.

    The caller should pass the remaining DB-adjusted hourly cap. This helper is
    intentionally Redis-only so the API dispatcher and workers share the same
    atomic reservation primitive.
    """
    try:
        cap = max(0, int(cap or 0))
        amount = max(0, int(amount or 0))
        ttl_seconds = max(60, int(ttl_seconds or ASM_RATE_RESERVATION_TTL_SECONDS))
    except (TypeError, ValueError):
        return 0
    if amount <= 0:
        return 0
    if not root_domain:
        return amount
    if cap <= 0:
        return 0
    try:
        granted = redis_client.eval(
            ASM_RATE_RESERVE_LUA,
            1,
            domain_rate_key(root_domain),
            amount,
            cap,
            ttl_seconds,
            "1" if all_or_nothing else "0",
        )
        return max(0, int(granted or 0))
    except Exception:
        return 0


def auth_state_from_options(options: dict[str, Any] | None) -> str:
    """Best-effort identity for the scan that discovered an endpoint worklist."""
    opts = options if isinstance(options, dict) else {}
    explicit = normalize_auth_state(opts.get("auth_state"))
    if opts.get("auth_state"):
        return explicit
    if opts.get("auth_header") or opts.get("auth_cookies") or opts.get("auth_headers_json") or opts.get("login_username"):
        return "user1"
    return "anonymous"


def normalize_path(path: str) -> str:
    """Template volatile id segments so near-duplicate paths dedupe."""
    if not path:
        return "/"
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if seg.isdigit():
            out.append("{id}")
        elif _UUID_RE.match(seg):
            out.append("{uuid}")
        elif len(seg) >= 24 and _HEX_RE.match(seg):
            out.append("{hash}")
        else:
            out.append(seg)
    return "/".join(out) or "/"


def _names_from_qs(qs: str) -> set[str]:
    names: set[str] = set()
    for pair in (qs or "").split("&"):
        if not pair:
            continue
        name = pair.split("=", 1)[0].strip()
        if name:
            names.add(name)
    return names


def _names_from_json(blob: str) -> set[str]:
    import json

    def flatten(obj: Any, prefix: str = "") -> set[str]:
        names: set[str] = set()
        if isinstance(obj, dict):
            for key, value in obj.items():
                full = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, dict):
                    names |= flatten(value, full)
                elif isinstance(value, list):
                    names.add(full)
                    if value and isinstance(value[0], dict):
                        names |= flatten(value[0], full)
                else:
                    names.add(full)
        elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
            names |= flatten(obj[0], prefix)
        return names

    try:
        obj = json.loads(blob)
        return flatten(obj)
    except (ValueError, TypeError):
        return set()


def _json_template_from_names(names: list[str]) -> dict[str, Any]:
    root: dict[str, Any] = {}
    for raw_name in names:
        parts = [p for p in str(raw_name or "").split(".") if p]
        if not parts:
            continue
        cursor = root
        for part in parts[:-1]:
            existing = cursor.get(part)
            if not isinstance(existing, dict):
                existing = {}
                cursor[part] = existing
            cursor = existing
        cursor[parts[-1]] = _json_seed_value_for_param(raw_name)
    return root


def _json_seed_value_for_param(param: str) -> Any:
    name = str(param or "").lower()
    leaf = name.rsplit(".", 1)[-1]
    if "email" in leaf:
        return "test@example.com"
    if "password" in leaf or "passwd" in leaf:
        return "TestPass123!"
    if leaf in ("username", "user", "login", "name", "uname") or "name" in leaf:
        return "testuser"
    if any(token in leaf for token in ("token", "apikey", "api_key")):
        return "test_token_abc123"
    if any(token in leaf for token in ("code", "coupon", "promo", "voucher", "discount")):
        return "TEST123"
    if any(token in leaf for token in ("id", "qty", "quantity", "count", "limit", "page", "offset", "amount", "price", "total", "rating")):
        return 1
    if leaf.startswith("is_") or leaf in ("enabled", "active", "verified", "confirmed"):
        return False
    if "url" in leaf or "link" in leaf or "redirect" in leaf:
        return "https://example.com"
    return "test"


def parse_worklist_entry_detail(entry: Any) -> ParsedEndpoint | None:
    """Parse a custom-endpoint string into a replay-preserving endpoint record.

    Accepts the shapes emitted by the scanner / harvester:
    ``"GET /a?x=1&y=2"``, ``"POST /a form:k=1"``, ``"POST /a json:{...}"``,
    ``"GET /a p1 p2"``, or just ``"/a"``. ``param_shape`` is a sorted,
    comma-joined set of parameter names (the injection surface). ``replay_spec``
    intentionally preserves form/json/query shape for future re-testing.
    """
    if not isinstance(entry, str):
        return None
    s = entry.strip()
    if not s:
        return None

    method = "GET"
    parts = s.split(" ", 1)
    if len(parts) == 2 and parts[0].isalpha() and parts[0].upper() in _HTTP_METHODS:
        method, s = parts[0].upper(), parts[1].strip()

    param_names: set[str] = set()
    param_location = "none"
    content_type: str | None = None
    path_part = s
    desc = ""
    if " " in s:
        path_part, desc = s.split(" ", 1)
        desc = desc.strip()
        desc_lower = desc.lower()
        if desc_lower.startswith("form:"):
            param_names |= _names_from_qs(desc[5:])
            param_location = "form"
            content_type = "application/x-www-form-urlencoded"
        elif desc_lower.startswith("json:"):
            param_names |= _names_from_json(desc[5:])
            param_location = "json"
            content_type = "application/json"
        elif desc_lower.startswith("query:") or desc_lower.startswith("params:"):
            raw = desc.split(":", 1)[1]
            param_names |= _names_from_qs(raw)
            param_location = "query"
        else:
            param_names |= {t for t in desc.split() if t}
            param_location = "json" if method in ("POST", "PUT", "PATCH") else "query"
            if method in ("POST", "PUT", "PATCH"):
                content_type = "application/json"

    if "?" in path_part:
        path, qs = path_part.split("?", 1)
        param_names |= _names_from_qs(qs)
        if param_location == "none":
            # The scanner treats POST query-style custom endpoints as JSON body
            # params, but GET/DELETE query strings remain query parameters.
            param_location = "json" if method in ("POST", "PUT", "PATCH") else "query"
            if method in ("POST", "PUT", "PATCH"):
                content_type = "application/json"
    else:
        path = path_part

    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    param_shape = ",".join(sorted(n for n in param_names if n))
    replay_path = path
    if "?" in path_part:
        replay_path = f"{path}?{qs}"
    if desc:
        replay_spec = f"{method} {replay_path} {desc}"
    elif "?" in path_part:
        replay_spec = f"{method} {replay_path}"
    else:
        replay_spec = _build_replay_spec(method, path, param_shape, param_location)
    return ParsedEndpoint(method, path, param_shape, param_location, replay_spec, content_type)


def parse_worklist_entry(entry: Any) -> tuple[str, str, str] | None:
    """Backward-compatible tuple view used by older planner tests/callers."""
    parsed = parse_worklist_entry_detail(entry)
    if not parsed:
        return None
    return parsed.method, parsed.path, parsed.param_shape


def endpoint_fingerprint(
    method: str,
    path: str,
    param_shape: str,
    *,
    param_location: str = "query",
    auth_state: str = "anonymous",
) -> str:
    """Stable identity: auth state + method + normalized path + param surface."""
    raw = (
        f"{normalize_auth_state(auth_state)} {method.upper()} "
        f"{normalize_path(path)} {param_location or 'none'}?{param_shape}"
    )
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def priority_score(method: str, path: str, param_shape: str) -> int:
    """Rank endpoints so partial coverage still hits the juiciest first."""
    score = 10
    p = (path or "").lower()
    segments = {seg for seg in re.split(r"[^a-z0-9]+", p) if seg}
    keyword_hits = sum(1 for k in _HIGH_VALUE if k in segments)
    if keyword_hits:
        score += min(45, keyword_hits * 10)
    if _AUTH_ROUTE_RE.search(p):
        score += 30
    if _SEARCH_ROUTE_RE.search(p):
        score += 25
    if _MUTATION_RESOURCE_RE.search(p):
        score += 15
    if param_shape:  # parameter-bearing = injection candidate
        score += 15
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 5
    # Version fan-out guesses are useful eventually, but they should not outrank
    # canonical routes extracted from the app bundle such as /rest/user/login.
    if _SPECULATIVE_VERSION_RE.search(p):
        score -= 10
    return score


def _claim_order_clause(family: str) -> str:
    """SQL ORDER BY expression for claim_test_batch.

    BOLA is read/proof driven: the useful first batch is a set of GET producers
    and detail candidates. Generic priority tends to over-rank auth and POST
    mutation guesses, which can burn focused BOLA batches before object replay
    sees owner-scoped list/detail routes.
    """
    normalized_family = normalize_check_family(family)
    if normalized_family == "auth":
        return "te.priority_score DESC, te.last_seen_at DESC"
    if normalized_family != "bola":
        return f"""
            CASE
                WHEN te.path ~* '{_AUTH_FLOW_SQL_RE}' THEN -300
                WHEN te.method = 'GET' AND te.path ~* '{_BOLA_DETAIL_SQL_RE}' THEN 260
                WHEN te.method = 'GET' AND te.path ~* '{_BOLA_COLLECTION_SQL_RE}' THEN 230
                WHEN te.method = 'GET' AND te.path ~* '{_BOLA_RESOURCE_SQL_RE}' THEN 180
                WHEN te.method IN ('POST', 'PUT', 'PATCH', 'DELETE') AND te.path ~* '{_BOLA_RESOURCE_SQL_RE}' THEN 120
                WHEN COALESCE(te.param_shape, '') <> '' THEN 40
                ELSE 0
            END DESC,
            te.priority_score DESC,
            te.last_seen_at DESC
        """
    return f"""
        CASE
            WHEN te.path ~* '{_AUTH_FLOW_SQL_RE}' THEN -300
            WHEN te.method = 'GET' AND te.path ~* '{_BOLA_DETAIL_SQL_RE}' THEN 500
            WHEN te.method = 'GET' AND te.path ~* '{_BOLA_COLLECTION_SQL_RE}' THEN 450
            WHEN te.method = 'GET' AND te.path ~* '{_BOLA_RESOURCE_SQL_RE}' THEN 300
            WHEN te.method IN ('POST', 'PUT', 'PATCH', 'DELETE') THEN -75
            ELSE 0
        END DESC,
        te.priority_score DESC,
        te.last_seen_at DESC
    """


def _build_replay_spec(
    method: str,
    path: str,
    param_shape: str,
    param_location: str = "query",
) -> str:
    base = f"{method.upper()} {path}"
    names = [n for n in (param_shape or "").split(",") if n]
    if not names:
        return base
    if param_location == "form":
        return base + " form:" + "&".join(f"{n}=1" for n in names)
    if param_location == "json":
        import json
        return base + " json:" + json.dumps(_json_template_from_names(names), separators=(",", ":"))
    return base + "?" + "&".join(f"{n}=1" for n in names)


def to_custom_endpoint(
    method: str,
    path: str,
    param_shape: str,
    *,
    param_location: str = "query",
    replay_spec: str | None = None,
) -> str:
    """Rebuild a scanner custom-endpoint string for re-testing an inventory row."""
    if replay_spec:
        return replay_spec
    return _build_replay_spec(method, path, param_shape, param_location)


def normalize_worklist(worklist: Any, *, limit: int = 20000) -> list[tuple[str, str, str]]:
    """Parse + dedupe a raw worklist into (method, path, param_shape) tuples,
    keeping the first concrete path seen per fingerprint."""
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for parsed in normalize_worklist_details(worklist, limit=limit):
        fp = endpoint_fingerprint(
            parsed.method,
            parsed.path,
            parsed.param_shape,
            param_location=parsed.param_location,
        )
        if fp in seen:
            continue
        seen.add(fp)
        out.append((parsed.method, parsed.path, parsed.param_shape))
        if len(out) >= limit:
            break
    return out


def normalize_worklist_details(
    worklist: Any,
    *,
    auth_state: str = "anonymous",
    limit: int = 20000,
) -> list[ParsedEndpoint]:
    """Parse + dedupe a raw worklist, preserving replay/auth identity."""
    state = normalize_auth_state(auth_state)
    seen: set[str] = set()
    out: list[ParsedEndpoint] = []
    for entry in (worklist or []):
        parsed = parse_worklist_entry_detail(entry)
        if not parsed:
            continue
        fp = endpoint_fingerprint(
            parsed.method,
            parsed.path,
            parsed.param_shape,
            param_location=parsed.param_location,
            auth_state=state,
        )
        if fp in seen:
            continue
        seen.add(fp)
        out.append(parsed)
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------------------
# Async DB helpers (asyncpg connection passed in)
# ---------------------------------------------------------------------------

# Soft-404 / unknown-route signature detection. Many apps never return a literal
# 404 for an unknown path: SPAs serve a 200 index shell (catch-all route), and
# API frameworks return 500/401/403/405 for unmatched routes under a prefix.
# A literal-404 filter is useless against those (observed: 0 of 1137 Juice Shop
# phantoms dropped vs 912 of 1095 honey phantoms). We learn each path-prefix's
# "not found" response signature (status + body size) by probing decoys, then
# drop candidates that match it. Bias is conservative: any inconclusive probe
# keeps the endpoint.
try:
    _SOFT404_SIZE_TOL_BYTES = max(0, int(os.environ.get("ASM_SOFT404_SIZE_TOL_BYTES") or 256))
except (TypeError, ValueError):
    _SOFT404_SIZE_TOL_BYTES = 256
_SOFT404_SIZE_TOL_FRAC = 0.08
_SOFT404_MAX_PREFIXES = 16
# Two decoys per prefix capture both the direct-unknown and nested-unknown
# signatures (some servers differ by depth). Tokens are fixed + implausible so
# the behaviour is deterministic (important for tests/replay).
_SOFT404_DECOY_TOKENS = ("zz9-shakerscan-probe-404a7", "zz9-shakerscan-probe-404a7/qx8w2")


def _soft404_enabled() -> bool:
    return str(os.environ.get("ASM_SOFT404_DETECT", "1")).strip().lower() not in {"0", "false", "no", "off"}


def _path_prefix(path: str) -> str:
    """The namespace a soft-404 signature is keyed on: the first path segment for
    nested paths, or ``/`` for root-level paths so they share one decoy probe.
    ``/api/v3/users`` -> ``/api`` ; ``/login`` or ``/`` -> ``/``."""
    p = (path or "").split("?", 1)[0].strip("/")
    if "/" not in p:
        return "/"
    return "/" + p.split("/", 1)[0]


def _soft404_matches(probe: tuple[str, int], signature: tuple[str, int]) -> bool:
    """True if a probe response matches a learned not-found signature: same HTTP
    status AND body size within tolerance. Status must match first so a real
    endpoint that merely shares a size with the decoy is never dropped."""
    if probe[0] != signature[0] or probe[0] in ("ERR", ""):
        return False
    if probe[1] < 0 or signature[1] < 0:
        return True  # status matched and size is unknown -> treat as match
    tol = max(_SOFT404_SIZE_TOL_BYTES, int(signature[1] * _SOFT404_SIZE_TOL_FRAC))
    return abs(probe[1] - signature[1]) <= tol


def _probe_auth_curl_config(options: dict[str, Any] | None) -> str:
    """Build a curl ``--config`` (``-K``) body carrying auth for reachability probes.

    The config is fed to curl via ``-K -`` on stdin (see ``_probe_path_status``), never on
    argv, so bearer tokens / session cookies / API keys are not exposed in ``ps`` or
    ``/proc/<pid>/cmdline`` while the probe runs. Probes still use the same credentials the
    scan would (otherwise auth-gated endpoints look like 404s).
    """
    o = options or {}
    lines: list[str] = []

    def _cfg(opt: str, value: str) -> str:
        # curl config values are double-quoted; escape backslash then quote.
        escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
        return f'{opt} = "{escaped}"'

    h = o.get("auth_header")
    if h:
        hs = str(h)
        lines.append(_cfg("header", hs if hs.lower().startswith("authorization") else f"Authorization: {hs}"))
    c = o.get("auth_cookies")
    if c:
        lines.append(_cfg("cookie", str(c)))
    hj = o.get("auth_headers_json")
    if hj:
        try:
            import json as _json
            d = _json.loads(hj) if isinstance(hj, str) else hj
            for k, v in (d or {}).items():
                lines.append(_cfg("header", f"{k}: {v}"))
        except Exception:
            pass
    return "\n".join(lines)


async def _probe_path_status(base_url: str, path: str, auth_config: str, timeout: int) -> tuple[str, int]:
    """Safe GET probe returning ``(http_code, body_size)``. Uses GET only (never a
    write method) so it cannot mutate the target. Returns ``("ERR", -1)`` on any
    transient error/timeout so callers keep the endpoint when the probe is
    inconclusive — reachability filtering must never drop a real endpoint on a
    flaky probe."""
    # Universal guard: a scheme-less base ("example.com") yields an invalid curl URL
    # ("example.com/path") that always errors -> inconclusive -> phantom endpoints
    # kept. Covers every prober (filter, sweep, decoy learning) in one place.
    if "://" not in base_url:
        base_url = "https://" + base_url.lstrip("/")
    url = base_url.rstrip("/") + (path if path.startswith("/") else "/" + path)
    cmd = [
        "curl", "-sS", "-k", "-o", "/dev/null", "-w", "%{http_code} %{size_download}",
        "--max-time", str(max(2, timeout - 1)),
        "-X", "GET", "-H", "User-Agent: Mozilla/5.0 (ShakerScan ASM reachability)",
    ]
    stdin_bytes: bytes | None = None
    if auth_config:
        # Auth secrets go to curl via a `-K -` config on stdin, never on argv, so they
        # are not visible in `ps` / /proc/<pid>/cmdline for the life of the probe.
        cmd += ["-K", "-"]
        stdin_bytes = auth_config.encode("utf-8")
    cmd += [url]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_bytes is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(input=stdin_bytes), timeout=timeout + 2)
        parts = (out or b"").decode("ascii", "replace").strip().split()
        if not parts:
            return ("ERR", -1)
        code = parts[0][-3:]
        # curl reports "000" when it never got an HTTP response (connection
        # refused / DNS / timeout). Treat that as INCONCLUSIVE, not a real status:
        # otherwise a transiently-down host makes decoys and candidates both "000",
        # they'd match, and the whole inventory could be retired on one outage.
        if code == "000":
            return ("ERR", -1)
        size = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
        return (code, size)
    except Exception:
        if proc is not None:
            try:
                proc.kill()
            except Exception:
                pass
        return ("ERR", -1)


async def _probe_path_exists(base_url: str, path: str, auth_config: str, timeout: int) -> bool:
    """True if `path` exists (any status other than a literal 404). Back-compat
    wrapper over :func:`_probe_path_status`; inconclusive probes keep the path."""
    code, _size = await _probe_path_status(base_url, path, auth_config, timeout)
    return code != "404"


async def _learn_not_found_signatures(
    base_url: str, prefixes: list[str], auth_config: str, timeout: int, sem: "asyncio.Semaphore"
) -> dict[str, list[tuple[str, int]]]:
    """Probe implausible decoy paths under each prefix to learn its soft-404
    signature(s) — the (status, body-size) the server returns for unknown routes."""
    not_found: dict[str, list[tuple[str, int]]] = {}

    async def _learn(prefix: str) -> None:
        sigs: list[tuple[str, int]] = []
        for token in _SOFT404_DECOY_TOKENS:
            async with sem:
                sig = await _probe_path_status(base_url, prefix.rstrip("/") + "/" + token, auth_config, timeout)
            if sig[0] not in ("ERR", ""):
                sigs.append(sig)
        not_found[prefix] = sigs

    await asyncio.gather(*(_learn(p) for p in prefixes))
    return not_found


def _reachability_verdict(probe: tuple[str, int], not_found_for_prefix: list[tuple[str, int]]) -> str:
    """Classify a GET probe into a method-aware verdict:

    - ``hard_404``    — a literal 404 to a safe GET probe. This proves the GET
      entry is not reachable, but does not prove a method-specific POST/PUT/PATCH
      route is absent; many routers return 404 for unsupported methods.
    - ``soft_404``    — matches the app's learned not-found signature (500/SPA-200/etc).
      This is GET-SPECIFIC evidence: a real POST/PUT/PATCH/DELETE endpoint may return
      the app's generic page to a GET. Only the GET entry should be dropped/retired;
      non-GET methods are kept.
    - ``reachable``   — a distinct, non-not-found response. Keep all methods.
    - ``inconclusive``— probe error (incl. connection-fail "000"). Leave everything as-is.
    """
    if probe[0] in ("ERR", ""):
        return "inconclusive"
    if probe[0] == "404":
        return "hard_404"
    if any(_soft404_matches(probe, sig) for sig in not_found_for_prefix):
        return "soft_404"
    return "reachable"


def _is_unreachable(probe: tuple[str, int], not_found_for_prefix: list[tuple[str, int]]) -> bool | None:
    """Back-compat scalar view of :func:`_reachability_verdict`: True = phantom
    (hard or soft 404), False = reachable, None = inconclusive."""
    verdict = _reachability_verdict(probe, not_found_for_prefix)
    if verdict == "inconclusive":
        return None
    return verdict in ("hard_404", "soft_404")


def _entry_is_get(entry: str) -> bool:
    """True if a worklist entry is a GET (the only method we can safely probe).
    Unparseable entries default to GET so soft-404 filtering still applies."""
    parsed = parse_worklist_entry(entry)
    method = (parsed[0] if parsed else "GET") or "GET"
    return method.upper() == "GET"


async def filter_reachable_worklist(
    base_url: str,
    worklist: Any,
    options: dict[str, Any] | None = None,
    *,
    max_probe: int = 2000,
    concurrency: int = 24,
    timeout: int = 5,
) -> list[str]:
    """Drop phantom endpoints (declared by OpenAPI/OPTIONS/synthetic generation
    but not actually served) so they don't pollute the inventory, inflate
    coverage denominators, or spam the new-surface feed.

    Probes each unique path once with a safe GET and drops it when the response
    is a literal 404 OR matches its prefix's learned *soft-404* signature (status
    + body size) — handling apps that answer unknown routes with 500/401/200-SPA
    instead of 404. Non-matching statuses (incl. real 401/403/405) are kept.

    Set ``ASM_VALIDATE_REACHABILITY=0`` to disable entirely, or
    ``ASM_SOFT404_DETECT=0`` to keep only the literal-404 behaviour. Skipped
    (keep all) above ``max_probe`` unique paths to bound cost."""
    entries = [e for e in (worklist or []) if isinstance(e, str) and e.strip()]
    if not entries or not base_url:
        return entries
    # Defensive: a scheme-less base (caller passed a raw "example.com") makes every
    # probe build an invalid curl URL -> all-inconclusive -> phantom endpoints kept,
    # inflating coverage/shard work. Normalize so the filter actually does its job.
    if "://" not in str(base_url):
        base_url = f"https://{str(base_url).lstrip('/')}"
    if str(os.environ.get("ASM_VALIDATE_REACHABILITY", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return entries

    by_path: dict[str, list[str]] = {}
    for e in entries:
        parsed = parse_worklist_entry(e)
        key = parsed[1] if parsed else "__unparsed__"
        by_path.setdefault(key, []).append(e)

    probe_paths = [p for p in by_path if p != "__unparsed__"]
    if len(probe_paths) > max_probe:
        return entries  # too many to probe within budget; don't block, keep all

    auth_config = _probe_auth_curl_config(options)
    sem = asyncio.Semaphore(max(1, concurrency))
    status: dict[str, tuple[str, int]] = {}

    async def _probe(path: str) -> None:
        async with sem:
            status[path] = await _probe_path_status(base_url, path, auth_config, timeout)

    # Learn the not-found signature for each path prefix by probing decoys.
    soft404 = _soft404_enabled()
    prefixes = sorted({_path_prefix(p) for p in probe_paths})[:_SOFT404_MAX_PREFIXES] if soft404 else []
    not_found, _ = await asyncio.gather(
        _learn_not_found_signatures(base_url, prefixes, auth_config, timeout, sem),
        asyncio.gather(*(_probe(p) for p in probe_paths)),
    )

    kept: list[str] = []
    for path, group in by_path.items():
        if path == "__unparsed__":
            kept.extend(group)
            continue
        # SPA client routes (#/search, #!/path) are resolved in the browser — the
        # server returns the same app shell for every fragment, so they match their
        # prefix's soft-404 signature and would be wrongly dropped. They are reachable
        # by definition (the route lives client-side); keep them so the XSS lane can
        # browser-prove DOM XSS on them.
        if "#/" in path or "#!" in path:
            kept.extend(group)
            continue
        verdict = _reachability_verdict(status.get(path, ("ERR", -1)), not_found.get(_path_prefix(path), []))
        if verdict == "hard_404":
            # GET-specific evidence: a method-specific API route may return 404
            # when probed with GET. Drop only GET worklist entries.
            kept.extend(e for e in group if not _entry_is_get(e))
            continue
        if verdict == "soft_404":
            # GET-specific evidence: drop only GET entries, keep POST/PUT/etc so a
            # real non-GET endpoint isn't removed because GET hit the app's error page.
            kept.extend(e for e in group if not _entry_is_get(e))
            continue
        kept.extend(group)  # reachable or inconclusive -> keep all
    return kept


async def sweep_endpoint_reachability(
    conn,
    base_url: str,
    target_id: str,
    options: dict[str, Any] | None = None,
    *,
    max_probe: int = 4000,
    concurrency: int = 24,
    timeout: int = 5,
    retire_threshold: int | None = None,
) -> dict[str, Any]:
    """Re-probe EXISTING (non-``gone``) inventory rows, persist the reachability
    result (``last_http_status``/``unreachable_streak``/``last_reachability_at``),
    and retire endpoints to ``test_status='gone'`` once their unreachable streak
    reaches the threshold — so phantom rows (incl. soft-404s the worklist filter
    can't retroactively clean) stop consuming test budget and stop inflating
    coverage. Retirement is reversible: re-discovery resets ``gone`` -> ``untested``
    (see :func:`upsert_endpoints`), so an endpoint that returns later comes back.

    Probes the least-recently-checked paths first, so a bounded sweep run on every
    recon cycles through the whole inventory over time. ``ASM_REACHABILITY_SWEEP=0``
    disables; ``ASM_GONE_STREAK_THRESHOLD`` (default 2) sets confirmations to retire."""
    empty = {"probed": 0, "reachable": 0, "unreachable": 0, "retired": 0}
    if not base_url or str(os.environ.get("ASM_REACHABILITY_SWEEP", "1")).strip().lower() in {"0", "false", "no", "off"}:
        return {**empty, "disabled": True}
    if retire_threshold is None:
        try:
            retire_threshold = max(1, int(os.environ.get("ASM_GONE_STREAK_THRESHOLD") or 2))
        except (TypeError, ValueError):
            retire_threshold = 2

    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    # Distinct paths, least-recently-swept first, so a bounded run rotates coverage.
    order = await conn.fetch(
        """
        SELECT path FROM target_endpoints
        WHERE target_id = $1 AND test_status <> 'gone'
        GROUP BY path
        ORDER BY MIN(COALESCE(last_reachability_at, '-infinity'::timestamptz)) ASC, path
        LIMIT $2
        """,
        tid, int(max_probe),
    )
    paths = [r["path"] for r in order if r["path"]]
    if not paths:
        return empty

    auth_config = _probe_auth_curl_config(options)
    sem = asyncio.Semaphore(max(1, concurrency))
    status: dict[str, tuple[str, int]] = {}

    async def _probe(path: str) -> None:
        async with sem:
            status[path] = await _probe_path_status(base_url, path, auth_config, timeout)

    soft404 = _soft404_enabled()
    prefixes = sorted({_path_prefix(p) for p in paths})[:_SOFT404_MAX_PREFIXES] if soft404 else []
    not_found, _ = await asyncio.gather(
        _learn_not_found_signatures(base_url, prefixes, auth_config, timeout, sem),
        asyncio.gather(*(_probe(p) for p in paths)),
    )

    # A GET probe is method-aware (see _reachability_verdict). Both literal and
    # soft 404 evidence are GET-specific: many routers return 404 when a real
    # POST/PUT/PATCH route is called with GET. Only GET rows are affected.
    reachable: list[tuple[str, int | None]] = []   # path alive -> reset streak, all methods
    hard: list[tuple[str, int | None]] = []        # literal GET 404 -> bump/retire GET rows
    soft: list[tuple[str, int | None]] = []        # GET-only not-found -> bump/retire GET rows
    for path in paths:
        st = status.get(path, ("ERR", -1))
        verdict = _reachability_verdict(st, not_found.get(_path_prefix(path), []))
        if verdict == "inconclusive":
            continue  # leave rows untouched
        code = int(st[0]) if st[0].isdigit() else None
        if verdict == "reachable":
            reachable.append((path, code))
        elif verdict == "hard_404":
            hard.append((path, code))
        else:
            soft.append((path, code))

    async def _bump(paths_codes: list[tuple[str, int | None]], get_only: bool) -> None:
        if not paths_codes:
            return
        method_clause = "AND te.method = 'GET'" if get_only else ""
        await conn.execute(
            f"""
            UPDATE target_endpoints te
            SET unreachable_streak = te.unreachable_streak + 1, last_http_status = v.code,
                last_reachability_at = NOW(), updated_at = NOW()
            FROM unnest($2::text[], $3::int[]) AS v(path, code)
            WHERE te.target_id = $1 AND te.path = v.path AND te.test_status <> 'gone' {method_clause}
            """,
            tid, [p for p, _ in paths_codes], [c for _, c in paths_codes],
        )

    async def _retire(u_paths: list[str], get_only: bool) -> int:
        if not u_paths:
            return 0
        method_clause = "AND method = 'GET'" if get_only else ""
        return int(await conn.fetchval(
            f"""
            WITH retired AS (
                UPDATE target_endpoints
                SET test_status = 'gone', last_attempt_status = 'unreachable', updated_at = NOW()
                WHERE target_id = $1 AND path = ANY($2::text[])
                  AND test_status NOT IN ('gone', 'in_progress')
                  AND unreachable_streak >= $3 {method_clause}
                RETURNING 1
            )
            SELECT count(*) FROM retired
            """,
            tid, u_paths, retire_threshold,
        ) or 0)

    if reachable:
        await conn.execute(
            """
            UPDATE target_endpoints te
            SET unreachable_streak = 0, last_http_status = v.code,
                last_reachability_at = NOW(), updated_at = NOW()
            FROM unnest($2::text[], $3::int[]) AS v(path, code)
            WHERE te.target_id = $1 AND te.path = v.path AND te.test_status <> 'gone'
            """,
            tid, [p for p, _ in reachable], [c for _, c in reachable],
        )
    await _bump(hard, get_only=True)
    await _bump(soft, get_only=True)
    retired = await _retire([p for p, _ in hard], get_only=True) + \
        await _retire([p for p, _ in soft], get_only=True)

    purged = await gc_endpoint_inventory(conn, target_id)

    return {
        "probed": len(paths),
        "reachable": len(reachable),
        "unreachable": len(hard) + len(soft),
        "hard_404": len(hard),
        "soft_404": len(soft),
        "retired": int(retired),
        "purged": int(purged),
        "threshold": retire_threshold,
    }


# §7.5: physically purge endpoints that have been retired ('gone') longer than the
# retention window. 'gone' rows are already excluded from coverage denominators, but
# purging stale ones keeps the inventory lean and prevents unbounded growth. Reversible:
# a path that returns later is simply re-inserted as 'untested' by upsert_endpoints.
# Duplicate rows can't exist (UNIQUE(target_id, fingerprint) + ON CONFLICT upsert).
ASM_GONE_RETENTION_DAYS = int(os.environ.get("ASM_GONE_RETENTION_DAYS", "30"))


async def gc_endpoint_inventory(
    conn, target_id: str, *, gone_retention_days: int | None = None
) -> int:
    """Delete long-retired ('gone') endpoint rows. Returns the number purged."""
    if gone_retention_days is None:
        gone_retention_days = ASM_GONE_RETENTION_DAYS
    if gone_retention_days <= 0:
        return 0
    import uuid as _uuid
    try:
        tid = _uuid.UUID(str(target_id))
    except (ValueError, TypeError):
        return 0
    try:
        deleted = await conn.fetchval(
            """
            WITH del AS (
                DELETE FROM target_endpoints
                WHERE target_id = $1
                  AND test_status = 'gone'
                  AND updated_at < NOW() - make_interval(days => $2)
                RETURNING 1
            )
            SELECT count(*) FROM del
            """,
            tid, int(gone_retention_days),
        )
        return int(deleted or 0)
    except Exception:
        return 0


async def upsert_endpoints(
    conn,
    target_id: str,
    worklist: Any,
    *,
    source: str = "recon",
    auth_state: str = "anonymous",
    campaign_id: str | None = None,
    scan_id: str | None = None,
    limit: int = 20000,
) -> int:
    """Upsert a discovered worklist into target_endpoints. New rows start
    ``untested``; existing rows refresh ``last_seen_at``/source/priority. Returns
    the number of endpoints processed."""
    import uuid as _uuid
    auth_state = normalize_auth_state(auth_state)
    rows = normalize_worklist_details(worklist, auth_state=auth_state, limit=limit)
    if not rows:
        return 0
    tid = _uuid.UUID(str(target_id))
    cid = _uuid.UUID(str(campaign_id)) if campaign_id else None
    sid = _uuid.UUID(str(scan_id)) if scan_id else None
    count = 0
    for parsed in rows:
        fp = endpoint_fingerprint(
            parsed.method,
            parsed.path,
            parsed.param_shape,
            param_location=parsed.param_location,
            auth_state=auth_state,
        )
        prio = priority_score(parsed.method, parsed.path, parsed.param_shape)
        await conn.execute(
            """
            INSERT INTO target_endpoints
                (target_id, method, path, param_shape, fingerprint, source,
                 auth_state, param_location, replay_spec, content_type, priority_score,
                 campaign_id, last_seen_scan_id, first_seen_at, last_seen_at, test_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, NOW(), NOW(), 'untested')
            ON CONFLICT (target_id, fingerprint) DO UPDATE SET
                last_seen_at = NOW(),
                last_seen_scan_id = COALESCE(EXCLUDED.last_seen_scan_id, target_endpoints.last_seen_scan_id),
                source = EXCLUDED.source,
                auth_state = EXCLUDED.auth_state,
                param_location = EXCLUDED.param_location,
                replay_spec = EXCLUDED.replay_spec,
                content_type = EXCLUDED.content_type,
                priority_score = EXCLUDED.priority_score,
                campaign_id = COALESCE(EXCLUDED.campaign_id, target_endpoints.campaign_id),
                test_status = CASE
                    WHEN target_endpoints.test_status = 'gone' THEN 'untested'
                    ELSE target_endpoints.test_status END,
                updated_at = NOW()
            """,
            tid, parsed.method, parsed.path, parsed.param_shape, fp, source, auth_state,
            parsed.param_location, parsed.replay_spec, parsed.content_type, prio, cid, sid,
        )
        count += 1
    return count


def _attempt_telemetry_true(telemetry: Any, key: str) -> bool:
    if isinstance(telemetry, str):
        try:
            import json
            telemetry = json.loads(telemetry)
        except Exception:
            telemetry = {}
    if not isinstance(telemetry, dict):
        return False
    value = telemetry.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() == "true"


def _attempt_telemetry_schema_declared(telemetry: Any) -> bool:
    if isinstance(telemetry, str):
        try:
            import json
            telemetry = json.loads(telemetry)
        except Exception:
            return False
    if not isinstance(telemetry, dict):
        return False
    endpoint_attempt = telemetry.get("endpoint_attempt")
    return bool(
        isinstance(endpoint_attempt, dict)
        and endpoint_attempt.get("schema_version") == ENDPOINT_ATTEMPT_SCHEMA_V1
    )


def normalize_attempt_status_for_coverage(status: Any, telemetry: Any = None) -> str:
    """Normalize attempt status before coverage accounting.

    A batch-level "completed" status is not endpoint proof. Completed rows count
    as tested only when scanner endpoint telemetry explicitly says the endpoint
    was exercised.
    """
    normalized = str(status or "").strip().lower()
    if normalized == "completed" and (
        not _attempt_telemetry_true(telemetry, "per_endpoint_telemetry")
        or not _attempt_telemetry_schema_declared(telemetry)
    ):
        return "partial"
    return normalized


def attempt_coverage_from_rows(
    rows: list[Any],
    *,
    total: int,
    basis: str,
    coverage_denominator: str | None = None,
) -> dict[str, Any]:
    attempted = 0
    completed = 0
    partial = 0
    auth_blocked = 0
    rate_limited = 0
    error = 0
    attempted_params = 0
    completed_params = 0

    def _get(row: Any, key: str, default: Any = None) -> Any:
        try:
            return row[key]
        except Exception:
            return default

    for row in rows or []:
        status = normalize_attempt_status_for_coverage(
            _get(row, "status"),
            _get(row, "scanner_telemetry_json"),
        )
        attempted += 1
        if status == "completed":
            completed += 1
        elif status in {"partial", "timeout"}:
            partial += 1
        elif status in {"auth_missing", "auth_failed"}:
            auth_blocked += 1
        elif status == "rate_limited":
            rate_limited += 1
        elif status == "error":
            error += 1
        try:
            attempted_params += int(_get(row, "attempted_params_count", 0) or 0)
        except Exception:
            pass
        try:
            completed_params += int(_get(row, "completed_params_count", 0) or 0)
        except Exception:
            pass

    total = max(0, int(total or 0), attempted)
    summary = {
        "total": total,
        # Single labeled denominator: coverage == tested / denominator, always
        # (docs proposed-next-steps §11 — tested/denominator must reproduce the
        # displayed coverage). The caller passes `total` already net of retired
        # ('gone') rows, so this denominator is the testable surface.
        "denominator": total,
        "denominator_label": coverage_denominator or "testable",
        "attempted": attempted,
        "completed": completed,
        "tested": completed,
        "untested": max(0, total - attempted),
        "partial": partial,
        "auth_blocked": auth_blocked,
        "rate_limited": rate_limited,
        "error": error,
        "coverage": round(completed / total, 3) if total else 0.0,
        "basis": basis,
    }
    if attempted_params or completed_params:
        summary["attempted_params"] = attempted_params
        summary["completed_params"] = completed_params
    if coverage_denominator:
        summary["coverage_denominator"] = coverage_denominator
    return summary


async def coverage_summary(conn, target_id: str) -> dict[str, Any]:
    """Per-target coverage counts for the ASM surface.

    Top-level tested/coverage prefer the normalized attempt ledger when it has
    facts for this target. The physical endpoint status rollup is still returned
    separately because the allocator uses it for stale/claimable work.
    """
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    row = await conn.fetchrow(
        """
        SELECT
            count(*) AS total,
            count(*) FILTER (WHERE test_status = 'tested') AS tested,
            count(*) FILTER (WHERE test_status = 'untested') AS untested,
            count(*) FILTER (WHERE test_status = 'in_progress') AS in_progress,
            count(*) FILTER (WHERE test_status = 'stale') AS stale,
            count(*) FILTER (WHERE test_status = 'gone') AS gone,
            count(*) FILTER (WHERE test_status = 'in_progress' AND lease_expires_at < NOW()) AS expired_leases,
            count(*) FILTER (WHERE last_attempt_status IN ('auth_missing', 'auth_failed')) AS auth_blocked,
            count(*) FILTER (WHERE last_attempt_status IN ('partial', 'partial_timeout', 'partial_findings', 'lease_expired')) AS partial
        FROM target_endpoints WHERE target_id = $1
        """,
        tid,
    )
    attempt_rows = await conn.fetch(
        """
        WITH latest_attempt AS (
            SELECT DISTINCT ON (te.id)
                te.id AS endpoint_id,
                aea.status,
                aea.scanner_telemetry_json
            FROM target_endpoints te
            JOIN asm_endpoint_attempts aea ON aea.endpoint_id = te.id
            WHERE te.target_id = $1 AND te.test_status <> 'gone'
            ORDER BY te.id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
        )
        SELECT status, scanner_telemetry_json
        FROM latest_attempt
        """,
        tid,
    )
    total = int(row["total"] or 0)
    status_tested = int(row["tested"] or 0)
    testable = total - int(row["gone"] or 0)
    status_summary = {
        "total": total,
        "tested": status_tested,
        "untested": int(row["untested"] or 0),
        "in_progress": int(row["in_progress"] or 0),
        "stale": int(row["stale"] or 0),
        "gone": int(row["gone"] or 0),
        "expired_leases": int(row["expired_leases"] or 0),
        "auth_blocked": int(row["auth_blocked"] or 0),
        "partial": int(row["partial"] or 0),
        "coverage": round(status_tested / testable, 3) if testable else 0.0,
        "basis": "endpoint_status",
    }

    attempt_summary = attempt_coverage_from_rows(
        list(attempt_rows or []),
        total=testable,
        basis="latest_attempt_per_endpoint",
    )
    attempted = int(attempt_summary["attempted"])
    attempt_completed = int(attempt_summary["completed"])
    attempt_partial = int(attempt_summary["partial"])
    attempt_auth_blocked = int(attempt_summary["auth_blocked"])
    attempt_rate_limited = int(attempt_summary["rate_limited"])
    attempt_error = int(attempt_summary["error"])
    attempt_untested = int(attempt_summary["untested"])
    use_attempts = attempted > 0
    tested = attempt_completed if use_attempts else status_summary["tested"]
    coverage = attempt_summary["coverage"] if use_attempts else status_summary["coverage"]
    # Headline coverage uses ONE labeled denominator: testable = total − gone
    # (docs proposed-next-steps §11). `total` (raw, incl. retired/phantom rows) is
    # kept for context but is NOT the coverage denominator, so the UI must divide
    # `tested` by `denominator`, never by `total`. coverage_reconciles is a
    # self-check so a desync is visible, not silently misleading.
    coverage_reconciles = (testable == 0 and tested == 0) or (
        testable > 0 and abs(coverage - round(tested / testable, 3)) <= 0.001
    )
    return {
        "total": total,
        "testable": testable,
        "denominator": testable,
        "denominator_label": "testable = total − gone",
        "tested": tested,
        "untested": attempt_untested if use_attempts else status_summary["untested"],
        "in_progress": status_summary["in_progress"],
        "stale": status_summary["stale"],
        "gone": status_summary["gone"],
        "expired_leases": status_summary["expired_leases"],
        "auth_blocked": attempt_auth_blocked if use_attempts else status_summary["auth_blocked"],
        "partial": attempt_partial if use_attempts else status_summary["partial"],
        "rate_limited": attempt_rate_limited,
        "error": attempt_error,
        "attempted": attempted,
        "coverage": coverage,
        "coverage_basis": "attempt_ledger" if use_attempts else "endpoint_status",
        "coverage_reconciles": coverage_reconciles,
        # Detail breakdowns (kept behind clearly-labeled keys so the headline shows
        # one number; the alternate-basis untested counts live here, not top-level).
        "detail": {
            "status_coverage": status_summary,
            "attempt_coverage": attempt_summary,
        },
        # Back-compat aliases (existing consumers); prefer `detail.*`.
        "status_coverage": status_summary,
        "attempt_coverage": attempt_summary,
    }


async def campaign_attempt_summary(
    conn,
    campaign_id: str,
    *,
    expected_total: int | None = None,
    check_families: list[str] | tuple[str, ...] | None = None,
    family_aware: bool = False,
) -> dict[str, Any]:
    """Coverage counts for one scan campaign from normalized attempt facts.

    Full Coverage parent reports use this after merge-time attempt rows are
    written. ``expected_total`` is the planner's assigned auth-scoped endpoint
    count, which preserves unattempted slots in the denominator if a worker
    never produced a ledger row.
    """
    import uuid as _uuid

    cid = _uuid.UUID(str(campaign_id))
    families = [normalize_check_family(f) for f in (check_families or [])]
    family_filter = families or None
    distinct_on = "aea.endpoint_id, COALESCE(aea.check_family, 'all')" if family_aware else "aea.endpoint_id"
    order_by = (
        "aea.endpoint_id, COALESCE(aea.check_family, 'all'), "
        "COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC"
        if family_aware
        else "aea.endpoint_id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC"
    )
    rows = await conn.fetch(
        f"""
        WITH latest_attempt AS (
            SELECT DISTINCT ON ({distinct_on})
                aea.endpoint_id,
                COALESCE(aea.check_family, 'all') AS check_family,
                aea.status,
                aea.scanner_telemetry_json,
                aea.attempted_params_count,
                aea.completed_params_count
            FROM asm_endpoint_attempts aea
            JOIN target_endpoints te ON te.id = aea.endpoint_id
            WHERE aea.campaign_id = $1
              AND te.test_status <> 'gone'
              AND ($2::text[] IS NULL OR COALESCE(aea.check_family, 'all') = ANY($2::text[]))
            ORDER BY {order_by}
        )
        SELECT status, scanner_telemetry_json, attempted_params_count, completed_params_count
        FROM latest_attempt
        """,
        cid,
        family_filter,
    )
    return attempt_coverage_from_rows(
        list(rows or []),
        total=int(expected_total or 0),
        basis="campaign_family_attempt_ledger" if family_aware else "campaign_attempt_ledger",
        coverage_denominator=(
            "assigned_endpoint_family_attempts"
            if family_aware and expected_total is not None
            else ("assigned_auth_scoped_endpoints" if expected_total is not None else "attempted_endpoints")
        ),
    )


async def create_campaign(
    conn,
    target_id: str,
    *,
    mode: str,
    requested_by: str = "api",
    parent_scan_id: str | None = None,
    priority: int = 100,
    budget_profile: str | None = None,
    wide_budget: dict[str, Any] | None = None,
    deep_budget: dict[str, Any] | None = None,
    check_families: list[str] | None = None,
    auth_states: list[str] | None = None,
    allowed_windows: dict[str, Any] | None = None,
    daily_cap: int | None = None,
    rate_caps: dict[str, Any] | None = None,
    status: str = "active",
    metadata_json: dict[str, Any] | None = None,
) -> str:
    """Create a durable budget/campaign record for ASM or future coverage work."""
    import json
    import uuid as _uuid

    tid = _uuid.UUID(str(target_id))
    parent_id = _uuid.UUID(str(parent_scan_id)) if parent_scan_id else None
    root_domain = await conn.fetchval("SELECT root_domain FROM targets WHERE id = $1", tid)
    campaign_id = await conn.fetchval(
        """
        INSERT INTO scan_campaigns (
            target_id, root_domain, requested_by, mode, priority, budget_profile,
            wide_budget, deep_budget, check_families, auth_states, allowed_windows,
            daily_cap, rate_caps, parent_scan_id, status, metadata_json
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, $11::jsonb,
            $12, $13::jsonb, $14, $15, $16::jsonb
        )
        RETURNING id
        """,
        tid,
        root_domain,
        requested_by or "api",
        mode,
        int(priority),
        budget_profile,
        json.dumps(wide_budget or {}),
        json.dumps(deep_budget or {}),
        json.dumps(check_families or []),
        json.dumps(auth_states or []),
        json.dumps(allowed_windows or {}),
        daily_cap,
        json.dumps(rate_caps or {}),
        parent_id,
        status,
        json.dumps(metadata_json or {}),
    )
    return str(campaign_id)


async def finish_campaign(conn, campaign_id: str | None, *, status: str = "completed") -> int:
    """Mark a campaign terminal. Missing campaign_id is a no-op for compatibility."""
    if not campaign_id:
        return 0
    import uuid as _uuid

    result = await conn.execute(
        """
        UPDATE scan_campaigns
        SET status = $2, completed_at = COALESCE(completed_at, NOW()), updated_at = NOW()
        WHERE id = $1
        """,
        _uuid.UUID(str(campaign_id)),
        status,
    )
    try:
        return int(result.split()[-1])
    except (ValueError, IndexError):
        return 0


async def reap_expired_leases(conn, target_id: str | None = None) -> int:
    """Release expired endpoint leases without marking them clean.

    Expired leased rows become ``stale`` so they are claimable again, while the
    last attempt status explains why coverage is still incomplete.
    """
    import uuid as _uuid

    if target_id:
        result = await conn.execute(
            """
            UPDATE target_endpoints
            SET test_status = 'stale',
                last_attempt_status = 'lease_expired',
                last_verdict = 'lease_expired',
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = NOW()
            WHERE target_id = $1
              AND test_status = 'in_progress'
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at < NOW()
            """,
            _uuid.UUID(str(target_id)),
        )
    else:
        result = await conn.execute(
            """
            UPDATE target_endpoints
            SET test_status = 'stale',
                last_attempt_status = 'lease_expired',
                last_verdict = 'lease_expired',
                lease_owner = NULL,
                lease_expires_at = NULL,
                updated_at = NOW()
            WHERE test_status = 'in_progress'
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at < NOW()
            """
        )
    try:
        return int(result.split()[-1])
    except (ValueError, IndexError):
        return 0


async def claim_test_batch(
    conn,
    target_id: str,
    *,
    limit: int = 100,
    stale_days: int = 30,
    lease_owner: str | None = None,
    lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
    campaign_id: str | None = None,
    campaign_only: bool = False,
    check_family: str | None = None,
    endpoint_filter: str | None = None,
    auth_state: str | None = None,
) -> list[dict]:
    """Atomically claim the next batch of untested/stale endpoints (priority
    first) and mark them in_progress. Uses FOR UPDATE SKIP LOCKED so multiple
    exploit workers steal disjoint work safely. A durable lease owner/expiry
    lets crashed workers return to the claimable pool. A batch is intentionally
    scoped to one auth_state because one scanner invocation can only use one
    credential identity correctly."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    cid = _uuid.UUID(str(campaign_id)) if campaign_id else None
    if campaign_only and not cid:
        return []
    restrict_campaign = bool(campaign_only and cid)
    family = normalize_check_family(check_family)
    requested_auth_state = normalize_auth_state(auth_state) if auth_state else None
    endpoint_filter = normalize_endpoint_filter(endpoint_filter)
    endpoint_clause = _endpoint_filter_clause("te", endpoint_filter)
    first_auth_clause = ""
    if requested_auth_state:
        first_auth_clause = "AND te.auth_state = $5" if restrict_campaign else "AND te.auth_state = $3"
    order_clause = _claim_order_clause(family)
    owner = str(lease_owner or "asm-worker")
    lease_seconds = max(60, int(lease_ttl_seconds or DEFAULT_LEASE_TTL_SECONDS))
    async with conn.transaction():
        await reap_expired_leases(conn, target_id)
        if restrict_campaign:
            first = await conn.fetchrow(
                """
                SELECT te.auth_state
                FROM target_endpoints te
                WHERE te.target_id = $1
                  AND te.campaign_id = $2
                  AND te.test_status <> 'gone'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM asm_endpoint_attempts aea
                      WHERE aea.endpoint_id = te.id
                        AND aea.campaign_id = $2
                        AND COALESCE(aea.check_family, 'all') = $3
                        AND aea.status = ANY($4::text[])
                  )
                  {first_auth_clause}
                  {endpoint_clause}
                ORDER BY {order_clause}
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """.format(
                    first_auth_clause=first_auth_clause,
                    endpoint_clause=endpoint_clause,
                    order_clause=order_clause,
                ),
                *(
                    (tid, cid, family, list(ATTEMPT_CLAIM_BLOCKING_STATUSES), requested_auth_state)
                    if requested_auth_state
                    else (tid, cid, family, list(ATTEMPT_CLAIM_BLOCKING_STATUSES))
                ),
            )
        else:
            first = await conn.fetchrow(
                """
                SELECT te.auth_state
                FROM target_endpoints te
                WHERE te.target_id = $1
                  AND (te.test_status IN ('untested', 'stale')
                       OR (te.test_status = 'tested' AND te.last_tested_at < NOW() - ($2 || ' days')::interval))
                  {first_auth_clause}
                  {endpoint_clause}
                ORDER BY {order_clause}
                LIMIT 1
                FOR UPDATE SKIP LOCKED
                """.format(
                    first_auth_clause=first_auth_clause,
                    endpoint_clause=endpoint_clause,
                    order_clause=order_clause,
                ),
                *((tid, str(stale_days), requested_auth_state) if requested_auth_state else (tid, str(stale_days))),
            )
        if not first:
            return []
        auth_state = normalize_auth_state(first["auth_state"])
        if restrict_campaign:
            rows = await conn.fetch(
                """
                SELECT te.id, te.method, te.path, te.param_shape, te.auth_state, te.param_location, te.replay_spec,
                       te.content_type, te.campaign_id, te.lease_owner, te.lease_expires_at, te.attempt_count
                FROM target_endpoints te
                WHERE te.target_id = $1
                  AND te.auth_state = $3
                  AND te.campaign_id = $4
                  AND te.test_status <> 'gone'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM asm_endpoint_attempts aea
                      WHERE aea.endpoint_id = te.id
                        AND aea.campaign_id = $4
                        AND COALESCE(aea.check_family, 'all') = $5
                        AND aea.status = ANY($6::text[])
                  )
                  {endpoint_clause}
                ORDER BY {order_clause}
                LIMIT $2
                FOR UPDATE SKIP LOCKED
                """.format(endpoint_clause=endpoint_clause, order_clause=order_clause),
                tid, limit, auth_state, cid, family, list(ATTEMPT_CLAIM_BLOCKING_STATUSES),
            )
        else:
            rows = await conn.fetch(
                """
                SELECT te.id, te.method, te.path, te.param_shape, te.auth_state, te.param_location, te.replay_spec,
                       te.content_type, te.campaign_id, te.lease_owner, te.lease_expires_at, te.attempt_count
                FROM target_endpoints te
                WHERE te.target_id = $1
                  AND te.auth_state = $4
                  AND (te.test_status IN ('untested', 'stale')
                       OR (te.test_status = 'tested' AND te.last_tested_at < NOW() - ($3 || ' days')::interval))
                  {endpoint_clause}
                ORDER BY {order_clause}
                LIMIT $2
                FOR UPDATE SKIP LOCKED
                """.format(endpoint_clause=endpoint_clause, order_clause=order_clause),
                tid, limit, str(stale_days), auth_state,
            )
        if rows:
            if restrict_campaign:
                await conn.executemany(
                    """
                    INSERT INTO asm_endpoint_attempts (
                        endpoint_id, campaign_id, worker_id, auth_state, check_family,
                        started_at, status, attempted_params_count,
                        completed_params_count, error_summary, scanner_telemetry_json
                    ) VALUES (
                        $1, $2, $3, $4, $5,
                        NOW(), 'leased', 0,
                        0, 'campaign_family_lease', $6::jsonb
                    )
                    """,
                    [
                        (
                            r["id"],
                            cid,
                            owner,
                            normalize_auth_state(r["auth_state"]),
                            family,
                            '{"per_endpoint_telemetry": true, "lease": true}',
                        )
                        for r in rows
                    ],
                )
            await conn.execute(
                """
                UPDATE target_endpoints
                SET test_status = 'in_progress',
                    last_attempt_status = 'leased',
                    lease_owner = $2,
                    lease_expires_at = NOW() + ($3 || ' seconds')::interval,
                    attempt_count = COALESCE(attempt_count, 0) + 1,
                    campaign_id = COALESCE($4, campaign_id),
                    updated_at = NOW()
                WHERE id = ANY($1::uuid[])
                """,
                [r["id"] for r in rows],
                owner,
                str(lease_seconds),
                cid,
            )
    return [dict(r) for r in rows]


async def load_leased_test_batch(
    conn,
    endpoint_ids: list,
    *,
    lease_owner: str,
) -> list[dict]:
    """Load one exact API-admitted ASM batch without selecting new work.

    Canonical V2 batches freeze their endpoint IDs before queue handoff so the
    action manifest and the inventory lease describe the same traffic.  The
    worker may only recover rows still owned by that immutable job identity;
    it cannot silently replace an expired or modified batch with other target
    endpoints.
    """
    import uuid as _uuid

    normalized_ids = [_uuid.UUID(str(item)) for item in endpoint_ids]
    if not normalized_ids:
        return []
    rows = await conn.fetch(
        """
        SELECT id, method, path, param_shape, auth_state, param_location,
               replay_spec, content_type, campaign_id, lease_owner,
               lease_expires_at, attempt_count
        FROM target_endpoints
        WHERE id = ANY($1::uuid[])
          AND test_status = 'in_progress'
          AND lease_owner = $2
          AND lease_expires_at > NOW()
        """,
        normalized_ids,
        str(lease_owner),
    )
    by_id = {str(row["id"]): dict(row) for row in rows}
    return [by_id[str(item)] for item in normalized_ids if str(item) in by_id]


async def release_leased_test_batch(
    conn,
    endpoint_ids: list,
    *,
    lease_owner: str,
    reason: str = "queue_failed",
) -> int:
    """Return an exact not-yet-executed canonical batch to the claimable pool."""
    import uuid as _uuid

    normalized_ids = [_uuid.UUID(str(item)) for item in endpoint_ids]
    if not normalized_ids:
        return 0
    result = await conn.execute(
        """
        UPDATE target_endpoints
        SET test_status = 'untested', last_attempt_status = $3,
            lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW()
        WHERE id = ANY($1::uuid[])
          AND test_status = 'in_progress'
          AND lease_owner = $2
        """,
        normalized_ids,
        str(lease_owner),
        str(reason)[:64],
    )
    try:
        return int(str(result).split()[-1])
    except (ValueError, IndexError):
        return 0


def _param_count(param_shape: Any) -> int:
    return len([p for p in str(param_shape or "").split(",") if p])


async def record_endpoint_attempts(
    conn,
    endpoint_ids: list,
    *,
    scan_id: str | None = None,
    parent_scan_id: str | None = None,
    campaign_id: str | None = None,
    worker_id: str | None = None,
    auth_state: str | None = None,
    check_family: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    status: str,
    attempted_params_count: int | None = None,
    completed_params_count: int | None = None,
    finding_ids: list | None = None,
    error_summary: str | None = None,
    scanner_telemetry_json: dict[str, Any] | None = None,
    replace_existing: bool = False,
) -> int:
    """Write normalized endpoint attempt rows.

    Until scanner-level per-endpoint telemetry exists, callers should set
    conservative counts for partial/timeout states. Completed ASM batches can
    record the param count because the scanner received exactly the claimed
    custom endpoints.
    """
    if not endpoint_ids:
        return 0
    import json
    import uuid as _uuid

    rows = await conn.fetch(
        "SELECT id, param_shape, auth_state, campaign_id FROM target_endpoints WHERE id = ANY($1::uuid[])",
        endpoint_ids,
    )
    if not rows:
        return 0
    sid = _uuid.UUID(str(scan_id)) if scan_id else None
    parent_id = _uuid.UUID(str(parent_scan_id)) if parent_scan_id else None
    cid = _uuid.UUID(str(campaign_id)) if campaign_id else None
    fids = [_uuid.UUID(str(fid)) for fid in (finding_ids or [])]
    family = normalize_check_family(check_family)
    if replace_existing and (sid or parent_id or cid):
        await conn.execute(
            """
            DELETE FROM asm_endpoint_attempts
            WHERE endpoint_id = ANY($1::uuid[])
              AND ($2::uuid IS NULL OR scan_id = $2)
              AND ($3::uuid IS NULL OR parent_scan_id = $3)
              AND ($4::uuid IS NULL OR campaign_id = $4)
              AND COALESCE(check_family, 'all') = $5
            """,
            endpoint_ids,
            sid,
            parent_id,
            cid,
            family,
        )
    started = started_at or datetime.now(timezone.utc)
    completed = completed_at or datetime.now(timezone.utc)
    telemetry = json.dumps(scanner_telemetry_json or {})
    records = []
    for row in rows:
        param_total = _param_count(row["param_shape"])
        attempted = param_total if attempted_params_count is None else max(0, int(attempted_params_count))
        completed_params = attempted if completed_params_count is None else max(0, int(completed_params_count))
        records.append((
            row["id"],
            sid,
            parent_id,
            cid or row["campaign_id"],
            worker_id,
            normalize_auth_state(auth_state or row["auth_state"]),
            family,
            started,
            completed,
            status,
            attempted,
            completed_params,
            fids,
            error_summary,
            telemetry,
        ))
    await conn.executemany(
        """
        INSERT INTO asm_endpoint_attempts (
            endpoint_id, scan_id, parent_scan_id, campaign_id, worker_id, auth_state, check_family,
            started_at, completed_at, status, attempted_params_count,
            completed_params_count, finding_ids, error_summary, scanner_telemetry_json
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10, $11,
            $12, $13::uuid[], $14, $15::jsonb
        )
        """,
        records,
    )
    return len(records)


async def endpoint_ids_for_worklist(
    conn,
    target_id: str,
    worklist: Any,
    *,
    auth_state: str = "anonymous",
    limit: int = 20000,
) -> list:
    """Resolve existing inventory row IDs for a worklist/auth identity.

    Callers should upsert first. This helper intentionally does not create rows;
    it is used when recording attempt facts against inventory rows that should
    already exist.
    """
    import uuid as _uuid

    rows = normalize_worklist_details(worklist, auth_state=auth_state, limit=limit)
    if not rows:
        return []
    state = normalize_auth_state(auth_state)
    fingerprints = [
        endpoint_fingerprint(
            parsed.method,
            parsed.path,
            parsed.param_shape,
            param_location=parsed.param_location,
            auth_state=state,
        )
        for parsed in rows
    ]
    fetched = await conn.fetch(
        """
        SELECT id, fingerprint
        FROM target_endpoints
        WHERE target_id = $1 AND fingerprint = ANY($2::text[])
        """,
        _uuid.UUID(str(target_id)),
        fingerprints,
    )
    by_fp = {str(row["fingerprint"]): row["id"] for row in fetched}
    return [by_fp[fp] for fp in fingerprints if fp in by_fp]


async def mark_tested(conn, endpoint_ids: list, *, verdict: str | None = None) -> int:
    """Stamp claimed endpoints as tested. Returns rows updated."""
    if not endpoint_ids:
        return 0
    result = await conn.execute(
        """
        UPDATE target_endpoints
        SET test_status = 'tested', last_tested_at = NOW(),
            last_verdict = COALESCE($2, last_verdict),
            last_attempt_status = 'completed',
            lease_owner = NULL,
            lease_expires_at = NULL,
            updated_at = NOW()
        WHERE id = ANY($1::uuid[])
        """,
        endpoint_ids, verdict,
    )
    try:
        return int(result.split()[-1])
    except (ValueError, IndexError):
        return 0


async def mark_partial(conn, endpoint_ids: list, *, verdict: str | None = "partial") -> int:
    """Mark claimed endpoints as incomplete so coverage is not overstated."""
    if not endpoint_ids:
        return 0
    result = await conn.execute(
        """
        UPDATE target_endpoints
        SET test_status = 'stale',
            last_verdict = COALESCE($2, last_verdict),
            last_attempt_status = COALESCE($2, 'partial'),
            lease_owner = NULL,
            lease_expires_at = NULL,
            updated_at = NOW()
        WHERE id = ANY($1::uuid[])
        """,
        endpoint_ids, verdict,
    )
    try:
        return int(result.split()[-1])
    except (ValueError, IndexError):
        return 0


# ---------------------------------------------------------------------------
# Continuous dispatcher policy (docs §16 Phase 3/4) — pure decision logic
# ---------------------------------------------------------------------------

# Defaults are deliberately conservative: one modest batch at a time, slow
# cadence, weekly recon. The crash lesson (concurrent shards + batch took a
# target down) means the engine must never stack load on a target.

# Default per-root-domain rate ceiling (endpoints tested per rolling hour across
# all targets sharing a root domain). A single target does ~50/hour (batch_size
# 50 + min_interval_minutes 60), so 1000 leaves ~20 targets'-worth of batches
# before throttling — gentle for one target, but caps a fleet of subdomains so
# auto-enabled Continuous ASM cannot collectively hammer a domain. Operators can
# set ASM_DEFAULT_DOMAIN_RATE_PER_HOUR=0 to restore the old unlimited behavior.
try:
    _DEFAULT_DOMAIN_RATE_PER_HOUR = max(0, int(os.environ.get("ASM_DEFAULT_DOMAIN_RATE_PER_HOUR") or 1000))
except (TypeError, ValueError):
    _DEFAULT_DOMAIN_RATE_PER_HOUR = 1000

DEFAULT_ASM_CONFIG: dict[str, Any] = {
    "batch_size": 50,                      # endpoints per exploit batch
    "stale_days": 30,                      # re-test tested endpoints older than this
    "min_interval_minutes": 60,            # min gap between test batches per target
    "daily_endpoint_cap": 2000,            # 0 = unlimited; endpoints/target/24h
    "recon_interval_hours": 168,           # 0 = never; periodic surface refresh (weekly)
    "exploit_depth": False,                # deeper active checks per batch
    "window_start_hour": None,             # int 0-23 UTC, None = no hour restriction
    "window_end_hour": None,               # int 0-23 UTC (exclusive); wraps midnight if < start
    "window_days": None,                   # list[int] 0=Mon..6=Sun, None = all days
    "max_requests_per_hour_per_domain": _DEFAULT_DOMAIN_RATE_PER_HOUR, # per-root-domain rate cap; 0 = unlimited (set via ASM_DEFAULT_DOMAIN_RATE_PER_HOUR)
}

_INT_BOUNDS = {
    "batch_size": (1, 1000),
    "stale_days": (0, 3650),
    "min_interval_minutes": (5, 10080),
    "daily_endpoint_cap": (0, 1_000_000),
    "recon_interval_hours": (0, 8760),
    "max_requests_per_hour_per_domain": (0, 1_000_000),
}


def _clamp_int(value: Any, lo: int, hi: int, default: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def merge_asm_config(config: Any) -> dict[str, Any]:
    """Overlay a (possibly partial / untrusted) config over the defaults with
    clamping, so the dispatcher always sees valid bounded values."""
    cfg = dict(DEFAULT_ASM_CONFIG)
    if not isinstance(config, dict):
        return cfg
    for key, (lo, hi) in _INT_BOUNDS.items():
        if key in config and config[key] is not None:
            cfg[key] = _clamp_int(config[key], lo, hi, cfg[key])
    if "exploit_depth" in config:
        cfg["exploit_depth"] = bool(config["exploit_depth"])
    for hk in ("window_start_hour", "window_end_hour"):
        if hk in config:
            v = config[hk]
            cfg[hk] = _clamp_int(v, 0, 23, 0) if v is not None and v != "" else None
    if "window_days" in config:
        v = config["window_days"]
        if isinstance(v, (list, tuple)):
            valid: set[int] = set()
            for x in v:
                try:
                    n = int(x)
                except (TypeError, ValueError):
                    continue
                if 0 <= n <= 6:  # drop out-of-range weekdays, don't clamp
                    valid.add(n)
            cfg["window_days"] = sorted(valid) or None
        else:
            cfg["window_days"] = None
    return cfg


def _as_utc(dt: datetime | None) -> datetime | None:
    """Normalize a datetime to tz-aware UTC. Callers mix naive (utc_now()) and
    tz-aware (asyncpg TIMESTAMPTZ) datetimes; subtracting across the two raises
    'can't subtract offset-naive and offset-aware'. Naive values are assumed UTC
    (the project's utc_now() convention)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def within_window(now: datetime, config: Any) -> bool:
    """True if `now` falls in the configured allowed window (interpreted in UTC).
    No window config = always allowed."""
    now = _as_utc(now)
    cfg = merge_asm_config(config)
    days = cfg["window_days"]
    if days is not None and now.weekday() not in days:
        return False
    start, end = cfg["window_start_hour"], cfg["window_end_hour"]
    if start is None or end is None or start == end:
        return True  # no hour restriction
    hour = now.hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end  # window wraps midnight


def next_window_start(now: datetime, config: Any) -> datetime | None:
    """Best-effort next UTC time that satisfies the ASM window.

    Windows are hour/day based, so an hourly scan over the next week is enough
    to explain "why skipped" without adding a scheduler dependency here.
    """
    now = _as_utc(now)
    cfg = merge_asm_config(config)
    if within_window(now, cfg):
        return now
    probe = now.replace(minute=0, second=0, microsecond=0)
    if probe <= now:
        probe += timedelta(hours=1)
    for _ in range(24 * 8):
        if within_window(probe, cfg):
            return probe
        probe += timedelta(hours=1)
    return None


def decide_asm_action(
    *,
    now: datetime,
    last_test_at: datetime | None,
    last_recon_at: datetime | None,
    has_active_scan: bool,
    claimable: int,
    tested_today: int,
    domain_rate_exceeded: bool = False,
    domain_rate_remaining: int | None = None,
    config: Any = None,
) -> dict[str, Any]:
    """Pure per-target dispatch decision. Returns {action, reason, config}
    where action is 'recon' | 'test' | 'none'. At most one action per tick so
    the engine never stacks load on a target."""
    # Normalize datetime awareness up front (naive utc_now() vs tz-aware
    # TIMESTAMPTZ) so the interval subtractions below never raise.
    now = _as_utc(now)
    last_test_at = _as_utc(last_test_at)
    last_recon_at = _as_utc(last_recon_at)
    cfg = merge_asm_config(config)
    daily_cap = int(cfg["daily_endpoint_cap"])
    daily_remaining = None if daily_cap <= 0 else max(0, daily_cap - int(tested_today or 0))
    rate_remaining = None if domain_rate_remaining is None else max(0, int(domain_rate_remaining or 0))

    def _iso(dt: datetime | None) -> str | None:
        return dt.isoformat() if dt else None

    def result(
        action: str,
        reason: str,
        *,
        blocked_by: str | None = None,
        next_eligible_at: datetime | None = None,
    ) -> dict[str, Any]:
        return {
            "action": action,
            "reason": reason,
            "blocked_by": blocked_by,
            "next_eligible_at": _iso(next_eligible_at),
            "daily_cap_remaining": daily_remaining,
            "rate_cap_remaining": rate_remaining,
            "claimable": max(0, int(claimable or 0)),
            "tested_today": max(0, int(tested_today or 0)),
            "config": cfg,
        }

    if not within_window(now, cfg):
        return result(
            "none",
            "outside allowed time window",
            blocked_by="outside_window",
            next_eligible_at=next_window_start(now, cfg),
        )
    if has_active_scan:
        return result("none", "target already has an active scan", blocked_by="active_scan")
    if domain_rate_exceeded:
        return result("none", "per-root-domain rate limit reached", blocked_by="domain_rate_cap")

    rih = cfg["recon_interval_hours"]
    if rih > 0 and (last_recon_at is None or (now - last_recon_at) >= timedelta(hours=rih)):
        return result("recon", "recon interval elapsed")

    if claimable <= 0:
        next_recon_at = last_recon_at + timedelta(hours=rih) if rih > 0 and last_recon_at else None
        return result(
            "none",
            "no claimable endpoints",
            blocked_by="no_claimable_endpoints",
            next_eligible_at=next_recon_at,
        )
    if last_test_at is not None and (now - last_test_at) < timedelta(minutes=cfg["min_interval_minutes"]):
        return result(
            "none",
            "within minimum test interval",
            blocked_by="min_interval",
            next_eligible_at=last_test_at + timedelta(minutes=cfg["min_interval_minutes"]),
        )
    cap = cfg["daily_endpoint_cap"]
    if cap > 0 and tested_today >= cap:
        return result(
            "none",
            "daily endpoint cap reached",
            blocked_by="daily_endpoint_cap",
            next_eligible_at=now + timedelta(hours=24),
        )
    return result("test", "claimable endpoints available")


# ---------------------------------------------------------------------------
# Async helpers for the dispatcher / new-surface feed
# ---------------------------------------------------------------------------

async def claimable_count(
    conn,
    target_id: str,
    *,
    stale_days: int = 30,
    endpoint_filter: str | None = None,
) -> int:
    """How many endpoints the next exploit batch could claim (untested/stale/
    tested-older-than-stale). Lets the dispatcher skip targets with no work."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    endpoint_filter = normalize_endpoint_filter(endpoint_filter)
    endpoint_clause = _endpoint_filter_clause("te", endpoint_filter)
    n = await conn.fetchval(
        """
        SELECT count(*) FROM target_endpoints te
        WHERE te.target_id = $1
          AND (te.test_status IN ('untested', 'stale')
               OR (te.test_status = 'tested' AND te.last_tested_at < NOW() - ($2 || ' days')::interval))
          {endpoint_clause}
        """.format(endpoint_clause=endpoint_clause),
        tid, str(stale_days),
    )
    return int(n or 0)


async def tested_recently_count(conn, target_id: str, *, hours: int = 24) -> int:
    """Endpoints stamped tested within the last N hours (for the daily cap)."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    n = await conn.fetchval(
        """
        SELECT count(*) FROM target_endpoints
        WHERE target_id = $1 AND last_tested_at >= NOW() - ($2 || ' hours')::interval
        """,
        tid, str(hours),
    )
    return int(n or 0)


async def domain_tested_recently_count(conn, root_domain: str, *, hours: int = 1) -> int:
    """Endpoints tested within the last N hours across ALL targets of a root
    domain (the per-root-domain distributed rate cap, docs §16 Phase 4)."""
    if not root_domain:
        return 0
    n = await conn.fetchval(
        """
        SELECT count(*) FROM target_endpoints te
        JOIN targets t ON t.id = te.target_id
        WHERE t.root_domain = $1
          AND te.last_tested_at >= NOW() - ($2 || ' hours')::interval
        """,
        root_domain, str(hours),
    )
    return int(n or 0)


async def new_surface(conn, target_id: str, *, days: int = 7, limit: int = 100) -> dict[str, Any]:
    """New attack surface: endpoints first seen within the last N days (the
    ASM diff feed — mirrors how Gungnir alerts on new certs)."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    rows = await conn.fetch(
        """
        SELECT id, method, path, param_shape, param_location, replay_spec, content_type,
               source, auth_state, priority_score, test_status, last_attempt_status,
               last_verdict, first_seen_at, last_seen_at, last_tested_at
        FROM target_endpoints
        WHERE target_id = $1 AND first_seen_at >= NOW() - ($2 || ' days')::interval
        ORDER BY first_seen_at DESC, priority_score DESC
        LIMIT $3
        """,
        tid, str(days), limit,
    )
    total = await conn.fetchval(
        """
        SELECT count(*) FROM target_endpoints
        WHERE target_id = $1 AND first_seen_at >= NOW() - ($2 || ' days')::interval
        """,
        tid, str(days),
    )
    return {"days": days, "total_new": int(total or 0), "endpoints": [dict(r) for r in rows]}
