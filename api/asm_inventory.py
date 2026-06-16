"""Continuous ASM — persistent per-target endpoint inventory (docs §16).

Recon upserts the discovered endpoint worklist into the ``target_endpoints``
table; the exploitation pipeline pulls untested/stale endpoints, tests them, and
stamps results. Endpoint identity reuses the findings dedup pattern:
``UNIQUE(target_id, fingerprint)`` with an ``ON CONFLICT`` upsert.

The pure helpers (parse/normalize/fingerprint/priority) are unit-tested; the
async helpers take an asyncpg connection and do the DB work.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

# Job type for the async exploitation pipeline (routed in worker.process_job).
EXPLOIT_BATCH_JOB_TYPE = "exploit_batch"
# Scan roles created by the continuous dispatcher (docs §16 Phase 3).
ASM_BATCH_ROLE = "asm_batch"
ASM_RECON_ROLE = "asm_recon"

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

VALID_AUTH_STATES = frozenset({"anonymous", "user1", "user2"})


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
        cursor[parts[-1]] = 1
    return root


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
    if any(k in p for k in _HIGH_VALUE):
        score += 20
    if param_shape:  # parameter-bearing = injection candidate
        score += 15
    if method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
        score += 5
    return score


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

async def upsert_endpoints(
    conn,
    target_id: str,
    worklist: Any,
    *,
    source: str = "recon",
    auth_state: str = "anonymous",
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
                 first_seen_at, last_seen_at, test_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW(), 'untested')
            ON CONFLICT (target_id, fingerprint) DO UPDATE SET
                last_seen_at = NOW(),
                source = EXCLUDED.source,
                auth_state = EXCLUDED.auth_state,
                param_location = EXCLUDED.param_location,
                replay_spec = EXCLUDED.replay_spec,
                content_type = EXCLUDED.content_type,
                priority_score = EXCLUDED.priority_score,
                test_status = CASE
                    WHEN target_endpoints.test_status = 'gone' THEN 'untested'
                    ELSE target_endpoints.test_status END,
                updated_at = NOW()
            """,
            tid, parsed.method, parsed.path, parsed.param_shape, fp, source, auth_state,
            parsed.param_location, parsed.replay_spec, parsed.content_type, prio,
        )
        count += 1
    return count


async def coverage_summary(conn, target_id: str) -> dict[str, Any]:
    """Per-target coverage counts for the ASM surface."""
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
            count(*) FILTER (WHERE test_status = 'gone') AS gone
        FROM target_endpoints WHERE target_id = $1
        """,
        tid,
    )
    total = int(row["total"] or 0)
    tested = int(row["tested"] or 0)
    testable = total - int(row["gone"] or 0)
    return {
        "total": total,
        "tested": tested,
        "untested": int(row["untested"] or 0),
        "in_progress": int(row["in_progress"] or 0),
        "stale": int(row["stale"] or 0),
        "gone": int(row["gone"] or 0),
        "coverage": round(tested / testable, 3) if testable else 0.0,
    }


async def claim_test_batch(conn, target_id: str, *, limit: int = 100, stale_days: int = 30) -> list[dict]:
    """Atomically claim the next batch of untested/stale endpoints (priority
    first) and mark them in_progress. Uses FOR UPDATE SKIP LOCKED so multiple
    exploit workers steal disjoint work safely. A batch is intentionally scoped
    to one auth_state because one scanner invocation can only use one credential
    identity correctly."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    async with conn.transaction():
        first = await conn.fetchrow(
            """
            SELECT auth_state
            FROM target_endpoints
            WHERE target_id = $1
              AND (test_status IN ('untested', 'stale')
                   OR (test_status = 'tested' AND last_tested_at < NOW() - ($2 || ' days')::interval))
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """,
            tid, str(stale_days),
        )
        if not first:
            return []
        auth_state = normalize_auth_state(first["auth_state"])
        rows = await conn.fetch(
            """
            SELECT id, method, path, param_shape, auth_state, param_location, replay_spec, content_type
            FROM target_endpoints
            WHERE target_id = $1
              AND auth_state = $4
              AND (test_status IN ('untested', 'stale')
                   OR (test_status = 'tested' AND last_tested_at < NOW() - ($3 || ' days')::interval))
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            """,
            tid, limit, str(stale_days), auth_state,
        )
        if rows:
            await conn.execute(
                """
                UPDATE target_endpoints
                SET test_status = 'in_progress', last_attempt_status = 'leased', updated_at = NOW()
                WHERE id = ANY($1::uuid[])
                """,
                [r["id"] for r in rows],
            )
    return [dict(r) for r in rows]


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
    "max_requests_per_hour_per_domain": 0, # 0 = unlimited; per-root-domain rate cap (Phase 4)
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


def decide_asm_action(
    *,
    now: datetime,
    last_test_at: datetime | None,
    last_recon_at: datetime | None,
    has_active_scan: bool,
    claimable: int,
    tested_today: int,
    domain_rate_exceeded: bool = False,
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

    def result(action: str, reason: str) -> dict[str, Any]:
        return {"action": action, "reason": reason, "config": cfg}

    if not within_window(now, cfg):
        return result("none", "outside allowed time window")
    if has_active_scan:
        return result("none", "target already has an active scan")
    if domain_rate_exceeded:
        return result("none", "per-root-domain rate limit reached")

    rih = cfg["recon_interval_hours"]
    if rih > 0 and (last_recon_at is None or (now - last_recon_at) >= timedelta(hours=rih)):
        return result("recon", "recon interval elapsed")

    if claimable <= 0:
        return result("none", "no claimable endpoints")
    if last_test_at is not None and (now - last_test_at) < timedelta(minutes=cfg["min_interval_minutes"]):
        return result("none", "within minimum test interval")
    cap = cfg["daily_endpoint_cap"]
    if cap > 0 and tested_today >= cap:
        return result("none", "daily endpoint cap reached")
    return result("test", "claimable endpoints available")


# ---------------------------------------------------------------------------
# Async helpers for the dispatcher / new-surface feed
# ---------------------------------------------------------------------------

async def claimable_count(conn, target_id: str, *, stale_days: int = 30) -> int:
    """How many endpoints the next exploit batch could claim (untested/stale/
    tested-older-than-stale). Lets the dispatcher skip targets with no work."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    n = await conn.fetchval(
        """
        SELECT count(*) FROM target_endpoints
        WHERE target_id = $1
          AND (test_status IN ('untested', 'stale')
               OR (test_status = 'tested' AND last_tested_at < NOW() - ($2 || ' days')::interval))
        """,
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
