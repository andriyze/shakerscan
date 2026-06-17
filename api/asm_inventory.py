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

# Campaign modes. They are intentionally broader than the current dispatcher
# path so one-shot Full Coverage can move onto the same allocator later.
CAMPAIGN_FULL_COVERAGE = "full_coverage"
CAMPAIGN_CONTINUOUS_ASM = "continuous_asm"
CAMPAIGN_FOCUSED_FAMILY = "focused_family"
CAMPAIGN_FINDING_RETEST = "finding_retest"
CAMPAIGN_SURFACE_RECON = "surface_recon"

DEFAULT_LEASE_TTL_SECONDS = 3600

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
    campaign_id: str | None = None,
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
                 campaign_id, first_seen_at, last_seen_at, test_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW(), 'untested')
            ON CONFLICT (target_id, fingerprint) DO UPDATE SET
                last_seen_at = NOW(),
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
            parsed.param_location, parsed.replay_spec, parsed.content_type, prio, cid,
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


def normalize_attempt_status_for_coverage(status: Any, telemetry: Any = None) -> str:
    """Normalize attempt status before coverage accounting.

    A batch-level "completed" status is not endpoint proof. Completed rows count
    as tested only when scanner endpoint telemetry explicitly says the endpoint
    was exercised.
    """
    normalized = str(status or "").strip().lower()
    if normalized == "completed" and not _attempt_telemetry_true(telemetry, "per_endpoint_telemetry"):
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
    return {
        "total": total,
        "tested": attempt_completed if use_attempts else status_summary["tested"],
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
        "coverage": attempt_summary["coverage"] if use_attempts else status_summary["coverage"],
        "coverage_basis": "attempt_ledger" if use_attempts else "endpoint_status",
        "status_coverage": status_summary,
        "attempt_coverage": attempt_summary,
    }


async def campaign_attempt_summary(
    conn,
    campaign_id: str,
    *,
    expected_total: int | None = None,
) -> dict[str, Any]:
    """Coverage counts for one scan campaign from normalized attempt facts.

    Full Coverage parent reports use this after merge-time attempt rows are
    written. ``expected_total`` is the planner's assigned auth-scoped endpoint
    count, which preserves unattempted slots in the denominator if a worker
    never produced a ledger row.
    """
    import uuid as _uuid

    cid = _uuid.UUID(str(campaign_id))
    rows = await conn.fetch(
        """
        WITH latest_attempt AS (
            SELECT DISTINCT ON (aea.endpoint_id)
                aea.endpoint_id,
                aea.status,
                aea.scanner_telemetry_json,
                aea.attempted_params_count,
                aea.completed_params_count
            FROM asm_endpoint_attempts aea
            JOIN target_endpoints te ON te.id = aea.endpoint_id
            WHERE aea.campaign_id = $1 AND te.test_status <> 'gone'
            ORDER BY aea.endpoint_id, COALESCE(aea.completed_at, aea.started_at) DESC, aea.started_at DESC
        )
        SELECT status, scanner_telemetry_json, attempted_params_count, completed_params_count
        FROM latest_attempt
        """,
        cid,
    )
    return attempt_coverage_from_rows(
        list(rows or []),
        total=int(expected_total or 0),
        basis="campaign_attempt_ledger",
        coverage_denominator="assigned_auth_scoped_endpoints" if expected_total is not None else "attempted_endpoints",
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
    owner = str(lease_owner or "asm-worker")
    lease_seconds = max(60, int(lease_ttl_seconds or DEFAULT_LEASE_TTL_SECONDS))
    async with conn.transaction():
        await reap_expired_leases(conn, target_id)
        first = await conn.fetchrow(
            """
            SELECT auth_state
            FROM target_endpoints
            WHERE target_id = $1
              AND (test_status IN ('untested', 'stale')
                   OR (test_status = 'tested' AND last_tested_at < NOW() - ($2 || ' days')::interval))
              AND ($3::boolean = false OR campaign_id = $4)
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT 1
            FOR UPDATE SKIP LOCKED
            """,
            tid, str(stale_days), restrict_campaign, cid,
        )
        if not first:
            return []
        auth_state = normalize_auth_state(first["auth_state"])
        rows = await conn.fetch(
            """
            SELECT id, method, path, param_shape, auth_state, param_location, replay_spec,
                   content_type, campaign_id, lease_owner, lease_expires_at, attempt_count
            FROM target_endpoints
            WHERE target_id = $1
              AND auth_state = $4
              AND (test_status IN ('untested', 'stale')
                   OR (test_status = 'tested' AND last_tested_at < NOW() - ($3 || ' days')::interval))
              AND ($5::boolean = false OR campaign_id = $6)
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            """,
            tid, limit, str(stale_days), auth_state, restrict_campaign, cid,
        )
        if rows:
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
    if replace_existing and (sid or parent_id or cid):
        await conn.execute(
            """
            DELETE FROM asm_endpoint_attempts
            WHERE endpoint_id = ANY($1::uuid[])
              AND ($2::uuid IS NULL OR scan_id = $2)
              AND ($3::uuid IS NULL OR parent_scan_id = $3)
              AND ($4::uuid IS NULL OR campaign_id = $4)
            """,
            endpoint_ids,
            sid,
            parent_id,
            cid,
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
            endpoint_id, scan_id, parent_scan_id, campaign_id, worker_id, auth_state,
            started_at, completed_at, status, attempted_params_count,
            completed_params_count, finding_ids, error_summary, scanner_telemetry_json
        ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10,
            $11, $12::uuid[], $13, $14::jsonb
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
