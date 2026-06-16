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
from typing import Any

# Job type for the async exploitation pipeline (routed in worker.process_job).
EXPLOIT_BATCH_JOB_TYPE = "exploit_batch"

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
    try:
        obj = json.loads(blob)
        return {str(k) for k in obj} if isinstance(obj, dict) else set()
    except (ValueError, TypeError):
        return set()


def parse_worklist_entry(entry: Any) -> tuple[str, str, str] | None:
    """Parse a custom-endpoint string into (method, concrete_path, param_shape).

    Accepts the shapes emitted by the scanner / harvester:
    ``"GET /a?x=1&y=2"``, ``"POST /a form:k=1"``, ``"POST /a json:{...}"``,
    ``"GET /a p1 p2"``, or just ``"/a"``. ``param_shape`` is a sorted,
    comma-joined set of parameter names (the injection surface).
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
    path_part = s
    if " " in s:
        path_part, desc = s.split(" ", 1)
        desc = desc.strip()
        if desc.startswith("form:"):
            param_names |= _names_from_qs(desc[5:])
        elif desc.startswith("json:"):
            param_names |= _names_from_json(desc[5:])
        else:
            param_names |= {t for t in desc.split() if t}

    if "?" in path_part:
        path, qs = path_part.split("?", 1)
        param_names |= _names_from_qs(qs)
    else:
        path = path_part

    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    param_shape = ",".join(sorted(n for n in param_names if n))
    return method, path, param_shape


def endpoint_fingerprint(method: str, path: str, param_shape: str) -> str:
    """Stable identity: method + normalized path + param-name set."""
    raw = f"{method.upper()} {normalize_path(path)}?{param_shape}"
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


def to_custom_endpoint(method: str, path: str, param_shape: str) -> str:
    """Rebuild a scanner custom-endpoint string for re-testing an inventory row."""
    base = f"{method.upper()} {path}"
    names = [n for n in (param_shape or "").split(",") if n]
    if names:
        base += "?" + "&".join(f"{n}=1" for n in names)
    return base


def normalize_worklist(worklist: Any, *, limit: int = 20000) -> list[tuple[str, str, str]]:
    """Parse + dedupe a raw worklist into (method, path, param_shape) tuples,
    keeping the first concrete path seen per fingerprint."""
    seen: set[str] = set()
    out: list[tuple[str, str, str]] = []
    for entry in (worklist or []):
        parsed = parse_worklist_entry(entry)
        if not parsed:
            continue
        method, path, shape = parsed
        fp = endpoint_fingerprint(method, path, shape)
        if fp in seen:
            continue
        seen.add(fp)
        out.append((method, path, shape))
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
    rows = normalize_worklist(worklist, limit=limit)
    if not rows:
        return 0
    tid = _uuid.UUID(str(target_id))
    count = 0
    for method, path, shape in rows:
        fp = endpoint_fingerprint(method, path, shape)
        prio = priority_score(method, path, shape)
        await conn.execute(
            """
            INSERT INTO target_endpoints
                (target_id, method, path, param_shape, fingerprint, source,
                 auth_state, priority_score, first_seen_at, last_seen_at, test_status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW(), 'untested')
            ON CONFLICT (target_id, fingerprint) DO UPDATE SET
                last_seen_at = NOW(),
                source = EXCLUDED.source,
                priority_score = EXCLUDED.priority_score,
                test_status = CASE
                    WHEN target_endpoints.test_status = 'gone' THEN 'untested'
                    ELSE target_endpoints.test_status END,
                updated_at = NOW()
            """,
            tid, method, path, shape, fp, source, auth_state, prio,
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
    exploit workers steal disjoint work safely."""
    import uuid as _uuid
    tid = _uuid.UUID(str(target_id))
    async with conn.transaction():
        rows = await conn.fetch(
            """
            SELECT id, method, path, param_shape, auth_state
            FROM target_endpoints
            WHERE target_id = $1
              AND (test_status IN ('untested', 'stale')
                   OR (test_status = 'tested' AND last_tested_at < NOW() - ($3 || ' days')::interval))
            ORDER BY priority_score DESC, last_seen_at DESC
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            """,
            tid, limit, str(stale_days),
        )
        if rows:
            await conn.execute(
                "UPDATE target_endpoints SET test_status = 'in_progress', updated_at = NOW() WHERE id = ANY($1::uuid[])",
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
            last_verdict = COALESCE($2, last_verdict), updated_at = NOW()
        WHERE id = ANY($1::uuid[])
        """,
        endpoint_ids, verdict,
    )
    try:
        return int(result.split()[-1])
    except (ValueError, IndexError):
        return 0
