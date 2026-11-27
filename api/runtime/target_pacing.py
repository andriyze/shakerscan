"""Adaptive pacing: a Scan slows down, and pauses, when its target degrades.

A Scan used to keep its full rate while the target answered 503 on every path, timed out or
slowed to a crawl. On a fragile production system that rate is part of the outage, and the
degraded answers tested nothing anyway. Before each external tool attempt (nuclei, katana, ffuf,
Dalfox, sqlmap, httpx) the worker now reads the target origin's recent answers in this Scan's own
HTTP archive (``http_transactions``: status, elapsed time, transport error) and sets the
attempt's rate from them:

==========  =============================================================  ==========
state       when (last 5 minutes, at least ``MIN_SAMPLES`` answers)        rate
==========  =============================================================  ==========
normal      fewer than 20 % degraded answers and latency under 4x baseline  as planned
slowed      20 % or more degraded, or median latency 4x the Scan's baseline  1/2
slowed      50 % or more degraded (or 30 % throttled with 429)             1/4
paused      80 % or more degraded                                           none
==========  =============================================================  ==========

A degraded answer is a 5xx, a 429 or a transport error (refused, reset, timed out). A paused
attempt waits, sending nothing, until the degraded answers age out of the window (the target had
time to recover) or its wait ends; an attempt the target never recovered for ends as
``target_degraded`` and the family is reported partial. Pacing never fails a whole Scan.

Every decision other than ``normal`` is recorded once per change in the Scan's
``execution_context.target_pacing`` (``GET /scans/{id}``): the origin, the state, why, when it
started, and how many attempts it slowed, paused or stopped.
"""
from __future__ import annotations

import asyncio
import json
import statistics
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Iterable, Mapping, Sequence

WINDOW_SECONDS = 300
WINDOW_ROWS = 60
MIN_SAMPLES = 8
BASELINE_ROWS = 20
SLOW_LATENCY_RATIO = 4.0
PAUSE_POLL_SECONDS = 15.0
MAX_PAUSE_SECONDS = 300.0
DEGRADED_STATUSES = frozenset({429})


@dataclass(frozen=True)
class PacingDecision:
    state: str  # normal | slowed | paused
    factor: float  # 1.0, 0.5, 0.25 or 0.0
    reason: str = ""
    samples: int = 0
    degraded_share: float = 0.0
    latency_ratio: float | None = None
    metrics: Mapping[str, Any] = field(default_factory=dict)

    def record(self) -> dict[str, Any]:
        return {
            "state": self.state, "rate_factor": self.factor, "reason": self.reason,
            "samples": self.samples, "degraded_share": round(self.degraded_share, 3),
            **({"latency_ratio": round(self.latency_ratio, 2)} if self.latency_ratio else {}),
        }


NORMAL = PacingDecision("normal", 1.0)


def _degraded(status: Any, error: Any) -> tuple[bool, bool]:
    """(degraded, throttled) for one answer."""
    if error:
        return True, False
    try:
        code = int(status)
    except (TypeError, ValueError):
        return True, False
    if code in DEGRADED_STATUSES:
        return True, True
    return code >= 500 and code != 501, False


def assess(rows: Iterable[Mapping[str, Any]], *, baseline_ms: float | None = None) -> PacingDecision:
    """The pacing state for an origin from its recent answers (newest first or any order)."""
    # A row with neither a status nor an error is a request whose answer was never read (an
    # encrypted tunnel's request line): no evidence either way, not a degraded answer.
    samples = [row for row in rows if row.get("status_code") is not None or row.get("error")]
    if len(samples) < MIN_SAMPLES:
        return NORMAL
    flags = [_degraded(row.get("status_code"), row.get("error")) for row in samples]
    degraded = sum(1 for bad, _ in flags if bad)
    throttled = sum(1 for _, limited in flags if limited)
    share = degraded / len(samples)
    throttled_share = throttled / len(samples)
    healthy_latencies = [
        float(row["elapsed_ms"]) for row, (bad, _) in zip(samples, flags)
        if not bad and isinstance(row.get("elapsed_ms"), (int, float))
    ]
    ratio = None
    if baseline_ms and baseline_ms > 0 and len(healthy_latencies) >= MIN_SAMPLES // 2:
        ratio = statistics.median(healthy_latencies) / float(baseline_ms)
    metrics = {"degraded": degraded, "throttled": throttled}
    if share >= 0.8:
        return PacingDecision("paused", 0.0, f"{degraded} of the last {len(samples)} answers were "
                              "errors, 5xx or 429", len(samples), share, ratio, metrics)
    if share >= 0.5 or throttled_share >= 0.3:
        why = (f"{throttled} of the last {len(samples)} answers were 429 (throttled)"
               if throttled_share >= 0.3 else
               f"{degraded} of the last {len(samples)} answers were errors, 5xx or 429")
        return PacingDecision("slowed", 0.25, why, len(samples), share, ratio, metrics)
    if share >= 0.2:
        return PacingDecision("slowed", 0.5, f"{degraded} of the last {len(samples)} answers were "
                              "errors, 5xx or 429", len(samples), share, ratio, metrics)
    if ratio is not None and ratio >= SLOW_LATENCY_RATIO:
        return PacingDecision("slowed", 0.5, f"median latency is {ratio:.1f}x this Scan's baseline",
                              len(samples), share, ratio, metrics)
    return PacingDecision("normal", 1.0, "", len(samples), share, ratio, metrics)


def origin_prefixes(url: str) -> tuple[str, ...]:
    """The URL prefixes an origin's archived requests start with (default port written or not)."""
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        port = parts.port
    except ValueError:
        return ()
    if scheme not in {"http", "https"} or not host:
        return ()
    if ":" in host:
        host = f"[{host}]"
    default = 443 if scheme == "https" else 80
    bare, explicit = f"{scheme}://{host}", f"{scheme}://{host}:{port or default}"
    return (explicit,) if port and port != default else (bare, explicit)


_RECENT_SQL = """
SELECT status_code, elapsed_ms, error FROM http_transactions
 WHERE scan_id = $1 AND started_at >= NOW() - make_interval(secs => $3)
   AND (status_code IS NOT NULL OR error IS NOT NULL)
   AND (url = ANY($2::text[]) OR url LIKE ANY(ARRAY(SELECT p || '/%' FROM unnest($2::text[]) p))
        OR url LIKE ANY(ARRAY(SELECT p || '?%' FROM unnest($2::text[]) p)))
 ORDER BY started_at DESC LIMIT $4"""

_BASELINE_SQL = """
SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY elapsed_ms) FROM (
  SELECT elapsed_ms FROM http_transactions
   WHERE scan_id = $1 AND elapsed_ms IS NOT NULL AND error IS NULL
     AND status_code < 500 AND status_code <> 429
     AND (url = ANY($2::text[]) OR url LIKE ANY(ARRAY(SELECT p || '/%' FROM unnest($2::text[]) p)))
   ORDER BY started_at LIMIT $3) first_answers"""


async def origin_pacing(conn: Any, scan_id: Any, url: str) -> PacingDecision:
    prefixes = list(origin_prefixes(url))
    if not prefixes or not scan_id:
        return NORMAL
    rows = await conn.fetch(_RECENT_SQL, scan_id, prefixes, float(WINDOW_SECONDS), WINDOW_ROWS)
    baseline = await conn.fetchval(_BASELINE_SQL, scan_id, prefixes, BASELINE_ROWS)
    return assess([dict(row) for row in rows], baseline_ms=float(baseline) if baseline else None)


_RECORD_SQL = """
UPDATE scans SET execution_context = COALESCE(execution_context, '{}'::jsonb) || jsonb_build_object(
    'target_pacing',
    COALESCE(execution_context->'target_pacing', '{}'::jsonb) || jsonb_build_object(
        $2::text,
        COALESCE(execution_context->'target_pacing'->$2::text, '{}'::jsonb)
          || $3::jsonb
          || jsonb_build_object($4::text,
                 COALESCE((execution_context->'target_pacing'->$2::text->>$4::text)::int, 0) + 1)))
 WHERE id = $1"""


async def record(conn: Any, scan_id: Any, url: str, decision: PacingDecision, *, outcome: str) -> None:
    """Keep the origin's latest pacing state and count the attempts it slowed/paused/stopped."""
    prefixes = origin_prefixes(url)
    if not prefixes:
        return
    state = {**decision.record(), "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    counter = {"slowed": "attempts_slowed", "paused": "attempts_paused",
               "stopped": "attempts_stopped"}.get(outcome)
    if counter is None:
        return
    await conn.execute(_RECORD_SQL, scan_id, prefixes[0], json.dumps(state), counter)


class TargetDegraded(RuntimeError):
    """The target stayed degraded for the whole pause: the attempt did not run."""


async def pace_attempt(
    pool: Any, scan_id: Any, url: str, *,
    wall_seconds: float,
    heartbeat: Callable[[], Awaitable[None]] | None = None,
    cancelled: Callable[[], Any] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> PacingDecision:
    """The rate factor for one external tool attempt; waits while the target is paused.

    Never raises for a database fault (pacing is advisory: the planned rate applies). Raises
    ``TargetDegraded`` when the target stayed degraded for the whole wait."""
    if pool is None or not scan_id:
        return NORMAL
    try:
        async with pool.acquire() as conn:
            decision = await origin_pacing(conn, scan_id, url)
            if decision.state == "slowed":
                await record(conn, scan_id, url, decision, outcome="slowed")
            if decision.state != "paused":
                return decision
            await record(conn, scan_id, url, decision, outcome="paused")
    except Exception:  # noqa: BLE001 - pacing never blocks a Scan on a database fault
        return NORMAL
    limit = max(0.0, min(MAX_PAUSE_SECONDS, float(wall_seconds) / 2))
    waited = 0.0
    while waited < limit:
        if cancelled is not None and cancelled():
            break
        step = min(PAUSE_POLL_SECONDS, limit - waited)
        await sleep(step)
        waited += step
        if heartbeat is not None:
            await heartbeat()
        try:
            async with pool.acquire() as conn:
                decision = await origin_pacing(conn, scan_id, url)
        except Exception:  # noqa: BLE001
            return NORMAL
        if decision.state != "paused":
            return decision
    try:
        async with pool.acquire() as conn:
            await record(conn, scan_id, url, decision, outcome="stopped")
    except Exception:  # noqa: BLE001
        pass
    raise TargetDegraded(
        f"target_degraded: {decision.reason}; the target did not recover within {int(waited)} s, "
        "so this attempt sent nothing (coverage is partial)")


#: The external tools whose rate pacing sets (port and TLS posture tools are not HTTP traffic).
PACED_TOOLS = frozenset({"nuclei", "katana", "katana_headless", "ffuf", "dalfox", "sqlmap", "httpx"})


async def pace_scanner_options(
    pool: Any, job_data: Mapping[str, Any], options: Mapping[str, Any], url: str, *,
    tool: str, wall_seconds: float,
    heartbeat: Callable[[], Awaitable[None]] | None = None,
    cancelled: Callable[[], Any] | None = None,
    error: type[Exception] = TargetDegraded,
) -> dict[str, Any]:
    """``options`` for one Scan tool attempt with its pacing factor (``_pacing_factor``) when
    the target is degraded; raises ``error`` when the target stayed down for the whole pause."""
    scan_id = job_data.get("scan_id")
    if str(tool or "").lower() not in PACED_TOOLS or not scan_id:
        return dict(options)
    try:
        decision = await pace_attempt(pool, scan_id, url, wall_seconds=wall_seconds,
                                      heartbeat=heartbeat, cancelled=cancelled)
    except TargetDegraded as exc:
        raise error(str(exc)) from exc
    if decision.factor < 1.0:
        return {**options, "_pacing_factor": decision.factor}
    return dict(options)
