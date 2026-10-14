"""Find a Scan's Redis job hash without a blocking walk of the keyspace (2.11).

Every Scan row records the job id its queue message and its ``job:<job_id>`` hash carry, so the hash
is read directly. A hash only counts as the Scan's when it names the Scan (its ``scan_id`` field, or
a key ending in the Scan id), as the earlier ``KEYS job:*`` walk required. For a Scan without such a
hash a fallback walks the keyspace with SCAN in bounded slices across ticks; until a complete pass
has been made since the Scan was first missed, its hash is "unknown", never "absent", so a slow
walk cannot make a live Scan look dead.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

JOB_KEY_PATTERN = "job:*"
DEFAULT_FALLBACK_KEYS_PER_TICK = 20_000
_PIPELINE_CHUNK = 500


class _Unknown:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "UNKNOWN"


UNKNOWN = _Unknown()


def _text(value: Any) -> str:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    return str(value)


def job_key(job_id: Any) -> str:
    return f"job:{job_id}"


def hash_names_scan(key: str, job_data: Mapping[str, Any], scan_id: str) -> bool:
    return str(job_data.get("scan_id") or "") == scan_id or key.endswith(scan_id)


def _pipelined(redis_client: Any, keys: list[str], call: Callable[[Any, str], Any]) -> list[Any]:
    results: list[Any] = []
    for start in range(0, len(keys), _PIPELINE_CHUNK):
        chunk = keys[start:start + _PIPELINE_CHUNK]
        pipeline_factory = getattr(redis_client, "pipeline", None)
        if callable(pipeline_factory):
            pipe = pipeline_factory(transaction=False)
            for key in chunk:
                call(pipe, key)
            results.extend(pipe.execute())
        else:
            results.extend(call(redis_client, key) for key in chunk)
    return results


class JobHashFallback:
    """The incremental SCAN walk for Scans whose recorded job hash does not name them.

    Owned by one process (the loop leader); a new leader starts a fresh walk, which only delays a
    verdict, never reverses one.
    """

    def __init__(self, *, keys_per_tick: int = DEFAULT_FALLBACK_KEYS_PER_TICK) -> None:
        self.keys_per_tick = max(1, int(keys_per_tick))
        self.cursor = 0
        self.passes = 0
        self._pending: dict[str, int] = {}  # scan id -> pass number when first missed
        self._found: dict[str, str] = {}

    def resolve(self, redis_client: Any, scan_ids: Iterable[str]) -> dict[str, Any]:
        """Return scan id -> key of a hash naming it, None (no hash after a full pass) or UNKNOWN."""
        wanted = {str(scan_id) for scan_id in scan_ids}
        self._pending = {sid: p for sid, p in self._pending.items() if sid in wanted}
        self._found = {sid: key for sid, key in self._found.items() if sid in wanted}
        for sid in wanted:
            if sid not in self._found and sid not in self._pending:
                self._pending[sid] = self.passes
        if self._pending:
            self._walk(redis_client)
        out: dict[str, Any] = {}
        for sid in wanted:
            if sid in self._found:
                out[sid] = self._found[sid]
            elif self.passes >= self._pending.get(sid, self.passes) + 2:
                # A complete pass started after this Scan was first missed: no hash names it.
                out[sid] = None
                self._pending.pop(sid, None)
            else:
                out[sid] = UNKNOWN
        return out

    def _walk(self, redis_client: Any) -> None:
        budget = self.keys_per_tick
        while budget > 0 and self._pending:
            cursor, raw_keys = redis_client.scan(
                cursor=self.cursor, match=JOB_KEY_PATTERN, count=min(1000, budget))
            keys = [_text(key) for key in raw_keys or []]
            budget -= max(1, len(keys))
            self._match(redis_client, keys)
            self.cursor = int(cursor or 0)
            if self.cursor == 0:
                self.passes += 1
                if self.passes >= max(self._pending.values(), default=0) + 2:
                    break

    def _match(self, redis_client: Any, keys: list[str]) -> None:
        if not keys:
            return
        by_suffix = [sid for sid in self._pending]
        scan_ids = _pipelined(redis_client, keys, lambda client, key: client.hget(key, "scan_id"))
        for key, raw in zip(keys, scan_ids):
            named = _text(raw) if raw is not None else ""
            if named in self._pending:
                self._found[named] = key
                self._pending.pop(named, None)
                continue
            for sid in by_suffix:
                if sid in self._pending and key.endswith(sid):
                    self._found[sid] = key
                    self._pending.pop(sid, None)
                    break


def load_scan_job_hashes(
    redis_client: Any,
    scans: Iterable[Mapping[str, Any]],
    *,
    decode: Callable[[Any], dict[str, str]],
    fallback: JobHashFallback | None,
) -> dict[str, Any]:
    """Map each Scan id to its decoded job hash, None (no hash names it) or UNKNOWN."""
    rows = [(str(scan["id"]), str(scan.get("job_id") or "")) for scan in scans]
    direct = [(sid, job_key(jid)) for sid, jid in rows if jid]
    hashes = _pipelined(redis_client, [key for _sid, key in direct], lambda client, key: client.hgetall(key))
    found: dict[str, Any] = {}
    for (sid, key), raw in zip(direct, hashes):
        data = decode(raw)
        if data and hash_names_scan(key, data, sid):
            found[sid] = data
    missing = [sid for sid, _jid in rows if sid not in found]
    if not missing:
        return found
    if fallback is None:
        found.update({sid: UNKNOWN for sid in missing})
        return found
    resolved = fallback.resolve(redis_client, missing)
    for sid in missing:
        verdict = resolved.get(sid, UNKNOWN)
        if isinstance(verdict, str):
            data = decode(redis_client.hgetall(verdict))
            found[sid] = data if data and hash_names_scan(verdict, data, sid) else UNKNOWN
        else:
            found[sid] = verdict
    return found


def find_hash_naming_scan(redis_client: Any, scan_id: str, *, max_keys: int) -> str | None:
    """The first ``job:*`` key whose hash names the Scan, within ``max_keys`` keys (non-blocking)."""
    cursor = 0
    seen = 0
    while seen < max_keys:
        cursor, raw_keys = redis_client.scan(cursor=cursor, match=JOB_KEY_PATTERN, count=min(1000, max_keys - seen))
        keys = [_text(key) for key in raw_keys or []]
        seen += max(1, len(keys))
        named = _pipelined(redis_client, keys, lambda client, key: client.hget(key, "scan_id"))
        for key, raw in zip(keys, named):
            if raw is not None and _text(raw) == scan_id:
                return key
        if int(cursor or 0) == 0:
            return None
    return None


CANCEL_FALLBACK_MAX_KEYS = 20_000


def hash_key_naming_scan(redis_client: Any, scan_id: str, job_id: Any, *, max_keys: int = CANCEL_FALLBACK_MAX_KEYS) -> str | None:
    """The job hash whose ``scan_id`` field names the Scan: its recorded job's hash, else the
    first found by a bounded walk (the earlier ``KEYS job:*`` loop, without blocking Redis)."""
    if job_id:
        key = job_key(job_id)
        named = redis_client.hget(key, "scan_id")
        if named is not None and _text(named) == scan_id:
            return key
    return find_hash_naming_scan(redis_client, scan_id, max_keys=max_keys)


# The running Scans one stale-check tick examines, oldest id first from where the last tick
# stopped, so a large running set is covered over several ticks instead of in one unbounded read.
STALE_CHECK_BATCH_SIZE = 500


async def fetch_running_scan_batch(conn: Any, state: dict[str, Any], *, limit: int = STALE_CHECK_BATCH_SIZE) -> list[Any]:
    """Running non-parent Scans after ``state['after']`` (wrapping to the start when exhausted)."""
    query = """
        SELECT id, job_id, scan_type, started_at, target_id, current_phase,
               progress, options, scan_role, parent_scan_id
        FROM scans
        WHERE status = 'running' AND started_at IS NOT NULL
          AND (scan_role IS NULL OR scan_role <> 'parent')
          AND ($1::uuid IS NULL OR id > $1::uuid)
        ORDER BY id
        LIMIT $2
    """
    rows = list(await conn.fetch(query, state.get("after"), int(limit)))
    if len(rows) < int(limit) and state.get("after") is not None:
        # The end was reached: wrap so the Scans before the cursor are examined this tick too.
        state["after"] = None
        seen = {row["id"] for row in rows}
        rows.extend(row for row in await conn.fetch(query, None, int(limit) - len(rows)) if row["id"] not in seen)
    state["after"] = rows[-1]["id"] if len(rows) >= int(limit) else None
    return rows


def heartbeat_verdict(
    job_data: Any,
    *,
    now: Any,
    started_at: Any,
    timeout_minutes: float,
    current_phase: str,
    progress: int,
) -> tuple[bool, str]:
    """(is_stale, reason) from the Scan's job hash (a dict, None, or UNKNOWN) and its claim age."""
    from datetime import datetime

    if job_data is UNKNOWN:
        # The hash may still exist beyond this tick's bounded walk: never reap on its absence.
        return False, ""
    if job_data:
        try:
            attempts = int(job_data.get("queue_delivery_attempts") or 0)
        except (TypeError, ValueError):
            attempts = 0
        reclaimed = (
            str(job_data.get("queue_reclaimed") or "").strip().lower() == "true" or attempts >= 2
        )
        heartbeat = job_data.get("heartbeat")
        if heartbeat:
            try:
                beat = datetime.fromisoformat(heartbeat.replace("Z", "+00:00").replace("+00:00", ""))
                age = (now - beat).total_seconds() / 60
            except (ValueError, TypeError):
                age = None
            if age is not None:
                if age <= timeout_minutes:
                    return False, ""
                if reclaimed:
                    return True, (
                        "Worker execution stopped after its queue lease was reclaimed "
                        f"(delivery attempt {attempts}); automatic replay was withheld "
                        "to avoid duplicate requests"
                    )
                return True, (
                    f"Worker stopped heartbeating for {age:.1f} minutes "
                    f"(timeout {timeout_minutes} min, "
                    f"last phase={current_phase or 'unknown'}, progress={progress})"
                )
    # No hash names the Scan, or its heartbeat is missing or unreadable: judge by claim age.
    scan_age = (now - started_at.replace(tzinfo=None)).total_seconds() / 60
    if scan_age > timeout_minutes:
        return True, (
            "The scan was claimed but no worker heartbeat was recorded; "
            f"claim age {scan_age:.1f} minutes (timeout {timeout_minutes} min)"
        )
    return False, ""


__all__ = [
    "JobHashFallback",
    "STALE_CHECK_BATCH_SIZE",
    "UNKNOWN",
    "fetch_running_scan_batch",
    "find_hash_naming_scan",
    "hash_key_naming_scan",
    "hash_names_scan",
    "heartbeat_verdict",
    "job_key",
    "load_scan_job_hashes",
]
