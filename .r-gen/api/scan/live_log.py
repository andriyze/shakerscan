"""A Scan's live activity lines in Redis, with an absolute sequence so a poller reads only new lines.

The lines live in ``scan:{id}:logs`` (a capped list: the oldest lines are trimmed away) and the
number of lines ever appended in ``scan:{id}:logs:seq``. Every writer appends through
``append_scan_log_lines``, which changes both in one MULTI, so the last line in the list always
has sequence number ``seq`` and the list's first line ``seq - LLEN + 1``. A reader takes both in one
MULTI too (``read_scan_log``), so the numbering it reports is consistent with the lines it returns.

``after_seq=k`` returns only the lines numbered above ``k`` (at most ``limit``, the newest ones);
``truncated`` says lines were missed (trimmed before this poll, or more new lines than ``limit``),
in which case the client replaces its view with the returned tail instead of appending. A list
written by an engine without the counter (or a counter that expired before the list) has no
numbering: ``seq_supported`` is false and the reader returns the tail as before.
"""
from __future__ import annotations

from typing import Any, Iterable

LOG_KEY = "scan:{scan_id}:logs"
SEQ_KEY = "scan:{scan_id}:logs:seq"


def log_key(scan_id: Any) -> str:
    return LOG_KEY.format(scan_id=scan_id)


def seq_key(scan_id: Any) -> str:
    return SEQ_KEY.format(scan_id=scan_id)


def append_scan_log_lines(redis_client: Any, scan_id: Any, lines: Iterable[Any], *, tail: int,
                          ttl_seconds: int) -> None:
    """Append ``lines`` (capped list of ``tail`` lines) and advance the sequence, atomically."""
    values = list(lines)
    if not values:
        return
    pipe = redis_client.pipeline(transaction=True)
    pipe.rpush(log_key(scan_id), *values)
    pipe.ltrim(log_key(scan_id), -int(tail), -1)
    pipe.expire(log_key(scan_id), int(ttl_seconds))
    pipe.incrby(seq_key(scan_id), len(values))
    pipe.expire(seq_key(scan_id), int(ttl_seconds))
    pipe.execute()


def _int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value.decode() if isinstance(value, bytes) else value)
    except (TypeError, ValueError):
        return None


def read_scan_log(redis_client: Any, scan_id: Any, *, limit: int, after_seq: int | None = None) -> dict[str, Any]:
    """The tail (or the lines after ``after_seq``) with their numbering; see the module notes."""
    pipe = redis_client.pipeline(transaction=True)
    pipe.get(seq_key(scan_id))
    pipe.llen(log_key(scan_id))
    pipe.lrange(log_key(scan_id), -int(limit), -1)
    raw_seq, length, tail = pipe.execute()
    seq = _int(raw_seq)
    length = int(length or 0)
    tail = list(tail or [])
    if seq is None or seq < length:
        # No numbering for this list (an older writer, or the counter expired first).
        return {"lines": tail, "seq_supported": False, "next_seq": None, "first_seq": None,
                "truncated": False}
    first_available = seq - length + 1
    if after_seq is None:
        lines, truncated = tail, False
    elif after_seq > seq:
        # After a reset the caller needs the current tail, not an empty successful delta.
        lines, truncated = tail, True
    elif after_seq == seq:
        lines, truncated = [], False
    else:
        wanted = seq - after_seq
        lines = tail[-wanted:] if wanted <= len(tail) else tail
        truncated = after_seq + 1 < first_available or wanted > len(tail)
    return {
        "lines": lines,
        "seq_supported": True,
        "next_seq": seq,
        "first_seq": (seq - len(lines) + 1) if lines else seq + 1,
        "truncated": truncated,
    }


__all__ = ["append_scan_log_lines", "log_key", "read_scan_log", "seq_key"]
