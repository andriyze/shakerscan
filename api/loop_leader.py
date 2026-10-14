"""One leader per background loop across processes, through PostgreSQL advisory locks.

Several API replicas or workers start the same maintenance loops. Each loop asks
``LoopLeadership.lead(name)`` before a tick: the first process to take the loop's session advisory
lock keeps it, on one held connection, for as long as that connection lives, and only it runs the
tick. The others try again on their next tick, which costs one ``pg_try_advisory_lock`` query, so
leadership moves on its own when the leader's process or connection goes away.

The lock only stops duplicate work. Every loop it guards stays safe to run twice (row claims, SKIP
LOCKED, conditional updates), because a leader whose connection dies mid-tick can overlap the
next leader's first tick.
"""

from __future__ import annotations

import asyncio
import zlib
from typing import Any

# The first key of the two-key advisory lock form: one namespace for every loop lock, so a loop
# lock can never collide with the single-key schema lock taken at startup.
LOOP_LOCK_NAMESPACE = 0x53534C50  # "SSLP"


def loop_lock_key(name: str) -> int:
    """A stable signed 32-bit key for a loop name."""
    value = zlib.crc32(name.encode("utf-8")) & 0xFFFFFFFF
    return value - 0x1_0000_0000 if value >= 0x8000_0000 else value


class LoopLeadership:
    """The loop locks this process holds, on one connection taken from the pool."""

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._conn: Any = None
        self._held: set[str] = set()
        self._lock = asyncio.Lock()

    @property
    def held(self) -> frozenset[str]:
        return frozenset(self._held)

    async def _drop_connection(self) -> None:
        conn, self._conn = self._conn, None
        self._held.clear()
        if conn is None:
            return
        try:
            await self._pool.release(conn)
        except Exception:
            # A broken connection is discarded by the pool; its locks ended with its session.
            pass

    async def lead(self, name: str) -> bool:
        """Return True when this process leads ``name`` now (taking the lock when it is free)."""
        async with self._lock:
            if self._conn is not None:
                try:
                    await self._conn.fetchval("SELECT 1")
                except Exception:
                    await self._drop_connection()
            if self._conn is None:
                self._conn = await self._pool.acquire()
            if name in self._held:
                return True
            try:
                acquired = bool(await self._conn.fetchval(
                    "SELECT pg_try_advisory_lock($1::int, $2::int)",
                    LOOP_LOCK_NAMESPACE, loop_lock_key(name),
                ))
            except Exception:
                await self._drop_connection()
                raise
            if acquired:
                self._held.add(name)
            elif not self._held:
                # A follower holds no connection between attempts.
                await self._drop_connection()
            return acquired

    async def close(self) -> None:
        """Give up every loop lock (the session's locks end with its release)."""
        async with self._lock:
            conn = self._conn
            if conn is not None and self._held:
                try:
                    await conn.execute("SELECT pg_advisory_unlock_all()")
                except Exception:
                    pass
            await self._drop_connection()


_leaderships: dict[int, LoopLeadership] = {}


def leadership_for(pool: Any) -> LoopLeadership:
    """The one leadership of a pool in this process (the pool owns the held connection)."""
    leadership = _leaderships.get(id(pool))
    if leadership is None or leadership._pool is not pool:
        leadership = LoopLeadership(pool)
        _leaderships[id(pool)] = leadership
    return leadership


async def lead(pool: Any, name: str) -> bool:
    """True when this process should run ``name``'s tick. A database error means not now."""
    try:
        return await leadership_for(pool).lead(name)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        print(f"[leader] could not check leadership of {name}: {type(exc).__name__}", flush=True)
        return False


__all__ = ["LOOP_LOCK_NAMESPACE", "LoopLeadership", "lead", "leadership_for", "loop_lock_key"]
