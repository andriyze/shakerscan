"""Find-or-create of a target row that two requests may run at the same moment.

Target inserts upsert on ``canonical_key`` (``ON CONFLICT (canonical_key) DO ...``). PostgreSQL
resolves a conflict only on that arbiter index: ``targets.url`` is UNIQUE too, and when two
transactions insert the same URL together, the second one waits on the first in the ``url`` index
and then fails with a unique violation instead of taking the conflict path. A caller saw that as
409 "Target already exists" (POST /targets) or a 500 (a Scan submission), although the target it
asked for now exists.

``fetch_target_upsert`` runs the upsert in a savepoint (or its own transaction outside one) and,
after such a violation, runs it again: by then the other row is committed, so the arbiter sees it
and the statement takes its ``ON CONFLICT`` path, exactly as a later request would.
"""

from __future__ import annotations

from typing import Any

import asyncpg

#: The first try plus retries; each retry follows a committed competing insert.
ATTEMPTS = 3


async def fetch_target_upsert(conn: Any, query: str, *args: Any, method: str = "fetchrow") -> Any:
    """``conn.<method>(query, *args)`` for a target upsert, retried after a concurrent insert."""
    for attempt in range(ATTEMPTS):
        try:
            async with conn.transaction():  # a savepoint inside the caller's transaction
                return await getattr(conn, method)(query, *args)
        except asyncpg.UniqueViolationError:
            if attempt == ATTEMPTS - 1:
                raise
    raise AssertionError("unreachable")  # pragma: no cover


__all__ = ["ATTEMPTS", "fetch_target_upsert"]
