"""GET /findings filters that are more than one SQL equality.

Severity takes several values (``severity=critical,high``). Proof is the canonical projection
(``finding_proof_fields``) over stored evidence and the latest retest. The proof filter applies its
exact SQL form (``proof_sql.py``, held to the Python projection by a real-PostgreSQL parity test),
so the database paginates and counts it; a row the SQL cannot decide sends the request through
``stream_proof_matches``, which projects in Python from a cursor without loading the result set.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

SEVERITIES = ("critical", "high", "medium", "low", "info")
PROOF_STATES = ("verified", "suspected", "unverified")


def parse_choice_list(value: str | None, allowed: Iterable[str], name: str) -> list[str] | None:
    """``a,b`` -> ``['a', 'b']``; None or blank -> None. Unknown values raise ValueError."""
    if value is None or not str(value).strip():
        return None
    allowed = tuple(allowed)
    chosen: list[str] = []
    for part in str(value).split(","):
        item = part.strip().lower()
        if not item:
            continue
        if item not in allowed:
            raise ValueError(
                f"{name} must be one or more of {', '.join(allowed)}, comma-separated; got {part.strip()!r}"
            )
        if item not in chosen:
            chosen.append(item)
    return chosen or None


async def stream_proof_matches(
    conn: Any,
    query: str,
    params: list,
    proof_states: Iterable[str],
    project: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    keep: int,
) -> tuple[list[dict[str, Any]], int]:
    """Exact proof filter by projection, streamed: the first ``keep`` matches and the match count.

    Rows come from a server-side cursor in query order, so memory holds the requested prefix and
    one fetch batch, whatever the number of rows the other filters leave.
    """
    wanted = set(proof_states)
    kept: list[dict[str, Any]] = []
    total = 0
    async with conn.transaction():
        async for row in conn.cursor(query, *params, prefetch=500):
            item = dict(row)
            item.pop("total_count", None)
            item.update(project(item))
            if item.get("proof_state") in wanted:
                if total < keep:
                    kept.append(item)
                total += 1
    return kept, total


# The host part of a URL or locator ("https://user@app.example.com:8443/x", "app.example.com:22").
_HOST_PATTERN = "^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)"


def host_in_domain_sql(column: str, param: str) -> str:
    """SQL: the host in ``column`` is the domain in ``param`` or one of its subdomains.

    A substring match let example.com select notexample.com; ``right`` avoids LIKE, whose ``_``
    wildcard a domain could contain.
    """
    host = f"substring(LOWER({column}) from '{_HOST_PATTERN}')"
    return f"({host} = LOWER({param}) OR right({host}, length({param}) + 1) = '.' || LOWER({param}))"
