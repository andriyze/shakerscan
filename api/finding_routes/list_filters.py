"""GET /findings filters that are more than one SQL equality.

Severity takes several values (``severity=critical,high``). Proof is the canonical projection
(``finding_proof_fields``) over stored evidence and the latest retest: it is not a column, and a
second SQL predicate for it would drift from the badge the list shows. So a proof filter projects
every row the other filters leave and paginates the matches; past PROOF_FILTER_MAX_ROWS rows it
refuses instead of answering from a sample.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable, Mapping

SEVERITIES = ("critical", "high", "medium", "low", "info")
PROOF_STATES = ("verified", "suspected", "unverified")
PROOF_FILTER_MAX_ROWS = 20_000


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


def project_and_filter_by_proof(
    rows: Iterable[Mapping[str, Any]],
    proof_states: Iterable[str],
    project: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Rows (in their query order) whose projected proof_state is one of ``proof_states``."""
    wanted = set(proof_states)
    matches: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item.pop("total_count", None)
        item.update(project(item))
        if item.get("proof_state") in wanted:
            matches.append(item)
    return matches


# The host part of a URL or locator ("https://user@app.example.com:8443/x", "app.example.com:22").
_HOST_PATTERN = "^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)"


def host_in_domain_sql(column: str, param: str) -> str:
    """SQL: the host in ``column`` is the domain in ``param`` or one of its subdomains.

    A substring match let example.com select notexample.com; ``right`` avoids LIKE, whose ``_``
    wildcard a domain could contain.
    """
    host = f"substring(LOWER({column}) from '{_HOST_PATTERN}')"
    return f"({host} = LOWER({param}) OR right({host}, length({param}) + 1) = '.' || LOWER({param}))"
