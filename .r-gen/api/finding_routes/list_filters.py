"""GET /findings filters that are more than one SQL equality.

Severity takes several values (``severity=critical,high``). Proof is the canonical projection
(``finding_proof_fields``) over stored evidence and the latest retest. The proof filter applies its
exact SQL form (``proof_sql.py``, held to the Python projection by a real-PostgreSQL parity test),
so the database paginates and counts it; the rare row the SQL cannot decide is projected in Python
first and joins the clause by id (``list_query.resolved_proof_filter``).
"""

from __future__ import annotations

from typing import Iterable, Literal

# The finding statuses the API writes (PATCH /findings/{id}, POST /findings/bulk, the scan
# merge). GET /findings matches its status filter literally, so a value outside this set
# (status=open) used to answer total 0 instead of an error.
FindingStatus = Literal["active", "resolved", "false_positive", "accepted_risk"]
# The filters' accepted values, published as enums in the schema (each answered 422 before by
# a regular expression, which the schema showed as a free string).
FindingSourceType = Literal[
    "dast", "device", "ai", "ai_gate", "ai_session", "deep_hunt", "autonomous", "model_intake", "asm", "manual",
]
VerificationVerdict = Literal[
    "exploited", "likely_vulnerable", "blocked_by_security", "out_of_scope_internal", "false_positive",
    "likely_fixed", "inconclusive", "error",
]

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


# The host part of a URL or locator ("https://user@app.example.com:8443/x", "app.example.com:22").
_HOST_PATTERN = "^(?:[a-z][a-z0-9+.-]*://)?(?:[^@/]*@)?([^/:?#]+)"


def host_in_domain_sql(column: str, param: str) -> str:
    """SQL: the host in ``column`` is the domain in ``param`` or one of its subdomains.

    A substring match let example.com select notexample.com; ``right`` avoids LIKE, whose ``_``
    wildcard a domain could contain.
    """
    host = f"substring(LOWER({column}) from '{_HOST_PATTERN}')"
    return f"({host} = LOWER({param}) OR right({host}, length({param}) + 1) = '.' || LOWER({param}))"
