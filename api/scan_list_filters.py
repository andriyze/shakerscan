"""WHERE clauses for GET /scans filters.

target_id is the exact filter: a target's scans, whatever URL spelling each used. The older
``target`` is a substring of the scan URL, which also matched other hosts and paths.
"""

from __future__ import annotations

import uuid
from typing import Any


def scan_list_filters(
    *,
    status: str | None = None,
    target_id: str | None = None,
    target: str | None = None,
    root_domain: str | None = None,
    created_within_days: int | None = None,
) -> tuple[str, list[Any]]:
    """The SQL fragment (parameters numbered from $1) and its values, in order.

    Raises ValueError for a target_id that is not a UUID.
    """
    clauses: list[str] = []
    values: list[Any] = []

    def add(sql: str, value: Any) -> None:
        values.append(value)
        clauses.append(sql.replace("$?", f"${len(values)}"))

    if status:
        add(" AND s.status = $?", status)
    if target_id:
        try:
            add(" AND s.target_id = $?", uuid.UUID(str(target_id)))
        except ValueError as exc:
            raise ValueError("target_id must be a UUID") from exc
    if target:
        add(" AND s.target_url ILIKE $?", f"%{target}%")
    if root_domain:
        add(" AND t.root_domain = $?", root_domain)
    if created_within_days:
        add(" AND s.created_at >= NOW() - INTERVAL '1 day' * $?", created_within_days)
    return "".join(clauses), values
