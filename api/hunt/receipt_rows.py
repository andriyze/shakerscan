"""The rows ``query(kind="receipts")`` returns: the receipt, the Hunt action it settled, and why it failed.

A receipt row named only its own id, tool, status and arguments. A failed row therefore told a
planner that something failed and nothing else: not which of its actions it was, nor whether the
request was refused, timed out or never got a response, so it could neither correlate the row with
its own call nor decide whether a retry could work. Each row now carries ``action_id`` (the Hunt
action that recorded it, when one did) and a row that did not succeed carries ``error``: the
action's own error token, bounded and redacted. Response bodies are never part of it.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping
import uuid

try:
    from redaction import redact_text
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import redact_text


#: Statuses that say the tool did not do what it was asked; such a row carries ``error``.
UNSUCCESSFUL = frozenset({"failed", "timeout", "parser_error"})
#: An error is a short token or sentence, never a response body.
MAX_ERROR_CHARS = 240


def _json(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def bounded_error(value: Any) -> str | None:
    """One line of at most MAX_ERROR_CHARS, with secrets and URL credentials redacted."""
    if value is None or isinstance(value, (dict, list, tuple)):
        return None
    text = " ".join(str(value).split())
    if not text:
        return None
    text = str(redact_text(text))
    return text if len(text) <= MAX_ERROR_CHARS else text[:MAX_ERROR_CHARS - 1] + "…"


def _receipt_error(metadata: Mapping[str, Any], status: str) -> str | None:
    """The error the receipt itself recorded, when its action has none."""
    errors = metadata.get("parser_errors")
    if isinstance(errors, list):
        for item in errors:
            if (found := bounded_error(item)) is not None:
                return found
    if status == "timeout":
        return "timeout"
    return None


async def project_receipt_rows(conn: Any, rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Add ``action_id`` to every row and ``error`` to an unsuccessful one; drop the raw metadata."""
    projected: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        metadata = _json(row.pop("metadata_json", None))
        metadata = metadata if isinstance(metadata, Mapping) else {}
        action = _uuid(metadata.get("hunt_action_id"))
        row["action_id"] = str(action) if action else None
        projected.append(row)
        row["_metadata"] = metadata
    # The action row holds the result the planner was shown, error included. Read by primary key
    # for receipts that name their action, else by the receipt link within the receipt's Hunt.
    by_action = [_uuid(row["action_id"]) for row in projected if row["action_id"]]
    unlinked = [row for row in projected if not row["action_id"] and _uuid(row.get("hunt_id"))]
    actions: dict[str, Mapping[str, Any]] = {}
    by_receipt: dict[str, Mapping[str, Any]] = {}
    if by_action or unlinked:
        found = await conn.fetch(
            "SELECT id, receipt_id, result_summary FROM hunt_actions "
            "WHERE id = ANY($1::uuid[]) "
            "OR (hunt_run_id = ANY($2::uuid[]) AND receipt_id = ANY($3::uuid[]))",
            [value for value in by_action if value],
            [_uuid(row["hunt_id"]) for row in unlinked],
            [_uuid(row["id"]) for row in unlinked if _uuid(row.get("id"))],
        )
        for item in found:
            actions[str(item["id"])] = item
            if item["receipt_id"] is not None:
                by_receipt[str(item["receipt_id"])] = item
    for row in projected:
        metadata = row.pop("_metadata")
        action = actions.get(row["action_id"] or "") or by_receipt.get(str(row.get("id")))
        if action is not None and not row["action_id"]:
            row["action_id"] = str(action["id"])
        status = str(row.get("status") or "")
        if status in UNSUCCESSFUL:
            summary = _json(action["result_summary"]) if action is not None else None
            error = bounded_error(summary.get("error")) if isinstance(summary, Mapping) else None
            row["error"] = error or _receipt_error(metadata, status)
    return projected
