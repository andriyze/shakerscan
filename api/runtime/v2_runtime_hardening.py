"""Fail-closed compatibility hardening for V2 runtime contracts.

These shims close migration defects in already-published classes without changing legacy queue
or persistence plumbing. They are intentionally idempotent and narrowly scoped. Native V2
repositories should eventually move each method into its owning module and remove this file.
"""

from __future__ import annotations

from datetime import datetime, timezone
import inspect
import re
from typing import Any, Mapping
import urllib.parse

from .budgets import reserve_budget_snapshot
from . import budget_reservations as _reservations
from . import receipts as _receipts


_APPLIED_MARKER = "_shakerscan_v2_hardening_applied"
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

_TERMINAL_RECEIPT_STATUSES = frozenset({
    "blocked", "cancelled", "completed", "failed", "partial", "success", "succeeded",
    "timed_out",
})
_SUCCESS_RECEIPT_STATUSES = frozenset({"completed", "success", "succeeded"})


# This module patches the receipt redactor at import time, so it must decide
# "is this key a secret" exactly as the receipt module does. It used to answer with
# its own copy of the key-set; the two drifted, and the copy here is what masked the
# TLS certificate block. There is now one implementation, imported from receipts.
_key_is_sensitive = _receipts.key_is_sensitive


def _redact_url_path(path: str) -> str:
    try:
        from scanner_tools.request_replay import redact_url_path
    except (ImportError, AttributeError):
        return str(path or "/")
    return redact_url_path(path)


def _redact_string(value: str) -> str:
    text = str(value)
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc:
        query = urllib.parse.urlencode([
            (str(name)[:200], "<redacted>")
            for name, _item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        ])
        text = urllib.parse.urlunsplit((
            parsed.scheme,
            parsed.netloc,
            _redact_url_path(parsed.path or "/"),
            query,
            "",
        ))
    for index, pattern in enumerate(_receipts._INLINE_SECRET_PATTERNS):
        if index == 0:
            text = pattern.sub(r"\1 ***", text)
        elif index == 3:
            text = pattern.sub(r"\1***@", text)
        else:
            text = pattern.sub(r"\1***", text)
    return text


def _redact_receipt_value(value: Any, *, key: str | None = None) -> Any:
    if key and _key_is_sensitive(key, item=value):
        return "***" if value not in (None, "", [], {}, ()) else value
    if isinstance(value, Mapping):
        return {
            str(item_key): _redact_receipt_value(item_value, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_redact_receipt_value(item) for item in value]
    if isinstance(value, bytes):
        import hashlib
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "size": len(value)}
    if isinstance(value, str):
        return _redact_string(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_string(str(value))


def _reserve_against(
    self: Any,
    *,
    limits: Mapping[str, int],
    consumed: Mapping[str, int],
    now: datetime | None = None,
    lease_seconds: int = 120,
) -> tuple[Any, dict[str, int]]:
    self._require_status("requested")
    held = reserve_budget_snapshot(limits, consumed, self.requested)
    return self.reserve(now=now, lease_seconds=lease_seconds), held


def apply_runtime_hardening() -> None:
    reservation_cls = _reservations.DurableBudgetReservation
    if not hasattr(reservation_cls, "reserve_against"):
        setattr(reservation_cls, "reserve_against", _reserve_against)

    if not getattr(reservation_cls.commit, _APPLIED_MARKER, False):
        original_commit = reservation_cls.commit

        def commit_with_lease_check(
            self: Any,
            *,
            actual: Mapping[str, int],
            execution_receipt_hash: str,
            now: datetime | None = None,
            worker_id: str | None = None,
        ) -> Any:
            timestamp = now or datetime.now(timezone.utc)
            if timestamp.tzinfo is None:
                raise _reservations.ReservationTransitionError(
                    "reservation timestamps must be timezone-aware"
                )
            timestamp = timestamp.astimezone(timezone.utc)
            if self.lease_expires_at and timestamp > self.lease_expires_at:
                raise _reservations.ReservationTransitionError(
                    "running reservation lease expired before commit"
                )
            if worker_id is not None and str(worker_id).strip() != self.worker_id:
                raise _reservations.ReservationTransitionError(
                    "only the owning worker may commit the reservation"
                )
            arguments = {
                "actual": actual,
                "execution_receipt_hash": execution_receipt_hash,
                "now": timestamp,
            }
            if "worker_id" in inspect.signature(original_commit).parameters:
                arguments["worker_id"] = worker_id or self.worker_id
            return original_commit(self, **arguments)

        setattr(commit_with_lease_check, _APPLIED_MARKER, True)
        setattr(reservation_cls, "commit", commit_with_lease_check)

    _receipts._redact_string = _redact_string
    _receipts.redact_receipt_value = _redact_receipt_value

    receipt_cls = _receipts.CapabilityReceipt
    if not getattr(receipt_cls.__post_init__, _APPLIED_MARKER, False):
        original_post_init = receipt_cls.__post_init__

        def hardened_post_init(self: Any) -> None:
            original_post_init(self)
            state = self.budget_reservation_state
            status = self.status
            if state == "released" and any(self.budget_consumed.values()):
                raise ValueError("released budget reservation cannot report consumed budget")
            if state == "released" and status in _SUCCESS_RECEIPT_STATUSES:
                raise ValueError("successful receipt requires a committed budget reservation")
            if state == "failed" and status in _SUCCESS_RECEIPT_STATUSES:
                raise ValueError("successful receipt cannot reference a failed budget reservation")
            if status in _TERMINAL_RECEIPT_STATUSES and not self.finished_at:
                raise ValueError("terminal capability receipt requires finished_at")
            object.__setattr__(self, "artifact_refs", tuple(
                dict.fromkeys(_redact_string(str(item)) for item in self.artifact_refs if str(item))
            ))

        setattr(hardened_post_init, _APPLIED_MARKER, True)
        setattr(receipt_cls, "__post_init__", hardened_post_init)


apply_runtime_hardening()
