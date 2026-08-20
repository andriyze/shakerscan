"""Shared multi-dimensional reservation ledger for Scan and Hunt execution."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Mapping
from uuid import uuid4


BUDGET_DIMENSIONS = frozenset({
    "http_requests",
    "browser_actions",
    "tcp_ports_attempted",
    "udp_ports_attempted",
    "hosts_attempted",
    "state_changing_requests",
    "tool_wall_seconds",
    "agent_actions",
    "active_actions",
    "device_fragility_points",
    "oob_interactions",
})


class BudgetError(ValueError):
    """Base class for invalid or unavailable budget operations."""


class BudgetExceeded(BudgetError):
    def __init__(self, shortages: Mapping[str, int]) -> None:
        self.shortages = dict(shortages)
        super().__init__(f"budget exhausted: {self.shortages}")


@dataclass(frozen=True)
class Reservation:
    id: str
    amounts: Mapping[str, int]


def _normalize_amounts(values: Mapping[str, int], *, dimensions: frozenset[str]) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for raw_kind, raw_amount in values.items():
        kind = str(raw_kind or "").strip()
        if kind not in dimensions:
            raise BudgetError(f"unknown budget dimension: {kind}")
        if isinstance(raw_amount, bool):
            raise BudgetError(f"budget amount for {kind} must be an integer")
        try:
            amount = int(raw_amount)
        except (TypeError, ValueError) as exc:
            raise BudgetError(f"budget amount for {kind} must be an integer") from exc
        if amount < 0:
            raise BudgetError(f"budget amount for {kind} must be non-negative")
        if amount:
            normalized[kind] = amount
    return normalized


def reserve_budget_snapshot(
    limits: Mapping[str, int], consumed: Mapping[str, int], charges: Mapping[str, int],
    *, dimensions: frozenset[str] = BUDGET_DIMENSIONS,
) -> dict[str, int]:
    """Atomically-computable persistent-ledger transition.

    Callers serialize the returned snapshot under their datastore lock before execution. This is
    the durable counterpart to :class:`BudgetLedger`, using the same dimensions and validation.
    """
    normalized_limits = _normalize_amounts(limits, dimensions=dimensions)
    normalized_consumed = _normalize_amounts(consumed, dimensions=dimensions)
    normalized_charges = _normalize_amounts(charges, dimensions=dimensions)
    undeclared = (set(normalized_consumed) | set(normalized_charges)) - set(normalized_limits)
    if undeclared:
        raise BudgetError(f"unlimited dimensions must be declared explicitly: {sorted(undeclared)}")
    shortages = {
        kind: normalized_consumed.get(kind, 0) + amount - normalized_limits[kind]
        for kind, amount in normalized_charges.items()
        if normalized_consumed.get(kind, 0) + amount > normalized_limits[kind]
    }
    if shortages:
        raise BudgetExceeded(shortages)
    result = {kind: normalized_consumed.get(kind, 0) for kind in normalized_limits}
    for kind, amount in normalized_charges.items():
        result[kind] += amount
    return result


class BudgetLedger:
    """Atomically reserves capacity before execution and reconciles actual use afterward."""

    def __init__(
        self, limits: Mapping[str, int], *, dimensions: frozenset[str] = BUDGET_DIMENSIONS
    ) -> None:
        self._dimensions = dimensions
        self._limits = _normalize_amounts(limits, dimensions=dimensions)
        self._reserved = {kind: 0 for kind in self._limits}
        self._consumed = {kind: 0 for kind in self._limits}
        self._reservations: dict[str, dict[str, int]] = {}
        self._lock = RLock()

    @property
    def limits(self) -> Mapping[str, int]:
        return MappingProxyType(dict(self._limits))

    def reserve(self, amounts: Mapping[str, int]) -> Reservation:
        requested = _normalize_amounts(amounts, dimensions=self._dimensions)
        unknown_limits = sorted(set(requested) - set(self._limits))
        if unknown_limits:
            raise BudgetError(f"unlimited dimensions must be declared explicitly: {unknown_limits}")
        with self._lock:
            shortages = {
                kind: amount - self.remaining(kind)
                for kind, amount in requested.items()
                if amount > self.remaining(kind)
            }
            if shortages:
                raise BudgetExceeded(shortages)
            reservation_id = str(uuid4())
            self._reservations[reservation_id] = requested
            for kind, amount in requested.items():
                self._reserved[kind] += amount
            return Reservation(reservation_id, MappingProxyType(dict(requested)))

    def commit(
        self, reservation: Reservation | str, actual: Mapping[str, int] | None = None
    ) -> Mapping[str, int]:
        reservation_id = reservation.id if isinstance(reservation, Reservation) else str(reservation)
        normalized_actual = (
            None if actual is None else _normalize_amounts(actual, dimensions=self._dimensions)
        )
        with self._lock:
            try:
                held = self._reservations.pop(reservation_id)
            except KeyError as exc:
                raise BudgetError("unknown or already reconciled reservation") from exc
            used = held if normalized_actual is None else normalized_actual
            if set(used) - set(held):
                self._reservations[reservation_id] = held
                raise BudgetError("actual usage contains dimensions not present in reservation")
            for kind, amount in used.items():
                if amount > held.get(kind, 0):
                    self._reservations[reservation_id] = held
                    raise BudgetError(f"actual usage exceeds reservation for {kind}")
            for kind, amount in held.items():
                self._reserved[kind] -= amount
                self._consumed[kind] += used.get(kind, 0)
            return MappingProxyType(dict(used))

    def release(self, reservation: Reservation | str) -> None:
        reservation_id = reservation.id if isinstance(reservation, Reservation) else str(reservation)
        with self._lock:
            try:
                held = self._reservations.pop(reservation_id)
            except KeyError as exc:
                raise BudgetError("unknown or already reconciled reservation") from exc
            for kind, amount in held.items():
                self._reserved[kind] -= amount

    def remaining(self, kind: str) -> int:
        if kind not in self._limits:
            raise BudgetError(f"unknown or undeclared budget dimension: {kind}")
        return self._limits[kind] - self._reserved[kind] - self._consumed[kind]

    def snapshot(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {
                "limits": dict(self._limits),
                "reserved": dict(self._reserved),
                "consumed": dict(self._consumed),
                "remaining": {kind: self.remaining(kind) for kind in self._limits},
            }
