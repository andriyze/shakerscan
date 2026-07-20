"""Auto-draft typed invariant contracts from black-box observations (Phase 0: access_control).

Pure + dependency-free (stdlib + the equally-dep-free ``invariant_contracts``) so it is host-testable
and importable flat in the container. A proposer NEVER approves or promotes anything: every draft it
emits is ``status='draft'``, ``promotion_authority=False``. Approval is a human action through the
existing ``POST /targets/{id}/invariants/{id}/approve``; only an *approved* contract can route an
Explorer finding through the invariant binder (`_arsenal_dispatch_workflow` fetches
``WHERE status='approved'``). So a proposer can only ever create *candidate rules for review* — it
cannot widen the VERIFIED surface on its own.
"""
from __future__ import annotations

from typing import Any

import invariant_contracts

# Expectations that express an access-control policy the binder can prove (a role must be required for,
# or denied on, a route). "allow" is intentionally excluded — an allowed access is not a vulnerability.
_ACCESS_EXPECTATIONS: frozenset[str] = frozenset({"deny", "requires_role"})


def _row_get(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, TypeError, IndexError):
        return row.get(key) if hasattr(row, "get") else None


def propose_access_control_drafts(expectation_rows: Any) -> list[dict[str, Any]]:
    """Turn ``target_endpoint_expectations`` rows into access_control invariant DRAFTS.

    One draft per (kind, method, path, role, expected_access) with a concrete method/path/role and an
    expected_access in {deny, requires_role}. Each draft carries ``approval_errors`` (from the shared
    validator) so a caller can tell which are approvable, but they are ALL emitted as drafts — the
    operator decides. Malformed rows are skipped, never raised.
    """
    drafts: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for row in expectation_rows or []:
        expected = str(_row_get(row, "expected_access") or "").strip().lower()
        method = str(_row_get(row, "method") or "").strip().upper()
        path = str(_row_get(row, "path") or "").strip()
        role = str(_row_get(row, "principal_role") or _row_get(row, "subject_role") or "").strip()
        if expected not in _ACCESS_EXPECTATIONS or not method or not path or not role:
            continue
        raw = {
            "contract_kind": "access_control",
            "method": method,
            "path": path,
            "subject_role": role,
            "expected_access": expected,
            "title": f"{role} {expected.replace('_', ' ')} on {method} {path}"[:160],
        }
        try:
            contract = invariant_contracts.canonical_contract(raw)
        except (TypeError, ValueError):
            continue
        key = (
            contract.get("contract_kind"), contract.get("method"), contract.get("path"),
            contract.get("subject_role"), contract.get("expected_access"),
        )
        if key in seen:
            continue
        seen.add(key)
        errors = invariant_contracts.approval_errors({**contract, "status": "approved"})
        drafts.append({
            **contract,
            "status": "draft",
            "source": "auto_black_box",
            "promotion_authority": False,
            "approval_errors": errors,
            "approvable": not errors,
        })
    return drafts
