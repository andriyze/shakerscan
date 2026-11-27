"""Persist a leased worker failure through the normal reservation and receipt path."""
from __future__ import annotations
from datetime import datetime, timezone
import json
import uuid
from typing import Any
from runtime.budgets import BUDGET_DIMENSIONS

from .capability_reservations import terminalize_hunt_capability
from .device_traffic import settle_device_traffic
from .worker_accounting import worker_hunt_budget_accounting


def _object(value: Any) -> dict:
    return json.loads(value) if isinstance(value, str) else dict(value or {})


async def settle_worker_failure(pool: Any, store: Any, persisted: Any, *, result: dict,
                                 target: Any, policy: Any, spec: Any,
                                 execution_started: bool) -> dict:
    """Release unspent preparation holds; retain the hold if execution is uncertain.

    A stale/redelivered worker cannot overwrite a different lease or a completed
    receipt. A transaction failure leaves recovery to the existing lease sweeper.
    """
    if persisted is None or result.get("durable_budget_settled") is True:
        return result
    record = persisted.record
    if record.status != "running":
        return result
    async with pool.acquire() as conn:
        async with conn.transaction():
            run = await conn.fetchrow("SELECT * FROM hunt_runs WHERE id=$1 FOR UPDATE", uuid.UUID(record.owner_id))
            latest = await store.load(conn, record.reservation_id, for_update=True)
            if (not run or latest is None or latest.record.state_digest != record.state_digest
                    or latest.record.status != "running" or latest.record.worker_id != record.worker_id):
                return result
            actual = dict(record.requested) if execution_started else {
                name: (min(1, amount) if name == "agent_actions" else 0)
                for name, amount in record.requested.items()}
            finished = datetime.now(timezone.utc).isoformat()
            receipt_id = str(uuid.uuid4())
            terminal, receipt = terminalize_hunt_capability(record,
                action_digest=latest.action_digest, capability_name=spec.name,
                adapter_name=spec.adapter, adapter_version=spec.adapter_version,
                parser_version=spec.output_schema, target_id=target.target_id,
                target_kind=target.target_kind, capability_input={}, action_status="failed",
                actual_budget=actual, worker_id=record.worker_id,
                started_at=(record.started_at or datetime.now(timezone.utc)).isoformat(),
                finished_at=finished, receipt_id=receipt_id,
                scope_receipt_id=target.scope_receipt_id, approval_receipt_id=policy.approval_receipt_id,
                result={"ok": False, "error": result.get("error"), "execution_started": execution_started})
            used = _object(run["budget_used_json"])
            ledger = {name: int(used.get(name) or 0) for name in BUDGET_DIMENSIONS}
            reconciled = terminal.reconcile_consumed(ledger)
            await settle_device_traffic(conn, run, record.requested, actual, status="failed")
            await store.persist_terminal(conn, previous=latest, terminal=terminal,
                ledger_after_settlement=reconciled, receipt=receipt)
            used.update(reconciled)
            result = {**result, "ok": False, "execution_started": execution_started,
                "execution_uncertain": execution_started,
                "reservation_id": record.reservation_id, "budget_reservation_id": record.reservation_id,
                "budget_reservation_state": terminal.status, "receipt_id": receipt_id,
                "receipt": receipt.public_dict(), "durable_budget_settled": True,
                "budget_consumed": actual, "used_after_reconciliation": reconciled,
                "budget_accounting": worker_hunt_budget_accounting(record.requested, actual, reconciled,
                    reservation_id=record.reservation_id, settlement_status="succeeded",
                    charge_basis="conservative_full_reservation" if execution_started else "not_executed")}
            await conn.execute("UPDATE hunt_runs SET budget_used_json=$2, updated_at=NOW() WHERE id=$1",
                uuid.UUID(record.owner_id), json.dumps(used))
            updated = await conn.execute("""UPDATE hunt_actions SET status='failed',
                result_summary=$3, receipt_id=$4, completed_at=NOW()
                WHERE id=$1 AND hunt_run_id=$2 AND status='running'""",
                uuid.UUID(latest.action_id), uuid.UUID(record.owner_id), json.dumps(result), uuid.UUID(receipt_id))
            if not str(updated).endswith(" 1"):
                raise RuntimeError("worker action changed before failure settlement")
    return result
