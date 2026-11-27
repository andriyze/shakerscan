"""A refused dispatch always answers its job, even when its settlement fails (D39 follow-up).

``settle_rejected_dispatch`` runs inside the worker's ``except HuntDispatchRejected`` handler. If
it raised there, the job was left without a result and the worker reported a fault instead of the
refusal. The pool below is a labelled double that fails the way an unreachable database does.
"""
from __future__ import annotations

import asyncio
import uuid

from hunt.dispatch_authority import HuntDispatchRejected, settle_rejected_dispatch


class UnreachablePool:
    """Labelled double: every acquire fails as an unreachable PostgreSQL does."""

    def acquire(self):
        raise ConnectionRefusedError("database unreachable")


class BrokenTransactionPool:
    """Labelled double: the connection opens and the first query fails."""

    def acquire(self):
        pool = self

        class Acquired:
            async def __aenter__(self):
                return pool

            async def __aexit__(self, *_exc):
                return False

        return Acquired()

    def transaction(self):
        class Transaction:
            async def __aenter__(self):
                return None

            async def __aexit__(self, *_exc):
                return False

        return Transaction()

    async def fetchrow(self, *_args, **_kwargs):
        raise RuntimeError("relation changed")


JOB = {"hunt_id": str(uuid.uuid4()), "action_id": str(uuid.uuid4()),
       "budget_reservation_id": str(uuid.uuid4()), "action_digest": "a" * 64}


def test_a_settlement_that_cannot_reach_the_database_still_answers_the_job():
    for pool in (UnreachablePool(), BrokenTransactionPool()):
        result = asyncio.run(settle_rejected_dispatch(
            pool, JOB, HuntDispatchRejected("Hunt action authority rejected at dispatch: x"), job_id="job-1",
        ))
        assert result == {
            "job_id": "job-1", "status": "failed",
            "error": "contract:Hunt action authority rejected at dispatch: x", "durable_budget_settled": False,
        }, pool
