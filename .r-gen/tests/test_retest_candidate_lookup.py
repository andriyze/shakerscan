"""A completed finding retest links to its Deep Hunt candidate without crashing."""
import asyncio
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from worker_handlers.retest_candidates import find_retest_candidate  # noqa: E402


class TextStrictConnection:
    """Binds parameters as asyncpg does: a ::text parameter refuses a UUID."""

    def __init__(self):
        self.bound = []

    async def fetchrow(self, query, *args):
        if "$1::text" in query and args[0] is not None and not isinstance(args[0], str):
            raise TypeError(f"expected str, got {type(args[0]).__name__}")
        self.bound.append(args)
        return {"id": "candidate", "verifier_contract_id": None}


def test_a_finding_retest_binds_its_finding_id_as_text():
    # The verification row carries a UUID; passing it straight through crashed every finding
    # retest after its result was saved, so the candidate verdict, ASM campaign completion and
    # the retest status update never ran.
    finding_id, candidate_id = uuid.uuid4(), uuid.uuid4()
    conn = TextStrictConnection()
    row = asyncio.run(find_retest_candidate(conn, {"finding_id": finding_id, "candidate_id": candidate_id}))
    assert row["id"] == "candidate"
    assert conn.bound == [(str(finding_id), candidate_id)]


def test_a_candidate_only_retest_binds_no_finding_id():
    candidate_id = uuid.uuid4()
    conn = TextStrictConnection()
    asyncio.run(find_retest_candidate(conn, {"finding_id": None, "candidate_id": candidate_id}))
    assert conn.bound == [(None, candidate_id)]


def test_the_retest_worker_uses_the_shared_lookup():
    worker = (ROOT / "api" / "worker.py").read_text()
    assert "candidate = await find_retest_candidate(conn, verification)" in worker
    assert "verification[\"finding_id\"], verification.get(\"candidate_id\")" not in worker
