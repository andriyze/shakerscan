"""PATCH /findings/{id}: the analyst verdict can be cleared and the response is what was stored.

A cleared verdict (``{"analyst_verdict": null}``) used to answer null while COALESCE kept the old
value, and the response echoed the request instead of the row. The unit tests pin the request
semantics and the read-back response with a fake connection; the PostgreSQL test runs the route's
own statement on the real schema when FINDING_VERDICT_TEST_DATABASE_URL names a disposable
localhost/shakerscan_verdict_test database.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import sys
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402

FINDING = uuid.UUID("44444444-4444-4444-8444-444444444444")
TARGET = uuid.UUID("11111111-1111-4111-8111-111111111111")


def test_an_explicit_null_clears_and_an_absent_verdict_keeps():
    assert findings_router.FindingUpdate.model_validate(
        {"status": "active", "analyst_verdict": None}
    ).verdict_change() == "clear"
    assert findings_router.FindingUpdate.model_validate(
        {"status": "active"}
    ).verdict_change() == "keep"
    assert findings_router.FindingUpdate.model_validate(
        {"status": "active", "analyst_verdict": "true_positive"}
    ).verdict_change() == "set"


class _StoredRowConn:
    """Answers the update with the row the database would hold, not with the request."""

    def __init__(self, row):
        self.row = row
        self.calls = []

    async def fetchrow(self, query, *args):
        self.calls.append((query, args))
        return self.row

    async def execute(self, query, *args):
        return "UPDATE 0"


def _run_update(monkeypatch, conn, body):
    @asynccontextmanager
    async def acquire():
        yield conn

    class _Pool:
        def acquire(self):
            return acquire()

    monkeypatch.setattr(findings_router, "_pool_provider", lambda: _Pool())
    return asyncio.run(findings_router.update_finding(
        str(FINDING), findings_router.FindingUpdate.model_validate(body), scan_id=None,
    ))


def test_the_response_reports_the_stored_verdict_and_the_status_change(monkeypatch):
    stored = {
        "id": FINDING, "target_id": None, "device_target_id": None,
        "status": "active", "previous_status": "false_positive",
        "analyst_verdict": "true_positive",
        "analyst_verdict_at": datetime(2026, 10, 7, tzinfo=timezone.utc),
    }
    conn = _StoredRowConn(stored)
    response = _run_update(monkeypatch, conn, {"status": "active", "analyst_verdict": None})

    # Whatever the request asked, the answer is the row: a response of null over a kept value
    # was the defect.
    assert response["analyst_verdict"] == "true_positive"
    assert response["status"] == "active"
    assert response["previous_status"] == "false_positive"
    assert response["status_changed"] is True
    _query, args = conn.calls[-1]
    assert args[-1] == "clear"


# --- the route's statement on real PostgreSQL ------------------------------------------------

DSN = os.environ.get("FINDING_VERDICT_TEST_DATABASE_URL")
postgres = pytest.mark.skipif(
    not DSN, reason="Requires an explicit disposable findings PostgreSQL database",
)


def _with_database(scenario):
    asyncpg = pytest.importorskip("asyncpg")
    dsn = require_disposable_database(DSN or "", "shakerscan_verdict_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
            # The verdict columns are added by the API's startup migration (retest_contract).
            await conn.execute(
                "ALTER TABLE findings ADD COLUMN IF NOT EXISTS analyst_verdict TEXT, "
                "ADD COLUMN IF NOT EXISTS analyst_verdict_at TIMESTAMPTZ, "
                "ADD COLUMN IF NOT EXISTS analyst_verdict_notes TEXT"
            )
            await conn.execute(
                "INSERT INTO targets (id, url, name) VALUES ($1, 'https://app.example.test', 'app')",
                TARGET,
            )
            await conn.execute(
                """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, status, source)
                   VALUES ($1, $2, 'fp', 'f', 'info', 'nuclei', 'false_positive', 'dast')""",
                FINDING, TARGET,
            )
            return await scenario(conn)
        finally:
            await conn.close()

    return asyncio.run(go())


async def _patch(conn, body):
    request = findings_router.FindingUpdate.model_validate(body)
    row = await conn.fetchrow(
        findings_router.FINDING_UPDATE_SQL, request.status, request.notes,
        request.analyst_verdict, FINDING, request.verdict_change(),
    )
    stored = await conn.fetchrow(
        "SELECT status, analyst_verdict, analyst_verdict_at, analyst_verdict_notes FROM findings WHERE id=$1",
        FINDING,
    )
    return findings_router.finding_update_response(row), dict(stored)


@postgres
def test_a_verdict_is_recorded_kept_and_cleared_on_the_real_schema():
    async def scenario(conn):
        response, stored = await _patch(
            conn, {"status": "active", "analyst_verdict": "true_positive", "notes": "confirmed"},
        )
        assert stored["analyst_verdict"] == "true_positive" and stored["analyst_verdict_at"]
        assert response["analyst_verdict"] == "true_positive"
        assert response["previous_status"] == "false_positive" and response["status_changed"] is True

        # A status-only update leaves the verdict alone.
        response, stored = await _patch(conn, {"status": "resolved"})
        assert stored["analyst_verdict"] == "true_positive"
        assert response["analyst_verdict"] == "true_positive"

        # An explicit null clears the verdict and its time, keeps its notes, and says so.
        response, stored = await _patch(conn, {"status": "resolved", "analyst_verdict": None})
        assert stored["analyst_verdict"] is None
        assert stored["analyst_verdict_at"] is None
        assert stored["analyst_verdict_notes"] == "confirmed"
        assert response["analyst_verdict"] is None and response["analyst_verdict_at"] is None
        assert response["status"] == "resolved" and response["status_changed"] is False

    _with_database(scenario)


AUTO_FP_NOTE = (
    "Auto-set false positive by retest 9f1c (mode=deterministic, confidence=0.97). "
    "Reversible by an analyst."
)


@postgres
def test_clearing_a_verdict_keeps_the_note_that_says_why_it_was_set():
    """A retest that auto-closes a finding records why only in the verdict notes. Clearing the
    verdict used to erase that note while the finding stayed a false positive."""
    async def scenario(conn):
        await conn.execute(
            """UPDATE findings SET analyst_verdict = 'false_positive', analyst_verdict_at = NOW(),
                   analyst_verdict_notes = $2 WHERE id = $1""",
            FINDING, AUTO_FP_NOTE,
        )
        response, stored = await _patch(
            conn, {"status": "false_positive", "analyst_verdict": None},
        )
        assert stored["analyst_verdict"] is None and stored["analyst_verdict_at"] is None
        assert stored["analyst_verdict_notes"] == AUTO_FP_NOTE
        assert stored["status"] == "false_positive"

        # Notes sent with the clear are the analyst's account and replace it.
        _response, stored = await _patch(
            conn, {"status": "false_positive", "analyst_verdict": None, "notes": "checked by hand"},
        )
        assert stored["analyst_verdict_notes"] == "checked by hand"

    _with_database(scenario)
