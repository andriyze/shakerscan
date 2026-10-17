"""A row a release retired is resolved but never counted as a fix, on the real findings schema.

The exposure "what changed" digest, the Hunt knowledge "what changed" counts and the findings list's
"resolved within" filter leave it out; the list rows and the detail label it "Retired by release".
Only FINDINGS_PROOF_SQL_TEST_DATABASE_URL on localhost/shakerscan_proof_sql_test is permitted. Its
public schema is RESET and db/init.sql is loaded.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json

import pytest

from tests.disposable_postgres import require_disposable_database
from tests.test_finding_detail_related_postgres import DSN, REQUIRED, TARGET, _fresh_schema_and_adder

if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable findings PostgreSQL database"
)

RETIRED = {"kind": "nuclei_opt_in_header_absent", "release": "2.11.0", "scan_id": "s",
           "reason": "An opt-in header whose absence is the browser default; not a finding (2.11)."}
OLDER_RETIRED = {"kind": "nuclei_hsts_on_plain_http",
                 "reason": "Browsers ignore HSTS received over plain HTTP; its absence there is not a finding (2.11)."}


class _Pool:
    def __init__(self, conn):
        self.conn = conn

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def test_retired_rows_are_labelled_and_never_counted_as_fixes(monkeypatch):
    from api.exposure import router as exposure_router
    from api.finding_routes import router as finding_router
    from api.finding_routes.list_query import ROW_JOINS_SQL, FindingFilters, apply_proof, row_select_sql
    from api.hunt.knowledge_changes import _findings
    from api.list_contract import SqlParams

    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            setup, add = _fresh_schema_and_adder(conn)
            await setup()
            # Added by the engine's startup migrations (asset grouping); the Hunt query reads it.
            await conn.execute("ALTER TABLE targets ADD COLUMN IF NOT EXISTS asset_owner_id UUID")
            fixed = await add("Reflected XSS", "dalfox", "https://app.invalid/q", {}, status="resolved")
            retired = await add("Missing COEP", "nuclei", "https://app.invalid/",
                                {"template_id": "http-missing-security-headers", "retired": RETIRED},
                                status="resolved", severity="info")
            older = await add("HSTS on http", "nuclei", "http://app.invalid/",
                              {"template_id": "http-missing-security-headers", "retired": OLDER_RETIRED},
                              status="resolved", severity="info")
            reopened = await add("Missing COEP (reopened)", "nuclei", "https://app.invalid/x",
                                 {"retired": RETIRED}, status="active", severity="info")
            await conn.execute("UPDATE findings SET resolved_at = NOW() - INTERVAL '1 hour' WHERE status = 'resolved'")
            monkeypatch.setattr(exposure_router, "_pool", lambda: _Pool(conn))
            monkeypatch.setattr(finding_router, "_pool", lambda: _Pool(conn))
            monkeypatch.setattr(finding_router, "_load_effective_ai_settings", lambda: {})

            changes = await exposure_router.exposure_changes(days=7, examples=5)
            knowledge = await _findings(conn, TARGET, datetime.now(timezone.utc) - timedelta(days=1))

            params = SqlParams()
            where = FindingFilters(resolved_within_days=7).clauses(params)
            recent = await conn.fetch(
                f"SELECT f.id FROM findings f WHERE {' AND '.join(where)}", *params.values)
            rows = await conn.fetch(
                f"SELECT {row_select_sql(details=False)}, NULL AS _proof_state FROM findings f {ROW_JOINS_SQL}")
            listed = {row["id"]: apply_proof(row, lambda item: {}) for row in rows}
            detail = await finding_router.get_finding(str(retired))
            fixed_detail = await finding_router.get_finding(str(fixed))
            return (changes, knowledge, {row["id"] for row in recent}, listed, detail, fixed_detail,
                    (fixed, retired, older, reopened))
        finally:
            await conn.close()

    changes, knowledge, recent, listed, detail, fixed_detail, ids = asyncio.run(go())
    fixed, retired, older, reopened = ids
    resolved = next(item for item in changes["categories"] if item["key"] == "resolved")
    assert resolved["label"] == "Findings resolved"
    assert resolved["count"] == 1, "a release's retirement is not a resolved finding"
    assert [example["label"] for example in resolved["examples"]] == ["Reflected XSS"]
    assert knowledge["resolved"]["count"] == 1
    assert recent == {fixed}, "the digest's href (resolved_within) lists exactly what it counted"

    assert listed[fixed]["resolution_reason"] == "resolved" and listed[fixed]["retirement"] is None
    assert listed[retired]["resolution_reason"] == "retired_by_release"
    assert listed[retired]["retirement"]["label"] == (
        "Retired by release 2.11.0: An opt-in header whose absence is the browser default; not a finding")
    # A row retired before the record named its release: the release comes from the reason.
    assert listed[older]["retirement"]["release"] == "2.11"
    assert listed[older]["retirement"]["label"].startswith("Retired by release 2.11: Browsers ignore HSTS")
    assert listed[reopened]["resolution_reason"] is None and listed[reopened]["retirement"] is None

    assert detail["resolution_reason"] == "retired_by_release"
    assert detail["retirement"]["release"] == "2.11.0"
    assert detail["retirement"]["kind"] == "nuclei_opt_in_header_absent"
    assert fixed_detail["resolution_reason"] == "resolved" and fixed_detail["retirement"] is None
    json.dumps(detail, default=str)
