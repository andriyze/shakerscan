"""The brief's related-findings query and the brief itself, on the real findings schema.

Only FINDINGS_PROOF_SQL_TEST_DATABASE_URL on localhost/shakerscan_proof_sql_test is permitted. Its
public schema is RESET and db/init.sql is loaded.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("FINDINGS_PROOF_SQL_TEST_DATABASE_URL")
REQUIRED = os.environ.get("FINDINGS_PROOF_SQL_POSTGRES_REQUIRED") == "1"
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED, reason="Requires an explicit disposable findings PostgreSQL database"
)

ROOT = Path(__file__).resolve().parents[1]
TARGET = uuid.UUID("22222222-2222-4222-8222-222222222222")
OTHER = uuid.UUID("33333333-3333-4333-8333-333333333333")
CERT = "c" * 64


def test_related_findings_come_from_the_same_target_and_rank_the_shared_certificate_first():
    from api.finding_detail import RELATED_SQL, build_finding_detail, related_findings
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
            for target in (TARGET, OTHER):
                await conn.execute("INSERT INTO targets (id, url, name) VALUES ($1, $2, 'app')", target, f"https://{target.hex[:6]}.invalid")

            async def add(target, title, tool, url, evidence, status="active", severity="medium"):
                finding_id = uuid.uuid4()
                await conn.execute(
                    """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, url, evidence, status, source)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, 'dast')""",
                    finding_id, target, finding_id.hex, title, severity, tool, url, json.dumps(evidence), status)
                return finding_id

            subject = await add(TARGET, "TLS certificate hostname mismatch", "tls.inspect", "https://h.invalid:8444", {
                "check": "tls_certificate_hostname_mismatch", "certificate_sha256": CERT,
                "certificate": {"dns_names": ["other.invalid"], "sha256": CERT}, "requested_host": "h.invalid"}, severity="high")
            shared = await add(TARGET, "TLS certificate chain is not trusted", "tls.inspect", "https://alt.invalid",
                               {"check": "tls_certificate_untrusted", "certificate": {"sha256": CERT}})
            same_check = await add(TARGET, "TLS certificate expires within 30 days", "tls.inspect", "https://h.invalid:8444",
                                   {"check": "tls_certificate_expiring"}, severity="low")
            await add(TARGET, "Resolved one", "tls.inspect", "https://h.invalid:8444", {"certificate_sha256": CERT}, status="resolved")
            await add(OTHER, "Other target", "tls.inspect", "https://h.invalid:8444", {"certificate_sha256": CERT})
            row = dict(await conn.fetchrow("SELECT * FROM findings WHERE id = $1", subject))
            rows = [dict(item) for item in await conn.fetch(RELATED_SQL, TARGET, subject)]
            return row, rows, shared, same_check
        finally:
            await conn.close()

    row, rows, shared, same_check = asyncio.run(go())
    related = related_findings(row, rows)
    assert [item["id"] for item in related] == [str(shared), str(same_check)]
    assert related[0]["relation"] == "Same certificate"
    brief = build_finding_detail(row)  # the JSONB evidence as asyncpg returns it (text)
    assert brief["class"] == "tls.certificate_hostname_mismatch"
    assert "other.invalid" in brief["summary"]
    assert brief["severity"]["current_rule"]["severity"] == "medium"
