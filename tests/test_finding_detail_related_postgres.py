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
SCAN = uuid.UUID("55555555-5555-4555-8555-555555555555")


def test_related_findings_come_from_the_same_target_and_rank_the_shared_certificate_first():
    from api.finding_detail import RELATED_SQL, build_finding_detail, related_findings, related_sql_args
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
            rows = [dict(item) for item in await conn.fetch(RELATED_SQL, *related_sql_args(row))]
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


def _fresh_schema_and_adder(conn):
    async def setup():
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
        await conn.execute("INSERT INTO targets (id, url, name) VALUES ($1, 'https://app.invalid', 'app')", TARGET)

    async def add(title, tool, url, evidence, status="active", severity="medium", verdict=None, fingerprint=None):
        finding_id = uuid.uuid4()
        await conn.execute(
            """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, url, evidence, status,
                                     source, analyst_verdict)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, 'dast', $10)""",
            finding_id, TARGET, fingerprint or finding_id.hex, title, severity, tool, url, json.dumps(evidence),
            status, verdict)
        return finding_id
    return setup, add


def test_related_findings_are_filtered_by_origin_in_sql_and_use_the_built_indexes():
    from api.finding_detail import RELATED_SQL, related_findings, related_sql_args
    from api.finding_routes.list_schema import FINDINGS_LIST_INDEXES
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            setup, add = _fresh_schema_and_adder(conn)
            await setup()
            # The background builder's definitions are valid (immutable expressions) on this schema.
            for name, definition in FINDINGS_LIST_INDEXES:
                if name in {"idx_findings_active_target_origin", "idx_findings_active_target_certificate"}:
                    await conn.execute(f"CREATE INDEX {name} ON {definition}")
            subject = await add("Missing CSP", "http_baseline", "https://app.invalid", {"check": "missing_header_csp"})
            default_port = await add("Same tool", "http_baseline", "https://APP.invalid:443/x", {})
            other_origin = await add("Other origin", "http_baseline", "https://other.invalid", {}, severity="critical")
            other_port = await add("Other port", "http_baseline", "https://app.invalid:8443", {}, severity="high")
            low = await add("Low, other tool", "nuclei", "https://app.invalid/y", {}, severity="low")
            significant = await add("Significant", "nuclei", "https://app.invalid/z", {}, severity="high")
            row = dict(await conn.fetchrow("SELECT * FROM findings WHERE id = $1", subject))
            rows = [dict(item) for item in await conn.fetch(RELATED_SQL, *related_sql_args(row))]
            await conn.execute("SET enable_seqscan = off")
            plan = "\n".join(r[0] for r in await conn.fetch("EXPLAIN " + RELATED_SQL, *related_sql_args(row)))
            return rows, plan, default_port, other_origin, other_port, low, significant
        finally:
            await conn.close()

    rows, plan, default_port, other_origin, other_port, low, significant = asyncio.run(go())
    returned = {str(item["id"]) for item in rows}
    assert str(other_origin) not in returned and str(other_port) not in returned and str(low) not in returned
    related = related_findings({"url": "https://app.invalid", "tool": "http_baseline", "evidence": {}}, rows)
    assert [item["id"] for item in related] == [str(default_port), str(significant)]
    assert "idx_findings_active_target_origin" in plan


def test_retired_kinds_resolve_only_untriaged_unseen_rows_on_the_covered_origin():
    from api.scan.retired_findings import retire_superseded_findings
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")
    template = {"template_id": "http-missing-security-headers"}

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            setup, add = _fresh_schema_and_adder(conn)
            await setup()
            folded = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid",
                               {**template, "header_name": "referrer-policy"}, severity="info")
            older_spelling = await add("HTTP Missing Security Headers", "nuclei", "https://app.invalid:443/about",
                                       {**template, "matcher_name": "referrer-policy"}, severity="info")
            accepted = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/a",
                                 {**template, "header_name": "referrer-policy"}, status="accepted_risk")
            judged = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/b",
                               {**template, "header_name": "referrer-policy"}, verdict="true_positive")
            seen = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/c",
                             {**template, "header_name": "referrer-policy"}, fingerprint="seen-now")
            present = await add("Missing HTTP response header: Content-Security-Policy", "nuclei", "https://app.invalid",
                                {**template, "header_name": "content-security-policy"})
            elsewhere = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://other.invalid",
                                  {**template, "header_name": "referrer-policy"})
            verdict_noted = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/d",
                                      {**template, "header_name": "referrer-policy"})
            retesting = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/e",
                                  {**template, "header_name": "referrer-policy"})
            reopened = await add("Missing HTTP response header: Referrer-Policy", "nuclei", "https://app.invalid/f",
                                 {**template, "header_name": "referrer-policy",
                                  "retired": {"kind": "nuclei_missing_header_folded_into_baseline"}})
            await conn.execute("UPDATE findings SET analyst_verdict_notes = 'keep' WHERE id = $1", verdict_noted)
            await conn.execute("UPDATE findings SET last_verification_status = 'queued' WHERE id = $1", retesting)
            baseline = await add("Missing Referrer Policy header", "http_baseline", "https://app.invalid",
                                 {"check": "missing_header_referrer-policy"})
            await conn.execute("INSERT INTO scans (id, target_id, target_url) VALUES ($1, $2, 'https://app.invalid')",
                               SCAN, TARGET)

            async def retire():
                return await retire_superseded_findings(conn, target_id=TARGET, scan_id=str(SCAN), report=report,
                                                        seen_fingerprints=["seen-now"])
            report = {"target": "https://app.invalid", "http": {"posture_observed": True},
                      "scan_metadata": {"status": "complete", "partial": False, "cancelled": False}, "findings": [{
                "tool": "http_baseline", "url": "https://app.invalid",
                "evidence": {"check": "missing_header_referrer-policy"}}]}
            # The baseline finding that carries the duplicates is not stored for this scan: nothing retires.
            unsaved = await retire()
            await conn.execute("UPDATE findings SET scan_id = $2, status = 'resolved' WHERE id = $1", baseline, SCAN)
            resolved_baseline = await retire()
            await conn.execute("UPDATE findings SET status = 'false_positive' WHERE id = $1", baseline)
            count = await retire()
            statuses = {row["id"]: (row["status"], row["retired"], row["resolved_at"] is not None) for row in await conn.fetch(
                "SELECT id, status, evidence->'retired' AS retired, resolved_at FROM findings")}
            return (unsaved, resolved_baseline, count), statuses, (
                folded, older_spelling, accepted, judged, seen, present, elsewhere, baseline, verdict_noted, retesting,
                reopened)
        finally:
            await conn.close()

    counts, statuses, ids = asyncio.run(go())
    folded, older_spelling, accepted, judged, seen, present, elsewhere, baseline, verdict_noted, retesting, reopened = ids
    assert counts == (0, 0, 2), "retired only while the baseline row is stored for this scan, active or triaged"
    for retired in (folded, older_spelling):
        status, evidence, resolved = statuses[retired]
        assert status == "resolved" and resolved
        assert json.loads(evidence)["kind"] == "nuclei_missing_header_folded_into_baseline"
    assert statuses[accepted][0] == "accepted_risk"
    for kept in (judged, seen, present, elsewhere, verdict_noted, retesting):
        assert statuses[kept][:2] == ("active", None)
    assert statuses[reopened][0] == "active", "an operator reopened this retired row: never retired again"
    assert statuses[baseline][:2] == ("false_positive", None)


def test_retirement_adversarial_cases_on_the_real_schema():
    """Folded exposure templates, triage of every kind, re-reports, scan state, idempotency, batches."""
    from api.scan.retired_findings import retire_superseded_findings
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")
    scan = uuid.UUID("44444444-4444-4444-8444-444444444444")
    git = {"template_id": "git-config"}

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            setup, add = _fresh_schema_and_adder(conn)
            await setup()
            await conn.execute("INSERT INTO scans (id, target_id, target_url) VALUES ($1, $2, 'https://app.invalid')", scan, TARGET)
            ids = {
                "folded": await add("Git config", "nuclei", "https://app.invalid/.git/config", git, severity="medium"),
                "folded_port": await add("Git config", "nuclei", "https://APP.invalid:443/.git/config/", git,
                                         severity="high"),
                "more_severe": await add("Git config", "nuclei", "https://app.invalid/.git/config", git,
                                         severity="critical"),
                "other_path": await add("Git config", "nuclei", "https://app.invalid/sub/.git/config", git),
                "other_origin": await add("Git config", "nuclei", "https://other.invalid/.git/config", git),
                "other_class": await add("web.config", "nuclei", "https://app.invalid/.git/config",
                                         {"template_id": "web-config"}),
                "noted": await add("Git config", "nuclei", "https://app.invalid/.git/config", git),
                "false_positive": await add("Git config", "nuclei", "https://app.invalid/.git/config", git,
                                            status="false_positive"),
                "verdict": await add("Git config", "nuclei", "https://app.invalid/.git/config", git,
                                     verdict="needs_review"),
                "excepted": await add("Git config", "nuclei", "https://app.invalid/.git/config", git),
                "last_seen_now": await add("Git config", "nuclei", "https://app.invalid/.git/config", git),
                "re_reported": await add("Git config", "nuclei", "https://app.invalid/.git/config", git,
                                         fingerprint="seen-now"),
            }
            await conn.execute("UPDATE findings SET notes = 'owner says legacy' WHERE id = $1", ids["noted"])
            await conn.execute("UPDATE findings SET last_seen_scan_id = $2 WHERE id = $1", ids["last_seen_now"], scan)
            await conn.execute(
                "INSERT INTO finding_exceptions (finding_id, target_id, status, reason) VALUES ($1, $2, 'approved', 'x')",
                str(ids["excepted"]), TARGET)
            proof = {"tool": "shakerscan_exposure_probe", "url": "https://app.invalid/.git/config",
                     "severity": "high", "proof_state": "verified",
                     "evidence": {"exposure_class": "version_control_exposure"}}
            stored_proof = await add("Git config exposed", "shakerscan_exposure_probe",
                                     "https://app.invalid/.git/config", {"exposure_class": "other_class"},
                                     severity="high")
            await conn.execute("UPDATE findings SET scan_id = $2 WHERE id = $1", stored_proof, scan)

            def report(status="complete"):
                return {"target": "https://app.invalid", "http": {"posture_observed": True}, "findings": [proof],
                        "scan_metadata": {"status": status, "partial": status == "partial",
                                          "cancelled": status == "cancelled"}}

            async def retire(rep, **kwargs):
                async with conn.transaction():
                    return await retire_superseded_findings(
                        conn, target_id=TARGET, scan_id=str(scan), report=rep, seen_fingerprints=["seen-now"],
                        **kwargs)

            not_complete = [await retire(report(status)) for status in ("partial", "failed", "cancelled")]
            # The stored proof is of another class: it does not carry these rows.
            wrong_class = await retire(report())
            await conn.execute("""UPDATE findings SET evidence = '{"exposure_class": "version_control_exposure"}'
                                  WHERE id = $1""", stored_proof)
            first = await retire(report(), batch_size=1, max_rows=1)
            rest = await retire(report(), batch_size=1)
            again = await retire(report())
            rows = {row["id"]: (row["status"], row["retired"]) for row in await conn.fetch(
                "SELECT id, status, evidence->'retired' AS retired FROM findings")}
            return ids, not_complete, first, rest, again, rows, wrong_class
        finally:
            await conn.close()

    ids, not_complete, first, rest, again, rows, wrong_class = asyncio.run(go())
    assert not_complete == [0, 0, 0], "a partial, failed or cancelled scan retires nothing"
    assert wrong_class == 0, "no stored proof of this class for this scan: nothing is retired"
    assert (first, rest, again) == (1, 1, 0), "bounded per call, and idempotent"
    for name in ("folded", "folded_port"):
        status, record = rows[ids[name]]
        assert status == "resolved"
        record = json.loads(record)
        assert record["kind"] == "nuclei_git_config_folded_into_exposure_proof"
        assert record["superseded_by"]["location"] == "https://app.invalid/.git/config"
    for name in ("more_severe", "other_path", "other_origin", "other_class", "noted", "verdict", "excepted",
                 "last_seen_now", "re_reported"):
        assert rows[ids[name]] == ("active", None), name
    assert rows[ids["false_positive"]] == ("false_positive", None)
