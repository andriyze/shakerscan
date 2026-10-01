"""The proof filter's SQL answers exactly what finding_proof_fields answers, on real PostgreSQL.

Only FINDINGS_PROOF_SQL_TEST_DATABASE_URL on localhost/shakerscan_proof_sql_test is permitted. Its
public schema is RESET and db/init.sql is loaded, so these tests run the list route's own query
against the real findings schema.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import random
import sys
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
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import finding_routes.router as findings_router  # noqa: E402
from finding_routes import proof_sql  # noqa: E402

TARGET = uuid.UUID("11111111-1111-4111-8111-111111111111")
CANONICAL = sorted(proof_sql.CANONICAL_PROOF_CONTRACTS)[0]


# --- JSON with exact number text --------------------------------------------------------------

@dataclass(frozen=True)
class Raw:
    """A JSON number written exactly as given (1e-400 cannot survive a Python float)."""

    text: str


MISSING = object()


def dumps(value) -> str:
    if isinstance(value, Raw):
        return value.text
    if isinstance(value, dict):
        return "{" + ", ".join(f"{json.dumps(k)}: {dumps(v)}" for k, v in value.items() if v is not MISSING) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(dumps(v) for v in value) + "]"
    return json.dumps(value)


SCALARS = [
    None, True, False, 0, 1, 2, Raw("0.0"), Raw("1.0"), Raw("-0.0"), Raw("1e-400"), Raw("2e-324"),
    Raw("5e-324"), Raw("1.00000000000000001"), Raw("0.99999999999999999"), Raw("1.0000000000000003"),
    "", " ", "true", " TRUE ", "Yes", "on\n", "1", "0", "false", "nope", [], [1], ["x"], {}, {"a": 1},
]
WORDS = [
    "verified", " Verified　", "VERIFIED ", "candidate", "SUSPECTED", " needs_review", "likely_vulnerable",
    "liKely_vulnerable", "candİdate", "　suspected ", "suspect", "dom_execution",
    "BROWSER_EXECUTION ", "headless_xss_reflected", " Headless_XSS_dom", "headless_xs",
    " headless_xss_x", "shakerscan", "ShakerScan", "sqli_data_extraction", "SQLi_Data_Extraction ",
    "oob_callback\n", "postcondition_verification", "exploited", "deterministic", CANONICAL,
    f" {CANONICAL} ", CANONICAL.upper(), "proof-contract/v2",
]
POOL = SCALARS + WORDS
TOP_KEYS = [
    "proof_of_exploitation", "payload_executed", "executed", "extraction_evidence", "extracted_data",
    "proof_type", "proof_state", "proof_contract", "proof_producer", "evidence_type", "technique",
    "dom_marker_executed",
]
TRIAGE_STRINGS = [
    '{"suspected": true}', '  {"needs_verification": true} ', '{"proof_state": "candidate"}',
    '{"proof_state": 0.0}', '{"proof_state": 1e-400}', '[{"suspected": true}]', "not json",
    '{"suspected": true', '　{"proof_state": " Needs_Review "}', '{"verified": true}',
]
UNDETERMINED_TRIAGE = ['{"suspected": true, "score": NaN}', '{"proof_state": "candidate", "x": Infinity}',
                       '{"suspected": true, "s": "\\ud800"}']


def valid_v2():
    return {"schema_version": "proof-contract/v2", "contract_id": "c", "contract_version": "1",
            "reexecution": {"required": True, "performed": True, "verifier_build": "b"},
            "verdict": "verified", "promotable": True, "predicate": {"satisfied": True, "missing": []}}


def mutate(document: dict, rng: random.Random) -> dict:
    """Change one leaf (or drop it) to a random value: every conjunct flips somewhere."""
    copy = json.loads(json.dumps(document))
    paths = []

    def walk(node, prefix):
        for key, value in node.items():
            paths.append(prefix + [key])
            if isinstance(value, dict):
                walk(value, prefix + [key])
    walk(copy, [])
    path = rng.choice(paths)
    node = copy
    for key in path[:-1]:
        node = node[key]
    if rng.random() < 0.15:
        del node[path[-1]]
    else:
        node[path[-1]] = rng.choice(POOL)
    return copy


def evidence_cases(rng: random.Random) -> list:
    cases: list = [MISSING, None, Raw("[]"), "plain string", 5, Raw('"{\\"proof_state\\": \\"suspected\\"}"'), {}]
    for _ in range(1500):  # random evidence: each key present with probability 0.3
        cases.append({key: rng.choice(POOL) for key in TOP_KEYS if rng.random() < 0.3})
    browser_nested = {"proven": True, "proof_producer": "shakerscan", "evidence_type": "dom_execution",
                      "technique": "headless_xss_reflected"}
    browser_flat = {"proof_producer": "shakerscan", "evidence_type": " Browser_Execution",
                    "technique": "headless_xss_dom", "dom_marker_executed": True}
    satisfied = {"proof_contract": CANONICAL, "proof_state": "verified", "triage": {"verified": True}}
    cases += [{"browser_proof": browser_nested}, browser_flat, satisfied, {"proof_contract_v2": valid_v2()}]
    for _ in range(400):
        cases.append({"browser_proof": mutate(browser_nested, rng)})
        cases.append(mutate(browser_flat, rng))
        cases.append(mutate(satisfied, rng))
        v2 = mutate(valid_v2(), rng)
        if rng.random() < 0.3:
            v2["reexecution"] = {"required": False, "performed": rng.choice(POOL), "verifier_build": "b"}
        cases.append({"proof_contract_v2": v2 if rng.random() < 0.9 else rng.choice(POOL)})
    for _ in range(600):  # triage: an object, a JSON string, or other, beside evidence.proof_state
        triage = rng.choice([
            {k: rng.choice(POOL) for k in ("suspected", "needs_verification", "proof_state", "verified") if rng.random() < 0.5},
            rng.choice(TRIAGE_STRINGS), rng.choice(POOL),
        ])
        case = {"triage": triage}
        if rng.random() < 0.5:
            case["proof_state"] = rng.choice(POOL)
        cases.append(case)
    cases += [{"triage": text} for text in UNDETERMINED_TRIAGE]
    return cases


SEVERITIES = ["high", "HIGH", "Critical", "critical ", "medium", "low", "info", "hıgh", "Kritical", ""]
VERDICTS = [None, "exploited", "EXPLOITED", "exploited ", "likely_vulnerable", "false_positive"]
RETESTS = [None, (None, "deterministic"), ("exploited", "deterministic"), ("exploited", "DETERMINISTIC"),
           ("exploited", "ai_driven"), ("likely_fixed", "deterministic"), ("exploited", None)]


# --- database -------------------------------------------------------------------------------

CANDIDATES_SQL = """
CREATE TABLE IF NOT EXISTS investigation_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), plane TEXT NOT NULL, target_id UUID,
    family TEXT NOT NULL, canonical_locus JSONB NOT NULL DEFAULT '{}'::jsonb, title TEXT NOT NULL,
    claim TEXT NOT NULL DEFAULT '', claimed_severity TEXT NOT NULL DEFAULT 'info',
    evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    verification_context JSONB NOT NULL DEFAULT '{}'::jsonb, status TEXT NOT NULL DEFAULT 'new',
    hunt_run_id UUID, agent_hunt_run_id UUID,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)"""


def run(scenario):
    dsn = require_disposable_database(DSN or "", "shakerscan_proof_sql_test")

    async def go():
        conn = await asyncpg.connect(dsn)
        try:
            await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
            await conn.execute((ROOT / "db" / "init.sql").read_text(encoding="utf-8"))
            await conn.execute(CANDIDATES_SQL)
            await conn.execute(
                "INSERT INTO targets (id, url, name) VALUES ($1, 'https://app.example.test', 'app')", TARGET)
            return await scenario(conn)
        finally:
            await conn.close()

    return asyncio.run(go())


async def insert_finding(conn, *, evidence, severity, verdict, retest, title="f"):
    finding_id = uuid.uuid4()
    await conn.execute(
        """INSERT INTO findings (id, target_id, fingerprint, title, severity, tool, evidence,
                                 last_verification_verdict, status, source)
           VALUES ($1, $2, $3, $4, $5, 'test', $6::jsonb, $7, 'active', 'dast')""",
        finding_id, TARGET, finding_id.hex, title, severity,
        None if evidence is MISSING else dumps(evidence), verdict,
    )
    if retest is not None:
        await conn.execute(
            """INSERT INTO finding_verifications (finding_id, verdict, verification_mode, finding_type, target_url)
               VALUES ($1, $2, $3, 'xss', 'https://app.example.test')""",
            finding_id, retest[0], retest[1],
        )
    return finding_id


def python_state(row) -> str:
    return findings_router.finding_proof_fields(dict(row))["proof_state"]


# --- the constants mirror Python ------------------------------------------------------------

def test_whitespace_and_case_folding_match_python():
    every = [chr(code) for code in range(0x110000) if not 0xD800 <= code <= 0xDFFF]
    assert set(proof_sql.PY_WHITESPACE) == {char for char in every if char.isspace()}
    # Characters whose lowercase is entirely ASCII: exactly what the SQL fold maps.
    to_ascii = {char: char.lower() for char in every if char.lower() != char and char.lower().isascii()}
    assert to_ascii == dict(zip(proof_sql.FOLD_FROM, proof_sql.FOLD_TO))


# --- parity ---------------------------------------------------------------------------------

def test_the_sql_projection_matches_finding_proof_fields_on_every_row():
    rng = random.Random(20261001)

    async def scenario(conn):
        for evidence in evidence_cases(rng):
            await insert_finding(conn, evidence=evidence, severity=rng.choice(SEVERITIES),
                                 verdict=rng.choice(VERDICTS), retest=rng.choice(RETESTS))
        for retest in RETESTS:  # every verdict/retest pair with plain evidence
            for verdict in VERDICTS:
                await insert_finding(conn, evidence={}, severity="medium", verdict=verdict, retest=retest)
        rows = await conn.fetch(
            findings_router.FINDINGS_LIST_SELECT_SQL
            + f", {findings_router.FINDING_PROOF_STATE_SQL} AS sql_proof_state"
            + f", {findings_router.FINDING_PROOF_UNDETERMINED_SQL} AS sql_undetermined"
            + findings_router.FINDINGS_LIST_FROM_SQL
        )
        mismatches, undetermined, states = [], [], {}
        for row in rows:
            item = dict(row)
            sql_state, flagged = item.pop("sql_proof_state"), item.pop("sql_undetermined")
            python = findings_router.finding_proof_fields(dict(item))["proof_state"]
            states[python] = states.get(python, 0) + 1
            if flagged:
                undetermined.append(json.loads(item["evidence"])["triage"])
                continue
            if python != sql_state:
                mismatches.append((python, sql_state, item["severity"], item["last_verification_verdict"],
                                   item["latest_retest_mode"], item["evidence"]))
        assert mismatches == [], f"{len(mismatches)} rows differ, e.g. {mismatches[:3]}"
        # Undetermined rows are triage strings opening with "{" that PostgreSQL's jsonb rejects: the
        # ones Python can still decode, and malformed ones (the route projects both in Python).
        assert set(UNDETERMINED_TRIAGE) <= set(undetermined)
        assert set(undetermined) <= set(UNDETERMINED_TRIAGE) | {'{"suspected": true'}
        assert min(states.values()) > 200 and set(states) == {"verified", "suspected", "unverified"}
        return len(rows)

    assert run(scenario) > 3500


# --- the route ------------------------------------------------------------------------------

class _Request:
    def __init__(self, **params):
        self.query_params = params


def _params(**overrides):
    params = dict(severity=None, status=None, source_type=None, target_id=None, ai_target_id=None,
                  device_target_id=None, scan_id=None, hunt_id=None, root_domain=None,
                  verification_verdict=None, verification_mode=None, verified_only=False,
                  proof_state=None, driven_by=None, research_campaign_id=None, search=None,
                  seen_within_days=None, not_seen_within_days=None, first_seen_within_days=None,
                  resolved_within_days=None, sort_by=None, sort_order="desc",
                  include_candidates=False, limit=100, offset=0, include_details=False)
    params.update(overrides)
    return params


class _Recording:
    """A connection that notes whether the streaming fallback ran."""

    def __init__(self, conn):
        self._conn = conn
        self.streamed = False

    def cursor(self, *args, **kwargs):
        self.streamed = True
        return self._conn.cursor(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._conn, name)


def _list(conn, monkeypatch, **overrides):
    recording = _Recording(conn)

    class _Pool:
        @asynccontextmanager
        async def acquire(self):
            yield recording

    monkeypatch.setattr(findings_router, "_pool", lambda: _Pool())
    params = _params(**overrides)
    request = _Request(**{key: value for key, value in overrides.items() if value not in (None, False)})
    return findings_router.list_findings(request, **params), recording


async def _expected(conn, states, *, limit, offset):
    rows = await conn.fetch(findings_router.FINDINGS_LIST_SELECT_SQL + findings_router.FINDINGS_LIST_FROM_SQL
                            + " ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2"
                            " WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END ASC, f.last_seen_at DESC NULLS LAST")
    matching = [str(row["id"]) for row in rows if python_state(row) in states]
    return len(matching), matching[offset:offset + limit]


def test_a_proof_filter_pages_past_the_old_ceiling_without_refusing(monkeypatch):
    async def scenario(conn):
        # 25,000 findings: more than the 20,000 the filter used to refuse past.
        await conn.execute("""
            INSERT INTO findings (target_id, fingerprint, title, severity, tool, evidence, status, source, last_seen_at)
            SELECT $1, 'bulk-' || i, 'bulk ' || i,
                   (ARRAY['critical','high','medium','low','info'])[1 + i % 5], 'test',
                   CASE WHEN i % 7 = 0 THEN '{"proof_of_exploitation": true}'::jsonb
                        WHEN i % 11 = 0 THEN '{"triage": {"suspected": true}}'::jsonb
                        ELSE '{}'::jsonb END,
                   'active', 'dast', NOW() - (i || ' seconds')::interval
            FROM generate_series(1, 25000) AS i""", TARGET)
        for states in (["verified"], ["suspected", "unverified"]):
            result_coro, recording = _list(conn, monkeypatch, proof_state=",".join(states), limit=50, offset=4000)
            result = await result_coro
            total, page = await _expected(conn, states, limit=50, offset=4000)
            assert not recording.streamed
            assert result["total"] == total and total > 3000
            assert [str(item["id"]) for item in result["findings"]] == page
            assert {item["proof_state"] for item in result["findings"]} <= set(states)

    run(scenario)


def test_an_undecidable_row_is_projected_in_python_and_still_exact(monkeypatch):
    async def scenario(conn):
        rng = random.Random(7)
        for index in range(300):
            await insert_finding(conn, evidence={"triage": rng.choice(TRIAGE_STRINGS)},
                                 severity=rng.choice(["medium", "low", "high"]), verdict=None, retest=None)
        await insert_finding(conn, evidence={"triage": UNDETERMINED_TRIAGE[0]}, severity="low", verdict=None,
                             retest=None, title="nan triage")
        result_coro, recording = _list(conn, monkeypatch, proof_state="suspected", limit=20, offset=10)
        result = await result_coro
        total, page = await _expected(conn, ["suspected"], limit=20, offset=10)
        assert recording.streamed
        assert result["total"] == total and [str(item["id"]) for item in result["findings"]] == page
        everything_coro, _ = _list(conn, monkeypatch, proof_state="suspected", limit=500)
        assert "nan triage" in {item["title"] for item in (await everything_coro)["findings"]}

    run(scenario)


def test_open_hunt_leads_join_the_suspected_filter_only(monkeypatch):
    async def scenario(conn):
        await insert_finding(conn, evidence={}, severity="high", verdict=None, retest=None, title="suspected finding")
        await insert_finding(conn, evidence={"proof_of_exploitation": True}, severity="high", verdict=None,
                             retest=None, title="proven finding")
        await conn.execute("INSERT INTO investigation_candidates (plane, target_id, family, title, claimed_severity)"
                           " VALUES ('web', $1, 'access_control', 'hunt lead', 'medium')", TARGET)
        suspected_coro, _ = _list(conn, monkeypatch, proof_state="suspected", include_candidates=True)
        suspected = await suspected_coro
        assert {item["title"] for item in suspected["findings"]} == {"suspected finding", "hunt lead"}
        assert suspected["total"] == 2 and suspected["included_candidates"] == 1
        verified_coro, _ = _list(conn, monkeypatch, proof_state="verified", include_candidates=True)
        verified = await verified_coro
        assert [item["title"] for item in verified["findings"]] == ["proven finding"]
        assert verified["candidates_total"] == 0

    run(scenario)
