"""Inline evidence read back from a real PostgreSQL JSONB column verifies, and tampering does not.

Audit S004. Inline evidence is hashed over its serialized text and stored in a JSONB column.
PostgreSQL keeps a JSON number as an exact ``numeric`` and prints it in plain decimal form, so
``1e+20`` comes back as ``100000000000000000000`` -- an int in Python, where it went in as a
float -- and the re-serialized text no longer matched the recorded digest: intact evidence was
reported as ``mismatch`` and withheld. This must run on a real server; a fixture that imitates
JSONB output would only test the imitation.

EVIDENCE_INTEGRITY_TEST_DATABASE_URL must address localhost/shakerscan_evidence_integrity_test.
That database's public schema is RESET at module setup. No target traffic is generated.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

import pytest

from tests.disposable_postgres import require_disposable_database

DSN = os.environ.get("EVIDENCE_INTEGRITY_TEST_DATABASE_URL")
REQUIRED = os.environ.get("EVIDENCE_INTEGRITY_POSTGRES_REQUIRED") == "1"
pytestmark = pytest.mark.skipif(
    not DSN and not REQUIRED,
    reason="Requires an explicit disposable local evidence integrity test database",
)
if REQUIRED:
    import asyncpg
else:
    asyncpg = pytest.importorskip("asyncpg")
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "api"), str(ROOT / "scanner")]
from api.evidence_storage import hydrate_evidence_content, store_evidence_content  # noqa: E402
from api.serialization import row_to_dict  # noqa: E402

# The worker's insert for inline evidence (api/worker.py _persist_evidence_object).
INSERT = """
    INSERT INTO evidence_objects (
        scan_id, finding_id, object_type, content_sha256, size_bytes,
        storage_uri, redaction_profile, retention_class, content
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    RETURNING id
"""
SELECT = "SELECT * FROM evidence_objects WHERE id=$1"

CONTENTS = {
    "exponent_integral": {
        "big": 1e20, "huge": 1e300, "max": 1.7976931348623157e308, "negative": -1e16,
        "whole": 3.0, "negative_zero": -0.0, "rounded": 1.2345678901234568e20,
    },
    "ordinary_floats": {
        "tenth": 0.1, "small": 1e-05, "tiny": 5e-324, "half": 2.5, "pi": 3.141592653589793,
        "mixed": 123456.789, "negative": -0.25, "third": 1 / 3,
    },
    "large_integers": {"u64": 2**64, "wide": 10**40, "negative": -(2**70), "zero": 0},
    "nested_numbers": {
        "outer": [1, 2.0, {"inner": [3e10, 0.5, [7e22, -1e-7, {"deep": 4.0}]]}],
        "matrix": [[1e3, 2e3], [0.001, 10**30]],
    },
    "unicode": {
        "accent": "café", "cjk": "日本語", "emoji": "\U0001F600",
        "rtl": "שלום", "escapes": "tab\tnewline\nquote\"slash\\",
        "über-key": 1,
    },
    "key_order": {"zz": 1, "a": 2, "bbb": 3, "cc": {"y": 1, "x": 2, "longer-key": 3}},
    "json_lookalike_strings": {
        "object": '{"n": 1e20}', "array": "[1, 2.0, 3e5]", "number": "1e20",
        "float": "2.0", "null": "null", "true": "true",
    },
}
# Whole-content values that are not objects.
SCALARS = {
    "json_text_string": '{"n": 1e20, "s": "x"}',
    "exponent_scalar": 1e20,
    "array": [1e20, "1e20", 0.1],
}


@pytest.fixture(scope="module", autouse=True)
def schema():
    require_disposable_database(DSN or "", "shakerscan_evidence_integrity_test")

    async def initialize():
        from retest_contract import run_schema_migrations

        async with asyncpg.create_pool(DSN, min_size=1, max_size=2) as pool:
            async with pool.acquire() as conn:
                await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
                await conn.execute((ROOT / "db/init.sql").read_text())
            await run_schema_migrations(pool)

    asyncio.run(initialize())


def _with_connection(work):
    async def run():
        conn = await asyncpg.connect(DSN)
        try:
            return await work(conn)
        finally:
            await conn.close()

    return asyncio.run(run())


async def _persist(conn, content, tmp_path) -> tuple[uuid.UUID, dict]:
    stored = store_evidence_content(content, results_dir=tmp_path, inline_max_bytes=1 << 20)
    assert stored["storage_uri"] == "inline:evidence_objects"
    row_id = await conn.fetchval(
        INSERT, uuid.uuid4(), None, "integrity_probe", stored["content_sha256"],
        stored["size_bytes"], stored["storage_uri"], "redact_sensitive_v1", "standard",
        stored["content"],
    )
    return row_id, stored


async def _read(conn, row_id, tmp_path) -> dict:
    # As the API reads it: the asyncpg record as a dict, JSONB as PostgreSQL's own text.
    row = row_to_dict(await conn.fetchrow(SELECT, row_id))
    return hydrate_evidence_content(row, results_dir=tmp_path)


@pytest.mark.parametrize("name", [*CONTENTS, *SCALARS])
def test_intact_inline_evidence_round_trips_through_jsonb_and_verifies(name, tmp_path):
    content = CONTENTS.get(name, SCALARS.get(name))

    async def work(conn):
        row_id, stored = await _persist(conn, content, tmp_path)
        text = await conn.fetchval("SELECT content::text FROM evidence_objects WHERE id=$1", row_id)
        hydrated = await _read(conn, row_id, tmp_path)
        return stored, text, hydrated

    stored, text, hydrated = _with_connection(work)

    assert hydrated["storage_integrity"] == "verified", (name, stored["content"], text)
    assert hydrated["content"] == text
    if not isinstance(json.loads(text), str):
        # The decoded value (a driver with a JSONB codec) verifies the same way. A str is read
        # as JSON text by hydration, so a top-level string value has only the text form.
        decoded = hydrate_evidence_content(
            dict(hydrated, content=json.loads(text)), results_dir=tmp_path,
        )
        assert decoded["storage_integrity"] == "verified"
    # The value PostgreSQL holds is the value that was hashed, number for number.
    assert json.loads(text) == json.loads(stored["content"])


def test_postgres_really_rewrites_exponent_numbers(tmp_path):
    """The premise: JSONB hands back a different text and type for an exponent-form number."""
    async def work(conn):
        return await conn.fetchval("SELECT $1::jsonb::text", json.dumps({"n": 1e20}))

    text = _with_connection(work)
    assert text == '{"n": 100000000000000000000}'
    assert isinstance(json.loads(text)["n"], int)


@pytest.mark.parametrize(
    ("name", "path", "replacement"),
    [
        ("exponent_integral", "{big}", "100000000000000000001"),
        ("exponent_integral", "{whole}", "3.5"),
        ("ordinary_floats", "{tenth}", "0.10000000000000002"),
        ("large_integers", "{u64}", "18446744073709551617"),
        ("nested_numbers", "{outer,2,inner,2,1}", "-2e-7"),
        ("unicode", "{accent}", '"cafe"'),
        ("key_order", "{cc,x}", "3"),
        ("json_lookalike_strings", "{number}", "1e20"),
        ("json_lookalike_strings", "{object}", '"{\\"n\\": 1e21}"'),
    ],
)
def test_tampered_inline_evidence_is_still_detected_and_withheld(name, path, replacement, tmp_path):
    async def work(conn):
        row_id, _stored = await _persist(conn, CONTENTS[name], tmp_path)
        assert (await _read(conn, row_id, tmp_path))["storage_integrity"] == "verified"
        await conn.execute(
            "UPDATE evidence_objects SET content=jsonb_set(content, $2::text[], $3::jsonb) WHERE id=$1",
            row_id, path.strip("{}").split(","), replacement,
        )
        return await _read(conn, row_id, tmp_path)

    tampered = _with_connection(work)
    assert tampered["storage_integrity"] == "mismatch"
    assert tampered["content"] is None


def test_added_or_removed_keys_are_detected(tmp_path):
    async def work(conn):
        added_id, _ = await _persist(conn, CONTENTS["large_integers"], tmp_path)
        removed_id, _ = await _persist(conn, CONTENTS["nested_numbers"], tmp_path)
        await conn.execute(
            "UPDATE evidence_objects SET content=content || '{\"extra\": 1}'::jsonb WHERE id=$1",
            added_id,
        )
        await conn.execute(
            "UPDATE evidence_objects SET content=content - 'matrix' WHERE id=$1", removed_id,
        )
        return await _read(conn, added_id, tmp_path), await _read(conn, removed_id, tmp_path)

    added, removed = _with_connection(work)
    assert added["storage_integrity"] == removed["storage_integrity"] == "mismatch"


def test_rows_hashed_before_canonical_numbers_keep_their_behaviour(tmp_path):
    """Existing rows were hashed over the plain serialization; they verify exactly as before."""
    content = {"a": 0.1, "b": [1, 2], "c": "café", "d": 10**30}
    legacy_text = json.dumps(content, sort_keys=True, default=str)

    async def work(conn):
        row_id = await conn.fetchval(
            INSERT, uuid.uuid4(), None, "integrity_probe",
            hashlib.sha256(legacy_text.encode()).hexdigest(), len(legacy_text),
            "inline:evidence_objects", "redact_sensitive_v1", "standard", legacy_text,
        )
        intact = await _read(conn, row_id, tmp_path)
        await conn.execute(
            "UPDATE evidence_objects SET content=jsonb_set(content, '{a}', '0.2') WHERE id=$1",
            row_id,
        )
        return intact, await _read(conn, row_id, tmp_path)

    intact, tampered = _with_connection(work)
    assert intact["storage_integrity"] == "verified"
    assert tampered["storage_integrity"] == "mismatch"
