"""PATCH /targets/{id} with metadata_json and cohort together must be one valid UPDATE."""

from __future__ import annotations

import asyncio
import json
import re
import uuid

import pytest

from targets import router as targets_router

TARGET_ID = "00000000-0000-4000-8000-0000000000a1"


class _Connection:
    def __init__(self):
        self.statements: list[tuple[str, tuple]] = []

    async def fetchval(self, query, *params):
        assignments = re.search(r"\bSET\s+(.*)\s+WHERE\b", query, re.S).group(1)
        columns = re.findall(r"(?:^|,)\s*([a-z_]+)\s*=", assignments)
        duplicates = {column for column in columns if columns.count(column) > 1}
        if duplicates:
            # PostgreSQL: "multiple assignments to same column".
            raise RuntimeError(f"multiple assignments to same column {sorted(duplicates)}")
        self.statements.append((query, params))
        return uuid.UUID(TARGET_ID)


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        pool = self

        class _Acquire:
            async def __aenter__(self):
                return pool.connection

            async def __aexit__(self, *_exc):
                return False

        return _Acquire()


@pytest.fixture
def connection(monkeypatch):
    conn = _Connection()
    monkeypatch.setattr(targets_router, "_pool_provider", lambda: _Pool(conn))
    return conn


def _metadata_patch(conn):
    query, params = conn.statements[-1]
    index = int(re.search(r"metadata_json = COALESCE\(metadata_json, '\{\}'::jsonb\) \|\| \$(\d+)", query).group(1))
    return json.loads(params[index - 1])


def test_metadata_and_cohort_update_together(connection):
    request = targets_router.TargetUpdate(metadata_json={"owner": "platform"}, cohort="staging")

    result = asyncio.run(targets_router.update_target(TARGET_ID, request))

    assert result == {"id": TARGET_ID, "status": "updated"}
    assert _metadata_patch(connection) == {"owner": "platform", "cohort": "staging"}


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"metadata_json": {"owner": "platform"}}, {"owner": "platform"}),
        ({"cohort": "lab"}, {"cohort": "lab"}),
        ({"metadata_json": {}}, {}),
    ],
)
def test_metadata_or_cohort_alone_still_merge(connection, fields, expected):
    asyncio.run(targets_router.update_target(TARGET_ID, targets_router.TargetUpdate(**fields)))

    assert _metadata_patch(connection) == expected


@pytest.mark.parametrize("metadata", [{"declared": True}, {"created_via": ""}, {"created_via": "hunt", "owner": "x"}])
def test_how_a_target_was_added_cannot_be_edited(metadata):
    """Subdomain discovery admits a domain by how its targets were added; PATCH cannot rewrite it."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="declared and created_via"):
        targets_router.TargetUpdate(metadata_json=metadata)
    assert targets_router.TargetUpdate(metadata_json={"owner": "team-a"}).metadata_json == {"owner": "team-a"}
