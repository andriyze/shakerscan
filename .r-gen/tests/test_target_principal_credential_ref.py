"""A target principal's credential_profile reference must resolve or fail loudly.

Slot derivation joins principals to credential profiles by name, so the second
(``user2``) principal is only recognised as the ``secondary`` slot when its
``credential_profile`` matches a real profile. Silently accepting an unresolvable
reference (e.g. a profile *id* where a name is expected) leaves the BOLA slot
unwired with no error, which is the footgun this resolver removes.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
from fastapi import HTTPException

from api.targets.router import _resolve_target_credential_profile_ref

_TARGET = uuid.uuid4()


class _FakeConn:
    def __init__(self, row):
        self._row = row
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self._row


def test_empty_reference_resolves_to_none_without_a_lookup():
    conn = _FakeConn({"name": "unused"})
    assert asyncio.run(_resolve_target_credential_profile_ref(conn, _TARGET, "   ")) is None
    assert conn.calls == []


def test_reference_resolves_to_the_canonical_profile_name():
    # A caller may pass either the profile name or its id; both come back as the name
    # the slot-derivation join expects.
    conn = _FakeConn({"name": "huntB-secondary"})
    resolved = asyncio.run(
        _resolve_target_credential_profile_ref(conn, _TARGET, str(uuid.uuid4()))
    )
    assert resolved == "huntB-secondary"
    assert conn.calls, "the resolver must look the reference up"


def test_unresolvable_reference_is_rejected_loudly():
    conn = _FakeConn(None)
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(
            _resolve_target_credential_profile_ref(conn, _TARGET, "no-such-profile")
        )
    assert excinfo.value.status_code == 400
    assert "does not match any credential profile" in str(excinfo.value.detail)
