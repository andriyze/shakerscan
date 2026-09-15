"""Cached credentials cannot authorize the next action after live authority changes."""
import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from api.runtime import scan_credential_guard as guard
from tests.test_credential_resolver import _metadata, _target


class Pool:
    @asynccontextmanager
    async def acquire(self):
        yield object()


def setup(monkeypatch):
    state = {"profile": _metadata("bearer_token"), "denied": False, "reads": 0}

    class Store:
        async def get_profile(self, conn, *, profile_id):
            state["reads"] += 1
            assert profile_id == state["profile"].profile_id
            return state["profile"]

        async def load_for_worker(self, *args, **kwargs):
            raise AssertionError("An action authority recheck must not load ciphertext")

    async def authority(conn, **kwargs):
        assert kwargs["action_name"] == "scan.submit"
        if state["denied"]:
            raise RuntimeError("seeded-secret-must-never-appear")

    monkeypatch.setattr(guard, "PostgresCredentialProfileStore", Store)
    monkeypatch.setattr(guard, "validate_worker_credential_authority", authority)
    profile = state["profile"]
    options = {"credential_action_name": "scan.submit", "credential_profile_refs": [{
        "profile_id": profile.profile_id, "profile_version": profile.current_version,
        "credential_record_version": profile.record_version, "auth_kind": profile.auth_kind,
        "principal_slot": profile.principal_slot, "allowed_capabilities": list(profile.allowed_capabilities),
    }]}
    return state, options


@pytest.mark.parametrize("change", [
    {"is_active": False}, {"current_version": 4}, {"record_version": 6},
    {"allowed_capabilities": ()}, {"target_id": "other-target"},
    {"target_kind": "web"}, {"principal_slot": "secondary"}, {"auth_kind": "cookie"},
    {"expires_at": datetime.now(timezone.utc) - timedelta(seconds=1)},
])
def test_rechecks_metadata_before_each_action(monkeypatch, change):
    state, options = setup(monkeypatch)
    check = guard.build_scan_credential_check(Pool(), options=options, target=_target(), scan_id="fixture")
    assert asyncio.run(check(None)) is None
    state["profile"] = replace(state["profile"], **change)
    assert asyncio.run(check(None)) == "authentication_uncertain"
    assert state["reads"] == 2


def test_authority_failure_is_content_free_and_never_loads_profile(monkeypatch):
    state, options = setup(monkeypatch)
    state["denied"] = True
    check = guard.build_scan_credential_check(Pool(), options=options, target=_target(), scan_id="fixture")
    assert asyncio.run(check(None)) == "authentication_uncertain"
    assert state["reads"] == 0


@pytest.mark.parametrize("refs", [[None], {"profile_id": "bad"}, [1, 2, 3]])
def test_malformed_references_fail_closed(monkeypatch, refs):
    state, options = setup(monkeypatch)
    options["credential_profile_refs"] = refs
    check = guard.build_scan_credential_check(Pool(), options=options, target=_target(), scan_id="fixture")
    assert asyncio.run(check(None)) == "authentication_uncertain"
    assert state["reads"] == 0


def test_anonymous_and_legacy_metadata_revision_compatibility(monkeypatch):
    state, options = setup(monkeypatch)
    assert guard.build_scan_credential_check(Pool(), options={}, target=_target(), scan_id="fixture") is None
    options["credential_profile_refs"][0].pop("credential_record_version")
    check = guard.build_scan_credential_check(Pool(), options=options, target=_target(), scan_id="fixture")
    assert asyncio.run(check(None)) is None
