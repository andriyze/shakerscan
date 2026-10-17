"""Stored credential bounds and grants fail closed (unit level; the routes are covered in
``test_hunt_permission_requests_postgres.py``).

A stored ``credential.use`` pre-authorization entry that is not a target id or an exact host, and a
stored ``credential.use`` grant whose subject lacks a profile UUID or a positive version, cover
nothing and are reported rather than matched by their stored text.
"""
from __future__ import annotations

import json
import uuid

import pytest

from hunt.credential_uses import _stored_credential_grant
from hunt.permission_bounds import bounds_from_public, refused_bounds
from scanner_tools.host_names import HOST_CANONICALIZATION

PROFILE = str(uuid.uuid4())


def _row(credentials):
    return {"budget_multiplier": None, "budget_totals": {}, "credential_targets": credentials,
            "target_patterns": [], "capability_flags": [], "ssh_host_trust_first_contact": False,
            "host_canonicalization": HOST_CANONICALIZATION}


@pytest.mark.parametrize("entry", ["*.app.example.com", "app.example.com:443", "bad_host!.example",
                                   "co.uk", "", "a..example.com"])
def test_a_stored_credential_entry_outside_the_grammar_covers_nothing_and_is_reported(entry):
    bounds = bounds_from_public(_row([entry, "api.example.com"]))
    assert bounds.credential_targets == ("api.example.com",)
    assert bounds.covers_credential(home_target_id="x", home_host="api.example.com")
    assert not bounds.covers_credential(home_target_id=entry, home_host=entry or None)
    reported = refused_bounds(_row([entry, "api.example.com"]))
    assert [item["bound"] for item in reported] == [f"credential.use:{entry}"]
    assert "no longer covers any host" in reported[0]["message"]


def test_a_stored_target_id_and_exact_host_still_cover_in_their_canonical_spelling():
    bounds = bounds_from_public(_row([PROFILE.upper(), "API.Example.com"]))
    assert bounds.credential_targets == (PROFILE, "api.example.com")
    assert bounds.covers_credential(home_target_id=PROFILE, home_host=None)
    assert bounds.covers_credential(home_target_id="x", home_host="api.example.com")
    assert refused_bounds(_row([PROFILE, "api.example.com"])) == []


@pytest.mark.parametrize("subject", [
    {"profile_id": PROFILE},                                   # no version: used to read as 0
    {"profile_id": PROFILE, "profile_version": 0},
    {"profile_id": PROFILE, "profile_version": "1"},
    {"profile_id": PROFILE, "profile_version": True},
    {"profile_id": PROFILE, "profile_version": "abc"},         # used to raise out of admission
    {"profile_version": 1},                                    # used to read as profile "None"
    {"profile_id": "not-a-uuid", "profile_version": 1},
    "{not json",
    ["a list"],
])
def test_a_malformed_stored_credential_grant_grants_nothing(subject):
    raw = subject if isinstance(subject, str) else json.dumps(subject)
    assert _stored_credential_grant(raw) is None


def test_a_well_formed_stored_credential_grant_is_read():
    raw = json.dumps({"profile_id": PROFILE.upper(), "profile_version": 3, "slot": "primary"})
    assert _stored_credential_grant(raw) == (PROFILE, 3, "primary")
    assert _stored_credential_grant({"profile_id": PROFILE, "profile_version": 1}) == (PROFILE, 1, None)
