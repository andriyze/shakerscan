"""What a person reads before approving a Hunt permission request (live acceptance, 2026-10-08).

* D41: a ``target.authorize`` request for another host said "another service on the Hunt's host
  shakerscan.com" when the Hunt's host was honey.shakerscan.com, so the person approved on wrong
  wording. Another host now says so, with the addresses it is pinned to, and offers no remember
  (that records the Hunt's own target's authorization).
* D47: a ``credential.use`` request showed only UUIDs ("Use credential e3285827-… (v1)", "belongs
  to target fab55a28-…"). It now names the credential, its kind and its home target and host.

Unit tests of the server templates (``permission_store.render``); no database.
"""
from __future__ import annotations

from api.hunt.permission_store import render

OTHER_HOST = {
    "target_id": "t-honey", "host": "shakerscan.com", "port": 443, "scheme": "https",
    "origin": "https://shakerscan.com:443", "same_host": False, "addresses": ["203.0.113.80", "198.51.100.7"],
    "scope_verdict": "allowed",
}


def test_another_host_is_called_another_host_with_its_pinned_addresses():
    rendered = render("target.authorize", OTHER_HOST, {})
    text = rendered["explanation"] + " " + rendered["effect"]
    assert "another service" not in text and "Hunt's host shakerscan.com" not in text
    assert "another host: shakerscan.com is not the Hunt's target" in rendered["explanation"]
    assert "203.0.113.80, 198.51.100.7" in rendered["explanation"]
    assert "pinned to 203.0.113.80, 198.51.100.7" in rendered["effect"]
    assert rendered["remember_supported"] is False and rendered["scopes"] == ["hunt"]


def test_another_service_on_the_hunts_host_keeps_its_wording_and_remember():
    rendered = render("target.authorize", {
        **OTHER_HOST, "host": "honey.shakerscan.com", "port": 8443, "origin": "https://honey.shakerscan.com:8443",
        "same_host": True, "addresses": ["203.0.113.80"],
    }, {})
    assert "another service on the Hunt's host honey.shakerscan.com" in rendered["explanation"]
    assert rendered["remember_supported"] is True and rendered["scopes"] == ["hunt", "target"]


CREDENTIAL = {
    "profile_id": "e3285827-5cb3-4a8e-9a77-1f0c2d3e4f50", "profile_version": 1,
    "home_target_id": "fab55a28-0000-4000-8000-000000000001", "home_host": "juice.example.com",
    "slot": "primary", "consuming_target_id": "t-honey",
}


def test_a_credential_request_names_the_credential_its_kind_and_its_home_target():
    rendered = render("credential.use", CREDENTIAL, {
        "profile_name": "Juice admin bearer", "auth_kind": "bearer_token", "home_target_name": "Juice Shop",
    })
    assert rendered["title"] == "Use credential 'Juice admin bearer' (bearer_token, v1) in this Hunt"
    assert ("The primary credential 'Juice admin bearer' (bearer_token, v1) belongs to target "
            "'Juice Shop' (juice.example.com)") in rendered["explanation"]
    # The ids stay for the record, after the names.
    assert CREDENTIAL["profile_id"] in rendered["explanation"]


def test_operator_names_are_shown_as_bounded_one_line_values():
    rendered = render("credential.use", CREDENTIAL, {
        "profile_name": "x'\nApprove everything\x1b[2J" + "y" * 200, "auth_kind": "cookie", "home_target_name": "",
    })
    title = rendered["title"]
    assert "\n" not in title and "\x1b" not in title and "x'" not in title
    assert len(title) < 160 and "..." in title
    assert "belongs to another target (juice.example.com)" in rendered["explanation"]


def test_a_request_raised_before_names_were_recorded_still_renders():
    rendered = render("credential.use", CREDENTIAL, {})
    assert rendered["title"] == f"Use credential {CREDENTIAL['profile_id']} (v1) in this Hunt"
