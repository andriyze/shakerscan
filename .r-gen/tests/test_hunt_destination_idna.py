"""A Hunt destination has one host spelling: the subject, the grant and the denial cooldown.

``destination_refusal`` keyed the subject on ``hostname.lower().rstrip(".")``, so
``https://ｅｖｉｌ.example`` (full-width) and ``evil.example`` were two questions although they
reach one host: after a person denied one, the agent could ask again with the other. The host is
now the scope guard's IDNA ASCII form (``action_scope._canonical_host``) everywhere, and the
approval screen shows that form. The end-to-end flow (deny, then a full-width spelling is refused
with ``permission_denied``) runs in tests/test_hunt_permission_requests_postgres.py.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from capabilities.http import granted_destination
from hunt.permission_store import KIND_TARGET_AUTHORIZE, cooldown_identity, render
from hunt.permission_subjects import destination_refusal, scanner_destination_refusal

TARGET = SimpleNamespace(target_id="t1", canonical_host="app.example.test", allowed_addresses=("93.184.216.34",))
SPELLINGS = (
    "https://ｅｖｉｌ.example",  # full-width
    "https://EVIL.example.",
    "https://e​vil.example",  # zero-width space, mapped away by IDNA
    "https://ＥＶＩＬ．example",  # full-width capitals and full stop
    "https://evil.example:443",
)


@pytest.mark.parametrize("origin", SPELLINGS)
def test_every_spelling_is_one_subject_and_one_cooldown(origin):
    plain = destination_refusal(TARGET, "https://evil.example", {}, principal_slot="anonymous")
    spelled = destination_refusal(TARGET, origin, {}, principal_slot="anonymous")
    assert spelled.reason_code == "scope_other_host"
    assert spelled.subject["host"] == "evil.example"
    assert spelled.subject["origin"] == "https://evil.example:443"
    assert cooldown_identity(KIND_TARGET_AUTHORIZE, spelled.subject) == cooldown_identity(
        KIND_TARGET_AUTHORIZE, plain.subject)


def test_a_stored_subject_in_another_spelling_still_meets_the_cooldown():
    stored = {"scheme": "https", "host": "ｅｖｉｌ.example", "port": 443}
    assert cooldown_identity(KIND_TARGET_AUTHORIZE, stored)["host"] == "evil.example"


def test_the_target_host_in_another_spelling_is_the_same_host():
    refusal = destination_refusal(TARGET, "https://ａｐｐ.example.test:8443", {}, principal_slot="primary")
    assert refusal.reason_code == "scope_other_service_port"
    assert scanner_destination_refusal(TARGET, "https://APP.example.test.") is None


def test_the_approval_screen_shows_the_ascii_form():
    shown = render(KIND_TARGET_AUTHORIZE, {
        "host": "bücher.example", "port": 443, "scheme": "https", "origin": "https://bücher.example:443",
        "same_host": False, "addresses": ["93.184.216.34"], "target_id": "t1",
    }, {})
    text = " ".join(str(value) for value in shown.values())
    assert "xn--bcher-kva.example" in text
    assert "bücher" not in shown["title"]


@pytest.mark.parametrize("origin", SPELLINGS)
def test_a_grant_matches_every_spelling(origin):
    policy = {"granted_destinations": [{"scheme": "https", "host": "evil.example", "port": 443,
                                         "addresses": ["93.184.216.34"]}]}
    assert granted_destination(policy, origin) is not None


def test_an_unencodable_host_is_an_invalid_origin():
    refusal = destination_refusal(TARGET, "https://" + "é" * 70 + ".example", {}, principal_slot="anonymous")
    assert refusal.reason_code == "scope_origin_invalid"


@pytest.mark.parametrize("origin", ["https://evil.example:0", "http://evil.example:0"])
def test_port_zero_is_not_the_default_port(origin):
    """``destination_refusal`` refuses port 0; the grant match read it as 443 (or 80)."""
    policy = {"granted_destinations": [
        {"scheme": scheme, "host": "evil.example", "port": port, "addresses": ["93.184.216.34"]}
        for scheme, port in (("https", 443), ("http", 80))
    ]}
    assert granted_destination(policy, origin) is None
    assert destination_refusal(TARGET, origin, {}, principal_slot="anonymous").reason_code == "scope_origin_invalid"
