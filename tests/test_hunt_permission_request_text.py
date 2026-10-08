"""What a person reads before approving a Hunt permission request (live acceptance, 2026-10-08).

* D41: a ``target.authorize`` request for another host said "another service on the Hunt's host
  shakerscan.com" when the Hunt's host was honey.shakerscan.com, so the person approved on wrong
  wording. Another host now says so, with the addresses it is pinned to, and offers no remember
  (that records the Hunt's own target's authorization).

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
