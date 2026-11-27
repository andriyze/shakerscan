"""Same-site decisions in scanner code use the Public Suffix List (PRIVATE section included),
never "the last two labels": credentials, first-party trust and crawl scope must not cross
registrants such as victim.github.io and attacker.github.io (unit tests, no network)."""
from __future__ import annotations

import pytest

from scanner_tools import common, form_login, vendor_risk
from scanner_tools.registrable import same_site, site_of


@pytest.mark.parametrize(("action", "base", "safe"), [
    ("https://attacker.github.io/collect", "https://victim.github.io/login", False),
    ("https://evil.herokuapp.com/x", "https://app.herokuapp.com/login", False),
    ("https://other.co.uk/login", "https://shop.example.co.uk/login", False),
    ("https://auth.example.co.uk/login", "https://shop.example.co.uk/login", True),
    ("https://auth.example.com/session", "https://app.example.com/login", True),
    ("https://victim.github.io/session", "https://victim.github.io/login", True),
    ("/session", "https://victim.github.io/login", True),
    ("http://auth.example.com/session", "https://app.example.com/login", False),
])
def test_form_login_never_posts_credentials_to_another_registrant(action, base, safe):
    assert form_login._is_action_safe_for_credentials(action, base) is safe


@pytest.mark.parametrize(("host", "site"), [
    ("victim.github.io", "victim.github.io"), ("cdn.example.co.uk", "example.co.uk"),
    ("app.example.com:8443", "example.com"), ("[2001:db8::1]", "2001:db8::1"),
    ("localhost", "localhost"), ("github.io", "github.io"),
])
def test_site_of(host, site):
    assert site_of(host) == site
    assert form_login._registrable_domain(host) == site


def test_vendor_risk_first_party_check_honours_private_suffixes():
    assert vendor_risk.get_registrable_domain("cdn.example.co.uk") == "example.co.uk"
    assert vendor_risk.is_third_party("https://attacker.github.io/a.js", "victim.github.io")
    assert not vendor_risk.is_third_party("https://static.example.com/a.js", "www.example.com")
    assert not same_site("victim.github.io", "attacker.github.io")


@pytest.mark.parametrize(("url", "base", "in_scope"), [
    ("https://attacker.github.io/", "https://github.io/", False),
    ("https://evil.co.uk/", "https://www.co.uk/", False),
    ("https://api.example.com/", "https://www.example.com/", True),
    ("https://a.b.example.com/", "https://b.example.com/", True),
])
def test_crawl_scope_never_takes_in_a_public_suffix_subtree(url, base, in_scope):
    assert common.is_in_scope_url(url, base) is in_scope
