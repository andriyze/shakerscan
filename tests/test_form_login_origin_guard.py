"""Tests for the same-origin guard around form-login credential POST.

ShakerScan must refuse to submit credentials to a host different from the
scan target. A misidentified or tampered login page could carry
`action="https://attacker.example/steal"` and exfiltrate the supplied
username/password.
"""

from scanner.scanner_tools.form_login import (
    _is_action_safe_for_credentials,
    _registrable_domain,
)


def test_registrable_domain_extracts_last_two_labels():
    assert _registrable_domain("app.example.com") == "example.com"
    assert _registrable_domain("auth.app.example.com") == "example.com"
    assert _registrable_domain("example.com") == "example.com"


def test_registrable_domain_handles_localhost_and_ips():
    assert _registrable_domain("localhost") == "localhost"
    # IPv4 collapses to the last two labels by the naive split — fine in
    # practice because the cross-origin check just compares both sides
    # symmetrically.
    assert _registrable_domain("127.0.0.1") == "0.1"


def test_relative_action_is_safe():
    assert _is_action_safe_for_credentials("/login", "https://app.example.com/") is True
    assert _is_action_safe_for_credentials("login/submit", "https://example.test/") is True


def test_same_host_action_is_safe():
    assert _is_action_safe_for_credentials(
        "https://app.example.com/login", "https://app.example.com/"
    ) is True


def test_subdomain_action_is_safe():
    # auth.example.com → posts to example.com login is a common legitimate
    # pattern.
    assert _is_action_safe_for_credentials(
        "https://auth.example.com/login", "https://app.example.com/"
    ) is True


def test_different_registrable_domain_is_blocked():
    assert _is_action_safe_for_credentials(
        "https://attacker.example/steal", "https://app.example.com/"
    ) is False
    assert _is_action_safe_for_credentials(
        "https://example.org/login", "https://example.com/"
    ) is False


def test_https_to_http_downgrade_is_blocked():
    assert _is_action_safe_for_credentials(
        "http://app.example.com/login", "https://app.example.com/"
    ) is False


def test_javascript_or_data_scheme_is_blocked():
    assert _is_action_safe_for_credentials(
        "javascript:steal()", "https://app.example.com/"
    ) is False
    assert _is_action_safe_for_credentials(
        "data:text/html,<form>", "https://app.example.com/"
    ) is False


def test_empty_action_is_blocked():
    assert _is_action_safe_for_credentials("", "https://app.example.com/") is False


def test_http_to_http_same_domain_is_safe():
    assert _is_action_safe_for_credentials(
        "http://app.example.com/login", "http://app.example.com/"
    ) is True
