"""A caller must not be told it registered one origin while the system uses another.

Web target identity is host-level by design: `http://host` and `https://host:8443` are one asset,
and a whole migration exists to merge rows that differed only by scheme or port. That is a
deliberate trade-off, not a defect. What is a defect is doing it silently.

`POST /targets` for `http://host:2222` returned the existing `http://host:1111` target with nothing
in the response saying the requested URL was not adopted, and `POST /arsenal/scope/preview`
accepted a URL for a target whose origin differs and returned `verdict: allowed` -- so the receipt
attested to a subject that would never be scanned. Observed live: a Hunt verification ran against a
completely different application on the same host and produced a result that looked correct.
"""

from __future__ import annotations

from tests.api_sources import definition_source


def test_target_creation_reports_a_resolved_origin_mismatch():
    source = definition_source("create_target")
    # The caller has to be able to see that its URL was not the one adopted.
    assert "requested_url" in source
    assert "origin_merged" in source


def test_scope_preview_refuses_a_url_from_another_origin():
    source = definition_source("arsenal_scope_preview")
    assert "_scope_origin_matches_target" in source


def test_the_origin_comparison_ignores_path_but_not_port():
    from api.action_scope import scope_origin_matches_target as matches

    # Same origin, different path: legitimate, a scope may narrow to a route.
    assert matches("http://host.test:3001/app/login", "http://host.test:3001") is True
    assert matches("http://host.test:3001", "http://host.test:3001/") is True
    # Different port on the same host is the dangerous case: host-level identity merges the
    # targets, so the receipt would attest to an origin the scan never touches.
    assert matches("http://host.test:8899", "http://host.test:3001") is False
    # Default ports are equivalent to their explicit form.
    assert matches("https://host.test", "https://host.test:443") is True
    assert matches("http://host.test", "http://host.test:80") is True
    # A different host is refused for the same reason.
    assert matches("http://other.test:3001", "http://host.test:3001") is False


def test_a_missing_or_unparseable_side_does_not_silently_pass():
    from api.action_scope import scope_origin_matches_target as matches

    # Unknown identity is not matching identity: the whole point is to refuse to attest to an
    # origin nobody established.
    assert matches("", "http://host.test:3001") is False
    assert matches("http://host.test:3001", "") is False
    assert matches("not a url", "http://host.test:3001") is False


def test_host_asset_scope_accepts_its_services_without_inventing_a_web_origin():
    from api.action_scope import scope_origin_matches_target as matches

    for scope in ("http://192.168.1.187", "https://192.168.1.187:8443/login"):
        assert matches(scope, "host://192.168.1.187") is True
    assert matches("http://[fd00::187]:8080/", "host://[fd00::187]") is True
    assert matches("https://tv.test:443", "host://TV.TEST.") is True
    assert matches("https://other.test:8443", "host://tv.test") is False
    assert matches("http://192.168.1.188", "host://192.168.1.187") is False
    assert matches("host://192.168.1.187", "host://192.168.1.187") is False
    assert matches("http://tv.test", "host://tv.test:invalid") is False
    assert matches("http://tv.test", "host://operator@tv.test") is False


def test_host_membership_does_not_admit_a_blocked_destination():
    from api.action_scope import evaluate_scope, scope_origin_matches_target

    url = "http://169.254.169.254"
    assert scope_origin_matches_target(url, "host://169.254.169.254") is True
    assert evaluate_scope(url, allowed_hosts=["169.254.169.254"], environment="lab").verdict == "blocked"
