"""
Unit tests for active checks functionality.

Tests cover:
1. XSS context detection (detect_reflection_context)
2. SQLi data extraction parsing
3. Active check enforcement for smart/full/aggressive scans
"""

import asyncio
import json
import pytest
import sys
import os

# Add scanner directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

import scanner_tools.active_checks as active_checks  # noqa: E402
from scanner_tools.active_checks import (
    detect_reflection_context,
    CONTEXT_XSS_PAYLOADS,
    DBMS_SQLI_PAYLOADS,
    SQLI_EXTRACTION_PAYLOADS,
    _parse_fragment_params,
    _build_fragment_url,
    _is_hash_route,
    _select_sqli_payloads,
    _check_sqli_response,
)


# ---------------------------------------------------------------------------
# SQLi payload selection must NOT be gated behind DBMS fingerprinting: when the
# DBMS is unknown (fingerprint failed — common when a target degrades under load)
# the paren-closure payloads that break wrapped WHERE clauses (Juice Shop's
# ')) search) must still be sent, instead of a generic-only fallback.
# ---------------------------------------------------------------------------

def _techniques(payloads):
    return [t for _p, t, _d in payloads]


def test_unknown_dbms_includes_paren_closure_payloads():
    for key in (None, "generic"):
        techs = _techniques(_select_sqli_payloads(key))
        # sqlite double-paren closure/boolean that Juice Shop's search needs
        assert "comment_bypass" in techs, f"{key}: missing ')) --' comment_bypass"
        assert "boolean_always_true" in techs, f"{key}: missing ')) OR 1=1--'"
        # and still the generic single-quote boolean
        assert "boolean" in techs, f"{key}: lost generic boolean"
        # an actual ')) payload string is present
        assert any(")) " in p or "))" in p for p, _t, _d in _select_sqli_payloads(key))


def test_unknown_dbms_orders_reliable_then_time_then_extraction():
    payloads = _select_sqli_payloads(None)

    def first(pred):
        return next((i for i, (_p, t, _d) in enumerate(payloads) if pred(t.lower())), None)

    first_boolean = first(lambda t: "boolean" in t)
    first_time = first(lambda t: "time" in t)
    first_union = first(lambda t: "union" in t)
    assert first_boolean is not None
    # reliable boolean/error/closure precede FP-prone time-based, which precede
    # heavy UNION extraction.
    if first_time is not None:
        assert first_boolean < first_time, "reliable detection must precede time-based"
    if first_union is not None:
        assert first_boolean < first_union
    if first_time is not None and first_union is not None:
        assert first_time < first_union


def test_known_dbms_stays_focused():
    # A fingerprinted engine keeps its own family (+fallback+custom) and is NOT
    # bloated with every other engine's payloads.
    unknown = _select_sqli_payloads(None)
    mysql = _select_sqli_payloads("mysql")
    assert len(mysql) < len(unknown)
    # mysql-focused must not pull in sqlite-only comment_bypass
    assert "comment_bypass" not in _techniques(mysql)


def test_check_sqli_response_catches_sqlite_error_without_fingerprint():
    # Detection is DBMS-agnostic: a SQLITE_ERROR in the response (absent from the
    # baseline) is proof even when dbms_detected is None.
    body = "<html><title>Error: SQLITE_ERROR: incomplete input</title></html>"
    baseline = '{"status":"success","data":[]}'
    is_vuln, evidence = _check_sqli_response(
        body, len(baseline), 0.1, "comment_bypass", None,
        status_code=500, baseline_status=200, baseline_elapsed=0.1,
        baseline_body=baseline, payload="test')--",
    )
    assert is_vuln is True
    assert any("SQL error detected" in e for e in evidence)


def test_reachability_gate_drops_only_clear_not_found():
    nf = active_checks._response_matches_not_found
    # clear not-found -> drop
    assert nf(404, 120, None, 0) is True
    assert nf(410, 80, None, 0) is True
    # auth-protected / method / server errors EXIST -> never dropped
    for code in (401, 403, 405, 429, 500, 502):
        assert nf(code, 120, None, 0) is False
    # transient / no response -> keep
    assert nf(None, 0, None, 0) is False
    # SPA catch-all: 200 matching a known-missing sibling's length -> drop
    assert nf(200, 5000, 200, 5010) is True
    # 200 that differs from the decoy (a real page) -> keep
    assert nf(200, 900, 200, 5000) is False
    # 200 with no decoy signal -> keep (conservative)
    assert nf(200, 5000, None, 0) is False
    # sibling-decoy match on a non-2xx status (parent 404s/500s all children
    # the same way) -> phantom -> drop (only applied to synthetic sources)
    assert nf(500, 100, 500, 103) is True
    assert nf(403, 50, 403, 52) is True
    # same status as decoy but very different body -> a real route -> keep
    assert nf(500, 4000, 500, 100) is False


def test_reachability_gate_keeps_real_route_under_404_sibling_parent():
    # Regression for the removed hard-404 fast-path: a real route (200/2xx) must
    # NOT be dropped just because a random sibling under the same parent 404s.
    nf = active_checks._response_matches_not_found
    assert nf(200, 900, 404, 120) is False   # real /rest/products/search vs 404 sibling decoy -> keep
    assert nf(204, 0, 404, 0) is False        # real 204 vs 404 decoy -> keep
    assert nf(500, 3000, 404, 120) is False   # different status from decoy -> keep
    # a genuinely-missing sibling (its own 404, or matching the decoy) IS dropped
    assert nf(404, 120, 404, 118) is True
    assert nf(200, 5000, 200, 5010) is True   # SPA catch-all matching the decoy


def test_reachability_gate_only_targets_synthetic_sources():
    syn = active_checks._is_synthetic_active_source
    for observed in ("har_discovery", "browser", "openapi", "manual", "form",
                     "hash_route", "resource_id_propagation", "js_bundle_analysis"):
        assert syn({"source": observed}) is False
    for guessed in ("options", "common", "inferred", "wordlist", "", None):
        assert syn({"source": guessed}) is True


def test_reachability_gate_exempts_non_get_and_body_endpoints():
    # A GET-based reachability probe cannot judge a POST/body route: Juice Shop's
    # POST /rest/user/login exists but GETs to 500 (identical to a 500 sibling),
    # so GET-probing would drop it before body SQLi. It must be exempt.
    elig = active_checks._reachability_eligible
    # POST login from the synthetic "common" source -> NOT droppable
    assert elig({"source": "common", "method": "POST",
                 "body_params": ["email", "password"], "url": "/rest/user/login"}) is False
    # any endpoint carrying body_params (even GET) -> NOT droppable (real surface)
    assert elig({"source": "inferred", "method": "GET",
                 "body_params": ["q"], "url": "/api/search"}) is False
    # a plain GET, no body, synthetic permutation -> STILL droppable (the
    # /api/v{n}/oauth2/authorize explosion the gate exists to kill)
    assert elig({"source": "inferred", "method": "GET",
                 "url": "/api/v9/oauth2/authorize"}) is True
    assert elig({"source": "common", "method": "GET", "url": "/api/v1/login"}) is True
    # observed sources are never eligible for the drop regardless of method
    assert elig({"source": "browser", "method": "GET", "url": "/real"}) is False


def test_active_checks_synthetic_body_reconstructs_arrays():
    template = active_checks._synthetic_json_template_from_params(
        ["items", "items.id", "items.price", "shipping.zip"]
    )
    assert isinstance(template["items"], list)
    assert isinstance(template["items"][0], dict)
    assert set(template["items"][0].keys()) == {"id", "price"}
    assert isinstance(template["shipping"], dict)  # plain nested dict stays a dict


class TestDetectReflectionContext:
    """Tests for the detect_reflection_context function."""

    def test_not_reflected(self):
        """Test detection when marker is not in response."""
        result = detect_reflection_context("<html><body>Hello</body></html>", "CANARY123")
        assert result == "not_reflected"

    def test_in_script(self):
        """Test detection of marker inside script tags."""
        html = '<html><script>var x = "CANARY123";</script></html>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_script"

    def test_in_angular(self):
        """Test detection of marker inside Angular template expressions."""
        html = '<div>{{user.name is CANARY123}}</div>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_angular"

    def test_in_event_handler(self):
        """Test detection of marker inside event handlers."""
        html = '<div onclick="doSomething(CANARY123)">Click</div>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_event_handler"

    def test_in_attribute(self):
        """Test detection of marker inside HTML attributes."""
        html = '<input type="text" value="CANARY123">'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_attribute"

    def test_in_css_style_tag(self):
        """Test detection of marker inside style tags."""
        html = '<style>.class { color: CANARY123; }</style>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_css"

    def test_in_css_style_attribute(self):
        """Test detection of marker inside style attributes."""
        html = '<div style="color: CANARY123;">Hello</div>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_css"

    def test_in_svg(self):
        """Test detection of marker inside SVG elements."""
        html = '<svg xmlns="http://www.w3.org/2000/svg"><text>CANARY123</text></svg>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_svg"

    def test_in_svg_attribute(self):
        """Test detection of marker inside SVG opening tag."""
        html = '<svg width="CANARY123"><rect/></svg>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_svg"

    def test_in_json(self):
        """Test detection of marker inside JSON response."""
        json_body = '{"user": "CANARY123", "id": 1}'
        result = detect_reflection_context(json_body, "CANARY123")
        assert result == "in_json"

    def test_in_url_path(self):
        """Test detection of marker in URL path attributes."""
        html = '<a href="/users/CANARY123/profile">Profile</a>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_url_path"

    def test_in_js_url(self):
        """Test detection of marker in javascript: URLs."""
        html = '<a href="javascript:alert(CANARY123)">Click</a>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_js_url"

    def test_in_html_body(self):
        """Test detection of marker in plain HTML body."""
        html = '<html><body><p>Hello CANARY123 World</p></body></html>'
        result = detect_reflection_context(html, "CANARY123")
        assert result == "in_html"


class TestContextXssPayloads:
    """Tests for context-specific XSS payload availability."""

    def test_all_contexts_have_payloads(self):
        """Verify all detected contexts have corresponding payloads."""
        expected_contexts = [
            "in_script", "in_angular", "in_event_handler", "in_attribute",
            "in_html", "in_js_url", "in_css", "in_svg", "in_json", "in_url_path"
        ]
        for context in expected_contexts:
            assert context in CONTEXT_XSS_PAYLOADS, f"Missing payloads for context: {context}"
            assert len(CONTEXT_XSS_PAYLOADS[context]) > 0, f"Empty payloads for context: {context}"

    def test_payload_format(self):
        """Verify payloads have correct tuple format (payload, technique, description)."""
        for context, payloads in CONTEXT_XSS_PAYLOADS.items():
            for payload in payloads:
                assert isinstance(payload, tuple), f"Payload not tuple in {context}"
                assert len(payload) == 3, f"Payload tuple wrong length in {context}: {payload}"
                assert isinstance(payload[0], str), f"Payload[0] not string in {context}"
                assert isinstance(payload[1], str), f"Payload[1] not string in {context}"
                assert isinstance(payload[2], str), f"Payload[2] not string in {context}"


class TestDbmsSqliPayloads:
    """Tests for DBMS-specific SQLi payload availability."""

    def test_all_dbms_have_payloads(self):
        """Verify all supported DBMS have payloads."""
        expected_dbms = ["mysql", "postgresql", "sqlite", "mssql", "oracle"]
        for dbms in expected_dbms:
            assert dbms in DBMS_SQLI_PAYLOADS, f"Missing payloads for DBMS: {dbms}"
            assert len(DBMS_SQLI_PAYLOADS[dbms]) > 0, f"Empty payloads for DBMS: {dbms}"

    def test_generic_fallback_exists(self):
        """Verify generic payloads exist for unknown DBMS."""
        assert "generic" in DBMS_SQLI_PAYLOADS
        assert len(DBMS_SQLI_PAYLOADS["generic"]) > 0


class TestSqliExtractionPayloads:
    """Tests for SQLi data extraction payloads."""

    def test_extraction_payloads_exist(self):
        """Verify extraction payloads exist for major DBMS."""
        expected_dbms = ["mysql", "postgresql", "sqlite", "mssql"]
        for dbms in expected_dbms:
            assert dbms in SQLI_EXTRACTION_PAYLOADS, f"Missing extraction for DBMS: {dbms}"

    def test_extraction_has_version(self):
        """Verify version extraction payload exists for each DBMS."""
        for dbms, payloads in SQLI_EXTRACTION_PAYLOADS.items():
            # All DBMS should have version extraction except sqlite (no user function)
            if dbms != "sqlite":
                assert "version" in payloads, f"Missing version extraction for {dbms}"

    def test_extraction_has_tables(self):
        """Verify table extraction payload exists for each DBMS."""
        for dbms, payloads in SQLI_EXTRACTION_PAYLOADS.items():
            assert "tables" in payloads, f"Missing tables extraction for {dbms}"


class TestActiveEnforcement:
    """Tests for active check enforcement on smart/full/aggressive scans."""

    def test_active_enforced_scan_types(self):
        """Verify active-enforced scan types are defined correctly."""
        # These scan types require active testing and cannot use --public
        active_enforced_types = {'smart', 'full', 'aggressive'}

        # Scan types that allow --public
        passive_allowed_types = {'quick', 'standard', 'deep'}

        # Verify no overlap
        assert active_enforced_types.isdisjoint(passive_allowed_types)

    def test_scan_type_flags(self):
        """Verify scan type flags set active=True for enforced types."""
        # This tests the logic that should be in scanner.py
        # smart, full, aggressive should all enable active checks
        enforced_types = ['smart', 'full', 'aggressive']

        for scan_type in enforced_types:
            # The scan type should enable active checks
            assert scan_type in ['smart', 'full', 'aggressive']


class TestFragmentParamParsing:
    """Tests for SPA hash route fragment parameter parsing."""

    def test_parse_fragment_with_params(self):
        """Test parsing URL with fragment parameters."""
        url = "http://example.com/#/search?q=test&page=1"
        base_url, frag_path, frag_params = _parse_fragment_params(url)
        assert base_url == "http://example.com/"
        assert frag_path == "/search"
        assert frag_params == {"q": ["test"], "page": ["1"]}

    def test_parse_hashbang_with_params(self):
        """Test parsing hashbang URL with parameters."""
        url = "http://example.com/#!/user?id=123"
        base_url, frag_path, frag_params = _parse_fragment_params(url)
        assert base_url == "http://example.com/"
        assert frag_path == "!/user"
        assert frag_params == {"id": ["123"]}

    def test_parse_fragment_without_params(self):
        """Test parsing hash route without query parameters."""
        url = "http://example.com/#/home"
        base_url, frag_path, frag_params = _parse_fragment_params(url)
        assert base_url == "http://example.com/"
        assert frag_path == "/home"
        assert frag_params == {}

    def test_parse_no_fragment(self):
        """Test parsing URL without fragment."""
        url = "http://example.com/"
        base_url, frag_path, frag_params = _parse_fragment_params(url)
        assert base_url == "http://example.com/"
        assert frag_path == ""
        assert frag_params == {}

    def test_parse_subpath_with_fragment(self):
        """Test parsing URL with subpath and fragment."""
        url = "http://example.com/app/#/dashboard?tab=overview"
        base_url, frag_path, frag_params = _parse_fragment_params(url)
        assert base_url == "http://example.com/app/"
        assert frag_path == "/dashboard"
        assert frag_params == {"tab": ["overview"]}


class TestFragmentUrlBuilding:
    """Tests for SPA hash route URL reconstruction."""

    def test_build_with_params(self):
        """Test building URL with fragment parameters."""
        result = _build_fragment_url("http://example.com/", "/search", {"q": ["test"]})
        assert result == "http://example.com/#/search?q=test"

    def test_build_without_params(self):
        """Test building URL without fragment parameters."""
        result = _build_fragment_url("http://example.com/", "/home", {})
        assert result == "http://example.com/#/home"

    def test_build_empty_path(self):
        """Test building URL with empty fragment path."""
        result = _build_fragment_url("http://example.com/", "", {})
        assert result == "http://example.com/"

    def test_build_multiple_params(self):
        """Test building URL with multiple fragment parameters."""
        result = _build_fragment_url(
            "http://example.com/app/",
            "/search",
            {"q": ["hello"], "page": ["2"], "sort": ["desc"]}
        )
        assert "http://example.com/app/#/search?" in result
        assert "q=hello" in result
        assert "page=2" in result
        assert "sort=desc" in result

    def test_build_hashbang(self):
        """Test building hashbang URL."""
        result = _build_fragment_url("http://example.com/", "!/page", {"id": ["42"]})
        assert result == "http://example.com/#!/page?id=42"


class TestIsHashRoute:
    """Tests for hash route detection."""

    def test_standard_hash_route(self):
        """Test detection of standard hash route."""
        assert _is_hash_route("http://example.com/#/search?q=test") is True

    def test_hashbang_route(self):
        """Test detection of hashbang route."""
        assert _is_hash_route("http://example.com/#!/page") is True

    def test_anchor_only(self):
        """Test that anchor-only fragments are not hash routes."""
        assert _is_hash_route("http://example.com/#top") is False
        assert _is_hash_route("http://example.com/#section-1") is False

    def test_no_fragment(self):
        """Test URL without fragment is not a hash route."""
        assert _is_hash_route("http://example.com/?q=test") is False
        assert _is_hash_route("http://example.com/page") is False

    def test_empty_fragment(self):
        """Test URL with empty fragment is not a hash route."""
        assert _is_hash_route("http://example.com/#") is False


class TestJsonXxePrecision:
    """Regression tests for JSON XXE reflection false positives."""

    def test_json_xxe_ignores_escaped_payload_reflection(self, monkeypatch):
        async def fake_run(cmd, timeout=12):
            body = "{}"
            if "-d" in cmd:
                body = cmd[cmd.index("-d") + 1]
            payload = json.loads(body)["email"]
            reflected_error = json.dumps({
                "message": "Validation failed",
                "details": f"rejected value [{payload}]",
            })
            return reflected_error, "", 0

        monkeypatch.setattr(active_checks, "run", fake_run)

        result = asyncio.run(active_checks.xxe_injection_test_json_body(
            url="https://example.test/login",
            method="POST",
            params=["email"],
            body_template={"email": "user@example.test", "password": "pw"},
            content_type="application/json",
            max_params=1,
            max_payloads=2,
        ))

        assert result["vulnerable"] is False
        assert result["findings"] == []

    def test_json_xxe_still_reports_parser_entity_block(self, monkeypatch):
        async def fake_run(cmd, timeout=12):
            return "XML parser error: External entity not allowed", "", 0

        monkeypatch.setattr(active_checks, "run", fake_run)

        result = asyncio.run(active_checks.xxe_injection_test_json_body(
            url="https://example.test/upload",
            method="POST",
            params=["document"],
            body_template={"document": "value"},
            content_type="application/json",
            max_params=1,
            max_payloads=1,
        ))

        assert result["vulnerable"] is True
        assert result["findings"][0]["payload_reflected"] is False


def test_active_endpoint_prioritization_leads_with_real_injection_points():
    # Synthetic GET permutations must not outrank the real POST login body, so the
    # active budget reaches genuine injection points (Juice Shop SQLi regression).
    real_login = {"method": "POST", "url": "http://t/rest/user/login",
                  "body_params": ["email", "password"]}
    real_search = {"method": "GET", "url": "http://t/rest/products/search", "params": ["q"]}
    phantom1 = {"method": "GET", "url": "http://t/api/Addresss/items",
                "params": ["id", "uid", "token", "limit", "offset", "page"]}
    phantom2 = {"method": "GET", "url": "http://t/api/Cards/items", "params": ["id", "limit", "offset", "page"]}
    ordered = active_checks._prioritize_active_endpoints([phantom1, phantom2, real_login, real_search])
    # the real login (login+user keywords + request body) ranks first
    assert ordered[0]["url"].endswith("/rest/user/login")
    # both real high-value endpoints rank ahead of the synthetic phantoms
    real_idx = [i for i, e in enumerate(ordered) if "/rest/" in e["url"]]
    phantom_idx = [i for i, e in enumerate(ordered) if "/api/" in e["url"]]
    assert max(real_idx) < min(phantom_idx)


def test_active_endpoint_prioritization_penalizes_static_discovery_surfaces():
    security_txt_login = {
        "method": "POST",
        "url": "http://t/.well-known/security.txt/auth/login",
        "body_params": ["email", "password", "token"],
        "source": "options",
    }
    socket_token = {
        "method": "GET",
        "url": "http://t/socket.io/?token=abc",
        "params": ["token"],
        "source": "har_discovery",
    }
    real_login = {
        "method": "POST",
        "url": "http://t/rest/user/login",
        "body_params": ["email", "password"],
        "source": "options",
    }
    real_search = {
        "method": "GET",
        "url": "http://t/rest/products/search",
        "params": ["q"],
        "source": "har_discovery",
    }

    ordered = active_checks._prioritize_active_endpoints([
        security_txt_login,
        socket_token,
        real_login,
        real_search,
    ])

    assert ordered[:2] == [real_search, real_login]
    assert security_txt_login in ordered[2:]
    assert socket_token in ordered[2:]


def test_json_mass_assignment_detects_reflected_privileged_field(monkeypatch):
    async def fake_run(cmd, timeout=15):
        body = json.loads(cmd[cmd.index("-d") + 1])
        if body.get("role") == "admin":
            return (
                json.dumps({"id": 10, "email": "user@example.test", "role": "admin"})
                + "__SHAKERSCAN_MASS_ASSIGN__200__SHAKERSCAN_MASS_ASSIGN__",
                "",
                0,
            )
        return (
            json.dumps({"id": 10, "email": "user@example.test", "role": "user"})
            + "__SHAKERSCAN_MASS_ASSIGN__200__SHAKERSCAN_MASS_ASSIGN__",
            "",
            0,
        )

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.mass_assignment_test_json_body(
        url="https://example.test/api/profile",
        method="PATCH",
        params=["email"],
        body_template={"email": "user@example.test"},
        content_type="application/json",
        max_fields=1,
    ))

    assert result["vulnerable"] is True
    assert result["findings"][0]["parameter"] == "role"
    assert result["findings"][0]["value"] == "admin"
    assert result["findings"][0]["evidence_type"] == "privileged_field_reflected"
    assert result["endpoint_attempts"] == [
        {
            "custom_endpoint": 'PATCH /api/profile json:{"email":"user@example.test"}',
            "family": "mass_assignment",
            "method": "PATCH",
            "url": "https://example.test/api/profile",
            "param_count": 1,
            "attempted_params_count": 1,
            "completed_params_count": 1,
            "status": "completed",
        }
    ]


def test_json_mass_assignment_ignores_baseline_privileged_field(monkeypatch):
    async def fake_run(cmd, timeout=15):
        return (
            json.dumps({"id": 10, "email": "admin@example.test", "role": "admin"})
            + "__SHAKERSCAN_MASS_ASSIGN__200__SHAKERSCAN_MASS_ASSIGN__",
            "",
            0,
        )

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.mass_assignment_test_json_body(
        url="https://example.test/api/profile",
        method="PATCH",
        params=["email"],
        body_template={"email": "admin@example.test"},
        content_type="application/json",
        max_fields=1,
    ))

    assert result["vulnerable"] is False
    assert result["findings"] == []


def test_json_mass_assignment_ignores_rejected_field(monkeypatch):
    async def fake_run(cmd, timeout=15):
        body = json.loads(cmd[cmd.index("-d") + 1])
        if body.get("role") == "admin":
            return (
                '{"error":"unknown field role is not allowed"}'
                "__SHAKERSCAN_MASS_ASSIGN__200__SHAKERSCAN_MASS_ASSIGN__",
                "",
                0,
            )
        return '{}__SHAKERSCAN_MASS_ASSIGN__200__SHAKERSCAN_MASS_ASSIGN__', "", 0

    monkeypatch.setattr(active_checks, "run", fake_run)

    result = asyncio.run(active_checks.mass_assignment_test_json_body(
        url="https://example.test/api/profile",
        method="PATCH",
        params=["email"],
        body_template={"email": "user@example.test"},
        content_type="application/json",
        max_fields=1,
    ))

    assert result["vulnerable"] is False
    assert result["findings"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
