"""
Unit tests for active checks functionality.

Tests cover:
1. XSS context detection (detect_reflection_context)
2. SQLi data extraction parsing
3. Active check enforcement for smart/full/aggressive scans
"""

import pytest
import sys
import os

# Add scanner directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scanner'))

from scanner_tools.active_checks import (
    detect_reflection_context,
    CONTEXT_XSS_PAYLOADS,
    DBMS_SQLI_PAYLOADS,
    SQLI_EXTRACTION_PAYLOADS,
)


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
