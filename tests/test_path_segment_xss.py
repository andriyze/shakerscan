"""Reflected XSS on id-like PATH segments (docs proposed-next-steps §12).

Query-only XSS testing misses path-parameter reflection (e.g. /track-order/{id}).
These pin the generic, route-name-free injectable-segment detector and the URL
rebuild — and confirm a path-reflected payload is detected end-to-end.
"""

import asyncio
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner_tools"))

from scanner_tools import active_checks as ac  # noqa: E402


def _seg(url):
    return ac._injectable_path_segment(urllib.parse.urlparse(url).path)


def test_detects_numeric_path_id():
    s = _seg("http://h/orders/42")
    assert s == ("42", 2)


def test_detects_uuid_path_id():
    u = "550e8400-e29b-41d4-a716-446655440000"
    s = _seg(f"http://h/users/{u}/profile")
    assert s == (u, 2)


def test_detects_mixed_alnum_order_token():
    # Juice-Shop-style order id: letters+digits, >=6 chars.
    s = _seg("http://h/rest/track-order/ab12cd34")
    assert s == ("ab12cd34", 3)


def test_ignores_pure_route_words():
    # No id-like segment -> nothing to fuzz (won't fuzz literal route names).
    assert _seg("http://h/rest/products/reviews") is None
    assert _seg("http://h/api/v2/login") is None


def test_short_segments_not_treated_as_ids():
    assert _seg("http://h/a/v2") is None


def test_build_path_segment_url_replaces_only_target_segment():
    parsed = urllib.parse.urlparse("http://h/rest/track-order/ab12cd34")
    out = ac._build_path_segment_url(parsed, 3, "<script>alert(1)</script>")
    assert "/rest/track-order/" in out
    assert "track-order" in out  # sibling segments untouched
    assert "%3Cscript%3E" in out  # payload url-encoded into the path


def test_path_segment_reflected_payload_is_detected(monkeypatch):
    # Stub curl so the path-injected payload is reflected unencoded -> finding.
    async def fake_run(cmd, timeout=15):
        test_url = cmd[-1]
        seg = urllib.parse.urlparse(test_url).path.rsplit("/", 1)[-1]
        reflected = urllib.parse.unquote(seg)
        body = f"<html><body>Order {reflected} not found</body></html>"
        return f"{body}\n200\ntext/html", "", 0

    monkeypatch.setattr(ac, "run", fake_run)
    res = asyncio.run(ac.custom_xss_test("http://h/rest/track-order/ab12cd34"))
    assert res["findings"], "expected a path-segment XSS finding"
    f = res["findings"][0]
    assert f["injection_point"] == "path_segment"
    assert f["severity"] == "high"


def test_no_injectable_surface_returns_empty():
    # No query, no fragment, no id-like path segment.
    res = asyncio.run(ac.custom_xss_test("http://h/rest/products/reviews"))
    assert res == {"findings": [], "tested": 0, "vulnerable": False}


# ---------------------------------------------------------------------------
# smart_xss_test path-segment coverage (the smart engine, not the legacy loop)
# ---------------------------------------------------------------------------

def _html_reflect_run():
    async def fake_run(cmd, timeout=15):
        seg = urllib.parse.urlparse(cmd[-1]).path.rsplit("/", 1)[-1]
        reflected = urllib.parse.unquote(seg)
        body = f"<html><body>Order {reflected} not found</body></html>"
        return f"{body}", "", 0
    return fake_run


def _json_reflect_run():
    async def fake_run(cmd, timeout=15):
        seg = urllib.parse.urlparse(cmd[-1]).path.rsplit("/", 1)[-1]
        reflected = urllib.parse.unquote(seg)
        # Value echoed into a JSON API response (Juice-Shop /rest/track-order shape).
        body = '{"status":"success","data":[{"orderId":"%s"}]}' % reflected
        return f"{body}", "", 0
    return fake_run


def test_smart_xss_path_segment_html_reflection_is_detected(monkeypatch):
    # A path segment reflected unescaped into an executable HTML context is a
    # finding even with no browser (medium without execution proof).
    monkeypatch.setattr(ac, "run", _html_reflect_run())
    monkeypatch.setattr(ac, "HAS_XSS_PROOF", False)
    res = asyncio.run(ac.smart_xss_test(
        "http://h", [{"url": "http://h/rest/track-order/ab12cd34", "method": "GET"}],
        max_endpoints=5))
    assert res["findings"], "expected a path-segment XSS finding in HTML context"
    f = res["findings"][0]
    assert f["injection_point"] == "path_segment"
    assert f["param"] == "ab12cd34"
    assert f["severity"] == "medium"       # unescaped HTML but not browser-proven
    assert f["verified"] is False


def test_smart_xss_path_segment_json_echo_is_suppressed(monkeypatch):
    # The SAME value echoed into a JSON response is NOT XSS at that layer; with no
    # execution proof it must NOT be reported (precision — else every id-reflecting
    # REST endpoint becomes a false high).
    monkeypatch.setattr(ac, "run", _json_reflect_run())
    monkeypatch.setattr(ac, "HAS_XSS_PROOF", False)
    res = asyncio.run(ac.smart_xss_test(
        "http://h", [{"url": "http://h/rest/track-order/ab12cd34", "method": "GET"}],
        max_endpoints=5))
    assert res["findings"] == [], "JSON echo without execution proof must not be reported"


def test_smart_xss_path_segment_browser_proof_is_high_verified(monkeypatch):
    # Browser-proven path-segment XSS -> verified High with explicit CVSS so the
    # generic reflected base score can't cap it to medium.
    class _Proof:
        proven = True
        confidence = 0.99
        technique = "headless_xss_dialog"
        extracted_data = "Dialog triggered: xss"

        def to_dict(self):
            return {"technique": self.technique, "proven": True}

    async def fake_proof(url, param, payload, prebuilt_url=None, **kwargs):
        return _Proof()

    monkeypatch.setattr(ac, "run", _html_reflect_run())
    monkeypatch.setattr(ac, "HAS_XSS_PROOF", True)
    monkeypatch.setattr(ac, "prove_xss_headless", fake_proof)
    res = asyncio.run(ac.smart_xss_test(
        "http://h", [{"url": "http://h/rest/track-order/ab12cd34", "method": "GET"}],
        max_endpoints=5))
    assert res["findings"], "expected a browser-proven path-segment finding"
    f = res["findings"][0]
    assert f["injection_point"] == "path_segment"
    assert f["verified"] is True
    assert f["severity"] == "high"
    assert f.get("cvss_score") == 7.4
    assert f.get("browser_proof")
