"""Finding-count-explosion collapse + strict anti-over-merge (docs proposed-next-steps §5).

One templated BOLA route (/orders/1../orders/46) and one SQLi param tested with N
payloads must collapse to a SINGLE finding identity — while genuinely distinct
vulns (different path template, parameter, method, or vuln class) must NOT merge.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from findings import template_path, templated_finding_identity  # noqa: E402


def fid(url, cwe="CWE-639", method=None, evidence=None):
    f = {"url": url, "cwe": cwe}
    ev = dict(evidence or {})
    if method:
        ev["method"] = method
    if ev:
        f["evidence"] = ev
    return templated_finding_identity(f)


# ---- template_path ----------------------------------------------------------

def test_template_path_collapses_numeric_uuid_hex():
    assert template_path("/orders/1") == "/orders/{id}"
    assert template_path("/orders/46") == "/orders/{id}"
    assert template_path("/users/550e8400-e29b-41d4-a716-446655440000") == "/users/{uuid}"
    assert template_path("/blob/0123456789abcdef0123456789abcdef") == "/blob/{hash}"


def test_template_path_keeps_literal_route_names():
    # Never collapse real route names — that would merge distinct endpoints.
    assert template_path("/users/profile") == "/users/profile"
    assert template_path("/api/v2/login") == "/api/v2/login"


# ---- collapse (SHOULD merge) ------------------------------------------------

def test_bola_path_ids_collapse():
    a = fid("http://h:8888/workshop/api/shop/orders/1")
    b = fid("http://h:8888/workshop/api/shop/orders/10")
    c = fid("http://h:8888/workshop/api/shop/orders/46")
    assert a == b == c


def test_bola_query_id_values_collapse():
    a = fid("http://h:8888/identity/api/v2/user/dashboard?id=15")
    b = fid("http://h:8888/identity/api/v2/user/dashboard?id=17")
    c = fid("http://h:8888/identity/api/v2/user/dashboard?id=21")
    assert a == b == c


def test_sqli_same_param_different_payloads_collapse():
    # The concrete payload lives in the query VALUE, not the identity.
    a = fid("http://h/search?q=' OR 1=1--", cwe="CWE-89")
    b = fid("http://h/search?q=' UNION SELECT NULL--", cwe="CWE-89")
    assert a == b


# ---- anti-over-merge (must NOT merge) ---------------------------------------

def test_different_path_template_does_not_merge():
    assert fid("http://h/orders/1") != fid("http://h/comments/1")


def test_different_query_param_does_not_merge():
    # /search?q (one SQLi) vs /search?name (a different SQLi) stay distinct.
    a = fid("http://h/search?q=x", cwe="CWE-89")
    b = fid("http://h/search?name=x", cwe="CWE-89")
    assert a != b


def test_different_vuln_class_does_not_merge():
    a = fid("http://h/search?q=x", cwe="CWE-89")   # SQLi
    b = fid("http://h/search?q=x", cwe="CWE-79")   # XSS
    assert a != b


def test_different_method_does_not_merge():
    a = fid("http://h/api/items", cwe="CWE-89", method="GET")
    b = fid("http://h/api/items", cwe="CWE-89", method="POST")
    assert a != b


def test_literal_sibling_routes_do_not_merge():
    assert fid("http://h/admin") != fid("http://h/users")


# ---- non-endpoint findings keep existing identity ---------------------------

def test_non_endpoint_finding_returns_none():
    # TLS/header/DNS/config findings have no endpoint URL -> keep scanner id.
    assert templated_finding_identity({"title": "Missing HSTS", "cwe": "CWE-693"}) is None
    assert templated_finding_identity({"cwe": "CWE-89", "url": "not a url"}) is None


def test_evidence_url_used_when_top_level_url_absent():
    f = {"cwe": "CWE-639", "evidence": {"url": "http://h/orders/7"}}
    assert templated_finding_identity(f) == fid("http://h/orders/99")


# ---- CWE-less checks keep their own identity ---------------------------------

def _header_finding(header):
    return {
        "url": "http://crapi-web/", "tool": "nuclei", "cwe": None,
        "title": f"Missing HTTP response header: {header}",
        "evidence": {"template_id": "http-missing-security-headers", "matcher_name": header.lower()},
    }


def test_cwe_less_template_matches_on_one_route_do_not_merge():
    """Ten missing-header findings on "/" have no CWE. Keying them on the tool
    name gave every one the same identity, so a scan that observed ten
    persisted one row and dropped nine. Every target scanned since carried
    exactly one header finding whose title changed from scan to scan."""
    headers = ("Content-Security-Policy", "X-Frame-Options", "Referrer-Policy",
               "Strict-Transport-Security", "X-Content-Type-Options")
    identities = {templated_finding_identity(_header_finding(h)) for h in headers}
    assert len(identities) == len(headers)


def test_the_same_cwe_less_check_still_collapses_across_payloads():
    a = templated_finding_identity({**_header_finding("X-Frame-Options"), "url": "http://crapi-web/?v=1"})
    b = templated_finding_identity({**_header_finding("X-Frame-Options"), "url": "http://crapi-web/?v=2"})
    assert a == b


def test_a_cwe_less_finding_without_a_template_falls_back_to_its_title():
    a = templated_finding_identity({"url": "http://h/", "tool": "custom", "title": "Directory listing enabled"})
    b = templated_finding_identity({"url": "http://h/", "tool": "custom", "title": "Server banner disclosed"})
    assert a != b
