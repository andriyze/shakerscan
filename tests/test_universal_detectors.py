"""Unit tests for the universal DAST detector improvements shipped this iteration.

These validate detector LOGIC without running a scan (the lab target is not
required): directory-listing parsing + sensitive-file harvest + encoded-null-byte
allowlist bypass, the content-gated auto-CRUD BFLA validator, the _fetch_url
IncompleteRead robustness fix, and source-level guards for the iframe DOM-XSS
vector and exposure_infra-in-smart. All detectors are app-agnostic; Juice Shop is
only the benchmark that exercised them.
"""
import asyncio
import http.client
import importlib
import os
import sys

_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
_added = _SCANNER_DIR not in sys.path
if _added:
    sys.path.insert(0, _SCANNER_DIR)
try:
    ic = importlib.import_module("scanner_tools.infrastructure_checks")
    ac = importlib.import_module("scanner_tools.access_control_checks")
finally:
    pass

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Directory-listing parsing (Apache "Index of", nginx autoindex, Node serve-index)
# ---------------------------------------------------------------------------
def test_parse_listing_hrefs_extracts_files_skips_dirs_and_sort_links():
    html = (
        '<a href="/parent">..</a>'
        '<a href="acquisitions.md">acquisitions.md</a>'
        '<a href="coupons_2013.md.bak">coupons</a>'
        '<a href="subdir/">subdir/</a>'      # directory -> skip
        '<a href="?C=N;O=D">Name</a>'        # sort link -> skip
        '<a href="https://x/evil">ext</a>'   # external -> skip
    )
    files = ic._parse_listing_hrefs(html)
    assert "acquisitions.md" in files
    assert "coupons_2013.md.bak" in files
    assert all(not f.endswith("/") for f in files)
    assert "Name" not in files and "evil" not in files


def test_serve_index_markers_present():
    # Node serve-index renders "listing directory" / id="files", not "Index of".
    src = open(os.path.join(_SCANNER_DIR, "scanner_tools", "infrastructure_checks.py")).read()
    assert "listing directory" in src
    assert 'id="files"' in src


def test_s3_listing_parser_does_not_expand_external_entities():
    hostile = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE bucket [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        '<Contents><Key>&xxe;</Key></Contents></ListBucketResult>'
    )

    extracted = ic._extract_s3_files(hostile)

    assert extracted == ["&xxe;"]
    assert not any("root:" in value for value in extracted)


# ---------------------------------------------------------------------------
# Sensitive-file harvest + encoded-null-byte allowlist bypass (CWE-158)
# ---------------------------------------------------------------------------
def test_harvest_listed_files_direct_and_nullbyte_bypass(monkeypatch):
    listing = (
        '<a href="acquisitions.md">acquisitions.md</a>'      # readable directly
        '<a href="coupons_2013.md.bak">coupons.bak</a>'       # blocked -> needs bypass
        '<a href="readme.txt">readme.txt</a>'                 # not sensitive, readable
    )

    async def fake_fetch(url, method="GET", timeout=10, headers=None):
        # .bak blocked directly (403); its %2500.md bypass succeeds.
        if url.endswith("coupons_2013.md.bak"):
            return (403, "", {})
        if "coupons_2013.md.bak%2500" in url:
            return (200, "PROMO: secret coupon codes\nAES key material", {})
        if url.endswith("acquisitions.md"):
            return (200, "CONFIDENTIAL acquisition target memo", {})
        if url.endswith("readme.txt"):
            return (200, "just a readme", {})
        return (404, "", {})

    monkeypatch.setattr(ic, "_fetch_url", fake_fetch)
    found = asyncio.run(ic.harvest_listed_files("http://t/ftp/", listing))
    by_file = {f["file"]: f for f in found}
    # The .bak is reported and flagged as accessed via the null-byte bypass.
    assert "coupons_2013.md.bak" in by_file
    assert by_file["coupons_2013.md.bak"]["bypass"] == "encoded_null_byte"
    # The directly-readable confidential .md is reported (sensitive markers/ext).
    assert "acquisitions.md" in by_file
    # A plain readme with no sensitive ext/markers is not reported as a finding.
    assert "readme.txt" not in by_file


# ---------------------------------------------------------------------------
# Content-gated auto-CRUD BFLA (fires only on leaked PII/creds, not public data)
# ---------------------------------------------------------------------------
def test_bfla_validator_fires_on_pii_not_on_public_catalog():
    pii = '[{"email":"a@b.c","password":"$2a$hash","role":"admin"}]'
    catalog = '[{"id":1,"name":"Apple Juice","price":1.99,"image":"a.png"}]'
    ok_pii, _ = ac._has_category_content(pii, "application/json", "rest_api_models")
    ok_cat, _ = ac._has_category_content(catalog, "application/json", "rest_api_models")
    assert ok_pii is True
    assert ok_cat is False


def test_bfla_validator_rejects_html_shell():
    html = "<!doctype html><html><head></head><body><app-root></app-root></body></html>"
    ok, _ = ac._has_category_content(html, "text/html", "rest_api_models")
    assert ok is False


def test_bfla_category_maps_to_high_severity():
    assert ac.determine_severity(200, "rest_api_models", "/api/Users") == "high"
    # case-sensitive PascalCase model routes are registered
    paths = ac.PRIVILEGED_PATHS.get("rest_api_models", [])
    assert "/api/Users" in paths


# ---------------------------------------------------------------------------
# _fetch_url robustness: a body that trips urllib IncompleteRead must NOT be
# dropped (Node serve-index / chunked responses) — return the bytes read.
# ---------------------------------------------------------------------------
def test_fetch_url_returns_partial_body_on_incomplete_read(monkeypatch):
    body = b"<title>listing directory /ftp/</title><div id=\"files\"></div>"

    class _FakeResp:
        def getcode(self):
            return 200
        headers = {}
        def read(self):
            raise http.client.IncompleteRead(body, 59)
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    monkeypatch.setattr(ic.urllib.request, "urlopen", lambda *a, **k: _FakeResp())
    status, out, _ = asyncio.run(ic._fetch_url("http://t/ftp/"))
    assert status == 200
    assert "listing directory" in out


# ---------------------------------------------------------------------------
# Source guards: iframe DOM-XSS vector + exposure_infra in the smart preset
# ---------------------------------------------------------------------------
def test_iframe_domxss_vector_present_in_hash_route_payloads():
    src = open(os.path.join(_SCANNER_DIR, "scanner_tools", "active_checks.py")).read()
    # The vector that survives Angular/React sanitizers (Juice Shop's headline DOM XSS).
    assert 'iframe src=\\"javascript:alert(1)\\"' in src or 'iframe src="javascript:alert(1)"' in src
    assert "iframe_js_uri" in src


def test_smart_scan_enables_infrastructure_exposure():
    src = open(os.path.join(_SCANNER_DIR, "scanner.py")).read()
    # Within the --smart preset block, exposure_infra must be enabled.
    smart_idx = src.index("if args.smart:")
    # find the end of the smart block (next dedented 'if args.' at col 4)
    tail = src[smart_idx: smart_idx + 2000]
    assert "args.exposure_infra = True" in tail
