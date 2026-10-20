"""A directory listing is a server-generated index, and a signature is a name, not a pattern.

Unit fixtures modelled on recorded scan evidence: an ordinary page titled "Directory listing"
that links to the real index was promoted to a verified listing, and the verified listings,
server status pages and private keys stored the raw regular expression as their signature,
which the finding page then showed as "Matched signature".
"""

from __future__ import annotations

import json

import pytest

from api.capabilities.exposure_probe import classify_exposure, redacted_exposure_excerpt
from api.finding_detail import build_finding_detail
from tests.graphql_fixtures import DVGA_GRAPHIQL

HTML = {"Content-Type": "text/html; charset=utf-8"}

# An ordinary page whose title and heading happen to say "Directory listing".
LANDING_PAGE = (
    b"<!doctype html><html><head><meta charset='utf-8'><title>Directory listing</title></head>"
    b'<body><h1>Directory listing</h1><ul><li><a href="/files/">Files</a></li></ul></body></html>'
)
# The real autoindex that page links to.
AUTOINDEX = (
    b"<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><hr><pre>"
    b'<a href="../">../</a>\n<a href="notes.txt">notes.txt</a>   16-Oct-2026 10:00   52\n'
    b"</pre><hr></body></html>"
)
APACHE_STATUS = (
    b"<html><head><title>Apache Status</title></head><body>"
    b"<h1>Apache Server Status for app.fixture.invalid (via 10.0.0.6)</h1>"
    b"<dl><dt>Server Version: Apache/2.4.41 (Ubuntu)</dt></dl></body></html>"
)
NGINX_STATUS = b"Active connections: 2 \nserver accepts handled requests\n 16 16 31 \nReading: 0 Writing: 1 Waiting: 1 \n"
APACHE_AUTO = b"app.fixture.invalid\nTotal Accesses: 12\nBusyWorkers: 1\nIdleWorkers: 4\nScoreboard: _W___....\n"
METRICS = b"# HELP http_requests_total Total requests.\n# TYPE http_requests_total counter\nhttp_requests_total 7\n"
REGEX_SYNTAX = ("(?", "\\", "|", "[", "^")


@pytest.mark.parametrize("title", [
    "Directory listing", "Directory Listings | City of Example", "Index of Enterprises",
    "Listing directory of local plumbers",
])
def test_a_page_titled_like_a_listing_is_not_a_listing(title):
    body = f"<html><head><title>{title}</title></head><body><a href='/files/'>Files</a></body></html>"
    assert classify_exposure(path="/", status=200, headers=HTML, body=body.encode()) is None


def test_the_landing_page_is_not_a_listing_but_the_index_it_links_to_is():
    assert classify_exposure(path="/", status=200, headers=HTML, body=LANDING_PAGE) is None
    listing = classify_exposure(path="/files/", status=200, headers=HTML, body=AUTOINDEX)
    assert listing is not None and listing.exposure_class == "directory_listing"


@pytest.mark.parametrize("path,body,content_type,klass", [
    ("/files/", AUTOINDEX, "text/html", "directory_listing"),
    ("/server-status", APACHE_STATUS, "text/html", "metrics_endpoint"),
    ("/server-status", APACHE_AUTO, "text/plain", "metrics_endpoint"),
    ("/nginx_status", NGINX_STATUS, "text/plain", "metrics_endpoint"),
    ("/metrics", METRICS, "text/plain", "metrics_endpoint"),
    ("/id_rsa", b"-----BEGIN " b"OPENSSH PRIVATE KEY-----\nb3Blbn...", "text/plain", "private_key_material"),
    ("/graphiql", DVGA_GRAPHIQL, "text/html", "graphql_ide_exposure"),
])
def test_signatures_are_names_and_excerpts_still_start_at_the_match(path, body, content_type, klass):
    signature = classify_exposure(path=path, status=200, headers={"Content-Type": content_type}, body=body)
    assert signature is not None and signature.exposure_class == klass
    assert not any(token in signature.matched_pattern for token in REGEX_SYNTAX), signature.matched_pattern
    if signature.exposure_class in {"directory_listing", "metrics_endpoint"}:
        excerpt = redacted_exposure_excerpt(body, signature)
        assert excerpt and len(excerpt) <= 400


def test_the_server_status_excerpt_starts_at_the_status_heading():
    padded = (b"<html><head><title>Apache Status</title>" + b"<meta name='x' content='y'>" * 40
              + b"</head><body><h1>Apache Server Status for app.fixture.invalid</h1>"
              + b"<dl><dt>Server Version: Apache/2.4.41 (Ubuntu)</dt></dl></body></html>")
    signature = classify_exposure(path="/server-status", status=200, headers=HTML, body=padded)
    assert signature is not None
    assert "Apache Server Status for" in redacted_exposure_excerpt(padded, signature)


def _exposure(url, klass, signature):
    return build_finding_detail({"tool": "shakerscan_exposure_probe", "severity": "medium", "url": url,
                                 "evidence": {"exposure_class": klass, "request_url": url, "response_status": 200,
                                              "matched_signature": signature}})


@pytest.mark.parametrize("signature", ["apache_server_status", "Apache Server Status for "])
def test_server_status_page_blocks_the_bare_path(signature):
    brief = _exposure("http://app.fixture.invalid/server-status", "metrics_endpoint", signature)
    assert brief["class_label"] == "Server status page public"
    examples = json.dumps(brief["examples"])
    assert "location ^~ /server-status { deny all; }" in examples
    assert '<Location \\"/server-status\\">' in examples
    assert "/server-status/" not in examples


def test_a_deeper_path_keeps_the_directory_prefix():
    brief = _exposure("http://app.fixture.invalid/actuator/env", "actuator_secret_disclosure", "actuator_property_sources")
    assert "location ^~ /actuator/ { deny all; }" in json.dumps(brief["examples"])


def test_a_stored_regular_expression_is_never_shown_as_the_signature():
    legacy = "(?i)<title>\\s*(?:index of|directory listing|listing directory)|Directory listing for /"
    brief = _exposure("http://app.fixture.invalid/files/", "directory_listing", legacy)
    assert not [fact for fact in brief["observed"] if fact["label"] == "Matched signature"]
    named = _exposure("http://app.fixture.invalid/files/", "directory_listing", "autoindex_title")
    assert {"label": "Matched signature", "value": "autoindex_title", "mono": True} in named["observed"]
