"""A finding about identified software links the Exposure candidates for the same CVE or product.

Service Intelligence lists CVE candidates from a ``Server: Apache/2.4.49`` header; a template
finding for CVE-2021-41773 on the same origin showed no link to them. The finding detail read path
now carries a bounded, value-free ``related_exposures`` list; findings about something else, and
services on another origin, link nothing. Unit fixtures: the database rows and the advisory
snapshot are fakes.
"""

from __future__ import annotations

import asyncio
import uuid

from api.exposure import finding_link
from api.exposure.finding_link import exposure_links, finding_cves, related_exposures, wants_exposure_link
from api.exposure.service_inventory import build_inventory

TARGET_ID = "00000000-0000-4000-8000-0000000000aa"
ORIGIN = "https://app.example.test"
SNAPSHOT = {"status": "available", "advisories": []}
ADVISORIES = [
    {"advisory_id": "CVE-2021-42013", "title": "Apache HTTP Server path traversal (incomplete fix)",
     "severity": "critical", "match_type": "exact_cpe_version_range"},
    {"advisory_id": "CVE-2021-41773", "title": "Apache HTTP Server path traversal",
     "severity": "high", "match_type": "exact_cpe_version_range"},
]


def _matcher(_records, *, cpe, product, version, identity_evidence_tier=None, limit=50):
    assert identity_evidence_tier == "network_service_fingerprint"
    return ADVISORIES if str(product).lower() == "apache" and version == "2.4.49" else []


def _source(origin=ORIGIN, server="Apache/2.4.49 (Unix)"):
    return {
        "ref": "scan:s1:baseline.http", "scan_id": "s1", "action_id": "baseline.http",
        "observed_at": "2026-10-16T00:00:00+00:00", "status": "success",
        "observations": [{
            "kind": "http_observation", "request": {"origin": origin, "pinned_address": "192.0.2.10"},
            "response": {"status": 200}, "webserver": server,
        }],
    }


def _finding(**overrides):
    finding = {
        "id": "f1", "target_id": TARGET_ID, "tool": "nuclei",
        "title": "Apache 2.4.49 - Path Traversal and Remote Code Execution",
        "url": f"{ORIGIN}/cgi-bin/.%2e/.%2e/etc/passwd",
        "evidence": {"template_id": "CVE-2021-41773", "cve_ids": ["CVE-2021-41773"]},
    }
    finding.update(overrides)
    return finding


def _services(*sources):
    services, _ = build_inventory({"kind": "web", "id": TARGET_ID}, list(sources))
    return services


def test_a_cve_finding_links_its_candidate_first_then_the_same_product():
    links = exposure_links(_finding(), _services(_source()), snapshot=SNAPSHOT, matcher=_matcher)
    assert [(item["cve"], item["relation"]) for item in links] == [
        ("CVE-2021-41773", "Same CVE"), ("CVE-2021-42013", "Same product on this origin"),
    ]
    first = links[0]
    assert first["product"] == "Apache" and first["version"] == "2.4.49"
    assert first["source"] == "Server header"
    assert first["exposure_href"].startswith("/exposure?service_query=app.example.test&service_id=")
    assert first["service_id"] in first["exposure_href"]


def test_cve_ids_come_from_evidence_and_title_and_are_bounded():
    finding = _finding(title="Exploit for cve-2021-42013 and CVE-2021-41773", evidence={"cve_ids": ["bad", "CVE-2021-41773"]})
    assert finding_cves(finding) == ["CVE-2021-41773", "CVE-2021-42013"]


def test_a_service_on_another_origin_links_nothing():
    links = exposure_links(_finding(), _services(_source(origin="https://other.example.test")),
                           snapshot=SNAPSHOT, matcher=_matcher)
    assert links == []


def test_a_finding_about_another_product_links_only_a_shared_cve():
    unrelated = _finding(title="nginx 1.18 - something", evidence={"cve_ids": []})
    assert exposure_links(unrelated, _services(_source()), snapshot=SNAPSHOT, matcher=_matcher) == []


def test_findings_that_name_no_software_skip_the_read():
    header = _finding(title="Missing Content-Security-Policy header", tool="http_baseline", evidence={"check": "missing_header_content-security-policy"})
    assert not wants_exposure_link(header)
    assert not wants_exposure_link(_finding(target_id=None))
    assert not wants_exposure_link(_finding(device_target_id="d1"))
    assert wants_exposure_link(_finding())

    class NoQueries:
        def transaction(self, **_kwargs):
            raise AssertionError("no read for a finding that names no software")

    assert asyncio.run(related_exposures(NoQueries(), header)) == []


class _Transaction:
    def __init__(self, conn, kwargs):
        self.conn, self.kwargs = conn, kwargs

    async def __aenter__(self):
        self.conn.transactions.append(self.kwargs)

    async def __aexit__(self, *_exc):
        return False


class _Conn:
    def __init__(self, rows):
        self.rows, self.queries, self.transactions = rows, [], []

    def transaction(self, **kwargs):
        return _Transaction(self, kwargs)

    async def fetch(self, query, *args):
        self.queries.append((query, args))
        return self.rows


def test_the_read_is_one_bounded_read_only_query(monkeypatch):
    rows = [{"action_id": "baseline.http", "scan_id": "s1"}, {"action_id": "web.probe", "scan_id": "s1"}]

    async def validated(_conn, row):
        if row["action_id"] == "web.probe":
            raise ValueError("service_source_invalid_or_over_budget")
        return _source()

    monkeypatch.setattr(finding_link, "validated_scan_source", validated)
    conn = _Conn(rows)
    links = asyncio.run(related_exposures(conn, _finding(), intelligence=lambda: (SNAPSHOT, _matcher)))
    assert [item["cve"] for item in links] == ["CVE-2021-41773", "CVE-2021-42013"]
    assert len(conn.queries) == 1
    query, args = conn.queries[0]
    assert args == (uuid.UUID(TARGET_ID), finding_link.MAX_FINDING_SOURCES)
    assert "LIMIT $2" in query
    assert conn.transactions == [{"isolation": "repeatable_read", "readonly": True}]


def test_a_failing_read_leaves_the_finding_without_links(monkeypatch):
    class Broken(_Conn):
        async def fetch(self, query, *args):
            raise RuntimeError("database unavailable")

    assert asyncio.run(related_exposures(Broken([]), _finding(), intelligence=lambda: (SNAPSHOT, _matcher))) == []


def test_no_snapshot_is_loaded_when_no_service_on_the_origin_has_a_product(monkeypatch):
    async def validated(_conn, _row):
        return _source(server="")

    def intelligence():
        raise AssertionError("snapshot loaded without an identified service")

    monkeypatch.setattr(finding_link, "validated_scan_source", validated)
    conn = _Conn([{"action_id": "baseline.http", "scan_id": "s1"}])
    assert asyncio.run(related_exposures(conn, _finding(), intelligence=intelligence)) == []


def test_a_product_is_matched_as_whole_words_not_as_a_substring():
    from api.exposure.finding_link import names_product
    assert names_product("apache 2.4.49 - path traversal", "Apache")
    assert names_product("cpe:2.3:a:apache:http_server:2.4.49 apache http server", "Apache")
    # A short product name inside another word is not that product.
    assert not names_product("ongoing deserialization in mongo-express", "go")
    assert names_product("go 1.20 net/http request smuggling", "Go")
    assert not names_product("phpmyadmin 4.8 local file inclusion", "PHP")
    assert names_product("php 8.1 cgi argument injection", "php")
    # Apache (the HTTP server) is not Apache Tomcat, and Tomcat stays Tomcat.
    assert not names_product("apache tomcat 9.0.30 ajp ghostcat", "Apache")
    assert not names_product("cpe:2.3:a:apache:tomcat:9.0.30", "Apache")
    assert names_product("apache tomcat 9.0.30 ajp ghostcat", "Tomcat")
    assert names_product("apache tomcat 9.0.30 ajp ghostcat", "Apache Tomcat")


def test_a_tomcat_finding_does_not_link_the_apache_httpd_candidates():
    links = exposure_links(
        _finding(title="Apache Tomcat 9.0.30 - AJP Ghostcat", evidence={"template_id": "tomcat-ajp"}),
        _services(_source()), snapshot=SNAPSHOT, matcher=_matcher,
    )
    assert links == []
