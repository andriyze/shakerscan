"""Behavioral regressions from the fix/scan1 review; no network traffic."""
from __future__ import annotations

import asyncio

import pytest

from api.scan import finalizer
from api.scan.continuation import network_receipt_from_capability_receipts
from api.scan.surface_manifest import build_scan_surface_manifest, wildcard_redirect_urls
from scanner.manifests import normalize_endpoint
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action
from tests.test_scan_surface_manifest import TARGET, _summary
from api.scan.action_plan import ScanActionPlan


HEADERS = {
    "content-security-policy": "default-src 'self'",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "strict-transport-security": "max-age=31536000",
}


def redirect_report(*, origin="https://app.example.test", location="https://www.app.example.test/",
                    missing=(), followup=None):
    baseline = _action("baseline.http", 0, capability_name="http.request")
    headers = {key: value for key, value in HEADERS.items() if key not in missing}
    # selected_headers is emitted by the real adapter and drives baseline findings.
    headers["server"] = "fixture"
    observations = {baseline.action_id: [{
        "kind": "http_observation", "request": {"origin": origin, "pinned_address": "192.0.2.10"},
        "response": {"status": 301, "location": location, "bytes_observed": 0,
                     "security_headers": headers, "selected_headers": headers},
    }]}
    actions = [baseline]
    if followup:
        action = _action("discover.web_probe", 1, capability_name="web.probe")
        actions.append(action)
        observations[action.action_id] = [{"kind": "http_fingerprint", "url": followup, "status": 200}]
    actions.append(_action("finalize.report", len(actions), dependencies=tuple(a.action_id for a in actions)))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                         target_binding_digest="a" * 64, actions=tuple(actions))
    results = {action.action_id: _result_with_observation_count(action, 1) for action in actions[:-1]}
    return finalizer.finalize_scan_report(plan=plan, target_url=origin,
                                        action_results=results, observations=observations)


@pytest.mark.parametrize("missing", [("permissions-policy",), tuple(HEADERS)])
def test_redirect_header_posture_is_not_application_proof(missing):
    report = redirect_report(missing=missing)
    assert report["findings"]  # Keep true observations about the redirect itself.
    assert any(row["tool"] == "http_baseline" and row["verified"] for row in report["findings"])
    assert report["result"]["application_observed"] is False
    assert report["result"]["risk_assessment_state"] == "not_examined"
    assert report["result"]["grade_reliable"] is False
    assert "bound_origin_redirects_off_origin" in report["coverage"]["reasons"]


@pytest.mark.parametrize("origin,location,expected", [
    ("https://app.example.test", "https://app.example.test:8443/", "https://app.example.test:8443"),
    ("http://app.example.test", "https://app.example.test/", "https://app.example.test"),
    ("http://app.example.test", "//www.app.example.test/", "http://www.app.example.test"),
    ("https://app.example.test", "//www.app.example.test:443/", "https://www.app.example.test"),
    ("https://app.example.test", "https://APP.EXAMPLE.TEST.:443/home", None),
    ("https://app.example.test", "/login", None),
    ("https://app.example.test", "//user:secret@www.app.example.test/", None),
    ("https://app.example.test", "https://www.app.example.test:99999/", None),
])
def test_redirect_origin_is_exact_and_safe(origin, location, expected):
    assert finalizer._off_origin_redirect({"status": 301, "location": location}, origin=origin) == expected


@pytest.mark.parametrize("origin,location", [
    ("https://app.example.test", "https://app.example.test:8443/"),
    ("http://app.example.test", "https://app.example.test/"),
    ("https://app.example.test", "/login"),
])
def test_redirect_without_followup_does_not_establish_application(origin, location):
    report = redirect_report(origin=origin, location=location)
    assert report["result"]["application_observed"] is False
    assert report["result"]["grade_reliable"] is False


def test_observed_bound_application_response_survives_redirect_warning():
    report = redirect_report(followup="https://app.example.test/health")
    assert report["result"]["application_observed"] is True
    assert "bound_origin_redirects_off_origin" not in report["coverage"]["reasons"]


def test_unrelated_origin_response_does_not_prove_redirected_application():
    report = redirect_report(followup="https://unrelated.example.test/")
    assert report["result"]["application_observed"] is False


def network_receipts(*, services_status="success", services_reason=None, open_ports=True):
    return {
        "discover.ports": {"status": "success", "capability_name": "ports.discover", "errors": [],
                           "budget_consumed": {"hosts_attempted": 1},
                           "observations": [{"kind": "open_port", "address": "192.0.2.10", "port": 443}]
                           if open_ports else []},
        "discover.services": {"status": services_status, "capability_name": "service.fingerprint",
                              "errors": [services_reason] if services_reason else [],
                              "budget_consumed": {}, "observations": []},
    }


@pytest.mark.parametrize("reason", ["insufficient_plan_budget", "dependency_incomplete", "placement_unavailable", "not_applicable"])
def test_skipped_fingerprint_with_open_ports_remains_incomplete(reason):
    summary = network_receipt_from_capability_receipts(
        network_receipts(services_status="skipped", services_reason=reason), addresses=("192.0.2.10",))
    assert summary["status"] == "partial"
    assert summary["partial"] is True
    assert reason in summary["errors"]


def test_missing_expected_fingerprint_receipt_is_incomplete():
    receipts = network_receipts()
    del receipts["discover.services"]
    summary = network_receipt_from_capability_receipts(receipts, addresses=("192.0.2.10",))
    assert summary["status"] == "partial"
    assert "missing_capability_receipt:discover.services" in summary["errors"]
    assert summary["durable_budget_settled"] is False


def test_no_ports_is_a_legitimate_fingerprint_skip():
    summary = network_receipt_from_capability_receipts(
        network_receipts(services_status="skipped", services_reason="not_applicable", open_ports=False), addresses=())
    assert summary["status"] == "success"
    assert summary["partial"] is False


@pytest.mark.parametrize("flag", ["partial", "timed_out"])
def test_inconsistent_success_flags_never_become_complete_network_coverage(flag):
    receipts = network_receipts()
    receipts["discover.services"][flag] = True
    summary = network_receipt_from_capability_receipts(receipts, addresses=())
    assert summary["status"] == "partial"


def content_rows(paths, *, source="https://app.example.test", destination="https://www.app.example.test"):
    return [{"kind": "content_discovery", "url": source + path, "status": 301,
             "redirect_location": destination + path} for path in paths]


def surface(**kwargs):
    defaults = dict(target_url="https://app.example.test", target=TARGET, options={}, max_endpoints=200,
                    collection_replay=_summary("skipped"), subdomains=_summary("skipped"),
                    probe=_summary("success"), crawl=_summary("success"), content=_summary("skipped"))
    return build_scan_surface_manifest(**{**defaults, **kwargs})


def test_query_variants_are_not_distinct_redirect_paths():
    rows = content_rows([f"/callback?code={i}" for i in range(5)])
    assert wildcard_redirect_urls(rows) == frozenset()
    manifest = surface(content=_summary("success", rows))
    assert any(row["concrete_path"] == "/callback" for row in manifest["endpoints"])


@pytest.mark.parametrize("dimension", ["source", "destination_port"])
def test_different_origin_rewrites_do_not_combine_into_wildcard(dimension):
    rows = []
    for i in range(5):
        rows += content_rows([f"/path{i}"], source=f"https://host{i}.example.test" if dimension == "source" else "https://app.example.test",
                             destination=f"https://www.app.example.test:{8000+i}" if dimension == "destination_port" else "https://www.app.example.test")
    assert wildcard_redirect_urls(rows) == frozenset()


def test_five_moved_routes_are_retained_but_do_not_claim_complete_coverage():
    paths = [f"/path{i}" for i in range(5)]
    manifest = surface(content=_summary("success", content_rows(paths)))
    assert {row["concrete_path"] for row in manifest["endpoints"] if row["source"] == "web.content_discover"} == set(paths)
    producer = manifest["producers"]["web.content_discover"]
    assert producer["status"] == "partial"
    assert "unverified_redirect_observations:5" in producer["reason"]


@pytest.mark.parametrize("source", ["seed", "known_endpoints", "collections.replay", "web.crawl", "web.browser_crawl"])
def test_literal_query_template_value_keeps_endpoint_and_parameter(source):
    record = normalize_endpoint(method="GET", url="https://app.example.test/render?template=%7B%7Bname%7D%7D", source=source)
    assert record.concrete_path == "/render"
    assert record.query_keys == ("template",)


def test_literal_seed_and_replay_paths_are_not_source_code_expressions():
    url = "https://app.example.test/templates/%7B%7Bname%7D%7D?q=%24%7Bvalue%7D"
    manifest = surface(target_url=url, collection_replay=_summary("success", [
        {"kind": "request_replay", "method": "GET", "final_url": url}]))
    assert manifest["endpoint_count"] == 1
    assert manifest["producers"]["seed"]["status"] == "complete"
    assert manifest["producers"]["collections.replay"]["status"] == "complete"


def test_crawler_template_paths_are_still_rejected_at_acquisition_boundary():
    manifest = surface(crawl=_summary("success", [
        {"kind": "discovered_route", "method": "GET", "url": "https://app.example.test/js/$%257BPATH%257D"},
        {"kind": "discovered_route", "method": "GET", "url": "https://app.example.test/render?template=%7B%7Bname%7D%7D"},
    ]))
    crawled = [row for row in manifest["endpoints"] if row["source"] == "web.crawl"]
    assert len(crawled) == 1 and crawled[0]["concrete_path"] == "/render"
    assert "invalid_observations:1" in manifest["producers"]["web.crawl"]["reason"]


@pytest.mark.parametrize("raw", [None, "null", "{}", "invalid-json"])
def test_missing_or_malformed_durable_receipt_is_not_a_successful_producer(raw):
    from api.scan.continuation import load_discovery_shard_capability_receipts

    class Connection:
        async def fetch(self, *_args):
            return [{"action_id": "discover.ports", "status": "success", "receipt_json": raw}]

    receipts = asyncio.run(load_discovery_shard_capability_receipts(
        Connection(), scan_id=SCAN_ID, action_ids=("discover.ports",)))
    assert receipts["discover.ports"]["status"] == "failed"
    summary = network_receipt_from_capability_receipts(receipts, addresses=())
    assert summary["status"] == "failed"
    assert summary["durable_budget_settled"] is False


def test_disabled_network_stage_is_not_reenabled_by_stale_receipts():
    from api.scan.continuation import placed_discovery_stage_receipts

    class Connection:
        async def fetch(self, *_args):
            return [{"action_id": "discover.ports", "status": "success",
                     "receipt_json": network_receipts()["discover.ports"]}]

    _, network = asyncio.run(placed_discovery_stage_receipts(
        Connection(), scan_id=SCAN_ID, root_domain=None, addresses=(),
        subdomain_enabled=False, network_enabled=False))
    assert network is None


def test_cancelled_network_evidence_is_not_success_or_failure():
    receipts = network_receipts(services_status="cancelled", services_reason="cancelled")
    summary = network_receipt_from_capability_receipts(receipts, addresses=())
    assert summary["status"] == "cancelled"
    assert summary["open_ports"]


def test_same_host_port_rewrites_group_by_exact_origin():
    rows = content_rows([f"/p{i}" for i in range(5)], destination="https://app.example.test:8443")
    assert wildcard_redirect_urls(rows) == frozenset(row["url"] for row in rows)


@pytest.mark.parametrize("location", ["ftp://www.app.example.test/p0", "https://www.app.example.test:99999/p0",
                                      "https://secret@www.app.example.test/p0"])
def test_unsafe_redirect_locations_do_not_become_rewrite_evidence(location):
    rows = content_rows([f"/p{i}" for i in range(5)])
    for row in rows:
        row["redirect_location"] = location.replace("p0", row["url"].rsplit("/", 1)[-1])
    assert wildcard_redirect_urls(rows) == frozenset()


def test_redirect_query_changes_are_not_blanket_origin_rewrites():
    rows = content_rows([f"/p{i}" for i in range(5)])
    for row in rows:
        row["redirect_location"] += "?token=some-value"
    assert wildcard_redirect_urls(rows) == frozenset()
