"""Offline regression tests for discovery evidence, not vulnerability recall."""

from __future__ import annotations

import json

import pytest

from api.runtime.models import TargetBinding
from api.scan.surface_manifest import _summary_status, build_scan_surface_manifest
from scanner.manifests import EndpointManifest


TARGET = TargetBinding(
    target_id="discovery-status-test",
    target_kind="web",
    canonical_host="app.example.test",
    allowed_origins=("https://app.example.test",),
)


def _manifest(**overrides):
    arguments = {
        "target_url": "https://app.example.test",
        "target": TARGET,
        "options": {},
        "collection_replay": {"status": "success"},
        "subdomains": {"status": "success"},
        "probe": {"status": "success"},
        "crawl": {"status": "success"},
        "content": {"status": "success"},
        "max_endpoints": 10,
    }
    arguments.update(overrides)
    return build_scan_surface_manifest(**arguments)


@pytest.mark.parametrize("status, expected, cancelled", [
    ("success", "complete", False),
    ("complete", "complete", False),
    (" SUCCESS ", "complete", False),
    ("skipped", "skipped", False),
    ("partial", "partial", False),
    ("failed", "failed", False),
    ("blocked", "failed", False),
    ("timed_out", "timed_out", False),
    ("timeout", "timed_out", False),
    ("cancelled", "cancelled", True),
    ("running", "partial", False),
    ("pending", "partial", False),
])
def test_summary_status_preserves_execution_outcome(status, expected, cancelled):
    assert _summary_status({"status": status, "reason": "upstream_reason"}) == (
        expected, "upstream_reason", cancelled,
    )


@pytest.mark.parametrize("summary", [None, [], True, "success"])
def test_invalid_summary_is_not_completed_or_intentionally_skipped(summary):
    assert _summary_status(summary) == ("failed", "capability_summary_invalid", False)


@pytest.mark.parametrize("status", [None, "", "  "])
def test_missing_status_is_not_success(status):
    assert _summary_status({"status": status}) == (
        "failed", "capability_status_missing", False,
    )
    assert _summary_status({}) == ("failed", "capability_status_missing", False)


@pytest.mark.parametrize("status", [0, False, [], {}])
def test_non_string_status_is_not_success(status):
    assert _summary_status({"status": status}) == (
        "failed", "capability_status_invalid", False,
    )


def test_unknown_status_uses_a_bounded_marker_not_raw_untrusted_text():
    secret = "unexpected-worker-status-private-value"
    outcome = _summary_status({"status": secret * 100})
    assert outcome == ("failed", "capability_status_unrecognized", False)
    assert secret not in json.dumps(outcome)


@pytest.mark.parametrize("status, reason", [
    ("skipped", "capability_skipped"),
    ("timed_out", "capability_timed_out"),
    ("running", "capability_not_terminal"),
    ("pending", "capability_not_terminal"),
    ("cancelled", "capability_cancelled"),
])
def test_non_success_without_upstream_reason_has_a_diagnostic(status, reason):
    assert _summary_status({"status": status})[1] == reason


def test_reason_remains_bounded():
    assert _summary_status({"status": "failed", "reason": "x" * 500})[1] == "x" * 200


@pytest.mark.parametrize("flag, expected", [("partial", "partial"), ("timed_out", "timed_out")])
def test_explicit_partial_or_timeout_flag_cannot_be_reported_complete(flag, expected):
    assert _summary_status({"status": "success", flag: True})[0] == expected


def test_cancellation_is_not_reclassified_as_timeout():
    assert _summary_status({"status": "cancelled", "timed_out": True}) == (
        "cancelled", "capability_cancelled", True,
    )


def test_absent_optional_producers_are_skipped_without_failing_the_manifest():
    manifest = _manifest()
    assert manifest["status"] == "complete"
    for name in ("web.browser_crawl", "web.spec_ingest"):
        assert manifest["producers"][name] == {
            "status": "skipped", "count": 0,
            "reason": "capability_skipped", "timed_out": False,
        }


@pytest.mark.parametrize("argument, producer", [
    ("browser", "web.browser_crawl"), ("spec", "web.spec_ingest"),
])
@pytest.mark.parametrize("summary", [{}, [], "success", False])
def test_malformed_optional_summary_is_not_confused_with_absence(argument, producer, summary):
    manifest = _manifest(**{argument: summary})
    assert manifest["status"] == "partial"
    assert manifest["producers"][producer]["status"] == "failed"


def test_explicit_skip_keeps_its_upstream_reason():
    manifest = _manifest(browser={"status": "skipped", "reason": "runtime_unavailable"})
    assert manifest["status"] == "complete"
    assert manifest["producers"]["web.browser_crawl"]["status"] == "skipped"
    assert manifest["producers"]["web.browser_crawl"]["reason"] == "runtime_unavailable"


@pytest.mark.parametrize("argument, producer", [
    ("collection_replay", "collections.replay"),
    ("subdomains", "subdomains.discover"),
    ("probe", "web.probe"),
    ("crawl", "web.crawl"),
    ("content", "web.content_discover"),
    ("browser", "web.browser_crawl"),
    ("spec", "web.spec_ingest"),
])
def test_timeout_marks_producer_and_aggregate_partial(argument, producer):
    manifest = _manifest(**{argument: {"status": "timed_out"}})
    assert manifest["status"] == "partial"
    assert manifest["producers"][producer]["status"] == "timed_out"
    assert manifest["producers"][producer]["timed_out"] is True
    assert manifest["endpoint_count"] == 1  # The valid seed is retained.


def test_failed_summary_retains_valid_redacted_observations():
    secret = "private-query-value"
    manifest = _manifest(browser={
        "observations": [{
            "kind": "discovered_route", "method": "GET",
            "url": f"https://app.example.test/catalog?cursor={secret}",
        }],
    })
    assert manifest["status"] == "partial"
    assert manifest["endpoint_count"] == 2
    assert manifest["producers"]["web.browser_crawl"]["status"] == "failed"
    assert manifest["producers"]["web.browser_crawl"]["count"] == 1
    assert secret not in json.dumps(manifest)


def test_cancelled_summary_keeps_aggregate_cancelled():
    manifest = _manifest(browser={"status": "cancelled"})
    assert manifest["status"] == "cancelled"
    assert manifest["producers"]["web.browser_crawl"]["status"] == "cancelled"


def test_manifest_accepts_skipped_as_a_distinct_terminal_producer_state():
    manifest = EndpointManifest(auto_persist=False)
    manifest.start_producer("optional")
    manifest.finish_producer("optional", status="skipped", reason="not_requested")
    manifest.finalize()
    payload = manifest.to_dict()
    assert payload["status"] == "complete"
    assert payload["producers"]["optional"]["status"] == "skipped"
    assert payload["producers"]["optional"]["timed_out"] is False
