"""Canonical target de-dupe: the canonical key + survivor selection that drive the
merge, find-or-create prevention, and the canonical-aware deploy gate. The SQL trigger
form must stay equivalent to _canonical_target_key (verified live); this covers the
Python side."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
import api  # noqa: E402


def test_canonical_key_is_scheme_slash_case_insensitive():
    k = api._canonical_target_key
    assert k("https://Example.com/") == "example.com"
    assert k("http://example.com") == "example.com"
    assert k("example.com") == "example.com"
    assert k("https://example.com///") == "example.com"
    assert k("HTTP://Host.Docker.Internal:3001/") == "host.docker.internal:3001"
    assert k("  https://example.com  ") == "example.com"


def test_canonical_key_keeps_path_drops_only_trailing_slash():
    # Path is part of the artifact identity (e.g. model-intake URLs); only the trailing
    # slash is stripped, not the whole path.
    assert api._canonical_target_key("https://hf.co/org/model/") == "hf.co/org/model"
    assert api._canonical_target_key("https://hf.co/org/model") == "hf.co/org/model"


def _row(rid, url, active=True, findings=0, scans=0):
    return {"id": rid, "url": url, "is_active": active,
            "active_findings_count": findings, "total_scans": scans}


def test_dedupe_collapses_canonical_variants_keeping_richest_survivor():
    rows = [
        _row("1", "host.docker.internal:3001", findings=0, scans=0),
        _row("2", "http://host.docker.internal:3001", findings=109, scans=5),
    ]
    out = api._dedupe_canonical_target_rows(rows)
    assert len(out) == 1
    assert out[0]["id"] == "2"  # survivor = the data-bearing row


def test_dedupe_survivor_prefers_active_then_findings_then_https():
    rows = [
        _row("inactive-https", "https://x.com", active=False, findings=50),
        _row("active-http", "http://x.com", active=True, findings=10),
    ]
    out = api._dedupe_canonical_target_rows(rows)
    assert len(out) == 1 and out[0]["id"] == "active-http"  # active beats more-findings-but-inactive


def test_dedupe_keeps_distinct_origins():
    rows = [_row("1", "https://a.com"), _row("2", "https://b.com")]
    out = api._dedupe_canonical_target_rows(rows)
    assert {r["id"] for r in out} == {"1", "2"}
