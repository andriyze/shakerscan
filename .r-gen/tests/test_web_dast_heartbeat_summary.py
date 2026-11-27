"""Web DAST pool presence from worker heartbeats, for socket-less deployments.

A self-hosted Enterprise gateway does not mount the Docker socket, so `/workers` cannot count
containers and used to answer `count: -1, error: "Docker socket not available"`, which the
dashboard renders as "Unknown" even while scans run fine. Every worker already refreshes a build
report to `shakerscan:worker_build` every ~30s; `web_dast_heartbeat_summary` turns those fresh
reports into the same summary shape the socket path produces, so the count is real.

These tests exercise the pure function directly (no Redis, no FastAPI); the api.py wiring that
reads Redis and calls it is covered by the engine's API suite.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from worker_pools import web_dast_heartbeat_summary, worker_pool_summaries  # noqa: E402

WINDOW = 120.0
SKEW = 30.0
NOW = 1_000_000.0


def _report(name, age, build_current, fingerprint="abc"):
    return {
        "name": name,
        "reported_epoch": NOW - age,
        "build_current": build_current,
        "build_fingerprint": fingerprint,
    }


def _summary(reports):
    return web_dast_heartbeat_summary(
        reports, now_epoch=NOW, max_age_seconds=WINDOW, clock_skew_seconds=SKEW
    )


def test_fresh_current_workers_are_counted_present():
    s = _summary([_report("w1", 5, True), _report("w2", 40, True)])
    assert s["count"] == 2
    assert s["current_count"] == 2
    assert s["stale_count"] == 0
    assert s["pending_count"] == 0
    assert s["fleet_uniform"] is True
    assert s["distinct_fingerprints"] == ["abc"]
    assert sorted(s["fresh_names"]) == ["w1", "w2"]


def test_a_worker_that_stopped_heartbeating_drops_out_like_a_removed_container():
    # One fresh worker, one whose last report is older than the window: only the fresh one counts.
    s = _summary([_report("live", 30, True), _report("gone", WINDOW + 60, True)])
    assert s["count"] == 1
    assert s["current_count"] == 1
    assert s["fresh_names"] == ["live"]


def test_stale_build_makes_the_pool_non_uniform():
    s = _summary(
        [_report("new", 10, True, "new-fp"), _report("old", 10, False, "old-fp")]
    )
    assert s["count"] == 2
    assert s["current_count"] == 1
    assert s["stale_count"] == 1
    assert s["fleet_uniform"] is False
    assert s["stale_workers"] == ["old"]
    assert set(s["distinct_fingerprints"]) == {"new-fp", "old-fp"}


def test_a_worker_that_has_not_classified_its_build_is_pending():
    s = _summary([_report("w1", 5, True), _report("w2", 5, None, fingerprint=None)])
    assert s["pending_count"] == 1
    assert s["fleet_uniform"] is False


def test_clock_skew_keeps_a_slightly_future_report_but_the_window_bounds_the_past():
    assert _summary([_report("future", -SKEW + 5, True)])["count"] == 1
    assert _summary([_report("too_future", -SKEW - 5, True)])["count"] == 0


def test_no_reports_is_an_empty_not_unknown_pool():
    s = _summary([])
    assert s["count"] == 0
    assert s["fleet_uniform"] is False
    assert s["stale_workers"] == []
    assert s["fresh_names"] == []


def test_summary_feeds_the_web_dast_pool_as_ready_when_uniform():
    # The summary is consumed as the `web_dast` argument of worker_pool_summaries; a uniform
    # heartbeat fleet reads ready, exactly as a healthy socket-counted fleet would.
    summary = _summary([_report("w1", 5, True)])
    pools = worker_pool_summaries(
        summary,
        agent_tool=lambda: {"status": "not_ready"},
        device=lambda: {"status": "not_ready"},
        model_intake=lambda: {"status": "not_ready"},
    )
    assert pools["web_dast"]["status"] == "ready"
    assert pools["web_dast"]["reason"] is None
    assert pools["web_dast"]["count"] == 1


def test_stale_heartbeat_fleet_reads_not_ready_in_the_pool():
    summary = _summary([_report("old", 10, False)])
    pools = worker_pool_summaries(
        summary,
        agent_tool=lambda: {"status": "not_ready"},
        device=lambda: {"status": "not_ready"},
        model_intake=lambda: {"status": "not_ready"},
    )
    assert pools["web_dast"]["status"] == "not_ready"
    assert pools["web_dast"]["reason"] == "web_dast_pool_not_uniform"
