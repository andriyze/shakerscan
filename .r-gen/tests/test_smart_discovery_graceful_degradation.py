"""Smart scan discovery must degrade gracefully instead of hard-aborting.

User report: "Smart scan timeout 3' min discovery, hard time out, no graceful
degradation." The browser crawl's 180s timeout was already rescued internally
(http_scanner.py recovers visited pages from captured requests), but the
scanner-level discovery awaits were not:

- ``httpx_meta = await httpx_task`` and ``katana_result = await katana_task``
  had no try/except and no deadline. An exception from smart_discovery escaped
  the adapter (the registry caught it, but all collected partials were dropped
  and the browser task was orphaned); a *hung* discovery was bounded by nothing
  short of the worker's process-level watchdog, whose hard kill arrives before
  the first checkpoint exists, so everything was lost.

These tests pin the graceful-degradation contract: a stalled/failed discovery
source is recorded as a truncation reason, the surviving sources' partial
results are kept, and the report wiring surfaces the truncation markers.
"""

import asyncio
import importlib.util
import inspect
import os
import sys


# scanner.py is a script-style module that does `from scanner_tools... import`,
# so scanner/ must be on sys.path for those top-level imports to resolve.
_SCANNER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scanner"))
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)

# Load scanner/scanner.py under a UNIQUE name to avoid colliding with the
# `scanner` package other tests cache in sys.modules.
_spec = importlib.util.spec_from_file_location(
    "shaker_scanner_main_graceful_discovery", os.path.join(_SCANNER_DIR, "scanner.py")
)
scanner_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(scanner_mod)


def test_smart_discovery_deadline_is_derived_from_scan_budget():
    resolve = scanner_mod.resolve_smart_discovery_deadline_seconds

    # No budget / non-dict / non-positive duration -> unbounded legacy behavior.
    assert resolve(None) is None
    assert resolve({}) is None
    assert resolve({"max_duration_minutes": 0}) is None
    assert resolve({"max_duration_minutes": "not-a-number"}) is None

    # A quarter of the overall wall-clock budget, clamped to [300s, 1800s].
    # smart fast = 30 min -> 450s; balanced = 90 min -> 1350s;
    # thorough = 240 min -> clamped to 1800s; tiny budgets floor at 300s.
    assert resolve({"max_duration_minutes": 30}) == 450
    assert resolve({"max_duration_minutes": 90}) == 1350
    assert resolve({"max_duration_minutes": 240}) == 1800
    assert resolve({"max_duration_minutes": 5}) == 300
    assert resolve({"max_duration_minutes": 600}) == 1800


def test_discovery_timeout_keeps_partial_results_and_marks_truncation():
    """A wedged smart-discovery crawl must not raise or discard the other
    sources' partial results: the scan proceeds with what was collected."""

    async def slow_smart_discovery():
        # Simulates the reported wedge: discovery that never finishes on its
        # own (previously only the worker's hard watchdog could end it).
        await asyncio.sleep(300)
        return {"all_urls": ["https://example.com/never-returned"]}

    async def partial_httpx():
        await asyncio.sleep(0)
        return [{"url": "https://example.com", "status_code": 200}]

    async def partial_browser():
        await asyncio.sleep(0)
        return {
            "page_urls": ["https://example.com", "https://example.com/about"],
            "crawl_stats": {
                "pages_visited": 2,
                "depth_reached": 0,
                "timed_out": True,  # the 180s crawl timeout already fired
                "requests_captured": 41,
            },
        }

    async def _drive():
        return await scanner_mod.await_discovery_sources_gracefully(
            asyncio.create_task(partial_httpx()),
            asyncio.create_task(slow_smart_discovery()),
            asyncio.create_task(partial_browser()),
            katana_deadline=0.05,
        )

    httpx_meta, katana_result, browser_res, browser_err, reasons = asyncio.run(_drive())

    # Partial results from the surviving sources are preserved.
    assert httpx_meta == [{"url": "https://example.com", "status_code": 200}]
    assert browser_res["page_urls"] == ["https://example.com", "https://example.com/about"]
    assert browser_err is None
    # The stalled source degrades to empty instead of raising.
    assert katana_result == []
    # Both truncation events are recorded: the discovery backstop and the
    # browser crawl's own 180s timeout.
    assert any(r.startswith("discovery_deadline_exceeded:") for r in reasons)
    assert "browser_crawl_timeout:180s" in reasons


def test_discovery_source_exception_degrades_instead_of_raising():
    """A discovery source that raises must not abort the phase (previously the
    exception escaped the adapter and orphaned the browser task)."""

    async def failing_httpx():
        raise ConnectionError("httpx probe exploded")

    async def failing_discovery():
        raise ValueError("smart discovery exploded")

    async def healthy_browser():
        return {
            "page_urls": ["https://example.com"],
            "crawl_stats": {"pages_visited": 1, "depth_reached": 1},
        }

    async def _drive():
        return await scanner_mod.await_discovery_sources_gracefully(
            asyncio.create_task(failing_httpx()),
            asyncio.create_task(failing_discovery()),
            asyncio.create_task(healthy_browser()),
            katana_deadline=5,
        )

    httpx_meta, katana_result, browser_res, browser_err, reasons = asyncio.run(_drive())

    assert httpx_meta == []
    assert katana_result == []
    assert "httpx_probe_failed:ConnectionError" in reasons
    assert "discovery_failed:ValueError" in reasons
    # The browser result is still collected even though earlier awaits failed
    # (this is the orphaned-task leak fix).
    assert browser_res["page_urls"] == ["https://example.com"]
    assert browser_err is None
    # No crawl timeout marker for a healthy crawl.
    assert "browser_crawl_timeout:180s" not in reasons


def test_healthy_discovery_records_no_truncation():
    async def healthy(tag, payload):
        await asyncio.sleep(0)
        return payload

    async def _drive():
        return await scanner_mod.await_discovery_sources_gracefully(
            asyncio.create_task(healthy("h", [{"url": "https://example.com"}])),
            asyncio.create_task(healthy("k", {"all_urls": ["https://example.com/a"]})),
            asyncio.create_task(
                healthy(
                    "b",
                    {
                        "page_urls": ["https://example.com"],
                        "crawl_stats": {"pages_visited": 1, "depth_reached": 1},
                    },
                )
            ),
            katana_deadline=5,
        )

    httpx_meta, katana_result, browser_res, browser_err, reasons = asyncio.run(_drive())

    assert httpx_meta == [{"url": "https://example.com"}]
    assert katana_result == {"all_urls": ["https://example.com/a"]}
    assert browser_res["page_urls"] == ["https://example.com"]
    assert browser_err is None
    assert reasons == []


def test_build_report_wires_discovery_truncation_markers():
    """Source contract: the truncation reasons collected during discovery must
    surface in the report (smart_coverage marker, completion-status skip entry,
    coverage gap, and the discovery summary) instead of being silently dropped."""
    source = inspect.getsource(scanner_mod.build_report)

    # The smart discovery crawl is bounded by a budget-derived backstop.
    assert "resolve_smart_discovery_deadline_seconds(scan_budget) if smart_mode" in source
    assert "await_discovery_sources_gracefully(" in source
    # Report markers.
    assert 'smart_coverage_block["discovery_truncated"] = True' in source
    assert 'discovery_summary["truncated"] = True' in source
    assert '"check": "discovery"' in source
    assert '"impact": "partial_discovery_results"' in source
    # Browser crawl timeout is surfaced in the report's browser_crawl block.
    assert '"timed_out": bool(browser_crawl_stats.get("timed_out"))' in source


def test_browser_crawl_timeout_was_already_rescued_internally():
    """The reported 3-minute discovery timeout is the browser crawl's 180s cap.
    Document (and pin) that http_scanner rescues it by recovering visited pages
    from captured network requests rather than discarding the crawl."""
    http_scanner_source = os.path.join(_SCANNER_DIR, "scanner_tools", "http_scanner.py")
    with open(http_scanner_source, "r", errors="replace") as fh:
        source = fh.read()

    assert "timeout=180  # 180s timeout for entire crawl" in source
    assert "Crawl timed out (180s), recovered" in source
    assert '"timed_out": True' in source
