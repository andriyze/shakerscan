"""The headless discovery capability that observes an application's own requests.

A single-page application builds its API calls in JavaScript at run time, so a
static crawl recovers the route but never the query the client actually sends.
Candidate generation only ever tests observed parameters, so without runtime
observation an SPA reaches the active families with almost no work to do.
"""
from __future__ import annotations

import pathlib
import urllib.parse

import pytest

import agent_tools as at
from runtime.capability_registry import CAPABILITY_REGISTRY
from scan.contracts import scan_family_capabilities


RESERVED = {"http_requests": 600, "tool_wall_seconds": 150}


def _plan(reserved=None, **kwargs):
    return at.build_enforced_scanner_plan(
        "katana_headless", "http://app.test/", {},
        reserved_budget=reserved or RESERVED, **kwargs,
    )


def test_capability_is_registered_as_a_read_only_recon_producer():
    specification = CAPABILITY_REGISTRY.require("web.browser_crawl")
    assert specification.risk_tier == "read_only"
    assert not specification.requires_active_approval
    assert specification.process_tool_name == "katana_headless"
    assert specification.binary == "katana"
    assert "web.browser_crawl" in scan_family_capabilities("recon")


def test_the_crawl_is_read_only_and_never_leaves_the_target_host():
    argv = _plan().argv
    assert "-field-scope" in argv and argv[argv.index("-field-scope") + 1] == "fqdn"
    for unsafe in (
        "-form-extraction", "-automatic-form-fill", "-aff",
        "-display-out-scope", "-do", "-sb", "-show-browser",
    ):
        assert unsafe not in argv


def test_the_browser_is_the_image_and_never_a_download():
    """Katana fetches its own Chromium when no path is given.

    A worker with no general egress cannot do that, and katana then reports a
    completed crawl with zero endpoints instead of failing, so the discovery
    stage would silently lose its highest-fidelity producer.
    """
    argv = _plan().argv
    assert "-system-chrome-path" in argv
    assert argv[argv.index("-system-chrome-path") + 1] == at._SYSTEM_CHROME_PATH
    assert "-headless" in argv and "-xhr-extraction" in argv


def test_egress_rides_the_pinned_proxy_like_every_other_scanner():
    argv = _plan(pinned_proxy_url="socks5://127.0.0.1:9050").argv
    assert "-proxy" in argv
    assert argv[argv.index("-proxy") + 1] == "socks5://127.0.0.1:9050"


def test_the_hard_ceiling_stays_inside_the_reservation():
    """The bound covers browser egress, not just the crawler's own requests.

    A browser fetches every subresource of every page it opens and katana's
    rate limiter does not govern those, so a crawl-rate bound would understate
    real traffic and let the run exceed the budget it reserved.
    """
    plan = _plan()
    hard = dict(plan.hard_budget)
    assert hard["http_requests"] <= RESERVED["http_requests"]
    assert hard["tool_wall_seconds"] <= RESERVED["tool_wall_seconds"]
    assert plan.timeout_ms // 1000 == hard["tool_wall_seconds"]

    proof = dict(plan.budget_proof)
    assert proof["accounting_mode"] == "conservative"
    assert proof["method"] == "browser_rate_time_upper_bound"
    inputs = dict(proof["inputs"])
    assert inputs["form_fill"] is False
    # The ceiling is exactly the documented rate over the enforced time box.
    assert hard["http_requests"] == (
        inputs["rate_per_second"] * inputs["duration_seconds"] + 1
    )


@pytest.mark.parametrize("reserved", (
    {"http_requests": 600, "tool_wall_seconds": 150},
    {"http_requests": 200, "tool_wall_seconds": 60},
    {"http_requests": 120, "tool_wall_seconds": 30},
))
def test_every_admissible_reservation_produces_a_fitting_plan(reserved):
    plan = _plan(reserved=reserved)
    hard = dict(plan.hard_budget)
    assert 0 < hard["http_requests"] <= reserved["http_requests"]
    assert 0 < hard["tool_wall_seconds"] <= reserved["tool_wall_seconds"]


def test_a_reservation_too_small_for_a_browser_fails_closed():
    """Never silently run a browser crawl that cannot fit its own teardown."""
    with pytest.raises(at.AgentToolError):
        _plan(reserved={"http_requests": 600, "tool_wall_seconds": 5})
    with pytest.raises(at.AgentToolError):
        _plan(reserved={"http_requests": 5, "tool_wall_seconds": 150})


def test_off_origin_links_never_enter_observations():
    """A browser follows the page's own third-party links.

    Those URLs are not scan destinations, and letting them into the
    observations made the runtime destination re-check fail the whole scan as
    out of scope -- for links the target itself published.
    """
    output = "\n".join((
        "http://app.test/rest/products/search?q=",
        "https://fonts.googleapis.com/css2?family=X",
        "http://gitter.im/some/room",
        "https://github.com/owner/repo",
        "http://app.test/rest/user/whoami",
    ))
    for tool in sorted(at.KATANA_TOOLS):
        parsed = at.parse_scanner_output(tool, output, allowed_host="app.test")
        hosts = {
            urllib.parse.urlsplit(record["url"]).hostname
            for record in parsed["records"]
        }
        assert hosts == {"app.test"}, tool


def test_both_crawl_tools_are_treated_as_one_family_everywhere():
    """The filter, parser, metering and pinning branches must all cover both.

    The headless variant was added to the parser but not to the worker's
    allowed-host filter, which is exactly how the off-origin URLs escaped.
    """
    assert at.KATANA_TOOLS == {"katana", "katana_headless"}
    worker_source = (
        pathlib.Path(__file__).resolve().parent.parent / "api" / "worker.py"
    ).read_text(encoding="utf-8")
    assert "name in agent_tools.KATANA_TOOLS" in worker_source
    assert 'if name == "katana"' not in worker_source
