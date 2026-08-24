from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import agent_tools
from scan.external_process import (
    ExternalProcessContractError,
    validate_enforcement_receipt,
)


TARGET = "https://app.example.test/search?q=one"
PIN = "192.0.2.20"
PROXY = "socks5://127.0.0.1:43123"


def _plan(name, reserved, *, runtime_paths=None):
    if name == "sqlmap" and runtime_paths is None:
        runtime_paths = {"sqlmap_output_dir": "/tmp/sqlmap-worker-owned"}
    return agent_tools.build_enforced_scanner_plan(
        name,
        TARGET,
        {},
        reserved_budget=reserved,
        pinned_address=PIN,
        pinned_proxy_url=PROXY,
        runtime_paths=runtime_paths,
    )


@pytest.mark.parametrize("http,wall", [(2, 1), (3, 2), (17, 16), (150, 75)])
def test_katana_command_is_derived_from_each_reservation(http, wall):
    plan = _plan("katana", {"http_requests": http, "tool_wall_seconds": wall})

    assert plan.hard_budget_dict["http_requests"] <= http
    assert plan.hard_budget_dict["tool_wall_seconds"] <= wall
    assert plan.argv[plan.argv.index("-rate-limit") + 1] == "1"
    assert plan.argv[plan.argv.index("-concurrency") + 1] == "1"
    assert plan.argv[plan.argv.index("-retry") + 1] == "0"
    assert "-disable-redirects" in plan.argv
    assert plan.budget_proof["method"] == "rate_time_upper_bound"


def test_httpx_is_exactly_one_request_without_fallback_or_redirects():
    plan = _plan("httpx", {"http_requests": 1, "tool_wall_seconds": 4})

    assert plan.hard_budget_dict == {
        "http_requests": 1,
        "tool_wall_seconds": 4,
    }
    assert "-no-fallback-scheme" in plan.argv
    assert "-disable-update-check" in plan.argv
    assert plan.argv[plan.argv.index("-retries") + 1] == "0"
    assert "-follow-redirects" not in plan.argv
    assert plan.budget_proof["accounting_mode"] == "exact"


def test_ffuf_exact_wordlist_has_no_hidden_calibration_or_redirect_requests():
    plan = _plan(
        "ffuf",
        {"http_requests": 7, "tool_wall_seconds": 9},
        runtime_paths={
            "ffuf_wordlist": "/tmp/worker-owned-list",
            "ffuf_word_count": 7,
        },
    )

    assert plan.hard_budget_dict == {
        "http_requests": 7,
        "tool_wall_seconds": 9,
    }
    assert plan.argv[plan.argv.index("-w") + 1] == "/tmp/worker-owned-list"
    assert "-ac" not in plan.argv
    assert "-r" not in plan.argv
    assert plan.argv[plan.argv.index("-t") + 1] == "1"
    assert plan.budget_proof["method"] == "exact_wordlist"


@pytest.mark.parametrize(
    "name,reserved,rate_flag,concurrency_flag",
    [
        ("nuclei", {"http_requests": 301, "tool_wall_seconds": 60}, "-rate-limit", "-concurrency"),
        ("dalfox", {"http_requests": 61, "tool_wall_seconds": 60}, "--delay", "--worker"),
        ("sqlmap", {"http_requests": 61, "tool_wall_seconds": 60}, "--delay", "--threads"),
    ],
)
def test_verifier_commands_scale_to_reviewed_reservations(
    name, reserved, rate_flag, concurrency_flag,
):
    plan = _plan(name, reserved)

    assert plan.hard_budget_dict == reserved
    assert plan.timeout_ms == reserved["tool_wall_seconds"] * 1_000
    assert plan.argv[plan.argv.index(concurrency_flag) + 1] == "1"
    assert rate_flag in plan.argv
    assert plan.budget_proof["inputs"]["profile"] == "reduced"
    assert plan.budget_proof["method"] == "rate_time_upper_bound"


@pytest.mark.parametrize("name", ["nuclei", "dalfox", "sqlmap"])
def test_reduced_verifier_profiles_still_fail_closed_below_minimum(name):
    with pytest.raises(agent_tools.AgentToolError, match="capacity"):
        _plan(name, {"http_requests": 1, "tool_wall_seconds": 1})


def test_sqlmap_profile_is_single_target_noninteractive_and_has_no_expansion_flags():
    plan = _plan("sqlmap", {"http_requests": 900, "tool_wall_seconds": 300})

    assert plan.argv[plan.argv.index("--threads") + 1] == "1"
    assert plan.argv[plan.argv.index("--retries") + 1] == "0"
    assert plan.argv[plan.argv.index("--technique") + 1] == "BEUT"
    assert "--crawl" not in plan.argv
    for forbidden in ("--os-shell", "--sql-shell", "--file-read", "--dump", "--dump-all"):
        assert forbidden not in plan.argv


def test_reduced_sqlmap_profile_drops_time_based_techniques_and_risk():
    plan = _plan("sqlmap", {"http_requests": 31, "tool_wall_seconds": 30})

    assert plan.argv[plan.argv.index("--technique") + 1] == "BE"
    assert plan.argv[plan.argv.index("--level") + 1] == "1"
    assert plan.argv[plan.argv.index("--risk") + 1] == "1"


def test_enforcement_receipt_cannot_authorize_more_than_the_hold():
    receipt = _plan(
        "nuclei", {"http_requests": 4_000, "tool_wall_seconds": 300},
    ).enforcement_receipt()
    receipt["hard_budget"] = {
        "http_requests": 4_001,
        "tool_wall_seconds": 300,
    }

    with pytest.raises(ExternalProcessContractError, match="exceeds reservation"):
        validate_enforcement_receipt(
            receipt,
            reserved={"http_requests": 4_000, "tool_wall_seconds": 300},
        )


def test_nuclei_enforced_plan_disables_redirects_retries_and_oob():
    plan = agent_tools.build_enforced_scanner_plan(
        "nuclei",
        TARGET,
        {},
        reserved_budget={"http_requests": 4_000, "tool_wall_seconds": 300},
        pinned_address=PIN,
        pinned_proxy_url=PROXY,
        oob_interactsh_server="https://private-oob.example.test",
        oob_interactsh_token="secret",
    )

    assert plan.argv[plan.argv.index("-retries") + 1] == "0"
    assert "-disable-redirects" in plan.argv
    assert "-no-interactsh" in plan.argv
    assert "-interactsh-server" not in plan.argv
