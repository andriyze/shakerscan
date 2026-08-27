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


@pytest.mark.parametrize("http,wall", [(3, 2), (17, 16), (150, 75)])
def test_katana_command_is_derived_from_each_reservation(http, wall):
    plan = _plan("katana", {"http_requests": http, "tool_wall_seconds": wall})

    assert plan.hard_budget_dict["http_requests"] <= http
    assert plan.hard_budget_dict["tool_wall_seconds"] <= wall
    # The rate is DERIVED from the reservation rather than pinned at one. A
    # fixed rate of one made a 150-request reservation emit about 31, which is
    # too small to enumerate a real application's surface.
    rate = int(plan.argv[plan.argv.index("-rate-limit") + 1])
    duration = int(
        plan.argv[plan.argv.index("-crawl-duration") + 1].removesuffix("s")
    )
    assert 1 <= rate <= agent_tools._KATANA_MAX_RATE_PER_SECOND
    assert plan.argv[plan.argv.index("-concurrency") + 1] == str(rate)
    # The ceiling is exactly the derived plan and still inside the reservation.
    assert plan.hard_budget_dict["http_requests"] == rate * duration + 1
    assert plan.argv[plan.argv.index("-retry") + 1] == "0"
    assert "-disable-redirects" in plan.argv
    assert plan.budget_proof["method"] == "rate_time_upper_bound"


def test_katana_supervisor_deadline_includes_bounded_shutdown_grace():
    plan = _plan(
        "katana", {"http_requests": 150, "tool_wall_seconds": 75}
    )

    crawl_seconds = int(
        plan.argv[plan.argv.index("-crawl-duration") + 1].removesuffix("s")
    )
    assert crawl_seconds == 30
    assert plan.timeout_ms == 35_000
    rate = plan.budget_proof["inputs"]["rate_per_second"]
    assert plan.hard_budget_dict == {
        "http_requests": rate * crawl_seconds + 1,
        "tool_wall_seconds": 35,
    }
    # A 150-request reservation must fund a materially larger crawl than the
    # one-request-per-second floor it used to be pinned to.
    assert plan.hard_budget_dict["http_requests"] >= 75
    assert plan.budget_proof["inputs"]["shutdown_grace_seconds"] == 5


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


def test_ffuf_scales_throughput_to_finish_immutable_wordlist_within_hold():
    plan = _plan(
        "ffuf",
        {"http_requests": 220, "tool_wall_seconds": 75},
        runtime_paths={
            "ffuf_wordlist": "/tmp/worker-owned-list",
            "ffuf_word_count": 108,
        },
    )

    assert plan.hard_budget_dict == {
        "http_requests": 108,
        "tool_wall_seconds": 75,
    }
    assert int(plan.argv[plan.argv.index("-rate") + 1]) >= 2
    assert int(plan.argv[plan.argv.index("-t") + 1]) >= 2
    assert plan.budget_proof["inputs"]["entries"] == 108


@pytest.mark.parametrize(
    "name,reserved,required",
    [
        ("nuclei", {"http_requests": 301, "tool_wall_seconds": 60}, "4000 HTTP requests and 300 seconds"),
        ("dalfox", {"http_requests": 61, "tool_wall_seconds": 60}, "400 HTTP requests and 120 seconds"),
        ("sqlmap", {"http_requests": 61, "tool_wall_seconds": 60}, "900 HTTP requests and 300 seconds"),
    ],
)
def test_underpowered_active_verifier_profiles_fail_before_launch(
    name, reserved, required,
):
    with pytest.raises(agent_tools.AgentToolError, match=required):
        _plan(name, reserved)


def test_sqlmap_profile_is_single_target_noninteractive_and_has_no_expansion_flags():
    plan = _plan("sqlmap", {"http_requests": 900, "tool_wall_seconds": 300})

    assert plan.argv[plan.argv.index("--threads") + 1] == "1"
    assert plan.argv[plan.argv.index("--retries") + 1] == "0"
    assert plan.argv[plan.argv.index("--technique") + 1] == "BEUT"
    assert "--crawl" not in plan.argv
    for forbidden in ("--os-shell", "--sql-shell", "--file-read", "--dump", "--dump-all"):
        assert forbidden not in plan.argv


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


def test_passive_nuclei_plan_uses_exact_reviewed_get_only_allowlist():
    template_ids = ",".join(sorted(
        row[0] for row in agent_tools.CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    ))
    plan = agent_tools.build_enforced_scanner_plan(
        "nuclei",
        TARGET,
        {
            "severity": "critical,high,medium,low,info",
            "template_ids": template_ids,
            "template_request_cost_upper_bound": 7,
        },
        reserved_budget={"http_requests": 7, "tool_wall_seconds": 30},
        pinned_address=PIN,
        pinned_proxy_url=PROXY,
    )

    assert plan.argv[plan.argv.index("-id") + 1] == template_ids
    assert "-severity" not in plan.argv
    assert "-tags" not in plan.argv
    assert "-disable-redirects" in plan.argv
    assert "-no-interactsh" in plan.argv
    assert "-omit-raw" in plan.argv
    assert "-omit-template" in plan.argv
    assert plan.budget_proof["accounting_mode"] == "exact"
    assert plan.budget_proof["method"] == "reviewed_template_allowlist"
    assert plan.hard_budget_dict["http_requests"] == 7


def test_passive_nuclei_plan_rejects_a_forged_request_ceiling():
    template_ids = ",".join(sorted(
        row[0] for row in agent_tools.CANONICAL_PASSIVE_NUCLEI_TEMPLATES
    ))
    with pytest.raises(
        agent_tools.AgentToolError,
        match="request ceiling is not canonical",
    ):
        agent_tools.build_enforced_scanner_plan(
            "nuclei",
            TARGET,
            {
                "template_ids": template_ids,
                "template_request_cost_upper_bound": 1,
            },
            reserved_budget={"http_requests": 7, "tool_wall_seconds": 30},
            pinned_address=PIN,
            pinned_proxy_url=PROXY,
        )


def _batch_plan(tool, reserved):
    paths = {"sqlmap_output_dir": "/tmp/sqlmap-scratch"} if tool == "sqlmap" else None
    return agent_tools.build_enforced_scanner_plan(
        tool, "https://app.example.test/search?q=1", {"_batch_attempt": True},
        reserved_budget=reserved, runtime_paths=paths,
    )


def test_a_batched_attempt_is_paced_to_spend_what_it_reserved():
    """The wall is the only runtime enforcement these tools have.

    Nothing counts their requests, so the inter-request delay is what keeps
    real traffic inside the reservation. A fixed one-second delay made the wall
    bind long before the requests did: sqlmap needs roughly a hundred requests
    to reach a verdict on an obvious injection and takes about two seconds
    unpaced, but at one second apiece no slice a batch could afford let it
    finish, so every attempt returned unproven.
    """
    plan = _batch_plan("sqlmap", {"http_requests": 160, "tool_wall_seconds": 30})
    argv = list(plan.argv)
    delay = float(argv[argv.index("--delay") + 1])
    hard = dict(plan.hard_budget)
    assert hard["http_requests"] <= 160 and hard["tool_wall_seconds"] <= 30
    # The pacing must leave headroom: planning to consume the whole wall means
    # start-up and teardown push the tool past its deadline and every attempt
    # returns "timeout" having proved nothing.
    planned_span = delay * hard["http_requests"]
    assert planned_span < hard["tool_wall_seconds"], (
        f"pacing plans {planned_span:.1f}s of a {hard['tool_wall_seconds']}s wall"
    )
    assert planned_span <= hard["tool_wall_seconds"] * 0.9
    # ...and still be slow enough that the wall bounds the traffic.
    assert delay > 0


def test_pacing_never_claims_more_requests_than_the_wall_can_cover():
    """A wall too short for the reservation must lower the claim, not the delay."""
    delay, affordable = agent_tools._batch_attempt_pacing(10_000, 5, minimum_seconds=0.05)
    assert delay == 0.05
    assert affordable <= int(5 / 0.05)
    assert affordable < 10_000


def test_both_batched_verifiers_declare_a_reachable_floor():
    """Below its floor an attempt cannot reach a verdict and is not worth starting."""
    for tool in ("sqlmap", "dalfox"):
        floor = agent_tools.EXTERNAL_BATCH_ATTEMPT_FLOORS[tool]
        plan = _batch_plan(tool, floor)
        hard = dict(plan.hard_budget)
        assert hard["http_requests"] >= 100, tool
        assert hard["tool_wall_seconds"] >= 20, tool


def test_a_timed_out_batch_reports_a_timeout_not_truncated_output():
    """The durable reason must be the real one.

    Every per-attempt error was the tool's own "timeout" string, which is not a
    reason code, so the result fell back to `output_truncated` -- a false reason
    on a required action that made the whole scan's grade unreliable.
    """
    import pathlib

    from scan.capability_result import CapabilityResultReason

    adapter = (
        pathlib.Path(__file__).resolve().parent.parent
        / "api" / "scan" / "action_adapter.py"
    ).read_text(encoding="utf-8")
    batch = adapter[adapter.index("async def _external_batch"):]
    batch = batch[:batch.index("    async def _authz(")]
    assert "CapabilityResultReason.TIMED_OUT.value" in batch
    assert "CapabilityResultReason.INSUFFICIENT_PLAN_BUDGET.value" in batch
    # The stated reason must lead, so _receipt_reason finds it before tool noise.
    assert "batch_errors.insert(0, stated)" in batch
    assert CapabilityResultReason.TIMED_OUT.value == "timed_out"


def test_the_planner_and_the_adapter_share_one_set_of_floors():
    """Drift between them is what broke batch funding.

    The planner sizes a slice and the adapter decides whether an attempt is
    worth starting. When those read different numbers, a batch declares more
    candidates than its own reservation can pay for and reports partial forever.
    """
    from scan.external_process import BATCH_ATTEMPT_FLOORS, batch_attempt_capacity

    assert agent_tools.EXTERNAL_BATCH_ATTEMPT_FLOORS["dalfox"] == (
        BATCH_ATTEMPT_FLOORS["xss.verify_batch"]
    )
    assert agent_tools.EXTERNAL_BATCH_ATTEMPT_FLOORS["sqlmap"] == (
        BATCH_ATTEMPT_FLOORS["sqli.verify_batch"]
    )
    # A capability with no declared floor is unbounded rather than zero.
    assert batch_attempt_capacity("exposure.verify_batch", {"http_requests": 600}) is None
    # ...and a real floor divides its reservation.
    assert batch_attempt_capacity(
        "sqli.verify_batch", {"http_requests": 1_600, "tool_wall_seconds": 300},
    ) == 10
