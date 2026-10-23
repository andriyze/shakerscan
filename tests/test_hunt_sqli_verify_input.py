"""A Hunt sqli.verify names the input sqlmap tests, or it is refused before anything is reserved.

A Hunt of 2026-10-23 on the honey target: two of three ``sqli.verify`` calls named a bare path
(``/search``, ``/reports``). sqlmap, given a URL with no parameter and no body, answers its own
"do you want to try URI injections in the target URL itself?" with yes under ``--batch`` and
injects into the path, so each call spent its hold (measured with the pinned sqlmap and the
Hunt's argv: 515 requests) testing the path and never the page's parameter (``q``,
``filter``). Admission now refuses such a call with how to name the input; the worker refuses a
queued one before sqlmap starts (tests/test_hunt_thorough_scanner_dispatch_postgres.py).
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from api import agent_tools
from api.hunt import interaction_router as router
from hunt.sqli_target import NO_INJECTION_POINT, sqli_injection_point_refusal
from runtime.capability_registry import CAPABILITY_REGISTRY
from tests.test_hunt_authz_verification_limit import HUNT, AdmissionStore, Lifecycle, admission


@pytest.mark.parametrize("url", [
    "https://app.test/search", "https://app.test/reports", "https://app.test/",
    "https://app.test/a/b/c", "https://app.test/search#q=1",
])
def test_a_url_with_no_parameter_names_no_input(url):
    assert sqli_injection_point_refusal(url, {}) == NO_INJECTION_POINT


@pytest.mark.parametrize("url,options", [
    ("https://app.test/search?q=1", {}),
    ("https://app.test/reports?filter=x", {}),
    ("https://app.test/search?q=", {}),  # an empty value still names the parameter
    ("https://app.test/products/1*", {}),  # sqlmap's explicit marker: the path is the input
    ("https://app.test/items?id=1*", {}),
    ("https://app.test/login", {"body_field_names": ["user"], "method": "POST"}),
])
def test_a_named_parameter_marker_or_body_field_is_an_input(url, options):
    assert sqli_injection_point_refusal(url, options) is None


def test_the_refusal_says_how_to_name_the_input():
    assert "/reports?filter=x" in NO_INJECTION_POINT and "/products/1*" in NO_INJECTION_POINT


def _admit(path, *, target_url="https://fixture.example.test"):
    store = AdmissionStore()
    store.run["budget_profile"] = "thorough"
    store.run["policy_json"].update(active_testing=True)
    store.run["context_pack"] = {"target": {"url": target_url},
                                 "authorized_target_addresses": ["192.0.2.20"]}
    store.run["budget_json"].update(max_duration_seconds=14_400, max_http_requests=20_000)
    reserved = []

    class Reservation:
        def __init__(self, amounts):
            self.requested = dict(amounts)
            self.status = "requested"

        def reserve_against(self, *, limits, consumed, lease_seconds):
            reserved.append(dict(self.requested))
            used = dict(consumed)
            for key, amount in self.requested.items():
                used[key] = used.get(key, 0) + amount
            self.status = "reserved"
            return self, used

    overrides = {
        "agent_tools": SimpleNamespace(
            normalize_principal_slot=lambda _value: "anonymous", IDENTITY_HEADERS=set(),
            affordable_hunt_scanner_hold=agent_tools.affordable_hunt_scanner_hold,
            hunt_scanner_dispatch_budgets=agent_tools.hunt_scanner_dispatch_budgets,
            hunt_scanner_budget_context=agent_tools.hunt_scanner_budget_context,
        ),
        "_hunt_public": lambda *args, **kwargs: {"capabilities": [{"name": "sqli.verify"}]},
        "DurableBudgetReservation": SimpleNamespace(request=lambda **kw: Reservation(kw["amounts"])),
        "BudgetExceeded": router.BudgetExceeded,
    }
    values = CAPABILITY_REGISTRY.validate_hunt_input("sqli.verify", {"path": path} if path else {})
    lifecycle = Lifecycle("xss.verify")  # the labelled double's worker_scanner placement
    lifecycle.specification.placement_requirements = dict(
        CAPABILITY_REGISTRY.require("sqli.verify").placement_requirements,
    )
    asyncio.run(admission(store, **overrides)(
        str(HUNT), "sqli.verify", SimpleNamespace(input=values, idempotency_key="sqli-0001"), lifecycle,
    ))
    return store, reserved


@pytest.mark.parametrize("path", ["/search", "/reports", "/"])
def test_admission_refuses_a_path_with_no_input_before_reserving(path):
    with pytest.raises(HTTPException) as refused:
        _admit(path)
    assert refused.value.status_code == 422
    assert refused.value.detail == NO_INJECTION_POINT


def test_admission_refuses_no_path_on_a_target_url_with_no_parameter():
    with pytest.raises(HTTPException, match="needs an input to test"):
        _admit(None)


@pytest.mark.parametrize("path,target_url", [
    ("/search?q=1", "https://fixture.example.test"),
    ("/products/1*", "https://fixture.example.test"),
    (None, "https://fixture.example.test/item?id=1"),  # the registered URL names the parameter
])
def test_admission_reserves_a_call_that_names_its_input(path, target_url):
    store, reserved = _admit(path, target_url=target_url)
    assert len(store.actions) == 1
    assert reserved and reserved[0]["tool_wall_seconds"] == 1_200


def test_a_finished_hunt_proposes_no_sqli_step_it_could_not_run_again():
    from hunt.saved_actions import retained_step

    # A retained step carries no query, so a sqli.verify step would name no input.
    assert retained_step("sqli.verify", {"path": "/search"}, "app.test") is None
    assert retained_step("http.request", {"method": "GET", "path": "/search"}, "app.test") is not None
