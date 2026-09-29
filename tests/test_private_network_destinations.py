"""A registered internal target on a private address, and the classes no setting admits.

Observed on an Enterprise soak (engine 2.5.4): ``http://172.17.0.1:3001`` -- the host's own lab
container on the Docker bridge, registered with the ``internal`` cohort and authorized -- was
refused with "Scan target address is not an allowed destination class" and nothing else.

The refusal itself is the documented design: outside Lab environments, loopback and private
ranges are admitted only when the deployment says the engine's network is the operator's own
(``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=allow``). The OSS default allows; the Enterprise gateway
passes ``refuse`` unless its operator chooses otherwise. What was wrong is that the refusal did
not say so, and gave the same words for the cloud metadata address, which no setting admits.

These tests pin both halves for Scan admission -- the path ``POST /scans`` and
``POST /targets/{id}/scan`` share -- and for the scope receipt that authorization records.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(1, str(ROOT / "scanner"))

import action_scope  # noqa: E402

SETTING = "SHAKERSCAN_PRIVATE_NETWORK_TARGETS"
NEVER = (
    "169.254.169.254", "169.254.170.2", "fd00:ec2::254", "169.254.10.1", "224.0.0.1", "0.0.0.0",
)


def _admit(url, *, environment="internal"):
    import fleet_routes.router as fleet_router

    return asyncio.run(fleet_router._resolve_runtime_target_addresses(
        url, subject="Scan target", environment=environment,
    ))


def _refusal(url, *, environment="internal"):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as refused:
        _admit(url, environment=environment)
    assert refused.value.status_code == 422
    return refused.value.detail


def test_an_internal_private_target_is_scannable_once_the_deployment_opts_in(monkeypatch):
    monkeypatch.setenv(SETTING, "allow")
    assert _admit("http://172.17.0.1:3001") == ["172.17.0.1"]
    assert _admit("http://10.20.30.40") == ["10.20.30.40"]
    assert _admit("http://[fd12:3456::7]:8080") == ["fd12:3456::7"]


def test_a_refusing_deployment_says_which_setting_refused_the_internal_target(monkeypatch):
    monkeypatch.setenv(SETTING, "refuse")
    detail = _refusal("http://172.17.0.1:3001")
    assert detail.startswith("Scan target address is not an allowed destination class: ")
    assert "172.17.0.1 is a private-network address; this deployment does not allow " in detail
    assert "private-network targets" in detail
    assert f"set {SETTING}=allow for the API and workers" in detail
    assert "docs/functionality-reference.md#15-safety-model" in detail
    assert "'internal'" in detail, "the environment the target was judged under is named"


def test_a_target_shown_as_internal_but_judged_as_production_is_explained(monkeypatch):
    """The target list derives an ``internal`` cohort from a private URL; policy reads only the
    stored environment/cohort, so the same row is judged as production. The refusal must not
    read as a contradiction of what the target list shows."""
    from asset_cohorts import target_cohort
    from target_authorization import effective_target_environment

    url = "http://172.17.0.1:3001"
    assert target_cohort(url=url, metadata={}) == "internal"
    environment = effective_target_environment({})
    assert environment == "production"

    monkeypatch.setenv(SETTING, "refuse")
    for judged in (environment, "unknown", ""):
        detail = _refusal(url, environment=judged)
        assert "evaluated under the 'production' environment" in detail
        assert "an 'internal' cohort does not make it a Lab target" in detail
        assert "set the target's cohort to Lab" in detail
        assert "judged as" not in detail


def test_a_lab_target_stays_admitted_under_a_refusing_deployment(monkeypatch):
    monkeypatch.setenv(SETTING, "refuse")
    assert _admit("http://172.17.0.1:3001", environment="lab") == ["172.17.0.1"]


@pytest.mark.parametrize("address", NEVER)
@pytest.mark.parametrize("policy", ["allow", "refuse"])
def test_restricted_classes_are_refused_under_every_setting(monkeypatch, address, policy):
    monkeypatch.setenv(SETTING, policy)
    host = f"[{address}]" if ":" in address else address
    for environment in ("internal", "production", "lab"):
        detail = _refusal(f"http://{host}", environment=environment)
        assert "never scanned in any environment" in detail
        assert SETTING not in detail, "no setting admits this class, so none is suggested"


def test_loopback_follows_the_deployment_setting_as_documented(monkeypatch):
    monkeypatch.setenv(SETTING, "refuse")
    detail = _refusal("http://127.0.0.1:3000")
    assert "127.0.0.1 is a loopback address" in detail and f"{SETTING}=allow" in detail
    monkeypatch.setenv(SETTING, "allow")
    assert _admit("http://127.0.0.1:3000") == ["127.0.0.1"]


def test_the_scope_receipt_records_the_same_explanation(monkeypatch):
    monkeypatch.setenv(SETTING, "refuse")
    receipt = action_scope.evaluate_scope("http://172.17.0.1:3001", environment="internal")
    assert receipt.verdict == "blocked"
    blocked = [check for check in receipt.checks if check.status == "blocked"]
    assert any(f"{SETTING}=allow" in check.message for check in blocked)

    monkeypatch.setenv(SETTING, "allow")
    receipt = action_scope.evaluate_scope("http://172.17.0.1:3001", environment="internal")
    assert "loopback_or_private_range" not in receipt.blocked_by
    assert any(check.name == "private_network_scope" for check in receipt.checks)


@pytest.mark.parametrize(
    ("value", "admitted"),
    [
        ("allow", True), ("ALLOWED", True), ("true", True),
        ("1", True), ("yes", True), ("on", True),
        ("", True),  # unset: the OSS default admits, as documented
        ("refuse", False), ("false", False), ("0", False), ("10.0.0.0/8", False),
    ],
)
def test_the_setting_is_a_switch_not_a_range_list(monkeypatch, value, admitted):
    """Values: allow/allowed/true/1/yes/on admit; unset admits (OSS default); anything else refuses.

    It is not a CIDR list: a range given as the value refuses rather than admitting that range.
    """
    monkeypatch.setenv(SETTING, value)
    if admitted:
        assert _admit("http://172.17.0.1:3001") == ["172.17.0.1"]
    else:
        assert "does not allow private-network targets" in _refusal("http://172.17.0.1:3001")


def test_both_submission_paths_reach_the_same_admission(monkeypatch):
    """POST /targets/{id}/scan submits the stored URL through the POST /scans admission."""
    from tests.api_import_stubs import install_fastapi_exception_stubs

    install_fastapi_exception_stubs()
    from targets import router as targets_router

    submitted = []

    class Conn:
        async def fetchrow(self, query, *args):
            return {"url": "http://172.17.0.1:3001", "scan_options": {}}

    class Pool:
        def acquire(self):
            class _A:
                async def __aenter__(self_inner):
                    return Conn()

                async def __aexit__(self_inner, *exc):
                    return False

            return _A()

    async def submit(request, *, stored_scheme_inferred=False):
        assert stored_scheme_inferred is False
        submitted.append(request.target)
        return {"scan_id": "s"}

    monkeypatch.setattr(targets_router, "_pool", lambda: Pool())
    monkeypatch.setattr(targets_router, "_submit_scan", submit)
    asyncio.run(targets_router.scan_target("00000000-0000-4000-8000-000000000001"))
    assert submitted == ["http://172.17.0.1:3001"]
