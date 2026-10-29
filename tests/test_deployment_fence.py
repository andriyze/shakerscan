"""This deployment's own addresses are never a scan destination.

Loopback and the networks in ``SHAKERSCAN_DEVICE_DENY_CIDRS`` (the Enterprise render sets the
container networks, loopback and link-local there, and every private range when private networks
are refused) are refused for a web Scan, a Hunt and a device scan, whatever the private-network
setting (``allow`` included) and whatever the environment label (Staging and Lab included). An
ordinary private target is still admitted where the setting or a Lab label allows it. Resolvers are
injected; no network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import sys

import pytest
from fastapi import HTTPException

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope  # noqa: E402
import deployment_policy  # noqa: E402
import target_resolution  # noqa: E402
from runtime.models import TargetBinding  # noqa: E402
from scan.runtime_dns import RuntimeDnsRevalidationError, revalidate_runtime_target_addresses  # noqa: E402
from scanner_tools import address_classes, device_posture  # noqa: E402

PRIVATE = "SHAKERSCAN_PRIVATE_NETWORK_TARGETS"
DENY = "SHAKERSCAN_DEVICE_DENY_CIDRS"
# What the Enterprise render passes (gateway deploy.py DEVICE_DENY_ALWAYS) under `allow`.
RENDER_DENY = "172.16.0.0/12,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10"
CONTAINER = "172.18.0.5"
LAN = "10.10.10.100"
LABELS = ("production", "staging", "lab", "development", "test")


@pytest.fixture
def enterprise_allow(monkeypatch):
    monkeypatch.setenv(PRIVATE, "allow")
    monkeypatch.setenv(DENY, RENDER_DENY)
    monkeypatch.delenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", raising=False)


def _blocked(url, environment):
    host = url.split("//", 1)[1].split("/", 1)[0].rsplit(":", 1)[0].strip("[]")
    return evaluate(url, environment, host)


def evaluate(url, environment, host):
    receipt = action_scope.evaluate_scope(url, allowed_hosts=[host], environment=environment)
    return "loopback_or_private_range" in receipt.blocked_by, receipt


# --- the shared classifier ------------------------------------------------------------------


def test_loopback_and_the_configured_list_are_fenced_in_every_spelling(enterprise_allow):
    fenced = address_classes.deployment_fenced
    for raw in ("127.0.0.1", "127.8.9.10", "::1", CONTAINER, "::ffff:172.18.0.5", "169.254.10.20"):
        assert fenced(ipaddress.ip_address(raw)), raw
    for raw in (LAN, "192.168.1.50", "93.184.216.34"):
        assert not fenced(ipaddress.ip_address(raw)), raw


def test_without_a_list_only_loopback_is_fenced(monkeypatch):
    monkeypatch.delenv(DENY, raising=False)
    assert address_classes.deployment_fenced(ipaddress.ip_address("127.0.0.1"))
    assert not address_classes.deployment_fenced(ipaddress.ip_address(CONTAINER))


def test_a_malformed_list_stops_the_process_at_startup(monkeypatch):
    monkeypatch.setenv(DENY, "172.16.0.0/12,not-a-network")
    with pytest.raises(RuntimeError, match=DENY):
        deployment_policy.require_valid_destination_settings()


# --- web Scan admission (the scope receipt and the resolved-address filter) --------------------


@pytest.mark.parametrize("environment", LABELS)
@pytest.mark.parametrize("url", [
    f"http://{CONTAINER}:8000/", "http://127.0.0.1:8080/", "http://localhost:3000/",
    "http://[::1]:8000/", "http://[::ffff:172.18.0.5]:8000/",
])
def test_a_web_scan_never_reaches_this_deployment_under_allow_or_any_label(enterprise_allow, url, environment):
    host = "localhost" if "localhost" in url else url.split("//", 1)[1].rsplit(":", 1)[0].strip("[]")
    blocked, receipt = evaluate(url, environment, host)
    assert blocked, (url, environment)
    message = next(check.message for check in receipt.checks if check.name == "loopback_or_private_range")
    assert "this deployment's own addresses" in message
    # The refusal never suggests a setting or label that would not admit it.
    assert "set the target's cohort to Lab" not in message


@pytest.mark.parametrize("environment", ["staging", "lab"])
def test_a_lab_label_on_a_refusing_deployment_does_not_reach_this_deployment(monkeypatch, environment):
    monkeypatch.setenv(PRIVATE, "refuse")
    monkeypatch.setenv(DENY, RENDER_DENY + ",10.0.0.0/8,192.168.0.0/16,100.64.0.0/10,0.0.0.0/8,fc00::/7")
    assert _blocked(f"http://{CONTAINER}:8000/", environment)[0]
    assert _blocked("http://127.0.0.1:8000/", environment)[0]


def test_ordinary_private_targets_still_work_where_the_setting_allows_them(enterprise_allow, monkeypatch):
    for environment in LABELS:
        blocked, receipt = _blocked(f"http://{LAN}:3000/", environment)
        assert not blocked and receipt.verdict == "allowed", environment
    # A refusing open-source install (no list) still admits a LAN target with a Lab label...
    monkeypatch.setenv(PRIVATE, "refuse")
    monkeypatch.delenv(DENY)
    assert not _blocked(f"http://{LAN}:3000/", "lab")[0]
    # ...and refuses it in production.
    assert _blocked(f"http://{LAN}:3000/", "production")[0]
    # Without a list, the open-source default still reaches its own compose services by name.
    monkeypatch.setenv(PRIVATE, "allow")
    assert not _blocked(f"http://{CONTAINER}:3000/", "production")[0]


@pytest.mark.parametrize("environment", LABELS)
def test_scan_admission_drops_resolved_addresses_inside_the_fence(enterprise_allow, environment):
    admits = target_resolution.policy_admits(environment)
    assert not admits(CONTAINER) and not admits("127.0.0.1") and not admits("::1")
    assert admits(LAN)


def _binding(addresses, host="app.example.test", environment="staging"):
    return TargetBinding(
        target_id="t1", target_kind="web", canonical_host=host,
        allowed_origins=(f"http://{host}",), allowed_addresses=tuple(addresses),
        allowed_root_domains=(host,), environment=environment,
    )


def test_execution_refuses_a_frozen_address_inside_the_fence(enterprise_allow):
    """A Scan or Hunt binding frozen before the list named the address is refused before it
    connects: every execution path re-classifies its frozen set (runtime_dns)."""
    with pytest.raises(RuntimeDnsRevalidationError, match="no longer an allowed destination"):
        revalidate_runtime_target_addresses(_binding([CONTAINER]), [CONTAINER])
    evidence = revalidate_runtime_target_addresses(_binding([LAN]), [LAN])
    assert evidence["effective_addresses"] == [LAN]


def test_a_runtime_destination_check_refuses_the_fence_even_when_frozen(enterprise_allow):
    guard = action_scope.runtime_scope_guard_from_scope({
        "id": "r1", "environment": "lab", "allowed_hosts": ["app.example.test"],
        "normalized_scope": {"host": "app.example.test"},
    })
    guard["allowed_addresses"] = [CONTAINER]
    result = action_scope.evaluate_runtime_destination_scope(
        guard, "http://app.example.test/", resolution_observations=[
            {"host": "app.example.test", "ips": [CONTAINER]},
        ],
    )
    assert result["verdict"] == "blocked"
    assert "runtime_dns_private_range" in result["blocked_by"]


# --- Hunt (start-time address freeze and operator-confirmed origins) ------------------------------


def _hunt_resolve(monkeypatch, url, answers, environment):
    import fleet_routes.router as fleet_router

    async def getaddrinfo(host, port, **_kwargs):
        return [(None, None, None, "", (address, port)) for address in answers]

    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)
    try:
        return loop.run_until_complete(fleet_router._resolve_runtime_target_addresses(
            url, subject="Hunt target", environment=environment,
        ))
    finally:
        loop.close()


@pytest.mark.parametrize("environment", LABELS)
def test_a_hunt_target_that_resolves_into_the_fence_is_refused(enterprise_allow, monkeypatch, environment):
    with pytest.raises(HTTPException) as caught:
        _hunt_resolve(monkeypatch, "http://app.example.test/", [CONTAINER], environment)
    assert caught.value.status_code == 422
    assert "this deployment's own addresses" in caught.value.detail
    with pytest.raises(HTTPException):
        _hunt_resolve(monkeypatch, f"http://{CONTAINER}:8000/", [], environment)
    # A mixed answer keeps only the address outside the fence.
    assert _hunt_resolve(monkeypatch, "http://app.example.test/", [CONTAINER, LAN], environment) == [LAN]


def test_a_hunt_direct_origin_inside_the_fence_is_refused(enterprise_allow):
    assert action_scope.direct_origin_refusal(CONTAINER) == "loopback_or_private_range"
    assert action_scope.direct_origin_refusal("127.0.0.1") == "loopback_or_private_range"
    assert action_scope.direct_origin_refusal(LAN) is None


# --- device plane (admission on both device routes, and the worker) -------------------------------


def _admit(locator, environment, **kwargs):
    from devices import destination_policy

    return asyncio.run(destination_policy.admit_device_destination(locator, environment, **kwargs))


@pytest.mark.parametrize("environment", LABELS)
@pytest.mark.parametrize("address", [CONTAINER, "127.0.0.1", "::1", "169.254.10.20"])
def test_device_admission_refuses_the_fence_before_queueing(enterprise_allow, environment, address):
    with pytest.raises(HTTPException) as caught:
        _admit(address, environment)
    assert caught.value.status_code == 422
    assert caught.value.detail["setting"] == DENY


@pytest.mark.parametrize("environment", ["production", "lab"])
def test_device_admission_resolves_names_under_allow_and_lab_labels(enterprise_allow, environment):
    async def container(_host):
        return [CONTAINER]

    async def mixed(_host):
        return [CONTAINER, LAN]

    with pytest.raises(HTTPException) as caught:
        _admit("db.internal.test", environment, resolve=container)
    assert caught.value.status_code == 422
    assert _admit("nas.internal.test", environment, resolve=mixed) == [LAN]
    assert _admit(LAN, environment) == [LAN]


def test_device_admission_on_a_refusing_deployment_reads_the_list_under_a_lab_label(monkeypatch):
    monkeypatch.setenv(PRIVATE, "refuse")
    monkeypatch.setenv(DENY, RENDER_DENY)
    with pytest.raises(HTTPException):
        _admit(CONTAINER, "lab")
    assert _admit("192.168.1.50", "lab") == ["192.168.1.50"]


@pytest.mark.parametrize("metadata_switch", ["false", "true"])
def test_the_device_worker_applies_the_fence_whatever_the_metadata_switch(enterprise_allow, monkeypatch, metadata_switch):
    monkeypatch.setenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", metadata_switch)
    for address in (CONTAINER, "127.0.0.1"):
        with pytest.raises(ValueError, match="configured control-plane address"):
            device_posture.validate_device_destination(address, environment="lab", policy="allow")
    assert device_posture.validate_device_destination(LAN, environment="production", policy="allow") == LAN
