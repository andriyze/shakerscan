"""Connected-device scans honour SHAKERSCAN_PRIVATE_NETWORK_TARGETS.

A deployment that sets ``SHAKERSCAN_PRIVATE_NETWORK_TARGETS=refuse`` used to refuse private web
targets while the device/network plane queued and scanned a private address (172.26.0.2, the
engine's own Docker network) anyway: neither the API admission nor the device worker consulted
the policy, and the device worker was not even given the setting. These tests pin the policy at
admission, in the worker (posture scan and service probe) and in the Compose plumbing, and keep
the OSS default (unset means allow) admitting LAN devices. Resolvers are injected; no network.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
import yaml
from fastapi import HTTPException

from tests.api_sources import definition_source

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import action_scope  # noqa: E402
import deployment_policy  # noqa: E402
from scanner_tools import device_posture  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ENV = "SHAKERSCAN_PRIVATE_NETWORK_TARGETS"


def _admit(locator, environment, **kwargs):
    from devices import destination_policy

    return asyncio.run(destination_policy.admit_device_destination(locator, environment, **kwargs))


@pytest.mark.parametrize("address", ["172.26.0.2", "10.0.0.5", "fd12::7", "::ffff:10.0.0.5", "127.0.0.1"])
def test_refusing_deployment_refuses_private_device_at_admission(monkeypatch, address):
    monkeypatch.setenv(ENV, "refuse")
    with pytest.raises(HTTPException) as caught:
        _admit(address, "production")
    assert caught.value.status_code == 422
    detail = caught.value.detail
    assert detail["reason"] == "loopback_or_private_range"
    assert detail["setting"] == ENV
    assert ENV in detail["message"]


@pytest.mark.parametrize("value", [None, "allow"])
def test_unset_and_allow_admit_lan_devices(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, value)
    assert _admit("192.168.1.50", "production") == ["192.168.1.50"]


def test_lab_environment_admits_private_under_refuse_but_internal_does_not(monkeypatch):
    monkeypatch.setenv(ENV, "refuse")
    assert _admit("192.168.1.50", "Lab") == ["192.168.1.50"]
    with pytest.raises(HTTPException):
        _admit("192.168.1.50", "internal")


@pytest.mark.parametrize("policy", ["allow", "refuse"])
@pytest.mark.parametrize("address", ["169.254.10.20", "fe80::1"])
def test_link_local_devices_stay_admitted(monkeypatch, policy, address):
    """APIPA/link-local LAN devices were scannable before; the policy is about private ranges."""
    monkeypatch.setenv(ENV, policy)
    assert _admit(address, "production") == [address]
    monkeypatch.delenv("SHAKERSCAN_DEVICE_DENY_CIDRS", raising=False)
    assert device_posture.validate_device_destination(address, environment="production", policy=policy) == address


def test_hostname_resolution_is_classified(monkeypatch):
    monkeypatch.setenv(ENV, "refuse")

    async def private_only(_host):
        return ["10.1.2.3"]

    async def mixed(_host):
        return ["10.1.2.3", "93.184.216.34"]

    async def failing(_host):
        raise OSError("no such host")

    with pytest.raises(HTTPException) as caught:
        _admit("nas.internal.test", "production", resolve=private_only)
    assert caught.value.status_code == 422
    assert _admit("nas.example.test", "production", resolve=mixed) == ["93.184.216.34"]
    # Unresolvable names are left to the worker, which reports unresolved reachability.
    assert _admit("gone.example.test", "production", resolve=failing) == []


def test_device_lab_set_matches_the_web_scope_guard():
    assert set(device_posture.DEVICE_LAB_ENVIRONMENTS) == set(action_scope.SAFE_LAB_ENVIRONMENTS)


@pytest.mark.parametrize("raw", [None, "", "allow", "ALLOW", "yes", "1", "refuse", "no", "0", "bogus"])
def test_worker_policy_parsing_matches_the_deployment_policy(raw):
    environ = {} if raw is None else {ENV: raw}
    assert device_posture.private_network_targets_policy(environ.get(ENV)) == (
        deployment_policy.private_network_targets_policy(environ)
    )


def test_worker_refuses_private_destination_under_refuse(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)
    monkeypatch.delenv("SHAKERSCAN_DEVICE_DENY_CIDRS", raising=False)
    with pytest.raises(ValueError, match=ENV):
        device_posture.validate_device_destination("172.26.0.2", environment="production", policy="refuse")
    assert device_posture.validate_device_destination("172.26.0.2", environment="production", policy="allow") == "172.26.0.2"
    assert device_posture.validate_device_destination("172.26.0.2", environment="lab", policy="refuse") == "172.26.0.2"


def test_stricter_of_admission_and_worker_policy_wins(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_DEVICE_DENY_CIDRS", raising=False)
    # A remote device worker with no setting still honours the refusing admitting deployment.
    monkeypatch.delenv(ENV, raising=False)
    with pytest.raises(ValueError, match=ENV):
        device_posture.validate_device_destination("10.0.0.9", environment="production", policy="refuse")
    # A refusing worker is not loosened by a job that was admitted under allow.
    monkeypatch.setenv(ENV, "refuse")
    with pytest.raises(ValueError, match=ENV):
        device_posture.validate_device_destination("10.0.0.9", environment="production", policy="allow")
    with pytest.raises(ValueError, match=ENV):
        device_posture.validate_device_destination("10.0.0.9")


def test_metadata_flag_keeps_its_meaning_and_does_not_bypass_private_policy(monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", "1")
    monkeypatch.setenv(ENV, "refuse")
    assert device_posture.validate_device_destination("169.254.169.254", policy="refuse") == "169.254.169.254"
    assert device_posture.validate_device_destination("fd00:ec2::254", policy="refuse") == "fd00:ec2::254"
    with pytest.raises(ValueError, match=ENV):
        device_posture.validate_device_destination("10.0.0.9", policy="refuse")


def test_metadata_stays_denied_without_the_flag_in_every_environment(monkeypatch):
    monkeypatch.delenv("SHAKERSCAN_DEVICE_ALLOW_METADATA_TARGETS", raising=False)
    monkeypatch.setenv(ENV, "allow")
    for environment in ("production", "lab"):
        with pytest.raises(ValueError, match="metadata"):
            device_posture.validate_device_destination("169.254.169.254", environment=environment)


def test_service_probe_refuses_private_destination_before_any_traffic(monkeypatch):
    from scanner_tools import device_probe

    monkeypatch.delenv(ENV, raising=False)
    calls: list[str] = []

    async def fake_resolve(_locator, **_kwargs):
        return "10.0.0.9"

    async def forbidden_health(*_args, **_kwargs):
        calls.append("health")
        return {"status": "healthy"}

    async def forbidden_run(*_args, **_kwargs):
        calls.append("nmap")
        return "", "", 0

    monkeypatch.setattr(device_probe, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_probe, "check_device_health", forbidden_health)
    monkeypatch.setattr(device_probe, "run", forbidden_run)
    with pytest.raises(ValueError, match=ENV):
        asyncio.run(device_probe.run_device_service_probe("device.test", {
            "probe_transport": "tcp", "probe_port": 8443, "expected_state": "open",
            "safety_profile": "safe_remote", "confirm_authorized": True,
            "device_environment": "production", "private_network_targets": "refuse",
        }))
    assert calls == []


def test_posture_scan_refuses_private_destination_before_any_stage(monkeypatch):
    """The web-DAST children of a device scan are gated by this parent check."""
    monkeypatch.delenv(ENV, raising=False)
    calls: list[str] = []

    async def fake_resolve(_locator, **_kwargs):
        return "172.26.0.2"

    async def forbidden(*_args, **_kwargs):
        calls.append("stage")
        raise AssertionError("no device stage may run against a refused destination")

    monkeypatch.setattr(device_posture, "resolve_device_address", fake_resolve)
    for name in ("check_device_health", "probe_device_reachability", "_nmap_scan",
                 "discover_core_device_protocols", "detect_web_origins"):
        monkeypatch.setattr(device_posture, name, forbidden)
    with pytest.raises(ValueError, match=ENV):
        asyncio.run(device_posture.run_device_posture_scan("tv.test", {
            "device_profile": "inventory", "safety_profile": "safe_remote",
            "confirm_authorized": True, "include_web_dast": True,
            "device_environment": "production", "private_network_targets": "refuse",
            "device_policy": {"name": "test", "rules": []},
        }))
    assert calls == []


def test_resolution_prefers_an_admitted_address(monkeypatch):
    class FakeLoop:
        async def getaddrinfo(self, *_args, **_kwargs):
            return [(2, 1, 6, "", ("10.0.0.1", 0)), (2, 1, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(device_posture.asyncio, "get_running_loop", lambda: FakeLoop())
    admit = lambda address: not address.startswith("10.")  # noqa: E731
    assert asyncio.run(device_posture.resolve_device_address("tv.example", admit=admit)) == "93.184.216.34"
    # Nothing admitted: keep the usual pick so validation names the refusal explicitly.
    assert asyncio.run(device_posture.resolve_device_address("tv.example", admit=lambda _a: False)) == "10.0.0.1"


@pytest.mark.parametrize("function", ["scan_device", "verify_device_service"])
def test_device_submissions_admit_the_destination_before_queueing(function):
    source = definition_source(function)
    assert "_admit_device_destination(" in source
    assert source.index("_admit_device_destination(") < source.index("INSERT INTO scans")
    assert '"device_environment"' in source
    assert '"private_network_targets"' in source


@pytest.mark.parametrize("compose", ["docker-compose.yml", "docker-compose.release.yml"])
def test_device_worker_receives_the_private_network_setting(compose):
    services = yaml.safe_load((ROOT / compose).read_text())["services"]
    for name in ("api", "worker", "device-worker"):
        environment = services[name]["environment"]
        assert any(str(item).startswith(f"{ENV}=") for item in environment), (compose, name)
