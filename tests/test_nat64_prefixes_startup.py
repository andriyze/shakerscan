"""``SHAKERSCAN_NAT64_PREFIXES`` is parsed once, at API and worker startup and in readiness.

A malformed value used to fail only when an IPv6 address was first classified, as an uncaught
``ValueError`` (a 500 from the API, a failed job in a worker). The API lifespan
(``tests/test_api_lifecycle.py``) and the worker entry point now refuse to start with an error
that names the setting, and ``/health`` reports it.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

import deployment_policy
from scanner_tools import address_classes

ENV = "SHAKERSCAN_NAT64_PREFIXES"
INVALID = {
    "garbage": "garbage",
    "not_ipv6": "10.0.0.0/8",
    "length_outside_rfc6052": "2001:db8::/80",
    "one_bad_entry_among_good": "64:ff9b::/96, 2001:db8::/33",
}


@pytest.mark.parametrize("value", INVALID.values(), ids=INVALID.keys())
def test_an_invalid_value_is_refused_naming_the_setting(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    with pytest.raises(ValueError, match=ENV):
        address_classes.validate_nat64_prefixes_setting()
    with pytest.raises(RuntimeError, match=f"refusing to start: {ENV}"):
        deployment_policy.require_valid_destination_settings()
    report = deployment_policy.health_report()["nat64_prefixes"]
    assert report["status"] == "error" and ENV in report["error"]


@pytest.mark.parametrize("value", ["", "2001:db8:64::/96", "2001:db8::/32, 2001:db8:100::/40"])
def test_a_valid_value_starts(monkeypatch, value):
    monkeypatch.setenv(ENV, value)
    deployment_policy.require_valid_destination_settings()
    report = deployment_policy.health_report()
    assert report["nat64_prefixes"]["status"] == "ok"
    assert report["nat64_prefixes"]["prefixes"] == [item.strip() for item in value.split(",") if item.strip()]
    assert report["private_network_targets"] in {"allow", "refuse"}


def test_the_worker_refuses_to_start_before_its_preflight(monkeypatch):
    import worker

    monkeypatch.setenv(ENV, "garbage")
    started: list[str] = []
    monkeypatch.setattr(worker, "run_worker_preflight", lambda: started.append("preflight"))
    monkeypatch.setattr(worker, "report_worker_build_fingerprint", lambda: started.append("report"))
    monkeypatch.setattr(worker, "async_main", lambda: started.append("main"))
    monkeypatch.setattr(worker.asyncio, "run", lambda _coroutine: started.append("loop"))
    with pytest.raises(RuntimeError, match=ENV):
        worker.main()
    assert started == []
    monkeypatch.setenv(ENV, "2001:db8:64::/96")
    worker.main()
    assert started == ["preflight", "report", "main", "loop"]


def test_the_broker_worker_refuses_to_start_before_any_lease(monkeypatch):
    import broker_worker

    monkeypatch.setenv(ENV, "garbage")
    monkeypatch.setattr(sys, "argv", ["broker_worker.py", "--once"])
    monkeypatch.setattr(broker_worker, "assert_outbound_only_runtime_environment", lambda: None)
    monkeypatch.setattr(broker_worker, "load_state", lambda _path: pytest.fail("state read before the check"))
    with pytest.raises(RuntimeError, match=ENV):
        broker_worker.main()


def test_the_gungnir_worker_refuses_to_start(monkeypatch):
    import gungnir_worker

    monkeypatch.setenv(ENV, "garbage")
    monkeypatch.setattr(gungnir_worker.asyncio, "run", lambda _coroutine: pytest.fail("started"))
    with pytest.raises(RuntimeError, match=ENV):
        gungnir_worker.main()
