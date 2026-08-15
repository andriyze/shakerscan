import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_probe  # noqa: E402


def _xml(state: str, *, port: int = 8443, transport: str = "tcp") -> str:
    return f"""<?xml version='1.0'?>
<nmaprun><host><ports><port protocol='{transport}' portid='{port}'>
<state state='{state}' reason='fixture'/><service name='https' product='fixture' version='1.0'><cpe>cpe:/a:test:fixture:1.0</cpe></service>
</port></ports></host><runstats><finished exit='success'/></runstats></nmaprun>"""


def test_single_port_parser_and_invariant_verdicts_are_fail_closed():
    observed = device_probe._parse_single_port(_xml("open"), transport="tcp", port=8443)
    assert observed["complete"] is True
    assert observed["state"] == "open"
    assert device_probe.evaluate_service_state("open", "open", complete=True)["verdict"] == "satisfied"
    assert device_probe.evaluate_service_state("open", "closed", complete=True)["verdict"] == "refuted"
    assert device_probe.evaluate_service_state("filtered", "closed", complete=False)["verdict"] == "inconclusive"


def test_missing_or_filtered_port_is_never_proof_of_absence():
    filtered = device_probe._parse_single_port(_xml("open|filtered"), transport="tcp", port=8443)
    assert filtered["complete"] is False
    assert device_probe.evaluate_service_state(filtered["state"], "closed", complete=False)["verdict"] == "inconclusive"
    missing = device_probe._parse_single_port("<nmaprun><runstats><finished exit='success'/></runstats></nmaprun>", transport="tcp", port=8443)
    assert missing["complete"] is False
    assert "requested_port_missing" in missing["incomplete_reasons"]


def test_probe_executes_one_pinned_target_and_one_fixed_port(monkeypatch):
    captured = {}

    async def fake_resolve(locator, **_kwargs):
        assert locator == "device.test"
        return "192.0.2.10"

    async def fake_health(_locator, *, stage, **_kwargs):
        return {"stage": stage, "status": "healthy"}

    async def fake_run(command, timeout):
        captured["command"] = command
        captured["timeout"] = timeout
        return _xml("closed"), "", 0

    monkeypatch.setattr(device_probe, "resolve_device_address", fake_resolve)
    monkeypatch.setattr(device_probe, "check_device_health", fake_health)
    monkeypatch.setattr(device_probe, "run", fake_run)
    result = asyncio.run(device_probe.run_device_service_probe("device.test", {
        "probe_transport": "tcp",
        "probe_port": 8443,
        "expected_state": "closed",
        "safety_profile": "safe_remote",
        "confirm_authorized": True,
        "include_web_dast": False,
    }))
    command = captured["command"]
    assert command[-1] == "192.0.2.10"
    assert command[command.index("-p") + 1] == "8443"
    assert "--max-rate" in command and command[command.index("--max-rate") + 1] == "5"
    assert result["device_probe"]["verification"]["verdict"] == "satisfied"
    assert result["findings"] == []


@pytest.mark.parametrize("field,value", [
    ("probe_transport", "sctp"),
    ("probe_port", 0),
    ("expected_state", "filtered"),
])
def test_probe_rejects_untyped_scope(field, value):
    options = {
        "probe_transport": "tcp",
        "probe_port": 22,
        "expected_state": "open",
        "safety_profile": "safe_remote",
        "confirm_authorized": True,
        "include_web_dast": False,
    }
    options[field] = value
    with pytest.raises(ValueError):
        asyncio.run(device_probe.run_device_service_probe("device.test", options))
