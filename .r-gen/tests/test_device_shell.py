import os
import sys

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))

from scanner_tools import device_shell  # noqa: E402


def _plan():
    return device_shell.build_shell_plan(
        plan_id="11111111-1111-4111-8111-111111111111",
        run_id="22222222-2222-4222-8222-222222222222",
        device_target_id="33333333-3333-4333-8333-333333333333",
        target_locator="tv.lan",
        locator_generation=4,
        credential_profile_id="44444444-4444-4444-8444-444444444444",
        ssh_port=2222,
        expected_host_key_fingerprint="SHA256:fixture",
        commands=["id", "systemctl status tv-service"],
        timeout_seconds=20,
        purpose="Inspect the runtime",
        risk_summary="The second command queries the service manager.",
        created_at="2026-08-15T20:00:00+00:00",
        expires_at="2026-08-15T20:30:00+00:00",
    )


def test_shell_plan_is_immutable_and_risk_marked():
    plan = _plan()
    assert device_shell.validate_shell_plan(plan)["commands"] == ["id", "systemctl status tv-service"]
    assert plan["confirmation_phrase"].startswith("RUN ")
    assert "service-or-process-change" in plan["detected_risks"]
    changed = dict(plan)
    changed["commands"] = ["id", "reboot"]
    with pytest.raises(ValueError, match="digest mismatch"):
        device_shell.validate_shell_plan(changed)


def test_shell_plan_rejects_control_characters_and_unbounded_commands():
    with pytest.raises(ValueError, match="control"):
        device_shell.normalize_shell_commands(["id\x01"])
    with pytest.raises(ValueError, match="1-8"):
        device_shell.normalize_shell_commands([])
    with pytest.raises(ValueError, match="4096"):
        device_shell.normalize_shell_commands(["x" * 4097])
