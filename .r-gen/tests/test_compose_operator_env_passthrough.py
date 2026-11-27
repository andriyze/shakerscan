"""Settings the operator docs tell people to put in .env reach the services that read them.

No service loads .env wholesale: a variable reaches a container only when its compose file lists it.
SHAKERSCAN_HEAVY_SCANNER_SLOTS, SHAKERSCAN_TRAFFIC_ATTRIBUTION and SHAKERSCAN_HUNT_IDLE_EXPIRY_HOURS
were documented while no compose file passed them, so setting them changed nothing.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "api": {"SHAKERSCAN_TRAFFIC_ATTRIBUTION", "SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN",
            "SHAKERSCAN_HUNT_IDLE_EXPIRY_HOURS", "SHAKERSCAN_HUNT_DEFAULT_CREDENTIALS"},
    "worker": {"SHAKERSCAN_TRAFFIC_ATTRIBUTION", "SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN",
               "SHAKERSCAN_HEAVY_SCANNER_SLOTS"},
    "agent-tool-worker": {"SHAKERSCAN_TRAFFIC_ATTRIBUTION", "SHAKERSCAN_TRAFFIC_USER_AGENT_TOKEN",
                          "SHAKERSCAN_HEAVY_SCANNER_SLOTS"},
}


def _names(environment) -> set[str]:
    if isinstance(environment, dict):
        return set(environment)
    return {str(item).split("=", 1)[0] for item in environment or ()}


@pytest.mark.parametrize("compose_file", ["docker-compose.yml", "docker-compose.release.yml"])
def test_documented_operator_settings_reach_their_services(compose_file):
    services = yaml.safe_load((ROOT / compose_file).read_text())["services"]
    for service, names in EXPECTED.items():
        missing = names - _names(services[service].get("environment"))
        assert not missing, f"{compose_file}: {service} does not receive {sorted(missing)}"
