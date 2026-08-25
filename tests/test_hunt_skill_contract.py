from __future__ import annotations

import json
from pathlib import Path
import re
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

from hunt.start_contract import (  # noqa: E402
    HuntStartContractError,
    normalize_hunt_start_payload,
)


SKILL = ROOT / "skills" / "hunt" / "SKILL.md"


def _json_examples() -> list[dict]:
    source = SKILL.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", source, re.DOTALL)
    assert blocks, "Hunt skill must contain executable JSON examples"
    return [json.loads(block) for block in blocks]


def test_every_hunt_skill_json_example_satisfies_hunt_start_v2():
    contracts = [normalize_hunt_start_payload(item) for item in _json_examples()]
    assert {contract.target_kind for contract in contracts} == {
        "web", "api", "network", "device",
    }
    assert any(len(contract.credential_refs) == 2 for contract in contracts)
    assert any(contract.target_kind == "device" for contract in contracts)
    assert all(contract.schema_version == "hunt-start/v2" for contract in contracts)


@pytest.mark.parametrize(
    "secret_field",
    ["password", "token", "cookie", "authorization", "api_key", "private_key"],
)
def test_skill_examples_never_embed_secret_fields(secret_field: str):
    for example in _json_examples():
        serialized = json.dumps(example, sort_keys=True).lower()
        assert f'"{secret_field}"' not in serialized


def test_agent_scenario_payloads_fail_closed_on_hidden_authority_or_targets():
    passive = _json_examples()[0]
    for forbidden in (
        {"target_url": "https://unregistered.invalid"},
        {"password": "do-not-store"},
        {"tool": "curl"},
        {"argv": ["curl", "https://unregistered.invalid"]},
    ):
        with pytest.raises(HuntStartContractError, match="unsupported Hunt start"):
            normalize_hunt_start_payload({**passive, **forbidden})


def test_skill_does_not_claim_the_server_infers_authority_fields():
    source = SKILL.read_text(encoding="utf-8")
    assert "The server infers target kind, credentials" not in source
    for required in (
        '"target_kind"', '"policy"', '"budgets"', '"credential_refs"',
        '"capabilities"', '"request_collection_ids"',
    ):
        assert required in source

