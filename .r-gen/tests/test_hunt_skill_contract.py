from __future__ import annotations

import asyncio
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


from hunt.run_router import apply_standing_authorization  # noqa: E402


SKILL = ROOT / "skills" / "hunt" / "SKILL.md"


async def _authorized_target(target_id):
    assert target_id.startswith("registered-")
    return {"approval_receipt_id": "approval-from-server", "scope_receipt_id": "scope-from-server"}


def _public_contract(example):
    payload = asyncio.run(apply_standing_authorization(example, _authorized_target))
    return normalize_hunt_start_payload(payload)


def _json_examples() -> list[dict]:
    source = SKILL.read_text(encoding="utf-8")
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", source, re.DOTALL)
    assert blocks, "Hunt skill must contain executable JSON examples"
    return [json.loads(block) for block in blocks]


def test_every_hunt_skill_json_example_satisfies_hunt_start_v2():
    contracts = [_public_contract(item) for item in _json_examples()]
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



def test_public_examples_use_defaults_and_server_resolved_authorization():
    for example in _json_examples():
        assert example["budgets"] == {}
        assert "approval_receipt_id" not in example["policy"]
        contract = _public_contract(example)
        if example["policy"]["active_testing"]:
            assert contract.policy.approval_receipt_id == "approval-from-server"
            assert contract.policy.authorization_confirmed is True
            assert contract.resolved_budget["max_active_actions"] > 0
        else:
            assert contract.policy.approval_receipt_id is None
            assert contract.resolved_budget["max_active_actions"] == 0
            assert contract.resolved_budget["max_state_changing_requests"] == 0


def test_active_examples_without_authorization_are_not_silently_admitted():
    for example in _json_examples():
        if example["policy"]["active_testing"]:
            payload = asyncio.run(apply_standing_authorization(example, None))
            with pytest.raises(HuntStartContractError):
                normalize_hunt_start_payload(payload)


def test_hunt_guidance_distinguishes_consent_from_repeated_prompts_and_submission():
    source = SKILL.read_text()
    assert "Without standing authorization, obtain explicit target-specific operator authorization" in source
    assert "record it once" in source
    assert "submission-only request" in source and "end-to-end Hunt" in source
    assert "report its ID and stop. Do not poll" not in source
