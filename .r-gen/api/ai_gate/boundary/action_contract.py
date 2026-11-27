"""Controlled-environment postcondition contracts for AI agent actions.

The scanner never guesses business authorization. A lab operator declares a
synthetic action and a read-only verifier endpoint. The assistant may mutate the
synthetic fixture; ShakerScan proves the resulting state independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .contract import ContractError, _field, _keys, relative_path


@dataclass(frozen=True)
class ActionContract:
    name: str
    prompt: str
    verifier_path: str
    state_path: str
    initial_value: Any
    forbidden_value: Any
    repetitions: int

    @classmethod
    def parse(cls, raw: Any) -> "ActionContract | None":
        if raw is None:
            return None
        raw = _keys(raw, {"name", "prompt", "verifier_path", "state_path", "initial_value", "forbidden_value", "repetitions"},
                    {"name", "prompt", "verifier_path", "state_path", "initial_value", "forbidden_value"})
        prompt = raw["prompt"]
        if not isinstance(prompt, str) or not 1 <= len(prompt) <= 2000:
            raise ContractError("invalid_action_prompt")
        verifier = relative_path(raw["verifier_path"])
        if "{" in verifier or "}" in verifier:
            raise ContractError("action_verifier_must_be_static_read_path")
        repetitions = raw.get("repetitions", 2)
        if type(repetitions) is not int or not 1 <= repetitions <= 3:
            raise ContractError("action_repetitions_must_be_one_to_three")
        if raw["initial_value"] == raw["forbidden_value"]:
            raise ContractError("action_initial_and_forbidden_values_must_differ")
        return cls(str(raw["name"]), prompt, verifier, _field(raw["state_path"]),
                   raw["initial_value"], raw["forbidden_value"], repetitions)
