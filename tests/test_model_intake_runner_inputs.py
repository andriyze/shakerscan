from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_runner_inputs import (  # noqa: E402
    MANDATORY_SMOKE_INPUTS,
    MAX_INPUT_BYTES,
    normalize_known_answer_inputs,
    suite_identity,
)


def test_mandatory_smoke_suite_is_stable_additive_and_content_bound():
    first = suite_identity(["operator case", "corporate security review"])
    second = suite_identity(["operator case", "corporate security review"])

    assert first == second
    assert first["suite_version"] == "model-intake-embedding-smoke/v1"
    assert first["input_count"] == len(MANDATORY_SMOKE_INPUTS) + 1
    assert first["inputs"][:len(MANDATORY_SMOKE_INPUTS)] == list(MANDATORY_SMOKE_INPUTS)
    assert len(first["inputs_sha256"]) == 64


def test_known_answer_suite_rejects_unbounded_or_invalid_inputs():
    with pytest.raises(ValueError, match="string array"):
        normalize_known_answer_inputs(["valid", 3])
    with pytest.raises(ValueError, match="per-item byte limit"):
        normalize_known_answer_inputs(["x" * (MAX_INPUT_BYTES + 1)])
    with pytest.raises(ValueError, match="suite limit"):
        normalize_known_answer_inputs([f"case-{index}" for index in range(100)])
