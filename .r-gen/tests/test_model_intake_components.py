from pathlib import Path
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from model_intake_components import component_identities  # noqa: E402


def test_component_identities_are_order_independent_and_separate_tokenizer_from_configuration():
    files = [
        {"path": "config.json", "sha256": "a" * 64},
        {"path": "tokenizer.json", "sha256": "b" * 64},
        {"path": "nested/runtime.yaml", "sha256": "c" * 64},
        {"path": "model.safetensors", "sha256": "d" * 64},
    ]

    first = component_identities(files)
    second = component_identities(list(reversed(files)))

    assert first == second
    assert first["tokenizer_file_count"] == 1
    assert first["configuration_file_count"] == 2
    assert len(first["tokenizer_sha256"]) == 64
    assert len(first["configuration_sha256"]) == 64


def test_component_identities_fail_closed_on_duplicate_or_invalid_members():
    with pytest.raises(ValueError, match="unsafe or duplicated"):
        component_identities([
            {"path": "config.json", "sha256": "a" * 64},
            {"path": "config.json", "sha256": "a" * 64},
        ])
    with pytest.raises(ValueError, match="digest is invalid"):
        component_identities([{"path": "config.json", "sha256": "caller-label"}])
