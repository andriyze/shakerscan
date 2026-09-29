"""A settings value can never add a line to the host environment file."""

from __future__ import annotations

import pytest

from settings_routes import router as settings_router


@pytest.mark.parametrize(
    "separator",
    ["\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " ", "\x00"],
)
def test_line_separator_in_value_cannot_plant_an_extra_key(tmp_path, separator):
    env_path = tmp_path / ".env"
    env_path.write_text("SHAKERSCAN_BIND_HOST=127.0.0.1\n")

    ok, message = settings_router._persist_env_updates(
        env_path, {"AI_MODEL": f"gpt{separator}SHAKERSCAN_BIND_HOST=0.0.0.0"},
    )

    assert ok is False
    assert "control" in message
    assert env_path.read_text() == "SHAKERSCAN_BIND_HOST=127.0.0.1\n"


def test_newline_is_still_escaped_and_ordinary_values_persist(tmp_path):
    env_path = tmp_path / ".env"

    ok, _ = settings_router._persist_env_updates(
        env_path, {"AI_MODEL": "model-a\nX=1", "AI_MASK_HOST": "mask.example.test"},
    )

    assert ok is True
    assert env_path.read_text().splitlines() == ["AI_MODEL=model-a\\nX=1", "AI_MASK_HOST=mask.example.test"]
