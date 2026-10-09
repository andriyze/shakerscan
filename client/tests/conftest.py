"""The client package's tests keep the client's files out of the real home."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _hermetic_client_home(monkeypatch, tmp_path_factory):
    base = tmp_path_factory.mktemp("client-home")
    monkeypatch.setenv("SHAKERSCAN_CONFIG_DIR", str(base / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(base / "state"))
    monkeypatch.setenv("XDG_DATA_HOME", str(base / "data"))
