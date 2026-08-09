import json
import os
import sys
from pathlib import Path

import pytest


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
import release_identity  # noqa: E402
sys.path.pop(0)


def _manifest(tmp_path: Path, *, version: str = "0.8.17", revision: str = "a" * 40) -> Path:
    path = tmp_path / "release.json"
    path.write_text(json.dumps({"version": version, "source_revision": revision}), encoding="utf-8")
    return path


def test_baked_release_identity_wins_over_mutable_runtime_environment(tmp_path, monkeypatch):
    path = _manifest(tmp_path)
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(path))
    monkeypatch.setenv("SCANNER_VERSION", "dev")
    monkeypatch.setenv("GIT_COMMIT", "wrong")

    identity = release_identity.load_release_identity()

    assert identity.version == "0.8.17"
    assert identity.source_revision == "a" * 40
    assert release_identity.published_scanner_version("also-wrong") == "0.8.17"


def test_release_identity_mismatch_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(_manifest(tmp_path)))

    with pytest.raises(RuntimeError, match="release identity mismatch"):
        release_identity.verify_runtime_identity(expected_version="0.8.16")
    with pytest.raises(RuntimeError, match="release revision mismatch"):
        release_identity.verify_runtime_identity(expected_revision="b" * 40)


def test_release_fingerprint_binds_version_and_revision(tmp_path, monkeypatch):
    first = _manifest(tmp_path, revision="a" * 40)
    monkeypatch.setenv("SHAKERSCAN_RELEASE_MANIFEST", str(first))
    fingerprint_a = release_identity.build_fingerprint("source")

    first.write_text(json.dumps({"version": "0.8.17", "source_revision": "b" * 40}))
    fingerprint_b = release_identity.build_fingerprint("source")

    assert fingerprint_a != fingerprint_b
    assert len(fingerprint_a or "") == 64


def test_development_commit_label_does_not_turn_local_image_into_release(tmp_path, monkeypatch):
    monkeypatch.setenv(
        "SHAKERSCAN_RELEASE_MANIFEST",
        str(_manifest(tmp_path, version="abc1234", revision="abc1234")),
    )

    assert release_identity.load_release_identity().is_release is False
    assert release_identity.build_fingerprint("source") == "source"
