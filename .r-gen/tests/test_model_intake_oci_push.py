import hashlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.model_intake_push_oci import layout_manifest, push_and_verify  # noqa: E402


def _layout(root: Path):
    bundle = "b" * 64
    manifest = {
        "schemaVersion": 2,
        "annotations": {"dev.shakerscan.deployment-bundle.sha256": bundle},
    }
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
    blob = root / "blobs" / "sha256" / digest.removeprefix("sha256:")
    blob.parent.mkdir(parents=True)
    blob.write_bytes(encoded)
    (root / "index.json").write_text(json.dumps({
        "manifests": [{
            "digest": digest,
            "annotations": {"org.opencontainers.image.ref.name": "admitted"},
        }],
    }))
    return digest, bundle


def test_layout_manifest_verifies_local_descriptor(tmp_path):
    expected = _layout(tmp_path)
    assert layout_manifest(tmp_path) == expected


def test_push_uses_fixed_oras_argv_and_requires_exact_remote_digest(tmp_path, monkeypatch):
    digest, bundle = _layout(tmp_path)
    calls = []

    class Completed:
        returncode = 0
        stderr = ""

        def __init__(self, stdout=""):
            self.stdout = stdout

    monkeypatch.setattr("scripts.model_intake_push_oci.shutil.which", lambda _value: "/usr/bin/oras")
    monkeypatch.setattr(
        "scripts.model_intake_push_oci.subprocess.run",
        lambda argv, **_kwargs: calls.append(argv) or Completed(json.dumps({"digest": digest}) if "fetch" in argv else ""),
    )
    receipt = push_and_verify(tmp_path, "registry.corp.example/models/code")
    assert calls[0][:3] == ["oras", "cp", "--from-oci-layout"]
    assert calls[1][:4] == ["oras", "manifest", "fetch", "--descriptor"]
    assert receipt["remote_reference"] == f"registry.corp.example/models/code@{digest}"
    assert receipt["deployment_bundle_sha256"] == bundle
    assert receipt["post_push_verified"] is True


@pytest.mark.parametrize("destination", ["localhost/models/x", "http://registry/models/x", "registry/x:tag", "../x"])
def test_push_rejects_unsafe_or_mutable_destination(tmp_path, destination):
    _layout(tmp_path)
    with pytest.raises(ValueError):
        push_and_verify(tmp_path, destination)
