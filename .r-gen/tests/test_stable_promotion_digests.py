"""Execute stable promotion against a fake registry; never call Docker or a network."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "SCANNER_IMAGE": "shakerscan/shakerscan-scanner",
    "API_IMAGE": "shakerscan/shakerscan-api",
    "UI_IMAGE": "shakerscan/shakerscan-ui",
    "SIGNER_IMAGE": "shakerscan/shakerscan-model-intake-signer",
    "MODEL_INTAKE_IMAGE": "shakerscan/shakerscan-model-intake",
}
VERSION = "2.7.0"


def _run_promotion(tmp_path: Path, *, changed_image: str | None = None,
                   missing: bool = False, late_drift: bool = False):
    workflow = yaml.safe_load((ROOT / ".github/workflows/promote-stable.yml").read_text())
    step = next(item for item in workflow["jobs"]["stable"]["steps"]
                if item.get("name") == "Move latest aliases without rebuilding")
    digests = {image: "sha256:" + f"{index:064x}"
               for index, image in enumerate(IMAGES.values(), start=1)}
    state = {f"{image}:{VERSION}": digest for image, digest in digests.items()}
    if changed_image:
        if missing:
            del state[f"{changed_image}:{VERSION}"]
        else:
            state[f"{changed_image}:{VERSION}"] = "sha256:" + "f" * 64
    (tmp_path / "registry.json").write_text(json.dumps(state))
    (tmp_path / "release-image-lock.env").write_text("".join(
        f"{variable}={image}@{digests[image]}\n" for variable, image in IMAGES.items()
    ))
    fake = tmp_path / "docker"
    fake.write_text(f"#!{sys.executable}\n" + '''
import json, os, pathlib, sys
root = pathlib.Path(os.environ["FAKE_REGISTRY_ROOT"])
args = sys.argv[1:]
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps(args) + "\\n")
state_path = root / "registry.json"
state = json.loads(state_path.read_text())
if args[:3] == ["buildx", "imagetools", "inspect"] and len(args) == 4:
    if args[3] not in state:
        raise SystemExit(1)
    print("Digest: " + state[args[3]])
elif args[:4] == ["buildx", "imagetools", "create", "-t"] and len(args) == 6:
    if os.environ.get("FAKE_LATE_DRIFT") == "1":
        state.update({key: "sha256:" + "f" * 64 for key in state if key.endswith(":2.7.0")})
    image, separator, digest = args[5].partition("@")
    assert separator and args[4] == image + ":latest"
    state[args[4]] = digest
    state_path.write_text(json.dumps(state))
else:
    raise SystemExit(2)
''')
    fake.chmod(0o755)
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", step["run"]], cwd=tmp_path,
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "VERSION": VERSION,
             "FAKE_REGISTRY_ROOT": str(tmp_path), "FAKE_LATE_DRIFT": "1" if late_drift else ""},
        capture_output=True, text=True, timeout=10,
    )
    commands = [json.loads(line) for line in (tmp_path / "commands.jsonl").read_text().splitlines()]
    return result, commands, json.loads((tmp_path / "registry.json").read_text()), digests


@pytest.mark.parametrize("changed_image", list(IMAGES.values()))
@pytest.mark.parametrize("missing", [False, True])
def test_stable_promotion_rejects_any_missing_or_drifted_tag_before_writing_aliases(
    tmp_path, changed_image, missing,
):
    result, commands, state, _digests = _run_promotion(
        tmp_path, changed_image=changed_image, missing=missing,
    )
    assert result.returncode != 0
    assert not any(command[2] == "create" for command in commands)
    assert not any(reference.endswith(":latest") for reference in state)


@pytest.mark.parametrize("late_drift", [False, True])
def test_stable_promotion_checks_all_tags_then_uses_only_accepted_digest_references(tmp_path, late_drift):
    result, commands, state, digests = _run_promotion(tmp_path, late_drift=late_drift)
    assert result.returncode == 0, result.stderr
    first_create = next(index for index, command in enumerate(commands) if command[2] == "create")
    assert {command[3] for command in commands[:first_create]} == {
        f"{image}:{VERSION}" for image in IMAGES.values()
    }
    assert [command[5] for command in commands if command[2] == "create"] == [
        f"{image}@{digests[image]}" for image in IMAGES.values()
    ]
    assert all(state[f"{image}:latest"] == digest for image, digest in digests.items())
