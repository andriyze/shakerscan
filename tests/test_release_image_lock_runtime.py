"""scanner.sh honors the installer's release image lock and names all five images.

The hosted installer records the five certified image digests in release-image-lock.env. Only the
generated launcher used to read it; `./scanner.sh start` run directly in an install directory
that also held a source tree (the installer run over a checkout) resolved local-build mode and
rebuilt the 5.7 GB scanner image from source. The Model Intake image was also never derived from
the selected tag, so a 2.1.0 selection could run four 2.1.0 images beside
shakerscan-model-intake:latest. These tests run the real configure_runtime_mode.
"""

from __future__ import annotations

import os
import pathlib
import shlex
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text(encoding="utf-8")
DIGEST = "sha256:" + "ab" * 32


def _fn(name: str) -> str:
    return SCRIPT.split(f"{name}() {{", 1)[1].split("\n}", 1)[0]


def _resolve(runtime: pathlib.Path, *, lock: str | None = None, source_tree: bool = False,
             explicit_local: bool = False, env: dict[str, str] | None = None,
             image_tag_override: str = "", command: str = "start") -> tuple[int, str, str]:
    runtime.mkdir(parents=True, exist_ok=True)
    (runtime / "docker-compose.release.yml").touch()
    if source_tree:
        for relative in ("docker-compose.yml", "scanner/Dockerfile", "scanner/Dockerfile.api", "ui/Dockerfile"):
            path = runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
    if lock is not None:
        (runtime / "release-image-lock.env").write_text(lock)
    harness = f"""
set -eu
SCRIPT_DIR={shlex.quote(str(runtime))}
LOCAL_BUILD_MARKER="$SCRIPT_DIR/.shakerscan-local-build"
PREBUILT_COMPOSE_FILE=docker-compose.release.yml
DEFAULT_PREBUILT_IMAGE_TAG=latest
IMAGE_TAG_OVERRIDE={shlex.quote(image_tag_override)}
RUNTIME_MODE_EXPLICIT={1 if explicit_local else 0}
USE_PREBUILT={0 if explicit_local else 1}
is_truthy() {{ case "${{1:-}}" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }}
get_release_version() {{ printf '2.2.0\\n'; }}
update_compose_file_args() {{
  if [ "$USE_PREBUILT" -eq 1 ]; then COMPOSE_FILE_ARGS="docker-compose.release.yml"; else COMPOSE_FILE_ARGS="docker-compose.yml"; fi
}}
has_local_source_tree() {{
{_fn("has_local_source_tree")}
}}
configure_runtime_mode() {{
{_fn("configure_runtime_mode")}
}}
configure_runtime_mode {command}
printf 'MODE=%s|%s\\n' "$USE_PREBUILT" "$COMPOSE_FILE_ARGS"
for key in SCANNER_IMAGE API_IMAGE UI_IMAGE SIGNER_IMAGE MODEL_INTAKE_IMAGE; do
  printf '%s=%s\\n' "$key" "${{!key:-}}"
done
"""
    result = subprocess.run(
        ["bash", "-c", harness], cwd=ROOT, capture_output=True, text=True, timeout=10, check=False,
        env={"PATH": os.environ["PATH"], **(env or {})},
    )
    return result.returncode, result.stdout, result.stderr


def _values(stdout: str) -> dict[str, str]:
    values = {}
    for line in stdout.strip().splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    return values


LOCK = "".join(
    f"{key}={repo}@{DIGEST}\n" for key, repo in (
        ("SCANNER_IMAGE", "shakerscan/shakerscan-scanner"),
        ("API_IMAGE", "shakerscan/shakerscan-api"),
        ("UI_IMAGE", "shakerscan/shakerscan-ui"),
        ("SIGNER_IMAGE", "shakerscan/shakerscan-model-intake-signer"),
        ("MODEL_INTAKE_IMAGE", "shakerscan/shakerscan-model-intake"),
    )
) + "RUNTIME_MANIFEST_SHA256=" + "0" * 64 + "\n"


def test_the_fifth_image_is_derived_from_the_selected_tag(tmp_path):
    rc, out, err = _resolve(tmp_path / "curl")
    assert rc == 0, err
    values = _values(out)
    assert values["MODE"] == "1|docker-compose.release.yml"
    assert values["SCANNER_IMAGE"] == "shakerscan/shakerscan-scanner:2.2.0"
    assert values["SIGNER_IMAGE"] == "shakerscan/shakerscan-model-intake-signer:2.2.0"
    # The Model Intake image follows the same tag as the other four; it is never left on :latest.
    assert values["MODEL_INTAKE_IMAGE"] == "shakerscan/shakerscan-model-intake:2.2.0"


def test_a_release_image_lock_wins_over_a_source_tree_and_exports_five_digests(tmp_path):
    # An installer run over a checkout: source tree present, no marker, lock present.
    rc, out, err = _resolve(tmp_path / "checkout", lock=LOCK, source_tree=True)
    assert rc == 0, err
    values = _values(out)
    assert values["MODE"] == "1|docker-compose.release.yml"
    assert "release image lock is present" in err
    for key, repo in (
        ("SCANNER_IMAGE", "shakerscan-scanner"), ("API_IMAGE", "shakerscan-api"),
        ("UI_IMAGE", "shakerscan-ui"), ("SIGNER_IMAGE", "shakerscan-model-intake-signer"),
        ("MODEL_INTAKE_IMAGE", "shakerscan-model-intake"),
    ):
        assert values[key] == f"shakerscan/{repo}@{DIGEST}", key


def test_without_a_lock_a_source_tree_still_builds_locally(tmp_path):
    rc, out, err = _resolve(tmp_path / "checkout", source_tree=True)
    assert rc == 0, err
    assert _values(out)["MODE"] == "0|docker-compose.yml"


def test_an_explicit_local_choice_beats_the_lock(tmp_path):
    rc, out, err = _resolve(tmp_path / "checkout", lock=LOCK, source_tree=True, explicit_local=True)
    assert rc == 0, err
    values = _values(out)
    assert values["MODE"] == "0|docker-compose.yml"
    assert "@sha256:" not in values["SCANNER_IMAGE"]


def test_the_lock_can_be_disabled_and_an_image_tag_override_skips_its_digests(tmp_path):
    rc, out, err = _resolve(tmp_path / "a", lock=LOCK, source_tree=True,
                            env={"SHAKERSCAN_DISABLE_IMAGE_LOCK": "1"})
    assert rc == 0, err
    assert _values(out)["MODE"] == "0|docker-compose.yml"
    rc, out, err = _resolve(tmp_path / "b", lock=LOCK, image_tag_override="latest")
    assert rc == 0, err
    values = _values(out)
    assert values["MODE"] == "1|docker-compose.release.yml"
    assert values["MODEL_INTAKE_IMAGE"] == "shakerscan/shakerscan-model-intake:latest"


def test_a_malformed_lock_fails_closed(tmp_path):
    rc, out, err = _resolve(tmp_path / "bad", lock="SCANNER_IMAGE=shakerscan/shakerscan-scanner:latest\n")
    assert rc != 0
    assert "invalid release image lock entry for SCANNER_IMAGE" in err
    rc, out, err = _resolve(tmp_path / "bad2", lock=LOCK + "EXTRA_KEY=1\n")
    assert rc != 0
    assert "unsupported release image lock key: EXTRA_KEY" in err


def test_pull_and_cache_fallback_cover_all_five_images():
    pull = _fn("pull_prebuilt_images")
    assert "compose pull api worker ui model-intake-signer model-intake-worker model-intake-sandbox" in pull
    for key in ("API_IMAGE", "SCANNER_IMAGE", "UI_IMAGE", "SIGNER_IMAGE", "MODEL_INTAKE_IMAGE"):
        assert f'"${{{key}:-' in pull, key


def test_lifecycle_paths_include_the_model_intake_worker():
    start = _fn("start_services")
    assert 'verify_specialized_worker_identity' in start
    assert '"$(running_compose_service_count model-intake-worker)"' in start
    rebuild = _fn("rebuild_images")
    assert 'refresh_running_service_after_rebuild model-intake-worker "$existing_model_intake_worker"' in rebuild
    reload = _fn("reload_services")
    assert "compose restart model-intake-worker" in reload
    verify = _fn("verify_specialized_worker_identity")
    assert ".model_intake_worker.status" in verify
