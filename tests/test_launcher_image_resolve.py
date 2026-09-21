"""A freshly built image that is not yet queryable must not fail the build outright.

On Docker 29 with the containerd image store, `docker image inspect` on a tag that
`compose build` just printed as "Built" can come back empty for a moment; a clean source
build failed with "could not resolve the newly built worker image" although the image was
there a second later.
"""

import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE_ID = "sha256:" + "5" * 64


def _run_resolve(tmp_path: Path, *, fail_first: int, attempts: int) -> subprocess.CompletedProcess:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    counter = tmp_path / "calls"
    counter.write_text("0")
    (fake_bin / "docker").write_text(
        "#!/bin/sh\n"
        f"n=$(cat '{counter}'); n=$((n + 1)); echo $n > '{counter}'\n"
        f"if [ $n -le {fail_first} ]; then echo 'Error: No such image' >&2; exit 1; fi\n"
        f"echo '{IMAGE_ID}'\n"
    )
    (fake_bin / "docker").chmod(0o755)
    script = (
        'RED=""; NC="";'
        f'source <(sed -n "/^docker_cli()/,/^}}$/p" {ROOT}/scanner.sh); '
        f'source <(sed -n "/^resolve_built_image_id()/,/^}}$/p" {ROOT}/scanner.sh); '
        "resolve_built_image_id shakerscan-worker:local"
    )
    return subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}",
             "SHAKERSCAN_IMAGE_RESOLVE_ATTEMPTS": str(attempts)},
    )


def test_a_tag_that_appears_after_a_moment_is_resolved(tmp_path):
    result = _run_resolve(tmp_path, fail_first=2, attempts=5)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == IMAGE_ID


def test_a_tag_that_never_appears_fails_with_the_daemon_error(tmp_path):
    result = _run_resolve(tmp_path, fail_first=99, attempts=2)
    assert result.returncode == 1
    assert result.stdout.strip() == ""
    assert "not resolvable after 2 attempts" in result.stderr
    assert "No such image" in result.stderr


def test_resolve_goes_through_sudo_when_compose_had_to(tmp_path):
    """Right after install-deps the shell has not joined the docker group: Compose ran through
    sudo, but the plain inspect was refused at the socket and the build failed anyway."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "docker").write_text("#!/bin/sh\necho 'permission denied while trying to connect to the docker API' >&2; exit 1\n")
    (fake_bin / "sudo").write_text(f"#!/bin/sh\n[ \"$1\" = docker ] || exit 9; echo '{IMAGE_ID}'\n")
    for name in ("docker", "sudo"):
        (fake_bin / name).chmod(0o755)
    script = (
        'RED=""; NC=""; DOCKER_COMPOSE_CMD=(sudo docker compose); '
        f'source <(sed -n "/^docker_cli()/,/^}}$/p" {ROOT}/scanner.sh); '
        f'source <(sed -n "/^resolve_built_image_id()/,/^}}$/p" {ROOT}/scanner.sh); '
        "resolve_built_image_id shakerscan-worker:local"
    )
    result = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, cwd=ROOT,
        env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "SHAKERSCAN_IMAGE_RESOLVE_ATTEMPTS": "2"},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == IMAGE_ID
