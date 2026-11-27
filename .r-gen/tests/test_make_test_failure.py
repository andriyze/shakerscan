"""A failing first test group must fail make, even if the next group would pass."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(not shutil.which("make"), reason="requires host make")
def test_make_test_preserves_first_group_failure(tmp_path):
    root = Path(__file__).resolve().parents[1]
    commands = tmp_path / "bin"
    commands.mkdir()
    docker = commands / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import os, subprocess, sys\n"
        "script = sys.argv[-1].replace('cd /workspace', 'cd ' + repr(os.environ['TEST_WORKSPACE']))\n"
        "sys.exit(subprocess.run(['/bin/sh', '-c', script], env=os.environ).returncode)\n"
    )
    python = commands / "python"
    python.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "-c" ]; then exit 0; fi\n'
        'if [ ! -f "$TEST_SENTINEL" ]; then\n'
        '  touch "$TEST_SENTINEL"\n'
        "  exit 17\n"
        "fi\nexit 0\n"
    )
    pytest_command = commands / "pytest"
    pytest_command.write_text("#!/bin/sh\nexit 0\n")
    for command in (docker, python, pytest_command):
        command.chmod(0o700)
    sentinel = tmp_path / "first-group-ran"
    completed = subprocess.run(
        ["make", "test"], cwd=root, capture_output=True, text=True,
        env={**os.environ, "PATH": f"{commands}:{os.environ['PATH']}",
             "TEST_SENTINEL": str(sentinel), "TEST_WORKSPACE": str(tmp_path)},
        timeout=10,
    )
    assert sentinel.exists(), completed.stderr
    assert completed.returncode != 0, "make hid a failed first test group"
