"""APT mirror/index races retry the same package set, never omit dependencies."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scanner/apt_install.sh"
PACKAGES = ["libexpat1", "libexpat1-dev", "nmap"]


def run_install(tmp_path, *, updates=(0,), installs=(0,), packages=PACKAGES):
    """Only stub executables run: no host apt, sleep or filesystem deletion."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    trace = tmp_path / "trace.jsonl"
    state = tmp_path / "counts.json"
    for name in ("apt-get", "rm", "sleep"):
        path = bindir / name
        path.write_text(f"#!{sys.executable} -S\n" + '''
import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
with open(os.environ["TRACE"], "a") as out:
    out.write(json.dumps([name, *sys.argv[1:]]) + "\\n")
if name == "apt-get":
    kind = "update" if "update" in sys.argv else "install"
    path = Path(os.environ["COUNTS"])
    counts = json.loads(path.read_text()) if path.exists() else {}
    i = counts.get(kind, 0)
    counts[kind] = i + 1
    path.write_text(json.dumps(counts))
    codes = json.loads(os.environ[kind.upper()])
    sys.exit(codes[min(i, len(codes) - 1)])
''')
        path.chmod(0o755)
    env = {**os.environ, "PATH": str(bindir), "TRACE": str(trace), "COUNTS": str(state),
           "UPDATE": json.dumps(updates), "INSTALL": json.dumps(installs)}
    result = subprocess.run(["/bin/sh", str(SCRIPT), *packages], env=env,
                            capture_output=True, text=True, timeout=10)
    calls = [json.loads(row) for row in trace.read_text().splitlines()] if trace.exists() else []
    return result, calls


def apt_calls(calls, kind):
    return [row for row in calls if row[0] == "apt-get" and kind in row]


def test_success_cleans_indexes_and_installs_every_requested_package(tmp_path):
    result, calls = run_install(tmp_path)
    assert result.returncode == 0
    assert len(apt_calls(calls, "update")) == len(apt_calls(calls, "install")) == 1
    assert apt_calls(calls, "install")[0][-len(PACKAGES):] == PACKAGES
    assert calls[0][0] == calls[-1][0] == "rm"
    assert not any(row[0] == "sleep" for row in calls)


def test_mirror_404_refreshes_indexes_before_retrying_the_identical_package_set(tmp_path):
    result, calls = run_install(tmp_path, installs=(100, 0))
    assert result.returncode == 0
    assert [row[0] for row in calls] == ["rm", "apt-get", "apt-get", "sleep", "rm", "apt-get", "apt-get", "rm"]
    first, second = apt_calls(calls, "install")
    assert first == second
    assert first[-len(PACKAGES):] == PACKAGES
    for row in apt_calls(calls, "update"):
        assert "APT::Update::Error-Mode=any" in row
        assert "Acquire::http::No-Cache=true" in row
        assert "Acquire::https::No-Cache=true" in row


def test_failed_update_does_not_install_from_stale_indexes(tmp_path):
    result, calls = run_install(tmp_path, updates=(100, 0))
    assert result.returncode == 0
    assert len(apt_calls(calls, "update")) == 2
    assert len(apt_calls(calls, "install")) == 1
    assert [row[0] for row in calls[:4]] == ["rm", "apt-get", "sleep", "rm"]


@pytest.mark.parametrize("failure", ["update", "install"])
def test_persistent_failure_is_bounded_and_propagated(tmp_path, failure):
    kwargs = {"updates" if failure == "update" else "installs": (100,)}
    result, calls = run_install(tmp_path, **kwargs)
    assert result.returncode == 100
    assert len(apt_calls(calls, "update")) == 3
    assert len(apt_calls(calls, "install")) == (0 if failure == "update" else 3)
    assert [row[1:] for row in calls if row[0] == "sleep"] == [["5"], ["10"]]
    assert "failed after 3 refreshed attempts" in result.stderr


def test_no_packages_is_an_error_before_any_commands(tmp_path):
    result, calls = run_install(tmp_path, packages=[])
    assert result.returncode == 2
    assert calls == []


def test_both_build_stages_use_helper_without_weakening_apt_verification():
    dockerfile = (ROOT / "scanner/Dockerfile").read_text()
    assert dockerfile.count("sh /tmp/apt_install.sh") == 2
    assert dockerfile.count("source=scanner/apt_install.sh,target=/tmp/apt_install.sh,ro") == 2
    api = (ROOT / "scanner/Dockerfile.api").read_text()
    assert "COPY scanner/apt_install.sh /opt/build-inputs/apt_install.sh" in dockerfile
    assert "COPY --from=scanner-runtime /opt/build-inputs/apt_install.sh /opt/build-inputs/apt_install.sh" in api
    commands = "\n".join(row for row in SCRIPT.read_text().splitlines() if not row.lstrip().startswith("#"))
    for bypass in ("--fix-missing", "--allow-unauthenticated", "AllowInsecureRepositories", "|| true"):
        assert bypass not in commands
    for required in ("nmap", "hydra", "medusa", "nikto", "libpcap-dev", "libssl-dev", "bsdmainutils"):
        assert required in dockerfile
