"""APT mirror/index races retry the same package set, never omit dependencies."""
import json
import os
import shlex
import shutil
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scanner/apt_install.sh"
PACKAGES = ["libexpat1", "libexpat1-dev", "nmap"]


def run_install(tmp_path, *, updates=(0,), installs=(0,), packages=PACKAGES, sources=None):
    """Only stub executables run: no host apt, sleep or filesystem deletion."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    # Redirect only the production call's filesystem root to fixtures. Execute the
    # same transformation code with real sed, never edit host APT configuration.
    etc = tmp_path / "apt"
    (etc / "sources.list.d").mkdir(parents=True)
    for relative, value in (sources or {}).items():
        path = etc / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(value, Path):
            path.symlink_to(value)
        else:
            path.write_text(value)
    production = SCRIPT.read_text()
    entry = "upgrade_ubuntu_sources /etc/apt\n"
    assert production.count(entry) == 1
    script = tmp_path / "apt_install.sh"
    script.write_text(production.replace(entry, f"upgrade_ubuntu_sources {shlex.quote(str(etc))}\n"))
    (bindir / "sed").symlink_to(shutil.which("sed"))
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
    result = subprocess.run(["/bin/sh", str(script), *packages], env=env,
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
    for bypass in ("--fix-missing", "--allow-unauthenticated", "AllowInsecureRepositories", "Verify-Peer=false", "Verify-Host=false", "|| true"):
        assert bypass not in commands
    for required in ("nmap", "hydra", "medusa", "nikto", "libpcap-dev", "libssl-dev", "bsdmainutils"):
        assert required in dockerfile


@pytest.mark.parametrize("relative", ["sources.list", "sources.list.d/ubuntu.list", "sources.list.d/ubuntu.sources"])
def test_official_ubuntu_sources_use_https_without_changing_repository_identity(tmp_path, relative):
    before = (
        "Types: deb\n"
        "URIs: http://archive.ubuntu.com/ubuntu/ http://security.ubuntu.com/ubuntu\n"
        "Suites: noble noble-updates noble-security\nComponents: main universe\n"
        "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n"
        "deb http://ports.ubuntu.com/ubuntu-ports/ noble main\n"
    )
    result, calls = run_install(tmp_path, sources={relative: before})
    assert result.returncode == 0
    after = (tmp_path / "apt" / relative).read_text()
    assert after == before.replace("http://", "https://")
    assert len(apt_calls(calls, "install")) == 1


def test_other_sources_and_existing_tls_are_unchanged(tmp_path):
    before = (
        "deb http://deb.debian.org/debian bookworm main\n"
        "deb https://archive.ubuntu.com/ubuntu noble main\n"
        "deb http://mirror.example.test/ubuntu noble main\n"
        "deb http://archive.ubuntu.com.example.test/ubuntu noble main\n"
        "deb http://archive.ubuntu.com/ubuntu-custom noble main\n"
    )
    result, _ = run_install(tmp_path, sources={"sources.list": before})
    assert result.returncode == 0
    assert (tmp_path / "apt/sources.list").read_text() == before


def test_source_symlink_target_is_not_modified(tmp_path):
    outside = tmp_path / "local-repository.list"
    before = "deb http://archive.ubuntu.com/ubuntu noble main\n"
    outside.write_text(before)
    result, _ = run_install(tmp_path, sources={"sources.list.d/local.list": outside})
    assert result.returncode == 0
    assert (tmp_path / "apt/sources.list.d/local.list").is_symlink()
    assert outside.read_text() == before


@pytest.mark.parametrize("image, expected", [
    ("Dockerfile.api", ["ca-certificates", "curl", "jq"]),
    ("Dockerfile.model-intake", [
        "make", "gcc", "libcurl4-openssl-dev", "libssl-dev", "python3-dev",
        "python3-venv", "python3-pip-whl", "python3-setuptools-whl",
    ]),
])
@pytest.mark.parametrize("updates, status", [((100, 0), 0), ((100,), 100)])
def test_overlay_installs_recover_from_index_mismatch_without_omitting_packages(
    tmp_path, image, expected, updates, status,
):
    """Exercise the package argv actually wired into each independent image build.

    Exit 100 covers the signed-index size/hash mismatch seen in Model Intake CI.
    No install may run until update succeeds; a persistent mismatch must fail.
    """
    dockerfile = (ROOT / "scanner" / image).read_text().replace("\\\n", " ")
    mount = "source=scanner/apt_install.sh,target=/tmp/apt_install.sh,ro"
    assert dockerfile.count(mount) == 1
    assert "apt-get update" not in dockerfile
    command = next(line for line in dockerfile.splitlines()
                   if "sh /tmp/apt_install.sh " in line)
    packages = shlex.split(command.split("sh /tmp/apt_install.sh ", 1)[1].split(";", 1)[0])
    assert packages == expected
    result, calls = run_install(tmp_path, packages=packages, updates=updates)
    assert result.returncode == status
    assert len(apt_calls(calls, "update")) == (2 if status == 0 else 3)
    installs = apt_calls(calls, "install")
    assert len(installs) == (1 if status == 0 else 0)
    if installs:
        assert installs[0][-len(expected):] == expected
