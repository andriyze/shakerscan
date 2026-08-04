"""`status` must not report a completed install as missing."""

from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import model_intake_runner_cli as cli  # noqa: E402


def _facts(**overrides):
    facts = {
        "installed": {
            "firecracker": True, "jailer": True, "kernel": True,
            "rootfs": True, "runner_env": True,
        },
        "service_state": "active",
        "api_wired_to_runner": True,
    }
    facts.update(overrides)
    return facts


def test_an_unreadable_root_only_component_is_not_a_missing_one():
    # The runner env file is root-owned inside a root-only directory. Reporting
    # it absent for the ordinary user running status made a finished install
    # look like no install, and told the operator to run it again.
    installed = dict(_facts()["installed"], runner_env=None)

    assert cli.install_is_complete(_facts(installed=installed)) is True
    # The systemd unit alone corroborates it.
    assert cli.install_is_complete(
        _facts(installed=installed, api_wired_to_runner=False)
    ) is True
    # So does the API wiring alone.
    assert cli.install_is_complete(
        _facts(installed=installed, service_state="inactive")
    ) is True
    # With nothing readable agreeing, unknown stays unresolved rather than
    # claiming an install that may not exist.
    assert cli.install_is_complete(
        _facts(installed=installed, service_state="unknown", api_wired_to_runner=False)
    ) is False


def test_a_component_that_is_definitely_absent_still_fails():
    installed = dict(_facts()["installed"], rootfs=False)
    # A readable "no" is authoritative; corroboration must not override it.
    assert cli.install_is_complete(_facts(installed=installed)) is False


def test_api_wiring_is_read_from_the_runtime_env(tmp_path):
    assert cli._runtime_runner_url(tmp_path) is False

    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=x\nMODEL_INTAKE_RUNNER_URL=\n")
    assert cli._runtime_runner_url(tmp_path) is False

    (tmp_path / ".env").write_text("MODEL_INTAKE_RUNNER_URL=http://127.0.0.1:9099\n")
    assert cli._runtime_runner_url(tmp_path) is True


def test_dotenv_upsert_preserves_existing_runtime_owner_and_mode(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("POSTGRES_PASSWORD=x\n")
    env_path.chmod(0o640)
    before = env_path.stat()

    cli._write_dotenv(env_path, {"MODEL_INTAKE_RUNNER_URL": "http://127.0.0.1:8092"})

    after = env_path.stat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert stat.S_IMODE(after.st_mode) == 0o640
    assert cli._runtime_runner_url(tmp_path) is True


def test_dotenv_upsert_rejects_symlink_targets(tmp_path):
    target = tmp_path / "target.env"
    target.write_text("SAFE=1\n")
    link = tmp_path / ".env"
    link.symlink_to(target)

    try:
        cli._write_dotenv(link, {"MODEL_INTAKE_RUNNER_URL": "http://127.0.0.1:8092"})
    except ValueError as exc:
        assert "symlinked environment file" in str(exc)
    else:
        raise AssertionError("symlinked runtime environment was accepted")
    assert target.read_text() == "SAFE=1\n"


def test_runner_shares_the_exact_compose_results_directory(tmp_path):
    results = tmp_path / "results"
    results.mkdir()
    assert cli._shared_results_root(tmp_path) == results.resolve()

    results.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    results.symlink_to(outside, target_is_directory=True)
    try:
        cli._shared_results_root(tmp_path)
    except ValueError as exc:
        assert "must not be a symlink" in str(exc)
    else:
        raise AssertionError("symlinked results directory was accepted")


def test_unreadable_paths_report_unknown_rather_than_absent(tmp_path, monkeypatch):
    present = tmp_path / "present.env"
    present.write_text("x")
    assert cli._path_exists(present) is True
    assert cli._path_exists(tmp_path / "absent.env") is False

    # Simulate the real host: stat() denied, and sudo refuses to run at all.
    class _Denied(Path.__class__ if False else object):
        pass

    def _raise(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "is_file", _raise)
    monkeypatch.setattr(
        cli, "_run",
        lambda argv, **kwargs: type("R", (), {"returncode": 1, "stderr": "sudo: a password is required"})(),
    )
    assert cli._path_exists(Path("/etc/shakerscan/model-intake-runner.env")) is None
