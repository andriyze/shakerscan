"""`release:` commits may carry version, notes, ledger, and channel metadata; never product code.

The check had no tests, and its functional-root list rejected the one commit the release process
requires to be labelled `release:` -- the stable-channel bump of `install/STABLE_VERSION`. It only
ever merged because the check was not enforced. These tests pin both sides of the rule.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _policy():
    path = ROOT / "scripts" / "check_commit_policy.py"
    spec = importlib.util.spec_from_file_location("commit_policy_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


policy = _policy()


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "test@example.test")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "commit.gpgsign", "false")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "chore: base")
    return repo


def _commit(repo: Path, subject: str, files: dict[str, str]) -> None:
    for relative, content in files.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        _git(repo, "add", relative)
    _git(repo, "commit", "-q", "-m", subject)


def _check(repo: Path, monkeypatch) -> tuple[list[str], int]:
    """Check every commit after the base commit, the way the PR workflow does."""
    monkeypatch.chdir(repo)
    root_commit = _git(repo, "rev-list", "--max-parents=0", "HEAD")
    return policy.check_range(root_commit, "HEAD")


def test_metadata_paths_are_not_functional():
    assert not policy.is_functional("install/STABLE_VERSION")
    assert not policy.is_functional("VERSION")
    assert not policy.is_functional("RELEASES.md")
    assert not policy.is_functional("docs/releases/2.0.0.md")
    assert policy.is_functional("install/index.sh")
    assert policy.is_functional("install/MANIFEST.sha256")
    assert policy.is_functional("scanner.sh")
    assert policy.is_functional("api/api.py")


def test_a_stable_channel_bump_may_carry_the_release_label(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _commit(repo, "release: promote 9.9.9 stable channel", {"install/STABLE_VERSION": "9.9.9\n"})
    failures, count = _check(repo, monkeypatch)
    assert count == 1
    assert failures == []


def test_a_release_commit_hiding_product_code_is_rejected(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _commit(
        repo,
        "release: prepare 9.9.9",
        {"VERSION": "9.9.9\n", "api/api.py": "print('changed')\n", "install/index.sh": "#!/bin/sh\n"},
    )
    failures, _count = _check(repo, monkeypatch)
    assert len(failures) == 1
    assert "api/api.py" in failures[0]
    assert "install/index.sh" in failures[0]
    assert "VERSION" not in failures[0].split("release::", 1)[1]


def test_non_release_commits_are_never_inspected(tmp_path, monkeypatch):
    repo = _repo(tmp_path)
    _commit(repo, "fix(api): change behaviour", {"api/api.py": "print('changed')\n"})
    failures, count = _check(repo, monkeypatch)
    assert count == 1
    assert failures == []


def test_the_script_exits_non_zero_on_a_violation(tmp_path):
    repo = _repo(tmp_path)
    _commit(repo, "release: sneaky", {"scanner.sh": "#!/bin/sh\n"})
    run = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_commit_policy.py"),
         "--base", _git(repo, "rev-parse", "HEAD~1"), "--head", "HEAD"],
        cwd=repo, capture_output=True, text=True,
    )
    assert run.returncode == 1
    assert "hides functional files" in run.stdout
