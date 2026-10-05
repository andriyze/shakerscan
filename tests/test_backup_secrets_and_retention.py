"""Backups leave the encryption key out, keep a bounded number, and can be deleted."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scanner.sh").read_text()


def _fn(name: str) -> str:
    body = SCRIPT.split(f"\n{name}() {{", 1)[1].split("\n}", 1)[0]
    return f"{name}() {{{body}\n}}"


FUNCTIONS = "\n".join(_fn(name) for name in (
    "backup_key_file", "backup_sha256", "backup_key_fingerprint", "create_backup",
    "prune_backups", "list_backups", "backup_key_state", "confirm_backup_delete", "delete_backups", "backup_cmd",
))


def _run(script_dir: Path, command: str, *, stdin: str = "", **env: str) -> subprocess.CompletedProcess[str]:
    harness = f"""
set -e
SCRIPT_DIR={script_dir}
RED=''; GREEN=''; YELLOW=''; NC=''
DEFAULT_PREBUILT_IMAGE_TAG=latest
get_release_version() {{ printf '9.9.9'; }}
compose() {{ printf 'PGDMP-fixture'; }}
{FUNCTIONS}
{command}
"""
    return subprocess.run(["bash", "-c", harness], input=stdin, capture_output=True, text=True,
                          timeout=30, env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", **env})


def _install(tmp_path: Path) -> Path:
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / ".credential_enc.key").write_text("fernet-key-fixture\n")
    (tmp_path / "results" / "scan.json").write_text("{}")
    (tmp_path / ".env").write_text("AI_API_KEY=provider-key\nAI_CREDENTIAL_ENC_KEY=env-key\nPOSTGRES_PASSWORD=pw\n")
    return tmp_path


def _only_backup(tmp_path: Path) -> Path:
    [backup] = list((tmp_path / "backups").iterdir())
    return backup


def test_a_backup_leaves_the_encryption_key_out_by_default(tmp_path):
    install = _install(tmp_path)
    result = _run(install, "create_backup")
    assert result.returncode == 0, result.stderr
    backup = _only_backup(install)
    with tarfile.open(backup / "results.tar.gz") as archive:
        names = archive.getnames()
    assert "results/scan.json" in names
    assert "results/.credential_enc.key" not in names
    runtime = (backup / "runtime.env").read_text()
    assert "AI_CREDENTIAL_ENC_KEY" not in runtime and "AI_API_KEY=provider-key" in runtime
    manifest = (backup / "manifest.txt").read_text()
    assert "encryption_key_included=false" in manifest
    fingerprint = manifest.split("encryption_key_fingerprint=", 1)[1].strip()
    assert len(fingerprint) == 16 and fingerprint in result.stdout
    assert not (backup / ".incomplete").exists()


def test_include_key_puts_the_key_in_and_says_so(tmp_path):
    install = _install(tmp_path)
    result = _run(install, "backup_cmd --include-key")
    assert result.returncode == 0, result.stderr
    backup = _only_backup(install)
    with tarfile.open(backup / "results.tar.gz") as archive:
        assert "results/.credential_enc.key" in archive.getnames()
    assert "AI_CREDENTIAL_ENC_KEY=env-key" in (backup / "runtime.env").read_text()
    assert "encryption_key_included=true" in (backup / "manifest.txt").read_text()
    assert "includes the encryption key" in result.stdout


def _fake_backups(root: Path, names: list[str], incomplete: tuple[str, ...] = ()) -> None:
    for name in names:
        (root / name).mkdir(parents=True)
        (root / name / "manifest.txt").write_text("encryption_key_included=false\n")
        if name in incomplete:
            (root / name / ".incomplete").write_text("x")


def test_pruning_keeps_the_newest_complete_backups_and_never_touches_an_incomplete_one(tmp_path):
    root = tmp_path / "backups"
    names = [f"shakerscan-2026100{day}T000000Z" for day in range(1, 6)]
    _fake_backups(root, names, incomplete=(names[0],))
    result = _run(tmp_path, f"prune_backups {root}", SHAKERSCAN_BACKUP_KEEP="2")
    assert result.returncode == 0, result.stderr
    assert sorted(p.name for p in root.iterdir()) == [names[0], names[3], names[4]]
    # 0 keeps every backup.
    _fake_backups(root, ["shakerscan-20260901T000000Z"])
    assert _run(tmp_path, f"prune_backups {root}", SHAKERSCAN_BACKUP_KEEP="0").returncode == 0
    assert len(list(root.iterdir())) == 4


def test_a_backup_can_be_deleted_by_name_or_all_of_them(tmp_path):
    root = tmp_path / "backups"
    _fake_backups(root, ["shakerscan-20261001T000000Z", "shakerscan-20261002T000000Z",
                         "postgres-16-to-18-20261001T000000Z"])
    listing = _run(tmp_path, "backup_cmd list")
    assert "postgres-16-to-18-20261001T000000Z" in listing.stdout and "key excluded" in listing.stdout
    # Unconfirmed deletion is cancelled; a path is never accepted as a name.
    assert _run(tmp_path, "backup_cmd delete shakerscan-20261001T000000Z", stdin="no\n").returncode == 1
    assert (root / "shakerscan-20261001T000000Z").exists()
    assert _run(tmp_path, "backup_cmd delete ../results --yes").returncode == 1
    assert _run(tmp_path, "backup_cmd delete shakerscan-20261001T000000Z --yes").returncode == 0
    assert not (root / "shakerscan-20261001T000000Z").exists()
    assert _run(tmp_path, "backup_cmd delete all", stdin="yes\n").returncode == 0
    assert list(root.iterdir()) == []


def _legacy_backup(root: Path, name: str, *, with_key: bool) -> None:
    """A backup made before the key was left out: its manifest says nothing about the key."""
    staging = root / f".{name}-staging" / "results"
    staging.mkdir(parents=True)
    (staging / "scan.json").write_text("{}")
    if with_key:
        (staging / ".credential_enc.key").write_text("fernet-key-fixture\n")
    (root / name).mkdir(parents=True)
    with tarfile.open(root / name / "results.tar.gz", "w:gz") as archive:
        archive.add(staging, arcname="results")
    (root / name / "manifest.txt").write_text("created_at=20261003T213901Z\nrelease_version=2.5.6\n")


def test_list_reads_older_backups_that_never_recorded_the_key(tmp_path):
    root = tmp_path / "backups"
    _legacy_backup(root, "shakerscan-20261001T000000Z", with_key=True)
    _legacy_backup(root, "shakerscan-20261002T000000Z", with_key=False)
    rows = {line.split()[0]: line for line in _run(tmp_path, "backup_cmd list").stdout.splitlines()}
    assert "KEY INCLUDED" in rows["shakerscan-20261001T000000Z"]
    assert "key excluded" in rows["shakerscan-20261002T000000Z"]


def test_delete_honours_the_launchers_global_yes_and_reports_a_missing_answer(tmp_path):
    root = tmp_path / "backups"
    _fake_backups(root, ["shakerscan-20261001T000000Z", "shakerscan-20261002T000000Z"])
    # `scanner.sh backup delete NAME --yes`: the global parser keeps --yes for itself.
    assert _run(tmp_path, "ASSUME_YES=1; backup_cmd delete shakerscan-20261001T000000Z").returncode == 0
    assert not (root / "shakerscan-20261001T000000Z").exists()
    # No terminal and no --yes: cancelled with a reason instead of a silent exit.
    missing = _run(tmp_path, "backup_cmd delete shakerscan-20261002T000000Z")
    assert missing.returncode == 1 and "Pass --yes" in missing.stdout
    assert (root / "shakerscan-20261002T000000Z").exists()


@pytest.mark.parametrize(
    "spelling", ["results/.credential_enc.key", "/results/.credential_enc.key", "./results//.credential_enc.key"],
)
def test_the_key_stays_out_whatever_spelling_the_key_file_setting_uses(tmp_path, spelling):
    """The exclusion used to strip "$SCRIPT_DIR/" from the configured path, so a relative or
    container path matched nothing and the key shipped while the manifest said it did not."""
    install = _install(tmp_path)
    (install / "results" / ".credential_enc.key.lock").write_text("")
    (install / "results" / ".credential_enc.key.tmp-123").write_text("half-written-key\n")
    (install / ".env").write_text(
        "AI_API_KEY=provider-key\nexport AI_CREDENTIAL_ENC_KEY=exported-key\n  AI_CREDENTIAL_ENC_KEY = spaced-key\n"
    )
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=spelling)
    assert result.returncode == 0, result.stderr
    backup = _only_backup(install)
    with tarfile.open(backup / "results.tar.gz") as archive:
        names = archive.getnames()
    assert "results/scan.json" in names
    assert not [name for name in names if ".credential_enc.key" in name], names
    runtime = (backup / "runtime.env").read_text()
    assert "AI_CREDENTIAL_ENC_KEY" not in runtime and "AI_API_KEY=provider-key" in runtime
    assert "encryption_key_included=false" in (backup / "manifest.txt").read_text()


def test_a_custom_key_file_name_inside_results_is_also_left_out(tmp_path):
    install = _install(tmp_path)
    (install / "results" / "custom.fernet").write_text("custom-key\n")
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=str(install / "results" / "custom.fernet"))
    assert result.returncode == 0, result.stderr
    with tarfile.open(_only_backup(install) / "results.tar.gz") as archive:
        names = archive.getnames()
    assert "results/custom.fernet" not in names and "results/scan.json" in names


@pytest.mark.parametrize("custom", [False, True])
def test_symlink_and_hardlink_key_aliases_never_enter_an_excluded_key_backup(tmp_path, custom):
    install = _install(tmp_path)
    results = install / "results"
    original = results / ".credential_enc.key"
    original.unlink()
    backing = results / "keys" / "actual.fernet"
    backing.parent.mkdir()
    backing.write_text("synthetic-key-canary\n")
    configured = results / "custom.fernet" if custom else original
    configured.symlink_to("keys/actual.fernet")
    (results / "renamed-hardlink").hardlink_to(backing)
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=str(configured))
    assert result.returncode == 0, result.stderr
    backup = _only_backup(install)
    with tarfile.open(backup / "results.tar.gz") as archive:
        assert "results/scan.json" in archive.getnames()
        assert not {"results/keys/actual.fernet", "results/renamed-hardlink", "results/custom.fernet", "results/.credential_enc.key"} & set(archive.getnames())
    assert "encryption_key_included=false" in (backup / "manifest.txt").read_text()


def test_custom_key_rotation_files_are_excluded_too(tmp_path):
    install = _install(tmp_path)
    key = install / "results" / "custom.fernet"
    key.write_text("custom-key-canary")
    key.with_name(key.name + ".tmp.123").write_text("partial-key-canary")
    result = _run(install, "create_backup", AI_CREDENTIAL_ENC_KEY_FILE=str(key))
    assert result.returncode == 0, result.stderr
    with tarfile.open(_only_backup(install) / "results.tar.gz") as archive:
        assert not any("custom.fernet" in name for name in archive.getnames())
