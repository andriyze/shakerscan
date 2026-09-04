"""The stable promotion must record the ledger row itself, from the published image lock.

For 2.0.1 the row was a separate hand-written pull request that landed after the channel had
moved, so main briefly had a stable version whose ledger row still said "pending": the
runtime-hardening ledger assertion and the upgrade smoke's baseline lookup both break in that
window. These tests pin the recorder the workflow now runs in the same ``release:`` commit.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
COMMIT = "b" * 40


def _load():
    spec = importlib.util.spec_from_file_location(
        "record_release_ledger_under_test", ROOT / "scripts" / "record_release_ledger.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _lock(**overrides):
    values = {
        "SCANNER_IMAGE": f"shakerscan/shakerscan-scanner@{DIGEST}",
        "API_IMAGE": f"shakerscan/shakerscan-api@{DIGEST}",
        "UI_IMAGE": f"shakerscan/shakerscan-ui@{DIGEST}",
        "SIGNER_IMAGE": f"shakerscan/shakerscan-model-intake-signer@{DIGEST}",
        "RUNTIME_MANIFEST_SHA256": "c" * 64,
    }
    values.update(overrides)
    return "\n".join(f"{k}={v}" for k, v in values.items() if v is not None) + "\n"


LEDGER = (
    "intro\n\n"
    "| Version | Git Commit | Scanner/Worker Image | API Image | UI Image | Model Intake Signer Image |\n"
    "| --- | --- | --- | --- | --- | --- |\n"
    "| 2.0.1 | pending candidate | pending | pending | pending | pending |\n"
    f"| 2.0.0 | `{'d' * 40}` | `shakerscan/shakerscan-scanner:2.0.0` (`{DIGEST}`) | `shakerscan/shakerscan-api:2.0.0` (`{DIGEST}`)"
    f" | `shakerscan/shakerscan-ui:2.0.0` (`{DIGEST}`) | `shakerscan/shakerscan-model-intake-signer:2.0.0` (`{DIGEST}`) |\n"
    "\nprose after the table\n"
)


def test_a_pending_row_is_replaced_from_the_lock_and_the_ledger_reads_it_back():
    recorder = _load()
    text, outcome = recorder.record_row(LEDGER, "2.0.1", COMMIT, recorder.parse_lock(_lock()))
    assert outcome == "replaced"
    assert "pending" not in text.splitlines()[4]
    # The consumer of the row is release_ledger.py: it must resolve every image from the new row.
    spec = importlib.util.spec_from_file_location("release_ledger_under_test", ROOT / "scripts" / "release_ledger.py")
    ledger = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ledger)
    for image in ("scanner", "api", "ui", "signer"):
        assert ledger.published_image("2.0.1", image, text).endswith(f"@{DIGEST}")
    assert f"| 2.0.1 | `{COMMIT}` |" in text
    assert "prose after the table" in text and "| 2.0.0 |" in text


def test_a_missing_row_is_inserted_newest_first():
    recorder = _load()
    text, outcome = recorder.record_row(LEDGER, "2.0.2", COMMIT, recorder.parse_lock(_lock()))
    assert outcome == "recorded"
    rows = [line for line in text.splitlines() if line.startswith("| 2.")]
    assert [row.split(" | ")[0] for row in rows] == ["| 2.0.2", "| 2.0.1", "| 2.0.0"]


def test_an_identical_row_is_left_alone_and_a_conflicting_row_is_refused():
    recorder = _load()
    once, _ = recorder.record_row(LEDGER, "2.0.1", COMMIT, recorder.parse_lock(_lock()))
    again, outcome = recorder.record_row(once, "2.0.1", COMMIT, recorder.parse_lock(_lock()))
    assert outcome == "unchanged" and again == once
    other = recorder.parse_lock(_lock(SCANNER_IMAGE="shakerscan/shakerscan-scanner@sha256:" + "e" * 64))
    with pytest.raises(recorder.LedgerError, match="refusing to rewrite"):
        recorder.record_row(once, "2.0.1", COMMIT, other)


def test_the_lock_must_carry_every_ledger_column_as_a_digest_reference():
    recorder = _load()
    with pytest.raises(recorder.LedgerError, match="no SIGNER_IMAGE"):
        recorder.parse_lock(_lock(SIGNER_IMAGE=None))
    with pytest.raises(recorder.LedgerError, match="not a repository@sha256"):
        recorder.parse_lock(_lock(UI_IMAGE="shakerscan/shakerscan-ui:2.0.1"))
    with pytest.raises(recorder.LedgerError, match="not a 40-character commit"):
        recorder.render_row("2.0.1", "abc", recorder.parse_lock(_lock()))


def test_the_cli_writes_the_ledger_and_fails_closed(tmp_path, capsys):
    recorder = _load()
    ledger = tmp_path / "RELEASES.md"
    ledger.write_text(LEDGER, encoding="utf-8")
    lock = tmp_path / "release-image-lock.env"
    lock.write_text(_lock(), encoding="utf-8")
    assert recorder.main(["--version", "2.0.1", "--commit", COMMIT, "--lock", str(lock), "--ledger", str(ledger)]) == 0
    assert "replaced 2.0.1" in capsys.readouterr().out
    assert f"`{COMMIT}`" in ledger.read_text(encoding="utf-8")
    lock.write_text(_lock(API_IMAGE=None), encoding="utf-8")
    assert recorder.main(["--version", "2.0.1", "--commit", COMMIT, "--lock", str(lock), "--ledger", str(ledger)]) == 2
    assert "no API_IMAGE" in capsys.readouterr().err


def test_the_stable_promotion_records_the_row_in_the_channel_commit():
    workflow = (ROOT / ".github" / "workflows" / "promote-stable.yml").read_text(encoding="utf-8")
    assert "scripts/record_release_ledger.py" in workflow
    prepare = workflow.index("Prepare the stable-channel pull request branch")
    tail = workflow[prepare:]
    assert tail.index("record_release_ledger.py") < tail.index("git commit")
    assert "git add RELEASES.md install/STABLE_VERSION" in tail
