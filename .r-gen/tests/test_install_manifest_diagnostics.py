"""Stale-manifest diagnostics identify file paths, including equal-content files."""

import pytest

from scripts import generate_install_manifest as generator


@pytest.mark.parametrize("current,rendered,paths", [
    ("a" * 64 + "  .dockerignore\n", "b" * 64 + "  .dockerignore\n", [".dockerignore"]),
    ("a" * 64 + "  removed.txt\n", "b" * 64 + "  added.txt\n", ["added.txt", "removed.txt"]),
    ("a" * 64 + "  first.txt\n" + "a" * 64 + "  second.txt\n",
     "b" * 64 + "  first.txt\n" + "b" * 64 + "  second.txt\n", ["first.txt", "second.txt"]),
])
def test_check_reports_paths_not_digest_keys(tmp_path, monkeypatch, capsys, current, rendered, paths):
    manifest = tmp_path / "MANIFEST.sha256"
    manifest.write_text(current)
    monkeypatch.setattr(generator, "MANIFEST", manifest)
    monkeypatch.setattr(generator, "render_manifest", lambda: rendered)
    assert generator.main(["--check"]) == 1
    error = capsys.readouterr().err
    assert "Changed: " + ", ".join(paths) in error
    assert "a" * 64 not in error and "b" * 64 not in error


def test_matching_manifest_remains_successful(tmp_path, monkeypatch, capsys):
    content = "a" * 64 + "  same.txt\n"
    manifest = tmp_path / "MANIFEST.sha256"
    manifest.write_text(content)
    monkeypatch.setattr(generator, "MANIFEST", manifest)
    monkeypatch.setattr(generator, "render_manifest", lambda: content)
    assert generator.main(["--check"]) == 0
    assert not capsys.readouterr().err
