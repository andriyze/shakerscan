"""The static gate that rejects names used but never defined (scripts/check_undefined_names.py).

Four such names were live in 2.12.2: a route, a scan stage, a login step and a script each used
a module or helper it never imported, on a path no test reached.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from scripts import check_undefined_names as gate


def test_the_gate_reads_every_tracked_python_tree():
    files = gate.tracked_python_files(gate.REPOSITORY_ROOT)
    top_level = {path.relative_to(gate.REPOSITORY_ROOT).parts[0] for path in files}
    assert {"api", "scanner", "scripts", "client", "tests"} <= top_level
    assert all(path.suffix == ".py" and path.is_file() for path in files)
    assert not any("node_modules" in path.parts for path in files)


def test_the_gate_cannot_pass_when_it_did_not_run(tmp_path: Path, monkeypatch, capsys):
    def unavailable(*_args, **_kwargs):
        raise gate.UndefinedNameCheckError("pyflakes is not installed")

    monkeypatch.setattr(gate, "undefined_names", unavailable)
    source = tmp_path / "ok.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    assert gate.main([str(source)]) == 2
    assert "could not run" in capsys.readouterr().err
    assert gate.main([str(tmp_path / "empty-directory")]) == 2


def test_the_gate_reports_unresolved_names_and_nothing_else(tmp_path: Path, capsys):
    pytest.importorskip("pyflakes")  # a gate tool with its own lock, not a runtime dependency
    source = tmp_path / "live.py"
    source.write_text(
        "import os\n"                                   # unused import: style, not this gate
        "def encode(data):\n"
        "    return base64.b64encode(data)\n"           # the form_login defect
        "def budget(limit):\n"
        "    return int(limit or config.get('max_urls', 1000))\n"  # the scan-stage defect
        "def later():\n"
        "    value = count\n"
        "    count = 1\n"
        "    return value\n"
        "__all__ = ['absent']\n",
        encoding="utf-8",
    )
    broken = tmp_path / "broken.py"
    broken.write_text("def (:\n", encoding="utf-8")
    problems = gate.undefined_names([source, broken], root=tmp_path)
    assert [line.split(": ", 1)[1].split(" (")[0] for line in problems[:4]] == [
        "undefined name 'base64'",
        "undefined name 'config'",
        "undefined name 'count'",
        "undefined name 'absent' in __all__",
    ]
    assert problems[0].startswith("live.py:3:")
    assert len(problems) == 5 and problems[4].startswith("broken.py:1:") and "does not parse" in problems[4]
    assert gate.main([str(tmp_path)]) == 1
    assert "undefined names: 5 in 2 files" in capsys.readouterr().err


def test_the_gate_passes_clean_source(tmp_path: Path, capsys):
    pytest.importorskip("pyflakes")
    source = tmp_path / "clean.py"
    source.write_text(
        "from __future__ import annotations\n"
        "import base64\n"
        "def encode(data: bytes) -> bytes:\n"
        "    return base64.b64encode(data)\n",
        encoding="utf-8",
    )
    assert gate.main([str(source)]) == 0
    assert "undefined names: OK (1 files)" in capsys.readouterr().out
