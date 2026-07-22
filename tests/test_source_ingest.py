"""Host tests for the B2 opt-in source ingester (api/source_ingest.py).

Pure + stdlib-only: containment (the whitebox.ts port), crawl ceilings, regex block
extraction, exposure ranking, budget packing, and route-hint lead extraction.
"""
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import source_ingest as si


@pytest.fixture()
def source_root(monkeypatch):
    with tempfile.TemporaryDirectory() as root:
        monkeypatch.setenv(si.SOURCE_ROOT_ENV, root)
        yield Path(root)


def _write(repo: Path, name: str, text: str) -> None:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)


# ---------------------------------------------------------------------------
# Containment (port of resolveContainedRepoPath)
# ---------------------------------------------------------------------------

def test_containment_requires_source_root_env(monkeypatch):
    monkeypatch.delenv(si.SOURCE_ROOT_ENV, raising=False)
    with pytest.raises(si.SourceIngestError, match="SOURCE_ROOT|not set"):
        si.resolve_contained_source_path("/tmp/anything")


def test_containment_accepts_repo_inside_root(source_root):
    repo = source_root / "app"
    repo.mkdir()
    assert si.resolve_contained_source_path(str(repo)) == os.path.realpath(str(repo))
    # the root itself is allowed
    assert si.resolve_contained_source_path(str(source_root)) == os.path.realpath(str(source_root))


def test_containment_rejects_outside_root(source_root):
    with tempfile.TemporaryDirectory() as outside:
        with pytest.raises(si.SourceIngestError, match="outside the allowed root"):
            si.resolve_contained_source_path(outside)
    # an existing directory outside the root reached via ".."
    with pytest.raises(si.SourceIngestError, match="outside the allowed root"):
        si.resolve_contained_source_path(str(source_root / ".."))


def test_containment_rejects_symlink_escape(source_root):
    repo = source_root / "app"
    repo.mkdir()
    with tempfile.TemporaryDirectory() as outside:
        link = source_root / "app" / "link"
        os.symlink(outside, link)
        with pytest.raises(si.SourceIngestError, match="outside the allowed root"):
            si.resolve_contained_source_path(str(link))


def test_crawl_skips_source_file_symlink_escape(source_root):
    repo = source_root / "app"
    repo.mkdir()
    with tempfile.TemporaryDirectory() as outside:
        secret = Path(outside) / "secret.py"
        secret.write_text("def leaked():\n    return 'outside'\n")
        os.symlink(secret, repo / "linked.py")
        _write(repo, "safe.py", "def safe():\n    return True\n")

        result = si.ingest_source(str(repo), token_budget=2000)

    assert result["stats"]["files"] == 1
    assert "safe.py" in result["text"]
    assert "linked.py" not in result["text"]
    assert "outside" not in result["text"]


def test_containment_rejects_nonexistent_and_files(source_root):
    with pytest.raises(si.SourceIngestError, match="must be a directory"):
        si.resolve_contained_source_path(str(source_root / "nope"))
    f = source_root / "file.py"
    f.write_text("x = 1\n")
    with pytest.raises(si.SourceIngestError, match="must be a directory"):
        si.resolve_contained_source_path(str(f))
    with pytest.raises(si.SourceIngestError, match="non-empty string"):
        si.resolve_contained_source_path("")


# ---------------------------------------------------------------------------
# Ingest: crawl / extract / classify / pack / hints
# ---------------------------------------------------------------------------

def test_ingest_ranks_exposed_blocks_first_and_extracts_hints(source_root):
    repo = source_root / "app"
    repo.mkdir()
    _write(repo, "routes.py",
           "from flask import request\n\n"
           "@app.route('/api/users')\n"
           "def users():\n"
           "    q = request.args.get('q')\n"
           "    return db.execute('SELECT * FROM users WHERE name=' + q)\n")
    _write(repo, "util.py", "def add(a, b):\n    return a + b\n")
    _write(repo, "notes.txt", "not source — excluded by extension\n")
    _write(repo, "node_modules/pkg.js", "eval('x')")  # excluded dir

    result = si.ingest_source(str(repo), token_budget=2000)
    stats = result["stats"]
    assert stats["files"] == 2  # .txt and node_modules excluded
    assert stats["by_exposure"]["exposed_externally"] >= 1
    # the decorated route block outranks the neutral helper
    first_chunk = result["text"].split("=== ")[1]
    assert "routes.py" in first_chunk
    assert result["hints"], "a route-decorated block must yield a route hint"
    hint = result["hints"][0]
    assert hint["route"] == "/api/users"
    assert hint["metadata_json"]["source"] == "source_ingest"


def test_ingest_respects_token_budget(source_root):
    repo = source_root / "big"
    repo.mkdir()
    for index in range(8):
        _write(repo, f"mod{index}.py",
               f"def handler{index}():\n" + "\n".join(f"    x{index}_{n} = 'aaaaaaaaaaaaaaaaaaaa'"
                                                       for n in range(40)))
    result = si.ingest_source(str(repo), token_budget=60)  # ~240 chars of packed body
    assert result["stats"]["included_units"] < result["stats"]["blocks"]
    assert result["stats"]["dropped_units"] > 0
    assert len(result["text"]) < 2000


def test_ingest_marks_truncation_on_file_ceiling(source_root, monkeypatch):
    monkeypatch.setattr(si, "_MAX_FILES", 2)
    repo = source_root / "many"
    repo.mkdir()
    for index in range(5):
        _write(repo, f"m{index}.py", f"def f{index}():\n    pass\n")
    result = si.ingest_source(str(repo), token_budget=4000)
    assert result["stats"]["truncated"] is True
    assert result["stats"]["files"] == 2


def test_risk_signals_raise_priority(source_root):
    repo = source_root / "risky"
    repo.mkdir()
    _write(repo, "safe.py", "def ok():\n    return 1\n")
    _write(repo, "danger.py",
           "def bad(user_input):\n"
           "    return eval(user_input)\n")
    result = si.ingest_source(str(repo), token_budget=4000)
    first_chunk = result["text"].split("=== ")[1]
    assert "danger.py" in first_chunk
    assert "signals=" in first_chunk
