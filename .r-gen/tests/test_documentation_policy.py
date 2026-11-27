from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_documentation_policy", ROOT / "scripts" / "check_documentation_policy.py"
)
assert SPEC is not None and SPEC.loader is not None
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)


def _minimal_tree(tmp_path: Path) -> Path:
    (tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
    (tmp_path / "docs" / "archive").mkdir(parents=True)
    (tmp_path / "docs" / "releases").mkdir()
    (tmp_path / "docs" / "decisions").mkdir()
    (tmp_path / "docs" / "README.md").write_text(
        "# Docs\n\n**Reconciled:** today\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "archive" / "README.md").write_text(
        "# Historical archive\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "releases" / "README.md").write_text(
        "# Releases\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "decisions" / "README.md").write_text(
        "# Decisions\n", encoding="utf-8"
    )
    return tmp_path


def test_repository_documentation_policy_passes() -> None:
    assert POLICY.check_documentation_policy(ROOT) == []


def test_oversized_agent_guide_is_rejected(tmp_path: Path) -> None:
    root = _minimal_tree(tmp_path)
    (root / "AGENTS.md").write_text(
        "line\n" * (POLICY.AGENT_GUIDE_MAX_LINES + 1), encoding="utf-8"
    )

    failures = POLICY.check_documentation_policy(root)

    assert any("always-loaded guide limit" in failure for failure in failures)


def test_unlabelled_current_and_archive_docs_are_rejected(tmp_path: Path) -> None:
    root = _minimal_tree(tmp_path)
    (root / "docs" / "current.md").write_text("# Current\n", encoding="utf-8")
    (root / "docs" / "archive" / "old.md").write_text("# Old plan\n", encoding="utf-8")

    failures = POLICY.check_documentation_policy(root)

    assert any("current.md must declare" in failure for failure in failures)
    assert any("old.md needs a historical/archive warning" in failure for failure in failures)


def test_collection_index_must_link_each_record_once(tmp_path: Path) -> None:
    root = _minimal_tree(tmp_path)
    (root / "docs" / "releases" / "1.0.md").write_text("# 1.0\n", encoding="utf-8")
    (root / "docs" / "decisions" / "0001.md").write_text("# ADR\n", encoding="utf-8")

    failures = POLICY.check_documentation_policy(root)

    assert any("releases/README.md must link 1.0.md" in failure for failure in failures)
    assert any("decisions/README.md must link 0001.md" in failure for failure in failures)
