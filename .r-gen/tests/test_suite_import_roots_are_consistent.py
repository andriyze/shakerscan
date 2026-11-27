"""A test file must not import the same module under two different roots.

The api tree is importable two ways: as a package (`api.scan.x`, used when the repo root is on
sys.path) and flatly (`scan.x`, the layout inside the container image, used when `api/` is on
sys.path). CI runs different steps under different roots, so a file whose module-level imports use
one root and whose function-local imports use the other passes locally and fails in exactly one CI
step -- which is how two of these reached the branch and left `V2 migration contracts` red without
any local signal.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

# Top-level packages that live under api/ and are therefore importable both ways.
DUAL_ROOT_PACKAGES = {
    "scan", "hunt", "runtime", "capabilities", "ai_gate", "devices", "model_intake",
}


def _imported_roots(path: Path) -> dict[str, set[str]]:
    """Return {module suffix: {roots it was imported under}} for one test file."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        return {}
    seen: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            names.append(node.module)
        elif isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        for name in names:
            parts = name.split(".")
            if parts[0] == "api" and len(parts) > 1 and parts[1] in DUAL_ROOT_PACKAGES:
                seen.setdefault(".".join(parts[1:]), set()).add("api")
            elif parts[0] in DUAL_ROOT_PACKAGES:
                seen.setdefault(name, set()).add("flat")
    return seen


def test_no_test_file_imports_one_module_under_both_roots():
    offenders: list[str] = []
    for path in sorted(TESTS.rglob("test_*.py")):
        for module, roots in _imported_roots(path).items():
            if len(roots) > 1:
                offenders.append(f"{path.relative_to(ROOT)}: {module} imported as {sorted(roots)}")
    assert not offenders, (
        "these files import the same module under both the package and flat roots, so they pass "
        "under one CI step's sys.path and fail under another:\n  " + "\n  ".join(offenders)
    )


def test_the_guard_recognises_both_import_forms(tmp_path):
    # Prove the detector actually sees the mixture rather than trivially passing.
    sample = tmp_path / "test_sample.py"
    sample.write_text(
        "from api.scan.work_manifests import a\n"
        "def t():\n"
        "    from scan.work_manifests import b\n",
        encoding="utf-8",
    )
    roots = _imported_roots(sample)
    assert roots["scan.work_manifests"] == {"api", "flat"}

    consistent = tmp_path / "test_consistent.py"
    consistent.write_text(
        "from api.scan.work_manifests import a\n"
        "def t():\n"
        "    from api.scan.external_process import b\n",
        encoding="utf-8",
    )
    assert all(len(value) == 1 for value in _imported_roots(consistent).values())
