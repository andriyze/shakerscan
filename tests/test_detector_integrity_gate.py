"""Release gate for benchmark-independent executable scanner logic."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DETECTOR_MODULES = (
    ROOT / "scanner" / "scanner.py",
    ROOT / "scanner" / "reporting.py",
    *sorted((ROOT / "scanner" / "scanner_tools").rglob("*.py")),
)
PROHIBITED_EXECUTABLE_LITERALS = (
    "juice-shop",
    "juice_shop",
    "crapi",
    "cr-api",
    "honey.shakerscan.com",
    "/community/api",
    "/identity/api",
    "/workshop/api",
)


def _executable_string_constants(path: Path) -> list[tuple[int, str]]:
    tree = ast.parse(path.read_text(), filename=str(path))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            docstrings.add(id(first.value))
    return [
        (int(getattr(node, "lineno", 0)), node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def test_detector_modules_do_not_embed_benchmark_answers():
    assert len(DETECTOR_MODULES) >= 80, "detector gate unexpectedly lost scanner module coverage"
    violations: list[str] = []
    for path in DETECTOR_MODULES:
        for line, value in _executable_string_constants(path):
            lowered = value.lower()
            for prohibited in PROHIBITED_EXECUTABLE_LITERALS:
                if prohibited in lowered:
                    violations.append(f"{path.relative_to(ROOT)}:{line}: {prohibited}")

    assert violations == [], "benchmark-specific detector inputs:\n" + "\n".join(violations)
