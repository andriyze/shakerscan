"""Build-failing anti-fitting guard (Wave 7).

Mechanises the plan §1 invariant: *benchmark hostnames, product nouns, and answer-key routes are
prohibited detector/planner inputs*. A benchmark noun in a **comment or docstring** (rationale for
why a general technique exists — "e.g. Juice Shop's search") is allowed; a benchmark noun in an
**executable string literal** (a hardcoded route/host the detector matches against) is a leak, the
"routed-by-class ≠ general-content" contamination T3MP3ST retracted a headline over.

Comments never reach the AST; docstrings are excluded explicitly; test/benchmark/honey-demo
fixtures are out of scope. Everything else in the production detector/planner surface is checked.
"""

import ast
import re
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Benchmark app / product nouns that must not be a detector INPUT. Intentionally specific — "owasp"
# is a legitimate general term (OWASP LLM, CSP guidance) and is NOT forbidden.
FORBIDDEN = re.compile(
    r"juice[\s_-]?shop|juiceshop|(?<![a-z])crapi(?![a-z])|(?:honey|test)\.shakerscan\.com",
    re.IGNORECASE,
)

# Production detector/planner surface.
SCAN_ROOTS = [ROOT / "scanner", ROOT / "api", ROOT / "scripts"]

# Exact fixture/harness directory names.  Do not use substring matching here: production modules
# such as ``oauth_tests.py`` and a checkout living below ``.../test-workspace`` must still be scanned.
EXCLUDE_DIRS = {"tests", "test", "benchmarks", "benchmark", "fixtures", "results", "__pycache__"}
EXCLUDE_FILES = {
    "ai_demo_scenarios.py",  # explicit user-facing demo fixture catalog
    "honey_calibration.py",  # benchmark harness with an intentionally fixed benchmark target
    "verify_acceptance.py",  # release scorecard that selects named benchmark fixtures
}


def _production_py_files():
    for root in SCAN_ROOTS:
        for path in root.rglob("*.py"):
            if path.name.lower() in EXCLUDE_FILES:
                continue
            relative_parts = {part.lower() for part in path.relative_to(ROOT).parts[:-1]}
            if relative_parts & EXCLUDE_DIRS:
                continue
            yield path


def _docstring_node_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def _static_string_value(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
        return node.value.decode("utf-8", errors="replace")
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string_value(node.left)
        right = _static_string_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _code_string_literals(source: str):
    tree = ast.parse(source)
    docstrings = _docstring_node_ids(tree)
    for node in ast.walk(tree):
        if id(node) in docstrings:
            continue
        value = _static_string_value(node)
        if value is not None:
            yield value, getattr(node, "lineno", 0)


def test_no_benchmark_nouns_in_detector_string_literals():
    leaks: list[str] = []
    for path in _production_py_files():
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not FORBIDDEN.search(source):
            continue  # fast path: file mentions nothing anywhere
        try:
            literals = list(_code_string_literals(source))
        except SyntaxError:
            continue
        for value, lineno in literals:
            if FORBIDDEN.search(value):
                rel = path.relative_to(ROOT)
                leaks.append(f"{rel}:{lineno}: benchmark noun in code string literal: {value!r:.120}")
    assert not leaks, (
        "Benchmark/product nouns leaked into detector/planner string literals (fitting). "
        "Move the app-specific fact into a comment/rationale or a general technique:\n  "
        + "\n  ".join(leaks)
    )


def test_guard_would_catch_a_planted_leak():
    # Self-check: the AST scan flags a code literal but not a docstring/comment.
    leaked = '"""crapi rationale docstring is fine"""\nROUTE = "/rest/products/reviews-juiceshop"\n'
    hits = [v for v, _ in _code_string_literals(leaked) if FORBIDDEN.search(v)]
    assert hits == ["/rest/products/reviews-juiceshop"]

    clean = 'x = 1  # crAPI comment is fine\ndef f():\n    """Juice Shop rationale is fine."""\n    return 2\n'
    assert [v for v, _ in _code_string_literals(clean) if FORBIDDEN.search(v)] == []

    evasions = 'HOST = "test." + "shakerscan.com"\nAPP = b"cra" + b"pi"\n'
    hits = [v for v, _ in _code_string_literals(evasions) if FORBIDDEN.search(v)]
    assert urllib.parse.urlparse(f"https://{hits[0]}").hostname == "test.shakerscan.com"
    assert "crapi" in hits
