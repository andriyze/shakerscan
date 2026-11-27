"""Regression guard: build_report's `target` parameter must not be shadowed.

A `for target in ...:` loop inside build_report leaks its loop variable into
the function scope (Python has no block scope), rebinding the original
`target` string parameter to the last iterated item (a dict for HAR targets).
Later code that assumed `target` was still the URL string then crashed with
`'dict' object has no attribute 'decode'` inside urllib.parse.urlparse — but
only on targets rich enough to populate HAR discovery, so unit tests missed it.

This test statically asserts the `target` parameter is never rebound by a
for-loop / comprehension / assignment within build_report.
"""

import ast
import os


SCANNER_PATH = os.path.join(os.path.dirname(__file__), "..", "scanner", "scanner.py")


def _build_report_node():
    tree = ast.parse(open(SCANNER_PATH).read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == "build_report":
            return node
    raise AssertionError("build_report not found in scanner.py")


def _names_bound_by(target_node) -> set[str]:
    """Collect simple Name targets bound by a for-loop/assignment target."""
    names = set()
    for sub in ast.walk(target_node):
        if isinstance(sub, ast.Name):
            names.add(sub.id)
    return names


def test_build_report_does_not_shadow_target_parameter():
    fn = _build_report_node()

    # Confirm `target` really is the first parameter (guards against rename).
    arg_names = [a.arg for a in fn.args.args]
    assert "target" in arg_names, f"expected 'target' parameter, got {arg_names}"

    offenders = []
    for node in ast.walk(fn):
        # for target in ...:  /  async for target in ...:
        if isinstance(node, (ast.For, ast.AsyncFor)):
            if "target" in _names_bound_by(node.target):
                offenders.append(("for-loop", getattr(node, "lineno", "?")))
        # comprehension: [... for target in ...]
        elif isinstance(node, ast.comprehension):
            if "target" in _names_bound_by(node.target):
                offenders.append(("comprehension", getattr(node, "lineno", "?")))
        # walrus: (target := ...)
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name) and node.target.id == "target":
                offenders.append(("walrus", getattr(node, "lineno", "?")))

    assert not offenders, (
        "build_report rebinds its `target` parameter, which will clobber the "
        f"scan URL string. Use a distinct loop variable. Offenders: {offenders}"
    )
