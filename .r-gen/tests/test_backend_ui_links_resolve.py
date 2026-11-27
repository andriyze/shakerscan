"""Every UI path the backend hands out must be a page the UI actually serves.

The dashboard action center and product-status cards embed `href` values that the
browser navigates to directly. Nothing tied those strings to the Next.js route
tree, so deleting a page left the backend cheerfully recommending a 404 -- which is
exactly what happened to `/exceptions` when the V2 UI dropped it, in six places
across two dashboard sections.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "api"
APP = ROOT / "ui" / "src" / "app"

# `"href": "/x"`, `href="/x"`, and the f-string forms of both. The first version of
# this matched only plain string literals, so `f"/interactive{suffix}"` -- a live link to
# a page that had just been deleted -- sailed straight through it.
HREF_RE = re.compile(
    r'"href"\s*:\s*f?"(/[^"{]*)'
    r'|\bhref\s*=\s*f?"(/[^"{]*)'
)


def _emitted_paths() -> dict[str, set[str]]:
    """Map each backend-emitted UI path to the files that emit it."""
    found: dict[str, set[str]] = {}
    for path in sorted(API.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        for match in HREF_RE.finditer(path.read_text(encoding="utf-8", errors="ignore")):
            raw = match.group(1) or match.group(2)
            route = raw.split("?", 1)[0].split("#", 1)[0].rstrip("/") or "/"
            found.setdefault(route, set()).add(str(path.relative_to(ROOT)))
    return found


def _ui_routes() -> set[str]:
    """Every route the Next.js app router serves, dynamic segments included."""
    routes = set()
    for page in APP.rglob("page.tsx"):
        parts = page.relative_to(APP).parent.parts
        # Route groups -- `(group)` -- do not appear in the URL.
        segments = [part for part in parts if not part.startswith("(")]
        routes.add("/" + "/".join(segments) if segments else "/")
    return routes


def _matches(route: str, ui_routes: set[str]) -> bool:
    if route in ui_routes:
        return True
    # A concrete path may be served by a dynamic segment: /scans/{id} -> /scans/[id].
    wanted = route.strip("/").split("/") if route != "/" else []
    for candidate in ui_routes:
        have = candidate.strip("/").split("/") if candidate != "/" else []
        if len(have) != len(wanted):
            continue
        if all(
            actual == expected or (expected.startswith("[") and expected.endswith("]"))
            for actual, expected in zip(wanted, have)
        ):
            return True
    return False


def test_every_backend_href_resolves_to_a_ui_page():
    ui_routes = _ui_routes()
    assert ui_routes, "no UI routes discovered -- the test would pass vacuously"

    dangling = {
        route: sorted(sources)
        for route, sources in _emitted_paths().items()
        if not _matches(route, ui_routes)
    }
    assert not dangling, (
        "the backend sends users to UI pages that do not exist: "
        + "; ".join(f"{route} (from {', '.join(src)})" for route, src in sorted(dangling.items()))
    )


def test_the_deleted_v2_surfaces_are_not_linked_anywhere():
    removed = ("/interactive", "/exceptions", "/settings/ai-ops-router")
    emitted = _emitted_paths()
    assert not [route for route in emitted if route in removed]
    assert not [route for route in _ui_routes() if route in removed]
