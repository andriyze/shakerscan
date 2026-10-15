"""Weak ETags and 304s on the polled list reads (api/list_etag.py)."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT / "api", ROOT / "scanner"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from fastapi import FastAPI, Response  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import list_etag  # noqa: E402

STATE = {"rows": [1, 2, 3], "generated_at": "2026-10-15T00:00:00Z"}


def _app(identity: str | None = None, max_bytes: int = list_etag.MAX_ETAG_BYTES) -> FastAPI:
    app = FastAPI()

    @app.get("/scans")
    async def scans(response: Response):
        response.headers["Deprecation"] = "true"
        return {"items": STATE["rows"], "generated_at": STATE["generated_at"]}

    @app.get("/scans/{scan_id}")
    async def scan(scan_id: str):
        return {"id": scan_id}

    @app.get("/findings")
    async def missing():
        return Response(status_code=404, content=b'{"detail":"x"}', media_type="application/json")

    @app.post("/scans")
    async def create():
        return {"ok": True}

    app.add_middleware(list_etag.ListETagMiddleware, max_bytes=max_bytes)
    if identity is not None:
        class SetIdentity:
            def __init__(self, inner):
                self.inner = inner

            async def __call__(self, scope, receive, send):
                if scope["type"] == "http":
                    scope["shakerscan.operator_identity"] = identity
                await self.inner(scope, receive, send)
        app.add_middleware(SetIdentity)
    return app


def setup_function(_fn):
    STATE.update(rows=[1, 2, 3], generated_at="2026-10-15T00:00:00Z")


def test_unchanged_answer_is_a_304_without_a_body_and_keeps_endpoint_headers():
    client = TestClient(_app())
    first = client.get("/scans")
    assert first.status_code == 200
    etag = first.headers["etag"]
    assert etag.startswith('W/"')
    assert first.headers["cache-control"] == "private, no-cache"
    assert "X-ShakerScan-Operator" in first.headers["vary"]
    assert first.headers["deprecation"] == "true"
    assert first.json()["items"] == [1, 2, 3]

    again = client.get("/scans", headers={"If-None-Match": etag})
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers["etag"] == etag
    assert again.headers["deprecation"] == "true"


def test_generated_at_alone_does_not_change_the_tag_but_rows_do():
    client = TestClient(_app())
    etag = client.get("/scans").headers["etag"]
    STATE["generated_at"] = "2026-10-15T00:00:15Z"
    assert client.get("/scans", headers={"If-None-Match": etag}).status_code == 304
    STATE["rows"] = [1, 2, 3, 4]
    changed = client.get("/scans", headers={"If-None-Match": etag})
    assert changed.status_code == 200
    assert changed.json()["items"] == [1, 2, 3, 4]
    assert changed.headers["etag"] != etag


def test_a_tag_issued_to_one_identity_never_validates_another():
    alice = TestClient(_app(identity="alice"))
    bob = TestClient(_app(identity="bob"))
    etag = alice.get("/scans").headers["etag"]
    assert alice.get("/scans", headers={"If-None-Match": etag}).status_code == 304
    assert bob.get("/scans", headers={"If-None-Match": etag}).status_code == 200


def test_weak_comparison_lists_and_star():
    client = TestClient(_app())
    etag = client.get("/scans").headers["etag"]
    strong = etag.removeprefix("W/")
    assert client.get("/scans", headers={"If-None-Match": f'"other", {strong}'}).status_code == 304
    assert client.get("/scans", headers={"If-None-Match": "*"}).status_code == 304
    assert client.get("/scans", headers={"If-None-Match": '"nope"'}).status_code == 200


def test_only_listed_get_paths_with_a_200_json_answer_are_tagged():
    client = TestClient(_app())
    assert "etag" not in client.get("/scans/abc").headers  # detail path, not listed
    assert "etag" not in client.get("/findings").headers  # 404 passes through
    assert "etag" not in client.post("/scans").headers


def test_an_oversized_body_is_sent_untagged_and_never_answered_304():
    client = TestClient(_app(max_bytes=10))
    response = client.get("/scans", headers={"If-None-Match": "*"})
    assert response.status_code == 200
    assert "etag" not in response.headers
    assert response.json()["items"] == [1, 2, 3]


def test_tag_material_ignores_only_top_level_volatile_keys():
    a = list_etag.tag_material(b'{"a":1,"generated_at":"x","n":{"generated_at":"y"}}')
    b = list_etag.tag_material(b'{"generated_at":"z","a":1,"n":{"generated_at":"y"}}')
    c = list_etag.tag_material(b'{"generated_at":"z","a":1,"n":{"generated_at":"q"}}')
    assert a == b
    assert a != c
    assert list_etag.tag_material(b"[1,2]") == b"[1,2]"
