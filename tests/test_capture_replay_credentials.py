"""What a browser capture's replay withholds as a credential, and what it leaves alone.

A capture's replay decides with its own rule (``device_request_formats``); the shared display
mask (``url_redaction``) keeps the behaviour every other consumer relies on: request lists,
receipts, the endpoint inventory and the Scan work-manifest sensitive-path gate. Every token,
session id and URL here is a unit fixture.
"""
from __future__ import annotations

import json
import urllib.parse
import uuid

import pytest

from api.capture.flows import CaptureFlow, empty_capture_document, har_entry
from scanner.scanner_tools.device_request_formats import (
    captured_path_credential_segments,
    redact_captured_url,
    resolve_imported_requests,
)
from scanner.scanner_tools.request_collections import index_appended_har_entries, validate_and_index
from scanner.scanner_tools.url_redaction import (
    redact_client_route,
    redact_path,
    redact_url,
    token_like_segment,
)

APP = "https://app.example.test"
SESSION = "Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6"

# The shared display mask as the previous release computed it (outputs recorded from that
# release's url_redaction). Paths the capture replay rule withholds are among them: the capture
# rule must not change what any other consumer sees or accepts.
REDACT_PATH_BEFORE = [
    ("/api/share/1234/comments", "/api/share/1234/comments"),
    ("/shared/abcd1234", "/shared/abcd1234"),
    ("/s/2024", "/s/2024"),
    ("/s/2024/report", "/s/2024/report"),
    ("/s/a1b2c3d4/dashboard", "/s/a1b2c3d4/dashboard"),
    ("/share/doc-2024/view", "/share/doc-2024/view"),
    ("/sid/1234", "/sid/1234"),
    ("/api/sessionid=1234/me", "/api/sessionid=1234/me"),
    ("/x-sig=abcd", "/x-sig=abcd"),
    ("/auth_code=abc", "/auth_code=abc"),
    ("/api/session-key=abc", "/api/session-key=abc"),
    ("/magic-login/abc1", "/magic-login/abc1"),
    ("/reset-password/ab12", "/reset-password/ab12"),
    ("/verify-email/Zx9Qp2Lm7Rt4Wv8Yb3", "/verify-email/<redacted>"),
    ("/(S(lit3py55t21z5v55vlm25s55))/default.aspx", "/(S(lit3py55t21z5v55vlm25s55))/default.aspx"),
    ("/download/Zx9Qp2Lm7Rt4Wv8Yb3NcKd", "/download/<redacted>"),
    ("/m/Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6", "/m/<redacted>"),
    ("/api/sessions/Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6", "/api/sessions/<redacted>"),
    ("/s/Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj6/dashboard", "/s/<redacted>/dashboard"),
    ("/auth/login", "/auth/<redacted>"),
    ("/api/auth/v3/check-otp", "/api/auth/<redacted>/check-otp"),
    ("/api/orders/550e8400-e29b-41d4-a716-446655440000", "/api/orders/<redacted>"),
    ("/api/token=a1b2c3/me", "/api/token=<redacted>/me"),
    ("/app;jsessionid=ABC123SECRET/home", "/app/home"),
    ("/rest/basket/6", "/rest/basket/6"),
    ("/products/ProductCategory12", "/products/ProductCategory12"),
    ("/blog/2024/10/s/my-post-1", "/blog/2024/10/s/my-post-1"),
    ("/r/s/12345", "/r/s/12345"),
    ("/api/share/settings", "/api/share/settings"),
    ("/apikey:abcd1234", "/apikey:<redacted>"),
    ("/catalog/key:Shoe-42", "/catalog/key:<redacted>"),
    ("/hooks/deadbeefcafebabedeadbeefcafebabe/events", "/hooks/<redacted>/events"),
    ("/otp/482913", "/otp/<redacted>"),
    ("/code/12345", "/code/<redacted>"),
    ("/files/report.pdf", "/files/report.pdf"),
    ("/", "/"),
]
REDACT_URL_BEFORE = [
    ("https://user:pw@App.Example.test:443/s/a1b2c3d4/dashboard?token=abc&page=2",
     "https://app.example.test/s/a1b2c3d4/dashboard?token=%3Credacted%3E&page=%3Credacted%3E"),
    ("https://app.example.test:8443/api/sessionid=1234/me#frag",
     "https://app.example.test:8443/api/sessionid=1234/me"),
    ("/share/doc-2024/view?x=1", "/share/doc-2024/view?x=%3Credacted%3E"),
    ("https://app.example.test/(S(lit3py55t21z5v55vlm25s55))/default.aspx",
     "https://app.example.test/(S(lit3py55t21z5v55vlm25s55))/default.aspx"),
]


@pytest.mark.parametrize(("path", "shown"), REDACT_PATH_BEFORE)
def test_the_shared_path_mask_is_what_it_was(path, shown):
    assert redact_path(path) == shown


@pytest.mark.parametrize(("url", "shown"), REDACT_URL_BEFORE)
def test_the_shared_url_mask_is_what_it_was(url, shown):
    assert redact_url(url) == shown


def test_the_shared_route_and_token_rules_are_what_they_were():
    assert redact_client_route("#/s/a1b2c3d4/dashboard?token=abc") == "/s/a1b2c3d4/dashboard?token="
    assert redact_client_route("#!/share/doc-2024/view") == "!/share/doc-2024/view"
    assert [token_like_segment(value) for value in (
        "a1b2c3d4", "Zx9Qp2Lm7Rt4Wv8Yb3Nc", "lit3py55t21z5v55vlm25s55", "doc-2024",
    )] == [False, True, False, False]


# Segments the capture replay rule reads, and ordinary ones. Every path of one to three of them
# goes through the shared masks; the digest was recorded from the previous release's
# url_redaction, so any change to what the shared masks show or accept fails here.
SHARED_MASK_SEGMENTS = [
    "", "api", "v2", "me", "s", "share", "sid", "auth", "login", "session", "sessions", "token",
    "reset-password", "magic-login", "download", "2024", "a1b2c3d4", "doc-2024", SESSION,
    "deadbeefcafebabedeadbeefcafebabe", "550e8400-e29b-41d4-a716-446655440000",
    "(S(lit3py55t21z5v55vlm25s55))", "sessionid=1234", "x-sig=abcd", "apikey:abcd1234",
    "app;jsessionid=JS1FIXTURE", "%2Fs%2F1234", "ProductCategory12",
    # Either side of the length at which a slug with digits reads as an opaque value.
    "release-notes-2026-10-19-ab", "release-notes-2026-10-19-abc",
]
SHARED_MASK_DIGEST = "d4b3901a947e8c82333ce001bf8848b4a1d6c3c3cd6a7b2c1b69ed659e1551b9"


def _shared_mask_record() -> str:
    import itertools

    lines = [
        f"{segment}\t{token_like_segment(urllib.parse.unquote(segment))}"
        for segment in SHARED_MASK_SEGMENTS
    ]
    for length in (1, 2, 3):
        for combination in itertools.product(SHARED_MASK_SEGMENTS, repeat=length):
            path = "/" + "/".join(combination)
            lines.append("\t".join((
                path, redact_path(path), redact_url(f"{APP}{path}?token=abc&page=2"),
                str(redact_client_route(f"#{path}?code=1")),
            )))
    return "\n".join(lines)


def test_the_shared_masks_are_unchanged_over_a_generated_corpus():
    import hashlib

    assert hashlib.sha256(_shared_mask_record().encode()).hexdigest() == SHARED_MASK_DIGEST


# Paths the shared mask shows as they are and the capture replay rule withholds.
UNMASKED_BUT_WITHHELD = [
    "/api/share/1234/comments", "/shared/abcd1234", "/s/2024", "/s/a1b2c3d4/dashboard",
    "/share/doc-2024/view", "/sid/1234", "/api/sessionid=1234/me",
]


def test_scanner_path_gates_accept_paths_only_a_capture_withholds():
    """Discovered endpoints and the rows of an ordinary import on these paths stay scannable:
    the endpoint inventory keeps them, recovery fan-out may use them, and a Scan work manifest
    gives them route ids. Only a capture's replay withholds them."""
    from api.scan.work_manifests import build_endpoint_manifest, route_id
    from scanner.manifests import EndpointRecord

    endpoints = []
    for path in UNMASKED_BUT_WITHHELD:
        assert captured_path_credential_segments(APP + path), path
        record = EndpointRecord(
            method="GET", scheme="https", host="app.example.test", port=443,
            normalized_path=path, concrete_path=path, source="web.crawl",
        )
        public = record.public_dict()
        assert public["sensitive_path_redacted"] is False and record.safe_for_recovery_fanout, path
        route_id(
            target_binding_digest="0" * 64, method="GET", scheme="https", host="app.example.test",
            port=443, canonical_path=path, query_parameter_names=[],
        )
        endpoints.append(public)
    manifest = build_endpoint_manifest(
        scan_id=str(uuid.uuid4()), target_binding_digest="0" * 64,
        surface_manifest={"schema_version": "endpoint-manifest/v2", "status": "complete",
                          "endpoints": endpoints},
        source_action_ids=["web.crawl"],
    )
    assert manifest.status == "complete" and manifest.reason_code is None
    assert sorted(entry["canonical_path"] for entry in manifest.entries) == sorted(UNMASKED_BUT_WITHHELD)


def test_an_ordinary_import_keeps_replaying_and_indexing_those_paths():
    document = {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": APP + path, "headers": [], "cookies": []}}
        for path in UNMASKED_BUT_WITHHELD
    ]}}
    payload, summary, rows = validate_and_index(document, import_format="har")
    assert [row["supported"] for row in rows] == [True] * len(UNMASKED_BUT_WITHHELD)
    assert summary["unsupported_request_count"] == 0
    assert [request["url"] for request in resolve_imported_requests(payload)] == [
        APP + path for path in UNMASKED_BUT_WITHHELD
    ]


# What a capture's replay withholds: (path, positions in path.split("/")).
WITHHELD = [
    # A value after a credential, share or sign-in word, including a number and a UUID.
    ("/s/a1b2c3d4/dashboard", [2]), ("/share/1234", [2]), ("/shared/abcd1234", [2]),
    ("/magic/Mgk7Fixture", [2]), ("/login/Lgn7Fixture", [2]), ("/invite/Inv7Fixture", [2]),
    ("/reset/rst7Fixture", [2]), ("/token/abc123def", [2]), ("/otp/482913", [2]),
    ("/2fa/482913", [2]), ("/code/12345", [2]), ("/api/session/10234", [3]),
    ("/invite/550e8400-e29b-41d4-a716-446655440000", [2]), ("/share/QwErTyUiOpAs", [2]),
    # Compound and plural labels, and a random token after a short-link or download word.
    ("/verify-email/Zx9Qp2Lm7Rt4Wv8Yb3", [2]), ("/confirm_account/Zx9Qp2Lm7Rt4Wv8Yb3", [2]),
    ("/password-reset/ab12", [2]), ("/api/sessions/" + SESSION, [3]),
    ("/auth/magic-link/verify/Zx9Qp2Lm7Rt4Wv8", [4]), ("/download/Zx9Qp2Lm7Rt4Wv8Yb3NcKd", [2]),
    ("/m/" + SESSION, [2]),
    # ASP.NET cookieless sessions and forms tickets.
    ("/(S(lit3py55t21z5v55vlm25s55))/default.aspx", [1]),
    ("/app/(X(1)F(Tkt7Fixture))/Orders.aspx", [2]),
    # Credential pairs: any value after "=", a value-shaped one after ":".
    ("/api/token=a1b2c3/me", [2]), ("/api/sessionid=qwertyuiop/me", [2]), ("/x-sig=abcd", [1]),
    ("/apikey:abcd1234", [1]),
    # Wherever it appears: a JWT, 32 or more hex characters (a dashless UUID, an MD5, a commit
    # id), a random run of 32 or more characters.
    ("/api/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl/me", [2]),
    ("/hooks/deadbeefcafebabedeadbeefcafebabe/events", [2]),
    ("/api/users/9f86d081884c7d659a2feaa0c55ad015", [3]),
    ("/repos/o/r/commits/9fceb02d0ae598e95dc970b74767f19372d61af8", [5]),
    ("/feeds/Ab3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zB5/items", [2]),
    ("/feeds/QwErTyUiOpAsDfGhJkLzXcVbNmQwErTy/items", [2]),  # letters only, in random case
    ("/s/" + SESSION + "/x/token=Tkn7Fixture", [2, 4]),
    # Known cost: a slug with a digit after one of those words reads as a value.
    ("/blog/2024/10/s/my-post-1", [5]), ("/confirm/order-2024", [2]),
]
# What it replays as recorded.
REPLAYED = [
    "/auth/login", "/api/auth/session", "/session/current", "/api/token/refresh",
    "/verify/email", "/verify/v2/check", "/invite/accept", "/login/oauth2", "/s/settings",
    "/s/v2", "/share/settings", "/verify-email/sent", "/sessions/123", "/check-otp/v2",
    "/api/orders/550e8400-e29b-41d4-a716-446655440000", "/api/users/507f1f77bcf86cd799439011",
    "/community/api/v2/community/posts/a5ZmDQ8Lx8A9LGmBbBKBjk",
    "/api/v1/invoices/inv_1NqZ8x2eZvKYlo2C9x7Yd3Ab",
    "/api/files/sha256-2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "/download/report-2024.pdf", "/download/550e8400-e29b-41d4-a716-446655440000",
    "/m/settings", "/api/token/v2.1/refresh", "/v1/sessions:create", "/catalog/key:Shoe",
    "/auth/resetPasswordRequest",
    "/rest/basket/6", "/products/ProductCategory12",
    # Known gaps: a letters-only code after a credential word, and an unlabelled token shorter
    # than 32 characters, read as route structure.
    "/invite/qwhtkzpm", "/share/QWERTYUIOPASDFGH", "/t/3f9a2b", "/p/Zx9Qp2Lm7Rt4Wv8Yb3NcKd5Hj",
]


@pytest.mark.parametrize(("path", "positions"), WITHHELD)
def test_what_a_capture_replay_withholds(path, positions):
    assert captured_path_credential_segments(APP + path) == positions
    shown = redact_captured_url(APP + path).removeprefix(APP).split("/")
    assert all(shown[position].endswith("<redacted>") for position in positions)


@pytest.mark.parametrize("path", REPLAYED)
def test_what_a_capture_replay_sends(path):
    assert captured_path_credential_segments(APP + path) == []
    assert redact_captured_url(APP + path) == redact_url(APP + path)


def _entry(method, path, headers=(), body=None, content_type="application/json"):
    flow = {"method": method, "url": APP + path,
            "request_headers": [{"name": name, "value": value} for name, value in headers]}
    if body is not None:
        flow["request_body"] = body
        flow["request_headers"].append({"name": "Content-Type", "value": content_type})
    return har_entry(CaptureFlow.model_validate(flow))[0]


def _replayed(*entries):
    payload = empty_capture_document()
    payload["document"]["log"]["entries"] = list(entries)
    return resolve_imported_requests(payload)


@pytest.mark.parametrize(("name", "value", "sent"), [
    ("Referer", f"{APP}/s/{SESSION}/dashboard", f"{APP}/"),
    ("Referer", "https://user:pw@app.example.test/home", f"{APP}/"),
    ("Referer", f"{APP}/welcome?token=Tok7Fixture", f"{APP}/"),
    ("Referer", f"{APP}/home;jsessionid=JSESSIONFIXTURE1", f"{APP}/"),
    ("Referer", f"{APP}/#/s/{SESSION}", f"{APP}/"),
    ("Referer", "not a url", None),
    ("Origin", f"{APP}/s/{SESSION}/dashboard", APP),
    ("HX-Current-URL", f"{APP}/s/{SESSION}/dashboard", f"{APP}/"),
    ("Next-Url", f"/s/{SESSION}/dashboard", "/"),
    ("X-Page", f"{APP}/reset/Rst7Fixture", f"{APP}/"),
    ("X-Original-URL", f"/s/{SESSION}/dashboard?tab=1", "/"),
    ("X-Callback", f"{APP}:notaport/s/2024", None),  # a URL that does not parse is not sent
])
def test_a_copy_of_a_credential_page_url_in_a_header_loses_the_credential(name, value, sent):
    (request,) = _replayed(_entry("GET", "/api/data", [(name, value), ("Accept", "*/*")]))
    assert dict(request["header_items"]).get(name) == sent
    assert request["headers"].get(name) == sent
    assert f"header:{name.lower()}" in request["captured_withheld"]
    assert dict(request["header_items"])["Accept"] == "*/*"
    assert request["error"] is None
    for secret in (SESSION, "pw@", "Tok7Fixture", "JSESSIONFIXTURE1", "Rst7Fixture"):
        assert secret not in json.dumps(request, default=str)


@pytest.mark.parametrize(("name", "value"), [
    ("Referer", f"{APP}/products/ProductCategory12?page=2"),
    ("Origin", APP),
    ("Origin", "null"),
    ("HX-Current-URL", f"{APP}/products"),
    ("Next-Url", "/products/ProductCategory12"),
    ("X-Page", f"{APP}/docs/getting-started"),
    ("X-Original-URL", "/products/ProductCategory12?page=2"),
    ("Accept-Language", "en-US"),
])
def test_a_header_without_a_credential_is_sent_as_recorded(name, value):
    (request,) = _replayed(_entry("GET", "/api/data", [(name, value)]))
    assert dict(request["header_items"])[name] == value
    assert request["captured_withheld"] == []


def test_a_header_holding_a_recorded_credential_value_is_left_out():
    """The Next.js router sends the route's segments, the session id among them, URL-encoded
    in Next-Router-State-Tree; a value recorded as a credential in any URL of the capture is
    not sent again under any header."""
    tree = urllib.parse.quote(json.dumps(
        ["", {"children": ["s", {"children": [["session", SESSION, "d"], {}]}]}]))
    page, rsc = _replayed(
        _entry("GET", f"/s/{SESSION}/dashboard"),
        _entry("GET", "/dashboard", [("Next-Router-State-Tree", tree), ("RSC", "1")]),
    )
    assert page["error"] == "captured_path_credential_withheld"
    assert dict(rsc["header_items"]) == {"RSC": "1"}
    assert rsc["captured_withheld"] == ["header:next-router-state-tree"]
    assert SESSION not in json.dumps(rsc, default=str)


@pytest.mark.parametrize(("name", "value"), [
    ("Referer", f"{APP}/s/{SESSION}/dashboard"),
    ("Next-Url", f"/s/{SESSION}/dashboard"),
])
def test_a_credential_value_seen_only_in_a_header_copy_is_not_sent_elsewhere(name, value):
    """The page itself need not be in the capture (recording started on it): its URL or path in
    a header is enough for the session id to be withheld from the body that repeats it."""
    data, reference = _replayed(
        _entry("GET", "/api/data", [(name, value)]),
        _entry("POST", "/api/ref", body=json.dumps({"sessionRef": SESSION})),
    )
    assert data["captured_withheld"] == [f"header:{name.lower()}"]
    assert json.loads(reference["body"]) == {"sessionRef": ""}
    assert reference["captured_withheld"] == ["body:sessionRef"]


def test_a_credential_query_value_is_not_sent_again_elsewhere():
    """A value recorded under a credential-named query parameter (``?token=``) is a credential
    wherever it appears again. A word recorded under such a name (``?session=current``) is not
    one, so the same word elsewhere is sent as recorded."""
    welcome, claim, view = _replayed(
        _entry("GET", "/welcome?token=Tok7Fixture99&session=current"),
        _entry("POST", "/api/claim", body=json.dumps({"claim": "Tok7Fixture99", "view": "current"})),
        _entry("GET", "/api/views/current"),
    )
    assert welcome["url"] == f"{APP}/welcome" and welcome["error"] is None
    assert json.loads(claim["body"]) == {"claim": "", "view": "current"}
    assert claim["captured_withheld"] == ["body:claim"]
    assert view["error"] is None and view["url"] == f"{APP}/api/views/current"
    assert view["captured_withheld"] == []


SHARE = "a1b2c3d4"


def test_a_request_whose_path_repeats_a_recorded_credential_is_withheld():
    """A share page's API calls carry its token in their own paths, under words the rule does
    not read as credential words. A request whose path repeats a value recorded as a credential
    in any URL of the capture cannot be sent without it either, so it is withheld like the page;
    a different value in the same place is replayed."""
    from scanner.scanner_tools.request_collections import RequestSelector, select_requests

    entries = [
        _entry("GET", f"/share/{SHARE}"),
        _entry("GET", f"/api/docs/{SHARE}/content"),
        _entry("GET", f"/api/docs/%61{SHARE[1:]}/meta"),
        _entry("GET", f"/api/docs/{SHARE}0/content"),
        _entry("GET", "/api/docs/e5f6a7b8/content"),
    ]
    page, content, encoded, longer, other = _replayed(*entries)
    assert page["captured_path_segments_withheld"] == [2]
    assert content["error"] == encoded["error"] == "captured_path_credential_withheld"
    assert content["captured_withheld"] == encoded["captured_withheld"] == ["path:3"]
    assert content["url"] == f"{APP}/api/docs/<redacted>/content"
    assert encoded["url"] == f"{APP}/api/docs/<redacted>/meta"
    assert longer["error"] is None and longer["url"] == f"{APP}/api/docs/{SHARE}0/content"
    assert other["error"] is None and other["url"] == f"{APP}/api/docs/e5f6a7b8/content"
    for request in (page, content, encoded):
        assert SHARE not in json.dumps(request, default=str)

    payload = empty_capture_document()
    payload["document"]["log"]["entries"] = entries
    selected = select_requests(payload, RequestSelector(safe_methods_only=False))
    assert [request["id"] for request in selected] == [longer["id"], other["id"]]

    # The request list of the batch that recorded them shows and marks them the same way.
    rows = index_appended_har_entries(entries, start_index=0)
    assert [row["supported"] for row in rows] == [False, False, False, True, True]
    assert [row["normalized_path"] for row in rows[:3]] == [
        "/share/<redacted>", "/api/docs/<redacted>/content", "/api/docs/<redacted>/meta"]
    assert SHARE not in json.dumps(rows[:3])


def test_a_repeat_of_a_value_recorded_in_an_earlier_batch_is_withheld_at_replay():
    """Each batch's request list sees only that batch, so a repeat of a value recorded in an
    earlier batch is listed as supported; replay resolves the whole capture and still leaves it
    out, whether selected by filter or named by id."""
    from scanner.scanner_tools.request_collections import RequestSelector, select_requests
    from scanner.scanner_tools.request_replay import build_selected_replay_plan

    first = [_entry("GET", f"/share/{SHARE}")]
    second = [_entry("GET", f"/api/docs/{SHARE}/content"), _entry("GET", "/api/items")]
    rows = index_appended_har_entries(second, start_index=1)
    assert [row["supported"] for row in rows] == [True, True]
    payload = empty_capture_document()
    payload["document"]["log"]["entries"] = first + second
    named = RequestSelector(request_ids=tuple(row["request_id"] for row in rows), safe_methods_only=False)
    assert [request["id"] for request in select_requests(payload, named)] == [rows[1]["request_id"]]
    plan = build_selected_replay_plan(payload, RequestSelector(), allowed_origins=[APP])
    assert [request.request_id for request in plan.requests] == [rows[1]["request_id"]]
    assert SHARE not in repr(list(plan.wire_requests()))


def test_body_copies_of_a_credential_page_url_lose_the_credential():
    page, beacon_json, beacon_form, reference, beacon_text, search, control = _replayed(
        _entry("GET", f"/s/{SESSION}/dashboard"),
        _entry("POST", "/api/track", body=json.dumps(
            {"url": f"{APP}/s/{SESSION}/dashboard", "event": "view",
             "visits": [f"/s/{SESSION}/a", "/products"], "next": f"{APP}:notaport/s/2024"})),
        _entry("POST", "/api/track", body=f"page=%2Fs%2F{SESSION}%2Fdashboard&event=view",
               content_type="application/x-www-form-urlencoded"),
        _entry("POST", "/api/ref", body=json.dumps({"sessionRef": SESSION, "count": 2})),
        _entry("POST", "/api/beacon", body=f"visited {APP}/s/{SESSION}/dashboard",
               content_type="text/plain"),
        _entry("GET", f"/api/search?from=%2Fs%2F{SESSION}%2Fdashboard&q=shoes"),
        _entry("POST", "/api/track", body=json.dumps({"url": f"{APP}/products", "event": "view"})),
    )
    # A URL that does not parse is emptied: the rule cannot see what it carries.
    assert json.loads(beacon_json["body"]) == {
        "url": f"{APP}/", "event": "view", "visits": ["/", "/products"], "next": ""}
    assert beacon_json["captured_withheld"] == ["body:next", "body:url", "body:visits"]
    assert urllib.parse.parse_qsl(beacon_form["body"].decode()) == [("page", "/"), ("event", "view")]
    assert beacon_form["captured_withheld"] == ["body:page"]
    assert json.loads(reference["body"]) == {"sessionRef": "", "count": 2}
    assert beacon_text["body"] == b"" and beacon_text["captured_withheld"] == ["body:*"]
    assert search["url"] == f"{APP}/api/search?q=shoes"
    assert search["captured_withheld"] == ["query:from"]
    assert json.loads(control["body"]) == {"url": f"{APP}/products", "event": "view"}
    assert control["captured_withheld"] == []
    assert page["error"] == "captured_path_credential_withheld"
    for request in (beacon_json, beacon_form, reference, beacon_text, search):
        assert request["error"] is None
        assert SESSION not in json.dumps(request, default=str)


def test_a_multipart_part_holding_a_credential_page_url_is_emptied():
    boundary = "----fixture"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"page\"\r\n\r\n"
        f"{APP}/s/{SESSION}/dashboard\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
        f"--{boundary}--\r\n"
    )
    (request,) = _replayed(_entry(
        "POST", "/api/upload", body=body, content_type=f"multipart/form-data; boundary={boundary}"))
    assert request["captured_withheld"] == ["body:page"]
    assert SESSION not in request["body"].decode() and b"hello" in request["body"]


def test_a_capture_marked_import_replays_a_url_without_its_userinfo():
    """A browser capture refuses a URL with userinfo; a capture-marked HAR imported as a
    document can still carry one, and replay sends the request without it."""
    document = empty_capture_document()["document"]
    document["log"]["entries"] = [
        {"request": {"method": "GET", "url": "https://user:Pw7Fixture@app.example.test/api/items",
                     "headers": [], "cookies": []}},
    ]
    payload, _summary, rows = validate_and_index(document, import_format="har")
    (request,) = resolve_imported_requests(payload)
    assert request["url"] == f"{APP}/api/items"
    assert request["captured_withheld"] == ["url:userinfo"] and request["error"] is None
    assert rows[0]["supported"] is True and "Pw7Fixture" not in json.dumps(rows)


def test_a_capture_marked_import_lists_a_withheld_request_masked():
    document = empty_capture_document()["document"]
    document["log"]["entries"] = [
        {"request": {"method": "GET", "url": f"{APP}/s/a1b2c3d4/dashboard", "headers": [], "cookies": []}},
    ]
    _payload, summary, rows = validate_and_index(document, import_format="har")
    assert rows[0]["supported"] is False
    assert rows[0]["redacted_url"] == f"{APP}/s/<redacted>/dashboard"
    assert rows[0]["normalized_path"] == "/s/<redacted>/dashboard"
    assert "a1b2c3d4" not in json.dumps(summary)


def test_a_capture_list_row_masks_what_the_old_list_showed():
    entries = [_entry("GET", path) for path in ("/s/a1b2c3d4/dashboard", "/api/sessionid=1234/me",
                                                "/(S(lit3py55t21z5v55vlm25s55))/default.aspx")]
    rows = index_appended_har_entries(entries, start_index=0)
    assert [row["normalized_path"] for row in rows] == [
        "/s/<redacted>/dashboard", "/api/sessionid=<redacted>/me", "/<redacted>/default.aspx"]
    assert [row["supported"] for row in rows] == [False, False, False]
    # A shown placeholder never trips the scanner's sensitive-path gate.
    assert all(redact_path(row["normalized_path"]) == row["normalized_path"] for row in rows)


# --- a bare query token (``/items?<token>``) in what the replay lists as withheld ----------------
# Unit fixture tokens, not credentials: a JWT, random strings of 32 and 20 characters, 40 hex
# characters, an AWS access key id shape and standard base64.
BARE_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3ZhbHVlXzEyMw"
BARE_TOKENS = {
    "jwt": BARE_JWT,
    "random32": "Zx9Qp2Lm7Rt4Wv8Yb3Nc5Kd1Hf6Gj0Ts",
    "random20": "Zx9Qp2Lm7Rt4Wv8Yb3Nc",
    "hex40": "0123456789abcdef0123456789abcdef01234567",
    "access_key_id": "AKIA" + "ZOOFIXTUREVALUE1",
    "base64": "q8Zx+2Lm/7Rt4Wv8Yb3Nc5Kd1Hf6G==",
}


def _bare_token_capture(query: str) -> dict:
    entry = {"request": {"method": "GET", "url": f"{APP}/items?{query}", "headers": [], "cookies": []},
             "response": {"status": 200}}
    return {"format": "capture", "document": {"log": {"version": "1.2", "entries": [entry]}}}


def _bare_token_absent(token: str, text: str) -> bool:
    readable = urllib.parse.unquote_plus(text)
    pieces = {token, token.rstrip("="), urllib.parse.quote(token, safe=""), urllib.parse.quote_plus(token)}
    return not any(piece in text or piece in readable for piece in pieces)


class _AnsweringTransport:
    """Unit fixture transport: every replayed request is answered 200 from a fixture address."""

    async def send(self, request, *, target, timeout_seconds, follow_redirects):
        from runtime.request_replay_executor import ReplayTransportResult
        return ReplayTransportResult(status_code=200, connected_address="192.0.2.10", final_url=request.url,
                                     response_headers={}, response_body=b"ok", elapsed_ms=1)


@pytest.mark.parametrize("shape", ["{t}", "{t}&page=2", "page=2&{t}"])
@pytest.mark.parametrize("token", BARE_TOKENS.values(), ids=BARE_TOKENS.keys())
def test_a_bare_query_token_never_reaches_the_withheld_list_the_plan_or_the_receipt(token, shape):
    import asyncio
    from datetime import datetime, timedelta, timezone

    from runtime.models import TargetBinding
    from runtime.request_replay_executor import execute_replay_plan
    from scanner.scanner_tools.request_collections import RequestSelector
    from scanner.scanner_tools.request_replay import build_selected_replay_plan

    capture = _bare_token_capture(shape.format(t=token))
    (request,) = resolve_imported_requests(capture)
    assert _bare_token_absent(token, request["url"])
    assert _bare_token_absent(token, json.dumps(request["captured_withheld"]))
    assert _bare_token_absent(token, json.dumps(request["captured_query_parameters_withheld"]))
    # Still listed as withheld, under a masked name.
    assert request["captured_withheld"] == ["query:<redacted>"]
    plan = build_selected_replay_plan(capture, RequestSelector(safe_methods_only=False), allowed_origins=[APP])
    assert _bare_token_absent(token, plan.requests[0].wire_dict()["url"])
    assert _bare_token_absent(token, json.dumps(plan.public_dict()))
    moments = iter(datetime(2026, 10, 25, 12, 0, tzinfo=timezone.utc) + timedelta(milliseconds=10 * step)
                   for step in range(1000))
    outcome = asyncio.run(execute_replay_plan(
        plan, target=TargetBinding(target_id="target-1", target_kind="web", canonical_host="app.example.test",
                                   allowed_origins=(APP,), allowed_addresses=("192.0.2.10",),
                                   scope_receipt_id="scope-1"),
        owner_kind="hunt", owner_id="hunt-1", worker_id="worker-1", limits={"http_requests": 10},
        consumed={}, transport=_AnsweringTransport(), clock=lambda: next(moments)))
    assert _bare_token_absent(token, json.dumps(outcome.public_dict(), default=str))


def test_ordinary_and_credential_named_bare_parameters_keep_their_names():
    (request,) = resolve_imported_requests(_bare_token_capture("debug&page=2"))
    assert request["captured_withheld"] == []
    (request,) = resolve_imported_requests(_bare_token_capture("access_token&page=2"))
    assert request["captured_withheld"] == ["query:access_token"]


@pytest.mark.parametrize("token", BARE_TOKENS.values(), ids=BARE_TOKENS.keys())
def test_a_replay_plan_masks_a_token_in_a_withheld_label_whoever_produced_it(token):
    from scanner.scanner_tools.request_replay import build_replay_plan

    rows = [{"id": "r1", "method": "GET", "url": f"{APP}/items?page=2",
             "captured_withheld": [f"query:{token}", "header:cookie", "path:2", "query:access_token"]}]
    plan = build_replay_plan(rows, allowed_origins=[APP])
    assert plan.requests[0].captured_withheld == (
        "query:<redacted>", "header:cookie", "path:2", "query:access_token")
    assert _bare_token_absent(token, json.dumps(plan.public_dict()))


@pytest.mark.parametrize("token", BARE_TOKENS.values(), ids=BARE_TOKENS.keys())
def test_an_imported_collections_request_list_masks_a_bare_query_token(token):
    document = {"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": f"{APP}/items?{token}&page=2", "headers": []},
         "response": {"status": 200}}]}}
    _payload, _summary, rows = validate_and_index(document, import_format="har")
    for row in rows:
        assert _bare_token_absent(token, json.dumps(row))
    postman = {"info": {"name": "fixture", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/"},
               "item": [{"name": "items", "request": {"method": "GET", "url": f"{APP}/items?{token}"}}]}
    _payload, _summary, rows = validate_and_index(postman, import_format="postman_collection")
    assert rows
    for row in rows:
        assert _bare_token_absent(token, json.dumps(row))
