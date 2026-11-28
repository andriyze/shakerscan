"""request.verify checks (capabilities/request_verify.py): each proves its class only with a repeat
and a silent control, against fake applications that are vulnerable, safe, or built to fool the
check (an echo of everything, a catch-all page, a fixed answer)."""
from __future__ import annotations

import asyncio
import json
import re
import urllib.parse

import pytest

from api.capabilities.request_verify import (
    PROOF_CONTRACTS, RATE_LIMIT_ATTEMPTS, RequestVerifyAdapter, RequestVerifyError, RequestVerifier,
)
from api.hunt.request_verification import build_request
from api.runtime.models import TargetBinding
from api.runtime.request_replay_executor import ReplayTransportResult

ORIGIN = "https://app.example.test"


def _target() -> TargetBinding:
    return TargetBinding(
        target_id="10000000-0000-4000-8000-000000000001", target_kind="web",
        canonical_host="app.example.test", allowed_origins=(ORIGIN,),
        allowed_addresses=("192.0.2.10",), allowed_root_domains=("example.test",),
        scope_receipt_id="10000000-0000-4000-8000-000000000002",
    )


def _answer(request, body=b"", *, status=200, headers=None, content_type="text/html"):
    merged = {"Content-Type": content_type, **(headers or {})}
    return ReplayTransportResult(
        status_code=status, connected_address="192.0.2.10", final_url=request.url,
        response_headers=merged, response_body=body if isinstance(body, bytes) else body.encode(),
        elapsed_ms=5,
    )


class Fake:
    """A transport answering with ``respond(request)`` and keeping every request it got."""

    def __init__(self, respond):
        self.respond = respond
        self.requests = []

    async def send(self, request, **_kwargs):
        self.requests.append(request)
        return self.respond(request)


def _run(check, values, respond, *, field=None, budget=48, options=None, request_class="safe_read"):
    request = build_request({"method": "GET", **values}, base_url=ORIGIN + "/",
                            headers=values.pop("_headers", {}) if "_headers" in values else {},
                            action_id="action-1")
    transport = Fake(respond)
    adapter = RequestVerifyAdapter(
        check=check, target=_target(), request=request, field=field, transport=transport,
        requested_budget={"http_requests": budget, "tool_wall_seconds": 120}, seed="seed-1",
        request_class=request_class, options=options,
    )

    async def heartbeat():
        return None

    result = asyncio.run(adapter.execute(heartbeat=heartbeat, cancelled=lambda: False))
    return result, transport


def _verified(result):
    return [item for item in result.observations if item.get("proof_state") == "verified"]


def _query(request, name):
    return urllib.parse.parse_qs(urllib.parse.urlsplit(request.url).query, keep_blank_values=True).get(name, [""])[0]


def _header(request, name):
    return next((value for key, value in request.headers if key.lower() == name.lower()), None)


# -- open redirect ---------------------------------------------------------------------------

def _redirector(request):
    return _answer(request, status=302, headers={"Location": _query(request, "next") or "/"})


def test_open_redirect_needs_two_random_hosts_and_a_silent_own_path():
    result, transport = _run("open_redirect", {"path": "/go", "query": {"next": "/home"}}, _redirector,
                             field="next")
    proof = _verified(result)[0]
    assert proof["proof_contract"] == PROOF_CONTRACTS["open_redirect"]
    assert proof["technique"] == "location_absolute_repeated" and proof["repetitions"] == 2
    hosts = {urllib.parse.urlsplit(_query(item, "next")).hostname for item in transport.requests[1:3]}
    assert len(hosts) == 2 and all(host.endswith(".shakerscan-redirect-probe.invalid") for host in hosts)
    assert _query(transport.requests[3], "next").startswith("/")  # the control: the application's own path


def test_open_redirect_is_not_a_reflection_in_the_body():
    def reflector(request):
        return _answer(request, f"<a href='{_query(request, 'next')}'>continue</a>")
    result, _ = _run("open_redirect", {"path": "/go", "query": {"next": "/"}}, reflector, field="next")
    assert not _verified(result)


def test_open_redirect_scheme_relative_bypass_is_tried_when_absolute_urls_are_refused():
    def careless(request):
        value = _query(request, "next")
        return _answer(request, status=302, headers={"Location": "/" if value.startswith("http") else value})
    result, _ = _run("open_redirect", {"path": "/go", "query": {"next": "/"}}, careless, field="next")
    assert _verified(result)[0]["technique"] == "location_scheme_relative_repeated"


def test_open_redirect_that_keeps_the_last_outside_host_is_caught_by_the_own_path_control():
    remembered = {}

    def sticky(request):
        value = _query(request, "next")
        if value.startswith("http"):
            remembered["host"] = value
        return _answer(request, status=302, headers={"Location": remembered.get("host", value)})
    result, _ = _run("open_redirect", {"path": "/go", "query": {"next": "/"}}, sticky, field="next")
    assert not _verified(result)


def test_open_redirect_to_the_first_outside_host_only_is_caught_by_the_second_host():
    seen = {}

    def first_only(request):
        value = _query(request, "next")
        if value.startswith(("http", "//")):  # every outside destination goes to the first one seen
            value = seen.setdefault("host", value)
        return _answer(request, status=302, headers={"Location": value})
    result, _ = _run("open_redirect", {"path": "/go", "query": {"next": "/"}}, first_only, field="next")
    assert not _verified(result)


# -- CRLF ------------------------------------------------------------------------------------

def _splitter(request):
    """Writes the parameter into a header without removing CR LF, as a naive server does."""
    headers = {}
    lines = ("X-Note: " + _query(request, "note")).replace("\r\n", "\n").split("\n")
    for line in lines:
        name, _, value = line.partition(": ")
        headers[name] = value
    return _answer(request, b"{}", headers=headers, content_type="application/json")


def test_crlf_injection_starts_a_random_header_twice_and_the_spaced_control_does_not():
    result, transport = _run("crlf_injection", {"path": "/log", "query": {"note": "x"}}, _splitter, field="note")
    proof = _verified(result)[0]
    assert proof["proof_contract"] == PROOF_CONTRACTS["crlf_injection"]
    assert "\r\n" not in _query(transport.requests[-1], "note")


def test_crlf_injection_is_not_proved_by_a_server_that_adds_any_named_header():
    def obliging(request):
        # Adds a header named in the value whatever separates it: the spaced control fires too.
        match = re.search(r"(X-Sk-\w+): (\w+)", _query(request, "note"))
        return _answer(request, b"{}", headers=dict([match.groups()]) if match else {})
    result, _ = _run("crlf_injection", {"path": "/log", "query": {"note": "x"}}, obliging, field="note")
    assert not _verified(result)


# -- host header -----------------------------------------------------------------------------

def _reset_page(request):
    host = _header(request, "Host") or "app.example.test"
    return _answer(request, f'{{"reset": true, "link": "https://{host}/reset?t=1"}}', content_type="application/json")


def test_host_header_written_into_the_page_twice_with_a_silent_unrelated_header():
    result, transport = _run("host_header_injection", {"method": "POST", "path": "/reset",
                                                       "form_body": {"email": "a@example.test"}}, _reset_page)
    proof = _verified(result)[0]
    assert proof["header_name"] == "Host" and proof["technique"] == "host_reflected_in_body_repeated"
    assert _header(transport.requests[-1], "X-Shakerscan-Control")


def test_host_header_is_not_proved_by_an_endpoint_that_echoes_every_header():
    def echo(request):
        return _answer(request, json.dumps(dict(request.headers)), content_type="application/json")
    result, _ = _run("host_header_injection", {"path": "/debug"}, echo)
    assert not _verified(result)


def test_host_header_is_not_proved_by_a_page_with_a_debug_footer_of_every_header():
    """The page is the same page, so only the unrelated-header control tells it apart."""
    body = "<h1>Shop</h1>" + "<p>Welcome to the shop, browse our products and offers today</p>" * 20

    def footer(request):
        listed = "".join(f"<li>{name}: {value}</li>" for name, value in request.headers)
        return _answer(request, body + f"<footer><ul>{listed}</ul></footer>")
    result, _ = _run("host_header_injection", {"path": "/"}, footer)
    assert not _verified(result)


def test_host_header_is_not_proved_by_a_catch_all_virtual_host_page():
    def vhosts(request):
        host = _header(request, "Host")
        if host:
            return _answer(request, f"<h1>No site configured for {host}</h1><p>nginx default server</p>", status=404)
        return _answer(request, "<h1>Shop</h1><p>Welcome to the shop, browse our products today</p>")
    result, _ = _run("host_header_injection", {"path": "/"}, vhosts)
    assert not _verified(result)


def test_host_header_is_not_proved_by_the_web_servers_own_redirect_to_the_same_path():
    """Every web server builds its trailing-slash (or http to https) redirect from Host."""
    def web_server(request):
        host = _header(request, "Host") or "app.example.test"
        return _answer(request, b"", status=301, headers={"Location": f"https://{host}/docs/"})
    result, _ = _run("host_header_injection", {"path": "/docs"}, web_server)
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "canonical_redirect_built_from_host"

    def application(request):  # a redirect somewhere else, built from Host by the application
        host = _header(request, "Host") or "app.example.test"
        return _answer(request, b"", status=302, headers={"Location": f"https://{host}/welcome"})
    result, _ = _run("host_header_injection", {"path": "/start"}, application)
    assert _verified(result)[0]["technique"] == "host_reflected_in_location_repeated"


def test_forwarding_headers_that_say_where_a_client_is_need_the_identity_header_permission():
    def forwarded(request):
        host = _header(request, "X-Forwarded-Host") or "app.example.test"
        return _answer(request, f"<a href='https://{host}/'>home</a>")
    result, transport = _run("host_header_injection", {"path": "/"}, forwarded)
    assert not _verified(result)
    assert not any(_header(item, "X-Forwarded-Host") for item in transport.requests)
    result, _ = _run("host_header_injection", {"path": "/"}, forwarded, options={"allow_identity_headers": True})
    assert _verified(result)[0]["header_name"] == "X-Forwarded-Host"


# -- CORS ------------------------------------------------------------------------------------

def _cors(reflect=True, credentials=True, null=False, wildcard=False):
    def respond(request):
        origin = _header(request, "Origin")
        headers = {}
        if wildcard:
            headers["Access-Control-Allow-Origin"] = "*"
        elif origin and (reflect or (null and origin == "null")):
            headers["Access-Control-Allow-Origin"] = origin
        if credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        return _answer(request, b'{"user": "alice"}', headers=headers, content_type="application/json")
    return respond


def test_cors_reflection_of_two_random_origins_with_credentials():
    result, _ = _run("cors", {"path": "/api/me"}, _cors())
    proof = _verified(result)[0]
    assert proof["proof_class"] == "cors_reflected_origin" and proof["credentials"] is True


def test_cors_null_origin_and_wildcard_with_credentials():
    result, _ = _run("cors", {"path": "/api/me"}, _cors(reflect=False, null=True))
    assert _verified(result)[0]["proof_class"] == "cors_null_origin"
    result, _ = _run("cors", {"path": "/api/me"}, _cors(wildcard=True))
    assert _verified(result)[0]["proof_class"] == "cors_wildcard_credentials"


def test_cors_granting_only_the_first_origin_it_saw_is_not_reflection():
    first = {}

    def sticky(request):
        origin = _header(request, "Origin")
        if origin and origin != "null":
            first.setdefault("origin", origin)
        return _answer(request, b"{}", headers={"Access-Control-Allow-Origin": first.get("origin", ""),
                                                "Access-Control-Allow-Credentials": "true"})
    result, _ = _run("cors", {"path": "/api/me"}, sticky)
    assert not _verified(result)


def test_cors_fixed_allow_list_is_not_a_finding():
    def fixed(request):
        return _answer(request, b"{}", headers={"Access-Control-Allow-Origin": "https://partner.example.test",
                                                "Access-Control-Allow-Credentials": "true"})
    result, _ = _run("cors", {"path": "/api/me"}, fixed)
    assert not _verified(result)


# -- posture ---------------------------------------------------------------------------------

def test_security_headers_missing_on_an_html_page_twice():
    result, _ = _run("security_headers", {"path": "/"}, lambda request: _answer(request, "<html>shop</html>"))
    classes = {item["proof_class"] for item in _verified(result)}
    assert classes == {"missing_content_security_policy", "clickjacking"}


def test_security_headers_present_or_not_html_prove_nothing():
    def guarded(request):
        return _answer(request, "<html>shop</html>", headers={
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"})
    result, _ = _run("security_headers", {"path": "/"}, guarded)
    assert not _verified(result)
    result, _ = _run("security_headers", {"path": "/api"}, lambda r: _answer(r, b"{}", content_type="application/json"))
    assert not _verified(result)


_LISTING = b'<html><head><title>Index of /files/</title></head><body><a href="a.txt">a.txt</a></body></html>'


def test_directory_listing_twice_and_none_for_a_missing_sibling():
    def server(request):
        path = urllib.parse.urlsplit(request.url).path
        return _answer(request, _LISTING) if path == "/files/" else _answer(request, b"not found", status=404)
    result, transport = _run("directory_listing", {"path": "/files/"}, server)
    assert _verified(result)[0]["proof_contract"] == PROOF_CONTRACTS["directory_listing"]
    assert urllib.parse.urlsplit(transport.requests[-1].url).path != "/files/"


def test_a_page_that_lists_whatever_is_asked_is_not_a_proven_listing():
    result, _ = _run("directory_listing", {"path": "/files/"}, lambda request: _answer(request, _LISTING))
    assert not _verified(result)


# -- GraphQL ---------------------------------------------------------------------------------

def _graphql(validating=True, introspection=True):
    def respond(request):
        document = _query(request, "query") or json.loads(request.body or b"{}").get("query", "")
        if "__typenamezq" in document and validating:
            return _answer(request, b'{"errors": [{"message": "Cannot query field"}]}', content_type="application/json")
        if "__schema" in document and introspection:
            return _answer(request, json.dumps({"data": {"__schema": {
                "queryType": {"name": "Query", "fields": [{"name": "users"}]},
                "types": [{"name": "Query"}, {"name": "User"}]}}}), content_type="application/json")
        if "__typename" in document and validating:
            count = document.count("__typename")
            data = {"__typename": "Query"} if count == 1 else {f"a{i}": "Query" for i in range(count)}
            return _answer(request, json.dumps({"data": data}), content_type="application/json")
        return _answer(request, b'{"data": {"ok": true}}', content_type="application/json")
    return respond


def test_graphql_introspection_needs_a_validating_server_or_an_ordinary_field_control():
    result, _ = _run("graphql", {"path": "/graphql"}, _graphql())
    assert "graphql_introspection" in {item["proof_class"] for item in _verified(result)}
    result, _ = _run("graphql", {"path": "/graphql"}, _graphql(validating=False))
    proof = _verified(result)[0]
    assert proof["technique"] == "schema_meta_field_answered_repeated_with_ordinary_field_control"


def test_graphql_responder_that_answers_a_schema_for_anything_is_not_introspection():
    def anything(request):
        return _answer(request, json.dumps({"data": {"__schema": {"queryType": {"name": "Query"},
                                                                  "types": [{"name": "Query"}]}}}),
                       content_type="application/json")
    result, _ = _run("graphql", {"path": "/graphql"}, anything)
    assert not _verified(result)


# -- uploads ---------------------------------------------------------------------------------

def _store():
    stored: dict[str, bytes] = {}

    def respond(request):
        if request.method == "POST":
            match = re.search(rb'filename="([^"]+)"\r\nContent-Type: text/html\r\n\r\n(.*?)\r\n--', request.body, re.S)
            stored[match.group(1).decode()] = match.group(2)
            return _answer(request, b'{"ok": true}', content_type="application/json")
        name = urllib.parse.unquote(urllib.parse.urlsplit(request.url).path.rsplit("/", 1)[-1])
        if name in stored:
            return _answer(request, stored[name])
        return _answer(request, b"missing", status=404)
    return respond


def test_upload_served_back_as_html_twice_and_not_for_a_name_never_uploaded():
    result, transport = _run("file_upload", {"method": "POST", "path": "/upload"}, _store(), field="file",
                             options={"retrieve_path": "/uploads/{filename}"})
    proof = _verified(result)[0]
    assert proof["proof_contract"] == PROOF_CONTRACTS["file_upload"]
    uploads = [item for item in transport.requests if item.method == "POST" and item.body]
    assert len(uploads) == 2 and all(b"<script" not in item.body.lower() for item in uploads)


def test_upload_served_as_text_or_any_name_answered_proves_nothing():
    inner = _store()

    def as_text(request):
        answer = inner(request)
        return _answer(request, answer.response_body, status=answer.status_code, content_type="text/plain")
    result, _ = _run("file_upload", {"method": "POST", "path": "/upload"}, as_text, field="file",
                     options={"retrieve_path": "/uploads/{filename}"})
    assert not _verified(result)
    last = {}

    def catch_all(request):
        if request.method == "POST":
            last["body"] = re.search(rb"\r\n\r\n(<!doctype.*?)\r\n--", request.body, re.S).group(1)
            return _answer(request, b"{}")
        return _answer(request, last.get("body", b""))
    result, _ = _run("file_upload", {"method": "POST", "path": "/upload"}, catch_all, field="file",
                     options={"retrieve_path": "/uploads/{filename}"})
    assert not _verified(result)


def test_upload_is_not_proved_by_a_page_that_prints_the_name_it_was_asked_for():
    """A landing page or soft 404: HTML, 200, and the requested file name in it. Nothing stored."""
    def landing(request):
        if request.method == "POST":
            return _answer(request, b'{"ok": true}', content_type="application/json")
        name = urllib.parse.unquote(urllib.parse.urlsplit(request.url).path.rsplit("/", 1)[-1])
        return _answer(request, f"<!doctype html><title>{name}</title><h1>Download {name}</h1>")
    result, transport = _run("file_upload", {"method": "POST", "path": "/upload"}, landing, field="file",
                             options={"retrieve_path": "/uploads/{filename}"})
    assert not _verified(result)
    # The uploaded markup is not the file name: a page cannot print it from the request it got.
    upload = next(item for item in transport.requests if item.method == "POST")
    name = re.search(rb'filename="([^"]+)\.html"', upload.body).group(1)
    assert upload.body.count(name) == 1


def test_upload_is_not_proved_when_the_stored_text_is_shown_escaped_or_the_route_echoes_names():
    import html
    inner = _store()

    def viewer(request):  # a file viewer: the stored text, escaped, inside its own page
        answer = inner(request)
        if request.method == "POST" or answer.status_code != 200:
            return answer
        return _answer(request, "<html><pre>" + html.escape(answer.response_body.decode()) + "</pre></html>")
    result, _ = _run("file_upload", {"method": "POST", "path": "/upload"}, viewer, field="file",
                     options={"retrieve_path": "/view/{filename}"})
    assert not _verified(result)

    def echoing(request):  # serves what was stored, and answers every other name with a page naming it
        answer = inner(request)
        if request.method == "POST" or answer.status_code == 200:
            return answer
        name = urllib.parse.unquote(urllib.parse.urlsplit(request.url).path.rsplit("/", 1)[-1])
        return _answer(request, f"<h1>{name}</h1>")
    result, _ = _run("file_upload", {"method": "POST", "path": "/upload"}, echoing, field="file",
                     options={"retrieve_path": "/uploads/{filename}"})
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "retrieve_route_echoes_the_requested_name"


def test_upload_needs_a_retrieve_path_with_the_file_name():
    with pytest.raises(RequestVerifyError):
        asyncio.run(RequestVerifier(
            check="file_upload", request=build_request({"method": "POST", "path": "/u"}, base_url=ORIGIN,
                                                       headers={}, action_id="a"),
            field="file", seed="s", send=None, left=lambda: 10, options={},
        )._file_upload(None))


# -- sign-in checks --------------------------------------------------------------------------

def _login(throttle_after=None):
    seen = {"count": 0}

    def respond(request):
        seen["count"] += 1
        if throttle_after and seen["count"] > throttle_after:
            return _answer(request, b'{"error": "too many attempts"}', status=429, headers={"Retry-After": "60"},
                           content_type="application/json")
        return _answer(request, b'{"error": "invalid credentials"}', status=401, content_type="application/json")
    return respond


def test_rate_limit_states_a_run_of_unthrottled_refusals_and_never_verifies_it():
    """A dozen refusals for a name that may be no account show neither a per-account lockout nor a
    threshold above a dozen (a login that locks at 20 answers exactly like this one)."""
    result, transport = _run("rate_limit", {"method": "POST", "path": "/login",
                                            "form_body": {"username": "alice", "password": "x"}},
                             _login(throttle_after=20), field="password", request_class="safe_authentication")
    assert not _verified(result) and "rate_limit" not in PROOF_CONTRACTS
    stated = result.observations[0]
    assert stated["proof_state"] == "not_proven" and stated["proof_contract"] is None
    assert stated["not_proven_reason"] == "unthrottled_run_is_not_proof"
    assert stated["attempts_unthrottled"] == RATE_LIMIT_ATTEMPTS and stated["refusal_status"] == 401
    from api.hunt.request_verification import finding_records
    assert finding_records("h", "a", ORIGIN, "r", {"check": "rate_limit"}, list(result.observations)) == []
    # Even an observation forged as verified has no finding to become.
    forged = {**stated, "proof_state": "verified", "finding_verdict": "verified", "repetitions": 12,
              "proof_contract": "request_sign_in_unthrottled/v1"}
    assert finding_records("h", "a", ORIGIN, "r", {"check": "rate_limit"}, [forged]) == []
    passwords = {urllib.parse.parse_qs(item.body.decode())["password"][0] for item in transport.requests[1:]}
    assert len(passwords) == RATE_LIMIT_ATTEMPTS  # every attempt a fresh random wrong password


def test_rate_limit_is_not_claimed_once_the_login_throttles():
    result, transport = _run("rate_limit", {"method": "POST", "path": "/login",
                                            "form_body": {"username": "alice", "password": "x"}},
                             _login(throttle_after=5), field="password", request_class="safe_authentication")
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "throttled"
    assert len(transport.requests) == 6  # it stops at the first throttled answer


def _ldap(escaped_accepted=False):
    def respond(request):
        user = urllib.parse.parse_qs(request.body.decode())["username"][0]
        accepted = "*" in user or (escaped_accepted and "\\2a" in user)
        return _answer(request, json.dumps({"authenticated": accepted, **({"token": "t" * 24} if accepted else {})}),
                       status=200 if accepted else 401, content_type="application/json")
    return respond


def test_ldap_wildcard_signs_in_twice_while_a_literal_and_the_escaped_wildcard_do_not():
    values = {"method": "POST", "path": "/ldap/auth", "form_body": {"username": "bob", "password": "x"}}
    result, _ = _run("ldap_injection", dict(values), _ldap(), field="username", request_class="safe_authentication")
    assert _verified(result)[0]["payload_shape"] == "*"
    result, _ = _run("ldap_injection", dict(values), _ldap(escaped_accepted=True), field="username",
                     request_class="safe_authentication")
    assert not _verified(result)


# -- CSRF ------------------------------------------------------------------------------------

def _account(check_origin=False, needs_session=True):
    def respond(request):
        cookie = _header(request, "Cookie")
        if needs_session and not cookie:
            return _answer(request, b'{"error": "unauthenticated"}', status=401, content_type="application/json")
        if check_origin and (_header(request, "Origin") or "").endswith(".invalid"):
            return _answer(request, b'{"error": "bad origin"}', status=403, content_type="application/json")
        return _answer(request, b'{"changed": true}', content_type="application/json")
    return respond


def _csrf(respond, headers=None):
    values = {"method": "POST", "path": "/account/email", "form_body": {"email": "a@example.test"},
              "_headers": headers if headers is not None else {"Cookie": "session=abcdefgh12345678"}}
    return _run("csrf", values, respond, request_class="confirmed_mutation")


def test_csrf_cross_site_request_accepted_twice_and_refused_without_the_session():
    result, transport = _csrf(_account())
    proof = _verified(result)[0]
    assert proof["proof_contract"] == PROOF_CONTRACTS["csrf"]
    forged = transport.requests[1]
    assert _header(forged, "Origin").endswith(".shakerscan-csrf-probe.invalid")
    assert _header(forged, "Sec-Fetch-Site") == "cross-site"
    assert _header(transport.requests[-1], "Cookie") is None


def test_csrf_not_proved_when_origin_is_checked_the_session_is_not_needed_or_a_bearer_token_is_used():
    assert not _verified(_csrf(_account(check_origin=True))[0])
    result, _ = _csrf(_account(needs_session=False))
    assert not _verified(result)
    result, _ = _csrf(_account(), headers={"Cookie": "s=abcdefgh12345678", "Authorization": "Bearer abc"})
    assert result.observations[0]["not_proven_reason"] == "header_authenticated"


def _form_body(request):
    return dict(urllib.parse.parse_qsl(request.body.decode(), keep_blank_values=True))


def _token_checked(refusal):
    """An application that checks its anti-CSRF form field; ``refusal(request)`` is its answer to a
    request without the right token."""
    def respond(request):
        if not _header(request, "Cookie"):
            return _answer(request, b"", status=302, headers={"Location": "/login"})
        if _form_body(request).get("csrf_token") != "tok-7f3a9c2e":
            return refusal(request)
        return _answer(request, "<html><nav>Shop Account Orders</nav><p>Your email was updated</p></html>")
    return respond


def _csrf_form(respond, **extra):
    values = {"method": "POST", "path": "/account/email",
              "form_body": {"email": "a@example.test", "csrf_token": "tok-7f3a9c2e"},
              "_headers": {"Cookie": "session=abcdefgh12345678"}, **extra}
    return _run("csrf", values, respond, request_class="confirmed_mutation")


@pytest.mark.parametrize("refusal", [
    # The same status and layout, with a sentence saying the token was wrong.
    lambda request: _answer(request, "<html><nav>Shop Account Orders</nav><p>Invalid CSRF token</p></html>"),
    # A redirect like any other accepted form, back to the form instead of onwards.
    lambda request: _answer(request, b"", status=302, headers={"Location": "/account/email?error=1"}),
    lambda request: _answer(request, b"", status=403),
], ids=["error-page-200", "redirect-to-form", "forbidden"])
def test_csrf_is_not_proved_when_the_token_is_checked_although_the_planner_named_no_token_field(refusal):
    result, transport = _csrf_form(_token_checked(refusal))
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "cross_site_refused"
    assert result.observations[0]["anti_csrf_fields_removed"] == ["csrf_token"]
    # The original keeps its token; no forged request carries it.
    assert _form_body(transport.requests[0])["csrf_token"] == "tok-7f3a9c2e"
    assert all("csrf_token" not in _form_body(item) and _form_body(item)["email"] == "a@example.test"
               for item in transport.requests[1:])


def test_csrf_is_proved_when_the_token_field_is_sent_but_never_checked():
    def unchecked(request):
        if not _header(request, "Cookie"):
            return _answer(request, b"", status=302, headers={"Location": "/login"})
        return _answer(request, b"", status=302, headers={"Location": "/account/saved"})
    result, transport = _csrf_form(unchecked)
    proof = _verified(result)[0]
    assert proof["anti_csrf_fields_removed"] == ["csrf_token"] and proof["token_field_removed"] is True
    assert proof["session_cookie_same_site"] == "not_observed"
    assert "csrf_token" not in _form_body(transport.requests[1])


def test_csrf_proves_nothing_from_a_redirect_back_to_the_requests_own_page():
    """Accepted or refused, the form answers with a redirect to itself: the answer shows no write."""
    def same_page(request):
        if not _header(request, "Cookie"):
            return _answer(request, b"", status=302, headers={"Location": "/login"})
        return _answer(request, b"", status=302, headers={"Location": "/account/email"})
    result, transport = _csrf_form(same_page)
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "redirect_to_own_page_shows_no_write"
    assert len(transport.requests) == 1  # nothing forged was sent


def test_csrf_is_not_proved_when_the_session_cookie_is_same_site():
    def lax(request):
        if not _header(request, "Cookie"):
            return _answer(request, b'{"error": "unauthenticated"}', status=401, content_type="application/json")
        return _answer(request, b'{"changed": true}', content_type="application/json",
                       headers={"Set-Cookie": "session=abcdefgh12345678; Path=/; HttpOnly; SameSite=Lax"})
    result, _ = _csrf(lax)
    assert not _verified(result)
    assert result.observations[0]["not_proven_reason"] == "session_cookie_same_site"
    assert result.observations[0]["same_site_cookie"] == "session"

    def unrelated(request):  # another cookie's attribute says nothing about the session's
        answer = _account()(request)
        return _answer(request, answer.response_body, status=answer.status_code, content_type="application/json",
                       headers={"Set-Cookie": "theme=dark; SameSite=Strict"})
    assert _verified(_csrf(unrelated)[0])[0]["session_cookie_same_site"] == "not_observed"


def test_anti_csrf_fields_are_recognised_by_name_in_the_query_a_form_and_json():
    from api.capabilities.request_verify import _anti_csrf_name, _without_anti_csrf_fields
    for name in ("csrf", "_csrf", "csrf_token", "csrfmiddlewaretoken", "X-XSRF-TOKEN", "_token", "token",
                 "authenticity_token", "__RequestVerificationToken", "_wpnonce", "nonce", "form_key", "sesskey"):
        assert _anti_csrf_name(name), name
    for name in ("email", "name", "tokens_per_minute", "description", "announcement", "state", "id"):
        assert not _anti_csrf_name(name), name
    request = build_request(
        {"method": "POST", "path": "/api/profile", "query": {"_csrf": "q1", "page": "2"},
         "json_body": {"name": "a", "meta": {"authenticity_token": "t", "keep": 1}, "items": [{"nonce": "n", "x": 1}]}},
        base_url=ORIGIN + "/", headers={"Cookie": "s=1"}, action_id="a")
    stripped, removed, complete = _without_anti_csrf_fields(request)
    assert complete and sorted(removed) == ["_csrf", "authenticity_token", "nonce"]
    assert urllib.parse.urlsplit(stripped.url).query == "page=2"
    assert json.loads(stripped.body) == {"name": "a", "meta": {"keep": 1}, "items": [{"x": 1}]}
    # A multipart body is not rewritten: a token in it means the forgery cannot be built.
    from dataclasses import replace
    multipart = replace(request, url=ORIGIN + "/api/profile", headers=(("Content-Type", "multipart/form-data; boundary=b"),),
                        body=b'--b\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\nt\r\n--b--\r\n')
    assert _without_anti_csrf_fields(multipart)[1:] == (["csrf_token"], False)


# -- budget and cancellation -----------------------------------------------------------------

def test_request_budget_is_never_exceeded():
    result, transport = _run("rate_limit", {"method": "POST", "path": "/login",
                                            "form_body": {"username": "alice", "password": "x"}},
                             _login(), field="password", budget=6, request_class="safe_authentication")
    assert len(transport.requests) <= 6
    assert result.actual_budget["http_requests"] == len(transport.requests)
    assert not _verified(result)


def test_a_refused_baseline_is_inconclusive_and_sends_nothing_more():
    result, transport = _run("cors", {"path": "/api/me"},
                             lambda request: _answer(request, b"", status=401, headers={"WWW-Authenticate": "Bearer"}))
    assert len(transport.requests) == 1
    assert result.observations[0]["finding_verdict"] == "inconclusive"


def test_no_check_can_send_more_than_its_request_budget(monkeypatch):
    async def greedy(self, baseline):
        for _ in range(20):
            await self.send(self.request)
        return [self.observation()]
    monkeypatch.setattr(RequestVerifier, "run", greedy)
    result, transport = _run("cors", {"path": "/"}, lambda request: _answer(request, b"{}"), budget=5)
    assert len(transport.requests) == 5 and result.actual_budget["http_requests"] == 5
    assert result.status == "partial" and "budget_exhausted" in result.errors


# -- JWT -------------------------------------------------------------------------------------

def _token():
    import base64

    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()
    return part({"alg": "HS256", "typ": "JWT"}) + "." + part({"sub": "alice"}) + ".c2lnbmF0dXJl"


def _whoami(verifies_signature):
    good = _token()

    def respond(request):
        auth = _header(request, "Authorization") or ""
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token or (verifies_signature and token != good):
            return _answer(request, b'{"error": "unauthorized"}', status=401, content_type="application/json")
        return _answer(request, b'{"user": "alice"}', content_type="application/json")
    return respond


def test_jwt_accepted_with_an_altered_signature_twice_and_refused_without_it():
    result, transport = _run("jwt", {"path": "/api/whoami", "_headers": {"Authorization": "Bearer " + _token()}},
                             _whoami(verifies_signature=False))
    proof = _verified(result)[0]
    assert proof["technique"] == "jwt_signature_not_verified_repeated"
    assert any(_header(item, "Authorization") is None for item in transport.requests)


def test_jwt_whose_signature_is_checked_proves_nothing():
    result, _ = _run("jwt", {"path": "/api/whoami", "_headers": {"Authorization": "Bearer " + _token()}},
                     _whoami(verifies_signature=True))
    assert not _verified(result)
