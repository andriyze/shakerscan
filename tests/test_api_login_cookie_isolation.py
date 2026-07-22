"""Tests for per-candidate cookie isolation in api_login.

A single shared cookie jar across candidate endpoints lets a cookie set by
one endpoint (e.g. an anonymous session from /wp-login.php) leak into requests
to the next, which can produce a false "logged in via cookie" success
attributed to the wrong endpoint. api_login must clear the jar per candidate.
"""

import asyncio

import scanner.scanner_tools.api_auth as api_auth


class _FakeResponse:
    def __init__(self, status_code=401, headers=None, text="", set_cookies=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        # `resp.cookies` reflects only this response's Set-Cookie headers.
        self.cookies = set_cookies or {}

    def json(self):
        import json as _json
        return _json.loads(self.text) if self.text else {}


class _FakeCookies(dict):
    def clear(self):  # noqa: D401 - dict.clear already exists; explicit for clarity
        super().clear()


class _RecordingClient:
    """Fake httpx.AsyncClient that records the order of clears and posts.

    Simulates the first candidate setting an anonymous cookie; no candidate
    returns a real token, so login should fail. We assert the jar is cleared
    before each candidate's requests.
    """

    def __init__(self, *args, **kwargs):
        self.cookies = _FakeCookies()
        self.events: list[tuple[str, str]] = []
        self._seen_candidates: set[str] = set()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, data=None):
        self.events.append(("post", url))
        # First candidate hands out an anonymous cookie via the jar (simulating
        # a Set-Cookie that the client would persist), but no auth token.
        if url not in self._seen_candidates and not self.cookies:
            self._seen_candidates.add(url)
        # Response itself carries no Set-Cookie and no token -> not a success.
        return _FakeResponse(status_code=401, text='{"error":"invalid"}')


def test_api_login_clears_cookies_per_candidate(monkeypatch):
    recorder = {}

    def _factory(*args, **kwargs):
        client = _RecordingClient(*args, **kwargs)
        # Wrap clear() to log it on the shared event list.
        orig_clear = client.cookies.clear

        def _logged_clear():
            client.events.append(("clear", ""))
            orig_clear()

        client.cookies.clear = _logged_clear
        recorder["client"] = client
        return client

    monkeypatch.setattr(api_auth.httpx, "AsyncClient", _factory)

    result = asyncio.run(
        api_auth.api_login(
            base_url="https://app.test",
            username="alice",
            password="secret",
            max_candidates=3,
            max_attempts=6,
        )
    )

    # No real token/cookie success was returned.
    assert result.success is False

    events = recorder["client"].events
    posts = [e for e in events if e[0] == "post"]
    clears = [e for e in events if e[0] == "clear"]
    assert posts, "expected at least one login attempt"
    # A clear happens before the first post, and there is at least one clear
    # per distinct candidate URL touched.
    assert events[0][0] == "clear"
    distinct_candidates = {url for kind, url in events if kind == "post"}
    assert len(clears) >= len(distinct_candidates)


def test_api_login_clear_precedes_each_new_candidate(monkeypatch):
    def _factory(*args, **kwargs):
        client = _RecordingClient(*args, **kwargs)
        orig_clear = client.cookies.clear

        def _logged_clear():
            client.events.append(("clear", ""))
            orig_clear()

        client.cookies.clear = _logged_clear
        _factory.client = client
        return client

    monkeypatch.setattr(api_auth.httpx, "AsyncClient", _factory)

    asyncio.run(
        api_auth.api_login(
            base_url="https://app.test",
            username="alice",
            password="secret",
            max_candidates=3,
            max_attempts=9,
        )
    )

    events = _factory.client.events
    # Walk events: every time we see the first post for a new candidate URL,
    # the most recent prior event must be a clear (jar reset for that candidate).
    seen = set()
    for i, (kind, url) in enumerate(events):
        if kind == "post" and url not in seen:
            seen.add(url)
            # Find the immediately preceding event.
            assert i > 0 and events[i - 1][0] == "clear", (
                f"candidate {url} first post not preceded by a cookie clear"
            )


def test_api_login_never_follows_redirects_with_credentials(monkeypatch):
    """SCAN-03a: login POSTs carry the operator's credentials — a target-
    controlled 307/308 would re-send the credential body to an off-origin
    Location if the client followed redirects. The client must be constructed
    with follow_redirects=False.
    """
    captured = {}

    def _factory(*args, **kwargs):
        captured.update(kwargs)
        return _RecordingClient(*args, **kwargs)

    monkeypatch.setattr(api_auth.httpx, "AsyncClient", _factory)

    asyncio.run(
        api_auth.api_login(
            base_url="https://app.test",
            username="alice",
            password="secret",
            max_candidates=1,
            max_attempts=1,
        )
    )

    assert captured.get("follow_redirects") is False
