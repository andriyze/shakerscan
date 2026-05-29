"""Tests for login-page candidate scoring in form_login.

Guards against submitting credentials to the wrong form (e.g. an /account
settings page with a change-password field beating the real /login).
"""

import asyncio
from types import SimpleNamespace

from scanner.scanner_tools.form_login import _score_login_page, find_login_page


LOGIN_HTML = """
<html><body>
  <h1>Sign in</h1>
  <form action="/login" method="post">
    <input type="email" name="email">
    <input type="password" name="password">
    <button>Log in</button>
  </form>
</body></html>
"""

CHANGE_PASSWORD_HTML = """
<html><body>
  <h1>Account settings</h1>
  <form action="/account/password" method="post">
    <input type="password" name="current_password">
    <input type="password" name="new_password">
    <input type="password" name="confirm_password">
    <button>Change password</button>
  </form>
</body></html>
"""


def test_real_login_page_scores_higher_than_change_password():
    login_score = _score_login_page("https://app.test/login", LOGIN_HTML)
    settings_score = _score_login_page("https://app.test/account", CHANGE_PASSWORD_HTML)
    assert login_score > settings_score


def test_change_password_page_scores_low():
    assert _score_login_page("https://app.test/account", CHANGE_PASSWORD_HTML) < 0.5


def test_real_login_page_scores_high():
    # Single password + email field + login URL + keywords → high confidence.
    assert _score_login_page("https://app.test/login", LOGIN_HTML) >= 0.9


def test_find_login_page_prefers_real_login_over_settings():
    # /login 404s; /account (settings, change-password) AND base URL both
    # carry password fields. The scorer must still avoid the settings page.
    pages = {
        "https://app.test/account": (200, CHANGE_PASSWORD_HTML),
        "https://app.test/users/sign_in": (200, LOGIN_HTML),
        "https://app.test/": (200, CHANGE_PASSWORD_HTML),
    }

    class _FakeSession:
        async def get(self, url):
            status, body = pages.get(url, (404, ""))
            return {"status": status, "body": body}

    result = asyncio.run(find_login_page("https://app.test/", _FakeSession()))
    assert result == "https://app.test/users/sign_in"


def test_find_login_page_returns_none_without_password_field():
    class _FakeSession:
        async def get(self, url):
            return {"status": 200, "body": "<html><body>no form here</body></html>"}

    result = asyncio.run(find_login_page("https://app.test/", _FakeSession()))
    assert result is None
