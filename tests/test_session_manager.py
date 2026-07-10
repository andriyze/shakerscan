import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from session_manager import InteractiveSession, UserSession


def test_endpoint_rejects_unknown_authenticated_user_before_anonymous_request():
    session = InteractiveSession("session-test", "https://app.example.test")

    result = asyncio.run(session.test_endpoint("/api/orders/1", as_user="user2"))

    assert result["success"] is False
    assert result["auth_required"] is True
    assert result["authenticated_user"] is False
    assert "not available" in result["error"]
    assert session._pages == {}


def test_managed_profile_auth_replaces_prior_identity_and_records_server_binding():
    session = InteractiveSession("session-test", "https://app.example.test")
    session.state.users["user1"] = UserSession(
        name="user1",
        cookies={"old": "cookie"},
        headers={"Authorization": "Bearer old"},
        is_authenticated=True,
        credential_profile_id="old-profile",
        principal_auth_state="user1",
    )

    class _Context:
        cleared = False

        async def clear_cookies(self):
            self.cleared = True

    context = _Context()
    session._contexts["user1"] = context
    page = type("Page", (), {"url": "https://app.example.test/account"})()

    result = asyncio.run(session._handle_set_auth(page, "user1", {
        "auth_header": "Bearer new",
        "_credential_profile_id": "new-profile",
        "_principal_auth_state": "user1",
        "_replace_auth_state": True,
    }))

    user = session.state.users["user1"]
    assert result["success"] is True
    assert context.cleared is True
    assert user.headers == {"Authorization": "Bearer new"}
    assert user.cookies == {}
    assert user.credential_profile_id == "new-profile"
    assert user.principal_auth_state == "user1"
