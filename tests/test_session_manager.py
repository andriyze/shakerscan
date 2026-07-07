import asyncio
import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from session_manager import InteractiveSession


def test_endpoint_rejects_unknown_authenticated_user_before_anonymous_request():
    session = InteractiveSession("session-test", "https://app.example.test")

    result = asyncio.run(session.test_endpoint("/api/orders/1", as_user="user2"))

    assert result["success"] is False
    assert result["auth_required"] is True
    assert result["authenticated_user"] is False
    assert "not available" in result["error"]
    assert session._pages == {}
