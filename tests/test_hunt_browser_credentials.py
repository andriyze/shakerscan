import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from api.hunt import browser_credentials as module


@pytest.mark.parametrize("revoked", [False, True])
def test_browser_rechecks_live_authority_and_exact_session_capability(monkeypatch, revoked):
    calls = []
    headers = {"authorization": "Bearer worker-only"}
    class Session:
        def headers(self): return headers
        def close(self): calls.append("closed")
    class Store:
        async def load_for_worker(self, conn, **kwargs):
            calls.append(("load", kwargs))
            return Session()
    async def validate(conn, **kwargs):
        calls.append(("validate", kwargs))
        if revoked: raise ValueError("revoked")
    class Pool:
        @asynccontextmanager
        async def acquire(self): yield object()
    monkeypatch.setattr(module, "PostgresAuthSessionStore", Store)
    monkeypatch.setattr(module, "validate_worker_credential_authority", validate)
    target = SimpleNamespace(scope_receipt_id="scope")
    prepared = SimpleNamespace(session_ref="session", capability_name="browser.interact", target=target,
                               origin="https://fixture.example.test:8443")
    async def run():
        async with module.browser_session_headers(Pool(), prepared=prepared, hunt_id="hunt", policy=SimpleNamespace(approval_receipt_id="approval")) as resolved:
            assert resolved["authorization"] == "Bearer worker-only"
            raise RuntimeError("browser failed after credentials loaded")
    with pytest.raises(ValueError if revoked else RuntimeError): asyncio.run(run())
    assert calls[0][1]["approval_receipt_id"] == "approval"
    assert calls[0][1]["scope_receipt_id"] == "scope"
    assert calls[0][1]["action_name"] == "hunt.capability:browser.interact"
    if revoked:
        assert len(calls) == 1  # No decrypt after failed live approval check.
    else:
        assert calls[1][1]["capability"] == "browser.interact"
        assert calls[1][1]["owner_id"] == "hunt"
        assert calls[1][1]["target"] is target
        assert calls[1][1]["selected_origins"] == ("https://fixture.example.test:8443",)
        assert headers == {}
        assert calls[-1] == "closed"


@pytest.mark.parametrize(("message", "code"), [
    ("authentication session is incompatible with the capability",
     "auth_session_capability_not_allowed"),
    ("authentication session profile no longer allows the capability",
     "auth_session_capability_not_allowed"),
    ("authentication session is expired or revoked", "auth_session_expired"),
])
def test_a_refused_browser_session_names_the_reason_and_sends_nothing(message, code):
    """A session the store refuses ends the browser action with its reason, before any request.

    The refusal escaped the adapter as a bare ``adapter_fault:AuthSessionStoreError``, so neither
    the agent nor the operator learned that the session's profile does not allow the browser.
    """
    from api.capabilities import browser

    # The store error class exactly as the browser module imported it (import layouts differ).
    AuthSessionStoreError = getattr(browser, "AuthSessionStoreError", RuntimeError)

    @asynccontextmanager
    async def refused_loader():
        raise AuthSessionStoreError(message)
        yield {}

    async def never(*_args, **_kwargs):
        raise AssertionError("no browser traffic after a refused session")

    prepared = SimpleNamespace(session_ref="session", parser_version="browser-navigation/v1",
                               redacted_execution={"origin": "https://fixture.example.test"})
    original = browser._execute_browser_action
    browser._execute_browser_action = never
    try:
        result = asyncio.run(browser._execute_browser_with_session(
            prepared, session_loader=refused_loader, heartbeat=None, cancelled=lambda: False,
        ))
    finally:
        browser._execute_browser_action = original
    assert result.status == "failed"
    assert result.errors == (code,)
    assert result.execution_started is False
    assert dict(result.actual_budget) == {}
