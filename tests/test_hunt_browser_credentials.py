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
    prepared = SimpleNamespace(session_ref="session", capability_name="browser.interact", target=target)
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
        assert headers == {}
        assert calls[-1] == "closed"
