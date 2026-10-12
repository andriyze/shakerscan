"""The trusted-gateway operator identity (api/gateway_identity.py).

Unit tests drive the ASGI middleware directly with a recording inner app (a test double, not the
engine). The test vector at the end is pinned in the Enterprise gateway's tests too, so both
sides compute the same assertion.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

import gateway_identity  # noqa: E402
from gateway_identity import (  # noqa: E402
    GatewayIdentityMiddleware, KEY_ENV, SCOPE_KEY, assertion, capture_key, configured_keys, decoded_operator,
    forget_key, operator_identity, signature,
)


@pytest.fixture(autouse=True)
def _no_captured_key():
    forget_key()
    yield
    forget_key()

KEY = b"k" * 64
OTHER = b"o" * 64
PATH = "/targets/0f5d2c3e-4a1b-4c8d-9e7f-0a1b2c3d4e5f/instruction-proposals/1a2b3c4d-1111-4222-8333-444455556666/accept"
NOW = 1_760_000_000.0


class Recorder:
    """The application behind the middleware (a test double): records the scope it receives."""

    def __init__(self) -> None:
        self.scopes: list[dict] = []

    async def __call__(self, scope, receive, send) -> None:
        self.scopes.append(scope)


def _scope(headers: list[tuple[bytes, bytes]], *, method: str = "POST", path: str = PATH, **extra) -> dict:
    return {"type": "http", "method": method, "path": path, "headers": headers, **extra}


def _run(middleware: GatewayIdentityMiddleware, scope: dict) -> dict:
    inner = middleware.app
    asyncio.run(middleware(scope, None, None))
    return inner.scopes[-1]


def _signed(operator: str = "Carol (local:carol)", *, key: bytes = KEY, method: str = "POST",
            path: str = PATH, now: float = NOW, nonce: str | None = None) -> list[tuple[bytes, bytes]]:
    return [(b"x-shakerscan-operator", operator.encode()),
            (b"X-ShakerScan-Operator-Assertion",
             assertion(key, method, path, operator, now=now, nonce=nonce).encode()),
            (b"content-type", b"application/json")]


def _middleware(keys=(KEY,), now: float = NOW) -> GatewayIdentityMiddleware:
    return GatewayIdentityMiddleware(Recorder(), keys=keys, clock=lambda: now)


def test_a_valid_assertion_names_the_operator_and_the_headers_never_reach_the_app():
    seen = _run(_middleware(), _scope(_signed()))
    assert seen[SCOPE_KEY] == "Carol (local:carol)"
    assert seen["headers"] == [(b"content-type", b"application/json")]
    assert operator_identity(SimpleNamespace(scope=seen)) == "Carol (local:carol)"


def test_without_a_key_the_headers_are_removed_and_nothing_is_trusted(monkeypatch):
    monkeypatch.delenv(KEY_ENV, raising=False)
    middleware = GatewayIdentityMiddleware(Recorder(), clock=lambda: NOW)
    seen = _run(middleware, _scope(_signed(), **{SCOPE_KEY: "smuggled"}))
    assert SCOPE_KEY not in seen
    assert [name for name, _ in seen["headers"]] == [b"content-type"]


def test_the_key_comes_from_the_environment_and_a_short_one_is_ignored(monkeypatch):
    middleware = GatewayIdentityMiddleware(Recorder(), clock=lambda: NOW)
    monkeypatch.setenv(KEY_ENV, "short")
    assert SCOPE_KEY not in _run(middleware, _scope(_signed(key=b"short")))
    monkeypatch.setenv(KEY_ENV, KEY.decode())
    assert _run(middleware, _scope(_signed()))[SCOPE_KEY] == "Carol (local:carol)"
    # Rotation: during the overlap either key verifies.
    monkeypatch.setenv(KEY_ENV, f"{OTHER.decode()}, {KEY.decode()}")
    assert _run(middleware, _scope(_signed(key=OTHER)))[SCOPE_KEY] == "Carol (local:carol)"
    assert _run(middleware, _scope(_signed()))[SCOPE_KEY] == "Carol (local:carol)"
    monkeypatch.setenv(KEY_ENV, OTHER.decode())
    assert SCOPE_KEY not in _run(middleware, _scope(_signed()))
    assert configured_keys("") == () and configured_keys(" , ,") == ()


@pytest.mark.parametrize("change", [
    {"key": OTHER},
    {"method": "PUT"},
    {"path": PATH.replace("accept", "reject")},
    {"now": NOW - 61},
    {"now": NOW + 61},
])
def test_a_signature_for_anything_else_is_ignored(change):
    seen = _run(_middleware(), _scope(_signed(**change)))
    assert SCOPE_KEY not in seen
    assert [name for name, _ in seen["headers"]] == [b"content-type"]


def test_the_operator_value_is_signed():
    headers = _signed()
    headers[0] = (b"x-shakerscan-operator", b"Mallory (local:mallory)")
    assert SCOPE_KEY not in _run(_middleware(), _scope(headers))


def test_a_replayed_assertion_is_ignored_and_a_fresh_nonce_is_not():
    middleware = _middleware()
    headers = _signed(nonce="0" * 32)
    assert _run(middleware, _scope(list(headers)))[SCOPE_KEY] == "Carol (local:carol)"
    assert SCOPE_KEY not in _run(middleware, _scope(list(headers)))
    assert _run(middleware, _scope(_signed(nonce="1" * 32)))[SCOPE_KEY] == "Carol (local:carol)"


@pytest.mark.parametrize("headers", [
    [(b"x-shakerscan-operator", b"Carol")],
    [(b"x-shakerscan-operator-assertion", b"t=1,n=" + b"0" * 32 + b",s=" + b"0" * 64)],
    _signed() + [(b"x-shakerscan-operator", b"Mallory")],
    _signed() + _signed()[1:2],
    [(b"x-shakerscan-operator", "Zoë".encode()), _signed("Zo%C3%AB")[1]],
    [(b"x-shakerscan-operator", b"a\r\nb"), _signed("a\r\nb")[1]],
    [(b"x-shakerscan-operator", b" Carol"), _signed(" Carol")[1]],
    [(b"x-shakerscan-operator", b"x" * 201), _signed("x" * 201)[1]],
    [(b"x-shakerscan-operator", b"a%0Ab"), _signed("a%0Ab")[1]],
    [(b"x-shakerscan-operator", b"a%E2%80%AEb"), _signed("a%E2%80%AEb")[1]],
    [(b"x-shakerscan-operator", b"a%FFb"), _signed("a%FFb")[1]],
    [_signed()[0], (b"x-shakerscan-operator-assertion", b"t=1760000000,s=" + b"0" * 64)],
    [_signed()[0], (b"x-shakerscan-operator-assertion", _signed()[1][1].upper())],
    [_signed()[0], (b"x-shakerscan-operator-assertion", _signed()[1][1] + b",x=1")],
], ids=["operator-only", "assertion-only", "repeated-operator", "repeated-assertion", "not-ascii",
        "control-characters", "leading-space", "too-long", "encoded-newline", "encoded-bidi",
        "encoded-not-utf8", "no-nonce", "upper-case", "trailing-field"])
def test_malformed_or_ambiguous_headers_are_ignored(headers):
    seen = _run(_middleware(), _scope(headers))
    assert SCOPE_KEY not in seen
    assert not [name for name, _ in seen["headers"] if name.lower().startswith(b"x-shakerscan-operator")]


def test_other_scopes_pass_untouched_and_websockets_are_stripped_too():
    middleware = _middleware()
    lifespan = {"type": "lifespan"}
    assert _run(middleware, lifespan) is lifespan
    seen = _run(middleware, {"type": "websocket", "path": PATH, "headers": _signed(method="GET")})
    assert seen[SCOPE_KEY] == "Carol (local:carol)"
    assert [name for name, _ in seen["headers"]] == [b"content-type"]


def test_the_nonce_table_is_bounded(monkeypatch):
    monkeypatch.setattr(gateway_identity, "MAX_REMEMBERED_NONCES", 2)
    clock = [NOW]
    middleware = GatewayIdentityMiddleware(Recorder(), keys=(KEY,), clock=lambda: clock[0])
    assert SCOPE_KEY in _run(middleware, _scope(_signed(nonce="1" * 32)))
    assert SCOPE_KEY in _run(middleware, _scope(_signed(nonce="2" * 32)))
    # Full of live nonces: nothing more is trusted until they expire.
    assert SCOPE_KEY not in _run(middleware, _scope(_signed(nonce="3" * 32)))
    clock[0] = NOW + 200
    assert SCOPE_KEY in _run(middleware, _scope(_signed(nonce="4" * 32, now=NOW + 200)))


def test_the_engine_app_registers_it_outermost():
    """Starlette wraps the last-added middleware around the rest: it must be this one, so no
    other layer reads the identity headers first (a source check; importing api.api here would
    mix the two import layouts the suite runner keeps apart)."""
    import ast
    tree = ast.parse((ROOT / "api" / "api.py").read_text())
    added = [node.args[0].id for node in ast.walk(tree)
             if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "add_middleware"
             and node.args and isinstance(node.args[0], ast.Name)]
    assert added[-1] == "GatewayIdentityMiddleware" and added.count("GatewayIdentityMiddleware") == 1
    source = (ROOT / "api" / "api.py").read_text()
    assert source.rindex("app.add_middleware(GatewayIdentityMiddleware)") > source.rindex("configure_host_guard(app")


def test_discovery_records_the_verified_operator_else_local_operator():
    sys.path.insert(0, str(ROOT / "api"))
    from operations.discovery import DEFAULT_REQUESTER, requester
    assert requester() == DEFAULT_REQUESTER == "local-operator"
    assert requester(SimpleNamespace(scope={})) == "local-operator"
    assert requester(SimpleNamespace(scope={SCOPE_KEY: "Carol (local:carol)"})) == "Carol (local:carol)"
    assert requester(SimpleNamespace(scope={SCOPE_KEY: "  "})) == "local-operator"
    assert requester(SimpleNamespace(scope={SCOPE_KEY: 7})) == "local-operator"


def test_the_contract_test_vector():
    """Pinned in the Enterprise gateway's tests (test_terminal_knowledge.py) as well."""
    value = signature(b"0123456789abcdef0123456789abcdef", "POST",
                      "/targets/0f5d2c3e-4a1b-4c8d-9e7f-0a1b2c3d4e5f/skill/confirm",
                      "Carol (local:carol)", "1760000000", "00112233445566778899aabbccddeeff")
    assert value == "a0c8ae1ee9de10f46fcf5de5e1229b3f3c5ad8cfe29bb4a856349f79d9cccec4"


def test_child_processes_of_the_api_never_inherit_the_key():
    """command_arsenal._safe_local_agent_env strips variables whose names contain a marker."""
    import ast
    tree = ast.parse((ROOT / "api" / "command_arsenal.py").read_text())
    markers = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Assign)
                   and any(getattr(t, "id", "") == "_SENSITIVE_ENV_MARKERS" for t in node.targets))
    values = {element.value for element in markers.elts}
    assert any(marker in KEY_ENV for marker in values)


def test_a_non_ascii_name_travels_percent_encoded_and_is_decoded():
    seen = _run(_middleware(), _scope(_signed("Zo%C3%AB (local:zoe) via service token")))
    assert seen[SCOPE_KEY] == "Zoë (local:zoe) via service token"
    assert _run(_middleware(), _scope(_signed("100%25 sure")))[SCOPE_KEY] == "100% sure"
    assert decoded_operator("%" * 3) is None and decoded_operator("a" * 201) is None


def test_the_key_is_taken_out_of_the_process_environment(monkeypatch):
    import os
    monkeypatch.setenv(KEY_ENV, KEY.decode())
    assert capture_key() == KEY.decode()
    assert KEY_ENV not in os.environ, "a child process started now cannot inherit it"
    middleware = GatewayIdentityMiddleware(Recorder(), clock=lambda: NOW)
    assert _run(middleware, _scope(_signed()))[SCOPE_KEY] == "Carol (local:carol)"
    forget_key()
    assert SCOPE_KEY not in _run(middleware, _scope(_signed(nonce="9" * 32)))
