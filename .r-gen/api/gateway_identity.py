"""Operator identity asserted by a trusted gateway in front of the API (managed deployments).

The open-source engine has one implicit operator: it receives no verified per-person identity,
and routes that record who acted name their provenance (``operator:...-api``) or
``local-operator``. A managed deployment puts an authenticating gateway in front of the API (the
API is not reachable around it) and can tell the engine who the person is. This middleware is that
channel, and the only one:

* It is active only when ``SHAKERSCAN_GATEWAY_IDENTITY_KEY`` holds a key of at least 32
  characters (a comma-separated list during a key rotation: any of them verifies). Without a key it
  never sets an identity.
* The API takes the key out of its process environment at startup (``capture_key``), so no
  process the API starts inherits it.
* On every request it reads ``X-ShakerScan-Operator`` (the operator, at most 200 characters,
  UTF-8 percent-encoded into printable ASCII) and ``X-ShakerScan-Operator-Assertion: t=<unix seconds>,n=<32 hex nonce>,s=<64 hex>`` where
  ``s`` is HMAC-SHA256(key, method "\\n" path "\\n" operator "\\n" t "\\n" n) over the request's
  method, its path (``scope["path"]``, without the query string) and the header value. A valid
  signature no more than 60 seconds old (or ahead), whose nonce was not seen before by this
  process, sets ``scope["shakerscan.operator_identity"]`` to the decoded operator. Anything else (no key,
  a missing, repeated or malformed header, a wrong or stale signature, a replayed nonce) sets
  nothing: the routes fall back to their own provenance names. Invalid assertions are logged
  without their values.
* It always removes both headers before the application sees the request, and removes any
  identity already in the scope, key or no key: a client can never supply an identity by header.

The identity is attribution (``decided_by``, ``proposed_by``, ``recorded_by``, ``requested_by``),
never authorization: the engine's routes decide what is allowed exactly as without it. Replay
protection is per process: with several API worker processes, a captured assertion could be
replayed once more to another worker within its 60 seconds, by someone who can already reach the
API behind the gateway.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
from typing import Any, Callable, Iterable

KEY_ENV = "SHAKERSCAN_GATEWAY_IDENTITY_KEY"
SCOPE_KEY = "shakerscan.operator_identity"
OPERATOR_HEADER = b"x-shakerscan-operator"
ASSERTION_HEADER = b"x-shakerscan-operator-assertion"
MAX_AGE_SECONDS = 60
MIN_KEY_CHARACTERS = 32
MAX_OPERATOR_CHARACTERS = 200
MAX_REMEMBERED_NONCES = 100_000
# The header value: printable ASCII, UTF-8 percent-encoded (the gateway encodes "%" and every
# non-ASCII character), decoded after the signature over the encoded value is checked.
_OPERATOR = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,1998}[\x21-\x7e])?")
# The process's key, taken out of os.environ (capture_key) so no child process the API starts can
# inherit it, whatever environment that child is given.
_captured: str | None = None


def capture_key() -> str:
    """The key from SHAKERSCAN_GATEWAY_IDENTITY_KEY, removed from this process's environment the
    first time it is seen there (again if it is set again); the last one captured otherwise."""
    global _captured
    raw = os.environ.pop(KEY_ENV, None)
    if raw is not None:
        _captured = raw
    return _captured or ""


def forget_key() -> None:
    """Drop the captured key (tests; a process that should stop trusting the gateway)."""
    global _captured
    _captured = None


def decoded_operator(value: str) -> str | None:
    """The operator a verified header names: percent-decoded UTF-8, at most 200 characters, with
    no control, bidirectional or invisible formatting character; None for anything else."""
    import unicodedata
    from urllib.parse import unquote
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None  # a "%" the gateway did not encode
    try:
        text = unquote(value, encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None
    if (not text or text != text.strip() or len(text) > MAX_OPERATOR_CHARACTERS
            or any(ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0
                   or unicodedata.category(ch) in {"Cf", "Zl", "Zp", "Cs"} for ch in text)):
        return None
    return text
_ASSERTION = re.compile(r"t=([0-9]{1,12}),n=([0-9a-f]{32}),s=([0-9a-f]{64})")

LOGGER = logging.getLogger("shakerscan.gateway_identity")


def configured_keys(value: str | None = None) -> tuple[bytes, ...]:
    """The verification keys from ``SHAKERSCAN_GATEWAY_IDENTITY_KEY`` (or ``value``); empty when
    none is set. A key shorter than MIN_KEY_CHARACTERS is ignored (and said so)."""
    raw = os.environ.get(KEY_ENV, "") if value is None else value
    keys = []
    for item in str(raw or "").split(","):
        item = item.strip()
        if not item:
            continue
        if len(item) < MIN_KEY_CHARACTERS:
            LOGGER.warning("gateway_identity_key_ignored reason=too_short minimum=%d", MIN_KEY_CHARACTERS)
            continue
        keys.append(item.encode("utf-8"))
    return tuple(keys)


def signature(key: bytes, method: str, path: str, operator: str, timestamp: str, nonce: str) -> str:
    """The assertion's ``s``: what the gateway computes and the engine checks."""
    message = "\n".join((method.upper(), path, operator, timestamp, nonce)).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def assertion(key: bytes, method: str, path: str, operator: str, *, now: float | None = None,
              nonce: str | None = None) -> str:
    """An ``X-ShakerScan-Operator-Assertion`` value (the gateway's side; used by tests here)."""
    stamp = str(int(time.time() if now is None else now))
    nonce = nonce or os.urandom(16).hex()
    return f"t={stamp},n={nonce},s={signature(key, method, path, operator, stamp, nonce)}"


def operator_identity(request: Any) -> str | None:
    """The verified operator this middleware put in the request's scope, or None."""
    scope = getattr(request, "scope", None)
    value = scope.get(SCOPE_KEY) if isinstance(scope, dict) else None
    return value[:MAX_OPERATOR_CHARACTERS] if isinstance(value, str) and value else None


class GatewayIdentityMiddleware:
    """See the module docstring. Register it outermost so nothing reads the headers first."""

    def __init__(self, app: Any, *, keys: Iterable[bytes] | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self.app = app
        # Keys given here are fixed; otherwise the environment is read (and parsed again only
        # when it changes), so the middleware never holds a key the process no longer has.
        self._fixed = tuple(keys) if keys is not None else None
        self._raw: str | None = None
        self._parsed: tuple[bytes, ...] = ()
        self.clock = clock
        self._nonces: dict[str, float] = {}
        self._last_warning: dict[str, float] = {}

    @property
    def keys(self) -> tuple[bytes, ...]:
        if self._fixed is not None:
            return self._fixed
        raw = capture_key()
        if raw != self._raw:
            self._raw, self._parsed = raw, configured_keys(raw)
        return self._parsed

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") not in {"http", "websocket"}:
            await self.app(scope, receive, send)
            return
        found: dict[bytes, list[bytes]] = {OPERATOR_HEADER: [], ASSERTION_HEADER: []}
        kept = []
        for name, value in scope.get("headers") or ():
            lowered = bytes(name).lower()
            if lowered in found:
                found[lowered].append(bytes(value))
            else:
                kept.append((name, value))
        scope = dict(scope)
        scope["headers"] = kept
        scope.pop(SCOPE_KEY, None)
        keys = self.keys
        if keys and (found[OPERATOR_HEADER] or found[ASSERTION_HEADER]):
            identity = self._verify(keys, scope, found[OPERATOR_HEADER], found[ASSERTION_HEADER])
            if identity is not None:
                scope[SCOPE_KEY] = identity
        await self.app(scope, receive, send)

    def _warn(self, reason: str) -> None:
        now = time.monotonic()
        if now - self._last_warning.get(reason, -3600.0) >= 60:
            self._last_warning[reason] = now
            LOGGER.warning("gateway_identity_ignored reason=%s", reason)

    def _verify(self, keys: tuple[bytes, ...], scope: dict[str, Any], operators: list[bytes],
                assertions: list[bytes]) -> str | None:
        if len(operators) != 1 or len(assertions) != 1:
            self._warn("missing_or_repeated_header")
            return None
        try:
            operator = operators[0].decode("ascii")
            presented = assertions[0].decode("ascii")
        except UnicodeDecodeError:
            self._warn("not_ascii")
            return None
        match = _ASSERTION.fullmatch(presented)
        if not _OPERATOR.fullmatch(operator) or not match:
            self._warn("malformed")
            return None
        stamp, nonce, given = match.groups()
        now = self.clock()
        if abs(now - int(stamp)) > MAX_AGE_SECONDS:
            self._warn("stale")
            return None
        method = str(scope.get("method") or ("GET" if scope.get("type") == "websocket" else ""))
        path = str(scope.get("path") or "")
        if not any(hmac.compare_digest(signature(key, method, path, operator, stamp, nonce), given)
                   for key in keys):
            self._warn("signature")
            return None
        identity = decoded_operator(operator)
        if identity is None:
            self._warn("malformed")
            return None
        if not self._remember(nonce, now):
            self._warn("replayed")
            return None
        return identity

    def _remember(self, nonce: str, now: float) -> bool:
        """Record ``nonce``; False when it was seen within its validity (a replay), or when the
        table is full of live nonces (then nothing is trusted until they expire)."""
        if nonce in self._nonces and self._nonces[nonce] > now:
            return False
        if len(self._nonces) >= MAX_REMEMBERED_NONCES:
            for key in [key for key, ends in self._nonces.items() if ends <= now]:
                del self._nonces[key]
            if len(self._nonces) >= MAX_REMEMBERED_NONCES:
                return False
        # A nonce stays remembered for as long as its timestamp could still be accepted.
        self._nonces[nonce] = now + 2 * MAX_AGE_SECONDS + 1
        return True


__all__ = [
    "ASSERTION_HEADER", "GatewayIdentityMiddleware", "KEY_ENV", "MAX_AGE_SECONDS", "OPERATOR_HEADER",
    "SCOPE_KEY", "assertion", "capture_key", "configured_keys", "decoded_operator", "forget_key",
    "operator_identity", "signature",
]
