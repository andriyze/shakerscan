"""Does the application check the signature of the JSON Web Token it is given?

Run with the signed-in principal's own bearer token against one route that refuses an anonymous
request and answers that principal. Three questions, in order; the first that is answered yes is
the finding and nothing further is sent:

1. **Is the signature checked at all?** The principal's token with its signature altered must be
   refused. Accepted twice: the application trusts whatever the token says.
2. **Is ``alg: none`` accepted?** The same claims under a header that names no algorithm and
   carries no signature, in the four spellings libraries have accepted.
3. **Is the signing secret guessable?** For an HMAC token the signature is recomputed offline with
   a short list of well-known secrets. A match is arithmetic, not an inference: whoever knows the
   secret can sign any claims. One token signed with it is then sent to show the application
   accepts it: the same claims, written with one byte of JSON whitespace added so the token is
   not the principal's own.

The claims are never changed or added to: no forged token names another user or role. A token is never kept or
reported, nor is a guessed secret: an observation holds statuses, the algorithm and which question
was answered.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any, Awaitable, Callable, Mapping

JWT_FORGERY_CONTRACT = "authz_surface_jwt_forgery/v1"  # the proof_contract of every observation
# The request without a bearer (1), the altered signature and its repeat (2), each ``none``
# spelling and the repeat of one accepted once (at most 8), the token signed with a guessed secret
# and its repeat (2).
MAXIMUM_REQUESTS = 13
MINIMUM_REQUESTS = 2
_NONE_SPELLINGS = ("none", "None", "NONE", "nOnE")
_HMAC = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
# Secrets shipped in tutorials, framework defaults and sample configuration. Deliberately short:
# this is a check for a secret nobody chose, not a cracking run.
WEAK_SECRETS: tuple[str, ...] = (
    "secret", "your-256-bit-secret", "your_jwt_secret", "jwt_secret", "jwtsecret", "jwt-secret",
    "secretkey", "secret_key", "secret-key", "mysecret", "my_secret", "my-secret", "supersecret",
    "super_secret", "super-secret", "changeme", "change_me", "changeit", "password", "passw0rd",
    "123456", "12345678", "1234567890", "qwerty", "admin", "test", "testing", "dev", "development",
    "key", "private", "token", "jwt", "example", "default", "shhhhh", "s3cr3t", "topsecret",
    "keyboard cat", "random", "access_secret", "refresh_secret", "ThisIsASecret", "SECRET_KEY",
    "JWT_SECRET", "", "null", "undefined",
)


def _decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def bearer_jwt(headers: Any) -> str | None:
    """The JSON Web Token of an ``Authorization: Bearer`` header, or None.

    Only a signed token in compact form (three parts, a JSON header naming an algorithm, JSON
    claims): an opaque session token or an encrypted token (five parts) is not one.
    """
    pairs = headers.items() if isinstance(headers, Mapping) else (headers or ())
    for name, value in pairs:
        if str(name).lower() != "authorization":
            continue
        scheme, _space, token = str(value).strip().partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or len(token) > 8_192 or token.count(".") != 2:
            return None
        head, claims, _signature = token.split(".")
        try:
            header = json.loads(_decode(head))
            payload = json.loads(_decode(claims))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return None
        if isinstance(header, dict) and isinstance(payload, dict) and isinstance(header.get("alg"), str):
            return token
        return None
    return None


def algorithm(token: str) -> str:
    return str(json.loads(_decode(token.split(".")[0])).get("alg") or "")[:20]


def altered_signature(token: str) -> str:
    """``token`` with one byte of its signature changed (a token without one gets a wrong one)."""
    head, claims, signature = token.split(".")
    try:
        raw = bytearray(_decode(signature))
    except (ValueError, binascii.Error):
        raw = bytearray()
    if raw:
        raw[len(raw) // 2] ^= 0x01
    else:
        raw = bytearray(b"\x00" * 32)
    return f"{head}.{claims}.{_encode(bytes(raw))}"


def unsigned(token: str, spelling: str) -> str:
    """The same claims under a header that names no algorithm, with an empty signature."""
    header = dict(json.loads(_decode(token.split(".")[0])))
    header["alg"] = spelling
    head = _encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    return f"{head}.{token.split('.')[1]}."


def guessed_secret(token: str) -> str | None:
    """The listed secret that reproduces an HMAC token's signature, offline; None otherwise."""
    head, claims, signature = token.split(".")
    digest = _HMAC.get(algorithm(token))
    if digest is None:
        return None
    try:
        expected = _decode(signature)
    except (ValueError, binascii.Error):
        return None
    signing_input = f"{head}.{claims}".encode("ascii", errors="ignore")
    for secret in WEAK_SECRETS:
        if hmac.compare_digest(hmac.new(secret.encode("utf-8"), signing_input, digest).digest(), expected):
            return secret
    return None


def signed_with(token: str, secret: str) -> str:
    """``token``'s own claims, signed with ``secret`` under its own algorithm.

    The claims document gains one trailing space, which JSON ignores: the same claims, but not
    the principal's own token, whose signature the target has already seen.
    """
    head, claims, _signature = token.split(".")
    body = _encode(_decode(claims) + b" ")
    signing_input = f"{head}.{body}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, _HMAC[algorithm(token)]).digest()
    return f"{head}.{body}.{_encode(signature)}"


# ``send(token)`` requests the route with that bearer token, every other header of the principal
# unchanged; ``send(None)`` sends those other headers with no Authorization header at all. Both
# answer ``(status, keyed body digest)``, the status None for no answer.
Send = Callable[[str | None], Awaitable[tuple[int | None, str]]]


async def check_token_handling(
    token: str, *, send: Send, accepted_status: int, accepted_digest: str,
    left: Callable[[], int],
) -> dict[str, Any] | None:
    """A verified observation when the route accepts a token it should refuse, else None.

    ``accepted_status`` and ``accepted_digest`` are what the route answers the principal's own
    token. A forged token is accepted only when it gets exactly that answer, body included,
    twice: an API that answers a bad token 200 with an error document did not accept it.

    The token must be what authenticates the principal there. The request is first sent with
    every other header the principal carries (a session cookie, an API key) and no bearer: a
    route that still answers the principal's page does not read the token, so nothing it does
    with a forged one says anything about its signature check.
    """
    async def accepted_twice(forged: str) -> tuple[bool, int | None]:
        first = await send(forged)
        if first != (accepted_status, accepted_digest) or left() < 1:
            return False, first[0]
        return (await send(forged)) == (accepted_status, accepted_digest), first[0]

    def observation(technique: str, forged_status: int | None, **fields: Any) -> dict[str, Any]:
        return {
            "kind": "authz_surface_proof", "proof_state": "verified", "finding_verdict": "verified",
            "proof_contract": JWT_FORGERY_CONTRACT, "technique": technique,
            "algorithm": algorithm(token), "authenticated_status": accepted_status,
            "forged_status": forged_status, "repetitions": 2, "secret_values_visible": False,
            **fields,
        }

    if left() < MINIMUM_REQUESTS + 1:
        return None
    without_bearer = await send(None)
    if without_bearer[0] is None or without_bearer == (accepted_status, accepted_digest):
        # No answer, or the principal's page without the token: the token is not what the
        # route checks.
        return None
    hit, status = await accepted_twice(altered_signature(token))
    if hit:
        return observation("jwt_signature_not_verified_repeated", status)
    if status is None:
        # No answer to the control: nothing after it could be compared with a refusal.
        return None
    for spelling in _NONE_SPELLINGS:
        if left() < MINIMUM_REQUESTS:
            # The offline check below needs no request.
            break
        hit, status = await accepted_twice(unsigned(token, spelling))
        if hit:
            return observation("jwt_alg_none_accepted_repeated", status, none_spelling=spelling)
    secret = guessed_secret(token)
    if secret is None:
        return None
    # The match above is the proof. Acceptance of a token signed with the secret is shown when
    # the slice has the two requests left; without them the finding says it was not shown.
    shown = None
    if left() >= MINIMUM_REQUESTS:
        shown, status = await accepted_twice(signed_with(token, secret))
    return observation(
        "jwt_weak_hmac_secret_reproduced", status if shown else None,
        secret_in_common_list=True, secret_length=len(secret), forged_token_accepted=shown,
    )


__all__ = [
    "JWT_FORGERY_CONTRACT", "MAXIMUM_REQUESTS", "MINIMUM_REQUESTS", "WEAK_SECRETS",
    "algorithm", "altered_signature", "bearer_jwt", "check_token_handling", "guessed_secret",
    "signed_with", "unsigned",
]
