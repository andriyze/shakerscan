"""What a discovered secret is, read from its value without disclosing it.

The worker holds the value when it stores a secret (discovered_secrets.record_discovered) and when
the sweeper fills in rows stored before this existed; it derives metadata here and keeps only
that. Nothing derived is the value, a part of it, or enough to rebuild it:

- a JWT: its header (``alg``, ``typ``, ``kid``) and claim *names*, the registered time claims as
  times, ``iss``/``aud``/``sub`` and role/scope claims as bounded text, and whether it has
  expired. The signature is never read or kept; a claim value that looks like a credential is
  dropped. The token stays a credential: it is still sent only by reference.
- a password hash: its scheme (bcrypt, argon2, sha512-crypt, pbkdf2, LDAP, bare hex digests)
  and work factor, never the salt or digest;
- a private key: its type and whether it is encrypted;
- a connection URL: scheme, host and port, whether it carries a username;
- a provider key: the provider and whether it is a live or test key, by prefix only.

Pure functions; no I/O. ``derive`` never raises.
"""
from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import json
import re
from typing import Any
import urllib.parse

DERIVED_SCHEMA = "discovered-secret-derived/v1"
MAX_TEXT = 120
MAX_CLAIM_NAMES = 40
MAX_LIST_ITEMS = 16
MAX_JWT_PART = 8_192

_JWT_RE = re.compile(r"^(?:[Bb]earer\s+)?(eyJ[A-Za-z0-9_-]{2,}=*)\.([A-Za-z0-9_-]{2,}=*)\.([A-Za-z0-9_-]*=*)$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_:.\-/@]{1,64}$")
_TIME_CLAIMS = {"exp": "expires_at", "iat": "issued_at", "nbf": "not_before"}
_TEXT_CLAIMS = {"iss": "issuer", "sub": "subject", "azp": "authorized_party", "client_id": "client_id",
                "token_use": "token_use", "typ": "token_type"}
_LIST_CLAIMS = {"aud": "audience", "scope": "scopes", "scp": "scopes", "role": "roles", "roles": "roles",
                "groups": "groups", "amr": "authentication_methods"}
_FLAG_CLAIMS = ("admin", "is_admin", "isAdmin", "superuser", "is_superuser", "staff", "is_staff")

_HEX_DIGESTS = {32: "md5_or_ntlm", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
_PROVIDER_PREFIXES = (
    ("sk_live_", "stripe", "live"), ("sk_test_", "stripe", "test"), ("rk_live_", "stripe", "live"),
    ("rk_test_", "stripe", "test"), ("pk_live_", "stripe", "live"), ("pk_test_", "stripe", "test"),
    ("AKIA", "aws_access_key_id", None), ("ASIA", "aws_temporary_access_key_id", None),
    ("github_pat_", "github", None), ("ghp_", "github", None), ("gho_", "github", None),
    ("ghs_", "github", None), ("ghu_", "github", None), ("glpat-", "gitlab", None),
    ("xoxb-", "slack_bot", None), ("xoxp-", "slack_user", None), ("AIza", "google", None),
    ("SG.", "sendgrid", None), ("sk-ant-", "anthropic", None), ("sk-proj-", "openai", None),
    ("sk-", "openai_compatible", None),
)


def _credential_shaped(text: str) -> bool:
    """A token that could itself be a credential: long and mixing character classes."""
    for token in re.findall(r"[A-Za-z0-9_+/=~.\-]{16,}", text):
        classes = (any(c.islower() for c in token) + any(c.isupper() for c in token)
                   + any(c.isdigit() for c in token))
        if classes >= 2 and len(token) >= 20:
            return True
    return False


def _text(value: Any, original: str) -> str | None:
    """A claim value fit to show: short printable text that is neither part of the secret nor
    shaped like a credential of its own."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        value = str(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_TEXT or not text.isprintable():
        return None
    if text in original or _credential_shaped(text):
        return None
    try:
        from redaction import redact_text
    except ModuleNotFoundError:  # package layout
        from scanner.redaction import redact_text
    return text if redact_text(text) == text else None


def _texts(value: Any, original: str) -> list[str]:
    items = value.split() if isinstance(value, str) and " " in value.strip() else (
        value if isinstance(value, list) else [value])
    shown = [item for item in (_text(entry, original) for entry in items[:MAX_LIST_ITEMS]) if item]
    return list(dict.fromkeys(shown))


def _b64_json(part: str) -> dict[str, Any] | None:
    if len(part) > MAX_JWT_PART:
        return None
    try:
        decoded = base64.urlsafe_b64decode(part.rstrip("=") + "=" * (-len(part.rstrip("=")) % 4))
        value = json.loads(decoded.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _time(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _jwt(text: str, now: datetime) -> dict[str, Any] | None:
    match = _JWT_RE.match(text)
    if not match:
        return None
    header, claims = _b64_json(match.group(1)), _b64_json(match.group(2))
    if header is None or claims is None:
        return None
    derived: dict[str, Any] = {"transform": "jwt"}
    for key in ("alg", "typ", "kid", "cty"):
        shown = _text(header.get(key), text)
        if shown and _NAME_RE.match(shown):
            derived[key] = shown
    derived["unsigned"] = str(header.get("alg") or "").lower() == "none" or not match.group(3)
    names = sorted(key for key in claims if isinstance(key, str) and _NAME_RE.fullmatch(key)
                   and _text(key, text) is not None)
    derived["claim_names"] = names[:MAX_CLAIM_NAMES]
    for claim, name in _TIME_CLAIMS.items():
        when = _time(claims.get(claim))
        if when:
            derived[name] = when
    expiry = claims.get("exp")
    if isinstance(expiry, (int, float)) and not isinstance(expiry, bool):
        derived["expired"] = float(expiry) <= now.timestamp()
    for claim, name in _TEXT_CLAIMS.items():
        shown = _text(claims.get(claim), text)
        if shown:
            derived[name] = shown
    for claim, name in _LIST_CLAIMS.items():
        if claim in claims:
            shown = _texts(claims[claim], text)
            if shown:
                derived[name] = list(dict.fromkeys([*derived.get(name, []), *shown]))[:MAX_LIST_ITEMS]
    flags = {claim: claims[claim] for claim in _FLAG_CLAIMS if isinstance(claims.get(claim), bool)}
    if flags:
        derived["flags"] = flags
    return derived


def _hash(text: str) -> dict[str, Any] | None:
    if text.startswith(("$2a$", "$2b$", "$2y$", "$2x$")):
        match = re.match(r"^\$2[abxy]\$(\d{2})\$[./A-Za-z0-9]{53}$", text)
        if match:
            return {"transform": "hash", "hash_type": "bcrypt", "cost": int(match.group(1))}
    match = re.match(r"^\$(argon2(?:id|i|d))\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$", text)
    if match:
        return {"transform": "hash", "hash_type": match.group(1), "version": int(match.group(2)),
                "memory_kib": int(match.group(3)), "iterations": int(match.group(4)),
                "parallelism": int(match.group(5))}
    match = re.match(r"^\$(1|5|6|apr1|y|7)\$(?:rounds=(\d+)\$)?[^$\s]{1,64}\$[^$\s]+$", text)
    if match:
        names = {"1": "md5_crypt", "5": "sha256_crypt", "6": "sha512_crypt", "apr1": "apache_md5",
                 "y": "yescrypt", "7": "scrypt_crypt"}
        derived: dict[str, Any] = {"transform": "hash", "hash_type": names[match.group(1)]}
        if match.group(2):
            derived["rounds"] = int(match.group(2))
        return derived
    match = re.match(r"^(pbkdf2_sha256|pbkdf2_sha1|argon2|bcrypt_sha256|scrypt)\$(\d+)?\$?[^$\s]+\$[^$\s]+$", text)
    if match:
        derived = {"transform": "hash", "hash_type": f"django_{match.group(1)}"}
        if match.group(2):
            derived["iterations"] = int(match.group(2))
        return derived
    match = re.match(r"^\{(SSHA|SHA|SMD5|MD5|SSHA256|SSHA512|CRYPT)\}\S+$", text, re.IGNORECASE)
    if match:
        return {"transform": "hash", "hash_type": f"ldap_{match.group(1).lower()}"}
    if re.fullmatch(r"[0-9a-fA-F]+", text) and len(text) in _HEX_DIGESTS and (
            text == text.lower() or text == text.upper()):
        return {"transform": "hash", "hash_type": _HEX_DIGESTS[len(text)], "encoding": "hex",
                "note": "a bare hex digest: the algorithm is a guess from its length"}
    return None


def _private_key(text: str) -> dict[str, Any] | None:
    match = re.match(r"^-----BEGIN ((?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----", text)
    if not match:
        return None
    label = (match.group(1) or "").strip().lower()
    encrypted = label == "encrypted" or "Proc-Type: 4,ENCRYPTED" in text[:400]
    key_type = {"rsa": "rsa", "ec": "ec", "dsa": "dsa", "openssh": "openssh", "pgp": "pgp"}.get(label, "pkcs8")
    return {"transform": "private_key", "key_type": key_type, "encrypted": encrypted}


def _connection_url(text: str) -> dict[str, Any] | None:
    if "://" not in text or "@" not in text:
        return None
    try:
        parsed = urllib.parse.urlsplit(text)
        port = parsed.port
    except ValueError:
        return None
    if not parsed.scheme or not parsed.hostname or parsed.password is None and parsed.username is None:
        return None
    derived = {"transform": "connection_url", "scheme": parsed.scheme.lower()[:20],
               "has_username": bool(parsed.username), "has_password": parsed.password is not None}
    host = _text(parsed.hostname, "")
    if host and _NAME_RE.match(host):
        derived["host"] = host
    if port:
        derived["port"] = port
    database = parsed.path.strip("/")
    if database and _NAME_RE.fullmatch(database) and _text(database, "") is not None:
        derived["database"] = database
    return derived


def _provider(text: str) -> dict[str, Any] | None:
    for prefix, provider, mode in _PROVIDER_PREFIXES:
        if text.startswith(prefix):
            derived: dict[str, Any] = {"transform": "provider_key", "provider": provider}
            if mode:
                derived["mode"] = mode
            return derived
    return None


def derive(value: Any, kind: str = "", *, now: datetime | None = None) -> dict[str, Any]:
    """Metadata about ``value`` (never the value or a piece of it): ``{"schema_version": ...,
    "transform": "jwt"|"hash"|"private_key"|"connection_url"|"provider_key"|"none", ...}``."""
    try:
        text = str(value or "").strip()
        when = now or datetime.now(timezone.utc)
        derived = None
        if text:
            derived = (_jwt(text, when) or _private_key(text) or _hash(text)
                       or _connection_url(text) or _provider(text))
    except Exception:
        derived = None
    return still_valid({"schema_version": DERIVED_SCHEMA, **(derived or {"transform": "none"})},
                       now=when if derived else now) or {"schema_version": DERIVED_SCHEMA, "transform": "none"}


# Stored metadata is target-controlled too. A schema allowlist prevents an older writer's
# unchecked names, nested objects or extra fields from becoming a second secret-export path.
_TEXT_FIELDS = {
    "jwt": ("alg", "typ", "kid", "cty", *_TEXT_CLAIMS.values()),
    "hash": ("hash_type", "encoding", "note"),
    "private_key": ("key_type",),
    "connection_url": ("scheme", "host", "database"),
    "provider_key": ("provider", "mode"),
    "none": (), "unreadable": (),
}
_NUMBER_FIELDS = {
    "hash": ("cost", "version", "memory_kib", "iterations", "parallelism", "rounds"),
    "connection_url": ("port",),
}
_BOOLEAN_FIELDS = {"jwt": ("unsigned",), "private_key": ("encrypted",),
                   "connection_url": ("has_username", "has_password")}
_HASH_TYPES = frozenset({
    "bcrypt", "argon2id", "argon2i", "argon2d", "md5_crypt", "sha256_crypt", "sha512_crypt",
    "apache_md5", "yescrypt", "scrypt_crypt", "django_pbkdf2_sha256", "django_pbkdf2_sha1",
    "django_argon2", "django_bcrypt_sha256", "django_scrypt", "ldap_ssha", "ldap_sha",
    "ldap_smd5", "ldap_md5", "ldap_ssha256", "ldap_ssha512", "ldap_crypt", *_HEX_DIGESTS.values(),
})


def still_valid(derived: Any, *, now: datetime | None = None) -> dict[str, Any] | None:
    """Bounded public metadata, re-screened even for old stored rows. JWT claims are decoded
    target data, never verified identity; expiry is recomputed only from an aware timestamp."""
    if not isinstance(derived, dict) or derived.get("schema_version") != DERIVED_SCHEMA:
        return None
    transform = derived.get("transform")
    if not isinstance(transform, str) or transform not in _TEXT_FIELDS:
        return None
    shown: dict[str, Any] = {"schema_version": DERIVED_SCHEMA, "transform": transform}
    for field in _TEXT_FIELDS[transform]:
        value = _text(derived.get(field), "")
        if value is not None:
            shown[field] = value
    if transform == "hash" and isinstance(derived.get("hash_type"), str) and derived["hash_type"] in _HASH_TYPES:
        # These are fixed parser enum values, not attacker-controlled descriptive text.
        shown["hash_type"] = derived["hash_type"]
    for field in _NUMBER_FIELDS.get(transform, ()):
        value = derived.get(field)
        ceiling = 65_535 if field == "port" else 2**31 - 1
        if type(value) is int and 0 <= value <= ceiling:
            shown[field] = value
    for field in _BOOLEAN_FIELDS.get(transform, ()):
        if type(derived.get(field)) is bool:
            shown[field] = derived[field]
    if transform == "jwt":
        shown["signature_verified"] = False
        shown["trust"] = "untrusted_target_data"
        names = derived.get("claim_names")
        if isinstance(names, list):
            shown["claim_names"] = list(dict.fromkeys(
                value for entry in names[:MAX_CLAIM_NAMES]
                if (value := _text(entry, "")) is not None and _NAME_RE.fullmatch(value)))
        for field in set(_LIST_CLAIMS.values()):
            values = derived.get(field)
            if isinstance(values, list):
                shown[field] = _texts(values, "")
        flags = derived.get("flags")
        if isinstance(flags, dict):
            shown["flags"] = {key: flags[key] for key in _FLAG_CLAIMS if type(flags.get(key)) is bool}
        for field in _TIME_CLAIMS.values():
            value = derived.get(field)
            if not isinstance(value, str) or len(value) > 40:
                continue
            try:
                when = datetime.fromisoformat(value)
                if when.utcoffset() is None:
                    continue
            except (ValueError, OverflowError):
                continue
            shown[field] = when.isoformat()
            if field == "expires_at":
                shown["expired"] = when <= (now or datetime.now(timezone.utc))
    return shown


__all__ = ["DERIVED_SCHEMA", "derive", "still_valid"]
