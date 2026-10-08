"""The narrow, entropy-screened secret contract shared by Hunt and DAST exposure proofs.

An anonymous read proves a data exposure only when the body carries secret material that is
sensitive on its own. Two producers make that judgment: the Hunt ``data_exposure`` verifier
(``workflow_experiment``) and the DAST exposure probe (``exposure_probe``). They read the same
patterns from here so the two cannot disagree about what a leaked secret is.

The contract has two parts.

* **Self-evident provider formats.** A value whose provider-issued shape is itself the proof
  (``sk_live_``, ``AKIA``, a PEM private key, a credentialed database URI ...). Every captured
  value is screened for documentation placeholders and low entropy first. Membership is
  deliberately narrow:

  - excluded because a public endpoint may legitimately issue them: ``jwt``, ``bearer_token``;
  - excluded because the pattern matches documentation samples: ``ssn``, ``credit_card`` and
    ``google_api_key`` (Maps/browser keys are designed to ship publicly, restricted by referrer).

* **Structured configuration secrets.** A secret-named key with an unmasked, entropy-screened
  value, granted only inside a configuration document whose structure the caller has already
  recognised (a dotenv file, a Spring actuator property source, an ASP.NET ``web.config``). The
  structure is what makes the key name meaningful: the same ``password=...`` text in a page of
  prose or an API response proves nothing here.

Raw values never leave this module's callers: they are used to compute a keyed fingerprint and
to scrub excerpts, and only labels, key names and fingerprints are persisted.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field

SELF_EVIDENT_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})")),
    ("stripe_key", re.compile(r"\b(sk_live_[0-9A-Za-z]{16,})\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,255})\b")),
    ("npm_token", re.compile(r"\b(npm_[A-Za-z0-9]{30,255})\b")),
    ("sendgrid_key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b")),
    ("password_hash", re.compile(
        r"(\$(?:2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|argon2(?:id|i|d)\$[^\s\"\']{20,}))")),
    ("credentialed_database_uri", re.compile(
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/?#]+:([^\s@/?#]+)@[^\s]+"
    )),
)

# Values that match a secret's shape but carry no secret. Vendor documentation ships these
# verbatim, so a page echoing one is not an exposure.
PLACEHOLDER_SECRET_TOKENS: frozenset[str] = frozenset({
    "example", "examplekey", "placeholder", "changeme", "password", "passwd", "secret",
    "yoursecret", "yourpassword", "yourkey", "test", "testing", "dummy", "sample", "redacted",
    "xxxxxxxx", "notreal", "fake", "insertkeyhere", "todo",
})

# A value that only names where the secret comes from carries none: ``${DB_PASSWORD}``,
# ``%DB_PASSWORD%``, ``<your-password>``, ``{{ vault "db" }}``. Its punctuation would otherwise
# lift it past the entropy bound.
_INDIRECTION_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%|<[^>]*>|\{\{.*\}\}|\[[^\]]*\])$"
)
# Spring Boot, ASP.NET and most config renderers mask a sanitized value with a run of
# asterisks; such a value is the absence of a leak.
_MASKED_VALUE_RE = re.compile(r"^\*+$|^\[?(?:redacted|hidden|masked|filtered)\]?$", re.IGNORECASE)

# Key names that hold a secret in server-side configuration. Matched on the normalized
# snake_case name. ``token`` and ``api_key`` count in server configuration (a dotenv file or an
# actuator property source is never meant to reach a browser) but not in a client config file,
# where public, publishable and search-only keys legitimately live (``strict``).
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|pass|secret|secret_key|private_key|privatekey|credential"
    r"|credentials|connection_string|connectionstring|signing_key|encryption_key|master_key"
    r"|client_secret|access_key)(?:_|$)"
    r"|password|passwd|secret|privatekey|credential"
)
_SERVER_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:token|api_key|apikey|auth_token|access_token|refresh_token|admin_token|webhook_key"
    r"|license_key|session_key)(?:_|$)|token$"
)
# Key names that look secret but name public, identifying or descriptive values.
_PUBLIC_KEY_RE = re.compile(
    r"(?:^|_)(?:public|publishable|pub|site|sitekey|site_key|anon|id|key_id|client_id|username"
    r"|user|name|host|port|url|uri|path|file|dir|enabled|enable|timeout|expiry|expires|ttl"
    r"|length|count|size|type|algorithm|header|policy|rotation|hint|mode|format)$"
)


def shannon_entropy_bits(value: str) -> float:
    """Return Shannon entropy in bits per character for a candidate secret."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = float(len(value))
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def is_placeholder_secret(value: str) -> bool:
    """True when a shape-matching value is a documentation placeholder, not real secret material."""
    stripped = value.strip()
    if not stripped:
        return True
    lowered = stripped.lower()
    if any(token in lowered for token in PLACEHOLDER_SECRET_TOKENS):
        return True
    # Provider secrets are random; a short or low-entropy tail is a stand-in. The bound is applied
    # to the random remainder so a long fixed prefix (``sk_live_``) cannot carry a value past it.
    tail = re.sub(r"^(?:AKIA|ASIA|sk_live_|gh[pousr]_|npm_|SG\.|xox[baprs]-)", "", stripped)
    if len(tail) < 12:
        return True
    return shannon_entropy_bits(tail) < 3.0


def selfevident_secret_matches(text: str) -> list[tuple[str, str | None]]:
    """``(label, value)`` for each self-evident provider secret in ``text``, screened.

    ``value`` is None for a structural marker (a PEM header). The values are for the caller's
    fingerprinting and scrubbing only and must never be persisted.
    """
    if not text:
        return []
    found: list[tuple[str, str | None]] = []
    for label, pattern in SELF_EVIDENT_SECRET_PATTERNS:
        for match in pattern.finditer(text):
            # A pattern with no capture group (private_key) is a structural marker, not a value.
            captured = match.group(1) if match.re.groups else None
            if captured is None or not is_placeholder_secret(captured):
                found.append((label, captured))
                break
    return found


def classify_selfevident_secret_values(text: str) -> list[str]:
    """Return category labels for provider-issued secrets present as real values in ``text``.

    Every match is screened for documentation placeholders and low entropy first. Returns only
    labels, never the matched value.
    """
    return sorted({label for label, _value in selfevident_secret_matches(text)})


def normalized_key_name(key: str) -> str:
    """``internalAdminToken`` / ``SPRING_DATASOURCE_PASSWORD`` / ``db.password`` -> snake_case."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key or "").strip())
    return re.sub(r"[^a-z0-9]+", "_", spaced.lower()).strip("_")


def is_secret_key_name(key: str, *, server_side: bool) -> bool:
    """Whether a configuration key names secret material.

    ``server_side`` admits token and API-key names, which a server's environment holds as
    secrets but a client configuration file may legitimately publish.
    """
    name = normalized_key_name(key)
    if not name or _PUBLIC_KEY_RE.search(name):
        return False
    if _SECRET_KEY_RE.search(name):
        return True
    return server_side and bool(_SERVER_SECRET_KEY_RE.search(name))


def is_structured_secret_value(value: object) -> bool:
    """An unmasked, non-indirect value that passes the placeholder and entropy screen."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    text = str(value).strip().strip("\"'")
    if not text or _MASKED_VALUE_RE.match(text) or _INDIRECTION_RE.match(text):
        return False
    return not is_placeholder_secret(text)


@dataclass(frozen=True)
class SecretEvidence:
    """One proven secret: its key and category are evidence; the value only fingerprints it."""

    key: str
    category: str
    fingerprint: str
    value_length: int
    value: str = field(default="", repr=False, compare=False)

    def public(self) -> dict[str, object]:
        """The persisted shape: never the value. ``field`` names the configuration key that
        held it (``key`` itself is a name every receipt redactor masks)."""
        return {
            "field": self.key, "category": self.category,
            "value_fingerprint": self.fingerprint, "value_length": self.value_length,
        }


_FINGERPRINT_DOMAIN = b"shakerscan-secret-fingerprint/v1\x00"


def value_fingerprint(value: str) -> str:
    """A short domain-separated digest that matches repeat sightings without revealing a value.

    Only entropy-screened values reach this, so the truncated digest cannot be inverted by
    guessing; a non-screened value is never fingerprinted.
    """
    digest = hashlib.sha256(_FINGERPRINT_DOMAIN + str(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"


def secret_evidence(key: str, category: str, value: str | None) -> SecretEvidence:
    shown_key = re.sub(r"[^A-Za-z0-9_.:\-\[\]]", "", str(key or ""))[:120] or category
    raw = "" if value is None else str(value)
    return SecretEvidence(
        key=shown_key, category=category,
        fingerprint=value_fingerprint(raw) if raw else "structural_marker",
        value_length=len(raw), value=raw,
    )


def structured_secret_assignments(
    pairs: list[tuple[str, object]], *, server_side: bool,
) -> list[SecretEvidence]:
    """Secret assignments among the ``(key, value)`` pairs of a recognised config document."""
    found: list[SecretEvidence] = []
    seen: set[str] = set()
    for key, value in pairs:
        if not is_secret_key_name(key, server_side=server_side):
            continue
        if not is_structured_secret_value(value):
            continue
        text = str(value).strip().strip("\"'")
        if text in seen:
            continue
        seen.add(text)
        found.append(secret_evidence(str(key), "config_secret_assignment", text))
    return found


def selfevident_secret_evidence(text: str, *, key: str = "") -> list[SecretEvidence]:
    """Self-evident provider secrets in one string, as fingerprinted evidence."""
    return [
        secret_evidence(key or label, label, value)
        for label, value in selfevident_secret_matches(text)
    ]


__all__ = [
    "PLACEHOLDER_SECRET_TOKENS",
    "SELF_EVIDENT_SECRET_PATTERNS",
    "SecretEvidence",
    "classify_selfevident_secret_values",
    "is_placeholder_secret",
    "is_secret_key_name",
    "is_structured_secret_value",
    "normalized_key_name",
    "selfevident_secret_evidence",
    "selfevident_secret_matches",
    "shannon_entropy_bits",
    "structured_secret_assignments",
    "value_fingerprint",
]
