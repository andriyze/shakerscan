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

Raw values never leave this module's callers: they are used to compute a scrypt fingerprint and
to scrub excerpts, and only labels, key names and fingerprints are persisted.
"""

from __future__ import annotations

import hashlib
import math
import re
import urllib.parse
from dataclasses import dataclass, field, replace

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

# Key names that hold a secret in server-side configuration, matched on whole segments of the
# normalized snake_case name (camelCase, kebab, dot and snake separators all normalize to ``_``).
# A secret word must be a segment of its own, or end a run-together segment for the words that
# cannot be anything else (``dbpassword``, ``clientsecret``, ``privatekey``). A name that merely
# contains the word is not secret: ``SECRETS_MANAGER_ENDPOINT`` names where secrets are kept and
# ``CREDENTIAL_PROVIDER_CLASS`` names the code that fetches them. ``token`` and ``api_key`` count
# in server configuration (a dotenv file or an actuator property source is never meant to reach a
# browser) but not in a client config file, where public, publishable and search-only keys
# legitimately live (``server_side``).
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:pwd|pass|passphrase|secret_key|private_key|credentials?|connection_string"
    r"|connectionstring|signing_key|encryption_key|master_key|client_secret|access_key)(?:_|$)"
    r"|(?:^|_)[a-z0-9]*(?:password|passwd|secret|secretkey|privatekey)(?:_|$)"
)
_SERVER_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:token|api_key|apikey|auth_token|access_token|refresh_token|admin_token|webhook_key"
    r"|license_key|session_key)(?:_|$)|(?:^|_)[a-z0-9]*token$"
)
# A last segment that names a public, identifying or descriptive value, or the place or code a
# secret comes from, rather than the secret: ``SECRET_KEY_FILE``, ``SECRETS_MANAGER_ENDPOINT``.
_PUBLIC_KEY_RE = re.compile(
    r"(?:^|_)(?:public|publishable|pub|site|sitekey|site_key|anon|id|key_id|client_id|username"
    r"|user|name|host|hostname|port|url|uri|path|file|dir|directory|enabled|enable|timeout|expiry"
    r"|expires|ttl|length|count|size|type|algorithm|header|policy|rotation|hint|mode|format"
    r"|endpoint|address|addr|server|region|provider|class|classname|driver|location|version"
    r"|prefix|method|strategy|required|min|max|label|description|pattern|regex|field|param)$"
)
# Value shapes that are configuration, not a secret, whatever their entropy: a URL that carries
# no credential, a host name, an address, a dotted class name, a file path, a boolean or number.
_BOOLEAN_WORDS = frozenset({
    "true", "false", "yes", "no", "on", "off", "null", "none", "nil", "enabled", "disabled",
})
_NUMBER_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$")
_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]{0,30}://")
_HOSTNAME_RE = re.compile(
    r"^(?:[a-z0-9][a-z0-9-]{0,62}\.){1,10}[a-z]{2,24}\.?(?::\d{1,5})?$"
)
_IP_ADDRESS_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?$|^\[[0-9A-Fa-f:.]{2,45}\](?::\d{1,5})?$")
_CLASS_NAME_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]{0,40}(?:\.[A-Za-z_$][A-Za-z0-9_$]{0,40}){2,12}$")
_DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/][^\x00-\x1f]{0,512}$")
_UNIX_PATH_RE = re.compile(r"^(?:~|\.{1,2})?/[a-z0-9_.\-~ ]{0,128}(?:/[a-z0-9_.\-~ ]{0,128}){0,32}$")
_EXTENSION_PATH_RE = re.compile(
    r"^(?:~|\.{1,2})?/[\w.\-~ ]{0,128}(?:/[\w.\-~ ]{0,128}){0,32}\.[A-Za-z][A-Za-z0-9]{0,7}$"
)
# Longer values are never one of the shapes above; skip the checks rather than scan them.
_SHAPE_MAX_CHARS = 2_048


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
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key or "").strip()[:200])
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


def _url_carries_credential(text: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(text)
    except ValueError:
        return True
    if parts.password:
        return True
    return any(
        is_secret_key_name(name, server_side=True)
        for name, _value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)[:50]
    )


def is_non_secret_value_shape(text: str) -> bool:
    """Whether a value is configuration by its shape: a URL without a credential, a host name
    or address, a dotted class name, a file path, a boolean or a number."""
    if len(text) > _SHAPE_MAX_CHARS:
        return False
    if text.lower() in _BOOLEAN_WORDS or _NUMBER_RE.match(text):
        return True
    if _URL_SCHEME_RE.match(text):
        return not _url_carries_credential(text)
    return bool(
        _HOSTNAME_RE.match(text) or _IP_ADDRESS_RE.match(text) or _CLASS_NAME_RE.match(text)
        or _DRIVE_PATH_RE.match(text) or _UNIX_PATH_RE.match(text)
        or _EXTENSION_PATH_RE.match(text)
    )


def is_structured_secret_value(value: object) -> bool:
    """An unmasked, non-indirect value that passes the placeholder and entropy screen and is
    not configuration by its shape (a URL, host, class name, path, boolean or number)."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return False
    text = str(value).strip().strip("\"'")
    if not text or _MASKED_VALUE_RE.match(text) or _INDIRECTION_RE.match(text):
        return False
    if is_non_secret_value_shape(text):
        return False
    return not is_placeholder_secret(text)


# --- Withholding: wider than proof ------------------------------------------------------------
# Whether a value is PROVEN secret (above) decides verified vs unverified. Whether a value may be
# SHOWN is a separate, wider question that entropy never answers: ``DB_PASS=Winter2023!`` fails
# the entropy screen and proves nothing, but it is still a password and must never be stored in
# clear. Any key with one of these segments, or a segment ending in one of the suffixes, has its
# value withheld from every excerpt. Over-matching only hides a harmless value.
_REDACTABLE_SEGMENTS = frozenset({
    "password", "passwd", "pwd", "pass", "passphrase", "secret", "secrets", "token", "tokens",
    "key", "keys", "apikey", "salt", "pepper", "signature", "sig", "cookie", "session", "auth",
    "authorization", "bearer", "jwt", "otp", "credential", "credentials", "private", "dsn",
    "connectionstring", "hmac", "nonce", "seed",
})
_REDACTABLE_SUFFIX_RE = re.compile(
    r"(?:password|passwd|passphrase|secret|token|key|credentials?)$"
)
_MAX_REDACTED_VALUES = 500


def is_redactable_key_name(key: object) -> bool:
    """Whether the value under ``key`` must be withheld from any excerpt, whatever it holds."""
    for segment in normalized_key_name(str(key or "")).split("_"):
        if segment in _REDACTABLE_SEGMENTS or _REDACTABLE_SUFFIX_RE.search(segment):
            return True
    return False


def redactable_assignments(pairs: list[tuple[str, object]]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(key names, raw values)`` of the pairs whose key is redactable and whose value is set.

    Masked and indirect values are skipped (they carry nothing). The values are for scrubbing
    and must never be persisted; the key names are evidence.
    """
    keys: list[str] = []
    values: list[str] = []
    seen: set[str] = set()
    for key, value in pairs:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        if not is_redactable_key_name(key):
            continue
        text = str(value).strip().strip("\"'")
        if not text or _MASKED_VALUE_RE.match(text) or _INDIRECTION_RE.match(text):
            continue
        shown = re.sub(r"[^A-Za-z0-9_.:\-\[\]]", "", str(key)[:400])[:120]
        if shown and shown not in keys:
            keys.append(shown)
        if text not in seen:
            seen.add(text)
            values.append(text)
        if len(values) >= _MAX_REDACTED_VALUES:
            break
    return tuple(keys), tuple(values)


# ``key = value`` / ``key: value`` / ``"key": "value"`` in free text. The look-behind starts a
# key only at a word boundary and every repetition is bounded, so the scan is linear.
_TEXT_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])([A-Za-z_][A-Za-z0-9_.\-]{0,80})([\"']?[ \t]*[:=][ \t]*[\"']?)"
    r"([^\s,;\"'<>&]{1,200})"
)


def text_assignment_values(text: str) -> tuple[str, ...]:
    """Raw values of redactable ``key = value`` assignments in free text, for scrubbing only."""
    values: list[str] = []
    seen: set[str] = set()
    for match in _TEXT_ASSIGNMENT_RE.finditer(text):
        value = match.group(3)
        if value not in seen and is_redactable_key_name(match.group(1)):
            seen.add(value)
            values.append(value)
            if len(values) >= _MAX_REDACTED_VALUES:
                break
    return tuple(values)


def redact_text_assignments(text: str, *, mask: str = "[REDACTED]") -> str:
    """Replace the value of every redactable ``key = value`` assignment in ``text``."""
    def replace_value(match: re.Match[str]) -> str:
        if not is_redactable_key_name(match.group(1)):
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}{mask}"

    return _TEXT_ASSIGNMENT_RE.sub(replace_value, text)


@dataclass(frozen=True)
class SecretEvidence:
    """One proven secret: its key and category are evidence; the value only fingerprints it.

    ``fingerprint`` stays empty until :func:`fingerprinted_secret_evidence` has cut and
    deduplicated the candidates: hashing is the expensive step, so it runs on at most
    ``MAX_FINGERPRINTED_SECRETS`` distinct values per body, never on every candidate.
    """

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
_STRUCTURAL_MARKER = "structural_marker"
# Evidence names at most this many distinct secrets per body; only these are fingerprinted.
MAX_FINGERPRINTED_SECRETS = 20
# Candidate assignments examined per document before the cut. Each is a cheap name and
# entropy check, but a hostile body can carry hundreds of thousands of them.
_MAX_ASSIGNMENT_CANDIDATES = 200


def value_fingerprint(value: str) -> str:
    """A short, deterministic fingerprint that matches repeat sightings without revealing a value.

    A leaked secret can be a human-chosen password, so a fast hash would let anyone holding
    the evidence test guesses offline. scrypt (memory-hard, fixed domain salt so the same value
    fingerprints the same across Scans) makes each guess cost what a password hash costs.
    """
    digest = hashlib.scrypt(
        str(value).encode("utf-8"), salt=_FINGERPRINT_DOMAIN, n=2**14, r=8, p=1, dklen=12,
    ).hex()
    return f"scrypt:{digest}"


def secret_evidence(key: str, category: str, value: str | None) -> SecretEvidence:
    """An unfingerprinted candidate; :func:`fingerprinted_secret_evidence` finishes it."""
    shown_key = re.sub(r"[^A-Za-z0-9_.:\-\[\]]", "", str(key or "")[:400])[:120] or category
    raw = "" if value is None else str(value)
    return SecretEvidence(
        key=shown_key, category=category,
        fingerprint="" if raw else _STRUCTURAL_MARKER,
        value_length=len(raw), value=raw,
    )


def fingerprinted_secret_evidence(
    items: list[SecretEvidence], *, limit: int = MAX_FINGERPRINTED_SECRETS,
) -> tuple[SecretEvidence, ...]:
    """Deduplicate by value, cut to ``limit``, and only then fingerprint what is kept.

    One entry per value: the configuration key that holds it, the provider category if a
    provider format recognises it. Provider-format secrets and structural markers are kept
    before plain configuration assignments, so the cut never drops the category that decides
    severity (a private key or a cloud key). A structural marker (a PEM header) has no value
    and is kept once per category.
    """
    kept: dict[tuple[str, str], SecretEvidence] = {}
    # Stable sort: provider categories first, each group in document order.
    for item in sorted(items, key=lambda entry: entry.category == "config_secret_assignment"):
        identity = ("value", item.value) if item.value else ("marker", item.category)
        prior = kept.get(identity)
        if prior is None:
            if len(kept) < limit:
                kept[identity] = item
        elif (prior.category != "config_secret_assignment"
              and item.category == "config_secret_assignment"):
            # The provider names the category; the configuration key names where it was held.
            kept[identity] = replace(prior, key=item.key)
    return tuple(
        replace(item, fingerprint=value_fingerprint(item.value)) if item.value else item
        for item in kept.values()
    )


def structured_secret_assignments(
    pairs: list[tuple[str, object]], *, server_side: bool,
) -> list[SecretEvidence]:
    """Secret assignments among the ``(key, value)`` pairs of a recognised config document.

    Unfingerprinted candidates, at most ``_MAX_ASSIGNMENT_CANDIDATES`` distinct values.
    """
    found: list[SecretEvidence] = []
    seen: set[str] = set()
    for key, value in pairs:
        if len(found) >= _MAX_ASSIGNMENT_CANDIDATES:
            break
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
    """Self-evident provider secrets in one string, as unfingerprinted candidates."""
    return [
        secret_evidence(key or label, label, value)
        for label, value in selfevident_secret_matches(text)
    ]


__all__ = [
    "MAX_FINGERPRINTED_SECRETS",
    "PLACEHOLDER_SECRET_TOKENS",
    "SELF_EVIDENT_SECRET_PATTERNS",
    "SecretEvidence",
    "classify_selfevident_secret_values",
    "fingerprinted_secret_evidence",
    "is_placeholder_secret",
    "is_non_secret_value_shape",
    "is_redactable_key_name",
    "is_secret_key_name",
    "is_structured_secret_value",
    "normalized_key_name",
    "redact_text_assignments",
    "redactable_assignments",
    "selfevident_secret_evidence",
    "selfevident_secret_matches",
    "shannon_entropy_bits",
    "structured_secret_assignments",
    "text_assignment_values",
    "value_fingerprint",
]
