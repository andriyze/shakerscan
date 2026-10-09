"""Withhold secret values from archived bodies in every masked archive view.

The masked HTTP archive and the masked HAR are the views offered for sharing, so they must
withhold what the exposure evidence withholds. Key-name redaction alone is not that: a
specification declares its secrets as the ``default`` or ``example`` of a parameter whose
*name* is secret (``{"name": "api_key", "default": "..."}``), or nests them one level below a
secret-named key (``"redis_password": {"example": "..."}``), and the stored body is text, so
a dictionary walk never sees it. Soak scan b723d50d exported a Stripe-format key, an admin
token and a redis password from ``/swagger.json`` this way while its exposure finding
withheld all three (N39).

The vocabulary is the exposure evidence's own (``capabilities.secret_material``) together with
the shared redactor's key set, so the two cannot disagree about what a secret-named key is.
Over every body, masked views withhold:

* every value under a secret-named key, at any depth below it, in JSON (complete or
  truncated) and YAML;
* every value beside a secret name in a ``name``/``key``/``header`` descriptor (an OpenAPI
  parameter, a Postman variable, a HAR header), except the descriptor's structural fields;
* secret-named ``key = value`` / ``key: value`` assignments, including a prose label of up
  to three words (``Master key: ...``, ``API Key: ...``), in any text *and inside every JSON
  string value*: a specification documents secrets in its ``description`` and ``summary``
  prose, which no key walk reaches (N39 residue: honey's ``/internal/admin`` operation
  description ``"... Master key: <value>"``);
* every credential-shaped (long, mixed-class) value in an OpenAPI security or parameter
  context (``securityDefinitions``, ``securitySchemes``, ``parameters``, ``headers`` and any
  ``x-`` extension), descriptive fields included;
* secret-named HTML form fields and meta tags in any text;
* every provider-format secret (``sk_live_``, ``AKIA``, ``ghp_``, a PEM private key block, a
  credentialed database URI ...), whatever its key and without the placeholder screen that
  proof applies: hiding a sample key costs nothing, showing a real one cannot be undone.

Every pass is a single linear scan, so a hostile body cannot stall an export. The raw view
is untouched; it is a separate, deployment-gated choice.
"""

from __future__ import annotations

import base64
import html
import json
import math
import re
import urllib.parse
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

try:
    from capabilities.secret_material import (
        SELF_EVIDENT_SECRET_PATTERNS,
        is_non_secret_value_shape,
        is_redactable_key_name,
        is_secret_key_name,
        normalized_key_name,
    )
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import (
        SELF_EVIDENT_SECRET_PATTERNS,
        is_non_secret_value_shape,
        is_redactable_key_name,
        is_secret_key_name,
        normalized_key_name,
    )

try:
    from redaction import MASK, is_sensitive_key
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import MASK, is_sensitive_key

_MASKED_JSON_VALUE = json.dumps(MASK)


# --- Withheld-value references (Hunt) ----------------------------------------------------------
# A masked archive view replaces every withheld value with ``***``. A Hunt planner reads the same
# masking through its capability outputs, but must still be able to *use* a leaked credential (the
# "leaked secret -> access" test). While a collector is active, each withheld value is replaced by
# a short marker (``[withheld:3]``) and the raw value stays in the collector, which the worker
# seals into the action's encrypted private result. The planner binds the value back into a later
# request by its reference (``withheld://hunt/<action id>/3``); the raw value never leaves the
# worker. Without a collector (the archive export and every other caller) nothing changes.

WITHHELD_MARKER_RE = re.compile(r"\[withheld:([1-9][0-9]{0,3})\]")
WITHHELD_REF_RE = re.compile(
    r"^withheld://hunt/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]{0,3})$"
)
MAX_WITHHELD_VALUES = 256
MAX_WITHHELD_VALUE_CHARS = 8_192
# Fingerprints are scrypt (memory-hard by design), so only the first few are computed.
_MAX_FINGERPRINTED_REFERENCES = 20
# A short value's fingerprint is a guessing oracle: a planner that can make the target reflect a
# guess sees the guess fingerprinted beside the secret. References already deduplicate within an
# output, so short values carry no fingerprint at all.
_MIN_FINGERPRINTED_CHARS = 12
# A bound value shorter than this is not searched for in echoes (it would match ordinary text).
_MIN_KNOWN_VALUE_CHARS = 3
_MIN_EDGE_FRAGMENT_CHARS = 4
# A value found (in context, or sealed earlier) rather than sent: shorter ones match ordinary text.
_MIN_FOUND_VALUE_CHARS = 6
# A short found value must stand alone to match (``admin`` is also a word and a path); a longer
# one matches anywhere, inside longer strings too (``aHunter2pass``, ``Hunter2pass9``).
_WHOLE_TOKEN_BELOW_CHARS = 10
_MAX_EDGE_VALUE_CHARS = 512


def withheld_preview(value: str) -> str:
    """A masked preview: at most the first three characters of a long value, never more."""
    return (value[:3] + "…") if len(value) >= 16 else "…"


class WithheldValues:
    """Raw values withheld from one capability output, numbered in first-seen order.

    Worker-private: ``repr`` never shows a value. ``entries`` gives the public view (reference,
    marker, masked preview, length, keyed fingerprint), never a value.
    """

    def __init__(self, action_id: str, *, limit: int = MAX_WITHHELD_VALUES) -> None:
        self.action_id = str(action_id)
        self.limit = limit
        self.values: list[str] = []
        self._numbers: dict[str, int] = {}
        self._fingerprints: dict[int, str | None] = {}
        # Values this action sends (bound by reference): withheld wherever the target echoes them.
        self.known: list[str] = []
        # Values found elsewhere (a window's preceding context, sealed earlier in the Hunt).
        self.found: list[str] = []
        self._known_scrubbers: list[KnownValueScrubber] | None = None
        # SQL dump column knowledge, by resource path: carried between windows of one dump, so a
        # window far past its CREATE TABLE still knows which column holds the password.
        self.sql_tables: dict[str, dict[str, list[str]]] = {}
        self.sql_path: str | None = None
        # Context bytes read for masking: this action's, and the Hunt's so far (a budget).
        self.context_bytes = 0
        self.context_bytes_used = 0

    def bind_known(self, values: Any, *, found: bool = False) -> None:
        """Values every echo of which is withheld, in any encoding. Values this action *sends*
        match anywhere; values *found* (a window's context, or sealed earlier in the Hunt) match
        only as whole tokens of at least six characters. A value is numbered only when an echo is
        actually withheld from this output."""
        target = self.found if found else self.known
        minimum = _MIN_FOUND_VALUE_CHARS if found else _MIN_KNOWN_VALUE_CHARS
        for value in values or ():
            text = str(value)
            if len(text) >= minimum and text not in target:
                target.append(text)
        self._known_scrubbers = None

    def known_scrubbers(self) -> list[KnownValueScrubber]:
        if self._known_scrubbers is None:
            self._known_scrubbers = [
                KnownValueScrubber(values, whole_tokens=found)
                for values, found in ((self.known, False), (self.found, True)) if values
            ]
        return self._known_scrubbers

    def __repr__(self) -> str:
        return f"WithheldValues(action_id={self.action_id!r}, count={len(self.values)}, values_visible=False)"

    def marker(self, raw: str) -> str:
        value = str(raw).strip()
        if WITHHELD_MARKER_RE.fullmatch(value):
            return value  # already withheld by an earlier pass: keep its reference
        if (
            not value or value == MASK or len(value) > MAX_WITHHELD_VALUE_CHARS
            or WITHHELD_MARKER_RE.search(value)
        ):
            return MASK
        number = self._numbers.get(value)
        if number is None:
            if len(self.values) >= self.limit:
                return MASK
            self.values.append(value)
            number = len(self.values)
            self._numbers[value] = number
        return f"[withheld:{number}]"

    def shown_numbers(self, *texts: str | None) -> list[int]:
        numbers: set[int] = set()
        for text in texts:
            if text:
                numbers.update(int(match.group(1)) for match in WITHHELD_MARKER_RE.finditer(text))
        return sorted(item for item in numbers if 1 <= item <= len(self.values))

    def shown_values(self, *texts: str | None) -> dict[int, str]:
        """The values whose markers reached a public output: only these are worth sealing."""
        return {number: self.values[number - 1] for number in self.shown_numbers(*texts)}

    def reference(self, number: int) -> str:
        return f"withheld://hunt/{self.action_id}/{number}"

    def entries(self, *texts: str | None) -> list[dict[str, Any]]:
        """Public entries for the markers that appear in ``texts`` (all when none are given)."""
        shown = self.shown_numbers(*texts) if texts else range(1, len(self.values) + 1)
        result = []
        for number in shown:
            value = self.values[number - 1]
            result.append({
                "ref": self.reference(number),
                "marker": f"[withheld:{number}]",
                "preview": withheld_preview(value),
                "length": len(value),
                "fingerprint": self._fingerprint(number, value),
            })
        return result

    def _fingerprint(self, number: int, value: str) -> str | None:
        if len(value) < _MIN_FINGERPRINTED_CHARS:
            return None
        if number not in self._fingerprints:
            if len(self._fingerprints) >= _MAX_FINGERPRINTED_REFERENCES:
                return None
            try:
                from capabilities.secret_material import value_fingerprint
            except ModuleNotFoundError:  # package import layout
                from api.capabilities.secret_material import value_fingerprint
            self._fingerprints[number] = value_fingerprint(value)
        return self._fingerprints[number]


_BASE64_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-=")
_MIN_BASE64_CORE_CHARS = 6


def _encodings(value: str) -> set[str]:
    """The forms a target echoes a value in: verbatim, HTML-, JSON- and URL-encoded, base64."""
    raw = value.encode("utf-8")
    forms = {
        value,
        html.escape(value, quote=True), html.escape(value, quote=False),
        html.escape(value, quote=True).replace("&#x27;", "&#39;"),
        json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1],
        json.dumps(value)[1:-1].replace("/", "\\/"),
        json.dumps(value, ensure_ascii=False)[1:-1].replace("/", "\\/"),
        urllib.parse.quote(value, safe=""), urllib.parse.quote(value),
        urllib.parse.quote_plus(value), urllib.parse.quote_plus(value, safe="/"),
    }
    for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
        text = encoded.decode("ascii")
        forms.update({text, text.rstrip("=")})
    # Encoders that escape only the special characters: Gson's HTML-safe ``\u003d`` for = & < > ',
    # ESAPI/PHP numeric entities (``&#33;``, ``&#x21;``, ``&#039;``), JSON ``\uXXXX`` for any special.
    specials = [char for char in dict.fromkeys(value) if not char.isalnum()]
    if specials:
        gson = {char: f"\\u{ord(char):04x}" for char in "=&<>'" if char in specials}
        forms.add("".join(gson.get(char, char) for char in value))
        for render in (
            lambda char: f"\\u{ord(char):04x}", lambda char: f"&#{ord(char)};",
            lambda char: f"&#{ord(char):03d};", lambda char: f"&#x{ord(char):x};",
            lambda char: f"&#x{ord(char):02x};",
        ):
            escaped = {char: render(char) for char in specials}
            forms.add("".join(escaped.get(char, char) for char in value))
            # Mixed: an encoder that escapes only what HTML needs and keeps the rest verbatim.
            html_needs = {char: render(char) for char in specials if char in "&<>\"'/!=`"}
            forms.add("".join(html_needs.get(char, char) for char in value))
    return {form for form in forms if len(form) >= _MIN_KNOWN_VALUE_CHARS}


def _base64_cores(value: str) -> set[str]:
    """Alignment-independent base64 fragments of ``value`` embedded in a longer encoding (a
    Basic credential, a JWT claim): the characters that depend only on the value's own bytes."""
    raw = value.encode("utf-8")
    cores: set[str] = set()
    for shift in range(3):
        total = shift + len(raw)
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(b"\0" * shift + raw).decode("ascii")
            # Leading characters mix in the shift bytes; trailing ones mix in what follows.
            core = encoded[-(-shift * 4 // 3):(total // 3) * 4]
            if len(core) >= _MIN_BASE64_CORE_CHARS:
                cores.add(core)
    return cores


_INDEX_HEAD_CHARS = _MIN_KNOWN_VALUE_CHARS


def _head_index(owners: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """``{first characters: [(form, value), ...] longest first}``; forms are matched as given."""
    index: dict[str, list[tuple[str, str]]] = {}
    for form, value in owners.items():
        index.setdefault(form[:_INDEX_HEAD_CHARS], []).append((form, value))
    for entries in index.values():
        entries.sort(key=lambda entry: len(entry[0]), reverse=True)
    return index


def _scan(text: str, index: dict[str, list[tuple[str, str]]]) -> Iterator[tuple[int, int, str]]:
    """Non-overlapping ``(start, end, value)`` matches of indexed forms, left to right."""
    position, limit = 0, len(text) - _INDEX_HEAD_CHARS
    while position <= limit:
        entries = index.get(text[position:position + _INDEX_HEAD_CHARS])
        if entries:
            for form, value in entries:
                if text.startswith(form, position):
                    yield position, position + len(form), value
                    position += len(form)
                    break
            else:
                position += 1
            continue
        position += 1


class KnownValueScrubber:
    """Withhold every echo of known values: any case, HTML/JSON/URL-encoded (including encoders
    that escape only the specials), base64 (whole or inside a longer encoding), and a fragment cut
    by the text's start or end.

    ``whole_tokens`` is for values *found* (in a window's context, or sealed earlier in the Hunt)
    rather than sent: an echo must stand alone (no letter or digit beside it), so a found
    ``admin`` password never masks the word or the ``/admin`` path. Edge fragments still count.
    """

    def __init__(self, values: list[str], *, whole_tokens: bool = False) -> None:
        minimum = _MIN_FOUND_VALUE_CHARS if whole_tokens else _MIN_KNOWN_VALUE_CHARS
        self.values = [value for value in dict.fromkeys(values) if len(value) >= minimum]
        self.whole_tokens = whole_tokens
        owners: dict[str, str] = {}
        for value in sorted(self.values, key=len):
            for form in _encodings(value):
                owners.setdefault(form.lower(), value)
        # Indexed by each form's first characters: one dictionary lookup per text position, however
        # many values are known (a regex alternation of thousands of forms is not linear in them).
        self._forms = _head_index(owners)
        cores: dict[str, str] = {}
        for value in self.values:
            # A JWT claim or a JSON document carries the value JSON-escaped before encoding.
            for form in {value, json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]}:
                for core in _base64_cores(form):
                    cores.setdefault(core, value)
        self._cores = _head_index(cores)
        # Edge fragments, indexed by a value's first and last few characters.
        self._heads: dict[str, list[str]] = {}
        self._tails: dict[str, list[str]] = {}
        for value in self.values:
            if len(value) <= _MAX_EDGE_VALUE_CHARS:
                folded = value.lower()
                self._heads.setdefault(folded[:_MIN_EDGE_FRAGMENT_CHARS], []).append(value)
                self._tails.setdefault(folded[-_MIN_EDGE_FRAGMENT_CHARS:], []).append(value)
        self._longest = max((len(value) for value in self.values), default=0)

    def __repr__(self) -> str:
        return f"KnownValueScrubber(count={len(self.values)}, values_visible=False)"

    def scrub(self, text: str, replace: Any) -> str:
        """``replace(value)`` gives the replacement text for an echo of ``value``."""
        if not text or not self.values:
            return text
        if self._forms:
            text = self._scrub_forms(text, replace)
        if self._cores:
            text = self._scrub_cores(text, replace)
        return self._scrub_edges(text, replace)

    def _scrub_forms(self, text: str, replace: Any) -> str:
        lowered = text.lower()
        if len(lowered) != len(text):  # a character whose lower case is longer: fold per character
            lowered = "".join(char.lower()[:1] for char in text)
        pieces: list[str] = []
        cursor = 0
        for start, end, value in _scan(lowered, self._forms):
            if start < cursor:
                continue
            if self.whole_tokens and len(value) < _WHOLE_TOKEN_BELOW_CHARS and (
                (start and lowered[start - 1].isalnum()) or (end < len(text) and lowered[end].isalnum())
            ):
                continue
            pieces.append(text[cursor:start])
            pieces.append(replace(value))
            cursor = end
        if not pieces:
            return text
        pieces.append(text[cursor:])
        return "".join(pieces)

    def _scrub_cores(self, text: str, replace: Any) -> str:
        pieces: list[str] = []
        cursor = 0
        for start, end, value in _scan(text, self._cores):
            if start < cursor:
                continue
            while start > cursor and text[start - 1] in _BASE64_RUN_CHARS:
                start -= 1
            while end < len(text) and text[end] in _BASE64_RUN_CHARS:
                end += 1
            pieces.append(text[cursor:start])
            pieces.append(replace(value))
            cursor = end
        if not pieces:
            return text
        pieces.append(text[cursor:])
        return "".join(pieces)

    def _scrub_edges(self, text: str, replace: Any) -> str:
        """A window or a truncated body can cut a value: its head ends the text, its tail starts it.
        Indexed: only positions whose next few characters begin (or end) a known value are tried."""
        size = _MIN_EDGE_FRAGMENT_CHARS
        span = min(len(text), self._longest)
        lowered_tail = text[-span:].lower() if span else ""
        for index in range(len(lowered_tail) - size + 1):
            candidates = self._heads.get(lowered_tail[index:index + size])
            if not candidates:
                continue
            fragment = lowered_tail[index:]
            match = next((value for value in candidates if
                          len(fragment) < len(value) and value.lower().startswith(fragment)), None)
            if match is not None:
                text = text[:len(text) - len(fragment)] + replace(match)
                break
        lowered_head = text[:span].lower()
        for end in range(min(len(lowered_head), self._longest - 1), size - 1, -1):
            candidates = self._tails.get(lowered_head[end - size:end])
            if not candidates:
                continue
            fragment = lowered_head[:end]
            match = next((value for value in candidates if
                          len(fragment) < len(value) and value.lower().endswith(fragment)), None)
            if match is not None:
                text = replace(match) + text[end:]
                break
        return text


def scrub_known_values(text: str, values: list[str], replacement: str) -> str:
    """Replace every echo of ``values`` in ``text`` (see ``KnownValueScrubber``)."""
    return KnownValueScrubber(values).scrub(text, lambda _value: replacement)


def _mask_known_values(text: str) -> str:
    collector = _COLLECTOR.get()
    if collector is None:
        return text
    for scrubber in collector.known_scrubbers():
        text = scrubber.scrub(text, collector.marker)
    return text


_COLLECTOR: ContextVar[WithheldValues | None] = ContextVar("withheld_values", default=None)


@contextmanager
def collecting_withheld_values(collector: WithheldValues) -> Iterator[WithheldValues]:
    """Within this context, masking keeps withheld values in ``collector`` behind markers."""
    token = _COLLECTOR.set(collector)
    try:
        yield collector
    finally:
        _COLLECTOR.reset(token)


def active_withheld_values() -> WithheldValues | None:
    return _COLLECTOR.get()


def holds_withheld_material(text: str) -> bool:
    """Whether masking would withhold anything from ``text`` (no collector side effects)."""
    token = _COLLECTOR.set(None)
    try:
        return mask_body_text(text) != text
    finally:
        _COLLECTOR.reset(token)


def _withhold(raw: str) -> str:
    """The replacement for one withheld value: ``***``, or a marker while collecting."""
    collector = _COLLECTOR.get()
    return MASK if collector is None else collector.marker(raw)


def _withhold_json(raw: str) -> str:
    collector = _COLLECTOR.get()
    return _MASKED_JSON_VALUE if collector is None else json.dumps(collector.marker(raw))
# Keys that name a value but are not secret-named themselves: a Postman variable's ``key``,
# an i18n table's ``keys``. Their *value* is a name, judged by the descriptor rule below.
_NEUTRAL_KEYS = frozenset({"key", "keys"})
# A descriptor whose one of these fields carries a secret name describes a secret value.
_DESCRIPTOR_NAME_KEYS = frozenset({
    "name", "key", "header", "param", "parameter", "field", "variable", "env", "property",
})
# The fields of such a descriptor that describe it rather than carry its value.
_STRUCTURAL_KEYS = frozenset({
    "name", "key", "header", "param", "parameter", "field", "variable", "env", "property",
    "in", "type", "format", "required", "description", "summary", "title", "style", "explode",
    "deprecated", "allowemptyvalue", "allowreserved", "$ref", "pattern", "nullable",
    "readonly", "writeonly", "minlength", "maxlength", "minimum", "maximum", "disabled",
})
_KEY_MAX_CHARS = 200
# OpenAPI containers whose every value describes a credential or a request input: a
# credential-shaped value anywhere inside them (a description, an example, an extension) is
# withheld even when no secret name is near it.
_CREDENTIAL_CONTEXT_KEYS = frozenset({
    "securitydefinitions", "securityschemes", "parameters", "headers",
})
# Fields that name or type a context entry; their values are identifiers, not credentials.
_CONTEXT_NAME_KEYS = frozenset({
    "name", "in", "type", "format", "$ref", "style", "scheme", "bearerformat",
})


def is_withheld_key(key: Any) -> bool:
    """Whether every value under ``key`` is withheld from a masked archive view."""
    text = str(key or "").strip()
    if not text or len(text) > _KEY_MAX_CHARS or text.startswith("/"):
        # A route (``/auth/token``) in a specification's ``paths`` is not a secret name.
        return False
    normalized = normalized_key_name(text)
    if (
        text.lower() in _NEUTRAL_KEYS or normalized in _NON_SECRET_KEY_NAMES
        or normalized.rsplit("_", 1)[-1] in _DESCRIPTIVE_LAST_SEGMENTS
    ):
        return False
    return is_redactable_key_name(text) or is_sensitive_key(text)


_CSRF_NAMES = frozenset({
    "_token", "authenticity_token", "__requestverificationtoken", "csrfmiddlewaretoken",
    "request_verification_token",
})


def is_csrf_name(name: Any) -> bool:
    """A CSRF/XSRF token form field: bound to the session and the page, and needed to submit
    it. A name that also says ``secret`` (``csrf_secret``) is a server key, not a form token."""
    raw = str(name or "").strip().lower()
    if "secret" in raw:
        return False
    if raw in _CSRF_NAMES:
        return True
    return any(
        segment.startswith(("csrf", "xsrf")) for segment in normalized_key_name(raw).split("_")
    ) or normalized_key_name(raw) in _CSRF_NAMES


# Database and structure terms that end in ``key`` but name no secret: a ``Primary key`` label in
# a schema page, a DynamoDB ``sort_key``, a published ``public_key`` (PR #361 review).
_NON_SECRET_KEY_NAMES = frozenset({
    "primary_key", "primary_keys", "foreign_key", "foreign_keys", "unique_key", "sort_key",
    "partition_key", "hash_key", "range_key", "composite_key", "surrogate_key", "natural_key",
    "candidate_key", "index_key", "public_key", "publishable_key",
})
# A last word that makes the name describe a secret rather than hold it: ``tokens_used: 42``,
# ``password_length``, ``token_type: bearer``, ``session_expires``.
_DESCRIPTIVE_LAST_SEGMENTS = frozenset({
    "used", "count", "counts", "remaining", "limit", "limits", "total", "length", "size",
    "ttl", "type", "expires", "expiry", "expiration", "enabled", "required", "policy",
})
# A name whose last word says its value is a location (``Token URL``, ``tokenUrl``,
# ``auth_endpoint``): a plain URL under it is where a secret is exchanged, not the secret.
_LOCATION_SEGMENTS = frozenset({"url", "uri", "endpoint", "href", "link"})
_URL_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]{0,30}://")


def is_location_value(key: Any, value: Any) -> bool:
    """Whether ``value`` is a credential-free URL under a name that says it is a location."""
    if not isinstance(value, str) or key is None:
        return False
    text = value.strip().strip("\"'")
    segments = normalized_key_name(str(key)).split("_")
    return (
        segments[-1] in _LOCATION_SEGMENTS and bool(_URL_VALUE_RE.match(text))
        and is_non_secret_value_shape(text)
    )


def _opens_credential_context(key: Any) -> bool:
    text = str(key or "").strip().lower()
    return text in _CREDENTIAL_CONTEXT_KEYS or text.startswith("x-")


# --- Credential-shaped values ------------------------------------------------------------------

_CREDENTIAL_TOKEN_RE = re.compile(r"[A-Za-z0-9_+/=~.\-]{16,512}")


def _is_credential_shaped(token: str) -> bool:
    """A long token mixing character classes: a key, a token, a signature, not a word."""
    if is_non_secret_value_shape(token):
        return False
    classes = (
        any(char.islower() for char in token) + any(char.isupper() for char in token)
        + any(char.isdigit() for char in token)
    )
    if classes == 3:
        return True
    if classes < 2 or len(token) < 24:
        return False
    counts: dict[str, int] = {}
    for char in token:
        counts[char] = counts.get(char, 0) + 1
    entropy = -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())
    return entropy >= 3.5


def mask_credential_shaped(text: str) -> str:
    """Withhold every credential-shaped token in ``text`` (one linear scan)."""
    return _CREDENTIAL_TOKEN_RE.sub(
        lambda match: (
            _withhold(match.group(0)) if _is_credential_shaped(match.group(0)) else match.group(0)
        ),
        text,
    )


def mask_string_content(text: str, *, credential_context: bool, depth: int = 0) -> str:
    """Withhold the secrets a string *documents*: labelled values (``Master key: ...``), the
    formats it nests (a config file, markup, a SQL dump, JSON) and, in a credential context,
    every credential-shaped token."""
    text = _mask_nested_text(text, depth)
    text = mask_text_assignments(text)
    if credential_context:
        text = mask_credential_shaped(text)
    return text


# --- JSON, complete or truncated ---------------------------------------------------------------

_JSON_TOKEN_RE = re.compile(r'"(?:[^"\\]|\\.)*"?|[{}\[\]:,]|[^\s{}\[\]:,"]+|\s+')
_JSON_LITERALS = frozenset({"true", "false", "null"})


def _string_value(token: str) -> str:
    try:
        decoded = json.loads(token)
    except ValueError:
        decoded = token.strip('"')
    return decoded if isinstance(decoded, str) else str(decoded)


def mask_json_text(text: str, *, _depth: int = 0) -> str:
    """Mask a JSON document's secret values in place, tolerating a truncated document.

    A tolerant tokenizer keeps the original formatting (and works on a body the archive cut
    short, which ``json.loads`` refuses). Values are replaced by ``"***"``; booleans and
    nulls carry nothing and are kept.
    """
    # Frame: [parent index, key in parent, descriptor names a secret, credential context]
    frames: list[list[Any]] = []
    stack: list[int] = []
    keys: dict[int, str | None] = {}
    expecting_key: dict[int, bool] = {}
    values: list[tuple[int, int, int, str | None]] = []
    for match in _JSON_TOKEN_RE.finditer(text):
        token = match.group(0)
        top = stack[-1] if stack else None
        is_object = top is not None and expecting_key.get(top) is not None
        if token in ("{", "["):
            key_in_parent = keys.get(top) if top is not None else None
            context = top is not None and (
                frames[top][3] or _opens_credential_context(key_in_parent)
            )
            frames.append([top, key_in_parent, False, context, token == "["])
            index = len(frames) - 1
            stack.append(index)
            keys[index] = None
            if token == "{":
                expecting_key[index] = True
        elif token in ("}", "]"):
            if stack:
                stack.pop()
        elif token == ":":
            if is_object:
                expecting_key[top] = False
        elif token == ",":
            if is_object:
                expecting_key[top] = True
                keys[top] = None
        elif token[0].isspace():
            continue
        elif is_object and expecting_key.get(top):
            keys[top] = _string_value(token) if token.startswith('"') else token
        elif top is not None:
            key = keys.get(top)
            if token.startswith('"'):
                if (
                    is_object and key is not None and key.lower() in _DESCRIPTOR_NAME_KEYS
                    and is_withheld_key(_string_value(token))
                ):
                    frames[top][2] = True
            elif token in _JSON_LITERALS:
                continue
            values.append((match.start(), match.end(), top, key))
    if not values:
        return text

    inherited: dict[int, bool] = {}

    def withheld_in(frame: int, key: str | None) -> bool:
        return key is not None and (
            is_withheld_key(key)
            or (frames[frame][2] and key.lower() not in _STRUCTURAL_KEYS)
        )

    def frame_withheld(frame: int) -> bool:
        chain: list[int] = []
        current: int | None = frame
        result = False
        while current is not None and current not in inherited:
            chain.append(current)
            parent, key_in_parent = frames[current][0], frames[current][1]
            if parent is not None and withheld_in(parent, key_in_parent):
                result = True
                break
            current = parent
        else:
            result = inherited.get(current, False) if current is not None else False
        for item in chain:
            inherited[item] = result
        return result

    pieces: list[str] = []
    cursor = 0
    # ``["smtp_password", "..."]``: a row of a settings table, a secret name then its value.
    named_next: set[int] = set()
    for start, end, frame, key in values:
        parent = frames[frame][0]
        if frames[frame][4] and parent is not None and frames[parent][4] and text[start] == '"':
            if frame in named_next:
                named_next.discard(frame)
                pieces.append(text[cursor:start])
                pieces.append(_withhold_json(_string_value(text[start:end])))
                cursor = end
                continue
            if _names_row_secret(_string_value(text[start:end])):
                named_next.add(frame)
        if withheld_in(frame, key) or frame_withheld(frame):
            if text[start] == '"' and is_location_value(key, _string_value(text[start:end])):
                continue
            replacement = _withhold_json(_string_value(text[start:end]))
        elif text[start] == '"':
            # Prose and examples inside a string: a key walk never reads them.
            decoded = _string_value(text[start:end])
            lowered = (key or "").lower()
            masked = mask_string_content(decoded, depth=_depth, credential_context=(
                lowered not in _CONTEXT_NAME_KEYS
                and (frames[frame][3] or frames[frame][2] or _opens_credential_context(key))
            ))
            if masked == decoded:
                continue
            replacement = json.dumps(masked, ensure_ascii=False)
        else:
            continue
        pieces.append(text[cursor:start])
        pieces.append(replacement)
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- YAML and other line-oriented text ---------------------------------------------------------

_YAML_KEY_RE = re.compile(r"""^(["']?)([^\s"':#{}\[\],][^"':#{}\[\]]{0,199}?)\1[ \t]*:(?:[ \t]+(.*))?$""")


def _yaml_line(line: str) -> tuple[int, bool, str | None, str | None, int]:
    """``(content indent, list item, key, value, value offset)`` of one line."""
    stripped = line.lstrip(" ")
    indent = len(line) - len(stripped)
    dash = re.match(r"-[ \t]+", stripped)
    if dash:
        indent += dash.end()
        stripped = stripped[dash.end():]
    offset = len(line) - len(stripped)
    match = _YAML_KEY_RE.match(stripped.rstrip())
    if match is None:
        return indent, bool(dash), None, stripped.rstrip() or None, offset
    value = match.group(3)
    value_offset = offset + match.start(3) if value is not None else len(line)
    return indent, bool(dash), match.group(2).strip(), (value or "").strip() or None, value_offset


_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}
_BACKSLASH_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)


def unescape_backslashes(text: str) -> str:
    return _BACKSLASH_ESCAPE_RE.sub(lambda match: _ESCAPES.get(match.group(1), match.group(1)), text)


def _scalar(text: str) -> tuple[int, int, str, str]:
    """``(start, end, raw value, quote)`` of a YAML/INI/dotenv scalar: a quoted string honouring
    its escapes (``''`` in single quotes), or an unquoted value without its trailing comment."""
    leading = len(text) - len(text.lstrip())
    body = text[leading:]
    if body[:1] in {'"', "'"}:
        quote = body[0]
        index = 1
        pieces: list[str] = []
        while index < len(body):
            char = body[index]
            if quote == '"' and char == "\\" and index + 1 < len(body):
                pieces.append(_ESCAPES.get(body[index + 1], body[index + 1]))
                index += 2
                continue
            if char == quote:
                if quote == "'" and body[index + 1:index + 2] == "'":
                    pieces.append("'")
                    index += 2
                    continue
                return leading + 1, leading + index, "".join(pieces), quote
            pieces.append(char)
            index += 1
        return leading + 1, len(text), "".join(pieces), quote
    comment = re.search(r"[ \t]+[#;]", body)
    value = (body[:comment.start()] if comment else body).rstrip()
    return leading, leading + len(value), value, ""


def _masked_line(line: str, offset: int, key: str | None = None) -> str:
    start, end, raw, _quote = _scalar(line[offset:])
    if key is not None and normalized_key_name(key) in _COOKIE_LABELS and ";" in raw:
        raw = raw.split(";", 1)[0].rstrip()  # Set-Cookie: the cookie, not its attributes
        end = start + len(raw)
    if not raw:
        return line
    return line[:offset + start] + _withhold(raw) + line[offset + end:]


def mask_yaml_text(text: str) -> str:
    """Withhold YAML values under a secret-named key and beside a secret-named descriptor."""
    lines = text.split("\n")
    parsed = [_yaml_line(line) for line in lines]
    masked = [False] * len(lines)

    # Every line below a secret-named key with no inline value (a mapping, a list or a block
    # scalar) is withheld until the indentation returns to that key's level.
    scope: int | None = None
    for index, (indent, item, key, value, _offset) in enumerate(parsed):
        if not lines[index].strip():
            continue
        if scope is not None:
            # A list item's content indent includes its dash, so ``key:\n- value`` is deeper.
            if indent > scope:
                masked[index] = value is not None
                continue
            scope = None
        if key is not None and is_withheld_key(key):
            if value is None or value in {"|", ">", "|-", ">-", "|+", ">+"}:
                scope = indent
            else:
                masked[index] = True

    # A descriptor (``- name: api_key``) whose name is secret: every non-structural value in
    # the same item, at any depth, is withheld.
    for index, (indent, item, key, value, _offset) in enumerate(parsed):
        if not (
            key is not None and key.lower() in _DESCRIPTOR_NAME_KEYS and value is not None
            and is_withheld_key(value.strip("\"'"))
        ):
            continue
        # The item starts at its list dash, or after the last line shallower than it.
        start = index
        if not item:
            for previous in range(index - 1, -1, -1):
                if not lines[previous].strip():
                    continue
                if parsed[previous][0] < indent:
                    break
                start = previous
                if parsed[previous][0] == indent and parsed[previous][1]:
                    break
        for position in range(start, len(lines)):
            other_indent, other_item, other_key, other_value, _ = parsed[position]
            if not lines[position].strip():
                continue
            if position > index and (
                other_indent < indent or (other_item and other_indent == indent)
            ):
                break
            if other_value is None:
                continue
            if other_key is None or other_key.lower() not in _STRUCTURAL_KEYS:
                masked[position] = True

    # Inside an OpenAPI credential context, a credential-shaped token in any value is withheld.
    shaped: dict[int, str] = {}
    context: int | None = None
    for index, (indent, item, key, value, offset) in enumerate(parsed):
        if not lines[index].strip() or masked[index]:
            continue
        if context is not None and indent <= context:
            context = None
        opens = key is not None and _opens_credential_context(key)
        if value is not None and (context is not None or opens) and (
            key is None or key.lower() not in _CONTEXT_NAME_KEYS
        ):
            rewritten = mask_credential_shaped(lines[index][offset:])
            if rewritten != lines[index][offset:]:
                shaped[index] = lines[index][:offset] + rewritten
        if context is None and opens and value is None:
            context = indent

    if not any(masked) and not shaped:
        return text
    return "\n".join(
        _masked_line(line, parsed[index][4], parsed[index][2])
        if masked[index] and not is_location_value(parsed[index][2], parsed[index][3])
        else shaped.get(index, line)
        for index, line in enumerate(lines)
    )


# --- HTML form fields and meta tags ------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"(?i)<(?:input|meta|param|option|textarea)\b([^<>]{0,4096})>")
_HTML_ATTRIBUTE_RE = re.compile(
    r"""([A-Za-z_:][\w:.\-]{0,63})[ \t\r\n]*=[ \t\r\n]*("[^"]{0,4096}"|'[^']{0,4096}'|[^\s"'=<>`]{1,4096})"""
)
_HTML_NAME_ATTRIBUTES = frozenset({"name", "id", "property", "itemprop", "data-name"})
_HTML_VALUE_ATTRIBUTES = frozenset({"value", "content"})


def mask_html_fields(text: str) -> str:
    """Withhold the value of an HTML field or meta tag whose name is secret (a CSRF token,
    an API key in a hidden input)."""
    def tag(match: re.Match[str]) -> str:
        body = match.group(1)
        attributes = list(_HTML_ATTRIBUTE_RE.finditer(body))
        names = [
            item.group(2).strip("\"'") for item in attributes
            if item.group(1).lower() in _HTML_NAME_ATTRIBUTES
        ]
        if not any(is_withheld_key(name) for name in names):
            return match.group(0)
        if _planner_form_token(match.group(0)[1:].split(None, 1)[0].rstrip(">/"), names):
            return match.group(0)
        pieces: list[str] = []
        cursor = 0
        for item in attributes:
            if item.group(1).lower() not in _HTML_VALUE_ATTRIBUTES:
                continue
            quote = item.group(2)[0] if item.group(2)[0] in "\"'" else '"'
            pieces.append(body[cursor:item.start(2)])
            pieces.append(f"{quote}{_withhold(html.unescape(item.group(2).strip(chr(34) + chr(39))))}{quote}")
            cursor = item.end(2)
        pieces.append(body[cursor:])
        start = match.start(1) - match.start(0)
        return match.group(0)[:start] + "".join(pieces) + match.group(0)[start + len(body):]

    return _HTML_TAG_RE.sub(tag, text)


# --- JSON fragments embedded in text (inline scripts, logs) ------------------------------------

_EMBEDDED_OBJECT_RE = re.compile(r"""["']([A-Za-z_$][\w$.\-]{0,199})["'][ \t]*:[ \t]*([{\[])""")
_EMBEDDED_LITERAL_RE = re.compile(r'"(?:[^"\\\n]|\\.){0,4096}"|\'(?:[^\'\\\n]|\\.){0,4096}\'|[{}\[\]]|-?\d[\w.+\-]{0,64}')
_EMBEDDED_SCAN_CHARS = 65_536
_KEY_SUFFIX_RE = re.compile(r"[ \t]*:")


def mask_embedded_objects(text: str) -> str:
    """Withhold every literal inside an object or array that a secret-named key opens."""
    pieces: list[str] = []
    cursor = 0
    for opener in _EMBEDDED_OBJECT_RE.finditer(text):
        if opener.start() < cursor or not is_withheld_key(opener.group(1)):
            continue
        depth = 0
        stop = min(len(text), opener.end(2) - 1 + _EMBEDDED_SCAN_CHARS)
        end = stop
        position = opener.end(2) - 1
        pieces.append(text[cursor:position])
        cursor = position
        for literal in _EMBEDDED_LITERAL_RE.finditer(text, position, stop):
            token = literal.group(0)
            if token in "{[" and len(token) == 1:
                depth += 1
                continue
            if token in "}]" and len(token) == 1:
                depth -= 1
                if depth <= 0:
                    end = literal.end()
                    break
                continue
            if token[0] in "\"'" and _KEY_SUFFIX_RE.match(text, literal.end()):
                continue  # a key names a field; only values are withheld
            pieces.append(text[cursor:literal.start()])
            pieces.append(f'"{_withhold(token[1:-1] if token[0] in chr(34) + chr(39) else token)}"')
            cursor = literal.end()
        pieces.append(text[cursor:end])
        cursor = end
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- ``key = value`` / ``key: value`` / ``"key": "value"`` in any text --------------------------

# The look-behind starts a key only at a word boundary and every repetition is bounded, so the
# scan is linear. A key may be a prose label of up to three words (``Master key: ...``); the
# words are separated by spaces or tabs only, so a label never spans lines. A value that opens
# an object or array is left to the embedded-object pass.
_TEXT_ASSIGNMENT_RE = re.compile(
    # ``<`` too: in ``<add key="ApiKey" ...>`` the tag name is not the first word of a label.
    r"(?<![A-Za-z0-9_.\-<])((?:[A-Za-z][A-Za-z0-9_\-]{0,40}[ \t]){0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,80})"
    r"([\"']?[ \t]*[:=][ \t]*[\"']?)"
    # The value is only looked at, not consumed, so a value that itself starts a label
    # (``description: 'Signing key: ...'``) is scanned again as one.
    r"(?=([^\s,;\"'<>&{`][^\r\n\"'<>&`]{0,511}))"
)
_LINE_HEAD_RE = re.compile(r"[ \t]*(?:(?:export|set)[ \t]+)?")


def _at_line_start(text: str, position: int) -> bool:
    """Whether only blanks (or ``export``) precede ``position`` on its line; a bounded look-back."""
    window_start = max(0, position - 32)
    prefix = text[window_start:position]
    newline = prefix.rfind("\n")
    if newline < 0 and window_start > 0:
        return False
    return bool(_LINE_HEAD_RE.fullmatch(prefix[newline + 1:]))
_COOKIE_LABELS = frozenset({"cookie", "set_cookie"})
# ``Bearer <token>``: an authorization scheme and its credential are one value.
_AUTH_SCHEME_RE = re.compile(r"(?i)(?:bearer|basic|digest|token|negotiate|apikey)[ \t]+[^\s,;]+")
# The tail an unquoted value ends with that is not part of it: an inline comment, a list or
# statement separator, trailing blanks.


def _trimmed_value(value: str) -> str:
    """An unquoted value runs to the end of its line (a password may hold ``;`` or spaces), less
    a trailing comment or separator."""
    if WITHHELD_MARKER_RE.match(value):
        return ""
    comment = re.search(r"(?:[ \t]+[#;]|[ \t]+//)", value)
    trimmed = value[:comment.start()] if comment else value
    # Trailing separators, and a closing bracket only when the value did not open it.
    while trimmed:
        last = trimmed[-1]
        if last in ";, \t\r\n":
            trimmed = trimmed[:-1]
        elif last in ")]}" and trimmed.count({")": "(", "]": "[", "}": "{"}[last]) < trimmed.count(last):
            trimmed = trimmed[:-1]
        else:
            break
    return trimmed


def mask_text_assignments(text: str) -> str:
    """Withhold the value of every secret-named assignment or labelled value in free text."""
    pieces: list[str] = []
    cursor = 0
    for match in _TEXT_ASSIGNMENT_RE.finditer(text):
        # ``Master key`` reads as ``master_key``; a lone neutral ``key`` stays a name.
        label = re.sub(r"[ \t]+", "_", match.group(1))
        if match.start(3) < cursor or not is_withheld_key(label):
            continue
        value = match.group(3)
        if value.startswith("[") and value[1:2] in {"", '"', "'", "{", "[", "]"}:
            continue  # an embedded array: the embedded-object pass owns it
        if normalized_key_name(label) in _COOKIE_LABELS:
            value = value.split(";", 1)[0]
        elif not _at_line_start(text, match.start(1)):
            # Inline (prose, a query, a header list): the value ends at the first blank.
            scheme = _AUTH_SCHEME_RE.match(value)
            value = (scheme.group(0) if scheme else re.split(r"[ \t]", value, maxsplit=1)[0])
        value = _trimmed_value(value)
        if not value or is_location_value(label, value):
            continue
        pieces.append(text[cursor:match.start(3)])
        pieces.append(_withhold(value))
        cursor = match.start(3) + len(value)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- Secret URL parameters (``Location: /cb?code=...``) -----------------------------------------
# An OAuth code, a reset token or a signed URL's signature in a redirect is a credential. In
# model-facing output it becomes a reference the Hunt can still follow.

_URL_SECRET_PARAMS = frozenset({
    "code", "token", "access_token", "id_token", "refresh_token", "reset", "reset_token", "key",
    "api_key", "apikey", "sig", "signature", "password", "passwd", "secret", "client_secret",
    "otp", "session", "sessionid", "x_amz_signature", "x_amz_credential", "x_amz_security_token",
})
_URL_PARAM_RE = re.compile(r"([?&#;])([^=&#\s]{1,100})=([^&#\s]{0,2048})")


# Values of those names that are plainly not credentials: ``?key=blue``, ``?reset=1``,
# ``?code=SKU123`` (a product code), ``?key=user_settings`` (an enum).
_URL_LOWER_ENUM_RE = re.compile(r"^[a-z]{1,24}(?:[_\-][a-z]{1,24}){0,3}$")


def _plain_url_value(value: str) -> bool:
    """For a code/token/reset/key-like parameter only a lowercase word enum, a boolean word or a
    short number (``?reset=1``) is plainly not a credential. ``?code=482193``, ``?token=ABCD-1234``
    and an upper-case code (``SKU123``, ``EXPIRED``) are withheld as references."""
    return bool(
        value.lower() in _PLAIN_WORDS or (value.isdigit() and len(value) <= 3)
        or _URL_LOWER_ENUM_RE.match(value)
    )


def mask_url_secrets(url: Any) -> Any:
    """Withhold the values of secret query/fragment parameters in one URL."""
    if not isinstance(url, str) or "=" not in url:
        return url

    def replace(match: re.Match[str]) -> str:
        name = urllib.parse.unquote_plus(match.group(2))
        if normalized_key_name(name) not in _URL_SECRET_PARAMS and not is_withheld_key(name):
            return match.group(0)
        raw = urllib.parse.unquote_plus(match.group(3))
        if not raw or WITHHELD_MARKER_RE.fullmatch(raw) or raw == MASK or _plain_url_value(raw):
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}={_withhold(raw)}"

    return _URL_PARAM_RE.sub(replace, url)


# --- Percent-encoded assignments (``next=%2Fcb%3Faccess_token%3D...``) -------------------------

_ENCODED_ASSIGNMENT_RE = re.compile(
    r"(?:(?<=%3[Ff])|(?<=%26)|(?<![A-Za-z0-9_.\-%]))([A-Za-z_][A-Za-z0-9_.\-]{0,80})%3[Dd]((?:[^&\s%\"'<>]|%(?!26)[0-9A-Fa-f]{2}){1,1024})"
)


def mask_encoded_assignments(text: str) -> str:
    """Withhold a secret-named assignment nested, percent-encoded, inside a URL parameter."""
    def replace(match: re.Match[str]) -> str:
        if not is_withheld_key(match.group(1)):
            return match.group(0)
        raw = urllib.parse.unquote(match.group(2))
        if is_location_value(match.group(1), raw):
            return match.group(0)
        return f"{match.group(1)}%3D{urllib.parse.quote(_withhold(raw), safe='[]:')}"

    return _ENCODED_ASSIGNMENT_RE.sub(replace, text)


# --- Quoted assignments and PHP defines -----------------------------------------------------------
# ``'password' => '...'`` (PHP arrays), ``password: "..."`` (JS objects, quoted YAML/dotenv),
# ``define('DB_PASSWORD', '...')`` (wp-config.php). The whole quoted value is withheld, escapes
# honoured, so a ``;``, a space or an escaped quote inside it never leaves a tail behind (N56).

_QUOTED_VALUE = r"""(["'`])((?:\\.|(?!\{q})[^\\\r\n]){{0,4096}})\{q}"""
_QUOTED_ASSIGNMENT_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-<$])([\"']?)((?:[A-Za-z][A-Za-z0-9_\-]{0,40}[ \t]){0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,80})\1"
    r"[ \t]*(?:=>|:=|[:=])[ \t]*" + _QUOTED_VALUE.format(q=3)
)
_PHP_DEFINE_RE = re.compile(
    r"(?i)\bdefine[ \t]*\([ \t]*([\"'])([A-Za-z_][A-Za-z0-9_]{0,80})\1[ \t]*,[ \t]*"
    + _QUOTED_VALUE.format(q=3)
)


def _replace_quoted(text: str, pattern: re.Pattern[str], name_group: int, value_group: int) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in pattern.finditer(text):
        name = re.sub(r"[ \t]+", "_", match.group(name_group))
        raw = unescape_backslashes(match.group(value_group))
        if (
            match.start() < cursor or not raw or not is_withheld_key(name)
            or is_location_value(name, raw) or WITHHELD_MARKER_RE.fullmatch(raw)
        ):
            continue
        pieces.append(text[cursor:match.start(value_group)])
        pieces.append(_withhold(raw))
        cursor = match.end(value_group)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


def mask_quoted_assignments(text: str) -> str:
    """Withhold the whole quoted value of a secret-named assignment or array/object entry."""
    return _replace_quoted(text, _QUOTED_ASSIGNMENT_RE, 2, 4)


def mask_php_defines(text: str) -> str:
    """Withhold ``define('DB_PASSWORD', '...')`` values (wp-config.php and the like)."""
    return _replace_quoted(text, _PHP_DEFINE_RE, 2, 4)


# --- XML element values (Hibernate, Maven, Spring, Tomcat) ---------------------------------------
# ``<password>...</password>``, ``<property name="hibernate.connection.password">...</property>``.

_MARKUP_ELEMENT_RE = re.compile(
    r"<([A-Za-z][\w:.\-]{0,63})\b([^<>]{0,1024})(?<!/)>([^<]{1,4096})</\1[ \t]*>"
)


def mask_markup_elements(text: str) -> str:
    """Withhold the text of an element whose tag or name attribute names a secret."""
    def element(match: re.Match[str]) -> str:
        tag = match.group(1).rsplit(":", 1)[-1]
        names = [
            item.group(2).strip("\"'") for item in _HTML_ATTRIBUTE_RE.finditer(match.group(2))
            if item.group(1).lower() in _MARKUP_NAME_ATTRIBUTES
        ]
        if not (_names_secret(tag) or any(_names_secret(name) for name in names)):
            return match.group(0)
        content = match.group(3)
        value = html.unescape(content).strip()
        if not value or WITHHELD_MARKER_RE.fullmatch(value) or value == MASK:
            return match.group(0)
        if _URL_VALUE_RE.match(value) and is_non_secret_value_shape(value):
            return match.group(0)
        leading = len(content) - len(content.lstrip())
        trailing = len(content.rstrip())
        start = match.start(3) - match.start(0)
        whole = match.group(0)
        return whole[:start + leading] + _withhold(value) + whole[start + trailing:]

    return _MARKUP_ELEMENT_RE.sub(element, text)


# --- Markup key/value pairs (web.config, XML settings) -----------------------------------------
# ``<add key="ApiKey" value="..."/>``: the secret name is the value of one attribute and the secret
# the value of another, so neither a key walk nor an assignment scan sees the pair (N56).

_MARKUP_TAG_RE = re.compile(r"<[A-Za-z][\w:.\-]{0,63}([^<>]{0,4096})>")
_MARKUP_NAME_ATTRIBUTES = frozenset({
    "key", "name", "id", "property", "param", "setting", "variable", "env",
})
_MARKUP_VALUE_ATTRIBUTES = frozenset({"value", "content", "default", "val", "data"})


_SHORT_SECRET_NAMES = frozenset({"pw", "db_pw", "user_pw", "passwd_hash"})


def _names_secret(name: str) -> bool:
    """A name that holds a secret, by the narrow configuration contract (not ``Primary key``)."""
    if not name:
        return False
    return is_secret_key_name(name, server_side=True) or normalized_key_name(name) in _SHORT_SECRET_NAMES


# A settings or session table row names its value: ``("session_id", "...")``.
_SESSION_ROW_NAMES = frozenset({
    "session", "session_id", "sessionid", "session_key", "session_token", "sid", "phpsessid",
    "jsessionid", "aspsessionid", "connect_sid",
})


def _names_row_secret(name: str) -> bool:
    """The name cell of a name->value row whose value is a secret."""
    return _names_secret(name) or normalized_key_name(name) in _SESSION_ROW_NAMES


_SETTING_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{1,80}$")


def _row_name_cell(raw: str, column: str | None, columns: list[str] | None) -> bool:
    """A settings row's name cell (``'mailserver_pass'``) in a known, non-secret column. With the
    columns unknown nothing is exempt: a password can look like a setting name."""
    return (
        columns is not None and column is not None and not _names_secret(column)
        and bool(_SETTING_NAME_RE.match(raw)) and _names_row_secret(raw)
    )


def _planner_form_token(tag: str, names: list[str]) -> bool:
    """A CSRF token in an HTML form input or ``<meta name=csrf-token>``, shown to a Hunt planner
    (it needs the token to submit the form). Shared archive views still withhold it."""
    return (
        _COLLECTOR.get() is not None and tag.lower() in {"input", "meta"}
        and any(is_csrf_name(name) for name in names)
    )


def mask_markup_pairs(text: str) -> str:
    """Withhold the value attribute of a markup element whose name attribute is secret."""
    def tag(match: re.Match[str]) -> str:
        body = match.group(1)
        attributes = list(_HTML_ATTRIBUTE_RE.finditer(body))
        names = [
            item.group(2).strip("\"'") for item in attributes
            if item.group(1).lower() in _MARKUP_NAME_ATTRIBUTES
        ]
        secret_name = next((name for name in names if _names_secret(name)), None)
        if secret_name is None or _planner_form_token(match.group(0)[1:].split(None, 1)[0].rstrip(">/"), names):
            return match.group(0)
        pieces: list[str] = []
        cursor = 0
        for item in attributes:
            if item.group(1).lower() not in _MARKUP_VALUE_ATTRIBUTES:
                continue
            raw = item.group(2).strip("\"'")
            if not raw or is_location_value(secret_name, raw):
                continue
            quote = item.group(2)[0] if item.group(2)[0] in "\"'" else '"'
            pieces.append(body[cursor:item.start(2)])
            pieces.append(f"{quote}{_withhold(html.unescape(raw))}{quote}")
            cursor = item.end(2)
        if not pieces:
            return match.group(0)
        pieces.append(body[cursor:])
        start = match.start(1) - match.start(0)
        return match.group(0)[:start] + "".join(pieces) + match.group(0)[start + len(body):]

    return _MARKUP_TAG_RE.sub(tag, text)


# --- HTML table cells (phpinfo, admin and status pages) ----------------------------------------
# ``<tr><td class="e">DB_PASSWORD</td><td class="v">...</td></tr>``: the label is one cell and the
# secret the next ones in the same row; or a header row names the column (N56).

# Inline formatting a cell may wrap its value in: ``<td class="v"><i>...</i></td>``.
_TABLE_CELL_RE = re.compile(
    r"(?i)<(t[dh])\b[^<>]{0,512}>(?:<(?:i|b|em|strong|code|span|font|tt|kbd|samp)\b[^<>]{0,256}>){0,4}([^<]{0,4096})"
)
_ROW_BREAK_RE = re.compile(r"(?i)<(/?)(tr|table)\b")


def _cell_label(text: str) -> str:
    # phpinfo labels environment entries ``$_SERVER['DB_PASSWORD']``.
    return html.unescape(text).strip().strip("$_[]'\" ")


def mask_table_cells(text: str) -> str:
    """Withhold table cells labelled as secrets by their row's first cell or column header."""
    pieces: list[str] = []
    cursor = 0
    previous_end = 0
    columns: list[bool] = []
    row_tags: list[str] = []
    row_labels: list[bool] = []
    row_secret = False
    for cell in _TABLE_CELL_RE.finditer(text):
        breaks = list(_ROW_BREAK_RE.finditer(text, previous_end, cell.start())) if row_tags else []
        if breaks or not row_tags:
            if row_tags and all(tag == "th" for tag in row_tags):
                columns = row_labels  # a header row names the columns of the rows below it
            if any(item.group(2).lower() == "table" for item in breaks):
                columns = []
            row_tags, row_labels, row_secret = [], [], False
        previous_end = cell.end()
        tag, content = cell.group(1).lower(), cell.group(2)
        index = len(row_tags)
        row_tags.append(tag)
        row_labels.append(_names_secret(_cell_label(content)))
        if tag == "th":
            continue
        column_secret = index < len(columns) and columns[index]
        if index == 0 and not column_secret:
            row_secret = row_labels[0]
            continue
        if not (row_secret or column_secret):
            continue
        value = html.unescape(content).strip()
        if not value or value == MASK or WITHHELD_MARKER_RE.fullmatch(value):
            continue
        if _URL_VALUE_RE.match(value) and is_non_secret_value_shape(value):
            continue
        leading = len(content) - len(content.lstrip())
        trailing = len(content.rstrip())
        pieces.append(text[cursor:cell.start(2) + leading])
        pieces.append(_withhold(value))
        cursor = cell.start(2) + trailing
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- SQL dumps -----------------------------------------------------------------------------------
# A leaked ``backup.sql`` carries credentials as quoted literals in ``INSERT`` rows (and pg_dump
# ``COPY`` rows). A literal is withheld when its column is secret-named (from the statement's
# column list or the dump's ``CREATE TABLE``) or when it looks like a key by itself: a key-like
# prefix (``ak_``, ``st_``, ``sk_live_``) or a long mixed-class token. UUIDs and hex digests (a git
# SHA, a SHA-256) are identifiers, not keys, and stay visible (N56).

_SQL_STATEMENT_RE = re.compile(
    r"(?i)\b(?:(CREATE[ \t\r\n]{1,16}TABLE)(?:[ \t\r\n]{1,16}IF[ \t\r\n]{1,16}NOT[ \t\r\n]{1,16}EXISTS)?"
    r"|(INSERT)(?:[ \t\r\n]{1,16}IGNORE)?[ \t\r\n]{1,16}INTO|(COPY))[ \t\r\n]{1,16}"
    r"((?:[`\"\[]?[\w$]{1,64}[`\"\]]?\.){0,2}[`\"\[]?[\w$]{1,64}[`\"\]]?)[ \t\r\n]{0,16}"
)
_SQL_TOKEN_RE = re.compile(
    r"'(?:[^'\\]|\\.|'')*'?|\"(?:[^\"\\]|\\.)*\"?|`[^`]*`?|[(),;]|[^\s'\"`(),;]+|\s+"
)
_SQL_CONSTRAINT_WORDS = frozenset({
    "primary", "unique", "key", "constraint", "index", "foreign", "check", "fulltext", "spatial",
    "exclude", "like", "period",
})
_SQL_VALUES_RE = re.compile(r"(?i)[ \t\r\n]{0,16}VALUES?\b")
_SQL_COPY_FROM_STDIN_RE = re.compile(r"(?i)[ \t\r\n]{0,16}FROM[ \t]{1,16}stdin")
_SQL_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}
# Prefixes that issue API keys and secret tokens (``ak_``, ``sk_live_``, ``whsec_``). Identifier
# prefixes (``pi_``, ``ch_``, ``cus_``, ``u_``) are deliberately absent: an ID is not a secret.
_KEYLIKE_PREFIX_RE = re.compile(
    r"^(?:ak|sk|rk|st|pat|whsec|apikey|api|key|secret|token)_(?:(?:live|test|prod)_)?[A-Za-z0-9]{16,256}$"
)
# Columns that hold identifiers, never secrets, whatever their values look like.
_ID_COLUMN_RE = re.compile(r"^(?:id|ref|uuid|guid|.*_(?:id|ref|uuid|guid))$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_DIGEST_RE = re.compile(r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
# A dump's column lists are remembered for at most this many tables.
_MAX_SQL_TABLES = 256


def _sql_identifier(token: str) -> str:
    return token.strip().split(".")[-1].strip("`\"[]")


def looks_like_key_literal(value: str) -> bool:
    """A literal that is a key by its own issued shape (an API-key prefix); provider formats
    (``AKIA``, ``ghp_``, ``sk_live_`` ...) are withheld everywhere by the provider pass."""
    if _UUID_RE.match(value) or _HEX_DIGEST_RE.match(value):
        return False
    return bool(_KEYLIKE_PREFIX_RE.match(value))


def _is_id_column(column: str | None) -> bool:
    return column is not None and bool(_ID_COLUMN_RE.match(normalized_key_name(column)))


# When a row's columns are unknown (a window far past its CREATE TABLE, an INSERT without a
# column list), every literal is withheld except shapes that are plainly not secrets.
_NUMBER_LITERAL_RE = re.compile(r"^[+-]?\d{1,30}(?:\.\d{1,30})?$")
_DATE_LITERAL_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?(?:Z|[+-]\d{2}:?\d{2})?$"
)
_EMAIL_LITERAL_RE = re.compile(r"^[^@\s'\"]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}$")
_PLAIN_WORDS = frozenset({"true", "false", "yes", "no", "on", "off", "null", "none"})


def plainly_not_secret(value: str) -> bool:
    """Values a fail-closed row keeps: short, numeric, a date, an email or a UUID. A 4-8 digit
    string may be a PIN, an OTP or a recovery code, and 40/64 hex characters may be a key: with
    the column unknown, those are withheld (as references) too."""
    if value.isdigit() and 4 <= len(value) <= 8:
        return False
    return bool(
        len(value) <= 3 or value.lower() in _PLAIN_WORDS or _NUMBER_LITERAL_RE.match(value)
        or _DATE_LITERAL_RE.match(value) or _EMAIL_LITERAL_RE.match(value)
        or _UUID_RE.match(value)
    )


def _sql_secret_literal(value: str, column: str | None, *, unknown: bool = False) -> bool:
    if not value or value.upper() in {"NULL", "\\N"}:
        return False
    if unknown:
        return not plainly_not_secret(value)
    if _is_id_column(column):
        return False
    if column is not None and _names_secret(column):
        return not is_location_value(column, value)
    return looks_like_key_literal(value)


def _sql_unquote(token: str) -> str:
    quote = token[0]
    inner = token[1:-1] if len(token) > 1 and token.endswith(quote) else token[1:]
    if quote == "'":
        inner = inner.replace("''", "'")
        inner = re.sub(r"\\(.)", lambda match: _SQL_ESCAPES.get(match.group(1), match.group(1)), inner)
    return inner


def _sql_columns(text: str, position: int) -> tuple[list[str], int]:
    """The column names of the parenthesised definition or list at ``position``, and its end."""
    columns: list[str] = []
    depth = 0
    expect_name = False
    for token in _SQL_TOKEN_RE.finditer(text, position):
        value = token.group(0)
        if value == "(":
            depth += 1
            expect_name = depth == 1
            continue
        if value.isspace():
            continue
        if depth <= 0 or value == ";":
            return columns, token.start()
        if value == ")":
            depth -= 1
            if depth == 0:
                return columns, token.end()
        elif value == ",":
            expect_name = depth == 1
        elif expect_name:
            expect_name = False
            name = _sql_identifier(value)
            if name.lower() not in _SQL_CONSTRAINT_WORDS:
                columns.append(name)
    return columns, len(text)


def _first_tuple_width(text: str, position: int) -> int | None:
    """How many values the first row of a VALUES list holds (``None`` if it is cut off)."""
    depth, width, seen = 0, 0, 0
    for token in _SQL_TOKEN_RE.finditer(text, position):
        value = token.group(0)
        seen += 1
        if seen > 4_096:
            return None
        if value == "(":
            depth += 1
            if depth == 1:
                width = 1
        elif value == ")":
            depth -= 1
            if depth == 0:
                return width
        elif value == "," and depth == 1:
            width += 1
        elif value == ";" and depth == 0:
            return None
    return None


def _sql_rows(
    text: str, position: int, columns: list[str] | None, pieces: list[str], cursor: int,
) -> tuple[int, int]:
    """Withhold the secret literals of ``VALUES (...), (...);``; returns (end, cursor)."""
    depth = 0
    index = 0
    named = False  # the previous literal of this row named a secret (``'mailserver_pass', '...'``)
    for token in _SQL_TOKEN_RE.finditer(text, position):
        value = token.group(0)
        if value == "(":
            depth += 1
            if depth == 1:
                index, named = 0, False
        elif value == ")":
            depth -= 1
        elif value == ",":
            if depth == 1:
                index += 1
        elif value == ";" and depth <= 0:
            return token.end(), cursor
        elif depth == 1 and value[0] in "'\"":
            raw = _sql_unquote(value)
            column = columns[index] if columns is not None and index < len(columns) else None
            if not named and _row_name_cell(raw, column, columns):
                secret, named = False, True  # a settings row's name cell: its value follows
            else:
                secret = (named and not _is_id_column(column) and bool(raw)) or _sql_secret_literal(
                    raw, column, unknown=column is None)
                named = False
            if secret:
                pieces.append(text[cursor:token.start()])
                pieces.append(f"{value[0]}{_withhold(raw)}{value[0]}")
                cursor = token.end()
    return len(text), cursor


_COPY_ESCAPES = {"t": "\t", "n": "\n", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "\\": "\\"}
_COPY_ESCAPE_RE = re.compile(r"\\(.)", re.DOTALL)
# The table whose COPY block is open (its header seen, its ``\.`` not yet), per resource.
OPEN_COPY_KEY = "\0copy_open"


def copy_field_value(field: str) -> str | None:
    """A COPY text-format field as the value it carries; ``\\N`` is NULL (``None``)."""
    if field == "\\N":
        return None
    return _COPY_ESCAPE_RE.sub(lambda match: _COPY_ESCAPES.get(match.group(1), match.group(1)), field)


def _copy_line(
    text: str, line_start: int, line: str, columns: list[str] | None, pieces: list[str], cursor: int,
    *, partial_head: bool = False,
) -> int:
    """Withhold the secret fields of one COPY row. ``partial_head``: the line was cut at its
    start (a window), so its fields align to the columns' end and its first field is a tail."""
    fields = line.split("\t")
    if columns is not None and len(fields) != len(columns):
        if partial_head and len(fields) < len(columns):
            columns = columns[len(columns) - len(fields):]
        elif len(fields) < len(columns):
            columns = columns[:len(fields)]  # cut at the window's end
        else:
            columns = None  # contradicts the carried columns: fail closed
    field_start = line_start
    named = False
    for index, field in enumerate(fields):
        column = columns[index] if columns is not None and index < len(columns) else None
        escaped = field.rstrip("\r")
        raw = copy_field_value(escaped)
        if raw is None or raw == "":
            secret = named = False
        elif partial_head and index == 0 and column is None:
            secret, named = not _plain_fragment(raw) and _sql_secret_literal(raw, None, unknown=True), False
        elif not named and _row_name_cell(raw, column, columns):
            secret, named = False, True
        else:
            secret = (named and not _is_id_column(column)) or _sql_secret_literal(
                raw, column, unknown=column is None)
            named = False
        if secret:
            pieces.append(text[cursor:field_start])
            pieces.append(_withhold(raw))
            cursor = field_start + len(escaped)
        field_start += len(field) + 1
    return cursor


def _copy_rows(
    text: str, position: int, columns: list[str] | None, pieces: list[str], cursor: int,
) -> tuple[int, int, bool]:
    """Withhold the secret fields of pg_dump ``COPY ... FROM stdin;`` rows up to ``\\.``;
    returns (end, cursor, whether the block ended in this text)."""
    line_start = text.find("\n", position)
    if line_start < 0:
        return len(text), cursor, False
    line_start += 1
    while line_start < len(text):
        line_end = text.find("\n", line_start)
        line_end = len(text) if line_end < 0 else line_end
        line = text[line_start:line_end]
        if line.rstrip("\r") == "\\.":
            return line_end, cursor, True
        cursor = _copy_line(text, line_start, line, columns, pieces, cursor)
        line_start = line_end + 1
    return len(text), cursor, False


_COPY_RUN_LINES = 3


def _mask_orphan_copy(
    text: str, end: int, tables: dict[str, list[str]], pieces: list[str], cursor: int,
) -> int:
    """COPY rows before the first statement of a window: a run of lines with one tab count.

    The open block's carried columns apply only when exactly that one block is open and its
    column count matches; otherwise every field fails closed by its shape."""
    lines: list[tuple[int, str]] = []
    position = 0
    while position < end:
        line_end = text.find("\n", position, end)
        line_end = end if line_end < 0 else line_end
        lines.append((position, text[position:line_end]))
        position = line_end + 1
    counts: dict[int, int] = {}
    for _start, line in lines[1:]:
        tabs = line.count("\t")
        if tabs:
            counts[tabs] = counts.get(tabs, 0) + 1
    if not counts:
        return cursor
    tabs, run = max(counts.items(), key=lambda item: item[1])
    if run < _COPY_RUN_LINES and not any(line.rstrip("\r") == "\\." for _start, line in lines):
        return cursor
    open_tables = tables.get(OPEN_COPY_KEY) or []
    carried = tables.get("copy:" + open_tables[0]) if len(open_tables) == 1 else None
    columns = carried if carried is not None and len(carried) == tabs + 1 else None
    for index, (line_start, line) in enumerate(lines):
        if line.rstrip("\r") == "\\.":
            tables.pop(OPEN_COPY_KEY, None)  # the block ended: what follows is not its rows
            break
        if "\t" not in line:
            continue
        cursor = _copy_line(text, line_start, line, columns, pieces, cursor, partial_head=index == 0)
    return cursor


# A window that starts inside a VALUES list: ``...'),(12,'bob','...');`` before any statement.
_SQL_ORPHAN_ROWS_RE = re.compile(r"\)[ \t\r\n]{0,8},[ \t\r\n]{0,8}\(|'[ \t]{0,8}\)[ \t]{0,8}[;,]")
_SQL_LITERAL_RE = re.compile(r"'(?:[^'\\\r\n]|\\.|''){0,4096}'")


# A string literal closing a row, then the next row or statement: ``'),(`` / ``');``.
_SQL_ROW_END_RE = re.compile(r"'[ \t]{0,8}\)[ \t\r\n]{0,8}(?:,[ \t\r\n]{0,8}\(|;)")


def _orphan_row_signals(text: str, end: int) -> int:
    """How many row endings a window shows before its first statement (two are enough)."""
    count = 0
    for _match in _SQL_ROW_END_RE.finditer(text, 0, end):
        count += 1
        if count >= 2:
            break
    return count


# The cut-off tail of a plainly non-secret literal: a date or time, a number, a host or email end.
_PLAIN_FRAGMENT_RE = re.compile(
    r"^(?:[\d\s:.\-+TZ]{1,40}|[A-Za-z0-9.\-]{0,64}@?[A-Za-z0-9\-]{0,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24})$"
)


def _plain_fragment(value: str) -> bool:
    """A cut tail that is plainly part of a date, time, number, host or email; a run of 4+
    digits alone may be a PIN's tail and is not."""
    return bool(_PLAIN_FRAGMENT_RE.match(value)) and not (value.isdigit() and len(value) >= 4)


# What lies between two literals of one VALUES list: punctuation, numbers, NULL, hex blobs.
_SQL_GAP_RE = re.compile(r"(?i)(?:[\s,();.+\-0-9]|null|true|false|_binary|0x[0-9a-f]+)*")


def _orphan_literals(text: str, end: int) -> tuple[int, list[re.Match[str]]]:
    """``(start, literals)`` of a window that may begin inside a literal: of the two quote
    parities, the one whose gaps read as a VALUES list (punctuation and numbers, not words)."""
    first_quote = text.find("'", 0, end)
    best: tuple[int, int, list[re.Match[str]]] | None = None
    for start in (0, first_quote + 1) if first_quote >= 0 else (0,):
        literals = list(_SQL_LITERAL_RE.finditer(text, start, end))
        edges = [start, *(item for literal in literals for item in (literal.start(), literal.end()))]
        gaps = [text[edges[index]:edges[index + 1]] for index in range(0, len(edges) - 1, 2)]
        score = sum(1 if _SQL_GAP_RE.fullmatch(gap) else -2 for gap in gaps)
        if best is None or score > best[0]:
            best = (score, start, literals)
    return (best[1], best[2]) if best else (0, [])


def _mask_orphan_rows(text: str, end: int, pieces: list[str], cursor: int) -> int:
    """Rows before the first statement of a window: their columns are unknown, so fail closed.
    A window that opens inside a literal withholds that literal's tail too."""
    start, literals = _orphan_literals(text, end)
    if start:
        tail = text[:start - 1]
        if tail and not _plain_fragment(tail) and _sql_secret_literal(tail, None, unknown=True):
            pieces.append(_withhold(tail))
            cursor = start - 1
    for literal in literals:
        raw = _sql_unquote(literal.group(0))
        if _sql_secret_literal(raw, None, unknown=True):
            pieces.append(text[cursor:literal.start()])
            pieces.append(f"'{_withhold(raw)}'")
            cursor = literal.end()
    return cursor


def mask_sql_values(text: str) -> str:
    """Withhold credential literals in SQL dump ``INSERT`` and ``COPY`` rows (one linear scan).

    Column names come from the rows' own column list, the dump's ``CREATE TABLE``, or (inside a
    Hunt, for windows of one resource) what earlier windows of the same dump showed. Rows whose
    columns stay unknown fail closed.
    """
    collector = _COLLECTOR.get()
    carried = (
        collector.sql_tables.setdefault(collector.sql_path, {})
        if collector is not None and collector.sql_path else None
    )
    tables: dict[str, list[str]] = carried if carried is not None else {}
    pieces: list[str] = []
    cursor = 0
    position = 0
    first = _SQL_STATEMENT_RE.search(text)
    prefix_end = first.start() if first else len(text)
    if prefix_end and (carried is not None or "\n\\.\n" in text or "COPY " in text[:prefix_end + 64]):
        cursor = _mask_orphan_copy(text, prefix_end, tables, pieces, cursor)
    if prefix_end and _SQL_ORPHAN_ROWS_RE.search(text, 0, prefix_end) and (
        first or carried or _orphan_row_signals(text, prefix_end) >= 2
    ):
        cursor = _mask_orphan_rows(text, prefix_end, pieces, cursor)
    while True:
        statement = _SQL_STATEMENT_RE.search(text, position)
        if statement is None:
            break
        table = _sql_identifier(statement.group(4)).lower()
        after = statement.end()
        if statement.group(1):
            columns, end = _sql_columns(text, after)
            if columns and (table in tables or len(tables) < _MAX_SQL_TABLES):
                tables[table] = columns
            position = max(end, after)
            continue
        columns = tables.get(table)
        if text.startswith("(", after):
            columns, after = _sql_columns(text, after)
            if columns and (table in tables or len(tables) < _MAX_SQL_TABLES):
                tables[table] = columns
        if statement.group(3):
            if not _SQL_COPY_FROM_STDIN_RE.match(text, after):
                position = after
                continue
            if columns:
                tables["copy:" + table] = columns
            tables[OPEN_COPY_KEY] = [table]
            position, cursor, ended = _copy_rows(text, after, columns, pieces, cursor)
            if ended:
                tables.pop(OPEN_COPY_KEY, None)
            continue
        values = _SQL_VALUES_RE.match(text, after)
        if values is None:
            position = after
            continue
        width = _first_tuple_width(text, values.end())
        if columns is not None and width is not None and width != len(columns):
            # The rows contradict the remembered columns (another dump at this path, a changed
            # table): forget them and fail closed.
            tables.pop(table, None)
            columns = None
        position, cursor = _sql_rows(text, values.end(), columns, pieces, cursor)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- Provider-format secrets anywhere ----------------------------------------------------------

_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    r"(?:[^-]|-(?!----END ))*(?:-----END [A-Z ]{0,24}PRIVATE KEY-----)?"
)


# crypt(3) password hashes (htpasswd, /etc/shadow): md5-crypt, apr1, sha256/512-crypt, yescrypt.
_CRYPT_HASH_RE = re.compile(r"\$(?:1|apr1|5|6|y|gy)\$[./A-Za-z0-9$=]{8,200}")


def mask_provider_secrets(text: str) -> str:
    """Mask every provider-format secret, screened or not, and every private key block."""
    text = _PRIVATE_KEY_BLOCK_RE.sub(lambda match: _withhold(match.group(0)), text)
    text = _CRYPT_HASH_RE.sub(lambda match: _withhold(match.group(0)), text)
    for label, pattern in SELF_EVIDENT_SECRET_PATTERNS:
        if label == "private_key" or not pattern.groups:
            continue

        def replace(match: re.Match[str]) -> str:
            whole = match.group(0)
            start, end = match.start(1) - match.start(0), match.end(1) - match.start(0)
            return whole[:start] + _withhold(match.group(1)) + whole[end:]

        text = pattern.sub(replace, text)
    return text


# An INI/TOML section header (``[client]`` in my.cnf, ``[database]`` in php.ini) starts with ``[``
# but is not JSON: such a body takes the text passes.
_INI_SECTION_RE = re.compile(r"\A\s*\[[^\[\]\"{}:,\r\n]{1,200}\][ \t]*(?:\r?\n|\Z)")
# JSON string values nest other formats (a config file inside an LFI response, a dump in a field):
# the text passes run over each decoded string, at most this deep.
_MAX_NESTED_DEPTH = 2
_NESTED_FORMAT_HINT_RE = re.compile(r"[=:<(\n]")


def _is_json_text(text: str) -> bool:
    return text.lstrip()[:1] in {"{", "["} and not _INI_SECTION_RE.match(text)


def _mask_text_passes(text: str) -> str:
    text = mask_yaml_text(text)
    text = mask_html_fields(text)
    text = mask_markup_pairs(text)
    text = mask_markup_elements(text)
    text = mask_table_cells(text)
    text = mask_sql_values(text)
    text = mask_php_defines(text)
    text = mask_quoted_assignments(text)
    text = mask_embedded_objects(text)
    text = mask_encoded_assignments(text)
    return mask_text_assignments(text)


def mask_body_text(text: str, *, _depth: int = 0) -> str:
    """Every masking pass that applies to one body's text."""
    text = _mask_known_values(text)
    if _is_json_text(text):
        text = mask_json_text(text, _depth=_depth)
    else:
        text = _mask_text_passes(text)
    return mask_provider_secrets(text)


def _mask_nested_text(text: str, depth: int) -> str:
    """The formats a JSON string value can carry: JSON, a config file, markup, a SQL dump."""
    if depth >= _MAX_NESTED_DEPTH or len(text) < 6 or not _NESTED_FORMAT_HINT_RE.search(text):
        return text
    if _is_json_text(text):
        return mask_json_text(text, _depth=depth + 1)
    return _mask_text_passes(text)


def withhold_body_secrets(value: Any) -> Any:
    """A masked view of one archived body: text, with every secret value withheld."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="replace")
    elif isinstance(value, (dict, list)):
        # A body the storage layer decoded as JSON: serialize it once and mask the text, so the
        # same rules apply to a stored object and to stored text.
        value = json.dumps(value, ensure_ascii=False)
    elif not isinstance(value, str):
        return value
    return mask_body_text(value)


__all__ = [
    "KnownValueScrubber",
    "MAX_WITHHELD_VALUES",
    "holds_withheld_material",
    "mask_url_secrets",
    "scrub_known_values",
    "WITHHELD_MARKER_RE",
    "WITHHELD_REF_RE",
    "WithheldValues",
    "active_withheld_values",
    "collecting_withheld_values",
    "is_location_value",
    "looks_like_key_literal",
    "mask_markup_pairs",
    "mask_sql_values",
    "mask_table_cells",
    "withheld_preview",
    "is_withheld_key",
    "mask_body_text",
    "mask_credential_shaped",
    "mask_embedded_objects",
    "mask_html_fields",
    "mask_json_text",
    "mask_provider_secrets",
    "mask_string_content",
    "mask_text_assignments",
    "mask_yaml_text",
    "withhold_body_secrets",
]
