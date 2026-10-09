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

import json
import math
import re
from typing import Any

try:
    from capabilities.secret_material import (
        SELF_EVIDENT_SECRET_PATTERNS,
        is_non_secret_value_shape,
        is_redactable_key_name,
    )
except ModuleNotFoundError:  # package import layout
    from api.capabilities.secret_material import (
        SELF_EVIDENT_SECRET_PATTERNS,
        is_non_secret_value_shape,
        is_redactable_key_name,
    )

try:
    from redaction import MASK, is_sensitive_key
except ModuleNotFoundError:  # package import layout
    from scanner.redaction import MASK, is_sensitive_key

_MASKED_JSON_VALUE = json.dumps(MASK)
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
    if text.lower() in _NEUTRAL_KEYS:
        return False
    return is_redactable_key_name(text) or is_sensitive_key(text)


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
        lambda match: MASK if _is_credential_shaped(match.group(0)) else match.group(0), text,
    )


def mask_string_content(text: str, *, credential_context: bool) -> str:
    """Withhold the secrets a string *documents*: labelled values (``Master key: ...``) and,
    in a credential context, every credential-shaped token."""
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


def mask_json_text(text: str) -> str:
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
            frames.append([top, key_in_parent, False, context])
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
    for start, end, frame, key in values:
        if withheld_in(frame, key) or frame_withheld(frame):
            replacement = _MASKED_JSON_VALUE
        elif text[start] == '"':
            # Prose and examples inside a string: a key walk never reads them.
            decoded = _string_value(text[start:end])
            lowered = (key or "").lower()
            masked = mask_string_content(decoded, credential_context=(
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


def _masked_line(line: str, offset: int) -> str:
    return line[:offset] + MASK


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
        _masked_line(line, parsed[index][4]) if masked[index] else shaped.get(index, line)
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
        if not any(
            item.group(1).lower() in _HTML_NAME_ATTRIBUTES
            and is_withheld_key(item.group(2).strip("\"'"))
            for item in attributes
        ):
            return match.group(0)
        pieces: list[str] = []
        cursor = 0
        for item in attributes:
            if item.group(1).lower() not in _HTML_VALUE_ATTRIBUTES:
                continue
            quote = item.group(2)[0] if item.group(2)[0] in "\"'" else '"'
            pieces.append(body[cursor:item.start(2)])
            pieces.append(f"{quote}{MASK}{quote}")
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
            pieces.append(f'"{MASK}"')
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
    r"(?<![A-Za-z0-9_.\-])((?:[A-Za-z][A-Za-z0-9_\-]{0,40}[ \t]){0,2}[A-Za-z_][A-Za-z0-9_.\-]{0,80})"
    r"([\"']?[ \t]*[:=][ \t]*[\"']?)"
    # The value is only looked at, not consumed, so a value that itself starts a label
    # (``description: 'Signing key: ...'``) is scanned again as one.
    r"(?=([^\s,;\"'<>&{\[][^\s,;\"'<>&]{0,199}))"
)


def mask_text_assignments(text: str) -> str:
    """Withhold the value of every secret-named assignment or labelled value in free text."""
    pieces: list[str] = []
    cursor = 0
    for match in _TEXT_ASSIGNMENT_RE.finditer(text):
        # ``Master key`` reads as ``master_key``; a lone neutral ``key`` stays a name.
        if match.start(3) < cursor or not is_withheld_key(re.sub(r"[ \t]+", "_", match.group(1))):
            continue
        pieces.append(text[cursor:match.start(3)])
        pieces.append(MASK)
        cursor = match.end(3)
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return "".join(pieces)


# --- Provider-format secrets anywhere ----------------------------------------------------------

_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    r"(?:[^-]|-(?!----END ))*(?:-----END [A-Z ]{0,24}PRIVATE KEY-----)?"
)


def mask_provider_secrets(text: str) -> str:
    """Mask every provider-format secret, screened or not, and every private key block."""
    text = _PRIVATE_KEY_BLOCK_RE.sub(MASK, text)
    for label, pattern in SELF_EVIDENT_SECRET_PATTERNS:
        if label == "private_key" or not pattern.groups:
            continue

        def replace(match: re.Match[str]) -> str:
            whole = match.group(0)
            start, end = match.start(1) - match.start(0), match.end(1) - match.start(0)
            return whole[:start] + MASK + whole[end:]

        text = pattern.sub(replace, text)
    return text


def _is_json_text(text: str) -> bool:
    return text.lstrip()[:1] in {"{", "["}


def mask_body_text(text: str) -> str:
    """Every masking pass that applies to one body's text."""
    if _is_json_text(text):
        text = mask_json_text(text)
    else:
        text = mask_yaml_text(text)
        text = mask_html_fields(text)
        text = mask_embedded_objects(text)
        text = mask_text_assignments(text)
    return mask_provider_secrets(text)


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
