"""Decode a quoted value's escapes by the grammar of the format it was written in.

A withheld value is sealed as the value the server holds, and later sent back by reference, so
the escapes of its source format must be decoded exactly: ``"\\u00e9"`` in YAML is ``é``,
``\\x41`` in a JavaScript string is ``A``, ``\\101`` in a PostgreSQL COPY field is ``A``, and
``'\\n'`` in a PHP single-quoted string is a backslash and an ``n``. An escape a grammar does not
define keeps what that grammar keeps (the backslash, or the character alone).

Every decoder is one left-to-right regular-expression pass with bounded repetitions.
"""

from __future__ import annotations

import re


def _code_point(digits: str, radix: int) -> str:
    value = int(digits, radix)
    return chr(value) if value <= 0x10FFFF else ""


def _join_surrogates(text: str) -> str:
    """``\\ud83d\\ude00`` decodes to two surrogates; a valid pair is one character."""
    if not any("\ud800" <= char <= "\udfff" for char in text):
        return text
    try:
        return text.encode("utf-16", "surrogatepass").decode("utf-16")
    except UnicodeError:
        return text


# JavaScript / JSON / Python-style string literals (single, double or backtick quoted).
_JS_SIMPLE = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\n": "", "\r": ""}
_JS_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}|0(?![0-9])"
    r"|([0-3][0-7]{0,2}|[4-7][0-7]?)|(\r\n|.))",
    re.DOTALL,
)


def _js_escape(match: re.Match[str]) -> str:
    hex2, hex4, braced, octal, other = match.groups()
    if hex2 or hex4 or braced:
        return _code_point(hex2 or hex4 or braced, 16)
    if octal:
        return chr(int(octal, 8))
    if other is None:
        return "\0"
    if other == "\r\n":
        return ""  # a line continuation
    return _JS_SIMPLE.get(other, other)  # any other escaped character is itself


def unescape_js(text: str) -> str:
    """A JavaScript, JSON or Python string literal's content as the string it denotes."""
    if "\\" not in text:
        return text
    return _join_surrogates(_JS_ESCAPE_RE.sub(_js_escape, text))


# YAML double-quoted scalars (YAML 1.2, 5.7). An undefined escape is an error in YAML; it is kept.
_YAML_SIMPLE = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "\t": "\t", "n": "\n", "v": "\v", "f": "\f",
    "r": "\r", "e": "\x1b", " ": " ", '"': '"', "/": "/", "\\": "\\", "N": "\x85", "_": "\xa0",
    "L": "\u2028", "P": "\u2029",
}
_YAML_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|(.))", re.DOTALL
)


def _yaml_escape(match: re.Match[str]) -> str:
    hex2, hex4, hex8, other = match.groups()
    if hex2 or hex4 or hex8:
        return _code_point(hex2 or hex4 or hex8, 16)
    return _YAML_SIMPLE.get(other, match.group(0))


def unescape_yaml_double(text: str) -> str:
    """A YAML double-quoted scalar's content (between the quotes) as the string it denotes."""
    if "\\" not in text:
        return text
    return _join_surrogates(_YAML_ESCAPE_RE.sub(_yaml_escape, text))


# PHP: a single-quoted string knows only ``\\`` and ``\'``; a double-quoted one keeps the
# backslash of an escape it does not define.
_PHP_SINGLE_RE = re.compile(r"\\([\\'])")
_PHP_DOUBLE_SIMPLE = {
    "n": "\n", "t": "\t", "r": "\r", "v": "\v", "e": "\x1b", "f": "\f", "\\": "\\", "$": "$",
    '"': '"',
}
_PHP_DOUBLE_RE = re.compile(
    r"\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|u\{([0-9A-Fa-f]{1,6})\}|(.))", re.DOTALL
)


def _php_double_escape(match: re.Match[str]) -> str:
    octal, hex2, braced, other = match.groups()
    if octal:
        return chr(int(octal, 8) & 0xFF)
    if hex2:
        return chr(int(hex2, 16))
    if braced:
        return _code_point(braced, 16)
    return _PHP_DOUBLE_SIMPLE.get(other, match.group(0))


def unescape_php(text: str, quote: str) -> str:
    """A PHP string literal's content, by its quote."""
    if "\\" not in text:
        return text
    if quote == "'":
        return _PHP_SINGLE_RE.sub(lambda match: match.group(1), text)
    return _PHP_DOUBLE_RE.sub(_php_double_escape, text)


# PostgreSQL COPY text format: ``\b \f \n \r \t \v``, ``\digits`` (one to three octal digits)
# and ``\xdigits`` (one or two hex digits) are bytes in the dump's encoding; any other
# backslashed character is itself.
_COPY_SIMPLE = {"b": 0x08, "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09, "v": 0x0B}
_COPY_ESCAPE_RE = re.compile(r"\\(?:([0-7]{1,3})|x([0-9A-Fa-f]{1,2})|(.))", re.DOTALL)


def unescape_copy_text(field: str) -> str:
    """One COPY text-format field (not ``\\N``) as the value it carries."""
    if "\\" not in field:
        return field
    out = bytearray()
    cursor = 0
    for match in _COPY_ESCAPE_RE.finditer(field):
        out += field[cursor:match.start()].encode("utf-8", "surrogatepass")
        octal, hex2, other = match.groups()
        if octal:
            out.append(int(octal, 8) & 0xFF)
        elif hex2:
            out.append(int(hex2, 16))
        elif other in _COPY_SIMPLE:
            out.append(_COPY_SIMPLE[other])
        else:
            out += other.encode("utf-8", "surrogatepass")
        cursor = match.end()
    out += field[cursor:].encode("utf-8", "surrogatepass")
    return out.decode("utf-8", errors="replace")


__all__ = ["unescape_copy_text", "unescape_js", "unescape_php", "unescape_yaml_double"]
