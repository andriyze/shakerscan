"""One string argument of a GraphQL document, as an injection proof's tested field.

A GraphQL API takes its inputs as arguments inside the query text (``pastes(filter: "a")``), not
as URL or body fields, so a verifier that rewrites one field cannot reach them. The field path
``graphql:<name>`` names the one string-literal argument (or input-object field) called
``<name>`` in the request body's ``query`` document; the verifier reads it decoded and writes its
payload back as a correctly escaped GraphQL string. Nothing else in the document changes.
"""
from __future__ import annotations

import json
import re

FIELD_PREFIX = "graphql:"
MAX_DOCUMENT_CHARS = 8_000
_NAME = re.compile(r"[_A-Za-z][_0-9A-Za-z]{0,63}\Z")
_OPERATION = re.compile(r"\s*(query|mutation|subscription)\b")


class GraphQLArgumentError(ValueError):
    """The document does not hold exactly one string argument of that name."""


def is_field(field_path: str) -> bool:
    return str(field_path or "").startswith(FIELD_PREFIX)


def argument_name(field_path: str) -> str:
    name = str(field_path or "")[len(FIELD_PREFIX):] if is_field(field_path) else str(field_path or "")
    if not _NAME.match(name):
        raise GraphQLArgumentError("a GraphQL argument name is a GraphQL identifier")
    return name


def operation_kind(document: str) -> str:
    """``query``, ``mutation`` or ``subscription``; a bare selection set is a query."""
    text = re.sub(r"#[^\n\r]*", " ", str(document or ""))
    match = _OPERATION.match(text)
    return match.group(1) if match else "query"


def _string_end(document: str, start: int) -> int:
    """Index just past the string literal opening at ``start``."""
    index = start + 1
    while index < len(document):
        char = document[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index + 1
        if char in "\r\n":
            break
        index += 1
    raise GraphQLArgumentError("unterminated GraphQL string")


def argument_span(document: str, name: str) -> tuple[int, int, str]:
    """``(start, end, value)`` of the one ``name: "..."`` string argument in ``document``."""
    if not isinstance(document, str) or not document.strip() or len(document) > MAX_DOCUMENT_CHARS:
        raise GraphQLArgumentError("the request carries no GraphQL document of a bounded size")
    if '"""' in document:
        raise GraphQLArgumentError("block strings are not rewritten")
    name = argument_name(name)
    found: list[tuple[int, int, str]] = []
    index = 0
    previous = ""  # the last token outside strings and comments
    while index < len(document):
        char = document[index]
        if char == "#":
            while index < len(document) and document[index] not in "\r\n":
                index += 1
            continue
        if char == '"':
            end = _string_end(document, index)
            index = end
            previous = "string"
            continue
        if char == "_" or char.isalpha():
            match = re.compile(r"[_0-9A-Za-z]+").match(document, index)
            token = match.group(0)
            after = match.end()
            colon = re.compile(r"\s*:\s*").match(document, after)
            if token == name and previous != "$" and colon and document[colon.end():colon.end() + 1] == '"':
                start = colon.end()
                end = _string_end(document, start)
                try:
                    value = json.loads(document[start:end])
                except ValueError as exc:
                    raise GraphQLArgumentError("the argument is not a plain GraphQL string") from exc
                found.append((start, end, value))
                index, previous = end, "string"
                continue
            index, previous = after, token
            continue
        if not char.isspace():
            previous = char
        index += 1
    if len(found) != 1:
        raise GraphQLArgumentError(
            f"the document holds {len(found)} string arguments named {name}; exactly one is tested")
    return found[0]


def argument_value(document: str, field_path: str) -> str:
    return argument_span(document, argument_name(field_path))[2]


def with_argument(document: str, field_path: str, replacement: str) -> str:
    """``document`` with the named argument's value replaced by ``replacement``, escaped."""
    start, end, _value = argument_span(document, argument_name(field_path))
    return document[:start] + json.dumps(str(replacement), ensure_ascii=True) + document[end:]
