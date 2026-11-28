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


class GraphQLArgumentError(ValueError):
    """The document does not hold exactly one string argument of that name."""


def is_field(field_path: str) -> bool:
    return str(field_path or "").startswith(FIELD_PREFIX)


def argument_name(field_path: str) -> str:
    name = str(field_path or "")[len(FIELD_PREFIX):] if is_field(field_path) else str(field_path or "")
    if not _NAME.match(name):
        raise GraphQLArgumentError("a GraphQL argument name is a GraphQL identifier")
    return name


def _skip_string(document: str, start: int) -> int:
    """Index just past the string or block string opening at ``start``."""
    if document.startswith('"""', start):
        index = start + 3
        while index < len(document):
            if document.startswith('\\"""', index):
                index += 4
            elif document.startswith('"""', index):
                return index + 3
            else:
                index += 1
        raise GraphQLArgumentError("unterminated GraphQL block string")
    return _string_end(document, start)


def _tokens(document: str) -> list[str]:
    """The document's names and punctuators in order; a string is the one token ``"``.

    Ignored tokens are dropped as the GraphQL grammar drops them: white space, commas, a byte
    order mark and comments. Nothing inside a string or a comment is a token, so a keyword
    written there is never read as one.
    """
    tokens: list[str] = []
    index = 0
    while index < len(document):
        char = document[index]
        if char in " \t\r\n,\ufeff":
            index += 1
        elif char == "#":
            while index < len(document) and document[index] not in "\r\n":
                index += 1
        elif char == '"':
            index = _skip_string(document, index)
            tokens.append('"')
        elif char == "_" or (char.isascii() and char.isalpha()):
            end = index + 1
            while end < len(document) and (document[end] == "_" or (
                    document[end].isascii() and document[end].isalnum())):
                end += 1
            tokens.append(document[index:end])
            index = end
        else:
            tokens.append(char)
            index += 1
    return tokens


_CLOSERS = {"{": "}", "(": ")", "[": "]"}


def operation_kinds(document: str) -> tuple[str, ...]:
    """The kind of every operation the document defines, in order.

    Each top-level definition is read: a bare selection set is a ``query``, an operation says
    what it is, a fragment defines no operation. The keyword is found wherever its definition
    starts -- after a fragment, another operation, a comment, a comma or a byte order mark --
    and never inside a string, a selection set or an argument list. A document that is not a
    sequence of complete executable definitions raises ``GraphQLArgumentError``.
    """
    tokens = _tokens(str(document or ""))
    kinds: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "{":
            kinds.append("query")
        elif token in {"query", "mutation", "subscription"}:
            kinds.append(token)
        elif token != "fragment":
            raise GraphQLArgumentError("the GraphQL document is not a list of operations and fragments")
        # To the definition's selection set: the first brace outside its variable definitions
        # and directive arguments, whose default values may hold braces of their own.
        nesting: list[str] = []
        while index < len(tokens) and not (tokens[index] == "{" and not nesting):
            current = tokens[index]
            if current in _CLOSERS:
                nesting.append(_CLOSERS[current])
            elif current in _CLOSERS.values():
                if not nesting or nesting.pop() != current:
                    raise GraphQLArgumentError("the GraphQL document's brackets do not balance")
            index += 1
        # Through the selection set.
        while index < len(tokens):
            current = tokens[index]
            index += 1
            if current in _CLOSERS:
                nesting.append(_CLOSERS[current])
            elif current in _CLOSERS.values():
                if not nesting or nesting.pop() != current:
                    raise GraphQLArgumentError("the GraphQL document's brackets do not balance")
                if not nesting:
                    break
        else:
            raise GraphQLArgumentError("a GraphQL definition has no complete selection set")
    if not kinds:
        raise GraphQLArgumentError("the GraphQL document defines no operation")
    return tuple(kinds)


def operation_kind(document: str) -> str:
    """``query``, ``mutation`` or ``subscription``: what sending the document may do.

    The most restrictive reading wins. ``query`` only for a document whose one operation is a
    query. A document with a subscription is a ``subscription``; one with a mutation, with more
    than one operation (the server picks which runs) or that cannot be read is a ``mutation``,
    so it is sent only as a write. The keyword at the start says nothing: ``fragment F on T{id}
    mutation{...}`` and ``query Q{a} mutation M{b}`` both begin as a read would.
    """
    try:
        kinds = operation_kinds(document)
    except GraphQLArgumentError:
        return "mutation"
    if "subscription" in kinds:
        return "subscription"
    return "query" if kinds == ("query",) else "mutation"


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
