"""The engine tests a GraphQL endpoint's query arguments as inputs.

A GraphQL API takes its inputs as arguments inside the query text, so the sweep's per-parameter
checks never reach them: in a driven DVGA Hunt the engine verified introspection and the missing
alias limit but never sent one probe to ``systemDebug(arg)`` (a shell) or ``pastes(filter)``
(SQL). Here the query type is read once by introspection, and each string argument of a query
field becomes a GraphQL-locus injection candidate (``hunt/injection_proof.graphql_locus``) that
``candidate.verify`` proves or not with the server's own differential proofs.

Only query fields: a mutation writes. A field whose name says it destroys or resets something
(``deleteAllPastes``, ``resetDb``) is never sent, whatever its operation type.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
import re
from typing import Any

MAX_ARGUMENTS = 16
_TYPE = "type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"
INTROSPECTION = "query{__schema{queryType{fields{name %s args{name %s}}}}}" % (_TYPE, _TYPE)
_SCALAR_KINDS = frozenset({"SCALAR", "ENUM"})
_PLACEHOLDERS = {"String": '"1"', "ID": '"1"', "Int": "1", "Float": "1", "Boolean": "false"}
# Argument names that usually reach a query, a shell, a path or a fetch go first.
_LIKELY = re.compile(
    r"^(?:cmd|command|exec|arg|args|argument|host|hostname|ip|addr|address|domain|path|file|filename|"
    r"dir|url|uri|link|src|filter|search|keyword|query|q|term|sort|order|orderby|where|template|"
    r"name|username|title|id)$", re.I)
_DESTRUCTIVE_WORD = re.compile(
    r"^(?:delete|remove|erase|drop|purge|wipe|truncate|destroy|clear|flush|reset|init|initialize|"
    r"setup|install|seed|populate|migrate|shutdown|restart|reboot|kill|logout|signout|deactivate|"
    r"disable|unsubscribe|createdb|initdb|dropdb|resetdb)$", re.I)


def destructive_field(name: str) -> bool:
    """Whether a field name's words name a destructive operation (``deleteAllPastes``)."""
    words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", str(name or ""))
    joined = "".join(words).lower()
    return bool(_DESTRUCTIVE_WORD.match(joined)) or any(_DESTRUCTIVE_WORD.match(word) for word in words)


def _base(type_ref: Any) -> tuple[str, str, bool, bool]:
    """``(kind, name, required, list)`` of a type reference, its wrappers unwrapped."""
    required = listed = False
    node = type_ref if isinstance(type_ref, Mapping) else {}
    first = True
    # ``kind`` is the target's value: only a string names a wrapper (a list or object is no kind).
    while isinstance(node.get("kind"), str) and node["kind"] in {"NON_NULL", "LIST"}:
        if node["kind"] == "NON_NULL" and first:
            required = True
        if node["kind"] == "LIST":
            listed = True
        first = False
        node = node.get("ofType") if isinstance(node.get("ofType"), Mapping) else {}
    return str(node.get("kind") or ""), str(node.get("name") or ""), required, listed


def _query_fields(answer: Any) -> list[Mapping[str, Any]]:
    # The answer is the target's text: any shape other than the introspection one names no field.
    try:
        document = json.loads(answer) if isinstance(answer, (str, bytes)) else answer
        fields = document["data"]["__schema"]["queryType"]["fields"]
    except (ValueError, TypeError, KeyError, RecursionError):
        return []
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, Mapping)]


def argument_loci(answer: Any, route: str) -> list[dict[str, str]]:
    """The query arguments to test, from an introspection answer: ``{field, argument, operation}``,
    the likeliest names first, at most ``MAX_ARGUMENTS``."""
    found: list[tuple[int, dict[str, str]]] = []
    for field in _query_fields(answer):
        name = str(field.get("name") or "")
        if not re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,63}", name) or name.startswith("__") or destructive_field(name):
            continue
        kind, _type_name, _required, _listed = _base(field.get("type"))
        selection = "" if kind in _SCALAR_KINDS else "{__typename}"
        declared = field.get("args")
        arguments = [arg for arg in (declared if isinstance(declared, list) else ()) if isinstance(arg, Mapping)]
        shapes = {str(arg.get("name") or ""): _base(arg.get("type")) for arg in arguments}
        if not all(re.fullmatch(r"[_A-Za-z][_0-9A-Za-z]{0,63}", arg) for arg in shapes):
            continue
        for tested, (arg_kind, arg_type, _req, arg_listed) in shapes.items():
            if arg_kind != "SCALAR" or arg_type not in {"String", "ID"} or arg_listed:
                continue
            # The other required arguments get a plain value of their type; a required input
            # object or list cannot be filled in, so the field is left alone.
            others = []
            for other, (o_kind, o_type, o_required, o_listed) in shapes.items():
                if other == tested or not o_required:
                    continue
                if o_listed or o_kind not in _SCALAR_KINDS or o_type not in _PLACEHOLDERS:
                    others = None
                    break
                others.append(f"{other}:{_PLACEHOLDERS[o_type]}")
            if others is None:
                continue
            arguments_text = ",".join([f'{tested}:"1"', *others])
            operation = f"query{{{name}({arguments_text}){selection}}}"
            rank = 0 if _LIKELY.match(tested) else 1
            found.append((rank, {"field": name, "argument": tested, "operation": operation, "route": route}))
    found.sort(key=lambda item: item[0])
    return [item for _rank, item in found[:MAX_ARGUMENTS]]


def candidate_values(locus: Mapping[str, str], introspection_action: str) -> dict[str, Any]:
    """The injection candidate for one argument; ``candidate.verify`` runs every proof on it."""
    return {
        "family": "injection",
        "title": f"GraphQL argument {locus['field']}({locus['argument']}) tested as an input",
        "claim": (f"The schema at {locus['route']} takes the string argument {locus['argument']} on the "
                  f"query field {locus['field']}; the engine's sweep tests it like a request parameter."),
        "severity": "info",
        "locus": {"method": "POST", "route": locus["route"], "operation": locus["operation"],
                  "parameter": locus["argument"]},
        "evidence_refs": [f"action:{introspection_action}"],
    }


def introspection_request(path: str, identity: Mapping[str, Any], *, writes: bool) -> dict[str, Any]:
    """The schema read: a POST when the Hunt may send them, else the GET form GraphQL also serves."""
    if writes:
        return {"method": "POST", "path": path, "json_body": {"query": INTROSPECTION}, **dict(identity)}
    return {"method": "GET", "path": path, "query": {"query": INTROSPECTION}, **dict(identity)}


def routes(seen: Sequence[tuple[str, str]]) -> list[tuple[str, dict[str, Any]]]:
    """``(path, identity)`` of each GraphQL endpoint once (the first identity it was reached with)."""
    out: dict[str, dict[str, Any]] = {}
    for path, identity in seen:
        out.setdefault(path, json.loads(identity) if identity else {})
    return list(out.items())
