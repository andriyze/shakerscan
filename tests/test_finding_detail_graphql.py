"""GraphQL finding pages reproduce what was proven and check the fix the server can actually show.

Unit fixtures built from recorded scan evidence of a permissive GraphQL server: introspection was
rendered with the file-exposure template (expect 404/403, deny the path at the web server), the
duplicate-field page sent an alias query, the alias page sent 20 aliases where 100 were proven,
and the suggestions command cut the probe names at 60 characters.
"""

from __future__ import annotations

import json
import shlex
import urllib.parse

import pytest

from api.capabilities.graphql_probe import (
    INTROSPECTION_QUERY,
    RESERVED_PROBE_FIELDS,
    alias_query,
    duplicate_field_query,
)
from api.finding_detail import build_finding_detail

ENDPOINT = "http://graphql.fixture.invalid/graphql"


def _probe(check, **evidence):
    return build_finding_detail({"tool": "shakerscan_graphql_probe", "severity": "low", "url": ENDPOINT,
                                 "proof_state": "verified", "evidence": {
                                     "check": check, "endpoint": ENDPOINT, "root_type": "Query",
                                     "response_status": 200, **evidence}})


def _document(command: str) -> str:
    """The GraphQL document a GET command sends (``--data-urlencode query=...``)."""
    args = shlex.split(command)
    value = args[args.index("--data-urlencode") + 1]
    assert value.startswith("query=")
    return value[len("query="):]


def test_introspection_is_checked_by_asking_for_the_schema_not_by_a_status():
    brief = build_finding_detail({
        "tool": "shakerscan_exposure_probe", "severity": "low", "url": ENDPOINT, "proof_state": "verified",
        "title": "GraphQL introspection enabled",
        "evidence": {"exposure_class": "graphql_introspection_enabled", "response_status": 200,
                     "request_url": f"{ENDPOINT}?query=%3Credacted%3E", "matched_signature": '"__schema"',
                     "content_type": "application/json"}})
    assert brief["class"] == "exposure.graphql_introspection_enabled"
    assert _document(brief["reproduce"]["command"]) == INTROSPECTION_QUERY
    assert _document(brief["verify"]["command"]) == INTROSPECTION_QUERY
    assert "<redacted>" not in json.dumps(brief) and "%3Credacted%3E" not in brief["reproduce"]["command"]
    assert "__schema" in brief["verify"]["expect"]
    assert "404" not in json.dumps(brief["verify"]) and "403" not in json.dumps(brief["expected"])
    # Denying the endpoint at the web server takes the whole API offline: no such example.
    assert not brief.get("examples")
    assert any("introspection" in step.lower() for step in brief["fix"])


def test_duplicate_field_page_sends_the_proven_duplicate_query():
    brief = _probe("duplicate_field_limit_absent", duplicate_count=100, alias_count=None)
    assert brief["class"] == "graphql.duplicate_field_limit_absent"
    assert _document(brief["reproduce"]["command"]) == duplicate_field_query(100)
    shown = json.dumps([brief[key] for key in ("class_label", "summary", "observed", "expected", "context",
                                               "reproduce", "verify", "fix")]).lower()
    assert "alias" not in shown
    assert brief["verify"]["command"] and brief["verify"]["expect"]


def test_alias_page_sends_as_many_aliases_as_were_proven():
    brief = _probe("alias_limit_absent", alias_count=100, duplicate_count=None)
    assert _document(brief["reproduce"]["command"]) == alias_query(100)
    assert "100" in brief["reproduce"]["expect"]
    assert brief["verify"]["command"] and brief["verify"]["expect"]


def test_suggestions_page_sends_every_probe_name():
    misspelling = ",".join(RESERVED_PROBE_FIELDS)
    assert len(misspelling) > 60
    brief = _probe("field_suggestions", misspelling=misspelling, suggested_fields=["user", "users"])
    document = _document(brief["reproduce"]["command"])
    assert all(name in document.replace("{", " ").replace("}", " ").split() for name in RESERVED_PROBE_FIELDS)
    assert "Did you mean" in brief["verify"]["expect"]


@pytest.mark.parametrize("misspelling", ["usr$(id)", "a' ; touch /tmp/x #"])
def test_a_target_chosen_name_never_reaches_the_command_unvalidated(misspelling):
    brief = _probe("field_suggestions", misspelling=misspelling, suggested_fields=["user"])
    assert "$(id)" not in _document(brief["reproduce"]["command"])
    assert "touch" not in _document(brief["reproduce"]["command"])


def test_commands_are_get_requests_like_the_probe():
    brief = _probe("alias_limit_absent", alias_count=100)
    args = shlex.split(brief["reproduce"]["command"])
    assert "-G" in args and ENDPOINT in args
    assert urllib.parse.urlsplit(ENDPOINT).path == "/graphql"
