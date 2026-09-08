import asyncio
from datetime import datetime, timezone
import json
import uuid

import pytest

from api.hunt.graph_projection import project_graph_node
from api.hunt.knowledge import KnowledgeQueryError, query_knowledge_page


HUNT, TARGET = str(uuid.uuid4()), uuid.uuid4()


def test_graph_exposes_only_typed_resume_references_not_arbitrary_attributes():
    result = project_graph_node({"node_type": "authorization_proposal", "attributes": json.dumps({
        "hunt_id": HUNT, "proposal_id": HUNT, "primary_session_ref": HUNT,
        "expected_access": "denied", "proposal_digest": "a" * 64,
        "headers": {"Authorization": "secret"}, "raw_body": "sensitive", "unknown": "secret",
    })})
    assert result["attributes"] == {"hunt_id": HUNT, "proposal_id": HUNT, "primary_session_ref": HUNT,
                                    "expected_access": "denied", "proposal_digest": "a" * 64}
    assert result["attributes_omitted"] is True
    assert "secret" not in json.dumps(result)
    assert result["attributes_are_references_only"] is True


@pytest.mark.parametrize("attributes", [{"hunt_id": "Bearer secret"}, {"expected_access": ["denied"]}, {"proposal_digest": "secret"}])
def test_malformed_allowlisted_fields_are_not_an_escape_hatch(attributes):
    assert project_graph_node({"node_type": "authorization_proposal", "attributes": attributes})["attributes"] == {}


def test_unknown_node_type_never_exposes_imported_attributes():
    result = project_graph_node({"node_type": "imported", "attributes": {"raw": "secret"}})
    assert result["attributes"] == {} and result["attributes_omitted"]


def test_paged_graph_filters_are_parameterized_and_projection_is_applied():
    calls = []
    class Conn:
        async def fetch(self, sql, *args):
            calls.append((sql, args))
            return [{"id": uuid.uuid4(), "node_type": "authorization_proposal",
                     "attributes": {"hunt_id": HUNT, "raw": "secret"},
                     "page_timestamp": datetime.now(timezone.utc)}]
    result = asyncio.run(query_knowledge_page(Conn(), target_id=TARGET, kind="graph_nodes",
        filters={"node_type": "authorization_proposal", "hunt_id": HUNT}, limit=10))
    sql, args = calls[0]
    assert "target_id=$1" in sql and "attributes->>'hunt_id'=" in sql
    assert HUNT not in sql and HUNT in args and TARGET in args
    assert result["rows"][0]["attributes"] == {"hunt_id": HUNT}


def test_invalid_hunt_scope_filter_fails_before_a_database_read():
    class Conn:
        async def fetch(self, *args):
            pytest.fail("invalid scope must not reach the database")
    with pytest.raises(KnowledgeQueryError, match="hunt_id must be a UUID"):
        asyncio.run(query_knowledge_page(Conn(), target_id=TARGET, kind="graph_nodes", filters={"hunt_id": "not-an-id"}))


def test_hunt_filter_is_not_accepted_for_an_unrelated_table():
    with pytest.raises(KnowledgeQueryError, match="Unsupported knowledge filters"):
        asyncio.run(query_knowledge_page(None, target_id=TARGET, kind="findings", filters={"hunt_id": HUNT}))
