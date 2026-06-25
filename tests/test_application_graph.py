"""Phase C: first-class application graph. Tests the pure transform that turns a
scan result (BOLA resource_map + discovery) into nodes/edges."""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *a, **k: None))

import worker  # noqa: E402


def test_build_graph_from_resource_map_and_discovery():
    result = {
        # resource_map can land anywhere in the report — found recursively.
        "phase4": {"access_control": {"authz_resource_replay": {"resource_map": [
            {
                "producer_endpoint": "GET /api/users",
                "object_id_key": "user_id",
                "object_id_location": "path",
                "source_principal": "user1",
                "excluded_from_principal": "user2",
                "consumer_candidates": ["GET /api/users/{user_id}", "GET /api/users/{user_id}/orders"],
                "sensitive_fields": ["email", "ssn"],
            }
        ]}}},
        "discovery": {"browser_api_endpoints": [{"url": "GET /api/health"}, "GET /api/profile"]},
    }
    nodes, edges = worker.build_application_graph(result)

    # producer + 2 consumers + 2 discovered = route nodes; one object node
    assert nodes["route:GET /api/users"]["node_type"] == "route"
    assert nodes["object:user_id"]["attributes"]["sensitive_fields"] == ["email", "ssn"]
    assert nodes["object:user_id"]["attributes"]["location"] == "path"

    # producer -> object (produces)
    assert ("route:GET /api/users", "object:user_id", "produces") in edges
    # producer -> consumer (auth_boundary with the principal pair)
    ab_key = ("route:GET /api/users", "route:GET /api/users/{user_id}", "auth_boundary")
    assert ab_key in edges
    assert edges[ab_key]["source_principal"] == "user1"
    assert edges[ab_key]["excluded_principal"] == "user2"
    assert edges[ab_key]["sensitive_fields"] == ["email", "ssn"]
    # object -> consumer (consumed_by)
    assert ("object:user_id", "route:GET /api/users/{user_id}", "consumed_by") in edges

    # discovery contributes route nodes even without producer/consumer structure
    assert "route:GET /api/health" in nodes
    assert "route:GET /api/profile" in nodes


def test_build_graph_empty_without_signal():
    assert worker.build_application_graph({}) == ({}, {})
    assert worker.build_application_graph("not-a-dict") == ({}, {})
    # discovery-only result still yields route nodes, no edges
    nodes, edges = worker.build_application_graph(
        {"discovery": {"browser_api_endpoints": ["GET /a", "GET /b"]}})
    assert set(nodes) == {"route:GET /a", "route:GET /b"} and edges == {}
