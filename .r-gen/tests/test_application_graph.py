"""Phase C: first-class application graph. Tests the pure transform that turns a
scan result (BOLA resource_map + discovery) into nodes/edges."""
import os
import sys
import types

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace(Pool=object))
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


def test_authenticated_attempts_populate_inventory_and_two_principal_graph():
    result = {
        "active_checks": {
            "endpoint_attempt_schema_version": "active_endpoint_attempt_v1",
            "endpoint_attempts": [
                {
                    "custom_endpoint": "GET /workshop/api/shop/orders/1?id=1",
                    "family": "authz",
                    "status": "completed",
                    "attempted_params_count": 2,
                    "completed_params_count": 2,
                    "source_principal": "user1",
                    "attacker_principal": "user2",
                    "producer_endpoint": "GET /workshop/api/shop/orders/1?id=1",
                    "consumer_endpoint": "GET /workshop/api/shop/orders/1?id=1",
                    "object_id_location": "producer_response",
                    "proof_type": "resource_producer_discovery",
                    "owner_status": 200,
                    "attacker_listing_status": 200,
                    "resource_ids_found": 3,
                },
                {
                    "custom_endpoint": "GET /guessed/phantom",
                    "family": "authz",
                    "status": "partial",
                    "attempted_params_count": 2,
                    "completed_params_count": 2,
                    "source_principal": "user1",
                    "attacker_principal": "user2",
                    "producer_endpoint": "GET /guessed/phantom",
                    "consumer_endpoint": "GET /guessed/phantom",
                    "owner_status": 404,
                    "attacker_listing_status": 404,
                },
            ],
        },
    }

    worklists = worker._authenticated_endpoint_worklists_from_report(result)
    assert worklists == {
        "user1": ["GET /workshop/api/shop/orders/1?id=1"],
        "user2": ["GET /workshop/api/shop/orders/1?id=1"],
    }

    nodes, edges = worker.build_application_graph(result)
    route = "route:GET /workshop/api/shop/orders/1?id=1"
    boundary = (route, route, "auth_boundary")
    assert route in nodes
    assert "route:GET /guessed/phantom" not in nodes
    assert boundary in edges
    assert edges[boundary]["source_principal"] == "user1"
    assert edges[boundary]["excluded_principal"] == "user2"
    assert edges[boundary]["observation"] == "two_principal_route_comparison"
    object_keys = [key for key in nodes if key.startswith("object:resource_id@")]
    assert len(object_keys) == 1
    assert (route, object_keys[0], "produces") in edges


def test_authenticated_attempt_persistence_rejects_unknown_schema():
    report = {
        "active_checks": {
            "endpoint_attempts": [{
                "custom_endpoint": "GET /api/orders/1",
                "status": "completed",
                "source_principal": "user1",
                "attacker_principal": "user2",
                "owner_status": 200,
                "attacker_status": 200,
                "producer_endpoint": "GET /api/orders/1",
                "consumer_endpoint": "GET /api/orders/1",
            }],
        },
    }

    assert worker._authenticated_endpoint_worklists_from_report(report) == {}
    assert worker.build_application_graph(report) == ({}, {})
