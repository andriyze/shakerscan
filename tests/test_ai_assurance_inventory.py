import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

import ai_assurance  # noqa: E402


def test_build_ai_inventory_discovers_openapi_ai_candidates_and_blast_radius():
    inventory = ai_assurance.build_ai_inventory(
        targets=[],
        ai_targets=[
            {
                "id": "target-agent",
                "name": "Refund agent",
                "target_type": "agent_trace",
                "endpoint_url": "https://api.example.com/agent/trace",
                "method": "POST",
                "production_mode": True,
                "metadata_json": {
                    "risk_tier": "high",
                    "data_classification": "restricted",
                    "tool_inventory": ["refund_payment", "search_docs"],
                    "tool_scopes": ["refund.write", "docs.read"],
                    "delegated_identity": ["svc-agent"],
                },
            }
        ],
        scans=[
            {
                "id": "scan-web",
                "target_url": "https://app.example.com",
                "run_kind": "web_dast",
                "result": {
                    "discovery": {
                        "api_security": {
                            "openapi": {
                                "endpoints": [
                                    {
                                        "method": "POST",
                                        "path": "/api/chat/completions",
                                        "body_params": ["messages", "model"],
                                    },
                                    {
                                        "method": "GET",
                                        "path": "/api/users/{id}",
                                        "query_params": ["id"],
                                    },
                                ]
                            }
                        }
                    }
                },
            }
        ],
        findings=[
            {
                "id": "finding-1",
                "ai_target_id": "target-agent",
                "status": "active",
                "severity": "high",
            }
        ],
    )

    assert inventory["summary"]["saved_ai_targets"] == 1
    assert inventory["summary"]["candidate_count"] == 1
    assert inventory["candidates"][0]["target_type"] == "api_chat"
    assert inventory["candidates"][0]["confidence"] >= 0.75
    blast_radius = inventory["assets"][0]["blast_radius"]
    assert blast_radius["tier"] in {"high", "critical"}
    assert "high_risk_action_scope" in blast_radius["factors"]
    assert "agent_runtime_controls_missing" in inventory["summary"]["coverage_gaps"]


def test_build_ai_inventory_skips_unsupported_ai_candidate_methods():
    inventory = ai_assurance.build_ai_inventory(
        targets=[],
        ai_targets=[],
        scans=[
            {
                "id": "scan-web",
                "target_url": "https://app.example.com",
                "run_kind": "web_dast",
                "result": {
                    "discovery": {
                        "api_security": {
                            "openapi": {
                                "endpoints": [
                                    {
                                        "method": "DELETE",
                                        "path": "/api/agent/trace",
                                        "body_params": ["tool", "prompt"],
                                    }
                                ]
                            }
                        }
                    }
                },
            }
        ],
        findings=[],
    )

    assert inventory["candidates"] == []


def test_mcp_live_readiness_probe_uses_metadata_and_attestations(monkeypatch):
    def fake_fetch(url, *, method="GET", timeout_seconds=8):
        return {
            "ok": True,
            "url": url,
            "method": method,
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "json": {
                "authorization_servers": ["https://auth.example.com"],
                "code_challenge_methods_supported": ["S256"],
            },
            "body_excerpt": "{}",
        }

    monkeypatch.setattr(ai_assurance, "_fetch_url_metadata", fake_fetch)
    result = ai_assurance.run_mcp_live_readiness_probe(
        {
            "target_type": "mcp_trace",
            "endpoint_url": "https://api.example.com/mcp",
            "metadata_json": {
                "token_audience_validation": True,
                "no_token_passthrough": True,
                "mcp_scopes": ["tools.read"],
                "session_isolation": True,
                "ssrf_protection": True,
            },
        }
    )

    assert result["ok"] is True
    assert result["summary"]["warnings"] == 0
    assert {check["id"] for check in result["checks"]} >= {
        "mcp.protected_resource_metadata",
        "mcp.token_audience_validation",
        "mcp.no_token_passthrough",
    }
