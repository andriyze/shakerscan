import os
import sys
import types


sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))
sys.modules.setdefault("asyncpg", types.SimpleNamespace())
sys.modules.setdefault("redis", types.SimpleNamespace(from_url=lambda *args, **kwargs: None))

if "fastapi" not in sys.modules:
    fastapi_mod = types.ModuleType("fastapi")

    class _FakeFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def _decorator(self, *args, **kwargs):
            def wrapper(fn):
                return fn
            return wrapper

        get = post = patch = put = delete = on_event = _decorator

    class _FakeHTTPException(Exception):
        def __init__(self, status_code: int = 500, detail=None):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def _fake_query(default=None, **kwargs):
        return default

    fastapi_mod.FastAPI = _FakeFastAPI
    fastapi_mod.HTTPException = _FakeHTTPException
    fastapi_mod.Query = _fake_query
    sys.modules["fastapi"] = fastapi_mod

    middleware_mod = types.ModuleType("fastapi.middleware")
    cors_mod = types.ModuleType("fastapi.middleware.cors")

    class _FakeCORSMiddleware:
        pass

    cors_mod.CORSMiddleware = _FakeCORSMiddleware
    sys.modules["fastapi.middleware"] = middleware_mod
    sys.modules["fastapi.middleware.cors"] = cors_mod

    responses_mod = types.ModuleType("fastapi.responses")

    class _FakeResponse:
        def __init__(self, content=None, status_code=200, headers=None):
            self.content = content
            self.status_code = status_code
            self.headers = headers or {}

    responses_mod.Response = _FakeResponse
    sys.modules["fastapi.responses"] = responses_mod

import api as api_module  # noqa: E402


def test_build_exposure_graph_links_domains_targets_findings_and_ai_surfaces():
    graph = api_module._build_exposure_graph(
        targets=[
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "url": "https://app.example.com",
                "name": "App",
                "root_domain": "example.com",
                "is_active": True,
                "active_findings_count": 1,
                "total_scans": 2,
            },
            {
                "id": "77777777-7777-4777-8777-777777777777",
                "url": "https://models.example.com/safe/model.safetensors",
                "name": "Safe model",
                "root_domain": "example.com",
                "discovery_source": "model-intake",
                "is_active": True,
                "active_findings_count": 0,
                "total_scans": 1,
            }
        ],
        ai_targets=[
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "name": "Support bot",
                "target_type": "api_chat",
                "endpoint_url": "https://api.example.com/chat",
                "method": "POST",
                "production_mode": True,
            }
        ],
        scans=[
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "target_id": "11111111-1111-1111-1111-111111111111",
                "target_url": "https://app.example.com",
                "status": "completed",
                "scan_type": "smart",
                "result": {
                    "smart_coverage": {
                        "auth_states_tested": ["anonymous", "user"]
                    },
                    "discovery": {
                        "api_security": {
                            "openapi": {
                                "url": "https://app.example.com/openapi.json",
                                "title": "Example API",
                                "endpoint_count": 2,
                                "endpoints": [
                                    {"method": "GET", "path": "/api/users/{id}", "query_params": ["id"]},
                                    {"method": "POST", "path": "/api/upload", "body_params": ["file"]},
                                ],
                            }
                        },
                        "browser_api_endpoints": [
                            {"method": "GET", "url": "https://app.example.com/api/session"}
                        ],
                        "cloud_services": {
                            "providers": ["aws"],
                            "services": [{"provider": "aws", "service": "s3"}],
                        },
                    },
                    "vendor_risk": {
                        "third_party_domains": ["cdn.example.net"],
                        "risk_level": "medium",
                        "risk_score": 42,
                        "resources": [
                            {
                                "url": "https://cdn.example.net/app.js",
                                "domain": "cdn.example.net",
                                "type": "script",
                                "provider": "Example CDN",
                                "trust_level": "unknown",
                                "security_score": 55,
                            }
                        ],
                    },
                    "attack_chains": {
                        "chains": [
                            {
                                "chain_type": "xss_to_account_takeover",
                                "name": "XSS to Account Takeover",
                                "severity": "critical",
                                "confidence": 0.9,
                            }
                        ]
                    },
                },
            },
            {
                "id": "66666666-6666-4666-8666-666666666666",
                "ai_target_id": "22222222-2222-2222-2222-222222222222",
                "target_url": "https://api.example.com/chat",
                "status": "completed",
                "scan_type": "ai_gate",
                "run_kind": "ai_mcp",
                "result": {
                    "ai_gate": {
                        "findings": [
                            {
                                "id": "mcp.scope",
                                "severity": "high",
                                "evidence": {"matched_markers": ["mcp_scope_expansion"]},
                            }
                        ]
                    }
                },
            },
            {
                "id": "88888888-8888-4888-8888-888888888888",
                "target_id": "77777777-7777-4777-8777-777777777777",
                "target_url": "https://models.example.com/safe/model.safetensors",
                "status": "completed",
                "scan_type": "model_intake",
                "run_kind": "model_intake",
                "result": {
                    "model_intake": {
                        "summary": {
                            "artifact_name": "model.safetensors",
                            "artifact_ref": "https://models.example.com/safe/model.safetensors",
                            "source_kind": "http",
                            "extension": ".safetensors",
                            "format_posture": "safer_static_format",
                            "provenance_present": True,
                            "signature_present": True,
                            "expected_hash_present": True,
                            "deployment_approved": True,
                        }
                    }
                },
            }
        ],
        findings=[
            {
                "id": "44444444-4444-4444-4444-444444444444",
                "scan_id": "33333333-3333-3333-3333-333333333333",
                "target_id": "11111111-1111-1111-1111-111111111111",
                "title": "Reflected XSS",
                "severity": "high",
                "status": "active",
                "tool": "dalfox",
                "root_domain": "example.com",
                "url": "https://app.example.com/api/upload",
            },
            {
                "id": "55555555-5555-5555-5555-555555555555",
                "ai_target_id": "22222222-2222-2222-2222-222222222222",
                "title": "Prompt injection",
                "severity": "critical",
                "status": "active",
                "source": "ai_gate",
                "ai_target_url": "https://api.example.com/chat",
            },
        ],
    )

    node_ids = {node["id"] for node in graph["nodes"]}
    edge_types = {edge["type"] for edge in graph["edges"]}

    assert "domain:example.com" in node_ids
    assert "target:11111111-1111-1111-1111-111111111111" in node_ids
    assert "target:77777777-7777-4777-8777-777777777777" in node_ids
    assert "ai_target:22222222-2222-2222-2222-222222222222" in node_ids
    assert "vendor:cdn.example.net" in node_ids
    assert any(node_id.startswith("api:33333333-3333-3333-3333-333333333333:openapi") for node_id in node_ids)
    assert any(node_id.startswith("endpoint:") for node_id in node_ids)
    assert any(node_id.startswith("auth_role:") for node_id in node_ids)
    assert any(node_id.startswith("third_party_js:") for node_id in node_ids)
    assert any(node_id.startswith("cloud_hint:") for node_id in node_ids)
    assert any(node_id.startswith("mcp_tool:") for node_id in node_ids)
    assert "has_finding" in edge_types
    assert "affected_by" in edge_types
    assert "exposes_ai_surface" in edge_types
    assert "exposes_api" in edge_types
    assert "defines_endpoint" in edge_types
    assert "tests_auth_role" in edge_types
    assert "has_cloud_hint" in edge_types
    assert "exposes_mcp_tool" in edge_types
    assert "contains_artifact" in edge_types
    assert "loads_third_party" in edge_types
    assert "loads_script" in edge_types
    assert "exploit_path" in edge_types
    assert graph["summary"]["node_type_counts"]["model_artifact"] == 1
    assert graph["summary"]["severity_counts"]["critical"] == 1
    assert graph["summary"]["severity_counts"]["high"] == 1
