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
                    "vendor_risk": {
                        "third_party_domains": ["cdn.example.net"],
                        "risk_level": "medium",
                        "risk_score": 42,
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
    assert "ai_target:22222222-2222-2222-2222-222222222222" in node_ids
    assert "vendor:cdn.example.net" in node_ids
    assert "has_finding" in edge_types
    assert "exposes_ai_surface" in edge_types
    assert "loads_third_party" in edge_types
    assert "produced_chain" in edge_types
    assert graph["summary"]["severity_counts"]["critical"] == 1
    assert graph["summary"]["severity_counts"]["high"] == 1
