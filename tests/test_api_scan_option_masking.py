import asyncio
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


def test_sanitize_scan_options_masks_sensitive_keys():
    options = {
        "scan_type": "smart",
        "auth_header": "Bearer token1",
        "auth_cookies": "session=abc",
        "user2_header": "Bearer token2",
        "user2_cookies": "session=def",
        "auth_headers_json": "{\"X-API-Key\":\"secret\"}",
        "auth_scenario_json": "{\"steps\":[]}",
        "login_password": "password123",
        "ai_api_key": "sk-test",
        "non_sensitive": "keep-me",
    }

    sanitized = api_module._sanitize_scan_options(options)

    assert sanitized["scan_type"] == "smart"
    assert sanitized["non_sensitive"] == "keep-me"
    assert sanitized["auth_header"] == "***"
    assert sanitized["auth_cookies"] == "***"
    assert sanitized["user2_header"] == "***"
    assert sanitized["user2_cookies"] == "***"
    assert sanitized["auth_headers_json"] == "***"
    assert sanitized["auth_scenario_json"] == "***"
    assert sanitized["login_password"] == "***"
    assert sanitized["ai_api_key"] == "***"


def test_sanitize_scan_options_decodes_json_string():
    raw = "{\"scan_type\":\"smart\",\"auth_header\":\"Bearer token\"}"
    sanitized = api_module._sanitize_scan_options(raw)
    assert sanitized["scan_type"] == "smart"
    assert sanitized["auth_header"] == "***"


def test_ai_demo_target_detection_uses_structured_metadata_only():
    assert api_module._is_ai_demo_target_row({
        "name": "Honey demo mcp.unsafe.oauth_audience_wildcard.v1",
        "endpoint_url": "https://honey.example/api/v1/mcp/trace",
        "metadata_json": {"shakerscan_demo": True},
    })
    assert api_module._is_ai_demo_target_row({
        "name": "Local Honey calibration mcp.safe.oauth_audience_pkce_rejection.v1 local-honey-1",
        "endpoint_url": "http://host.docker.internal:18080/api/v1/mcp/trace?calibration_run=local-honey-1",
        "metadata_json": {"calibration_run": "local-honey-1"},
    })
    assert not api_module._is_ai_demo_target_row({
        "name": "Honey Production",
        "endpoint_url": "https://example.com/api/chat",
        "metadata_json": {},
    })
    assert not api_module._is_ai_demo_target_row({
        "name": "Calibration audit",
        "endpoint_url": "https://example.com/api/chat",
        "metadata_json": {},
    })


def test_demo_target_url_rewrites_base_and_adds_calibration_query():
    rewritten = api_module._demo_target_url(
        "https://honey.shakerscan.com/api/v1/mcp/trace?existing=1",
        "http://host.docker.internal:18080/",
        "demo-123",
        "mcp.unsafe.oauth_audience_wildcard.v1",
    )

    assert rewritten.startswith("http://host.docker.internal:18080/api/v1/mcp/trace?")
    assert "existing=1" in rewritten
    assert "calibration_run=demo-123" in rewritten
    assert "calibration_scenario=mcp.unsafe.oauth_audience_wildcard.v1" in rewritten


def test_demo_request_template_preserves_mcp_shape_and_injects_prompt():
    template = {"jsonrpc": "2.0", "id": "fixed", "method": "tools/list", "params": {"scenario_id": "x"}}
    rewritten = api_module._demo_request_template_with_prompt(template, "mcp")

    assert rewritten["id"] == "fixed"
    assert rewritten["params"]["scenario_id"] == "x"
    assert rewritten["params"]["prompt"] == "{{prompt}}"
    assert "prompt" not in template["params"]


def test_sanitize_ai_settings_includes_demo_fields():
    settings = api_module._sanitize_ai_settings_response({
        "demo_mode_enabled": True,
        "demo_honey_public_url": "https://honey.example",
        "demo_honey_scanner_url": "http://host.docker.internal:18080",
    })

    assert settings["demo_mode_enabled"] is True
    assert settings["demo_honey_public_url"] == "https://honey.example"
    assert settings["demo_honey_scanner_url"] == "http://host.docker.internal:18080"


def test_sanitize_ai_settings_leaves_demo_urls_empty_by_default():
    settings = api_module._sanitize_ai_settings_response({})

    assert settings["demo_mode_enabled"] is False
    assert settings["demo_honey_public_url"] == ""
    assert settings["demo_honey_scanner_url"] == ""
    assert api_module._normalize_demo_base_url("") == ""


def test_huggingface_model_info_requests_lfs_blob_metadata(monkeypatch):
    captured = {}

    class FakeResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, limit):
            return b'{"siblings":[]}'

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(api_module.urllib.request, "urlopen", fake_urlopen)

    result = api_module._hf_api_model_info("acme/ranker", "abc123", 7)

    assert result == {"siblings": []}
    assert captured["timeout"] == 7
    assert captured["url"] == "https://huggingface.co/api/models/acme/ranker/revision/abc123?blobs=true"


def test_huggingface_model_info_rejects_oversized_payload(monkeypatch):
    class FakeResponse:
        headers = {}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, limit):
            return b"x" * limit

    monkeypatch.setattr(api_module, "HF_MODEL_INFO_MAX_BYTES", 10)
    monkeypatch.setattr(api_module.urllib.request, "urlopen", lambda request, timeout: FakeResponse())

    try:
        api_module._hf_api_model_info("acme/ranker", "main", 7)
    except RuntimeError as exc:
        assert "exceeded 10 byte cap" in str(exc)
    else:
        raise AssertionError("expected oversized Hugging Face payload to be rejected")


def test_huggingface_resolver_prefills_hash_license_and_dependency_inventory(monkeypatch):
    model_info = {
        "sha": "abc123",
        "pipeline_tag": "text-generation",
        "library_name": "transformers",
        "tags": ["license:apache-2.0"],
        "cardData": {"base_model": "base/model"},
        "siblings": [
            {
                "rfilename": "vision/vit.safetensors",
                "size": 1024,
                "blobId": "blob-vit",
                "lfs": {"sha256": "e" * 64, "size": 1024},
            },
            {
                "rfilename": "model.safetensors",
                "size": 2048,
                "blobId": "blob-model",
                "lfs": {"sha256": "f" * 64, "size": 2048},
            },
            {"rfilename": "tokenizer.json", "size": 100, "blobId": "blob-tokenizer"},
            {"rfilename": "requirements.txt", "size": 42, "blobId": "blob-reqs"},
        ],
    }
    monkeypatch.setattr(api_module, "_hf_api_model_info", lambda repo_id, revision, timeout_seconds: model_info)

    resolved = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker",
            timeout_seconds=5,
        )
    )

    metadata = resolved["metadata_json"]
    assert resolved["selected_file"]["path"] == "model.safetensors"
    assert resolved["scan_payload"]["expected_sha256"] == "f" * 64
    assert metadata["sha256_source"] == "huggingface_lfs"
    assert metadata["license"] == "apache-2.0"
    assert metadata["tokenizer"][0]["path"] == "tokenizer.json"
    assert metadata["package_dependencies"]["files"][0]["path"] == "requirements.txt"

    resolved_file_url = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker/resolve/abc123/vision/vit.safetensors",
            timeout_seconds=5,
        )
    )
    assert resolved_file_url["selected_file"]["path"] == "vision/vit.safetensors"
    assert resolved_file_url["scan_payload"]["expected_sha256"] == "e" * 64


def test_huggingface_resolver_does_not_emit_scan_payload_without_metadata_or_file(monkeypatch):
    def unavailable_model_info(repo_id, revision, timeout_seconds):
        raise RuntimeError("hub unavailable")

    monkeypatch.setattr(api_module, "_hf_api_model_info", unavailable_model_info)

    resolved = api_module._resolve_huggingface_model_intake(
        api_module.ModelIntakeResolveRequest(
            platform="huggingface",
            ref="https://huggingface.co/acme/ranker",
            timeout_seconds=5,
        )
    )

    assert resolved["scan_payload"] is None
    assert resolved["candidate_files"] == []
    assert any("metadata is required" in warning for warning in resolved["warnings"])


def test_direct_huggingface_scan_request_is_auto_enriched(monkeypatch):
    monkeypatch.setattr(api_module, "_resolve_huggingface_model_intake", lambda request: {
        "scan_payload": {
            "artifact_url": "https://huggingface.co/acme/ranker/resolve/abc123/model.safetensors",
            "name": "Hugging Face: acme/ranker",
            "expected_sha256": "a" * 64,
            "model_card_url": "https://huggingface.co/acme/ranker",
            "metadata_json": {
                "huggingface_repo": "acme/ranker",
                "huggingface_file": "model.safetensors",
                "license": "apache-2.0",
                "sha256": "a" * 64,
            },
        },
    })

    request = api_module.ModelIntakeScanRequest(artifact_url="acme/ranker")
    enriched = asyncio.run(api_module._enrich_model_intake_scan_request(request))

    assert enriched.artifact_url.endswith("/resolve/abc123/model.safetensors")
    assert enriched.expected_sha256 == "a" * 64
    assert enriched.model_card_url == "https://huggingface.co/acme/ranker"
    assert enriched.metadata_json["license"] == "apache-2.0"
