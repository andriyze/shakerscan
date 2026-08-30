import base64
import asyncio
import json

from api.capabilities import artifact as artifact_capability
from api.capabilities.artifact import analyze_javascript_bytes
from api.capabilities.http import WorkerPrivateHTTPResponse
from api.runtime.capability_registry import CAPABILITY_REGISTRY
from api.runtime.models import TargetBinding


def _segment(value):
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":")).encode()
    ).decode().rstrip("=")


def test_javascript_analysis_decodes_claims_without_returning_token():
    token = ".".join((
        _segment({"alg": "HS256", "typ": "JWT"}),
        _segment({
            "iss": "https://project.supabase.co/auth/v1",
            "role": "service_role",
            "exp": 2_000_000_000,
        }),
        "signaturebytes",
    ))
    body = (
        f'const endpoint="/api/users"; const key="{token}"; '
        'const db="https://project.supabase.co"; element.innerHTML=value;'
    ).encode()

    result = analyze_javascript_bytes(body)

    assert result["routes"] == ["/api/users"]
    assert result["supabase_origins"] == ["https://project.supabase.co"]
    assert result["client_sink_signals"] == ["innerHTML"]
    assert len(result["jwt_observations"]) == 1
    jwt = result["jwt_observations"][0]
    assert jwt["classification"] == "privileged"
    assert jwt["claims"]["role"] == "service_role"
    assert jwt["algorithm"] == "HS256"
    assert jwt["token_value_visible"] is False
    assert token not in json.dumps(result)


def test_artifact_capabilities_are_bounded_worker_http_contracts():
    artifact = CAPABILITY_REGISTRY.require("artifact.inspect")
    javascript = CAPABILITY_REGISTRY.require("javascript.analyze")

    assert artifact.hunt_executor == "worker_http"
    assert javascript.hunt_executor == "worker_http"
    assert artifact.risk_tier == javascript.risk_tier == "passive"
    assert artifact.input_schema["properties"]["max_bytes"]["maximum"] == 16_384
    assert javascript.input_schema["properties"]["max_bytes"]["maximum"] == 262_144
    assert artifact.placement_requirements["runtime_target_binding"] is True
    assert javascript.placement_requirements["worker_private_result"] is True


def test_artifact_window_redacts_jwt_and_reports_range_decision(monkeypatch):
    token = ".".join((
        _segment({"alg": "HS256"}),
        _segment({"role": "anon"}),
        "signaturebytes",
    ))
    seen = {}

    async def fake_execute(_target_url, args, **kwargs):
        seen.update(args)
        kwargs["private_response_sink"](WorkerPrivateHTTPResponse(
            status_code=206,
            final_url="https://app.example.test/assets/app.js",
            _body=f'const token="{token}";'.encode(),
            _headers={"content-type": "application/javascript", "content-range": "bytes 10-99/100"},
            _cookies={},
        ))
        return {"ok": True, "response": {"status": 206}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)
    binding = TargetBinding(
        target_id="target-1",
        target_kind="web",
        canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",),
        allowed_addresses=("192.0.2.10",),
    )
    result = asyncio.run(artifact_capability.inspect_target_artifact(
        "https://app.example.test",
        {"path": "/assets/app.js", "offset": 10, "max_bytes": 90},
        target=binding,
    ))

    assert seen["headers"] == {"Range": "bytes=10-99"}
    assert result["ok"] is True
    sample = result["observation"]["text_sample"]
    assert "<jwt:sha256:" in sample
    assert token not in sample


def test_worker_persists_semantic_ok_for_future_hunt_outcomes():
    from tests.api_sources import definition_source

    source = definition_source("process_canonical_http_capability_job")
    assert 'capability_name in {"artifact.inspect", "javascript.analyze"}' in source
    assert '"ok": status == "success"' in source
    assert "ArtifactInspectionExecutionAdapter" in source
