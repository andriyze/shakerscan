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
            # The range now starts at the resource's head: the 10 bytes before the window are the
            # masking context (N56), the window follows them.
            _body=b"/*ctx*/   " + f'const token="{token}";'.encode(),
            _headers={"content-type": "application/javascript", "content-range": "bytes 0-99/100"},
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

    assert seen["headers"] == {"Range": "bytes=0-99"}  # window 10-99 plus its preceding context
    assert result["ok"] is True
    sample = result["observation"]["text_sample"]
    assert "***" in sample
    assert token not in sample


def test_artifact_window_redacts_common_secret_shapes_before_planner_exposure():
    sample = artifact_capability._redacted_text_sample(b"\n".join((
        b'const password="correct-horse-battery";',
        b'const apiKey="sk-live-123456789";',
        b'const config={"client_secret":"CLIENT-SECRET-123"};',
        b'Cookie: session=topsecret; csrf=csrfsecret',
        b'Authorization: Basic dXNlcjpwYXNz',
        b'https://user:dbsecret@db.example.test/app?token=querysecret&safe=1',
        b'tokens_used: 42',
    )))

    for secret in (
        "correct-horse-battery", "sk-live-123456789", "CLIENT-SECRET-123",
        "topsecret", "csrfsecret", "dXNlcjpwYXNz", "dbsecret", "querysecret",
    ):
        assert secret not in sample
    assert "tokens_used: 42" in sample


def test_javascript_analysis_redacts_source_map_query_credentials():
    result = analyze_javascript_bytes(
        b"//# sourceMappingURL=app.js.map?token=source-map-secret&build=42"
    )

    assert "source-map-secret" not in json.dumps(result)
    assert "build=42" in result["source_maps"][0]


def test_worker_persists_semantic_ok_for_future_hunt_outcomes():
    from tests.api_sources import definition_source

    source = definition_source("process_canonical_http_capability_job")
    assert 'capability_name in {"artifact.inspect", "javascript.analyze"}' in source
    assert '"ok": status == "success"' in source
    assert "ArtifactInspectionExecutionAdapter" in source


def _inspect_with(monkeypatch, response, args):
    async def fake_execute(_target_url, _args, **kwargs):
        kwargs["private_response_sink"](response)
        return {"ok": True, "response": {"status": response.status_code}}

    monkeypatch.setattr(artifact_capability, "execute_bound_http_request", fake_execute)
    binding = TargetBinding(
        target_id="target-1", target_kind="web", canonical_host="app.example.test",
        allowed_origins=("https://app.example.test",), allowed_addresses=("192.0.2.10",),
    )
    return asyncio.run(artifact_capability.inspect_target_artifact(
        "https://app.example.test", {"path": "/ftp/", **args}, target=binding,
    ))["observation"]


LISTING = (b"<li>quarantine/</li>\n" * 300) + b'<li><a href="jwt.pub">jwt.pub</a></li>\n'


def test_a_search_inside_a_truncated_window_says_the_resource_was_larger(monkeypatch):
    """Live: search_terms ["jwt.pub"] counted 0 on a 7,913-byte listing that contains it,
    with nothing saying only the first 4,096 bytes were searched."""
    assert len(LISTING) > 4096 and b"jwt.pub" not in LISTING[:4096]
    ranged = WorkerPrivateHTTPResponse(
        status_code=206, final_url="https://app.example.test/ftp/", _body=LISTING[:4096],
        _headers={"content-type": "text/html", "content-range": f"bytes 0-4095/{len(LISTING)}"},
        _cookies={},
    )
    observation = _inspect_with(monkeypatch, ranged, {"search_terms": ["jwt.pub"]})
    assert observation["search_matches"] == [{"term": "jwt.pub", "count": 0}]
    assert observation["search_scope"] == "window"
    assert observation["resource_bytes"] == len(LISTING)
    assert observation["window_truncated"] is True
    assert observation["returned_bytes"] == 4096

    # A server that ignores Range: the bounded read kept a prefix and says so.
    whole = WorkerPrivateHTTPResponse(
        status_code=200, final_url="https://app.example.test/ftp/", _body=LISTING[:4096],
        _headers={"content-type": "text/html", "content-length": str(len(LISTING))},
        _cookies={}, body_truncated=True,
    )
    observation = _inspect_with(monkeypatch, whole, {"search_terms": ["jwt.pub"]})
    assert (observation["resource_bytes"], observation["window_truncated"]) == (len(LISTING), True)
    assert len(observation["text_sample"]) <= artifact_capability.MAX_PUBLIC_TEXT


def test_a_complete_small_resource_is_not_called_truncated(monkeypatch):
    body = b'<li><a href="jwt.pub">jwt.pub</a></li>\n'
    complete = WorkerPrivateHTTPResponse(
        status_code=200, final_url="https://app.example.test/ftp/", _body=body,
        _headers={"content-type": "text/html"}, _cookies={},
    )
    observation = _inspect_with(monkeypatch, complete, {"search_terms": ["jwt.pub"]})
    assert observation["search_matches"] == [{"term": "jwt.pub", "count": 2}]
    assert (observation["resource_bytes"], observation["window_truncated"]) == (len(body), False)


def test_a_window_narrower_than_the_body_read_is_truncated(monkeypatch):
    response = WorkerPrivateHTTPResponse(
        status_code=200, final_url="https://app.example.test/ftp/", _body=LISTING[:4096],
        _headers={"content-type": "text/html"}, _cookies={},
    )
    observation = _inspect_with(monkeypatch, response, {"max_bytes": 100})
    assert observation["returned_bytes"] == 100
    assert observation["resource_bytes"] == 4096 and observation["window_truncated"] is True


def test_loopback_listing_larger_than_the_window_is_reported_truncated():
    """The real bounded HTTP read against a server that ignores Range."""
    from aiohttp import web

    async def scenario():
        async def listing(_request):
            return web.Response(body=LISTING, content_type="text/html")

        app = web.Application()
        app.router.add_get("/ftp/", listing)
        runner = web.AppRunner(app, shutdown_timeout=1)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        try:
            binding = TargetBinding(
                target_id="target-1", target_kind="web", canonical_host="127.0.0.1",
                allowed_origins=(base,), allowed_addresses=("127.0.0.1",),
                allowed_root_domains=("127.0.0.1",), environment="lab",
            )
            return await artifact_capability.inspect_target_artifact(
                base, {"path": "/ftp/", "search_terms": ["jwt.pub"]}, target=binding,
            )
        finally:
            await runner.cleanup()

    result = asyncio.run(scenario())
    assert result["ok"] is True, result
    observation = result["observation"]
    assert observation["returned_bytes"] == 4096
    assert observation["search_matches"] == [{"term": "jwt.pub", "count": 0}]
    assert observation["window_truncated"] is True
    assert observation["resource_bytes"] == len(LISTING)
    assert observation["search_scope"] == "window"
