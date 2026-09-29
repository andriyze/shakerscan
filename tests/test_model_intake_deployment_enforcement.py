import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import urllib.error

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

import model_intake_admission_webhook as webhook  # noqa: E402
from scripts import model_intake_verify_deployment as cli


def _encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def _review(*, model=True, annotations=None):
    return {
        "request": {
            "uid": "request-1",
            "object": {
                "metadata": {
                    "labels": {webhook.MODEL_LABEL: "true" if model else "false"},
                    "annotations": annotations or {},
                },
            },
        },
    }


def test_model_workload_is_denied_when_admission_material_is_missing():
    result = webhook.review_admission(_review())
    assert result["response"]["allowed"] is False
    assert result["response"]["status"]["reason"] == "ModelAdmissionDenied"


def test_non_model_workload_is_out_of_scope_without_calling_verifier(monkeypatch):
    monkeypatch.setattr(webhook, "_verify", lambda *_args: (_ for _ in ()).throw(AssertionError("must not call")))
    assert webhook.review_admission(_review(model=False))["response"]["allowed"] is True


def test_exact_model_bundle_is_allowed_only_after_live_registry_verification(monkeypatch):
    package = {"schema_version": "model-intake-admission/v2"}
    bundle = {"bundle_sha256": "a" * 64, "target_environment": "production"}
    monkeypatch.setattr(webhook, "_verify", lambda actual_package, actual_bundle: {
        "verified": actual_package == package and actual_bundle == bundle,
        "deployment_observed": False,
        "side_effects": False,
        "registry": {"admission_id": "admission-1"},
    })
    result = webhook.review_admission(_review(annotations={
        webhook.PACKAGE_ANNOTATION: _encoded(package),
        webhook.BUNDLE_ANNOTATION: _encoded(bundle),
    }))
    assert result["response"]["allowed"] is True
    assert result["response"]["auditAnnotations"]["shakerscan.dev/admission-id"] == "admission-1"


def test_webhook_verifier_calls_pure_exact_bundle_gate(monkeypatch):
    package = {"schema_version": "model-intake-admission/v2"}
    bundle = {
        "bundle_sha256": "a" * 64,
        "target_environment": "production",
        "model_artifact_sha256": "b" * 64,
        "runtime_image_digest": "sha256:" + "c" * 64,
    }
    observed = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, _limit):
            return json.dumps({"verified": True, "side_effects": False}).encode()

    def open_request(request, timeout):
        observed["url"] = request.full_url
        observed["payload"] = json.loads(request.data)
        observed["timeout"] = timeout
        return Response()

    class Opener:
        open = staticmethod(open_request)

    monkeypatch.setenv("SHAKERSCAN_API_URL", "https://scanner.corp.example")
    monkeypatch.setenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "x" * 40)
    monkeypatch.setattr(webhook.urllib.request, "build_opener", lambda *_args: Opener())

    assert webhook._verify(package, bundle)["verified"] is True
    assert observed["url"].endswith("/model-intake/admissions/v2/verify")
    assert observed["payload"]["expected_bundle_sha256"] == "a" * 64
    assert observed["payload"]["expected_components"]["model_artifact_sha256"] == "b" * 64


@pytest.mark.parametrize(
    "api_url",
    [
        "http://127.0.0.1.attacker.example",
        "http://127.0.0.1@attacker.example",
        "http://127.0.0.1:8080@attacker.example:80",
        "http://scanner.corp.example",
        "ftp://127.0.0.1",
        "https://",
    ],
)
def test_webhook_refuses_to_send_the_verifier_token_off_loopback_in_cleartext(monkeypatch, api_url):
    monkeypatch.setenv("SHAKERSCAN_API_URL", api_url)
    monkeypatch.setenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "x" * 40)
    monkeypatch.setattr(
        webhook.urllib.request,
        "build_opener",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("token left the process")),
    )
    with pytest.raises(RuntimeError, match="HTTPS or loopback"):
        webhook._verify({}, {"bundle_sha256": "a" * 64, "target_environment": "production"})


@pytest.mark.parametrize(
    "api_url",
    ["https://scanner.corp.example", "http://127.0.0.1:8080", "http://127.0.0.2", "http://[::1]:8080"],
)
def test_webhook_verifier_transport_accepts_https_and_loopback(api_url):
    assert webhook._verifier_transport_allowed(api_url) is True


def test_webhook_does_not_forward_verifier_token_after_redirect(monkeypatch):
    received = []

    class RedirectDestination(BaseHTTPRequestHandler):
        def do_GET(self):
            received.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"verified":true,"side_effects":false}')

        def log_message(self, *_args):
            pass

    destination = ThreadingHTTPServer(("127.0.0.1", 0), RedirectDestination)

    class Verifier(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{destination.server_port}/capture")
            self.end_headers()

        def log_message(self, *_args):
            pass

    verifier = ThreadingHTTPServer(("127.0.0.1", 0), Verifier)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (destination, verifier)]
    for thread in threads:
        thread.start()
    try:
        monkeypatch.setenv("SHAKERSCAN_API_URL", f"http://127.0.0.1:{verifier.server_port}")
        monkeypatch.setenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "review-probe-token")
        assert webhook._verifier_transport_allowed(f"http://localhost:{destination.server_port}") is False

        with pytest.raises(urllib.error.HTTPError) as exc:
            webhook._verify({}, {"bundle_sha256": "a" * 64, "target_environment": "production"})

        assert exc.value.code == 302
        assert received == []
    finally:
        for server in (verifier, destination):
            server.shutdown()
            server.server_close()


def test_webhook_installation_is_namespace_scoped_certified_and_fail_closed():
    root = Path(__file__).resolve().parents[1]
    manifest = (root / "deploy" / "kubernetes" / "model-intake-validating-webhook.yaml").read_text()
    installer = (root / "scripts" / "install-model-intake-webhook.sh").read_text()
    assert "failurePolicy: Fail" in manifest
    assert "namespaceSelector:" in manifest
    assert "shakerscan.dev/model-admission: enabled" in manifest
    assert "objectSelector:" in manifest
    assert "kind: Certificate" in manifest
    assert "cert-manager.io/inject-ca-from" in manifest
    assert "MODEL_INTAKE_WEBHOOK_IMAGE_DIGEST" in installer
    assert "rollout status" in installer


def test_cli_verifier_fails_closed_when_api_is_unavailable(monkeypatch):
    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("down")))
    try:
        cli.verify("https://scanner.example", {}, {"bundle_sha256": "a" * 64, "target_environment": "production"}, "token", 1)
    except RuntimeError as exc:
        assert "unavailable or rejected" in str(exc)
    else:
        raise AssertionError("unavailable verifier must deny")
