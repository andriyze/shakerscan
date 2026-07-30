import base64
import json
from pathlib import Path
import sys

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

    def urlopen(request, timeout):
        observed["url"] = request.full_url
        observed["payload"] = json.loads(request.data)
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setenv("SHAKERSCAN_API_URL", "https://scanner.corp.example")
    monkeypatch.setenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "x" * 40)
    monkeypatch.setattr(webhook.urllib.request, "urlopen", urlopen)

    assert webhook._verify(package, bundle)["verified"] is True
    assert observed["url"].endswith("/model-intake/admissions/v2/verify")
    assert observed["payload"]["expected_bundle_sha256"] == "a" * 64
    assert observed["payload"]["expected_components"]["model_artifact_sha256"] == "b" * 64


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
