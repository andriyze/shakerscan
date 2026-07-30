import base64
import json

from api import model_intake_admission_webhook as webhook
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
        "deployment_observed": True,
        "registry": {"admission_id": "admission-1"},
    })
    result = webhook.review_admission(_review(annotations={
        webhook.PACKAGE_ANNOTATION: _encoded(package),
        webhook.BUNDLE_ANNOTATION: _encoded(bundle),
    }))
    assert result["response"]["allowed"] is True
    assert result["response"]["auditAnnotations"]["shakerscan.dev/admission-id"] == "admission-1"


def test_cli_verifier_fails_closed_when_api_is_unavailable(monkeypatch):
    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("down")))
    try:
        cli.verify("https://scanner.example", {}, {"bundle_sha256": "a" * 64, "target_environment": "production"}, "token", 1)
    except RuntimeError as exc:
        assert "unavailable or rejected" in str(exc)
    else:
        raise AssertionError("unavailable verifier must deny")
