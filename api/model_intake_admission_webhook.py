"""Kubernetes ValidatingAdmissionWebhook for exact Model Intake bundles."""

from __future__ import annotations

import base64
import json
import os
from typing import Any
import urllib.error
import urllib.request

from fastapi import FastAPI, HTTPException


MODEL_LABEL = "shakerscan.dev/model-deployment"
PACKAGE_ANNOTATION = "shakerscan.dev/model-admission-package-b64"
BUNDLE_ANNOTATION = "shakerscan.dev/model-deployment-bundle-b64"

app = FastAPI(title="ShakerScan Model Admission Webhook")


def _decode_annotation(value: Any, label: str) -> dict[str, Any]:
    try:
        raw = base64.b64decode(str(value or ""), validate=True)
        if len(raw) > 220_000:
            raise ValueError("annotation too large")
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}") from exc
    if not isinstance(decoded, dict):
        raise ValueError(f"invalid {label}")
    return decoded


def _verify(package: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    api_url = os.getenv("SHAKERSCAN_API_URL", "").rstrip("/")
    token = os.getenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "")
    if not api_url or (not api_url.startswith("https://") and not api_url.startswith("http://127.0.0.1")):
        raise RuntimeError("verifier API must be HTTPS or loopback")
    payload = {
        "admission_package": package,
        "expected_bundle_sha256": bundle["bundle_sha256"],
        "expected_environment": bundle["target_environment"],
        "expected_components": {key: value for key, value in bundle.items() if key.endswith("_sha256") or key == "runtime_image_digest"},
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        api_url + "/model-intake/admissions/v2/verify",
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read(2_000_000))
    if result.get("verified") is not True or result.get("deployment_observed") is not True:
        raise RuntimeError("exact bundle was not admitted")
    return result


def review_admission(review: dict[str, Any]) -> dict[str, Any]:
    request = review.get("request") if isinstance(review.get("request"), dict) else {}
    uid = str(request.get("uid") or "")
    obj = request.get("object") if isinstance(request.get("object"), dict) else {}
    metadata = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    labels = metadata.get("labels") if isinstance(metadata.get("labels"), dict) else {}
    response: dict[str, Any] = {"uid": uid, "allowed": True}
    if str(labels.get(MODEL_LABEL) or "").lower() != "true":
        return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response}
    annotations = metadata.get("annotations") if isinstance(metadata.get("annotations"), dict) else {}
    try:
        package = _decode_annotation(annotations.get(PACKAGE_ANNOTATION), "admission package")
        bundle = _decode_annotation(annotations.get(BUNDLE_ANNOTATION), "deployment bundle")
        verified = _verify(package, bundle)
        response["auditAnnotations"] = {
            "shakerscan.dev/admission-id": str(verified.get("registry", {}).get("admission_id") or ""),
            "shakerscan.dev/bundle-sha256": str(bundle.get("bundle_sha256") or ""),
        }
    except Exception as exc:
        response = {
            "uid": uid,
            "allowed": False,
            "status": {"code": 403, "reason": "ModelAdmissionDenied", "message": str(exc)[:1000]},
        }
    return {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview", "response": response}


@app.get("/health")
async def health():
    configured = bool(os.getenv("SHAKERSCAN_API_URL"))
    return {"status": "healthy" if configured else "not_ready", "fail_open": False}


@app.post("/validate")
async def validate(review: dict[str, Any]):
    if not isinstance(review, dict):
        raise HTTPException(status_code=400, detail="AdmissionReview object required")
    return review_admission(review)
