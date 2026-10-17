"""Kubernetes ValidatingAdmissionWebhook for exact Model Intake bundles."""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid

from fastapi import FastAPI, HTTPException


MODEL_LABEL = "shakerscan.dev/model-deployment"
PACKAGE_ANNOTATION = "shakerscan.dev/model-admission-package-b64"
BUNDLE_ANNOTATION = "shakerscan.dev/model-deployment-bundle-b64"

app = FastAPI(title="ShakerScan Model Admission Webhook")
logger = logging.getLogger(__name__)


# Every reason the webhook names itself, written for the caller (no exception text, URL or body).
# A denial carries one of these keys; the caller is answered from this table, never from text
# that travelled with an exception.
DENIAL_MESSAGES = {
    "invalid_package": "invalid admission package",
    "invalid_bundle": "invalid deployment bundle",
    "verifier_transport": "verifier API must be HTTPS or loopback",
    "not_admitted": "exact bundle was not admitted",
}


class AdmissionDenied(RuntimeError):
    """A denial the webhook named itself: ``reason`` is a key of DENIAL_MESSAGES."""

    def __init__(self, reason: str):
        if reason not in DENIAL_MESSAGES:
            raise ValueError(f"unknown admission denial {reason!r}")
        super().__init__(DENIAL_MESSAGES[reason])
        self.reason = reason


# A failure the webhook did not name itself (verifier unreachable, HTTP error, malformed
# verifier answer) is logged here and reported to the Kubernetes API with this fixed text.
VERIFIER_FAILURE_MESSAGE = "model admission could not be verified"


def _decode_annotation(value: Any, reason: str) -> dict[str, Any]:
    try:
        raw = base64.b64decode(str(value or ""), validate=True)
        if len(raw) > 220_000:
            raise ValueError("annotation too large")
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise AdmissionDenied(reason) from exc
    if not isinstance(decoded, dict):
        raise AdmissionDenied(reason)
    return decoded


def _verifier_transport_allowed(api_url: str) -> bool:
    """The verifier token may travel over HTTPS, or over plain HTTP only to a loopback address."""
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme == "https":
        return bool(parsed.hostname)
    if parsed.scheme != "http" or parsed.username is not None or parsed.password is not None:
        return False
    try:
        return ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        return False


class _NoVerifierRedirects(urllib.request.HTTPRedirectHandler):
    """Keep the verifier bearer token on the configured endpoint."""

    def redirect_request(self, *_args, **_kwargs):
        return None


def _verify(package: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    api_url = os.getenv("SHAKERSCAN_API_URL", "").rstrip("/")
    token = os.getenv("MODEL_INTAKE_DEPLOYMENT_VERIFIER_TOKEN", "")
    if not api_url or not _verifier_transport_allowed(api_url):
        raise AdmissionDenied("verifier_transport")
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
    with urllib.request.build_opener(_NoVerifierRedirects()).open(request, timeout=10) as response:
        result = json.loads(response.read(2_000_000))
    if result.get("verified") is not True or result.get("side_effects") is not False:
        raise AdmissionDenied("not_admitted")
    return result


def _logged_uid(uid: str) -> str:
    """The request uid as the log shows it: Kubernetes uids are UUIDs, anything else is not echoed."""
    try:
        return str(uuid.UUID(uid))
    except ValueError:
        return "(not a UUID)"


def _denied(uid: str, message: str) -> dict[str, Any]:
    return {
        "uid": uid,
        "allowed": False,
        "status": {"code": 403, "reason": "ModelAdmissionDenied", "message": message},
    }


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
        package = _decode_annotation(annotations.get(PACKAGE_ANNOTATION), "invalid_package")
        bundle = _decode_annotation(annotations.get(BUNDLE_ANNOTATION), "invalid_bundle")
        verified = _verify(package, bundle)
        response["auditAnnotations"] = {
            "shakerscan.dev/admission-id": str(verified.get("registry", {}).get("admission_id") or ""),
            "shakerscan.dev/bundle-sha256": str(bundle.get("bundle_sha256") or ""),
        }
    except AdmissionDenied as exc:
        response = _denied(uid, next((text for key, text in DENIAL_MESSAGES.items() if key == exc.reason),
                                     VERIFIER_FAILURE_MESSAGE))
    except Exception:
        # Exception text can carry the verifier URL, an HTTP body or a traceback detail; it
        # stays in the webhook log and the caller gets a fixed message. Still fail closed.
        logger.exception("Model admission verification failed for request %s", _logged_uid(uid))
        response = _denied(uid, VERIFIER_FAILURE_MESSAGE)
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
