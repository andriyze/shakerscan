"""A password file, a YAML configuration with secrets and a server status page are reported.

The seed list already requested ``/.htpasswd``, ``/config.yml`` and ``/server-status``, but the
classifier had no grammar for any of them: a single ``user:$apr1$...`` line is neither a dotenv
file nor a credential store, YAML was never parsed, and mod_status/stub_status output matched no
diagnostic signature. Each now verifies by its own grammar, and a lookalike does not.
Values are synthetic fixtures.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from api.capabilities.exposure_probe import (
    classify_exposure,
    is_sensitive_exposure_class,
    redacted_exposure_excerpt,
)
from api.finding_detail import build_finding_detail
from api.scan.action_plan import ScanActionPlan as ApiScanActionPlan
from api.scan.finalizer import finalize_scan_report
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action as _plan_action

HTPASSWD_HASH = "$apr1$zoo12345$Qb3b7oH0iJpQ7pR2sT5uV/"
HTPASSWD = f"admin:{HTPASSWD_HASH}\n"
DB_PASSWORD = "Zr7#qLm2!vXp9Tn4"
SMTP_PASSWORD = "Sm7p-Zoo-2026"
CONFIG_YML = (
    "database:\n  host: db\n  user: app\n"
    f"  password: {DB_PASSWORD}\n"
    f"smtp:\n  password: {SMTP_PASSWORD}\n"
)
SERVER_STATUS = (
    '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html><head><title>Apache Status'
    "</title></head><body><h1>Apache Server Status for app.fixture.invalid (via 10.0.0.6)</h1>"
    "<dl><dt>Server Version: Apache/2.4.41 (Ubuntu)</dt><dt>Server MPM: prefork</dt>"
    "<dt>Current Time: Friday, 16-Oct-2026 10:00:00 UTC</dt></dl><table><tr><th>Srv</th>"
    "<th>PID</th><th>Client</th><th>VHost</th><th>Request</th></tr><tr><td>0-0</td><td>1201</td>"
    "<td>10.0.0.55</td><td>shop.fixture.invalid</td><td>GET /admin/orders?token=abc123 HTTP/1.1"
    "</td></tr></table></body></html>"
)
NGINX_STATUS = (
    "Active connections: 2 \nserver accepts handled requests\n 16 16 31 \n"
    "Reading: 0 Writing: 1 Waiting: 1 \n"
)
APACHE_AUTO = (
    "app.fixture.invalid\nServerVersion: Apache/2.4.41 (Ubuntu)\nServerMPM: prefork\n"
    "Total Accesses: 12\nBusyWorkers: 1\nIdleWorkers: 4\nScoreboard: _W___....\n"
)


def _classify(path: str, body: str, content_type: str):
    return classify_exposure(path=path, status=200, headers={"Content-Type": content_type},
                             body=body.encode())


def test_htpasswd_hash_line_is_password_hash_material_and_withheld():
    signature = _classify("/.htpasswd", HTPASSWD, "text/plain")
    assert signature is not None
    assert signature.exposure_class == "configuration_secret_file"
    assert signature.matched_pattern == "htpasswd_hash_lines"
    assert signature.severity == "high"
    assert signature.proof_contract is not None
    evidence = signature.secret_evidence()
    assert [(item["field"], item["category"]) for item in evidence] == [("admin.password", "password_hash")]
    assert HTPASSWD_HASH not in json.dumps(evidence)
    excerpt = redacted_exposure_excerpt(HTPASSWD.encode(), signature)
    assert HTPASSWD_HASH not in excerpt and "zoo12345" not in excerpt


@pytest.mark.parametrize("line", [
    "alice:$2y$10$" + "abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ01234",
    "bob:{SHA}" + "W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
    "root:$6$saltsalt$" + "a" * 86 + ":19000:0:99999:7:::",
])
def test_other_crypt_formats_are_password_hashes(line):
    signature = _classify("/backup/users", line + "\n", "application/octet-stream")
    assert signature is not None and signature.matched_pattern == "htpasswd_hash_lines"


def test_des_crypt_needs_a_password_file_name():
    body = "admin:rl0uE8bA9fXyQ\n"
    assert _classify("/notes.txt", body, "text/plain") is None
    named = _classify("/.htpasswd", body, "text/plain")
    assert named is not None and named.matched_pattern == "htpasswd_hash_lines"


@pytest.mark.parametrize("body", [
    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "Our admin:$apr1$ hashes are rotated weekly, see the runbook for the procedure.\n",
    "db:5432\ncache:6379\n",
])
def test_lookalikes_are_not_password_files(body):
    signature = _classify("/.htpasswd", body, "text/plain")
    assert signature is None or signature.matched_pattern != "htpasswd_hash_lines"


def test_yaml_configuration_with_passwords_is_a_configuration_secret_file():
    signature = _classify("/config.yml", CONFIG_YML, "text/yaml")
    assert signature is not None
    assert signature.exposure_class == "configuration_secret_file"
    assert signature.matched_pattern == "yaml_configuration_secret"
    assert signature.severity == "high"
    assert {item["field"] for item in signature.secret_evidence()} == {"database.password", "smtp.password"}
    serialized = json.dumps(signature.secret_evidence())
    excerpt = redacted_exposure_excerpt(CONFIG_YML.encode(), signature)
    for value in (DB_PASSWORD, SMTP_PASSWORD):
        assert value not in serialized and value not in excerpt


def test_yaml_is_recognised_by_content_type_as_well_as_name():
    signature = _classify("/settings", CONFIG_YML, "application/x-yaml")
    assert signature is not None and signature.matched_pattern == "yaml_configuration_secret"


@pytest.mark.parametrize("body", [
    "app:\n  name: shop\n  port: 8080\nlogging:\n  level: info\n",
    # Indirect and placeholder values prove no secret.
    "database:\n  password: ${DB_PASSWORD}\n  user: app\nsmtp:\n  password: changeme\n",
    "database:\n  password: \"<%= ENV['DB_PASSWORD'] %>\"\n  host: db\n",
])
def test_yaml_without_a_proven_secret_is_not_reported(body):
    signature = _classify("/config.yml", body, "text/yaml")
    assert signature is None or not is_sensitive_exposure_class(signature.exposure_class)
    if signature is not None:  # an observation with secret-named keys: its body is withheld
        assert signature.withholds_content


@pytest.mark.parametrize("body", [
    "openapi: 3.0.0\ninfo:\n  title: Shop\ncomponents:\n  schemas:\n    Login:\n      properties:\n"
    "        password:\n          type: string\n          example: Zr7qLm2vXp9Tn4Kw8sJ3\n",
    "fixtures:\n  login:\n    examples:\n      password: Zr7qLm2vXp9Tn4Kw8sJ3\n    user: demo\n",
])
def test_yaml_examples_and_api_descriptions_are_not_configuration_secrets(body):
    signature = _classify("/api.yaml", body, "application/yaml")
    assert signature is None or not is_sensitive_exposure_class(signature.exposure_class)


def test_yaml_grammar_is_not_read_from_prose():
    body = "Release notes: password rotation\nNote: the password: Zr7qLm2vXp9Tn4Kw is gone now and more text\n"
    assert _classify("/notes.txt", body, "text/plain") is None


@pytest.mark.parametrize("path,body,content_type", [
    ("/server-status", SERVER_STATUS, "text/html"),
    ("/server-status", APACHE_AUTO, "text/plain"),
    ("/nginx_status", NGINX_STATUS, "text/plain"),
])
def test_server_status_pages_are_metrics_endpoints(path, body, content_type):
    signature = _classify(path, body, content_type)
    assert signature is not None
    assert signature.exposure_class == "metrics_endpoint"
    assert is_sensitive_exposure_class(signature.exposure_class)
    excerpt = redacted_exposure_excerpt(body.encode(), signature)
    assert "abc123" not in excerpt


@pytest.mark.parametrize("body", [
    "<html><head><title>Docs</title></head><body><p>Enable mod_status to see the Apache Server "
    "Status for your host; it lists Server Version and more.</p></body></html>",
    "<html><body><h1>Welcome</h1><p>Active connections: 4 today.</p></body></html>",
])
def test_pages_about_server_status_are_not_status_pages(body):
    assert _classify("/server-status", body, "text/html") is None


def _finalize(observations):
    probe = _plan_action("verify.exposure", 0, capability_name="exposure.verify_batch")
    final = _plan_action("finalize.report", 1, dependencies=(probe.action_id,))
    plan = ApiScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                             target_binding_digest="a" * 64, actions=(probe, final))
    results = {probe.action_id: _result_with_observation_count(probe, len(observations))}
    return finalize_scan_report(plan=plan, target_url="https://app.example.test",
                                action_results=results, observations={probe.action_id: tuple(observations)})


# --- Through the batch executor and the finalizer ---------------------------------------------

SERVED = {
    "/.htpasswd": ("text/plain", HTPASSWD),
    "/config.yml": ("text/yaml", CONFIG_YML),
    "/server-status": ("text/html", SERVER_STATUS),
}


def test_a_host_serving_all_three_reports_three_findings(monkeypatch):
    # The adapter test module puts the runtime layout (``scan``, ``runtime``) on the path.
    from tests.test_scan_action_adapter import TARGET, Backend, _action, _dispatcher, _lease, _noop
    from tests.test_exposure_probe_batch_controls import _manifest
    import scan.action_adapter as action_adapter_module
    from runtime.models import ScanPolicy
    from runtime.request_replay_executor import ReplayTransportResult
    # The runtime layout's plan class, read off the adapter module: importing ``scan.action_plan``
    # here beside this file's ``api.scan.action_plan`` import would load it under both roots.
    ScanActionPlan = action_adapter_module.ScanActionPlan

    class Transport:
        async def send(self, request, *, target, timeout_seconds, follow_redirects):
            path = "/" + request.url.split("/", 3)[3] if request.url.count("/") >= 3 else "/"
            content_type, body = SERVED.get(path, ("text/plain", "not found"))
            return ReplayTransportResult(
                status_code=200 if path in SERVED else 404, connected_address="192.0.2.10",
                final_url=request.url, response_headers={"Content-Type": content_type},
                response_body=body.encode(), elapsed_ms=3,
            )

    monkeypatch.setattr(action_adapter_module, "PinnedAiohttpReplayTransport", lambda **_: Transport())
    scan_id = str(uuid.uuid4())
    manifest = _manifest(scan_id, ("/app",))
    action = _action("verify.exposure", "exposure.verify_batch", 0, capability_args={
        "endpoint_manifest_ref": manifest.reference().canonical_dict(),
        "slice": {"start": 0, "count": 100}, "profile": "balanced",
        "proof_policy": "deterministic_proof_contract_required",
    })
    action = type(action)(**{**action.__dict__, "requested_budget": {"http_requests": 300, "tool_wall_seconds": 180}})
    plan = ScanActionPlan(scan_id=scan_id, execution_plan_digest="a" * 64,
                          target_binding_digest=TARGET.digest, actions=(action,))
    backend = Backend(manifests={manifest.manifest_id: manifest})
    receipt = asyncio.run(_dispatcher(plan, backend, policy=ScanPolicy())(action, _lease(plan, action), _noop))
    verified = [item for item in receipt.observations
                if item.get("kind") == "sensitive_exposure_proof" and item.get("proof_state") == "verified"]
    by_path = {item["request_url"].rsplit("/", 1)[-1]: item for item in verified}
    assert set(by_path) == {".htpasswd", "config.yml", "server-status"}
    text = json.dumps([receipt.observations, receipt.redacted_execution], default=str)
    for value in (HTPASSWD_HASH, DB_PASSWORD, SMTP_PASSWORD, "abc123"):
        assert value not in text

    report = _finalize(verified)
    findings = {finding["evidence"]["request_url"].rsplit("/", 1)[-1]: finding for finding in report["findings"]}
    assert set(findings) == {".htpasswd", "config.yml", "server-status"}
    assert findings[".htpasswd"]["severity"] == "high"
    assert findings["config.yml"]["severity"] == "high"
    # Calibrated like any metrics endpoint: it reveals internals, no credential was proven.
    assert findings["server-status"]["severity"] == "medium"

    hashes = build_finding_detail(findings[".htpasswd"])
    assert hashes["class_label"] == "Password hashes exposed"
    assert [item["field"] for item in hashes["secrets"]] == ["admin.password"]
    status = build_finding_detail(findings["server-status"])
    assert status["class_label"] == "Server status page public"
    assert any("Require local" in step for step in status["fix"])
    config = build_finding_detail(findings["config.yml"])
    assert config["class_label"] == "Configuration file with secrets"
    assert json.dumps([hashes, status, config]).count(DB_PASSWORD) == 0
