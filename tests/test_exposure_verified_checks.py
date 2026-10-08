"""Verified exposure checks: each file type is proved by its own grammar, never by a word.

Soak retest on the owned honeypot (plan-dast-main35): DAST verified none of the four exposures
the Hunt candidate verifier proved in about two seconds each -- /.git/config, /actuator/env,
/.env and /swagger.json with an embedded live key. Every check below therefore has a vulnerable
twin that must verify, a fixed twin that must not, and lookalikes (documentation pages, sample
keys, masked values, soft-404 pages) that must stay unverified. Secret values are synthetic
canaries assembled at runtime; none of them may reach a finding, its evidence or an export.
"""

from __future__ import annotations

import json
import logging

import pytest

from api.capabilities.exposure_probe import (
    _CLASS_SEVERITY,
    EXPOSURE_PROOF_CONTRACTS,
    SENSITIVE_SEED_PATHS,
    classify_exposure,
    exposure_first_slice_hold,
    is_never_requested,
    is_sensitive_exposure_class,
    redacted_exposure_excerpt,
)
from api.capabilities.secret_material import (
    classify_selfevident_secret_values,
    is_secret_key_name,
    is_structured_secret_value,
)
from api.proof_contracts import CANONICAL_PROOF_CONTRACTS
from api.scan.action_plan import ScanActionPlan
from api.scan.finalizer import finalize_scan_report
from scanner.scanner_tools.sarif_output import convert_to_sarif
from tests.test_scan_finalizer import _result_with_observation_count
from tests.test_scan_orchestrator import SCAN_ID, _action

# Synthetic canaries, assembled so no literal provider secret sits in the repository.
STRIPE = "sk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd"
PASSWORD = "Vt9qLx2Rm7Zp4Kw8sJ3n"
AWS_ID = "AK" + "IA" + "Q7RZ2VX9LM4TB8NC"
AWS_SECRET = "q7Rz2Vx9Lm4Tb8Nc1Hd6Kp3Ws5Fy0Ge2Ju7Ab9Q"
GITHUB = "gh" + "p_" + "Rk3Vn8Tq2Lx7Zm4Wb9Hc6Jd1Fs5Gy0Pa2Ne8Q"
MACHINE_KEY = "9F2C4B7A1E8D3F6A0C5B9E2D7F4A1C8B6E3D0F9A"
CANARIES = (STRIPE, PASSWORD, AWS_ID, AWS_SECRET, GITHUB, MACHINE_KEY)

SPA_SHELL = b"<!doctype html><html><head><title>Shop</title></head><body><div id=app></div></body></html>"


def _classify(path: str, body: bytes, content_type: str = "text/plain", status: int = 200):
    return classify_exposure(
        path=path, status=status, headers={"Content-Type": content_type}, body=body,
    )


def _verified(signature) -> bool:
    return signature is not None and signature.proves_sensitive_exposure


def _keys(signature) -> dict[str, str]:
    return {item["field"]: item["category"] for item in signature.secret_evidence()}


# --- .env ----------------------------------------------------------------------------------

def test_dotenv_with_an_entropy_screened_secret_verifies_and_its_fixed_twin_does_not():
    body = (
        "APP_ENV=production\n"
        f"DB_PASSWORD={PASSWORD}\n"
        f"STRIPE_SECRET_KEY={STRIPE}\n"
        "PORT=3000\n"
    ).encode()
    for path in ("/.env", "/.env.local", "/.env.production"):
        signature = _classify(path, body)
        assert _verified(signature), path
        assert signature.exposure_class == "environment_secret_file"
        assert signature.proof_contract == "dotenv_secret_exposure/v1"
        assert signature.severity == "high"
        # Key names are evidence; the provider category wins for a value it recognises.
        assert _keys(signature) == {"DB_PASSWORD": "config_secret_assignment",
                                    "STRIPE_SECRET_KEY": "stripe_key"}
    for status in (401, 403, 404):
        assert _classify("/.env", body, status=status) is None
    assert _classify("/.env", b"") is None


def test_dotenv_example_files_and_masked_or_indirect_values_are_not_secrets():
    example = (
        b"# copy to .env\n"
        b"APP_ENV=production\n"
        b"DB_PASSWORD=changeme\n"
        b"STRIPE_SECRET_KEY=sk_live_your_key_here\n"
        b"JWT_SECRET=${JWT_SECRET}\n"
        b"API_TOKEN=<your-api-token>\n"
        b"SESSION_SECRET=******\n"
        b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    signature = _classify("/.env.example", example)
    assert signature is not None and signature.exposure_class == "configuration_file"
    assert not signature.proves_sensitive_exposure
    assert signature.proof_contract is None


def test_documentation_pages_quoting_a_dotenv_line_prove_nothing():
    secret_line = f"STRIPE_SECRET_KEY={STRIPE}"
    html = f"<html><body><h1>Configure</h1><pre>DB_PASSWORD={PASSWORD}\n{secret_line}</pre></body></html>"
    assert _classify("/docs/setup", html.encode(), "text/html") is None
    # The same page served as text: prose dominates, so it is not a dotenv file.
    prose = (
        "Configuring the service\n"
        "Put your Stripe key in the environment before you start the server.\n"
        f"{secret_line}\n"
        "Then restart the worker and check the dashboard for errors.\n"
        "Never commit this file to version control.\n"
    )
    assert _classify("/docs/setup.txt", prose.encode()) is None


# --- .git --------------------------------------------------------------------------------

GIT_CONFIG = (
    "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
    "[remote \"origin\"]\n\turl = https://github.com/acme/shop.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
)


def test_git_metadata_is_proved_by_git_grammar():
    config = _classify("/.git/config", GIT_CONFIG.encode())
    assert _verified(config) and config.exposure_class == "version_control_exposure"
    assert config.proof_contract == "vcs_metadata_exposure/v1"
    for head in (b"ref: refs/heads/main\n", b"3f786850e387550fdab836ed7e6dc881de23001b\n"):
        signature = _classify("/.git/HEAD", head)
        assert _verified(signature) and signature.matched_pattern == "git_head_ref"
    assert _classify("/.git/config", GIT_CONFIG.encode(), status=404) is None


def test_git_lookalikes_do_not_verify():
    tutorial = f"<html><body><p>A repository config:</p><pre>{GIT_CONFIG}</pre></body></html>"
    assert _classify("/blog/git", tutorial.encode(), "text/html") is None
    # The section name in prose, without git's own keys under it.
    assert _classify("/notes.txt", b"Edit the [core] section of your config\nand save it.\n") is None
    # A HEAD-looking first line followed by anything else is not a HEAD file.
    assert _classify("/.git/HEAD", b"ref: refs/heads/main\n<html>soft 404</html>\n") is None


def test_a_credential_in_the_git_remote_is_fingerprinted_and_never_excerpted():
    body = GIT_CONFIG.replace(
        "https://github.com/acme/shop.git",
        f"https://x-access-token:{GITHUB}@github.com/acme/shop.git",
    ).encode()
    signature = _classify("/.git/config", body)
    assert _verified(signature)
    assert {item["category"] for item in signature.secret_evidence()} == {"github_token"}
    excerpt = redacted_exposure_excerpt(body, signature)
    assert GITHUB not in excerpt and "content withheld" in excerpt
    # Without a secret the structural excerpt is kept, still through the shared redactor.
    plain = _classify("/.git/config", GIT_CONFIG.encode())
    assert "[core]" in redacted_exposure_excerpt(GIT_CONFIG.encode(), plain)


# --- Spring Boot actuator -------------------------------------------------------------------

def _env(value: str) -> bytes:
    return json.dumps({
        "activeProfiles": ["prod"],
        "propertySources": [{
            "name": "systemEnvironment",
            "properties": {
                "SPRING_DATASOURCE_USERNAME": {"value": "app"},
                "SPRING_DATASOURCE_PASSWORD": {"value": value},
                "SERVER_PORT": {"value": "8080"},
            },
        }],
    }).encode()


def test_actuator_env_with_an_unmasked_secret_verifies_and_the_masked_twin_does_not():
    leaked = _classify("/actuator/env", _env(PASSWORD), "application/json")
    assert _verified(leaked) and leaked.exposure_class == "actuator_secret_disclosure"
    assert leaked.proof_contract == "actuator_secret_exposure/v1"
    assert _keys(leaked) == {"SPRING_DATASOURCE_PASSWORD": "config_secret_assignment"}
    # Spring's sanitizer masks the value: the endpoint is reachable but leaks nothing.
    masked = _classify("/actuator/env", _env("******"), "application/vnd.spring-boot.actuator.v3+json")
    assert masked is not None and masked.exposure_class == "actuator_endpoint"
    assert not masked.proves_sensitive_exposure


def test_actuator_env_holding_a_cloud_key_is_critical():
    body = json.dumps({"propertySources": [{"name": "env", "properties": {
        "AWS_ACCESS_KEY_ID": {"value": AWS_ID},
        "AWS_SECRET_ACCESS_KEY": {"value": AWS_SECRET},
    }}]}).encode()
    signature = _classify("/actuator/env", body, "application/json")
    assert _verified(signature) and signature.severity == "critical"


def test_boot1_env_and_configprops_are_property_sources_too():
    boot1 = json.dumps({
        "profiles": ["prod"],
        "applicationConfig: [classpath:/application.properties]": {
            "spring.datasource.password": PASSWORD, "server.port": 8080,
        },
    }).encode()
    assert _classify("/env", boot1, "application/json").exposure_class == "actuator_secret_disclosure"

    def configprops(password: str) -> bytes:
        return json.dumps({"contexts": {"application": {"beans": {
            "spring.datasource-org.springframework.boot.autoconfigure.jdbc.DataSourceProperties": {
                "prefix": "spring.datasource",
                "properties": {"username": "app", "password": password, "url": "jdbc:postgresql://db/app"},
            },
        }}}}).encode()

    leaked = _classify("/actuator/configprops", configprops(PASSWORD), "application/json")
    assert _verified(leaked) and _keys(leaked) == {"spring.datasource.password": "config_secret_assignment"}
    masked = _classify("/actuator/configprops", configprops("******"), "application/json")
    assert masked.exposure_class == "actuator_endpoint" and not masked.proves_sensitive_exposure


def test_ordinary_json_with_a_password_key_is_not_an_actuator_leak():
    body = json.dumps({"properties": {"password": {"value": PASSWORD}}}).encode()
    assert _classify("/api/settings", body, "application/json") is None


def test_heapdump_existence_is_proved_from_the_index_and_never_requested():
    index = json.dumps({"_links": {
        "self": {"href": "https://app.example.test/actuator", "templated": False},
        "health": {"href": "https://app.example.test/actuator/health", "templated": False},
        "heapdump": {"href": "https://app.example.test/actuator/heapdump", "templated": False},
    }}).encode()
    signature = _classify("/actuator", index, "application/vnd.spring-boot.actuator.v3+json")
    assert _verified(signature) and signature.exposure_class == "actuator_heapdump_exposed"
    assert signature.proof_contract == "actuator_heapdump_exposure/v1"
    without = json.dumps({"_links": {
        "self": {"href": "https://app.example.test/actuator"},
        "health": {"href": "https://app.example.test/actuator/health"},
    }}).encode()
    assert not _verified(_classify("/actuator", without, "application/vnd.spring-boot.actuator.v3+json"))
    # Requesting the dump makes the JVM write one; the probe never sends that request.
    assert "/actuator/heapdump" not in SENSITIVE_SEED_PATHS
    assert is_never_requested("https://app.example.test/actuator/heapdump")
    assert is_never_requested("https://app.example.test/management/heapdump/")
    assert not is_never_requested("https://app.example.test/actuator/env")


# --- OpenAPI / Swagger -----------------------------------------------------------------------

def _spec(**extra) -> dict:
    spec = {
        "swagger": "2.0",
        "info": {"title": "Shop API", "version": "1.0.0"},
        "paths": {"/users": {"get": {"parameters": [{"name": "api_key", "in": "query", "type": "string"}]}}},
    }
    spec.update(extra)
    return spec


def test_an_api_spec_embedding_a_live_key_verifies_and_a_clean_spec_does_not():
    leaked = _spec(securityDefinitions={"ApiKeyAuth": {
        "type": "apiKey", "in": "header", "name": "Authorization",
        "description": f"Use the service key {STRIPE} for server calls.",
    }})
    signature = _classify("/swagger.json", json.dumps(leaked).encode(), "application/json")
    assert _verified(signature) and signature.exposure_class == "api_specification_secret"
    assert signature.proof_contract == "api_spec_secret_exposure/v1"
    assert _keys(signature) == {"securityDefinitions.ApiKeyAuth.description": "stripe_key"}
    clean = _classify("/swagger.json", json.dumps(_spec()).encode(), "application/json")
    assert clean.exposure_class == "exposed_api_specification"
    assert not clean.proves_sensitive_exposure


def test_sample_keys_in_a_spec_are_documentation_not_leaks():
    in_examples = _spec(definitions={"Config": {"properties": {
        "stripe_key": {"type": "string", "example": STRIPE},
        "database_url": {"type": "string", "examples": [f"postgres://app:{PASSWORD}@db/app"]},
    }}})
    signature = _classify("/openapi.json", json.dumps(in_examples).encode(), "application/json")
    assert signature.exposure_class == "exposed_api_specification"
    aws_docs = _spec(info={"title": "x", "version": "1", "description": "e.g. AKIAIOSFODNN7EXAMPLE"})
    assert not _verified(_classify("/openapi.json", json.dumps(aws_docs).encode(), "application/json"))
    # A key name alone in a spec describes a parameter; it configures nothing.
    named = _spec(definitions={"Login": {"properties": {"password": {"default": PASSWORD}}}})
    assert not _verified(_classify("/swagger.json", json.dumps(named).encode(), "application/json"))


# --- Configuration and backup files ----------------------------------------------------------

def test_config_json_with_a_server_secret_verifies_but_public_client_keys_do_not():
    leaked = json.dumps({"api": "https://api.example.test", "db": {"password": PASSWORD}}).encode()
    signature = _classify("/config.json", leaked, "application/json")
    assert _verified(signature) and signature.exposure_class == "configuration_secret_file"
    assert signature.proof_contract == "config_secret_exposure/v1"
    # Browser configuration legitimately publishes these.
    public = json.dumps({
        "firebase": {"apiKey": "AIza" + "SyD3x9Lm2Qp7Rt4Vw8Zc1Nb6Hk5Jf0Ge2Yq", "projectId": "shop"},
        "algoliaSearchKey": "4f8a2b3c9d1e7f6a5b0c8d2e4f6a1b3c",
        "stripePublishableKey": "pk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd",
        "sentryDsn": "https://4f8a2b3c9d1e7f6a@o1.ingest.sentry.io/1",
    }).encode()
    assert _classify("/config.json", public, "application/json") is None
    # The same secret-bearing JSON from an API route is a response, not a config file.
    assert _classify("/api/users/1", leaked, "application/json") is None


def test_appsettings_connection_string_password_verifies_unless_it_is_a_placeholder():
    def appsettings(password: str) -> bytes:
        return json.dumps({"ConnectionStrings": {
            "Default": f"Server=db;Database=shop;User Id=app;Password={password};",
        }, "Logging": {"LogLevel": {"Default": "Warning"}}}).encode()

    assert _verified(_classify("/appsettings.json", appsettings(PASSWORD), "application/json"))
    assert _classify("/appsettings.json", appsettings("changeme"), "application/json") is None


def _web_config(password: str, machine_key: str = "AutoGenerate") -> bytes:
    return (
        '<?xml version="1.0"?>\n<configuration>\n  <connectionStrings>\n'
        f'    <add name="Default" connectionString="Server=db;Database=shop;User Id=app;Password={password};" />\n'
        '  </connectionStrings>\n  <system.web>\n'
        f'    <machineKey validationKey="{machine_key}" decryptionKey="AutoGenerate" />\n'
        '  </system.web>\n</configuration>\n'
    ).encode()


def test_web_config_backups_are_proved_by_aspnet_structure():
    leaked = _classify("/web.config.bak", _web_config(PASSWORD), "application/octet-stream")
    assert _verified(leaked) and leaked.exposure_class == "configuration_secret_file"
    keyed = _classify("/web.config", _web_config("changeme", MACHINE_KEY), "text/xml")
    assert _verified(keyed) and _keys(keyed) == {"validationKey": "config_secret_assignment"}
    # A backup copy with no secret is still a source/config artifact served by name.
    backup = _classify("/web.config.bak", _web_config("changeme"), "application/octet-stream")
    assert _verified(backup) and backup.exposure_class == "backup_or_source_artifact"
    # The live file without a secret is configuration, not a finding.
    live = _classify("/web.config", _web_config("changeme"), "text/xml")
    assert live.exposure_class == "configuration_file" and not live.proves_sensitive_exposure


def test_sql_dumps_and_backup_archives_and_ds_store_are_proved_by_their_headers():
    dump = b"-- MySQL dump 10.13\n--\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);\n"
    assert _classify("/backup.sql", dump).exposure_class == "backup_or_source_artifact"
    assert _classify("/notes.txt", b"INSERT INTO users VALUES (1);\n") is None
    archive = b"PK\x03\x04" + b"\x00" * 40
    assert _verified(_classify("/backup.zip", archive, "application/zip"))
    # An ordinary download that happens to be a zip is not a backup.
    assert _classify("/downloads/brochure.zip", archive, "application/zip") is None
    ds_store = b"\x00\x00\x00\x01Bud1" + b"\x00" * 64
    signature = _classify("/.DS_Store", ds_store, "application/octet-stream")
    assert _verified(signature) and signature.exposure_class == "directory_metadata_file"
    assert signature.severity == "low"
    assert "binary content withheld" in redacted_exposure_excerpt(ds_store, signature)


# --- Debug pages -------------------------------------------------------------------------------

def test_phpinfo_and_debug_consoles_verify_and_pages_about_them_do_not():
    phpinfo = (
        "<!DOCTYPE html><html><head><title>PHP 8.2.12 - phpinfo()</title></head><body>"
        "<h1 class=\"p\">PHP Version 8.2.12</h1><table>"
        "<tr><td class=\"e\">DOCUMENT_ROOT </td><td class=\"v\">/var/www/html </td></tr>"
        "</table></body></html>"
    )
    plain = _classify("/phpinfo.php", phpinfo.encode(), "text/html")
    assert _verified(plain) and plain.exposure_class == "phpinfo_disclosure"
    assert plain.severity == "medium" and plain.proof_contract == "phpinfo_exposure/v1"
    with_secret = phpinfo.replace(
        "</table>", f"<tr><td class=\"e\">DB_PASSWORD </td><td class=\"v\">{PASSWORD} </td></tr></table>",
    )
    escalated = _classify("/info.php", with_secret.encode(), "text/html")
    assert escalated.severity == "high" and _keys(escalated) == {"DB_PASSWORD": "config_secret_assignment"}
    article = "<html><head><title>How to use phpinfo() safely</title></head><body>PHP Version 8.2 ...</body></html>"
    assert _classify("/blog/phpinfo", article.encode(), "text/html") is None

    werkzeug = (
        "<html><head><title>Console // Werkzeug Debugger</title></head><body>"
        "<script>var CONSOLE_MODE = true, EVALEX = true;</script>"
        "<script src=\"?__debugger__=yes&cmd=resource&f=debugger.js\"></script></body></html>"
    )
    console = _classify("/console", werkzeug.encode(), "text/html")
    assert _verified(console) and console.exposure_class == "debug_interface_exposure"
    assert console.severity == "high"
    pprof = _classify("/debug/pprof/", b"<html><head><title>/debug/pprof/</title></head></html>", "text/html")
    assert _verified(pprof) and pprof.severity == "medium"
    post = "<html><head><title>Disabling the Werkzeug Debugger</title></head><body>__debugger__</body></html>"
    assert _classify("/blog/werkzeug", post.encode(), "text/html") is None


# --- Soft-404 ------------------------------------------------------------------------------

def test_a_soft_404_site_answering_every_seed_with_its_shell_proves_nothing():
    for path in SENSITIVE_SEED_PATHS:
        assert _classify(path, SPA_SHELL, "text/html; charset=utf-8") is None, path
        # The same shell without a content type is still recognised as HTML.
        assert _classify(path, SPA_SHELL, "") is None, path


# --- Proof contracts --------------------------------------------------------------------------

def test_every_promotable_class_has_a_registered_contract_and_nothing_else_does():
    promotable = {name for name in _CLASS_SEVERITY if is_sensitive_exposure_class(name)}
    assert promotable == set(EXPOSURE_PROOF_CONTRACTS)
    assert set(EXPOSURE_PROOF_CONTRACTS.values()) <= CANONICAL_PROOF_CONTRACTS
    for observation_only in ("listed_file", "actuator_endpoint", "exposed_api_specification",
                             "configuration_file", "confidential_file"):
        assert not is_sensitive_exposure_class(observation_only)


def test_the_data_exposure_contract_keeps_its_narrow_exclusions():
    # Shared with the Hunt verifier: JWTs, bearer tokens, SSNs, cards and Google API keys
    # stay outside the self-evident set, and documentation placeholders are screened.
    for body in (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123",
        "ssn 123-45-6789 card 4111 1111 1111 1111",
        "AIza" + "SyD3x9Lm2Qp7Rt4Vw8Zc1Nb6Hk5Jf0Ge2Yq",
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://user:password@localhost/example",
    ):
        assert classify_selfevident_secret_values(body) == [], body
    assert classify_selfevident_secret_values(STRIPE) == ["stripe_key"]
    # Structured secrets need a secret-named key AND a screened, unmasked, direct value.
    assert is_secret_key_name("SPRING_DATASOURCE_PASSWORD", server_side=False)
    assert is_secret_key_name("internalAdminToken", server_side=True)
    assert not is_secret_key_name("internalAdminToken", server_side=False)
    for public in ("AWS_ACCESS_KEY_ID", "stripePublishableKey", "recaptcha_site_key",
                   "password_policy", "SECRET_KEY_FILE", "client_id"):
        assert not is_secret_key_name(public, server_side=True), public
    for value in ("******", "${DB_PASSWORD}", "%DB_PASSWORD%", "<password>", "changeme",
                  "short", True, None, "aaaaaaaaaaaaaaaa"):
        assert not is_structured_secret_value(value), value
    assert is_structured_secret_value(PASSWORD)


def _finalized(observation: dict) -> dict:
    probe = _action("verify.exposure", 0, capability_name="exposure.verify_batch")
    final = _action("finalize.report", 1, dependencies=(probe.action_id,))
    plan = ScanActionPlan(scan_id=SCAN_ID, execution_plan_digest="b" * 64,
                          target_binding_digest="a" * 64, actions=(probe, final))
    return finalize_scan_report(
        plan=plan, target_url="https://app.example.test",
        action_results={probe.action_id: _result_with_observation_count(probe, 1)},
        observations={probe.action_id: (observation,)},
    )


def _observation(path: str, body: bytes, content_type: str) -> dict:
    from types import SimpleNamespace

    from api.runtime.receipts import redact_receipt_value
    from api.scan.action_adapter import _exposure_observation

    signature = _classify(path, body, content_type)
    result = SimpleNamespace(status_code=200, response_headers={"Content-Type": content_type},
                             response_body=body)
    observation = _exposure_observation(f"https://app.example.test{path}", "seed_path", signature, result)
    # Observations are persisted through the receipt redactor; the finalizer reads what survives.
    return dict(redact_receipt_value(dict(observation)))


def test_the_finding_names_its_contract_and_carries_only_fingerprints():
    body = (f"DB_PASSWORD={PASSWORD}\nSTRIPE_SECRET_KEY={STRIPE}\nAPP_ENV=prod\n").encode()
    observation = _observation("/.env", body, "text/plain")
    # A stored observation cannot smuggle a raw value into evidence through an extra field.
    observation["secret_value"] = PASSWORD
    observation["exposure_fingerprints"] = [*observation["exposure_fingerprints"], {"field": "x", "value": STRIPE}]
    report = _finalized(observation)
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["verified"] is True and finding["proof_state"] == "verified"
    assert finding["cwe"] == "CWE-538"
    evidence = finding["evidence"]
    assert evidence["proof_contract"] == "dotenv_secret_exposure/v1"
    assert {item["field"] for item in evidence["exposure_fingerprints"]} >= {"DB_PASSWORD", "STRIPE_SECRET_KEY"}
    assert all(set(item) == {"field", "category", "value_fingerprint", "value_length"}
               for item in evidence["exposure_fingerprints"])
    real = [item for item in evidence["exposure_fingerprints"] if item["field"] != "x"]
    assert all(str(item["value_fingerprint"]).startswith("sha256:") and item["value_length"] > 0
               for item in real)
    assert all(item["value_fingerprint"] is None for item in evidence["exposure_fingerprints"]
               if item["field"] == "x")


@pytest.mark.parametrize(("path", "body", "content_type"), [
    ("/.env", f"DB_PASSWORD={PASSWORD}\nSTRIPE_SECRET_KEY={STRIPE}\n".encode(), "text/plain"),
    ("/actuator/env", json.dumps({"propertySources": [{"name": "env", "properties": {
        "AWS_ACCESS_KEY_ID": {"value": AWS_ID}, "AWS_SECRET_ACCESS_KEY": {"value": AWS_SECRET},
        "SPRING_DATASOURCE_PASSWORD": {"value": PASSWORD}}}]}).encode(), "application/json"),
    ("/swagger.json", json.dumps(_spec(info={"title": "x", "version": "1",
                                             "description": f"key {STRIPE}"})).encode(), "application/json"),
    ("/.git/config", GIT_CONFIG.replace("https://github.com", f"https://u:{GITHUB}@github.com").encode(),
     "text/plain"),
    ("/web.config.bak", _web_config(PASSWORD, MACHINE_KEY), "application/octet-stream"),
])
def test_no_raw_secret_reaches_findings_evidence_exports_or_logs(path, body, content_type, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    observation = _observation(path, body, content_type)
    report = _finalized(observation)
    assert report["findings"], path
    surfaces = {
        "observation": json.dumps(observation, default=str),
        "report": json.dumps(report, default=str),
        "sarif": json.dumps(convert_to_sarif(report), default=str),
        "logs": caplog.text,
        "stdout": "".join(capsys.readouterr()),
        "signature_repr": repr(_classify(path, body, content_type)),
    }
    for surface, text in surfaces.items():
        for canary in CANARIES:
            assert canary not in text, (surface, path)


def test_first_slice_reserves_the_seed_sweep_beyond_its_endpoint_share():
    hold = exposure_first_slice_hold(3)
    # 44 seeds + 2 soft-404 controls + 3 endpoints + 10 listing follow-ups.
    assert hold["http_requests"] == len(SENSITIVE_SEED_PATHS) + 2 + 3 + 10
    assert hold["tool_wall_seconds"] >= len(SENSITIVE_SEED_PATHS)
