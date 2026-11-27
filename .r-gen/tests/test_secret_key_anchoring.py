"""Secret-named keys are matched on whole name segments, and configuration shapes are not secrets.

Audit M3: the key vocabulary ended with an unanchored alternative, so any key that merely
contained ``secret`` or ``credential`` was secret-named, and a URL or class name passed the
entropy screen. ``SECRETS_MANAGER_ENDPOINT=https://vault.internal.corp:8200`` became a verified
high ``dotenv_secret_exposure``. Each vector below verified before the fix; the genuine
positives must keep verifying, for the DAST exposure probe and for the Hunt data_exposure
verifier that shares ``capabilities/secret_material.py``.
"""

from __future__ import annotations

import pytest

from api.capabilities.exposure_probe import classify_exposure
from api.capabilities.secret_material import is_secret_key_name, is_structured_secret_value

PASSWORD = "Vt9qLx2Rm7Zp4Kw8sJ3n"
STRIPE = "sk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd"
AWS_ID = "AK" + "IA" + "Q7RZ2VX9LM4TB8NC"


def _dotenv(*lines: str):
    body = "\n".join(("APP_ENV=production", "PORT=3000", *lines)).encode() + b"\n"
    return classify_exposure(path="/.env", status=200,
                             headers={"Content-Type": "text/plain"}, body=body)


@pytest.mark.parametrize("line", [
    # Key names that contain a secret word without naming a secret.
    "SECRETS_MANAGER_ENDPOINT=https://vault.internal.corp:8200",
    "CREDENTIAL_PROVIDER_CLASS=com.acme.security.VaultCredentialProvider",
    "SECRETSTORE_REGION=eu-central-1-prod-x9",
    # Secret-named keys whose value is configuration by its shape.
    "JWT_SECRET=/etc/keys/jwt-signing.pem",
    "API_TOKEN=vault-01.prod.internal.acme.io",
    "DB_PASS=10.20.30.40:5432",
    "SIGNING_KEY=C:\\Keys\\Signing-2024.pfx",
    "CLIENT_SECRET=com.acme.auth.ClientSecretResolver",
    "AUTH_TOKEN=https://auth.internal.acme.io/oauth2/token",
])
def test_lookalike_keys_and_configuration_values_are_not_verified(line):
    signature = _dotenv(line)
    assert signature is not None
    assert signature.exposure_class == "configuration_file", line
    assert not signature.proves_sensitive_exposure
    assert signature.secret_evidence() == []


@pytest.mark.parametrize(("line", "field"), [
    (f"DB_PASSWORD={PASSWORD}", "DB_PASSWORD"),
    (f"dbPassword={PASSWORD}", "dbPassword"),
    (f"DBPASSWORD={PASSWORD}", "DBPASSWORD"),
    (f"APPSECRET={PASSWORD}", "APPSECRET"),
    (f"SESSION_SECRET_KEY={PASSWORD}", "SESSION_SECRET_KEY"),
    (f"GITHUB_TOKEN={PASSWORD}", "GITHUB_TOKEN"),
    (f"DB_PASS={PASSWORD}", "DB_PASS"),
    # A URL that carries a credential is still a secret.
    (f"QUEUE_CREDENTIALS=amqp://svc:{PASSWORD}@mq.internal:5672/", "QUEUE_CREDENTIALS"),
    (f"STRIPE_SECRET_KEY={STRIPE}", "STRIPE_SECRET_KEY"),
])
def test_genuine_secrets_still_verify(line, field):
    signature = _dotenv(line)
    assert signature is not None and signature.proves_sensitive_exposure, line
    assert signature.exposure_class == "environment_secret_file"
    assert [item["field"] for item in signature.secret_evidence()] == [field]


def test_key_names_match_on_whole_segments():
    for name in ("SECRETS_MANAGER_ENDPOINT", "CREDENTIAL_PROVIDER_CLASS", "secretsDir",
                 "passwordless_login", "SECRET_KEY_FILE", "password_policy", "AWS_ACCESS_KEY_ID",
                 "secretStoreLocation", "credentialsProviderClass"):
        assert not is_secret_key_name(name, server_side=True), name
    for name in ("SPRING_DATASOURCE_PASSWORD", "spring.datasource.password", "db-password",
                 "clientSecret", "privatekey", "SECRETKEY", "credentials", "connectionString",
                 "aws_secret_access_key", "internalAdminToken"):
        assert is_secret_key_name(name, server_side=True), name


def test_value_shapes_that_are_configuration():
    from api.capabilities.secret_material import is_non_secret_value_shape

    for value in ("https://vault.internal.corp:8200", "vault.internal.corp", "10.0.0.12:8200",
                  "com.acme.security.VaultCredentialProvider", "/etc/ssl/private/server-key.pem",
                  "C:\\Keys\\Signing.pfx", "3.14159", "TRUE", "off"):
        assert is_non_secret_value_shape(value), value
        assert not is_structured_secret_value(value), value
    for value in (PASSWORD, f"postgres://u:{PASSWORD}@db/x", "/x8Ab+Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd=",
                  "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
                  "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"):
        assert not is_non_secret_value_shape(value), value
        assert is_structured_secret_value(value), value


def test_actuator_and_json_config_use_the_same_anchored_vocabulary():
    import json

    def actuator(properties):
        body = json.dumps({"propertySources": [{"name": "env", "properties": {
            key: {"value": value} for key, value in properties.items()}}]}).encode()
        return classify_exposure(path="/actuator/env", status=200,
                                 headers={"Content-Type": "application/json"}, body=body)

    fixed = actuator({"secrets.manager.endpoint": "https://vault.internal.corp:8200",
                      "credential.provider.class": "com.acme.security.VaultCredentialProvider"})
    assert fixed is not None and fixed.exposure_class == "actuator_endpoint"
    leaked = actuator({"spring.datasource.password": PASSWORD})
    assert leaked is not None and leaked.exposure_class == "actuator_secret_disclosure"
    body = json.dumps({"Vault": {"SecretsManagerEndpoint": "https://vault.internal.corp:8200"},
                       "Auth": {"ClientSecret": PASSWORD}}).encode()
    config = classify_exposure(path="/appsettings.json", status=200,
                               headers={"Content-Type": "application/json"}, body=body)
    assert config is not None and config.proves_sensitive_exposure
    assert [item["field"] for item in config.secret_evidence()] == ["ClientSecret"]


def test_hunt_data_exposure_keeps_its_verified_behaviour():
    import workflow_experiment

    classify = workflow_experiment._classify_selfevident_secret_values
    assert classify(f'{{"key":"{STRIPE}"}}') == ["stripe_key"]
    assert classify(f"aws {AWS_ID}") == ["aws_access_key"]
    assert classify(f"postgres://app:{PASSWORD}@db.internal/app") == ["credentialed_database_uri"]
    # Neither M3 vector is provider-shaped, so neither ever reached a Hunt proof.
    assert classify("SECRETS_MANAGER_ENDPOINT=https://vault.internal.corp:8200") == []
    assert classify("CREDENTIAL_PROVIDER_CLASS=com.acme.security.VaultCredentialProvider") == []
