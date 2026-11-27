"""Regression corpus: every place OpenAPI 2/3 can carry a secret is withheld in masked views.

The N39 residue (plan-DAST main673) was a secret in a place the masking did not read: the
prose of an operation ``description``. This corpus enumerates the placements a provider-format
or secret-named value can take in an OpenAPI 2 (Swagger) or OpenAPI 3 document -- descriptor
defaults and examples, schema properties, prose labels in every descriptive field, security
schemes, server variables, response headers, ``x-`` extensions -- and reads each one back
through the masked archive JSON and the masked HAR, as JSON text, a decoded JSON object and
YAML. Every value here is a test fixture.
"""

from __future__ import annotations

import json
import time

import pytest
import yaml

from api.runtime.archive_body_masking import mask_body_text
from api.runtime.http_archive_reader import export_document, project

# Fixture values of the shapes that matter: low-entropy word-like (only a label or a name can
# reveal it), mixed-class credential-shaped, and provider formats.
WORDY = "canary_wordy_secret_value_17"
SHAPED = "Fx7Qm2Lp9Rt4Kz8Wn3Vb6Hc1Yd5"
STRIPE = "sk_" + "live_" + "CorpusFixture0123456789abcXyZ"
GITHUB = "ghp_" + "Co1Rp2Us3Fi4Xt5Ur6Ea7Bc8De9Fg0Hi1Jk2"
AWS = "AKIA" + "CORPUSFIXTURE7QZ"


def _op(**fields):
    return {"paths": {"/admin": {"post": dict({"responses": {"200": {"description": "ok"}}}, **fields)}}}


def _param(oas3: bool, **fields):
    return _op(parameters=[dict({"in": "header", "required": True}, **fields)])


# (placement, OpenAPI fragment builder taking ``oas3``, secret value)
PLACEMENTS = [
    # Prose labels in every descriptive field (the N39 residue and its relatives).
    ("operation description label", lambda o: _op(description=f"Internal admin endpoint. Master key: {WORDY}"), WORDY),
    ("operation summary label", lambda o: _op(summary=f"Admin password: {WORDY}"), WORDY),
    ("info description label", lambda o: {"info": {"title": "t", "description": f"Use the service token: {WORDY}"}}, WORDY),
    ("tag description label", lambda o: {"tags": [{"name": "admin", "description": f"root password = {WORDY}"}]}, WORDY),
    ("response description label", lambda o: {"paths": {"/x": {"get": {"responses": {"200": {"description": f"Session secret: {WORDY}"}}}}}}, WORDY),
    ("parameter description label", lambda o: _param(o, name="X-Trace", description=f"Pass the admin credential: {WORDY}"), WORDY),
    ("schema property description label", lambda o: {"definitions": {"C": {"properties": {"region": {"type": "string", "description": f"Signing key: {WORDY}"}}}}}, WORDY),
    # A descriptor whose name is secret: every non-structural value.
    ("secret-named parameter default", lambda o: _param(o, name="admin_token", default=WORDY), WORDY),
    ("secret-named parameter example", lambda o: _param(o, name="X-Api-Key", example=WORDY), WORDY),
    ("secret-named parameter x-example", lambda o: _param(o, name="X-Master-Key", **{"x-example": WORDY}), WORDY),
    ("secret-named parameter enum", lambda o: _param(o, name="client_secret", enum=[WORDY]), WORDY),
    ("secret-named parameter schema default", lambda o: _param(o, name="api_key", schema={"type": "string", "default": WORDY}), WORDY),
    ("secret-named parameter examples value", lambda o: _param(o, name="password", examples={"demo": {"value": WORDY}}), WORDY),
    ("Authorization header default", lambda o: _param(o, name="Authorization", default=f"Bearer {WORDY}"), WORDY),
    # A credential-shaped value in a security or parameter context, whatever its name.
    ("neutral-named parameter example", lambda o: _param(o, name="X-Client-Ref", example=SHAPED), SHAPED),
    ("neutral-named parameter description", lambda o: _param(o, name="X-Client-Ref", description=f"e.g. {SHAPED}"), SHAPED),
    ("security scheme description, unlabelled", lambda o: {("components" if o else "securityDefinitions"): ({"securitySchemes": {"Partner": {"type": "apiKey", "in": "header", "name": "X-Partner", "description": f"Sandbox value {SHAPED}"}}} if o else {"Partner": {"type": "apiKey", "in": "header", "name": "X-Partner", "description": f"Sandbox value {SHAPED}"}})}, SHAPED),
    ("security scheme x- extension", lambda o: {"securityDefinitions": {"Partner": {"type": "apiKey", "in": "header", "name": "X-Partner", "x-sandbox": SHAPED}}}, SHAPED),
    ("security scheme label in description", lambda o: {"securityDefinitions": {"Partner": {"type": "apiKey", "in": "query", "name": "p", "description": f"Master key: {WORDY}"}}}, WORDY),
    ("response header example", lambda o: {"paths": {"/x": {"get": {"responses": {"200": {"description": "ok", "headers": {"X-Rate": {"example": SHAPED}}}}}}}}, SHAPED),
    ("x- extension object", lambda o: {"x-internal": {"value": SHAPED}}, SHAPED),
    ("x- extension prose label", lambda o: {"x-notes": f"redis password: {WORDY}"}, WORDY),
    # Secret-named keys anywhere below.
    ("schema property example", lambda o: {"definitions": {"C": {"properties": {"redis_password": {"type": "string", "example": WORDY}}}}}, WORDY),
    ("request body example object", lambda o: _op(requestBody={"content": {"application/json": {"example": {"user": "a", "password": WORDY}}}}), WORDY),
    ("secret-named response header", lambda o: {"paths": {"/x": {"get": {"responses": {"200": {"description": "ok", "headers": {"X-Auth-Token": {"schema": {"example": WORDY}}}}}}}}}, WORDY),
    ("server variable default", lambda o: {"servers": [{"url": "https://{apiKey}.example", "variables": {"apiKey": {"default": WORDY}}}]}, WORDY),
    ("oauth2 client secret extension", lambda o: {"securityDefinitions": {"O": {"type": "oauth2", "flow": "application", "tokenUrl": "https://a.example/t", "x-client-secret": WORDY}}}, WORDY),
    # Provider formats anywhere, under any key.
    ("provider key in a summary", lambda o: _op(summary=f"Example {STRIPE}"), STRIPE),
    ("provider key as a neutral example", lambda o: {"definitions": {"C": {"properties": {"note": {"example": GITHUB}}}}}, GITHUB),
    ("provider key in a server description", lambda o: {"servers": [{"url": "https://a.example", "description": AWS}]}, AWS),
    ("credentialed server URL", lambda o: {"servers": [{"url": f"postgres://app:{WORDY}@db.example/app"}]}, WORDY),
]


def _document(builder, oas3: bool) -> dict:
    head = {"openapi": "3.0.3"} if oas3 else {"swagger": "2.0"}
    head.setdefault("info", {"title": "corpus", "version": "1"})
    fragment = builder(oas3)
    return {**head, **fragment}


def _bodies(document: dict) -> dict:
    return {
        "json_text": json.dumps(document, indent=2),
        "json_compact": json.dumps(document),
        "json_decoded": document,
        "yaml": yaml.safe_dump(document, sort_keys=False, width=4096),
    }


def _row(body) -> dict:
    return {
        "id": "1", "sequence": 0, "plane": "scan", "capability_name": "web.spec_ingest",
        "method": "GET", "url": "https://corpus.example/openapi", "status_code": 200,
        "request_headers": {}, "request_body": None, "response_headers": {},
        "response_body": body,
    }


@pytest.mark.parametrize("oas3", [False, True], ids=["oas2", "oas3"])
@pytest.mark.parametrize(
    "placement,builder,secret", PLACEMENTS, ids=[item[0] for item in PLACEMENTS],
)
def test_every_openapi_secret_placement_is_withheld(placement, builder, secret, oas3):
    for kind, body in _bodies(_document(builder, oas3)).items():
        archive = json.dumps(project(_row(body), redaction="redacted"))
        assert secret not in archive, (placement, kind, "archive JSON")
        har = json.dumps(export_document(
            [_row(body)], export_format="har", redaction="redacted",
            owner={"scan_id": "s"}, total=1,
        ))
        assert secret not in har, (placement, kind, "masked HAR")


def test_the_specification_still_reads_as_one():
    """Aimed withholding: names, locations, types, plain prose and ordinary examples stay."""
    document = {
        "openapi": "3.0.3",
        "info": {"title": "corpus", "description": "Sign in with your account."},
        "paths": {"/users": {"get": {
            "summary": "List users",
            "description": "Returns users. Sort key: name",
            "parameters": [
                {"name": "X-Api-Key", "in": "header", "schema": {"type": "string"}},
                {"name": "page", "in": "query", "schema": {"type": "integer", "default": 7}},
                {"name": "region", "in": "query", "example": "eu-west-1"},
                {"name": "callback", "in": "query", "example": "https://app.example/cb"},
            ],
        }}},
    }
    masked = json.loads(mask_body_text(json.dumps(document)))
    get = masked["paths"]["/users"]["get"]
    assert masked["info"]["description"] == "Sign in with your account."
    assert get["summary"] == "List users"
    assert [p["name"] for p in get["parameters"]] == ["X-Api-Key", "page", "region", "callback"]
    assert get["parameters"][0]["in"] == "header"
    assert get["parameters"][1]["schema"]["default"] == 7
    assert get["parameters"][2]["example"] == "eu-west-1"
    assert get["parameters"][3]["example"] == "https://app.example/cb"
    yaml_text = mask_body_text(yaml.safe_dump(document, sort_keys=False))
    assert "name: X-Api-Key" in yaml_text and "example: eu-west-1" in yaml_text
    assert "default: 7" in yaml_text


@pytest.mark.parametrize("unit", [
    "Master key ",
    "a b c: ",
    '{"description": "k: v ',
    "x-a:\n  - name: token\n    ",
    "aB3" * 40 + " ",
])
def test_masking_stays_linear_on_hostile_bodies(unit):
    """Doubling a hostile body must not much more than double the masking time."""
    def elapsed(repeat: int) -> float:
        body = unit * repeat
        started = time.perf_counter()
        mask_body_text(body)
        mask_body_text('{"description": "' + body.replace('"', "'") + '"}')
        return time.perf_counter() - started

    small, large = elapsed(4_000), elapsed(16_000)
    assert large < max(small * 12, 0.05) and large < 5.0
