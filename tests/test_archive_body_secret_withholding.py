"""Masked archive views withhold every secret the exposure evidence withholds (soak N39).

Soak scans b723d50d, 47449681 and 06b5bd1d exported, in the masked HTTP archive and the UI's
"HAR 1.2 (masked)" download, the ``web.spec_ingest`` body of ``/swagger.json`` with three
secrets in clear: a Stripe-format API-key ``default``, an internal admin token ``default`` and a
``redis_password`` ``example``. Key-name redaction never saw them: the first two sit beside a
secret *name* in a parameter descriptor, the third one level below a secret-named key, and the
stored body is text. The exposure finding for the same file withheld all three.

These tests put canaries in every body shape (JSON whole and truncated, a decoded JSON object,
YAML, HTML, dotenv text, bytes) and read them back through the archive JSON projection, the
HAR export and the export route the UI downloads from. The canaries are test fixtures.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

import pytest

from api.runtime import http_archive_router as archive_router
from api.runtime.http_archive_reader import export_document, project

STRIPE = "sk_" + "live_" + "Qz7Lm2Xc9Vb4Nr8Tk1Wp6Hd5Fa"
ADMIN_TOKEN = "AdmTokCanary7Q2x9LkPz4Wm"
REDIS_PASSWORD = "RedisCnry13x"
LOW_ENTROPY = "Winter2023!"
CSRF = "CsrfCanary5Rt8Yu1Io"
GITHUB = "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2"
AWS = "AKIA" + "Q7RZ3XKC5LMN2PWD"
DB_PASSWORD = "DbUriCanary88"
CANARIES = (STRIPE, ADMIN_TOKEN, REDIS_PASSWORD, LOW_ENTROPY, CSRF, GITHUB, AWS, DB_PASSWORD)

SWAGGER = {
    "swagger": "2.0",
    "info": {"title": "honey", "version": "1"},
    "paths": {
        "/users": {"get": {"parameters": [{
            "name": "api_key", "in": "query", "type": "string", "default": STRIPE,
        }]}},
        "/internal/admin": {"post": {"parameters": [{
            "name": "X-Admin-Token", "in": "header", "type": "string", "default": ADMIN_TOKEN,
        }]}},
        "/auth/login": {"post": {"summary": "Sign in"}},
    },
    "definitions": {"Config": {"properties": {
        "redis_password": {"type": "string", "example": REDIS_PASSWORD},
        "database_url": {"type": "string", "example": f"postgres://app:{DB_PASSWORD}@db/app"},
        "region": {"type": "string", "example": "eu-west-1"},
    }}},
}
SWAGGER_TEXT = json.dumps(SWAGGER, indent=2)
OPENAPI_YAML = f"""openapi: 3.0.0
info:
  title: honey
paths:
  /users:
    get:
      parameters:
        - name: api_key
          in: query
          schema:
            type: string
            default: {STRIPE}
        - name: page
          in: query
          schema:
            default: 7
components:
  schemas:
    Config:
      properties:
        redis_password:
          type: string
          example: {REDIS_PASSWORD}
        admin_token: {ADMIN_TOKEN}
"""
HTML = (
    "<!doctype html><html><body><form>"
    f'<input type="hidden" name="csrf_token" value="{CSRF}">'
    f'<meta name="api-key" content="{ADMIN_TOKEN}">'
    "</form><script>window.cfg = "
    f'{{"credentials": {{"github": "{GITHUB}", "aws": "{AWS}"}}, "theme": "dark"}};'
    "</script></body></html>"
)
DOTENV = (
    f"DB_PASS={LOW_ENTROPY}\nSTRIPE_SECRET_KEY={STRIPE}\n"
    f"DATABASE_URL=postgres://app:{DB_PASSWORD}@db/app\nAPP_ENV=production\n"
)
BODIES = {
    "json_text": SWAGGER_TEXT,
    "json_truncated": SWAGGER_TEXT[:SWAGGER_TEXT.index("region")],
    "json_decoded": SWAGGER,
    "yaml": OPENAPI_YAML,
    "html": HTML,
    "dotenv": DOTENV,
    "bytes": DOTENV.encode(),
}


def _row(body, *, request_body=None) -> dict:
    return {
        "id": "1", "sequence": 0, "plane": "scan", "capability_name": "web.spec_ingest",
        "method": "GET", "url": "https://honey.example/swagger.json", "status_code": 200,
        "request_headers": {"accept": "*/*"}, "request_body": request_body,
        "response_headers": {"content-type": "application/json"}, "response_body": body,
    }


def _present(text: str, body_kind: str) -> list[str]:
    expected = {
        "json_text": (STRIPE, ADMIN_TOKEN, REDIS_PASSWORD, DB_PASSWORD),
        "json_truncated": (STRIPE, ADMIN_TOKEN, REDIS_PASSWORD, DB_PASSWORD),
        "json_decoded": (STRIPE, ADMIN_TOKEN, REDIS_PASSWORD, DB_PASSWORD),
        "yaml": (STRIPE, ADMIN_TOKEN, REDIS_PASSWORD),
        "html": (CSRF, ADMIN_TOKEN, GITHUB, AWS),
        "dotenv": (LOW_ENTROPY, STRIPE, DB_PASSWORD),
        "bytes": (LOW_ENTROPY, STRIPE, DB_PASSWORD),
    }[body_kind]
    return [canary for canary in expected if canary in text]


@pytest.mark.parametrize("body_kind", sorted(BODIES))
def test_the_masked_archive_json_withholds_every_canary(body_kind):
    item = project(_row(BODIES[body_kind]), redaction="redacted")
    assert _present(json.dumps(item), body_kind) == []
    # The raw view is the verbatim record (and stays a separate, deployment-gated choice).
    raw = json.dumps(project(_row(BODIES[body_kind]), redaction="raw"))
    assert _present(raw, body_kind) or body_kind == "json_decoded"


@pytest.mark.parametrize("body_kind", sorted(BODIES))
def test_the_masked_har_withholds_every_canary(body_kind):
    document = export_document(
        [_row(BODIES[body_kind], request_body=BODIES[body_kind])],
        export_format="har", redaction="redacted", owner={"scan_id": "s"}, total=1,
    )
    entries = json.dumps(document["log"]["entries"])
    assert _present(entries, body_kind) == []
    assert document["log"]["creator"]["name"] == "ShakerScan (masked)"


def test_the_masked_view_keeps_what_is_not_secret():
    """Withholding is aimed: the specification still reads as one."""
    masked = json.loads(project(_row(SWAGGER_TEXT), redaction="redacted")["response"]["body"])
    users = masked["paths"]["/users"]["get"]["parameters"][0]
    assert users["name"] == "api_key" and users["in"] == "query" and users["type"] == "string"
    assert users["default"] == "***"
    assert masked["paths"]["/auth/login"]["post"]["summary"] == "Sign in"
    assert masked["definitions"]["Config"]["properties"]["region"]["example"] == "eu-west-1"
    from api.runtime.archive_body_masking import mask_body_text

    yaml = mask_body_text(OPENAPI_YAML)
    assert "default: 7" in yaml and "name: page" in yaml and "name: api_key" in yaml


def _export_with_rows(monkeypatch, rows, *, export_format, redaction):
    @asynccontextmanager
    async def acquire():
        yield object()

    class _Pool:
        def acquire(self):
            return acquire()

    async def _ids(conn, scan_id):
        return (scan_id,)

    async def _count(conn, **kwargs):
        return len(rows)

    async def _stats(conn, **kwargs):
        return {}

    async def _rows(conn, **kwargs):
        return rows

    monkeypatch.setattr(archive_router, "_pool", lambda: _Pool())
    monkeypatch.setattr(archive_router, "_scan_archive_ids", _ids)
    monkeypatch.setattr(archive_router, "count_transactions", _count)
    monkeypatch.setattr(archive_router, "read_archive_stats", _stats)
    monkeypatch.setattr(archive_router, "read_transactions", _rows)
    return asyncio.run(archive_router._export(
        request=object(), scan_id="11111111-1111-4111-8111-111111111111", hunt_run_id=None,
        export_format=export_format, redaction=redaction, method=None, status_code=None,
        search=None, limit=10_000, offset=0,
    ))


@pytest.mark.parametrize("export_format", ["har", "transactions"])
def test_the_ui_download_route_withholds_every_canary(monkeypatch, export_format):
    """``HttpArchiveExport`` downloads ``?format=har&redaction=redacted`` (HAR 1.2 masked) and
    ``?format=transactions&redaction=redacted`` (the archive JSON) from this route."""
    rows = [dict(_row(body), id=str(index)) for index, body in enumerate(BODIES.values())]
    response = _export_with_rows(
        monkeypatch, rows, export_format=export_format, redaction="redacted",
    )
    body = response.body.decode()
    assert [canary for canary in CANARIES if canary in body] == []
    assert response.headers["x-shakerscan-archive-redaction"] == "redacted"


def test_verbatim_har_stays_refused_where_the_deployment_disables_it(monkeypatch):
    """Enterprise publishes the API beyond loopback without the raw opt-in: only the masked
    HAR is offered, so the masked HAR is the one that has to be safe."""
    from fastapi import HTTPException

    monkeypatch.setenv("SHAKERSCAN_BIND_HOST", "0.0.0.0")
    monkeypatch.delenv("SHAKERSCAN_HTTP_ARCHIVE_RAW_HAR", raising=False)
    with pytest.raises(HTTPException) as refused:
        _export_with_rows(
            monkeypatch, [_row(SWAGGER_TEXT)], export_format="har", redaction="raw",
        )
    assert refused.value.status_code == 403
