"""No value under a secret-named key is ever stored in clear, whatever its entropy.

Audit M1: when no value in a .env or web.config.bak passed the entropy screen, the body was
classed as a plain configuration file and its first 400 characters went through a redactor
that only knew the values that HAD passed the screen. ``DB_PASS=Winter2023!``,
``APP_KEY=base64:...`` and ``JWT_KEY=...`` stayed in clear while the record claimed
``"secret_values_visible": False``. Classification may decide verified vs unverified; it must
never decide whether a raw value is shown. Each case below carries a low-entropy and a
high-entropy canary under secret-named keys that the proof contract does not verify; neither
may reach the stored observation, the report, its findings, SARIF, logs or stdout.
"""

from __future__ import annotations

import json
import logging

import pytest

from api.capabilities.exposure_probe import classify_exposure, redacted_exposure_excerpt
from scanner.scanner_tools.sarif_output import convert_to_sarif
from tests.test_exposure_verified_checks import _finalized, _observation

# Canaries assembled at runtime. LOW fails the entropy screen; the HIGH ones pass it but sit
# under names (APP_KEY, JWT_KEY) the proof vocabulary does not verify.
LOW = "Winter" + "2023!"
LOW_PIN = "hunter" + "22hunter"
HIGH_APP_KEY = "base64:" + "q7Rz2Vx9Lm4Tb8Nc1Hd6Kp3Ws5Fy0Ge2Ju7Ab9QxY4="
HIGH_JWT = "Jk4" + "Pz8Wq2Nv6Rt1Ly5Xb9Hc3Md7Fg0Ks"
PROVEN = "Vt9qLx2Rm7Zp4Kw8sJ3n"
CANARIES = (LOW, LOW_PIN, HIGH_APP_KEY, HIGH_JWT, PROVEN)


def _web_config(*adds: str, connection: str = "") -> bytes:
    rows = "".join(f'<add key="{key}" value="{value}" />' for key, value in
                   (item.split("=", 1) for item in adds))
    strings = (f'<connectionStrings><add name="Default" connectionString="{connection}" />'
               "</connectionStrings>") if connection else ""
    return (f'<?xml version="1.0"?><configuration><appSettings>{rows}</appSettings>{strings}'
            '<system.web><compilation debug="false" /></system.web></configuration>').encode()


CASES = [
    # (label, path, body, content type, verified)
    ("dotenv_unverified", "/.env",
     f"APP_ENV=production\nDB_PASS={LOW}\nAPP_KEY={HIGH_APP_KEY}\nJWT_KEY={HIGH_JWT}\n"
     f"ADMIN_PIN_CODE_PASSWORD={LOW_PIN}\nPORT=3000\n".encode(), "text/plain", False),
    ("dotenv_verified", "/.env.production",
     f"DB_PASSWORD={PROVEN}\nDB_PASS={LOW}\nAPP_KEY={HIGH_APP_KEY}\nJWT_KEY={HIGH_JWT}\n".encode(),
     "text/plain", True),
    ("properties", "/application.properties",
     f"server.port=8080\nspring.datasource.password={LOW}\njwt.key={HIGH_JWT}\n"
     f"app.key={HIGH_APP_KEY}\n".encode(), "text/plain", False),
    ("web_config", "/web.config",
     _web_config(f"DbPassword={LOW}", f"JwtKey={HIGH_JWT}", f"AppKey={HIGH_APP_KEY}",
                 connection=f"Server=db;User Id=sa;Password={LOW_PIN};"), "text/xml", False),
    ("web_config_backup", "/web.config.bak",
     _web_config(f"DbPassword={LOW}", f"JwtKey={HIGH_JWT}", f"AppKey={HIGH_APP_KEY}",
                 connection=f"Server=db;User Id=sa;Password={LOW_PIN};"),
     "application/octet-stream", True),  # a backup artifact verifies; its values do not
    ("web_config_verified", "/web.config.bak",
     _web_config(f"DbPassword={PROVEN}", f"JwtKey={HIGH_JWT}", f"AppKey={HIGH_APP_KEY}",
                 connection=f"Server=db;Password={LOW};"), "application/octet-stream", True),
    ("appsettings", "/appsettings.json", json.dumps({
        "Auth": {"ClientSecret": PROVEN, "Jwt": {"Key": HIGH_JWT}, "AppKey": HIGH_APP_KEY},
        "ConnectionStrings": {"Default": f"Server=db;User Id=sa;Password={LOW};"},
    }).encode(), "application/json", True),
    ("actuator_unverified", "/actuator/env", json.dumps({"propertySources": [
        {"name": "applicationConfig", "properties": {
            "spring.datasource.password": {"value": LOW},
            "jwt.key": {"value": HIGH_JWT}, "app.key": {"value": HIGH_APP_KEY},
            "server.port": {"value": 8080}}}]}).encode(), "application/json", False),
    ("phpinfo", "/phpinfo.php", (
        "<html><head><title>PHP 8.2.1 - phpinfo()</title></head><body><h1>PHP Version 8.2.1</h1>"
        f'<table><tr><td class="e">DB_PASS</td><td class="v">{LOW}</td></tr>'
        f'<tr><td class="e">APP_KEY</td><td class="v">{HIGH_APP_KEY}</td></tr>'
        f'<tr><td class="e">JWT_KEY</td><td class="v">{HIGH_JWT}</td></tr></table></body></html>'
    ).encode(), "text/html", True),
    ("verbose_error", "/debug", (
        "Traceback (most recent call last):\n  File \"app.py\", line 3, in <module>\n"
        f"KeyError: settings DB_PASS={LOW} APP_KEY={HIGH_APP_KEY} JWT_KEY={HIGH_JWT}\n"
    ).encode(), "text/plain", True),
]


@pytest.mark.parametrize(("label", "path", "body", "content_type", "verified"), CASES,
                         ids=[case[0] for case in CASES])
def test_no_secret_named_value_reaches_any_stored_surface(
    label, path, body, content_type, verified, caplog, capsys,
):
    caplog.set_level(logging.DEBUG)
    signature = classify_exposure(path=path, status=200,
                                  headers={"Content-Type": content_type}, body=body)
    assert signature is not None, label
    assert signature.proves_sensitive_exposure is verified, (label, signature.exposure_class)
    observation = _observation(path, body, content_type)
    assert observation["secret_values_visible"] is False
    report = _finalized(observation)
    if verified:
        assert report["findings"], label
    surfaces = {
        "excerpt": redacted_exposure_excerpt(body, signature),
        "observation": json.dumps(observation, default=str),
        "report": json.dumps(report, default=str),
        "sarif": json.dumps(convert_to_sarif(report), default=str),
        "logs": caplog.text,
        "stdout": "".join(capsys.readouterr()),
        "signature_repr": repr(signature),
    }
    for surface, text in surfaces.items():
        for canary in CANARIES:
            assert canary not in text, (label, surface)


@pytest.mark.parametrize(("label", "path", "body", "content_type"), [
    (case[0], case[1], case[2], case[3]) for case in CASES
    if case[0] not in {"phpinfo", "verbose_error"}
], ids=[case[0] for case in CASES if case[0] not in {"phpinfo", "verbose_error"}])
def test_configuration_documents_are_withheld_and_keep_only_key_names(
    label, path, body, content_type,
):
    signature = classify_exposure(path=path, status=200,
                                  headers={"Content-Type": content_type}, body=body)
    excerpt = redacted_exposure_excerpt(body, signature)
    assert excerpt.startswith(f"[{signature.exposure_class} detected - content withheld"), label
    # Key names stay as evidence so an operator knows what to rotate.
    assert "secret-named keys:" in excerpt


def test_free_text_excerpts_mask_every_secret_named_assignment():
    body = (
        "Traceback (most recent call last):\n"
        f'KeyError: {{"db_pass": "{LOW}", "jwtKey": "{HIGH_JWT}"}} DB_PASS={LOW} '
        "mode=debug\n"
    ).encode()
    signature = classify_exposure(path="/debug", status=200,
                                  headers={"Content-Type": "text/plain"}, body=body)
    assert signature is not None and signature.exposure_class == "verbose_error_disclosure"
    excerpt = redacted_exposure_excerpt(body, signature)
    assert "Traceback" in excerpt and "mode=debug" in excerpt
    for canary in (LOW, HIGH_JWT):
        assert canary not in excerpt
