"""Credential stores are reviewed exposure seeds with a deterministic proof (soak N42).

The Hunt verified a GitHub token at honey's ``/.git-credentials``; DAST only had nuclei's
"Git Credentials - Detect" as a suspicion, because the path was not in the exposure seed list.
These tests pin ``/.git-credentials`` and the closely related ``.netrc``, ``.npmrc`` (with auth)
and ``.pypirc`` as seeds, each proved by its own grammar, verified only for a credential that
passes the shared secret screen, and never stored in clear. The canaries are test fixtures.
The batch run over ``/.git-credentials`` is in tests/test_exposure_probe_batch_controls.py,
which uses the flat import layout of the dispatcher.
"""

from __future__ import annotations

import json

import pytest

from api.capabilities.exposure_probe import (
    SENSITIVE_SEED_PATHS,
    classify_exposure,
    redacted_exposure_excerpt,
)

GITHUB = "ghp_" + "Zt8Qw3Er6Ty9Ui2Op5As7Df1Gh4Jk0Lz3Xc6V"
NETRC_PASSWORD = "Nr7c-Qx2v9Lm4Tb8Wk1Zp6Hd"
NPM = "npm_" + "Q7rZ3xKc5LmN2pWd9VbT4yHs8JfGa1Ue6Ri0"
PYPI = "pypi-AgEIcHlwaS5vcmcCJGQ3Zjg5YTEyLWI0NTYtNDc4OS05YWJjLWRlZjAxMjM0NTY3OAACKlszLCJm"

STORES = {
    "/.git-credentials": f"https://deploy:{GITHUB}@github.com\nhttps://ci:{NETRC_PASSWORD}@git.example.com:8443/org\n",
    "/.netrc": (
        "# deploy host\nmachine api.example.com\n  login deploy@example.com\n"
        f"  password {NETRC_PASSWORD}\n"
    ),
    "/.npmrc": f"registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken={NPM}\nalways-auth=true\n",
    "/.pypirc": (
        "[distutils]\nindex-servers =\n    pypi\n\n[pypi]\nusername = __token__\n"
        f"password = {PYPI}\n"
    ),
}
CANARIES = {
    "/.git-credentials": (GITHUB, NETRC_PASSWORD),
    "/.netrc": (NETRC_PASSWORD,),
    "/.npmrc": (NPM,),
    "/.pypirc": (PYPI,),
}
PATTERNS = {
    "/.git-credentials": "git_credentials_store",
    "/.netrc": "netrc_credentials",
    "/.npmrc": "npmrc_auth_token",
    "/.pypirc": "pypirc_credentials",
}


def _classify(path: str, body: str, content_type: str = "text/plain"):
    return classify_exposure(
        path=path, status=200, headers={"content-type": content_type}, body=body.encode(),
    )


def test_every_credential_store_is_a_reviewed_seed():
    for path in STORES:
        assert path in SENSITIVE_SEED_PATHS


@pytest.mark.parametrize("path", sorted(STORES))
def test_a_credential_store_verifies_by_its_grammar_and_is_withheld(path):
    signature = _classify(path, STORES[path])
    assert signature is not None
    assert signature.exposure_class == "configuration_secret_file"
    assert signature.matched_pattern == PATTERNS[path]
    assert signature.proof_contract == "config_secret_exposure/v1"
    assert signature.secrets and signature.withholds_content
    excerpt = redacted_exposure_excerpt(STORES[path].encode(), signature)
    stored = json.dumps([excerpt, signature.secret_evidence(), list(signature.withheld_keys)])
    for canary in CANARIES[path]:
        assert canary not in stored and canary not in repr(signature)
    assert "content withheld" in excerpt


@pytest.mark.parametrize(("path", "body"), [
    ("/.git-credentials", "https://deploy:changeme@github.com\n"),
    ("/.netrc", "machine api.example.com login deploy password ${NETRC_PASSWORD}\n"),
    ("/.npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"),
    ("/.pypirc", "[pypi]\nusername = __token__\npassword = <your-token>\n"),
])
def test_a_placeholder_credential_is_an_observation_not_a_finding(path, body):
    signature = _classify(path, body)
    assert signature is not None and signature.exposure_class == "configuration_file"
    assert signature.proof_contract is None
    assert signature.withholds_content


@pytest.mark.parametrize("path", sorted(STORES))
def test_a_page_about_the_file_proves_nothing(path):
    prose = f"How to configure {path.lstrip('/')}: put your credentials in it.\nSee the docs."
    assert _classify(path, prose) is None
    assert _classify(path, f"<html><body><pre>{STORES[path]}</pre></body></html>", "text/html") is None
