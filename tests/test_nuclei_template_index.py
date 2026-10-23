"""Authorization-aware active Nuclei template selection.

The fixtures under ``tests/fixtures/nuclei_templates`` are real templates copied
verbatim from the pinned ProjectDiscovery bundle:

* ``squid-analysis-report-generator`` -- GET only (exposure/high)
* ``django-debug-exposure`` -- ``method: POST`` (exposure/high)
* ``bloofoxcms-default-login`` -- raw-request POST (default-login/high)
* ``tomcat-default-login`` -- raw-request GET (default-login/high) that sends payload
  usernames and passwords in an ``Authorization`` header: a login attempt by GET
* ``put-method-enabled`` -- raw ``PUT``, tagged ``intrusive`` (misconfig/high)
* ``springboot-heapdump`` -- GET only (exposure,misconfig/critical), but requests
  ``/heapdump`` and ``/actuator/heapdump``, which a Scan never requests
* ``broken-template.yaml`` -- deliberately malformed YAML (parse error)

``tests/fixtures/nuclei_templates_credentials`` holds real templates of the same bundle, copied
verbatim, that send only GET requests and either try a login or change state by GET:

* ``CVE-2020-24285``, ``CVE-2024-28987`` -- template ``variables`` username/password in a Basic
  ``Authorization`` header
* ``CVE-2024-20439``, ``CVE-2021-26294`` -- a literal Basic ``user:password`` pair
* ``CVE-2026-8181`` -- an extracted administrator name signed in as with password ``x``
* ``CVE-2025-0674`` -- ``GET /json_data/set_pwd?...&pass=admin1234`` sets the admin password
* ``CVE-2024-43919`` -- ``GET .../yarpp_pro_set_display_types.php?...`` sets the plugin's display
  types
* ``CVE-2024-5910`` -- ``GET /OS/startup/restore/restoreAdmin.php`` restores the default admin
  password
* ``CVE-2024-9989`` -- ``GET .../admin-ajax.php?...&method_name=register&param1=admin`` calls the
  plugin's register method for user ``admin``
* ``CNVD-2023-72138`` -- ``GET /api/v1/user/save?...&Username={{user}}...`` adds an administrator
  (outside the default tags)
* ``CVE-2013-4982`` -- a payload username and password in the query string: a login attempt (low
  severity, outside the default selection)
* ``CVE-2024-33939`` -- a payload user id in the query string reads that user's progress: neither
  (medium severity, outside the default selection)
* ``CVE-2023-29298`` -- ``inPassword=foo`` sent to a hashing method: neither
* ``github-personal-access`` -- a token found in the page, sent to its issuer in a ``flow`` step:
  exploit-class

``tests/fixtures/nuclei_templates_exploit`` holds real exploit-class templates of the same bundle,
copied verbatim, that send only GET requests:

* ``CVE-2022-46169`` -- ``poller_id=;curl ...;``: a command run on the target (``rce``)
* ``CVE-2024-28255`` -- a ``Runtime.exec`` expression in the path (``rce``)
* ``sitecore-lfi`` -- a file read through a path parameter (``lfi``)
* ``prest-sqli-auth-bypass`` -- a SQL expression in the path (``sqli``)

Tests that write templates into ``tmp_path`` use synthetic unit fixtures.
"""

from __future__ import annotations

import os
from pathlib import Path
import re

import pytest
import yaml

from capabilities.exposure_probe import is_never_requested
from scan import nuclei_template_index
from scan.nuclei_template_index import (
    NEVER_REQUESTED_TEMPLATE_IDS,
    STATE_CHANGING_GET_TEMPLATE_IDS,
    build_nuclei_method_index,
    clear_index_cache,
    nuclei_templates_directory,
    resolve_active_nuclei_selection,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates"
CREDENTIAL_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates_credentials"
EXPLOIT_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates_exploit"


@pytest.fixture(autouse=True)
def _fresh_index_cache():
    clear_index_cache()
    yield
    clear_index_cache()


def test_index_classifies_methods_and_intrusive_from_real_templates():
    index = build_nuclei_method_index(str(FIXTURES))
    by_id = {record.template_id: record for record in index.templates}
    assert set(by_id) == {
        "squid-analysis-report-generator",
        "django-debug-exposure",
        "bloofoxcms-default-login",
        "tomcat-default-login",
        "put-method-enabled",
        "springboot-heapdump",
    }
    # The malformed template is counted, not silently classified as GET-only.
    assert index.parse_errors >= 1
    assert not by_id["squid-analysis-report-generator"].state_changing
    assert by_id["django-debug-exposure"].state_changing  # method: POST
    assert by_id["bloofoxcms-default-login"].state_changing  # raw-request POST
    # A default login sent by GET is still a login attempt: credential-level, so it needs the
    # state-changing permission whatever its method.
    tomcat = by_id["tomcat-default-login"]
    assert tomcat.methods == frozenset({"GET"})
    assert tomcat.credential_level and tomcat.state_changing
    assert by_id["bloofoxcms-default-login"].credential_level
    assert not any(by_id[name].credential_level for name in (
        "squid-analysis-report-generator", "django-debug-exposure", "put-method-enabled",
        "springboot-heapdump"))
    assert by_id["put-method-enabled"].intrusive  # raw PUT, tagged intrusive
    heapdump = by_id["springboot-heapdump"]
    assert heapdump.never_requested and not heapdump.state_changing and not heapdump.intrusive
    assert not any(by_id[name].never_requested for name in set(by_id) - {"springboot-heapdump"})


def test_unauthorized_selection_excludes_post_raw_and_intrusive_templates():
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=False,
    )
    assert selection.skip is False
    assert selection.template_ids == ("squid-analysis-report-generator",)
    assert selection.includes_state_changing is False
    # Neither the method-POST, the raw-POST, nor the intrusive template may run.
    assert "django-debug-exposure" not in selection.template_ids
    assert "bloofoxcms-default-login" not in selection.template_ids
    assert "put-method-enabled" not in selection.template_ids
    # Nor a default login that sends its passwords by GET.
    assert "tomcat-default-login" not in selection.template_ids
    assert selection.credential_level_count == 2
    assert selection.state_changing_count == 3
    assert selection.intrusive_excluded == 1
    # GET-only, critical and tagged exposure/misconfig, but it requests /heapdump.
    assert "springboot-heapdump" not in selection.template_ids
    assert selection.never_requested_excluded == 1


def test_authorized_selection_includes_post_but_still_excludes_intrusive():
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True,
    )
    assert selection.skip is False
    assert selection.includes_state_changing is True
    assert set(selection.template_ids) == {
        "squid-analysis-report-generator",
        "django-debug-exposure",
        "bloofoxcms-default-login",
        "tomcat-default-login",
    }
    assert selection.credential_level_count == 2
    # A destructive template needs more than state-changing permission, which
    # Scan has no tier to grant, so it is excluded even when authorized.
    assert "put-method-enabled" not in selection.template_ids
    assert selection.intrusive_excluded == 1
    assert "springboot-heapdump" not in selection.template_ids
    assert selection.never_requested_excluded == 1


def test_index_failure_fails_closed(tmp_path):
    # A directory with no http/ subtree cannot be classified: fail closed in both
    # authorization states rather than running an unknown selection.
    for authorized in (False, True):
        selection = resolve_active_nuclei_selection(
            str(tmp_path), allow_state_changing_http=authorized,
        )
        assert selection.skip is True
        assert selection.skip_reason == "nuclei_template_index_unavailable"
        assert selection.template_ids == ()
        assert selection.includes_state_changing is False


def test_severity_filter_narrows_the_selection():
    # Only high/critical fixtures exist; a medium-only filter selects nothing and
    # fails closed (an honest coverage gap, not a clean empty run).
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), severities="medium", allow_state_changing_http=True,
    )
    assert selection.skip is True
    assert selection.skip_reason == "no_eligible_nuclei_templates"


def _write_template(root, relpath, text):
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_unreadable_raw_request_line_counts_as_a_mutation(tmp_path):
    _write_template(tmp_path, "http/exposures/templated-verb.yaml", """id: templated-verb
info:
  name: templated verb
  severity: high
  tags: exposure
http:
  - raw:
      - |
        GET /status HTTP/1.1
        Host: {{Hostname}}
      - |
        {{verb}} /status HTTP/1.1
        Host: {{Hostname}}
""")
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert record.state_changing
    selection = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=False)
    assert selection.skip is True and selection.template_ids == ()


def test_shared_template_id_is_classified_by_every_template_that_carries_it(tmp_path):
    header = "info:\n  name: shared\n  severity: high\n  tags: exposure{extra}\n"
    _write_template(tmp_path, "http/a/shared.yaml", "id: shared-id\n" + header.format(extra="")
                    + "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/a'\n")
    _write_template(tmp_path, "http/b/shared.yaml", "id: shared-id\n" + header.format(extra=",intrusive")
                    + "http:\n  - method: PUT\n    path:\n      - '{{BaseURL}}/b'\n")
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert record.methods == frozenset({"GET", "PUT"}) and record.intrusive
    for allowed in (False, True):
        selection = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=allowed)
        assert "shared-id" not in selection.template_ids


def test_a_verify_scan_never_runs_a_template_that_requests_a_never_requested_path():
    selection = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True, allow_exploit_classes=True,
        only_template_ids="springboot-heapdump,squid-analysis-report-generator",
    )
    assert selection.template_ids == ("squid-analysis-report-generator",)
    assert selection.verify_selection["excluded"] == {"springboot-heapdump": "never_requested_path"}
    only = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True, allow_exploit_classes=True,
        only_template_ids="springboot-heapdump",
    )
    assert only.skip is True and only.template_ids == ()


_GET_TEMPLATE = """id: {template_id}
info:
  name: synthetic unit fixture
  severity: high
  tags: exposure
{body}"""


_REQUEST_FORMS = {
    "path-entry": ("http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/management/heapdump/'\n", True),
    "raw-with-query": ("http:\n  - raw:\n      - |\n        @timeout: 5s\n        GET /heapdump?live=true HTTP/1.1\n"
                       "        Host: {{Hostname}}\n", True),
    "payload-file": ("http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/{{route}}'\n"
                     "    payloads:\n      route: helpers/wordlists/routes.txt\n", True),
    "variable": ("variables:\n  dump: actuator/heapdump\nhttp:\n  - method: GET\n    path:\n"
                 "      - '{{BaseURL}}/{{dump}}'\n", True),
    "other-actuator-route": ("http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/actuator/env'\n", False),
    # The word in a matcher is not a request.
    "matcher-word-only": ("http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/actuator'\n"
                          "    matchers:\n      - type: word\n        words:\n          - heapdump\n", False),
}


@pytest.mark.parametrize("template_id", sorted(_REQUEST_FORMS))
def test_never_requested_paths_are_found_in_every_request_form(tmp_path, template_id):
    # Synthetic unit fixtures: one template per request form the index expands.
    body, never_requested = _REQUEST_FORMS[template_id]
    (tmp_path / "helpers" / "wordlists").mkdir(parents=True)
    (tmp_path / "helpers" / "wordlists" / "routes.txt").write_text("status\nactuator/heapdump\n")
    _write_template(tmp_path, f"http/{template_id}.yaml", _GET_TEMPLATE.format(template_id=template_id, body=body))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert record.never_requested is never_requested
    selection = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=True)
    assert (template_id in selection.template_ids) is not never_requested


def test_a_reviewed_never_requested_template_is_excluded_even_when_its_paths_are_not_found(tmp_path):
    # Synthetic unit fixture: a bundle update that moves the reviewed template's paths where the
    # request parser cannot see them must not bring it back.
    _write_template(tmp_path, "http/springboot-heapdump.yaml", _GET_TEMPLATE.format(
        template_id="springboot-heapdump",
        body="http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/{{unknown}}'\n"))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert not record.never_requested
    for authorized in (False, True):
        selection = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=authorized)
        assert selection.skip is True and selection.never_requested_excluded == 1


def _request_tokens(document, bundle: Path):
    """Every word a template's request section can put in a URL: paths, raw request text,
    payload values (inline or from a bundle file) and variables. Matchers are left out."""
    texts = [str(value) for value in (document.get("variables") or {}).values()]
    for request in document.get("http") or document.get("requests") or []:
        if not isinstance(request, dict):
            continue
        texts.extend(str(item) for item in (request.get("path") or []))
        texts.extend(str(item) for item in (request.get("raw") or []))
        for values in (request.get("payloads") or {}).values():
            if isinstance(values, str) and (bundle / values).is_file():
                texts.append((bundle / values).read_text(encoding="utf-8", errors="replace"))
            else:
                texts.extend(str(item) for item in (values if isinstance(values, list) else [values]))
    for text in texts:
        yield from re.split(r"[\s'\",]+", re.sub(r"\{\{[^{}]*\}\}", "", text))


def test_pinned_bundle_never_runs_a_template_that_requests_a_never_requested_path():
    """Image test: the pinned bundle the scanner image installs (``NUCLEI_TEMPLATES``).

    The release candidate runs it in the scanner image. Where ``NUCLEI_TEMPLATES`` is set
    the bundle must be there, so a missing bundle fails instead of skipping."""
    if "NUCLEI_TEMPLATES" not in os.environ:
        pytest.skip("requires the pinned Nuclei template bundle of the scanner image")
    bundle = Path(nuclei_templates_directory())
    # The cached index is the one the selections below read, so the bundle is parsed once.
    index = nuclei_template_index._cached_index(str(bundle))
    found = {record.template_id for record in index.templates if record.never_requested}
    # A bundle update that adds a template requesting such a path, or hides one from the
    # parser, fails here until the reviewed set is updated.
    assert found == NEVER_REQUESTED_TEMPLATE_IDS
    selected: set[str] = set()
    for authorized in (False, True):
        selection = resolve_active_nuclei_selection(str(bundle), allow_state_changing_http=authorized)
        assert selection.skip is False and selection.never_requested_excluded == len(found)
        selected.update(selection.template_ids)
    assert not selected & found
    # Independently of the index's request parser, no selected template names such a path.
    offenders = set()
    for dirpath, _dirs, files in os.walk(bundle / "http"):
        for filename in files:
            if not filename.endswith(".yaml"):
                continue
            source = (Path(dirpath) / filename).read_text(encoding="utf-8", errors="replace")
            template_id = re.search(r"^id:\s*(\S+)", source, re.MULTILINE)
            if template_id is None or template_id.group(1).strip().lower() not in selected:
                continue
            document = yaml.safe_load(source)
            if any(is_never_requested("/" + token.lstrip("/")) for token in _request_tokens(document, bundle)):
                offenders.add(template_id.group(1))
    assert offenders == set()


def test_release_candidate_runs_the_pinned_bundle_test_in_the_scanner_image():
    root = Path(__file__).resolve().parents[1]
    workflow = yaml.safe_load(
        (root / ".github" / "workflows" / "release-candidate.yml").read_text(encoding="utf-8"))
    steps = [step for job in workflow["jobs"].values() for step in job.get("steps") or []]
    names = [str(step.get("name") or "") for step in steps]
    check = next(step for step in steps
                 if step.get("name") == "Verify the active Nuclei selection never requests a heapdump path")
    script = check["run"]
    assert "--network none" in script and "shakerscan-scanner:release-candidate" in script
    assert "tests/test_nuclei_template_index.py" in script
    # The same candidate bytes are checked before the wire acceptance and publication.
    assert names.index(check["name"]) < names.index("Enforce candidate-image external wire ceilings")


_CREDENTIAL_TEMPLATE = """id: {template_id}
info:
  name: synthetic unit fixture
  severity: high
  tags: {tags}
http:
{body}"""


_CREDENTIAL_FORMS = {
    # Tagged default-login: credential-level whatever it sends.
    "tagged-get": ("default-login", "  - method: GET\n    path:\n      - '{{BaseURL}}/manager/html'\n", True),
    # A username/password payload put into a header of a raw GET.
    "raw-header": ("exposure", "  - raw:\n      - |\n        GET /admin HTTP/1.1\n        Host: {{Hostname}}\n"
                   "        Authorization: Basic {{base64(username + ':' + password)}}\n"
                   "    payloads:\n      username:\n        - admin\n      password:\n        - admin\n", True),
    # ... into a structured request's header.
    "structured-header": ("misconfig", "  - method: GET\n    path:\n      - '{{BaseURL}}/api'\n"
                          "    headers:\n      X-Api-User: '{{user}}'\n      X-Api-Pass: '{{pass}}'\n"
                          "    payloads:\n      user:\n        - admin\n      pass:\n        - admin\n", True),
    # ... into a raw request's body.
    "raw-body": ("exposure", "  - raw:\n      - |\n        GET /login HTTP/1.1\n        Host: {{Hostname}}\n\n"
                 "        login={{admin_user}}&secret={{admin_password}}\n"
                 "    payloads:\n      admin_user:\n        - admin\n      admin_password:\n        - admin\n", True),
    # A username list that only names paths enumerates accounts; it signs in as nobody.
    "username-in-path": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/users/{{username}}'\n"
                         "    payloads:\n      username:\n        - admin\n", False),
    # ... and so does one in a raw request line.
    "raw-username-in-path": ("exposure", "  - raw:\n      - |\n        GET /users/{{username}} HTTP/1.1\n"
                             "        Host: {{Hostname}}\n"
                             "    payloads:\n      username:\n        - admin\n", False),
    # A header payload that is not named like a username or password.
    "other-header-payload": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"
                             "    headers:\n      X-Forwarded-Host: '{{host}}'\n"
                             "    payloads:\n      host:\n        - example.test\n", False),
    # A payload put into a structured request's body.
    "structured-body": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/session'\n"
                        "    body: 'name={{username}}&secret={{password}}'\n"
                        "    payloads:\n      username:\n        - admin\n      password:\n        - admin\n", True),
    # A request's own variables, not a payload list, put into a header.
    "request-variables": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/api'\n"
                          "    variables:\n      api_user: admin\n      api_pass: admin\n"
                          "    headers:\n      Authorization: \"Basic {{base64(api_user + ':' + api_pass)}}\"\n", True),
    # A username and password put into a raw request line's query string.
    "raw-query": ("exposure", "  - raw:\n      - |\n        GET /login.cgi?user={{username}}&pwd={{password}} HTTP/1.1\n"
                  "        Host: {{Hostname}}\n"
                  "    payloads:\n      username:\n        - admin\n      password:\n        - admin\n", True),
    # ... and into a structured path's query string.
    "path-query": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/login?u={{user}}&p={{pass}}'\n"
                   "    payloads:\n      user:\n        - admin\n      pass:\n        - admin\n", True),
    # A password alone in the query string is still a login attempt.
    "password-only-query": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/unlock?pin={{password}}'\n"
                            "    payloads:\n      password:\n        - '0000'\n", True),
    # A username alone in the query string looks the account up; it signs in as nobody.
    "username-only-query": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/api/users?name={{username}}'\n"
                            "    payloads:\n      username:\n        - admin\n", False),
    # ... and so does a user id in a raw request line's query string.
    "raw-user-id-query": ("exposure", "  - raw:\n      - |\n        GET /progress?user_id={{user}} HTTP/1.1\n"
                          "        Host: {{Hostname}}\n"
                          "    payloads:\n      user:\n        - '1'\n", False),
    # A literal Basic user:password pair (admin:admin) in a structured request's header.
    "structured-literal-basic": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/manager'\n"
                                 "    headers:\n      Authorization: 'Basic YWRtaW46YWRtaW4='\n", True),
    # A literal Basic value that decodes to no pair is not a credential.
    "structured-basic-no-pair": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/manager'\n"
                                 "    headers:\n      Authorization: 'Basic YWRtaW4='\n", False),
    # A literal Basic user with an empty password (admin:) is a default login.
    "literal-basic-empty-password": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/manager'\n"
                                     "    headers:\n      Authorization: 'Basic YWRtaW46'\n", True),
    # ... and so is a literal password with an empty user (:admin), as a device that asks only
    # for a password takes it.
    "literal-basic-password-only": ("exposure", "  - raw:\n      - |\n        GET /cgi-bin/status HTTP/1.1\n"
                                    "        Host: {{Hostname}}\n"
                                    "        Authorization: Basic OmFkbWlu\n", True),
    # A literal Basic value of an empty user and password (:) names no account.
    "literal-basic-empty-pair": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/manager'\n"
                                 "    headers:\n      Authorization: 'Basic Og=='\n", False),
    # A literal user:password pair inside a Basic header expression.
    "literal-basic-expression": ("exposure", "  - raw:\n      - |\n        GET /admin HTTP/1.1\n"
                                 "        Host: {{Hostname}}\n"
                                 "        Authorization: Basic {{base64('admin:admin')}}\n", True),
    # A Basic header that carries only a token found earlier names no account.
    "basic-token-only": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"
                         "    extractors:\n      - type: regex\n        name: token\n        internal: true\n"
                         "        regex:\n          - 'tok_[a-z0-9]{8}'\n"
                         "  - raw:\n      - |\n        GET /me HTTP/1.1\n        Host: {{Hostname}}\n"
                         "        Authorization: Basic {{base64(token + ':')}}\n", False),
    # A fixed API user name joined to a token found earlier sends no password of that user.
    "basic-api-user-token": ("exposure", "  - method: GET\n    path:\n      - '{{BaseURL}}/'\n"
                             "    extractors:\n      - type: regex\n        name: token\n        internal: true\n"
                             "        regex:\n          - 'key-[a-z0-9]{8}'\n"
                             "  - raw:\n      - |\n        GET /v3/domains HTTP/1.1\n        Host: {{Hostname}}\n"
                             "        Authorization: Basic {{base64('api:' + token)}}\n", False),
}


#: Every word that names a value like a username or like a password. A value whose name holds
#: either kind of word is a credential in a header or the body; in the query string only a
#: password is (a username alone there looks an account up).
_USERNAME_WORDS = ("user", "users", "username", "usernames", "login", "logins")
_PASSWORD_WORDS = ("pass", "passwd", "password", "passwords", "pwd", "pw")


@pytest.mark.parametrize("name", [*(f"{prefix}{word}" for word in (*_USERNAME_WORDS, *_PASSWORD_WORDS)
                                    for prefix in ("", "admin_"))])
@pytest.mark.parametrize("place", ["header", "query"])
def test_each_credential_word_names_a_credential_payload(tmp_path, name, place):
    # Synthetic unit fixtures: a payload of that name, sent in a header or the query string.
    sent = ("    headers:\n      X-Check: '{{" + name + "}}'\n" if place == "header" else "")
    path = "{{BaseURL}}/check" + ("?v={{" + name + "}}" if place == "query" else "")
    body = f"  - method: GET\n    path:\n      - '{path}'\n{sent}    payloads:\n      {name}:\n        - admin\n"
    _write_template(tmp_path, "http/word.yaml",
                    _CREDENTIAL_TEMPLATE.format(template_id="word-check", tags="exposure", body=body))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    is_password = name.removeprefix("admin_") in _PASSWORD_WORDS
    assert record.credential_level is (place == "header" or is_password)


@pytest.mark.parametrize("template_id", sorted(_CREDENTIAL_FORMS))
def test_a_login_attempt_by_get_needs_the_state_changing_permission(tmp_path, template_id):
    # Synthetic unit fixtures: one GET-only template per credential rule.
    tags, body, credential_level = _CREDENTIAL_FORMS[template_id]
    _write_template(tmp_path, f"http/{template_id}.yaml",
                    _CREDENTIAL_TEMPLATE.format(template_id=template_id, tags=tags, body=body))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert not record.methods - {"GET", "HEAD"}
    assert record.credential_level is credential_level
    plain = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=True)
    assert (template_id in plain.template_ids) is not credential_level
    assert template_id in authorized.template_ids
    assert authorized.includes_state_changing is credential_level
    assert plain.credential_level_count == authorized.credential_level_count == int(credential_level)


def test_a_verify_scan_runs_a_default_login_check_only_with_state_changing_permission():
    plain = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=False, only_template_ids="tomcat-default-login")
    assert plain.skip is True and plain.template_ids == ()
    assert plain.verify_selection["excluded"] == {
        "tomcat-default-login": "credential_level_needs_state_changing_http"}
    authorized = resolve_active_nuclei_selection(
        str(FIXTURES), allow_state_changing_http=True, only_template_ids="tomcat-default-login")
    assert authorized.template_ids == ("tomcat-default-login",)
    assert authorized.includes_state_changing is True
    assert authorized.credential_level_count == 1


#: The verbatim credential fixtures: credential-level, changes state by GET (reviewed), or neither.
_CREDENTIAL_FIXTURE_CLASSES = {
    "cve-2020-24285": "credential_level",
    "cve-2024-28987": "credential_level",
    "cve-2024-20439": "credential_level",
    "cve-2021-26294": "credential_level",
    "cve-2026-8181": "credential_level",
    "cve-2013-4982": "credential_level",
    "cve-2025-0674": "changes_state_by_get",
    "cve-2024-43919": "changes_state_by_get",
    "cve-2024-5910": "changes_state_by_get",
    "cve-2024-9989": "changes_state_by_get",
    "cnvd-2023-72138": "changes_state_by_get",
    "cve-2023-29298": "neither",
    "cve-2024-33939": "neither",
    "github-personal-access": "exploit_class",
}
#: Fixtures outside the default severities and tags: only a verify Scan of exactly that template
#: requests them.
_OUTSIDE_DEFAULT_SELECTION = {"cve-2013-4982", "cnvd-2023-72138", "cve-2024-33939"}


def test_real_templates_that_sign_in_or_change_state_by_get_need_the_state_changing_permission():
    index = build_nuclei_method_index(str(CREDENTIAL_FIXTURES))
    by_id = {record.template_id: record for record in index.templates}
    assert set(by_id) == set(_CREDENTIAL_FIXTURE_CLASSES)
    for template_id, kind in _CREDENTIAL_FIXTURE_CLASSES.items():
        record = by_id[template_id]
        assert record.methods == frozenset({"GET"}), template_id
        assert record.credential_level is (kind == "credential_level"), template_id
        if kind in {"exploit_class", "neither"}:
            assert record.exploit_class is (kind == "exploit_class"), template_id
        assert record.state_changing is (kind != "neither"), template_id
    plain = resolve_active_nuclei_selection(str(CREDENTIAL_FIXTURES), allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(str(CREDENTIAL_FIXTURES), allow_state_changing_http=True)
    assert set(plain.template_ids) == {"cve-2023-29298"}
    assert set(authorized.template_ids) == set(_CREDENTIAL_FIXTURE_CLASSES) - _OUTSIDE_DEFAULT_SELECTION
    assert plain.credential_level_count == authorized.credential_level_count == 5
    assert plain.state_changing_count == 10


@pytest.mark.parametrize("template_id", sorted(
    template_id for template_id, kind in _CREDENTIAL_FIXTURE_CLASSES.items() if kind == "changes_state_by_get"))
def test_a_get_reviewed_as_changing_state_runs_only_with_the_permission(template_id):
    assert template_id in STATE_CHANGING_GET_TEMPLATE_IDS
    plain = resolve_active_nuclei_selection(
        str(CREDENTIAL_FIXTURES), allow_state_changing_http=False, allow_exploit_classes=True,
        only_template_ids=template_id)
    assert plain.skip is True and plain.verify_selection["excluded"] == {
        template_id: "needs_state_changing_http"}
    authorized = resolve_active_nuclei_selection(
        str(CREDENTIAL_FIXTURES), allow_state_changing_http=True, allow_exploit_classes=True,
        only_template_ids=template_id)
    assert authorized.template_ids == (template_id,) and authorized.includes_state_changing


@pytest.mark.parametrize("template_id,reason", [
    ("cve-2013-4982", "credential_level_needs_state_changing_http"),
    ("cve-2024-33939", None),
])
def test_a_verify_scan_holds_back_a_password_in_the_query_but_not_a_user_lookup(template_id, reason):
    plain = resolve_active_nuclei_selection(
        str(CREDENTIAL_FIXTURES), allow_state_changing_http=False, only_template_ids=template_id)
    assert plain.verify_selection["excluded"] == ({template_id: reason} if reason else {})
    assert plain.template_ids == (() if reason else (template_id,))


#: The reviewed state-changing GETs (``STATE_CHANGING_GET_TEMPLATE_IDS``). Four are in the pinned
#: bundle's default selection; CNVD-2023-72138 is outside it, and a verify Scan can request it.
_REVIEWED_STATE_CHANGING_GETS = {
    "cve-2025-0674": True, "cve-2024-43919": True, "cve-2024-5910": True, "cve-2024-9989": True,
    "cnvd-2023-72138": False,
}


def test_the_state_changing_get_review_names_its_templates_and_the_bundle_it_read():
    from scan.work_manifests import CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256

    assert STATE_CHANGING_GET_TEMPLATE_IDS == frozenset(_REVIEWED_STATE_CHANGING_GETS)
    # A bundle bump fails here, on any host, until its selection is reviewed again.
    assert nuclei_template_index.STATE_CHANGING_GET_REVIEWED_BUNDLE_SHA256 == (
        CANONICAL_NUCLEI_TEMPLATE_BUNDLE_SHA256)
    dockerfile = (Path(__file__).parents[1] / "scanner" / "Dockerfile").read_text()
    assert ("ARG NUCLEI_TEMPLATES_SHA256="
            f"{nuclei_template_index.STATE_CHANGING_GET_REVIEWED_BUNDLE_SHA256}") in dockerfile


def test_the_reviewed_passive_pack_holds_no_default_login():
    # Hunt and the passive family run only this pack, whatever their permissions.
    from scan.work_manifests import CANONICAL_PASSIVE_NUCLEI_TEMPLATES

    assert all("default-login" not in row[4] for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES)


_EXPLOIT_FIXTURE_IDS = frozenset({
    "cve-2022-46169", "cve-2024-28255", "sitecore-lfi", "prest-sqli-auth-bypass",
})


def test_an_exploit_template_sent_by_get_needs_the_state_changing_permission():
    index = build_nuclei_method_index(str(EXPLOIT_FIXTURES))
    by_id = {record.template_id: record for record in index.templates}
    assert set(by_id) == _EXPLOIT_FIXTURE_IDS
    for template_id, record in by_id.items():
        assert record.methods == frozenset({"GET"}), template_id
        assert record.exploit_class and record.state_changing, template_id
        assert not record.credential_level and not record.intrusive, template_id
    plain = resolve_active_nuclei_selection(str(EXPLOIT_FIXTURES), allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(str(EXPLOIT_FIXTURES), allow_state_changing_http=True)
    # Without the permission nothing of the four runs, so the sweep fails closed as a gap.
    assert plain.skip is True and plain.template_ids == ()
    assert plain.skip_reason == "no_eligible_nuclei_templates"
    assert set(authorized.template_ids) == _EXPLOIT_FIXTURE_IDS
    assert authorized.includes_state_changing is True
    # Counted under their own name, whether or not the permission was granted.
    assert plain.exploit_class_count == authorized.exploit_class_count == 4
    assert plain.telemetry()["exploit_class"] == authorized.telemetry()["exploit_class"] == 4
    assert plain.get_only_count == 0 and plain.state_changing_count == 4


@pytest.mark.parametrize("form,header", [
    ("tagged-rce", ""),
    ("tagged-lfi", ""),
    ("flow-step", "flow: http(1)\n"),
])
def test_a_get_template_with_an_exploit_tag_or_a_script_step_needs_the_permission(tmp_path, form, header):
    # Synthetic unit fixtures: one GET-only template per exploit-class rule.
    tags = {"tagged-rce": "exposure,rce", "tagged-lfi": "misconfig,lfi"}.get(form, "exposure")
    _write_template(tmp_path, f"http/{form}.yaml", (
        f"id: {form}\ninfo:\n  name: synthetic unit fixture\n  severity: high\n  tags: {tags}\n{header}"
        "http:\n  - method: GET\n    path:\n      - '{{BaseURL}}/status'\n"))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert record.methods == frozenset({"GET"}) and record.exploit_class and record.state_changing
    plain = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=True)
    assert plain.skip is True and form not in plain.template_ids
    assert authorized.template_ids == (form,) and authorized.includes_state_changing is True
    assert plain.exploit_class_count == authorized.exploit_class_count == 1


def test_a_verify_scan_runs_an_exploit_check_only_with_the_state_changing_tier():
    # A verify Scan grants the exploit tier exactly when it has state-changing authority.
    for allowed in (False, True):
        selection = resolve_active_nuclei_selection(
            str(EXPLOIT_FIXTURES), allow_state_changing_http=allowed, allow_exploit_classes=allowed,
            only_template_ids="prest-sqli-auth-bypass")
        assert selection.exploit_class_count == 1
        if allowed:
            assert selection.template_ids == ("prest-sqli-auth-bypass",)
            assert selection.includes_state_changing is True
        else:
            assert selection.skip is True and selection.verify_selection["excluded"] == {
                "prest-sqli-auth-bypass": "exploit_class_needs_exploit_tier"}
    # Neither grant alone runs it.
    for state_changing, exploit, reason in (
            (True, False, "exploit_class_needs_exploit_tier"), (False, True, "needs_state_changing_http")):
        selection = resolve_active_nuclei_selection(
            str(EXPLOIT_FIXTURES), allow_state_changing_http=state_changing,
            allow_exploit_classes=exploit, only_template_ids="prest-sqli-auth-bypass")
        assert selection.template_ids == () and selection.exploit_class_count == 1
        assert selection.verify_selection["excluded"] == {"prest-sqli-auth-bypass": reason}
    # A check that needs a callback is not run at all, whatever the grants.
    oob = resolve_active_nuclei_selection(
        str(EXPLOIT_FIXTURES), allow_state_changing_http=True, allow_exploit_classes=True,
        only_template_ids="cve-2024-28255")
    assert oob.verify_selection["excluded"] == {"cve-2024-28255": "needs_oob_interaction"}


#: Templates in the pinned bundle's active selection that send only GET or HEAD requests but
#: are credential-level: tagged default-login, a value named like a username or password (a
#: payload, a variable or an extracted value) sent in a header or the body, a password-named value
#: in the query string, or a literal Basic ``user:password`` pair. Before 2.11.1 they ran without
#: the state-changing permission; so did the GETs reviewed as changing state
#: (``STATE_CHANGING_GET_TEMPLATE_IDS``).
PINNED_BUNDLE_GET_ONLY_CREDENTIAL_LEVEL = 52
#: GET-only templates of the pinned bundle's active selection that are exploit-class and neither
#: credential-level nor reviewed as changing state: 13 tagged rce, 10 lfi, 2 sqli, 2 ssrf and 41
#: with a code, JavaScript or flow step. They also ran without the permission before 2.11.1.
PINNED_BUNDLE_GET_ONLY_EXPLOIT_CLASS = 68
#: Exploit-class templates among the eligible ones, whatever their method.
PINNED_BUNDLE_EXPLOIT_CLASS = 162
#: The GET-only selection without the permission: 760 GETs before 2.11.1, 124 of them now behind
#: it (52 login attempts, the 4 reviewed state-changing GETs of the default selection and the 68
#: exploit-class GETs).
PINNED_BUNDLE_GET_ONLY_SELECTION = 636
#: The selection with the permission: the same 1,145 templates, in the same order, as before
#: 2.11.1 held anything back, so every window position with the permission is unchanged.
PINNED_BUNDLE_AUTHORIZED_SELECTION = 1145
PINNED_BUNDLE_AUTHORIZED_SELECTION_SHA256 = (
    "49465477e3b156b3ffc717a23f0da07c8baf65a00876284f095abf1ed5361093"
)


def test_pinned_bundle_default_logins_run_only_with_state_changing_permission():
    """Image test: the pinned bundle the scanner image installs (``NUCLEI_TEMPLATES``)."""
    if "NUCLEI_TEMPLATES" not in os.environ:
        pytest.skip("requires the pinned Nuclei template bundle of the scanner image")
    bundle = str(nuclei_templates_directory())
    index = nuclei_template_index._cached_index(bundle)
    by_id = {record.template_id: record for record in index.templates}
    tomcat = by_id["tomcat-default-login"]
    assert tomcat.methods == frozenset({"GET"}) and tomcat.credential_level
    plain = resolve_active_nuclei_selection(bundle, allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(bundle, allow_state_changing_http=True)
    selected = set(authorized.template_ids)
    moved = {
        template_id for template_id in selected
        if by_id[template_id].credential_level and not by_id[template_id].methods - {"GET", "HEAD"}
    }
    assert len(moved) == PINNED_BUNDLE_GET_ONLY_CREDENTIAL_LEVEL
    assert "tomcat-default-login" in moved
    assert {"cve-2020-24285", "cve-2024-28987", "cve-2024-20439", "cve-2021-26294",
            "cve-2026-8181"} <= moved
    # Each reviewed state-changing GET is in the bundle, sends only GET and is not already held
    # back as a login attempt, so the list names exactly what it adds; the review says which are
    # in the default selection.
    for template_id, in_selection in _REVIEWED_STATE_CHANGING_GETS.items():
        record = by_id[template_id]
        assert (template_id in selected) is in_selection, template_id
        assert record.methods == frozenset({"GET"}), template_id
        assert not record.credential_level and record.state_changing, template_id
    assert not STATE_CHANGING_GET_TEMPLATE_IDS & set(plain.template_ids)
    assert len(plain.template_ids) == PINNED_BUNDLE_GET_ONLY_SELECTION
    # The reviewed pack Hunt and the passive family run, whatever their permissions, holds no
    # login attempt and nothing else that needs the state-changing permission.
    from scan.work_manifests import CANONICAL_PASSIVE_NUCLEI_TEMPLATES

    pack = [str(row[0]).lower() for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES]
    assert all(template_id in by_id and not by_id[template_id].state_changing for template_id in pack)
    assert not {
        template_id for template_id in plain.template_ids if by_id[template_id].credential_level}
    assert plain.credential_level_count == authorized.credential_level_count
    assert authorized.credential_level_count == sum(
        1 for template_id in selected if by_id[template_id].credential_level)


def test_pinned_bundle_exploit_templates_run_only_with_state_changing_permission():
    """Image test: the pinned bundle the scanner image installs (``NUCLEI_TEMPLATES``)."""
    if "NUCLEI_TEMPLATES" not in os.environ:
        pytest.skip("requires the pinned Nuclei template bundle of the scanner image")
    import hashlib
    import math

    from scan.external_process import (
        ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS, ACTIVE_TEMPLATE_PLANNED_WINDOWS,
    )
    from scan.nuclei_execution import ACTIVE_TEMPLATE_WINDOW_SIZE

    bundle = str(nuclei_templates_directory())
    index = nuclei_template_index._cached_index(bundle)
    by_id = {record.template_id: record for record in index.templates}
    plain = resolve_active_nuclei_selection(bundle, allow_state_changing_http=False)
    authorized = resolve_active_nuclei_selection(bundle, allow_state_changing_http=True)
    # The two the review named: a command run on the target, and a Runtime.exec call, by GET.
    for template_id in ("cve-2022-46169", "cve-2024-28255"):
        record = by_id[template_id]
        assert record.methods == frozenset({"GET"}) and record.exploit_class and "rce" in record.tags
        assert template_id in authorized.template_ids and template_id not in plain.template_ids
    assert not {template_id for template_id in plain.template_ids if by_id[template_id].exploit_class}
    moved = {
        template_id for template_id in authorized.template_ids
        if by_id[template_id].exploit_class and not by_id[template_id].methods - {"GET", "HEAD"}
        and not by_id[template_id].credential_level
        and template_id not in STATE_CHANGING_GET_TEMPLATE_IDS
    }
    assert len(moved) == PINNED_BUNDLE_GET_ONLY_EXPLOIT_CLASS
    assert len(plain.template_ids) == PINNED_BUNDLE_GET_ONLY_SELECTION
    assert plain.exploit_class_count == authorized.exploit_class_count == PINNED_BUNDLE_EXPLOIT_CLASS
    assert authorized.exploit_class_count == sum(
        1 for template_id in authorized.template_ids if by_id[template_id].exploit_class)
    # With the permission nothing moved: the same templates in the same order, so the same
    # windows at the same positions; without it, the GET-only allowlist has fewer windows.
    assert len(authorized.template_ids) == PINNED_BUNDLE_AUTHORIZED_SELECTION
    assert hashlib.sha256(",".join(authorized.template_ids).encode()).hexdigest() == (
        PINNED_BUNDLE_AUTHORIZED_SELECTION_SHA256)
    assert set(plain.template_ids) == {
        template_id for template_id in authorized.template_ids if not by_id[template_id].state_changing}
    assert ACTIVE_TEMPLATE_PLANNED_WINDOWS == math.ceil(
        PINNED_BUNDLE_AUTHORIZED_SELECTION / ACTIVE_TEMPLATE_WINDOW_SIZE) == 39
    assert ACTIVE_TEMPLATE_PLANNED_GET_ONLY_WINDOWS == math.ceil(
        PINNED_BUNDLE_GET_ONLY_SELECTION / ACTIVE_TEMPLATE_WINDOW_SIZE) == 22


@pytest.mark.parametrize("login_first", [True, False])
def test_a_shared_template_id_is_credential_level_when_any_template_carrying_it_is(tmp_path, login_first):
    # Synthetic unit fixtures: `-id` runs both, so the GET default login keeps the id behind
    # the permission even though its sibling only reads a page, whichever is read first.
    order = ("default-login", "exposure") if login_first else ("exposure", "default-login")
    for name, tags in zip(("a", "b"), order):
        _write_template(tmp_path, f"http/{name}/shared.yaml", _CREDENTIAL_TEMPLATE.format(
            template_id="shared-login", tags=tags,
            body="  - method: GET\n    path:\n      - '{{BaseURL}}/" + name + "'\n"))
    (record,) = build_nuclei_method_index(str(tmp_path)).templates
    assert record.methods == frozenset({"GET"}) and record.credential_level
    plain = resolve_active_nuclei_selection(str(tmp_path), allow_state_changing_http=False)
    assert plain.skip is True and plain.template_ids == ()
