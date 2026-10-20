"""Authorization-aware active Nuclei template selection.

The fixtures under ``tests/fixtures/nuclei_templates`` are real templates copied
verbatim from the pinned ProjectDiscovery bundle:

* ``squid-analysis-report-generator`` -- GET only (exposure/high)
* ``django-debug-exposure`` -- ``method: POST`` (exposure/high)
* ``bloofoxcms-default-login`` -- raw-request POST (default-login/high)
* ``put-method-enabled`` -- raw ``PUT``, tagged ``intrusive`` (misconfig/high)
* ``springboot-heapdump`` -- GET only (exposure,misconfig/critical), but requests
  ``/heapdump`` and ``/actuator/heapdump``, which a Scan never requests
* ``broken-template.yaml`` -- deliberately malformed YAML (parse error)

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
    build_nuclei_method_index,
    clear_index_cache,
    nuclei_templates_directory,
    resolve_active_nuclei_selection,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nuclei_templates"


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
        "put-method-enabled",
        "springboot-heapdump",
    }
    # The malformed template is counted, not silently classified as GET-only.
    assert index.parse_errors >= 1
    assert not by_id["squid-analysis-report-generator"].state_changing
    assert by_id["django-debug-exposure"].state_changing  # method: POST
    assert by_id["bloofoxcms-default-login"].state_changing  # raw-request POST
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
    }
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
    """Image test: the pinned bundle the scanner image installs (``NUCLEI_TEMPLATES``)."""
    bundle = Path(nuclei_templates_directory())
    if not (bundle / "http").is_dir():
        pytest.skip("requires the pinned Nuclei template bundle of the scanner image")
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
