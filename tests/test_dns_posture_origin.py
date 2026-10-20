"""DNS posture findings name the target's own origin, not an HTTPS origin it may not serve.

Unit fixture modelled on recorded scan evidence: an http-only apex target's SPF, DMARC and CAA
findings carried https://<apex>/, where nothing listened, while the same Scan's HTTP findings
carried the target's http:// origin.
"""

from __future__ import annotations

import pytest

from api.finding_detail import build_finding_detail
from tests.test_detect211_posture import _dns, _report

RECORDS = {"host_txt": ["v=spf1 +all"], "host_mx": [{"host": "mail.example.com", "priority": 10}]}


def _found(target, host="example.com"):
    report = _report(_dns(RECORDS, host=host), target=target, capabilities={"baseline.dns": "dns.inspect"})
    return {f["evidence"]["check"]: f for f in report["findings"]}


@pytest.mark.parametrize("target,origin", [
    ("http://example.com", "http://example.com"),
    ("https://example.com", "https://example.com"),
    ("http://example.com:8080", "http://example.com:8080"),
    ("https://example.com:443", "https://example.com"),
])
def test_dns_findings_use_the_target_origin(target, origin):
    found = _found(target)
    assert set(found) == {"spf_pass_all", "dmarc_missing", "caa_missing"}
    for finding in found.values():
        assert finding["url"].rstrip("/") == origin, finding["url"]


def test_a_name_that_is_not_the_target_host_keeps_its_https_origin():
    found = _found("http://www.example.com", host="example.com")
    assert all(finding["url"].rstrip("/") == "https://example.com" for finding in found.values())


def test_the_dns_page_still_names_the_domain():
    brief = build_finding_detail(_found("http://example.com")["spf_pass_all"])
    assert brief["reproduce"]["command"] == "dig +short TXT example.com"
