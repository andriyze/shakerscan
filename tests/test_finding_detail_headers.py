"""Header and cookie finding pages: the detected stack, and copyable advice that matches what was seen.

Unit fixtures modelled on recorded scan evidence (a Tomcat connector's Server header, a session
cookie without flags).
"""

from __future__ import annotations

import json

import pytest

from api.finding_detail import build_finding_detail
from api.finding_detail.common import detected_stack


@pytest.mark.parametrize("server", ["Apache-Coyote/1.1", "fixture/1.0, Apache-Coyote/1.1", "Apache Tomcat/9.0.85"])
def test_tomcat_connector_is_not_apache_httpd(server):
    assert detected_stack({"server": server}) == "tomcat"


def test_apache_httpd_is_still_apache():
    assert detected_stack({"server": "Apache/2.4.58 (Ubuntu)"}) == "apache"


def test_weak_header_on_tomcat_leads_with_the_tomcat_example():
    brief = build_finding_detail({"tool": "http_baseline", "severity": "info", "url": "http://app.fixture.invalid/",
        "evidence": {"check": "weak_header_content-security-policy", "header": "content-security-policy",
                     "url": "http://app.fixture.invalid/", "observed_value": "default-src 'self' 'unsafe-inline'",
                     "observed_response": {"response_status": 200, "observed_headers": {
                         "server": "fixture/1.0, Apache-Coyote/1.1"}}}})
    assert brief["stack"] == "tomcat"
    assert brief["examples"][0]["label"] == "Tomcat / Spring"
    assert "Header always set" not in json.dumps(brief["examples"][0])

