"""Every connected-device check's findings get fix guidance on the finding page.

Guidance comes from the remediation knowledge base, matched by what produced the finding
(``finding_type``), or, for checks whose titles are per-probe catalog text, from the check's own
remediation text persisted in evidence (``producer``). A device check added without either shows
an empty "How to fix", so this guard enumerates the checks the code emits and fails until the new
one is listed in EMITTED_DEVICE_CHECKS below.

The producer calls here use unit fixtures (synthetic headers, services and requests), not a device.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / "api"))
sys.path.insert(0, str(_ROOT / "scanner"))

from evidence_triage import build_evidence_with_triage  # noqa: E402
from finding_routes.remediation import finding_remediation  # noqa: E402
from scanner_tools import (  # noqa: E402
    device_application,
    device_control_plane,
    device_posture,
    device_web,
    remediation_kb_findings,
)

# tool -> titles it emits whose guidance must come from the knowledge base. Tools listed in
# PRODUCER_GUIDED instead emit per-probe catalog titles with per-probe remediation text.
EMITTED_DEVICE_CHECKS: dict[str, tuple[str, ...]] = {
    "device_ssh": (
        "SSH Password Authentication Enabled",
        "SSH Keyboard-Interactive Authentication Enabled",
        "SSH Negotiated Weak Cryptographic Algorithm",
    ),
    "device_policy": (
        "Device service requirement not met: ssh on 22/tcp",
        "Deny device service: telnet on 23/tcp",
        "Review device service: http on 80/tcp",
    ),
    "device_tls": ("Device HTTPS trust could not be established",),
    "device_web_headers": (
        "Device HTTPS management interface does not declare HSTS",
        "Device management page has no Content Security Policy",
        "Device management page lacks framing protection",
        "Device management page allows content-type sniffing",
        "Authenticated device response lacks private cache controls",
        "Device management cookie lacks protective attributes",
    ),
    "device_candidate_verifier": (
        "Affected connected-device software: CVE-2024-0001",
        "Policy-denied connected-device service is exposed",
        "Device SSH cryptographic posture violates policy",
        "Device HTTPS identity verification failed",
        "Device API authentication bypass reproduced",
    ),
    "device_request_dast": (),
    "device_application_dast": (),
    "device_control_plane_dast": (),
    "device_web_discovery": (),
}
PRODUCER_GUIDED = frozenset({
    "device_request_dast", "device_application_dast", "device_control_plane_dast", "device_web_discovery",
})

_PRODUCER_SOURCES = (
    *sorted((_ROOT / "scanner" / "scanner_tools").glob("device_*.py")),
    _ROOT / "scanner" / "scanner_tools" / "ssh_scanner.py",
    _ROOT / "api" / "worker.py",
    *sorted((_ROOT / "api" / "devices").glob("*.py")),
)


def _literal(value: ast.AST, constants: dict[str, str]) -> str | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    if isinstance(value, ast.Name):
        return constants.get(value.id)
    return None


def _emitted_device_tools() -> set[str]:
    """String literals a producer assigns to a finding's ``tool``, resolving module constants."""
    tools: set[str] = set()
    for path in _PRODUCER_SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        constants = {
            target.id: node.value.value
            for node in tree.body if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
            for target in node.targets if isinstance(target, ast.Name) and isinstance(node.value.value, str)
        }
        for node in ast.walk(tree):
            values: list[ast.AST] = []
            if isinstance(node, ast.Dict):
                values = [v for k, v in zip(node.keys, node.values) if isinstance(k, ast.Constant) and k.value == "tool"]
            elif (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "setdefault" and len(node.args) == 2
                and isinstance(node.args[0], ast.Constant) and node.args[0].value == "tool"
            ):
                values = [node.args[1]]
            for value in values:
                text = _literal(value, constants)
                if text and text.startswith("device_"):
                    tools.add(text)
    return tools


def test_every_device_check_the_code_emits_is_listed():
    emitted = _emitted_device_tools()
    assert {"device_ssh", "device_policy", "device_web_discovery"} <= emitted, "the AST scan lost its producers"
    assert emitted == set(EMITTED_DEVICE_CHECKS), (
        "Device checks changed. Add each new check to EMITTED_DEVICE_CHECKS with the titles it emits "
        "and give it knowledge-base guidance (remediation_kb_findings), or list it in PRODUCER_GUIDED "
        f"if every finding carries its own remediation text. New: {sorted(emitted - set(EMITTED_DEVICE_CHECKS))}; "
        f"gone: {sorted(set(EMITTED_DEVICE_CHECKS) - emitted)}"
    )


@pytest.mark.parametrize(("tool", "title"), [
    (tool, title) for tool, titles in EMITTED_DEVICE_CHECKS.items() for title in titles
])
def test_device_findings_have_knowledge_base_guidance(tool, title):
    guidance = finding_remediation({"tool": tool, "title": title, "source": "device", "evidence": {}})
    assert guidance and guidance["matched_by"] == "finding_type" and guidance["steps"], (tool, title, guidance)


def _as_persisted(finding: dict) -> dict:
    """What GET /findings/{id} sees: the row's title/tool and the evidence the worker saved."""
    return {
        "title": finding["title"], "tool": finding["tool"], "source": finding.get("source"),
        "evidence": build_evidence_with_triage(finding),
    }


def test_the_header_check_titles_listed_are_the_ones_it_emits():
    findings = device_web._security_header_findings(
        origin="https://device.example.test", response_url="https://device.example.test/",
        status=200, headers={"Content-Type": "text/html", "Set-Cookie": "sid=fixture"}, protected_access=True,
    )
    assert {finding["title"] for finding in findings} == set(EMITTED_DEVICE_CHECKS["device_web_headers"])
    for finding in findings:
        assert finding_remediation(_as_persisted(finding))["matched_by"] == "finding_type", finding["title"]


def test_the_policy_check_titles_are_matched_after_persistence():
    services = [
        {"transport": "tcp", "port": 23, "service_name": "telnet", "state": "open"},
        {"transport": "tcp", "port": 80, "service_name": "http", "state": "open"},
    ]
    rules = [{"action": "deny", "transport": "tcp", "ports": [23], "service": "telnet"}]
    _evaluated, findings = device_posture.evaluate_service_policy(services, rules, policy_name="fixture")
    assert {finding["title"] for finding in findings} == {
        "Deny device service: telnet on 23/tcp", "Review device service: http on 80/tcp",
    }
    for finding in findings:
        assert set(EMITTED_DEVICE_CHECKS["device_policy"]) >= {finding["title"]}
        assert finding_remediation(_as_persisted(finding))["matched_by"] == "finding_type"


def test_per_probe_checks_carry_their_own_guidance_through_persistence():
    findings = [
        device_web._request_finding(
            title="Fixture probe title", severity="medium", description="d",
            recommendation="Require authentication for the fixture operation.",
            url="http://device.example.test/api/x", collection_id="c", request_id="r", evidence={},
        ),
        *device_web._dir_discovery_findings(
            origin="http://device.example.test",
            discovery={"discovered": [{"path": "/admin", "status": 200}], "wordlist": "fixture"},
        ),
        device_application._application_finding(
            title="Fixture application probe", severity="medium", description="d",
            remediation="Disable the fixture action.", observation={"origin": "http://device.example.test", "path": "/x"},
            cwe="CWE-306",
        ),
        device_control_plane._control_plane_finding(
            title="Fixture control-plane probe", severity="medium", description="d",
            remediation="Disable the fixture control service.", observation={"origin": "http://device.example.test", "path": "/x"},
            cwe=None,
        ),
    ]
    assert {finding["tool"] for finding in findings} == PRODUCER_GUIDED
    for finding in findings:
        guidance = finding_remediation(_as_persisted(finding))
        expected = finding.get("remediation") or finding.get("recommendation")
        assert guidance and guidance["matched_by"] == "producer" and guidance["steps"] == [expected], finding["tool"]


def test_template_ids_are_reviewed_ones_from_the_pinned_bundle():
    from scan.work_manifests import CANONICAL_PASSIVE_NUCLEI_TEMPLATES

    reviewed = {row[0] for row in CANONICAL_PASSIVE_NUCLEI_TEMPLATES}
    assert set(remediation_kb_findings.TEMPLATE_REMEDIATION) <= reviewed
