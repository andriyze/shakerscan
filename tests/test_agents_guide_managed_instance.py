"""The agent guide is vendored into the client's agent kit and read by agents on Enterprise.

Hunt report D14: it said connected Enterprise clients use the instance's `/public/check` (an
Enterprise instance does not serve it, and the client does not offer the check there) and told
agents to "Use OpenAPI for bodies", which an Enterprise gateway refuses.
"""

from pathlib import Path
import re

GUIDE = (Path(__file__).resolve().parents[1] / "AGENTS.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def test_the_posture_check_is_not_promised_on_an_enterprise_instance():
    flat = _flat(GUIDE)
    assert "OSS or Enterprise instance's `/public/check`" not in flat
    assert "Enterprise does not serve it, so its clients lack the check" in flat


def test_request_bodies_point_at_contracts_every_instance_serves():
    flat = _flat(GUIDE)
    assert "Use OpenAPI for bodies not shown here" not in flat
    assert "Bodies: `/scan/contracts`, `/hunts/contract`." in flat
    for line in GUIDE.splitlines():
        if "openapi.json" in line:
            assert "Enterprise" in line or "open-source" in line, line
