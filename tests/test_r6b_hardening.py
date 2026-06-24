"""R6b hardening: SPDX license normalization, per-profile response caps, MCP resources/list."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

from scanner.scanner_tools.model_intake import _license_policy  # noqa: E402
from ai_gate.targets.rest_json import RestJsonConversationTarget, profile_response_byte_cap  # noqa: E402
from ai_assurance import _extract_mcp_resources  # noqa: E402


# --- §3.15 SPDX license normalization + expression parsing ---

def test_spdx_expression_classification():
    assert _license_policy("MIT OR Apache-2.0")["status"] == "permissive"
    assert _license_policy("(MIT AND BSD-3-Clause)")["status"] == "permissive"
    assert _license_policy("MIT AND GPL-3.0-only")["status"] == "restricted"  # any restricted -> restricted
    assert _license_policy("AGPL-3.0-or-later")["status"] == "restricted"
    assert _license_policy("research only")["status"] == "restricted"
    assert _license_policy("apache 2.0")["status"] == "permissive"          # alias normalized
    assert _license_policy("")["status"] == "missing"
    assert _license_policy("some-weird-license")["status"] == "review_required"


def test_spdx_normalized_tokens_exposed():
    pol = _license_policy("MIT OR Apache-2.0")
    assert "mit" in pol["normalized"] and "apache-2.0" in pol["normalized"]


# --- §3.8 per-profile response caps ---

def test_profile_response_byte_caps():
    assert profile_response_byte_cap("smoke") == 65_536
    assert profile_response_byte_cap("standard") == 262_144
    assert profile_response_byte_cap("deep") == 1_000_000
    assert profile_response_byte_cap("unknown") == 262_144


def test_target_uses_profile_default_unless_overridden():
    base = {"endpoint_url": "https://x/api", "request_template": {"q": "{{prompt}}"}}
    t = RestJsonConversationTarget("https://x/api", base, default_max_response_bytes=65_536)
    assert t.max_response_bytes == 65_536
    # explicit metadata override still wins over the profile default
    override = {**base, "metadata_json": {"max_response_bytes": 300_000}}
    t2 = RestJsonConversationTarget("https://x/api", override, default_max_response_bytes=65_536)
    assert t2.max_response_bytes == 300_000


# --- §3.13 MCP resources/list ---

def test_extract_mcp_resources():
    assert _extract_mcp_resources({"result": {"resources": [{"uri": "a"}]}}) == [{"uri": "a"}]
    assert _extract_mcp_resources({"resources": [{"uri": "b"}]}) == [{"uri": "b"}]
    assert _extract_mcp_resources({"result": {}}) == []
    assert _extract_mcp_resources(None) == []
