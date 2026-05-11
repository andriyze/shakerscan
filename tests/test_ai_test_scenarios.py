import importlib.util
import sys
from pathlib import Path


_SCENARIO_MODULE_PATH = Path(__file__).resolve().parents[1] / "api" / "ai_demo_scenarios.py"
_API_PATH = str(_SCENARIO_MODULE_PATH.parent)
if _API_PATH not in sys.path:
    sys.path.append(_API_PATH)
_SCENARIO_SPEC = importlib.util.spec_from_file_location("ai_demo_scenarios", _SCENARIO_MODULE_PATH)
assert _SCENARIO_SPEC and _SCENARIO_SPEC.loader
_SCENARIO_MODULE = importlib.util.module_from_spec(_SCENARIO_SPEC)
_SCENARIO_SPEC.loader.exec_module(_SCENARIO_MODULE)
get_ai_test_scenarios = _SCENARIO_MODULE.get_ai_test_scenarios


def _has_any_key(metadata: dict, keys: list[str]) -> bool:
    for key in keys:
        value = metadata.get(key)
        if value in (None, "", [], {}):
            continue
        return True
    return False


def test_ai_test_scenario_catalog_contains_required_workflows():
    payload = get_ai_test_scenarios()
    scenario_ids = {scenario["id"] for scenario in payload["scenarios"]}

    assert "secure-rag-agent" in scenario_ids
    assert "model-intake-pipeline" in scenario_ids


def test_secure_rag_agent_templates_cover_control_metadata():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "secure-rag-agent")
    controls = scenario["readiness_controls"]

    for template in scenario["target_templates"]:
        metadata = template["metadata_json"]
        applies_to = {"all"}
        if template["target_type"] == "rag":
            applies_to.add("rag")
        if template["target_type"] in {"agent_trace", "mcp_trace"}:
            applies_to.add("agent")

        missing = [
            control["id"]
            for control in controls
            if control.get("applies_to", "all") in applies_to
            and not _has_any_key(metadata, control["keys"])
        ]
        assert missing == []


def test_secure_rag_agent_catalog_uses_engine_control_requirements():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "secure-rag-agent")
    catalog_ids = {control["id"] for control in scenario["readiness_controls"]}
    engine_ids = {control["id"] for control in _SCENARIO_MODULE.AI_CONTROL_REQUIREMENTS}

    assert engine_ids.issubset(catalog_ids)
    assert "threat_model" in catalog_ids
    assert "cloud_security_design" in catalog_ids


def test_secure_rag_agent_contract_lists_canonical_honey_routes():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "secure-rag-agent")
    routes = set(scenario["honey_contract"]["required_routes"])
    template_urls = {template["endpoint_url"] for template in scenario["target_templates"]}

    assert "GET /api/secure-demo/rag-agent/threat-model" in routes
    assert "POST /api/secure-demo/rag-agent/query" in routes
    assert "GET /api/secure-demo/rag-agent/runs/{run_id}" in routes
    assert "GET /api/secure-demo/governance/mapping" in routes
    assert "GET /api/ai-gate/scenarios" in routes
    assert "POST /api/v1/rag/answer" in routes
    assert "POST /api/v1/agent/trace" in routes
    assert "POST /api/v1/mcp/trace" in routes
    assert "https://honey.shakerscan.com/api/secure-demo/rag-agent/query" in template_urls


def test_model_intake_presets_are_honey_absolute_urls():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "model-intake-pipeline")

    assert scenario["request_presets"]
    for preset in scenario["request_presets"]:
        assert preset["artifact_url"].startswith("https://honey.shakerscan.com/")
        assert preset["metadata_url"].startswith("https://honey.shakerscan.com/")
        assert "expected_findings" in preset


def test_model_intake_contract_lists_lifecycle_routes():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "model-intake-pipeline")
    routes = set(scenario["honey_contract"]["required_routes"])

    assert "GET /api/model-intake/scenarios" in routes
    assert "GET /model-intake/" in routes
    assert "GET /model-intake/artifacts/{scenario}/{filename}" in routes
    assert "GET /model-intake/manifests/{filename}" in routes
    assert "GET /model-intake/signatures/{filename}" in routes
    assert "GET /model-intake/cards/{filename}" in routes
    assert "POST /api/model-intake/submit" in routes
    assert "GET /api/model-intake/{intake_id}" in routes
    assert "POST /api/model-intake/{intake_id}/scan" in routes
    assert "POST /api/model-intake/{intake_id}/approve" in routes
    assert "POST /api/model-intake/{intake_id}/deploy" in routes
