from api.ai_demo_scenarios import get_ai_test_scenarios


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


def test_model_intake_presets_are_honey_absolute_urls():
    payload = get_ai_test_scenarios()
    scenario = next(item for item in payload["scenarios"] if item["id"] == "model-intake-pipeline")

    assert scenario["request_presets"]
    for preset in scenario["request_presets"]:
        assert preset["artifact_url"].startswith("https://honey.shakerscan.com/")
        assert preset["metadata_url"].startswith("https://honey.shakerscan.com/")
        assert "expected_findings" in preset

