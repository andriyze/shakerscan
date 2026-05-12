import os
import sys


API_PATH = os.path.join(os.path.dirname(__file__), "..", "api")
if API_PATH not in sys.path:
    sys.path.append(API_PATH)

from ai_redteam_artifacts import (  # noqa: E402
    build_ai_learning_guide,
    build_ai_redteam_report,
    build_ai_test_case_catalog,
    build_ai_test_case_export,
    render_ai_redteam_markdown,
)


def test_learning_guide_exposes_course_and_capstone_map():
    guide = build_ai_learning_guide()

    assert guide["schema_version"]
    assert len(guide["modules"]) == 12
    assert any(item["id"] == "manual_validation" for item in guide["capstone_checklist"])


def test_test_case_catalog_and_exports_are_generic():
    catalog = build_ai_test_case_catalog(pack="shaker-rag-lite")

    assert catalog["packs"][0]["id"] == "shaker-rag-lite"
    assert catalog["packs"][0]["probes"]
    serialized = repr(catalog)
    assert "honey.shakerscan.com" not in serialized

    promptfoo, media_type, extension = build_ai_test_case_export("promptfoo", pack="shaker-ai-smoke")
    assert "tests:" in promptfoo
    assert media_type.startswith("text/yaml")
    assert extension == "yaml"

    pyrit, media_type, extension = build_ai_test_case_export("pyrit", pack="shaker-ai-smoke")
    assert pyrit["format"] == "pyrit-seed-json"
    assert pyrit["prompts"]
    assert media_type == "application/json"
    assert extension == "json"

    garak, media_type, extension = build_ai_test_case_export("garak", pack="shaker-ai-smoke")
    assert '"prompt"' in garak
    assert media_type.startswith("application/x-ndjson")
    assert extension == "jsonl"


def test_ai_redteam_report_includes_validation_and_calibration_summary():
    scan = {
        "id": "scan-1",
        "status": "completed",
        "target_url": "http://example.test/api/rag",
        "target_name": "RAG staging",
        "scan_type": "ai_gate",
        "run_kind": "ai_rag",
        "created_at": "2026-05-11T12:00:00Z",
        "completed_at": "2026-05-11T12:01:00Z",
        "options": {"probe_pack": "shaker-rag-lite", "scan_profile": "standard"},
        "result": {
            "ai_gate": {
                "control_evidence": {
                    "schema_version": "test",
                    "target_type": "rag",
                    "probe_pack": "shaker-rag-lite",
                    "scan_profile": "standard",
                    "risk_tier": "high",
                    "summary": {"required": 2, "present": 1, "missing": 1, "evidence_ready": False},
                    "missing_required_controls": [{"id": "retrieval_acl_matrix", "label": "Retrieval ACLs"}],
                }
            },
            "findings": [
                {
                    "id": "rag-cross-tenant:rag_cross_tenant_document_inventory",
                    "title": "RAG cross-tenant document inventory exposed",
                    "severity": "high",
                    "owasp": "LLM02:2025",
                    "evidence": {
                        "probe_id": "rag-cross-tenant",
                        "judge_layer": "structured_oracle",
                        "oracle_expected_finding": "ai_gate:rag_cross_tenant_document_inventory",
                        "response_excerpt": "Returned restricted document IDs.",
                    },
                    "ai_verdict": "true_positive",
                    "ai_confidence": 0.98,
                }
            ],
        },
        "findings": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "fingerprint": "rag-cross-tenant:rag_cross_tenant_document_inventory",
                "title": "RAG cross-tenant document inventory exposed",
                "severity": "high",
                "status": "active",
                "notes": "Manually reproduced with tenant B token.",
                "last_verification_verdict": "exploited",
            }
        ],
    }
    metadata = {
        "risk_tier": "high",
        "expected_shakerscan_findings": ["ai_gate:rag_cross_tenant_document_inventory"],
    }

    report = build_ai_redteam_report(scan, target_metadata=metadata)
    markdown = render_ai_redteam_markdown(report)

    assert report["calibration_summary"]["verdict"] == "pass"
    assert report["control_evidence"]["summary"]["missing"] == 1
    assert report["evidence_items"][0]["validation"]["notes"] == "Manually reproduced with tenant B token."
    assert "ShakerScan AI Red-Team Report" in markdown
    assert "RAG cross-tenant document inventory exposed" in markdown
