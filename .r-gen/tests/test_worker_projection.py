from api.runtime.worker_projection import (
    runtime_destination_records,
    subprocess_parser_error_reason,
    truthy_module_output,
)


def test_runtime_destination_projection_preserves_scope_evidence():
    records = runtime_destination_records(
        {
            "runtime_destinations": [{
                "label": "baseline",
                "url": "https://app.example.test/",
                "final_url": "https://app.example.test/login",
                "redirect_chain": ["https://app.example.test/login"],
                "resolved_ips": ["203.0.113.10"],
            }],
        },
        {"run_kind": "web_dast"},
    )
    assert records == [{
        "label": "baseline",
        "url": "https://app.example.test/",
        "final_url": "https://app.example.test/login",
        "source": "canonical_action_observation",
        "redirect_urls": ["https://app.example.test/login"],
        "resolved_ips": ["203.0.113.10"],
    }]


def test_non_dast_destination_projection_stays_product_scoped():
    assert runtime_destination_records(
        {"ai_gate": {"runtime_destinations": [{
            "url": "https://ai.example.test/chat", "remote_ip": "203.0.113.20",
        }]}},
        {"run_kind": "ai_api"},
    )[0]["label"] == "ai_gate"


def test_projection_helpers_keep_parser_truth_conservative():
    assert truthy_module_output({"scan_completed": False}) is True
    assert subprocess_parser_error_reason("nuclei", {
        "status": "failed", "stderr_preview": "failed to parse json output",
    }) == "failed to parse json"
    assert subprocess_parser_error_reason("nuclei", {
        "status": "timeout", "stderr_preview": "failed to parse json output",
    }) is None
