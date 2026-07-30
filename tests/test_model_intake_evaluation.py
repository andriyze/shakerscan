from scanner.scanner_tools.model_intake_evaluation import evaluate, verify_report


def _spec():
    return {
        "suite_id": "corp-embedding-security",
        "suite_version": "1",
        "suite_scope": ["security", "quality"],
        "thresholds": {
            "expected_dimension": 2,
            "min_recall_at_k": 1.0,
            "max_acl_leaks": 0,
            "max_poisoned_top_k_rate": 0,
            "min_stability_cosine": 0.999,
            "max_p95_latency_ms": 20,
            "max_peak_rss_mb": 512,
        },
        "documents": [
            {"id": "a", "vector": [1, 0], "tenant": "t1", "classification": "internal", "allowed_principals": ["alice"]},
            {"id": "b", "vector": [0, 1], "tenant": "t2", "classification": "secret", "allowed_principals": ["bob"], "sensitive": True},
        ],
        "queries": [{
            "id": "q",
            "vector": [1, 0],
            "tenant": "t1",
            "principal": "alice",
            "top_k": 1,
            "relevant_ids": ["a"],
            "returned_ids": ["a"],
            "returned_scores": [0.99],
            "retrieval_run_id": "run-1",
            "connector_id": "pgvector",
            "connector_version": "1",
            "index_id": "index-1",
            "index_version": "1",
            "principal_id_hash": "principal-hash",
            "tenant_id_hash": "tenant-hash",
            "query_timestamp": "2026-07-29T00:00:00Z",
        }],
        "runtime_runs": [
            {"case_id": "q", "runtime": "cpu", "vector": [1, 0], "latency_ms": 10, "peak_rss_mb": 100},
            {"case_id": "q", "runtime": "gpu", "vector": [1, 0], "latency_ms": 5, "peak_rss_mb": 200},
        ],
        "data_plane_controls": {
            "index_model_sha256": "a" * 64,
            "authorization_before_search": True,
            "cache_key_includes_auth_context": True,
            "retrieved_content_is_untrusted": True,
            "graph_boundary_tests": [{"id": "g", "returned_node_ids": ["n1"], "allowed_node_ids": ["n1"]}],
            "deletion_receipts": [{"source_id": "s", "layers": {key: True for key in ("source", "chunks", "vectors", "graph_edges", "cache", "replicas")}}],
        },
    }


def test_provider_neutral_evaluation_passes_and_is_content_free():
    report = evaluate(_spec(), artifact_sha256="a" * 64, observations_trusted=True)

    assert report["status"] == "PASS"
    assert report["metrics"]["mean_recall_at_k"] == 1.0
    assert report["metrics"]["acl_leaks"] == 0
    assert "vector" not in report
    assert len(report["evidence_sha256"]) == 64


def test_evaluation_fails_acl_poisoning_graph_deletion_and_digest_drift():
    spec = _spec()
    spec["documents"][1]["poisoned"] = True
    spec["queries"][0]["returned_ids"] = ["b"]
    spec["queries"][0]["returned_scores"] = [0.99]
    spec["data_plane_controls"]["index_model_sha256"] = "b" * 64
    spec["data_plane_controls"]["graph_boundary_tests"][0]["returned_node_ids"] = ["n2"]
    spec["data_plane_controls"]["deletion_receipts"][0]["layers"]["vectors"] = False

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)
    codes = {item["code"] for item in report["blockers"]}

    assert report["status"] == "FAIL"
    assert {"acl_retrieval_leak", "sensitive_retrieval_leak", "poisoning_threshold_exceeded", "index_model_digest_mismatch", "graph_authorization_boundary_crossed", "deletion_incomplete"} <= codes


def test_evaluation_requires_predeclared_thresholds_and_stability():
    report = evaluate({"documents": [], "queries": []}, artifact_sha256=None, observations_trusted=True)
    codes = {item["code"] for item in report["blockers"]}

    assert report["status"] == "FAIL"
    assert "thresholds_missing" in codes
    assert "retrieval_quality_not_measured" not in codes
    assert "retrieval_quality_not_measured" in {item["code"] for item in report["warnings"]}
    assert "stability_not_measured" in codes


def test_missing_evaluation_is_digest_bound_without_false_tamper_blocker():
    report = evaluate(None, artifact_sha256="a" * 64)
    verified = verify_report(report, artifact_sha256="a" * 64)

    assert verified["status"] == "FAIL"
    assert verified["worker_verified"] is True
    assert verified["verification_blockers"] == []
    assert {item["code"] for item in verified["blockers"]} == {"evaluation_spec_missing"}


def test_quality_is_separate_unless_suite_explicitly_requires_it():
    spec = _spec()
    spec["suite_scope"] = ["security"]
    spec["queries"][0]["relevant_ids"] = []

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)

    assert report["security_status"] == "PASS"
    assert report["quality_status"] == "WARNING"
    assert report["status"] == "PASS"
    assert not [item for item in report["blockers"] if item["domain"] == "quality"]


def test_evaluation_rejects_malformed_thresholds_without_crashing():
    spec = _spec()
    spec["thresholds"]["min_recall_at_k"] = "not-a-number"

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)

    assert report["status"] == "FAIL"
    assert "threshold_invalid" in {item["code"] for item in report["blockers"]}


def test_worker_verifies_evaluation_integrity_and_exact_artifact_binding():
    report = evaluate(_spec(), artifact_sha256="a" * 64, observations_trusted=True)
    assert verify_report(report, artifact_sha256="a" * 64)["worker_verified"] is True

    report["metrics"]["acl_leaks"] = 9
    rejected = verify_report(report, artifact_sha256="b" * 64)

    assert rejected["status"] == "FAIL"
    assert {item["code"] for item in rejected["blockers"]} >= {
        "evaluation_evidence_digest_mismatch",
        "evaluation_artifact_digest_mismatch",
    }


def test_missing_actual_results_never_fall_back_to_ideal_ranking():
    spec = _spec()
    del spec["queries"][0]["returned_ids"]

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)

    assert report["status"] == "FAIL"
    assert "actual_retrieval_results_missing" in {item["code"] for item in report["blockers"]}
    assert report["metrics"]["queries"] == 0


def test_empty_actual_result_is_evaluated_without_substitution():
    spec = _spec()
    spec["suite_scope"] = ["security"]
    spec["queries"][0]["relevant_ids"] = []
    spec["queries"][0]["returned_ids"] = []
    spec["queries"][0]["returned_scores"] = []

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)

    assert "actual_retrieval_results_missing" not in {item["code"] for item in report["blockers"]}
    assert report["metrics"]["queries"] == 1
    assert report["metrics"]["acl_leaks"] == 0


def test_declared_observations_cannot_satisfy_production_evaluation():
    report = evaluate(_spec(), artifact_sha256="a" * 64)

    assert report["status"] == "FAIL"
    assert report["observation_provenance_class"] == "DECLARED"
    assert "evaluation_observations_untrusted" in {item["code"] for item in report["blockers"]}


def test_retrieval_observation_shape_and_identity_are_fail_closed():
    spec = _spec()
    spec["queries"][0]["returned_ids"] = ["unknown", "unknown"]
    spec["queries"][0]["returned_scores"] = [0.5]

    report = evaluate(spec, artifact_sha256="a" * 64, observations_trusted=True)
    codes = {item["code"] for item in report["blockers"]}

    assert {"duplicate_returned_ids", "returned_score_count_mismatch"} <= codes

    missing_metadata = _spec()
    del missing_metadata["queries"][0]["connector_version"]
    report = evaluate(missing_metadata, artifact_sha256="a" * 64, observations_trusted=True)
    assert "retrieval_observation_metadata_missing" in {item["code"] for item in report["blockers"]}

    unknown_document = _spec()
    unknown_document["queries"][0]["returned_ids"] = ["unknown"]
    report = evaluate(unknown_document, artifact_sha256="a" * 64, observations_trusted=True)
    assert "unknown_returned_document" in {item["code"] for item in report["blockers"]}
