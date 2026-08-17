from scanner.scanner_tools import device_advisories


def test_cpe_version_range_match_is_promotable_advisory_evidence():
    matches = device_advisories.match_advisories([
        {
            "cve": "CVE-2026-0001",
            "cpe": "cpe:2.3:o:acme:tv_firmware:*:*:*:*:*:*:*:*",
            "version_start_including": "1.0.0",
            "version_end_excluding": "2.4.0",
            "severity": "high",
        }
    ], cpe="cpe:2.3:o:acme:tv_firmware:2.3.1:*:*:*:*:*:*:*", product=None, version="2.3.1")

    assert len(matches) == 1
    assert matches[0]["promotable"] is True
    assert matches[0]["proof_basis"] == "advisory_matched"
    assert matches[0]["match_type"] == "exact_cpe_version_range"


def test_out_of_range_or_heuristic_product_match_cannot_promote():
    records = [{
        "cve": "CVE-2026-0002",
        "cpe": "cpe:2.3:o:acme:camera:*:*:*:*:*:*:*:*",
        "product": "Acme Camera",
        "version_end_including": "3.0.0",
    }]

    assert device_advisories.match_advisories(
        records,
        cpe="cpe:2.3:o:acme:camera:4.0.0:*:*:*:*:*:*:*",
        product="Acme Camera",
        version="4.0.0",
    ) == []
    heuristic = device_advisories.match_advisories(
        records, cpe=None, product="Acme Camera", version="2.0.0",
    )[0]
    assert heuristic["promotable"] is False
    assert heuristic["proof_basis"] == "signal_only"


def test_embedded_version_comparison_handles_numeric_segments():
    assert device_advisories.compare_versions("2.10.0", "2.9.9") > 0
    assert device_advisories.compare_versions("1.0", "1.0.0") == 0
