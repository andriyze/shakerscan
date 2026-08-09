from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_main_ruleset_requires_pr_and_current_checks_without_reviews():
    text = (ROOT / ".github" / "rulesets" / "main.json").read_text(encoding="utf-8")
    assert '"type": "pull_request"' in text
    assert '"required_approving_review_count": 0' in text
    assert '"require_code_owner_review": false' in text
    assert '"require_last_push_approval": false' in text
    assert '"strict_required_status_checks_policy": true' in text
    assert '"bypass_actors": []' in text


def test_worker_only_status_does_not_report_missing_local_api_as_failure():
    script = (ROOT / "scanner.sh").read_text(encoding="utf-8")
    body = script.split("show_status() {", 1)[1].split("\n}", 1)[0]
    assert "Fleet broker worker node" in body
    assert "Local API/UI: not installed" in body
    assert body.index("Fleet broker worker node") < body.index("api_probe_url")


def test_release_process_documents_build_promote_stable_order():
    text = (ROOT / "docs" / "release-process.md").read_text(encoding="utf-8")
    assert text.index("## 1. Freeze and build") < text.index("## 2. Physical acceptance")
    assert text.index("## 2. Physical acceptance") < text.index("## 3. Publish")
    assert text.index("## 3. Publish") < text.index("## 4. Public smoke")
