#!/usr/bin/env python3
"""Exercise the installed Model Intake credential flow through the real browser bundle."""

import sys

from playwright.sync_api import expect, sync_playwright


ui_url = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:3000"
protected_responses: list[int] = []

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True)
    page = browser.new_page()

    def record(response):
        if "/model-intake/submissions?limit=50" in response.url:
            protected_responses.append(response.status)

    page.on("response", record)
    page.goto(f"{ui_url}/model-intake", wait_until="domcontentloaded")
    page.get_by_role("button", name="Advanced / manual").click()
    page.get_by_role("button", name="3. Admission").click()
    expect(page.get_by_text("Using this deployment's own operator credential", exact=False)).to_be_visible(
        timeout=30_000
    )
    expect(page.get_by_label("Operator credential")).to_have_count(0)
    page.wait_for_timeout(1_000)
    if 200 not in protected_responses:
        raise SystemExit(f"protected Model Intake browser request did not succeed: {protected_responses}")
    browser.close()

print("Model Intake browser session smoke passed")
