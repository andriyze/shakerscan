#!/usr/bin/env python3
"""Exposure-page E2E smoke suite (non-mutating).

Runs headless Chromium via Playwright INSIDE the worker container, where the
compose network exposes the UI as http://ui:3000 and the API as
http://api:8080. The UI derives its API URL from the page hostname, so a
request-rewrite routes ui:8080 -> api:8080.

Run from the repo root with:  ui/e2e/run.sh

Covers: deep-link interactivity (the App Router shallow-routing regression),
triage filters/presets/search, change strip, drawer modality, bulk selection
(dialog cancelled, nothing queued), map highlight/focus URL state, attack
paths, and the 390px mobile layout. No scans are queued and nothing is saved.
"""

import json
import sys

from playwright.sync_api import sync_playwright

UI = "http://ui:3000"
results: list[str] = []
console_errors: list[str] = []


def check(name: str, ok: bool, note: str = "") -> None:
    results.append(f"{'PASS' if ok else 'FAIL'} | {name}" + (f" | {note}" if note else ""))


def reroute(route, request):
    if "//ui:8080" in request.url:
        route.continue_(url=request.url.replace("//ui:8080", "//api:8080"))
    else:
        route.continue_()


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        page.route("**/*", reroute)
        page.on("console", lambda m: console_errors.append(m.text[:200]) if m.type == "error" else None)

        # --- Deep-link interactivity (regression guard for shallow routing) ---
        page.goto(f"{UI}/exposure?posture=p1", wait_until="networkidle")
        page.wait_for_timeout(3500)
        page.get_by_role("button", name="P2", exact=False).first.click()
        page.wait_for_timeout(1200)
        check("deep-link page stays interactive", "posture=p2" in page.url, page.url)

        # --- Triage basics ---
        page.goto(f"{UI}/exposure", wait_until="networkidle")
        page.wait_for_timeout(4000)
        check("changes strip", page.get_by_text("What changed").is_visible())
        check("action queue", page.get_by_text("Action queue").is_visible())
        showing = page.get_by_text("Showing ").first.inner_text()
        check("table count line", "of" in showing, showing)

        # Search: Enter commits inventory filter
        sb = page.get_by_label("Search exposure nodes")
        sb.fill("a")
        page.wait_for_timeout(400)
        sb.press("Enter")
        page.wait_for_timeout(900)
        check("search enter commits q", "q=a" in page.url)
        page.get_by_role("button", name='Remove Search: "a" filter').click()
        page.wait_for_timeout(600)
        check("search chip clears", "q=" not in page.url)

        # --- Drawer modality ---
        page.locator("button[aria-label^='Open details for']").first.click()
        page.wait_for_timeout(1500)
        dlg = page.locator("[role=dialog][aria-modal=true]").first
        check("drawer opens aria-modal", dlg.is_visible())
        inside = True
        for _ in range(25):
            page.keyboard.press("Tab")
            if not page.evaluate("() => document.querySelector('[role=dialog]')?.contains(document.activeElement)"):
                inside = False
                break
        check("drawer focus trap", inside)
        page.keyboard.press("Escape")
        page.wait_for_timeout(600)
        check("drawer escape close", page.locator("[role=dialog][aria-modal=true]").count() == 0)

        # --- Bulk selection (cancelled, nothing queued) ---
        rowbox = page.locator("input[aria-label^='Select ']:not([aria-label='Select all visible assets'])")
        rowbox.nth(0).check()
        rowbox.nth(1).check()
        page.wait_for_timeout(500)
        check("bulk bar", page.get_by_text("2 selected").is_visible())
        page.get_by_role("button", name="Scan selected (2)").click()
        page.wait_for_timeout(600)
        check("bulk confirm dialog", page.get_by_text("Queue 2 scans?").is_visible())
        page.get_by_role("button", name="Cancel").last.click()
        page.wait_for_timeout(400)
        check("bulk cancel keeps selection", page.get_by_text("2 selected").is_visible())
        page.get_by_role("button", name="Clear selection").click()
        page.wait_for_timeout(300)

        # --- Map lens: URL-encoded investigation state ---
        page.goto(f"{UI}/exposure?lens=map", wait_until="networkidle")
        page.wait_for_timeout(7000)
        tile = page.locator("button[aria-pressed]").filter(has_text="Endpoints").first
        tile.click()
        page.wait_for_timeout(1200)
        check("map highlight in url", "highlight=endpoint" in page.url, page.url)
        page.get_by_text("Highlighting").click()
        page.wait_for_timeout(800)
        check("map highlight clears", "highlight=" not in page.url)
        # rank "02" only appears as a priority-row rank
        page.get_by_text("02", exact=True).locator("xpath=ancestor::button[1]").click()
        page.wait_for_timeout(4000)
        check("priority target focuses", "focus=" in page.url)
        check("selected node panel", page.get_by_text("Selected node").is_visible())
        focus_url = page.url
        page.goto(focus_url, wait_until="networkidle")
        page.wait_for_timeout(8000)
        check("focus deep link restores", page.get_by_text("Selected node").is_visible())

        # --- Attack paths ---
        page.goto(f"{UI}/exposure?lens=paths", wait_until="networkidle")
        page.wait_for_timeout(4000)
        panel = page.locator("#lens-panel-paths")
        check("paths summary", panel.get_by_text("exploit paths").first.is_visible())
        card = panel.locator("button[aria-expanded='false']").first
        name = card.get_attribute("aria-label") or ""
        check("path card scoped aria-label", 0 < len(name) < 140 and "chain" in name, name[:80])
        card.click()
        page.wait_for_timeout(800)
        check("path card expands", panel.locator("button[aria-expanded='true']").count() > 0)
        check("view scan link", panel.get_by_role("link", name="View scan").first.is_visible())

        # --- Mobile 390px ---
        mob = browser.new_page(viewport={"width": 390, "height": 844})
        mob.route("**/*", reroute)
        mob.goto(f"{UI}/exposure", wait_until="networkidle")
        mob.wait_for_timeout(4000)
        check("mobile top bar", mob.get_by_label("Open navigation").is_visible())
        main_w = mob.evaluate("() => document.querySelector('main').clientWidth")
        check("mobile main full width", main_w > 350, f"{main_w}px")
        mob.get_by_label("Open navigation").click()
        mob.wait_for_timeout(500)
        check("mobile nav drawer", mob.get_by_role("dialog", name="Navigation").is_visible())

        browser.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - report, don't lose prior results
        results.append(f"CRASH | {type(exc).__name__}: {str(exc)[:200]}")
    finally:
        print("\n".join(results))
        print("CONSOLE_ERRORS:", json.dumps(console_errors[:8]))
        failed = sum(1 for r in results if not r.startswith("PASS"))
        print(f"SUMMARY: {len(results) - failed}/{len(results)} passed")
        sys.exit(1 if failed else 0)
