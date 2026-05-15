from pathlib import Path

import pytest


pytestmark = pytest.mark.playwright


def test_documentation_page_renders_on_desktop_and_mobile(darkstar_server):
    sync_api = pytest.importorskip("playwright.sync_api")
    output_dir = Path("test-results/playwright")
    output_dir.mkdir(parents=True, exist_ok=True)

    with sync_api.sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            desktop = browser.new_page(viewport={"width": 1440, "height": 1200})
            desktop.goto(f"{darkstar_server}/documentation", wait_until="networkidle")
            assert desktop.locator("h1").inner_text() == "Darkstar Documentation"
            assert desktop.locator("#responsible-use").is_visible()
            assert desktop.locator("#tools").is_visible()
            assert desktop.evaluate("getComputedStyle(document.body).backgroundColor") == "rgb(255, 255, 255)"
            desktop.screenshot(path=str(output_dir / "documentation-desktop.png"), full_page=True)

            mobile = browser.new_page(viewport={"width": 390, "height": 1100}, is_mobile=True)
            mobile.goto(f"{darkstar_server}/documentation", wait_until="networkidle")
            assert mobile.locator("h1").is_visible()
            assert mobile.locator(".doc-sidebar").is_visible()
            assert mobile.locator("text=Responsible Use").first.is_visible()
            box = mobile.locator(".hero-section").bounding_box()
            assert box is not None
            assert box["width"] <= 390
            mobile.screenshot(path=str(output_dir / "documentation-mobile.png"), full_page=True)
        finally:
            browser.close()
