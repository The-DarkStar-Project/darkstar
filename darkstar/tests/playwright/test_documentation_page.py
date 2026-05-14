import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

import pytest


pytestmark = pytest.mark.playwright


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_http(url: str, timeout: int = 30) -> None:
    deadline = time.time() + timeout
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            with urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except Exception as exc:
            last_error = exc
            time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {url}: {last_error}")


@pytest.fixture(scope="module")
def darkstar_server():
    if os.environ.get("RUN_PLAYWRIGHT") != "1":
        pytest.skip("Set RUN_PLAYWRIGHT=1 to run browser tests")

    repo_root = Path(__file__).resolve().parents[3]
    port = _free_port()
    env = os.environ.copy()
    env.setdefault("WEB_SESSION_SECRET", "playwright-test-secret")
    env["PYTHONPATH"] = f"{repo_root}:{repo_root / 'darkstar'}:{env.get('PYTHONPATH', '')}"
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "darkstar.webapp:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(repo_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_for_http(f"{base_url}/documentation")
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


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
            assert mobile.locator("text=Verantwoord gebruik").first.is_visible()
            box = mobile.locator(".hero-section").bounding_box()
            assert box is not None
            assert box["width"] <= 390
            mobile.screenshot(path=str(output_dir / "documentation-mobile.png"), full_page=True)
        finally:
            browser.close()
