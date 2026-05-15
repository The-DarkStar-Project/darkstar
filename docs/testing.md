# Darkstar Testing

This page describes how to run the Darkstar test suite locally and in CI/CD.
The test setup is intended for fast feedback during development and for
repeatable evidence in the Sec/DevOps pipeline.

## Test Layers

| Layer | Purpose | Command |
| --- | --- | --- |
| Unit tests | Pure functions, scanner parsers, scan payload validation, endpoint matching and worker command building | `python -m pytest -m "not smoke and not playwright"` |
| Smoke tests | Fast web app checks for documentation, static assets, OpenAPI, auth boundaries and API contracts for scans, ASM, schedules and notifications | `python -m pytest -m smoke` |
| Playwright tests | Browser checks for documentation and normal application flows with mocked APIs | `RUN_PLAYWRIGHT=1 python -m pytest -m playwright` |
| CI tests | Unit, smoke and Playwright in GitHub Actions | `.github/workflows/tests.yml` |

## Install Dependencies

Use the dev requirements for local test environments:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

For Playwright, Chromium must be installed once:

```bash
python3 -m playwright install chromium
```

On a Linux runner that lacks system libraries:

```bash
python3 -m playwright install --with-deps chromium
```

## Run Unit Tests

All non-browser tests:

```bash
python3 -m pytest -m "not playwright"
```

Only fast unit/contract tests without smoke:

```bash
python3 -m pytest -m "not smoke and not playwright"
```

With coverage:

```bash
python3 -m pytest -m "not playwright" --cov=darkstar --cov-report=term-missing
```

## Run Smoke Tests

Smoke tests use FastAPI `TestClient` and do not start real scanner tools. They
verify that important web app routes still render, enforce access correctly and
use the right contracts with backend helpers.

```bash
python3 -m pytest -m smoke
```

The smoke tests check, among other things:

- `/documentation`
- `/static/css/documentation.css`
- sponsor/logo assets
- `/api/me` without login
- protection for a secured API route
- presence of relevant OpenAPI routes
- vulnerability filtering, detail view and grouping
- attack-surface and BBot subdomain target endpoints
- scan queueing to scanner workers without starting scanner binaries
- schedule create/update/delete/run contracts
- notification settings and test notification route

## Run Playwright Tests

Playwright tests start a temporary Uvicorn server on a free local port and open
the application with Chromium. They run only when `RUN_PLAYWRIGHT=1` is set, so
regular unit runs do not need to start a browser.

The application flows mock API responses in the browser. This lets the test view
vulnerabilities, select targets, submit scan payloads and save notification
settings without scanning real targets or starting external scanner tools.

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright
```

The browser tests create screenshots as artifacts:

```text
test-results/playwright/documentation-desktop.png
test-results/playwright/documentation-mobile.png
test-results/playwright/dashboard-workflow.png
test-results/playwright/attack-surface-workflow.png
test-results/playwright/settings-notifications-workflow.png
```

Use these screenshots for visual regressions or when investigating layout
problems in the documentation.

## Run Everything

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest
```

For CI-like output:

```bash
mkdir -p test-results
python3 -m pytest -m "not playwright" --junitxml=test-results/pytest-unit-smoke.xml
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright --junitxml=test-results/pytest-playwright.xml
```

## GitHub Actions

The workflow `.github/workflows/tests.yml` runs on pushes to `main` and on pull
requests.

Jobs:

- `unit-smoke`: installs `requirements-dev.txt` and runs all tests except
  Playwright.
- `playwright`: installs Chromium with Playwright and runs the browser tests.

Artifacts:

- `pytest-unit-smoke`: JUnit XML from unit and smoke tests.
- `playwright-results`: JUnit XML plus desktop/mobile screenshots.

## Test Rules For New Features

- Pure parsing, normalization and validation get unit tests.
- New API routes get at least a contract test or smoke test.
- New scan flows get tests for command building and output parsing, not only a
  happy path.
- New frontend/documentation pages get a Playwright test when layout,
  navigation or responsive behavior matters.
- Playwright may test scan actions by mocking and asserting API payloads, but it
  must not start long-running or real scanner runs.
- Tests must not scan real targets and must not require secrets.
- Network-dependent services such as OSV, MSRC, OpenVAS, ZAP and scanner
  binaries are mocked in unit tests.

## Troubleshooting

If `pytest_mock`, `fastapi` or `playwright` is missing, install again:

```bash
python3 -m pip install -r requirements-dev.txt
```

If Chromium is missing for Playwright:

```bash
python3 -m playwright install chromium
```

If a Playwright test fails locally, open the screenshots in
`test-results/playwright/` and run the same test again with:

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright -vv
```
