# Darkstar testing

Deze pagina beschrijft hoe je de Darkstar testset lokaal en in CI/CD draait.
De testopzet is bedoeld voor snelle feedback tijdens ontwikkeling en voor
herhaalbare evidence in de Sec/DevOps pipeline.

## Testlagen

| Laag | Doel | Command |
| --- | --- | --- |
| Unit tests | Pure functies, scanner parsers, scanpayload-validatie, endpoint matching en worker command building | `python -m pytest -m "not smoke and not playwright"` |
| Smoke tests | Snelle webapp-controle van documentatie, static assets, OpenAPI, auth boundaries en API-contracten voor scans, ASM, schedules en notificaties | `python -m pytest -m smoke` |
| Playwright tests | Browsercontrole van documentatie en normale applicatieflows met gemockte API's | `RUN_PLAYWRIGHT=1 python -m pytest -m playwright` |
| CI tests | Unit, smoke en Playwright in GitHub Actions | `.github/workflows/tests.yml` |

## Dependencies installeren

Gebruik de dev requirements voor lokale testomgevingen:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements-dev.txt
```

Voor Playwright moet Chromium eenmalig worden geinstalleerd:

```bash
python3 -m playwright install chromium
```

Op een Linux runner waar systeemlibraries ontbreken:

```bash
python3 -m playwright install --with-deps chromium
```

## Unit tests draaien

Alle niet-browser tests:

```bash
python3 -m pytest -m "not playwright"
```

Alleen snelle unit/contract tests zonder smoke:

```bash
python3 -m pytest -m "not smoke and not playwright"
```

Met coverage:

```bash
python3 -m pytest -m "not playwright" --cov=darkstar --cov-report=term-missing
```

## Smoke tests draaien

Smoke tests gebruiken FastAPI `TestClient` en starten geen echte scanner tools.
Ze controleren dat belangrijke webapp-routes nog renderen, correct afschermen en
de juiste contracten met de backend helpers gebruiken.

```bash
python3 -m pytest -m smoke
```

De smoke tests controleren onder andere:

- `/documentation`
- `/static/css/documentation.css`
- sponsor/logo assets
- `/api/me` zonder login
- afscherming van een beschermde API route
- aanwezigheid van relevante OpenAPI routes
- vulnerability filtering, detailweergave en groepering
- attack-surface en BBot-subdomain target endpoints
- scan queueing naar scanner workers, zonder scanner binaries te starten
- schedule create/update/delete/run-contracten
- notificatie-instellingen en testnotificatie-route

## Playwright tests draaien

Playwright tests starten een tijdelijke Uvicorn server op een vrije lokale poort
en openen de applicatie met Chromium. Ze draaien alleen wanneer
`RUN_PLAYWRIGHT=1` is gezet, zodat reguliere unit runs geen browser hoeven te
starten.

De applicatieflows mocken de API-responses in de browser. Daardoor kan de test
vulnerabilities bekijken, targets selecteren, scanpayloads submitten en
notificatie-instellingen opslaan zonder echte targets te scannen of externe
scanner tools te starten.

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright
```

De browsertests maken screenshots als artifact:

```text
test-results/playwright/documentation-desktop.png
test-results/playwright/documentation-mobile.png
test-results/playwright/dashboard-workflow.png
test-results/playwright/attack-surface-workflow.png
test-results/playwright/settings-notifications-workflow.png
```

Gebruik deze screenshots bij visuele regressies of wanneer layoutproblemen in
de documentatie worden onderzocht.

## Alles draaien

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest
```

Voor CI-achtige output:

```bash
mkdir -p test-results
python3 -m pytest -m "not playwright" --junitxml=test-results/pytest-unit-smoke.xml
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright --junitxml=test-results/pytest-playwright.xml
```

## GitHub Actions

De workflow `.github/workflows/tests.yml` draait op push naar `main` en op pull
requests.

Jobs:

- `unit-smoke`: installeert `requirements-dev.txt` en draait alle tests behalve
  Playwright.
- `playwright`: installeert Chromium met Playwright en draait de browsertests.

Artifacts:

- `pytest-unit-smoke`: JUnit XML van unit en smoke tests.
- `playwright-results`: JUnit XML plus desktop/mobile screenshots.

## Testregels voor nieuwe features

- Pure parsing, normalisatie en validatie krijgen unit tests.
- Nieuwe API routes krijgen minimaal een contracttest of smoke test.
- Nieuwe scanflows krijgen tests voor command building en output parsing, niet
  alleen een happy path.
- Nieuwe frontend/documentatiepagina's krijgen een Playwright test wanneer
  layout, navigatie of responsive gedrag belangrijk is.
- Playwright mag scanacties testen door API-payloads te mocken en te asserten,
  maar mag geen langdurige of echte scanner-run starten.
- Tests mogen geen echte targets scannen en geen secrets vereisen.
- Netwerkafhankelijke services zoals OSV, MSRC, OpenVAS, ZAP en scanner binaries
  worden in unit tests gemockt.

## Troubleshooting

Ontbreekt `pytest_mock`, `fastapi` of `playwright`, installeer dan opnieuw:

```bash
python3 -m pip install -r requirements-dev.txt
```

Ontbreekt Chromium voor Playwright:

```bash
python3 -m playwright install chromium
```

Als een Playwright test lokaal faalt, open dan de screenshots in
`test-results/playwright/` en draai dezelfde test opnieuw met:

```bash
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright -vv
```
