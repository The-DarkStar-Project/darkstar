# Security Testing and Sec/DevOps Pipeline

This page describes how Darkstar makes security testing part of the development
and release pipeline. The goal is for security testing to happen not only
manually, but also as a fixed control with reproducible evidence.

## Pipeline Objectives

- Security checks run automatically per pull request or release.
- Results are stored as pipeline artifacts.
- Releases are blocked for unaccepted critical findings.
- High findings have a ticket, owner and target date.
- Secrets are stored in CI/CD secret storage, not in repository files.
- DAST and aggressive scans run only against approved test or staging
  environments.

## Recommended Controls

| Phase | Control | Examples |
| --- | --- | --- |
| Code | Unit tests, linting, SAST, secrets scanning | `pytest`, Semgrep, Gitleaks or TruffleHog |
| Dependencies | Package vulnerability scanning | OSV Scanner, Grype, Trivy |
| Build | Container and base image scanning | Trivy, Grype |
| Config | IaC and Compose/Kubernetes checks | Checkov, Trivy config |
| Staging | DAST baseline | OWASP ZAP baseline, Nuclei, Nikto, Wapiti |
| Darkstar | Centralized scan and reporting | Darkstar API, CSV/XLSX/HTML exports |

## Minimum Local Test Set

Use at least the following locally:

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m pytest -m "not playwright"
python3 - <<'PY'
from pathlib import Path
for root in (Path("darkstar"), Path("openvas_api")):
    for path in root.rglob("*.py"):
        if "__pycache__" not in path.parts:
            compile(path.read_text(), str(path), "exec")
PY
```

For browser checks of the documentation and responsive layout:

```bash
python3 -m playwright install chromium
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright
```

When the tools are available:

```bash
semgrep scan --config auto
osv-scanner --recursive .
trivy fs .
trivy config .
```

These commands are examples. The final pipeline should match the tooling
available in the runner.

See [Testing](./testing.md) for markers, Playwright screenshots, CI artifacts
and troubleshooting.

## Darkstar In CI/CD

Create an API key in Darkstar with the lowest role the pipeline needs. Store the
key as a CI/CD secret, for example `DARKSTAR_API_KEY`.

Example variables:

```bash
DARKSTAR_URL=https://darkstar.example.org
DARKSTAR_API_KEY=dstar_...
DARKSTAR_TARGET=https://staging.example.org
```

A pipeline can then:

1. deploy to staging
2. start a Darkstar scan against the staging URL
3. wait until the scan is complete
4. export findings
5. block the release if acceptance criteria are exceeded

## Acceptance Criteria

Recommended default:

- New critical findings block the release.
- New high findings block unless a risk acceptance or hotfix ticket exists.
- Medium findings get a ticket and are scheduled.
- Low and info findings are reviewed periodically.
- False positives are recorded with evidence.

## Evidence Artifacts

Store per release:

- test results
- dependency scan results
- container scan results
- DAST output
- Darkstar vulnerability export
- Darkstar attack-surface export when relevant
- link to tickets or risk acceptance

## Secrets and Access Management

- Use only CI/CD secret storage for API keys.
- Do not give pipeline keys platform admin rights.
- Rotate API keys periodically.
- Revoke unused keys immediately.
- Never log secrets to stdout.

## Scope and Safety

DAST, aggressive scans and brute-force options may run only against systems for
which explicit permission and scope have been recorded. For production, the
pipeline should default to passive or limited checks unless there is a separate
change window and approval.

## Periodic Controls

Daily:

- review failed scans
- review critical/high deltas

Weekly:

- sample pipeline artifacts
- validate scan scope and staging URLs

Monthly:

- rotate or reconfirm API keys
- check MFA/SSO enforcement
- clean up scanner nodes and endpoint agents
