# Darkstar Application Documentation

This documentation describes how to use and administer the Darkstar web
application. The full web version is available at `/documentation` in the
running application.

## Purpose

Darkstar is a multi-tenant vulnerability intelligence platform. The dashboard
combines:

- scans and scan logs
- vulnerability findings
- attack-surface data
- endpoint inventory and endpoint CVE matching
- cloud security score data
- exports for reporting and audit
- tenant security settings such as MFA, SSO, API keys and notifications

Darkstar is supported by [SIDN](https://www.sidnfonds.nl/) and
[NLnet](https://nlnet.nl/). The Darkstar repository itself is licensed under
GNU GPLv3. Upstream tools keep their own licenses.

## Responsible and Authorized Use

Darkstar includes security tooling for ASM, DAST, network vulnerability
scanning and internal scans. Use this tooling only for legitimate security
purposes on systems you own or for which you have explicit prior permission.

This documentation describes the intended use of Darkstar, but it is not legal
advice. Users and organizations remain responsible for complying with laws,
contracts, bug bounty rules, cloud provider terms and customer agreements.

The user is responsible for:

- verifying the allowed scope, targets, scan windows and scan intensity;
- obtaining explicit permission from the owner, client or responsible
  organization;
- testing production environments only when that is part of the agreed test
  scope;
- handling results, exports, screenshots, secrets and personal data securely;
- limiting access to findings and exports to people who need that information;
- stopping further tests when a target turns out to be out of scope.

Darkstar must not be used for activities outside permission or outside the test
scope, including:

- unauthorized scans, exploitation or access to systems;
- credential stuffing, password attacks or use of compromised credentials;
- phishing, social engineering, data theft or collecting personal data without
  a valid basis;
- denial-of-service, disruption, destructive tests or aggressive load without
  approval;
- persistence, lateral movement or attempts to bypass security monitoring.

If a scan touches an out-of-scope vulnerability or system, stop further testing
on that target. Record what was found, do not share sensitive details more
widely than needed, and follow a responsible disclosure or Coordinated
Vulnerability Disclosure process.

## Roles

| Role | Permissions |
| --- | --- |
| `viewer` | View results and reports. |
| `security_analyst` | Start scans and use operational scan workflows. |
| `tenant_admin` | Manage tenant settings, users, API keys, endpoint tokens and scanner nodes. |
| `platform_admin` | Platform-wide tenant overview and administration. |

## Testing and Quality Control

Darkstar has a layered test setup for developers and CI/CD:

- unit tests for validation, parsing, endpoint matching, scanner workers and
  scanner output normalization;
- smoke tests for important web app routes, documentation, static assets,
  OpenAPI, auth boundaries and API contracts for vulnerabilities, ASM, scans,
  schedules and notifications;
- Playwright browser tests for the standalone documentation page and normal
  application flows such as viewing vulnerabilities, selecting targets, creating
  scan payloads and configuring notifications;
- a GitHub Actions workflow for unit/smoke and Playwright checks.

Install local test dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run unit and smoke tests:

```bash
python3 -m pytest -m "not playwright"
```

Run only smoke tests:

```bash
python3 -m pytest -m smoke
```

Run Playwright tests:

```bash
python3 -m playwright install chromium
RUN_PLAYWRIGHT=1 python3 -m pytest -m playwright
```

Playwright mocks scan APIs in the browser. The tests therefore verify the UI
flow and payloads, but they do not start real scanner tools and do not scan
targets. Screenshots are stored in `test-results/playwright/`. The full testing
guide is in [Testing](./testing.md).

## Getting Started

1. Log in with an organization account or via SSO.
2. Select the correct tenant if your account belongs to multiple organizations.
3. Check your role in the upper-right corner of the dashboard.
4. Open `Scan Center`.
5. Enter a target, such as a domain, hostname, IP address or CIDR range.
6. Choose a scan mode or an individual scanner.
7. Start the scan and follow the output in `Debug`.
8. Triage results in `Vulnerabilities`.

## Dashboard

The dashboard shows a short status summary of:

- total number of findings
- severity distribution
- recent scans
- active and scheduled scans

Use this screen for daily status checks.

## Scan Center

Scan Center queues scan jobs centrally. A scan can run locally or through a
distributed scanner appliance.

### Targets

Targets can be entered as:

- `example.com`
- `app.example.com`
- `192.0.2.10`
- `192.0.2.0/24`

Multiple targets can be separated with commas or new lines.

### Scan Mode Or Scanner

Use a scan mode when you want a fixed workflow:

- Passive
- Normal
- Aggressive
- Attack Surface

Use an individual scanner when you intentionally want to run a specific tool,
such as BBot, RustScan, Nuclei, OWASP ZAP, Nikto, Wapiti, OpenVAS or an
Asteroid module.

Do not choose a scan mode and an individual scanner at the same time. The
backend accepts exactly one of them.

### Scanner Appliance

With `Auto`, Darkstar chooses an available scanner. Choose a specific scanner
appliance when the scan must run from a particular network position.

### Scheduled Scans

Recurring scans support:

- an interval in hours, days, weeks, months or years
- an optional start date
- an optional end date
- an optional preferred appliance

Darkstar temporarily skips an identical scheduled scan when the same scanner and
target set are already active.

## Vulnerabilities

The `Vulnerabilities` page shows findings per tenant. Available filters:

- severity
- host
- tool
- grouping

Grouping can be set to raw findings, deduplicated, severity, host, tool, asset
or vulnerability.

### Triage Process

1. Start with critical and high findings.
2. Check host, CVE, exploit status and tool.
3. Open details for evidence and score context.
4. Export the relevant set as a CSV, XLSX or HTML report.
5. Record false positives or accepted risks outside Darkstar in the ticket or
   risk register.

## Attack Surface

Attack Surface combines external asset information from recon scans. Use this
page for:

- asset review
- host and port overview
- subdomain investigation
- follow-up scans on selected subdomains
- exports for scope and exposure reports

Always verify scan scope before using aggressive scans or brute-force options.

## ASM, DAST and Internal Scanning

Darkstar supports three scan perspectives:

- ASM: external attack-surface mapping with BBOT, DNS/OSINT sources and port
  data.
- DAST: dynamic web application checks with Nuclei, OWASP ZAP, Wapiti, Nikto,
  Dalfox, testssl.sh and Asteroid modules.
- Internal networks: scanner-only containers run in an internal network or VPN
  and claim jobs from the central orchestrator.

### Activate An Internal Scanner Container

Create an attach token from the orchestrator:

```bash
docker compose exec darkstar-web python3 -m darkstar.scanner_attach create \
  --name local-scanner \
  --url http://darkstar-web:8080 \
  --network darkstar_vuln_net \
  --max-parallel-jobs 2
```

The CLI writes the scanner token and worker settings to a protected env file
(`0600`) and prints a `docker run --env-file ...` command. Copy values only to
the worker host or to a secret manager; do not paste tokens into logs or
tickets. For a local Compose worker, put the same values in the local `.env`:

```bash
DARKSTAR_ORCHESTRATOR_URL='http://darkstar-web:8080'
DARKSTAR_SCANNER_TOKEN='dscan_...'
DARKSTAR_SCANNER_NAME='local-scanner'
DARKSTAR_WORKER_MAX_PARALLEL='2'
```

Start the worker:

```bash
docker compose --profile scanner up -d darkstar-scanner
```

Then choose the worker that must scan from the internal network in `Scan Center`
under `Scanner appliance`.

## Endpoints

Endpoint agents send software inventory and endpoint context to Darkstar.
Darkstar matches software against known vulnerabilities.

### Enrollment

1. Open `Endpoints`.
2. Create an enrollment token.
3. Run the displayed install command on the endpoint host.
4. Check that the agent comes online.
5. Check software inventory and endpoint vulnerabilities.

### Debian/Linux Agent

For Debian and Ubuntu hosts, Darkstar uses the Python endpoint agent through a
systemd installer:

```bash
curl -fsSLo /tmp/darkstar-endpoint-install.sh \
  https://raw.githubusercontent.com/The-DarkStar-Project/darkstar/main/agents/darkstar-debian-agent/install.sh
sudo bash /tmp/darkstar-endpoint-install.sh \
  --url "https://darkstar.example" \
  --org "org_example" \
  --enrollment-token "<endpoint enrollment token>"
```

The installer creates a `darkstar-endpoint-agent` service, a protected env file
in `/etc/darkstar/endpoint-agent.env` and state in
`/var/lib/darkstar-endpoint/agent.json`. The agent collects Debian packages,
optional osquery data, Python/npm packages, IP/MAC metadata and internal network
observations for the endpoint network map.

Management:

```bash
sudo systemctl status darkstar-endpoint-agent
sudo systemctl restart darkstar-endpoint-agent
sudo journalctl -u darkstar-endpoint-agent -f
sudo darkstar-endpoint-agent --once
sudo darkstar-endpoint-agent --print-inventory
```

Treat `/etc/darkstar/endpoint-agent.env` and
`/var/lib/darkstar-endpoint/agent.json` as secrets.

### Windows Agent

The native Windows agent is in `agents/darkstar-windows-agent/` and is installed
as a Windows Service. Use it for Windows fleets where a single binary is more
convenient than Python.

### Management

Tenant admins can:

- revoke enrollment tokens
- revoke endpoint agents
- delete local endpoint records

Revoke blocks future agent communication. Delete removes the local record and
the linked inventory.

## Security Settings

Security settings are under `Settings`.

### MFA

Users can enable MFA with an authenticator app. Tenant admins can require MFA
for the organization. Platform admins can require MFA platform-wide.

### SSO

SSO uses OIDC. Configure:

- issuer URL
- client ID
- client secret
- optional allowed email domain

Register `/api/auth/sso/callback` as the redirect URI with the identity
provider, or set `SSO_REDIRECT_URI` if the public URL differs.

### API Keys

API keys use:

```http
Authorization: Bearer dstar_...
```

The secret is shown once. Store API keys only in a secret manager or CI/CD
secret storage and rotate them periodically.

## MFA and SSO Configuration

MFA:

1. Open `Settings` -> `Authentication`.
2. Click `Setup MFA`.
3. Scan the QR code with an authenticator app.
4. Enter the TOTP code and click `Enable MFA`.
5. Tenant admins can then require MFA for the organization.

SSO:

1. Create an OIDC application with the identity provider.
2. Configure the callback URL `/api/auth/sso/callback`.
3. Open `Settings` -> `Authentication` -> `Setup SSO`.
4. Enter the issuer URL, client ID, client secret and optionally an allowed
   email domain.
5. Test SSO login before enabling `Require SSO for this organization`.

Use `SSO_REDIRECT_URI` when the public callback URL differs from the internal
container URL.

### Email Notifications

Notifications can be limited by minimum severity. Darkstar can also report
successful, failed or stopped scans.

SMTP is configured through environment variables:

```bash
SMTP_HOST='smtp.example.org'
SMTP_PORT='587'
SMTP_FROM='darkstar@example.org'
SMTP_USER='darkstar@example.org'
SMTP_PASSWORD='...'
SMTP_TLS='true'
```

In the UI, configure recipients, minimum severity and success/failure messages
per tenant under `Settings` -> `Email Notifications`.

## Tools and Licenses

| Tool | Use | License |
| --- | --- | --- |
| Darkstar | Dashboard, API, orchestrator | GNU GPLv3 |
| Asteroid | Modular web application scanner | GNU AGPLv3 |
| BBOT | ASM, recon, subdomains | GPL-3.0 |
| RustScan | Port discovery | GPL-3.0 |
| Nmap | Service detection | Nmap Public Source License |
| OpenVAS Scanner / Greenbone CE | Network vulnerability scanning | GPLv2 for scanner components; feed/data objects have their own terms |
| Nuclei | Template-based vulnerability scanning | MIT |
| OWASP ZAP | DAST baseline/spider/passive alerts | Apache-2.0 |
| Nikto | Webserver misconfiguration checks | GPL; check upstream database/test terms |
| Wapiti | Black-box web vulnerability scanner | GPL-2.0 |
| Dalfox | XSS scanning | MIT |
| testssl.sh | TLS/SSL checks | GPL-2.0 |
| THC-Hydra | Optional brute force | GPL-3.0-or-later |
| massdns | DNS brute-force support | GPL-3.0 |
| Katana | Crawling | MIT |
| httpx | HTTP probing/filtering | MIT |
| Gau | URL discovery | MIT |
| Feroxbuster | Directory/file discovery | MIT |
| Arjun | Parameter discovery | AGPL-3.0 |
| TruffleHog | Secrets scanning | AGPL-3.0 |
| wappalyzer-next | Technology detection | GPL-3.0 |
| RetireJS | Vulnerable JavaScript library detection | Apache-2.0 |
| uro | URL normalization | Apache-2.0 |

## Distributed Scanner Workers

Distributed scanners claim jobs through the orchestrator API and send logs back.
See [distributed-scanners.md](./distributed-scanners.md) for setup details.

## Operational Checklist

Daily:

- check failed or stuck scans
- review new critical and high findings
- check scanner node heartbeats

Weekly:

- export vulnerability and attack-surface reports
- review scan schedules and scan scope
- check offline endpoint agents

Monthly:

- rotate unused API keys
- review user roles and MFA/SSO enforcement
- check CI/CD security artifacts
