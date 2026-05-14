# Darkstar applicatiedocumentatie

Deze documentatie beschrijft het gebruik en beheer van de Darkstar webapplicatie.
De uitgebreide webversie staat op `/documentation` in de draaiende applicatie.

## Doel

Darkstar is een multi-tenant vulnerability intelligence platform. Het dashboard
combineert:

- scans en scanlogs
- vulnerability findings
- attack-surface data
- endpoint inventory en endpoint CVE matching
- cloud security score data
- exports voor rapportage en audit
- tenant security settings zoals MFA, SSO, API keys en notificaties

Darkstar wordt ondersteund door [SIDN](https://www.sidnfonds.nl/) en
[NLnet](https://nlnet.nl/). De Darkstar repository zelf is gelicenseerd onder
GNU GPLv3. Upstream tools houden hun eigen licenties.

## Verantwoord en toegestaan gebruik

Darkstar bevat security tooling voor ASM, DAST, netwerk vulnerability scanning
en interne scans. Gebruik deze tooling uitsluitend voor legitieme
beveiligingsdoeleinden op systemen waarvan je eigenaar bent of waarvoor je
vooraf expliciete toestemming hebt gekregen.

Deze documentatie beschrijft bedoeld gebruik van Darkstar, maar vervangt geen
juridisch advies. Gebruikers en organisaties blijven zelf verantwoordelijk voor
naleving van wetgeving, contracten, bug bounty regels, cloudprovider
voorwaarden en klantafspraken.

De gebruiker is zelf verantwoordelijk voor:

- het controleren van toegestane scope, targets, scanvensters en
  scanintensiteit;
- het verkrijgen van expliciete toestemming van de eigenaar, opdrachtgever of
  verantwoordelijke organisatie;
- het alleen testen van productieomgevingen wanneer dat binnen de afgesproken
  testscope valt;
- het veilig behandelen van resultaten, exports, screenshots, secrets en
  persoonsgegevens;
- het beperken van toegang tot findings en exports tot personen die deze
  informatie nodig hebben;
- het stoppen van verdere tests wanneer een target buiten scope blijkt te
  vallen.

Darkstar mag niet worden gebruikt voor activiteiten buiten toestemming of buiten
testscope, waaronder:

- ongeautoriseerde scans, exploitatie of toegang tot systemen;
- credential stuffing, wachtwoordaanvallen of gebruik van buitgemaakte
  credentials;
- phishing, social engineering, datadiefstal of verzamelen van persoonsgegevens
  zonder grondslag;
- denial-of-service, verstoring, destructieve tests of agressieve belasting
  zonder akkoord;
- persistentie, laterale beweging of pogingen om beveiligingsmonitoring te
  omzeilen.

Als een scan een kwetsbaarheid of systeem buiten scope raakt, stop dan met
verdere tests op dat target. Leg vast wat er is gevonden, deel geen gevoelige
details breder dan nodig en volg een responsible disclosure of Coordinated
Vulnerability Disclosure proces.

## Rollen

| Rol | Rechten |
| --- | --- |
| `viewer` | Resultaten en rapportages bekijken. |
| `security_analyst` | Scans starten en operationele scanworkflows gebruiken. |
| `tenant_admin` | Tenantinstellingen, gebruikers, API keys, endpoint tokens en scanner nodes beheren. |
| `platform_admin` | Platformbreed tenant-overzicht en beheer. |

## Aan de slag

1. Log in met een organisatieaccount of via SSO.
2. Kies de juiste tenant als je account meerdere organisaties heeft.
3. Controleer je rol rechtsboven in het dashboard.
4. Open `Scan Center`.
5. Voer een target in, bijvoorbeeld een domein, hostname, IP-adres of CIDR range.
6. Kies een scan mode of een individuele scanner.
7. Start de scan en volg de output in `Debug`.
8. Triageer resultaten in `Vulnerabilities`.

## Dashboard

Het dashboard toont een korte status van:

- totaal aantal findings
- severity verdeling
- recente scans
- actieve en geplande scans

Gebruik dit scherm voor dagelijkse statuschecks.

## Scan Center

Scan Center queue't scanjobs centraal. Een scan kan lokaal of via een distributed
scanner appliance worden uitgevoerd.

### Targets

Targets mogen worden ingevoerd als:

- `example.com`
- `app.example.com`
- `192.0.2.10`
- `192.0.2.0/24`

Meerdere targets kunnen met komma's of nieuwe regels worden opgegeven.

### Scan mode of scanner

Gebruik een scan mode als je een vaste workflow wilt:

- Passive
- Normal
- Aggressive
- Attack Surface

Gebruik een individuele scanner als je bewust een specifiek hulpmiddel wilt
draaien, zoals BBot, RustScan, Nuclei, OWASP ZAP, Nikto, Wapiti, OpenVAS of een
Asteroid module.

Kies niet tegelijk een scan mode en een individuele scanner. De backend
accepteert precies een van beide.

### Scanner appliance

Met `Auto` kiest Darkstar een beschikbare scanner. Kies een specifieke scanner
appliance wanneer de scan vanuit een bepaalde netwerkpositie moet draaien.

### Geplande scans

Recurring scans ondersteunen:

- interval in uren, dagen, weken, maanden of jaren
- optionele startdatum
- optionele einddatum
- optionele voorkeursappliance

Darkstar slaat een identieke geplande scan tijdelijk over wanneer dezelfde
scanner en targetset al actief zijn.

## Vulnerabilities

De `Vulnerabilities` pagina toont findings per tenant. Beschikbare filters:

- severity
- host
- tool
- grouping

Groepering kan worden gezet op raw findings, deduplicated, severity, host, tool,
asset of vulnerability.

### Triageproces

1. Begin met critical en high findings.
2. Controleer host, CVE, exploitstatus en tool.
3. Open details voor evidence en scorecontext.
4. Exporteer de relevante set als CSV, XLSX of HTML report.
5. Leg false positives of accepted risks vast buiten Darkstar in het ticket- of
   riskregister.

## Attack Surface

Attack Surface bundelt externe assetinformatie uit recon-scans. Gebruik deze
pagina voor:

- asset review
- host en poortoverzicht
- subdomeinonderzoek
- vervolgscans op geselecteerde subdomeinen
- exports voor scope- en exposure-rapportages

Controleer scan-scope altijd voordat agressieve scans of brute-force opties
worden gebruikt.

## ASM, DAST en interne scanning

Darkstar ondersteunt drie scanperspectieven:

- ASM: externe attack-surface mapping met BBOT, DNS/OSINT-bronnen en portdata.
- DAST: dynamische webapplicatiechecks met onder andere Nuclei, OWASP ZAP,
  Wapiti, Nikto, Dalfox, testssl.sh en Asteroid modules.
- Interne netwerken: scanner-only containers draaien in een intern netwerk of
  VPN en claimen jobs bij de centrale orchestrator.

### Interne scanner container activeren

Maak een attach token aan vanuit de orchestrator:

```bash
docker compose exec darkstar-web python3 -m darkstar.scanner_attach create \
  --name local-scanner \
  --url http://darkstar-web:8080 \
  --network darkstar_vuln_net \
  --max-parallel-jobs 2
```

Zet daarna in `.env`:

```bash
DARKSTAR_ORCHESTRATOR_URL='http://darkstar-web:8080'
DARKSTAR_SCANNER_TOKEN='dscan_...'
DARKSTAR_SCANNER_NAME='local-scanner'
DARKSTAR_WORKER_MAX_PARALLEL='2'
```

Start de worker:

```bash
docker compose --profile scanner up -d darkstar-scanner
```

Kies daarna in `Scan Center` bij `Scanner appliance` de worker die vanuit het
interne netwerk moet scannen.

## Endpoints

Endpoint Agents leveren software-inventaris en endpointcontext aan Darkstar.
Darkstar matcht software tegen bekende vulnerabilities.

### Enrollment

1. Open `Endpoints`.
2. Maak een enrollment token aan.
3. Voer het getoonde install command uit op de endpoint host.
4. Controleer of de agent online komt.
5. Controleer software inventory en endpoint vulnerabilities.

### Beheer

Tenant admins kunnen:

- enrollment tokens intrekken
- endpoint agents revoken
- lokale endpoint records verwijderen

Revoke blokkeert toekomstige agentcommunicatie. Delete verwijdert het lokale
record met gekoppelde inventory.

## Security instellingen

Security instellingen staan onder `Settings`.

### MFA

Gebruikers kunnen MFA activeren met een authenticator-app. Tenant admins kunnen
MFA verplicht maken voor de organisatie. Platform admins kunnen MFA
platformbreed verplicht maken.

### SSO

SSO gebruikt OIDC. Configureer:

- issuer URL
- client ID
- client secret
- optioneel toegestaan e-maildomein

Registreer `/api/auth/sso/callback` als redirect URI bij de identity provider,
of stel `SSO_REDIRECT_URI` in als de publieke URL afwijkt.

### API keys

API keys gebruiken:

```http
Authorization: Bearer dstar_...
```

De secret wordt eenmalig getoond. Sla API keys alleen op in een secret manager of
CI/CD secret storage en roteer ze periodiek.

## MFA en SSO configuratie

MFA:

1. Open `Settings` -> `Authentication`.
2. Klik `Setup MFA`.
3. Scan de QR-code met een authenticator app.
4. Voer de TOTP-code in en klik `Enable MFA`.
5. Tenant admins kunnen daarna MFA verplicht maken voor de organisatie.

SSO:

1. Maak een OIDC application bij de identity provider.
2. Configureer de callback URL `/api/auth/sso/callback`.
3. Open `Settings` -> `Authentication` -> `Setup SSO`.
4. Vul issuer URL, client ID, client secret en eventueel allowed email domain in.
5. Test SSO login voordat `Require SSO for this organization` wordt aangezet.

Gebruik `SSO_REDIRECT_URI` als de publieke callback URL afwijkt van de interne
container URL.

### Email notificaties

Notificaties kunnen worden beperkt op minimale severity. Darkstar kan ook
succesvolle, gefaalde of gestopte scans melden.

SMTP wordt via environment variabelen ingesteld:

```bash
SMTP_HOST='smtp.example.org'
SMTP_PORT='587'
SMTP_FROM='darkstar@example.org'
SMTP_USER='darkstar@example.org'
SMTP_PASSWORD='...'
SMTP_TLS='true'
```

In de UI stel je per tenant ontvangers, minimale severity en succes/foutmeldingen
in onder `Settings` -> `Email Notifications`.

## Tools en licenties

| Tool | Gebruik | Licentie |
| --- | --- | --- |
| Darkstar | Dashboard, API, orchestrator | GNU GPLv3 |
| Asteroid | Modulaire web application scanner | GNU AGPLv3 |
| BBOT | ASM, recon, subdomains | GPL-3.0 |
| RustScan | Port discovery | GPL-3.0 |
| Nmap | Service detection | Nmap Public Source License |
| OpenVAS Scanner / Greenbone CE | Netwerk vulnerability scanning | GPLv2 voor scannercomponenten; feed/data objecten hebben eigen voorwaarden |
| Nuclei | Template-based vulnerability scanning | MIT |
| OWASP ZAP | DAST baseline/spider/passive alerts | Apache-2.0 |
| Nikto | Webserver misconfiguration checks | GPL; controleer upstream database/testvoorwaarden |
| Wapiti | Black-box web vulnerability scanner | GPL-2.0 |
| Dalfox | XSS scanning | MIT |
| testssl.sh | TLS/SSL checks | GPL-2.0 |
| THC-Hydra | Optionele bruteforce | GPL-3.0-or-later |
| massdns | DNS brute-force ondersteuning | GPL-3.0 |
| Katana | Crawling | MIT |
| httpx | HTTP probing/filtering | MIT |
| Gau | URL discovery | MIT |
| Feroxbuster | Directory/file discovery | MIT |
| Arjun | Parameter discovery | AGPL-3.0 |
| TruffleHog | Secrets scanning | AGPL-3.0 |
| wappalyzer-next | Technology detection | GPL-3.0 |
| RetireJS | Vulnerable JavaScript library detection | Apache-2.0 |
| uro | URL normalisatie | Apache-2.0 |

## Distributed scanner workers

Distributed scanners claimen jobs via de orchestrator API en sturen logs terug.
Zie [distributed-scanners.md](./distributed-scanners.md) voor setupdetails.

## Operationele checklist

Dagelijks:

- controleer mislukte of vastgelopen scans
- review nieuwe critical en high findings
- controleer scanner node heartbeats

Wekelijks:

- exporteer vulnerability en attack-surface rapportages
- review scanplanning en scan-scope
- controleer offline endpoint agents

Maandelijks:

- roteer ongebruikte API keys
- review gebruikersrollen en MFA/SSO enforcement
- controleer CI/CD security artifacts
