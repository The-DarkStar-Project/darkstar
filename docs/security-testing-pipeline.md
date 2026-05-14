# Security testing en Sec/DevOps pipeline

Deze pagina beschrijft hoe Darkstar security testing onderdeel maakt van de
ontwikkel- en releasepipeline. Het doel is dat security testing niet alleen
handmatig gebeurt, maar terugkomt als vaste controle met reproduceerbare
evidence.

## Pipeline doelstellingen

- Security checks draaien automatisch per pull request of release.
- Resultaten worden bewaard als pipeline artifacts.
- Releases worden geblokkeerd bij niet-geaccepteerde critical findings.
- High findings hebben een ticket, eigenaar en streefdatum.
- Secrets staan in CI/CD secret storage, niet in repositorybestanden.
- DAST en agressieve scans draaien alleen op toegestane test- of
  stagingomgevingen.

## Aanbevolen controles

| Fase | Controle | Voorbeelden |
| --- | --- | --- |
| Code | Unit tests, linting, SAST, secrets scanning | `pytest`, Semgrep, Gitleaks of TruffleHog |
| Dependencies | Package vulnerability scanning | OSV Scanner, Grype, Trivy |
| Build | Container en base image scanning | Trivy, Grype |
| Config | IaC en Compose/Kubernetes checks | Checkov, Trivy config |
| Staging | DAST baseline | OWASP ZAP baseline, Nuclei, Nikto, Wapiti |
| Darkstar | Gecentraliseerde scan en rapportage | Darkstar API, CSV/XLSX/HTML exports |

## Minimale lokale testset

Gebruik lokaal minimaal:

```bash
pytest
python -m compileall darkstar
```

Wanneer de tools beschikbaar zijn:

```bash
semgrep scan --config auto
osv-scanner --recursive .
trivy fs .
trivy config .
```

Deze commands zijn voorbeelden. De uiteindelijke pipeline moet aansluiten bij de
tooling die in de runner beschikbaar is.

## Darkstar in CI/CD

Maak in Darkstar een API key aan met de laagste rol die de pipeline nodig heeft.
Sla de key op als CI/CD secret, bijvoorbeeld `DARKSTAR_API_KEY`.

Voorbeeldvariabelen:

```bash
DARKSTAR_URL=https://darkstar.example.org
DARKSTAR_API_KEY=dstar_...
DARKSTAR_TARGET=https://staging.example.org
```

Een pipeline kan daarna:

1. een deployment naar staging uitvoeren
2. een Darkstar scan starten tegen de staging URL
3. wachten tot de scan is afgerond
4. findings exporteren
5. release blokkeren als de acceptatiecriteria worden overschreden

## Acceptatiecriteria

Aanbevolen default:

- Nieuwe critical findings blokkeren de release.
- Nieuwe high findings blokkeren tenzij er een risk acceptance of hotfix-ticket
  bestaat.
- Medium findings krijgen een ticket en worden gepland.
- Low en info findings worden periodiek gereviewd.
- False positives worden met evidence vastgelegd.

## Evidence artifacts

Bewaar per release:

- testresultaten
- dependency scanresultaten
- container scanresultaten
- DAST output
- Darkstar vulnerability export
- Darkstar attack-surface export wanneer relevant
- link naar tickets of risk acceptance

## Secrets en toegangsbeheer

- Gebruik alleen CI/CD secret storage voor API keys.
- Geef pipeline keys geen platform admin rechten.
- Roteer API keys periodiek.
- Trek ongebruikte keys direct in.
- Log secrets nooit naar stdout.

## Scope en veiligheid

DAST, agressieve scans en brute-force opties mogen alleen draaien tegen systemen
waarvoor expliciet toestemming en scope is vastgelegd. Voor productie moet de
pipeline standaard passieve of beperkte checks gebruiken, tenzij er een apart
change window en akkoord is.

## Periodieke controles

Dagelijks:

- gefaalde scans nalopen
- critical/high deltas reviewen

Wekelijks:

- pipeline artifacts steekproefsgewijs controleren
- scan-scope en staging URL's valideren

Maandelijks:

- API keys roteren of herbevestigen
- MFA/SSO enforcement controleren
- scanner nodes en endpoint agents opschonen
