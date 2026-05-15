# Darkstar Windows Endpoint Agent

Native Windows endpoint inventory agent. It uses the same Darkstar enrollment and inventory API as the Python agent, but ships as a single Windows executable and runs as a Windows Service.

The agent also performs passive security posture checks for weak Windows
settings, password-policy issues and local privilege escalation indicators. It
reports failed checks as an `Endpoint Security Posture` inventory item; it does
not collect passwords or password hashes.

## Build

From this directory:

```bash
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/darkstar-agent.exe .
```

## Install On Windows

Copy `darkstar-agent.exe` and `install.ps1` to the target machine, then run an elevated PowerShell session:

```powershell
.\install.ps1 `
  -Url "http://darkstar.local:8080" `
  -Org "org_platform_admin" `
  -EnrollmentToken "<endpoint enrollment token>" `
  -IntervalSeconds 3600
```

The installer creates:

- Service: `DarkstarEndpointAgent`
- Binary: `C:\Program Files\Darkstar\EndpointAgent\darkstar-agent.exe`
- Config/state/logs: `C:\ProgramData\Darkstar\EndpointAgent\`

After first successful enrollment, the one-time enrollment token is removed from `config.json`; the long-lived agent token is stored in `agent.json`.

## Update Existing Agent

Build a fresh `darkstar-agent.exe`, copy it next to `install.ps1` on the target,
and run the installer from an elevated PowerShell session. If the service already
exists, the installer stops it, replaces the executable and starts it again; no
enrollment token is required for updates.

```powershell
.\install.ps1
darkstar-agent.exe run --print-inventory
```

The printed inventory should contain an `Endpoint Security Posture` software item
with any failed passive checks under `raw.security_checks`.

## Useful Commands

```powershell
darkstar-agent.exe install --url http://darkstar.local:8080 --org org_platform_admin --enrollment-token <token>
darkstar-agent.exe start
darkstar-agent.exe stop
darkstar-agent.exe uninstall
darkstar-agent.exe run --once --config "C:\ProgramData\Darkstar\EndpointAgent\config.json"
darkstar-agent.exe run --print-inventory
```
