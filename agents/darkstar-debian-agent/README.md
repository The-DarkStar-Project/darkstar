# Darkstar Debian Endpoint Agent

Debian/Linux installer for the Python Darkstar endpoint agent. The collector is
implemented in `darkstar.endpoint_agent`; this package adds a systemd service,
a protected environment file, and a small launcher for server rollouts.

## What It Collects

- Debian packages via `dpkg-query`
- RPM packages when `rpm` is present
- Python packages for the agent interpreter
- global npm packages when `npm` is present
- OS, hostname, IP and MAC metadata
- internal network map observations from routes, neighbors, gateways and
  endpoint peer probes
- optional osquery data when `osqueryi` is installed

## Install

Run this on the endpoint host:

```bash
curl -fsSLo /tmp/darkstar-endpoint-install.sh \
  https://raw.githubusercontent.com/The-DarkStar-Project/darkstar/main/agents/darkstar-debian-agent/install.sh
sudo bash /tmp/darkstar-endpoint-install.sh \
  --url "https://darkstar.example" \
  --org "org_example" \
  --enrollment-token "<endpoint enrollment token>"
```

The installer creates:

- service user: `darkstar-endpoint`
- service: `darkstar-endpoint-agent.service`
- install dir: `/opt/darkstar/endpoint-agent`
- config: `/etc/darkstar/endpoint-agent.env`
- state: `/var/lib/darkstar-endpoint/agent.json`

The enrollment token is only needed for first registration. After registration
the long-lived agent token is stored in the state file.

## Manage

```bash
sudo systemctl status darkstar-endpoint-agent
sudo systemctl restart darkstar-endpoint-agent
sudo journalctl -u darkstar-endpoint-agent -f
sudo darkstar-endpoint-agent --once
sudo darkstar-endpoint-agent --print-inventory
```

## Secret Handling

`/etc/darkstar/endpoint-agent.env` is written with mode `0600`. Treat this file
and `/var/lib/darkstar-endpoint/agent.json` as secrets because they can contain
enrollment or agent tokens.
