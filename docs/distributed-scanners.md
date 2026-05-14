# Distributed Scanner Workers

Darkstar can run as an orchestrator plus scanner-only workers.

The orchestrator is the normal web/API container. It owns:

- the frontend
- tenant auth, SSO/MFA and API keys
- the central scan queue
- scanner node registration
- scan logs, lifecycle and locking

Scanner workers run the same scanner tooling without frontend/auth UI. They:

- authenticate with a one-time generated `dscan_...` token
- poll `/api/scanner-workers/jobs/claim`
- atomically claim one queued job
- execute `python3 -m darkstar.main`
- stream logs back to the orchestrator
- write results to the central Darkstar database using the supplied DB connection
- complete the job through the orchestrator API

## Create An Attach Command

Run this on the orchestrator host/container:

```bash
python3 -m darkstar.scanner_attach create \
  --name edge-office \
  --url http://darkstar.local:8080 \
  --max-parallel-jobs 2
```

For a local Compose worker, use the Compose network:

```bash
docker compose exec darkstar-web python3 -m darkstar.scanner_attach create \
  --name local-scanner \
  --url http://darkstar-web:8080 \
  --network darkstar_vuln_net
```

The scanner token is written to a `0600` env file and the printed `docker run`
command references that file with `--env-file`. Do not paste the token into
logs or tickets. Revoking the scanner node invalidates it.

## Start A Local Worker

Copy the generated env file values into the worker host's protected `.env`
or use the printed `docker run --env-file ...` command on the host where the
scanner container will run.

```bash
docker compose --profile scanner up -d darkstar-scanner
```

## Remote Worker Notes

Remote workers need outbound access to:

- the orchestrator API URL
- the central MariaDB endpoint, or a VPN/tunnel that exposes it

This keeps scans running from the remote/internal network while results land in
the central tenant database.

Every scanner node can run every scanner by default. Use `max-parallel-jobs` to
control capacity per worker.
