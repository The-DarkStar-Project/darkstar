#!/usr/bin/env bash
set -Eeuo pipefail

profile="${COMPOSE_PROFILE:-darkstar}"
web_service="${DARKSTAR_WEB_SERVICE:-darkstar-web}"
app_url="${DARKSTAR_APP_URL:-http://localhost:8080}"
ready_url="${DARKSTAR_APP_READY_URL:-${app_url%/}/documentation}"
timeout_seconds="${DARKSTAR_STARTUP_TIMEOUT:-300}"

log() {
  printf '[+] %s\n' "$*"
}

warn() {
  printf '[!] %s\n' "$*" >&2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[!] Required command not found: %s\n' "$1" >&2
    exit 1
  fi
}

require_env_key() {
  local key="$1"
  if ! grep -Eq "^[[:space:]]*${key}=" .env; then
    printf '[!] Missing required .env key: %s\n' "$key" >&2
    exit 1
  fi
}

require_command docker
require_command curl

if ! docker compose version >/dev/null 2>&1; then
  printf '[!] Docker Compose v2 is required. Install the docker compose plugin and try again.\n' >&2
  exit 1
fi

if [[ ! -f .env ]]; then
  if [[ ! -f .env.example ]]; then
    printf '[!] .env is missing and .env.example was not found.\n' >&2
    exit 1
  fi
  log 'Creating .env from .env.example'
  cp .env.example .env
  warn 'Review .env before using this outside local development.'
else
  log 'Using existing .env'
fi

for key in MYSQL_ROOT_PASSWORD DB_HOST DB_NAME DB_USER DB_PASSWORD; do
  require_env_key "$key"
done

log "Building and starting Docker Compose profile '${profile}'"
docker compose --profile "$profile" up -d --build

log "Waiting for ${web_service} to start on ${app_url}"
deadline=$((SECONDS + timeout_seconds))
while (( SECONDS < deadline )); do
  state="$(docker compose ps "$web_service" --format json 2>/dev/null || true)"
  if [[ -n "$state" ]] && grep -q '"State":"exited"\|"State":"dead"' <<<"$state"; then
    docker compose logs --tail=120 "$web_service" >&2 || true
    printf '[!] %s exited before becoming ready.\n' "$web_service" >&2
    exit 1
  fi

  if curl -fsS "$ready_url" >/dev/null; then
    log "Darkstar web app is ready at ${app_url}"
    exit 0
  fi

  sleep 5
done

docker compose ps >&2 || true
docker compose logs --tail=120 "$web_service" >&2 || true
printf '[!] Timed out after %s seconds waiting for %s.\n' "$timeout_seconds" "$ready_url" >&2
exit 1
