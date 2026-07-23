#!/usr/bin/env bash
set -Eeuo pipefail

profile="${COMPOSE_PROFILE:-darkstar}"
web_service="${DARKSTAR_WEB_SERVICE:-darkstar-web}"
app_url="${DARKSTAR_APP_URL:-http://localhost:8080}"
ready_url="${DARKSTAR_APP_READY_URL:-${app_url%/}/documentation}"
timeout_seconds="${DARKSTAR_STARTUP_TIMEOUT:-900}"
openvas_ready_url="${DARKSTAR_OPENVAS_READY_URL:-http://localhost:8008/health}"

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

if ! docker info >/dev/null 2>&1; then
  printf '[!] Docker daemon is unavailable. Start Docker and ensure this user can access it.\n' >&2
  exit 1
fi

if [[ ! -f darkstar/scanners/asteroid/asteroid.py ]]; then
  if [[ -d .git ]] && command -v git >/dev/null 2>&1; then
    log 'Initializing scanner submodules'
    git submodule update --init --recursive
  else
    printf '[!] Asteroid scanner sources are missing. Clone with --recurse-submodules or install Git and rerun.\n' >&2
    exit 1
  fi
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

for key in MYSQL_ROOT_PASSWORD DB_HOST DB_NAME DB_USER DB_PASSWORD OPENVAS_USER OPENVAS_PASS; do
  require_env_key "$key"
done

if ! docker compose --profile "$profile" config --quiet; then
  printf '[!] Docker Compose configuration is invalid. Check .env and docker-compose.yaml.\n' >&2
  exit 1
fi

build_services=(darkstar)
case "$profile" in
  darkstar|gvm)
    build_services+=(openvas-api)
    ;;
esac

# All three application containers use the same image. Building the image once
# avoids three expensive, identical scanner-tool compilations on hosts without
# Docker Buildx, while --no-build guarantees `up` will not repeat the work.
log "Building shared application image for Docker Compose profile '${profile}'"
docker compose --progress plain --profile "$profile" build "${build_services[@]}"
log "Starting Docker Compose profile '${profile}'"
docker compose --profile "$profile" up -d --no-build

wait_for_url() {
  local service="$1"
  local url="$2"
  local label="$3"
  local deadline=$((SECONDS + timeout_seconds))

  log "Waiting for ${label} at ${url}"
  while (( SECONDS < deadline )); do
    local state
    state="$(docker compose ps "$service" --format json 2>/dev/null || true)"
    if [[ -n "$state" ]] && grep -q '"State":"exited"\|"State":"dead"' <<<"$state"; then
      docker compose logs --tail=120 "$service" >&2 || true
      printf '[!] %s exited before becoming ready.\n' "$service" >&2
      return 1
    fi

    if curl -fsS --max-time 10 "$url" >/dev/null; then
      log "${label} is ready"
      return 0
    fi
    sleep 5
  done

  docker compose ps >&2 || true
  docker compose logs --tail=120 "$service" >&2 || true
  printf '[!] Timed out after %s seconds waiting for %s.\n' "$timeout_seconds" "$url" >&2
  return 1
}

wait_for_url "$web_service" "$ready_url" "Darkstar web app"

case "$profile" in
  darkstar|gvm)
    wait_for_url "openvas-api" "$openvas_ready_url" "OpenVAS API"
    ;;
esac

docker compose ps
log "Darkstar installation is ready at ${app_url}"
