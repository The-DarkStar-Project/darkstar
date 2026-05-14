#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="darkstar-endpoint-agent"
SERVICE_USER="darkstar-endpoint"
INSTALL_DIR="/opt/darkstar/endpoint-agent"
ENV_FILE="/etc/darkstar/endpoint-agent.env"
SOURCE_BASE_URL="${DARKSTAR_AGENT_SOURCE_BASE_URL:-https://raw.githubusercontent.com/The-DarkStar-Project/darkstar/main}"
URL=""
ORG=""
ENROLLMENT_TOKEN=""
AGENT_TOKEN=""
INTERVAL="3600"
FORCE_ENV=0
SKIP_APT=0
START_SERVICE=1

usage() {
    cat <<'EOF'
Usage: install.sh --url URL [options]

Options:
  --org ORG_DB                  Tenant org database name for first enrollment
  --enrollment-token TOKEN      One-time endpoint enrollment token
  --agent-token TOKEN           Existing endpoint agent token
  --interval SECONDS            Inventory interval, default 3600
  --install-dir PATH            Install directory, default /opt/darkstar/endpoint-agent
  --env-file PATH               Environment file, default /etc/darkstar/endpoint-agent.env
  --source-base-url URL         Raw source base URL for standalone installs
  --force-env                   Overwrite existing environment file
  --skip-apt                    Do not install Debian package dependencies
  --no-start                    Install files but do not enable/start systemd service
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --url)
            URL="${2:-}"; shift 2 ;;
        --org)
            ORG="${2:-}"; shift 2 ;;
        --enrollment-token)
            ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
        --agent-token)
            AGENT_TOKEN="${2:-}"; shift 2 ;;
        --interval)
            INTERVAL="${2:-3600}"; shift 2 ;;
        --install-dir)
            INSTALL_DIR="${2:-}"; shift 2 ;;
        --env-file)
            ENV_FILE="${2:-}"; shift 2 ;;
        --source-base-url)
            SOURCE_BASE_URL="${2:-}"; shift 2 ;;
        --force-env)
            FORCE_ENV=1; shift ;;
        --skip-apt)
            SKIP_APT=1; shift ;;
        --no-start)
            START_SERVICE=0; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run this installer as root, for example with sudo." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." 2>/dev/null && pwd || true)"

fetch_file() {
    local relative_path="$1"
    local target_path="$2"
    local local_path="$REPO_ROOT/$relative_path"
    if [[ -f "$local_path" ]]; then
        cp "$local_path" "$target_path"
        return
    fi
    if command -v curl >/dev/null 2>&1; then
        curl -fsSLo "$target_path" "$SOURCE_BASE_URL/$relative_path"
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -qO "$target_path" "$SOURCE_BASE_URL/$relative_path"
        return
    fi
    echo "Cannot fetch $relative_path; install curl or wget." >&2
    exit 1
}

if [[ ! -f "$ENV_FILE" && -z "$URL" ]]; then
    echo "--url is required for first install when $ENV_FILE does not exist." >&2
    exit 2
fi

if [[ "$SKIP_APT" -eq 0 && -x /usr/bin/apt-get ]]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        ca-certificates \
        curl \
        iproute2 \
        iputils-ping \
        net-tools \
        python3 \
        python3-pip \
        python3-venv
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/darkstar-endpoint --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -m 0755 "$INSTALL_DIR"
install -d -m 0755 "$INSTALL_DIR/darkstar"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/lib/darkstar-endpoint
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" /var/log/darkstar-endpoint
install -d -m 0750 /etc/darkstar

fetch_file "darkstar/endpoint_agent.py" "$INSTALL_DIR/darkstar/endpoint_agent.py"
printf '' > "$INSTALL_DIR/darkstar/__init__.py"

python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade "requests>=2.32.4,<3"

fetch_file "agents/darkstar-debian-agent/darkstar-endpoint-agent" /usr/local/bin/darkstar-endpoint-agent
chmod 0755 /usr/local/bin/darkstar-endpoint-agent

if [[ ! -f "$ENV_FILE" || "$FORCE_ENV" -eq 1 ]]; then
    umask 077
    {
        printf "DARKSTAR_URL=%q\n" "$URL"
        printf "DARKSTAR_ORG=%q\n" "$ORG"
        printf "DARKSTAR_ENROLLMENT_TOKEN=%q\n" "$ENROLLMENT_TOKEN"
        printf "DARKSTAR_AGENT_TOKEN=%q\n" "$AGENT_TOKEN"
        printf "DARKSTAR_INTERVAL_SECONDS=%q\n" "$INTERVAL"
        printf "DARKSTAR_STATE_FILE=%q\n" "/var/lib/darkstar-endpoint/agent.json"
        printf "ENDPOINT_NETWORK_PROBE_MAX_TARGETS=%q\n" "48"
    } > "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
else
    echo "Keeping existing $ENV_FILE. Use --force-env to overwrite it."
fi

fetch_file "agents/darkstar-debian-agent/darkstar-endpoint-agent.service" "/etc/systemd/system/$SERVICE_NAME.service"
if [[ "$ENV_FILE" != "/etc/darkstar/endpoint-agent.env" ]]; then
    sed -i "s|^EnvironmentFile=.*|EnvironmentFile=$ENV_FILE|" "/etc/systemd/system/$SERVICE_NAME.service"
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    if [[ "$START_SERVICE" -eq 1 ]]; then
        systemctl enable --now "$SERVICE_NAME.service"
    fi
else
    echo "systemctl not found; files installed but service was not started."
fi

echo "Darkstar endpoint agent installed."
echo "Config: $ENV_FILE"
echo "State: /var/lib/darkstar-endpoint/agent.json"
