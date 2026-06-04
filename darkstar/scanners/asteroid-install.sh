#!/bin/bash
# DarkStar specific Asteroid installation script
# Uses Ubuntu apt packages and does not install go binaries, as these are installed using the go-builder

set -euo pipefail

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"

dashes() {
    local cols="${COLUMNS:-80}"

    if ! [[ "$cols" =~ ^[0-9]+$ ]] || [ "$cols" -lt 1 ]; then
        cols=80
    fi

    printf '%*s\n' "$cols" '' | tr ' ' '-'
}

install_apt_packages() {
    apt-get install -y --no-install-recommends "$@"
}

# Move to asteroid directory
cd "$(dirname "$0")/asteroid"
echo "Moved to $(pwd)"

# General dependencies
dashes
echo "Installing general dependencies"
dashes

apt-get update
install_apt_packages python3 curl unzip software-properties-common sudo git

if ! dpkg-query -W firefox-esr >/dev/null 2>&1; then
    add-apt-repository -y ppa:mozillateam/ppa
    apt-get update
    install_apt_packages firefox-esr
fi

# UV
# curl -LsSf https://astral.sh/uv/install.sh | sh
# uv venv
pip3 install --no-cache-dir -r requirements.txt

# Feroxbuster
curl -fsSL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s -- "$HOME/.local/bin"

# Arjun
pipx install arjun

# Trufflehog
curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/.local/bin"

# Vulnscan
pipx install wappalyzer
pip3 install --no-cache-dir -r "modules/50-vulnscan/requirements.txt"
