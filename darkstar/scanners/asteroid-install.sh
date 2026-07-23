#!/bin/bash
# DarkStar specific Asteroid installation script
# Uses Ubuntu apt packages and does not install go binaries, as these are installed using the go-builder

set -euo pipefail

export DEBIAN_FRONTEND="${DEBIAN_FRONTEND:-noninteractive}"
export PATH="$HOME/.local/bin:/root/.local/bin:$PATH"

: "${FEROXBUSTER_VERSION:=2.13.1}"
: "${FEROXBUSTER_SHA256:=7985c00e6803b0f25d5e9139f7472279f3f4d891429627a5cedc629e53992d80}"
: "${TRUFFLEHOG_VERSION:=3.95.9}"
: "${TRUFFLEHOG_SHA256:=f6d1106b85107d79527ed7a5b98b592beadd8b770dc3c9e8c1ad99e1b2cf127e}"
: "${ARJUN_VERSION:=2.2.7}"
: "${WAPPALYZER_VERSION:=2.0.2}"

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
install_apt_packages python3 curl unzip software-properties-common gnupg sudo git

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
ferox_archive="$(mktemp)"
curl -fsSL --retry 5 --retry-all-errors \
    -o "$ferox_archive" \
    "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.tar.gz"
echo "${FEROXBUSTER_SHA256}  ${ferox_archive}" | sha256sum --check
tar -xzf "$ferox_archive" -C "$HOME/.local/bin" feroxbuster
chmod 0755 "$HOME/.local/bin/feroxbuster"
rm -f "$ferox_archive"

# Arjun
pipx install "arjun==${ARJUN_VERSION}"

# Trufflehog
trufflehog_archive="$(mktemp)"
trufflehog_extract="$(mktemp -d)"
curl -fsSL --retry 5 --retry-all-errors \
    -o "$trufflehog_archive" \
    "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz"
echo "${TRUFFLEHOG_SHA256}  ${trufflehog_archive}" | sha256sum --check
tar -xzf "$trufflehog_archive" -C "$trufflehog_extract" trufflehog
install -m 0755 "$trufflehog_extract/trufflehog" "$HOME/.local/bin/trufflehog"
rm -rf "$trufflehog_extract"
rm -f "$trufflehog_archive"

# Vulnscan
pipx install "wappalyzer==${WAPPALYZER_VERSION}"
pip3 install --no-cache-dir -r "modules/50-vulnscan/requirements.txt"
