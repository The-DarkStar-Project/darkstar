#!/bin/bash
# DarkStar specific Asteroid installation script
# Uses Ubuntu apt packages and does not install go binaries, as these are installed using the go-builder

# Move to asteroid directory
cd "$(dirname "$0")/asteroid"
echo "Moved to $(pwd)"

# General dependencies
dashes
echo "Installing general dependencies"
dashes

apt update && apt install -y python3 curl firefox # python3-pip pypy3-venv
# UV
# curl -LsSf https://astral.sh/uv/install.sh | sh
# uv venv
pip install -r requirements.txt

# Feroxbuster
apt install -y unzip
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s $HOME/.local/bin

# Arjun
pipx install arjun

# Trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b $HOME/.local/bin

# Vulnscan
apt install -y software-properties-common
sudo add-apt-repository ppa:mozillateam/ppa
apt install -y firefox-esr sudo git
pipx install wappalyzer
pip install -r "modules/50-vulnscan/requirements.txt"