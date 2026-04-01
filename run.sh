#!/bin/bash

#? Step 0 - Copy .env.example to .env
echo '[+] Moving example env to project env'
cp .env.example .env

echo 'Please change the variables in the .env now, than press a key to continue...'
read 

#? Step 1 - Grep env variables from the .env
echo '[+] Loading environment variables...'
if [ ! -f .env ]; then
    echo "Error: .env file not found"
    exit 1
fi

# set -a 
# source .env 
# set +a

ROOT_PASSWORD=$(grep ROOT_PASSWORD .env | cut -d '=' -f2)
DB_HOST=$(grep DB_HOST .env | cut -d '=' -f2)
DB_NAME=$(grep DB_NAME .env | cut -d '=' -f2)
DB_USER=$(grep DB_USER .env | cut -d '=' -f2)
DB_PASSWORD=$(grep DB_PASSWORD .env | cut -d '=' -f2)
HIBP_KEY=$(grep HIBP_KEY .env | cut -d '=' -f2)
OPENVAS_USER=$(grep OPENVAS_USER .env | cut -d '=' -f2)
OPENVAS_PASS=$(grep OPENVAS_PASS .env | cut -d '=' -f2)

echo "[+] Environment variables successfully loaded"

#? Step 2 - build the darkstar project
docker compose --profile darkstar up -d 

#? Step 3 - Wait till the openvas feed is synced
echo '[+] Openvas data feed syncing, can take a while (~20 minutes)'
while true; do
    OUT="$(docker compose run --rm --no-deps gvm-tools gvm-cli --gmp-username admin --gmp-password admin socket --socketpath /run/gvmd/gvmd.sock --xml '<get_feeds/>')" && \
    if echo "$OUT" | grep -qE '<currently_syncing>|<sync_not_available>|<version></version>'; then
        echo "[>] Openvas feed is still syncing..."
    else
        break
    fi
    sleep 30
done
echo '[+] Openvas data feed synced!'