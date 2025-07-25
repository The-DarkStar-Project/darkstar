#!/bin/bash

# Function to display usage information
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --fresh             Perform a fresh installation (removes all containers, volumes, and images)"
    echo "  --help, -h          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                  # Default installation with OpenVAS"
    echo "  $0 --fresh          # Fresh installation (removes all existing data)"
}

# Default values for the .env file
ROOT_PASSWORD="database_is_fun01"
DB_HOST="mariadb"
DB_NAME="test"
DB_USER="data_guru"
DB_PASSWORD="kjafskljfs836487348akskdhkasdhk"
HIBP_KEY=""

# Default installation mode - OpenVAS is required for darkstar to function properly
PROFILE="darkstar"
FRESH_INSTALL=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fresh)
            FRESH_INSTALL=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if .env file exists, if not create it
if [ ! -f .env ]; then
  echo "Creating .env file..."
  cat > .env << EOF
# Database credentials for MariaDB and Python
MYSQL_ROOT_PASSWORD=${ROOT_PASSWORD}
DB_HOST=${DB_HOST}
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}

# HIBPam
HIBP_KEY=${HIBP_KEY}
EOF
fi

# Also ensure the darkstar/.env file exists for the darkstar container
if [ ! -f ./darkstar/.env ]; then
  echo "Creating darkstar/.env file..."
  cp .env ./darkstar/.env
fi

# Function to perform fresh installation
perform_fresh_install() {
    echo '[!] FRESH INSTALL REQUESTED - This will remove all containers, volumes, and images!'
    echo '[!] This action is irreversible. All data will be lost!'
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo '[!] Fresh install cancelled.'
        exit 1
    fi
    
    echo '[+] Stopping and removing all containers...'
    docker compose --profile openvas down --remove-orphans 2>/dev/null || true
    
    echo '[+] Removing all volumes...'
    docker volume rm darkstar_mariadb_data 2>/dev/null || true
    docker volume rm darkstar_redis_socket_vol 2>/dev/null || true
    docker volume rm darkstar_psql_data_vol 2>/dev/null || true
    docker volume rm darkstar_psql_socket_vol 2>/dev/null || true
    docker volume rm darkstar_gvmd_data_vol 2>/dev/null || true
    docker volume rm darkstar_scap_data_vol 2>/dev/null || true
    docker volume rm darkstar_cert_data_vol 2>/dev/null || true
    docker volume rm darkstar_data_objects_vol 2>/dev/null || true
    docker volume rm darkstar_vt_data_vol 2>/dev/null || true
    docker volume rm darkstar_notus_data_vol 2>/dev/null || true
    docker volume rm darkstar_gpg_data_vol 2>/dev/null || true
    docker volume rm darkstar_ospd_openvas_socket_vol 2>/dev/null || true
    
    echo '[+] Removing darkstar-related images...'
    docker rmi $(docker images --format "table {{.Repository}}:{{.Tag}}" | grep -E "(darkstar|registry.community.greenbone.net)" | tr -s ' ' | cut -d' ' -f1) 2>/dev/null || true
    
    echo '[+] Cleaning up unused Docker resources...'
    docker system prune -f
    
    echo '[+] Fresh install preparation complete!'
}

# Enabling BuildKit for faster builds
export DOCKER_BUILDKIT=1

# Perform fresh install if requested
if [ "$FRESH_INSTALL" = true ]; then
    perform_fresh_install
fi

# Setup the docker
echo "[+] Building the Darkstar docker with profile: $PROFILE"
docker compose --profile $PROFILE up -d --build

# Wait briefly to ensure containers have time to start properly
echo '[+] Waiting for containers to initialize...'
sleep 10

# Function to start interactive shell
start_interactive_shell() {
    echo '[+] Checking if darkstar container is running...'
    if [ "$(docker inspect -f '{{.State.Running}}' darkstar 2>/dev/null)" == "true" ]; then
      echo '[+] Starting interactive shell inside the container'
      docker exec -it darkstar /bin/bash
    else
      echo '[!] Error: The darkstar container is not running. Cannot start interactive shell.'
      echo '[!] Attempting to restart the container...'
      docker compose --profile $PROFILE restart darkstar
      sleep 5
      
      # Check again after restart attempt
      if [ "$(docker inspect -f '{{.State.Running}}' darkstar 2>/dev/null)" == "true" ]; then
        echo '[+] Container restarted successfully. Starting interactive shell.'
        docker exec -it darkstar /bin/bash
      else
        echo '[!] Failed to restart container. Check the logs with: docker logs darkstar'
        echo '[!] You can also try: docker compose --profile $PROFILE logs darkstar'
      fi
    fi
}
# clear
# Display installation summary
echo ""
echo "██████╗  █████╗ ██████╗ ██╗  ██╗███████╗████████╗ █████╗ ██████╗ "
echo "██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗"
echo "██║  ██║███████║██████╔╝█████╔╝ ███████╗   ██║   ███████║██████╔╝"
echo "██║  ██║██╔══██║██╔══██╗██╔═██╗ ╚════██║   ██║   ██╔══██║██╔══██╗"
echo "██████╔╝██║  ██║██║  ██║██║  ██╗███████║   ██║   ██║  ██║██║  ██║"
echo "╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝"
echo ""
echo "=============================================="
echo "            INSTALLATION COMPLETE"
echo "=============================================="
echo "Profile: $PROFILE"
echo "Fresh Install: $FRESH_INSTALL"
echo ""
echo "Available commands:"
echo "  docker compose --profile $PROFILE logs        # View logs"
echo "  docker compose --profile $PROFILE down        # Stop services"
echo "  docker compose --profile $PROFILE restart     # Restart services"
echo ""

# Start interactive shell
start_interactive_shell