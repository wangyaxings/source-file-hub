#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_DIR="$SCRIPT_DIR"
IMAGES_DIR="$BUNDLE_DIR/images"
CONFIGS_DIR="$BUNDLE_DIR/configs"
CERTS_DIR="$BUNDLE_DIR/certs"
DATA_DIR="$BUNDLE_DIR/data"
LOGS_DIR="$BUNDLE_DIR/logs"
DOWNLOADS_DIR="$BUNDLE_DIR/downloads"
COMPOSE_FILE="$BUNDLE_DIR/docker-compose.yml"

echo "[+] Secure File Hub deploy starting in: $BUNDLE_DIR"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "[-] '$1' not found"; exit 1; }
}

need_cmd docker
if docker compose version >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_COMPOSE=(docker-compose)
else
  echo "[-] docker compose or docker-compose not found"
  exit 1
fi

mkdir -p "$DATA_DIR" "$LOGS_DIR" "$DOWNLOADS_DIR"
mkdir -p "$CONFIGS_DIR" "$CERTS_DIR"

load_if_present() {
  local tarball="$1"
  if [[ -f "$tarball" ]]; then
    echo "[+] Loading image: $(basename "$tarball")"
    docker load -i "$tarball"
  else
    echo "[i] Image tar not found: $(basename "$tarball") (skipping)"
  fi
}

if [[ -d "$IMAGES_DIR" ]]; then
  load_if_present "$IMAGES_DIR/backend.tar"
  load_if_present "$IMAGES_DIR/frontend.tar"
  load_if_present "$IMAGES_DIR/proxy.tar"
  load_if_present "$IMAGES_DIR/alpine.tar"
else
  echo "[i] images/ not found; assuming images are available on host"
fi

# Retag :bundle -> :latest for compose-based run
if docker image inspect secure-file-hub-backend:bundle >/dev/null 2>&1; then
  docker tag secure-file-hub-backend:bundle secure-file-hub-backend:latest || true
fi
if docker image inspect secure-file-hub-frontend:bundle >/dev/null 2>&1; then
  docker tag secure-file-hub-frontend:bundle secure-file-hub-frontend:latest || true
fi

# Ensure helper image exists for permission fix (alpine:3.18)
if ! docker image inspect alpine:3.18 >/dev/null 2>&1; then
  echo "[i] Helper image alpine:3.18 not present. Attempting to pull (requires network)..."
  docker pull alpine:3.18 >/dev/null 2>&1 || echo "[i] Pull failed or offline. If bundle/images/alpine.tar was provided, it should have been loaded above."
fi

# Self-heal permissions for mounted folders so UID 1001 (appuser) can write
echo "[+] Fixing ownership and permissions on mounted folders..."
for d in "$DATA_DIR" "$LOGS_DIR" "$DOWNLOADS_DIR"; do
  mkdir -p "$d"
  # Try with helper container; if it fails, continue without blocking
  docker run --rm -v "$d":/mnt alpine:3.18 sh -lc 'chown -R 1001:1001 /mnt && chmod -R u+rwX,g+rwX /mnt' \
    && echo "    [+] Fixed: $d" \
    || echo "    [i] Could not adjust perms for $d (offline image missing or permission denied). Proceeding..."
done

# Write docker-compose.yml if missing (runtime-only compose, no build sections)
if [[ ! -f "$COMPOSE_FILE" ]]; then
  echo "[i] docker-compose.yml not found in bundle; generating a runtime compose file"
  cat > "$COMPOSE_FILE" <<'YAML'
services:
  backend:
    image: secure-file-hub-backend:latest
    container_name: secure-file-hub-backend
    ports:
      - "8444:8443"
    environment:
      - GO_ENV=production
      - DISABLE_HTTPS_REDIRECT=true
      - DB_PATH=/app/data/fileserver.db
      - AUTHBOSS_ROOT_URL=https://localhost:8444
    volumes:
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
      - ./scripts:/app/scripts:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "sh", "-c", "curl -f -k https://localhost:8443/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    networks:
      - fileserver-network

  frontend:
    image: secure-file-hub-frontend:latest
    container_name: secure-file-hub-frontend
    depends_on:
      backend:
        condition: service_healthy
    ports:
      - "30000:30000"
    environment:
      - NODE_ENV=production
      - NODE_TLS_REJECT_UNAUTHORIZED=0
      - PORT=30000
      - HOSTNAME=0.0.0.0
      - BACKEND_URL=https://backend:8443
    volumes:
      - ./certs:/app/certs:ro
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "sh", "-c", "curl -f -k https://localhost:30000"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge
YAML
fi

echo "[+] Bringing up stack via compose..."
"${DOCKER_COMPOSE[@]}" -f "$COMPOSE_FILE" up -d

echo "[+] Deployment complete. Check services with:"
echo "    ${DOCKER_COMPOSE[*]} -f '$COMPOSE_FILE' ps"
echo "[i] Access URLs:"
echo "    Backend API: https://<host>:8444/api/v1/health"
echo "    Web UI:      https://<host>:30000"
echo "[i] A reference compose is included as docker-compose.source.yml (not used by this script)."
