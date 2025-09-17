#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "[+] Checking docker and compose..."
if ! command -v docker >/dev/null 2>&1; then
  echo "[-] docker not found" >&2; exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "[-] docker compose plugin not found" >&2; exit 1
fi

echo "[+] Creating required directories..."
mkdir -p data logs downloads configs certs images

echo "[+] Loading images..."
if [ -f images/backend.tar ]; then
  docker load -i images/backend.tar
else
  echo "[-] images/backend.tar missing" >&2; exit 1
fi
if [ -f images/frontend.tar ]; then
  docker load -i images/frontend.tar
else
  echo "[-] images/frontend.tar missing" >&2; exit 1
fi
if [ -f images/proxy.tar ]; then
  docker load -i images/proxy.tar
else
  echo "[i] images/proxy.tar missing (will pull caddy:2-alpine from registry if available)"
fi

if [ -f images/alpine.tar ]; then
  docker load -i images/alpine.tar
else
  echo "[i] images/alpine.tar missing (will pull alpine:3.18 from registry if available)"
fi

# Try to ensure proper permissions for container user (uid:1001)
echo "[+] Fixing permissions on data/logs/downloads (uid:1001,gid:1001)"
for d in data logs downloads; do
  if [ -d "$d" ]; then
    docker run --rm -v "$(pwd)/$d:/v" alpine:3.18 sh -c "chown -R 1001:1001 /v 2>/dev/null || true; chmod -R g+rwX /v 2>/dev/null || true" || true
  fi
done

echo "[+] Bringing up stack (docker compose up -d)..."
docker compose up -d

echo "[+] Waiting for services..."
sleep 5
docker ps

echo "[+] Health checks:"
set +e
curl -sk https://localhost:8444/api/v1/health && echo || true
curl -sk https://localhost:30000 && echo || true
set -e

echo "[+] Done. Access:"
echo "  Frontend: https://localhost:30000"
echo "  Backend:  https://localhost:8444/api/v1"
