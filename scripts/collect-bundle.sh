#!/usr/bin/env bash
set -euo pipefail

# collect-bundle.sh
# Linux shell equivalent of scripts/collect-bundle.bat
# - Builds (optional), tags and saves backend/frontend images into bundle/images
# - Collects configs, certs, helper scripts into bundle/
#
# Usage:
#   scripts/collect-bundle.sh [--no-build] [--skip-proxy-pull]

NO_BUILD=0
SKIP_PROXY_PULL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build) NO_BUILD=1; shift ;;
    --skip-proxy-pull) SKIP_PROXY_PULL=1; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)"
cd "$script_dir"

# Defaults (can be overridden by environment)
BACKEND_REPO=${BACKEND_REPO:-secure-file-hub-backend}
FRONTEND_REPO=${FRONTEND_REPO:-secure-file-hub-frontend}
BACKEND_TAG=${BACKEND_TAG:-bundle}
FRONTEND_TAG=${FRONTEND_TAG:-bundle}
PROXY_IMAGE=${PROXY_IMAGE:-caddy:2-alpine}
HELPER_IMAGE=${HELPER_IMAGE:-alpine:3.18}

log() { printf '%b\n' "$*"; }
info() { log "[+] $*"; }
warn() { log "[i] $*"; }
err()  { log "[-] $*"; }

info "Checking docker and compose..."
if ! command -v docker >/dev/null 2>&1; then err "docker not found"; exit 1; fi
if ! docker compose version >/dev/null 2>&1; then err "docker compose plugin not found"; exit 1; fi

info "Preparing bundle tree..."
mkdir -p bundle bundle/images bundle/certs bundle/configs bundle/data bundle/logs bundle/downloads bundle/scripts

# Copy certs if available
if [[ -f certs/server.crt ]]; then
  if [[ -f certs/server.key ]]; then
    cp -f certs/server.crt bundle/certs/server.crt || true
    cp -f certs/server.key bundle/certs/server.key || true
    info "Copied certs/server.*"
  else
    warn "certs/server.key not found; you can place it into bundle/certs later"
  fi
else
  warn "certs/server.crt not found; you can place it into bundle/certs later"
fi

# app.yaml
APP_YAML_SRC=""
if [[ -f configs/app.yaml ]]; then APP_YAML_SRC=configs/app.yaml; fi
if [[ -z "$APP_YAML_SRC" && -f configs/app.yaml.example ]]; then APP_YAML_SRC=configs/app.yaml.example; fi
if [[ -n "$APP_YAML_SRC" ]]; then
  cp -f "$APP_YAML_SRC" bundle/configs/app.yaml || true
  if [[ "$APP_YAML_SRC" == "configs/app.yaml" ]]; then
    info "Copied configs/app.yaml"
  else
    info "Generated bundle/configs/app.yaml from app.yaml.example"
  fi
else
  warn "configs/app.yaml not found; using existing bundle/configs/app.yaml if present"
fi

# Casbin model
if [[ -f configs/casbin_model.conf ]]; then
  cp -f configs/casbin_model.conf bundle/configs/casbin_model.conf
  info "Copied configs/casbin_model.conf"
else
  warn "configs/casbin_model.conf not found; provide it for policy initialization"
fi

# Deploy & helper scripts
if [[ -f scripts/deploy.sh ]]; then
  cp -f scripts/deploy.sh bundle/deploy.sh
  info "Copied scripts/deploy.sh to bundle/deploy.sh"
else
  warn "scripts/deploy.sh not found; please ensure it exists for deployment"
fi

if [[ -f scripts/init-database.sh ]]; then
  cp -f scripts/init-database.sh bundle/scripts/init-database.sh
  info "Included scripts/init-database.sh"
else
  warn "scripts/init-database.sh not found; skipping"
fi

if [[ -f scripts/init-clean-db.sql ]]; then
  cp -f scripts/init-clean-db.sql bundle/scripts/init-clean-db.sql
  info "Included scripts/init-clean-db.sql"
else
  warn "scripts/init-clean-db.sql not found; skipping"
fi

if [[ -f scripts/Caddyfile ]]; then
  cp -f scripts/Caddyfile bundle/scripts/Caddyfile
  info "Included scripts/Caddyfile"
else
  warn "scripts/Caddyfile not found; skipping"
fi

# Docs and compose (reference only)
if [[ -f docs/README.txt ]]; then
  cp -f docs/README.txt bundle/README.txt
  info "Included docs/README.txt -> bundle/README.txt"
else
  warn "docs/README.txt not found; skipping"
fi

if [[ -f docker-compose.yml ]]; then
  cp -f docker-compose.yml bundle/docker-compose.source.yml
  info "Included docker-compose.yml as bundle/docker-compose.source.yml"
else
  warn "docker-compose.yml not found; skipping"
fi

# Build images
if [[ "$NO_BUILD" == "0" ]]; then
  info "Building backend/frontend images via docker compose..."
  docker compose build backend frontend
else
  warn "Skipping build --no-build. Ensure images exist locally."
fi

info "Tagging images as :$BACKEND_TAG and :$FRONTEND_TAG..."
docker tag "$BACKEND_REPO:latest" "$BACKEND_REPO:$BACKEND_TAG" || true
docker tag "$FRONTEND_REPO:latest" "$FRONTEND_REPO:$FRONTEND_TAG" || true

info "Saving images to bundle/images ..."
docker save -o bundle/images/backend.tar "$BACKEND_REPO:$BACKEND_TAG"
docker save -o bundle/images/frontend.tar "$FRONTEND_REPO:$FRONTEND_TAG"

info "Ensuring proxy image ($PROXY_IMAGE) is available..."
if [[ "$SKIP_PROXY_PULL" == "0" ]]; then
  if ! docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1; then
    docker pull "$PROXY_IMAGE" || warn "Failed to pull $PROXY_IMAGE"
  fi
fi
if docker image inspect "$PROXY_IMAGE" >/dev/null 2>&1; then
  docker save -o bundle/images/proxy.tar "$PROXY_IMAGE"
  info "Saved proxy image to bundle/images/proxy.tar"
else
  warn "Proxy image $PROXY_IMAGE not present; bundle will attempt to pull during deploy"
fi

info "Ensuring helper image ($HELPER_IMAGE) is available..."
if [[ "$SKIP_PROXY_PULL" == "0" ]]; then
  if ! docker image inspect "$HELPER_IMAGE" >/dev/null 2>&1; then
    docker pull "$HELPER_IMAGE" || warn "Failed to pull $HELPER_IMAGE"
  fi
fi
if docker image inspect "$HELPER_IMAGE" >/dev/null 2>&1; then
  docker save -o bundle/images/alpine.tar "$HELPER_IMAGE"
  info "Saved helper image to bundle/images/alpine.tar"
else
  warn "Helper image $HELPER_IMAGE not present; deploy will try to pull if needed"
fi

info "Bundle ready at: $(pwd)/bundle"
info "Next steps:"
echo "    - Copy the bundle/ folder to the Linux host"
echo "    - On Linux host: chmod +x ./deploy.sh"
echo "    - On Linux host: ./deploy.sh"

exit 0

