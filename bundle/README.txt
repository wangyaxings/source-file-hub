Secure File Hub - Offline Bundle
================================

This folder contains prebuilt images (as tar) and a compose file to run
Secure File Hub on any machine with Docker + Docker Compose.

Contents
- images/backend.tar            Prebuilt backend image (tag: secure-file-hub-backend:bundle)
- images/frontend.tar           Prebuilt frontend image (tag: secure-file-hub-frontend:bundle)
- images/proxy.tar              Caddy proxy image (optional; pulled if missing)
- images/alpine.tar            Helper image for permission fix (alpine:3.18)
- docker-compose.yml (with Caddy proxy)  Uses the above images without building
- deploy.sh                     One‑shot loader + compose up script (Linux)
- configs/app.yaml            Backend config (TLS + DB path)
- configs/casbin_model.conf   Casbin model used to initialize permissions
- certs/server.crt|server.key   TLS certs used by proxy and backend
- data, logs, downloads         Runtime volumes (created on first run)
- Caddyfile                     TLS termination + routing (/api -> backend, others -> frontend)

Usage (Linux)
  ./deploy.sh

Access
- Frontend: https://localhost:30000
- Backend:  https://localhost:8444/api/v1

Notes
- Certificates here are for development/testing. Use trusted certs in production.
- Volumes map to subfolders in this directory; data persists across container restarts.
