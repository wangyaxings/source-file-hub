Secure File Hub — Offline Windows Package

Overview
- This folder contains a runnable offline package for Windows.
- It includes the compiled backend (`fileserver.exe`), the compiled frontend (Next.js standalone server), self-signed TLS certs, configs, and startup scripts.

What You Need
- Windows 10/11 (x64)
- Node.js 18+ (for the frontend runtime)
  - No npm/yarn/network needed at runtime. `node_modules` is included.

Folder Structure
- fileserver.exe               Backend HTTPS server
- frontend/                   Frontend standalone server (Next.js)
  - server.js                 Entry file
  - .next/static/             Static assets
  - package.json
  - node_modules/             Offline dependencies
- certs/
  - server.crt, server.key    Self-signed TLS certs for https://localhost
- configs/
  - config.json               Server configuration (ports, cert paths)
- data/                       SQLite database (auto-created)
- downloads/                  Download artifacts
- logs/                       Runtime logs
- start.bat                   Start both backend (8443) and frontend (30000)
- stop.bat                    Stop both services

Quick Start
1) Double-click `start.bat` (Run as Administrator recommended on first start)
2) Open https://localhost:30000 in a browser
3) Login with admin / admin123 (or set `ADMIN_PASSWORD` before start)

Environment Variables (optional)
- ADMIN_PASSWORD=yourpassword   Set initial admin password on first boot
- DB_PATH=data\fileserver.db    Override database path (defaults as shown)

Notes
- The backend listens on HTTPS 8443 using the included self-signed certificate.
- The frontend proxies to https://localhost:8443; certificate is accepted by setting `NODE_TLS_REJECT_UNAUTHORIZED=0` in the script for local development.
- To replace the self-signed certs, drop `server.crt` and `server.key` into `certs/` and update paths in `configs/config.json` if needed.
- To stop services cleanly, use `stop.bat`.

