# API Key Usage Guide

This guide shows how to use API keys to access the Operation Center public APIs for health checks, checking and downloading the latest Roadmap and Recommendation files (with version and checksum), and uploading Assets/Others packages.

## Base URL and Auth

- Base: `https://<HOSTNAME>:<PORT>/api/v1/public`
- Default test target IP: `10.48.102.36`
- Example with SNI mapping (self‑signed or custom certs):
  - `curl -k --resolve localhost:8444:10.48.102.36 https://localhost:8444/...`
- Send API key via either header:
  - `X-API-Key: <key>`
  - or `Authorization: ApiKey <key>` (or `Bearer <key>`)

## Quick Test Script

Use the helper script to run end‑to‑end checks against the Operation Center.

- Command
  - `API_KEY=sk_xxx IPS="10.48.102.36" PORTS="8444" TENANT=tenant123 DO_DOWNLOADS=1 DO_UPLOADS=1 ./scripts/api-test.sh`
- What it does
  - Health: `/health`, `/healthz`
  - Latest info: `/versions/roadmap/latest`, `/versions/recommendation/latest`
  - Downloads latest files and prints: version, size and `checksum=sha256:<value>`
  - Uploads valid ZIP packages to `/upload/assets-zip` and `/upload/others-zip`
- Outputs
  - Files and JSON saved under `tmp/api-test/`
  - Summary lines like: `[download] roadmap -> 200 | version=12 | size=12345 bytes | checksum=sha256:abcdef... | time=2025-09-08T14:14:28Z`

## Health Endpoints

- `GET /api/v1/health`
- `GET /api/v1/healthz`

Examples

- `curl -k --resolve localhost:8444:10.48.102.36 https://localhost:8444/api/v1/health`
- `curl -k --resolve localhost:8444:10.48.102.36 https://localhost:8444/api/v1/healthz`

## Latest Roadmap/Recommendation

Check latest metadata (now includes `version`, `versionId`, and `checksum`):

- `GET /api/v1/public/versions/roadmap/latest` or `/latest/info`
- `GET /api/v1/public/versions/recommendation/latest` or `/latest/info`

Get info for a specific versionId (extensible pattern):

- `GET /api/v1/public/versions/roadmap/{versionId}/info`
- `GET /api/v1/public/versions/recommendation/{versionId}/info`

Download latest file:

- `GET /api/v1/public/versions/roadmap/latest/download`
- `GET /api/v1/public/versions/recommendation/latest/download`

Examples

- Roadmap info (latest)
  - `curl -s -k -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \`
    `https://localhost:8444/api/v1/public/versions/roadmap/latest/info`
- Roadmap info for specific versionId
  - `curl -s -k -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \`
    `https://localhost:8444/api/v1/public/versions/roadmap/v20250908T141425Z/info`
- Roadmap download
  - `curl -s -k -OJ -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \`
    `https://localhost:8444/api/v1/public/versions/roadmap/latest/download`
- Recommendation info
  - `curl -s -k -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \`
    `https://localhost:8444/api/v1/public/versions/recommendation/latest`
- Recommendation download
  - `curl -s -k -OJ -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \`
    `https://localhost:8444/api/v1/public/versions/recommendation/latest/download`

Compute checksum locally after download (pick one):

- Linux: `sha256sum <downloaded-file>`
- macOS/Linux: `shasum -a 256 <downloaded-file>`
- OpenSSL: `openssl dgst -sha256 <downloaded-file>`

Notes

- The latest‑info JSON returns both `version` and `checksum` (sha256) and `versionId`. You can cross‑validate by computing SHA‑256 of the downloaded file if desired.

## Upload Assets/Others Packages

Endpoints

- `POST /api/v1/public/upload/assets-zip`
- `POST /api/v1/public/upload/others-zip`

Rules

- File must be a `.zip` and the filename must be:
  - `<tenant>_assets_<UTC>.zip` or `<tenant>_others_<UTC>.zip`
  - `<UTC>` format: `YYYYMMDDThhmmssZ` (UTC time, e.g., `20250908T141425Z`)

Example (Linux)

```
utc=$(date -u +%Y%m%dT%H%M%SZ)
echo hello > dummy.txt
zip -q tenant123_assets_${utc}.zip dummy.txt
curl -s -k -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \
  -F file=@tenant123_assets_${utc}.zip \
  https://localhost:8444/api/v1/public/upload/assets-zip

zip -q tenant123_others_${utc}.zip dummy.txt
curl -s -k -H "X-API-Key: sk_xxx" --resolve localhost:8444:10.48.102.36 \
  -F file=@tenant123_others_${utc}.zip \
  https://localhost:8444/api/v1/public/upload/others-zip
```

## Tips

- Poll `/healthz` periodically (e.g., every 30–60 seconds) to display connection status in your UI.
- For domains, keep the same calls but set `<HOSTNAME>` to that domain and use `--resolve` to pin to an IP as needed.
- Ports are configurable; the examples use `8444`. Replace with your deployment’s port if different (e.g., `443`).
