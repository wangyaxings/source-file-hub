# Secure File Hub API Guide

## Overview

Secure File Hub uses HTTPS and session-based authentication (Authboss). Clients authenticate via login and receive an HttpOnly, Secure cookie; subsequent requests include cookies automatically.

## Base Information

- API Base URL: `https://localhost:8443/api/v1/web`
- Authentication: Session cookie (Authboss)
- Protocol: HTTPS only
- Content-Type: `application/json`

## Authentication

### Get Default Users

```http
GET /auth/users
```

Returns a list of default demo users (no authentication required).

### Login

```http
POST /auth/ab/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123",
  "code": "123456" // optional TOTP when 2FA enabled
}
```

On success Authboss sets a session cookie and returns:

```json
{
  "status": "success",
  "location": "/api/v1/web/auth/me"
}
```

### Current User

```http
GET /auth/me
Cookie: ab_session=...
```

Response example:

```json
{
  "success": true,
  "data": {
    "user": { "username": "admin", "role": "administrator", "two_fa": true }
  }
}
```

### Logout

```http
POST /auth/ab/logout
```

### 2FA (TOTP)

- Setup: `POST /auth/ab/2fa/totp/setup`
- Confirm: `POST /auth/ab/2fa/totp/confirm`
- Remove: `POST /auth/ab/2fa/totp/remove`

## File Operations

### Download Files (Web)

```http
GET /files/{path}
Cookie: ab_session=...
```

Examples:

```text
/files/configs/config.json
/files/certificates/server.crt
/files/docs/api_guide.txt
```

## System Endpoints

### Health Check

```http
GET https://localhost:8443/api/v1/health
```

## Usage Examples

### cURL (with cookies)

```bash
# 1) Login and store cookies
curl -k -c cookie.txt -X POST https://localhost:8443/api/v1/web/auth/ab/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# 2) Get current user using cookie
curl -k -b cookie.txt https://localhost:8443/api/v1/web/auth/me

# 3) Download a file using cookie
curl -k -b cookie.txt -O -J https://localhost:8443/api/v1/web/files/configs/config.json

# 4) Logout
curl -k -b cookie.txt -X POST https://localhost:8443/api/v1/web/auth/ab/logout
```

### PowerShell

```powershell
# Login
$cookies = New-Object System.Net.CookieContainer
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.CookieContainer = $cookies
$client = New-Object System.Net.Http.HttpClient($handler)
$loginBody = '{"username":"admin","password":"admin123"}'
$result = $client.PostAsync('https://localhost:8443/api/v1/web/auth/ab/login',
  (New-Object System.Net.Http.StringContent($loginBody, [Text.Encoding]::UTF8, 'application/json'))).Result

# Get current user
$me = $client.GetAsync('https://localhost:8443/api/v1/web/auth/me').Result
$me.Content.ReadAsStringAsync().Result | Write-Output
```

## Error Handling

- 401 Unauthorized: Missing/invalid session
- 403 Forbidden: Not permitted or 2FA required
- 404 Not Found: Resource not found
- 500 Internal Server Error

Error format:

```json
{ "success": false, "error": "message", "code": "ERROR_CODE" }
```

## Security Features

- HTTPS only; HSTS recommended
- Session cookies: HttpOnly, Secure, SameSite=Lax
- Authboss-managed login/logout and 2FA

## Testing

Use provided scripts for quick checks:
- `scripts/quick-test.sh` (Linux/macOS)
- `scripts/quick-test.ps1` (Windows PowerShell)

