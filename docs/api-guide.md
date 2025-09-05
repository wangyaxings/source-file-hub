# FileServer API Guide

## Overview

FileServer provides a secure REST API for file management with HTTPS-only access and JWT-based authentication.

## Base Information

- **API Base URL**: `https://localhost:8443/api/v1`
- **Authentication**: Bearer Token (JWT)
- **Protocol**: HTTPS Only
- **Content-Type**: `application/json`

## Authentication

### Get Default Users

```http
GET /api/v1/auth/users
```

Returns a list of default test users (no authentication required).

**Response Example:**
```json
{
  "success": true,
  "message": "默认测试用户列表",
  "data": {
    "users": [
      {
        "tenant_id": "demo",
        "username": "admin",
        "password": "admin123",
        "desc": "管理员账户"
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "password": "password123",
        "desc": "普通用户账户"
      }
    ]
  }
}
```

### User Login

```http
POST /api/v1/auth/login
```

**Request Body:**
```json
{
  "tenant_id": "demo",
  "username": "admin",
  "password": "admin123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "登录成功",
  "data": {
    "token": "abc123def456...",
    "expires_in": 86400,
    "user": {
      "tenant_id": "demo",
      "username": "admin"
    }
  }
}
```

### User Logout

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

## File Operations

### Download Files

```http
GET /api/v1/files/{file_path}
Authorization: Bearer <token>
```

All file downloads require authentication. Supported file paths:

| Type | Path | Description |
|------|------|-------------|
| Config | `configs/config.json` | System configuration |
| SSL Certificate | `certificates/server.crt` | SSL certificate file |
| SSL Private Key | `certificates/server.key` | SSL private key file |
| Certificate Info | `certificates/cert_info.json` | Certificate details |
| API Documentation | `docs/api_guide.txt` | API usage guide |

**Examples:**
```bash
# Download configuration file
GET /api/v1/files/configs/config.json

# Download SSL certificate
GET /api/v1/files/certificates/server.crt

# Download API documentation
GET /api/v1/files/docs/api_guide.txt
```

## System Endpoints

### Health Check

```http
GET /api/v1/health
```

Check service status (no authentication required).

**Response:**
```json
{
  "success": true,
  "message": "服务运行正常",
  "data": {
    "status": "healthy",
    "timestamp": "1640995200"
  }
}
```

### API Information

```http
GET /api/v1
```

Get comprehensive API information (no authentication required).

## Usage Examples

### Complete Workflow

```bash
# 1. Get default users
curl -k https://localhost:8443/api/v1/auth/users

# 2. Login
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'

# 3. Download files using token
TOKEN="your_token_here"
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 4. Logout
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### PowerShell Examples

```powershell
# Login
$loginData = @{
    tenant_id = "demo"
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "https://localhost:8443/api/v1/auth/login" -Method POST -Body $loginData -ContentType "application/json" -SkipCertificateCheck

# Download file
$token = ($response.Content | ConvertFrom-Json).data.token
$headers = @{"Authorization" = "Bearer $token"}
Invoke-WebRequest -Uri "https://localhost:8443/api/v1/files/configs/config.json" -Headers $headers -SkipCertificateCheck -OutFile "config.json"
```

## Error Handling

### Common Error Codes

- **401 Unauthorized**: Missing or invalid token
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: File or endpoint not found
- **500 Internal Server Error**: Server-side error

### Error Response Format

```json
{
  "success": false,
  "error": "Error message",
  "code": "ERROR_CODE"
}
```

## Security Features

- **HTTPS Only**: All communications encrypted
- **JWT Authentication**: Secure token-based auth
- **Multi-tenant Support**: Tenant isolation
- **Path Validation**: Prevents directory traversal
- **File Type Filtering**: Only allowed file types
- **Token Expiration**: 24-hour token lifetime

## Best Practices

1. **Always use HTTPS**: Never downgrade to HTTP
2. **Store tokens securely**: Use secure storage mechanisms
3. **Handle token expiration**: Implement automatic re-authentication
4. **Validate responses**: Check success status in responses
5. **Use proper error handling**: Handle all error scenarios
6. **Log API interactions**: Monitor for security issues

## Rate Limiting

Currently no rate limiting is implemented, but it's recommended to implement client-side throttling for production use.

## Testing

Use the provided test scripts to verify API functionality:
- `scripts/quick-test.sh` (Linux/macOS)
- `scripts/quick-test.ps1` (Windows PowerShell)
# Packages (Assets/Others) APIs

Two ZIP upload endpoints are available for assets and others. Filenames are strictly validated before upload.

- POST /api/v1/public/upload/assets-zip
- POST /api/v1/public/upload/others-zip

Request:
- Content-Type: multipart/form-data
- Field: `file` (ZIP file)
- Filename rules:
  - `<tenantToken>_assets_<UTC>.zip` for assets
  - `<tenantToken>_others_<UTC>.zip` for others
  - `<UTC>` format: `YYYYMMDDThhmmssZ` (e.g., `20250101T120000Z`)

On success, the file is stored under `downloads/packages/<tenantToken>/<assets|others>/`.

List and remark management:

- GET /api/v1/public/packages?tenant=&type=&q=&page=&limit=
  - Query params (optional):
    - `tenant`: Tenant ID
    - `type`: `assets` or `others`
    - `q`: search string (matches filename/path/remark)
    - `page`: default 1
    - `limit`: default 50, max 1000
  - Response data: `{ items: PackageRecord[], count, page, limit }`

- PATCH /api/v1/public/packages/{id}/remark
  - Body: `{ "remark": "text" }`

Web-authenticated mirrors (for use from the UI) exist under `/api/v1/web/...`:
- POST `/api/v1/web/packages/upload/assets-zip`
- POST `/api/v1/web/packages/upload/others-zip`
- GET `/api/v1/web/packages`
- PATCH `/api/v1/web/packages/{id}/remark`
