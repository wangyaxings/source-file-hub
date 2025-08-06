#!/bin/bash

# FileServer Docker Deployment Script
# Version: 1.0.0

set -e

echo "FileServer Docker Deployment Script"
echo "===================================="

# Check Docker and Docker Compose
echo "[INFO] Checking environment dependencies..."
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed. Please install Docker first."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "[ERROR] Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

echo "[OK] Docker environment check passed"

# Navigate to project root directory
cd "$(dirname "$0")/.."

# Create directory structure
echo "[INFO] Creating project directory structure..."
mkdir -p {configs,certs,data,downloads,logs}
mkdir -p downloads/{configs,certificates,docs}
echo "[OK] Directory structure created"

# Generate configuration files
echo "[INFO] Generating configuration files..."
cat > configs/config.json << 'EOF'
{
  "server": {
    "host": "0.0.0.0",
    "https_port": 8443,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "ssl_enabled": true,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  },
  "application": {
    "name": "FileServer",
    "version": "4.0.0",
    "environment": "production",
    "protocol": "https"
  },
  "logging": {
    "level": "info",
    "format": "json"
  },
  "features": {
    "download_enabled": true,
    "cors_enabled": true,
    "auth_enabled": true,
    "ssl_enabled": true,
    "unified_file_download": true,
    "authenticated_downloads": true
  },
  "auth": {
    "token_expiry": "24h",
    "require_auth": true,
    "default_users": [
      {
        "tenant_id": "demo",
        "username": "admin",
        "description": "Administrator Account"
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "description": "Regular User Account"
      }
    ]
  },
  "downloads": {
    "base_directory": "downloads",
    "allowed_paths": [
      "configs/",
      "certificates/",
      "docs/"
    ],
    "supported_types": [".json", ".crt", ".key", ".txt", ".log", ".pem"]
  }
}
EOF

echo "[OK] Configuration files generated"

# Generate SSL certificates
echo "[INFO] Generating SSL certificates..."
if command -v openssl &> /dev/null; then
    # Generate private key
    openssl genrsa -out certs/server.key 2048 2>/dev/null

    # Generate certificate
    openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=FileServer/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:fileserver.local,IP:127.0.0.1" 2>/dev/null

    # Generate certificate info
    cat > certs/cert_info.json << EOF
{
  "subject": {
    "common_name": "localhost",
    "organization": ["FileServer"],
    "country": ["CN"],
    "province": ["Beijing"],
    "locality": ["Beijing"]
  },
  "validity": {
    "not_before": "$(date -Iseconds)",
    "not_after": "$(date -d '+365 days' -Iseconds)"
  },
  "key_usage": ["Digital Signature", "Key Encipherment"],
  "ext_key_usage": ["Server Authentication"],
  "dns_names": ["localhost", "fileserver.local"],
  "ip_addresses": ["127.0.0.1", "::1"],
  "key_size": 2048,
  "signature_algorithm": "SHA256-RSA",
  "files": {
    "certificate": "server.crt",
    "private_key": "server.key"
  }
}
EOF

    echo "[OK] SSL certificates generated"
else
    echo "[WARNING] OpenSSL not installed, using default certificates"
    echo "Please manually generate SSL certificates or install OpenSSL"
fi

# Prepare download files
echo "[INFO] Preparing initial download files..."
cp configs/config.json downloads/configs/ 2>/dev/null || true
cp certs/server.crt downloads/certificates/ 2>/dev/null || true
cp certs/server.key downloads/certificates/ 2>/dev/null || true
cp certs/cert_info.json downloads/certificates/ 2>/dev/null || true

# Create API documentation
cat > downloads/docs/api_guide.txt << 'EOF'
FileServer API Usage Guide

Basic Information:
- API Base URL: https://localhost:8443/api/v1
- Authentication: Bearer Token
- Protocol: HTTPS Only

Main Endpoints:
1. Health Check: GET /health
2. User Login: POST /auth/login
3. Get Users: GET /auth/users
4. File Download: GET /files/{path}
5. User Logout: POST /auth/logout

Default Test Users:
- admin@demo (password: admin123)
- user1@demo (password: password123)

Usage Steps:
1. Call /auth/users to get test user information
2. Call /auth/login to login and get token
3. Use token to access /files/* for file downloads
4. Call /auth/logout to logout

Example Commands:
# Login
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'

# Download file (use returned token)
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

Notes:
- All APIs require HTTPS access
- File downloads require user authentication
- Token valid for 24 hours
- Use -k parameter to skip SSL certificate verification (self-signed certificate)
EOF

echo "[OK] Initial files prepared"

# Check if frontend code exists
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    echo "[INFO] Frontend code detected, building complete service (frontend + backend)..."
else
    echo "[WARNING] Frontend code not detected, building backend service only..."
    echo "[INFO] For complete functionality, ensure frontend directory exists with package.json"
fi

echo "[INFO] Building FileServer application..."

# Start services
echo "[INFO] Starting FileServer services..."
docker compose up -d

echo "[INFO] Waiting for services to start..."
sleep 10

# Check service status
echo "[INFO] Checking service status..."
if docker compose ps | grep -q "Up"; then
    echo "[OK] Services started successfully!"

    # Verify API access
    echo "[INFO] Verifying API access..."
    if curl -k -s https://localhost:8443/api/v1/health > /dev/null; then
        echo "[OK] Backend API access normal"
    else
        echo "[WARNING] Backend API temporarily unavailable, may still be starting"
    fi

    # Check frontend
    echo "[INFO] Verifying frontend access..."
    if curl -s http://localhost:3000 > /dev/null; then
        echo "[OK] Frontend interface access normal"
    else
        echo "[WARNING] Frontend interface temporarily unavailable, may still be starting"
    fi
else
    echo "[ERROR] Service startup failed, please check logs"
    docker compose logs
    exit 1
fi

echo ""
echo "FileServer deployment completed!"
echo "================================"

# Display service information
echo "Frontend Interface: http://localhost:3000"
echo "Backend API: https://localhost:8443"
echo "Health Check: https://localhost:8443/api/v1/health"
echo "API Info: https://localhost:8443/api/v1"
echo "Default Users: https://localhost:8443/api/v1/auth/users"
echo ""
echo "Recommended Access: http://localhost:3000 (Complete frontend interface)"
echo "Direct API Access: https://localhost:8443/api/v1 (Pure API access)"

echo ""
echo "Management Commands:"
echo "  View logs: docker compose logs -f"
echo "  Stop services: docker compose down"
echo "  Restart services: docker compose restart"
echo ""
echo "NOTE: Using self-signed certificates, browsers will show security warnings"
echo "Documentation: cat docs/deployment-guide.md"