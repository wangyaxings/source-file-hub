# FileServer

A secure REST API file server implemented in Go with HTTPS support and unified authenticated file download service. Provides enterprise-grade file management, user authentication, and structured logging capabilities.

**🌏 Language**: [English](README.md) | [中文](docs/README-CN.md)

## ✨ Features

- ✅ **HTTPS-Only**: Supports only secure HTTPS connections
- ✅ **Unified File Downloads**: All files downloaded through unified API
- ✅ **Mandatory Authentication**: All file downloads require user authentication
- ✅ **Multi-tenant Support**: tenant_id + username authentication model
- ✅ **Token-based Authentication**: 24-hour long-lived tokens
- ✅ **RESTful API Design**: Compliant with REST standards
- ✅ **Modern Web UI**: Complete frontend interface built with Next.js
- ✅ **Structured Logging**: Best practice structured logging system
- ✅ **SQLite Log Storage**: Persistent log data with query and analysis support
- ✅ **Access Log API**: RESTful API for querying access logs
- ✅ **Path Security**: Protection against path traversal attacks
- ✅ **Multiple File Types**: Support for config, certificate, documentation files
- ✅ **Request Logging**: Detailed access and download logging
- ✅ **Graceful Shutdown**: Supports graceful service shutdown

## 🚀 Quick Start

### Option 1: One-Click Startup (Recommended)

**Windows:**
```cmd
startup.bat
```

This will present you with options for:
1. **Development Mode** - Native Go + Node.js development
2. **Docker Deployment** - Containerized deployment
3. **Help/Documentation** - Access to guides

### Option 2: Docker Deployment

```bash
# Quick setup
docker-compose up -d

# Or use deployment script
scripts/docker-deploy.sh    # Linux/macOS
scripts/docker-deploy.bat   # Windows
```

### Option 3: Development Mode

```bash
# Install dependencies
go mod download
cd frontend && yarn install

# Start services
scripts/dev-startup.bat     # Windows
```

## 🌐 Access URLs

### Complete Deployment (Frontend + Backend)
- **🎯 Web Interface**: http://localhost:3000 (Recommended)
- **📡 Backend API**: https://localhost:8443/api/v1
- **🏥 Health Check**: https://localhost:8443/api/v1/health

### Backend Only
- **📡 API Endpoint**: https://localhost:8443/api/v1
- **🏥 Health Check**: https://localhost:8443/api/v1/health

## 👥 Default Users

| Tenant ID | Username | Password | Description |
|-----------|----------|----------|-------------|
| demo | admin | admin123 | Administrator |
| demo | user1 | password123 | Regular User |
| tenant1 | test | test123 | Test Account |

## 📖 Documentation

- **[Quick Start Guide](docs/quick-start.md)** - Get up and running quickly
- **[Deployment Guide](docs/deployment-guide.md)** - Complete deployment instructions
- **[API Documentation](docs/api-guide.md)** - REST API reference
- **[中文文档](docs/README-CN.md)** - Complete Chinese documentation

## 🛠️ Project Structure

```
fileserver/
├── cmd/server/          # Main application entry
├── internal/            # Internal packages
│   ├── auth/           # User authentication module
│   ├── handler/        # HTTP handlers
│   ├── logger/         # Structured logging system
│   ├── middleware/     # Authentication, logging middleware
│   └── server/         # HTTPS server configuration
├── frontend/           # Next.js frontend application
│   ├── app/           # Next.js app directory
│   ├── components/    # React components
│   └── lib/           # Utility libraries
├── configs/           # Configuration files
├── certs/             # SSL certificates
├── downloads/         # Unified download directory
├── scripts/           # Deployment and utility scripts
├── docs/              # Documentation
└── docker-compose.yml # Docker deployment configuration
```

## 🔧 Development

### Prerequisites
- Go 1.19+
- Node.js 18+
- Yarn package manager

### Building

```bash
# Backend
go build -o fileserver cmd/server/main.go

# Frontend
cd frontend
yarn build
```

### Testing

```bash
# Backend tests
go test ./...

# API functionality test
scripts/quick-test.sh     # Linux/macOS
scripts/quick-test.ps1    # Windows PowerShell
```

## 🐳 Docker

### Using Pre-built Image

```bash
# Pull the image
docker pull ghcr.io/wangyaxings/source-file-hub:latest

# Start with docker-compose
docker-compose up -d
```

### Building Locally

```bash
# Build backend image
docker build -t fileserver-backend .

# Build frontend image
docker build -t fileserver-frontend ./frontend

# Start services
docker-compose up -d
```

## 🔒 Security Features

### HTTPS-First Architecture
- **HTTPS-Only**: Removed HTTP support, focused on secure connections
- **End-to-End Encryption**: All API communications use TLS encryption
- **Self-signed Certificates**: For development (replace with CA certificates in production)

### Unified Authentication Downloads
- **Mandatory Authentication**: All file downloads require user authentication
- **Unified Interface**: Manage all downloads through `/api/v1/files/{path}`
- **Path Control**: Only allows access to files in the `downloads/` directory

### Multi-tenant Authentication
- Uses `tenant_id + username + password` triplet authentication
- Supports same usernames under different tenants
- Suitable for SaaS application multi-tenant architecture

### Security Features
- BCrypt password hashing
- Automatic token expiration cleanup
- HTTPS enforced encrypted transmission
- Detailed authentication and access logging
- Path traversal attack prevention
- Whitelist path validation
- Input validation and sanitization

## 📊 API Usage Example

```bash
# 1. Get user list
curl -k https://localhost:8443/api/v1/auth/users

# 2. Login
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'

# 3. Download files with token
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 4. Logout
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/fileserver/issues)
- **Documentation**: See the `docs/` directory
- **API Reference**: [API Guide](docs/api-guide.md)

---

**⚡ Quick Tip**: For the best experience, use the web interface at http://localhost:3000 which provides a complete file management experience with automatic API authentication handling.