# FileServer

## Versioning and Builds

- Single source of truth: set `application.version` in `configs/app.yaml`.
- Backend API `/api/v1/web` returns this value.
- The frontend About dialog calls the same endpoint, keeping UI and API consistent.
- Update the version by editing `configs/app.yaml` (or the example file) and redeploying; no extra environment variables are required.
- Track optional build metadata (time/commit/tag) separately if needed - version checks rely only on `application.version`.

A secure REST API file server implemented in Go with HTTPS support and unified authenticated file download service. Provides enterprise-grade file management, user authentication, and structured logging capabilities.

**🌏 Language**: [English](README.md)

## ✨ Features

- ✅ **HTTPS-Only**: Supports only secure HTTPS connections
- ✅ **Unified File Downloads**: All files downloaded through unified API
- ✅ **Mandatory Authentication**: All file downloads require user authentication
- ✅ **Multi-tenant Support**: tenant_id + username authentication model
- ✅ **Session-based Authentication**: Secure Authboss sessions via HttpOnly cookies
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
- **🎯 Web Interface**: http://localhost:30000 (Recommended)
- **📡 Backend API**: https://localhost:8443/api/v1
- **🏥 Health Check**: https://localhost:8443/api/v1/health

### Backend Only
- **📡 API Endpoint**: https://localhost:8443/api/v1
- **🏥 Health Check**: https://localhost:8443/api/v1/health

## 👥 Default Users

## 🚀 快速开始

### 📦 优化后的部署方案

本项目已完成架构优化，现在提供：
- ✅ **单容器部署** - 前后端合并在一个容器中
- ✅ **外部数据挂载** - 数据库和日志文件存储在容器外
- ✅ **统一镜像构建** - 简化的 GitHub Actions 工作流
- ✅ **多平台支持** - 支持 linux/amd64 和 linux/arm64

### 🔧 部署方式

#### 使用 Docker Compose

```bash
# 启动生产环境
docker-compose up -d

# 停止服务
docker-compose down

# 查看日志
docker-compose logs -f

# 重启服务
docker-compose restart
```

### 📁 目录结构

部署后将在项目根目录创建以下外部挂载目录：
```
project-root/
├── data/           # 数据库文件 (fileserver.db)
├── logs/           # 应用日志文件
├── downloads/      # 用户下载文件
├── configs/        # 配置文件 (只读)
├── certs/          # SSL证书 (只读)
└── docker-compose.yml
```

### 🌐 访问地址

- **前端应用**: http://localhost:30000
- **后端API**: https://localhost:8443

## 👥 默认用户

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
docker pull xxxx/source-file-hub:latest

# Start with docker-compose
docker-compose up -d
```

### Frontend/Backend Split (Best Practice)

- New compose with two services: `backend` (Go, HTTPS) and `frontend` (Next.js, HTTPS + API proxy).
- Build and run locally:

```bash
docker-compose up -d --build
```

See docs at `docs/docker-split-deployment.md` for details.

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

# 3. Download files with session cookie
curl -k -b cookie.txt -O -J https://localhost:8443/api/v1/web/files/configs/config.json

# 4. Logout
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -b cookie.txt
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request


---

**⚡ Quick Tip**: For the best experience, use the web interface at http://localhost:30000 which provides a complete file management experience with automatic API authentication handling.

## Recent Changes: Roadmap/Recommendation Uploads and New APIs

- Allowed upload types are now restricted to:
  - Roadmap: `.tsv`
  - Recommendation: `.xlsx`

- Single-file versioning per category:
  - The server normalizes original names so each category has one logical file:
    - Roadmap → `roadmap.tsv`
    - Recommendation → `recommendation.xlsx`
  - Versioned filenames are created as `roadmap_vN.tsv` and `recommendation_vN.xlsx`.
  

- Web UI upload endpoint:
  - `POST /api/v1/web/upload`
  - Form fields: `file` (binary), `fileType` (`roadmap`|`recommendation`), `description` (optional)
  - The server validates the extension matches the selected `fileType`.

- New public API endpoints (API Key auth) for ZIP packages:
  - `POST /api/v1/public/upload/assets-zip`
  - `POST /api/v1/public/upload/others-zip`
  - Request: multipart/form-data with `file` (the ZIP)
  - Filename rule (strict validation):
    - `<tenantToken>_assets_<UTC>.zip` for assets
    - `<tenantToken>_others_<UTC>.zip` for others
    - `<UTC>` format: `YYYYMMDDThhmmssZ` (e.g., `20250101T120000Z`)
  - Storage: `downloads/packages/<tenantToken>/<assets|others>/<filename>` (directories created if missing)

### cURL Examples

Upload Roadmap via UI API:
```
curl -k -X POST https://localhost:8443/api/v1/web/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F file=@./my_roadmap.tsv \
  -F fileType=roadmap \
  -F description="Initial roadmap"
```

Upload assets ZIP via public API:
```
curl -k -X POST https://localhost:8443/api/v1/public/upload/assets-zip \
  -H "Authorization: Bearer $API_KEY" \
  -F file=@./tenant123_assets_20250101T120000Z.zip
```

Upload others ZIP via public API:
```
curl -k -X POST https://localhost:8443/api/v1/public/upload/others-zip \
  -H "Authorization: Bearer $API_KEY" \
  -F file=@./tenant123_others_20250101T120000Z.zip
```

