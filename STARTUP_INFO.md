# FileServer Startup Script

## Overview
The `startup.bat` script provides a complete automated startup solution for the FileServer application with frontend interface auto-launch.

## Features

### ✅ Dependency Checking
- **Go** - Backend development environment
- **Node.js** - JavaScript runtime
- **Yarn** - Frontend package manager

### ✅ Automated Setup
- Creates required directories (`downloads`, `logs`, `pids`)
- Builds backend service (`file-server.exe`)
- Installs frontend dependencies (`yarn install`)

### ✅ Service Management
- Starts backend service in separate window
- Starts frontend development server in separate window
- Monitors service health with HTTP status checks
- Provides retry mechanism for startup failures

### ✅ Browser Integration
- Automatically opens main interface in default browser
- Verifies frontend availability before opening
- Opens `http://localhost:3000` when ready

### ✅ User Experience
- Real-time status updates during startup
- Clear error messages and troubleshooting hints
- Background service operation after startup completion

## Usage

Simply double-click or run from command line:
```cmd
startup.bat
```

## Startup Process

1. **Dependency Check** (15 seconds)
   - Validates Go, Node.js, and Yarn installations
   - Shows download links if dependencies missing

2. **Environment Setup** (5 seconds)
   - Creates project directories
   - Builds backend executable

3. **Frontend Setup** (30-60 seconds)
   - Installs/updates Yarn packages
   - Only runs if `node_modules` missing

4. **Service Launch** (15-20 seconds)
   - Starts backend service (port 8443)
   - Starts frontend service (port 3000)
   - Monitors startup with health checks

5. **Browser Launch** (2-3 seconds)
   - Final availability check
   - Opens main interface automatically

## Service Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| Frontend | http://localhost:3000 | Main user interface |
| Backend | https://localhost:8443 | REST API server |
| API Docs | https://localhost:8443/api/v1 | API information |
| Health Check | https://localhost:8443/api/v1/health | Service status |

## Service Management

### Running Services
After startup completion, two service windows run in background:
- **FileServer Backend** - Go server process
- **FileServer Frontend** - Yarn development server

### Stopping Services
To stop all services:
1. Close the "FileServer Backend" window, OR
2. Close the "FileServer Frontend" window, OR
3. Press `Ctrl+C` in each service window

### Service Logs
Logs are automatically saved to:
- `logs/backend.log` - Backend service logs
- `logs/frontend.log` - Frontend service logs

## Default Authentication

| Username | Tenant | Role | Description |
|----------|--------|------|-------------|
| admin | demo | Administrator | Full system access |
| user1 | demo | Regular User | Standard file operations |
| test | tenant1 | Test User | Testing account |

**Note**: Any password will be accepted for authentication.

## Troubleshooting

### Common Issues

**"Go is not installed"**
- Download from: https://golang.org/dl/
- Ensure Go is in system PATH

**"Node.js is not installed"**
- Download from: https://nodejs.org/
- Ensure Node.js is in system PATH

**"yarn is not installed"**
- Run: `npm install -g yarn`
- Restart command prompt

**"Failed to build backend"**
- Check Go installation
- Verify project files are complete
- Review `logs/backend.log` for errors

**"Frontend service failed to start"**
- Ensure port 3000 is available
- Check Yarn installation
- Review `logs/frontend.log` for errors

**"Services not responding"**
- Wait additional 30 seconds for startup
- Check Windows Firewall settings
- Verify no other services using ports 3000/8443

### Manual Recovery

If startup fails, you can manually run:

```cmd
# Backend
go mod tidy
go build -o file-server.exe cmd/server/main.go
file-server.exe

# Frontend (separate window)
cd frontend
yarn install
yarn dev
```

## System Requirements

- **Windows** 10/11 or Windows Server 2016+
- **RAM** 4GB minimum, 8GB recommended
- **Disk Space** 2GB for dependencies and files
- **Network** Ports 3000 and 8443 available

## File Structure

After startup, the following structure is created:
```
FileServer/
├── downloads/          # File storage
│   ├── configs/        # Configuration files
│   ├── certificates/   # SSL certificates
│   └── docs/          # Documentation
├── logs/              # Service logs
├── pids/              # Process IDs
└── startup.bat        # This script
```

## Security Notes

- Backend uses HTTPS with self-signed certificates
- Frontend development server uses HTTP
- Authentication tokens expire after 24 hours
- All file operations require authentication
- Logs contain access and security information