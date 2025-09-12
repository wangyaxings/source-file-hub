@echo off
REM FileServer Startup Script
REM Author: FileServer Team
REM Version: 1.0.0

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo ================================
echo    FileServer Startup Script
echo ================================
echo.

REM Check dependencies
echo [INFO] Checking dependencies...

REM Check Go
where go >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Go is not installed. Please install Go first.
    echo [INFO] Download from: https://golang.org/dl/
    pause
    exit /b 1
)
echo [OK] Go is installed

REM Check Node.js
where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed. Please install Node.js first.
    echo [INFO] Download from: https://nodejs.org/
    pause
    exit /b 1
)
echo [OK] Node.js is installed

REM Check yarn
where yarn >nul 2>&1
if errorlevel 1 (
    echo [ERROR] yarn is not installed. Please install yarn first.
    echo [INFO] Install with: npm install -g yarn
    pause
    exit /b 1
)
echo [OK] yarn is installed

echo.
echo [INFO] Dependencies check completed successfully
echo.

REM Create required directories
echo [INFO] Creating required directories...
if not exist "downloads" mkdir downloads
if not exist "downloads\configs" mkdir downloads\configs
if not exist "downloads\certificates" mkdir downloads\certificates
if not exist "downloads\docs" mkdir downloads\docs
if not exist "logs" mkdir logs
if not exist "pids" mkdir pids
if not exist "data" mkdir data
echo [OK] Directories created

echo.

REM Build backend
echo [INFO] Building backend service...
go mod tidy
if errorlevel 1 (
    echo [ERROR] Failed to update Go modules
    pause
    exit /b 1
)

go build -o file-server.exe cmd/server/main.go
if errorlevel 1 (
    echo [ERROR] Failed to build backend
    pause
    exit /b 1
)
echo [OK] Backend built successfully

echo.

REM Install frontend dependencies
echo [INFO] Installing frontend dependencies...
cd frontend
if not exist "node_modules" (
    echo [INFO] Installing yarn packages...
    cmd /c yarn install
    if errorlevel 1 (
        echo [ERROR] Failed to install frontend dependencies
        pause
        exit /b 1
    )
    echo [OK] Frontend dependencies installed
) else (
    echo [OK] Frontend dependencies already exist
)
cd ..

echo.

REM Always (re)generate SSL certificates for a unified HTTPS setup
echo [INFO] Generating SSL certificates (self-signed)...
go run scripts/generate_cert.go > logs\cert-generate.log 2>&1
if errorlevel 1 (
    echo [ERROR] Failed to generate SSL certificates. See logs\cert-generate.log
    pause
    exit /b 1
)
echo [OK] SSL certificates ready (certs\server.crt, certs\server.key)

REM Unified environment (HTTPS only)
set "GO_ENV=local"
set "BACKEND_URL=https://localhost:8443"

REM Start backend service (HTTPS only)
echo [INFO] Starting backend service (HTTPS on 8443)...
start "FileServer Backend" /min cmd /c "set GO_ENV=%GO_ENV% && file-server.exe > logs\backend.log 2>&1"
echo [INFO] Waiting for backend to start...
timeout /t 5 /nobreak >nul

REM Check backend status (HTTPS)
echo [INFO] Checking backend status (HTTPS)...
netstat -an | findstr ":8443" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Backend service failed to start properly
    echo [INFO] Check logs\backend.log for details
) else (
    echo [OK] Backend service is running on port 8443
)

REM Start frontend service
echo [INFO] Starting frontend service...
cd frontend
start "FileServer Frontend" /min cmd /c "cd /d %cd% && set BACKEND_URL=%BACKEND_URL% && set NODE_TLS_REJECT_UNAUTHORIZED=0 && node server.js > ..\logs\frontend.log 2>&1"
cd ..
echo [INFO] Waiting for frontend to start...
timeout /t 8 /nobreak >nul

REM Check if frontend is running (HTTPS)
echo [INFO] Checking frontend status (HTTPS)...
netstat -an | findstr ":30000" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Frontend may still be starting...
    echo [INFO] Waiting additional 5 seconds for frontend...
    timeout /t 5 /nobreak >nul
    netstat -an | findstr ":30000" >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Frontend service failed to start properly
        echo [INFO] Check logs\frontend.log for details
    ) else (
        echo [OK] Frontend service is now running on port 30000
    )
) else (
    echo [OK] Frontend service is running on port 30000
)

echo.
echo ================================
echo       Services Started!
echo ================================
echo.
echo Frontend URL: https://127.0.0.1:30000
echo Backend URL:  https://localhost:8443
echo API Info:    https://localhost:8443/api/v1/health
echo.
echo Default Users:
echo - admin@demo     (Administrator)
echo - user1@demo     (Regular User)
echo - test@tenant1   (Test User)
echo.
echo [INFO] Password can be any value
echo [INFO] Check logs folder for service logs
echo [INFO] Frontend uses yarn for package management
echo [INFO] Press Ctrl+C in service windows to stop
echo.

REM Open main interface in browser
echo [INFO] Preparing to open main interface...
netstat -an | findstr ":30000" >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Frontend service not responding, opening anyway...
    echo [INFO] You may need to refresh the page once services are ready
    start "" "https://127.0.0.1:30000"
    echo [OK] Browser opened (services may still be starting)
) else (
    echo [INFO] Opening main interface in browser...
    timeout /t 1 /nobreak >nul
    start "" "https://127.0.0.1:30000"
    echo [OK] Browser opened with FileServer interface
)

echo.
echo [SUCCESS] FileServer is now running!
echo [SUCCESS] Main interface opened in your default browser
echo.
echo To stop services:
echo - Close the "FileServer Backend" window
echo - Close the "FileServer Frontend" window
echo - Or press Ctrl+C in each service window
echo.
echo This startup window can be safely closed.
echo Services will continue running in background.
echo.
echo Press any key to close this startup window...
pause >nul

endlocal
