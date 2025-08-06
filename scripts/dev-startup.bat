@echo off
REM FileServer Development Mode Startup Script
REM Author: FileServer Team

setlocal enabledelayedexpansion
cd /d "%~dp0\.."

echo.
echo ================================
echo   FileServer Development Mode
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

REM Check certificates and set mode
set "DEV_MODE=false"
if not exist "certs\server.crt" (
    echo [INFO] SSL certificates not found, enabling development mode
    set "DEV_MODE=true"
)
if not exist "certs\server.key" (
    echo [INFO] SSL certificates not found, enabling development mode
    set "DEV_MODE=true"
)

REM Set environment variables
set "GO_ENV=development"
if "%DEV_MODE%"=="true" (
    set "DEV_MODE=true"
    echo [INFO] Starting in development mode (HTTP only)
) else (
    echo [INFO] Starting in production mode (HTTPS)
)

REM Start backend service
echo [INFO] Starting backend service...
start "FileServer Backend" /min cmd /c "set DEV_MODE=%DEV_MODE% && set GO_ENV=%GO_ENV% && file-server.exe > logs\backend.log 2>&1"
echo [INFO] Waiting for backend to start...
timeout /t 5 /nobreak >nul

REM Check backend status
echo [INFO] Checking backend status...
set "backend_status=0"

if "%DEV_MODE%"=="true" (
    for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:8080/api/v1/health' -TimeoutSec 10).StatusCode } catch { 0 }"') do set "backend_status=%%i"
    if "%backend_status%"=="200" (
        echo [OK] Backend service is running (HTTP mode)
    ) else (
        echo [WARNING] Backend may still be starting...
        timeout /t 5 /nobreak >nul
    )
) else (
    for /f %%i in ('powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -TimeoutSec 10).StatusCode } catch { 0 }"') do set "backend_status=%%i"
    if "%backend_status%"=="200" (
        echo [OK] Backend service is running (HTTPS mode)
    ) else (
        echo [WARNING] Backend may still be starting...
        timeout /t 5 /nobreak >nul
    )
)

REM Start frontend service
echo [INFO] Starting frontend service...
cd frontend
start "FileServer Frontend" /min cmd /c "cd /d %cd% && yarn dev > ..\logs\frontend.log 2>&1"
cd ..
echo [INFO] Waiting for frontend to start...
timeout /t 8 /nobreak >nul

REM Check frontend status
echo [INFO] Checking frontend status...
for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 10).StatusCode } catch { 0 }"') do set "frontend_status=%%i"
if "%frontend_status%"=="200" (
    echo [OK] Frontend service is running
) else (
    echo [WARNING] Frontend may still be starting...
    timeout /t 5 /nobreak >nul
)

echo.
echo ================================
echo       Services Started!
echo ================================
echo.
echo 🌐 Frontend URL: http://localhost:3000
if "%DEV_MODE%"=="true" (
    echo 📡 Backend URL:  http://localhost:8080
    echo 🏥 API Health:   http://localhost:8080/api/v1/health
) else (
    echo 📡 Backend URL:  https://localhost:8443
    echo 🏥 API Health:   https://localhost:8443/api/v1/health
)
echo.
echo 👥 Default Users:
echo - admin@demo     (Administrator)
echo - user1@demo     (Regular User)
echo - test@tenant1   (Test User)
echo.
echo 💡 Tips:
echo - Check logs\ folder for service logs
echo - Press Ctrl+C in service windows to stop
echo - Visit frontend URL for complete interface
echo.

REM Open interface in browser
echo [INFO] Opening interface in browser...
start "" "http://localhost:3000"

echo [SUCCESS] FileServer is now running!
echo.
echo Press any key to close this window (services will continue)...
pause >nul

endlocal