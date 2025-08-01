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

REM Start backend service
echo [INFO] Starting backend service...
start "FileServer Backend" /min cmd /c "file-server.exe > logs\backend.log 2>&1"
echo [INFO] Waiting for backend to start...
timeout /t 5 /nobreak >nul

REM Check if backend is running
echo [INFO] Checking backend status...
for /f %%i in ('powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -TimeoutSec 10).StatusCode } catch { 0 }"') do set "backend_status=%%i"
if "%backend_status%"=="200" (
    echo [OK] Backend service is running
) else (
    echo [WARNING] Backend may still be starting... (Status: %backend_status%)
    echo [INFO] Waiting additional 5 seconds for backend...
    timeout /t 5 /nobreak >nul
    for /f %%i in ('powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "backend_status=%%i"
    if "%backend_status%"=="200" (
        echo [OK] Backend service is now running
    ) else (
        echo [ERROR] Backend service failed to start properly
        echo [INFO] Check logs\backend.log for details
    )
)

REM Start frontend service
echo [INFO] Starting frontend service...
cd frontend
start "FileServer Frontend" /min cmd /c "cd /d %cd% && yarn dev > ..\logs\frontend.log 2>&1"
cd ..
echo [INFO] Waiting for frontend to start...
timeout /t 8 /nobreak >nul

REM Check if frontend is running
echo [INFO] Checking frontend status...
for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 10).StatusCode } catch { 0 }"') do set "frontend_status=%%i"
if "%frontend_status%"=="200" (
    echo [OK] Frontend service is running
) else (
    echo [WARNING] Frontend may still be starting... (Status: %frontend_status%)
    echo [INFO] Waiting additional 5 seconds for frontend...
    timeout /t 5 /nobreak >nul
    for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "frontend_status=%%i"
    if "%frontend_status%"=="200" (
        echo [OK] Frontend service is now running
    ) else (
        echo [ERROR] Frontend service failed to start properly
        echo [INFO] Check logs\frontend.log for details
    )
)

echo.
echo ================================
echo       Services Started!
echo ================================
echo.
echo Frontend URL: http://localhost:3000
echo Backend URL:  https://localhost:8443
echo API Info:    https://localhost:8443/api/v1
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
REM Final check before opening browser
for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "final_check=%%i"
if "%final_check%"=="200" (
    echo [INFO] Opening main interface in browser...
    timeout /t 1 /nobreak >nul
    start "" "http://localhost:3000"
    echo [OK] Browser opened with FileServer interface
) else (
    echo [WARNING] Frontend service not responding, opening anyway...
    echo [INFO] You may need to refresh the page once services are ready
    start "" "http://localhost:3000"
    echo [OK] Browser opened (services may still be starting)
)

echo.
echo [SUCCESS] FileServer is now running!
echo [SUCCESS] Main interface opened in your default browser
echo.
echo ================================
echo         Service Status
echo ================================
echo Frontend: http://localhost:3000
echo Backend:  https://localhost:8443
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