@echo off
REM ========================================
REM Secure File Hub - Clean Docker Build Script (Windows)
REM ========================================
REM This script builds a clean Docker image with only admin user

setlocal enabledelayedexpansion

echo =======================================
echo Secure File Hub - Clean Docker Build
echo =======================================

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker and try again.
    exit /b 1
)

REM Check if required files exist
if not exist "Dockerfile" (
    echo [ERROR] Dockerfile not found in current directory
    exit /b 1
)

if not exist "scripts\init-clean-db.sql" (
    echo [ERROR] Database initialization script not found: scripts\init-clean-db.sql
    exit /b 1
)

if not exist "scripts\init-database.sh" (
    echo [ERROR] Database initialization script not found: scripts\init-database.sh
    exit /b 1
)

REM Configuration
set IMAGE_NAME=secure-file-hub
set IMAGE_TAG=clean
set FULL_IMAGE_NAME=%IMAGE_NAME%:%IMAGE_TAG%
set COMPOSE_FILE=docker-compose.clean.yml

REM Clean up existing containers and images
echo [INFO] Cleaning up existing containers and images...

REM Stop and remove existing containers
for /f "tokens=*" %%i in ('docker ps -a --format "table {{.Names}}" ^| findstr "secure-file-hub"') do (
    echo [INFO] Stopping container: %%i
    docker stop %%i >nul 2>&1
    docker rm %%i >nul 2>&1
)

REM Remove existing images
for /f "tokens=*" %%i in ('docker images --format "table {{.Repository}}:{{.Tag}}" ^| findstr "%FULL_IMAGE_NAME%"') do (
    echo [INFO] Removing existing image: %%i
    docker rmi %%i >nul 2>&1
)

REM Build the Docker image
echo [INFO] Building Docker image: %FULL_IMAGE_NAME%
echo [INFO] This may take several minutes...

docker build -t %FULL_IMAGE_NAME% .
if errorlevel 1 (
    echo [ERROR] Failed to build Docker image
    exit /b 1
)

echo [SUCCESS] Docker image built successfully: %FULL_IMAGE_NAME%

REM Show image information
echo [INFO] Image information:
docker images %IMAGE_NAME% --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"

REM Test the image
echo [INFO] Testing the built image...

REM Create a temporary container to test
set TEST_CONTAINER=secure-file-hub-test-%RANDOM%
docker run --name %TEST_CONTAINER% --rm -d %FULL_IMAGE_NAME%
if errorlevel 1 (
    echo [ERROR] Failed to start test container
    exit /b 1
)

echo [SUCCESS] Test container started successfully

REM Wait for services to start
echo [INFO] Waiting for services to start...
timeout /t 30 /nobreak >nul

REM Check if services are running
docker exec %TEST_CONTAINER% curl -f -k https://localhost:8443/api/v1/health >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Backend service health check failed
) else (
    echo [SUCCESS] Backend service is running
)

docker exec %TEST_CONTAINER% curl -f http://localhost:30000 >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Frontend service health check failed
) else (
    echo [SUCCESS] Frontend service is running
)

REM Stop test container
docker stop %TEST_CONTAINER% >nul 2>&1
echo [SUCCESS] Test container stopped

REM Save image to file
set SAVE_FILE=secure-file-hub-clean-%date:~0,4%%date:~5,2%%date:~8,2%-%time:~0,2%%time:~3,2%%time:~6,2%.tar
set SAVE_FILE=%SAVE_FILE: =0%
echo [INFO] Saving image to file: %SAVE_FILE%

docker save -o %SAVE_FILE% %FULL_IMAGE_NAME%
if errorlevel 1 (
    echo [ERROR] Failed to save image to file
    exit /b 1
)

echo [SUCCESS] Image saved to: %SAVE_FILE%

REM Get file size
for %%A in (%SAVE_FILE%) do set FILE_SIZE=%%~zA
set /a FILE_SIZE_MB=%FILE_SIZE%/1024/1024
echo [INFO] File size: %FILE_SIZE_MB% MB

echo =======================================
echo [SUCCESS] Build completed successfully!
echo =======================================
echo [INFO] Image name: %FULL_IMAGE_NAME%
echo [INFO] Image file: %SAVE_FILE%
echo [INFO] Admin username: admin
echo [INFO] Admin password: admin123
echo.
echo [INFO] To run the container:
echo   docker run -d -p 30000:30000 -p 8443:8443 %FULL_IMAGE_NAME%
echo.
echo [INFO] Or use docker-compose:
echo   docker-compose -f %COMPOSE_FILE% up -d
echo =======================================

pause
