@echo off
REM FileServer Docker Deployment Script (Windows)
REM Version: 1.0.0

setlocal enabledelayedexpansion
cd /d "%~dp0\.."

echo.
echo FileServer Docker Deployment Script
echo ====================================
echo.

REM Check dependencies
echo [INFO] Checking environment dependencies...
where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    echo [INFO] Download from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

docker compose version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker Compose is not available. Please ensure Docker Desktop includes Compose.
    pause
    exit /b 1
)

echo [OK] Docker environment check passed

REM Create directory structure
echo [INFO] Creating project directory structure...
if not exist "configs" mkdir configs
if not exist "certs" mkdir certs
if not exist "data" mkdir data
if not exist "downloads" mkdir downloads
if not exist "logs" mkdir logs
if not exist "downloads\configs" mkdir downloads\configs
if not exist "downloads\certificates" mkdir downloads\certificates
if not exist "downloads\docs" mkdir downloads\docs
echo [OK] Directory structure created

REM Generate configuration files
echo [INFO] Generating configuration files...
(
echo {
echo   "server": {
echo     "host": "0.0.0.0",
echo     "https_port": 8443,
echo     "read_timeout": "30s",
echo     "write_timeout": "30s",
echo     "ssl_enabled": true,
echo     "cert_file": "certs/server.crt",
echo     "key_file": "certs/server.key"
echo   },
echo   "application": {
echo     "name": "FileServer",
echo     "version": "4.0.0",
echo     "environment": "production",
echo     "protocol": "https"
echo   },
echo   "logging": {
echo     "level": "info",
echo     "format": "json"
echo   },
echo   "features": {
echo     "download_enabled": true,
echo     "cors_enabled": true,
echo     "auth_enabled": true,
echo     "ssl_enabled": true,
echo     "unified_file_download": true,
echo     "authenticated_downloads": true
echo   },
echo   "auth": {
echo     "token_expiry": "24h",
echo     "require_auth": true,
echo     "default_users": [
echo       {
echo         "tenant_id": "demo",
echo         "username": "admin",
echo         "description": "Administrator Account"
echo       },
echo       {
echo         "tenant_id": "demo",
echo         "username": "user1",
echo         "description": "Regular User Account"
echo       }
echo     ]
echo   },
echo   "downloads": {
echo     "base_directory": "downloads",
echo     "allowed_paths": [
echo       "configs/",
echo       "certificates/",
echo       "docs/"
echo     ],
echo     "supported_types": [".json", ".crt", ".key", ".txt", ".log", ".pem"]
echo   }
echo }
) > configs\config.json

echo [OK] Configuration files generated

REM Generate SSL certificates using PowerShell
echo [INFO] Generating SSL certificates...
powershell -Command "& {
    $ErrorActionPreference = 'SilentlyContinue'

    # Create self-signed certificate
    $cert = New-SelfSignedCertificate -DnsName 'localhost', 'fileserver.local' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(365)

    # Export certificate and private key
    $password = ConvertTo-SecureString -String 'fileserver' -Force -AsPlainText
    $certPath = 'certs\server.pfx'
    Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $password | Out-Null

    # Convert to PEM format if OpenSSL is available
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl pkcs12 -in $certPath -out 'certs\server.crt' -clcerts -nokeys -password pass:fileserver 2>`$null
        openssl pkcs12 -in $certPath -out 'certs\server.key' -nocerts -nodes -password pass:fileserver 2>`$null
        Remove-Item $certPath -Force

        # Generate certificate info
        $certInfo = @{
            subject = @{
                common_name = 'localhost'
                organization = @('FileServer')
                country = @('CN')
                province = @('Beijing')
                locality = @('Beijing')
            }
            validity = @{
                not_before = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssZ')
                not_after = (Get-Date).AddDays(365).ToString('yyyy-MM-ddTHH:mm:ssZ')
            }
            key_usage = @('Digital Signature', 'Key Encipherment')
            ext_key_usage = @('Server Authentication')
            dns_names = @('localhost', 'fileserver.local')
            ip_addresses = @('127.0.0.1', '::1')
            key_size = 2048
            signature_algorithm = 'SHA256-RSA'
            files = @{
                certificate = 'server.crt'
                private_key = 'server.key'
            }
        }
        $certInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath 'certs\cert_info.json' -Encoding UTF8

        Write-Host '[OK] SSL certificates generated'
    } else {
        Write-Host '[WARNING] OpenSSL not installed, using default PFX format certificate'
        Write-Host '   Please manually convert to PEM format or install OpenSSL'
    }

    # Remove from certificate store
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
}"

REM Create placeholder if certificate generation failed
if not exist "certs\server.crt" (
    echo [WARNING] Automatic certificate generation failed, please generate SSL certificates manually
    echo Please generate SSL certificates named server.crt and server.key in certs directory
    echo Or install OpenSSL and re-run this script

    REM Create placeholder hint file
    echo Please manually generate SSL certificates and place them in this directory > certs\README_CERT_NEEDED.txt
    echo Certificate file: server.crt >> certs\README_CERT_NEEDED.txt
    echo Private key file: server.key >> certs\README_CERT_NEEDED.txt
)

REM Prepare download files
echo [INFO] Preparing initial download files...
copy configs\config.json downloads\configs\ >nul 2>&1
copy certs\server.crt downloads\certificates\ >nul 2>&1
copy certs\server.key downloads\certificates\ >nul 2>&1
copy certs\cert_info.json downloads\certificates\ >nul 2>&1

REM Create API documentation
(
echo FileServer API Usage Guide
echo.
echo Basic Information:
echo - API Base URL: https://localhost:8443/api/v1
echo - Authentication: Bearer Token
echo - Protocol: HTTPS Only
echo.
echo Main Endpoints:
echo 1. Health Check: GET /health
echo 2. User Login: POST /auth/login
echo 3. Get Users: GET /auth/users
echo 4. File Download: GET /files/{path}
echo 5. User Logout: POST /auth/logout
echo.
echo Default Test Users:
echo - admin@demo ^(password: admin123^)
echo - user1@demo ^(password: password123^)
echo.
echo Usage Steps:
echo 1. Call /auth/users to get test user information
echo 2. Call /auth/login to login and get token
echo 3. Use token to access /files/* for file downloads
echo 4. Call /auth/logout to logout
echo.
echo PowerShell Example:
echo # Login
echo Invoke-WebRequest -Uri "https://localhost:8443/api/v1/auth/login" -Method POST -Body '{"tenant_id": "demo", "username": "admin", "password": "admin123"}' -ContentType "application/json" -SkipCertificateCheck
echo.
echo # Download file ^(use returned token^)
echo Invoke-WebRequest -Uri "https://localhost:8443/api/v1/files/configs/config.json" -Headers @{"Authorization"="Bearer YOUR_TOKEN"} -SkipCertificateCheck -OutFile "config.json"
echo.
echo Notes:
echo - All APIs require HTTPS access
echo - File downloads require user authentication
echo - Token valid for 24 hours
echo - Use -SkipCertificateCheck to skip SSL certificate verification ^(self-signed certificate^)
) > downloads\docs\api_guide.txt

echo [OK] Initial files prepared

REM Check if frontend code exists
if exist "frontend" (
    if exist "frontend\package.json" (
        echo [INFO] Frontend code detected, building complete service ^(frontend + backend^)...
    ) else (
        echo [WARNING] Frontend code not detected, building backend service only...
        echo [INFO] For complete functionality, ensure frontend directory exists with package.json
    )
) else (
    echo [WARNING] Frontend code not detected, building backend service only...
    echo [INFO] For complete functionality, ensure frontend directory exists with package.json
)

echo [INFO] Building FileServer application...

REM Start services
echo [INFO] Starting FileServer services...
docker compose up -d
if errorlevel 1 (
    echo [ERROR] Service startup failed
    docker compose logs
    pause
    exit /b 1
)

echo [INFO] Waiting for services to start...
timeout /t 10 /nobreak >nul

REM Check service status
echo [INFO] Checking service status...
docker compose ps | findstr "Up" >nul
if errorlevel 1 (
    echo [ERROR] Service startup failed, please check logs
    docker compose logs
    pause
    exit /b 1
)

echo [OK] Services started successfully!

REM Verify API access
echo [INFO] Verifying API access...
for /f %%i in ('powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "api_status=%%i"
if "%api_status%"=="200" (
    echo [OK] Backend API access normal
) else (
    echo [WARNING] Backend API temporarily unavailable, may still be starting
)

REM Check frontend
echo [INFO] Verifying frontend access...
for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "frontend_status=%%i"
if "%frontend_status%"=="200" (
    echo [OK] Frontend interface access normal
) else (
    echo [WARNING] Frontend interface temporarily unavailable, may still be starting
)

echo.
echo FileServer deployment completed!
echo =================================

REM Display service information
echo Frontend Interface: http://localhost:3000
echo Backend API: https://localhost:8443
echo Health Check: https://localhost:8443/api/v1/health
echo API Info: https://localhost:8443/api/v1
echo Default Users: https://localhost:8443/api/v1/auth/users
echo.
echo Recommended Access: http://localhost:3000 ^(Complete frontend interface^)
echo Direct API Access: https://localhost:8443/api/v1 ^(Pure API access^)

echo.
echo Management Commands:
echo   View logs: docker compose logs -f
echo   Stop services: docker compose down
echo   Restart services: docker compose restart
echo.
echo NOTE: Using self-signed certificates, browsers will show security warnings
echo Documentation: type docs\deployment-guide.md
echo.
echo Press any key to close this window...
pause >nul

endlocal