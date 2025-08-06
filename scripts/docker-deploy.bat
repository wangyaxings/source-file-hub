@echo off
REM FileServer Docker部署自动化脚本 (Windows)
REM 版本: 1.0.0

setlocal enabledelayedexpansion
cd /d "%~dp0"

echo.
echo 🚀 FileServer Docker部署脚本
echo ================================
echo.

REM 检查Docker
echo 📋 检查环境依赖...
where docker >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker未安装，请先安装Docker Desktop
    echo 📥 下载地址: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

where docker-compose >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker Compose未安装，请确保Docker Desktop包含Compose
    pause
    exit /b 1
)

echo ✅ Docker环境检查通过

REM 创建目录结构
echo 📁 创建项目目录结构...
if not exist "configs" mkdir configs
if not exist "certs" mkdir certs
if not exist "data" mkdir data
if not exist "downloads" mkdir downloads
if not exist "logs" mkdir logs
if not exist "downloads\configs" mkdir downloads\configs
if not exist "downloads\certificates" mkdir downloads\certificates
if not exist "downloads\docs" mkdir downloads\docs
echo ✅ 目录结构创建完成

REM 生成配置文件
echo ⚙️ 生成配置文件...
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
echo         "description": "管理员账户"
echo       },
echo       {
echo         "tenant_id": "demo",
echo         "username": "user1",
echo         "description": "普通用户账户"
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

echo ✅ 配置文件生成完成

REM 生成SSL证书 (使用PowerShell)
echo 🔐 生成SSL证书...
powershell -Command "& {
    $ErrorActionPreference = 'SilentlyContinue'

    # 创建自签名证书
    $cert = New-SelfSignedCertificate -DnsName 'localhost', 'fileserver.local' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -NotAfter (Get-Date).AddDays(365)

    # 导出证书和私钥
    $password = ConvertTo-SecureString -String 'fileserver' -Force -AsPlainText
    $certPath = 'certs\server.pfx'
    Export-PfxCertificate -Cert $cert -FilePath $certPath -Password $password | Out-Null

    # 转换为PEM格式
    if (Get-Command openssl -ErrorAction SilentlyContinue) {
        openssl pkcs12 -in $certPath -out 'certs\server.crt' -clcerts -nokeys -password pass:fileserver 2>`$null
        openssl pkcs12 -in $certPath -out 'certs\server.key' -nocerts -nodes -password pass:fileserver 2>`$null
        Remove-Item $certPath -Force

        # 生成证书信息
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

        Write-Host '✅ SSL证书生成完成'
    } else {
        Write-Host '⚠️ OpenSSL未安装，使用默认PFX格式证书'
        Write-Host '   请手动转换为PEM格式或安装OpenSSL'
    }

    # 从证书存储中删除
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
}"

REM 如果PowerShell证书生成失败，创建占位符文件
if not exist "certs\server.crt" (
    echo ⚠️ 自动证书生成失败，请手动生成SSL证书
    echo 请将SSL证书命名为 server.crt 和 server.key 放在 certs 目录
    echo 或安装OpenSSL后重新运行此脚本

    REM 创建占位符提示文件
    echo 请手动生成SSL证书并放置在此目录 > certs\README_CERT_NEEDED.txt
    echo 证书文件: server.crt >> certs\README_CERT_NEEDED.txt
    echo 私钥文件: server.key >> certs\README_CERT_NEEDED.txt
)

REM 准备下载文件
echo 📄 准备初始下载文件...
copy configs\config.json downloads\configs\ >nul 2>&1
copy certs\server.crt downloads\certificates\ >nul 2>&1
copy certs\server.key downloads\certificates\ >nul 2>&1
copy certs\cert_info.json downloads\certificates\ >nul 2>&1

REM 创建API文档
(
echo FileServer API 使用指南
echo.
echo 基础信息:
echo - API Base URL: https://localhost:8443/api/v1
echo - 认证方式: Bearer Token
echo - 协议: HTTPS Only
echo.
echo 主要接口:
echo 1. 健康检查: GET /health
echo 2. 用户登录: POST /auth/login
echo 3. 获取用户: GET /auth/users
echo 4. 文件下载: GET /files/{path}
echo 5. 用户登出: POST /auth/logout
echo.
echo 默认测试用户:
echo - admin@demo ^(密码: admin123^)
echo - user1@demo ^(密码: password123^)
echo.
echo 使用步骤:
echo 1. 调用 /auth/users 获取测试用户信息
echo 2. 调用 /auth/login 登录获取token
echo 3. 使用token访问 /files/* 下载文件
echo 4. 调用 /auth/logout 登出
echo.
echo PowerShell示例:
echo # 登录
echo Invoke-WebRequest -Uri "https://localhost:8443/api/v1/auth/login" -Method POST -Body '{"tenant_id": "demo", "username": "admin", "password": "admin123"}' -ContentType "application/json" -SkipCertificateCheck
echo.
echo # 下载文件 ^(使用返回的token^)
echo Invoke-WebRequest -Uri "https://localhost:8443/api/v1/files/configs/config.json" -Headers @{"Authorization"="Bearer YOUR_TOKEN"} -SkipCertificateCheck -OutFile "config.json"
echo.
echo 注意事项:
echo - 所有API都需要HTTPS访问
echo - 文件下载需要用户认证
echo - Token有效期24小时
echo - 使用 -SkipCertificateCheck 跳过SSL证书验证^(自签名证书^)
) > downloads\docs\api_guide.txt

echo ✅ 初始文件准备完成

REM 拉取Docker镜像
echo 📦 拉取Docker镜像...
docker pull ghcr.io/wangyaxings/source-file-hub:latest
if errorlevel 1 (
    echo ❌ 镜像拉取失败，请检查网络连接
    pause
    exit /b 1
)
echo ✅ 镜像拉取完成

REM 检查是否存在前端代码
set "COMPOSE_FILE=docker-compose.yml"
if exist "frontend" (
    if exist "frontend\package.json" (
        echo 🎨 检测到前端代码，将启动完整服务（前端+后端）...
        set "COMPOSE_FILE=docker-compose.yml"

        REM 创建前端Dockerfile
        if not exist "frontend\Dockerfile" (
            echo 📝 创建前端Dockerfile...
            (
            echo # Frontend Dockerfile for FileServer
            echo FROM node:18-alpine AS base
            echo.
            echo # Install dependencies only when needed
            echo FROM base AS deps
            echo WORKDIR /app
            echo.
            echo # Copy package files
            echo COPY package.json yarn.lock* ./
            echo RUN yarn install --frozen-lockfile
            echo.
            echo # Rebuild the source code only when needed
            echo FROM base AS builder
            echo WORKDIR /app
            echo COPY --from=deps /app/node_modules ./node_modules
            echo COPY . .
            echo.
            echo # Build the application
            echo RUN yarn build
            echo.
            echo # Production image, copy all the files and run next
            echo FROM base AS runner
            echo WORKDIR /app
            echo.
            echo ENV NODE_ENV=production
            echo ENV NODE_TLS_REJECT_UNAUTHORIZED=0
            echo.
            echo RUN addgroup --system --gid 1001 nodejs
            echo RUN adduser --system --uid 1001 nextjs
            echo.
            echo # Copy the built application
            echo COPY --from=builder /app/public ./public
            echo COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
            echo COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
            echo.
            echo # Copy the server.js for custom server
            echo COPY --from=builder --chown=nextjs:nodejs /app/server.js ./
            echo COPY --from=builder --chown=nextjs:nodejs /app/package.json ./
            echo.
            echo # Install only production dependencies for custom server
            echo RUN yarn install --production --frozen-lockfile
            echo.
            echo USER nextjs
            echo.
            echo EXPOSE 3000
            echo.
            echo ENV PORT=3000
            echo ENV HOSTNAME="0.0.0.0"
            echo.
            echo # Run the custom server
            echo CMD ["node", "server.js"]
            ) > frontend\Dockerfile
            echo ✅ 前端Dockerfile创建完成
        )

        REM 创建完整的docker-compose文件
        (
        echo version: '3.8'
        echo.
        echo services:
        echo   # 后端服务 ^(使用预构建镜像^)
        echo   fileserver-backend:
        echo     image: ghcr.io/wangyaxings/source-file-hub:latest
        echo     container_name: fileserver-backend
        echo     ports:
        echo       - "8443:8443"  # HTTPS端口
        echo     volumes:
        echo       # 持久化数据
        echo       - ./data:/app/data
        echo       - ./downloads:/app/downloads
        echo       - ./logs:/app/logs
        echo       # 配置文件 ^(只读^)
        echo       - ./configs:/app/configs:ro
        echo       - ./certs:/app/certs:ro
        echo     environment:
        echo       - GO_ENV=production
        echo       - DB_PATH=/app/data/fileserver.db
        echo     restart: unless-stopped
        echo     healthcheck:
        echo       test: ["CMD-SHELL", "wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health ^|^| exit 1"]
        echo       interval: 30s
        echo       timeout: 10s
        echo       retries: 3
        echo       start_period: 40s
        echo     networks:
        echo       - fileserver-network
        echo.
        echo   # 前端服务 ^(本地构建^)
        echo   fileserver-frontend:
        echo     build:
        echo       context: ./frontend
        echo       dockerfile: Dockerfile
        echo     container_name: fileserver-frontend
        echo     ports:
        echo       - "3000:3000"  # 前端端口
        echo     environment:
        echo       - NODE_ENV=production
        echo       - NEXT_PUBLIC_API_URL=https://fileserver-backend:8443
        echo     depends_on:
        echo       fileserver-backend:
        echo         condition: service_healthy
        echo     restart: unless-stopped
        echo     networks:
        echo       - fileserver-network
        echo.
        echo networks:
        echo   fileserver-network:
        echo     driver: bridge
        ) > docker-compose.complete.yml
    ) else (
        echo ⚠️ 未检测到前端代码，仅启动后端服务...
    )
) else (
    echo ⚠️ 未检测到前端代码，仅启动后端服务...
)

REM 启动服务
echo 🚀 启动FileServer服务...
docker-compose -f %COMPOSE_FILE% up -d
if errorlevel 1 (
    echo ❌ 服务启动失败
    docker-compose -f docker-compose.simple.yml logs
    pause
    exit /b 1
)

echo ⏳ 等待服务启动...
timeout /t 10 /nobreak >nul

REM 检查服务状态
echo 🔍 检查服务状态...
docker-compose -f %COMPOSE_FILE% ps | findstr "Up" >nul
if errorlevel 1 (
    echo ❌ 服务启动失败，请检查日志
    docker-compose -f %COMPOSE_FILE% logs
    pause
    exit /b 1
)

echo ✅ 服务启动成功！

REM 验证API访问
echo 🧪 验证API访问...
for /f %%i in ('powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; (Invoke-WebRequest -Uri 'https://localhost:8443/api/v1/health' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "api_status=%%i"
if "%api_status%"=="200" (
    echo ✅ 后端API访问正常
) else (
    echo ⚠️ 后端API暂时无法访问，可能仍在启动中
)

REM 如果启动了前端，也检查前端
if "%COMPOSE_FILE%"=="docker-compose.complete.yml" (
    echo 🧪 验证前端访问...
    for /f %%i in ('powershell -Command "try { (Invoke-WebRequest -Uri 'http://localhost:3000' -TimeoutSec 5).StatusCode } catch { 0 }"') do set "frontend_status=%%i"
    if "!frontend_status!"=="200" (
        echo ✅ 前端界面访问正常
    ) else (
        echo ⚠️ 前端界面暂时无法访问，可能仍在启动中
    )
)

echo.
echo 🎉 FileServer部署完成！
echo ================================

REM 显示不同的服务信息
if "%COMPOSE_FILE%"=="docker-compose.complete.yml" (
    echo 🌐 前端界面: http://localhost:3000
    echo 📡 后端API: https://localhost:8443
    echo 🏥 健康检查: https://localhost:8443/api/v1/health
    echo 📚 API信息: https://localhost:8443/api/v1
    echo 👥 默认用户: https://localhost:8443/api/v1/auth/users
    echo.
    echo 🎯 推荐访问: http://localhost:3000 ^(完整前端界面^)
    echo ⚡ API直连: https://localhost:8443/api/v1 ^(纯API访问^)
) else (
    echo 📡 后端API: https://localhost:8443
    echo 🏥 健康检查: https://localhost:8443/api/v1/health
    echo 📚 API信息: https://localhost:8443/api/v1
    echo 👥 默认用户: https://localhost:8443/api/v1/auth/users
    echo.
    echo ⚠️ 仅启动了后端服务，如需前端界面请在包含frontend目录的位置运行
)

echo.
echo 📋 管理命令:
echo   查看日志: docker-compose -f %COMPOSE_FILE% logs -f
echo   停止服务: docker-compose -f %COMPOSE_FILE% down
echo   重启服务: docker-compose -f %COMPOSE_FILE% restart
echo.
echo ⚠️ 注意: 使用自签名证书，浏览器会显示安全警告
echo 📖 详细文档: type docker-deployment-guide.md
echo.
echo 按任意键关闭此窗口...
pause >nul

endlocal