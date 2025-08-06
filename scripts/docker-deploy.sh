#!/bin/bash

# FileServer Docker部署自动化脚本
# 版本: 1.0.0

set -e

echo "🚀 FileServer Docker部署脚本"
echo "================================"

# 检查Docker和Docker Compose
echo "📋 检查环境依赖..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker未安装，请先安装Docker"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose未安装，请先安装Docker Compose"
    exit 1
fi

echo "✅ Docker环境检查通过"

# 创建目录结构
echo "📁 创建项目目录结构..."
mkdir -p {configs,certs,data,downloads,logs}
mkdir -p downloads/{configs,certificates,docs}
echo "✅ 目录结构创建完成"

# 生成配置文件
echo "⚙️ 生成配置文件..."
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
        "description": "管理员账户"
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "description": "普通用户账户"
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

echo "✅ 配置文件生成完成"

# 生成SSL证书
echo "🔐 生成SSL证书..."
if command -v openssl &> /dev/null; then
    # 生成私钥
    openssl genrsa -out certs/server.key 2048 2>/dev/null

    # 生成证书
    openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
        -subj "/C=CN/ST=Beijing/L=Beijing/O=FileServer/CN=localhost" \
        -addext "subjectAltName=DNS:localhost,DNS:fileserver.local,IP:127.0.0.1" 2>/dev/null

    # 生成证书信息
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

    echo "✅ SSL证书生成完成"
else
    echo "⚠️ OpenSSL未安装，将使用默认证书"
    echo "请手动生成SSL证书或安装OpenSSL"
fi

# 准备下载文件
echo "📄 准备初始下载文件..."
cp configs/config.json downloads/configs/ 2>/dev/null || true
cp certs/server.crt downloads/certificates/ 2>/dev/null || true
cp certs/server.key downloads/certificates/ 2>/dev/null || true
cp certs/cert_info.json downloads/certificates/ 2>/dev/null || true

# 创建API文档
cat > downloads/docs/api_guide.txt << 'EOF'
FileServer API 使用指南

基础信息:
- API Base URL: https://localhost:8443/api/v1
- 认证方式: Bearer Token
- 协议: HTTPS Only

主要接口:
1. 健康检查: GET /health
2. 用户登录: POST /auth/login
3. 获取用户: GET /auth/users
4. 文件下载: GET /files/{path}
5. 用户登出: POST /auth/logout

默认测试用户:
- admin@demo (密码: admin123)
- user1@demo (密码: password123)

使用步骤:
1. 调用 /auth/users 获取测试用户信息
2. 调用 /auth/login 登录获取token
3. 使用token访问 /files/* 下载文件
4. 调用 /auth/logout 登出

示例命令:
# 登录
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'

# 下载文件 (使用返回的token)
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

注意事项:
- 所有API都需要HTTPS访问
- 文件下载需要用户认证
- Token有效期24小时
- 使用 -k 参数跳过SSL证书验证(自签名证书)
EOF

echo "✅ 初始文件准备完成"

# 拉取Docker镜像
echo "📦 拉取Docker镜像..."
docker pull ghcr.io/wangyaxings/source-file-hub:latest
echo "✅ 镜像拉取完成"

# 检查是否存在前端代码
if [ -d "frontend" ] && [ -f "frontend/package.json" ]; then
    echo "🎨 检测到前端代码，将启动完整服务（前端+后端）..."
    COMPOSE_FILE="docker-compose.yml"

    # 创建前端Dockerfile
    if [ ! -f "frontend/Dockerfile" ]; then
        echo "📝 创建前端Dockerfile..."
        cat > frontend/Dockerfile << 'DOCKERFILE_EOF'
# Frontend Dockerfile for FileServer
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
WORKDIR /app

# Copy package files
COPY package.json yarn.lock* ./
RUN yarn install --frozen-lockfile

# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build the application
RUN yarn build

# Production image, copy all the files and run next
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NODE_TLS_REJECT_UNAUTHORIZED=0

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy the built application
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Copy the server.js for custom server
COPY --from=builder --chown=nextjs:nodejs /app/server.js ./
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./

# Install only production dependencies for custom server
RUN yarn install --production --frozen-lockfile

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Run the custom server
CMD ["node", "server.js"]
DOCKERFILE_EOF
        echo "✅ 前端Dockerfile创建完成"
    fi

    # 创建完整的docker-compose文件
    cat > docker-compose.complete.yml << 'COMPOSE_EOF'
version: '3.8'

services:
  # 后端服务 (使用预构建镜像)
  fileserver-backend:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: fileserver-backend
    ports:
      - "8443:8443"  # HTTPS端口
    volumes:
      # 持久化数据
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      # 配置文件 (只读)
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
    environment:
      - GO_ENV=production
      - DB_PATH=/app/data/fileserver.db
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fileserver-network

  # 前端服务 (本地构建)
  fileserver-frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    container_name: fileserver-frontend
    ports:
      - "3000:3000"  # 前端端口
    environment:
      - NODE_ENV=production
      - NEXT_PUBLIC_API_URL=https://fileserver-backend:8443
    depends_on:
      fileserver-backend:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge
COMPOSE_EOF
else
    echo "⚠️ 未检测到前端代码，仅启动后端服务..."
    COMPOSE_FILE="docker-compose.yml"
fi

# 启动服务
echo "🚀 启动FileServer服务..."
docker-compose -f $COMPOSE_FILE up -d

echo "⏳ 等待服务启动..."
sleep 10

# 检查服务状态
echo "🔍 检查服务状态..."
if docker-compose -f $COMPOSE_FILE ps | grep -q "Up"; then
    echo "✅ 服务启动成功！"

    # 验证API访问
    echo "🧪 验证API访问..."
    if curl -k -s https://localhost:8443/api/v1/health > /dev/null; then
        echo "✅ 后端API访问正常"
    else
        echo "⚠️ 后端API暂时无法访问，可能仍在启动中"
    fi

    # 如果启动了前端，也检查前端
    if [ "$COMPOSE_FILE" = "docker-compose.complete.yml" ]; then
        echo "🧪 验证前端访问..."
        if curl -s http://localhost:3000 > /dev/null; then
            echo "✅ 前端界面访问正常"
        else
            echo "⚠️ 前端界面暂时无法访问，可能仍在启动中"
        fi
    fi
else
    echo "❌ 服务启动失败，请检查日志"
    docker-compose -f $COMPOSE_FILE logs
    exit 1
fi

echo ""
echo "🎉 FileServer部署完成！"
echo "================================"

# 显示不同的服务信息
if [ "$COMPOSE_FILE" = "docker-compose.complete.yml" ]; then
    echo "🌐 前端界面: http://localhost:3000"
    echo "📡 后端API: https://localhost:8443"
    echo "🏥 健康检查: https://localhost:8443/api/v1/health"
    echo "📚 API信息: https://localhost:8443/api/v1"
    echo "👥 默认用户: https://localhost:8443/api/v1/auth/users"
    echo ""
    echo "🎯 推荐访问: http://localhost:3000 (完整前端界面)"
    echo "⚡ API直连: https://localhost:8443/api/v1 (纯API访问)"
else
    echo "📡 后端API: https://localhost:8443"
    echo "🏥 健康检查: https://localhost:8443/api/v1/health"
    echo "📚 API信息: https://localhost:8443/api/v1"
    echo "👥 默认用户: https://localhost:8443/api/v1/auth/users"
    echo ""
    echo "⚠️ 仅启动了后端服务，如需前端界面请在包含frontend目录的位置运行"
fi

echo ""
echo "📋 管理命令:"
echo "  查看日志: docker-compose -f $COMPOSE_FILE logs -f"
echo "  停止服务: docker-compose -f $COMPOSE_FILE down"
echo "  重启服务: docker-compose -f $COMPOSE_FILE restart"
echo ""
echo "⚠️ 注意: 使用自签名证书，浏览器会显示安全警告"
echo "📖 详细文档: cat docker-deployment-guide.md"