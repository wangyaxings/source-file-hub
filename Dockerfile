# ================================
# Secure File Hub - Optimized Single Container
# ================================

# ================================
# 后端构建阶段
# ================================
FROM golang:1.23-alpine AS backend-builder

# 元数据
LABEL maintainer="Secure File Hub Team"
LABEL description="Secure File Hub - Backend Builder"

WORKDIR /build

# 安装构建依赖
RUN apk add --no-cache git ca-certificates tzdata upx

# 复制依赖文件并下载
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# 复制源代码
COPY cmd/ cmd/
COPY internal/ internal/

# 构建后端应用
# 禁用CGO以创建静态二进制文件，减小镜像大小
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags '-s -w -extldflags "-static"' \
    -tags 'netgo osusergo' \
    -o fileserver \
    cmd/server/main.go

# 使用UPX压缩二进制文件以进一步减小大小
RUN upx --best --lzma fileserver

# ================================
# 前端构建阶段
# ================================
FROM node:20-alpine AS frontend-builder

# 元数据
LABEL description="Secure File Hub - Frontend Builder"

WORKDIR /build

# 复制依赖文件
COPY frontend/package*.json frontend/yarn.lock ./

# 安装依赖（使用yarn缓存优化）
RUN yarn install --frozen-lockfile --prefer-offline --network-timeout 600000

# 复制源代码
COPY frontend/ ./

# 设置构建时环境变量
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

# 构建前端应用
RUN yarn build

# 创建生产依赖目录（优化镜像大小）
RUN mkdir -p /tmp/prod-deps && \
    cd /tmp/prod-deps && \
    cp ../package*.json ../yarn.lock . && \
    yarn install --production --frozen-lockfile --prefer-offline

# ================================
# 运行时镜像
# ================================
FROM alpine:3.18

# 元数据
LABEL maintainer="Secure File Hub Team"
LABEL description="Secure File Hub - Production Runtime"
LABEL version="1.0.0"

WORKDIR /app

# 安装最小运行时依赖
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    wget \
    dumb-init \
    libgcc \
    && rm -rf /var/cache/apk/*

# 创建专用用户和组（安全最佳实践）
RUN addgroup -g 1001 -S appgroup && \
    adduser -D -u 1001 -G appgroup -s /sbin/nologin -S appuser

# 创建应用目录结构
RUN mkdir -p \
    data \
    downloads \
    configs \
    certs \
    logs \
    frontend \
    && chown -R appuser:appgroup /app && \
    chmod 755 /app && \
    chmod 755 data downloads configs certs logs frontend

# 复制后端二进制文件
COPY --from=backend-builder --chown=appuser:appgroup /build/fileserver /app/fileserver
RUN chmod +x /app/fileserver

# 复制前端应用
COPY --from=frontend-builder --chown=appuser:appgroup /build/.next/standalone /app/frontend/
COPY --from=frontend-builder --chown=appuser:appgroup /build/.next/static /app/frontend/.next/static/
COPY --from=frontend-builder --chown=appuser:appgroup /build/server.js /app/frontend/
COPY --from=frontend-builder --chown=appuser:appgroup /build/package.json /app/frontend/

# 复制生产依赖
COPY --from=frontend-builder --chown=appuser:appgroup /tmp/prod-deps/node_modules /app/frontend/node_modules/

# 创建优化的启动脚本
COPY --chown=appuser:appgroup <<EOF /app/start.sh
#!/bin/sh
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "\${BLUE}[INFO]\${NC} \$(date '+%Y-%m-%d %H:%M:%S') - \$1"
}

log_error() {
    echo -e "\${RED}[ERROR]\${NC} \$(date '+%Y-%m-%d %H:%M:%S') - \$1" >&2
}

log_success() {
    echo -e "\${GREEN}[SUCCESS]\${NC} \$(date '+%Y-%m-%d %H:%M:%S') - \$1"
}

# 优雅关闭处理
cleanup() {
    log_info "Received shutdown signal, stopping services..."
    if [ ! -z "\$BACKEND_PID" ]; then
        kill -TERM \$BACKEND_PID 2>/dev/null || true
    fi
    if [ ! -z "\$FRONTEND_PID" ]; then
        kill -TERM \$FRONTEND_PID 2>/dev/null || true
    fi
    log_info "Services stopped"
    exit 0
}

# 设置信号处理器
trap cleanup TERM INT

# 验证环境
check_environment() {
    log_info "Validating environment..."

    # 检查必要目录
    for dir in data downloads configs certs logs; do
        if [ ! -d "\$dir" ]; then
            mkdir -p "\$dir"
            log_info "Created directory: \$dir"
        fi
    done

    # 检查二进制文件
    if [ ! -x "./fileserver" ]; then
        log_error "Backend binary not found or not executable"
        exit 1
    fi

    # 检查前端文件
    if [ ! -f "./frontend/server.js" ]; then
        log_error "Frontend server.js not found"
        exit 1
    fi

    log_success "Environment validation complete"
}

# 启动后端服务
start_backend() {
    log_info "Starting backend service..."

    # 设置后端环境变量
    export GO_ENV=production
    export DISABLE_HTTPS_REDIRECT=true

    # 启动后端服务
    ./fileserver &
    BACKEND_PID=\$!

    log_success "Backend started with PID: \$BACKEND_PID"

    # 等待后端健康检查
    log_info "Waiting for backend to be ready..."
    for i in \$(seq 1 30); do
        if curl -f -k https://localhost:8443/api/v1/health >/dev/null 2>&1; then
            log_success "Backend is ready"
            return 0
        fi
        sleep 2
    done

    log_error "Backend failed to start within 60 seconds"
    return 1
}

# 启动前端服务
start_frontend() {
    log_info "Starting frontend service..."

    # 设置前端环境变量
    export NODE_ENV=production
    export NODE_TLS_REJECT_UNAUTHORIZED=0
    export PORT=30000
    export HOSTNAME=0.0.0.0

    # 切换到前端目录
    cd frontend

    # 启动前端服务
    node server.js &
    FRONTEND_PID=\$!

    cd ..
    log_success "Frontend started with PID: \$FRONTEND_PID"

    # 等待前端健康检查
    log_info "Waiting for frontend to be ready..."
    for i in \$(seq 1 30); do
        if curl -f http://localhost:30000 >/dev/null 2>&1; then
            log_success "Frontend is ready"
            return 0
        fi
        sleep 2
    done

    log_error "Frontend failed to start within 60 seconds"
    return 1
}

# 主函数
main() {
    log_info "======================================="
    log_info "Starting Secure File Hub"
    log_info "======================================="

    check_environment

    # 启动服务
    start_backend || exit 1
    start_frontend || exit 1

    log_success "All services started successfully!"
    log_info "======================================="
    log_info "Secure File Hub is running:"
    log_info "  Frontend: http://localhost:30000"
    log_info "  Backend:  https://localhost:8443"
    log_info "======================================="

    # 等待进程结束
    wait \$BACKEND_PID \$FRONTEND_PID
}

# 执行主函数
main "\$@"
EOF

# 设置脚本权限
RUN chmod +x /app/start.sh

# 环境变量配置
ENV NODE_ENV=production \
    GO_ENV=production \
    NODE_TLS_REJECT_UNAUTHORIZED=0 \
    PORT=30000 \
    HOSTNAME=0.0.0.0 \
    BACKEND_URL=https://localhost:8443 \
    DISABLE_HTTPS_REDIRECT=true

# 暴露端口
EXPOSE 30000 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f -k https://localhost:8443/api/v1/health >/dev/null && \
        curl -f http://localhost:30000 >/dev/null

# 使用非root用户运行
USER appuser

# 启动命令
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/app/start.sh"]
