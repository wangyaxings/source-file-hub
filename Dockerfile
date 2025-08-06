# ================================
# FileServer - Combined Frontend + Backend
# ================================

# 构建后端
FROM golang:1.23-alpine AS backend-builder

WORKDIR /app

# 安装必要的构建工具
RUN apk add --no-cache git ca-certificates tzdata

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY cmd/ cmd/
COPY internal/ internal/

# 构建后端应用
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fileserver cmd/server/main.go

# ================================
# 构建前端
# ================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# 复制前端依赖文件
COPY frontend/package*.json ./
# 检查是否有 yarn.lock，如果有则复制
COPY frontend/yarn.loc[k] ./

# 安装依赖（检测使用 npm 还是 yarn）
RUN if [ -f yarn.lock ]; then \
        yarn install --frozen-lockfile; \
    else \
        npm ci; \
    fi

# 复制前端源代码
COPY frontend/ ./

# 构建前端应用
RUN if [ -f yarn.lock ]; then \
        yarn build; \
    else \
        npm run build; \
    fi

# ================================
# 最终镜像
# ================================
FROM node:20-alpine

WORKDIR /app

# 安装运行时依赖
RUN apk add --no-cache ca-certificates tzdata wget curl su-exec bash

# 创建非root用户和用户组
RUN addgroup -g 1001 -S nodejs && \
    adduser -D -u 1001 -G nodejs -s /bin/sh -S nextjs

# 创建应用需要的目录结构
RUN mkdir -p data downloads configs certs logs \
    downloads/configs downloads/certificates downloads/docs && \
    chown -R root:root data downloads configs certs logs && \
    chmod 755 data downloads configs certs logs

# 复制后端构建结果
COPY --from=backend-builder /app/fileserver /app/fileserver
RUN chmod +x /app/fileserver

# 复制配置文件（如果存在）
# 使用通配符模式，避免目录不存在时失败
COPY config[s]/ configs/

# 创建前端目录并设置权限
RUN mkdir -p frontend && chown nextjs:nodejs frontend

# 复制前端构建结果
# 检查是否是 standalone 模式
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/standalone ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/static ./frontend/.next/static

# 如果有 public 目录，也需要复制
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/public ./frontend/public

# 复制前端必要文件
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/server.js ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/package.json ./frontend/

# 如果不是 standalone 模式，需要复制 node_modules 和其他文件
# COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/node_modules ./frontend/node_modules
# COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next ./frontend/.next

# 创建启动脚本
RUN cat > /app/start.sh << 'SCRIPT_END'
#!/bin/bash
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# 处理优雅关闭
cleanup() {
    log_info "Shutting down services..."

    if [ ! -z "$BACKEND_PID" ]; then
        log_info "Stopping backend (PID: $BACKEND_PID)..."
        kill -TERM $BACKEND_PID 2>/dev/null || true
    fi

    if [ ! -z "$FRONTEND_PID" ]; then
        log_info "Stopping frontend (PID: $FRONTEND_PID)..."
        kill -TERM $FRONTEND_PID 2>/dev/null || true
    fi

    # 等待进程结束
    if [ ! -z "$BACKEND_PID" ]; then
        wait $BACKEND_PID 2>/dev/null || true
    fi

    if [ ! -z "$FRONTEND_PID" ]; then
        wait $FRONTEND_PID 2>/dev/null || true
    fi

    log_info "Shutdown complete"
    exit 0
}

# 注册信号处理
trap cleanup SIGTERM SIGINT SIGQUIT

# 确保必要的目录存在
log_info "Checking directories..."
for dir in data downloads configs certs logs; do
    if [ ! -d "$dir" ]; then
        log_warn "Creating missing directory: $dir"
        mkdir -p $dir
    fi
done

# 检查配置文件
if [ ! -f "configs/config.yaml" ] && [ ! -f "configs/config.json" ]; then
    log_warn "No configuration file found in configs/"
fi

# 启动后端服务
log_info "Starting backend service..."
./fileserver &
BACKEND_PID=$!
log_info "Backend started with PID: $BACKEND_PID"

# 等待后端启动
sleep 2

# 检查后端是否成功启动
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    log_error "Backend failed to start"
    exit 1
fi

# 启动前端服务
log_info "Starting frontend service..."
cd frontend

# 检查前端启动方式
if [ -f "server.js" ]; then
    # Next.js standalone 模式
    su-exec nextjs:nodejs node server.js &
    FRONTEND_PID=$!
elif [ -f "package.json" ]; then
    # 标准 Next.js 模式
    su-exec nextjs:nodejs npm start &
    FRONTEND_PID=$!
else
    log_error "No frontend server found"
    kill $BACKEND_PID
    exit 1
fi

cd ..
log_info "Frontend started with PID: $FRONTEND_PID"

# 等待前端启动
sleep 3

# 检查前端是否成功启动
if ! kill -0 $FRONTEND_PID 2>/dev/null; then
    log_error "Frontend failed to start"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

log_info "=========================================="}
log_info "Both services started successfully"
log_info "Backend PID: $BACKEND_PID (Port: 8443)"
log_info "Frontend PID: $FRONTEND_PID (Port: 3000)"
log_info "=========================================="}

# 监控服务状态
while true; do
    # 检查后端状态
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        log_error "Backend service crashed, restarting..."
        ./fileserver &
        BACKEND_PID=$!
        log_info "Backend restarted with PID: $BACKEND_PID"
    fi

    # 检查前端状态
    if ! kill -0 $FRONTEND_PID 2>/dev/null; then
        log_error "Frontend service crashed, restarting..."
        cd frontend
        su-exec nextjs:nodejs node server.js &
        FRONTEND_PID=$!
        cd ..
        log_info "Frontend restarted with PID: $FRONTEND_PID"
    fi

    # 每10秒检查一次
    sleep 10
done
SCRIPT_END

# 给启动脚本添加执行权限
RUN chmod +x /app/start.sh

# 创建健康检查脚本
RUN cat > /app/healthcheck.sh << 'HEALTH_END'
#!/bin/sh
set -e

# 检查后端健康状态
if ! wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health 2>/dev/null; then
    echo "Backend health check failed"
    exit 1
fi

# 检查前端健康状态
if ! wget --quiet --tries=1 --spider http://localhost:3000 2>/dev/null; then
    echo "Frontend health check failed"
    exit 1
fi

echo "Health check passed"
exit 0
HEALTH_END

RUN chmod +x /app/healthcheck.sh

# 环境变量
ENV NODE_ENV=production \
    NODE_TLS_REJECT_UNAUTHORIZED=0 \
    GO_ENV=production \
    PORT=3000 \
    BACKEND_PORT=8443 \
    HOSTNAME="0.0.0.0" \
    NEXT_TELEMETRY_DISABLED=1

# 暴露端口
EXPOSE 3000 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD /app/healthcheck.sh

# 使用 root 用户运行启动脚本（脚本内部会切换用户）
USER root

# 运行启动脚本
ENTRYPOINT ["/app/start.sh"]