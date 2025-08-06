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
COPY frontend/package*.json frontend/yarn.lock ./

# 安装依赖
RUN yarn install --frozen-lockfile

# 复制前端源代码
COPY frontend/ ./

# 构建前端应用
RUN yarn build

# ================================
# 最终镜像
# ================================
FROM node:20-alpine

WORKDIR /app

# 安装运行时依赖
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    wget \
    curl \
    su-exec

# 创建非root用户和用户组
RUN addgroup -g 1001 nodejs && \
    adduser -D -u 1001 -G nodejs -s /bin/sh nextjs

# 创建后端需要的目录
RUN mkdir -p data downloads configs certs logs && \
    chown root:root data downloads configs certs logs

# 复制后端构建结果
COPY --from=backend-builder /app/fileserver /app/fileserver
RUN chmod +x /app/fileserver

# 复制默认配置文件
COPY configs/ configs/

# 创建前端目录并设置权限
RUN mkdir -p frontend && chown nextjs:nodejs frontend

# 复制前端构建结果
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/standalone ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/static ./frontend/.next/static

# 复制前端服务器文件
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/server.js ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/package.json ./frontend/

# 切换到frontend目录并安装生产依赖
WORKDIR /app/frontend
USER nextjs
RUN yarn install --production --frozen-lockfile
USER root

WORKDIR /app

# ================================
# 创建启动脚本
# ================================
RUN cat > start.sh << 'STARTEOF' && \
#!/bin/sh

# 处理优雅关闭的函数
cleanup() {
    echo "Shutting down services..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null
    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null
    exit 0
}

# 设置信号处理
trap cleanup SIGTERM SIGINT

# 启动后端服务
echo "Starting backend service..."
./fileserver &
BACKEND_PID=$!

# 启动前端服务
echo "Starting frontend service..."
cd frontend
su-exec nextjs:nodejs node server.js &
FRONTEND_PID=$!
cd ..

# 等待所有服务
echo "Both services started"
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"

# 保持脚本运行并等待任何服务退出
wait $BACKEND_PID $FRONTEND_PID
STARTEOF
chmod +x start.sh

# 环境变量
ENV NODE_ENV=production
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV GO_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# 暴露端口
EXPOSE 3000 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD (wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health && \
         wget --quiet --tries=1 --spider http://localhost:3000) || exit 1

# 运行启动脚本
CMD ["./start.sh"]