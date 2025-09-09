# ================================
# FileServer - Combined Frontend + Backend (Optimized)
# ================================

# 构建后端
FROM golang:1.23-alpine AS backend-builder

WORKDIR /app

# 安装必要的构建工具，包括GCC用于CGO
RUN apk add --no-cache git ca-certificates tzdata

# 复制依赖文件
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY cmd/ cmd/
COPY internal/ internal/

# 构建后端应用 - 启用CGO以支持SQLite
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags '-s -w' -o fileserver cmd/server/main.go

# ================================
# 构建前端
# ================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# 复制前端依赖文件
COPY frontend/package*.json frontend/yarn.lock ./

# 安装所有依赖（包括开发依赖）
RUN yarn install --frozen-lockfile

# 复制前端源代码
COPY frontend/ ./

# 构建前端应用
RUN yarn build

# 安装生产依赖到单独目录
RUN mkdir -p /tmp/prod-modules && \
    cd /tmp/prod-modules && \
    cp /app/frontend/package*.json /app/frontend/yarn.lock . && \
    yarn install --production --frozen-lockfile

# ================================
# 最终镜像
# ================================
FROM node:20-alpine

WORKDIR /app

# 安装运行时依赖，包括SQLite
RUN apk add --no-cache ca-certificates tzdata wget curl su-exec

# 创建非root用户和用户组
RUN addgroup -g 1001 -S nodejs && adduser -D -u 1001 -G nodejs -s /bin/sh -S nextjs

# 创建应用需要的目录结构
RUN mkdir -p data downloads configs certs logs && \
    mkdir -p downloads/configs downloads/certificates downloads/docs && \
    chown -R root:root data downloads configs certs logs && \
    chmod 755 data downloads configs certs logs

# 复制后端构建结果
COPY --from=backend-builder /app/fileserver /app/fileserver
RUN chmod +x /app/fileserver

# 创建前端目录并设置权限
RUN mkdir -p frontend && chown nextjs:nodejs frontend

# 复制前端构建结果和生产依赖
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/standalone ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/.next/static ./frontend/.next/static
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/server.js ./frontend/
COPY --from=frontend-builder --chown=nextjs:nodejs /app/frontend/package.json ./frontend/

# 复制预编译的生产依赖
COPY --from=frontend-builder --chown=nextjs:nodejs /tmp/prod-modules/node_modules ./frontend/node_modules

WORKDIR /app

# 创建启动脚本
RUN echo '#!/bin/sh' > start.sh && \
    echo '' >> start.sh && \
    echo '# 处理优雅关闭' >> start.sh && \
    echo 'cleanup() {' >> start.sh && \
    echo '    echo "Shutting down services..."' >> start.sh && \
    echo '    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true' >> start.sh && \
    echo '    wait $BACKEND_PID $FRONTEND_PID 2>/dev/null || true' >> start.sh && \
    echo '    exit 0' >> start.sh && \
    echo '}' >> start.sh && \
    echo '' >> start.sh && \
    echo 'trap cleanup SIGTERM SIGINT' >> start.sh && \
    echo '' >> start.sh && \
    echo '# 确保目录存在' >> start.sh && \
    echo 'mkdir -p data downloads configs certs logs' >> start.sh && \
    echo '' >> start.sh && \
    echo '# 启动后端服务' >> start.sh && \
    echo 'echo "Starting backend service..."' >> start.sh && \
    echo './fileserver &' >> start.sh && \
    echo 'BACKEND_PID=$!' >> start.sh && \
    echo '' >> start.sh && \
    echo '# 等待后端启动' >> start.sh && \
    echo 'sleep 5' >> start.sh && \
    echo '' >> start.sh && \
    echo '# 启动前端服务' >> start.sh && \
    echo 'echo "Starting frontend service..."' >> start.sh && \
    echo 'cd frontend' >> start.sh && \
    echo 'su-exec nextjs:nodejs node server.js &' >> start.sh && \
    echo 'FRONTEND_PID=$!' >> start.sh && \
    echo 'cd ..' >> start.sh && \
    echo '' >> start.sh && \
    echo 'echo "Both services started"' >> start.sh && \
    echo 'echo "Backend PID: $BACKEND_PID"' >> start.sh && \
    echo 'echo "Frontend PID: $FRONTEND_PID"' >> start.sh && \
    echo '' >> start.sh && \
    echo '# 等待服务' >> start.sh && \
    echo 'wait $BACKEND_PID $FRONTEND_PID' >> start.sh

# 给启动脚本添加执行权限
RUN chmod +x start.sh

# 环境变量
ENV NODE_ENV=production
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
ENV GO_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
ENV BACKEND_URL=https://localhost:8443

# 暴露端口
EXPOSE 3000 8443

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD (wget --no-check-certificate --quiet --tries=1 --spider https://localhost:8443/api/v1/health) && \
        wget --no-check-certificate --quiet --tries=1 --spider https://localhost:3000

# 运行启动脚本
CMD ["./start.sh"]
