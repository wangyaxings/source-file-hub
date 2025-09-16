# ================================
# Secure File Hub - Optimized Single Container
# External volumes for data, logs, and database
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

# 接受构建参数
ARG VERSION=dev
ARG BUILD_TIME=unknown

# 构建后端应用
# 禁用CGO以创建静态二进制文件，减小镜像大小
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -extldflags '-static' -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
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
    cp /build/package*.json /build/yarn.lock . && \
    yarn install --production --frozen-lockfile --prefer-offline

# ================================
# 运行时镜像
# ================================
FROM alpine:3.18 AS runtime

# 元数据
LABEL maintainer="Secure File Hub Team"
LABEL description="Secure File Hub - Production Runtime with External Volumes"
LABEL version="2.0.0"

WORKDIR /app

# 安装最小运行时依赖
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    curl \
    wget \
    dumb-init \
    libgcc \
    sqlite \
    nodejs \
    npm \
    && rm -rf /var/cache/apk/*

# 创建专用用户和组（安全最佳实践）
RUN addgroup -g 1001 -S appgroup && \
    adduser -D -u 1001 -G appgroup -s /sbin/nologin -S appuser

# 创建应用目录结构
# 注意：data, logs, downloads 将作为外部卷挂载
RUN mkdir -p \
    /app/data \
    /app/downloads \
    /app/logs \
    /app/frontend \
    /app/configs \
    /app/certs \
    /app/scripts \
    && chown -R appuser:appgroup /app && \
    chmod 755 /app && \
    chmod 755 /app/data /app/downloads /app/logs /app/frontend /app/configs /app/certs /app/scripts

# 复制后端二进制文件
COPY --from=backend-builder --chown=appuser:appgroup /build/fileserver /app/fileserver
RUN chmod +x /app/fileserver

# 复制数据库初始化脚本
COPY --chown=appuser:appgroup scripts/init-clean-db.sql /app/scripts/
COPY --chown=appuser:appgroup scripts/init-database.sh /app/scripts/
RUN chmod +x /app/scripts/init-database.sh

# 复制前端应用
COPY --from=frontend-builder --chown=appuser:appgroup /build/.next/standalone /app/frontend/
COPY --from=frontend-builder --chown=appuser:appgroup /build/.next/static /app/frontend/.next/static/
COPY --from=frontend-builder --chown=appuser:appgroup /build/server.js /app/frontend/
COPY --from=frontend-builder --chown=appuser:appgroup /build/package.json /app/frontend/

# 复制生产依赖
COPY --from=frontend-builder --chown=appuser:appgroup /tmp/prod-deps/node_modules /app/frontend/node_modules/

# 复制启动脚本
COPY --chown=appuser:appgroup scripts/start.sh /app/start.sh

# 设置脚本权限
RUN chmod +x /app/start.sh

# 环境变量配置
ENV NODE_ENV=production \
    GO_ENV=production \
    NODE_TLS_REJECT_UNAUTHORIZED=0 \
    PORT=30000 \
    HOSTNAME=0.0.0.0 \
    BACKEND_URL=https://localhost:8443 \
    DISABLE_HTTPS_REDIRECT=true \
    DB_PATH=/app/data/fileserver.db \
    LOG_PATH=/app/logs \
    DOWNLOAD_PATH=/app/downloads

# 声明外部挂载卷（用于文档说明）
# 这些目录应该通过docker-compose或docker run -v参数挂载
VOLUME ["/app/data", "/app/logs", "/app/downloads"]

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
