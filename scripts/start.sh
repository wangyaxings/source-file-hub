#!/bin/sh
set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# 优雅关闭处理
cleanup() {
    log_info "Received shutdown signal, stopping services..."
    if [ ! -z "$BACKEND_PID" ]; then
        kill -TERM $BACKEND_PID 2>/dev/null || true
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill -TERM $FRONTEND_PID 2>/dev/null || true
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
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            log_info "Created directory: $dir"
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

# 初始化数据库
init_database() {
    log_info "Initializing database..."

    # 设置环境变量
    export DB_PATH="/app/data/fileserver.db"
    export INIT_SCRIPT="/app/scripts/init-clean-db.sql"
    export BACKUP_DIR="/app/data/backups"

    # 运行数据库初始化脚本
    if [ -f "/app/scripts/init-database.sh" ]; then
        if /app/scripts/init-database.sh; then
            log_success "Database initialized successfully"
        else
            log_error "Database initialization failed"
            exit 1
        fi
    else
        log_error "Database initialization script not found"
        exit 1
    fi
}

# 启动后端服务
start_backend() {
    log_info "Starting backend service..."

    # 设置后端环境变量
    export GO_ENV=production
    export DISABLE_HTTPS_REDIRECT=true

    # 启动后端服务
    ./fileserver &
    BACKEND_PID=$!

    log_success "Backend started with PID: $BACKEND_PID"

    # 等待后端健康检查
    log_info "Waiting for backend to be ready..."
    for i in $(seq 1 30); do
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
    FRONTEND_PID=$!

    cd ..
    log_success "Frontend started with PID: $FRONTEND_PID"

    # 等待前端健康检查
    log_info "Waiting for frontend to be ready..."
    for i in $(seq 1 30); do
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
    log_info "Starting File Hub"
    log_info "======================================="

    check_environment
    init_database

    # 启动服务
    start_backend || exit 1
    start_frontend || exit 1

    log_success "All services started successfully!"
    log_info "======================================="
    log_info "File Hub is running:"
    log_info "  Frontend: http://localhost:30000"
    log_info "  Backend:  https://localhost:8443"
    log_info "======================================="

    # 等待进程结束
    wait $BACKEND_PID $FRONTEND_PID
}

# 执行主函数
main "$@"
