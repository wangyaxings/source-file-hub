#!/bin/bash

# ================================
# Secure File Hub - 目录初始化脚本
# ================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 配置变量
DEFAULT_DEPLOY_DIR="$HOME/secure-file-hub"
DEPLOY_DIR="${DEPLOY_DIR:-$DEFAULT_DEPLOY_DIR}"
USER_ID="${USER_ID:-1001}"
GROUP_ID="${GROUP_ID:-1001}"

# 显示帮助信息
show_help() {
    cat << EOF
Secure File Hub 目录初始化脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -d, --dir DIR           指定部署目录 (默认: $DEFAULT_DEPLOY_DIR)
    -u, --uid UID           指定用户ID (默认: $USER_ID)
    -g, --gid GID           指定组ID (默认: $GROUP_ID)
    --force                 强制重新创建目录
    --backup                备份现有目录

示例:
    $0                      # 标准初始化
    $0 -d /opt/filehub      # 初始化到指定目录
    $0 --backup             # 备份现有目录后初始化
    $0 --force              # 强制重新创建

EOF
}

# 检查目录是否存在
check_directory() {
    if [ -d "$DEPLOY_DIR" ]; then
        return 0
    else
        return 1
    fi
}

# 备份现有目录
backup_directory() {
    if check_directory; then
        local backup_dir="${DEPLOY_DIR}.backup.$(date +%Y%m%d_%H%M%S)"
        log_info "备份现有目录到: $backup_dir"

        if cp -r "$DEPLOY_DIR" "$backup_dir"; then
            log_success "目录备份完成"
        else
            log_error "目录备份失败"
            exit 1
        fi
    fi
}

# 创建目录结构
create_directories() {
    log_info "创建目录结构: $DEPLOY_DIR"

    # 创建主目录
    mkdir -p "$DEPLOY_DIR"

    # 创建子目录
    local subdirs=("data" "downloads" "logs" "configs" "certs" "scripts" "backups")

    for dir in "${subdirs[@]}"; do
        mkdir -p "$DEPLOY_DIR/$dir"
        log_info "创建目录: $DEPLOY_DIR/$dir"
    done

    # 设置权限
    chmod 755 "$DEPLOY_DIR"
    for dir in "${subdirs[@]}"; do
        chmod 755 "$DEPLOY_DIR/$dir"
    done

    log_success "目录结构创建完成"
}

# 设置目录权限
set_permissions() {
    log_info "设置目录权限..."

    # 设置所有者
    if command -v chown &> /dev/null; then
        chown -R "$USER_ID:$GROUP_ID" "$DEPLOY_DIR"
        log_success "设置所有者: $USER_ID:$GROUP_ID"
    else
        log_warning "chown 命令不可用，跳过权限设置"
    fi

    # 设置权限
    chmod -R 755 "$DEPLOY_DIR"

    # 设置特殊权限
    chmod 700 "$DEPLOY_DIR/certs"  # 证书目录更严格权限
    chmod 600 "$DEPLOY_DIR/configs"  # 配置文件目录

    log_success "权限设置完成"
}

# 创建默认配置文件
create_default_configs() {
    log_info "创建默认配置文件..."

    # 创建应用配置文件
    cat > "$DEPLOY_DIR/configs/app.yaml" << 'EOF'
# Secure File Hub 配置文件
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: true
    cert_file: "/app/certs/server.crt"
    key_file: "/app/certs/server.key"

database:
  path: "/app/data/fileserver.db"

logging:
  level: "info"
  file: "/app/logs/backend.log"
  max_size: 100
  max_backups: 3
  max_age: 28

auth:
  session_timeout: 3600
  totp_issuer: "Secure File Hub"
  password_min_length: 8

file:
  max_upload_size: 104857600  # 100MB
  allowed_extensions: [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar"]

security:
  enable_2fa: true
  require_2fa_for_admin: true
  max_login_attempts: 5
  lockout_duration: 900  # 15 minutes
EOF

    # 创建环境配置文件
    cat > "$DEPLOY_DIR/.env" << EOF
# Secure File Hub 环境配置
NODE_ENV=production
GO_ENV=production
NODE_TLS_REJECT_UNAUTHORIZED=0
DISABLE_HTTPS_REDIRECT=true

# 数据库配置
DB_PATH=/app/data/fileserver.db

# 前端配置
PORT=30000
HOSTNAME=0.0.0.0
NEXT_PUBLIC_API_URL=https://localhost:8443

# 后端配置
BACKEND_URL=https://localhost:8443

# 管理员配置
ADMIN_PASSWORD=admin123
EOF

    # 创建 Docker Compose 环境文件
    cat > "$DEPLOY_DIR/docker-compose.override.yml" << 'EOF'
# Docker Compose 覆盖配置
version: '3.8'

services:
  fileserver:
    environment:
      - DB_PATH=/app/data/fileserver.db
      - LOG_LEVEL=info
    volumes:
      # 确保数据目录存在
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
EOF

    log_success "默认配置文件创建完成"
}

# 创建启动脚本
create_startup_scripts() {
    log_info "创建启动脚本..."

    # 创建启动脚本
    cat > "$DEPLOY_DIR/start.sh" << 'EOF'
#!/bin/bash

# Secure File Hub 启动脚本
set -e

echo "Starting Secure File Hub..."

# 检查 Docker 是否运行
if ! docker info >/dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# 检查 docker-compose 文件
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found"
    exit 1
fi

# 启动服务
docker-compose up -d

echo "Secure File Hub started successfully!"
echo "Frontend: http://localhost:30000"
echo "Backend: https://localhost:8443"
EOF

    # 创建停止脚本
    cat > "$DEPLOY_DIR/stop.sh" << 'EOF'
#!/bin/bash

# Secure File Hub 停止脚本
set -e

echo "Stopping Secure File Hub..."

if [ -f "docker-compose.yml" ]; then
    docker-compose down
    echo "Secure File Hub stopped successfully!"
else
    echo "Error: docker-compose.yml not found"
    exit 1
fi
EOF

    # 创建重启脚本
    cat > "$DEPLOY_DIR/restart.sh" << 'EOF'
#!/bin/bash

# Secure File Hub 重启脚本
set -e

echo "Restarting Secure File Hub..."

if [ -f "docker-compose.yml" ]; then
    docker-compose down
    sleep 5
    docker-compose up -d
    echo "Secure File Hub restarted successfully!"
else
    echo "Error: docker-compose.yml not found"
    exit 1
fi
EOF

    # 创建日志查看脚本
    cat > "$DEPLOY_DIR/logs.sh" << 'EOF'
#!/bin/bash

# Secure File Hub 日志查看脚本
set -e

if [ -f "docker-compose.yml" ]; then
    docker-compose logs -f
else
    echo "Error: docker-compose.yml not found"
    exit 1
fi
EOF

    # 设置脚本权限
    chmod +x "$DEPLOY_DIR"/*.sh

    log_success "启动脚本创建完成"
}

# 创建备份脚本
create_backup_script() {
    log_info "创建备份脚本..."

    cat > "$DEPLOY_DIR/backup.sh" << 'EOF'
#!/bin/bash

# Secure File Hub 备份脚本
set -e

BACKUP_DIR="./backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="secure-file-hub-backup-$TIMESTAMP.tar.gz"

echo "Creating backup: $BACKUP_FILE"

# 创建备份目录
mkdir -p "$BACKUP_DIR"

# 停止服务
if [ -f "docker-compose.yml" ]; then
    echo "Stopping services for backup..."
    docker-compose down
fi

# 创建备份
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude='./backups' \
    --exclude='./logs/*.log' \
    --exclude='./data/*.db-journal' \
    .

# 重启服务
if [ -f "docker-compose.yml" ]; then
    echo "Restarting services..."
    docker-compose up -d
fi

echo "Backup completed: $BACKUP_DIR/$BACKUP_FILE"
EOF

    chmod +x "$DEPLOY_DIR/backup.sh"

    log_success "备份脚本创建完成"
}

# 验证目录结构
verify_structure() {
    log_info "验证目录结构..."

    local required_dirs=("data" "downloads" "logs" "configs" "certs" "scripts" "backups")
    local missing_dirs=()

    for dir in "${required_dirs[@]}"; do
        if [ ! -d "$DEPLOY_DIR/$dir" ]; then
            missing_dirs+=("$dir")
        fi
    done

    if [ ${#missing_dirs[@]} -eq 0 ]; then
        log_success "目录结构验证通过"
        return 0
    else
        log_error "缺少以下目录: ${missing_dirs[*]}"
        return 1
    fi
}

# 显示目录信息
show_directory_info() {
    log_info "目录信息:"
    echo "  部署目录: $DEPLOY_DIR"
    echo "  用户ID: $USER_ID"
    echo "  组ID: $GROUP_ID"
    echo ""
    echo "目录结构:"
    tree "$DEPLOY_DIR" 2>/dev/null || find "$DEPLOY_DIR" -type d | sed 's|[^/]*/|- |g'
    echo ""
    echo "可用脚本:"
    ls -la "$DEPLOY_DIR"/*.sh 2>/dev/null || echo "  无脚本文件"
}

# 主函数
main() {
    local force=false
    local backup=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -d|--dir)
                DEPLOY_DIR="$2"
                shift 2
                ;;
            -u|--uid)
                USER_ID="$2"
                shift 2
                ;;
            -g|--gid)
                GROUP_ID="$2"
                shift 2
                ;;
            --force)
                force=true
                shift
                ;;
            --backup)
                backup=true
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    log_info "开始初始化 Secure File Hub 目录..."

    # 检查目录是否存在
    if check_directory; then
        if [ "$force" = true ]; then
            log_warning "强制重新创建目录: $DEPLOY_DIR"
            rm -rf "$DEPLOY_DIR"
        elif [ "$backup" = true ]; then
            backup_directory
        else
            log_error "目录已存在: $DEPLOY_DIR"
            log_info "使用 --force 强制重新创建或 --backup 备份现有目录"
            exit 1
        fi
    fi

    # 创建目录结构
    create_directories
    set_permissions
    create_default_configs
    create_startup_scripts
    create_backup_script

    # 验证结构
    if verify_structure; then
        log_success "🎉 目录初始化完成！"
        show_directory_info
    else
        log_error "目录初始化失败"
        exit 1
    fi
}

# 执行主函数
main "$@"
