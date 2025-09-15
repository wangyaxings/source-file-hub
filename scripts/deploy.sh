#!/bin/bash

# ================================
# Secure File Hub - 部署脚本
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
PROJECT_NAME="secure-file-hub"
DEPLOY_DIR="$HOME/$PROJECT_NAME"
IMAGE_TAG="${IMAGE_TAG:-ghcr.io/wangyaxings/source-file-hub:latest}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

# 显示帮助信息
show_help() {
    cat << EOF
Secure File Hub 部署脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -d, --dir DIR           指定部署目录 (默认: $DEPLOY_DIR)
    -i, --image IMAGE       指定镜像标签 (默认: $IMAGE_TAG)
    -f, --file FILE         指定 compose 文件 (默认: $COMPOSE_FILE)
    -c, --clean             清理部署 (停止并删除容器)
    -s, --setup             仅设置目录结构
    -l, --logs              显示容器日志
    -r, --restart           重启服务
    --health                执行健康检查

示例:
    $0                      # 标准部署
    $0 -d /opt/filehub      # 部署到指定目录
    $0 -i myregistry/filehub:v1.0.0  # 使用指定镜像
    $0 -c                   # 清理部署
    $0 --health             # 健康检查

EOF
}

# 检查依赖
check_dependencies() {
    log_info "检查系统依赖..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker 未安装，请先安装 Docker"
        exit 1
    fi

    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose 未安装，请先安装 Docker Compose"
        exit 1
    fi

    if ! command -v curl &> /dev/null; then
        log_warning "curl 未安装，健康检查可能失败"
    fi

    log_success "依赖检查完成"
}

# 创建目录结构
setup_directories() {
    log_info "创建目录结构..."

    # 创建主目录
    mkdir -p "$DEPLOY_DIR"
    cd "$DEPLOY_DIR"

    # 创建子目录
    mkdir -p data downloads logs configs certs

    # 设置权限
    chmod 755 data downloads logs configs certs

    # 创建必要的配置文件（如果不存在）
    if [ ! -f configs/app.yaml ]; then
        log_info "创建默认配置文件..."
        cat > configs/app.yaml << 'EOF'
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

auth:
  session_timeout: 3600
  totp_issuer: "Secure File Hub"
EOF
    fi

    log_success "目录结构创建完成"
}

# 复制配置文件
copy_config_files() {
    log_info "复制配置文件..."

    # 复制 docker-compose 文件
    if [ -f "$(dirname "$0")/../docker-compose.yml" ]; then
        cp "$(dirname "$0")/../docker-compose.yml" "$DEPLOY_DIR/"
        log_success "复制 docker-compose.yml"
    fi

    if [ -f "$(dirname "$0")/../docker-compose.clean.yml" ]; then
        cp "$(dirname "$0")/../docker-compose.clean.yml" "$DEPLOY_DIR/"
        log_success "复制 docker-compose.clean.yml"
    fi

    # 复制配置文件
    if [ -d "$(dirname "$0")/../configs" ]; then
        cp -r "$(dirname "$0")/../configs/"* "$DEPLOY_DIR/configs/" 2>/dev/null || true
        log_success "复制配置文件"
    fi

    # 复制证书文件
    if [ -d "$(dirname "$0")/../certs" ]; then
        cp -r "$(dirname "$0")/../certs/"* "$DEPLOY_DIR/certs/" 2>/dev/null || true
        log_success "复制证书文件"
    fi
}

# 停止现有服务
stop_services() {
    log_info "停止现有服务..."

    cd "$DEPLOY_DIR"

    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" down || true
        log_success "服务已停止"
    else
        log_warning "未找到 $COMPOSE_FILE 文件"
    fi
}

# 拉取镜像
pull_image() {
    log_info "拉取镜像: $IMAGE_TAG"

    if docker pull "$IMAGE_TAG"; then
        log_success "镜像拉取成功"
    else
        log_error "镜像拉取失败"
        exit 1
    fi
}

# 启动服务
start_services() {
    log_info "启动服务..."

    cd "$DEPLOY_DIR"

    # 更新镜像标签
    if [ -f "$COMPOSE_FILE" ]; then
        # 使用 sed 替换镜像标签
        sed -i.bak "s|image:.*|image: $IMAGE_TAG|g" "$COMPOSE_FILE"
        log_info "更新镜像标签为: $IMAGE_TAG"
    fi

    # 启动服务
    if docker-compose -f "$COMPOSE_FILE" up -d; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        exit 1
    fi
}

# 等待服务启动
wait_for_services() {
    log_info "等待服务启动..."

    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if curl -f -k https://localhost:8443/api/v1/health >/dev/null 2>&1; then
            log_success "后端服务已就绪"
            break
        fi

        if [ $attempt -eq $max_attempts ]; then
            log_error "后端服务启动超时"
            return 1
        fi

        echo -n "."
        sleep 2
        ((attempt++))
    done

    attempt=1
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:30000 >/dev/null 2>&1; then
            log_success "前端服务已就绪"
            break
        fi

        if [ $attempt -eq $max_attempts ]; then
            log_error "前端服务启动超时"
            return 1
        fi

        echo -n "."
        sleep 2
        ((attempt++))
    done
}

# 健康检查
health_check() {
    log_info "执行健康检查..."

    local backend_ok=false
    local frontend_ok=false

    # 检查后端
    if curl -f -k https://localhost:8443/api/v1/health >/dev/null 2>&1; then
        log_success "✅ 后端健康检查通过"
        backend_ok=true
    else
        log_error "❌ 后端健康检查失败"
    fi

    # 检查前端
    if curl -f http://localhost:30000 >/dev/null 2>&1; then
        log_success "✅ 前端健康检查通过"
        frontend_ok=true
    else
        log_error "❌ 前端健康检查失败"
    fi

    if [ "$backend_ok" = true ] && [ "$frontend_ok" = true ]; then
        log_success "🎉 所有服务健康检查通过！"
        echo ""
        echo "访问地址:"
        echo "  前端: http://localhost:30000"
        echo "  后端: https://localhost:8443"
        echo ""
        echo "默认管理员账户: demo/admin (密码: admin123)"
        return 0
    else
        log_error "健康检查失败，请查看日志"
        return 1
    fi
}

# 显示日志
show_logs() {
    log_info "显示容器日志..."

    cd "$DEPLOY_DIR"

    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" logs -f
    else
        log_error "未找到 $COMPOSE_FILE 文件"
        exit 1
    fi
}

# 清理部署
clean_deployment() {
    log_info "清理部署..."

    cd "$DEPLOY_DIR"

    if [ -f "$COMPOSE_FILE" ]; then
        docker-compose -f "$COMPOSE_FILE" down -v
        log_success "容器和卷已清理"
    fi

    # 可选：删除镜像
    read -p "是否删除镜像? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        docker rmi "$IMAGE_TAG" || true
        log_success "镜像已删除"
    fi
}

# 重启服务
restart_services() {
    log_info "重启服务..."

    stop_services
    sleep 5
    start_services
    wait_for_services
    health_check
}

# 主函数
main() {
    local setup_only=false
    local clean_only=false
    local show_logs_only=false
    local restart_only=false
    local health_only=false

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
            -i|--image)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -f|--file)
                COMPOSE_FILE="$2"
                shift 2
                ;;
            -s|--setup)
                setup_only=true
                shift
                ;;
            -c|--clean)
                clean_only=true
                shift
                ;;
            -l|--logs)
                show_logs_only=true
                shift
                ;;
            -r|--restart)
                restart_only=true
                shift
                ;;
            --health)
                health_only=true
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 执行相应操作
    if [ "$setup_only" = true ]; then
        check_dependencies
        setup_directories
        copy_config_files
        log_success "目录设置完成"
        exit 0
    fi

    if [ "$clean_only" = true ]; then
        clean_deployment
        exit 0
    fi

    if [ "$show_logs_only" = true ]; then
        show_logs
        exit 0
    fi

    if [ "$restart_only" = true ]; then
        restart_services
        exit 0
    fi

    if [ "$health_only" = true ]; then
        health_check
        exit $?
    fi

    # 完整部署流程
    log_info "开始部署 Secure File Hub..."

    check_dependencies
    setup_directories
    copy_config_files
    stop_services
    pull_image
    start_services
    wait_for_services
    health_check

    log_success "🎉 部署完成！"
}

# 执行主函数
main "$@"