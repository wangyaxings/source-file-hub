#!/bin/bash

# ================================
# Secure File Hub - 快速部署脚本
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
REPO_URL="${REPO_URL:-https://github.com/wangyaxings/source-file-hub.git}"
DEPLOY_DIR="$HOME/$PROJECT_NAME"
IMAGE_TAG="${IMAGE_TAG:-ghcr.io/wangyaxings/source-file-hub:latest}"

# 显示横幅
show_banner() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    Secure File Hub                          ║
║                  快速部署脚本 v1.0.0                        ║
╚══════════════════════════════════════════════════════════════╝
EOF
}

# 显示帮助信息
show_help() {
    cat << EOF
Secure File Hub 快速部署脚本

用法: $0 [选项]

选项:
    -h, --help              显示此帮助信息
    -r, --repo URL          指定仓库URL (默认: $REPO_URL)
    -d, --dir DIR           指定部署目录 (默认: $DEPLOY_DIR)
    -i, --image IMAGE       指定镜像标签 (默认: $IMAGE_TAG)
    --dev                   开发环境部署
    --prod                  生产环境部署
    --update                更新现有部署
    --clean                 清理部署

示例:
    $0                      # 标准部署
    $0 --dev                # 开发环境部署
    $0 --prod               # 生产环境部署
    $0 --update             # 更新现有部署
    $0 --clean              # 清理部署

EOF
}

# 检查系统要求
check_requirements() {
    log_info "检查系统要求..."

    local missing_deps=()

    # 检查 Docker
    if ! command -v docker &> /dev/null; then
        missing_deps+=("docker")
    fi

    # 检查 Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        missing_deps+=("docker-compose")
    fi

    # 检查 Git
    if ! command -v git &> /dev/null; then
        missing_deps+=("git")
    fi

    # 检查 curl
    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_error "缺少以下依赖: ${missing_deps[*]}"
        log_info "请先安装缺少的依赖"
        exit 1
    fi

    # 检查 Docker 是否运行
    if ! docker info >/dev/null 2>&1; then
        log_error "Docker 未运行，请启动 Docker 服务"
        exit 1
    fi

    log_success "系统要求检查通过"
}

# 克隆或更新仓库
setup_repository() {
    log_info "设置代码仓库..."

    if [ -d "$DEPLOY_DIR" ]; then
        log_info "更新现有仓库..."
        cd "$DEPLOY_DIR"
        git pull origin main || git pull origin master
    else
        log_info "克隆仓库: $REPO_URL"
        git clone "$REPO_URL" "$DEPLOY_DIR"
        cd "$DEPLOY_DIR"
    fi

    log_success "代码仓库设置完成"
}

# 初始化目录结构
init_directories() {
    log_info "初始化目录结构..."

    cd "$DEPLOY_DIR"

    # 运行目录初始化脚本
    if [ -f "scripts/setup-directories.sh" ]; then
        chmod +x scripts/setup-directories.sh
        ./scripts/setup-directories.sh --force
    else
        # 手动创建目录
        mkdir -p data downloads logs configs certs
        chmod 755 data downloads logs configs certs
    fi

    log_success "目录结构初始化完成"
}

# 部署开发环境
deploy_dev() {
    log_info "部署开发环境..."

    cd "$DEPLOY_DIR"

    # 停止现有服务
    if [ -f "docker-compose.dev.yml" ]; then
        docker-compose -f docker-compose.dev.yml down || true
    fi

    # 构建并启动开发环境
    if [ -f "docker-compose.dev.yml" ]; then
        docker-compose -f docker-compose.dev.yml up -d --build
    else
        log_warning "未找到 docker-compose.dev.yml，使用标准配置"
        docker-compose up -d --build
    fi

    log_success "开发环境部署完成"
}

# 部署生产环境
deploy_prod() {
    log_info "部署生产环境..."

    cd "$DEPLOY_DIR"

    # 停止现有服务
    docker-compose down || true

    # 拉取最新镜像
    log_info "拉取镜像: $IMAGE_TAG"
    docker pull "$IMAGE_TAG"

    # 启动生产环境
    docker-compose up -d

    log_success "生产环境部署完成"
}

# 更新部署
update_deployment() {
    log_info "更新部署..."

    cd "$DEPLOY_DIR"

    # 更新代码
    git pull origin main || git pull origin master

    # 拉取最新镜像
    docker pull "$IMAGE_TAG"

    # 重启服务
    docker-compose down
    docker-compose up -d

    log_success "部署更新完成"
}

# 清理部署
clean_deployment() {
    log_info "清理部署..."

    cd "$DEPLOY_DIR"

    # 停止并删除容器
    docker-compose down -v || true

    # 删除镜像
    docker rmi "$IMAGE_TAG" || true

    # 清理未使用的资源
    docker system prune -f

    log_success "部署清理完成"
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

# 显示部署信息
show_deployment_info() {
    log_info "部署信息:"
    echo "  项目名称: $PROJECT_NAME"
    echo "  部署目录: $DEPLOY_DIR"
    echo "  镜像标签: $IMAGE_TAG"
    echo "  仓库地址: $REPO_URL"
    echo ""
    echo "可用命令:"
    echo "  cd $DEPLOY_DIR"
    echo "  docker-compose ps          # 查看服务状态"
    echo "  docker-compose logs -f     # 查看日志"
    echo "  docker-compose down        # 停止服务"
    echo "  docker-compose up -d       # 启动服务"
}

# 主函数
main() {
    local deploy_mode=""
    local update_mode=false
    local clean_mode=false

    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -r|--repo)
                REPO_URL="$2"
                shift 2
                ;;
            -d|--dir)
                DEPLOY_DIR="$2"
                shift 2
                ;;
            -i|--image)
                IMAGE_TAG="$2"
                shift 2
                ;;
            --dev)
                deploy_mode="dev"
                shift
                ;;
            --prod)
                deploy_mode="prod"
                shift
                ;;
            --update)
                update_mode=true
                shift
                ;;
            --clean)
                clean_mode=true
                shift
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 显示横幅
    show_banner

    # 执行相应操作
    if [ "$clean_mode" = true ]; then
        check_requirements
        clean_deployment
        exit 0
    fi

    if [ "$update_mode" = true ]; then
        check_requirements
        update_deployment
        wait_for_services
        health_check
        exit 0
    fi

    # 完整部署流程
    log_info "开始快速部署 Secure File Hub..."

    check_requirements
    setup_repository
    init_directories

    # 根据模式部署
    case $deploy_mode in
        "dev")
            deploy_dev
            ;;
        "prod")
            deploy_prod
            ;;
        *)
            # 默认生产环境部署
            deploy_prod
            ;;
    esac

    wait_for_services
    health_check
    show_deployment_info

    log_success "🎉 快速部署完成！"
}

# 执行主函数
main "$@"
