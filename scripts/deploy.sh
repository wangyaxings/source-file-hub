#!/bin/bash

# ================================
# Secure File Hub - 部署脚本
# ================================

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 默认配置
DOCKER_REGISTRY="${DOCKER_REGISTRY:-localhost:5000}"
IMAGE_NAME="${IMAGE_NAME:-secure-file-hub}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
ENVIRONMENT="${ENVIRONMENT:-production}"
SKIP_BUILD="${SKIP_BUILD:-false}"

# 日志函数
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

# 显示帮助信息
show_help() {
    cat << EOF
Secure File Hub 部署脚本

用法: $0 [选项...]

选项:
  -r, --registry REGISTRY    Docker镜像仓库 (默认: localhost:5000)
  -n, --name NAME           镜像名称 (默认: secure-file-hub)
  -t, --tag TAG            镜像标签 (默认: latest)
  -e, --env ENV            部署环境 (默认: production)
  --skip-build             跳过镜像构建
  -h, --help               显示帮助信息

环境变量:
  DOCKER_REGISTRY          Docker镜像仓库
  IMAGE_NAME              镜像名称
  IMAGE_TAG               镜像标签
  ENVIRONMENT            部署环境

示例:
  $0                                    # 使用默认配置部署
  $0 -r registry.example.com -t v1.0.0  # 指定仓库和标签
  $0 --skip-build                      # 跳过构建，使用现有镜像
EOF
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--registry)
                DOCKER_REGISTRY="$2"
                shift 2
                ;;
            -n|--name)
                IMAGE_NAME="$2"
                shift 2
                ;;
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -e|--env)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "未知参数: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# 检查依赖
check_dependencies() {
    log_info "检查依赖..."

    local deps=("docker" "docker-compose")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "$dep 未安装或不在PATH中"
            exit 1
        fi
    done

    # 检查Docker是否运行
    if ! docker info &> /dev/null; then
        log_error "Docker daemon 未运行"
        exit 1
    fi

    log_success "依赖检查通过"
}

# 验证项目结构
validate_project() {
    log_info "验证项目结构..."

    local required_files=(
        "Dockerfile"
        "docker-compose.yml"
        "frontend/package.json"
        "go.mod"
        "configs"
        "certs"
    )

    for file in "${required_files[@]}"; do
        if [[ ! -e "$file" ]]; then
            log_error "缺少必需文件: $file"
            exit 1
        fi
    done

    log_success "项目结构验证通过"
}

# 构建Docker镜像
build_image() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "跳过镜像构建"
        return 0
    fi

    log_info "构建Docker镜像..."
    log_info "镜像: $DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"

    # 启用BuildKit以提高构建性能
    export DOCKER_BUILDKIT=1

    docker build \
        --target runtime \
        --tag "$DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG" \
        --label "build-date=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --label "version=$IMAGE_TAG" \
        --label "environment=$ENVIRONMENT" \
        .

    if [[ $? -eq 0 ]]; then
        log_success "镜像构建成功"
    else
        log_error "镜像构建失败"
        exit 1
    fi
}

# 推送镜像到仓库
push_image() {
    if [[ "$SKIP_BUILD" == "true" ]]; then
        log_info "跳过镜像推送"
        return 0
    fi

    log_info "推送镜像到仓库..."

    docker push "$DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"

    if [[ $? -eq 0 ]]; then
        log_success "镜像推送成功"
    else
        log_error "镜像推送失败"
        exit 1
    fi
}

# 停止现有服务
stop_services() {
    log_info "停止现有服务..."

    docker-compose down --remove-orphans

    log_success "服务已停止"
}

# 启动服务
start_services() {
    log_info "启动服务..."

    # 设置环境变量
    export IMAGE_NAME="$DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"

    # 启动服务
    docker-compose up -d

    if [[ $? -eq 0 ]]; then
        log_success "服务启动成功"
    else
        log_error "服务启动失败"
        exit 1
    fi
}

# 等待服务就绪
wait_for_services() {
    log_info "等待服务就绪..."

    local max_attempts=30
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        log_info "检查服务状态 (尝试 $attempt/$max_attempts)..."

        # 检查容器状态
        if docker-compose ps | grep -q "Up"; then
            log_success "服务已就绪"
            return 0
        fi

        sleep 10
        ((attempt++))
    done

    log_error "服务启动超时"
    exit 1
}

# 显示服务信息
show_service_info() {
    log_info "服务信息:"

    echo ""
    echo "======================================="
    echo "Secure File Hub 已部署成功!"
    echo "======================================="
    echo ""
    echo "服务地址:"
    echo "  前端: http://localhost:30000"
    echo "  后端: https://localhost:8443"
    echo ""
    echo "镜像信息:"
    echo "  名称: $DOCKER_REGISTRY/$IMAGE_NAME:$IMAGE_TAG"
    echo "  环境: $ENVIRONMENT"
    echo ""
    echo "查看服务状态: docker-compose ps"
    echo "查看服务日志: docker-compose logs -f"
    echo "停止服务: docker-compose down"
    echo "======================================="
}

# 清理函数
cleanup() {
    log_warning "收到中断信号，正在清理..."
    docker-compose down --remove-orphans 2>/dev/null || true
    exit 1
}

# 主函数
main() {
    # 设置清理函数
    trap cleanup INT TERM

    log_info "======================================="
    log_info "Secure File Hub 部署脚本"
    log_info "======================================="

    # 解析参数
    parse_args "$@"

    # 显示配置
    log_info "部署配置:"
    log_info "  镜像仓库: $DOCKER_REGISTRY"
    log_info "  镜像名称: $IMAGE_NAME"
    log_info "  镜像标签: $IMAGE_TAG"
    log_info "  环境: $ENVIRONMENT"
    log_info "  跳过构建: $SKIP_BUILD"

    # 执行部署步骤
    check_dependencies
    validate_project
    build_image
    push_image
    stop_services
    start_services
    wait_for_services
    show_service_info

    log_success "部署完成!"
}

# 执行主函数
main "$@"
