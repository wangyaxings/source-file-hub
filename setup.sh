#!/bin/bash

# Secure File Hub - 快速部署脚本
# 用于在 Ubuntu 系统上快速部署 Secure File Hub

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# 检查是否为 root 用户
check_user() {
    if [[ $EUID -eq 0 ]]; then
        log_error "请不要使用 root 用户运行此脚本"
        exit 1
    fi
}

# 检查 Docker 是否已安装
check_docker() {
    log_info "检查 Docker 安装状态..."

    if ! command -v docker &> /dev/null; then
        log_warning "Docker 未安装，正在安装..."
        install_docker
    else
        log_success "Docker 已安装: $(docker --version)"
    fi

    if ! command -v docker-compose &> /dev/null; then
        log_warning "Docker Compose 未安装，正在安装..."
        install_docker_compose
    else
        log_success "Docker Compose 已安装: $(docker-compose --version)"
    fi
}

# 安装 Docker
install_docker() {
    log_info "更新系统包..."
    sudo apt update

    log_info "安装 Docker..."
    sudo apt install -y docker.io

    log_info "启动 Docker 服务..."
    sudo systemctl start docker
    sudo systemctl enable docker

    log_info "将当前用户添加到 docker 组..."
    sudo usermod -aG docker $USER

    log_success "Docker 安装完成"
    log_warning "请重新登录或运行 'newgrp docker' 使组权限生效"
}

# 安装 Docker Compose
install_docker_compose() {
    log_info "安装 Docker Compose..."
    sudo apt install -y docker-compose
    log_success "Docker Compose 安装完成"
}

# 创建项目目录结构
create_directories() {
    log_info "创建项目目录结构..."

    mkdir -p data downloads logs configs certs

    log_success "目录结构创建完成"
}

# 生成 SSL 证书
generate_certificates() {
    log_info "生成 SSL 证书..."

    cd certs

    # 生成私钥
    openssl genrsa -out server.key 2048

    # 生成证书签名请求
    openssl req -new -key server.key -out server.csr \
        -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"

    # 生成自签名证书
    openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

    # 删除临时文件
    rm server.csr

    # 设置权限
    chmod 600 server.key
    chmod 644 server.crt

    cd ..

    log_success "SSL 证书生成完成"
}

# 创建配置文件
create_config() {
    log_info "创建应用配置文件..."

    cat > configs/app.yaml << 'EOF'
server:
  host: 0.0.0.0
  port: 8443
  tls:
    cert_file: certs/server.crt
    key_file: certs/server.key

database:
  driver: sqlite
  database: data/fileserver.db

security: {}
storage: {}
EOF

    log_success "配置文件创建完成"
}

# 权限配置
declare -A PERMISSIONS=(
    ["data"]="755:1001:1001"
    ["downloads"]="755:1001:1001"
    ["logs"]="755:1001:1001"
    ["configs"]="644:root:root"
    ["certs"]="600:root:root"
)

# 设置单个目录权限
set_directory_permission() {
    local dir=$1
    local permission_config=$2

    IFS=':' read -r mode owner group <<< "$permission_config"

    log_info "设置 $dir 目录权限: $mode $owner:$group"

    # 设置所有者
    if sudo chown -R $owner:$group "$dir" 2>/dev/null; then
        log_success "$dir 所有者设置为 $owner:$group"
    else
        log_warning "无法设置 $dir 所有者，尝试使用当前用户"
        current_user=$(whoami)
        current_group=$(id -gn)
        chown -R $current_user:$current_group "$dir" 2>/dev/null || {
            log_warning "无法更改 $dir 所有者"
        }
    fi

    # 设置权限
    if chmod -R $mode "$dir" 2>/dev/null; then
        log_success "$dir 权限设置为 $mode"
    else
        log_warning "无法设置 $dir 权限"
    fi
}

# 显示权限状态
show_permission_status() {
    log_info "当前目录权限状态:"
    echo "目录    权限    所有者"
    echo "------------------------"

    for dir in "${!PERMISSIONS[@]}"; do
        if [[ -d "$dir" ]]; then
            perm=$(ls -ld "$dir" | cut -d' ' -f1)
            owner=$(ls -ld "$dir" | awk '{print $3":"$4}')
            printf "%-10s %-8s %s\n" "$dir" "$perm" "$owner"
        else
            printf "%-10s %-8s %s\n" "$dir" "不存在" "-"
        fi
    done
}

# 验证权限设置
validate_permissions() {
    log_info "验证权限设置..."
    local all_good=true

    for dir in "${!PERMISSIONS[@]}"; do
        if [[ -d "$dir" ]]; then
            IFS=':' read -r expected_mode expected_owner expected_group <<< "${PERMISSIONS[$dir]}"

            # 检查权限
            actual_perm=$(ls -ld "$dir" | cut -d' ' -f1)
            actual_owner=$(ls -ld "$dir" | awk '{print $3}')
            actual_group=$(ls -ld "$dir" | awk '{print $4}')

            # 验证权限模式（只检查最后3位）
            expected_perm_suffix=${expected_mode: -3}
            actual_perm_suffix=${actual_perm: -3}

            if [[ "$actual_perm_suffix" == "$expected_perm_suffix" ]]; then
                log_success "$dir 权限正确: $actual_perm"
            else
                log_warning "$dir 权限不匹配: 期望 $expected_mode，实际 $actual_perm"
                all_good=false
            fi
        else
            log_warning "$dir 目录不存在"
            all_good=false
        fi
    done

    if $all_good; then
        log_success "所有目录权限验证通过"
        return 0
    else
        log_warning "部分目录权限需要调整"
        return 1
    fi
}

# 使用Docker容器修复权限
docker_fix_permissions() {
    log_info "使用Docker容器修复权限..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker未安装，无法使用容器修复权限"
        return 1
    fi

    # 创建临时容器来修复权限
    docker run --rm \
        -v "$(pwd)/data:/fix/data" \
        -v "$(pwd)/downloads:/fix/downloads" \
        -v "$(pwd)/logs:/fix/logs" \
        -v "$(pwd)/configs:/fix/configs" \
        -v "$(pwd)/certs:/fix/certs" \
        alpine:latest \
        sh -c "
            chown -R 1001:1001 /fix/data /fix/downloads /fix/logs &&
            chown -R root:root /fix/configs /fix/certs &&
            chmod -R 755 /fix/data /fix/downloads /fix/logs &&
            chmod -R 644 /fix/configs &&
            chmod -R 600 /fix/certs
        " 2>/dev/null

    if [[ $? -eq 0 ]]; then
        log_success "Docker容器权限修复成功"
        return 0
    else
        log_error "Docker容器权限修复失败"
        return 1
    fi
}

# 设置目录权限
set_permissions() {
    log_info "设置目录权限..."

    # 检查必要目录
    for dir in "${!PERMISSIONS[@]}"; do
        if [[ ! -d "$dir" ]]; then
            log_info "创建目录: $dir"
            mkdir -p "$dir"
        fi
    done

    # 设置所有目录权限
    for dir in "${!PERMISSIONS[@]}"; do
        if [[ -d "$dir" ]]; then
            set_directory_permission "$dir" "${PERMISSIONS[$dir]}"
        else
            log_warning "目录 $dir 不存在，跳过"
        fi
    done

    # 设置脚本执行权限
    log_info "设置脚本执行权限..."
    chmod +x *.sh 2>/dev/null || log_warning "无法设置脚本执行权限"
    chmod +x scripts/*.sh 2>/dev/null || log_warning "无法设置脚本目录执行权限"

    # 显示权限状态
    show_permission_status

    # 验证权限设置
    if ! validate_permissions; then
        log_warning "权限验证失败，尝试Docker修复..."
        if docker_fix_permissions; then
            log_info "Docker修复后的权限状态:"
            show_permission_status
            validate_permissions
        else
            log_warning "Docker修复也失败，但可以尝试继续部署"
        fi
    fi
}

# 启动服务
start_services() {
    log_info "拉取最新镜像..."
    docker-compose pull

    log_info "启动服务..."
    docker-compose up -d

    log_info "等待服务启动..."
    sleep 30

    # 检查服务状态
    if docker-compose ps | grep -q "Up"; then
        log_success "服务启动成功！"
        echo ""
        log_info "============================================"
        log_info "Secure File Hub 部署完成！"
        log_info "============================================"
        log_info "前端访问地址: http://localhost:30000"
        log_info "后端 API 地址: https://localhost:8443"
        log_info "默认管理员账户:"
        log_info "  用户名: admin"
        log_info "  密码: admin123"
        log_info "============================================"
        log_warning "请立即登录并修改默认密码！"
        echo ""
    else
        log_error "服务启动失败，请检查日志："
        docker-compose logs
        exit 1
    fi
}

# 显示帮助信息
show_help() {
    echo "Secure File Hub 部署和权限管理脚本"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  -h, --help     显示此帮助信息"
    echo "  -p, --permissions  仅设置目录权限"
    echo "  -s, --status   显示当前权限状态"
    echo "  -v, --validate 验证权限设置"
    echo "  -d, --docker-fix 使用Docker容器修复权限"
    echo "  -f, --full     完整部署流程（默认）"
    echo ""
    echo "示例:"
    echo "  $0                    # 完整部署流程"
    echo "  $0 --permissions      # 仅设置权限"
    echo "  $0 --status          # 查看权限状态"
    echo "  $0 --validate        # 验证权限设置"
    echo "  $0 --docker-fix      # 使用Docker修复权限"
}

# 主函数
main() {
    case "${1:-}" in
        -h|--help)
            show_help
            ;;
        -p|--permissions)
            echo ""
            log_info "============================================"
            log_info "Secure File Hub - 权限设置"
            log_info "============================================"
            echo ""
            set_permissions
            log_success "权限设置完成！"
            ;;
        -s|--status)
            echo ""
            log_info "============================================"
            log_info "Secure File Hub - 权限状态"
            log_info "============================================"
            echo ""
            show_permission_status
            ;;
        -v|--validate)
            echo ""
            log_info "============================================"
            log_info "Secure File Hub - 权限验证"
            log_info "============================================"
            echo ""
            validate_permissions
            ;;
        -d|--docker-fix)
            echo ""
            log_info "============================================"
            log_info "Secure File Hub - Docker权限修复"
            log_info "============================================"
            echo ""
            if docker_fix_permissions; then
                show_permission_status
                log_success "Docker权限修复完成！"
            else
                log_error "Docker权限修复失败！"
                exit 1
            fi
            ;;
        -f|--full|"")
            # 完整部署流程
            echo ""
            log_info "============================================"
            log_info "Secure File Hub 快速部署脚本"
            log_info "============================================"
            echo ""

            check_user
            check_docker
            create_directories
            generate_certificates
            create_config
            set_permissions
            start_services

            log_success "部署完成！"
            ;;
        *)
            log_error "未知选项: $1"
            show_help
            exit 1
            ;;
    esac
}

# 运行主函数
main "$@"