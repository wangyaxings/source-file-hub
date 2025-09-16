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

# 设置目录权限
set_permissions() {
    log_info "设置目录权限..."
    
    # 首先尝试获取当前目录的所有权
    current_user=$(whoami)
    
    # 设置数据目录权限（容器内用户 UID:1001）
    if sudo chown -R 1001:1001 data downloads logs 2>/dev/null; then
        log_info "使用 sudo 设置目录所有者为 1001:1001"
    else
        log_warning "无法使用 sudo 设置所有者，尝试使用当前用户权限"
        # 如果 sudo 失败，尝试设置为当前用户
        chown -R $current_user:$current_user data downloads logs 2>/dev/null || true
    fi
    
    # 设置目录权限
    if chmod -R 755 data downloads logs 2>/dev/null; then
        log_success "目录权限设置完成"
    else
        log_warning "权限设置可能不完整，容器启动时会自动调整"
    fi
    
    # 设置配置和证书目录权限
    chmod -R 644 configs/ certs/ 2>/dev/null || {
        log_warning "配置目录权限设置失败，使用默认权限"
    }
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

# 主函数
main() {
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
}

# 运行主函数
main "$@"