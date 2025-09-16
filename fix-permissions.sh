#!/bin/bash

# 权限修复脚本 - 用于解决目录权限问题

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

# 检查目录是否存在
check_directories() {
    for dir in data downloads logs configs certs; do
        if [[ ! -d "$dir" ]]; then
            log_info "创建目录: $dir"
            mkdir -p "$dir"
        fi
    done
}

# 修复权限
fix_permissions() {
    log_info "修复目录权限..."
    
    current_user=$(whoami)
    current_group=$(id -gn)
    
    # 方法1: 尝试使用 sudo 设置为容器用户 (UID:1001)
    if sudo chown -R 1001:1001 data downloads logs 2>/dev/null; then
        log_success "设置目录所有者为容器用户 (1001:1001)"
    else
        log_warning "无法使用 sudo，尝试其他方法..."
        
        # 方法2: 设置为当前用户
        if chown -R $current_user:$current_group data downloads logs 2>/dev/null; then
            log_success "设置目录所有者为当前用户 ($current_user:$current_group)"
        else
            log_warning "无法更改所有者，尝试仅设置权限..."
        fi
    fi
    
    # 设置目录权限
    if chmod -R 755 data downloads logs 2>/dev/null; then
        log_success "设置目录权限为 755"
    else
        log_warning "无法设置目录权限，可能需要管理员权限"
    fi
    
    # 设置配置文件权限
    chmod -R 644 configs/ certs/ 2>/dev/null || log_warning "配置目录权限设置失败"
    
    # 确保脚本可执行
    chmod +x *.sh 2>/dev/null || log_warning "无法设置脚本执行权限"
}

# 检查权限状态
check_permissions() {
    log_info "检查目录权限状态..."
    
    for dir in data downloads logs; do
        if [[ -d "$dir" ]]; then
            perm=$(ls -ld "$dir" | cut -d' ' -f1)
            owner=$(ls -ld "$dir" | awk '{print $3":"$4}')
            echo "  $dir: $perm $owner"
        fi
    done
}

# 使用 Docker 临时容器修复权限（最后手段）
docker_fix_permissions() {
    log_info "尝试使用 Docker 容器修复权限..."
    
    if command -v docker &> /dev/null; then
        # 创建临时容器来修复权限
        docker run --rm \
            -v "$(pwd)/data:/fix/data" \
            -v "$(pwd)/downloads:/fix/downloads" \
            -v "$(pwd)/logs:/fix/logs" \
            alpine:latest \
            sh -c "chown -R 1001:1001 /fix/* && chmod -R 755 /fix/*" 2>/dev/null
        
        if [[ $? -eq 0 ]]; then
            log_success "使用 Docker 容器成功修复权限"
            return 0
        else
            log_error "Docker 容器修复权限失败"
            return 1
        fi
    else
        log_error "Docker 未安装，无法使用容器修复权限"
        return 1
    fi
}

# 显示解决方案建议
show_solutions() {
    echo ""
    log_info "如果权限问题仍然存在，请尝试以下解决方案："
    echo ""
    echo "1. 使用 sudo 运行修复脚本:"
    echo "   sudo ./fix-permissions.sh"
    echo ""
    echo "2. 手动修复权限:"
    echo "   sudo chown -R 1001:1001 data downloads logs"
    echo "   sudo chmod -R 755 data downloads logs"
    echo ""
    echo "3. 或者使用当前用户权限启动（可能会有警告但通常可以工作）:"
    echo "   docker-compose up -d"
    echo ""
    echo "4. 检查 SELinux 状态（如果适用）:"
    echo "   sestatus"
    echo "   # 如果启用了 SELinux，可能需要设置 SELinux 上下文"
    echo ""
}

# 主函数
main() {
    echo ""
    log_info "============================================"
    log_info "Secure File Hub - 权限修复脚本"
    log_info "============================================"
    echo ""
    
    check_directories
    
    echo ""
    log_info "修复前的权限状态:"
    check_permissions
    
    echo ""
    fix_permissions
    
    echo ""
    log_info "修复后的权限状态:"
    check_permissions
    
    echo ""
    
    # 如果标准方法失败，尝试 Docker 方法
    if [[ ! -w "data" ]] || [[ ! -w "downloads" ]] || [[ ! -w "logs" ]]; then
        log_warning "标准权限修复可能不完整，尝试 Docker 方法..."
        if docker_fix_permissions; then
            echo ""
            log_info "最终权限状态:"
            check_permissions
        else
            show_solutions
        fi
    else
        log_success "权限修复完成！可以继续运行 docker-compose up -d"
    fi
    
    echo ""
}

# 运行主函数
main "$@"