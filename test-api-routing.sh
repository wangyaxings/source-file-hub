#!/bin/bash

# API路由测试脚本
# 用于验证单容器部署中的API代理是否正常工作

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

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# 测试函数
test_endpoint() {
    local url=$1
    local description=$2
    local expected_status=${3:-200}

    log_info "Testing: $description"
    log_info "URL: $url"

    if response=$(curl -s -w "\n%{http_code}" -k "$url" 2>/dev/null); then
        http_code=$(echo "$response" | tail -n1)
        body=$(echo "$response" | head -n -1)

        if [ "$http_code" = "$expected_status" ]; then
            log_success "✓ $description - HTTP $http_code"
            if [ -n "$body" ] && [ "$body" != "null" ]; then
                echo "  Response: $(echo "$body" | head -c 100)..."
            fi
        else
            log_error "✗ $description - Expected HTTP $expected_status, got HTTP $http_code"
            echo "  Response: $body"
        fi
    else
        log_error "✗ $description - Connection failed"
    fi
    echo
}

# 主测试函数
main() {
    log_info "======================================="
    log_info "API路由测试 - 单容器部署"
    log_info "======================================="

    # 等待服务启动
    log_info "等待服务启动..."
    sleep 10

    # 测试前端页面
    test_endpoint "http://localhost:30000" "前端页面访问"

    # 测试后端健康检查（直接访问）
    test_endpoint "https://localhost:8443/api/v1/health" "后端健康检查（直接访问）"

    # 测试API代理（通过前端）
    test_endpoint "http://localhost:30000/api/v1/health" "API代理健康检查"

    # 测试认证相关API
    test_endpoint "http://localhost:30000/api/v1/web/auth/me" "用户认证状态检查" 401

    # 测试文件API
    test_endpoint "http://localhost:30000/api/v1/web/files" "文件列表API" 401

    # 测试外部API（需要API Key）
    test_endpoint "https://localhost:8444/api/v1/public/files" "外部文件列表API（需要API Key）" 401
    test_endpoint "https://localhost:8444/api/v1/public/packages" "外部包列表API（需要API Key）" 401

    # 测试外部API健康检查（无需认证）
    test_endpoint "https://localhost:8444/api/v1/health" "外部API健康检查"
    test_endpoint "https://localhost:8444/api/v1/healthz" "外部API健康检查(healthz)"

    log_info "======================================="
    log_info "测试完成"
    log_info "======================================="

    log_info "如果所有测试都通过，说明API代理配置正确："
    log_info "1. 前端页面可以正常访问"
    log_info "2. 后端API可以通过前端代理访问"
    log_info "3. 认证和权限控制正常工作"
    log_info "4. 外部API Key功能正常（端口8444）"
    log_info "5. 健康检查API对外暴露（无需认证）"
    log_info ""
    log_info "健康检查API（无需认证）："
    log_info "curl https://localhost:8444/api/v1/health"
    log_info "curl https://localhost:8444/api/v1/healthz"
    log_info ""
    log_info "API Key使用示例："
    log_info "curl -H 'X-API-Key: your-api-key' https://localhost:8444/api/v1/public/files"
    log_info "curl -H 'Authorization: Bearer your-api-key' https://localhost:8444/api/v1/public/files/upload"
}

# 检查依赖
if ! command -v curl &> /dev/null; then
    log_error "curl命令未找到，请安装curl"
    exit 1
fi

# 运行测试
main "$@"
