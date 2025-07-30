#!/bin/bash

# FileServer 认证功能演示脚本
# 
# 这个脚本演示了完整的认证流程：
# 1. 获取默认用户列表
# 2. 用户登录获取token
# 3. 使用token访问受保护的接口
# 4. 用户登出

echo "🚀 FileServer 认证功能演示"
echo "========================================"

BASE_URL="http://localhost:8080/api/v1"

# 检查服务器是否运行
echo "🔍 检查服务器状态..."
if ! curl -s "$BASE_URL/health" > /dev/null 2>&1; then
    echo "❌ 服务器未运行，请先启动服务器："
    echo "   go run cmd/server/main.go"
    exit 1
fi
echo "✅ 服务器运行正常"
echo

# 1. 获取默认用户列表
echo "👥 获取默认测试用户..."
curl -s "$BASE_URL/auth/users" | jq '.'
echo

# 2. 用户登录
echo "🔐 用户登录 (demo/admin)..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{
        "tenant_id": "demo",
        "username": "admin",
        "password": "admin123"
    }')

echo "$LOGIN_RESPONSE" | jq '.'

# 提取token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.token')

if [ "$TOKEN" == "null" ]; then
    echo "❌ 登录失败，无法获取token"
    exit 1
fi

echo "✅ 登录成功，Token: ${TOKEN:0:20}..."
echo

# 3. 使用token访问受保护的接口
echo "📁 使用token下载配置文件..."
CONFIG_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/config/download")

# 检查是否成功
if echo "$CONFIG_RESPONSE" | jq -e '.success' > /dev/null 2>&1; then
    # 如果返回的是错误JSON
    echo "❌ 下载失败："
    echo "$CONFIG_RESPONSE" | jq '.'
else
    # 如果返回的是文件内容
    echo "✅ 配置文件下载成功："
    echo "$CONFIG_RESPONSE" | jq '.'
fi
echo

# 4. 测试无token访问（应该失败）
echo "🚫 测试无token访问 (应该失败)..."
NO_TOKEN_RESPONSE=$(curl -s "$BASE_URL/config/download")
echo "$NO_TOKEN_RESPONSE" | jq '.'
echo

# 5. 用户登出
echo "👋 用户登出..."
LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/auth/logout" \
    -H "Authorization: Bearer $TOKEN")
echo "$LOGOUT_RESPONSE" | jq '.'
echo

# 6. 测试登出后访问（应该失败）
echo "🚫 测试登出后访问 (应该失败)..."
AFTER_LOGOUT_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" \
    "$BASE_URL/config/download")
echo "$AFTER_LOGOUT_RESPONSE" | jq '.'

echo
echo "🎉 演示完成！"
echo
echo "💡 提示："
echo "- 默认用户: demo/admin (密码: admin123)"
echo "- Token有效期: 24小时"
echo "- 所有配置文件下载都需要认证"
echo "- 健康检查接口无需认证"