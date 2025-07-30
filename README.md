# FileServer

一个使用Go实现的安全REST API文件服务器，支持HTTPS和统一的认证文件下载服务。

## 功能特性

- ✅ **HTTPS专用**: 仅支持HTTPS安全连接
- ✅ **统一文件下载**: 所有文件通过统一API下载
- ✅ **强制认证**: 所有文件下载都需要用户认证
- ✅ **多租户支持**: tenantid + username 认证模式
- ✅ **Token-based认证**: 24小时长效token
- ✅ **RESTful API设计**: 符合REST规范
- ✅ **路径安全**: 防路径遍历攻击
- ✅ **文件类型支持**: 配置、证书、文档等多类型文件
- ✅ **请求日志记录**: 详细的访问和下载日志
- ✅ **优雅关闭**: 支持graceful shutdown

## 项目结构

```
FileServer/
├── cmd/server/         # 主程序入口
├── internal/           # 内部包
│   ├── auth/           # 用户认证模块
│   ├── handler/        # HTTP处理器 (统一文件下载)
│   ├── middleware/     # 认证中间件
│   └── server/         # HTTPS服务器配置
├── configs/            # 原始配置文件
├── certs/              # SSL证书目录
│   ├── server.crt      # SSL证书文件
│   ├── server.key      # SSL私钥文件
│   └── cert_info.json  # 证书信息
├── downloads/          # 🆕 统一下载文件目录
│   ├── configs/        # 配置文件
│   │   └── config.json
│   ├── certificates/   # 证书文件
│   │   ├── server.crt
│   │   ├── server.key
│   │   └── cert_info.json
│   └── docs/           # 文档文件
│       └── api_guide.txt
├── scripts/            # 工具脚本
│   └── generate_cert.go # SSL证书生成脚本
├── .gitignore          # Git忽略文件
├── go.mod              # Go模块文件
└── README.md           # 项目说明
```

## 安装和运行

### 前置要求

- Go 1.19 或更高版本

### 安装依赖

```bash
go mod download
```

### 运行服务器

```bash
go run cmd/server/main.go
```

服务器将启动HTTPS服务在 `https://localhost:8443`（仅支持HTTPS）。

## API接口

### 🔐 认证相关接口

**注意：仅支持HTTPS，访问地址为 `https://localhost:8443/api/v1/...`**

#### 获取默认测试用户

```http
GET /api/v1/auth/users
```

获取预设的测试用户列表（无需认证）。

**响应示例：**
```json
{
  "success": true,
  "message": "默认测试用户列表",
  "data": {
    "users": [
      {
        "tenant_id": "demo",
        "username": "admin",
        "password": "admin123",
        "desc": "管理员账户"
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "password": "password123",
        "desc": "普通用户账户"
      },
      {
        "tenant_id": "tenant1",
        "username": "test",
        "password": "test123",
        "desc": "测试账户"
      }
    ]
  }
}
```

#### 用户登录

```http
POST /api/v1/auth/login
```

**请求体：**
```json
{
  "tenant_id": "demo",
  "username": "admin",
  "password": "admin123"
}
```

**响应示例：**
```json
{
  "success": true,
  "message": "登录成功",
  "data": {
    "token": "abc123def456...",
    "expires_in": 86400,
    "user": {
      "tenant_id": "demo",
      "username": "admin"
    }
  }
}
```

#### 用户登出

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

### 📁 统一文件下载接口

#### 文件下载接口

```http
GET /api/v1/files/{文件路径}
Authorization: Bearer <token>
```

**统一的文件下载接口，所有文件下载都需要认证。**

**支持的文件路径：**

| 类型 | 路径 | 描述 |
|------|------|------|
| 配置文件 | `configs/config.json` | 系统配置文件 |
| SSL证书 | `certificates/server.crt` | SSL证书文件 |
| SSL私钥 | `certificates/server.key` | SSL私钥文件 |
| 证书信息 | `certificates/cert_info.json` | 证书详细信息 |
| API文档 | `docs/api_guide.txt` | API使用指南 |

**响应：**
- 成功：返回文件内容，适当的Content-Type和下载头部
- 失败：返回错误信息的JSON响应

**示例：**
```bash
# 下载配置文件
GET /api/v1/files/configs/config.json

# 下载SSL证书
GET /api/v1/files/certificates/server.crt

# 下载API文档
GET /api/v1/files/docs/api_guide.txt
```

### 🩺 系统接口

#### 健康检查

```http
GET /api/v1/health
```

检查服务状态（无需认证）。

**响应示例：**
```json
{
  "success": true,
  "message": "服务运行正常",
  "data": {
    "status": "healthy",
    "timestamp": "1640995200"
  }
}
```

## 使用示例

### 🚀 快速开始

#### 1. 获取测试用户信息

```bash
curl -k https://localhost:8443/api/v1/auth/users
```

#### 2. 用户登录

```bash
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "demo",
    "username": "admin",
    "password": "admin123"
  }'
```

#### 3. 使用token下载文件

```bash
# 使用登录返回的token
TOKEN="your_token_here"

# 下载配置文件
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 下载SSL证书
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.crt

# 下载SSL私钥
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.key

# 下载证书信息
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/certificates/cert_info.json

# 下载API文档
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/docs/api_guide.txt
```

#### 4. 登出

```bash
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### 🌐 浏览器使用

由于所有文件下载都需要认证（Authorization header），浏览器无法直接访问下载接口。推荐使用：

1. **API测试工具**: Postman、Insomnia、Thunder Client等
2. **命令行工具**: curl、wget等
3. **前端应用**: 可以自动管理token的Web应用

**注意**：使用自签名证书时，浏览器会显示安全警告，这是正常的。在开发环境中可以选择"继续访问"。

### 🔧 完整的curl验证逻辑

以下是使用curl完整验证所有功能的脚本：

```bash
#!/bin/bash

# FileServer 完整功能验证脚本
BASE_URL="https://localhost:8443/api/v1"

echo "🚀 FileServer 完整功能验证"
echo "=============================="

# 1. 健康检查（无需认证）
echo "1. 健康检查..."
curl -k -s "$BASE_URL/health" | jq '.'
echo

# 2. 获取默认用户列表（无需认证）
echo "2. 获取默认用户列表..."
curl -k -s "$BASE_URL/auth/users" | jq '.'
echo

# 3. 用户登录
echo "3. 用户登录..."
LOGIN_RESPONSE=$(curl -k -s -X POST "$BASE_URL/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}')
echo "$LOGIN_RESPONSE" | jq '.'

# 提取token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.data.token')
echo "Token: ${TOKEN:0:20}..."
echo

# 4. 下载各类文件（需要认证）
echo "4. 下载配置文件..."
curl -k -H "Authorization: Bearer $TOKEN" \
  -o "downloaded_config.json" \
  "$BASE_URL/files/configs/config.json"
echo "✅ 配置文件下载完成"

echo "5. 下载SSL证书..."
curl -k -H "Authorization: Bearer $TOKEN" \
  -o "downloaded_server.crt" \
  "$BASE_URL/files/certificates/server.crt"
echo "✅ SSL证书下载完成"

echo "6. 下载证书信息..."
curl -k -H "Authorization: Bearer $TOKEN" \
  -o "downloaded_cert_info.json" \
  "$BASE_URL/files/certificates/cert_info.json"
echo "✅ 证书信息下载完成"

echo "7. 下载API文档..."
curl -k -H "Authorization: Bearer $TOKEN" \
  -o "downloaded_api_guide.txt" \
  "$BASE_URL/files/docs/api_guide.txt"
echo "✅ API文档下载完成"

# 8. 测试无认证访问（应该失败）
echo "8. 测试无认证访问..."
curl -k -s "$BASE_URL/files/configs/config.json" | jq '.'
echo

# 9. 用户登出
echo "9. 用户登出..."
curl -k -s -X POST "$BASE_URL/auth/logout" \
  -H "Authorization: Bearer $TOKEN" | jq '.'
echo

echo "🎉 验证完成！"
echo "下载的文件："
ls -la downloaded_*
```

### 💡 无感认证体验

用户只需要：
1. **一次登录** - 获取token
2. **自动携带** - 在后续请求中携带token
3. **长期有效** - token有效期24小时，减少重复登录

前端应用可以：
- 自动存储token到localStorage/sessionStorage
- 在请求拦截器中自动添加Authorization header
- token过期时自动引导用户重新登录
- 使用HTTPS确保token传输安全

## 配置说明

配置文件位于 `configs/config.json`，包含以下配置项：

- `server`: 服务器配置（HTTPS端口、HTTP端口、SSL证书路径等）
- `application`: 应用程序信息（名称、版本、协议等）
- `logging`: 日志配置
- `features`: 功能开关（SSL、认证、证书下载等）
- `auth`: 认证配置
- `ssl`: SSL证书配置

## 🔒 安全设计

### HTTPS专用架构
- **仅HTTPS**: 移除HTTP支持，专注于安全连接
- **端到端加密**: 所有API通信使用TLS加密
- **自签名证书**: 开发环境使用，生产环境建议替换为CA证书

### 统一认证下载
- **强制认证**: 所有文件下载都必须通过用户认证
- **统一接口**: 通过 `/api/v1/files/{路径}` 统一管理所有下载
- **路径控制**: 仅允许访问 `downloads/` 目录下的文件

### 多租户认证
- 使用 `tenant_id + username + password` 三元组认证
- 支持不同租户下的同名用户
- 便于SaaS应用的多租户架构

### 无感认证体验
- **一次登录，长期使用**: 24小时token有效期
- **自动认证**: 中间件自动验证token
- **简单集成**: 只需在请求头添加`Authorization: Bearer <token>`
- **安全传输**: Token通过HTTPS安全传输

### 安全特性
- 密码BCrypt哈希存储
- Token自动过期清理
- HTTPS强制加密传输
- 详细的认证和访问日志记录
- 防路径遍历攻击
- 白名单路径验证
- 输入验证和清理

## 最佳实践

本项目遵循Go项目的最佳实践：

1. **项目结构**: 使用标准的Go项目布局
2. **HTTPS专用**: 移除HTTP支持，专注HTTPS安全通信
3. **RESTful API**: 符合REST规范的统一文件下载接口
4. **认证架构**: Token-based认证，支持多租户
5. **错误处理**: 完善的错误处理和日志记录
6. **分层中间件**: 日志、CORS、认证中间件分层处理
7. **优雅关闭**: 支持HTTPS服务器的优雅关闭
8. **安全性**: HTTPS加密、密码哈希、token验证、路径白名单
9. **统一下载**: 所有文件通过统一接口下载，强制认证
10. **路径安全**: 防路径遍历，仅允许访问downloads目录
11. **可维护性**: 清晰的代码结构和注释
12. **用户体验**: 最小化认证复杂度，提供默认测试用户

## 开发

### 构建

```bash
go build -o fileserver cmd/server/main.go
```

### 测试

```bash
go test ./...
```

## 许可证

MIT License