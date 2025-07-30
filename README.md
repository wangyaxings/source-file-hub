# FileServer

一个使用Go实现的安全REST API文件服务器，支持HTTPS和统一的认证文件下载服务。

## 功能特性

- ✅ **HTTPS专用**: 仅支持HTTPS安全连接
- ✅ **统一文件下载**: 所有文件通过统一API下载
- ✅ **强制认证**: 所有文件下载都需要用户认证
- ✅ **多租户支持**: tenantid + username 认证模式
- ✅ **Token-based认证**: 24小时长效token
- ✅ **RESTful API设计**: 符合REST规范
- ✅ **API信息页面**: 类似GitHub API的根信息页面，提供完整的API文档
- ✅ **结构化日志**: 基于最佳实践的结构化日志记录系统
- ✅ **SQLite日志存储**: 持久化日志数据，支持查询和分析
- ✅ **访问日志API**: 提供RESTful API查询访问日志
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
│   ├── logger/         # 结构化日志系统
│   ├── middleware/     # 认证、日志记录中间件
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
├── logs.db             # SQLite日志数据库
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
curl -k -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 下载SSL证书
curl -k -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.crt

# 下载SSL私钥
curl -k -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.key

# 下载证书信息
curl -k -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b" \
  -O -J https://localhost:8443/api/v1/files/certificates/cert_info.json

# 下载API文档
curl -k -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b" \
  -O -J https://localhost:8443/api/v1/files/docs/api_guide.txt
```

#### 4. 登出

```bash
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer 99cab419f558d453ea5177b36e200b9a458f97539375680b22f46884e4d0cb4b"
```

### 🌐 浏览器使用

由于所有文件下载都需要认证（Authorization header），浏览器无法直接访问下载接口。推荐使用：

1. **API测试工具**: Postman、Insomnia、Thunder Client等
2. **命令行工具**: curl、wget等
3. **前端应用**: 可以自动管理token的Web应用

**注意**：使用自签名证书时，浏览器会显示安全警告，这是正常的。在开发环境中可以选择"继续访问"。

### 🔧 完整的curl验证逻辑

以下是使用curl完整验证所有功能的命令，可以直接复制粘贴执行：

#### 步骤0: API信息页面（无需认证）
```bash
# Bash/Linux/macOS
curl -k -s https://localhost:8443/api/v1

# PowerShell/Windows
Invoke-WebRequest -Uri "https://localhost:8443/api/v1" -SkipCertificateCheck | Select-Object -ExpandProperty Content
```

**预期响应：**
```json
{
  "success": true,
  "message": "FileServer REST API Information",
  "data": {
    "name": "FileServer REST API",
    "version": "v1.0.0",
    "description": "A secure file server with user authentication and SSL support",
    "base_url": "https://localhost:8443/api/v1",
    "endpoints": {
      "api_info": "https://localhost:8443/api/v1",
      "health_check": "https://localhost:8443/api/v1/health",
      "authentication": {
        "login": "https://localhost:8443/api/v1/auth/login",
        "logout": "https://localhost:8443/api/v1/auth/logout",
        "default_users": "https://localhost:8443/api/v1/auth/users"
      },
      "file_downloads": {
        "unified_download": "https://localhost:8443/api/v1/files/{path}",
        "examples": [
          "https://localhost:8443/api/v1/files/configs/config.json",
          "https://localhost:8443/api/v1/files/certificates/server.crt"
        ]
      },
      "logs": {
        "access_logs": "https://localhost:8443/api/v1/logs/access",
        "system_logs": "https://localhost:8443/api/v1/logs/system"
      }
    },
    "features": [
      "JWT Authentication",
      "Multi-tenant Support",
      "HTTPS Only",
      "Path Traversal Protection",
      "Structured Logging",
      "SQLite Log Storage"
    ]
  }
}
```

#### 步骤1: 健康检查（无需认证）
```bash
# Bash/Linux/macOS
curl -k -s https://localhost:8443/api/v1/health

# PowerShell/Windows
Invoke-WebRequest -Uri "https://localhost:8443/api/v1/health" -SkipCertificateCheck | Select-Object -ExpandProperty Content
```

**预期响应：**
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

#### 步骤2: 获取默认用户列表（无需认证）
```bash
curl -k -s https://localhost:8443/api/v1/auth/users
```

**预期响应：**
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
      }
    ]
  }
}
```

#### 步骤3: 用户登录获取token
```bash
curl -k -s -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'
```

**预期响应（复制token用于后续请求）：**
```json
{
  "success": true,
  "message": "登录成功",
  "data": {
    "token": "7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39",
    "expires_in": 86400,
    "user": {
      "tenant_id": "demo",
      "username": "admin"
    }
  }
}
```

#### 步骤4: 下载配置文件（需要认证）
```bash
curl -k -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json
```

#### 步骤5: 下载SSL证书（需要认证）
```bash
curl -k -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.crt
```

#### 步骤6: 下载SSL私钥（需要认证）
```bash
curl -k -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.key
```

#### 步骤7: 下载证书信息（需要认证）
```bash
curl -k -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J https://localhost:8443/api/v1/files/certificates/cert_info.json
```

#### 步骤8: 下载API文档（需要认证）
```bash
curl -k -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J https://localhost:8443/api/v1/files/docs/api_guide.txt
```

#### 步骤9: 测试无认证访问（应该失败）
```bash
curl -k -s https://localhost:8443/api/v1/files/configs/config.json
```

**预期响应（401错误）：**
```json
{
  "success": false,
  "error": "缺少Authorization header",
  "code": "UNAUTHORIZED"
}
```

#### 步骤10: 测试错误token（应该失败）
```bash
curl -k -s -H "Authorization: Bearer invalid_token_12345" \
  https://localhost:8443/api/v1/files/configs/config.json
```

**预期响应（401错误）：**
```json
{
  "success": false,
  "error": "无效的token",
  "code": "UNAUTHORIZED"
}
```

#### 步骤11: 用户登出
```bash
curl -k -s -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39"
```

**预期响应：**
```json
{
  "success": true,
  "message": "登出成功"
}
```

#### 步骤12: 验证登出后访问（应该失败）
```bash
curl -k -s -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  https://localhost:8443/api/v1/files/configs/config.json
```

**预期响应（401错误）：**
```json
{
  "success": false,
  "error": "无效的token",
  "code": "UNAUTHORIZED"
}
```

### 📋 快速验证脚本

#### Bash脚本 (Linux/macOS/WSL)
如果你想一次性运行所有验证，可以将以下脚本保存为 `verify.sh`：

```bash
#!/bin/bash

echo "🚀 FileServer 完整功能验证"
echo "=============================="

echo "0. API信息页面..."
curl -k -s https://localhost:8443/api/v1
echo -e "\n"

echo "1. 健康检查..."
curl -k -s https://localhost:8443/api/v1/health
echo -e "\n"

echo "2. 获取默认用户列表..."
curl -k -s https://localhost:8443/api/v1/auth/users
echo -e "\n"

echo "3. 用户登录..."
curl -k -s -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'
echo -e "\n"

echo "4. 测试无认证访问（应该失败）..."
curl -k -s https://localhost:8443/api/v1/files/configs/config.json
echo -e "\n"

echo "⚠️  请手动复制上面登录响应中的token，然后使用该token进行文件下载验证"
echo "🎉 基础验证完成！"
```

#### PowerShell脚本 (Windows)
对于Windows PowerShell用户，可以使用以下脚本：

```powershell
# verify.ps1
Write-Host "🚀 FileServer 完整功能验证" -ForegroundColor Green
Write-Host "==============================" -ForegroundColor Green

Write-Host "0. API信息页面..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://localhost:8443/api/v1" -SkipCertificateCheck | Select-Object -ExpandProperty Content

Write-Host "`n1. 健康检查..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://localhost:8443/api/v1/health" -SkipCertificateCheck | Select-Object -ExpandProperty Content

Write-Host "`n2. 获取默认用户列表..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "https://localhost:8443/api/v1/auth/users" -SkipCertificateCheck | Select-Object -ExpandProperty Content

Write-Host "`n3. 用户登录..." -ForegroundColor Yellow
$loginData = @{
    tenant_id = "demo"
    username = "admin"
    password = "admin123"
} | ConvertTo-Json

Invoke-WebRequest -Uri "https://localhost:8443/api/v1/auth/login" -Method POST -Body $loginData -ContentType "application/json" -SkipCertificateCheck | Select-Object -ExpandProperty Content

Write-Host "`n⚠️  请手动复制上面登录响应中的token，然后使用该token进行文件下载验证" -ForegroundColor Red
Write-Host "🎉 基础验证完成！" -ForegroundColor Green
```

### 🔍 验证要点

1. **SSL警告**: `-k` 参数跳过SSL证书验证（因为使用自签名证书）
2. **Token更新**: 每次登录都会产生新的token，请使用最新的token
3. **文件下载**: `-O -J` 参数会保存文件到当前目录
4. **错误验证**: 测试无认证和错误token访问，确保安全机制正常工作
5. **完整流程**: 从登录到下载到登出的完整认证生命周期

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