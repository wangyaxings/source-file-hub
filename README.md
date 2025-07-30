# FileServer

一个使用Go实现的安全REST API文件服务器，支持HTTPS、用户认证和SSL证书管理。

## 功能特性

- ✅ HTTPS安全连接
- ✅ SSL证书管理和下载
- ✅ RESTful API设计
- ✅ 配置文件下载功能
- ✅ 用户认证和授权
- ✅ 多租户支持（tenantid + username）
- ✅ Token-based认证（无感体验）
- ✅ 健康检查接口
- ✅ CORS支持
- ✅ 请求日志记录
- ✅ 优雅关闭
- ✅ HTTP自动重定向到HTTPS

## 项目结构

```
FileServer/
├── cmd/server/         # 主程序入口
├── internal/           # 内部包
│   ├── auth/           # 用户认证模块
│   ├── handler/        # HTTP处理器
│   ├── middleware/     # 中间件
│   └── server/         # 服务器配置
├── configs/            # 配置文件
├── certs/              # SSL证书目录
│   ├── server.crt      # SSL证书文件
│   ├── server.key      # SSL私钥文件
│   └── cert_info.json  # 证书信息
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

服务器将启动HTTPS服务在 `https://localhost:8443`，HTTP重定向服务在 `http://localhost:8080`。

## API接口

### 🔐 认证相关接口

**注意：所有API都已升级为HTTPS，访问地址为 `https://localhost:8443/api/v1/...`**

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

### 🔒 SSL证书相关接口（RESTful API）

#### 获取证书列表

```http
GET /api/v1/certificates
```

获取所有可用的SSL证书列表（无需认证）。

**响应示例：**
```json
{
  "success": true,
  "message": "证书列表获取成功",
  "data": {
    "total_count": 3,
    "certificates": [
      {
        "name": "server.crt",
        "type": "X.509 Certificate",
        "download_url": "/api/v1/certificates/server.crt",
        "info_url": "/api/v1/certificates/server.crt/info"
      },
      {
        "name": "server.key",
        "type": "Private Key",
        "download_url": "/api/v1/certificates/server.key"
      },
      {
        "name": "cert_info.json",
        "type": "Certificate Information",
        "download_url": "/api/v1/certificates/cert_info.json"
      }
    ],
    "directory": "certs"
  }
}
```

#### 下载指定证书

```http
GET /api/v1/certificates/{cert_name}
```

下载指定的证书文件（无需认证）。

**参数：**
- `cert_name`: 证书文件名（如：server.crt, server.key）

**响应：**
- 成功：返回证书文件内容，适当的Content-Type
- 失败：返回错误信息的JSON响应

#### 获取证书信息

```http
GET /api/v1/certificates/{cert_name}/info
```

获取指定证书文件的详细信息（无需认证）。

**参数：**
- `cert_name`: 证书文件名（仅支持.crt和.pem文件）

**响应示例：**
```json
{
  "success": true,
  "message": "证书信息获取成功",
  "data": {
    "certificate_name": "server.crt",
    "certificate_info": {
      "subject": {
        "common_name": "FileServer Local Certificate",
        "organization": ["FileServer"],
        "country": ["CN"]
      },
      "validity": {
        "not_before": "2025-07-30T10:30:00Z",
        "not_after": "2026-07-30T10:30:00Z"
      },
      "key_usage": ["Digital Signature", "Key Encipherment"],
      "dns_names": ["localhost", "fileserver.local"],
      "key_size": 2048
    }
  }
}
```

### 📁 文件相关接口

#### 下载配置文件

```http
GET /api/v1/config/download
Authorization: Bearer <token>
```

下载 `config.json` 配置文件。**需要认证。**

**响应：**
- 成功：返回配置文件内容，Content-Type: `application/json`
- 失败：返回错误信息的JSON响应

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

#### 3. 下载SSL证书

```bash
# 获取证书列表
curl -k https://localhost:8443/api/v1/certificates

# 下载服务器证书
curl -k -O -J https://localhost:8443/api/v1/certificates/server.crt

# 获取证书信息
curl -k https://localhost:8443/api/v1/certificates/server.crt/info
```

#### 4. 使用token下载配置文件

```bash
# 使用登录返回的token
TOKEN="your_token_here"
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/config/download
```

#### 5. 登出

```bash
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### 🌐 浏览器使用

1. **访问HTTPS地址**：直接访问 `https://localhost:8443/api/v1/certificates` 可以查看证书列表
2. **下载证书**：访问 `https://localhost:8443/api/v1/certificates/server.crt` 可以直接下载证书
3. **认证功能**：由于浏览器无法直接发送Authorization header，推荐使用API工具（如Postman、Insomnia）或前端应用来测试认证功能

**注意**：使用自签名证书时，浏览器会显示安全警告，这是正常的。在开发环境中可以选择"继续访问"。

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

### HTTPS/SSL安全
- **端到端加密**: 所有API通信使用HTTPS加密
- **自签名证书**: 开发环境使用自签名证书，生产环境建议使用CA签发的证书
- **证书管理**: 提供完整的证书下载和信息查看功能
- **自动重定向**: HTTP请求自动重定向到HTTPS

### 多租户认证
- 使用 `tenant_id + username` 的组合来唯一标识用户
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
- HTTPS加密传输
- 详细的认证和访问日志记录
- 防路径遍历攻击
- 输入验证和清理

## 最佳实践

本项目遵循Go项目的最佳实践：

1. **项目结构**: 使用标准的Go项目布局
2. **HTTPS优先**: 所有通信使用HTTPS加密，HTTP自动重定向
3. **RESTful API**: 符合REST规范的API设计
4. **认证架构**: Token-based认证，支持多租户
5. **错误处理**: 完善的错误处理和日志记录
6. **分层中间件**: 日志、CORS、认证中间件分层处理
7. **优雅关闭**: 支持HTTPS和HTTP服务器的优雅关闭
8. **安全性**: HTTPS加密、密码哈希、token验证、输入验证
9. **证书管理**: 自动生成SSL证书，提供证书下载和信息API
10. **可维护性**: 清晰的代码结构和注释
11. **用户体验**: 最小化认证复杂度，提供默认测试用户

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