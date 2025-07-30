# FileServer

一个使用Go实现的REST API文件服务器，支持配置文件下载功能和用户认证。

## 功能特性

- ✅ REST API接口
- ✅ 配置文件下载功能
- ✅ 用户认证和授权
- ✅ 多租户支持（tenantid + username）
- ✅ Token-based认证（无感体验）
- ✅ 健康检查接口
- ✅ CORS支持
- ✅ 请求日志记录
- ✅ 优雅关闭

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

服务器将在 `http://localhost:8080` 启动。

## API接口

### 🔐 认证相关接口

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
curl http://localhost:8080/api/v1/auth/users
```

#### 2. 用户登录

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "demo",
    "username": "admin",
    "password": "admin123"
  }'
```

#### 3. 使用token下载配置文件

```bash
# 使用上一步返回的token
TOKEN=""
curl -H "Authorization: Bearer 7304073a5931c42401c7ed29204942286b41df1f392294d280cc3233c53aac39" \
  -O -J http://localhost:8080/api/v1/config/download
```

#### 4. 登出

```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### 🌐 浏览器使用

由于浏览器无法直接发送Authorization header，推荐使用API工具（如Postman、Insomnia）或前端应用来测试认证功能。

### 💡 无感认证体验

用户只需要：
1. **一次登录** - 获取token
2. **自动携带** - 在后续请求中携带token
3. **长期有效** - token有效期24小时，减少重复登录

前端应用可以：
- 自动存储token到localStorage/sessionStorage
- 在请求拦截器中自动添加Authorization header
- token过期时自动引导用户重新登录

## 配置说明

配置文件位于 `configs/config.json`，包含以下配置项：

- `server`: 服务器配置（主机、端口、超时等）
- `application`: 应用程序信息
- `logging`: 日志配置
- `features`: 功能开关

## 🔒 认证设计

### 多租户支持
- 使用 `tenant_id + username` 的组合来唯一标识用户
- 支持不同租户下的同名用户
- 便于SaaS应用的多租户架构

### 无感认证体验
- **一次登录，长期使用**: 24小时token有效期
- **自动认证**: 中间件自动验证token
- **简单集成**: 只需在请求头添加`Authorization: Bearer <token>`

### 安全特性
- 密码BCrypt哈希存储
- Token自动过期清理
- 详细的认证日志记录

## 最佳实践

本项目遵循Go项目的最佳实践：

1. **项目结构**: 使用标准的Go项目布局
2. **认证架构**: Token-based认证，支持多租户
3. **错误处理**: 完善的错误处理和日志记录
4. **HTTP中间件**: 分层中间件（日志、CORS、认证）
5. **优雅关闭**: 支持优雅关闭服务器
6. **安全性**: 密码哈希、token验证、适当的HTTP头部
7. **可维护性**: 清晰的代码结构和注释
8. **用户体验**: 最小化认证复杂度，提供默认测试用户

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