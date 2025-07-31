# FileServer 默认账户说明

## 🔐 默认测试账户

本系统预配置了以下测试账户，用于开发和演示：

### 管理员账户
- **租户ID**: `demo`
- **用户名**: `admin`
- **密码**: `admin123`
- **登录格式**: `admin@demo`
- **权限**: 系统管理员
- **用途**: 完整的系统管理功能

### 普通用户账户
- **租户ID**: `demo`
- **用户名**: `user1`
- **密码**: `password123`
- **登录格式**: `user1@demo`
- **权限**: 普通用户
- **用途**: 标准文件上传和管理功能

### 测试账户
- **租户ID**: `tenant1`
- **用户名**: `test`
- **密码**: `test123`
- **登录格式**: `test@tenant1`
- **权限**: 测试用户
- **用途**: 多租户环境测试

## 🚀 如何登录

### 前端登录界面
1. 访问: `http://localhost:3000`
2. 在登录界面输入:
   - **用户名**: 上述任一登录格式 (如: `admin@demo`)
   - **密码**: 对应的密码

### API 登录
```bash
curl -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "demo",
    "username": "admin",
    "password": "admin123"
  }'
```

## ⚙️ 用户管理

### 查看所有默认用户
在代码中可以调用:
```go
users := auth.GetDefaultUsers()
```

### 添加新用户
```go
err := auth.AddUser("tenant_id", "username", "password")
```

## 🔒 安全说明

⚠️ **重要安全提醒**:

1. **生产环境**: 这些是测试账户，在生产环境中必须:
   - 更改所有默认密码
   - 删除不需要的测试账户
   - 实施强密码策略
   - 配置适当的用户权限

2. **密码策略**: 当前密码为简单测试密码，建议:
   - 使用强密码 (8+ 字符，包含大小写、数字、特殊字符)
   - 定期更换密码
   - 不要在多个系统中重复使用相同密码

3. **Token 管理**:
   - Token 有效期为 24 小时
   - 登出时会自动清除 Token
   - Token 存储在内存中 (生产环境建议使用 Redis)

## 📝 开发说明

### 修改默认用户
编辑 `internal/auth/user.go` 文件中的 `userStore` 变量:

```go
var userStore = map[string]*User{
    "admin:demo@admin": {
        TenantID: "demo",
        Username: "admin",
        Password: hashPassword("your_new_password"),
    },
    // ... 其他用户
}
```

### 数据库集成
当前使用内存存储，生产环境建议:
- 使用 PostgreSQL/MySQL 等数据库
- 实施用户角色和权限系统
- 添加用户注册和密码重置功能

## 🎯 快速测试

启动服务后，可以使用以下账户快速测试不同功能:

1. **管理功能测试**: 使用 `admin@demo` / `admin123`
2. **普通用户测试**: 使用 `user1@demo` / `password123`
3. **多租户测试**: 使用 `test@tenant1` / `test123`

---

💡 **提示**: 在 `startup.bat` 执行时会显示这些账户信息，方便快速查看。