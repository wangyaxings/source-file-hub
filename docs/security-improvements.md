# 安全改进说明

本文档描述了系统的最新安全改进，包括API列表接口、SHA256校验和、API Key安全性和HTTPS强制。

## 1. API列表接口权限控制

### 新增功能
- 添加了 `/api/v1/public/list` 接口，提供基于权限的API端点列表
- 根据用户权限动态显示可访问的API端点
- 管理员可以看到所有端点，普通用户只能看到有权限的端点

### 权限级别
- **read**: 可以查看文件列表、文件信息、包列表
- **download**: 可以下载文件
- **upload**: 可以上传文件和包
- **admin**: 可以访问所有管理功能

### 使用示例
```bash
# 获取API列表
curl -H "Authorization: Bearer YOUR_API_KEY" \
     https://localhost:8443/api/v1/public/list
```

## 2. SHA256校验和

### 改进内容
- 使用SHA256作为文件校验和算法，提高安全性
- 简化实现，只支持SHA256校验和
- 新上传的文件自动计算SHA256校验和

### 数据库变更
- `files` 表的 `checksum` 字段存储SHA256校验和
- 无需数据库迁移，直接使用现有字段

### API响应格式
```json
{
  "id": "file_123",
  "name": "example.txt",
  "checksum": "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d"  // SHA256
}
```

## 3. API Key安全性

### 安全最佳实践
- **不允许二次查看**: API Key创建后只显示一次，后续只能看到掩码版本
- **重新生成功能**: 提供API Key重新生成功能，旧Key自动失效
- **掩码显示**: 使用 `sk_1234...5678` 格式显示部分Key

### 新增接口
- `POST /api/v1/admin/api-keys/{keyId}/regenerate` - 重新生成API Key
- `GET /api/v1/admin/api-keys/{keyId}/download` - 下载API Key文件

### 下载功能
- **临时存储**: API Key创建后临时存储10分钟供下载
- **自动清理**: 下载后立即删除临时存储，或10分钟后自动过期
- **文件格式**: 下载为包含完整信息的文本文件
- **安全措施**: 包含使用说明和安全建议

### 使用示例

#### 创建API Key并下载
```bash
# 1. 创建API Key
curl -X POST https://localhost:8443/api/v1/admin/api-keys \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "description": "For testing purposes",
    "permissions": ["read", "upload"]
  }'

# 响应包含下载链接
{
  "success": true,
  "message": "API key created successfully...",
  "data": {
    "api_key": { ... },
    "download_url": "/api/v1/admin/api-keys/key_123/download"
  }
}

# 2. 下载API Key文件
curl -X GET https://localhost:8443/api/v1/admin/api-keys/key_123/download \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -o api-key.txt
```

#### 下载文件内容示例
```
# API Key Information
# Generated: 2024-01-15 10:30:45 UTC
# Key ID: key_123
# Name: My API Key
# User ID: user_456

# API Key (keep this secure!)
sk_1234567890abcdef1234567890abcdef12345678

# Usage Instructions:
# 1. Store this key securely
# 2. Use it in the Authorization header: "Authorization: Bearer sk_1234567890abcdef1234567890abcdef12345678"
# 3. This key will not be shown again after download
# 4. If you lose this key, you'll need to regenerate it

# Security Notes:
# - Never share this key publicly
# - Store it in a secure password manager
# - Rotate keys regularly
# - Monitor key usage for suspicious activity
```

### 安全建议
1. 创建API Key后立即下载并保存到安全位置
2. 定期轮换API Key
3. 使用最小权限原则分配权限
4. 监控API Key使用情况

## 4. HTTPS强制

### 实现方式
- 添加HTTPS重定向中间件
- 自动将HTTP请求重定向到HTTPS
- 支持负载均衡器和代理的X-Forwarded-Proto头

### 配置选项
- `DISABLE_HTTPS_REDIRECT=true` - 禁用HTTPS重定向（仅用于特殊环境）
- 默认强制所有请求使用HTTPS

### 端口配置
- HTTP: 9000 (仅用于重定向)
- HTTPS: 8443 (主要服务端口)

## 部署说明

### 环境变量
```bash
# 禁用HTTPS重定向（不推荐）
export DISABLE_HTTPS_REDIRECT=true

# 开发模式
export DEV_MODE=true

# 数据库路径
export DB_PATH=data/fileserver.db
```

### 证书要求
- 生产环境需要有效的SSL证书
- 证书文件位置: `certs/server.crt` 和 `certs/server.key`
- 可以使用自签名证书进行测试

### 数据库结构
系统使用简化的数据库结构：
- `files` 表的 `checksum` 字段直接存储SHA256校验和
- 无需复杂的迁移脚本

## 安全建议

1. **定期更新**: 保持系统和依赖项的最新版本
2. **监控日志**: 定期检查访问日志和错误日志
3. **权限审计**: 定期审查API Key权限分配
4. **备份策略**: 实施定期数据备份
5. **网络安全**: 使用防火墙和网络隔离

## 故障排除

### 常见问题

1. **HTTPS重定向循环**
   - 检查证书配置
   - 确认负载均衡器配置

2. **API Key无法使用**
   - 检查权限分配
   - 确认Key未过期

3. **数据库连接问题**
   - 检查数据库文件权限
   - 查看错误日志

### 日志位置
- 应用日志: `logs/backend.log`
- 前端日志: `logs/frontend.log`
- 数据库日志: 应用日志中

## 联系支持

如有问题，请联系系统管理员或查看项目文档。
