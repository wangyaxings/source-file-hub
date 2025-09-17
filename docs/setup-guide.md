# Secure File Hub 部署指南

## 快速开始

### 一键部署

```bash
# 克隆项目
git clone <repository-url>
cd source-file-hub

# 一键部署（包含权限设置）
./setup.sh
```

### 部署完成后

- **前端访问**: http://localhost:30000
- **后端API**: https://localhost:8444
- **默认账户**: admin / admin123

## 权限管理

所有权限相关操作都通过 `setup.sh` 脚本统一管理：

```bash
# 查看权限状态
./setup.sh --status

# 仅设置权限
./setup.sh --permissions

# 验证权限设置
./setup.sh --validate

# 使用Docker修复权限
./setup.sh --docker-fix

# 显示帮助信息
./setup.sh --help
```

## 目录权限配置

| 目录 | 权限 | 所有者 | 用途 |
|------|------|--------|------|
| `data/` | 755 | 1001:1001 | 数据库文件 |
| `downloads/` | 755 | 1001:1001 | 下载文件存储 |
| `logs/` | 755 | 1001:1001 | 日志文件 |
| `configs/` | 644 | root:root | 配置文件 |
| `certs/` | 600 | root:root | SSL证书 |

## 常见问题

### 权限问题

如果遇到权限相关错误：

```bash
# 修复权限
./setup.sh --permissions

# 或使用Docker修复
./setup.sh --docker-fix
```

### 服务启动失败

```bash
# 查看容器日志
docker-compose logs fileserver

# 重启服务
docker-compose restart
```

## API使用

### Web界面
- 访问 http://localhost:30000 使用Web界面

### 外部API
- 基础地址: https://localhost:8444/api/v1/public/
- 健康检查: https://localhost:8444/api/v1/health
- 需要API Key认证

详细API使用说明请参考 [API使用指南](api-key-usage.md)

## 安全建议

1. **立即修改默认密码**: 部署完成后立即登录并修改admin密码
2. **证书管理**: 生产环境请使用正式的SSL证书
3. **权限检查**: 定期使用 `./setup.sh --validate` 检查权限设置
4. **备份数据**: 定期备份 `data/` 目录中的数据库文件

## 维护

### 更新服务

```bash
# 拉取最新镜像
docker-compose pull

# 重启服务
docker-compose restart
```

### 查看服务状态

```bash
# 查看容器状态
docker-compose ps

# 查看日志
docker-compose logs -f fileserver
```

通过统一的 `setup.sh` 脚本，所有部署和权限管理操作都变得简单而一致。
