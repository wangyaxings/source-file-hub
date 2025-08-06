# FileServer Docker 快速启动指南

## 🚀 一键启动

### Linux/macOS 用户
```bash
# 下载并运行自动化部署脚本
wget https://raw.githubusercontent.com/your-repo/FileServer/main/setup-fileserver.sh
chmod +x setup-fileserver.sh
./setup-fileserver.sh
```

### Windows 用户
```cmd
REM 下载并运行自动化部署脚本
curl -O https://raw.githubusercontent.com/your-repo/FileServer/main/setup-fileserver.bat
setup-fileserver.bat
```

## 📋 手动部署步骤

### 1. 准备环境
确保已安装 Docker 和 Docker Compose

### 2. 创建目录结构
```bash
mkdir fileserver-docker && cd fileserver-docker
mkdir -p {configs,certs,data,downloads,logs}
mkdir -p downloads/{configs,certificates,docs}
```

### 3. 下载配置文件
```bash
# 下载Docker Compose配置
curl -O https://raw.githubusercontent.com/your-repo/FileServer/main/docker-compose.simple.yml

# 下载配置文件模板
curl -o configs/config.json https://raw.githubusercontent.com/your-repo/FileServer/main/configs/config.json
```

### 4. 生成SSL证书
```bash
# 使用OpenSSL生成自签名证书
openssl genrsa -out certs/server.key 2048
openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=FileServer/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:fileserver.local,IP:127.0.0.1"
```

### 5. 启动服务
```bash
# 拉取镜像
docker pull ghcr.io/wangyaxings/source-file-hub:latest

# 启动服务
docker-compose -f docker-compose.simple.yml up -d

# 查看状态
docker-compose -f docker-compose.simple.yml ps
```

## 🧪 验证部署

### 快速测试
```bash
# Linux/macOS
curl -O https://raw.githubusercontent.com/your-repo/FileServer/main/quick-test.sh
chmod +x quick-test.sh
./quick-test.sh

# Windows PowerShell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/your-repo/FileServer/main/quick-test.ps1" -OutFile "quick-test.ps1"
.\quick-test.ps1
```

### 手动验证
```bash
# 1. 健康检查
curl -k https://localhost:8443/api/v1/health

# 2. 获取默认用户
curl -k https://localhost:8443/api/v1/auth/users

# 3. 用户登录
curl -k -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}'

# 4. 使用返回的token下载文件
curl -k -H "Authorization: Bearer YOUR_TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json
```

## 📡 服务地址

### 完整部署（前端+后端）
- **🎯 前端界面**: http://localhost:3000 （推荐访问）
- **📡 后端API**: https://localhost:8443/api/v1
- **🏥 健康检查**: https://localhost:8443/api/v1/health
- **👥 用户管理**: https://localhost:8443/api/v1/auth/users
- **📁 文件下载**: https://localhost:8443/api/v1/files/{path}

### 仅后端部署
- **📡 API根路径**: https://localhost:8443/api/v1
- **🏥 健康检查**: https://localhost:8443/api/v1/health
- **👥 用户管理**: https://localhost:8443/api/v1/auth/users
- **📁 文件下载**: https://localhost:8443/api/v1/files/{path}

## 👥 默认用户

| 租户ID | 用户名 | 密码 | 描述 |
|--------|--------|------|------|
| demo | admin | admin123 | 管理员账户 |
| demo | user1 | password123 | 普通用户账户 |

## 🛠️ 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.simple.yml logs -f

# 停止服务
docker-compose -f docker-compose.simple.yml down

# 重启服务
docker-compose -f docker-compose.simple.yml restart

# 进入容器
docker-compose -f docker-compose.simple.yml exec fileserver sh

# 备份数据
tar -czf fileserver-backup-$(date +%Y%m%d).tar.gz data/ downloads/ configs/
```

## ⚠️ 注意事项

1. **自签名证书**: 使用 `-k` 或 `-SkipCertificateCheck` 跳过SSL证书验证
2. **防火墙**: 确保8443端口可访问
3. **权限**: 确保Docker有权限访问挂载目录
4. **生产部署**: 建议使用正式的SSL证书和强密码

## 🔧 故障排除

### 常见问题

1. **端口被占用**: 修改docker-compose.yml中的端口映射
2. **权限错误**: 检查目录权限和Docker权限
3. **证书错误**: 重新生成SSL证书
4. **服务无法启动**: 查看容器日志排查问题

### 获取帮助

- 查看详细文档: `docker-deployment-guide.md`
- 检查服务日志: `docker logs fileserver-app`
- 验证配置: `docker-compose config`

---

🎉 **恭喜！您的FileServer现在已经通过Docker成功运行！**