# FileServer Deployment Guide

## 概述

本指南将详细说明如何使用预构建的Docker镜像 `ghcr.io/wangyaxings/source-file-hub:latest` 部署FileServer项目。

## 前置要求

- Docker 20.0+
- Docker Compose 2.0+
- 至少 2GB 可用磁盘空间

## 快速开始

### 1. 创建项目目录结构

```bash
# 创建主目录
mkdir fileserver-docker
cd fileserver-docker

# 创建必要的子目录
mkdir -p {configs,certs,data,downloads,logs}
mkdir -p downloads/{configs,certificates,docs}
```

### 2. 准备配置文件

创建 `configs/config.json`:

```json
{
  "server": {
    "host": "0.0.0.0",
    "https_port": 8443,
    "read_timeout": "30s",
    "write_timeout": "30s",
    "ssl_enabled": true,
    "cert_file": "certs/server.crt",
    "key_file": "certs/server.key"
  },
  "application": {
    "name": "FileServer",
    "version": "4.0.0",
    "environment": "production",
    "protocol": "https"
  },
  "logging": {
    "level": "info",
    "format": "json"
  },
  "features": {
    "download_enabled": true,
    "cors_enabled": true,
    "auth_enabled": true,
    "ssl_enabled": true,
    "unified_file_download": true,
    "authenticated_downloads": true
  },
  "auth": {
    "token_expiry": "24h",
    "require_auth": true,
    "default_users": [
      {
        "tenant_id": "demo",
        "username": "admin",
        "description": "管理员账户"
      },
      {
        "tenant_id": "demo",
        "username": "user1",
        "description": "普通用户账户"
      }
    ]
  },
  "downloads": {
    "base_directory": "downloads",
    "allowed_paths": [
      "configs/",
      "certificates/",
      "docs/"
    ],
    "supported_types": [".json", ".crt", ".key", ".txt", ".log", ".pem"]
  }
}
```

### 3. 生成SSL证书

创建证书生成脚本 `generate-certs.sh`:

```bash
#!/bin/bash

# 生成SSL证书用于HTTPS
openssl genrsa -out certs/server.key 2048

openssl req -new -x509 -key certs/server.key -out certs/server.crt -days 365 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=FileServer/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:fileserver.local,IP:127.0.0.1"

# 生成证书信息文件
cat > certs/cert_info.json << 'EOF'
{
  "subject": {
    "common_name": "localhost",
    "organization": ["FileServer"],
    "country": ["CN"],
    "province": ["Beijing"],
    "locality": ["Beijing"]
  },
  "validity": {
    "not_before": "$(date -d 'now' -Iseconds)",
    "not_after": "$(date -d '+365 days' -Iseconds)"
  },
  "key_usage": ["Digital Signature", "Key Encipherment"],
  "ext_key_usage": ["Server Authentication"],
  "dns_names": ["localhost", "fileserver.local"],
  "ip_addresses": ["127.0.0.1", "::1"],
  "key_size": 2048,
  "signature_algorithm": "SHA256-RSA",
  "files": {
    "certificate": "server.crt",
    "private_key": "server.key"
  }
}
EOF

echo "✅ SSL证书生成完成"
echo "  证书文件: certs/server.crt"
echo "  私钥文件: certs/server.key"
echo "  证书信息: certs/cert_info.json"
```

执行生成证书:
```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

### 4. 创建Docker Compose配置

创建 `docker-compose.yml`:

```yaml
version: '3.8'

services:
  fileserver:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: fileserver-app
    ports:
      - "8443:8443"  # HTTPS端口
    volumes:
      # 持久化数据
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      # 配置文件 (只读)
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
    environment:
      - GO_ENV=production
      - DB_PATH=/app/data/fileserver.db
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:8443/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge

volumes:
  # 如果需要外部卷管理，可以定义命名卷
  fileserver_data:
    driver: local
  fileserver_logs:
    driver: local
```

### 5. 准备初始下载文件

复制配置文件到下载目录:
```bash
# 复制配置文件到下载目录
cp configs/config.json downloads/configs/
cp certs/server.crt downloads/certificates/
cp certs/server.key downloads/certificates/
cp certs/cert_info.json downloads/certificates/

# 创建API文档
cat > downloads/docs/api_guide.txt << 'EOF'
FileServer API 使用指南

基础信息:
- API Base URL: https://localhost:8443/api/v1
- 认证方式: Bearer Token
- 协议: HTTPS Only

主要接口:
1. 健康检查: GET /health
2. 用户登录: POST /auth/login
3. 获取用户: GET /auth/users
4. 文件下载: GET /files/{path}
5. 用户登出: POST /auth/logout

使用步骤:
1. 调用 /auth/users 获取测试用户
2. 调用 /auth/login 登录获取token
3. 使用token访问 /files/* 下载文件
4. 调用 /auth/logout 登出

注意事项:
- 所有API都需要HTTPS访问
- 文件下载需要用户认证
- Token有效期24小时
EOF
```

## 启动服务

### 6. 拉取镜像并启动

```bash
# 拉取最新镜像
docker pull ghcr.io/wangyaxings/source-file-hub:latest

# 启动服务
docker-compose up -d

# 查看服务状态
docker-compose ps

# 查看日志
docker-compose logs -f fileserver
```

### 7. 验证服务运行

```bash
# 检查健康状态
curl -k https://localhost:8443/api/v1/health

# 获取API信息
curl -k https://localhost:8443/api/v1

# 获取默认用户列表
curl -k https://localhost:8443/api/v1/auth/users
```

## 完整测试流程

### 8. API功能验证

```bash
# 1. 用户登录
RESPONSE=$(curl -k -s -X POST https://localhost:8443/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"tenant_id": "demo", "username": "admin", "password": "admin123"}')

# 2. 提取token
TOKEN=$(echo $RESPONSE | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
echo "Token: $TOKEN"

# 3. 下载配置文件
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/configs/config.json

# 4. 下载SSL证书
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/certificates/server.crt

# 5. 下载API文档
curl -k -H "Authorization: Bearer $TOKEN" \
  -O -J https://localhost:8443/api/v1/files/docs/api_guide.txt

# 6. 用户登出
curl -k -X POST https://localhost:8443/api/v1/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

## 管理操作

### 9. 服务管理命令

```bash
# 停止服务
docker-compose down

# 重启服务
docker-compose restart

# 查看实时日志
docker-compose logs -f

# 进入容器
docker-compose exec fileserver sh

# 备份数据
tar -czf fileserver-backup-$(date +%Y%m%d).tar.gz data/ downloads/ configs/

# 清理（慎用 - 会删除所有数据）
docker-compose down -v
```

### 10. 故障排除

```bash
# 查看容器状态
docker ps -a

# 查看详细日志
docker logs fileserver-app

# 检查配置文件
docker-compose config

# 检查网络连接
docker network ls
docker network inspect fileserver_fileserver-network

# 检查卷挂载
docker inspect fileserver-app | grep -A 20 "Mounts"
```

## 高级配置

### 11. 生产环境优化

对于生产环境，创建 `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  fileserver:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: fileserver-prod
    ports:
      - "8443:8443"
    volumes:
      # 使用绝对路径挂载
      - /var/lib/fileserver/data:/app/data
      - /var/lib/fileserver/downloads:/app/downloads
      - /var/log/fileserver:/app/logs
      - /etc/fileserver/configs:/app/configs:ro
      - /etc/ssl/fileserver:/app/certs:ro
    environment:
      - GO_ENV=production
      - DB_PATH=/app/data/fileserver.db
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD", "curl", "-k", "-f", "https://localhost:8443/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge
    name: fileserver-prod-network
```

### 12. 反向代理配置 (可选)

如需要通过Nginx反向代理，创建 `nginx.conf`:

```nginx
upstream fileserver_backend {
    server fileserver:8443;
}

server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    location / {
        proxy_pass https://fileserver_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_ssl_verify off;
    }
}
```

## 安全建议

1. **更换默认密码**: 登录后立即更改默认用户密码
2. **使用正式证书**: 生产环境使用CA签发的SSL证书
3. **定期备份**: 设置自动备份数据库和配置文件
4. **网络隔离**: 使用防火墙限制访问端口
5. **日志监控**: 定期检查访问日志发现异常
6. **更新镜像**: 定期拉取最新镜像获取安全更新

## 常见问题

**Q: 容器启动失败怎么办？**
A: 检查日志 `docker logs fileserver-app`，通常是配置文件或权限问题

**Q: 无法访问HTTPS服务？**
A: 确认证书文件存在且格式正确，检查防火墙设置

**Q: 文件下载失败？**
A: 检查downloads目录权限，确认文件存在于allowed_paths中

**Q: 如何更新服务？**
A: 拉取新镜像后执行 `docker-compose up -d` 会自动重启服务

---

💡 **提示**: 首次启动建议先在测试环境验证所有功能正常后再部署到生产环境。