# Secure File Hub - Docker 完整部署指南

## 概述

本指南提供了在 Ubuntu 系统上使用 Docker 部署 Secure File Hub 的完整步骤，包括环境准备、首次部署、数据备份和更新操作。

## 前置要求

- Ubuntu 18.04+ 系统
- 已安装 Docker 和 Docker Compose
- 具有 sudo 权限的用户账户

### 安装 Docker（如果未安装）

```bash
# 更新系统包
sudo apt update

# 安装 Docker
sudo apt install -y docker.io docker-compose

# 启动 Docker 服务
sudo systemctl start docker
sudo systemctl enable docker

# 将当前用户添加到 docker 组
sudo usermod -aG docker $USER

# 重新登录或执行以下命令使组权限生效
newgrp docker

# 验证安装
docker --version
docker-compose --version
```

## 快速部署

### 自动化部署（推荐）

如果您从 GitHub 克隆了完整项目，可以使用自动化部署脚本：

```bash
# 克隆项目（如果还没有）
git clone https://github.com/wangyaxings/source-file-hub.git
cd source-file-hub

# 运行自动部署脚本
chmod +x setup.sh
./setup.sh
```

自动化脚本将完成以下操作：
- 检查并安装 Docker 和 Docker Compose
- 创建必要的目录结构
- 生成 SSL 证书
- 创建配置文件
- 设置目录权限
- 启动服务

### 手动部署

如果您喜欢手动控制每个步骤，请按照以下说明操作：

#### 1. 创建项目目录

```bash
# 创建项目根目录
mkdir -p ~/secure-file-hub
cd ~/secure-file-hub

# 创建必要的数据目录
mkdir -p data downloads logs configs certs

# 如果有自动部署脚本，设置执行权限
chmod +x setup.sh backup.sh 2>/dev/null || true
```

### 2. 创建配置文件

创建 `docker-compose.yml` 文件：

```yaml
version: '3.8'

services:
  fileserver:
    image: ghcr.io/wangyaxings/source-file-hub:latest
    container_name: secure-file-hub
    ports:
      - "30000:30000"   # 前端端口
      - "8443:8443"     # 后端 HTTPS 端口
    volumes:
      # 数据持久化
      - ./data:/app/data
      - ./downloads:/app/downloads
      - ./logs:/app/logs
      # 配置文件（只读）
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
    environment:
      - NODE_ENV=production
      - GO_ENV=production
      - NODE_TLS_REJECT_UNAUTHORIZED=0
      - DISABLE_HTTPS_REDIRECT=true
      - DB_PATH=/app/data/fileserver.db
      - PORT=30000
      - HOSTNAME=0.0.0.0
      - NEXT_PUBLIC_API_URL=https://localhost:8443
      - BACKEND_URL=https://localhost:8443
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 256M
          cpus: '0.5'
    healthcheck:
      test: ["CMD", "curl", "-f", "-k", "https://localhost:8443/api/v1/health", "&&", "curl", "-f", "http://localhost:30000"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
    networks:
      - fileserver-network

networks:
  fileserver-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 3. 创建基础配置

创建应用配置文件 `configs/app.yaml`：

```yaml
server:
  host: 0.0.0.0
  port: 8443
  tls:
    cert_file: certs/server.crt
    key_file: certs/server.key

database:
  driver: sqlite
  database: data/fileserver.db

security: {}
storage: {}
```

### 4. 生成 SSL 证书

```bash
# 创建自签名证书（用于开发和测试）
cd certs

# 生成私钥
openssl genrsa -out server.key 2048

# 生成证书签名请求
openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"

# 生成自签名证书
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt

# 删除临时文件
rm server.csr

# 设置权限
chmod 600 server.key
chmod 644 server.crt

cd ..
```

### 5. 设置目录权限

```bash
# 设置数据目录权限（容器内用户 UID:1001）
sudo chown -R 1001:1001 data downloads logs
chmod -R 755 data downloads logs

# 设置配置和证书目录权限
chmod -R 644 configs/ certs/
```

### 6. 启动服务

```bash
# 拉取最新镜像
docker-compose pull

# 启动服务
docker-compose up -d

# 查看启动日志
docker-compose logs -f
```

### 7. 验证部署

```bash
# 检查容器状态
docker-compose ps

# 检查健康状态
docker-compose exec fileserver curl -k https://localhost:8443/api/v1/health

# 访问应用
echo "前端访问地址: http://localhost:30000"
echo "后端 API 地址: https://localhost:8443"
```

## 首次访问

应用启动后，可以通过以下方式访问：

- **前端界面**: http://localhost:30000
- **默认管理员账户**:
  - 用户名: `admin`
  - 密码: `admin123`

> ⚠️ **重要**: 首次登录后请立即修改默认密码！

## 数据管理

### 数据备份

#### 使用备份脚本（推荐）

项目提供了自动化备份脚本：

```bash
# 设置执行权限
chmod +x backup.sh

# 创建完整备份
./backup.sh backup all

# 仅备份数据库
./backup.sh backup data

# 仅备份用户文件
./backup.sh backup files

# 列出所有备份
./backup.sh list

# 清理7天前的备份
./backup.sh cleanup 7
```

#### 手动备份

```bash
# 停止服务（可选，建议备份前停止）
docker-compose stop

# 备份所有数据
tar -czf backup-$(date +%Y%m%d-%H%M%S).tar.gz data/ downloads/ logs/ configs/ certs/

# 仅备份数据库
cp data/fileserver.db backup-fileserver-$(date +%Y%m%d-%H%M%S).db

# 重新启动服务
docker-compose start
```

### 数据恢复

```bash
# 停止服务
docker-compose stop

# 恢复所有数据
tar -xzf backup-20240101-120000.tar.gz

# 或仅恢复数据库
cp backup-fileserver-20240101-120000.db data/fileserver.db

# 设置权限
sudo chown -R 1001:1001 data downloads logs

# 重新启动服务
docker-compose start
```

## 更新应用

### 更新到最新版本

```bash
# 备份数据（推荐）
tar -czf backup-before-update-$(date +%Y%m%d-%H%M%S).tar.gz data/ downloads/ logs/

# 停止当前服务
docker-compose stop

# 拉取最新镜像
docker-compose pull

# 启动服务
docker-compose up -d

# 查看启动日志
docker-compose logs -f
```

### 更新到指定版本

```bash
# 修改 docker-compose.yml 中的镜像标签
# 将 image: ghcr.io/wangyaxings/source-file-hub:latest
# 改为 image: ghcr.io/wangyaxings/source-file-hub:v1.2.3

# 拉取指定版本
docker-compose pull

# 重启服务
docker-compose up -d
```

## 清理重新部署

如果需要完全重新开始（⚠️ 这将删除所有数据）：

```bash
# 停止并删除容器
docker-compose down

# 删除所有数据（谨慎操作！）
sudo rm -rf data/* downloads/* logs/*

# 重新创建目录权限
sudo chown -R 1001:1001 data downloads logs

# 重新启动
docker-compose up -d
```

## 生产环境优化

### 1. 使用外部数据库（可选）

对于生产环境，可以考虑使用外部数据库：

```yaml
# 在 docker-compose.yml 中添加
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: fileserver
      POSTGRES_USER: fileserver
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

### 2. 反向代理配置

使用 Nginx 作为反向代理：

```nginx
# /etc/nginx/sites-available/fileserver
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/ssl/cert.pem;
    ssl_certificate_key /path/to/ssl/private.key;

    # 前端代理
    location / {
        proxy_pass http://localhost:30000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 后端 API 代理
    location /api/ {
        proxy_pass https://localhost:8443;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3. 日志管理

配置日志轮转：

```bash
# 创建 logrotate 配置
sudo tee /etc/logrotate.d/secure-file-hub > /dev/null <<EOF
/home/user/secure-file-hub/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    notifempty
    copytruncate
    postrotate
        docker-compose -f /home/user/secure-file-hub/docker-compose.yml restart fileserver
    endscript
}
EOF
```

## 故障排除

### 常见问题

1. **容器无法启动**
   ```bash
   # 查看详细日志
   docker-compose logs fileserver
   
   # 检查目录权限
   ls -la data/ downloads/ logs/
   
   # 重新设置权限
   sudo chown -R 1001:1001 data downloads logs
   ```

2. **端口冲突**
   ```bash
   # 检查端口占用
   sudo netstat -tlnp | grep -E ':(30000|8443)'
   
   # 修改 docker-compose.yml 中的端口映射
   ports:
     - "30001:30000"
     - "8444:8443"
   ```

3. **SSL 证书问题**
   ```bash
   # 重新生成证书
   cd certs
   rm -f server.crt server.key
   openssl genrsa -out server.key 2048
   openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=State/L=City/O=Organization/CN=localhost"
   openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
   rm server.csr
   ```

4. **数据库初始化失败**
   ```bash
   # 删除现有数据库
   rm -f data/fileserver.db
   
   # 重启容器让其重新初始化
   docker-compose restart fileserver
   ```

### 调试命令

```bash
# 进入容器调试
docker-compose exec fileserver sh

# 查看容器资源使用情况
docker stats secure-file-hub

# 查看容器详细信息
docker inspect secure-file-hub

# 查看网络连接
docker-compose exec fileserver netstat -tlnp
```

## 性能监控

### 监控脚本

创建简单的监控脚本 `monitor.sh`：

```bash
#!/bin/bash

# 检查容器状态
if ! docker-compose ps | grep -q "Up"; then
    echo "$(date): Container is down!" >> monitor.log
    docker-compose restart fileserver
fi

# 检查服务可用性
if ! curl -f -k https://localhost:8443/api/v1/health >/dev/null 2>&1; then
    echo "$(date): Backend health check failed!" >> monitor.log
fi

if ! curl -f http://localhost:30000 >/dev/null 2>&1; then
    echo "$(date): Frontend health check failed!" >> monitor.log
fi
```

添加到 crontab：
```bash
# 每5分钟检查一次
*/5 * * * * /path/to/secure-file-hub/monitor.sh
```

## 安全建议

1. **定期更新**
   - 定期更新 Docker 镜像到最新版本
   - 监控安全漏洞通知

2. **访问控制**
   - 使用防火墙限制访问端口
   - 配置强密码策略
   - 启用双因素认证

3. **数据保护**
   - 定期备份数据
   - 加密敏感数据
   - 使用有效的 SSL 证书

4. **日志审计**
   - 定期检查访问日志
   - 监控异常活动
   - 保留审计记录

## GitHub Actions 构建问题解决

如果在 GitHub Actions 中遇到 attestation 相关错误，可以尝试以下解决方案：

### 解决方案 1：使用修复后的工作流
主工作流文件已经更新，包含以下修复：
- 添加了必要的权限 (`attestations: write`, `actions: read`)
- 设置了 `continue-on-error: true` 使 attestation 失败不会中断构建
- 添加了条件检查，只在 tag 推送时运行 attestation

### 解决方案 2：使用简化版工作流
如果仍有问题，可以使用简化版工作流：
```bash
# 重命名当前工作流（备份）
mv .github/workflows/docker-build.yml .github/workflows/docker-build-with-attestation.yml.bak

# 使用简化版工作流
mv .github/workflows/docker-build-simple.yml .github/workflows/docker-build.yml
```

简化版工作流移除了 attestation 步骤，但保留了所有核心功能。

### 解决方案 3：完全禁用 attestation
在主工作流中注释掉 attestation 步骤：
```yaml
# - name: Generate artifact attestation
#   uses: actions/attest-build-provenance@v2
#   ...
```

## 总结

本指南提供了 Secure File Hub 的完整 Docker 部署流程。按照以上步骤，您可以快速在 Ubuntu 系统上部署并运行应用程序。

如有问题，请检查日志文件或参考故障排除部分。建议在生产环境中实施额外的安全措施和监控。