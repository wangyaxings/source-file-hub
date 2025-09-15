# Secure File Hub 部署指南

## 📋 概述

Secure File Hub 是一个企业级的文件管理系统，采用前后端分离架构。本指南介绍如何使用优化的单容器部署方案进行发布。

## 🏗️ 架构特点

### 单容器部署优势
- **简化管理**: 一个容器管理前后端，无需处理多容器编排复杂性
- **资源优化**: 减少容器间通信开销，提高资源利用率
- **部署简化**: 减少发布步骤和潜在故障点
- **维护便利**: 统一的日志管理和监控

### 技术栈
- **后端**: Go + SQLite + Gin
- **前端**: Next.js + React + TypeScript
- **容器**: Docker (单容器架构)
- **认证**: JWT + TOTP 2FA
- **权限**: Casbin RBAC

## 🚀 快速开始

### 环境要求

- Docker >= 20.0
- Docker Compose >= 2.0
- 至少 1GB 可用内存
- 至少 5GB 可用磁盘空间

### 1. 克隆项目

```bash
git clone <repository-url>
cd secure-file-hub
```

### 2. 配置环境

```bash
# 复制配置模板
cp configs/app.yaml.example configs/app.yaml

# 编辑配置文件
vim configs/app.yaml
```

### 3. 启动服务

```bash
# 使用部署脚本（推荐）
chmod +x scripts/deploy.sh
./scripts/deploy.sh

# 或使用 Docker Compose 直接启动
docker-compose up -d
```

### 4. 验证部署

```bash
# 检查服务状态
docker-compose ps

# 查看服务日志
docker-compose logs -f

# 验证服务健康状态
curl -k https://localhost:8443/api/v1/health
curl http://localhost:30000
```

## 📁 项目结构

```
secure-file-hub/
├── Dockerfile                 # 优化的单容器构建文件
├── docker-compose.yml         # 容器编排配置
├── scripts/
│   └── deploy.sh             # 自动化部署脚本
├── frontend/                 # Next.js 前端应用
├── internal/                 # Go 后端代码
├── configs/                  # 配置文件
├── certs/                    # SSL 证书
├── data/                     # 持久化数据
├── downloads/                # 文件存储
└── logs/                     # 应用日志
```

## 🛠️ 部署配置

### Docker Compose 配置

```yaml
version: '3.8'

services:
  fileserver:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "30000:30000"   # 前端端口
      - "8443:8443"     # 后端端口
    volumes:
      - fileserver_data:/app/data
      - fileserver_downloads:/app/downloads
      - ./configs:/app/configs:ro
      - ./certs:/app/certs:ro
    environment:
      - NODE_ENV=production
      - GO_ENV=production
      - DISABLE_HTTPS_REDIRECT=true
    restart: unless-stopped
```

### 环境变量说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `NODE_ENV` | `production` | 前端运行环境 |
| `GO_ENV` | `production` | 后端运行环境 |
| `PORT` | `30000` | 前端服务端口 |
| `HOSTNAME` | `0.0.0.0` | 前端绑定地址 |
| `BACKEND_URL` | `https://localhost:8443` | 后端API地址 |
| `DISABLE_HTTPS_REDIRECT` | `true` | 禁用HTTPS重定向 |

## 🔧 部署选项

### 方式1: 自动化部署脚本

```bash
# 基本部署
./scripts/deploy.sh

# 指定镜像仓库
./scripts/deploy.sh -r registry.example.com

# 指定版本标签
./scripts/deploy.sh -t v1.0.0

# 跳过构建（使用现有镜像）
./scripts/deploy.sh --skip-build
```

### 方式2: Docker Compose 手动部署

```bash
# 构建镜像
docker-compose build

# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

### 方式3: 生产环境部署

```bash
# 使用生产配置
export ENVIRONMENT=production
export DOCKER_REGISTRY=your-registry.com
export IMAGE_TAG=v1.0.0

./scripts/deploy.sh
```

## 📊 监控和维护

### 健康检查

```bash
# 检查容器状态
docker-compose ps

# 检查服务健康
curl -k https://localhost:8443/api/v1/health
curl http://localhost:30000

# 查看资源使用
docker stats secure-file-hub
```

### 日志管理

```bash
# 查看应用日志
docker-compose logs -f

# 查看后端日志
docker-compose logs -f | grep "backend"

# 查看前端日志
docker-compose logs -f | grep "frontend"
```

### 数据备份

```bash
# 备份数据卷
docker run --rm -v fileserver_data:/data -v $(pwd):/backup alpine tar czf /backup/backup-data.tar.gz -C /data .

# 备份下载文件
docker run --rm -v fileserver_downloads:/downloads -v $(pwd):/backup alpine tar czf /backup/backup-downloads.tar.gz -C /downloads .
```

## 🔄 更新部署

### 滚动更新

```bash
# 重新构建并部署
./scripts/deploy.sh

# 或手动更新
docker-compose build --no-cache
docker-compose up -d
```

### 零停机更新

```bash
# 启动新版本
docker-compose up -d --scale fileserver=2

# 等待新实例就绪
sleep 30

# 停止旧实例
docker-compose up -d --scale fileserver=1
```

## 🚨 故障排除

### 常见问题

#### 1. 端口冲突
```bash
# 检查端口占用
netstat -tlnp | grep :30000
netstat -tlnp | grep :8443

# 修改端口映射
# 编辑 docker-compose.yml 中的 ports 配置
```

#### 2. 权限问题
```bash
# 检查文件权限
ls -la data/
ls -la downloads/

# 修复权限
sudo chown -R 1001:1001 data/ downloads/
```

#### 3. 内存不足
```bash
# 检查系统内存
free -h

# 增加Docker内存限制
# 编辑 docker-compose.yml 中的 deploy.resources 配置
```

#### 4. 启动失败
```bash
# 查看详细日志
docker-compose logs --tail=100

# 检查容器状态
docker inspect secure-file-hub

# 重新启动
docker-compose restart
```

### 调试模式

```bash
# 以调试模式启动
docker-compose up

# 进入容器调试
docker exec -it secure-file-hub /bin/sh

# 检查进程状态
ps aux

# 检查网络连接
netstat -tlnp
```

## 🔒 安全配置

### HTTPS 配置

```bash
# 放置SSL证书
cp your-cert.pem certs/
cp your-key.pem certs/

# 更新环境变量
export BACKEND_URL=https://your-domain.com:8443
```

### 防火墙配置

```bash
# 只开放必要端口
ufw allow 30000/tcp
ufw allow 8443/tcp
ufw deny 22/tcp  # 如果不需要SSH
```

### 资源限制

```yaml
# 在 docker-compose.yml 中添加资源限制
deploy:
  resources:
    limits:
      memory: 2G
      cpus: '2.0'
    reservations:
      memory: 512M
      cpus: '0.5'
```

## 📈 性能优化

### 镜像优化

- 使用多阶段构建减少镜像大小
- 使用 `.dockerignore` 文件排除不必要的文件
- 启用BuildKit加速构建

### 应用优化

```bash
# 设置适当的资源限制
# 启用Gzip压缩
# 配置适当的缓存策略
# 优化数据库连接池
```

### 系统优化

```bash
# 增加系统文件描述符限制
echo "fs.file-max = 65536" >> /etc/sysctl.conf

# 优化Docker性能
# 编辑 /etc/docker/daemon.json
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

## 📚 相关文档

- [API文档](./api-guide.md)
- [开发指南](./development-guide.md)
- [测试指南](./testing-guide.md)
- [故障排除](./troubleshooting.md)

## 🆘 支持

如果遇到部署问题，请：

1. 查看本文档的故障排除部分
2. 检查应用日志
3. 查看系统资源使用情况
4. 联系开发团队

---

**最后更新**: 2025-09-15
**版本**: v1.0.0