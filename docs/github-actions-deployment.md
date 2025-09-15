# GitHub Actions Docker 部署指南

## 概述

本项目配置了完整的 GitHub Actions 工作流，支持自动构建 Docker 镜像并通过 Docker Compose 部署到服务器。

## 工作流程

### 1. 自动触发条件
- **推送代码**: 推送到 `main`、`master`、`develop` 分支
- **创建标签**: 创建 `v*` 格式的标签
- **Pull Request**: 创建到主分支的 PR

### 2. 构建流程
1. **检出代码**: 获取最新源代码
2. **设置 Docker Buildx**: 配置多平台构建
3. **登录容器注册表**: 使用 GitHub Token 登录
4. **提取元数据**: 生成镜像标签和标签
5. **构建推送镜像**: 构建并推送到 GitHub Container Registry
6. **生成部署信息**: 创建部署配置

### 3. 部署流程
1. **环境检查**: 验证部署环境
2. **目录设置**: 创建必要的目录结构
3. **停止服务**: 停止现有容器
4. **拉取镜像**: 拉取最新构建的镜像
5. **启动服务**: 使用 Docker Compose 启动服务
6. **健康检查**: 验证服务是否正常运行

## 配置要求

### GitHub Secrets 配置

在 GitHub 仓库设置中添加以下 Secrets：

```bash
# 部署服务器配置
DEPLOY_HOST=your-server-ip-or-domain
DEPLOY_USER=your-username
DEPLOY_SSH_KEY=your-private-ssh-key
DEPLOY_PORT=22  # 可选，默认 22
```

### 服务器环境要求

1. **Docker**: 安装 Docker Engine
2. **Docker Compose**: 安装 Docker Compose
3. **SSH 访问**: 配置 SSH 密钥认证
4. **网络访问**: 能够访问 GitHub Container Registry

## 使用方法

### 1. 首次部署

#### 在服务器上初始化目录结构
```bash
# 下载并运行目录初始化脚本
curl -fsSL https://raw.githubusercontent.com/your-username/secure-file-hub/main/scripts/setup-directories.sh | bash

# 或者手动运行
./scripts/setup-directories.sh -d /opt/secure-file-hub
```

#### 配置 GitHub Secrets
1. 进入 GitHub 仓库设置
2. 选择 "Secrets and variables" > "Actions"
3. 添加必要的 Secrets

#### 推送代码触发部署
```bash
git add .
git commit -m "Initial deployment setup"
git push origin main
```

### 2. 日常部署

#### 自动部署
```bash
# 推送代码到主分支
git push origin main

# 或创建标签
git tag v1.0.0
git push origin v1.0.0
```

#### 手动部署
```bash
# 在服务器上运行部署脚本
./scripts/deploy.sh

# 或使用指定镜像
./scripts/deploy.sh -i ghcr.io/your-username/secure-file-hub:v1.0.0
```

### 3. 开发环境

#### 本地开发
```bash
# 使用开发环境配置
docker-compose -f docker-compose.dev.yml up -d --build
```

#### 本地测试
```bash
# 构建镜像
docker build -t secure-file-hub:local .

# 运行容器
docker run -d \
  -p 30000:30000 \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/logs:/app/logs \
  secure-file-hub:local
```

## 目录结构

### 服务器目录结构
```
/opt/secure-file-hub/          # 部署根目录
├── data/                      # 数据库文件
├── downloads/                 # 用户文件
├── logs/                      # 日志文件
├── configs/                   # 配置文件
├── certs/                     # SSL 证书
├── scripts/                   # 脚本文件
├── backups/                   # 备份文件
├── docker-compose.yml         # 生产环境配置
├── docker-compose.clean.yml   # 清理环境配置
├── .env                       # 环境变量
├── start.sh                   # 启动脚本
├── stop.sh                    # 停止脚本
├── restart.sh                 # 重启脚本
├── logs.sh                    # 日志查看脚本
└── backup.sh                  # 备份脚本
```

### 容器内部目录
```
/app/
├── data/                      # 挂载到主机 ./data
├── downloads/                 # 挂载到主机 ./downloads
├── logs/                      # 挂载到主机 ./logs
├── configs/                   # 挂载到主机 ./configs (只读)
├── certs/                     # 挂载到主机 ./certs (只读)
└── frontend/                  # 前端应用文件
```

## 镜像管理

### 镜像标签策略
- `latest`: 主分支最新版本
- `v1.0.0`: 语义化版本标签
- `v1.0`: 主版本标签
- `main`: 分支标签
- `pr-123`: Pull Request 标签

### 镜像拉取
```bash
# 拉取最新镜像
docker pull ghcr.io/your-username/secure-file-hub:latest

# 拉取特定版本
docker pull ghcr.io/your-username/secure-file-hub:v1.0.0

# 查看可用标签
docker search ghcr.io/your-username/secure-file-hub
```

## 监控和维护

### 健康检查
```bash
# 检查服务状态
docker-compose ps

# 查看日志
docker-compose logs -f

# 手动健康检查
curl -f -k https://localhost:8443/api/v1/health
curl -f http://localhost:30000
```

### 备份和恢复
```bash
# 创建备份
./backup.sh

# 恢复备份
tar -xzf backups/secure-file-hub-backup-20240101_120000.tar.gz
```

### 更新部署
```bash
# 停止服务
docker-compose down

# 拉取最新镜像
docker pull ghcr.io/your-username/secure-file-hub:latest

# 启动服务
docker-compose up -d
```

## 故障排除

### 常见问题

#### 1. 镜像拉取失败
```bash
# 检查网络连接
ping ghcr.io

# 检查认证
docker login ghcr.io

# 手动拉取镜像
docker pull ghcr.io/your-username/secure-file-hub:latest
```

#### 2. 容器启动失败
```bash
# 查看详细日志
docker-compose logs

# 检查配置文件
cat docker-compose.yml

# 检查目录权限
ls -la data/ downloads/ logs/
```

#### 3. 健康检查失败
```bash
# 检查端口占用
netstat -tlnp | grep -E ':(30000|8443)'

# 检查防火墙
ufw status

# 检查 SSL 证书
openssl x509 -in certs/server.crt -text -noout
```

### 日志分析
```bash
# 查看应用日志
tail -f logs/backend.log

# 查看容器日志
docker-compose logs -f fileserver

# 查看系统日志
journalctl -u docker -f
```

## 安全考虑

### 1. SSH 密钥管理
- 使用专用部署密钥
- 定期轮换密钥
- 限制密钥权限

### 2. 容器安全
- 使用非 root 用户运行
- 定期更新基础镜像
- 扫描镜像漏洞

### 3. 网络安全
- 配置防火墙规则
- 使用 HTTPS
- 限制网络访问

### 4. 数据安全
- 定期备份数据
- 加密敏感数据
- 监控访问日志

## 性能优化

### 1. 资源限制
```yaml
deploy:
  resources:
    limits:
      memory: 1G
      cpus: '1.0'
    reservations:
      memory: 256M
      cpus: '0.5'
```

### 2. 缓存优化
- 使用 Docker 层缓存
- 配置构建缓存
- 优化镜像大小

### 3. 网络优化
- 使用本地镜像仓库
- 配置 CDN
- 优化网络配置

## 扩展部署

### 多环境部署
```bash
# 生产环境
docker-compose -f docker-compose.yml up -d

# 测试环境
docker-compose -f docker-compose.test.yml up -d

# 开发环境
docker-compose -f docker-compose.dev.yml up -d
```

### 集群部署
- 使用 Docker Swarm
- 配置负载均衡
- 实现高可用性

### 监控集成
- 集成 Prometheus
- 配置 Grafana
- 设置告警规则
