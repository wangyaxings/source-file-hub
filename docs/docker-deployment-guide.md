# Docker 部署指南

## 概述

Secure File Hub 现在使用优化的单容器部署方案，将前端和后端合并到一个容器中，并将数据库和日志文件挂载到容器外部。

## 架构特点

### ✅ 优化完成的功能

1. **前后端合并部署** - 单个容器包含完整的前后端应用
2. **外部数据持久化** - 数据库、日志和下载文件挂载到主机目录
3. **统一镜像构建** - 合并的 GitHub Actions 工作流
4. **多平台支持** - 支持 linux/amd64 和 linux/arm64 架构

### 📁 目录结构

```
project-root/
├── data/           # 数据库文件 (外部挂载)
├── logs/           # 日志文件 (外部挂载) 
├── downloads/      # 下载文件 (外部挂载)
├── configs/        # 配置文件 (只读挂载)
├── certs/          # SSL证书 (只读挂载)
└── docker-compose.yml
```

## 部署方式

### 使用 docker-compose

```bash
# 拉取最新镜像并启动
docker-compose pull
docker-compose up -d

# 查看状态
docker-compose ps
docker-compose logs -f

# 重启服务
docker-compose restart

# 停止服务
docker-compose down
```

### 方式二：直接使用 Docker

```bash
# 创建必要目录
mkdir -p data logs downloads configs certs

# 运行容器
docker run -d \
  --name secure-file-hub \
  -p 30000:30000 \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/configs:/app/configs:ro \
  -v $(pwd)/certs:/app/certs:ro \
  ghcr.io/wangyaxings/source-file-hub:latest
```

## 镜像构建

### 自动构建（GitHub Actions）

新的工作流 `.github/workflows/docker-build.yml` 会在以下情况自动构建镜像：

- Push 到 `main`, `master`, `0912`, `develop` 分支
- 创建标签（如 `v1.0.0`）
- Pull Request

### 手动构建

```bash
# 本地构建
docker build -t secure-file-hub:local .

# 多平台构建
docker buildx build --platform linux/amd64,linux/arm64 -t secure-file-hub:multi .
```

## 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `NODE_ENV` | `production` | Node.js 环境 |
| `GO_ENV` | `production` | Go 环境 |
| `PORT` | `30000` | 前端端口 |
| `DB_PATH` | `/app/data/fileserver.db` | 数据库文件路径 |
| `LOG_PATH` | `/app/logs` | 日志目录路径 |
| `DOWNLOAD_PATH` | `/app/downloads` | 下载目录路径 |

## 端口说明

- **30000**: 前端服务端口
- **8443**: 后端 HTTPS API 端口

## 数据持久化

### 外部挂载的目录

1. **`./data`** - 数据库文件存储
   - `fileserver.db` - 主数据库文件
   - `backups/` - 数据库备份

2. **`./logs`** - 应用日志
   - 后端服务日志
   - 前端服务日志
   - 错误日志

3. **`./downloads`** - 用户下载的文件
   - 临时下载文件
   - 导出文件

### 只读挂载的目录

1. **`./configs`** - 配置文件
   - `app.yaml` - 应用配置
   - `casbin_model.conf` - 权限模型

2. **`./certs`** - SSL 证书
   - `server.crt` - 服务器证书
   - `server.key` - 私钥

## 健康检查

容器包含内置健康检查：

```bash
# 检查后端健康状态
curl -f -k https://localhost:8443/api/v1/health

# 检查前端健康状态  
curl -f http://localhost:30000
```

## 故障排除

### 查看日志
```bash
# 查看容器日志
docker-compose logs -f fileserver

# 查看应用日志（主机目录）
tail -f logs/app.log
tail -f logs/error.log
```

### 重启服务
```bash
# 重启单个服务
docker-compose restart fileserver

# 完全重建
docker-compose down
docker-compose pull
docker-compose up -d
```

### 权限问题
```bash
# 确保目录权限正确
sudo chown -R 1001:1001 data logs downloads
chmod 755 data logs downloads
```

## 监控和维护

### 资源使用
```bash
# 查看资源使用情况
docker stats secure-file-hub

# 查看镜像大小
docker images | grep secure-file-hub
```

### 备份数据
```bash
# 备份数据库
cp data/fileserver.db data/backups/fileserver_$(date +%Y%m%d_%H%M%S).db

# 备份配置
tar -czf backup_$(date +%Y%m%d).tar.gz data/ configs/ certs/
```

## 升级指南

1. 备份当前数据
2. 拉取新镜像：`docker-compose pull`
3. 重启服务：`docker-compose up -d`
4. 验证服务正常运行

## 安全注意事项

- 数据库文件存储在主机，确保适当的文件权限
- SSL 证书应定期更新
- 定期备份数据和配置
- 监控日志文件以检测异常活动