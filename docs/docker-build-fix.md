# Docker 构建问题修复说明

## 问题描述

GitHub Actions 构建时出现错误：
```
ERROR: failed to build: failed to solve: target stage "runtime" could not be found
```

## 问题原因

Dockerfile 中缺少 `AS runtime` 标签，导致构建器无法找到指定的目标阶段。

## 修复内容

### 1. 修复 Dockerfile 目标阶段标签

**修复前:**
```dockerfile
FROM alpine:3.18
```

**修复后:**
```dockerfile
FROM alpine:3.18 AS runtime
```

### 2. 验证相关文件

确保以下文件存在且正确：

- ✅ `scripts/start.sh` - 启动脚本
- ✅ `scripts/init-database.sh` - 数据库初始化脚本
- ✅ `scripts/init-clean-db.sql` - 数据库初始化 SQL
- ✅ `frontend/next.config.js` - Next.js 配置 (output: 'standalone')
- ✅ `frontend/server.js` - 前端服务器
- ✅ `frontend/package.json` - 前端依赖配置

### 3. 构建流程验证

Dockerfile 包含以下构建阶段：

1. **backend-builder**: Go 后端构建
2. **frontend-builder**: Next.js 前端构建
3. **runtime**: 运行时镜像 (目标阶段)

## 测试方法

### 本地测试构建

```bash
# 使用测试脚本
chmod +x scripts/test-docker-build.sh
./scripts/test-docker-build.sh

# 或手动构建
docker build --target runtime -t secure-file-hub:test .
```

### 验证构建结果

```bash
# 检查镜像
docker image inspect secure-file-hub:test

# 运行容器测试
docker run -d \
  --name test-container \
  -p 30000:30000 \
  -p 8443:8443 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/downloads:/app/downloads \
  -v $(pwd)/logs:/app/logs \
  secure-file-hub:test
```

## GitHub Actions 配置

### 工作流文件

`.github/workflows/docker-build-deploy.yml` 已配置：

- 多平台构建 (linux/amd64, linux/arm64)
- 构建缓存优化
- 自动推送到 GitHub Container Registry
- 部署到服务器

### 构建参数

```yaml
- name: Build and push Docker image
  uses: docker/build-push-action@v5
  with:
    context: .
    platforms: linux/amd64,linux/arm64
    push: true
    tags: ${{ steps.meta.outputs.tags }}
    target: runtime  # 指定目标阶段
    cache-from: type=gha
    cache-to: type=gha,mode=max
```

## 部署配置

### Docker Compose 配置

生产环境使用预构建镜像：

```yaml
services:
  fileserver:
    image: ghcr.io/your-username/secure-file-hub:latest
    # 不再使用本地构建
```

开发环境使用本地构建：

```yaml
services:
  fileserver:
    build:
      context: .
      dockerfile: Dockerfile
      target: runtime
```

## 故障排除

### 常见问题

1. **目标阶段未找到**
   - 检查 Dockerfile 中是否有 `AS runtime` 标签
   - 确认构建命令中指定了正确的 target

2. **前端构建失败**
   - 检查 Next.js 配置 `output: 'standalone'`
   - 确认 package.json 中的构建脚本

3. **后端构建失败**
   - 检查 Go 模块依赖
   - 确认 CGO 设置正确

4. **运行时错误**
   - 检查启动脚本权限
   - 确认环境变量配置

### 调试命令

```bash
# 查看构建日志
docker build --target runtime -t test . --progress=plain

# 检查镜像层
docker history secure-file-hub:test

# 进入容器调试
docker run -it --entrypoint /bin/sh secure-file-hub:test

# 查看容器日志
docker logs container-name
```

## 最佳实践

### 构建优化

1. **多阶段构建**: 减少最终镜像大小
2. **构建缓存**: 使用 GitHub Actions 缓存
3. **并行构建**: 后端和前端并行构建
4. **安全扫描**: 集成安全漏洞扫描

### 部署优化

1. **健康检查**: 自动验证服务状态
2. **滚动更新**: 零停机部署
3. **资源限制**: 合理设置内存和 CPU 限制
4. **日志管理**: 结构化日志记录

## 验证清单

- [ ] Dockerfile 包含 `AS runtime` 标签
- [ ] 所有必需文件存在
- [ ] 本地构建测试通过
- [ ] GitHub Actions 构建成功
- [ ] 容器健康检查通过
- [ ] 前后端服务正常启动
- [ ] 数据库初始化成功
- [ ] SSL 证书配置正确

## 下一步

1. 推送修复到 GitHub
2. 触发 GitHub Actions 构建
3. 验证部署结果
4. 更新文档和脚本
