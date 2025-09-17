# Secure File Hub - 前后端分离部署（Docker）

本文档说明如何以业界最佳实践的方式，将后端（Go，HTTPS API）与前端（Next.js）分离成两个容器，通过 `docker-compose` 进行编排与联调。

## 架构概览

- backend：Go 后端服务，HTTPS-only，暴露 8443（Compose 映射为宿主 8444）。
- frontend：Next.js 前端，HTTPS 提供页面与 `/api` 反向代理到 backend。
- 二者通过默认的 Docker 网络互联，前端通过服务名 `backend` 访问后端。

## 目录与文件

- Dockerfile.backend：后端镜像构建文件
- Dockerfile.frontend：前端镜像构建文件
- docker-compose.yml：分离后的编排文件
- certs/：HTTPS 证书（同时挂载到前后端容器）
- data/、logs/、downloads/：仅由后端容器挂载与持久化

## 快速开始

```bash
# 1) 初始化目录（首次）
mkdir -p data logs downloads configs certs

# 2) 准备证书（开发可用自签名）
#   - certs/server.crt
#   - certs/server.key

# 3) 启动（构建并运行两个服务）
docker-compose up -d --build

# 4) 访问
# 前端： https://localhost:30000
# 后端： https://localhost:8444/api/v1
```

提示：前端容器通过环境变量 `BACKEND_URL=https://backend:8443` 反向代理到后端容器，无需在浏览器中直接访问 8443。

## 运行时行为

- 后端容器：
  - 默认启用 `DISABLE_HTTPS_REDIRECT=true`，后端仅监听 8443（HTTPS）。
  - 读取 `configs/app.yaml`（可选），证书默认路径 `certs/server.crt|server.key`。
  - 数据库路径 `DB_PATH=/app/data/fileserver.db`。

- 前端容器：
  - 以 HTTPS 方式提供 Web 界面（使用 `certs/` 中证书）。
  - `server.js` 内置 `/api` 反向代理至 `BACKEND_URL`。

## docker-compose 关键配置（节选）

- backend
  - 端口：`8444:8443`
  - 卷：`data/`、`downloads/`、`logs/`、`configs/`、`certs/`
  - 健康检查：`/api/v1/health`

- frontend
  - 端口：`30000:30000`
  - 卷：`certs/`
  - 环境：`BACKEND_URL=https://backend:8443`

## 常见问题

- 证书问题：开发环境使用自签名证书时，前端已通过 `NODE_TLS_REJECT_UNAUTHORIZED=0` 放宽后端证书校验，仅用于开发/测试。生产建议使用受信任证书或在内部网络使用受信任 CA。
- 跨域问题：前端默认通过容器内的反向代理访问后端，不需要额外 CORS 配置；如果直接在浏览器访问后端域名，请确保后端 CORS 开启且配置正确。

## 从单容器迁移

- 旧的单容器方式仍保留在根目录 `Dockerfile` 中，以兼容已有 CI/CD；
- 推荐在本地与新环境使用 `docker-compose.yml` 的前后端分离方案；
- 如需 CI 推镜像，可分别构建并推送 `Dockerfile.backend` 与 `Dockerfile.frontend` 生成的镜像。

