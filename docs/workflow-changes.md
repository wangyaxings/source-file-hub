# GitHub Actions Workflow 修改说明

## 修改概述

本次修改将 Docker Build and Push workflow 的触发条件从每次代码推送改为仅在推送 tag 时触发，同时保留手动触发功能。

## 修改详情

### 触发条件变更

**修改前：**
```yaml
on:
  push:
    branches: [ 0912, main, master, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ 0912, main, master ]
  workflow_dispatch:
```

**修改后：**
```yaml
on:
  push:
    tags: [ 'v*' ]
  workflow_dispatch:
```

### 主要变更

1. **移除分支推送触发**：不再在每次推送到指定分支时触发构建
2. **移除 Pull Request 触发**：不再在创建或更新 PR 时触发构建
3. **保留 Tag 触发**：仅在推送以 `v` 开头的 tag 时触发（如 `v1.0.0`, `v2.1.3`）
4. **保留手动触发**：通过 `workflow_dispatch` 支持手动触发

### 简化的条件判断

由于移除了 pull request 触发，以下条件判断被简化：

- 移除了 `if: github.event_name != 'pull_request'` 条件
- 所有步骤现在都会执行，包括：
  - 登录到容器注册表
  - 构建和推送 Docker 镜像
  - 生成 artifact attestation
  - 输出镜像信息
  - 安全扫描

## 使用方法

### 自动触发（推荐）

创建并推送版本 tag：

```bash
# 创建 tag
git tag v1.0.0

# 推送 tag 到远程仓库
git push origin v1.0.0
```

### 手动触发

1. 访问 GitHub 仓库的 Actions 页面
2. 选择 "Docker Build and Push" workflow
3. 点击 "Run workflow" 按钮
4. 选择分支并点击 "Run workflow"

## 优势

1. **减少不必要的构建**：避免每次代码推送都触发构建，节省 CI/CD 资源
2. **版本控制**：只在发布版本时构建，与语义化版本控制保持一致
3. **灵活性**：保留手动触发功能，便于测试和紧急构建
4. **简化配置**：移除复杂的条件判断，使 workflow 更易维护

## 注意事项

- 确保使用正确的 tag 格式（以 `v` 开头）
- 手动触发时选择正确的分支
- 构建的镜像将使用 tag 名称作为版本标识

## 相关文件

- `.github/workflows/docker-build.yml` - 主要的 workflow 配置文件
- `docs/workflow-changes.md` - 本文档
