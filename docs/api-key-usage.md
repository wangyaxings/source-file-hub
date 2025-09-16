# API Key 使用指南

## 概述

Secure File Hub 支持通过 API Key 进行外部 API 访问，允许第三方应用程序通过 REST API 进行文件管理操作。

## 访问地址

- **外部 API 基础地址**: `https://localhost:8444/api/v1/public/`
- **健康检查**: `https://localhost:8444/api/v1/health` 或 `https://localhost:8444/api/v1/healthz`

## 认证方式

支持两种 API Key 认证方式：

### 方式1: X-API-Key Header
```bash
curl -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/files
```

### 方式2: Authorization Header
```bash
# Bearer Token 格式
curl -H "Authorization: Bearer your-api-key-here" \
     https://localhost:8444/api/v1/public/files

# ApiKey 格式
curl -H "Authorization: ApiKey your-api-key-here" \
     https://localhost:8444/api/v1/public/files
```

## API 端点

### 健康检查（无需认证）

#### 1. 服务健康检查
```bash
# 使用 /health 端点
curl https://localhost:8444/api/v1/health

# 使用 /healthz 端点（Kubernetes 标准）
curl https://localhost:8444/api/v1/healthz
```

**响应示例**:
```json
{
  "success": true,
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-15T10:30:00Z",
    "version": "v1.0.0"
  }
}
```

### 文件管理

#### 1. 上传文件
```bash
curl -X POST \
     -H "X-API-Key: your-api-key-here" \
     -F "file=@/path/to/your/file.txt" \
     -F "description=文件描述" \
     https://localhost:8444/api/v1/public/files/upload
```

#### 2. 获取文件列表
```bash
curl -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/files
```

#### 3. 下载文件
```bash
curl -H "X-API-Key: your-api-key-here" \
     -O \
     https://localhost:8444/api/v1/public/files/{file-id}/download
```

#### 4. 删除文件
```bash
curl -X DELETE \
     -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/files/{file-id}
```

#### 5. 恢复文件（从回收站）
```bash
curl -X POST \
     -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/files/{file-id}/restore
```

### 包管理

#### 1. 获取包列表
```bash
curl -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/packages
```

#### 2. 更新包备注
```bash
curl -X PATCH \
     -H "X-API-Key: your-api-key-here" \
     -H "Content-Type: application/json" \
     -d '{"remark": "新的备注信息"}' \
     https://localhost:8444/api/v1/public/packages/{package-id}/remark
```

## 权限说明

API Key 的权限基于以下角色：

- **read**: 读取文件列表、下载文件
- **download**: 下载文件
- **upload**: 上传文件
- **delete**: 删除文件
- **admin**: 所有权限

## 响应格式

### 成功响应
```json
{
  "success": true,
  "data": {
    // 具体数据
  }
}
```

### 错误响应
```json
{
  "success": false,
  "error": "错误描述",
  "code": "ERROR_CODE",
  "details": {
    "request_id": "请求ID"
  }
}
```

## 常见错误码

- `MISSING_API_KEY`: 缺少 API Key
- `INVALID_API_KEY_FORMAT`: API Key 格式无效
- `INVALID_API_KEY`: API Key 无效或已过期
- `API_KEY_DISABLED`: API Key 已被禁用
- `API_KEY_EXPIRED`: API Key 已过期
- `INSUFFICIENT_PERMISSIONS`: 权限不足

## 使用示例

### Python 示例
```python
import requests

# 配置
API_BASE_URL = "https://localhost:8444/api/v1/public"
API_KEY = "your-api-key-here"

headers = {
    "X-API-Key": API_KEY
}

# 获取文件列表
response = requests.get(f"{API_BASE_URL}/files", headers=headers)
if response.status_code == 200:
    files = response.json()["data"]
    print(f"找到 {len(files)} 个文件")

# 上传文件
with open("test.txt", "rb") as f:
    files = {"file": f}
    data = {"description": "测试文件"}
    response = requests.post(
        f"{API_BASE_URL}/files/upload",
        headers=headers,
        files=files,
        data=data
    )
    if response.status_code == 200:
        print("文件上传成功")
```

### JavaScript 示例
```javascript
const API_BASE_URL = "https://localhost:8444/api/v1/public";
const API_KEY = "your-api-key-here";

// 获取文件列表
async function getFiles() {
    const response = await fetch(`${API_BASE_URL}/files`, {
        headers: {
            "X-API-Key": API_KEY
        }
    });

    if (response.ok) {
        const data = await response.json();
        console.log("文件列表:", data.data);
    }
}

// 上传文件
async function uploadFile(file, description) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("description", description);

    const response = await fetch(`${API_BASE_URL}/files/upload`, {
        method: "POST",
        headers: {
            "X-API-Key": API_KEY
        },
        body: formData
    });

    if (response.ok) {
        const data = await response.json();
        console.log("上传成功:", data.data);
    }
}
```

## 注意事项

1. **HTTPS 要求**: 所有 API 调用必须使用 HTTPS
2. **证书验证**: 开发环境可能需要忽略 SSL 证书验证
3. **文件大小限制**: 默认上传限制为 128MB
4. **API Key 管理**: 通过 Web 界面的管理面板创建和管理 API Key
5. **日志记录**: 所有 API 调用都会被记录用于审计

## 故障排除

### SSL 证书问题
如果遇到 SSL 证书验证错误，可以：

1. **curl**: 添加 `-k` 参数忽略证书验证
2. **Python**: 设置 `verify=False`
3. **JavaScript**: 在开发环境中可能需要特殊配置

### 连接问题
- 确保容器正在运行: `docker-compose ps`
- 检查端口映射: `docker-compose port fileserver 8443`
- 查看容器日志: `docker-compose logs fileserver`
