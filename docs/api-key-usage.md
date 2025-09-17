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

#### 3.1 下载最新 Roadmap/Recommendation
```bash
# 获取最新版本元数据
curl -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/versions/roadmap/latest

curl -H "X-API-Key: your-api-key-here" \
     https://localhost:8444/api/v1/public/versions/recommendation/latest

# 直接下载最新文件
curl -H "X-API-Key: your-api-key-here" -OJ \
     https://localhost:8444/api/v1/public/versions/roadmap/latest/download

curl -H "X-API-Key: your-api-key-here" -OJ \
     https://localhost:8444/api/v1/public/versions/recommendation/latest/download
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

### 资源包上传（assets / others）

通过 API Key 上传资源包 ZIP 文件，文件名需严格遵循：

- `<tenant>_assets_<UTC>.zip`
- `<tenant>_others_<UTC>.zip`

其中 `<UTC>` 格式为 `YYYYMMDDThhmmssZ`（例如：`20250101T120000Z`）。

```bash
# 上传 assets
curl -X POST \
     -H "X-API-Key: your-api-key-here" \
     -F "file=@./tenant123_assets_20250101T120000Z.zip" \
     https://localhost:8444/api/v1/public/upload/assets-zip

# 上传 others
curl -X POST \
     -H "X-API-Key: your-api-key-here" \
     -F "file=@./tenant123_others_20250101T120000Z.zip" \
     https://localhost:8444/api/v1/public/upload/others-zip
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


Added Test Scripts

scripts/api-test.ps1: PowerShell batch test with variables
scripts/api-test.sh: Bash batch test with variables
Both support:

Variable IPs and ports, SNI --resolve for TLS
API key via header
Health, files list, latest endpoints, and optional assets/others ZIP upload
PowerShell Usage

Minimal:
.\scripts\api-test.ps1 -Ips 192.168.197.130 -Ports 8444,30000 -Hostname localhost -ApiKey 'sk_6946cb70c5ad8efe4748cbb587a04e8ace3f6e3c9fb56e32a6ca29529385ac66'
With uploads (creates valid <tenant>_assets_<UTC>.zip and <tenant>_others_<UTC>.zip):
.\scripts\api-test.ps1 -Ips 192.168.197.130 -Ports 8444,30000 -Hostname localhost -ApiKey 'sk_...' -Tenant tenant123 -DoUploads
Env alternatives:
setx API_KEY sk_...
setx TARGET_IP 192.168.197.130
setx TARGET_HOSTNAME localhost
Outputs: tmp/api-test/* per IP:port.
Bash Usage

Minimal:
API_KEY=sk_... IPS="192.168.197.130" PORTS="8444,30000" ./scripts/api-test.sh
With uploads:
API_KEY=sk_... IPS="192.168.197.130" PORTS="8444,30000" TENANT=tenant123 DO_UPLOADS=1 ./scripts/api-test.sh
Outputs: tmp/api-test/*
What I Updated

Public bypass so API-key endpoints don’t require session:
internal/middleware/auth.go: adds /api/v1/public/ to public paths
Safer permission fallback (if Casbin errors/denies):
internal/middleware/apiauth.go: infers required permission by method/path
Public endpoints for your use cases:
Latest/version download and info, and download by file ID
Assets/others ZIP upload with strict naming and DB record
internal/handler/handler.go
Expanded policy mapping to cover new endpoints:
internal/authz/casbin.go
Next Steps

If you have existing API keys, trigger a policy refresh:
Use the admin API to “update” the key’s permissions (even without changes) to reapply policies, or run a small maintenance to call RemoveAllAPIKeyPolicies/CreateAPIKeyPolicies per key.
Run the test script with your target IP(s) and API key to validate read/download/upload flows.