# FileHub 状态检查API接口文档

## 接口概述

`/api/v1/status-check` 是一个合并了健康检查和API key验证功能的接口，用于检查FileHub服务的运行状态和API key的有效性。

## 接口信息

- **URL**: `/api/v1/status-check`
- **方法**: `GET`
- **认证**: 无需认证（公开接口）
- **参数**: 通过查询参数传递API key（可选）

## 请求参数

| 参数名 | 类型 | 必填 | 描述 |
|--------|------|------|------|
| api_key | string | 否 | API密钥，用于验证有效性 |

## 请求示例

### 1. 不带API key的请求
```bash
curl -k "https://localhost:8443/api/v1/status-check"
```

### 2. 带API key的请求
```bash
curl -k "https://localhost:8443/api/v1/status-check?api_key=sk_your_api_key_here"
```

### 3. 使用PowerShell
```powershell
# 不带API key
Invoke-RestMethod -Uri "https://localhost:8443/api/v1/status-check" -SkipServerCertificateValidation

# 带API key
Invoke-RestMethod -Uri "https://localhost:8443/api/v1/status-check?api_key=sk_your_api_key_here" -SkipServerCertificateValidation
```

### 4. 使用Python
```python
import requests
import urllib3

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 不带API key
response = requests.get("https://localhost:8443/api/v1/status-check", verify=False)
print(response.json())

# 带API key
api_key = "sk_your_api_key_here"
response = requests.get(f"https://localhost:8443/api/v1/status-check?api_key={api_key}", verify=False)
print(response.json())
```

## 响应格式

### 成功响应结构
```json
{
  "success": true,
  "message": "描述信息",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648864"
  }
}
```

### 响应字段说明

| 字段 | 类型 | 描述 |
|------|------|------|
| success | boolean | 请求是否成功 |
| message | string | 响应消息描述 |
| data.healthy | boolean | 服务是否健康运行 |
| data.api_key_valid | boolean | API key是否有效（仅当提供api_key时） |
| data.timestamp | string | 响应时间戳（Unix时间戳） |

## 响应示例

### 1. 服务健康，未提供API key
```json
{
  "success": true,
  "message": "Service is healthy, but no API key provided",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648864"
  }
}
```

### 2. 服务健康，API key有效
```json
{
  "success": true,
  "message": "Service is healthy and API key is valid",
  "data": {
    "healthy": true,
    "api_key_valid": true,
    "timestamp": "1758648865"
  }
}
```

### 3. 服务健康，API key无效
```json
{
  "success": true,
  "message": "Service is healthy, but API key is invalid",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648866"
  }
}
```

### 4. 服务健康，API key格式错误
```json
{
  "success": true,
  "message": "Service is healthy, but API key format is invalid",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648867"
  }
}
```

### 5. 服务健康，API key已禁用
```json
{
  "success": true,
  "message": "Service is healthy, but API key is disabled",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648868"
  }
}
```

### 6. 服务健康，API key已过期
```json
{
  "success": true,
  "message": "Service is healthy, but API key has expired",
  "data": {
    "healthy": true,
    "api_key_valid": false,
    "timestamp": "1758648869"
  }
}
```

### 7. 服务不健康（数据库不可用）
```json
{
  "success": false,
  "message": "Service is unhealthy - database not available",
  "data": {
    "healthy": false,
    "api_key_valid": false,
    "timestamp": "1758648870"
  }
}
```

## 使用场景

### 1. 服务监控
定期检查FileHub服务是否正常运行：
```bash
# 简单的健康检查
curl -k "https://localhost:8443/api/v1/status-check"
```

### 2. API key验证
验证API key是否有效：
```bash
# 验证API key
curl -k "https://localhost:8443/api/v1/status-check?api_key=sk_your_api_key_here"
```

### 3. 集成到监控系统
```python
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_filehub_status(api_key=None):
    url = "https://localhost:8443/api/v1/status-check"
    if api_key:
        url += f"?api_key={api_key}"

    try:
        response = requests.get(url, verify=False, timeout=10)
        data = response.json()

        if data['success'] and data['data']['healthy']:
            if api_key:
                return data['data']['api_key_valid']
            return True
        return False
    except Exception as e:
        print(f"检查失败: {e}")
        return False

# 使用示例
is_healthy = check_filehub_status()
api_key_valid = check_filehub_status("sk_your_api_key_here")
```

## 错误处理

### HTTP状态码
- `200 OK`: 请求成功（无论服务是否健康）
- `503 Service Unavailable`: 服务不可用（数据库连接失败等）

### 常见错误情况
1. **网络连接失败**: 检查FileHub服务是否运行
2. **SSL证书错误**: 使用 `-k` 参数跳过证书验证（仅用于测试）
3. **超时**: 设置合适的超时时间

## 注意事项

1. **安全性**: 此接口为公开接口，无需认证即可访问
2. **SSL证书**: 生产环境建议使用有效的SSL证书
3. **API key格式**: API key必须以 `sk_` 开头，后跟64位十六进制字符
4. **响应时间**: 接口响应时间通常在100ms以内
5. **频率限制**: 建议不要过于频繁地调用此接口

## 与其他接口的区别

| 接口 | 功能 | 认证要求 |
|------|------|----------|
| `/api/v1/health` | 仅健康检查 | 无需认证 |
| `/api/v1/healthz` | 仅健康检查 | 无需认证 |
| `/api/v1/status-check` | 健康检查 + API key验证 | 无需认证 |

## 测试工具

项目提供了测试脚本，位于 `tests/api/op_center_api_test.py`：

```bash
# 测试状态检查接口
python tests/api/op_center_api_test.py --base https://localhost:8443 --api-key sk_your_api_key --do-status-check

# 测试所有功能
python tests/api/op_center_api_test.py --base https://localhost:8443 --api-key sk_your_api_key --do-all
```

## 更新日志

- **v1.0.0** (2025-09-24): 初始版本，支持健康检查和API key验证合并功能
