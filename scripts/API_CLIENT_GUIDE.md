# File Server API 客户端使用指南

## 概述

`file_server_api_client.py` 是一个功能完整的 Python 客户端，用于与文件管理系统 API 进行交互。它支持两种认证方式，并提供完整的文件管理功能。

## 系统要求

- Python 3.6+
- 必要依赖包：
  ```bash
  pip install requests python-dotenv
  ```

## 快速开始

### 1. 检查服务器状态

```bash
python scripts/file_server_api_client.py --check-server
```

### 2. 使用默认凭据运行演示

```bash
python scripts/file_server_api_client.py --demo
```

### 3. 自动创建API密钥

```bash
python scripts/file_server_api_client.py --create-key
```

## 认证方式

### 方式一：API密钥认证（推荐）

API密钥认证适合程序化访问，安全性更高：

```bash
# 使用API密钥
python scripts/file_server_api_client.py --api-key sk_your_api_key_here
```

**获取API密钥的方法：**
1. 通过Web界面创建：访问 `http://localhost:8080` → 管理界面 → API密钥管理
2. 自动创建：`python scripts/file_server_api_client.py --create-key`

### 方式二：用户名密码认证

适合交互式使用：

```bash
# 使用用户名密码
python scripts/file_server_api_client.py --username admin --password admin123
```

## 详细用法

### 基本参数

| 参数 | 默认值 | 描述 |
|------|--------|------|
| `--base-url` | `http://localhost:8080` | 服务器地址 |
| `--api-key` | - | API密钥 |
| `--username` | - | 用户名 |
| `--password` | - | 密码 |
| `--tenant-id` | `demo` | 租户ID |

### 功能选项

| 选项 | 描述 |
|------|------|
| `--demo` | 运行交互式演示 |
| `--create-key` | 自动创建API密钥 |
| `--check-server` | 检查服务器连接状态 |

## 使用示例

### 1. 基础文件操作

```bash
# 列出文件
python scripts/file_server_api_client.py --api-key sk_xxx --demo

# 使用自定义服务器地址
python scripts/file_server_api_client.py --base-url https://your-server.com --api-key sk_xxx
```

### 2. 管理员操作

```bash
# 创建API密钥并运行演示
python scripts/file_server_api_client.py --create-key --demo

# 仅创建API密钥
python scripts/file_server_api_client.py --create-key --username admin --password yourpassword
```

### 3. 环境变量配置

创建 `.env` 文件：

```env
API_KEY=sk_your_api_key_here
USERNAME=admin
PASSWORD=admin123
TENANT_ID=demo
```

然后直接运行：

```bash
python scripts/file_server_api_client.py --demo
```

## 编程接口

### 基本用法

```python
from file_server_api_client import FileServerAPIClient

# API密钥认证
client = FileServerAPIClient(
    base_url='http://localhost:8080',
    api_key='sk_your_api_key_here'
)

# 用户名密码认证
client = FileServerAPIClient(
    base_url='http://localhost:8080',
    username='admin',
    password='admin123'
)
```

### 文件操作

```python
# 列出文件
files = client.list_files(limit=10)
print(f"找到 {len(files['data']['files'])} 个文件")

# 下载文件
success = client.download_file('file_id', './downloads/file.txt')

# 按路径下载
success = client.download_file_by_path('configs/config.json', './config.json')

# 上传文件
result = client.upload_file('./local_file.txt', 'docs', '文件描述')
```

### 管理功能

```python
# 创建API密钥（需要管理员权限）
api_key = client.create_api_key(
    name='My API Key',
    user_id='admin',
    permissions=['read', 'download', 'upload']
)

# 列出API密钥
keys = client.list_api_keys()

# 获取使用日志
logs = client.get_usage_logs(limit=50)
```

## 服务器配置

### 开发环境
- 地址：`http://localhost:8080`
- 协议：HTTP
- 用途：开发和测试

### 生产环境
- 地址：`https://localhost:8443`
- 协议：HTTPS
- 用途：生产部署

## 权限系统

API密钥支持以下权限：

| 权限 | 描述 |
|------|------|
| `read` | 查看文件列表和元数据 |
| `download` | 下载文件内容 |
| `upload` | 上传新文件 |
| `admin` | 完整管理员权限 |

## 故障排除

### 常见问题

1. **连接失败**
   ```
   ❌ Cannot connect to server: http://localhost:8080
   ```
   - 检查服务器是否运行
   - 确认端口和协议正确
   - 检查防火墙设置

2. **认证失败**
   ```
   ❌ Authentication failed
   ```
   - 检查API密钥是否有效
   - 确认用户名密码正确
   - 检查密钥是否过期

3. **权限不足**
   ```
   ❌ Admin operations failed
   ```
   - 确认API密钥包含所需权限
   - 检查用户是否为管理员

### 调试技巧

1. **启用详细日志**
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **检查服务器健康状态**
   ```bash
   curl http://localhost:8080/api/v1/health
   ```

3. **验证API密钥**
   ```bash
   curl -H "Authorization: Bearer sk_your_key" \
        http://localhost:8080/api/v1/public/files
   ```

## 安全注意事项

1. **保护API密钥**
   - 不要在代码中硬编码API密钥
   - 使用环境变量或配置文件
   - 定期轮换API密钥

2. **HTTPS使用**
   - 生产环境始终使用HTTPS
   - 验证SSL证书（生产环境）

3. **权限最小化**
   - 只授予必要的权限
   - 为不同用途创建不同的API密钥

## 测试和验证

### API日志记录测试

使用提供的测试脚本验证Usage Logs和Analytics功能：

```bash
# 测试API调用日志记录
python scripts/test_api_logging.py --api-key sk_your_api_key
```

此脚本会：
- 发送15个随机API请求
- 测试不同的端点和参数
- 模拟真实的使用模式
- 在Web界面的Usage Logs和Analytics中生成可见的数据

**验证步骤：**
1. 运行测试脚本
2. 打开Web界面 → 管理界面 → API密钥管理
3. 查看"Usage Logs"标签页（30秒内自动刷新）
4. 查看"Analytics"标签页（60秒内自动刷新）
5. 确认看到测试请求的记录

## 高级用法

### 批量文件操作

```python
import os
from pathlib import Path

client = FileServerAPIClient(base_url='http://localhost:8080', api_key='sk_xxx')

# 批量下载
files = client.list_files()['data']['files']
download_dir = Path('./downloads')
download_dir.mkdir(exist_ok=True)

for file in files:
    local_path = download_dir / file['name']
    client.download_file(file['id'], str(local_path))
    print(f"下载完成: {file['name']}")
```

### 自定义会话配置

```python
import requests
from file_server_api_client import FileServerAPIClient

# 自定义超时和重试
session = requests.Session()
session.timeout = 30
session.max_retries = 3

client = FileServerAPIClient('http://localhost:8080', api_key='sk_xxx')
client.session = session
```

## 更新日志

### v1.0 (当前版本)
- 支持API密钥和用户名密码认证
- 完整的文件上传下载功能
- 管理员API密钥管理
- 使用日志查询
- 自动服务器检测和切换
- 详细的错误处理和调试信息

## 支持

如有问题或建议，请：
1. 检查本文档的故障排除部分
2. 查看服务器日志文件
3. 联系系统管理员

---

**注意**：本客户端是文件管理系统的官方Python SDK，提供了完整的API访问能力。建议在生产环境中使用API密钥认证以确保安全性。