
# File Management System - API Usage Guide

This document explains how to use the API key management system and external API access.

## 🎯 Overview

The File Management System now provides two types of access:

1. **Web Interface** - Traditional browser-based access for file management
2. **API Access** - Programmatic access using API keys (similar to OpenAI's API)

## 🔑 API Key Management

### Admin Interface

Administrators can manage API keys through the web interface:

1. Login as `admin` user
2. Navigate to the "API Keys" tab
3. Create, manage, and monitor API keys

### API Key Features

- **Scoped Permissions**: `read`, `download`, `upload`, `admin`
- **Usage Tracking**: Monitor API calls, download counts, response times
- **Expiration**: Set optional expiration dates
- **Status Control**: Enable/disable keys instantly
- **User Association**: Link keys to specific users

## 🌐 API Endpoints

### Base URLs

- **Web API**: `/api/v1/web/*` (for frontend)
- **Public API**: `/api/v1/public/*` (for external access)
- **Admin API**: `/api/v1/admin/*` (for administration)

### Authentication

Include your API key in the Authorization header:

```bash
Authorization: Bearer sk_your_api_key_here
# or
Authorization: ApiKey sk_your_api_key_here
```

### Core Endpoints

#### 1. List Files
```bash
GET /api/v1/public/files
```

**Parameters:**
- `type` (optional): Filter by file type (`config`, `certificate`, `docs`)
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50, max: 1000)

**Example:**
```bash
curl -H "Authorization: Bearer sk_your_api_key" \
     "https://your-domain.com/api/v1/public/files?type=config&page=1&limit=10"
```

**Response:**
```json
{
  "success": true,
  "data": {
    "files": [
      {
        "id": "file_123",
        "name": "config_v2.json",
        "original_name": "config.json",
        "type": "config",
        "size": 1024,
        "description": "Application configuration",
        "uploader": "admin",
        "upload_time": "2024-01-01T12:00:00Z",
        "version": 2,
        "is_latest": true,
        "checksum": "abc123...",
        "download_url": "/api/v1/public/files/file_123/download"
      }
    ],
    "count": 1
  },
  "meta": {
    "page": 1,
    "limit": 10,
    "total": 1,
    "total_pages": 1
  }
}
```

#### 2. Download File
```bash
GET /api/v1/public/files/{fileId}/download
```

**Example:**
```bash
curl -H "Authorization: Bearer sk_your_api_key" \
     -o downloaded_file.json \
     "https://your-domain.com/api/v1/public/files/file_123/download"
```

#### 3. Get File Information
```bash
GET /api/v1/public/files/{fileId}
```

**Example:**
```bash
curl -H "Authorization: Bearer sk_your_api_key" \
     "https://your-domain.com/api/v1/public/files/file_123"
```

#### 4. Upload File (requires upload permission)
```bash
POST /api/v1/public/files/upload
```

**Example:**
```bash
curl -H "Authorization: Bearer sk_your_api_key" \
     -F "file=@config.json" \
     -F "type=config" \
     -F "description=New configuration file" \
     "https://your-domain.com/api/v1/public/files/upload"
```

#### 5. API Information
```bash
GET /api/v1/public/info
```

Get API version and available endpoints.

#### 6. API Status
```bash
GET /api/v1/public/status
```

Check API health status.

## 🔧 Admin API (Admin Permission Required)

### API Key Management

#### Create API Key
```bash
POST /api/v1/admin/api-keys
```

**Body:**
```json
{
  "name": "My Application Key",
  "description": "API key for my application",
  "user_id": "user_123",
  "permissions": ["read", "download"],
  "expires_at": "2024-12-31T23:59:59Z"
}
```

#### List API Keys
```bash
GET /api/v1/admin/api-keys?user_id=user_123
```

#### Update API Key Status
```bash
PATCH /api/v1/admin/api-keys/{keyId}/status
```

**Body:**
```json
{
  "status": "disabled"
}
```

#### Delete API Key
```bash
DELETE /api/v1/admin/api-keys/{keyId}
```

### Usage Analytics

#### Get Usage Logs
```bash
GET /api/v1/admin/usage/logs?user_id=user_123&limit=100
```

#### Get Usage Statistics
```bash
GET /api/v1/admin/usage/stats?period=daily
```

#### Get Usage Summary
```bash
GET /api/v1/admin/usage/summary
```

## 📊 Usage Tracking

All API requests are logged with the following information:

- **Request Details**: Endpoint, method, timestamp
- **User Information**: API key ID, user ID
- **Performance**: Response time, response size
- **Context**: IP address, user agent, file accessed
- **Status**: HTTP status code, error messages

## 🛡️ Security Features

### Permission System

- **read**: View file lists and metadata
- **download**: Download file contents
- **upload**: Upload new files
- **admin**: Full administrative access

### Rate Limiting

- Per-API key usage tracking
- Configurable quotas (daily/monthly)
- Automatic key expiration

### Audit Trail

- Complete request logging
- User activity tracking
- File access history
- Administrative actions log

## 🔄 Integration Examples

### Python Example

```python
import requests

class FileManagerAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

    def list_files(self, file_type=None, page=1, limit=50):
        params = {'page': page, 'limit': limit}
        if file_type:
            params['type'] = file_type

        response = requests.get(
            f'{self.base_url}/api/v1/public/files',
            headers=self.headers,
            params=params
        )
        return response.json()

    def download_file(self, file_id, save_path):
        response = requests.get(
            f'{self.base_url}/api/v1/public/files/{file_id}/download',
            headers=self.headers
        )

        with open(save_path, 'wb') as f:
            f.write(response.content)

        return True

    def upload_file(self, file_path, file_type, description=None):
        files = {'file': open(file_path, 'rb')}
        data = {'type': file_type}
        if description:
            data['description'] = description

        # Remove Content-Type for multipart
        headers = {k: v for k, v in self.headers.items()
                  if k != 'Content-Type'}

        response = requests.post(
            f'{self.base_url}/api/v1/public/files/upload',
            headers=headers,
            files=files,
            data=data
        )
        return response.json()

# Usage
api = FileManagerAPI('https://your-domain.com', 'sk_your_api_key')

# List config files
files = api.list_files(file_type='config')
print(f"Found {files['data']['count']} config files")

# Download a file
api.download_file('file_123', 'local_config.json')

# Upload a file
result = api.upload_file('new_config.json', 'config', 'Updated configuration')
print(f"Upload result: {result}")
```

### Node.js Example

```javascript
const axios = require('axios');
const FormData = require('form-data');
const fs = require('fs');

class FileManagerAPI {
    constructor(baseUrl, apiKey) {
        this.baseUrl = baseUrl;
        this.headers = {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
        };
    }

    async listFiles(fileType = null, page = 1, limit = 50) {
        const params = { page, limit };
        if (fileType) params.type = fileType;

        const response = await axios.get(`${this.baseUrl}/api/v1/public/files`, {
            headers: this.headers,
            params
        });
        return response.data;
    }

    async downloadFile(fileId, savePath) {
        const response = await axios.get(
            `${this.baseUrl}/api/v1/public/files/${fileId}/download`,
            {
                headers: this.headers,
                responseType: 'stream'
            }
        );

        const writer = fs.createWriteStream(savePath);
        response.data.pipe(writer);

        return new Promise((resolve, reject) => {
            writer.on('finish', resolve);
            writer.on('error', reject);
        });
    }

    async uploadFile(filePath, fileType, description = null) {
        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));
        form.append('type', fileType);
        if (description) form.append('description', description);

        const response = await axios.post(
            `${this.baseUrl}/api/v1/public/files/upload`,
            form,
            {
                headers: {
                    ...this.headers,
                    ...form.getHeaders()
                }
            }
        );
        return response.data;
    }
}

// Usage
const api = new FileManagerAPI('https://your-domain.com', 'sk_your_api_key');

(async () => {
    // List files
    const files = await api.listFiles('config');
    console.log(`Found ${files.data.count} config files`);

    // Download file
    await api.downloadFile('file_123', 'local_config.json');

    // Upload file
    const result = await api.uploadFile('new_config.json', 'config', 'Updated config');
    console.log('Upload result:', result);
})();
```

## 🚀 Best Practices

### Security
1. **Store API keys securely** - Never commit keys to version control
2. **Use environment variables** - Keep keys in environment configuration
3. **Rotate keys regularly** - Set expiration dates and refresh keys
4. **Principle of least privilege** - Grant only necessary permissions
5. **Monitor usage** - Review API usage logs regularly

### Performance
1. **Use pagination** - Don't fetch all files at once
2. **Cache responses** - Cache file lists when possible
3. **Parallel downloads** - Download multiple files concurrently
4. **Error handling** - Implement retry logic for transient failures

### Integration
1. **Version your API clients** - Track client library versions
2. **Handle rate limits** - Implement backoff strategies
3. **Log API calls** - Track API usage in your application
4. **Test thoroughly** - Test all permission scenarios

## 🆘 Troubleshooting

### Common Issues

#### 401 Unauthorized
- Check API key format (`sk_` prefix)
- Verify key is active and not expired
- Ensure key has required permissions

#### 403 Forbidden
- Check user permissions
- Verify user account is active
- Review permission requirements for endpoint

#### 404 Not Found
- Verify file ID exists
- Check file hasn't been deleted
- Ensure correct endpoint URL

#### 429 Rate Limited
- Review usage quotas
- Implement request throttling
- Check daily/monthly limits

### Getting Help

1. Check API logs in admin interface
2. Review usage statistics
3. Contact system administrator
4. Check system status endpoint

## 📈 Monitoring and Analytics

The admin interface provides comprehensive analytics:

- **Real-time metrics**: Active keys, request counts, error rates
- **Usage patterns**: Top files, most active users, peak usage times
- **Performance metrics**: Response times, data transfer volumes
- **Security insights**: Failed authentication attempts, suspicious activity

Access these through the "Analytics" tab in the admin interface.