# File Server API Scripts

This directory contains example scripts for interacting with the File Management System API.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install requests python-dotenv
   ```

2. **Configure your API access:**
   ```bash
   cp .env.example .env
   # Edit .env with your actual API URL and key
   ```

3. **Run the example client:**
   ```bash
   python file_server_api_client.py
   ```

## Getting Your API Key

1. Log in to the web interface as an admin user
2. Navigate to the "API Keys" tab
3. Click "Create API Key"
4. Fill in the form:
   - **Name**: Descriptive name for your key
   - **User ID**: Select from dropdown (use 'admin' for full access)
   - **Permissions**: Select required permissions:
     - `read`: View file lists and metadata
     - `download`: Download file contents
     - `upload`: Upload new files
     - `admin`: Full administrative access
   - **Expiration**: Optional expiration date

5. Copy the generated API key (starts with `sk_`) - you won't see it again!

## Available Permissions

- **read**: List files and view metadata
- **download**: Download file contents
- **upload**: Upload new files and versions
- **admin**: Full access including API key management and analytics

## API Endpoints

The API provides three main endpoint groups:

### Public API (`/api/v1/public/`)
- File listing, downloading, uploading
- Requires valid API key with appropriate permissions

### Admin API (`/api/v1/admin/`)
- API key management
- Usage analytics and logs
- User management
- Requires admin permission

### Web API (`/api/v1/web/`)
- Used by the web interface
- Requires browser session authentication

## Example Operations

### List Files
```python
# List all files
files = client.list_files()

# List only config files
config_files = client.list_files(file_type='config')

# Paginated listing
files = client.list_files(page=2, limit=25)
```

### Download Files
```python
# Download by file ID
client.download_file('file_123', 'local_file.json')

# Download to specific directory
client.download_file('file_123', 'downloads/config.json')
```

### Upload Files
```python
# Upload a new file
result = client.upload_file(
    'local_file.json',
    'config',
    'Updated configuration file'
)
```

### Admin Operations
```python
# Create new API key
new_key = client.create_api_key(
    name='My App Key',
    user_id='api_user',
    permissions=['read', 'download']
)

# List all API keys
keys = client.list_api_keys()

# Get usage logs
logs = client.get_usage_logs(limit=50)
```

## Error Handling

The client raises exceptions for API errors:

```python
try:
    files = client.list_files()
except Exception as e:
    print(f"API Error: {e}")
```

Common error codes:
- **401**: Invalid or expired API key
- **403**: Insufficient permissions
- **404**: File not found
- **429**: Rate limit exceeded

## Security Best Practices

1. **Keep API keys secure** - never commit to version control
2. **Use environment variables** for configuration
3. **Rotate keys regularly** - set expiration dates
4. **Principle of least privilege** - only grant needed permissions
5. **Monitor usage** - review logs for suspicious activity

## Support

For issues or questions:
1. Check the API logs in the admin interface
2. Verify your API key permissions
3. Review usage statistics for quota limits
4. Contact your system administrator