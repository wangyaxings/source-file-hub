#!/usr/bin/env python3
"""
Enhanced File Server API Client

This script demonstrates how to interact with the File Management System API
using both API Key authentication and username/password authentication.

Requirements:
    pip install requests python-dotenv

Usage:
    1. Using API Key:
       python file_server_api_client.py --api-key sk_your_api_key_here

    2. Using Username/Password:
       python file_server_api_client.py --username admin --password admin123

    3. Interactive demo:
       python file_server_api_client.py --demo

    4. Auto-create API Key:
       python file_server_api_client.py --create-key

    5. Auto-detect server and create key:
       python file_server_api_client.py --create-key --demo
"""

import os
import sys
import json
import requests
import argparse
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("Warning: python-dotenv not installed. Using environment variables directly.")


class FileServerAPIClient:
    """
    Enhanced Python client for the File Management System API

    Supports two authentication methods:
    1. API Key authentication (for programmatic access)
    2. Username/Password authentication (for interactive use)
    """

    def __init__(self, base_url: str, api_key: str = None, username: str = None,
                 password: str = None, tenant_id: str = "demo"):
        """
        Initialize the API client

        Args:
            base_url: Base URL of the File Server API
            api_key: API key for authentication (preferred)
            username: Username for login authentication
            password: Password for login authentication
            tenant_id: Tenant ID (default: demo)
        """
        self.base_url = base_url.rstrip('/')
        self.tenant_id = tenant_id
        self.session = requests.Session()

        # Configure session
        self.session.headers.update({
            'User-Agent': 'FileServerAPIClient/1.0',
            'Content-Type': 'application/json'
        })

        # Handle HTTPS verification for localhost
        if 'localhost' in base_url and base_url.startswith('https'):
            self.session.verify = False

        # Set up authentication
        if api_key:
            self._setup_api_key_auth(api_key)
        elif username and password:
            self._setup_password_auth(username, password)

    def _setup_api_key_auth(self, api_key: str):
        """Set up API key authentication"""
        self.session.headers['Authorization'] = f'Bearer {api_key}'
        print(f"✅ API Key authentication configured: {api_key[:20]}...")

    def _setup_password_auth(self, username: str, password: str):
        """Set up username/password authentication"""
        try:
            response = self.session.post(
                f'{self.base_url}/api/v1/web/auth/login',
                json={
                    'tenant_id': self.tenant_id,
                    'username': username,
                    'password': password
                }
            )

            if response.status_code == 200:
                token = response.json()['data']['token']
                self.session.headers['Authorization'] = f'Bearer {token}'
                print(f"✅ Username/password authentication successful for: {username}")
            else:
                raise Exception(f"Login failed: HTTP {response.status_code}")

        except Exception as e:
            raise Exception(f"Authentication failed: {e}")

    def logout(self) -> bool:
        """Logout and clear authentication"""
        try:
            if 'Authorization' in self.session.headers:
                response = self.session.post(f'{self.base_url}/api/v1/web/auth/logout')
                del self.session.headers['Authorization']
                return response.status_code == 200
            return True
        except Exception:
            return False

    def _handle_response(self, response: requests.Response) -> Dict[str, Any]:
        """Handle API response and check for errors"""
        try:
            data = response.json()
        except ValueError:
            raise Exception(f"Invalid JSON response: {response.text}")

        if not response.ok:
            error_msg = data.get('error', data.get('message', f'HTTP {response.status_code}'))
            raise Exception(f"API Error ({response.status_code}): {error_msg}")

        if not data.get('success', True):
            raise Exception(f"API Error: {data.get('error', 'Unknown error')}")

        return data

    # ==========================================================================
    # File Management Methods
    # ==========================================================================

    def list_files(self, file_type: Optional[str] = None, page: int = 1,
                   limit: int = 50) -> Dict[str, Any]:
        """
        List files from the server

        Args:
            file_type: Filter by file type
            page: Page number (1-based)
            limit: Number of files per page

        Returns:
            Dictionary containing files list and metadata
        """
        params = {'page': page, 'limit': limit}
        if file_type:
            params['type'] = file_type

        response = self.session.get(
            f'{self.base_url}/api/v1/public/files',
            params=params
        )

        return self._handle_response(response)

    def download_file(self, file_id: str, save_path: str, create_dirs: bool = True) -> bool:
        """
        Download a file by ID

        Args:
            file_id: ID of the file to download
            save_path: Local path where to save the file
            create_dirs: Whether to create directories if they don't exist

        Returns:
            True if download successful, False otherwise
        """
        try:
            # Remove Content-Type header for file download
            temp_headers = self.session.headers.copy()
            if 'Content-Type' in self.session.headers:
                del self.session.headers['Content-Type']

            response = self.session.get(
                f'{self.base_url}/api/v1/public/files/{file_id}/download',
                stream=True
            )

            # Restore headers
            self.session.headers = temp_headers

            if response.status_code != 200:
                print(f"❌ Download failed: HTTP {response.status_code}")
                return False

            # Create directories if needed
            if create_dirs:
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Write file
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"✅ File downloaded successfully to: {save_path}")
            return True

        except Exception as e:
            print(f"❌ Download error: {e}")
            return False

    def download_file_by_path(self, file_path: str, save_path: str) -> bool:
        """
        Download a file by path

        Args:
            file_path: Server-side file path
            save_path: Local path where to save the file

        Returns:
            True if download successful, False otherwise
        """
        try:
            # Remove Content-Type header for file download
            temp_headers = self.session.headers.copy()
            if 'Content-Type' in self.session.headers:
                del self.session.headers['Content-Type']

            response = self.session.get(
                f'{self.base_url}/api/v1/public/files/download/{file_path}',
                stream=True
            )

            # Restore headers
            self.session.headers = temp_headers

            if response.status_code != 200:
                print(f"❌ Download failed: HTTP {response.status_code}")
                return False

            # Create directories if needed
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            # Write file
            with open(save_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            print(f"✅ File downloaded successfully to: {save_path}")
            return True

        except Exception as e:
            print(f"❌ Download error: {e}")
            return False

    def upload_file(self, file_path: str, file_type: str,
                   description: Optional[str] = None) -> Dict[str, Any]:
        """
        Upload a file to the server

        Args:
            file_path: Local path to the file to upload
            file_type: Type/category for the file
            description: Optional description for the file

        Returns:
            Dictionary containing upload result and file information
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        # Prepare form data
        files = {'file': open(file_path, 'rb')}
        data = {'type': file_type}
        if description:
            data['description'] = description

        # Remove Content-Type for multipart upload
        temp_headers = self.session.headers.copy()
        if 'Content-Type' in self.session.headers:
            del self.session.headers['Content-Type']

        try:
            response = self.session.post(
                f'{self.base_url}/api/v1/public/files/upload',
                files=files,
                data=data
            )

            # Restore headers
            self.session.headers = temp_headers

            result = self._handle_response(response)
            print(f"✅ File uploaded successfully: {os.path.basename(file_path)}")
            return result

        except Exception as e:
            print(f"❌ Upload error: {e}")
            # Restore headers on error
            self.session.headers = temp_headers
            raise
        finally:
            files['file'].close()

    # ==========================================================================
    # API Status and Information
    # ==========================================================================

    def get_api_status(self) -> Dict[str, Any]:
        """Get API health status (public endpoint)"""
        # Temporarily remove auth for public endpoint
        temp_auth = self.session.headers.get('Authorization')
        if 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

        try:
            response = self.session.get(f'{self.base_url}/api/v1/health', timeout=10)
            result = response.json() if response.status_code == 200 else {"message": "Service unavailable"}
            return result
        except Exception as e:
            return {"message": f"Connection failed: {e}"}
        finally:
            # Restore auth header
            if temp_auth:
                self.session.headers['Authorization'] = temp_auth

    # ==========================================================================
    # Admin Methods (require admin permissions)
    # ==========================================================================

    def create_api_key(self, name: str, user_id: str, permissions: List[str],
                      description: Optional[str] = None,
                      expires_at: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new API key (admin only)

        Args:
            name: Name for the API key
            user_id: User ID to associate with the key
            permissions: List of permissions ('read', 'download', 'upload', 'admin')
            description: Optional description
            expires_at: Optional expiration date in ISO format

        Returns:
            Dictionary containing the new API key information
        """
        data = {
            'name': name,
            'user_id': user_id,
            'permissions': permissions
        }
        if description:
            data['description'] = description
        if expires_at:
            data['expires_at'] = expires_at

        response = self.session.post(
            f'{self.base_url}/api/v1/admin/api-keys',
            json=data
        )

        return self._handle_response(response)

    def list_api_keys(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        List API keys (admin only)

        Args:
            user_id: Optional user ID to filter by

        Returns:
            Dictionary containing API keys list
        """
        params = {}
        if user_id:
            params['user_id'] = user_id

        response = self.session.get(
            f'{self.base_url}/api/v1/admin/api-keys',
            params=params
        )

        return self._handle_response(response)

    def get_usage_logs(self, user_id: Optional[str] = None,
                      limit: int = 100) -> Dict[str, Any]:
        """
        Get API usage logs (admin only)

        Args:
            user_id: Optional user ID to filter by
            limit: Number of logs to retrieve

        Returns:
            Dictionary containing usage logs
        """
        params = {'limit': limit}
        if user_id:
            params['user_id'] = user_id

        response = self.session.get(
            f'{self.base_url}/api/v1/admin/usage/logs',
            params=params
        )

        return self._handle_response(response)


def create_api_key(base_url: str, username: str = 'admin', password: str = 'admin123', tenant_id: str = 'demo') -> str:
    """Create an API key for testing"""
    print("📝 Creating API key for demo...")

    # Login first
    login_response = requests.post(f"{base_url}/api/v1/web/auth/login", json={
        "tenant_id": tenant_id,
        "username": username,
        "password": password
    })

    if login_response.status_code != 200:
        raise Exception(f"Login failed: {login_response.text}")

    token = login_response.json()['data']['token']

    # Create API key
    api_key_response = requests.post(f"{base_url}/api/v1/web/admin/api-keys",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        json={
            "name": f"Demo Key {datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "description": "Auto-generated key for demo",
            "user_id": "admin",
            "permissions": ["read", "download", "upload"]
        }
    )

    if api_key_response.status_code != 201:
        raise Exception(f"API key creation failed: {api_key_response.text}")

    api_key = api_key_response.json()['data']['key']
    print(f"✅ API key created: {api_key[:20]}...")
    return api_key


def demo_api_key_auth(base_url: str, api_key: str):
    """Demonstrate API Key authentication"""
    print("\n" + "="*60)
    print("🔑 API KEY AUTHENTICATION DEMO")
    print("="*60)

    client = FileServerAPIClient(base_url, api_key=api_key)

    try:
        # Check API status
        print("\n1. Checking API status...")
        status = client.get_api_status()
        print(f"   API Status: {status.get('message', 'Unknown')}")

        # List files
        print("\n2. Listing files...")
        files_response = client.list_files(limit=10)
        files = files_response.get('data', {}).get('files', [])
        print(f"   Found {len(files)} files:")

        for i, file in enumerate(files[:5], 1):
            print(f"   {i}. {file.get('name', 'Unknown')} "
                  f"({file.get('type', 'Unknown')}, {file.get('size', 0)} bytes)")

        if files:
            # Download first file
            first_file = files[0]
            print(f"\n3. Downloading file: {first_file.get('name', 'Unknown')}")

            downloads_dir = Path('downloads')
            downloads_dir.mkdir(exist_ok=True)

            download_path = downloads_dir / first_file.get('name', 'unknown_file')
            success = client.download_file(first_file['id'], str(download_path))

            if success:
                print(f"   File saved to: {download_path}")

        # Try admin operations
        print("\n4. Testing admin operations...")
        try:
            api_keys = client.list_api_keys()
            print(f"   API Keys: {api_keys.get('data', {}).get('count', 0)} keys found")
        except Exception as e:
            print(f"   Admin operations failed (may not have admin permissions): {e}")

        print("\n✅ Demo completed successfully!")

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        print("\n🔍 Troubleshooting tips:")
        print("   1. Make sure the server is running and accessible")
        print("   2. Check if the API key is valid and not expired")
        print("   3. Verify the server URL is correct")
        print("   4. Ensure the API key has the required permissions")
        print("   5. Check network connectivity and firewall settings")
        print(f"   6. Try accessing the health endpoint: {base_url}/api/v1/health")


def demo_password_auth(base_url: str, username: str, password: str, tenant_id: str = "demo"):
    """Demonstrate username/password authentication"""
    print("\n" + "="*60)
    print("🔐 USERNAME/PASSWORD AUTHENTICATION DEMO")
    print("="*60)

    client = FileServerAPIClient(base_url, username=username, password=password, tenant_id=tenant_id)

    try:
        # List files
        print("\n1. Listing files...")
        files_response = client.list_files(limit=10)
        files = files_response.get('data', {}).get('files', [])
        print(f"   Found {len(files)} files:")

        for i, file in enumerate(files[:3], 1):
            print(f"   {i}. {file.get('name', 'Unknown')} "
                  f"({file.get('type', 'Unknown')}, {file.get('size', 0)} bytes)")

        # Test direct file path download
        print("\n2. Testing direct file path downloads...")
        test_paths = [
            'configs/config.json',
            'certificates/server.crt',
            'docs/api_guide.txt'
        ]

        downloads_dir = Path('downloads')
        downloads_dir.mkdir(exist_ok=True)

        for file_path in test_paths:
            print(f"\n   Downloading: {file_path}")
            local_path = downloads_dir / file_path.replace('/', '_')
            success = client.download_file_by_path(file_path, str(local_path))

            if success:
                file_size = os.path.getsize(local_path)
                print(f"   ✅ Saved to: {local_path} ({file_size} bytes)")

        # Logout
        print("\n3. Logging out...")
        client.logout()

        print("\n✅ Demo completed successfully!")

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        print("\n🔍 Troubleshooting tips:")
        print("   1. Make sure the server is running and accessible")
        print("   2. Check username/password credentials")
        print("   3. Verify the server URL is correct")
        print("   4. Ensure the user account is active and not locked")
        print("   5. Check network connectivity and firewall settings")
        print(f"   6. Try accessing the health endpoint: {base_url}/api/v1/health")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced File Server API Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python file_server_api_client.py --api-key sk_1234567890abcdef
  python file_server_api_client.py --username admin --password admin123
  python file_server_api_client.py --demo
  python file_server_api_client.py --create-key
  python file_server_api_client.py --create-key --base-url http://localhost:8080
        """)

    parser.add_argument('--base-url', default='http://localhost:8080',
                       help='Server URL (default: http://localhost:8080)')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--username', help='Username for authentication')
    parser.add_argument('--password', help='Password for authentication')
    parser.add_argument('--tenant-id', default='demo', help='Tenant ID (default: demo)')
    parser.add_argument('--demo', action='store_true',
                       help='Run interactive demo with default credentials')
    parser.add_argument('--create-key', action='store_true',
                       help='Create a new API key automatically')
    parser.add_argument('--check-server', action='store_true',
                       help='Check if server is responding')

    args = parser.parse_args()

    # Normalize base URL
    base_url = args.base_url.rstrip('/')

    # Check if server is accessible
    try:
        session = requests.Session()
        if base_url.startswith('https') and 'localhost' in base_url:
            session.verify = False
        response = session.get(f"{base_url}/api/v1/health", timeout=5)
    except Exception:
        if base_url.startswith('https://localhost:8443'):
            print("⚠️  Warning: Server URL uses HTTPS:8443, but development server runs on HTTP:8080")
            print("   Switching to HTTP:8080 for compatibility...")
            base_url = 'http://localhost:8080'
        else:
            print(f"❌ Cannot connect to server: {base_url}")
            print("Please ensure the server is running and try:")
            print("   --base-url https://localhost:8443  (for production mode)")
            print("   --base-url http://localhost:8080   (for development mode)")
            sys.exit(1)

    # Check environment variables if not provided as arguments
    api_key = args.api_key or os.getenv('API_KEY')
    username = args.username or os.getenv('USERNAME')
    password = args.password or os.getenv('PASSWORD')
    tenant_id = args.tenant_id or os.getenv('TENANT_ID', 'demo')

    # Handle API key creation
    if args.create_key:
        try:
            api_key = create_api_key(base_url, username or 'admin', password or 'admin123', tenant_id)
        except Exception as e:
            print(f"\n❌ API key creation failed: {e}")
            sys.exit(1)

    if args.check_server:
        print(f"🔍 Checking server at: {base_url}")
        try:
            session = requests.Session()
            if base_url.startswith('https'):
                session.verify = False
            response = session.get(f"{base_url}/api/v1/health", timeout=10)
            print(f"✅ Server is responding: HTTP {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
        except Exception as e:
            print(f"❌ Server check failed: {e}")
        sys.exit(0)

    print(f"🚀 File Server API Client Demo")
    print(f"   Server: {base_url}")
    print(f"   Tenant: {tenant_id}")

    if args.demo:
        # Run both demos with default credentials
        print("\n🎭 Running complete demo with default credentials...")

        # Demo with username/password
        demo_password_auth(base_url, 'admin', 'admin123', tenant_id)

        # If we have an API key, demo that too
        if api_key:
            demo_api_key_auth(base_url, api_key)
        else:
            print("\n⚠️  No API key provided, skipping API key demo")
            print("   Create an API key in the web interface to test API key authentication")

    elif api_key:
        # API Key authentication
        demo_api_key_auth(base_url, api_key)

    elif username and password:
        # Username/password authentication
        demo_password_auth(base_url, username, password, tenant_id)

    else:
        print("\n❌ Error: No authentication method provided")
        print("\nUsage options:")
        print("  1. API Key:           --api-key sk_your_key_here")
        print("  2. Username/Password: --username admin --password admin123")
        print("  3. Environment vars:  Set API_KEY or USERNAME/PASSWORD")
        print("  4. Interactive demo:  --demo")
        print("  5. Create API key:    --create-key")
        print("\nExamples:")
        print("  python file_server_api_client.py --api-key sk_1234567890abcdef")
        print("  python file_server_api_client.py --username admin --password admin123")
        print("  python file_server_api_client.py --demo")
        print("  python file_server_api_client.py --create-key")
        print("  python file_server_api_client.py --create-key --base-url http://localhost:8080")
        sys.exit(1)

    print("\n🎉 Demo completed!")


if __name__ == '__main__':
    main()