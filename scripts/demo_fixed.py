#!/usr/bin/env python3
"""
Fixed demo script for File Server API Client
This fixes the protocol/port issue and provides better error handling
"""

import os
import sys
import requests
import argparse
from datetime import datetime

class FileServerAPIClient:
    """Simple API client for demonstration"""

    def __init__(self, base_url: str, api_key: str = None):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

        if api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {api_key}',
                'User-Agent': 'FileServerAPIClient-Demo/1.0'
            })

    def get_api_status(self):
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

    def list_files(self, limit=10):
        """List files using API key authentication"""
        try:
            response = self.session.get(f'{self.base_url}/api/v1/public/files', params={'limit': limit})

            if response.status_code == 200:
                return response.json()
            else:
                error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {"error": response.text}
                raise Exception(f"HTTP {response.status_code}: {error_data.get('error', {}).get('message', 'Unknown error')}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Network error: {e}")

def create_api_key(base_url: str) -> str:
    """Create an API key for testing"""
    print("📝 Creating API key for demo...")

    # Login first
    login_response = requests.post(f"{base_url}/api/v1/web/auth/login", json={
        "tenant_id": "demo",
        "username": "admin",
        "password": "admin123"
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
    print(f"✅ API Key authentication configured: {api_key[:20]}...")

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
            print(f"   {i}. {file['name']} ({file['type']}, {file['size']} bytes)")

        if len(files) > 5:
            print(f"   ... and {len(files) - 5} more files")

        print("\n✅ Demo completed successfully!")

    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        print("\n🔍 Troubleshooting tips:")
        print("   1. Make sure the server is running")
        print("   2. Check if the API key is valid and not expired")
        print("   3. Verify the server URL is correct")
        print("   4. Ensure the API key has the required permissions")

def main():
    parser = argparse.ArgumentParser(description="File Server API Client Demo (Fixed)")
    parser.add_argument('--server', default='http://localhost:8080',
                       help='Server URL (default: http://localhost:8080)')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--create-key', action='store_true',
                       help='Create a new API key automatically')

    args = parser.parse_args()

    # Detect server protocol and port
    base_url = args.server
    if base_url.startswith('https://localhost:8443'):
        print("⚠️  Warning: Server URL uses HTTPS:8443, but development server runs on HTTP:8080")
        print("   Switching to HTTP:8080 for compatibility...")
        base_url = 'http://localhost:8080'

    print(f"🚀 File Server API Client Demo")
    print(f"   Server: {base_url}")

    try:
        # Get or create API key
        api_key = args.api_key
        if not api_key and args.create_key:
            api_key = create_api_key(base_url)
        elif not api_key:
            # Check environment variable
            api_key = os.getenv('API_KEY')

        if not api_key:
            print("\n❌ No API key provided!")
            print("\nOptions:")
            print("  1. Use --api-key sk_your_key_here")
            print("  2. Use --create-key to auto-generate one")
            print("  3. Set API_KEY environment variable")
            print("\nExample:")
            print("  python demo_fixed.py --create-key")
            print("  python demo_fixed.py --api-key sk_1234567890abcdef...")
            sys.exit(1)

        # Run demo
        demo_api_key_auth(base_url, api_key)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()