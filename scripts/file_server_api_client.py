#!/usr/bin/env python3
"""
File Server API Client Example

This script demonstrates how to interact with the File Management System API
from external Python applications.

Requirements:
    pip install requests python-dotenv

Usage:
    1. Create a .env file with your API configuration:
       API_BASE_URL=https://your-domain.com
       API_KEY=sk_your_api_key_here

    2. Run the script:
       python file_server_api_client.py
"""

import os
import sys
import json
import requests
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
    Python client for the File Management System API

    Provides methods for:
    - Listing files
    - Downloading files
    - Uploading files
    - Managing API keys (admin only)
    - Retrieving usage statistics
    """

    def __init__(self, base_url: str, api_key: str):
        """
        Initialize the API client

        Args:
            base_url: Base URL of the file server (e.g., https://your-domain.com)
            api_key: Your API key (starts with sk_)
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'FileServerAPIClient/1.0.0'
        })

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
            file_type: Filter by file type ('config', 'certificate', 'docs', etc.)
            page: Page number (default: 1)
            limit: Items per page (default: 50, max: 1000)

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

    def get_file_info(self, file_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific file

        Args:
            file_id: ID of the file

        Returns:
            Dictionary containing file information
        """
        response = self.session.get(
            f'{self.base_url}/api/v1/public/files/{file_id}'
        )

        return self._handle_response(response)

    def download_file(self, file_id: str, save_path: str,
                     create_dirs: bool = True) -> bool:
        """
        Download a file from the server

        Args:
            file_id: ID of the file to download
            save_path: Local path where the file should be saved
            create_dirs: Whether to create parent directories if they don't exist

        Returns:
            True if download was successful
        """
        response = self.session.get(
            f'{self.base_url}/api/v1/public/files/{file_id}/download',
            stream=True
        )

        if not response.ok:
            error_data = response.json() if response.content else {}
            error_msg = error_data.get('error', f'HTTP {response.status_code}')
            raise Exception(f"Download failed: {error_msg}")

        # Create parent directories if needed
        if create_dirs:
            Path(save_path).parent.mkdir(parents=True, exist_ok=True)

        # Save file
        with open(save_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"File downloaded successfully to: {save_path}")
        return True

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
        headers = {k: v for k, v in self.session.headers.items()
                  if k.lower() != 'content-type'}

        try:
            response = requests.post(
                f'{self.base_url}/api/v1/public/files/upload',
                headers=headers,
                files=files,
                data=data
            )

            result = self._handle_response(response)
            print(f"File uploaded successfully: {os.path.basename(file_path)}")
            return result

        finally:
            files['file'].close()

    # ==========================================================================
    # API Status and Information
    # ==========================================================================

    def get_api_status(self) -> Dict[str, Any]:
        """Get API health status"""
        response = self.session.get(f'{self.base_url}/api/v1/public/status')
        return self._handle_response(response)

    def get_api_info(self) -> Dict[str, Any]:
        """Get API version and information"""
        response = self.session.get(f'{self.base_url}/api/v1/public/info')
        return self._handle_response(response)

    # ==========================================================================
    # Admin Methods (require admin permission)
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


def main():
    """Example usage of the FileServerAPIClient"""

    # Configuration
    BASE_URL = os.getenv('API_BASE_URL', 'http://localhost:8080')
    API_KEY = os.getenv('API_KEY')

    if not API_KEY:
        print("Error: API_KEY environment variable is required")
        print("Please set your API key: export API_KEY=sk_your_api_key_here")
        sys.exit(1)

    # Initialize client
    print(f"Connecting to: {BASE_URL}")
    client = FileServerAPIClient(BASE_URL, API_KEY)

    try:
        # Check API status
        print("\n1. Checking API status...")
        status = client.get_api_status()
        print(f"API Status: {status}")

        # List files
        print("\n2. Listing files...")
        files_response = client.list_files(limit=10)
        files = files_response.get('data', {}).get('files', [])
        print(f"Found {len(files)} files:")

        for file in files[:5]:  # Show first 5 files
            print(f"  - {file['name']} ({file['type']}, {file['size']} bytes)")

        if files:
            # Download first file as example
            first_file = files[0]
            print(f"\n3. Downloading file: {first_file['name']}")

            # Create downloads directory
            downloads_dir = Path('downloads')
            downloads_dir.mkdir(exist_ok=True)

            download_path = downloads_dir / first_file['name']
            client.download_file(first_file['id'], str(download_path))

            print(f"File saved to: {download_path}")

        # Example upload (uncomment if you have a file to upload)
        """
        print("\n4. Uploading example file...")
        upload_result = client.upload_file(
            'example.txt',
            'docs',
            'Example file uploaded via API'
        )
        print(f"Upload result: {upload_result}")
        """

        # Admin operations (if you have admin permissions)
        try:
            print("\n5. Admin operations...")

            # List API keys
            api_keys = client.list_api_keys()
            print(f"API Keys: {api_keys.get('data', {}).get('count', 0)} keys found")

            # Get usage logs
            usage_logs = client.get_usage_logs(limit=5)
            logs = usage_logs.get('data', {}).get('logs', [])
            print(f"Recent usage: {len(logs)} log entries")

        except Exception as e:
            print(f"Admin operations failed (may not have admin permissions): {e}")

        print("\nAPI client test completed successfully!")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()