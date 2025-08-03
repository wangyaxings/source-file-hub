#!/usr/bin/env python3
"""
API测试脚本 - 演示文件管理系统的API使用方法

用法:
    python test_api.py create_key    # 创建API密钥
    python test_api.py test_api      # 测试API功能
    python test_api.py full_demo     # 完整演示
"""

import requests
import json
import sys
import os
from datetime import datetime

class FileManagerAPITester:
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.api_key = None
        self.session = requests.Session()

    def login_admin(self, username="admin", password="admin"):
        """使用管理员账号登录获取访问令牌"""
        try:
            response = self.session.post(f"{self.base_url}/api/v1/web/auth/login", json={
                "username": username,
                "password": password
            })

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    self.admin_token = data.get('data', {}).get('token')
                    print(f"✅ 管理员登录成功")
                    return True

            print(f"❌ 管理员登录失败: {response.text}")
            return False

        except Exception as e:
            print(f"❌ 登录时发生错误: {e}")
            return False

    def create_api_key(self, name="Test API Key", user_id="admin", permissions=None):
        """创建API密钥"""
        if not hasattr(self, 'admin_token'):
            print("❌ 请先登录管理员账号")
            return None

        if permissions is None:
            permissions = ["read", "download", "upload"]

        try:
            response = self.session.post(
                f"{self.base_url}/api/v1/admin/api-keys",
                headers={
                    'Authorization': f'Bearer {self.admin_token}',
                    'Content-Type': 'application/json'
                },
                json={
                    "name": name,
                    "description": f"API密钥用于测试 - 创建于 {datetime.now().isoformat()}",
                    "user_id": user_id,
                    "permissions": permissions
                }
            )

            if response.status_code == 201:
                data = response.json()
                if data.get('success'):
                    api_key = data.get('data', {}).get('key')
                    print(f"✅ API密钥创建成功")
                    print(f"   名称: {name}")
                    print(f"   密钥: {api_key}")
                    print(f"   权限: {', '.join(permissions)}")
                    self.api_key = api_key
                    return api_key

            print(f"❌ API密钥创建失败: {response.text}")
            return None

        except Exception as e:
            print(f"❌ 创建API密钥时发生错误: {e}")
            return None

    def test_api_info(self):
        """测试API信息端点"""
        if not self.api_key:
            print("❌ 没有API密钥，无法测试")
            return False

        try:
            response = requests.get(
                f"{self.base_url}/api/v1/public/info",
                headers={'Authorization': f'Bearer {self.api_key}'}
            )

            if response.status_code == 200:
                data = response.json()
                print("✅ API信息获取成功:")
                print(f"   API名称: {data['data']['name']}")
                print(f"   API版本: {data['data']['version']}")
                print(f"   API描述: {data['data']['description']}")
                return True
            else:
                print(f"❌ API信息获取失败: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ 测试API信息时发生错误: {e}")
            return False

    def test_list_files(self):
        """测试文件列表端点"""
        if not self.api_key:
            print("❌ 没有API密钥，无法测试")
            return False

        try:
            response = requests.get(
                f"{self.base_url}/api/v1/public/files",
                headers={'Authorization': f'Bearer {self.api_key}'},
                params={'limit': 10}
            )

            if response.status_code == 200:
                data = response.json()
                files = data.get('data', {}).get('files', [])
                print(f"✅ 文件列表获取成功，共 {len(files)} 个文件:")

                for file in files[:3]:  # 只显示前3个文件
                    print(f"   📁 {file['original_name']} (ID: {file['id']}, 大小: {file['size']} bytes)")

                if len(files) > 3:
                    print(f"   ... 还有 {len(files) - 3} 个文件")

                return True
            else:
                print(f"❌ 文件列表获取失败: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ 测试文件列表时发生错误: {e}")
            return False

    def test_upload_file(self):
        """测试文件上传"""
        if not self.api_key:
            print("❌ 没有API密钥，无法测试")
            return False

        # 创建一个测试文件
        test_content = {
            "test": True,
            "message": "这是一个API测试文件",
            "timestamp": datetime.now().isoformat(),
            "version": "1.0.0"
        }

        test_file_path = "test_config.json"

        try:
            # 写入测试文件
            with open(test_file_path, 'w', encoding='utf-8') as f:
                json.dump(test_content, f, ensure_ascii=False, indent=2)

            # 上传文件
            with open(test_file_path, 'rb') as f:
                response = requests.post(
                    f"{self.base_url}/api/v1/public/files/upload",
                    headers={'Authorization': f'Bearer {self.api_key}'},
                    files={'file': f},
                    data={
                        'type': 'config',
                        'description': 'API测试上传的配置文件'
                    }
                )

            # 清理测试文件
            if os.path.exists(test_file_path):
                os.remove(test_file_path)

            if response.status_code == 201:
                data = response.json()
                print("✅ 文件上传成功:")
                print(f"   文件ID: {data.get('data', {}).get('file_id', '未知')}")
                return True
            else:
                print(f"❌ 文件上传失败: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ 测试文件上传时发生错误: {e}")
            # 确保清理测试文件
            if os.path.exists(test_file_path):
                os.remove(test_file_path)
            return False

    def test_download_file(self, file_id=None):
        """测试文件下载"""
        if not self.api_key:
            print("❌ 没有API密钥，无法测试")
            return False

        if not file_id:
            # 先获取文件列表找一个文件
            try:
                response = requests.get(
                    f"{self.base_url}/api/v1/public/files",
                    headers={'Authorization': f'Bearer {self.api_key}'},
                    params={'limit': 1}
                )

                if response.status_code == 200:
                    data = response.json()
                    files = data.get('data', {}).get('files', [])
                    if files:
                        file_id = files[0]['id']
                    else:
                        print("❌ 没有可下载的文件")
                        return False
                else:
                    print(f"❌ 获取文件列表失败: {response.status_code}")
                    return False

            except Exception as e:
                print(f"❌ 获取文件列表时发生错误: {e}")
                return False

        try:
            response = requests.get(
                f"{self.base_url}/api/v1/public/files/{file_id}/download",
                headers={'Authorization': f'Bearer {self.api_key}'}
            )

            if response.status_code == 200:
                print(f"✅ 文件下载成功:")
                print(f"   文件ID: {file_id}")
                print(f"   文件大小: {len(response.content)} bytes")
                print(f"   内容类型: {response.headers.get('Content-Type', '未知')}")
                return True
            else:
                print(f"❌ 文件下载失败: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ 测试文件下载时发生错误: {e}")
            return False

    def get_usage_stats(self):
        """获取使用统计"""
        if not hasattr(self, 'admin_token'):
            print("❌ 需要管理员权限查看使用统计")
            return False

        try:
            response = self.session.get(
                f"{self.base_url}/api/v1/admin/usage/summary",
                headers={'Authorization': f'Bearer {self.admin_token}'}
            )

            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {})
                print("✅ 使用统计:")
                print(f"   今日请求: {stats.get('today', {}).get('requests', 0)}")
                print(f"   今日下载: {stats.get('today', {}).get('downloads', 0)}")
                print(f"   今日上传: {stats.get('today', {}).get('uploads', 0)}")
                print(f"   总API密钥: {stats.get('total', {}).get('api_keys', 0)}")
                print(f"   活跃密钥: {stats.get('total', {}).get('active_keys', 0)}")
                return True
            else:
                print(f"❌ 获取使用统计失败: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ 获取使用统计时发生错误: {e}")
            return False

    def run_full_demo(self):
        """运行完整演示"""
        print("🚀 开始API功能完整演示")
        print("=" * 50)

        # 1. 管理员登录
        print("\n1️⃣ 管理员登录")
        if not self.login_admin():
            return False

        # 2. 创建API密钥
        print("\n2️⃣ 创建API密钥")
        api_key = self.create_api_key(
            name="完整演示API密钥",
            permissions=["read", "download", "upload"]
        )
        if not api_key:
            return False

        # 3. 测试API信息
        print("\n3️⃣ 测试API信息")
        self.test_api_info()

        # 4. 测试文件列表
        print("\n4️⃣ 测试文件列表")
        self.test_list_files()

        # 5. 测试文件上传
        print("\n5️⃣ 测试文件上传")
        self.test_upload_file()

        # 6. 测试文件下载
        print("\n6️⃣ 测试文件下载")
        self.test_download_file()

        # 7. 获取使用统计
        print("\n7️⃣ 获取使用统计")
        self.get_usage_stats()

        print("\n🎉 API功能演示完成！")
        print("\n💡 提示：")
        print(f"   - 您的API密钥: {self.api_key}")
        print("   - 请保存好API密钥，它不会再次显示")
        print("   - 可以在管理员界面查看详细的使用统计")
        print("   - 查看 API_USAGE_GUIDE.md 了解更多使用方法")

def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python test_api.py create_key    # 创建API密钥")
        print("  python test_api.py test_api      # 测试API功能")
        print("  python test_api.py full_demo     # 完整演示")
        return

    command = sys.argv[1]
    tester = FileManagerAPITester()

    if command == "create_key":
        print("🔑 创建API密钥")
        tester.login_admin()
        tester.create_api_key()

    elif command == "test_api":
        # 需要先手动设置API密钥
        api_key = input("请输入API密钥: ").strip()
        if not api_key:
            print("❌ 未提供API密钥")
            return

        tester.api_key = api_key
        print("🧪 测试API功能")
        tester.test_api_info()
        tester.test_list_files()

    elif command == "full_demo":
        tester.run_full_demo()

    else:
        print(f"❌ 未知命令: {command}")

if __name__ == "__main__":
    main()