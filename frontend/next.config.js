/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // 配置API代理，将前端API请求转发到后端
  async rewrites() {
    return [
      {
        source: '/api/v1/:path*',
        destination: 'https://localhost:8443/api/v1/:path*',
      },
    ]
  },

  // 配置实验性功能以支持HTTPS代理
  experimental: {
    serverComponentsExternalPackages: [],
  },
}

module.exports = nextConfig