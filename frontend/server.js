const { createServer } = require('https')
const { parse } = require('url')
const next = require('next')
const { createProxyMiddleware } = require('http-proxy-middleware')
const fs = require('fs')
const path = require('path')

const dev = process.env.NODE_ENV !== 'production'
const hostname = process.env.HOSTNAME || '127.0.0.1'
const port = Number(process.env.PORT || 30000)

// Disable SSL certificate verification for development
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const app = next({ dev, hostname, port })
const handle = app.getRequestHandler()

// Resolve backend target based on env
const backendTarget = process.env.BACKEND_URL || 'https://localhost:8443'

// Proxy configuration for API requests
const apiProxy = createProxyMiddleware({
  target: backendTarget,
  changeOrigin: true,
  // 修复路径重写问题 - 不需要重写，直接转发
  secure: false, // Ignore SSL certificate errors
  logLevel: 'debug',
  timeout: 120000, // 120 seconds timeout
  proxyTimeout: 120000, // 120 seconds proxy timeout
  onError: (err, req, res) => {
    console.error('Proxy error:', err)
    res.writeHead(500, {
      'Content-Type': 'text/plain',
    })
    res.end('Proxy error: ' + err.message)
  }
})

app.prepare().then(() => {
  const certDir = path.resolve(__dirname, '..', 'certs')
  const options = {
    key: fs.readFileSync(path.join(certDir, 'server.key')),
    cert: fs.readFileSync(path.join(certDir, 'server.crt')),
  }

  createServer(options, async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true)
      const { pathname } = parsedUrl

      // Handle API proxy - 直接转发所有/api 开头的请求
      if (pathname.startsWith('/api')) {
        console.log(`Proxying request: ${pathname}`)
        apiProxy(req, res)
        return
      }

      // Handle everything else with Next.js
      await handle(req, res, parsedUrl)
    } catch (err) {
      console.error('Error occurred handling', req.url, err)
      res.statusCode = 500
      res.end('internal server error')
    }
  }).listen(port, hostname, (err) => {
    if (err) throw err
    console.log(`> Ready on https://${hostname}:${port}`)
    console.log(`> API proxy target: ${backendTarget}`)
  })
})