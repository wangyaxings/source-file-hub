const { createServer } = require('http')
const { parse } = require('url')
const next = require('next')
const { createProxyMiddleware } = require('http-proxy-middleware')

const dev = process.env.NODE_ENV !== 'production'
const hostname = 'localhost'
const port = 3000

// Disable SSL certificate verification for development
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'

const app = next({ dev, hostname, port })
const handle = app.getRequestHandler()

// Proxy configuration for API requests
const apiProxy = createProxyMiddleware({
  target: 'https://localhost:8443',
  changeOrigin: true,
  pathRewrite: {
    '^/api': '/api/v1'
  },
  secure: false, // Ignore SSL certificate errors
  logLevel: 'debug'
})

app.prepare().then(() => {
  createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true)
      const { pathname } = parsedUrl

      // Handle API proxy
      if (pathname.startsWith('/api')) {
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
  }).listen(port, (err) => {
    if (err) throw err
    console.log(`> Ready on http://${hostname}:${port}`)
  })
})