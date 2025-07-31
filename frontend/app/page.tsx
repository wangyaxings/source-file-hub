'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { LoginForm } from "@/components/auth/login-form"
import { FileUpload } from "@/components/file/file-upload"
import { FileList } from "@/components/file/file-list"
import { apiClient, type UserInfo } from "@/lib/api"
import {
  LogOut,
  Upload,
  Files,
  Shield,
  User,
  Server,
  CheckCircle,
  AlertTriangle
} from "lucide-react"

export default function HomePage() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [refreshTrigger, setRefreshTrigger] = useState(0)
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null)
  const [serverStatus, setServerStatus] = useState<{
    online: boolean
    message: string
  } | null>(null)

  useEffect(() => {
    // 检查是否已登录
    const checkAuth = async () => {
      const authenticated = apiClient.isAuthenticated()
      setIsAuthenticated(authenticated)

      if (authenticated) {
        const user = apiClient.getCurrentUser()
        setCurrentUser(user)
      }

      setIsLoading(false)

      // 检查服务器状态
      try {
        await apiClient.healthCheck()
        setServerStatus({ online: true, message: "服务器连接正常" })
      } catch (error) {
        setServerStatus({
          online: false,
          message: error instanceof Error ? error.message : "服务器连接失败"
        })
      }
    }

    checkAuth()
  }, [])

  const handleLogin = () => {
    setIsAuthenticated(true)
    const user = apiClient.getCurrentUser()
    setCurrentUser(user)
  }

  const handleLogout = async () => {
    try {
      await apiClient.logoutUser()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      setIsAuthenticated(false)
      setCurrentUser(null)
    }
  }

  const handleUploadComplete = () => {
    // 触发文件列表刷新
    setRefreshTrigger(prev => prev + 1)
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-500">正在加载...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md space-y-6">
          {/* 服务器状态 */}
          {serverStatus && (
            <Card className={serverStatus.online ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}>
              <CardContent className="pt-4">
                <div className="flex items-center gap-2">
                  {serverStatus.online ? (
                    <CheckCircle className="h-4 w-4 text-green-600" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-red-600" />
                  )}
                  <span className={`text-sm ${serverStatus.online ? "text-green-800" : "text-red-800"}`}>
                    {serverStatus.message}
                  </span>
                </div>
              </CardContent>
            </Card>
          )}

          <LoginForm onLogin={handleLogin} />
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* 头部导航 */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">文件管理系统</h1>
                <p className="text-sm text-gray-500">安全文件上传与管理平台</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* 服务器状态指示 */}
              {serverStatus && (
                <div className="flex items-center gap-2 text-sm">
                  <Server className="h-4 w-4 text-gray-400" />
                  <span className={serverStatus.online ? "text-green-600" : "text-red-600"}>
                    {serverStatus.online ? "在线" : "离线"}
                  </span>
                </div>
              )}

              {/* 用户信息 */}
              {currentUser && (
                <div className="flex items-center gap-3">
                  <Avatar className="h-8 w-8">
                    <AvatarImage src="" />
                    <AvatarFallback className="bg-primary text-white text-sm">
                      {currentUser.username.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="hidden sm:block">
                    <div className="text-sm font-medium text-gray-900">
                      {currentUser.username}
                    </div>
                    <div className="text-xs text-gray-500">
                      @{currentUser.tenant_id}
                    </div>
                  </div>
                </div>
              )}

              <Button variant="outline" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4 mr-2" />
                退出登录
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* 主要内容 */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <Tabs defaultValue="upload" className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 max-w-md">
            <TabsTrigger value="upload" className="flex items-center gap-2">
              <Upload className="h-4 w-4" />
              文件上传
            </TabsTrigger>
            <TabsTrigger value="manage" className="flex items-center gap-2">
              <Files className="h-4 w-4" />
              文件管理
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="space-y-6">
            <FileUpload onUploadComplete={handleUploadComplete} />
          </TabsContent>

          <TabsContent value="manage" className="space-y-6">
            <FileList refreshTrigger={refreshTrigger} />
          </TabsContent>
        </Tabs>
      </main>

      {/* 页脚 */}
      <footer className="bg-white border-t border-gray-200 mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-sm text-gray-500">
            <p>© 2024 File Manager. 安全文件管理系统</p>
            <p className="mt-2">支持配置文件、证书文件和文档的版本化管理</p>
          </div>
        </div>
      </footer>
    </div>
  )
}