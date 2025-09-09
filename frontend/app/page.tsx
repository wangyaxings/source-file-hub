'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { LoginForm } from "@/components/auth/login-form"
import { FileUpload } from "@/components/file/file-upload"
import { PackagesPanel } from "@/components/packages/packages-panel"
import { FileList } from "@/components/file/file-list"
import { RecycleBin } from "@/components/file/recycle-bin"
import { Toaster } from "@/components/ui/toaster"
import { apiClient, type UserInfo } from "@/lib/api"
import { APIKeyManagement } from "@/components/admin/api-key-management"
import {
  LogOut,
  Upload,
  Files,
  Shield,
  User,
  Server,
  CheckCircle,
  AlertTriangle,
  Trash2,
  
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
    // Check if already logged in
    const checkAuth = async () => {
      const authenticated = apiClient.isAuthenticated()
      setIsAuthenticated(authenticated)

      if (authenticated) {
        const user = apiClient.getCurrentUser()
        setCurrentUser(user)
      }

      setIsLoading(false)

      // Check server status
      try {
        await apiClient.healthCheck()
        setServerStatus({ online: true, message: "Server connection normal" })
      } catch (error) {
        setServerStatus({
          online: false,
          message: error instanceof Error ? error.message : "Server connection failed"
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
    // Trigger file list refresh
    setRefreshTrigger(prev => prev + 1)
  }

  const isAdmin = currentUser?.username === 'admin'
  const tabsColsClass = isAdmin ? 'grid-cols-5' : 'grid-cols-4'

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-500">Loading...</p>
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
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* 头部导航 */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-primary rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">File Management System</h1>
                <p className="text-sm text-gray-500">Secure File Upload and Management Platform</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* 服务器状态指示 */}
              {serverStatus && (
                <div className="flex items-center gap-2 text-sm">
                  <Server className="h-4 w-4 text-gray-400" />
                  <span className={serverStatus.online ? "text-green-600" : "text-red-600"}>
                    {serverStatus.online ? "Online" : "Offline"}
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
                  </div>
                </div>
              )}

              <Button variant="outline" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4 mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* 主要内容 */}
            <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        <Tabs defaultValue="upload" className="space-y-6">
          <TabsList className={`grid w-full ${tabsColsClass} max-w-3xl`}>
            <TabsTrigger value="upload" className="flex items-center gap-2">
              <Upload className="h-4 w-4" />
              Upload
            </TabsTrigger>
            <TabsTrigger value="manage" className="flex items-center gap-2">
              <Files className="h-4 w-4" />
              Files
            </TabsTrigger>
            <TabsTrigger value="recycle" className="flex items-center gap-2">
              <Trash2 className="h-4 w-4" />
              Recycle
            </TabsTrigger>
            <TabsTrigger value="packages" className="flex items-center gap-2">
              <Files className="h-4 w-4" />
              Packages
            </TabsTrigger>
            {isAdmin && (
              <TabsTrigger value="admin" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                API Keys
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="upload" className="space-y-6">
            <FileUpload onUploadComplete={handleUploadComplete} />
          </TabsContent>

          <TabsContent value="manage" className="space-y-6">
            <FileList refreshTrigger={refreshTrigger} />
          </TabsContent>

          <TabsContent value="recycle" className="space-y-6">
            <RecycleBin />
          </TabsContent>

          <TabsContent value="packages" className="space-y-6">
            <PackagesPanel />
          </TabsContent>

          {isAdmin && (
            <TabsContent value="admin" className="space-y-6">
              <APIKeyManagement />
            </TabsContent>
          )}
        </Tabs>
      </main>

      {/* 页脚 - 固定在底部 */}
      <footer className="bg-white border-t border-gray-200 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-sm text-gray-500">
            <p>© 2024 File Manager. Secure File Management System</p>
            <p className="mt-2">Supports versioned management of configuration files, certificates and documents</p>
          </div>
        </div>
      </footer>

      <Toaster />
    </div>
  )
}
