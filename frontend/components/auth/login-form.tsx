'use client'

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { apiClient, type LoginRequest } from "@/lib/api"
import { LogIn, Loader2 } from "lucide-react"

interface LoginFormProps {
  onLogin: () => void
}

const defaultUsers = [
  { tenant_id: "demo", username: "admin", description: "管理员账户" },
  { tenant_id: "demo", username: "user1", description: "普通用户账户" },
  { tenant_id: "tenant1", username: "test", description: "测试账户" }
]

export function LoginForm({ onLogin }: LoginFormProps) {
  const [formData, setFormData] = useState<LoginRequest>({
    tenant_id: "",
    username: "",
    password: ""
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  const handleUserSelect = (value: string) => {
    const [tenant_id, username] = value.split(":")
    setFormData(prev => ({
      ...prev,
      tenant_id,
      username
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setIsLoading(true)

    try {
      await apiClient.login(formData)
      onLogin()
    } catch (error) {
      setError(error instanceof Error ? error.message : "登录失败")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold">登录系统</CardTitle>
        <CardDescription>
          选择用户账户或手动输入凭据
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="user-select">选择用户</Label>
            <Select onValueChange={handleUserSelect}>
              <SelectTrigger id="user-select">
                <SelectValue placeholder="选择预设用户" />
              </SelectTrigger>
              <SelectContent>
                {defaultUsers.map((user) => (
                  <SelectItem
                    key={`${user.tenant_id}:${user.username}`}
                    value={`${user.tenant_id}:${user.username}`}
                  >
                    <div className="flex flex-col">
                      <span>{user.username}@{user.tenant_id}</span>
                      <span className="text-xs text-muted-foreground">{user.description}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="tenantId">租户ID</Label>
              <Input
                id="tenantId"
                type="text"
                value={formData.tenant_id}
                onChange={(e) => setFormData(prev => ({ ...prev, tenant_id: e.target.value }))}
                placeholder="demo"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="username">用户名</Label>
              <Input
                id="username"
                type="text"
                value={formData.username}
                onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                placeholder="admin"
                required
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">密码</Label>
            <Input
              id="password"
              type="password"
              value={formData.password}
              onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
              placeholder="输入密码"
              required
            />
          </div>

          {error && (
            <div className="text-sm text-red-500 bg-red-50 p-3 rounded-md border border-red-200">
              {error}
            </div>
          )}
        </CardContent>
        <CardFooter>
          <Button type="submit" className="w-full" disabled={isLoading}>
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                登录中...
              </>
            ) : (
              <>
                <LogIn className="mr-2 h-4 w-4" />
                登录
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}