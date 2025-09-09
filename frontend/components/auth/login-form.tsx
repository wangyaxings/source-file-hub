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
  { username: "admin", description: "Administrator Account" },
  { username: "user1", description: "Regular User Account" },
  { username: "test", description: "Test Account" }
]

export function LoginForm({ onLogin }: LoginFormProps) {
  const [formData, setFormData] = useState<LoginRequest>({
    username: "",
    password: ""
  })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  const handleUserSelect = (value: string) => {
    setFormData(prev => ({
      ...prev,
      username: value
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
      setError(error instanceof Error ? error.message : "Login failed")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold">System Login</CardTitle>
        <CardDescription>
          Select user account or manually enter credentials
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="user-select">Select User</Label>
            <Select onValueChange={handleUserSelect}>
              <SelectTrigger id="user-select">
                <SelectValue placeholder="Select preset user" />
              </SelectTrigger>
              <SelectContent>
                {defaultUsers.map((user) => (
                  <SelectItem
                    key={user.username}
                    value={user.username}
                  >
                    <div className="flex flex-col">
                      <span>{user.username}</span>
                      <span className="text-xs text-muted-foreground">{user.description}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              type="text"
              value={formData.username}
              onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
              placeholder="admin"
              required
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={formData.password}
              onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
              placeholder="Enter password"
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
                Logging in...
              </>
            ) : (
              <>
                <LogIn className="mr-2 h-4 w-4" />
                Login
              </>
            )}
          </Button>
        </CardFooter>
      </form>
    </Card>
  )
}