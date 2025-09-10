'use client'

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { apiClient, type LoginRequest } from "@/lib/api"
import { LogIn, Loader2 } from "lucide-react"

interface LoginFormProps {
  onLogin: () => void
}


export function LoginForm({ onLogin }: LoginFormProps) {
  const [formData, setFormData] = useState<LoginRequest>({
    username: "",
    password: ""
  })
  const [isLoading, setIsLoading] = useState(false)
  const [showOtpInfo, setShowOtpInfo] = useState(true)
  const [error, setError] = useState("")


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
          Enter your credentials to access the system
        </CardDescription>
      </CardHeader>
      <form onSubmit={handleSubmit}>
        <CardContent className="space-y-4">
          {/* Removed preset user select for production security */}

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

          {showOtpInfo && (
            <div className="text-xs text-muted-foreground bg-muted/30 p-3 rounded">
              If your account has 2FA enabled, you may be prompted to verify with a one-time code. After login, visit
              <code className="px-1">/api/v1/web/auth/2fa/totp/validate</code> to enter your 2FA code or
              set up via <code className="px-1">/api/v1/web/auth/2fa/totp/setup</code>.
            </div>
          )}

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
