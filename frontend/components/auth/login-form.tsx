'use client'

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { apiClient, type LoginRequest } from "@/lib/api"
import { LogIn, Loader2 } from "lucide-react"
import { TwoFASetupDialog } from "@/components/auth/twofa-setup-dialog"

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
  const [show2FASetup, setShow2FASetup] = useState(false)
  const [pendingUsername, setPendingUsername] = useState("")
  const [loginStep, setLoginStep] = useState<'login' | '2fa'>('login')


  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    try {
      const result = await apiClient.login(formData)

      if (result.status === 'success') {
        onLogin()
      }
    } catch (error: any) {
      const errorMessage = error?.message || 'Login failed'

      // 处理2FA相关错误
      if (errorMessage.includes('2FA_REQUIRED')) {
        setLoginStep('2fa')
        setError("Please enter your 2FA verification code")
      } else if (errorMessage.includes('2fa setup required')) {
        setShow2FASetup(true)
        setError("Please complete 2FA setup")
      } else {
        setError(errorMessage)
      }
    } finally {
      setIsLoading(false)
    }
  }

  const handle2FASetupComplete = async () => {
    setShow2FASetup(false)
    setError("")
    // 2FA设置完成后，尝试重新登录
    try {
      await apiClient.login(formData)
      onLogin()
    } catch (error) {
      setError(error instanceof Error ? error.message : "Login failed after 2FA setup")
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
              If your account has 2FA enabled, you will be prompted for verification code.
              <br />
              <small>
                After login, you can manage 2FA settings in your profile.
              </small>
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
      
      {/* 2FA设置对话框 */}
      {show2FASetup && (
        <TwoFASetupDialog
          open={show2FASetup}
          onOpenChange={setShow2FASetup}
          onSetupComplete={handle2FASetupComplete}
        />
      )}
    </Card>
  )
}
