'use client'

import { useState, useRef, useEffect } from "react"
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
  const [error, setError] = useState("")
  const [show2FASetup, setShow2FASetup] = useState(false)
  const [show2FAVerification, setShow2FAVerification] = useState(false)
  const [pendingUsername, setPendingUsername] = useState("")
  const [loginStep, setLoginStep] = useState<'login' | '2fa-setup' | '2fa-verify'>('login')
  const [otpCode, setOtpCode] = useState("")
  const [otpAttempts, setOtpAttempts] = useState(0)
  const [cooldown, setCooldown] = useState(0) // seconds remaining
  const otpInputRef = useRef<HTMLInputElement | null>(null)
  
  useEffect(() => {
    if (cooldown <= 0) return
    const t = setInterval(() => setCooldown((c) => c - 1), 1000)
    return () => clearInterval(t)
  }, [cooldown])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    try {
      // Ensure any existing session is cleared to avoid cross-user mixups (e.g., previous admin session)
      try { await apiClient.logoutUser() } catch {}

      const result = await apiClient.login(formData)

      if (result.status === 'success') {
        onLogin()
      }
    } catch (error: any) {
      const errorMessage = error?.message || 'Login failed'

      // 处理2FA相关错误
      if (errorMessage.includes('2FA_SETUP_REQUIRED')) {
        setPendingUsername(formData.username)
        setLoginStep('2fa-setup')
        setShow2FASetup(true)
        setError("Please complete 2FA setup")
      } else if (errorMessage.includes('2FA_VERIFICATION_REQUIRED')) {
        setLoginStep('2fa-verify')
        setShow2FAVerification(true)
        setError("Please enter your 2FA verification code")
      } else if (errorMessage.includes('2FA_REQUIRED')) {
        setLoginStep('2fa-verify')
        setShow2FAVerification(true)
        setError("Please enter your 2FA verification code")
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

  const handle2FAVerification = async () => {
    if (!otpCode.trim()) {
      setError("Please enter your 2FA verification code")
      return
    }

    setIsLoading(true)
    try {
      await apiClient.verifyTOTP(otpCode)
      setOtpAttempts(0)
      onLogin()
    } catch (error: any) {
      const code = error?.code as string | undefined
      const retryAfter = Number(error?.retry_after || 0)

      if (code === '2FA_COOLDOWN') {
        setError(error?.message || 'Too many attempts. Please wait.')
        setCooldown(retryAfter > 0 ? retryAfter : 5)
      } else if (code === '2FA_TOO_MANY_ATTEMPTS') {
        setError('Too many 2FA failures. Please login again.')
        // Force re-login
        try { await apiClient.logoutUser() } catch {}
        setLoginStep('login')
        setShow2FAVerification(false)
        setOtpAttempts(0)
        setOtpCode("")
        return
      } else {
        setError(error?.message || 'Invalid 2FA code')
        setOtpAttempts((n) => n + 1)
      }

      // Clear and focus input for retry
      setOtpCode("")
      setTimeout(() => otpInputRef.current?.focus(), 50)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="space-y-1">
        <CardTitle className="text-2xl font-bold">FileHub</CardTitle>
        <CardDescription>
          Enter your credentials to login
        </CardDescription>
      </CardHeader>
      
      {loginStep === 'login' && (
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
                placeholder="Enter username"
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
      )}

      {loginStep === '2fa-verify' && (
        <>
          <CardContent className="space-y-4">
            <div className="text-center">
              <h3 className="text-lg font-semibold">2FA Verification</h3>
              <p className="text-sm text-muted-foreground">
                Enter the 6-digit code from your authenticator app
              </p>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="otp">Verification Code</Label>
              <Input
                id="otp"
                type="text"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="123456"
                ref={otpInputRef}
                className={`text-center text-lg font-mono tracking-widest ${error ? 'border-red-500 focus-visible:ring-red-500' : ''}`}
                maxLength={6}
              />
            </div>

            {error && (
              <div className="text-sm text-red-500 bg-red-50 p-3 rounded-md border border-red-200">
                {error}
              </div>
            )}
          </CardContent>
          <CardFooter className="flex gap-2">
            <Button variant="outline" onClick={() => setLoginStep('login')} className="flex-1">
              Back
            </Button>
            <Button onClick={handle2FAVerification} disabled={isLoading || otpCode.length !== 6 || cooldown > 0} className="flex-1">
              {isLoading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Verifying...
                </>
              ) : cooldown > 0 ? (
                `Wait ${cooldown}s`
              ) : (
                'Verify'
              )}
            </Button>
          </CardFooter>
        </>
      )}
      
      {/* 2FA设置对话框 */}
      {show2FASetup && (
        <TwoFASetupDialog
          open={show2FASetup}
          onOpenChange={setShow2FASetup}
          onSetupComplete={handle2FASetupComplete}
          isRequired={true}
          username={pendingUsername}
        />
      )}
    </Card>
  )
}
