'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/lib/use-toast"
import { apiClient } from "@/lib/api"
import {
  Shield,
  Smartphone,
  Copy,
  CheckCircle,
  AlertTriangle,
  Loader2,
  QrCode
} from "lucide-react"

interface TwoFASetupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSetupComplete: () => void
  isRequired?: boolean
  username?: string // 用于记住该账户已确认“已添加账户”，避免再次显示二维码
}

export function TwoFASetupDialog({ open, onOpenChange, onSetupComplete, isRequired = false, username }: TwoFASetupDialogProps) {
  const { toast } = useToast()
  const [step, setStep] = useState<'setup' | 'qrcode' | 'verify'>('setup')
  const [secret, setSecret] = useState('')
  const [qrCodeUrl, setQrCodeUrl] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isVerifying, setIsVerifying] = useState(false)
  const [hasStartedSetup, setHasStartedSetup] = useState(false)
  const [qrAcknowledged, setQrAcknowledged] = useState(false)
  const [setupError, setSetupError] = useState<string | null>(null)

  // 每次弹窗打开或账户变更时，读取本地状态：该账户是否已点击“已添加账户”
  useEffect(() => {
    if (!open) return
    if (!username) return
    try {
      const key = `2fa.qrAck.${username}`
      const val = localStorage.getItem(key)
      setQrAcknowledged(val === 'true')
    } catch {
      // 忽略本地存储读取错误
    }
  }, [open, username])

  useEffect(() => {
    if (open && step === 'setup' && !hasStartedSetup && !isLoading) {
      startSetup()
    }
  }, [open, step, hasStartedSetup, isLoading])

  const startSetup = async () => {
    if (hasStartedSetup) return // Prevent duplicate calls
    
    setHasStartedSetup(true)
    setIsLoading(true)
    try {
      setSetupError(null)
      const response = await apiClient.setupTOTP()
      setSecret(response.secret || '')
      setQrCodeUrl(response.otpauth_url || '')
      // 如果该账户已经确认“已添加账户”，则直接进入验证码验证步骤
      let acknowledged = qrAcknowledged
      try {
        if (!acknowledged && username) {
          acknowledged = localStorage.getItem(`2fa.qrAck.${username}`) === 'true'
        }
      } catch {
        // ignore
      }
      if (acknowledged) {
        setStep('verify')
      } else {
        setStep('qrcode')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to start 2FA setup'
      setSetupError(message)
      toast({
        variant: "destructive",
        title: "Setup Failed",
        description: message
      })
      // Do NOT auto-retry when required; avoid infinite request loops
      // Keep dialog open and show a Retry button instead.
    } finally {
      setIsLoading(false)
    }
  }

  const verifyAndEnable = async () => {
    if (!verificationCode.trim()) {
      toast({
        variant: "destructive",
        title: "Verification Required",
        description: "Please enter the verification code from your authenticator app"
      })
      return
    }

    setIsVerifying(true)
    try {
      await apiClient.confirmTOTP(verificationCode)
      toast({
        title: "2FA Enabled",
        description: "Two-factor authentication has been successfully enabled for your account"
      })
      onSetupComplete()
      onOpenChange(false)
      // Reset state
      setStep('setup')
      setSecret('')
      setQrCodeUrl('')
      setVerificationCode('')
      setHasStartedSetup(false)
      setQrAcknowledged(false)
      try {
        if (username) {
          localStorage.removeItem(`2fa.qrAck.${username}`)
        }
      } catch {
        // ignore
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Verification Failed",
        description: error instanceof Error ? error.message : 'Failed to verify and enable 2FA'
      })
    } finally {
      setIsVerifying(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard.writeText(secret)
    toast({
      title: "Copied",
      description: "Secret key copied to clipboard"
    })
  }

  const copyQrUrl = () => {
    navigator.clipboard.writeText(qrCodeUrl)
    toast({
      title: "Copied",
      description: "QR code URL copied to clipboard"
    })
  }

  const proceedToVerify = () => {
    setStep('verify')
    setQrAcknowledged(true)
    try {
      if (username) {
        localStorage.setItem(`2fa.qrAck.${username}`, 'true')
      }
    } catch {
      // 忽略本地存储写入错误
    }
  }

  return (
    <Dialog open={open} onOpenChange={isRequired ? () => {} : onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-600" />
            {isRequired ? "Complete Required Security Setup" : "Enable Two-Factor Authentication"}
          </DialogTitle>
          <DialogDescription>
            {isRequired 
              ? "Your administrator requires two-factor authentication for your account. Please complete the setup to continue."
              : "Secure your account with two-factor authentication using an authenticator app"
            }
          </DialogDescription>
        </DialogHeader>

        {step === 'setup' && (
          <div className="space-y-6">
            {setupError ? (
              <div className="space-y-4">
                <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="h-4 w-4 text-red-600" />
                    <span className="font-medium text-red-800">Setup failed</span>
                  </div>
                  <p className="text-sm text-red-700 break-words">{setupError}</p>
                </div>
                <div className="flex items-center gap-3">
                  <Button
                    onClick={() => { setHasStartedSetup(false); setSetupError(null); setStep('setup') }}
                    disabled={isLoading}
                  >
                    Retry
                  </Button>
                  {!isRequired && (
                    <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isLoading}>
                      Cancel
                    </Button>
                  )}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
                <span className="ml-2">Setting up 2FA...</span>
              </div>
            )}
          </div>
        )}

        {step === 'qrcode' && (
          <div className="space-y-6">
            <div className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Smartphone className="h-4 w-4 text-blue-600" />
                  <span className="font-medium text-blue-800">Step 1: Install an Authenticator App</span>
                </div>
                <p className="text-sm text-blue-700">
                  Download and install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.
                </p>
              </div>

              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <QrCode className="h-4 w-4 text-green-600" />
                  <span className="font-medium text-green-800">Step 2: Scan QR Code</span>
                </div>
                <p className="text-sm text-green-700 mb-3">
                  Open your authenticator app and scan the QR code below, or manually enter the secret key.
                </p>

                {qrCodeUrl && (
                  <div className="flex items-center gap-4">
                    <div className="bg-white p-2 rounded border">
                      <img
                        src={`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(qrCodeUrl)}`}
                        alt="2FA QR Code"
                        className="w-32 h-32"
                      />
                    </div>
                    <div className="space-y-2">
                      <Button variant="outline" size="sm" onClick={copyQrUrl}>
                        <Copy className="h-4 w-4 mr-2" />
                        Copy QR URL
                      </Button>
                      <div className="text-xs text-gray-600">
                        <p className="font-medium">Or enter this secret key manually:</p>
                        <div className="flex items-center gap-2 mt-1">
                          <code className="bg-gray-100 px-2 py-1 rounded text-xs font-mono">
                            {secret}
                          </code>
                          <Button variant="ghost" size="sm" onClick={copySecret}>
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                <div className="flex items-center gap-2 mb-2">
                  <AlertTriangle className="h-4 w-4 text-yellow-600" />
                  <span className="font-medium text-yellow-800">Important</span>
                </div>
                <p className="text-sm text-yellow-700">
                  Save the secret key in a secure location. You'll need it to recover your account if you lose access to your authenticator app.
                </p>
              </div>
            </div>
          </div>
        )}

        {step === 'verify' && (
          <div className="space-y-6">
            <div className="bg-green-50 border border-green-200 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="h-4 w-4 text-green-600" />
                <span className="font-medium text-green-800">Step 3: Verify Setup</span>
              </div>
              <p className="text-sm text-green-700 mb-4">
                Enter the 6-digit code from your authenticator app to complete the setup.
              </p>

              <div className="space-y-2">
                <Label htmlFor="verificationCode">Verification Code</Label>
                <Input
                  id="verificationCode"
                  type="text"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="123456"
                  className="text-center text-lg font-mono tracking-widest"
                  maxLength={6}
                />
              </div>
            </div>
          </div>
        )}

        <DialogFooter>
          {!isRequired && (
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
          )}
          {step === 'qrcode' && (
            <Button onClick={proceedToVerify}>
              I've Added the Account
            </Button>
          )}
          {step === 'verify' && (
            <Button onClick={verifyAndEnable} disabled={isVerifying || verificationCode.length !== 6}>
              {isVerifying ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                'Verify'
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
