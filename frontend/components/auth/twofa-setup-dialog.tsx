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
}

export function TwoFASetupDialog({ open, onOpenChange, onSetupComplete }: TwoFASetupDialogProps) {
  const { toast } = useToast()
  const [step, setStep] = useState<'setup' | 'verify'>('setup')
  const [secret, setSecret] = useState('')
  const [qrCodeUrl, setQrCodeUrl] = useState('')
  const [verificationCode, setVerificationCode] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isVerifying, setIsVerifying] = useState(false)

  useEffect(() => {
    if (open && step === 'setup') {
      startSetup()
    }
  }, [open, step])

  const startSetup = async () => {
    setIsLoading(true)
    try {
      const response = await apiClient.request('/auth/2fa/setup', { method: 'POST' })
      if (response.success && response.data) {
        setSecret(response.data.secret || '')
        setQrCodeUrl(response.data.otpauth_url || '')
        setStep('verify')
      } else {
        throw new Error(response.error || 'Failed to start 2FA setup')
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Setup Failed",
        description: error instanceof Error ? error.message : 'Failed to start 2FA setup'
      })
      onOpenChange(false)
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
      const response = await apiClient.request('/auth/2fa/enable', {
        method: 'POST',
        body: JSON.stringify({ code: verificationCode })
      })

      if (response.success) {
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
      } else {
        throw new Error(response.error || 'Failed to enable 2FA')
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-blue-600" />
            Enable Two-Factor Authentication
          </DialogTitle>
          <DialogDescription>
            Secure your account with two-factor authentication using an authenticator app
          </DialogDescription>
        </DialogHeader>

        {step === 'setup' && (
          <div className="space-y-6">
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
                <span className="ml-2">Setting up 2FA...</span>
              </div>
            ) : (
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
            )}
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
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          {step === 'verify' && (
            <Button onClick={verifyAndEnable} disabled={isVerifying || verificationCode.length !== 6}>
              {isVerifying ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                'Enable 2FA'
              )}
            </Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
