'use client'

import { useState, useEffect } from "react"
import { Modal, Button, Input, Alert, Typography, Space, Card, Spin, message } from "antd"
import { 
  SafetyOutlined, 
  MobileOutlined, 
  CopyOutlined, 
  CheckCircleOutlined, 
  ExclamationCircleOutlined,
  QrcodeOutlined,
  LoadingOutlined
} from "@ant-design/icons"
import { apiClient } from "@/lib/api"

const { Title, Text, Paragraph } = Typography

interface TwoFASetupDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSetupComplete: () => void
  isRequired?: boolean
  username?: string // 用于记住该账户已确认"已添加账户"，避免再次显示二维码
}

export function TwoFASetupDialog({ open, onOpenChange, onSetupComplete, isRequired = false, username }: TwoFASetupDialogProps) {
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
      const errorMessage = error instanceof Error ? error.message : 'Failed to start 2FA setup'
      setSetupError(errorMessage)
      message.error(`Setup Failed: ${errorMessage}`)
      // Do NOT auto-retry when required; avoid infinite request loops
      // Keep dialog open and show a Retry button instead.
    } finally {
      setIsLoading(false)
    }
  }

  const verifyAndEnable = async () => {
    if (!verificationCode.trim()) {
      message.error('Please enter the verification code from your authenticator app')
      return
    }

    setIsVerifying(true)
    try {
      await apiClient.confirmTOTP(verificationCode)
      message.success('Two-factor authentication has been successfully enabled for your account')
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
      message.error(error instanceof Error ? error.message : 'Failed to verify and enable 2FA')
    } finally {
      setIsVerifying(false)
    }
  }

  const copySecret = () => {
    navigator.clipboard.writeText(secret)
    message.success('Secret key copied to clipboard')
  }

  const copyQrUrl = () => {
    navigator.clipboard.writeText(qrCodeUrl)
    message.success('QR code URL copied to clipboard')
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
    <Modal
      title={
        <Space>
          <SafetyOutlined style={{ color: '#1890ff' }} />
          {isRequired ? "Complete Required Security Setup" : "Enable Two-Factor Authentication"}
        </Space>
      }
      open={open}
      onCancel={isRequired ? undefined : () => onOpenChange(false)}
      footer={null}
      width={600}
      maskClosable={!isRequired}
    >
      <Space direction="vertical" size="large" style={{ width: '100%' }}>
        <Text type="secondary">
          {isRequired 
            ? "Your administrator requires two-factor authentication for your account. Please complete the setup to continue."
            : "Secure your account with two-factor authentication using an authenticator app"
          }
        </Text>

        {step === 'setup' && (
          <div>
            {setupError ? (
              <Space direction="vertical" size="middle" style={{ width: '100%' }}>
                <Alert
                  type="error"
                  showIcon
                  icon={<ExclamationCircleOutlined />}
                  message="Setup failed"
                  description={setupError}
                />
                <Space>
                  <Button
                    onClick={() => { setHasStartedSetup(false); setSetupError(null); setStep('setup') }}
                    disabled={isLoading}
                  >
                    Retry
                  </Button>
                  {!isRequired && (
                    <Button onClick={() => onOpenChange(false)} disabled={isLoading}>
                      Cancel
                    </Button>
                  )}
                </Space>
              </Space>
            ) : (
              <div style={{ textAlign: 'center', padding: '32px 0' }}>
                <Spin indicator={<LoadingOutlined style={{ fontSize: 32 }} spin />} />
                <div style={{ marginTop: 16 }}>Setting up 2FA...</div>
              </div>
            )}
          </div>
        )}

        {step === 'qrcode' && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Card size="small">
              <Space>
                <MobileOutlined style={{ color: '#1890ff' }} />
                <Text strong>Step 1: Install an Authenticator App</Text>
              </Space>
              <Paragraph style={{ marginTop: 8, marginBottom: 0 }}>
                Download and install an authenticator app like Google Authenticator, Authy, or Microsoft Authenticator on your mobile device.
              </Paragraph>
            </Card>

            <Card size="small">
              <Space>
                <QrcodeOutlined style={{ color: '#52c41a' }} />
                <Text strong>Step 2: Scan QR Code</Text>
              </Space>
              <Paragraph style={{ marginTop: 8 }}>
                Open your authenticator app and scan the QR code below, or manually enter the secret key.
              </Paragraph>

              {qrCodeUrl && (
                <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
                  <div style={{ padding: 8, background: 'white', border: '1px solid #d9d9d9', borderRadius: 4 }}>
                    <img
                      src={`https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(qrCodeUrl)}`}
                      alt="2FA QR Code"
                      style={{ width: 128, height: 128 }}
                    />
                  </div>
                  <Space direction="vertical">
                    <Button icon={<CopyOutlined />} onClick={copyQrUrl}>
                      Copy QR URL
                    </Button>
                    <div>
                      <Text strong style={{ fontSize: 12 }}>Or enter this secret key manually:</Text>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                        <code style={{ background: '#f5f5f5', padding: '2px 6px', borderRadius: 2, fontSize: 11, fontFamily: 'monospace' }}>
                          {secret}
                        </code>
                        <Button size="small" type="text" icon={<CopyOutlined />} onClick={copySecret} />
                      </div>
                    </div>
                  </Space>
                </div>
              )}
            </Card>

            <Alert
              type="warning"
              showIcon
              icon={<ExclamationCircleOutlined />}
              message="Important"
              description="Save the secret key in a secure location. You'll need it to recover your account if you lose access to your authenticator app."
            />

            <div style={{ textAlign: 'right' }}>
              <Button type="primary" onClick={proceedToVerify}>
                I've Added the Account
              </Button>
            </div>
          </Space>
        )}

        {step === 'verify' && (
          <Space direction="vertical" size="middle" style={{ width: '100%' }}>
            <Card size="small">
              <Space>
                <CheckCircleOutlined style={{ color: '#52c41a' }} />
                <Text strong>Step 3: Verify Setup</Text>
              </Space>
              <Paragraph style={{ marginTop: 8 }}>
                Enter the 6-digit code from your authenticator app to complete the setup.
              </Paragraph>

              <Space direction="vertical" style={{ width: '100%' }}>
                <Text strong>Verification Code</Text>
                <Input
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="123456"
                  style={{ textAlign: 'center', fontSize: 18, fontFamily: 'monospace', letterSpacing: '0.4em' }}
                  maxLength={6}
                  size="large"
                />
              </Space>
            </Card>

            <div style={{ textAlign: 'right' }}>
              <Space>
                {!isRequired && (
                  <Button onClick={() => onOpenChange(false)}>
                    Cancel
                  </Button>
                )}
                <Button 
                  type="primary" 
                  onClick={verifyAndEnable} 
                  disabled={isVerifying || verificationCode.length !== 6}
                  loading={isVerifying}
                >
                  {isVerifying ? 'Verifying...' : 'Verify'}
                </Button>
              </Space>
            </div>
          </Space>
        )}
      </Space>
    </Modal>
  )
}
