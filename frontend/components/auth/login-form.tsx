"use client";

import { useState, useEffect } from "react";
import { Form, Input, Button, Card, Alert, Typography, Space } from "antd";
import { LoginOutlined, ArrowLeftOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { apiClient, type LoginRequest } from "@/lib/api";
import { TwoFASetupDialog } from "@/components/auth/twofa-setup-dialog";

interface LoginFormProps {
  onLogin: () => void;
}

type LoginFormValues = Pick<LoginRequest, "username" | "password">;

const OTP_INPUT_ID = "twofa-otp-input";

export function LoginForm({ onLogin }: LoginFormProps) {
  const [form] = Form.useForm<LoginFormValues>();
  const [isLoading, setIsLoading] = useState(false);
  const [showOtpInfo, setShowOtpInfo] = useState(true);
  const [error, setError] = useState("");
  const [show2FASetup, setShow2FASetup] = useState(false);
  const [loginStep, setLoginStep] = useState<'login' | '2fa-setup' | '2fa-verify'>('login');
  const [otpCode, setOtpCode] = useState("");
  const [cooldown, setCooldown] = useState(0);
  const [pendingUsername, setPendingUsername] = useState("");
  const [lastCredentials, setLastCredentials] = useState<LoginFormValues | null>(null);

  useEffect(() => {
    if (cooldown <= 0) {
      return;
    }
    const timer = window.setInterval(() => {
      setCooldown((current) => {
        if (current <= 1) {
          return 0;
        }
        return current - 1;
      });
    }, 1000);

    return () => window.clearInterval(timer);
  }, [cooldown]);

  const attemptLogin = async (credentials: LoginFormValues) => {
    setIsLoading(true);
    setError("");

    try {
      try {
        await apiClient.logoutUser();
      } catch {
        // ignore logout errors
      }

      setLastCredentials(credentials);
      const result = await apiClient.login(credentials);

      if (result.status === 'success') {
        onLogin();
        return;
      }

      setError('Login failed');
    } catch (err: any) {
      const errorMessage = err?.message || 'Login failed';

      if (errorMessage.includes('2FA_SETUP_REQUIRED')) {
        setPendingUsername(credentials.username);
        setLoginStep('2fa-setup');
        setShow2FASetup(true);
        setError('Please complete 2FA setup');
      } else if (errorMessage.includes('2FA_VERIFICATION_REQUIRED') || errorMessage.includes('2FA_REQUIRED')) {
        setPendingUsername(credentials.username);
        setLoginStep('2fa-verify');
        setOtpCode("");
        setCooldown(0);
        setError('Please enter your 2FA verification code');
      } else {
        setError(errorMessage);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleFinish = (values: LoginFormValues) => {
    attemptLogin(values);
  };

  const handle2FASetupComplete = async () => {
    setShow2FASetup(false);
    setError("");

    const credentials = lastCredentials ?? form.getFieldsValue() ?? null;
    if (!credentials || !credentials.username || !credentials.password) {
      setLoginStep('login');
      return;
    }

    await attemptLogin(credentials);
  };

  const handle2FAVerification = async () => {
    if (!otpCode.trim()) {
      setError('Please enter your 2FA verification code');
      return;
    }

    setIsLoading(true);
    try {
      await apiClient.verifyTOTP(otpCode);
      setError("");
      setCooldown(0);
      onLogin();
    } catch (err: any) {
      const code = err?.code as string | undefined;
      const retryAfter = Number(err?.retry_after || 0);

      if (code === '2FA_COOLDOWN') {
        setError(err?.message || 'Too many attempts. Please wait.');
        setCooldown(retryAfter > 0 ? retryAfter : 5);
      } else if (code === '2FA_TOO_MANY_ATTEMPTS') {
        setError('Too many 2FA failures. Please login again.');
        try {
          await apiClient.logoutUser();
        } catch {
          // ignore
        }
        setLoginStep('login');
        setOtpCode("");
        setCooldown(0);
      } else {
        setError(err?.message || 'Invalid 2FA code');
        setCooldown(0);
      }

      setOtpCode("");
      window.setTimeout(() => {
        document.getElementById(OTP_INPUT_ID)?.focus();
      }, 50);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Card
      className="w-full max-w-md mx-auto"
      title={
        <div>
          <Typography.Title level={3} className="!mb-1">
            System Login
          </Typography.Title>
          <Typography.Paragraph type="secondary" className="!mb-0">
            Enter your credentials to access the system
          </Typography.Paragraph>
        </div>
      }
    >
      {loginStep === 'login' && (
        <Form
          form={form}
          layout="vertical"
          onFinish={handleFinish}
          initialValues={{ username: '', password: '' }}
          autoComplete="off"
        >
          <Form.Item
            label="Username"
            name="username"
            rules={[{ required: true, message: 'Please enter your username' }]}
          >
            <Input placeholder="admin" autoComplete="username" />
          </Form.Item>

          <Form.Item
            label="Password"
            name="password"
            rules={[{ required: true, message: 'Please enter your password' }]}
          >
            <Input.Password placeholder="Enter password" autoComplete="current-password" />
          </Form.Item>

          <Space direction="vertical" size="middle" className="w-full">
            {showOtpInfo && (
              <Alert
                type="info"
                showIcon
                message="Two-factor authentication"
                description={
                  <span>
                    If your account has 2FA enabled, you will be prompted for a verification code.
                    <br />
                    After login, you can manage 2FA settings in your profile.
                  </span>
                }
                closable
                onClose={() => setShowOtpInfo(false)}
              />
            )}

            {error && (
              <Alert type="error" showIcon message={error} />
            )}

            <Button
              type="primary"
              htmlType="submit"
              block
              icon={<LoginOutlined />}
              loading={isLoading}
            >
              Login
            </Button>
          </Space>
        </Form>
      )}

      {loginStep === '2fa-verify' && (
        <Space direction="vertical" size="large" className="w-full">
          <div className="text-center space-y-1">
            <Typography.Title level={4} className="!mb-0">
              2FA Verification
            </Typography.Title>
            <Typography.Text type="secondary">
              Enter the 6-digit code from your authenticator app
            </Typography.Text>
          </div>

          <Space direction="vertical" size="small" className="w-full">
            <Typography.Text strong>Verification Code</Typography.Text>
            <Input
              id={OTP_INPUT_ID}
              value={otpCode}
              inputMode="numeric"
              onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              placeholder="123456"
              maxLength={6}
              status={error ? 'error' : ''}
              size="large"
              className="text-center tracking-[0.4em] font-mono"
            />
          </Space>

          {error && (
            <Alert type="error" showIcon message={error} />
          )}

          <div className="flex gap-2">
            <Button
              block
              onClick={() => {
                setLoginStep('login');
                setError("");
                setOtpCode("");
                setCooldown(0);
              }}
              icon={<ArrowLeftOutlined />}
            >
              Back
            </Button>
            <Button
              type="primary"
              block
              onClick={handle2FAVerification}
              disabled={otpCode.length !== 6 || cooldown > 0}
              loading={isLoading}
              icon={<SafetyCertificateOutlined />}
            >
              {cooldown > 0 ? `Wait ${cooldown}s` : 'Verify'}
            </Button>
          </div>
        </Space>
      )}

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
  );
}
