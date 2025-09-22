'use client'

import { useState, useEffect, useRef } from "react"
import { Tabs, Button, Space, Avatar, Dropdown, Badge, Spin, Card, Modal, Input, message, Typography } from "antd"
import { 
  UserOutlined, 
  UploadOutlined,
  FileOutlined,
  DeleteOutlined,
  SafetyOutlined,
  DatabaseOutlined,
  BellOutlined,
  SettingOutlined,
  LogoutOutlined,
  KeyOutlined,
  CheckCircleOutlined,
  ExclamationCircleOutlined
} from "@ant-design/icons"
import { LoginForm } from "@/components/auth/login-form"
import { TwoFASetupDialog } from "@/components/auth/twofa-setup-dialog"
import { FileUpload } from "@/components/file/file-upload"
import { PackagesPanel } from "@/components/packages/packages-panel"
import { FileListPaginated as FileList } from "@/components/file/file-list-paginated"
import { RecycleBin } from "@/components/file/recycle-bin"
import { apiClient, type UserInfo } from "@/lib/api"
import { APIKeyManagement } from "@/components/admin/api-key-management"
import UserManagement from "@/components/admin/user-management"
import { usePermissions } from "@/lib/permissions"

const { Title, Text } = Typography

export default function HomePage() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [refreshTrigger, setRefreshTrigger] = useState(0)
  const [permissionsRefreshTrigger, setPermissionsRefreshTrigger] = useState(0)
  const [currentUser, setCurrentUser] = useState<UserInfo | null>(null)
  const [serverStatus, setServerStatus] = useState<{
    online: boolean
    message: string
  } | null>(null)
  const [userNotice, setUserNotice] = useState("")

  // Change password dialog state
  const [showChangePwd, setShowChangePwd] = useState(false)
  const [oldPwd, setOldPwd] = useState("")
  const [newPwd, setNewPwd] = useState("")
  const [confirmPwd, setConfirmPwd] = useState("")
  const [isChanging, setIsChanging] = useState(false)
  const [changeErr, setChangeErr] = useState("")
  const [showReLoginPrompt, setShowReLoginPrompt] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const userMenuRef = useRef<HTMLDivElement | null>(null)
  const [showProfile, setShowProfile] = useState(false)
  const [showAbout, setShowAbout] = useState(false)
  const [apiInfo, setApiInfo] = useState<any | null>(null)
  const [showTwoFASetup, setShowTwoFASetup] = useState(false)

  useEffect(() => {
    if (!showUserMenu) return
    const onDocClick = (e: MouseEvent) => {
      if (!userMenuRef.current) return
      if (!userMenuRef.current.contains(e.target as Node)) {
        setShowUserMenu(false)
      }
    }
    document.addEventListener('mousedown', onDocClick)
    return () => document.removeEventListener('mousedown', onDocClick)
  }, [showUserMenu])

  // Load API info when About dialog opens
  useEffect(() => {
    const load = async () => {
      try {
        const info = await apiClient.getApiInfo()
        setApiInfo(info)
      } catch {
        // ignore errors
      }
    }
    if (showAbout && !apiInfo) load()
  }, [showAbout])

  useEffect(() => {
    // Check if already logged in
    const checkAuth = async () => {
      try {
        // Always check server-side authentication status first
        const userDetails = await fetch('/api/v1/web/auth/me', {
          method: 'GET',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
        })

        if (userDetails.ok) {
          const data = await userDetails.json()
          if (data.success && data.data && data.data.user) {
            const userInfo = data.data.user
            // Update local authentication state
            apiClient.setUser(userInfo)
            setIsAuthenticated(true)
            setCurrentUser(userInfo)

            // Set default tab based on user role
            setDefaultTabByRole(userInfo)

            // Check if user has 2FA enabled but no TOTP secret (needs setup)
            // Backend returns: two_fa (boolean), totp_secret (boolean indicating if secret exists)
            const has2FAEnabled = userInfo.two_fa || userInfo.two_fa_enabled
            const hasTOTPSecret = userInfo.totp_secret === true || userInfo.totp_secret === "true"

            if (has2FAEnabled && !hasTOTPSecret) {
              console.log('User needs 2FA setup:', { userInfo, has2FAEnabled, hasTOTPSecret })
              setShowTwoFASetup(true)
              // Don't load permissions yet - wait for 2FA setup completion
            } else {
              // Trigger permissions load for authenticated user who doesn't need 2FA setup
              setPermissionsRefreshTrigger(prev => prev + 1)
            }
          } else {
            // Server says not authenticated
            setIsAuthenticated(false)
            setCurrentUser(null)
            apiClient.logout()
          }
        } else {
          // Check if this is a 2FA setup required error
          try {
            const errorData = await userDetails.json()
            if (errorData.code === "2FA_SETUP_REQUIRED") {
              // User is authenticated but needs 2FA setup
              // Try to get user info from local storage as fallback
              const user = apiClient.getCurrentUser()
              if (user) {
                setIsAuthenticated(true)
                setCurrentUser(user)
                // Set default tab based on user role
                setDefaultTabByRole(user)
                setShowTwoFASetup(true)
              }
            } else {
              // Other error - not authenticated
              setIsAuthenticated(false)
              setCurrentUser(null)
              apiClient.logout()
            }
          } catch {
            // Server returned error - not authenticated
            setIsAuthenticated(false)
            setCurrentUser(null)
            apiClient.logout()
          }
        }
      } catch (error) {
        console.error('Failed to check authentication status:', error)
        // On error, fall back to local state
        const authenticated = apiClient.isAuthenticated()
        setIsAuthenticated(authenticated)
        if (authenticated) {
          const user = apiClient.getCurrentUser()
          setCurrentUser(user)
          // Set default tab based on user role
          setDefaultTabByRole(user)
        }
      } finally {
        setIsLoading(false)
      }

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

  // Main tabs state (to allow deep link to Admin sub-tabs)
  const [mainTab, setMainTab] = useState<'upload'|'manage'|'recycle'|'packages'|'admin'|'admin-users'>('upload')

  useEffect(() => {
    // Parse deep link query for selecting main tab
    if (typeof window !== 'undefined') {
      const params = new URLSearchParams(window.location.search)
      const view = params.get('view')
      if (view === 'admin') setMainTab('admin')
      if (view === 'users') setMainTab('admin-users')
    }
  }, [])

  // Function to set default tab based on user role
  const setDefaultTabByRole = (user: any) => {
    if (!user) return

    // Set default tab based on user role
    if (user.role === 'viewer') {
      setMainTab('manage') // Files tab for viewer
    } else if (user.role === 'administrator') {
      setMainTab('upload') // Upload tab for administrator
    } else {
      // Default fallback
      setMainTab('upload')
    }
  }

  const handleLogin = () => {
    setIsAuthenticated(true)
    const user = apiClient.getCurrentUser()
    setCurrentUser(user)

    // Set default tab based on user role
    setDefaultTabByRole(user)

    // Check if user needs 2FA setup
    if (user) {
      const has2FAEnabled = user.two_fa || user.two_fa_enabled
      const hasTOTPSecret = user.totp_secret === true || user.totp_secret === "true"

      if (has2FAEnabled && !hasTOTPSecret) {
        console.log('User needs 2FA setup after login:', { user, has2FAEnabled, hasTOTPSecret })
        setShowTwoFASetup(true)
        // Don't load permissions yet - wait for 2FA setup completion
      } else {
        // Trigger permissions reload after successful login for users who don't need 2FA setup
        setPermissionsRefreshTrigger(prev => prev + 1)
      }
    } else {
      // No user info, trigger permissions reload
      setPermissionsRefreshTrigger(prev => prev + 1)
    }

    if (user && (user as any).status && (user as any).status !== 'active') {
      setUserNotice('Your account is pending approval. Limited access until an admin activates your account.')
    } else {
      setUserNotice("")
    }
  }

  const handleTwoFASetupComplete = () => {
    // Refresh user info to get updated 2FA status
    const user = apiClient.getCurrentUser()
    setCurrentUser(user)

    // Set default tab based on user role after 2FA setup
    setDefaultTabByRole(user)

    // Now trigger permissions load since 2FA setup is complete
    setPermissionsRefreshTrigger(prev => prev + 1)
    // Exit 2FA setup screen to main workspace
    setShowTwoFASetup(false)
  }

  const handleLogout = async () => {
    try {
      await apiClient.logoutUser()
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      setIsAuthenticated(false)
      setCurrentUser(null)
      // Reset permissions on logout
      setPermissionsRefreshTrigger(0)
    }
  }

  const doChangePassword = async () => {
    setChangeErr("")
    if (!oldPwd || !newPwd || !confirmPwd) {
      setChangeErr("Please fill in all fields")
      return
    }
    if (newPwd.length < 8) {
      setChangeErr("New password must be at least 8 characters")
      return
    }
    if (newPwd !== confirmPwd) {
      setChangeErr("New passwords do not match")
      return
    }
    try {
      setIsChanging(true)
      // Use Authboss password change API
      const response = await fetch('/api/v1/web/auth/ab/password', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify({
          current_password: oldPwd,
          new_password: newPwd,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || errorData.message || 'Password change failed')
      }
      message.success("Password changed successfully")
      setShowChangePwd(false)
      setShowReLoginPrompt(true)
      setOldPwd("")
      setNewPwd("")
      setConfirmPwd("")
    } catch (err) {
      setChangeErr(err instanceof Error ? err.message : "Change password failed")
    } finally {
      setIsChanging(false)
    }
  }

  const handleUploadComplete = () => {
    // Trigger file list refresh
    setRefreshTrigger(prev => prev + 1)
  }


  const { permissions, loading: permissionsLoading } = usePermissions(permissionsRefreshTrigger)

  const baseTabs = 2 // manage + recycle
  const totalTabs = baseTabs +
    (permissions?.canUpload ? 1 : 0) +
    (permissions?.canAccessPackages ? 1 : 0) +
    (permissions?.canManageAPIKeys ? 1 : 0) +
    (permissions?.canManageUsers ? 1 : 0)
  const tabsColsClass = totalTabs === 6 ? 'grid-cols-6' :
                       totalTabs === 5 ? 'grid-cols-5' :
                       totalTabs === 4 ? 'grid-cols-4' :
                       totalTabs === 3 ? 'grid-cols-3' : 'grid-cols-2'

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

  // Show 2FA setup interface if user needs to complete 2FA setup
  if (isAuthenticated && showTwoFASetup) {
    return (
      <div className="min-h-screen bg-gray-50 flex flex-col">
        {/* Header */}
        <header className="bg-white border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center py-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-600 rounded-lg">
                  <SafetyOutlined className="text-white text-xl" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-gray-900">File Management System</h1>
                  <p className="text-sm text-gray-500">Secure File Upload and Management Platform</p>
                </div>
              </div>
              <Button onClick={handleLogout}>
                <LogoutOutlined className="mr-2" />
                Logout
              </Button>
            </div>
          </div>
        </header>

        {/* 2FA Setup Content */}
        <main className="flex-1 flex items-center justify-center p-4">
          <Card className="w-full max-w-2xl">
            <div className="p-6">
              <div className="text-center mb-6">
                <div className="mx-auto mb-4 p-3 bg-blue-100 rounded-full w-fit">
                  <SafetyOutlined className="text-blue-600 text-2xl" />
                </div>
                <Title level={2}>Security Setup Required</Title>
                <Text className="text-base mt-2 block">
                  Your account has two-factor authentication enabled for enhanced security.
                  Please complete the setup process to continue.
                </Text>
              </div>
              <div className="space-y-4">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="font-medium text-blue-800 mb-2">Why is this required?</h3>
                <p className="text-sm text-blue-700">
                  Two-factor authentication (2FA) provides an additional layer of security for your account.
                  This setup is required by your administrator and helps protect sensitive files and data.
                </p>
              </div>
              <div className="text-center">
                <p className="text-sm text-gray-600 mb-4">
                  Click the button below to open the 2FA setup wizard.
                </p>
              </div>
              </div>
            </div>
          </Card>
        </main>


        {/* 2FA Setup Dialog - Always open when in 2FA setup mode */}
        <TwoFASetupDialog
          open={true}
          onOpenChange={() => {}}
          onSetupComplete={handleTwoFASetupComplete}
          isRequired={true}
        />
      </div>
    )
  }

  // Show loading state when authenticated but permissions are still loading
  if (isAuthenticated && permissionsLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-500">Setting up your workspace...</p>
          <p className="text-xs text-gray-400 mt-2">Loading permissions and user interface</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
        <div className="w-full max-w-md space-y-6">
          {/* Server Status */}
          {serverStatus && (
            <Card className={serverStatus.online ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}>
              <div className="p-4">
                <div className="flex items-center gap-2">
                  {serverStatus.online ? (
                    <CheckCircleOutlined className="text-green-600" />
                  ) : (
                    <ExclamationCircleOutlined className="text-red-600" />
                  )}
                  <span className={`text-sm ${serverStatus.online ? "text-green-800" : "text-red-800"}`}>
                    {serverStatus.message}
                  </span>
                </div>
              </div>
            </Card>
          )}

          <LoginForm onLogin={handleLogin} />
        </div>
      </div>
    )
  }

    return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-blue-600 rounded-lg">
                <SafetyOutlined className="text-white text-xl" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">File Management System</h1>
                <p className="text-sm text-gray-500">Secure File Upload and Management Platform</p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {/* Server Status */}
              {serverStatus && (
                <div className="flex items-center gap-2 text-sm">
                  <DatabaseOutlined className="text-gray-400" />
                  <span className={serverStatus.online ? "text-green-600" : "text-red-600"}>
                    {serverStatus.online ? "Online" : "Offline"}
                  </span>
                </div>
              )}

              {/* User Menu */}
              {currentUser && (
                <div className="relative" ref={userMenuRef}>
                  <button
                    onClick={() => setShowUserMenu(v => !v)}
                    className="flex items-center gap-3 focus:outline-none"
                  >
                    <Avatar size="small" style={{ backgroundColor: '#1890ff' }}>
                      {currentUser.username.charAt(0).toUpperCase()}
                    </Avatar>
                    <div className="hidden sm:block">
                      <div className="text-sm font-medium text-gray-900">
                        {currentUser.username}
                      </div>
                    </div>
                  </button>

                  {showUserMenu && (
                    <div className="absolute right-0 mt-2 w-48 bg-white border border-gray-200 rounded-md shadow-lg z-50">
                      {permissions?.canManageAPIKeys && (
                        <>
                          {/* Admin quick links removed by request */}
                        </>
                      )}
                      <button
                        className="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 flex items-center gap-2"
                        onClick={() => { setShowUserMenu(false); setShowProfile(true) }}
                      >
                        <UserOutlined /> Profile
                      </button>
                      <button
                        className="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 flex items-center gap-2"
                        onClick={() => { setShowUserMenu(false); setShowAbout(true) }}
                      >
                        <SafetyOutlined /> About
                      </button>
                      <button
                        className="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 flex items-center gap-2"
                        onClick={() => { setShowUserMenu(false); setShowChangePwd(true) }}
                      >
                        <KeyOutlined /> Change Password
                      </button>
                      <div className="my-1 border-t border-gray-100" />
                      <button
                        className="w-full text-left px-3 py-2 text-sm hover:bg-gray-50 flex items-center gap-2"
                        onClick={() => { setShowUserMenu(false); handleLogout() }}
                      >
                        <LogoutOutlined /> Logout
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
          {userNotice && (
            <div className="mb-2 rounded-md bg-yellow-50 border border-yellow-200 text-yellow-800 px-3 py-2 text-sm">
              {userNotice}
            </div>
          )}
        </div>
      </header>

      {/* Main Content */}
            <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        <Tabs 
          activeKey={mainTab} 
          onChange={(key) => setMainTab(key as any)}
          items={[
            ...(permissions?.canUpload ? [{
              key: 'upload',
              label: (
                <Space>
                  <UploadOutlined />
                  Upload
                </Space>
              ),
              children: <FileUpload onUploadComplete={handleUploadComplete} />
            }] : []),
            ...(permissions?.canManageFiles ? [{
              key: 'manage',
              label: (
                <Space>
                  <FileOutlined />
                  Files
                </Space>
              ),
              children: <FileList refreshTrigger={refreshTrigger} />
            }] : []),
            ...(permissions?.canAccessRecycle ? [{
              key: 'recycle',
              label: (
                <Space>
                  <DeleteOutlined />
                  Recycle
                </Space>
              ),
              children: <RecycleBin />
            }] : []),
            ...(permissions?.canAccessPackages ? [{
              key: 'packages',
              label: (
                <Space>
                  <FileOutlined />
                  Packages
                </Space>
              ),
              children: <PackagesPanel />
            }] : []),
            ...(permissions?.canManageAPIKeys ? [{
              key: 'admin',
              label: (
                <Space>
                  <SafetyOutlined />
                  API Keys
                </Space>
              ),
              children: <APIKeyManagement />
            }] : []),
            ...(permissions?.canManageUsers ? [{
              key: 'admin-users',
              label: (
                <Space>
                  <UserOutlined />
                  Users
                </Space>
              ),
              children: <UserManagement />
            }] : [])
          ]}
        />
      </main>

      {/* 濡炪倓绲婚崜?- 闁搞儱鎼悾楣冨捶閵娿儳淇洪梺?*/}
      <footer className="bg-white border-t border-gray-200 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="text-center text-sm text-gray-500">
            <p>File Manager. Secure File Management System</p>
            <p className="mt-2">Supports versioned management of configuration files, certificates and documents</p>
          </div>
        </div>
      </footer>


      {/* Change Password Modal */}
      <Modal
        title="Change Password"
        open={showChangePwd}
        onCancel={() => setShowChangePwd(false)}
        footer={[
          <Button key="cancel" onClick={() => setShowChangePwd(false)} disabled={isChanging}>
            Cancel
          </Button>,
          <Button key="submit" type="primary" onClick={doChangePassword} loading={isChanging}>
            Update Password
          </Button>
        ]}
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Current Password</label>
            <Input.Password 
              value={oldPwd} 
              onChange={(e) => setOldPwd(e.target.value)} 
              placeholder="Enter current password" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">New Password</label>
            <Input.Password 
              value={newPwd} 
              onChange={(e) => setNewPwd(e.target.value)} 
              placeholder="At least 8 characters" 
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Confirm New Password</label>
            <Input.Password 
              value={confirmPwd} 
              onChange={(e) => setConfirmPwd(e.target.value)} 
              placeholder="Re-enter new password" 
            />
          </div>
          {changeErr && (
            <div className="text-sm text-red-600 bg-red-50 border border-red-200 rounded p-3">
              {changeErr}
            </div>
          )}
        </div>
      </Modal>

      {/* Profile Modal */}
      <Modal
        title="Profile"
        open={showProfile}
        onCancel={() => setShowProfile(false)}
        footer={[
          <Button key="close" onClick={() => setShowProfile(false)}>
            Close
          </Button>
        ]}
      >
        <div className="flex items-center gap-4">
          <Avatar size="large" style={{ backgroundColor: '#1890ff' }}>
            {currentUser?.username?.charAt(0)?.toUpperCase()}
          </Avatar>
          <div className="space-y-1 text-sm">
            <div><span className="text-gray-500">Username:</span> <span className="font-medium">{currentUser?.username}</span></div>
            <div><span className="text-gray-500">Role:</span> <span className="font-medium">{currentUser?.role || 'viewer'}</span></div>
          </div>
        </div>
      </Modal>

      {/* About Modal */}
      <Modal
        title="About"
        open={showAbout}
        onCancel={() => setShowAbout(false)}
        footer={[
          <Button key="close" onClick={() => setShowAbout(false)}>
            Close
          </Button>
        ]}
      >
        <div className="space-y-2 text-sm text-gray-700">
          <Text>Secure File Management System</Text>
          <div>Version: {apiInfo?.version || 'N/A'}</div>
        </div>
      </Modal>

      {/* Re-login Prompt Modal */}
      <Modal
        title="Re-login Recommended"
        open={showReLoginPrompt}
        onCancel={() => setShowReLoginPrompt(false)}
        footer={[
          <Button key="later" onClick={() => setShowReLoginPrompt(false)}>
            Later
          </Button>,
          <Button key="relogin" type="primary" onClick={handleLogout}>
            Re-login now
          </Button>
        ]}
      >
        <Text>
          Your password has been updated. For security, please log in again.
        </Text>
      </Modal>

      {/* 2FA Setup Dialog */}
      <TwoFASetupDialog
        open={showTwoFASetup}
        onOpenChange={setShowTwoFASetup}
        onSetupComplete={handleTwoFASetupComplete}
      />
    </div>
  )
}

