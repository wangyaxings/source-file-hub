export interface FileInfo {
  id: string
  fileName: string
  originalName: string
  fileType: string
  size: number
  description: string
  uploadTime: string
  version: number
  isLatest: boolean
  uploader: string
  path: string
  versionId?: string
}

export interface LoginRequest {
  username: string
  password: string
  otp?: string
}

export interface LoginResponse {
  status?: string
  location?: string
}

export interface UserInfo {
  username: string
  role?: string
  status?: string
  permissions?: string[]
  quota_daily?: number
  quota_monthly?: number
  two_fa?: boolean
  two_fa_enabled?: boolean
  totp_secret?: boolean | string
}



export interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
  code?: string
  details?: any
}

class ApiClient {
  private baseUrl = '/api/v1/web'
  private currentUser: UserInfo | null = null

  constructor() {
    // The user is initialized as null. The actual user state will be determined
    // by the /auth/me endpoint when the application loads.
    this.currentUser = null
  }

  public async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseUrl}${endpoint}`

    // 确保headers存在
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...((options.headers as Record<string, string>) || {})
    }

    // Note: No longer using Authorization header - authboss handles authentication via session cookies

    const config: RequestInit = {
      ...options,
      headers,
      // Important: Include credentials for session cookie authentication
      credentials: 'include',
    }

    try {
      console.log(`Making request to: ${url}`)
      console.log(`Request config:`, config)
      const response = await fetch(url, config)

      // 妫€鏌ュ搷搴旂姸鎬?
      if (!response.ok) {
        if (response.status === 401) {
          const wasAuthenticated = this.isAuthenticated()
          // Only force logout + show "expired" if we previously had a session
          if (wasAuthenticated) {
            console.log('401 Unauthorized - logging out user')
            this.logout()
            throw new Error('Authentication expired, please log in again')
          }
          // If not authenticated yet (e.g., checking /auth/me prior to login),
          // surface a neutral error without implying session expiry.
          throw new Error('Unauthorized')
        }

        let errorData: any = null
        try { errorData = await response.json() } catch {}
        const err: any = new Error(errorData?.error || errorData?.message || `HTTP ${response.status}: ${response.statusText}`)
        err.code = errorData?.code
        err.details = errorData?.details
        err.request_id = response.headers.get('X-Request-ID') || errorData?.details?.request_id
        err.status = response.status
        throw err
      }

      // Check if response has content before trying to parse JSON
      const contentType = response.headers.get('content-type')
      let data: any = null

      if (contentType && contentType.includes('application/json')) {
        try {
          data = await response.json()
        } catch (parseError) {
          // If JSON parsing fails, check if response is empty
          const text = await response.text()
          if (text.trim() === '') {
            // Empty response - treat as success for some endpoints
            return { success: true, data: undefined } as any
          }
          throw new Error(`Invalid JSON response: ${parseError}`)
        }
      } else {
        // Non-JSON response - read as text
        const text = await response.text()
        if (text.trim() === '') {
          return { success: true, data: undefined } as any
        }
        throw new Error(`Expected JSON response but got: ${contentType}`)
      }

      if (typeof (data?.success) === 'boolean') {
        if (!data.success) {
          throw new Error(data.error || data.message || 'Request failed')
        }
        return data
      }

      // Fallback for Authboss JSON responses that use { status: "success" }
      if ((data as any)?.status === 'success') {
        return { success: true, data } as any
      }

      throw new Error((data as any)?.error || (data as any)?.message || 'Request failed')
    } catch (error) {
      console.error(`Request failed for ${url}:`, error)
      console.error('Error type:', typeof error)

      // Type-safe error handling
      if (error instanceof Error) {
        console.error('Error message:', error.message)
        console.error('Error stack:', error.stack)

        if (error instanceof TypeError && error.message.includes('fetch')) {
          throw new Error('Network connection failed, please check server status')
        }
      } else {
        console.error('Unknown error type:', error)
      }

      throw error
    }
  }

  // Authentication handled via Authboss session cookies

  setUser(user: UserInfo) {
    this.currentUser = user
    // No longer storing user info in localStorage
  }

  getCurrentUser(): UserInfo | null {
    return this.currentUser
  }

  isAuthenticated(): boolean {
    return this.currentUser !== null
  }

  logout() {
    // Clear local user state - session cookie will be cleared by authboss
    this.currentUser = null
    // No longer removing user info from localStorage
  }

  // 统一使用Authboss登录
  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await fetch(`${this.baseUrl}/auth/ab/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(data),
      credentials: 'include',
    })

    // Handle Authboss redirect response (status 307)
    if (response.status === 307) {
      const result = await response.json()

      // Detect 2FA verification requirement via redirect location
      if (typeof result.location === 'string' && result.location.includes('/2fa/totp/validate')) {
        throw new Error('2FA_VERIFICATION_REQUIRED: Please enter your 2FA verification code')
      }

      // Authboss成功响应处理（非2FA验证流程）
      if (result.status === 'success') {
        // 获取用户信息
        const meResponse = await this.request<{ user: UserInfo }>('/auth/me')
        if (meResponse.success && meResponse.data) {
          this.setUser((meResponse.data as any).user)
        }
        return { status: 'success', location: result.location }
      }
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      const errorMessage = errorData.error || errorData.message || 'Login failed'

      // 处理2FA相关错误
      if (errorMessage.includes('2FA_SETUP_REQUIRED')) {
        throw new Error(`2FA_SETUP_REQUIRED: ${errorMessage}`)
      } else if (errorMessage.includes('2FA_VERIFICATION_REQUIRED')) {
        throw new Error(`2FA_VERIFICATION_REQUIRED: ${errorMessage}`)
      } else if (errorMessage.includes('otp') || errorMessage.includes('2fa')) {
        throw new Error(`2FA_REQUIRED: ${errorMessage}`)
      }

      throw new Error(errorMessage)
    }

    const result = await response.json()

    // Authboss成功响应处理
    if (result.status === 'success') {
      // 获取用户信息
      const meResponse = await this.request<{ user: UserInfo }>('/auth/me')
      if (meResponse.success && meResponse.data) {
        this.setUser((meResponse.data as any).user)
      }
      return { status: 'success', location: result.location }
    }

    throw new Error('Login failed')
  }

  // Verify TOTP (2FA) after login redirect to validate
  async verifyTOTP(code: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/auth/ab/2fa/totp/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({ code }),
      credentials: 'include',
    })

    let data: any = null
    try { data = await response.json() } catch {}

    if (!response.ok || !data || data.success === false) {
      const errCode = data?.code
      const errMsg = data?.error || `HTTP ${response.status}: ${response.statusText}`
      // Throw structured error so UI can handle cooldown/lockout
      throw { code: errCode, message: errMsg, retry_after: data?.retry_after }
    }

    // On success, refresh current user
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) this.setUser((me.data as any).user)
  }

  // Note: changePassword method removed - password changes are now handled by authboss
  // Use authboss password change endpoints instead

  async logoutUser(): Promise<void> {
    try {
      // Authboss logout under /auth/ab/logout
      await fetch(`${this.baseUrl}/auth/ab/logout`, {
        method: 'POST',
        headers: { 'Accept': 'application/json' },
        credentials: 'include' // Important: Include credentials for session cookies
      })
    } finally {
      this.logout()
    }
  }

  async getDefaultUsers(): Promise<any[]> {
    const response = await this.request<any[]>('/auth/users')
    return response.data || []
  }

  // 文件相关
  async uploadFile(file: File, fileType: string, description: string, versionTags?: string): Promise<FileInfo> {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('fileType', fileType)
    formData.append('description', description)
    if (versionTags) formData.append('versionTags', versionTags)

    const response = await fetch(`${this.baseUrl}/upload`, {
      method: 'POST',
      body: formData,
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please log in again')
      }
      let errorData: any = null
      try { errorData = await response.json() } catch {}
      const err: any = new Error(errorData?.error || errorData?.message || `Upload failed: ${response.statusText}`)
      err.code = errorData?.code
      err.details = errorData?.details
      err.request_id = response.headers.get('X-Request-ID') || errorData?.details?.request_id
      err.status = response.status
      throw err
    }

    const result = await response.json()
    if (!result.success) {
      const err: any = new Error(result.error || 'Upload failed')
      err.code = result.code
      err.details = result.details
      throw err
    }

    return result.data
  }

  async getFilesPaginated(params: { type?: string; page?: number; limit?: number } = {}): Promise<{ files: FileInfo[]; count: number; page: number; limit: number }> {
    const qs = new URLSearchParams()
    if (params.type) qs.set('type', params.type)
    if (params.page && params.page > 0) qs.set('page', String(params.page))
    if (params.limit && params.limit > 0) qs.set('limit', String(params.limit))
    const query = qs.toString()
    const response = await this.request<{ files: FileInfo[]; count: number; page: number; limit: number }>(`/files/list${query ? `?${query}` : ''}`)
    const data: any = response.data || {}
    return {
      files: data.files || [],
      count: data.count || 0,
      page: data.page || params.page || 1,
      limit: data.limit || params.limit || 50,
    }
  }

  async getFiles(type?: string): Promise<FileInfo[]> {
    const res = await this.getFilesPaginated({ type })
    return res.files
  }

  async getFileVersions(type: string, filename: string): Promise<FileInfo[]> {
    const response = await this.request<{ versions: FileInfo[]; count: number }>(`/files/versions/${type}/${filename}`)
    return response.data?.versions || []
  }

  async downloadFile(path: string): Promise<void> {
    // Remove downloads/ prefix if present since the API expects the path relative to downloads
    const cleanPath = path.startsWith('downloads/') ? path.substring('downloads/'.length) : path
    const url = `${this.baseUrl}/files/${cleanPath}`

    const response = await fetch(url, {
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      throw new Error(`Download failed: ${response.statusText}`)
    }

    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = path.split('/').pop() || 'download'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(downloadUrl)
  }

  // Generic binary download helper (uses session cookies)
  async downloadBinary(endpoint: string, filename: string, options: RequestInit = {}): Promise<void> {
    const url = `${this.baseUrl}${endpoint}`
    const response = await fetch(url, {
      ...options,
      credentials: 'include'
    })
    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      const errorText = response.statusText || `HTTP ${response.status}`
      throw new Error(`Download failed: ${errorText}`)
    }
    const blob = await response.blob()
    const downloadUrl = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = downloadUrl
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(downloadUrl)
  }

  async deleteFile(fileId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/files/${fileId}/delete`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `Delete failed: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || 'Delete failed')
    }
  }

  async restoreFile(fileId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/files/${fileId}/restore`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `Restore failed: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || 'Restore failed')
    }
  }

  async getRecycleBin(): Promise<any[]> {
    const response = await fetch(`${this.baseUrl}/recycle-bin`, {
      method: 'GET',
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      throw new Error(`Failed to get recycle bin: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || 'Failed to get recycle bin')
    }

    return result.data.items || []
  }

  async clearRecycleBin(): Promise<void> {
    const response = await fetch(`${this.baseUrl}/recycle-bin/clear`, {
      method: 'DELETE',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include' // Important: Include credentials for session cookies
    })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('Login expired, please login again')
      }
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `Clear recycle bin failed: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || 'Clear recycle bin failed')
    }
  }

  // Admin: Users management (web namespace)
  async adminListUsers(params: { q?: string; status?: string; page?: number; limit?: number } = {}): Promise<{ users: any[]; count: number; total?: number; page?: number; limit?: number }> {
    const qs = new URLSearchParams()
    if (params.q) qs.set('q', params.q)
    if (params.status) qs.set('status', params.status)
    if (params.page) qs.set('page', String(params.page))
    if (params.limit) qs.set('limit', String(params.limit))
    const resp = await this.request<{ users: any[]; count: number; total?: number; page?: number; limit?: number }>(`/admin/users${qs.toString() ? `?${qs.toString()}` : ''}`)
    return (resp.data as any) || { users: [], count: 0 }
  }

  async adminCreateUser(payload: { username: string; email?: string; role?: string; must_reset?: boolean }): Promise<any> {
    const resp = await this.request(`/admin/users`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    if (!resp.success) throw new Error(resp.error || 'Create user failed')
    return resp.data
  }

  async adminApproveUser(userId: string): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}/approve`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Approve failed')
  }

  async adminSuspendUser(userId: string): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}/suspend`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Suspend failed')
  }

  async adminDisable2FA(userId: string): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}/2fa/disable`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Disable 2FA failed')
  }

  async adminEnable2FA(userId: string): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}/2fa/enable`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Enable 2FA failed')
  }

  async adminResetPassword(userId: string): Promise<{ username: string; temporary_password: string }> {
    const resp = await this.request<{ username: string; temporary_password: string }>(`/admin/users/${encodeURIComponent(userId)}/reset-password`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Reset password failed')
    return (resp.data || {}) as any
  }

  async adminSetUserRole(userId: string, payload: { role: string; permissions?: string[]; quota_daily?: number; quota_monthly?: number; status?: string }): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}/role`, { method: 'PUT', body: JSON.stringify(payload) })
    if (!resp.success) throw new Error(resp.error || 'Set role failed')
  }

  async adminGetUser(userId: string): Promise<any> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}`)
    if (!resp.success) throw new Error(resp.error || 'Get user failed')
    return resp.data
  }

  async adminUpdateUser(userId: string, payload: Partial<{ role: string; twofa_enabled: boolean; reset_2fa: boolean }>): Promise<void> {
    const resp = await this.request(`/admin/users/${encodeURIComponent(userId)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    })
    if (!resp.success) throw new Error(resp.error || 'Update user failed')
  }

  async getApiInfo(): Promise<any> {
    const resp = await this.request<any>(``)
    return resp.data
  }

  // Packages API (web wrappers)
  async uploadAssetsZip(file: File, tenantId: string): Promise<any> {
    if (!tenantId || tenantId.trim() === '') throw new Error('Tenant ID is required')
    const formData = new FormData()
    formData.append('file', file)
    formData.append('tenant_id', tenantId)
    const response = await fetch(`${this.baseUrl}/packages/upload/assets-zip`, {
      method: 'POST',
      body: formData,
      credentials: 'include' // Important: Include credentials for session cookies
    })
    if (!response.ok) throw new Error(`Upload failed: ${response.statusText}`)
    const result = await response.json()
    if (!result.success) throw new Error(result.error || 'Upload failed')
    return result.data
  }

  async uploadOthersZip(file: File, tenantId: string): Promise<any> {
    if (!tenantId || tenantId.trim() === '') throw new Error('Tenant ID is required')
    const formData = new FormData()
    formData.append('file', file)
    formData.append('tenant_id', tenantId)
    const response = await fetch(`${this.baseUrl}/packages/upload/others-zip`, {
      method: 'POST',
      body: formData,
      credentials: 'include' // Important: Include credentials for session cookies
    })
    if (!response.ok) throw new Error(`Upload failed: ${response.statusText}`)
    const result = await response.json()
    if (!result.success) throw new Error(result.error || 'Upload failed')
    return result.data
  }

  async listPackages(params: { tenant?: string; type?: string; q?: string; page?: number; limit?: number } = {}): Promise<{ items: any[]; count: number; page: number; limit: number }> {
    const qs = new URLSearchParams()
    if (params.tenant) qs.set('tenant', params.tenant)
    if (params.type) qs.set('type', params.type)
    if (params.q) qs.set('q', params.q)
    if (params.page) qs.set('page', String(params.page))
    if (params.limit) qs.set('limit', String(params.limit))
    const response = await this.request<{ items: any[]; count: number; page: number; limit: number }>(`/packages?${qs.toString()}`)
    return response.data as any
  }

  async updatePackageRemark(id: string, remark: string): Promise<void> {
    await this.request(`/packages/${id}/remark`, { method: 'PATCH', body: JSON.stringify({ remark }) })
  }

  // Web versioning (roadmap/recommendation) no channels
  async getVersionsListWeb(type: 'roadmap'|'recommendation'): Promise<{ versions: { version_id: string; tags?: string[]; status?: string; date?: string }[] }> {
    const resp = await this.request(`/versions/${type}/versions.json`)
    return (resp.data || { versions: [] }) as any
  }

  async getVersionManifestWeb(type: 'roadmap'|'recommendation', versionId: string): Promise<any> {
    const url = `${this.baseUrl}/versions/${type}/${encodeURIComponent(versionId)}/manifest`
    const response = await fetch(url, {
      credentials: 'include' // Important: Include credentials for session cookies
    })
    if (!response.ok) throw new Error(`Failed to get manifest: ${response.statusText}`)
    return await response.json()
  }

  async updateVersionTagsWeb(type: 'roadmap'|'recommendation', versionId: string, tags: string[]): Promise<void> {
    await this.request(`/versions/${type}/${encodeURIComponent(versionId)}/tags`, {
      method: 'PATCH',
      body: JSON.stringify({ tags })
    })
  }

  // 鍋ュ悍妫€鏌?- 浣跨敤姝ｇ‘鐨勭鐐?
  async healthCheck(): Promise<any> {
    try {
      // 浣跨敤鍚庣鐨勫仴搴锋鏌ョ鐐?
      const response = await fetch('/api/v1/health')

      if (!response.ok) {
        throw new Error(`Health check failed: ${response.status}`)
      }

      return await response.json()
    } catch (error) {
      console.error('Health check failed:', error)
      throw new Error('Server connection failed')
    }
  }

  // 2FA TOTP API（统一命名：setup / confirm / remove）
  async setupTOTP(): Promise<{ secret: string; otpauth_url: string }> {
    // Attempt JSON setup first (backend shim returns secret immediately)
    const setupResp = await this.request<any>('/auth/ab/2fa/totp/setup', { method: 'POST' })
    let body: any = (setupResp as any)?.data ?? setupResp
    let payload: any = (body as any)?.data ?? body
    let secret: string = (payload?.totp_secret ?? payload?.secret ?? '').toString()

    // If setup didn't include the secret (e.g., 307 flow), fetch from confirm
    if (!secret) {
      const confirm = await this.request<any>('/auth/ab/2fa/totp/confirm', { method: 'GET' })
      body = (confirm as any)?.data ?? confirm
      payload = (body as any)?.data ?? body
      secret = (payload?.totp_secret ?? payload?.secret ?? '').toString()
    }

    if (!secret) {
      throw new Error('TOTP secret not provided by server after setup')
    }

    const issuer = 'Secure File Hub'
    const label = this.currentUser?.username || 'user'
    const otpauth_url = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?issuer=${encodeURIComponent(issuer)}&secret=${encodeURIComponent(secret)}`

    return { secret, otpauth_url }
  }

  async confirmTOTP(code: string): Promise<void> {
    await this.request('/auth/ab/2fa/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({ code })
    })

    // Mark this session as 2FA-verified by validating once
    try {
      await this.verifyTOTP(code)
    } catch {
      // Ignore if validation step fails here; user can still navigate and verify when prompted
    }

    // Refresh current user after enabling 2FA
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) this.setUser((me.data as any).user)
  }

  async removeTOTP(): Promise<void> {
    await this.request('/auth/ab/2fa/totp/remove', { method: 'POST' })

    // Refresh current user after disabling 2FA
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) this.setUser((me.data as any).user)
  }

}

export const apiClient = new ApiClient()
