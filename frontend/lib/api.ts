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
}

class ApiClient {
  private baseUrl = '/api/v1/web'
  private currentUser: UserInfo | null = null

  constructor() {
    // Check if we're running in the browser (client-side)
    // Note: No longer using localStorage for token - authboss handles session via cookies
    this.currentUser = typeof window !== 'undefined'
      ? JSON.parse(localStorage.getItem('currentUser') || 'null')
      : null
  }

  private async request<T>(
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

        try {
          const errorData = await response.json()
          throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`)
        } catch (parseError) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }
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

      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network connection failed, please check server status')
      }

      throw error
    }
  }

  // Note: setToken method removed - authboss handles authentication via session cookies

  setUser(user: UserInfo) {
    this.currentUser = user
    if (typeof window !== 'undefined') {
      localStorage.setItem('currentUser', JSON.stringify(user))
    }
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
    if (typeof window !== 'undefined') {
      localStorage.removeItem('currentUser')
      // Note: No longer managing token in localStorage
    }
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

      // Authboss成功响应处理
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
      if (errorMessage.includes('otp') || errorMessage.includes('2fa')) {
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
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `Upload failed: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || 'Upload failed')
    }

    return result.data
  }

  async getFiles(type?: string): Promise<FileInfo[]> {
    const query = type ? `?type=${type}` : ''
    const response = await this.request<{ files: FileInfo[]; count: number }>(`/files/list${query}`)
    return response.data?.files || []
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
  async uploadAssetsZip(file: File): Promise<any> {
    const formData = new FormData()
    formData.append('file', file)
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

  async uploadOthersZip(file: File): Promise<any> {
    const formData = new FormData()
    formData.append('file', file)
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

  // 使用Authboss TOTP API
  async startTOTP(): Promise<{ secret: string; otpauth_url: string }> {
    const resp = await this.request('/auth/ab/2fa/totp/setup', { method: 'POST' })
    if (!resp.data) {
      throw new Error('Failed to get TOTP setup data from server')
    }
    return resp.data as any
  }

  async enableTOTP(code: string): Promise<void> {
    await this.request('/auth/ab/2fa/totp/confirm', {
      method: 'POST',
      body: JSON.stringify({ code })
    })

    // 重新获取用户信息以更新2FA状态
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) {
      this.setUser((me.data as any).user)
    }
  }

  async disableTOTP(): Promise<void> {
    await this.request('/auth/ab/2fa/totp/remove', { method: 'POST' })

    // 重新获取用户信息以更新2FA状态
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) {
      this.setUser((me.data as any).user)
    }
  }
}

export const apiClient = new ApiClient()

