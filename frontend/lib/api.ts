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
}

export interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

class ApiClient {
  private baseUrl = '/api/v1/web'
  private token: string | null = null
  private currentUser: UserInfo | null = null

  constructor() {
    // Check if we're running in the browser (client-side)
    this.token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
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

    // 添加认证header
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const config: RequestInit = {
      ...options,
      headers
    }

    try {
      console.log(`Making request to: ${url}`)
      const response = await fetch(url, config)

      // 检查响应状态
      if (!response.ok) {
        if (response.status === 401) {
          this.logout()
          throw new Error('Authentication expired, please log in again')
        }

        // 尝试解析错误响应
        try {
          const errorData = await response.json()
          throw new Error(errorData.error || errorData.message || `HTTP ${response.status}: ${response.statusText}`)
        } catch (parseError) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`)
        }
      }

      const data = await response.json()

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

  setToken(token: string) {
    // Deprecated: switching to cookie-based session via Authboss
    this.token = token
    if (typeof window !== 'undefined') {
      localStorage.setItem('token', token)
    }
  }

  setUser(user: UserInfo) {
    this.currentUser = user
    if (typeof window !== 'undefined') {
      localStorage.setItem('currentUser', JSON.stringify(user))
    }
  }

  getCurrentUser(): UserInfo | null {
    return this.currentUser
  }

  logout() {
    this.token = null
    this.currentUser = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('token')
      localStorage.removeItem('currentUser')
    }
  }

  isAuthenticated(): boolean {
    // Cookie-session based; consider currentUser as the source of truth
    return !!this.currentUser
  }

  // 认证相关
  async login(data: LoginRequest): Promise<LoginResponse> {
    // Use manual fetch to handle Authboss JSON redirect under /auth/ab/*
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    }
    if (this.token) headers.Authorization = `Bearer ${this.token}`

    const res = await fetch(`${this.baseUrl}/auth/ab/login`, {
      method: 'POST',
      headers,
      body: JSON.stringify(data),
      credentials: 'same-origin',
    })

    if (res.status >= 300 && res.status < 400) {
      // Authboss JSON redirect payload
      const redir = await res.json().catch(() => ({} as any))
      const loc: string | undefined = (redir as any)?.location
      if (loc) {
        // Follow redirect by calling target endpoint
        let followEp = loc
        if (followEp.startsWith(this.baseUrl)) followEp = followEp.substring(this.baseUrl.length)
        else if (followEp.startsWith('/api/v1/web')) followEp = followEp.substring('/api/v1/web'.length)
        await this.request(followEp, { method: 'GET' })
      } else {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`)
      }
    } else if (!res.ok) {
      // Try to surface JSON error
      try {
        const j = await res.json()
        throw new Error(j.error || j.message || `HTTP ${res.status}: ${res.statusText}`)
      } catch {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`)
      }
    }

    // After Authboss login, session cookie is set; load current user
    const me = await this.request<{ user: { username: string; role?: string } }>(`/auth/me`)
    if (me.success && me.data && (me.data as any).user) {
      const u = (me.data as any).user
      this.setUser({ username: u.username, role: u.role })
      return { status: 'success' }
    }

    throw new Error('Login failed')
  }

  async changePassword(oldPassword: string, newPassword: string): Promise<void> {
    const resp = await this.request(`/auth/change-password`, {
      method: 'POST',
      body: JSON.stringify({ old_password: oldPassword, new_password: newPassword })
    })
    if (!resp.success) throw new Error(resp.error || 'Failed to change password')
  }

  async logoutUser(): Promise<void> {
    try {
      // Authboss logout under /auth/ab/logout
      await fetch(`${this.baseUrl}/auth/ab/logout`, { method: 'POST', headers: { 'Accept': 'application/json' } })
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

    const headers: Record<string, string> = {}
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseUrl}/upload`, {
      method: 'POST',
      headers,
      body: formData
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
    const headers: Record<string, string> = {}
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(url, { headers })

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
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseUrl}/files/${fileId}/delete`, {
      method: 'DELETE',
      headers
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
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseUrl}/files/${fileId}/restore`, {
      method: 'POST',
      headers
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
    const headers: Record<string, string> = {}
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseUrl}/recycle-bin`, {
      method: 'GET',
      headers
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
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(`${this.baseUrl}/recycle-bin/clear`, {
      method: 'DELETE',
      headers
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
  async adminListUsers(): Promise<any[]> {
    const resp = await this.request<{ users: any[] }>(`/admin/users`)
    return (resp.data as any)?.users || []
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

  async adminResetPassword(userId: string): Promise<{ username: string; temporary_password: string }> {
    const resp = await this.request<{ username: string; temporary_password: string }>(`/admin/users/${encodeURIComponent(userId)}/reset-password`, { method: 'POST' })
    if (!resp.success) throw new Error(resp.error || 'Reset password failed')
    return (resp.data || {}) as any
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
    const headers: Record<string, string> = {}
    if (this.token) headers.Authorization = `Bearer ${this.token}`
    const formData = new FormData()
    formData.append('file', file)
    const response = await fetch(`${this.baseUrl}/packages/upload/assets-zip`, { method: 'POST', headers, body: formData })
    if (!response.ok) throw new Error(`Upload failed: ${response.statusText}`)
    const result = await response.json()
    if (!result.success) throw new Error(result.error || 'Upload failed')
    return result.data
  }

  async uploadOthersZip(file: File): Promise<any> {
    const headers: Record<string, string> = {}
    if (this.token) headers.Authorization = `Bearer ${this.token}`
    const formData = new FormData()
    formData.append('file', file)
    const response = await fetch(`${this.baseUrl}/packages/upload/others-zip`, { method: 'POST', headers, body: formData })
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
    const headers: Record<string, string> = {}
    if (this.token) headers.Authorization = `Bearer ${this.token}`
    const response = await fetch(url, { headers })
    if (!response.ok) throw new Error(`Failed to get manifest: ${response.statusText}`)
    return await response.json()
  }

  async updateVersionTagsWeb(type: 'roadmap'|'recommendation', versionId: string, tags: string[]): Promise<void> {
    await this.request(`/versions/${type}/${encodeURIComponent(versionId)}/tags`, {
      method: 'PATCH',
      body: JSON.stringify({ tags })
    })
  }

  // 健康检查 - 使用正确的端点
  async healthCheck(): Promise<any> {
    try {
      // 使用后端的健康检查端点
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
}

export const apiClient = new ApiClient()
