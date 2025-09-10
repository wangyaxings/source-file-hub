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
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expiresIn: number
  user: {
    username: string
    role?: string
  }
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

      if (!data.success) {
        throw new Error(data.error || data.message || 'Request failed')
      }

      return data
    } catch (error) {
      console.error(`Request failed for ${url}:`, error)

      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new Error('Network connection failed, please check server status')
      }

      throw error
    }
  }

  setToken(token: string) {
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
    return !!this.token
  }

  // 认证相关
  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data)
    })

    if (response.success && response.data) {
      this.setToken(response.data.token)
      this.setUser({
        username: response.data.user.username,
        role: response.data.user.role,
      })
      return response.data
    }

    throw new Error(response.error || 'Login failed')
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
      await this.request('/auth/logout', { method: 'POST' })
    } finally {
      this.logout()
    }
  }

  async getDefaultUsers(): Promise<any[]> {
    const response = await this.request<any[]>('/auth/users')
    return response.data || []
  }

  // 文件相关
  async uploadFile(file: File, fileType: string, description: string): Promise<FileInfo> {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('fileType', fileType)
    formData.append('description', description)

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
