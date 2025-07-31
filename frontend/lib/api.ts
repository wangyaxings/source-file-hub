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
  tenantID: string
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  expiresIn: number
  user: {
    tenantID: string
    username: string
  }
}

export interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

class ApiClient {
  private baseUrl = '/api'
  private token: string | null = null

  constructor() {
    // Check if we're running in the browser (client-side)
    this.token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseUrl}${endpoint}`

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...options.headers as Record<string, string>
    }

    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers
      })

      if (!response.ok) {
        if (response.status === 401) {
          this.logout()
          throw new Error('登录已过期，请重新登录')
        }
        throw new Error(`HTTP ${response.status}: ${response.statusText}`)
      }

      return await response.json()
    } catch (error) {
      console.error('API request failed:', error)
      throw error
    }
  }

  setToken(token: string) {
    this.token = token
    if (typeof window !== 'undefined') {
      localStorage.setItem('token', token)
    }
  }

  logout() {
    this.token = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('token')
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
      return response.data
    }

    throw new Error(response.error || '登录失败')
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
        throw new Error('登录已过期，请重新登录')
      }
      const errorData = await response.json().catch(() => ({ error: response.statusText }))
      throw new Error(errorData.error || `上传失败: ${response.statusText}`)
    }

    const result = await response.json()
    if (!result.success) {
      throw new Error(result.error || '上传失败')
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
    const url = `${this.baseUrl}/files/${path}`
    const headers: Record<string, string> = {}
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`
    }

    const response = await fetch(url, { headers })

    if (!response.ok) {
      if (response.status === 401) {
        this.logout()
        throw new Error('登录已过期，请重新登录')
      }
      throw new Error(`下载失败: ${response.statusText}`)
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

  // 健康检查
  async healthCheck(): Promise<any> {
    const response = await this.request('/health')
    return response.data
  }
}

export const apiClient = new ApiClient()