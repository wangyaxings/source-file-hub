import React, { useState, useEffect } from 'react'

// 权限管理工具类
export interface Permission {
  resource: string
  action: string
}

export interface UserPermissions {
  canUpload: boolean
  canManageFiles: boolean
  canAccessRecycle: boolean
  canAccessPackages: boolean
  canManageAPIKeys: boolean
  canManageUsers: boolean
  canViewAnalytics: boolean
}

// 权限检查函数
export async function checkPermission(resource: string, action: string): Promise<boolean> {
  try {
    const response = await fetch('/api/v1/web/auth/check-permission', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ resource, action })
    })
    
    if (!response.ok) {
      return false
    }
    
    const data = await response.json()
    return data.success && data.allowed === true
  } catch (error) {
    console.error('Permission check failed:', error)
    return false
  }
}

// 批量权限检查
export async function checkMultiplePermissions(permissions: Permission[]): Promise<Record<string, boolean>> {
  try {
    const response = await fetch('/api/v1/web/auth/check-permissions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({ permissions })
    })
    
    if (!response.ok) {
      return {}
    }
    
    const data = await response.json()
    return data.success ? data.results : {}
  } catch (error) {
    console.error('Multiple permission check failed:', error)
    return {}
  }
}

// 获取用户所有权限
export async function getUserPermissions(): Promise<UserPermissions> {
  const permissions: Permission[] = [
    { resource: '/api/v1/web/upload', action: 'POST' },
    { resource: '/api/v1/web/files/list', action: 'GET' },
    { resource: '/api/v1/web/recycle-bin', action: 'GET' },
    { resource: '/api/v1/web/packages', action: 'GET' },
    { resource: '/api/v1/web/admin/api-keys', action: 'GET' },
    { resource: '/api/v1/web/admin/users', action: 'GET' },
    { resource: '/api/v1/web/admin/analytics', action: 'GET' }
  ]

  const results = await checkMultiplePermissions(permissions)
  
  return {
    canUpload: results['/api/v1/web/upload:POST'] || false,
    canManageFiles: results['/api/v1/web/files/list:GET'] || false,
    canAccessRecycle: results['/api/v1/web/recycle-bin:GET'] || false,
    canAccessPackages: results['/api/v1/web/packages:GET'] || false,
    canManageAPIKeys: results['/api/v1/web/admin/api-keys:GET'] || false,
    canManageUsers: results['/api/v1/web/admin/users:GET'] || false,
    canViewAnalytics: results['/api/v1/web/admin/analytics:GET'] || false
  }
}

// 权限Hook
export function usePermissions(refreshTrigger?: number) {
  const [permissions, setPermissions] = useState<UserPermissions | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadPermissions = async () => {
      try {
        setLoading(true)
        const userPermissions = await getUserPermissions()
        setPermissions(userPermissions)
      } catch (error) {
        console.error('Failed to load permissions:', error)
        setPermissions({
          canUpload: false,
          canManageFiles: false,
          canAccessRecycle: false,
          canAccessPackages: false,
          canManageAPIKeys: false,
          canManageUsers: false,
          canViewAnalytics: false
        })
      } finally {
        setLoading(false)
      }
    }

    loadPermissions()
  }, [refreshTrigger])

  return { permissions, loading }
}

// 权限组件
interface PermissionGateProps {
  resource: string
  action: string
  children: React.ReactNode
  fallback?: React.ReactNode
}

export function PermissionGate({ resource, action, children, fallback = null }: PermissionGateProps) {
  const [hasPermission, setHasPermission] = useState<boolean | null>(null)

  useEffect(() => {
    checkPermission(resource, action).then(setHasPermission)
  }, [resource, action])

  if (hasPermission === null) {
    return <div>Loading...</div>
  }

  return hasPermission ? <>{children}</> : <>{fallback}</>
}
