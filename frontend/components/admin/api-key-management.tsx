'use client'

import { apiClient } from "@/lib/api"
import { mapApiErrorToMessage } from "@/lib/errors"
import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/lib/use-toast"
import { formatDate, isoToDatetimeLocal, datetimeLocalToISO } from "@/lib/utils"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { AnalyticsCharts } from "./analytics-charts"
import {
  Key,
  Plus,
  RefreshCw,
  Eye,
  EyeOff,
  Copy,
  Trash2,
  Users,
  BarChart3,
  Settings,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Calendar,
  X
} from "lucide-react"

// Feature flag: backend does not yet support clearing expiry
const CLEAR_EXPIRY_SUPPORTED = true as const

interface APIKey {
  id: string
  name: string
  description?: string
  role: string
  permissions: string[]
  status: string
  expiresAt?: string
  usageCount: number
  lastUsedAt?: string
  createdAt: string
  key?: string // Only available on creation
}

interface UsageLog {
  id: number
  apiKeyId: string
  apiKeyName: string
  userId: string
  endpoint: string
  method: string
  fileId?: string
  filePath?: string
  ipAddress: string
  statusCode: number
  responseSize: number
  responseTimeMs: number
  requestTime: string
}

export function APIKeyManagement() {
  const { toast } = useToast()
  const [activeTab, setActiveTab] = useState("keys")
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [usageLogs, setUsageLogs] = useState<UsageLog[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [usageLogsPage, setUsageLogsPage] = useState(1)
  const [usageLogsLimit] = useState(20)
  const [usageLogsTotal, setUsageLogsTotal] = useState(0)
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [showKeyDialog, setShowKeyDialog] = useState(false)
  const [selectedKey, setSelectedKey] = useState<APIKey | null>(null)
  const [newKey, setNewKey] = useState("")
  const [showDatePicker, setShowDatePicker] = useState(false)
  const [tempExpiryDate, setTempExpiryDate] = useState("")
  const [deleteDialog, setDeleteDialog] = useState<{
    isOpen: boolean
    apiKey: APIKey | null
  }>({
    isOpen: false,
    apiKey: null
  })

  const [downloadUrl, setDownloadUrl] = useState<string | null>(null)

  // Create API Key Form State (role-based API key creation)
  const [createForm, setCreateForm] = useState({
    name: "",
    description: "",
    role: "", // API role
    permissions: [] as string[],
    expiresAt: ""
  })

  // Edit dialog state
  const [showEditDialog, setShowEditDialog] = useState(false)
  const [editTarget, setEditTarget] = useState<APIKey | null>(null)
  const [editForm, setEditForm] = useState({
    name: "",
    description: "",
    role: "",
    permissions: [] as string[],
    expiresAt: ""
  })
  const [isSavingEdit, setIsSavingEdit] = useState(false)
  const [clearExpiry, setClearExpiry] = useState(false)

  useEffect(() => {
    console.log('🔄 [useEffect] Dialog state changed:', {
      showKeyDialog,
      newKey: newKey ? `has key (${newKey.length} chars)` : 'no key',
      selectedKey: selectedKey ? `has selected (${selectedKey.id})` : 'no selected',
      downloadUrl: downloadUrl ? 'has download URL' : 'no download URL'
    })
  }, [showKeyDialog, newKey, selectedKey, downloadUrl])

  // Additional state monitoring
  useEffect(() => {
    console.log('🔄 [useEffect] Create dialog state changed:', { showCreateDialog })
  }, [showCreateDialog])

  const permissions = [
    { value: "read", label: "Read Files", description: "View file lists and metadata" },
    { value: "download", label: "Download Files", description: "Download file contents" },
    { value: "upload", label: "Upload Files", description: "Upload new files" },
    { value: "admin", label: "Admin Access", description: "Full administrative access" }
  ]

  const loadAPIKeys = async () => {
    setIsLoading(true)
    try {
      const resp = await apiClient.request<{ keys: APIKey[]; count: number }>(`/admin/api-keys`)
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to load API keys'), { code: resp.code, details: (resp as any).details })
      setApiKeys(resp.data?.keys || [])
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: "destructive", title, description })
    } finally {
      setIsLoading(false)
    }
  }

  const loadUsageLogs = async () => {
    try {
      const offset = (usageLogsPage - 1) * usageLogsLimit
      const resp = await apiClient.request<{ logs: UsageLog[]; count: number }>(`/admin/usage/logs?limit=${usageLogsLimit}&offset=${offset}`)
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to load usage logs'), { code: (resp as any).code, details: (resp as any).details })
      const data = resp.data as any
      setUsageLogs(data?.logs || [])
      setUsageLogsTotal(data?.count || 0)
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: 'destructive', title, description })
    }
  }

  const createAPIKey = async () => {
    if (!createForm.name.trim() || !createForm.role) {
      toast({
        variant: "destructive",
        title: "Validation Error",
        description: "Name and role are required"
      })
      return
    }

    try {
      setIsLoading(true)

      // Prepare request payload
      const payload = {
        name: createForm.name,
        description: createForm.description,
        role: createForm.role,
        permissions: roleToPermissions(createForm.role),
        expires_at: createForm.expiresAt ? datetimeLocalToISO(createForm.expiresAt) : undefined
      }

      // Call real API
      const resp = await apiClient.request<{ api_key: APIKey; download_url: string }>(`/admin/api-keys`, {
        method: 'POST',
        body: JSON.stringify(payload)
      })

      if (!resp.success) {
        throw Object.assign(new Error(resp.error || 'Failed to create API key'), {
          code: resp.code,
          details: (resp as any).details
        })
      }

      const createdKey = (resp.data as any)?.api_key as APIKey
      const downloadUrl = (resp.data as any)?.download_url as string

      if (!createdKey || !createdKey.key) {
        throw new Error('Invalid response: missing API key data')
      }

      // Set the new key and selected key
      setNewKey(createdKey.key)
      setSelectedKey(createdKey)
      if (downloadUrl) {
        setDownloadUrl(downloadUrl)
      }

      // Close create dialog and reset form
      setShowCreateDialog(false)
      setCreateForm({
        name: "",
        description: "",
        role: "",
        permissions: [],
        expiresAt: ""
      })

      // Show success toast
      toast({
        title: "Success",
        description: "API key created successfully"
      })

      // Show the key dialog immediately
      setShowKeyDialog(true)

      // Reload API keys list
      loadAPIKeys()

    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: "destructive", title, description })
    } finally {
      setIsLoading(false)
    }
  }

  // Map API role to permissions
  const roleToPermissions = (role: string): string[] => {
    switch (role) {
      case 'admin':
        return ['read', 'download', 'upload', 'admin']
      case 'read_only':
        return ['read']
      case 'download_only':
        return ['read', 'download']
      case 'upload_only':
        return ['upload']
      case 'read_upload':
        return ['read', 'upload']
      default:
        return []
    }
  }

  const updateAPIKeyStatus = async (keyId: string, status: string) => {
    try {
      const resp = await apiClient.request(`/admin/api-keys/${encodeURIComponent(keyId)}/status`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      })
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to update API key status'), { code: (resp as any).code, details: (resp as any).details })
      loadAPIKeys()
      toast({ title: "Success", description: `API key ${status === 'active' ? 'enabled' : 'disabled'} successfully` })
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: 'destructive', title, description })
    }
  }

  const openEditDialog = (key: APIKey) => {
    setEditTarget(key)
    setEditForm({
      name: key.name || '',
      description: key.description || '',
      role: key.role || '',
      permissions: Array.isArray(key.permissions) ? key.permissions.slice() : [],
      expiresAt: isoToDatetimeLocal(key.expiresAt)
    })
    setClearExpiry(false)
    setShowEditDialog(true)
  }

  const submitUpdateAPIKey = async () => {
    if (!editTarget) return
    try {
      setIsSavingEdit(true)
      const payload: any = {}
      if (editForm.name && editForm.name !== editTarget.name) payload.name = editForm.name
      if (editForm.description !== editTarget.description) payload.description = editForm.description || ''
      if (editForm.permissions && editForm.permissions.length >= 0) payload.permissions = editForm.permissions
      if (CLEAR_EXPIRY_SUPPORTED && clearExpiry) { payload.expires_at = "" } else if (editForm.expiresAt) { payload.expires_at = editForm.expiresAt }

      const resp = await apiClient.request<{ api_key: APIKey }>(`/admin/api-keys/${encodeURIComponent(editTarget.id)}`, {
        method: 'PUT',
        body: JSON.stringify(payload)
      })
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to update API key'), { code: (resp as any).code, details: (resp as any).details })
      const updated = ((resp.data as any)?.api_key || (resp.data as any)) as APIKey
      if (updated && updated.id) {
        setApiKeys(prev => prev.map(k => k.id === updated.id ? { ...k, ...updated } as any : k))
      }
      toast({ title: 'Saved', description: 'API key updated successfully' })
      setShowEditDialog(false)
      setEditTarget(null)
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: 'destructive', title, description })
    } finally {
      setIsSavingEdit(false)
    }
  }


  const handleDeleteAPIKey = (apiKey: APIKey) => {
    setDeleteDialog({
      isOpen: true,
      apiKey: apiKey
    })
  }

  const confirmDeleteAPIKey = async () => {
    if (!deleteDialog.apiKey) return

    try {
      const resp = await apiClient.request(`/admin/api-keys/${encodeURIComponent(deleteDialog.apiKey.id)}`, { method: 'DELETE' })
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to delete API key'), { code: (resp as any).code, details: (resp as any).details })
      loadAPIKeys()
      toast({ title: 'Success', description: 'API key deleted successfully' })
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: 'destructive', title, description })
    } finally {
      setDeleteDialog({ isOpen: false, apiKey: null })
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: "Copied",
      description: "API key copied to clipboard"
    })
  }

  // Format date for display
  const formatDisplayDate = (isoString: string) => {
    if (!isoString) return ""
    try {
      const date = new Date(isoString)
      return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
      })
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      toast({ variant: 'destructive', title, description })
      return ""
    }
  }

  // Get API key display name by ID
  const getAPIKeyDisplayName = (apiKeyId: string, apiKeyName?: string) => {
    if (apiKeyId === 'web_session') {
      return 'Web Session'
    }

    // If we already have the name from the backend, use it (this should work with our fixed backend)
    if (apiKeyName && apiKeyName !== 'Unknown') {
      return apiKeyName
    }

    // Try to find the key by ID in our loaded API keys
    const foundKey = apiKeys.find(key => key.id === apiKeyId)
    if (foundKey) {
      return foundKey.name
    }

    return apiKeyName || 'Unknown API Key'
  }

  useEffect(() => {
    if (activeTab === "keys") {
      loadAPIKeys()
    } else if (activeTab === "usage") {
      loadUsageLogs()
    }
  }, [activeTab, usageLogsPage])

  // Auto-refresh usage logs every 30 seconds when on usage tab
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null

    if (activeTab === "usage") {
      interval = setInterval(() => {
        loadUsageLogs()
      }, 30000) // 30 seconds
    }

    return () => {
      if (interval) {
        clearInterval(interval)
      }
    }
  }, [activeTab])

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Key className="h-5 w-5" />
            API Key Management
          </CardTitle>
          <CardDescription>
            Manage API keys for external access to the file management system
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="keys" className="flex items-center gap-2">
            <Key className="h-4 w-4" />
            API Keys
          </TabsTrigger>
          <TabsTrigger value="usage" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Usage Logs
          </TabsTrigger>
          <TabsTrigger value="analytics" className="flex items-center gap-2">
            <BarChart3 className="h-4 w-4" />
            Analytics
          </TabsTrigger>
        </TabsList>

        {/* API Keys Tab */}
        <TabsContent value="keys" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>API Keys</CardTitle>
                  <CardDescription>
                    Manage API keys and their permissions
                  </CardDescription>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={loadAPIKeys} disabled={isLoading}>
                    <RefreshCw className={`h-4 w-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
                    Refresh
                  </Button>
                  <Button onClick={() => setShowCreateDialog(true)}>
                    <Plus className="h-4 w-4 mr-2" />
                    Create API Key
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {apiKeys.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <Key className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No API keys found</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="border rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-3">
                            <h3 className="font-semibold">{key.name}</h3>
                            <span className={`px-2 py-1 rounded-full text-xs ${
                              key.status === 'active'
                                ? 'bg-green-100 text-green-800'
                                : 'bg-red-100 text-red-800'
                            }`}>
                              {key.status}
                            </span>
                          </div>
                          {key.description && (
                            <p className="text-sm text-gray-600 mt-1">{key.description}</p>
                          )}
                          <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
                            <span>Role: {key.role}</span>
                            <span>Usage: {key.usageCount}</span>
                            <span>Created: {formatDate(key.createdAt)}</span>
                            {key.lastUsedAt && (
                              <span>Last used: {formatDate(key.lastUsedAt)}</span>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {(key.permissions || []).map((perm) => (
                              <span key={perm} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                                {perm}
                              </span>
                            ))}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => updateAPIKeyStatus(key.id, key.status === 'active' ? 'disabled' : 'active')}
                          >
                            {key.status === 'active' ? (
                              <>
                                <XCircle className="h-4 w-4 mr-1" />
                                Disable
                              </>
                            ) : (
                              <>
                                <CheckCircle className="h-4 w-4 mr-1" />
                                Enable
                              </>
                            )}
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => openEditDialog(key)}
                          >
                            <Edit className="h-4 w-4 mr-1" />
                            Edit
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={() => handleDeleteAPIKey(key)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Usage Logs Tab */}
        <TabsContent value="usage" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Usage Logs</CardTitle>
                  <CardDescription>
                    API usage history and statistics
                  </CardDescription>
                </div>
                <Button variant="outline" size="sm" onClick={loadUsageLogs}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Refresh
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {usageLogs.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  <BarChart3 className="h-12 w-12 mx-auto mb-4 text-gray-300" />
                  <p>No usage logs found</p>
                </div>
              ) : (
                <>
                  <div className="border rounded-md">
                    <div className="overflow-x-auto">
                      <Table className="text-sm min-w-[800px]">
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-32">Time</TableHead>
                            <TableHead className="w-32">API Key</TableHead>
                            <TableHead className="w-20">Method</TableHead>
                            <TableHead className="w-48">Endpoint</TableHead>
                            <TableHead className="w-20">Status</TableHead>
                            <TableHead className="w-24">Response</TableHead>
                            <TableHead className="w-32">IP Address</TableHead>
                          </TableRow>
                        </TableHeader>
                      <TableBody>
                        {usageLogs.map((log) => (
                          <TableRow key={log.id}>
                            <TableCell className="text-xs truncate" title={formatDate(log.requestTime)}>
                              {formatDate(log.requestTime)}
                            </TableCell>
                            <TableCell className="w-32">
                              <div className="truncate" title={getAPIKeyDisplayName(log.apiKeyId, log.apiKeyName)}>
                                {(() => {
                                  const displayName = getAPIKeyDisplayName(log.apiKeyId, log.apiKeyName)
                                  return displayName.length > 20 ? `${displayName.slice(0, 17)}...` : displayName
                                })()}
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                log.method === 'GET' ? 'bg-blue-100 text-blue-800' :
                                log.method === 'POST' ? 'bg-green-100 text-green-800' :
                                log.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                                log.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-gray-100 text-gray-800'
                              }`}>
                                {log.method}
                              </span>
                            </TableCell>
                            <TableCell className="w-48">
                              <div className="truncate" title={log.endpoint}>
                                <code className="text-xs bg-gray-100 px-1 py-0.5 rounded font-mono">
                                  {log.endpoint.length > 40 ? `${log.endpoint.slice(0, 37)}...` : log.endpoint}
                                </code>
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className={`px-2 py-0.5 rounded text-xs ${
                                log.statusCode >= 200 && log.statusCode < 300
                                  ? 'bg-green-100 text-green-800'
                                  : log.statusCode >= 400
                                  ? 'bg-red-100 text-red-800'
                                  : 'bg-yellow-100 text-yellow-800'
                              }`}>
                                {log.statusCode}
                              </span>
                            </TableCell>
                            <TableCell className="text-xs">{log.responseTimeMs}ms</TableCell>
                            <TableCell className="text-xs font-mono truncate" title={log.ipAddress}>
                              {log.ipAddress}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                      </Table>
                    </div>
                  </div>

                  {/* Pagination */}
                  <div className="flex items-center justify-between mt-4 text-sm text-gray-600">
                    <div>
                      Showing {((usageLogsPage - 1) * usageLogsLimit) + 1} to {Math.min(usageLogsPage * usageLogsLimit, usageLogsTotal)} of {usageLogsTotal} entries
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={usageLogsPage <= 1}
                        onClick={() => setUsageLogsPage(1)}
                      >
                        First
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={usageLogsPage <= 1}
                        onClick={() => setUsageLogsPage(prev => Math.max(1, prev - 1))}
                      >
                        Prev
                      </Button>
                      <span className="px-3 py-1 bg-gray-100 rounded text-sm">
                        Page {usageLogsPage} of {Math.max(1, Math.ceil(usageLogsTotal / usageLogsLimit))}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={usageLogsPage >= Math.ceil(usageLogsTotal / usageLogsLimit)}
                        onClick={() => setUsageLogsPage(prev => prev + 1)}
                      >
                        Next
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={usageLogsPage >= Math.ceil(usageLogsTotal / usageLogsLimit)}
                        onClick={() => setUsageLogsPage(Math.ceil(usageLogsTotal / usageLogsLimit))}
                      >
                        Last
                      </Button>
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Analytics Tab */}
        <TabsContent value="analytics" className="space-y-4">
          <AnalyticsCharts usageLogs={usageLogs} apiKeys={apiKeys} />
        </TabsContent>
      </Tabs>

      {/* Create API Key Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Create API Key</DialogTitle>
            <DialogDescription>
              Create a new API key for external access
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label htmlFor="name">Name *</Label>
              <Input
                id="name"
                value={createForm.name}
                onChange={(e) => setCreateForm(prev => ({ ...prev, name: e.target.value }))}
                placeholder="My API Key"
              />
            </div>

            <div>
              <Label htmlFor="description">Description</Label>
              <Input
                id="description"
                value={createForm.description}
                onChange={(e) => setCreateForm(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Optional description"
              />
            </div>

            <div>
              <Label htmlFor="role">API Role *</Label>
              <Select
                value={createForm.role}
                onValueChange={(value) => setCreateForm(prev => ({
                  ...prev,
                  role: value, // store selected role string
                  permissions: roleToPermissions(value)
                }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select an API role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Administrator (full access)</SelectItem>
                  <SelectItem value="read_only">Read Only</SelectItem>
                  <SelectItem value="download_only">Read + Download</SelectItem>
                  <SelectItem value="upload_only">Upload Only</SelectItem>
                  <SelectItem value="read_upload">Read + Upload</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-gray-500 mt-1">
                Role determines permissions automatically. No manual selection needed.
              </p>
            </div>

            <div>
              <Label>Permissions</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {createForm.permissions.length === 0 ? (
                  <span className="text-sm text-gray-500">Select a role to apply permissions</span>
                ) : (
                  createForm.permissions.map((perm) => (
                    <span key={perm} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                      {perm}
                    </span>
                  ))
                )}
              </div>
            </div>

            <div>
              <Label htmlFor="expiresAt">Expires At (optional)</Label>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Input
                    id="expiresAt"
                    value={createForm.expiresAt ? formatDisplayDate(createForm.expiresAt) || "No expiration" : "No expiration"}
                    readOnly
                    placeholder="Click to set expiration date"
                    className="cursor-pointer"
                    onClick={() => setShowDatePicker(true)}
                  />
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => setShowDatePicker(true)}
                  >
                    <Calendar className="h-4 w-4" />
                  </Button>
                  {createForm.expiresAt && (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      onClick={() => setCreateForm(prev => ({ ...prev, expiresAt: "" }))}
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  )}
                </div>

                {/* Date picker popup */}
                {showDatePicker && (
                  <div className="border rounded-lg p-4 bg-white shadow-lg">
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <Label className="text-sm font-medium">Set Expiration Date</Label>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowDatePicker(false)}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>

                      <Input
                        type="datetime-local"
                        value={tempExpiryDate}
                        onChange={(e) => setTempExpiryDate(e.target.value)}
                        min={new Date().toISOString().slice(0, 16)} // Prevent selecting past dates
                      />

                      <div className="flex justify-end gap-2">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          onClick={() => {
                            setShowDatePicker(false)
                            setTempExpiryDate("")
                          }}
                        >
                          Cancel
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          onClick={() => {
                            if (tempExpiryDate) {
                              // Convert to ISO format for backend
                              const isoDate = new Date(tempExpiryDate).toISOString()
                              setCreateForm(prev => ({ ...prev, expiresAt: isoDate }))
                            } else {
                              setCreateForm(prev => ({ ...prev, expiresAt: "" }))
                            }
                            setShowDatePicker(false)
                            setTempExpiryDate("")
                          }}
                        >
                          OK
                        </Button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={createAPIKey}>
              Create API Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Edit API Key Dialog */}
      <Dialog open={showEditDialog} onOpenChange={(open) => { setShowEditDialog(open); if (!open) { setEditTarget(null); setClearExpiry(false) } }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Edit API Key</DialogTitle>
            <DialogDescription>
              Update the API key details and permissions
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label htmlFor="edit-name">Name</Label>
              <Input
                id="edit-name"
                value={editForm.name}
                onChange={(e) => setEditForm(prev => ({ ...prev, name: e.target.value }))}
              />
            </div>

            <div>
              <Label htmlFor="edit-description">Description</Label>
              <Input
                id="edit-description"
                value={editForm.description}
                onChange={(e) => setEditForm(prev => ({ ...prev, description: e.target.value }))}
                placeholder="Optional description"
              />
            </div>

            <div>
              <Label htmlFor="edit-role">API Role</Label>
              <Select
                value={editForm.role}
                onValueChange={(value) => setEditForm(prev => ({
                  ...prev,
                  role: value,
                  permissions: roleToPermissions(value)
                }))}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select an API role" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Administrator (full access)</SelectItem>
                  <SelectItem value="read_only">Read Only</SelectItem>
                  <SelectItem value="download_only">Read + Download</SelectItem>
                  <SelectItem value="upload_only">Upload Only</SelectItem>
                  <SelectItem value="read_upload">Read + Upload</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-gray-500 mt-1">
                Role determines permissions automatically. No manual selection needed.
              </p>
            </div>

            <div>
              <Label>Permissions</Label>
              <div className="flex flex-wrap gap-2 mt-2">
                {editForm.permissions.length === 0 ? (
                  <span className="text-sm text-gray-500">Select a role to apply permissions</span>
                ) : (
                  editForm.permissions.map((perm) => (
                    <span key={perm} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded">
                      {perm}
                    </span>
                  ))
                )}
              </div>
            </div>

            <div>
              <Label htmlFor="edit-expiresAt">Expires At (optional)</Label>
              <Input
                id="edit-expiresAt"
                type="datetime-local" disabled={clearExpiry}
                value={editForm.expiresAt}
                onChange={(e) => setEditForm(prev => ({ ...prev, expiresAt: e.target.value }))}
              />
              <div className="flex items-center gap-2 mt-2">
                <input id="clear-expiry" type="checkbox" checked={clearExpiry} onChange={(e) => setClearExpiry(e.target.checked)} disabled={!CLEAR_EXPIRY_SUPPORTED} title={!CLEAR_EXPIRY_SUPPORTED ? "Pending backend support" : undefined} />
                <Label htmlFor="clear-expiry">Clear expiry</Label>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowEditDialog(false)}>
              Cancel
            </Button>
            <Button onClick={submitUpdateAPIKey} disabled={isSavingEdit || !editTarget}>
              Save Changes
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Show New API Key Dialog */}
      <Dialog open={showKeyDialog} onOpenChange={(open) => {
        console.log('🔄 [Dialog] onOpenChange called:', {
          open,
          currentShowKeyDialog: showKeyDialog,
          hasNewKey: !!newKey,
          hasSelectedKey: !!selectedKey,
          hasDownloadUrl: !!downloadUrl
        })
        setShowKeyDialog(open)
        if (!open) {
          console.log('🔄 [Dialog] Dialog closing - resetting states...')
          // Reset states when dialog closes
          setNewKey("")
          setSelectedKey(null)
          setDownloadUrl(null)
          // Reload API keys list after user has viewed the new key
          console.log('🔄 [Dialog] Reloading API keys list...')
          loadAPIKeys().catch(() => {})
        } else {
          console.log('🔄 [Dialog] Dialog opening...')
        }
      }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-green-600">
              <CheckCircle className="h-5 w-5" />
              API Key Created Successfully
            </DialogTitle>
            <DialogDescription>
              Your API key has been created. Make sure to copy it now as you won't be able to see it again.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label>API Key</Label>
              <div className="flex items-center gap-2 mt-1">
                <Input
                  value={newKey}
                  readOnly
                  className="font-mono text-sm"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(newKey)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            {selectedKey && (
              <div className="space-y-2">
                <p><strong>Name:</strong> {selectedKey.name}</p>
                <p><strong>Role:</strong> {selectedKey.role}</p>
                <p><strong>Permissions:</strong> {(selectedKey.permissions || []).join(", ")}</p>
              </div>
            )}

            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-600" />
                <span className="text-sm font-medium text-yellow-800">Important</span>
              </div>
              <p className="text-sm text-yellow-700 mt-1">
                Store this API key securely. You won't be able to view it again after closing this dialog.
              </p>
            </div>
          </div>

          <DialogFooter>
            {downloadUrl && (
              <Button variant="outline" onClick={() => { window.location.href = downloadUrl! }}>
                <Download className="h-4 w-4 mr-2" />
                Download Key
              </Button>
            )}
            <Button onClick={() => setShowKeyDialog(false)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog.isOpen} onOpenChange={(open) => setDeleteDialog({ isOpen: open, apiKey: null })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-600">
              <AlertTriangle className="h-5 w-5" />
              Confirm Delete API Key
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete API key "<strong>{deleteDialog.apiKey?.name}</strong>"?
              This action cannot be undone and will immediately revoke all access using this key.
            </DialogDescription>
          </DialogHeader>

          <div className="bg-red-50 border border-red-200 rounded-lg p-3">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-600" />
              <span className="text-sm font-medium text-red-800">Warning</span>
            </div>
            <p className="text-sm text-red-700 mt-1">
              Any applications or scripts using this API key will immediately lose access to the system.
            </p>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setDeleteDialog({ isOpen: false, apiKey: null })}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDeleteAPIKey}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete API Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}