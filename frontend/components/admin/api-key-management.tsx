'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useToast } from "@/lib/use-toast"
import { formatDate } from "@/lib/utils"
import { AnalyticsCharts } from "./analytics-charts"
import {
  Key,
  Plus,
  RefreshCw,
  Eye,
  EyeOff,
  Copy,
  Trash2,
  Edit,
  Users,
  BarChart3,
  Settings,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Loader2,
  Download,
  Calendar,
  X
} from "lucide-react"

interface APIKey {
  id: string
  name: string
  description?: string
  userId: string
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
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [showKeyDialog, setShowKeyDialog] = useState(false)
  const [selectedKey, setSelectedKey] = useState<APIKey | null>(null)
  const [newKey, setNewKey] = useState("")
  const [showDatePicker, setShowDatePicker] = useState(false)
  const [tempExpiryDate, setTempExpiryDate] = useState("")

  // Create API Key Form State
  const [createForm, setCreateForm] = useState({
    name: "",
    description: "",
    userId: "",
    permissions: [] as string[],
    expiresAt: ""
  })

  const permissions = [
    { value: "read", label: "Read Files", description: "View file lists and metadata" },
    { value: "download", label: "Download Files", description: "Download file contents" },
    { value: "upload", label: "Upload Files", description: "Upload new files" },
    { value: "admin", label: "Admin Access", description: "Full administrative access" }
  ]

  const loadAPIKeys = async () => {
    setIsLoading(true)
    try {
      const response = await fetch('/api/v1/web/admin/api-keys', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        }
      })

      if (!response.ok) throw new Error('Failed to load API keys')

      const result = await response.json()
      setApiKeys(result.data?.keys || [])
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to load API keys'
      })
    } finally {
      setIsLoading(false)
    }
  }

  const loadUsageLogs = async () => {
    try {
      const response = await fetch('/api/v1/web/admin/usage/logs?limit=100', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        }
      })

      if (!response.ok) throw new Error('Failed to load usage logs')

      const result = await response.json()
      setUsageLogs(result.data?.logs || [])
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to load usage logs'
      })
    }
  }

  const createAPIKey = async () => {
    if (!createForm.name || !createForm.userId || createForm.permissions.length === 0) {
      toast({
        variant: "destructive",
        title: "Validation Error",
        description: "Please fill in all required fields"
      })
      return
    }

    // Validate expiration time
    if (createForm.expiresAt) {
      const expiryDate = new Date(createForm.expiresAt)
      if (expiryDate <= new Date()) {
        toast({
          variant: "destructive",
          title: "Invalid Expiration Date",
          description: "Expiration date must be in the future"
        })
        return
      }
    }

    try {
      const requestBody = {
        name: createForm.name,
        description: createForm.description,
        user_id: createForm.userId,
        permissions: createForm.permissions,
        expires_at: createForm.expiresAt || undefined
      }

      console.log('Creating API key with data:', requestBody) // Debug log

      const response = await fetch('/api/v1/web/admin/api-keys', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      })

      const result = await response.json()

      if (!response.ok) {
        // Provide more friendly error messages based on specific errors
        let errorMessage = result.message || 'Failed to create API key'

        if (response.status === 400) {
          if (errorMessage.includes('expiration date')) {
            errorMessage = 'Invalid expiration date format. Please select a valid future date.'
          } else if (errorMessage.includes('permissions')) {
            errorMessage = 'Invalid permissions selected. Please check your selections.'
          }
        }

        throw new Error(errorMessage)
      }

      const createdKey = result.data

      setNewKey(createdKey.key)
      setSelectedKey(createdKey)
      setShowCreateDialog(false)
      setShowKeyDialog(true)

      // Reset form
      setCreateForm({
        name: "",
        description: "",
        userId: "",
        permissions: [],
        expiresAt: ""
      })

      loadAPIKeys()

      toast({
        title: "Success",
        description: "API key created successfully"
      })
    } catch (error) {
      console.error('API key creation error:', error) // Debug log
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to create API key'
      })
    }
  }

  const updateAPIKeyStatus = async (keyId: string, status: string) => {
    try {
      const response = await fetch(`/api/v1/web/admin/api-keys/${keyId}/status`, {
        method: 'PATCH',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ status })
      })

      if (!response.ok) throw new Error('Failed to update API key status')

      loadAPIKeys()

      toast({
        title: "Success",
        description: `API key ${status === 'active' ? 'enabled' : 'disabled'} successfully`
      })
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to update API key status'
      })
    }
  }

  const deleteAPIKey = async (keyId: string) => {
    if (!confirm('Are you sure you want to delete this API key? This action cannot be undone.')) {
      return
    }

    try {
      const response = await fetch(`/api/v1/web/admin/api-keys/${keyId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        }
      })

      if (!response.ok) throw new Error('Failed to delete API key')

      loadAPIKeys()

      toast({
        title: "Success",
        description: "API key deleted successfully"
      })
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to delete API key'
      })
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
    } catch (error) {
      return isoString
    }
  }

  useEffect(() => {
    if (activeTab === "keys") {
      loadAPIKeys()
    } else if (activeTab === "usage") {
      loadUsageLogs()
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
                            <span>User: {key.userId}</span>
                            <span>Usage: {key.usageCount}</span>
                            <span>Created: {formatDate(key.createdAt)}</span>
                            {key.lastUsedAt && (
                              <span>Last used: {formatDate(key.lastUsedAt)}</span>
                            )}
                          </div>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {key.permissions.map((perm) => (
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
                            variant="destructive"
                            size="sm"
                            onClick={() => deleteAPIKey(key.id)}
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
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b text-left text-sm text-gray-500">
                        <th className="pb-2">Time</th>
                        <th className="pb-2">User</th>
                        <th className="pb-2">Method</th>
                        <th className="pb-2">Endpoint</th>
                        <th className="pb-2">Status</th>
                        <th className="pb-2">Response Time</th>
                        <th className="pb-2">IP Address</th>
                      </tr>
                    </thead>
                    <tbody>
                      {usageLogs.map((log) => (
                        <tr key={log.id} className="border-b text-sm">
                          <td className="py-2">{formatDate(log.requestTime)}</td>
                          <td className="py-2">{log.userId}</td>
                          <td className="py-2">
                            <span className={`px-2 py-1 rounded text-xs ${
                              log.method === 'GET' ? 'bg-blue-100 text-blue-800' :
                              log.method === 'POST' ? 'bg-green-100 text-green-800' :
                              log.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                              'bg-gray-100 text-gray-800'
                            }`}>
                              {log.method}
                            </span>
                          </td>
                          <td className="py-2 font-mono text-xs">{log.endpoint}</td>
                          <td className="py-2">
                            <span className={`px-2 py-1 rounded text-xs ${
                              log.statusCode >= 200 && log.statusCode < 300
                                ? 'bg-green-100 text-green-800'
                                : log.statusCode >= 400
                                ? 'bg-red-100 text-red-800'
                                : 'bg-yellow-100 text-yellow-800'
                            }`}>
                              {log.statusCode}
                            </span>
                          </td>
                          <td className="py-2">{log.responseTimeMs}ms</td>
                          <td className="py-2 font-mono text-xs">{log.ipAddress}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
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
              <Label htmlFor="userId">User ID *</Label>
              <Select value={createForm.userId} onValueChange={(value) => setCreateForm(prev => ({ ...prev, userId: value }))}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a user ID" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">admin (Administrator)</SelectItem>
                  <SelectItem value="api_user">api_user (API Access User)</SelectItem>
                  <SelectItem value="demo_user">demo_user (Demo User)</SelectItem>
                  <SelectItem value="system">system (System User)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-gray-500 mt-1">
                Select the user ID that will own this API key. Use 'admin' for administrative access.
              </p>
            </div>

            <div>
              <Label>Permissions *</Label>
              <div className="space-y-2 mt-2">
                {permissions.map((perm) => (
                  <label key={perm.value} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={createForm.permissions.includes(perm.value)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setCreateForm(prev => ({
                            ...prev,
                            permissions: [...prev.permissions, perm.value]
                          }))
                        } else {
                          setCreateForm(prev => ({
                            ...prev,
                            permissions: prev.permissions.filter(p => p !== perm.value)
                          }))
                        }
                      }}
                      className="rounded"
                    />
                    <div>
                      <span className="text-sm font-medium">{perm.label}</span>
                      <p className="text-xs text-gray-500">{perm.description}</p>
                    </div>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <Label htmlFor="expiresAt">Expires At (optional)</Label>
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <Input
                    id="expiresAt"
                    value={createForm.expiresAt ? formatDisplayDate(createForm.expiresAt) : "No expiration"}
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

      {/* Show New API Key Dialog */}
      <Dialog open={showKeyDialog} onOpenChange={setShowKeyDialog}>
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
                <p><strong>User:</strong> {selectedKey.userId}</p>
                <p><strong>Permissions:</strong> {selectedKey.permissions.join(", ")}</p>
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
            <Button onClick={() => setShowKeyDialog(false)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}