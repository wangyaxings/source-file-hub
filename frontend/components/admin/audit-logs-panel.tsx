"use client"

import React, { useEffect, useState } from 'react'
import { apiClient } from '@/lib/api'
import { mapApiErrorToMessage } from '@/lib/errors'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useToast } from '@/lib/use-toast'
import { Search, RefreshCw, Loader2 } from 'lucide-react'

interface UsageLogItem {
  id: number
  apiKeyId: string
  apiKeyName: string
  userId: string
  endpoint: string
  method: string
  fileId?: string
  filePath?: string
  ipAddress: string
  userAgent?: string
  statusCode: number
  responseSize: number
  responseTimeMs: number
  errorMessage?: string
  requestTime: string
  createdAt: string
}

export function AuditLogsPanel() {
  const [mounted, setMounted] = useState(false)
  const [items, setItems] = useState<UsageLogItem[]>([])
  const [apiKeyFilter, setApiKeyFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('all')
  const [endpointFilter, setEndpointFilter] = useState('')
  const [timeFromFilter, setTimeFromFilter] = useState('')
  const [timeToFilter, setTimeToFilter] = useState('')
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(20)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const { toast } = useToast()

  const load = async () => {
    setLoading(true)
    try {
      const qs = new URLSearchParams()
      if (apiKeyFilter) qs.set('apiKey', apiKeyFilter)
      if (methodFilter && methodFilter !== 'all') qs.set('method', methodFilter)
      if (endpointFilter) qs.set('endpoint', endpointFilter)
      if (timeFromFilter) qs.set('timeFrom', timeFromFilter)
      if (timeToFilter) qs.set('timeTo', timeToFilter)
      qs.set('limit', String(limit))
      qs.set('offset', String((page - 1) * limit))
      
      const resp = await apiClient.request<{ items: UsageLogItem[]; logs: UsageLogItem[]; count: number }>(`/admin/usage/logs?${qs.toString()}`)
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to load usage logs'), { code: (resp as any).code, details: (resp as any).details })
      
      const logs = (resp.data as any)?.items || (resp.data as any)?.logs || []
      setItems(logs)
      setTotal((resp.data as any)?.count || 0)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => { load() }, [page, limit])

  if (!mounted) return null

  const handleSearch = async () => {
    setPage(1)
    await load()
  }

  const totalPages = Math.max(1, Math.ceil(total / limit))

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>API Usage Logs</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-4 items-end">
            <div className="space-y-2">
              <Label htmlFor="time-from-filter" className="text-sm font-medium">From Time</Label>
              <Input 
                id="time-from-filter"
                type="datetime-local"
                value={timeFromFilter} 
                onChange={e => setTimeFromFilter(e.target.value)} 
                className="w-48" 
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="time-to-filter" className="text-sm font-medium">To Time</Label>
              <Input 
                id="time-to-filter"
                type="datetime-local"
                value={timeToFilter} 
                onChange={e => setTimeToFilter(e.target.value)} 
                className="w-48" 
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="api-key-filter" className="text-sm font-medium">API Key</Label>
              <Input 
                id="api-key-filter"
                placeholder="Enter API key name or ID" 
                value={apiKeyFilter} 
                onChange={e => setApiKeyFilter(e.target.value)} 
                className="w-48" 
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="method-filter" className="text-sm font-medium">HTTP Method</Label>
              <Select value={methodFilter} onValueChange={setMethodFilter}>
                <SelectTrigger className="w-32" id="method-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Methods</SelectItem>
                  <SelectItem value="GET">GET</SelectItem>
                  <SelectItem value="POST">POST</SelectItem>
                  <SelectItem value="PUT">PUT</SelectItem>
                  <SelectItem value="DELETE">DELETE</SelectItem>
                  <SelectItem value="PATCH">PATCH</SelectItem>
                </SelectContent>
              </Select>
      </div>
            <div className="space-y-2">
              <Label htmlFor="endpoint-filter" className="text-sm font-medium">Endpoint</Label>
              <Input 
                id="endpoint-filter"
                placeholder="Enter endpoint path" 
                value={endpointFilter} 
                onChange={e => setEndpointFilter(e.target.value)} 
                className="w-48" 
              />
      </div>
            <div className="space-y-2">
              <Label htmlFor="page-size" className="text-sm font-medium">Rows per page</Label>
          <Select value={String(limit)} onValueChange={(v) => { setLimit(parseInt(v || '20', 10)); setPage(1) }}>
                <SelectTrigger className="w-28" id="page-size" size="sm">
                  <SelectValue />
                </SelectTrigger>
            <SelectContent>
                  <SelectItem value="10">10</SelectItem>
                  <SelectItem value="20">20</SelectItem>
                  <SelectItem value="50">50</SelectItem>
            </SelectContent>
          </Select>
            </div>
            <div className="space-y-2">
              <Label className="text-sm font-medium opacity-0">Actions</Label>
          <div className="flex gap-2">
                <Button variant="outline" onClick={handleSearch} size="sm" disabled={loading}>
                  <Search className="h-4 w-4 mr-2"/>
                  Search
                </Button>
                <Button variant="outline" onClick={load} size="sm" disabled={loading}>
                  <RefreshCw className="h-4 w-4 mr-2"/>
                  Refresh
                </Button>
              </div>
            </div>
          </div>

          <div className="border rounded-md">
            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[1200px]">
                <thead className="bg-muted">
                  <tr>
                    <th className="text-left p-3 w-36 max-w-36">Request Time</th>
                    <th className="text-left p-3 w-40 max-w-40">API Key</th>
                    <th className="text-left p-3 w-20 max-w-20">Method</th>
                    <th className="text-left p-3 w-48 max-w-48">Endpoint</th>
                    <th className="text-left p-3 w-20 max-w-20">Status</th>
                    <th className="text-left p-3 w-24 max-w-24">Response Size</th>
                    <th className="text-left p-3 w-24 max-w-24">Response Time</th>
                    <th className="text-left p-3 w-32 max-w-32">IP Address</th>
                    <th className="text-left p-3 w-56 max-w-56">File Path</th>
                  </tr>
                </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan={9} className="p-6 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading...
                      </div>
                    </td>
                  </tr>
                ) : items.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="p-6 text-center text-muted-foreground">
                      No usage logs found.
                    </td>
                  </tr>
                ) : (
                  items.map((item, idx) => (
                    <tr key={item.id || idx} className="border-t hover:bg-muted/50">
                      <td className="p-3 w-36 max-w-36 text-xs truncate" title={
                        item.requestTime ?
                          new Date(item.requestTime).toLocaleString('zh-CN', {
                            year: 'numeric',
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit'
                          }) : ''
                      }>
                        {item.requestTime ?
                          new Date(item.requestTime).toLocaleString('zh-CN', {
                            year: 'numeric',
                            month: '2-digit',
                            day: '2-digit',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit'
                          }) : ''
                        }
                      </td>
                      <td className="p-3 w-40 max-w-40 truncate text-sm" title={item.apiKeyName}>
                        {item.apiKeyName || 'Unknown'}
                      </td>
                      <td className="p-3 w-20 max-w-20">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          item.method === 'GET' ? 'bg-green-100 text-green-800' :
                          item.method === 'POST' ? 'bg-blue-100 text-blue-800' :
                          item.method === 'PUT' ? 'bg-yellow-100 text-yellow-800' :
                          item.method === 'DELETE' ? 'bg-red-100 text-red-800' :
                          'bg-gray-100 text-gray-800'
                        }`}>
                          {item.method}
                        </span>
                      </td>
                      <td className="p-3 w-48 max-w-48">
                        <code className="text-xs font-mono truncate block" title={item.endpoint}>
                          {item.endpoint}
                        </code>
                      </td>
                      <td className="p-3 w-20 max-w-20">
                        <span className={`px-2 py-0.5 rounded text-xs ${
                          item.statusCode >= 200 && item.statusCode < 300 ? 'bg-green-100 text-green-800' :
                          item.statusCode >= 400 && item.statusCode < 500 ? 'bg-yellow-100 text-yellow-800' :
                          item.statusCode >= 500 ? 'bg-red-100 text-red-800' :
                          'bg-gray-100 text-gray-800'
                        }`}>
                          {item.statusCode}
                        </span>
                      </td>
                      <td className="p-3 w-24 max-w-24 text-xs truncate" title={item.responseSize ? `${(item.responseSize / 1024).toFixed(1)} KB` : '-'}>
                        {item.responseSize ? `${(item.responseSize / 1024).toFixed(1)} KB` : '-'}
                      </td>
                      <td className="p-3 w-24 max-w-24 text-xs truncate" title={item.responseTimeMs ? `${item.responseTimeMs}ms` : '-'}>
                        {item.responseTimeMs ? `${item.responseTimeMs}ms` : '-'}
                      </td>
                      <td className="p-3 w-32 max-w-32 text-xs truncate font-mono" title={item.ipAddress}>
                        {item.ipAddress}
                      </td>
                      <td className="p-3 w-56 max-w-56">
                        {item.filePath ? (
                          <code className="text-xs font-mono truncate block" title={item.filePath}>
                            {item.filePath}
                          </code>
                        ) : (
                          <span className="text-xs text-gray-400">-</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4">
            <div className="text-muted-foreground hidden flex-1 text-sm lg:flex">
              Showing {Math.min((page - 1) * limit + 1, total)} to {Math.min(page * limit, total)} of {total} results
            </div>
            <div className="flex w-full items-center gap-8 lg:w-fit">
              <div className="flex w-fit items-center justify-center text-sm font-medium">
                Page {page} of {totalPages}
              </div>
              <div className="ml-auto flex items-center gap-2 lg:ml-0">
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(1)}
                  disabled={page <= 1}
                  size="icon"
                >
                  <span className="sr-only">Go to first page</span>
                  ««
                </Button>
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  size="icon"
                >
                  <span className="sr-only">Go to previous page</span>
                  «
                </Button>
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  size="icon"
                >
                  <span className="sr-only">Go to next page</span>
                  »
                </Button>
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(totalPages)}
                  disabled={page >= totalPages}
                  size="icon"
                >
                  <span className="sr-only">Go to last page</span>
                  »»
                </Button>
          </div>
        </div>
      </div>
        </CardContent>
      </Card>
    </div>
  )
}

