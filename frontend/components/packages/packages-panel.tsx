"use client"

import { useEffect, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
// Removed Table imports - now using native HTML table
import { Badge } from "@/components/ui/badge"
// Removed DropdownMenu imports - now using direct button
import { apiClient } from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { Search, Loader2, Edit, RefreshCw, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight, Filter } from "lucide-react"

type PackageItem = {
  id: string
  tenantId: string
  type: string
  fileName: string
  size: number
  path: string
  ip: string
  timestamp: string
  remark?: string
}

export function PackagesPanel() {
  const [items, setItems] = useState<PackageItem[]>([])
  const [count, setCount] = useState(0)
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(50)
  // Removed tenant state - now use general search
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [q, setQ] = useState("")
  const [loadingList, setLoadingList] = useState(false)
  const [remarkDialog, setRemarkDialog] = useState<{ open: boolean; item: PackageItem | null; text: string }>({ open: false, item: null, text: "" })

  const fetchList = async () => {
    setLoadingList(true)
    try {
      const params: any = { page, limit }
      if (typeFilter !== "all") params.type = typeFilter
      if (q) params.q = q
      const res = await apiClient.listPackages(params)
      const newItems = Array.isArray((res as any)?.items) ? (res as any).items : []
      const newCount = typeof (res as any)?.count === 'number' ? (res as any).count : 0
      setItems(newItems as any)
      setCount(newCount)
    } finally {
      setLoadingList(false)
    }
  }

  useEffect(() => { fetchList() }, [page, limit])

  const totalPages = useMemo(() => Math.max(1, Math.ceil(count / limit)), [count, limit])

  const handleSearch = async () => {
    setPage(1)
    await fetchList()
  }

  const openRemark = (item: PackageItem) => {
    setRemarkDialog({ open: true, item, text: item.remark || "" })
  }

  const saveRemark = async () => {
    if (!remarkDialog.item) return
    try {
      await apiClient.updatePackageRemark(remarkDialog.item.id, remarkDialog.text)
      setRemarkDialog({ open: false, item: null, text: "" })
      await fetchList()
    } catch (e) {
      console.error("Update remark failed", e)
      alert(e instanceof Error ? e.message : "Update failed")
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Uploaded Packages</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <Button variant="outline" onClick={handleSearch} size="sm" title="Search and Filter">
                <Filter className="h-4 w-4" />
              </Button>
              <Select value={typeFilter} onValueChange={(v)=>setTypeFilter(v)}>
                <SelectTrigger className="w-28">
                  <SelectValue placeholder="Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="assets">Assets</SelectItem>
                  <SelectItem value="others">Others</SelectItem>
                </SelectContent>
              </Select>
              <Input
                placeholder="Search by tenant, filename, or path..."
                value={q}
                onChange={e=>setQ(e.target.value)}
                className="w-80"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm text-gray-600">{limit} per page</span>
              <Select value={String(limit)} onValueChange={(v)=>{ setLimit(Number(v)); setPage(1); }}>
                <SelectTrigger className="w-20">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10</SelectItem>
                  <SelectItem value="20">20</SelectItem>
                  <SelectItem value="50">50</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" onClick={fetchList} size="sm" title="Refresh">
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          </div>

          <div className="border rounded-md">
            <div className="overflow-x-auto">
              <table className="w-full text-sm min-w-[1000px]">
              <thead className="bg-muted">
                <tr>
                  <th className="text-left p-3 w-32 max-w-32">Tenant</th>
                  <th className="text-left p-3 w-28 max-w-28">IP</th>
                  <th className="text-left p-3 w-44 max-w-44">Timestamp</th>
                  <th className="text-left p-3 w-20 max-w-20">Type</th>
                  <th className="text-left p-3 w-24 max-w-24">Size</th>
                  <th className="text-left p-3 w-64 max-w-64">File Path</th>
                  <th className="text-left p-3 w-40 max-w-40">Remark</th>
                  <th className="text-left p-3 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {loadingList ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading...
                      </div>
                    </td>
                  </tr>
                ) : (items?.length ?? 0) === 0 ? (
                  <tr>
                    <td colSpan={8} className="p-6 text-center text-muted-foreground">
                      No packages found.
                    </td>
                  </tr>
                ) : (
                  (items || []).map(item => (
                    <PackageRow key={item.id} item={item} onEdit={() => openRemark(item)} />
                  ))
                )}
              </tbody>
            </table>
            </div>
          </div>

          <div className="flex items-center justify-between px-4">
            <div className="text-muted-foreground hidden flex-1 text-sm lg:flex">
              Showing {Math.min((page - 1) * limit + 1, count)} to {Math.min(page * limit, count)} of {count} results
            </div>
            <div className="flex w-full items-center gap-8 lg:w-fit">
              <div className="flex w-fit items-center justify-center text-sm font-medium">
                Page {page} of {totalPages}
              </div>
              <div className="ml-auto flex items-center gap-2 lg:ml-0">
                <Button
                  variant="outline"
                  className="hidden h-8 w-8 p-0 lg:flex"
                  onClick={() => setPage(1)}
                  disabled={page <= 1}
                  size="icon"
                >
                  <span className="sr-only">Go to first page</span>
                  <ChevronsLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  size="icon"
                >
                  <span className="sr-only">Go to previous page</span>
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  className="h-8 w-8 p-0"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page >= totalPages}
                  size="icon"
                >
                  <span className="sr-only">Go to next page</span>
                  <ChevronRight className="h-4 w-4" />
                </Button>
                <Button
                  variant="outline"
                  className="hidden h-8 w-8 p-0 lg:flex"
                  onClick={() => setPage(totalPages)}
                  disabled={page >= totalPages}
                  size="icon"
                >
                  <span className="sr-only">Go to last page</span>
                  <ChevronsRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
      <Dialog open={remarkDialog.open} onOpenChange={(open)=> setRemarkDialog(prev => ({ ...prev, open }))}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Remark</DialogTitle>
            <DialogDescription>Update the remark for this upload record.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label>Remark</Label>
            <Input value={remarkDialog.text} onChange={(e)=> setRemarkDialog(prev => ({ ...prev, text: e.target.value }))} placeholder="Enter remark" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={()=> setRemarkDialog({ open: false, item: null, text: "" })}>Cancel</Button>
            <Button onClick={saveRemark}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function PackageRow({ item, onEdit }: { item: PackageItem, onEdit: () => void }) {
  const sizeFmt = useMemo(() => {
    const bytes = item.size
    if (bytes === 0) return '0 B'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
    return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
  }, [item.size])

  const fullPath = useMemo(() => {
    const p = (item.path || '').replace(/\\/g, '/');
    return p
  }, [item.path])

  const displayPath = useMemo(() => {
    // Remove downloads/packages prefix for display
    const prefix = 'downloads/packages/'
    return fullPath.startsWith(prefix) ? fullPath.slice(prefix.length) : fullPath
  }, [fullPath])

  return (
    <tr className="border-t hover:bg-muted/50">
      <td className="p-3 w-32 max-w-32">
        <div className="truncate text-sm font-medium" title={item.tenantId}>
          {item.tenantId}
        </div>
      </td>
      <td className="p-3 w-28 max-w-28">
        <div className="truncate text-sm font-mono" title={item.ip}>
          {item.ip}
        </div>
      </td>
      <td className="p-3 w-44 max-w-44">
        <div className="text-sm truncate" title={formatDate(item.timestamp)}>
          {formatDate(item.timestamp)}
        </div>
      </td>
      <td className="p-3 w-20 max-w-20">
        <Badge
          variant={item.type === 'assets' ? 'default' : 'secondary'}
          className="text-xs"
          title={item.type}
        >
          {item.type}
        </Badge>
      </td>
      <td className="p-3 w-24 max-w-24">
        <div className="text-sm truncate" title={sizeFmt}>{sizeFmt}</div>
      </td>
      <td className="p-3 w-64 max-w-64">
        <div className="text-sm overflow-hidden" title={fullPath}>
          <span className="font-mono truncate">
            {displayPath}
          </span>
        </div>
      </td>
      <td className="p-3 w-40 max-w-40">
        <div className="truncate text-sm" title={item.remark || ''}>
          {item.remark || ''}
        </div>
      </td>
      <td className="p-3 w-10 max-w-10">
        <Button
          variant="ghost"
          className="h-8 w-8 p-0"
          size="icon"
          onClick={onEdit}
          title="Edit Remark"
        >
          <Edit className="h-4 w-4" />
          <span className="sr-only">Edit Remark</span>
        </Button>
      </td>
    </tr>
  )
}
