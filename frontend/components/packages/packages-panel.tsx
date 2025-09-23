"use client"

import { useEffect, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { apiClient } from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { Search, Loader2, Edit, Copy, MoreVertical, RefreshCw, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react"

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
  const [tenant, setTenant] = useState("")
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [q, setQ] = useState("")
  const [loadingList, setLoadingList] = useState(false)
  const [remarkDialog, setRemarkDialog] = useState<{ open: boolean; item: PackageItem | null; text: string }>({ open: false, item: null, text: "" })

  const fetchList = async () => {
    setLoadingList(true)
    try {
      const params: any = { page, limit }
      if (tenant) params.tenant = tenant
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
          <div className="flex flex-wrap gap-4 items-end">
            <div className="space-y-2">
              <Label htmlFor="tenant-filter" className="text-sm font-medium">Tenant ID</Label>
              <Input 
                id="tenant-filter"
                placeholder="Enter tenant ID" 
                value={tenant} 
                onChange={e=>setTenant(e.target.value)} 
                className="w-48" 
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="type-filter" className="text-sm font-medium">Type</Label>
              <Select value={typeFilter} onValueChange={(v)=>setTypeFilter(v)}>
                <SelectTrigger className="w-40" id="type-filter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  <SelectItem value="assets">Assets</SelectItem>
                  <SelectItem value="others">Others</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="search-filter" className="text-sm font-medium">Search</Label>
              <div className="flex gap-2">
                <Input 
                  id="search-filter"
                  placeholder="Search filename, path, or remark" 
                  value={q} 
                  onChange={e=>setQ(e.target.value)} 
                  className="w-64" 
                />
                <Button variant="outline" onClick={handleSearch} size="sm">
                  <Search className="h-4 w-4 mr-2"/>
                  Search
                </Button>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="page-size" className="text-sm font-medium">Rows per page</Label>
              <Select value={String(limit)} onValueChange={(v)=>{ setLimit(Number(v)); setPage(1); }}>
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
              <Button variant="outline" onClick={fetchList} size="sm">
                <RefreshCw className="h-4 w-4 mr-2"/>
                Refresh
              </Button>
            </div>
          </div>

          <div className="overflow-hidden rounded-lg border">
            <Table>
              <TableHeader className="bg-muted">
                <TableRow>
                  <TableHead className="w-24">Tenant</TableHead>
                  <TableHead className="w-20">IP</TableHead>
                  <TableHead className="w-32">Timestamp</TableHead>
                  <TableHead className="w-16">Type</TableHead>
                  <TableHead className="w-40">Filename</TableHead>
                  <TableHead className="w-20">Size</TableHead>
                  <TableHead className="flex-1">Path</TableHead>
                  <TableHead className="w-48">Remark</TableHead>
                  <TableHead className="w-12"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loadingList ? (
                  <TableRow>
                    <TableCell colSpan={9} className="h-24 text-center">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Loading...
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (items?.length ?? 0) === 0 ? (
                  <TableRow>
                    <TableCell colSpan={9} className="h-24 text-center text-muted-foreground">
                      No packages found.
                    </TableCell>
                  </TableRow>
                ) : (
                  (items || []).map(item => (
                    <PackageRow key={item.id} item={item} onEdit={() => openRemark(item)} />
                  ))
                )}
              </TableBody>
            </Table>
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
  const sizeFmt = useMemo(() => `${(item.size/1024/1024).toFixed(2)} MB`, [item.size])
  const dirPath = useMemo(() => {
    const p = (item.path || '').replace(/\\/g, '/');
    const idx = p.lastIndexOf('/');
    return idx >= 0 ? p.slice(0, idx) : p;
  }, [item.path])

  return (
    <TableRow>
      <TableCell className="w-24 font-medium">
        <div className="truncate" title={item.tenantId}>
          {item.tenantId}
        </div>
      </TableCell>
      <TableCell className="w-20">
        <div className="truncate font-mono text-sm" title={item.ip}>
          {item.ip}
        </div>
      </TableCell>
      <TableCell className="w-32">
        <div className="truncate text-sm" title={formatDate(item.timestamp)}>
          {formatDate(item.timestamp)}
        </div>
      </TableCell>
      <TableCell className="w-16">
        <Badge 
          variant={item.type === 'assets' ? 'default' : 'secondary'}
          className="text-xs"
        >
          {item.type}
        </Badge>
      </TableCell>
      <TableCell className="w-40">
        <div className="truncate text-sm" title={item.fileName}>
          {item.fileName}
        </div>
      </TableCell>
      <TableCell className="w-20 text-sm">
        {sizeFmt}
      </TableCell>
      <TableCell className="flex-1">
        <div className="truncate font-mono text-sm" title={item.path}>
          {dirPath}
        </div>
      </TableCell>
      <TableCell className="w-48">
        <div className="truncate text-sm" title={item.remark || ''}>
          {item.remark || <span className="text-muted-foreground">No remark</span>}
        </div>
      </TableCell>
      <TableCell className="w-12">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              className="data-[state=open]:bg-muted flex h-8 w-8 p-0"
              size="icon"
            >
              <MoreVertical className="h-4 w-4" />
              <span className="sr-only">Open menu</span>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-32">
            <DropdownMenuItem onClick={onEdit}>
              <Edit className="mr-2 h-4 w-4" />
              Edit Remark
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}
