"use client"

import { useEffect, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient } from "@/lib/api"
import { formatDate } from "@/lib/utils"
import { Upload, Search, Loader2, Edit, Copy, MoreVertical } from "lucide-react"

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
  const [assetsFile, setAssetsFile] = useState<File | null>(null)
  const [othersFile, setOthersFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)

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

  const handleUpload = async (kind: "assets" | "others") => {
    if (!tenant.trim()) { alert('Tenant ID is required'); return }
    try {
      setIsUploading(true)
      if (kind === "assets" && assetsFile) await apiClient.uploadAssetsZip(assetsFile, tenant.trim())
      if (kind === "others" && othersFile) await apiClient.uploadOthersZip(othersFile, tenant.trim())
      setAssetsFile(null)
      setOthersFile(null)
      await fetchList()
    } catch (e) {
      console.error("Upload failed", e)
      alert(e instanceof Error ? e.message : "Upload failed")
    } finally {
      setIsUploading(false)
    }
  }

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
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            Assets/Others Upload (via API)
          </CardTitle>
        </CardHeader>
        <CardContent className="grid md:grid-cols-2 gap-6">
          <div className="space-y-2 md:col-span-2">
            <Label>Tenant ID (required for upload)</Label>
            <Input placeholder="tenant id" value={tenant} onChange={e=>setTenant(e.target.value)} className="w-64" />
          </div>
          <div className="space-y-2">
            <Label>Upload Assets ZIP</Label>
            <Input type="file" accept=".zip" onChange={(e) => setAssetsFile(e.target.files?.[0] || null)} />
            <Button onClick={() => handleUpload("assets")} disabled={!assetsFile || isUploading}>
              {isUploading ? <Loader2 className="h-4 w-4 animate-spin mr-2"/> : null}
              Upload Assets
            </Button>
            <div className="text-xs text-gray-500">Will upload to packages/&lt;tenant_id&gt;/assets/ ...</div>
          </div>
          <div className="space-y-2">
            <Label>Upload Others ZIP</Label>
            <Input type="file" accept=".zip" onChange={(e) => setOthersFile(e.target.files?.[0] || null)} />
            <Button onClick={() => handleUpload("others")} disabled={!othersFile || isUploading}>
              {isUploading ? <Loader2 className="h-4 w-4 animate-spin mr-2"/> : null}
              Upload Others
            </Button>
            <div className="text-xs text-gray-500">Will upload to packages/&lt;tenant_id&gt;/others/ ...</div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Uploaded Packages</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="space-y-1">
              <Label>Tenant ID</Label>
              <Input placeholder="tenant id" value={tenant} onChange={e=>setTenant(e.target.value)} className="w-48" />
            </div>
            <div className="space-y-1">
              <Label>Type</Label>
              <Select value={typeFilter} onValueChange={(v)=>setTypeFilter(v)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="assets">assets</SelectItem>
                  <SelectItem value="others">others</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>Search</Label>
              <div className="flex gap-2">
                <Input placeholder="filename / path / remark" value={q} onChange={e=>setQ(e.target.value)} className="w-64" />
                <Button variant="outline" onClick={handleSearch}><Search className="h-4 w-4 mr-2"/>Search</Button>
              </div>
            </div>
            <div className="space-y-1">
              <Label>Page Size</Label>
              <Select value={String(limit)} onValueChange={(v)=>{ setLimit(Number(v)); setPage(1); }}>
                <SelectTrigger className="w-28">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10</SelectItem>
                  <SelectItem value="20">20</SelectItem>
                  <SelectItem value="50">50</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label>&nbsp;</Label>
              <Button variant="outline" onClick={fetchList}>Refresh</Button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-sm table-fixed">
              <thead>
                <tr className="text-left border-b text-gray-600 bg-gray-50">
                  <th className="py-3 px-2 w-24 font-medium text-xs uppercase tracking-wide">Tenant</th>
                  <th className="py-3 px-2 w-20 font-medium text-xs uppercase tracking-wide">IP</th>
                  <th className="py-3 px-2 w-32 font-medium text-xs uppercase tracking-wide">Timestamp</th>
                  <th className="py-3 px-2 w-16 font-medium text-xs uppercase tracking-wide">Type</th>
                  <th className="py-3 px-2 w-40 font-medium text-xs uppercase tracking-wide">Filename</th>
                  <th className="py-3 px-2 w-20 font-medium text-xs uppercase tracking-wide">Size</th>
                  <th className="py-3 px-2 flex-1 font-medium text-xs uppercase tracking-wide">Path</th>
                  <th className="py-3 px-2 w-48 font-medium text-xs uppercase tracking-wide">Remark</th>
                  <th className="py-3 px-2 w-12 font-medium text-xs uppercase tracking-wide"></th>
                </tr>
              </thead>
              <tbody>
                {loadingList ? (
                  <tr><td colSpan={9} className="py-6 text-center text-gray-500">Loading...</td></tr>
                ) : (items?.length ?? 0) === 0 ? (
                  <tr><td colSpan={9} className="py-6 text-center text-gray-500">No data</td></tr>
                ) : (
                  (items || []).map(item => (
                    <Row key={item.id} item={item} onEdit={() => openRemark(item)} />
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between pt-2">
            <div className="text-xs text-gray-500">Total: {count}</div>
            <div className="flex items-center gap-2">
              <Button variant="outline" disabled={page<=1} onClick={()=>setPage(p=>Math.max(1,p-1))}>Prev</Button>
              <span className="text-sm">Page {page} / {totalPages}</span>
              <Button variant="outline" disabled={page>=totalPages} onClick={()=>setPage(p=>Math.min(totalPages,p+1))}>Next</Button>
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

function Row({ item, onEdit }: { item: PackageItem, onEdit: () => void }) {
  const sizeFmt = useMemo(() => `${(item.size/1024/1024).toFixed(2)} MB`, [item.size])
  const dirPath = useMemo(() => {
    const p = (item.path || '').replace(/\\/g, '/');
    const idx = p.lastIndexOf('/');
    return idx >= 0 ? p.slice(0, idx) : p;
  }, [item.path])

  return (
    <tr className="border-b hover:bg-gray-50">
      <td className="py-3 px-2 w-24 truncate" title={item.tenantId}>
        <span className="text-xs">{item.tenantId}</span>
      </td>
      <td className="py-3 px-2 w-20 truncate" title={item.ip}>
        <span className="text-xs font-mono">{item.ip}</span>
      </td>
      <td className="py-3 px-2 w-32 truncate" title={formatDate(item.timestamp)}>
        <span className="text-xs">{formatDate(item.timestamp)}</span>
      </td>
      <td className="py-3 px-2 w-16 truncate">
        <span className={`px-2 py-1 rounded text-xs ${
          item.type === 'assets' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'
        }`}>
          {item.type}
        </span>
      </td>
      <td className="py-3 px-2 w-40 truncate" title={item.fileName}>
        <span className="text-xs">{item.fileName}</span>
      </td>
      <td className="py-3 px-2 w-20 text-xs">
        {sizeFmt}
      </td>
      <td className="py-3 px-2 flex-1 truncate font-mono text-xs" title={item.path}>
        {dirPath}
      </td>
      <td className="py-3 px-2 w-48 truncate" title={item.remark || ''}>
        <span className="text-xs">{item.remark || <span className="text-gray-400">No remark</span>}</span>
      </td>
      <td className="py-3 px-2 w-12">
        <Button size="sm" variant="ghost" onClick={onEdit} className="p-1 h-8 w-8" title="Edit remark">
          <Edit className="h-4 w-4" />
        </Button>
      </td>
    </tr>
  )
}
