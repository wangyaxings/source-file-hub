'use client'

import { useEffect, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { apiClient, type FileInfo } from '@/lib/api'
import { useToast } from '@/lib/use-toast'
import { mapApiErrorToMessage } from '@/lib/errors'
import { usePermissions } from '@/lib/permissions'
import { formatDate, formatFileSize } from '@/lib/utils'
import { Files, Loader2, RefreshCw, FileText, Download, Clock, User, History, Trash2, Settings, AlertTriangle } from 'lucide-react'

type VersionRow = { versionId: string; tags: string[]; date?: string; sha256?: string; size?: number; fileName?: string; path?: string }

interface FileListPaginatedProps { refreshTrigger?: number }

export function FileListPaginated({ refreshTrigger }: FileListPaginatedProps) {
  const { toast } = useToast()
  const { permissions } = usePermissions()
  const searchParams = useSearchParams()
  const router = useRouter()

  const [type, setType] = useState<string>('all')
  const [page, setPage] = useState<number>(1)
  const [limit, setLimit] = useState<number>(20)
  const [count, setCount] = useState<number>(0)
  const [items, setItems] = useState<FileInfo[]>([])
  const [loading, setLoading] = useState<boolean>(true)
  const [downloadingFile, setDownloadingFile] = useState<string | null>(null)

  const [deleteDialog, setDeleteDialog] = useState<{ isOpen: boolean; file: FileInfo | null }>({ isOpen: false, file: null })
  const [versionsDialog, setVersionsDialog] = useState<{ isOpen: boolean; file: FileInfo | null; versions: VersionRow[]; loading: boolean }>({ isOpen: false, file: null, versions: [], loading: false })

  // URL -> local state
  useEffect(() => {
    const t = searchParams?.get('type') || 'all'
    const p = parseInt(searchParams?.get('page') || '1', 10)
    const l = parseInt(searchParams?.get('limit') || '20', 10)
    setType(t)
    setPage(!isNaN(p) && p > 0 ? p : 1)
    setLimit(!isNaN(l) && l > 0 ? Math.min(l, 100) : 20)
  }, [searchParams])

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiClient.getFilesPaginated({ type: type === 'all' ? undefined : type, page, limit })
      setItems(res.files)
      setCount(res.count)
    } catch (e: any) {
      const { title, description } = mapApiErrorToMessage(e)
      toast({ variant: 'destructive', title, description })
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [type, page, limit, refreshTrigger])

  const changeType = (t: string) => {
    const sp = new URLSearchParams(searchParams?.toString())
    if (t && t !== 'all') sp.set('type', t); else sp.delete('type')
    sp.set('page', '1')
    sp.set('limit', String(limit))
    router.push(`?${sp.toString()}`)
  }

  const changeLimit = (l: number) => {
    const sp = new URLSearchParams(searchParams?.toString())
    sp.set('limit', String(l))
    sp.set('page', '1')
    if (type && type !== 'all') sp.set('type', type)
    router.push(`?${sp.toString()}`)
  }

  const goToPage = (p: number) => {
    const total = Math.max(1, Math.ceil(count / Math.max(1, limit)))
    const newPage = Math.max(1, Math.min(total, p))
    const sp = new URLSearchParams(searchParams?.toString())
    sp.set('page', String(newPage))
    sp.set('limit', String(limit))
    if (type && type !== 'all') sp.set('type', type); else sp.delete('type')
    router.push(`?${sp.toString()}`)
  }

  const handleDownload = async (file: FileInfo) => {
    setDownloadingFile(file.path)
    try { await apiClient.downloadFile(file.path) }
    catch (e: any) { const { title, description } = mapApiErrorToMessage(e); toast({ variant:'destructive', title, description }) }
    finally { setDownloadingFile(null) }
  }

  const confirmDelete = async () => {
    if (!deleteDialog.file) return
    try { await apiClient.deleteFile(deleteDialog.file.id); toast({ title:'Success', description:'File moved to recycle bin successfully' }); load() }
    catch (e: any) { const { title, description } = mapApiErrorToMessage(e); toast({ variant:'destructive', title, description }) }
    finally { setDeleteDialog({ isOpen:false, file:null }) }
  }

  const handleViewVersions = async (file: FileInfo) => {
    const ftype = (file.fileType === 'roadmap' || file.fileType === 'recommendation') ? file.fileType : null
    if (!ftype) { toast({ variant:'destructive', title:'Unsupported', description:'Version history is only for roadmap/recommendation' }); return }
    setVersionsDialog(prev => ({ ...prev, isOpen:true, file, versions:[], loading:true }))
    try {
      const list = await apiClient.getVersionsListWeb(ftype)
      const items = Array.isArray((list as any).versions) ? (list as any).versions : []
      items.sort((a: any, b: any) => (b.date || '').localeCompare(a.date || ''))
      const rows: VersionRow[] = await Promise.all(items.map(async (it: any) => {
        let sha256: string | undefined; let size: number | undefined; let fileName: string | undefined; let path: string | undefined
        try { const mf = await apiClient.getVersionManifestWeb(ftype, it.version_id); sha256 = mf?.artifact?.sha256; size = mf?.artifact?.size; fileName = mf?.artifact?.file_name; path = mf?.artifact?.path } catch {}
        return { versionId: it.version_id, tags: it.tags || [], date: it.date, sha256, size, fileName, path }
      }))
      setVersionsDialog(prev => ({ ...prev, versions: rows, loading: false }))
    } catch (e: any) {
      const { title, description } = mapApiErrorToMessage(e)
      toast({ variant:'destructive', title, description })
      setVersionsDialog(prev => ({ ...prev, loading:false }))
    }
  }

  const totalPages = Math.max(1, Math.ceil(count / Math.max(1, limit)))

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2"><Files className="h-5 w-5"/> File Management</CardTitle>
              <CardDescription>Manage uploaded Roadmaps (.tsv) and Recommendations (.xlsx)</CardDescription>
            </div>
            <div className="flex items-center gap-3">
              <Select value={type} onValueChange={changeType}>
                <SelectTrigger className="w-40"><SelectValue placeholder="Filter by type"/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Files</SelectItem>
                  <SelectItem value="roadmap">Roadmaps</SelectItem>
                  <SelectItem value="recommendation">Recommendations</SelectItem>
                </SelectContent>
              </Select>
              <Select value={String(limit)} onValueChange={(v)=> changeLimit(parseInt(v,10))}>
                <SelectTrigger className="w-32"><SelectValue placeholder="Page size"/></SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10 / page</SelectItem>
                  <SelectItem value="20">20 / page</SelectItem>
                  <SelectItem value="50">50 / page</SelectItem>
                  <SelectItem value="100">100 / page</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={load}><RefreshCw className="h-4 w-4 mr-2"/>Refresh</Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-gray-500"><Loader2 className="h-4 w-4 mr-2 animate-spin"/> Loading files...</div>
          ) : (
            <>
              <FileTable files={items} onDownload={handleDownload} onViewVersions={handleViewVersions} onDelete={permissions?.canManageFiles ? (f)=> setDeleteDialog({ isOpen:true, file:f }) : undefined} downloadingFile={downloadingFile} showVersions={type === 'roadmap' || type === 'recommendation'}/>
              <div className="flex items-center justify-between mt-4 text-sm text-gray-600">
                <div>Page {page} / {totalPages} · {count} items</div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" disabled={page<=1} onClick={()=>goToPage(1)}>First</Button>
                  <Button variant="outline" size="sm" disabled={page<=1} onClick={()=>goToPage(page-1)}>Prev</Button>
                  <Button variant="outline" size="sm" disabled={page>=totalPages} onClick={()=>goToPage(page+1)}>Next</Button>
                  <Button variant="outline" size="sm" disabled={page>=totalPages} onClick={()=>goToPage(totalPages)}>Last</Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialog.isOpen} onOpenChange={(open) => setDeleteDialog({ isOpen: open, file: null })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-600">
              <AlertTriangle className="h-5 w-5" />
              Confirm Delete
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to delete "<strong>{deleteDialog.file?.originalName}</strong>"?
              The file will be moved to the recycle bin and can be restored later.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialog({ isOpen: false, file: null })}>Cancel</Button>
            <Button variant="destructive" onClick={confirmDelete}><Trash2 className="mr-2 h-4 w-4" /> Move to Recycle Bin</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Versions dialog */}
      <Dialog open={versionsDialog.isOpen} onOpenChange={(open)=> setVersionsDialog(prev => ({ ...prev, isOpen: open }))}>
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><History className="h-5 w-5"/> Version History - {versionsDialog.file?.originalName || versionsDialog.file?.fileName}</DialogTitle>
            <DialogDescription>View and download all versions of this file</DialogDescription>
          </DialogHeader>
          <div className="max-h-[60vh] overflow-y-auto">
            {versionsDialog.loading ? (
              <div className="p-6 text-sm text-gray-500 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin"/> Loading versions...</div>
            ) : (versionsDialog.versions.length === 0 ? (
              <div className="p-6 text-sm text-gray-500">No versions</div>
            ) : (
              <table className="w-full table-fixed text-sm">
                <thead>
                  <tr className="text-left border-b text-gray-600 bg-gray-50">
                    <th className="py-3 px-4 w-56 font-medium text-xs uppercase tracking-wide">Version ID</th>
                    <th className="py-3 px-4 font-medium text-xs uppercase tracking-wide">Tags</th>
                    <th className="py-3 px-4 w-40 font-medium text-xs uppercase tracking-wide">Date</th>
                    <th className="py-3 px-4 w-44 font-medium text-xs uppercase tracking-wide">SHA256</th>
                    <th className="py-3 px-4 w-24 font-medium text-xs uppercase tracking-wide">Size</th>
                    <th className="py-3 px-4 w-40 font-medium text-xs uppercase tracking-wide">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {versionsDialog.versions.map(v => (
                    <tr key={v.versionId} className="border-b last:border-0 hover:bg-gray-50">
                      <td className="py-3 px-4 font-mono text-sm truncate" title={v.versionId}>{v.versionId}</td>
                      <td className="py-3 px-4 text-sm truncate" title={(v.tags||[]).join(', ')}>{(v.tags||[]).length ? v.tags.join(', ') : <span className="text-gray-400">-</span>}</td>
                      <td className="py-3 px-4 text-sm text-gray-600 truncate" title={v.date || ''}>{v.date ? formatDate(v.date) : ''}</td>
                      <td className="py-3 px-4 font-mono text-sm truncate" title={v.sha256 || ''}>{v.sha256 ? v.sha256.slice(0, 12) : ''}</td>
                      <td className="py-3 px-4 text-sm">{typeof v.size === 'number' ? formatFileSize(v.size) : ''}</td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          {v.path && (<Button variant="outline" size="sm" onClick={() => apiClient.downloadFile(v.path!)} title="Download file"><Download className="h-4 w-4" /></Button>)}
                          {permissions?.canManageFiles && (
                            <Button variant="ghost" size="sm" title="Edit tags"><Settings className="h-4 w-4" /> Edit Tags</Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

interface FileTableProps {
  files: FileInfo[]
  onDownload: (file: FileInfo) => void
  onViewVersions?: (file: FileInfo) => void
  onDelete?: (file: FileInfo) => void
  downloadingFile: string | null
  showVersions?: boolean
}

function FileTable({ files, onDownload, onViewVersions, onDelete, downloadingFile, showVersions = false }: FileTableProps) {
  if (files.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <FileText className="h-12 w-12 mx-auto mb-4 text-gray-300" />
        <p>No files</p>
      </div>
    )
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b text-left text-sm text-gray-500">
            <th className="pb-4 font-medium w-1/3">File Name</th>
            <th className="pb-4 font-medium w-20">Size</th>
            <th className="pb-4 font-medium w-32">Upload Time</th>
            <th className="pb-4 font-medium w-24">Uploader</th>
            {showVersions && <th className="pb-4 font-medium w-16">Version</th>}
            <th className="pb-4 font-medium w-32">Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id || file.path} className="border-b last:border-0 hover:bg-gray-50">
              <td className="py-4">
                <div className="flex items-center gap-3">
                  <div className="flex-shrink-0"><FileText className="h-5 w-5 text-gray-400" /></div>
                  <div>
                    <div className="font-medium text-gray-900">{file.originalName || file.fileName}</div>
                    {file.description && (<div className="text-sm text-gray-500 mt-1">{file.description}</div>)}
                  </div>
                </div>
              </td>
              <td className="py-4 text-sm text-gray-600">{formatFileSize(file.size)}</td>
              <td className="py-4 text-sm text-gray-600"><div className="flex items-center gap-2"><Clock className="h-3 w-3" /><span>{formatDate(file.uploadTime)}</span></div></td>
              <td className="py-4 text-sm text-gray-600"><div className="flex items-center gap-2"><User className="h-3 w-3" /><span>{file.uploader || 'unknown'}</span></div></td>
              {showVersions && (<td className="py-4 text-sm text-gray-600 font-mono">v{file.version}</td>)}
              <td className="py-4">
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => onDownload(file)} disabled={downloadingFile === file.path}>{downloadingFile === file.path ? (<Loader2 className="h-4 w-4 animate-spin" />) : (<Download className="h-4 w-4" />)}</Button>
                  {!showVersions && onViewVersions && (<Button variant="ghost" size="sm" onClick={() => onViewVersions(file)} title="View Version History"><History className="h-4 w-4" /></Button>)}
                  {!showVersions && onDelete && (<Button variant="ghost" size="sm" onClick={() => onDelete(file)} className="text-red-600 hover:text-red-700 hover:bg-red-50" title="Delete File"><Trash2 className="h-4 w-4" /></Button>)}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

