'use client'

import { useEffect, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { apiClient, type FileInfo } from '@/lib/api'
import { useToast } from '@/lib/use-toast'
import { mapApiErrorToMessage } from '@/lib/errors'
import { usePermissions } from '@/lib/permissions'
import { formatDate, formatFileSize } from '@/lib/utils'
import { Files, Loader2, RefreshCw, FileText, Download, Clock, User, History, Trash2, Settings, AlertTriangle, Edit } from 'lucide-react'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

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
  const [editTagsDialog, setEditTagsDialog] = useState<{ isOpen: boolean; versionId: string; fileType: 'roadmap' | 'recommendation' | null; currentTags: string; loading: boolean }>({ isOpen: false, versionId: '', fileType: null, currentTags: '', loading: false })

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
      // 只显示最新版本的文件
      const latestFiles = res.files.filter(file => file.isLatest)

      // 定义文件类型显示顺序，roadmap 始终在 recommendation 之前
      const fileTypeOrder = ['roadmap', 'recommendation']

      // 对文件按类型排序，确保 roadmap 始终在 recommendation 之前
      const sortedFiles = latestFiles.sort((a, b) => {
        const aIndex = fileTypeOrder.indexOf(a.fileType)
        const bIndex = fileTypeOrder.indexOf(b.fileType)

        // 如果两个文件类型都在排序数组中，按顺序排序
        if (aIndex !== -1 && bIndex !== -1) {
          return aIndex - bIndex
        }

        // 如果一个文件类型在排序数组中，另一个不在，在排序数组中的排在前面
        if (aIndex !== -1) return -1
        if (bIndex !== -1) return 1

        // 如果都不在排序数组中，保持原顺序
        return 0
      })

      setItems(sortedFiles)
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
              {false && (
                <Select value={type} onValueChange={changeType}>
                  <SelectTrigger className="w-40"><SelectValue placeholder="Filter by type"/></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Files</SelectItem>
                    <SelectItem value="roadmap">Roadmaps</SelectItem>
                    <SelectItem value="recommendation">Recommendations</SelectItem>
                  </SelectContent>
                </Select>
              )}
              {false && (
                <Select value={String(limit)} onValueChange={(v)=> changeLimit(parseInt(v,10))}>
                  <SelectTrigger className="w-32"><SelectValue placeholder="Page size"/></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="10">10 / page</SelectItem>
                    <SelectItem value="20">20 / page</SelectItem>
                    <SelectItem value="50">50 / page</SelectItem>
                    <SelectItem value="100">100 / page</SelectItem>
                  </SelectContent>
                </Select>
              )}
              <Button variant="outline" size="sm" onClick={load}><RefreshCw className="h-4 w-4 mr-2"/>Refresh</Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-12 text-gray-500"><Loader2 className="h-4 w-4 mr-2 animate-spin"/> Loading files...</div>
          ) : (
              <>
              <FileTable files={items} onDownload={handleDownload} onViewVersions={handleViewVersions} onDelete={permissions?.canManageFiles ? (f)=> setDeleteDialog({ isOpen:true, file:f }) : undefined} downloadingFile={downloadingFile} showVersions={false}/>
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
              Are you sure you want to delete "<strong>{deleteDialog.file?.fileName}</strong>"?
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
        <DialogContent className="max-w-6xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><History className="h-5 w-5"/> Version History - {versionsDialog.file?.fileName}</DialogTitle>
            <DialogDescription>View and download all versions of this file</DialogDescription>
          </DialogHeader>
          <div className="max-h-[60vh] overflow-y-auto">
            {versionsDialog.loading ? (
              <div className="p-6 text-sm text-gray-500 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin"/> Loading versions...</div>
            ) : (versionsDialog.versions.length === 0 ? (
              <div className="p-6 text-sm text-gray-500">No versions</div>
            ) : (
              <div className="border rounded-md">
                <table className="w-full text-sm">
                  <thead className="bg-muted">
                    <tr>
                      <th className="text-left p-3 w-40">Version</th>
                      <th className="text-left p-3 w-44">Date</th>
                      <th className="text-left p-3 w-32">SHA256</th>
                      <th className="text-left p-3 w-48">Tags</th>
                      <th className="text-left p-3 w-20">Size</th>
                      <th className="text-left p-3 w-20">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {versionsDialog.versions.map((v, index) => (
                      <tr key={v.versionId} className="border-t hover:bg-muted/50">
                        <td className="p-3 w-40">
                          <div className="flex items-center gap-2">
                            {index === 0 && (
                              <Badge variant="default" className="text-xs bg-green-600 hover:bg-green-700">
                                Latest
                              </Badge>
                            )}
                            <div className="font-mono text-sm" title={v.versionId}>
                              {v.versionId}
                            </div>
                          </div>
                        </td>
                        <td className="p-3 w-44">
                          <div className="text-sm whitespace-nowrap">
                            {v.date ? formatDate(v.date) : ''}
                          </div>
                        </td>
                        <td className="p-3 w-32">
                          <div className="font-mono text-sm truncate" title={v.sha256 || ''}>
                            {v.sha256 ? v.sha256.slice(0, 12) : ''}
                          </div>
                        </td>
                        <td className="p-3 w-48">
                          <div className="text-sm truncate" title={(v.tags||[]).join(', ')}>
                            {(v.tags||[]).length ? v.tags.join(', ') : <span className="text-muted-foreground">-</span>}
                          </div>
                        </td>
                        <td className="p-3 w-20">
                          <div className="text-sm">
                            {typeof v.size === 'number' ? formatFileSize(v.size) : ''}
                          </div>
                        </td>
                        <td className="p-3 w-20">
                          <div className="flex items-center gap-1">
                            {v.path && (
                              <Button 
                                variant="ghost" 
                                size="sm" 
                                onClick={() => apiClient.downloadFile(v.path!)} 
                                title="Download"
                                className="h-7 px-2"
                              >
                                <Download className="h-3 w-3" />
                              </Button>
                            )}
                            {permissions?.canManageFiles && (
                              <Button 
                                variant="ghost" 
                                size="sm" 
                                onClick={() => {
                                  const fileType = versionsDialog.file?.fileType as 'roadmap' | 'recommendation'
                                  setEditTagsDialog({
                                    isOpen: true,
                                    versionId: v.versionId,
                                    fileType: fileType,
                                    currentTags: (v.tags || []).join(', '),
                                    loading: false
                                  })
                                }}
                                title="Edit tags"
                                className="h-7 px-2"
                              >
                                <Edit className="h-3 w-3" />
                              </Button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        </DialogContent>
      </Dialog>

      {/* Edit Tags Dialog */}
      <Dialog open={editTagsDialog.isOpen} onOpenChange={(open) => setEditTagsDialog(prev => ({ ...prev, isOpen: open }))}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Version Tags</DialogTitle>
            <DialogDescription>
              Edit tags for version {editTagsDialog.versionId}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label htmlFor="tags">Tags (comma-separated)</Label>
              <Input
                id="tags"
                value={editTagsDialog.currentTags}
                onChange={(e) => setEditTagsDialog(prev => ({ ...prev, currentTags: e.target.value }))}
                placeholder="Enter tags separated by commas"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditTagsDialog(prev => ({ ...prev, isOpen: false }))}>
              Cancel
            </Button>
            <Button 
              onClick={async () => {
                if (!editTagsDialog.fileType || !editTagsDialog.versionId) return
                
                setEditTagsDialog(prev => ({ ...prev, loading: true }))
                try {
                  const tags = editTagsDialog.currentTags.split(',').map(t => t.trim()).filter(Boolean)
                  await apiClient.updateVersionTagsWeb(editTagsDialog.fileType, editTagsDialog.versionId, tags)
                  
                  // Refresh the versions dialog to show updated tags
                  if (versionsDialog.file) {
                    await handleViewVersions(versionsDialog.file)
                  }
                  
                  // Force refresh the main file list to show updated tags
                  load()
                  
                  setEditTagsDialog(prev => ({ ...prev, isOpen: false, loading: false }))
                  toast({ title: 'Success', description: 'Tags updated successfully' })
                } catch (e: any) {
                  const { title, description } = mapApiErrorToMessage(e)
                  toast({ variant: 'destructive', title, description })
                  setEditTagsDialog(prev => ({ ...prev, loading: false }))
                }
              }}
              disabled={editTagsDialog.loading}
            >
              {editTagsDialog.loading ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : null}
              Save
            </Button>
          </DialogFooter>
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
    <div className="border rounded-md">
      <table className="w-full text-sm">
        <thead className="bg-muted">
          <tr>
            <th className="text-left p-3 font-medium">File Name</th>
            <th className="text-left p-3 font-medium w-20">Size</th>
            <th className="text-left p-3 font-medium w-32">Upload Time</th>
            <th className="text-left p-3 font-medium w-24">Uploader</th>
            {showVersions && <th className="text-left p-3 font-medium w-16">Version</th>}
            <th className="text-left p-3 font-medium w-32">Actions</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id || file.path} className="border-t hover:bg-muted/50">
              <td className="p-3">
                <div className="flex items-center gap-3">
                  <div className="flex-shrink-0"><FileText className="h-5 w-5 text-gray-400" /></div>
                  <div>
                    <div className="font-medium text-gray-900">{file.fileName}</div>
                    {file.description && (<div className="text-sm text-gray-500 mt-1">{file.description}</div>)}
                  </div>
                </div>
              </td>
              <td className="p-3 text-sm text-gray-600">{formatFileSize(file.size)}</td>
              <td className="p-3 text-sm text-gray-600"><div className="flex items-center gap-2 whitespace-nowrap"><Clock className="h-3 w-3 flex-shrink-0" /><span>{formatDate(file.uploadTime)}</span></div></td>
              <td className="p-3 text-sm text-gray-600"><div className="flex items-center gap-2"><User className="h-3 w-3" /><span>{file.uploader || 'unknown'}</span></div></td>
              {showVersions && (<td className="p-3 text-sm text-gray-600 font-mono">v{file.version}</td>)}
              <td className="p-3">
                <div className="flex items-center gap-2">
                  <Button variant="ghost" size="sm" onClick={() => onDownload(file)} disabled={downloadingFile === file.path} title="Download File">{downloadingFile === file.path ? (<Loader2 className="h-4 w-4 animate-spin" />) : (<Download className="h-4 w-4" />)}</Button>
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

