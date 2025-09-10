'use client'

import { useState, useEffect, useMemo } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient, type FileInfo } from "@/lib/api"
import { formatFileSize, formatDate } from "@/lib/utils"
import { useToast } from "@/lib/use-toast"
import {
  Files,
  Download,
  Clock,
  User,
  FileText,
  Settings,
  Shield,
  BookOpen,
  Loader2,
  RefreshCw,
  History,
  Trash2,
  AlertTriangle
} from "lucide-react"

const fileTypeIcons = {
  roadmap: FileText,
  recommendation: FileText
}

const fileTypeLabels = {
  roadmap: "Roadmaps",
  recommendation: "Recommendations"
}

interface FileListProps {
  refreshTrigger?: number
}

export function FileList({ refreshTrigger }: FileListProps) {
  const { toast } = useToast()
  const [files, setFiles] = useState<FileInfo[]>([])
  const [filteredFiles, setFilteredFiles] = useState<FileInfo[]>([])
  const [selectedType, setSelectedType] = useState<string>("all")
  const [isLoading, setIsLoading] = useState(true)
  const [downloadingFile, setDownloadingFile] = useState<string | null>(null)
  const [deleteDialog, setDeleteDialog] = useState<{
    isOpen: boolean
    file: FileInfo | null
  }>({
    isOpen: false,
    file: null
  })
  type VersionRow = { versionId: string; tags: string[]; date?: string; sha256?: string; size?: number; fileName?: string; path?: string }
  const [versionsDialog, setVersionsDialog] = useState<{
    isOpen: boolean
    file: FileInfo | null
    fileType: 'roadmap'|'recommendation'|null
    versions: VersionRow[]
    loading: boolean
  }>({ isOpen: false, file: null, fileType: null, versions: [], loading: false })
  const [editTags, setEditTags] = useState<{ open: boolean; fileType: 'roadmap'|'recommendation'|null; versionId: string; text: string }>({ open: false, fileType: null, versionId: '', text: '' })

  const currentUser = apiClient.getCurrentUser()
  const isAdmin = currentUser?.role === 'administrator' || currentUser?.username === 'admin'

  const loadFiles = async () => {
    setIsLoading(true)
    try {
      const allFiles = await apiClient.getFiles()
      setFiles(allFiles)
      filterFiles(allFiles, selectedType)
    } catch (error) {
      console.error('Failed to load files:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const filterFiles = (fileList: FileInfo[], type: string) => {
    if (type === "all") {
      setFilteredFiles(fileList)
    } else {
      setFilteredFiles(fileList.filter(file => file.fileType === type))
    }
  }

  const handleViewVersions = async (file: FileInfo) => {
    const type = (file.fileType === 'roadmap' || file.fileType === 'recommendation') ? file.fileType : null
    if (!type) {
      toast({ variant: 'destructive', title: 'Unsupported', description: 'Version history is only for roadmap/recommendation' })
      return
    }
    setVersionsDialog(prev => ({ ...prev, isOpen: true, file, fileType: type, versions: [], loading: true }))
    try {
      const list = await apiClient.getVersionsListWeb(type)
      const items = Array.isArray((list as any).versions) ? (list as any).versions : []
      // sort desc by date
      items.sort((a: any, b: any) => (b.date || '').localeCompare(a.date || ''))
      // fetch manifests for sha256/path/size/file_name
      const rows: VersionRow[] = await Promise.all(items.map(async (it: any) => {
        let sha256: string | undefined
        let size: number | undefined
        let fileName: string | undefined
        let path: string | undefined
        try {
          const mf = await apiClient.getVersionManifestWeb(type, it.version_id)
          sha256 = mf?.artifact?.sha256
          size = mf?.artifact?.size
          fileName = mf?.artifact?.file_name
          path = mf?.artifact?.path
        } catch {}
        return { versionId: it.version_id, tags: it.tags || [], date: it.date, sha256, size, fileName, path }
      }))
      setVersionsDialog(prev => ({ ...prev, versions: rows, loading: false }))
    } catch (e) {
      console.error('Load versions failed', e)
      toast({ variant: 'destructive', title: 'Failed to load versions', description: e instanceof Error ? e.message : 'Failed' })
      setVersionsDialog(prev => ({ ...prev, loading: false }))
    }
  }

  const handleTypeChange = (type: string) => {
    setSelectedType(type)
    filterFiles(files, type)
  }

  const handleDownload = async (file: FileInfo) => {
    setDownloadingFile(file.path)
    try {
      await apiClient.downloadFile(file.path)
    } catch (error) {
      console.error('Download failed:', error)
      toast({
        variant: "destructive",
        title: "Download Failed",
        description: error instanceof Error ? error.message : 'Download failed'
      })
    } finally {
      setDownloadingFile(null)
    }
  }

  const handleDelete = (file: FileInfo) => {
    setDeleteDialog({
      isOpen: true,
      file: file
    })
  }

  const confirmDelete = async () => {
    if (!deleteDialog.file) return

    try {
      await apiClient.deleteFile(deleteDialog.file.id)
      toast({
        title: "Success",
        description: 'File moved to recycle bin successfully'
      })
      loadFiles() // Refresh the file list
    } catch (error) {
      console.error('Delete failed:', error)
      toast({
        variant: "destructive",
        title: "Delete Failed",
        description: error instanceof Error ? error.message : 'Delete failed'
      })
    } finally {
      setDeleteDialog({ isOpen: false, file: null })
    }
  }

  useEffect(() => {
    loadFiles()
  }, [refreshTrigger])

  if (isLoading) {
    return (
      <Card>
        <CardContent className="flex items-center justify-center py-12">
          <div className="flex items-center gap-2 text-gray-500">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading file list...
          </div>
        </CardContent>
      </Card>
    )
  }

  // 按类型分组文件，只显示最新版本
  const latestFiles = files.filter(file => file.isLatest)
  const groupedFiles = latestFiles.reduce((acc, file) => {
    if (!acc[file.fileType]) {
      acc[file.fileType] = []
    }
    acc[file.fileType].push(file)
    return acc
  }, {} as Record<string, FileInfo[]>)

  return (
    <div className="space-y-6">
      {/* 头部控制 */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Files className="h-5 w-5" />
                File Management
              </CardTitle>
              <CardDescription>
                Manage uploaded Roadmaps (.tsv) and Recommendations (.xlsx)
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Select value={selectedType} onValueChange={handleTypeChange}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Files</SelectItem>
                  <SelectItem value="roadmap">Roadmaps</SelectItem>
                  <SelectItem value="recommendation">Recommendations</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={loadFiles}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* 文件列表 */}
      {selectedType === "all" ? (
        // 分组显示
        <div className="space-y-6">
          {Object.entries(groupedFiles).map(([type, typeFiles]) => {
            const Icon = (fileTypeIcons as any)[type] || FileText
            const label = (fileTypeLabels as any)[type] || type
            return (
              <Card key={type}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Icon className="h-5 w-5" />
                    {label}
                    <span className="text-sm font-normal text-gray-500">
                      ({typeFiles.length} files)
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <FileTable
                    files={typeFiles}
                    onDownload={handleDownload}
                    onViewVersions={handleViewVersions}
                    onDelete={isAdmin ? handleDelete : undefined}
                    downloadingFile={downloadingFile}
                  />
                </CardContent>
              </Card>
            )
          })}
        </div>
      ) : (
        // 单类型显示
        <Card>
          <CardContent className="pt-6">
            <FileTable
              files={filteredFiles.filter(f => f.isLatest)}
              onDownload={handleDownload}
              onViewVersions={handleViewVersions}
              onDelete={isAdmin ? handleDelete : undefined}
              downloadingFile={downloadingFile}
            />
          </CardContent>
        </Card>
      )}

      {/* 版本历史对话框 */}
      <Dialog
        open={versionsDialog.isOpen}
        onOpenChange={(open) => setVersionsDialog(prev => ({ ...prev, isOpen: open }))}
      >
        <DialogContent className="max-w-4xl max-h-[80vh]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              Version History - {versionsDialog.file?.originalName || versionsDialog.file?.fileName}
            </DialogTitle>
            <DialogDescription>
              View and download all versions of this file, {versionsDialog.versions.length} versions total
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-[60vh] overflow-y-auto">
            {versionsDialog.loading ? (
              <div className="p-6 text-sm text-gray-500 flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin"/> Loading versions...</div>
            ) : (versionsDialog.versions.length === 0 ? (
              <div className="p-6 text-sm text-gray-500">No versions</div>
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left border-b">
                    <th className="py-2 w-64">Version ID</th>
                    <th className="py-2">Tags</th>
                    <th className="py-2 w-40">Date</th>
                    <th className="py-2 w-40">SHA256</th>
                    <th className="py-2 w-24">Size</th>
                    <th className="py-2 w-40">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {versionsDialog.versions.map(v => (
                    <tr key={v.versionId} className="border-b last:border-0">
                      <td className="py-2 font-mono">{v.versionId}</td>
                      <td className="py-2">
                        {(v.tags || []).length === 0 ? (
                          <span className="text-gray-400">—</span>
                        ) : (
                          <span>{v.tags.join(', ')}</span>
                        )}
                      </td>
                      <td className="py-2 text-gray-600">{v.date ? formatDate(v.date) : ''}</td>
                      <td className="py-2 font-mono">{v.sha256 ? v.sha256.slice(0, 12) : ''}</td>
                      <td className="py-2">{typeof v.size === 'number' ? formatFileSize(v.size) : ''}</td>
                      <td className="py-2">
                        <div className="flex items-center gap-2">
                          {v.path && (
                            <Button variant="outline" size="sm" onClick={() => apiClient.downloadFile(v.path!)}>
                              <Download className="h-4 w-4" />
                            </Button>
                          )}
                          {isAdmin && (
                            <Button variant="ghost" size="sm" onClick={() => setEditTags({ open: true, fileType: versionsDialog.fileType, versionId: v.versionId, text: (v.tags||[]).join(', ') })}>
                              <Settings className="h-4 w-4" /> Edit Tags
                            </Button>
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

      {/* Edit Tags Dialog */}
      <Dialog open={editTags.open} onOpenChange={(open)=> setEditTags(prev => ({ ...prev, open }))}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Version Tags</DialogTitle>
            <DialogDescription>Comma-separated tags for {editTags.versionId}</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <input className="w-full border rounded px-3 py-2 text-sm" value={editTags.text} onChange={(e)=> setEditTags(prev => ({ ...prev, text: e.target.value }))} placeholder="v1.2.3, Q3-Final" />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={()=> setEditTags(prev => ({ ...prev, open: false }))}>Cancel</Button>
            <Button onClick={async ()=>{
              if (!editTags.fileType) return
              const tags = editTags.text.split(',').map(t=>t.trim()).filter(Boolean)
              try{
                await apiClient.updateVersionTagsWeb(editTags.fileType, editTags.versionId, tags)
                // refresh current list
                if (versionsDialog.file) {
                  await handleViewVersions(versionsDialog.file)
                }
                setEditTags(prev => ({ ...prev, open: false }))
              }catch(e){
                toast({ variant:'destructive', title:'Update failed', description: e instanceof Error ? e.message : 'Failed' })
              }
            }}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

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
            <Button
              variant="outline"
              onClick={() => setDeleteDialog({ isOpen: false, file: null })}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={confirmDelete}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Move to Recycle Bin
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
                  <div className="flex-shrink-0">
                    <FileText className="h-5 w-5 text-gray-400" />
                  </div>
                  <div>
                    <div className="font-medium text-gray-900">
                      {file.originalName || file.fileName}
                    </div>
                    {file.description && (
                      <div className="text-sm text-gray-500 mt-1">{file.description}</div>
                    )}
                  </div>
                </div>
              </td>
              <td className="py-4 text-sm text-gray-600">
                {formatFileSize(file.size)}
              </td>
              <td className="py-4 text-sm text-gray-600">
                <div className="flex items-center gap-2">
                  <Clock className="h-3 w-3" />
                  <span>{formatDate(file.uploadTime)}</span>
                </div>
              </td>
              <td className="py-4 text-sm text-gray-600">
                <div className="flex items-center gap-2">
                  <User className="h-3 w-3" />
                  <span>{file.uploader || "unknown"}</span>
                </div>
              </td>
              {showVersions && (
                <td className="py-4 text-sm text-gray-600 font-mono">
                  v{file.version}
                </td>
              )}
              <td className="py-4">
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => onDownload(file)}
                    disabled={downloadingFile === file.path}
                  >
                    {downloadingFile === file.path ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <Download className="h-4 w-4" />
                    )}
                  </Button>
                  {!showVersions && onViewVersions && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onViewVersions(file)}
                      title="View Version History"
                    >
                      <History className="h-4 w-4" />
                    </Button>
                  )}
                  {!showVersions && onDelete && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onDelete(file)}
                      className="text-red-600 hover:text-red-700 hover:bg-red-50"
                      title="Delete File"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

