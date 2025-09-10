'use client'

import { useState, useEffect } from "react"
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
  const [versionsDialog, setVersionsDialog] = useState<{
    isOpen: boolean
    file: FileInfo | null
    versions: FileInfo[]
  }>({
    isOpen: false,
    file: null,
    versions: []
  })

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

  const handleViewVersions = async (file: FileInfo) => {
    try {
      const versions = await apiClient.getFileVersions(file.fileType, file.originalName || file.fileName)
      setVersionsDialog({
        isOpen: true,
        file,
        versions
      })
    } catch (error) {
      console.error('Failed to load versions:', error)
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to load file versions'
      })
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
            <FileTable
              files={versionsDialog.versions}
              onDownload={handleDownload}
              downloadingFile={downloadingFile}
              showVersions={true}
            />
          </div>
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
