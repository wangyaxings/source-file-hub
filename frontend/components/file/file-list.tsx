'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient, type FileInfo } from "@/lib/api"
import { formatFileSize, formatDate } from "@/lib/utils"
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
  History
} from "lucide-react"

const fileTypeIcons = {
  config: Settings,
  certificate: Shield,
  docs: BookOpen
}

const fileTypeLabels = {
  config: "配置文件",
  certificate: "证书文件",
  docs: "文档文件"
}

interface FileListProps {
  refreshTrigger?: number
}

export function FileList({ refreshTrigger }: FileListProps) {
  const [files, setFiles] = useState<FileInfo[]>([])
  const [filteredFiles, setFilteredFiles] = useState<FileInfo[]>([])
  const [selectedType, setSelectedType] = useState<string>("all")
  const [isLoading, setIsLoading] = useState(true)
  const [downloadingFile, setDownloadingFile] = useState<string | null>(null)
  const [versionsDialog, setVersionsDialog] = useState<{
    isOpen: boolean
    file: FileInfo | null
    versions: FileInfo[]
  }>({
    isOpen: false,
    file: null,
    versions: []
  })

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
      alert(error instanceof Error ? error.message : '下载失败')
    } finally {
      setDownloadingFile(null)
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
      alert(error instanceof Error ? error.message : '获取版本列表失败')
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
            加载文件列表...
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
                文件管理
              </CardTitle>
              <CardDescription>
                管理已上传的配置文件、证书文件和文档
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Select value={selectedType} onValueChange={handleTypeChange}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">所有文件</SelectItem>
                  <SelectItem value="config">配置文件</SelectItem>
                  <SelectItem value="certificate">证书文件</SelectItem>
                  <SelectItem value="docs">文档文件</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={loadFiles}>
                <RefreshCw className="h-4 w-4 mr-2" />
                刷新
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
            const Icon = fileTypeIcons[type as keyof typeof fileTypeIcons]
            return (
              <Card key={type}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Icon className="h-5 w-5" />
                    {fileTypeLabels[type as keyof typeof fileTypeLabels]}
                    <span className="text-sm font-normal text-gray-500">
                      ({typeFiles.length} 个文件)
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <FileTable
                    files={typeFiles}
                    onDownload={handleDownload}
                    onViewVersions={handleViewVersions}
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
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <History className="h-5 w-5" />
              版本历史 - {versionsDialog.file?.originalName || versionsDialog.file?.fileName}
            </DialogTitle>
            <DialogDescription>
              查看和下载此文件的所有版本
            </DialogDescription>
          </DialogHeader>

          <div className="max-h-96 overflow-y-auto">
            <FileTable
              files={versionsDialog.versions}
              onDownload={handleDownload}
              downloadingFile={downloadingFile}
              showVersions={true}
            />
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
  downloadingFile: string | null
  showVersions?: boolean
}

function FileTable({ files, onDownload, onViewVersions, downloadingFile, showVersions = false }: FileTableProps) {
  if (files.length === 0) {
    return (
      <div className="text-center py-8 text-gray-500">
        <FileText className="h-12 w-12 mx-auto mb-4 text-gray-300" />
        <p>暂无文件</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full">
        <thead>
          <tr className="border-b text-left text-sm text-gray-500">
            <th className="pb-3 font-medium">文件名</th>
            <th className="pb-3 font-medium">大小</th>
            <th className="pb-3 font-medium">上传时间</th>
            <th className="pb-3 font-medium">上传者</th>
            {showVersions && <th className="pb-3 font-medium">版本</th>}
            <th className="pb-3 font-medium">操作</th>
          </tr>
        </thead>
        <tbody>
          {files.map((file) => (
            <tr key={file.id || file.path} className="border-b last:border-0">
              <td className="py-3">
                <div className="flex items-center gap-3">
                  <div className="flex-shrink-0">
                    <FileText className="h-5 w-5 text-gray-400" />
                  </div>
                  <div>
                    <div className="font-medium">
                      {file.originalName || file.fileName}
                    </div>
                    {file.description && (
                      <div className="text-sm text-gray-500">{file.description}</div>
                    )}
                  </div>
                </div>
              </td>
              <td className="py-3 text-sm text-gray-600">
                {formatFileSize(file.size)}
              </td>
              <td className="py-3 text-sm text-gray-600">
                <div className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  {formatDate(file.uploadTime)}
                </div>
              </td>
              <td className="py-3 text-sm text-gray-600">
                <div className="flex items-center gap-1">
                  <User className="h-3 w-3" />
                  {file.uploader || "unknown"}
                </div>
              </td>
              {showVersions && (
                <td className="py-3 text-sm text-gray-600">
                  v{file.version}
                </td>
              )}
              <td className="py-3">
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
                    >
                      <History className="h-4 w-4" />
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