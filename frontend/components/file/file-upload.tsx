'use client'

import { useState, useCallback, useEffect } from "react"
import { useDropzone } from "react-dropzone"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient, type FileInfo } from "@/lib/api"
import { mapApiErrorToMessage } from "@/lib/errors"
import { formatFileSize } from "@/lib/utils"
import { Upload, FileText, Loader2, CheckCircle, AlertCircle, X } from "lucide-react"

interface FileUploadProps {
  onUploadComplete?: (file: FileInfo) => void
}

// Allowed upload types: Roadmap (.tsv) and Recommendation (.xlsx)
const allowedFileTypes = [
  { value: "roadmap", label: "Roadmap (.tsv)", extensions: [".tsv"] },
  { value: "recommendation", label: "Recommendation (.xlsx)", extensions: [".xlsx"] }
]

const fileTypes = [
  { value: "config", label: "Configuration Files", extensions: [".json"], icon: "⚙️" },
  { value: "certificate", label: "Certificate Files", extensions: [".crt", ".key", ".pem"], icon: "🔐" },
  { value: "docs", label: "Document Files", extensions: [".txt", ".log"], icon: "📄" }
]

export function FileUpload({ onUploadComplete }: FileUploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileType, setFileType] = useState("")
  const [description, setDescription] = useState("")
  const [versionTags, setVersionTags] = useState("")
  const [isUploading, setIsUploading] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [uploadResult, setUploadResult] = useState<{
    success: boolean
    message: string
    file?: FileInfo
  } | null>(null)
  const [maxBytes, setMaxBytes] = useState(128 * 1024 * 1024)
  // Optionally fetch from backend API info
  useEffect(() => {
    (async () => {
      try {
        const info = await apiClient.getApiInfo()
        const b = (info?.upload_limits?.max_upload_bytes as number) || 0
        if (b > 0) setMaxBytes(b)
      } catch { /* ignore */ }
    })()
  }, [])

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0]
    if (file) {
      if (file.size > maxBytes) {
        setUploadResult({ success: false, message: `File is too large. Max ${(maxBytes/(1024*1024)).toFixed(0)} MB` })
        return
      }
      setSelectedFile(file)
      // 根据文件扩展名自动选择类型
      const ext = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
      const detectedType = allowedFileTypes.find(type =>
        type.extensions.includes(ext)
      )
      if (detectedType) {
        setFileType(detectedType.value)
      }
    }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'text/tab-separated-values': ['.tsv'],
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx']
    },
    maxFiles: 1,
    multiple: false
  })

  const handleUpload = async () => {
    if (!selectedFile || !fileType) return
    if (selectedFile.size > maxBytes) {
      setUploadResult({ success: false, message: `File is too large. Max ${(maxBytes/(1024*1024)).toFixed(0)} MB` })
      return
    }

    setIsUploading(true)
    try {
      const result = await apiClient.uploadFile(selectedFile, fileType, description, versionTags)
      setUploadResult({
        success: true,
        message: "File uploaded successfully!",
        file: result
      })
      onUploadComplete?.(result)

      // 重置表单
      setSelectedFile(null)
      setFileType("")
      setDescription("")
      setVersionTags("")
    } catch (error: any) {
      const { title, description } = mapApiErrorToMessage(error)
      setUploadResult({ success: false, message: `${title}: ${description}` })
    } finally {
      setIsUploading(false)
      setShowConfirmDialog(false)
    }
  }

  const isValidFile = selectedFile && fileType &&
    allowedFileTypes.find(type => type.value === fileType)?.extensions
      .some(ext => selectedFile.name.toLowerCase().endsWith(ext))

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            File Upload
          </CardTitle>
          <CardDescription>
            Upload Roadmap (.tsv) and Recommendation (.xlsx) files
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* 拖拽上传区域 */}
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
              isDragActive
                ? "border-primary bg-primary/5"
                : "border-gray-300 hover:border-gray-400"
            }`}
          >
            <input {...getInputProps()} />
            <div className="flex flex-col items-center space-y-4">
              <div className="p-4 bg-gray-100 rounded-full">
                <Upload className="h-8 w-8 text-gray-600" />
              </div>
              {selectedFile ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-sm font-medium">
                    <FileText className="h-4 w-4" />
                    {selectedFile.name}
                  </div>
                  <div className="text-sm text-gray-500">
                    {formatFileSize(selectedFile.size)}
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <p className="text-lg font-medium">
                    {isDragActive ? "Drop file to upload" : "Click or drag file here"}
                  </p>
                  <p className="text-sm text-gray-500">
                    Supports .tsv (Roadmap) and .xlsx (Recommendation)
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* 文件类型选择 */}
          <div className="space-y-2">
            <Label htmlFor="fileType">File Type</Label>
            <Select value={fileType} onValueChange={setFileType}>
              <SelectTrigger id="fileType">
                <SelectValue placeholder="Select file type" />
              </SelectTrigger>
              <SelectContent>
                {allowedFileTypes.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    <div className="flex items-center gap-2">
                      <div>
                        <div>{type.label}</div>
                        <div className="text-xs text-muted-foreground">
                          {type.extensions.join(", ")}
                        </div>
                      </div>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* 文件描述 */}
          <div className="space-y-2">
            <Label htmlFor="description">File Description (Optional)</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value.slice(0, 200))}
              placeholder="Enter file description (max 200 characters)"
              maxLength={200}
            />
          </div>

          {/* Version Tags */}
          <div className="space-y-2">
            <Label htmlFor="tags">Version Tags (Optional)</Label>
            <Input
              id="tags"
              value={versionTags}
              onChange={(e) => setVersionTags(e.target.value)}
              placeholder="comma separated tags"
            />
          </div>

          {/* 上传按钮 */}
          <Button
            onClick={() => setShowConfirmDialog(true)}
            disabled={!isValidFile || isUploading}
            className="w-full"
          >
            {isUploading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Uploading...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                Upload File
              </>
            )}
          </Button>

          {!isValidFile && selectedFile && (
            <div className="text-sm text-red-500 bg-red-50 p-3 rounded-md border border-red-200">
              <AlertCircle className="inline mr-2 h-4 w-4" />
              Please select the correct file type or check if the file extension is valid
            </div>
          )}
        </CardContent>
      </Card>

      {/* 确认上传对话框 */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm Upload</DialogTitle>
            <DialogDescription>
              Please confirm the file information is correct:
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-3 text-sm">
              <div className="flex justify-between">
                <strong>File Name:</strong>
                <span className="text-right max-w-64 truncate" title={selectedFile?.name}>{selectedFile?.name}</span>
              </div>
              <div className="flex justify-between">
                <strong>File Size:</strong>
                <span className="text-right max-w-20 truncate" title={selectedFile ? formatFileSize(selectedFile.size) : undefined}>{selectedFile ? formatFileSize(selectedFile.size) : ''}</span>
              </div>
              <div className="flex justify-between">
                <strong>File Type:</strong>
                <span className="text-right flex-1 ml-2 whitespace-nowrap">{allowedFileTypes.find(t => t.value === fileType)?.label}</span>
              </div>
              <div className="flex justify-between">
                <strong>Description:</strong>
                <span className="text-right max-w-48 truncate" title={description || "None"}>{description || "None"}</span>
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowConfirmDialog(false)}
              disabled={isUploading}
            >
              Cancel
            </Button>
            <Button onClick={handleUpload} disabled={isUploading}>
              {isUploading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Uploading...
                </>
              ) : (
                "Confirm Upload"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* 上传结果提示 */}
      {uploadResult && (
        <Card className={uploadResult.success ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"}>
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {uploadResult.success ? (
                  <CheckCircle className="h-5 w-5 text-green-600" />
                ) : (
                  <AlertCircle className="h-5 w-5 text-red-600" />
                )}
                <span className={uploadResult.success ? "text-green-800" : "text-red-800"}>
                  {uploadResult.message}
                </span>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setUploadResult(null)}
              >
                <X className="h-4 w-4" />
              </Button>
            </div>

            {uploadResult.success && uploadResult.file && (
              <div className="mt-3 text-sm text-green-700">
                File saved as: {uploadResult.file.fileName}
                {uploadResult.file.versionId && (
                  <div className="mt-1">
                    Version ID: <span className="font-mono">{uploadResult.file.versionId}</span>
                  </div>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
