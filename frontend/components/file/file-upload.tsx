'use client'

import { useState, useCallback } from "react"
import { useDropzone } from "react-dropzone"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient, type FileInfo } from "@/lib/api"
import { formatFileSize } from "@/lib/utils"
import { Upload, FileText, Loader2, CheckCircle, AlertCircle, X } from "lucide-react"

interface FileUploadProps {
  onUploadComplete?: (file: FileInfo) => void
}

const fileTypes = [
  { value: "config", label: "配置文件", extensions: [".json"], icon: "⚙️" },
  { value: "certificate", label: "证书文件", extensions: [".crt", ".key", ".pem"], icon: "🔐" },
  { value: "docs", label: "文档文件", extensions: [".txt", ".log"], icon: "📄" }
]

export function FileUpload({ onUploadComplete }: FileUploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileType, setFileType] = useState("")
  const [description, setDescription] = useState("")
  const [isUploading, setIsUploading] = useState(false)
  const [showConfirmDialog, setShowConfirmDialog] = useState(false)
  const [uploadResult, setUploadResult] = useState<{
    success: boolean
    message: string
    file?: FileInfo
  } | null>(null)

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0]
    if (file) {
      setSelectedFile(file)
      // 根据文件扩展名自动选择类型
      const ext = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
      const detectedType = fileTypes.find(type =>
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
      'application/json': ['.json'],
      'application/x-x509-ca-cert': ['.crt', '.pem'],
      'application/pkcs8': ['.key'],
      'text/plain': ['.txt', '.log']
    },
    maxFiles: 1,
    multiple: false
  })

  const handleUpload = async () => {
    if (!selectedFile || !fileType) return

    setIsUploading(true)
    try {
      const result = await apiClient.uploadFile(selectedFile, fileType, description)
      setUploadResult({
        success: true,
        message: "文件上传成功！",
        file: result
      })
      onUploadComplete?.(result)

      // 重置表单
      setSelectedFile(null)
      setFileType("")
      setDescription("")
    } catch (error) {
      setUploadResult({
        success: false,
        message: error instanceof Error ? error.message : "上传失败"
      })
    } finally {
      setIsUploading(false)
      setShowConfirmDialog(false)
    }
  }

  const isValidFile = selectedFile && fileType &&
    fileTypes.find(type => type.value === fileType)?.extensions
      .some(ext => selectedFile.name.toLowerCase().endsWith(ext))

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Upload className="h-5 w-5" />
            文件上传
          </CardTitle>
          <CardDescription>
            支持上传配置文件、证书文件和文档文件
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
                    {isDragActive ? "放下文件以上传" : "点击或拖拽文件到此处"}
                  </p>
                  <p className="text-sm text-gray-500">
                    支持 .json, .crt, .key, .pem, .txt, .log 格式
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* 文件类型选择 */}
          <div className="space-y-2">
            <Label htmlFor="fileType">文件类型</Label>
            <Select value={fileType} onValueChange={setFileType}>
              <SelectTrigger id="fileType">
                <SelectValue placeholder="选择文件类型" />
              </SelectTrigger>
              <SelectContent>
                {fileTypes.map((type) => (
                  <SelectItem key={type.value} value={type.value}>
                    <div className="flex items-center gap-2">
                      <span>{type.icon}</span>
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
            <Label htmlFor="description">文件描述 (可选)</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="输入文件描述信息"
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
                上传中...
              </>
            ) : (
              <>
                <Upload className="mr-2 h-4 w-4" />
                上传文件
              </>
            )}
          </Button>

          {!isValidFile && selectedFile && (
            <div className="text-sm text-red-500 bg-red-50 p-3 rounded-md border border-red-200">
              <AlertCircle className="inline mr-2 h-4 w-4" />
              请选择正确的文件类型，或者检查文件扩展名是否正确
            </div>
          )}
        </CardContent>
      </Card>

      {/* 确认上传对话框 */}
      <Dialog open={showConfirmDialog} onOpenChange={setShowConfirmDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>确认上传</DialogTitle>
            <DialogDescription>
              请确认以下文件信息是否正确：
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <strong>文件名:</strong> {selectedFile?.name}
              </div>
              <div>
                <strong>文件大小:</strong> {selectedFile && formatFileSize(selectedFile.size)}
              </div>
              <div>
                <strong>文件类型:</strong> {fileTypes.find(t => t.value === fileType)?.label}
              </div>
              <div>
                <strong>描述:</strong> {description || "无"}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowConfirmDialog(false)}
              disabled={isUploading}
            >
              取消
            </Button>
            <Button onClick={handleUpload} disabled={isUploading}>
              {isUploading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  上传中...
                </>
              ) : (
                "确认上传"
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
                文件已保存为: {uploadResult.file.fileName}
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}