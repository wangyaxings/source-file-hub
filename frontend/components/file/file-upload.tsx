'use client'

import { useState, useCallback, useEffect } from "react"
import { 
  Upload, 
  Button, 
  Card, 
  Input, 
  Select, 
  Modal, 
  message, 
  Typography,
  Space,
  Alert
} from "antd"
import { 
  UploadOutlined, 
  FileTextOutlined, 
  LoadingOutlined, 
  CheckCircleOutlined, 
  ExclamationCircleOutlined,
  InboxOutlined,
  CloseOutlined
} from "@ant-design/icons"
import type { UploadProps, UploadFile } from 'antd'
import { apiClient, type FileInfo } from "@/lib/api"
import { mapApiErrorToMessage } from "@/lib/errors"
import { formatFileSize } from "@/lib/utils"

const { Dragger } = Upload
const { Title, Text } = Typography
const { Option } = Select

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
  const [fileList, setFileList] = useState<UploadFile[]>([])

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

  // AntD Upload props
  const uploadProps: UploadProps = {
    name: 'file',
    multiple: false,
    maxCount: 1,
    accept: '.tsv,.xlsx',
    beforeUpload: (file) => {
      // Check file size
      if (file.size > maxBytes) {
        message.error(`File is too large. Max ${(maxBytes/(1024*1024)).toFixed(0)} MB`)
        return false
      }
      
      // Auto-detect file type based on extension
      const ext = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
      const detectedType = allowedFileTypes.find(type =>
        type.extensions.includes(ext)
      )
      if (detectedType) {
        setFileType(detectedType.value)
      }
      
      setSelectedFile(file)
      setFileList([{
        uid: file.name,
        name: file.name,
        status: 'done',
        size: file.size,
      }])
      
      // Prevent auto upload
      return false
    },
    onRemove: () => {
      setSelectedFile(null)
      setFileList([])
      setFileType("")
    },
    fileList,
  }

  const handleUpload = async () => {
    if (!selectedFile || !fileType) return
    if (selectedFile.size > maxBytes) {
      message.error(`File is too large. Max ${(maxBytes/(1024*1024)).toFixed(0)} MB`)
      return
    }

    setIsUploading(true)
    try {
      const result = await apiClient.uploadFile(selectedFile, fileType, description, versionTags)
      message.success("File uploaded successfully!")
      onUploadComplete?.(result)

      // 重置表单
      setSelectedFile(null)
      setFileList([])
      setFileType("")
      setDescription("")
      setVersionTags("")
      setUploadResult({
        success: true,
        message: "File uploaded successfully!",
        file: result
      })
    } catch (error: any) {
      const { title, description: desc } = mapApiErrorToMessage(error)
      const errorMsg = `${title}: ${desc}`
      message.error(errorMsg)
      setUploadResult({ success: false, message: errorMsg })
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
        <div className="p-6">
          <div className="mb-6">
            <Title level={3} className="flex items-center gap-2 mb-2">
              <UploadOutlined />
              File Upload
            </Title>
            <Text type="secondary">
              Upload Roadmap (.tsv) and Recommendation (.xlsx) files
            </Text>
          </div>

          <div className="space-y-4">
            {/* 拖拽上传区域 */}
            <Dragger {...uploadProps}>
              <p className="ant-upload-drag-icon">
                <InboxOutlined />
              </p>
              <p className="ant-upload-text">Click or drag file to this area to upload</p>
              <p className="ant-upload-hint">
                Supports .tsv (Roadmap) and .xlsx (Recommendation) files. Max size: {(maxBytes/(1024*1024)).toFixed(0)} MB
              </p>
            </Dragger>

            {/* 文件类型选择 */}
            <div className="space-y-2">
              <label className="block text-sm font-medium">File Type</label>
              <Select
                value={fileType}
                onChange={setFileType}
                placeholder="Select file type"
                style={{ width: '100%' }}
              >
                {allowedFileTypes.map((type) => (
                  <Option key={type.value} value={type.value}>
                    <div>
                      <div>{type.label}</div>
                      <div className="text-xs text-gray-500">
                        {type.extensions.join(", ")}
                      </div>
                    </div>
                  </Option>
                ))}
              </Select>
            </div>

            {/* 文件描述 */}
            <div className="space-y-2">
              <label className="block text-sm font-medium">File Description (Optional)</label>
              <Input
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Enter file description"
              />
            </div>

            {/* Version Tags */}
            <div className="space-y-2">
              <label className="block text-sm font-medium">Version Tags (Optional)</label>
              <Input
                value={versionTags}
                onChange={(e) => setVersionTags(e.target.value)}
                placeholder="comma separated, e.g. v1.2.3, Q3-Final"
              />
            </div>

            {/* 上传按钮 */}
            <Button
              type="primary"
              onClick={() => setShowConfirmDialog(true)}
              disabled={!isValidFile || isUploading}
              loading={isUploading}
              icon={<UploadOutlined />}
              block
            >
              {isUploading ? 'Uploading...' : 'Upload File'}
            </Button>

            {!isValidFile && selectedFile && (
              <Alert
                message="Please select the correct file type or check if the file extension is valid"
                type="error"
                showIcon
              />
            )}
          </div>
        </div>
      </Card>

      {/* 确认上传对话框 */}
      <Modal
        title="Confirm Upload"
        open={showConfirmDialog}
        onCancel={() => setShowConfirmDialog(false)}
        footer={[
          <Button key="cancel" onClick={() => setShowConfirmDialog(false)} disabled={isUploading}>
            Cancel
          </Button>,
          <Button key="upload" type="primary" onClick={handleUpload} loading={isUploading}>
            Confirm Upload
          </Button>
        ]}
      >
        <div className="space-y-4">
          <Text>Please confirm the file information is correct:</Text>
          <div className="space-y-3 text-sm">
            <div className="flex justify-between">
              <strong>File Name:</strong>
              <span className="text-right flex-1 ml-2">{selectedFile?.name}</span>
            </div>
            <div className="flex justify-between">
              <strong>File Size:</strong>
              <span className="text-right flex-1 ml-2">{selectedFile && formatFileSize(selectedFile.size)}</span>
            </div>
            <div className="flex justify-between">
              <strong>File Type:</strong>
              <span className="text-right flex-1 ml-2 whitespace-nowrap">{allowedFileTypes.find(t => t.value === fileType)?.label}</span>
            </div>
            <div className="flex justify-between">
              <strong>Description:</strong>
              <span className="text-right flex-1 ml-2">{description || "None"}</span>
            </div>
          </div>
        </div>
      </Modal>

      {/* 上传结果提示 */}
      {uploadResult && (
        <Alert
          message={uploadResult.message}
          type={uploadResult.success ? "success" : "error"}
          showIcon
          closable
          onClose={() => setUploadResult(null)}
          description={uploadResult.success && uploadResult.file && (
            <div className="mt-2 text-sm">
              File saved as: {uploadResult.file.fileName}
              {uploadResult.file.versionId && (
                <div className="mt-1">
                  Version ID: <span className="font-mono">{uploadResult.file.versionId}</span>
                </div>
              )}
            </div>
          )}
        />
      )}
    </div>
  )
}
