'use client'

import { useSearchParams, useRouter } from "next/navigation"
import { mapApiErrorToMessage } from "@/lib/errors"

import { useState, useEffect, useMemo } from "react"
import { 
  Button, 
  Card, 
  Table, 
  Select, 
  Modal, 
  Space, 
  Typography, 
  Tag, 
  Tooltip, 
  Input,
  message,
  Popconfirm,
  Spin,
  Empty
} from "antd"
import {
  FileOutlined,
  DownloadOutlined,
  ClockCircleOutlined,
  UserOutlined,
  FileTextOutlined,
  SettingOutlined,
  SafetyOutlined,
  BookOutlined,
  LoadingOutlined,
  ReloadOutlined,
  HistoryOutlined,
  DeleteOutlined,
  ExclamationCircleOutlined
} from "@ant-design/icons"
import type { ColumnsType } from 'antd/es/table'
import { apiClient, type FileInfo } from "@/lib/api"
import { formatFileSize, formatDate } from "@/lib/utils"
import { usePermissions } from "@/lib/permissions"

const { Title, Text } = Typography
const { Option } = Select

const fileTypeIcons = {
  roadmap: FileTextOutlined,
  recommendation: FileTextOutlined
}

const fileTypeLabels = {
  roadmap: "Roadmaps",
  recommendation: "Recommendations"
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
  // 浣跨敤鏉冮檺绯荤粺鏇夸唬纭紪鐮佺殑瑙掕壊妫€鏌?
  const { permissions } = usePermissions()

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
      message.error('Version history is only for roadmap/recommendation')
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
      message.error(`Failed to load versions: ${e instanceof Error ? e.message : 'Failed'}`)
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
      message.error(`Download failed: ${error instanceof Error ? error.message : 'Download failed'}`)
    } finally {
      setDownloadingFile(null)
    }
  }


  useEffect(() => {
    loadFiles()
  }, [refreshTrigger])

  if (isLoading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <Space>
            <Spin indicator={<LoadingOutlined style={{ fontSize: 24 }} spin />} />
            <Text>Loading file list...</Text>
          </Space>
        </div>
      </Card>
    )
  }

  // 鎸夌被鍨嬪垎缁勬枃浠讹紝鍙樉绀烘渶鏂扮増鏈?
  const latestFiles = files.filter(file => file.isLatest)
  const groupedFiles = latestFiles.reduce((acc, file) => {
    if (!acc[file.fileType]) {
      acc[file.fileType] = []
    }
    acc[file.fileType].push(file)
    return acc
  }, {} as Record<string, FileInfo[]>)

  // Define table columns for AntD Table
  const columns: ColumnsType<FileInfo> = [
    {
      title: 'File Name',
      dataIndex: 'originalName',
      key: 'name',
      render: (text, record) => (
        <Space>
          <FileTextOutlined />
          <div>
            <div className="font-medium">{text || record.fileName}</div>
            {record.description && (
              <div className="text-sm text-gray-500">{record.description}</div>
            )}
          </div>
        </Space>
      )
    },
    {
      title: 'Size',
      dataIndex: 'size',
      key: 'size',
      render: (size) => formatFileSize(size),
      width: 100
    },
    {
      title: 'Upload Time',
      dataIndex: 'uploadTime',
      key: 'uploadTime',
      render: (time) => (
        <Space>
          <ClockCircleOutlined />
          {formatDate(time)}
        </Space>
      ),
      width: 180
    },
    {
      title: 'Uploader',
      dataIndex: 'uploader',
      key: 'uploader',
      render: (uploader) => (
        <Space>
          <UserOutlined />
          {uploader || "unknown"}
        </Space>
      ),
      width: 120
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Tooltip title="Download">
            <Button
              type="text"
              icon={downloadingFile === record.path ? <LoadingOutlined /> : <DownloadOutlined />}
              onClick={() => handleDownload(record)}
              loading={downloadingFile === record.path}
            />
          </Tooltip>
          <Tooltip title="View Version History">
            <Button
              type="text"
              icon={<HistoryOutlined />}
              onClick={() => handleViewVersions(record)}
            />
          </Tooltip>
          {permissions?.canManageFiles && (
            <Tooltip title="Delete">
              <Popconfirm
                title="Delete file?"
                description="Are you sure you want to move this file to recycle bin?"
                onConfirm={async () => {
                  try {
                    await apiClient.deleteFile(record.id)
                    message.success('File moved to recycle bin successfully')
                    loadFiles() // Refresh the file list
                  } catch (error) {
                    console.error('Delete failed:', error)
                    message.error(`Delete failed: ${error instanceof Error ? error.message : 'Delete failed'}`)
                  }
                }}
                okText="Yes"
                cancelText="No"
              >
                <Button
                  type="text"
                  danger
                  icon={<DeleteOutlined />}
                />
              </Popconfirm>
            </Tooltip>
          )}
        </Space>
      ),
      width: 150
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header Controls */}
      <Card>
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <Title level={3} className="flex items-center gap-2 mb-2">
                <FileOutlined />
                File Management
              </Title>
              <Text type="secondary">
                Manage uploaded Roadmaps (.tsv) and Recommendations (.xlsx)
              </Text>
            </div>
            <Space>
              <Select
                value={selectedType}
                onChange={handleTypeChange}
                style={{ width: 160 }}
              >
                <Option value="all">All Files</Option>
                <Option value="roadmap">Roadmaps</Option>
                <Option value="recommendation">Recommendations</Option>
              </Select>
              <Button icon={<ReloadOutlined />} onClick={loadFiles}>
                Refresh
              </Button>
            </Space>
          </div>
        </div>
      </Card>

      {/* File List */}
      {selectedType === "all" ? (
        // Grouped display
        <div className="space-y-6">
          {Object.entries(groupedFiles).map(([type, typeFiles]) => {
            const Icon = (fileTypeIcons as any)[type] || FileTextOutlined
            const label = (fileTypeLabels as any)[type] || type
            return (
              <Card key={type}>
                <div className="p-6">
                  <Title level={4} className="flex items-center gap-2 mb-4">
                    <Icon />
                    {label}
                    <Tag color="blue">{typeFiles.length} files</Tag>
                  </Title>
                  <Table
                    columns={columns}
                    dataSource={typeFiles}
                    rowKey={(record) => record.id || record.path}
                    pagination={false}
                    size="small"
                  />
                </div>
              </Card>
            )
          })}
        </div>
      ) : (
        // Single type display
        <Card>
          <div className="p-6">
            <Table
              columns={columns}
              dataSource={filteredFiles.filter(f => f.isLatest)}
              rowKey={(record) => record.id || record.path}
              pagination={{
                showSizeChanger: true,
                showQuickJumper: true,
                showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} files`
              }}
            />
          </div>
        </Card>
      )}

      {/* Version History Modal */}
      <Modal
        title={
          <Space>
            <HistoryOutlined />
            Version History - {versionsDialog.file?.originalName || versionsDialog.file?.fileName}
          </Space>
        }
        open={versionsDialog.isOpen}
        onCancel={() => setVersionsDialog(prev => ({ ...prev, isOpen: false }))}
        width={1200}
        footer={null}
      >
        <Text type="secondary" className="block mb-4">
          View and download all versions of this file, {versionsDialog.versions.length} versions total
        </Text>

        {versionsDialog.loading ? (
          <div className="text-center py-8">
            <Spin indicator={<LoadingOutlined style={{ fontSize: 24 }} spin />} />
            <Text className="block mt-2">Loading versions...</Text>
          </div>
        ) : versionsDialog.versions.length === 0 ? (
          <Empty description="No versions found" />
        ) : (
          <Table
            columns={[
              {
                title: 'Version ID',
                dataIndex: 'versionId',
                key: 'versionId',
                render: (text) => <Text code>{text}</Text>,
                width: 200
              },
              {
                title: 'Tags',
                dataIndex: 'tags',
                key: 'tags',
                render: (tags) => (
                  <Space wrap>
                    {tags && tags.length > 0 ? (
                      tags.map((tag: string, index: number) => (
                        <Tag key={index} color="blue">{tag}</Tag>
                      ))
                    ) : (
                      <Text type="secondary">-</Text>
                    )}
                  </Space>
                ),
                width: 150
              },
              {
                title: 'Date',
                dataIndex: 'date',
                key: 'date',
                render: (date) => date ? formatDate(date) : '-',
                width: 150
              },
              {
                title: 'SHA256',
                dataIndex: 'sha256',
                key: 'sha256',
                render: (sha256) => sha256 ? (
                  <Tooltip title={sha256}>
                    <Text code>{sha256.slice(0, 12)}...</Text>
                  </Tooltip>
                ) : '-',
                width: 120
              },
              {
                title: 'Size',
                dataIndex: 'size',
                key: 'size',
                render: (size) => typeof size === 'number' ? formatFileSize(size) : '-',
                width: 100
              },
              {
                title: 'Actions',
                key: 'actions',
                render: (_, record) => (
                  <Space>
                    {record.path && (
                      <Tooltip title="Download file">
                        <Button
                          type="text"
                          icon={<DownloadOutlined />}
                          onClick={() => apiClient.downloadFile(record.path!)}
                        />
                      </Tooltip>
                    )}
                    {permissions?.canManageFiles && (
                      <Tooltip title="Edit tags">
                        <Button
                          type="text"
                          icon={<SettingOutlined />}
                          onClick={() => setEditTags({ 
                            open: true, 
                            fileType: versionsDialog.fileType, 
                            versionId: record.versionId, 
                            text: (record.tags || []).join(', ') 
                          })}
                        />
                      </Tooltip>
                    )}
                  </Space>
                )
              }
            ]}
            dataSource={versionsDialog.versions}
            rowKey="versionId"
            pagination={false}
            size="small"
            scroll={{ y: 400 }}
          />
        )}
      </Modal>

      {/* Edit Tags Modal */}
      <Modal
        title="Edit Version Tags"
        open={editTags.open}
        onCancel={() => setEditTags(prev => ({ ...prev, open: false }))}
        footer={[
          <Button key="cancel" onClick={() => setEditTags(prev => ({ ...prev, open: false }))}>
            Cancel
          </Button>,
          <Button 
            key="save" 
            type="primary" 
            onClick={async () => {
              if (!editTags.fileType) return
              const tags = editTags.text.split(',').map(t => t.trim()).filter(Boolean)
              try {
                await apiClient.updateVersionTagsWeb(editTags.fileType, editTags.versionId, tags)
                // refresh current list
                if (versionsDialog.file) {
                  await handleViewVersions(versionsDialog.file)
                }
                setEditTags(prev => ({ ...prev, open: false }))
                message.success('Tags updated successfully')
              } catch (e) {
                message.error(`Update failed: ${e instanceof Error ? e.message : 'Failed'}`)
              }
            }}
          >
            Save
          </Button>
        ]}
      >
        <div className="space-y-4">
          <Text>Comma-separated tags for version {editTags.versionId}</Text>
          <Input
            value={editTags.text}
            onChange={(e) => setEditTags(prev => ({ ...prev, text: e.target.value }))}
            placeholder="v1.2.3, Q3-Final"
          />
        </div>
      </Modal>

    </div>
  )
}



