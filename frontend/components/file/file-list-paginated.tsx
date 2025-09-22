'use client'

import { useEffect, useState } from 'react'
import { useSearchParams, useRouter } from 'next/navigation'
import { 
  Button, 
  Card, 
  Select, 
  Modal, 
  Table, 
  Space, 
  Typography, 
  Tag, 
  Tooltip, 
  message,
  Spin,
  Empty,
  Popconfirm
} from "antd"
import {
  FileOutlined,
  LoadingOutlined,
  ReloadOutlined,
  FileTextOutlined,
  DownloadOutlined,
  ClockCircleOutlined,
  UserOutlined,
  HistoryOutlined,
  DeleteOutlined,
  SettingOutlined,
  ExclamationCircleOutlined
} from "@ant-design/icons"
import type { ColumnsType } from 'antd/es/table'
import { apiClient, type FileInfo } from '@/lib/api'
import { mapApiErrorToMessage } from '@/lib/errors'
import { usePermissions } from '@/lib/permissions'
import { formatDate, formatFileSize } from '@/lib/utils'

const { Title, Text } = Typography
const { Option } = Select

type VersionRow = { versionId: string; tags: string[]; date?: string; sha256?: string; size?: number; fileName?: string; path?: string }

interface FileListPaginatedProps { refreshTrigger?: number }

export function FileListPaginated({ refreshTrigger }: FileListPaginatedProps) {
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
      // 只显示最新版本的文件
      const latestFiles = res.files.filter(file => file.isLatest)
      setItems(latestFiles)
      setCount(res.count)
    } catch (e: any) {
      const { title, description } = mapApiErrorToMessage(e)
      message.error(`${title}: ${description}`)
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
    try { 
      await apiClient.downloadFile(file.path) 
    }
    catch (e: any) { 
      const { title, description } = mapApiErrorToMessage(e)
      message.error(`${title}: ${description}`)
    }
    finally { setDownloadingFile(null) }
  }

  const handleViewVersions = async (file: FileInfo) => {
    const ftype = (file.fileType === 'roadmap' || file.fileType === 'recommendation') ? file.fileType : null
    if (!ftype) { 
      message.error('Version history is only for roadmap/recommendation')
      return 
    }
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
      message.error(`${title}: ${description}`)
      setVersionsDialog(prev => ({ ...prev, loading:false }))
    }
  }

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
                    load() // Refresh the file list
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
                value={type}
                onChange={changeType}
                style={{ width: 160 }}
              >
                <Option value="all">All Files</Option>
                <Option value="roadmap">Roadmaps</Option>
                <Option value="recommendation">Recommendations</Option>
              </Select>
              <Select
                value={String(limit)}
                onChange={(v) => changeLimit(parseInt(v, 10))}
                style={{ width: 120 }}
              >
                <Option value="10">10 / page</Option>
                <Option value="20">20 / page</Option>
                <Option value="50">50 / page</Option>
                <Option value="100">100 / page</Option>
              </Select>
              <Button icon={<ReloadOutlined />} onClick={load}>
                Refresh
              </Button>
            </Space>
          </div>
          
          <Table
            columns={columns}
            dataSource={items}
            rowKey={(record) => record.id || record.path}
            loading={loading}
            pagination={{
              current: page,
              pageSize: limit,
              total: count,
              showSizeChanger: false,
              showQuickJumper: true,
              showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} items`,
              onChange: (newPage) => goToPage(newPage)
            }}
          />
        </div>
      </Card>

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
    </div>
  )
}


