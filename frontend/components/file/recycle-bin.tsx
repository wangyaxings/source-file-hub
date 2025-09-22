'use client'

import { useState, useEffect } from "react"
import { 
  Button, 
  Card, 
  Table, 
  Modal, 
  Space, 
  Typography, 
  Tag, 
  Tooltip, 
  message,
  Popconfirm,
  Spin,
  Empty
} from "antd"
import {
  DeleteOutlined,
  ReloadOutlined,
  UndoOutlined,
  ExclamationCircleOutlined,
  FileTextOutlined,
  ClockCircleOutlined,
  UserOutlined,
  LoadingOutlined,
  CloseOutlined
} from "@ant-design/icons"
import type { ColumnsType } from 'antd/es/table'
import { apiClient } from "@/lib/api"
import { formatFileSize, formatDate } from "@/lib/utils"
import { usePermissions } from "@/lib/permissions"

const { Title, Text } = Typography

interface RecycleBinItem {
  id: string
  originalName: string
  versionedName: string
  fileType: string
  filePath: string
  size: number
  description: string
  uploader: string
  uploadTime: string
  version: number
  isLatest: boolean
  status: string
  deletedAt: string
  deletedBy: string
  fileExists: boolean
  checksum: string
  createdAt: string
  updatedAt: string
  daysUntilPurge: number
}

export function RecycleBin() {
  const currentUser = apiClient.getCurrentUser()
  // 使用权限系统替代硬编码的角色检查
  const { permissions } = usePermissions()
  const [items, setItems] = useState<RecycleBinItem[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [restoringFile, setRestoringFile] = useState<string | null>(null)
  const [showClearDialog, setShowClearDialog] = useState(false)
  const [isClearing, setIsClearing] = useState(false)

  const loadRecycleBin = async () => {
    setIsLoading(true)
    try {
      const data = await apiClient.getRecycleBin()
      setItems(data)
    } catch (error) {
      console.error('Failed to load recycle bin:', error)
      message.error(`Failed to load recycle bin: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setIsLoading(false)
    }
  }

  const [restoreDialog, setRestoreDialog] = useState<{
    isOpen: boolean
    item: RecycleBinItem | null
  }>({
    isOpen: false,
    item: null
  })

  const handleRestore = (item: RecycleBinItem) => {
    setRestoreDialog({
      isOpen: true,
      item: item
    })
  }

  const confirmRestore = async () => {
    if (!restoreDialog.item) return

    setRestoringFile(restoreDialog.item.id)
    try {
      await apiClient.restoreFile(restoreDialog.item.id)
      message.success('File restored successfully')
      loadRecycleBin() // Refresh the list
    } catch (error) {
      console.error('Restore failed:', error)
      message.error(`Restore failed: ${error instanceof Error ? error.message : 'Restore failed'}`)
    } finally {
      setRestoringFile(null)
      setRestoreDialog({ isOpen: false, item: null })
    }
  }

  const handleClearRecycleBin = async () => {
    setIsClearing(true)
    try {
      await apiClient.clearRecycleBin()
      message.success('Recycle bin cleared successfully')
      loadRecycleBin()
    } catch (error) {
      console.error('Clear failed:', error)
      message.error(`Clear failed: ${error instanceof Error ? error.message : 'Failed to clear recycle bin'}`)
    } finally {
      setIsClearing(false)
      setShowClearDialog(false)
    }
  }

  useEffect(() => {
    loadRecycleBin()
  }, [])

  if (isLoading) {
    return (
      <Card>
        <div className="flex items-center justify-center py-12">
          <Space>
            <Spin indicator={<LoadingOutlined style={{ fontSize: 24 }} spin />} />
            <Text>Loading recycle bin...</Text>
          </Space>
        </div>
      </Card>
    )
  }

  // Define table columns for AntD Table
  const columns: ColumnsType<RecycleBinItem> = [
    {
      title: 'File Name',
      dataIndex: 'originalName',
      key: 'name',
      render: (text, record) => (
        <Space direction="vertical" size="small">
          <Space>
            <FileTextOutlined />
            <Text strong>{text}</Text>
          </Space>
          {record.description && (
            <Text type="secondary" className="text-sm">{record.description}</Text>
          )}
          {!record.fileExists && (
            <Space>
              <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
              <Text type="danger" className="text-sm">Physical file missing</Text>
            </Space>
          )}
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
      title: 'Deleted By',
      dataIndex: 'deletedBy',
      key: 'deletedBy',
      render: (deletedBy) => (
        <Space>
          <UserOutlined />
          {deletedBy || "unknown"}
        </Space>
      ),
      width: 120
    },
    {
      title: 'Deleted At',
      dataIndex: 'deletedAt',
      key: 'deletedAt',
      render: (deletedAt) => (
        <Space>
          <ClockCircleOutlined />
          {formatDate(deletedAt)}
        </Space>
      ),
      width: 180
    },
    {
      title: 'Days Left',
      dataIndex: 'daysUntilPurge',
      key: 'daysLeft',
      render: (days) => {
        const color = days <= 7 ? 'red' : days <= 30 ? 'orange' : 'green'
        return (
          <Tag color={color}>
            {days <= 0 ? 'Expired' : `${days} days`}
          </Tag>
        )
      },
      width: 120
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          {permissions?.canAccessRecycle && (
            <Tooltip title="Restore file">
              <Button
                type="text"
                icon={restoringFile === record.id ? <LoadingOutlined /> : <UndoOutlined />}
                onClick={() => handleRestore(record)}
                loading={restoringFile === record.id}
              />
            </Tooltip>
          )}
        </Space>
      ),
      width: 100
    }
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <div className="p-6">
          <div className="flex items-center justify-between">
            <div>
              <Title level={3} className="flex items-center gap-2 mb-2">
                <DeleteOutlined />
                Recycle Bin
              </Title>
              <Text type="secondary">
                Manage deleted files. Files are automatically purged after 90 days.
              </Text>
            </div>
            <Space>
              <Button icon={<ReloadOutlined />} onClick={loadRecycleBin}>
                Refresh
              </Button>
              {permissions?.canAccessRecycle && items.length > 0 && (
                <Button
                  danger
                  icon={<DeleteOutlined />}
                  onClick={() => setShowClearDialog(true)}
                >
                  Clear All
                </Button>
              )}
            </Space>
          </div>
        </div>
      </Card>

      {/* Items List */}
      <Card>
        <div className="p-6">
          <Table
            columns={columns}
            dataSource={items}
            rowKey="id"
            pagination={{
              showSizeChanger: true,
              showQuickJumper: true,
              showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} items`
            }}
            locale={{
              emptyText: (
                <Empty
                  image={<DeleteOutlined style={{ fontSize: 48, color: '#d9d9d9' }} />}
                  description="Recycle bin is empty"
                />
              )
            }}
          />
        </div>
      </Card>

      {/* Clear All Confirmation Modal */}
      {permissions?.canAccessRecycle && (
        <Modal
          title={
            <Space>
              <ExclamationCircleOutlined style={{ color: '#ff4d4f' }} />
              Clear Recycle Bin
            </Space>
          }
          open={showClearDialog}
          onCancel={() => setShowClearDialog(false)}
          footer={[
            <Button key="cancel" onClick={() => setShowClearDialog(false)} disabled={isClearing}>
              Cancel
            </Button>,
            <Button 
              key="clear" 
              danger 
              onClick={handleClearRecycleBin} 
              loading={isClearing}
              icon={!isClearing ? <DeleteOutlined /> : undefined}
            >
              {isClearing ? 'Clearing...' : 'Clear All'}
            </Button>
          ]}
        >
          <Text>
            This will permanently delete all {items.length} files in the recycle bin.
            This action cannot be undone.
          </Text>
        </Modal>
      )}

      {/* Restore Confirmation Modal */}
      {permissions?.canAccessRecycle && (
        <Modal
          title={
            <Space>
              <UndoOutlined style={{ color: '#52c41a' }} />
              Confirm Restore
            </Space>
          }
          open={restoreDialog.isOpen}
          onCancel={() => setRestoreDialog({ isOpen: false, item: null })}
          footer={[
            <Button key="cancel" onClick={() => setRestoreDialog({ isOpen: false, item: null })}>
              Cancel
            </Button>,
            <Button 
              key="restore" 
              type="primary" 
              onClick={confirmRestore}
              style={{ backgroundColor: '#52c41a', borderColor: '#52c41a' }}
              icon={<UndoOutlined />}
            >
              Restore File
            </Button>
          ]}
        >
          <Text>
            Are you sure you want to restore "<Text strong>{restoreDialog.item?.originalName}</Text>"?
            The file will be moved back to the active files list.
          </Text>
        </Modal>
      )}
    </div>
  )
}
