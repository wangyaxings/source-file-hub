"use client"

import { useEffect, useMemo, useState } from "react"
import { 
  Card, 
  Button, 
  Input, 
  Select, 
  Modal, 
  Table, 
  Space, 
  Typography, 
  Tag, 
  Tooltip, 
  Upload as AntUpload,
  message,
  Form
} from "antd"
import {
  UploadOutlined,
  SearchOutlined,
  LoadingOutlined,
  EditOutlined,
  CopyOutlined,
  MoreOutlined,
  InboxOutlined
} from "@ant-design/icons"
import type { ColumnsType } from 'antd/es/table'
import { apiClient } from "@/lib/api"
import { formatDate } from "@/lib/utils"

const { Title, Text } = Typography
const { Option } = Select
const { Dragger } = AntUpload

type PackageItem = {
  id: string
  tenantId: string
  type: string
  fileName: string
  size: number
  path: string
  ip: string
  timestamp: string
  remark?: string
}

export function PackagesPanel() {
  const [assetsFile, setAssetsFile] = useState<File | null>(null)
  const [othersFile, setOthersFile] = useState<File | null>(null)
  const [isUploading, setIsUploading] = useState(false)

  const [items, setItems] = useState<PackageItem[]>([])
  const [count, setCount] = useState(0)
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(50)
  const [tenant, setTenant] = useState("")
  const [typeFilter, setTypeFilter] = useState<string>("all")
  const [q, setQ] = useState("")
  const [loadingList, setLoadingList] = useState(false)
  const [remarkDialog, setRemarkDialog] = useState<{ open: boolean; item: PackageItem | null; text: string }>({ open: false, item: null, text: "" })

  const fetchList = async () => {
    setLoadingList(true)
    try {
      const params: any = { page, limit }
      if (tenant) params.tenant = tenant
      if (typeFilter !== "all") params.type = typeFilter
      if (q) params.q = q
      const res = await apiClient.listPackages(params)
      const newItems = Array.isArray((res as any)?.items) ? (res as any).items : []
      const newCount = typeof (res as any)?.count === 'number' ? (res as any).count : 0
      setItems(newItems as any)
      setCount(newCount)
    } finally {
      setLoadingList(false)
    }
  }

  useEffect(() => { fetchList() }, [page, limit])

  const totalPages = useMemo(() => Math.max(1, Math.ceil(count / limit)), [count, limit])

  const handleUpload = async (kind: "assets" | "others") => {
    if (!tenant.trim()) { 
      message.error('Tenant ID is required')
      return 
    }
    try {
      setIsUploading(true)
      if (kind === "assets" && assetsFile) await apiClient.uploadAssetsZip(assetsFile, tenant.trim())
      if (kind === "others" && othersFile) await apiClient.uploadOthersZip(othersFile, tenant.trim())
      setAssetsFile(null)
      setOthersFile(null)
      await fetchList()
      message.success('Upload completed successfully')
    } catch (e) {
      console.error("Upload failed", e)
      message.error(e instanceof Error ? e.message : "Upload failed")
    } finally {
      setIsUploading(false)
    }
  }

  const handleSearch = async () => {
    setPage(1)
    await fetchList()
  }

  const openRemark = (item: PackageItem) => {
    setRemarkDialog({ open: true, item, text: item.remark || "" })
  }

  const saveRemark = async () => {
    if (!remarkDialog.item) return
    try {
      await apiClient.updatePackageRemark(remarkDialog.item.id, remarkDialog.text)
      setRemarkDialog({ open: false, item: null, text: "" })
      await fetchList()
      message.success('Remark updated successfully')
    } catch (e) {
      console.error("Update remark failed", e)
      message.error(e instanceof Error ? e.message : "Update failed")
    }
  }

  // Define table columns for AntD Table
  const columns: ColumnsType<PackageItem> = [
    {
      title: 'Tenant',
      dataIndex: 'tenantId',
      key: 'tenant',
      width: 100,
      render: (text) => <Text className="text-xs">{text}</Text>
    },
    {
      title: 'IP',
      dataIndex: 'ip',
      key: 'ip',
      width: 120,
      render: (text) => <Text code className="text-xs">{text}</Text>
    },
    {
      title: 'Timestamp',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 150,
      render: (timestamp) => <Text className="text-xs">{formatDate(timestamp)}</Text>
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 80,
      render: (type) => (
        <Tag color={type === 'assets' ? 'blue' : 'green'}>
          {type}
        </Tag>
      )
    },
    {
      title: 'Filename',
      dataIndex: 'fileName',
      key: 'fileName',
      width: 200,
      render: (text) => (
        <Tooltip title={text}>
          <Text className="text-xs" ellipsis>{text}</Text>
        </Tooltip>
      )
    },
    {
      title: 'Size',
      dataIndex: 'size',
      key: 'size',
      width: 100,
      render: (size) => <Text className="text-xs">{`${(size/1024/1024).toFixed(2)} MB`}</Text>
    },
    {
      title: 'Path',
      dataIndex: 'path',
      key: 'path',
      render: (path) => {
        const dirPath = (path || '').replace(/\\/g, '/');
        const idx = dirPath.lastIndexOf('/');
        const displayPath = idx >= 0 ? dirPath.slice(0, idx) : dirPath;
        return (
          <Tooltip title={path}>
            <Text code className="text-xs" ellipsis>{displayPath}</Text>
          </Tooltip>
        )
      }
    },
    {
      title: 'Remark',
      dataIndex: 'remark',
      key: 'remark',
      width: 200,
      render: (remark) => (
        <Tooltip title={remark || 'No remark'}>
          <Text className="text-xs" ellipsis>
            {remark || <Text type="secondary">No remark</Text>}
          </Text>
        </Tooltip>
      )
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 80,
      render: (_, record) => (
        <Tooltip title="Edit remark">
          <Button
            type="text"
            icon={<EditOutlined />}
            onClick={() => openRemark(record)}
            size="small"
          />
        </Tooltip>
      )
    }
  ]

  return (
    <div className="space-y-6">
      {/* Upload Section */}
      <Card>
        <div className="p-6">
          <Title level={3} className="flex items-center gap-2 mb-4">
            <UploadOutlined />
            Assets/Others Upload (via API)
          </Title>
          
          <div className="grid md:grid-cols-2 gap-6">
            <div className="space-y-4 md:col-span-2">
              <div>
                <Text strong>Tenant ID (required for upload)</Text>
                <Input 
                  placeholder="tenant id" 
                  value={tenant} 
                  onChange={e => setTenant(e.target.value)} 
                  style={{ width: 250, marginTop: 8 }}
                />
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <Text strong>Upload Assets ZIP</Text>
                <Input 
                  type="file" 
                  accept=".zip" 
                  onChange={(e) => setAssetsFile(e.target.files?.[0] || null)}
                  style={{ marginTop: 8 }}
                />
                <Button 
                  onClick={() => handleUpload("assets")} 
                  disabled={!assetsFile || isUploading}
                  loading={isUploading}
                  icon={<UploadOutlined />}
                  style={{ marginTop: 8 }}
                >
                  Upload Assets
                </Button>
                <Text type="secondary" className="block text-xs mt-2">
                  Will upload to packages/&lt;tenant_id&gt;/assets/ ...
                </Text>
              </div>
            </div>
            
            <div className="space-y-4">
              <div>
                <Text strong>Upload Others ZIP</Text>
                <Input 
                  type="file" 
                  accept=".zip" 
                  onChange={(e) => setOthersFile(e.target.files?.[0] || null)}
                  style={{ marginTop: 8 }}
                />
                <Button 
                  onClick={() => handleUpload("others")} 
                  disabled={!othersFile || isUploading}
                  loading={isUploading}
                  icon={<UploadOutlined />}
                  style={{ marginTop: 8 }}
                >
                  Upload Others
                </Button>
                <Text type="secondary" className="block text-xs mt-2">
                  Will upload to packages/&lt;tenant_id&gt;/others/ ...
                </Text>
              </div>
            </div>
          </div>
        </div>
      </Card>

      {/* Packages List */}
      <Card>
        <div className="p-6">
          <Title level={3} className="mb-4">Uploaded Packages</Title>
          
          <div className="flex flex-wrap gap-4 items-end mb-6">
            <div>
              <Text strong>Tenant ID</Text>
              <Input 
                placeholder="tenant id" 
                value={tenant} 
                onChange={e => setTenant(e.target.value)} 
                style={{ width: 200, marginTop: 8 }}
              />
            </div>
            <div>
              <Text strong>Type</Text>
              <Select 
                value={typeFilter} 
                onChange={(v) => setTypeFilter(v)}
                style={{ width: 120, marginTop: 8 }}
              >
                <Option value="all">All</Option>
                <Option value="assets">assets</Option>
                <Option value="others">others</Option>
              </Select>
            </div>
            <div>
              <Text strong>Search</Text>
              <Space style={{ marginTop: 8 }}>
                <Input 
                  placeholder="filename / path / remark" 
                  value={q} 
                  onChange={e => setQ(e.target.value)} 
                  style={{ width: 250 }}
                />
                <Button icon={<SearchOutlined />} onClick={handleSearch}>
                  Search
                </Button>
              </Space>
            </div>
            <div>
              <Text strong>Page Size</Text>
              <Select 
                value={String(limit)} 
                onChange={(v) => { setLimit(Number(v)); setPage(1); }}
                style={{ width: 80, marginTop: 8 }}
              >
                <Option value="10">10</Option>
                <Option value="20">20</Option>
                <Option value="50">50</Option>
              </Select>
            </div>
            <Button onClick={fetchList}>Refresh</Button>
          </div>

          <Table
            columns={columns}
            dataSource={items}
            rowKey="id"
            loading={loadingList}
            pagination={{
              current: page,
              pageSize: limit,
              total: count,
              showSizeChanger: false,
              showQuickJumper: true,
              showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} items`,
              onChange: (newPage) => setPage(newPage)
            }}
            scroll={{ x: 1200 }}
            size="small"
          />
        </div>
      </Card>

      {/* Edit Remark Modal */}
      <Modal
        title="Edit Remark"
        open={remarkDialog.open}
        onCancel={() => setRemarkDialog({ open: false, item: null, text: "" })}
        footer={[
          <Button key="cancel" onClick={() => setRemarkDialog({ open: false, item: null, text: "" })}>
            Cancel
          </Button>,
          <Button key="save" type="primary" onClick={saveRemark}>
            Save
          </Button>
        ]}
      >
        <div className="space-y-4">
          <Text>Update the remark for this upload record.</Text>
          <Input 
            value={remarkDialog.text} 
            onChange={(e) => setRemarkDialog(prev => ({ ...prev, text: e.target.value }))} 
            placeholder="Enter remark" 
          />
        </div>
      </Modal>
    </div>
  )
}

