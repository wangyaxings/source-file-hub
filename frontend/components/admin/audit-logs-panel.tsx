"use client"

import React, { useEffect, useState } from 'react'
import { apiClient } from '@/lib/api'
import { mapApiErrorToMessage } from '@/lib/errors'
import { 
  Table, 
  Input, 
  Button, 
  Space, 
  Typography, 
  Tag, 
  message,
  Tooltip
} from 'antd'
import { 
  SearchOutlined, 
  AuditOutlined, 
  ClockCircleOutlined,
  UserOutlined,
  FileTextOutlined
} from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'

const { Title, Text } = Typography

export function AuditLogsPanel() {
  const [mounted, setMounted] = useState(false)
  const [items, setItems] = useState<any[]>([])
  const [actor, setActor] = useState('')
  const [target, setTarget] = useState('')
  const [action, setAction] = useState('')
  const [page, setPage] = useState(1)
  const [limit, setLimit] = useState(20)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const qs = new URLSearchParams()
      if (actor) qs.set('actor', actor)
      if (target) qs.set('target', target)
      if (action) qs.set('action', action)
      qs.set('page', String(page))
      qs.set('limit', String(limit))
      const resp = await apiClient.request<{ items: any[]; total: number }>(`/admin/audit-logs?${qs.toString()}`)
      if (!resp.success) throw Object.assign(new Error(resp.error || 'Failed to load audit logs'), { code: (resp as any).code, details: (resp as any).details })
      setItems((resp.data as any)?.items || [])
      setTotal((resp.data as any)?.total || 0)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => { load() }, [page, limit])

  if (!mounted) return null

  // Define table columns
  const columns: ColumnsType<any> = [
    {
      title: (
        <Space>
          <ClockCircleOutlined />
          Time
        </Space>
      ),
      dataIndex: 'createdAt',
      key: 'time',
      render: (text, record) => {
        const time = text || record.created_at || ''
        return time ? new Date(time).toLocaleString() : '-'
      },
      width: 180
    },
    {
      title: (
        <Space>
          <UserOutlined />
          Actor
        </Space>
      ),
      dataIndex: 'actor',
      key: 'actor',
      render: (text) => <Tag color="blue">{text}</Tag>
    },
    {
      title: (
        <Space>
          <UserOutlined />
          Target
        </Space>
      ),
      dataIndex: 'targetUser',
      key: 'target',
      render: (text, record) => {
        const target = text || record.target_user
        return target ? <Tag color="green">{target}</Tag> : '-'
      }
    },
    {
      title: (
        <Space>
          <FileTextOutlined />
          Action
        </Space>
      ),
      dataIndex: 'action',
      key: 'action',
      render: (text) => <Tag color="orange">{text}</Tag>
    },
    {
      title: 'Details',
      dataIndex: 'details',
      key: 'details',
      render: (text) => (
        <Tooltip title={text} placement="topLeft">
          <Text code className="text-xs break-words max-w-xs block truncate">
            {text}
          </Text>
        </Tooltip>
      ),
      ellipsis: true
    }
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <Title level={3}>
          <Space>
            <AuditOutlined />
            Audit Logs
          </Space>
        </Title>
        <Space>
          <Input
            placeholder="Actor"
            value={actor}
            onChange={e => setActor(e.target.value)}
            style={{ width: 150 }}
            prefix={<UserOutlined />}
          />
          <Input
            placeholder="Target user"
            value={target}
            onChange={e => setTarget(e.target.value)}
            style={{ width: 150 }}
            prefix={<UserOutlined />}
          />
          <Input
            placeholder="Action"
            value={action}
            onChange={e => setAction(e.target.value)}
            style={{ width: 150 }}
            prefix={<FileTextOutlined />}
          />
          <Button
            type="primary"
            icon={<SearchOutlined />}
            onClick={() => { setPage(1); load() }}
            loading={loading}
          >
            Search
          </Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={items}
        rowKey={(record, index) => `${record.id || index}`}
        loading={loading}
        pagination={{
          current: page,
          pageSize: limit,
          total: total,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} records`,
          onChange: (newPage, newPageSize) => {
            setPage(newPage)
            if (newPageSize !== limit) {
              setLimit(newPageSize)
            }
          }
        }}
        scroll={{ x: 800 }}
      />
    </div>
  )
}

