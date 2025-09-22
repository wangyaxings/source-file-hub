"use client"

import React, { useEffect, useMemo, useState } from 'react'
import { apiClient } from "@/lib/api"
import { mapApiErrorToMessage } from "@/lib/errors"
import { 
  Button, 
  Table, 
  Input, 
  Select, 
  Modal, 
  Form, 
  Tag, 
  Space, 
  Pagination,
  message,
  Typography,
  Checkbox,
  InputNumber,
  Popconfirm,
  Tooltip
} from "antd"
import { 
  UserOutlined, 
  EditOutlined, 
  DeleteOutlined, 
  CheckOutlined, 
  StopOutlined,
  KeyOutlined,
  CopyOutlined,
  DownloadOutlined,
  SafetyOutlined
} from "@ant-design/icons"
import type { ColumnsType } from 'antd/es/table'
import { usePermissions } from "@/lib/permissions"

const { Title, Text } = Typography
const { Option } = Select

type UserRow = {
  user_id: string
  email?: string
  role: string
  status: string
  two_fa: boolean
  last_login?: string
}

export default function UserManagement() {
  const [mounted, setMounted] = useState(false)
  const [loading, setLoading] = useState(false)
  const [users, setUsers] = useState<UserRow[]>([])
  const [filter, setFilter] = useState('')
  const [status, setStatus] = useState<string>('all')
  const [page, setPage] = useState<number>(1)
  const [limit, setLimit] = useState<number>(20)
  const [total, setTotal] = useState<number>(0)
  const [credOpen, setCredOpen] = useState(false)
  const [cred, setCred] = useState<{ username?: string; password?: string } | null>(null)

  const load = async () => {
    setLoading(true)
    try {
      const resp = await apiClient.adminListUsers({ q: filter.trim(), status: status === 'all' ? undefined : status, page, limit })
      setUsers((resp as any).users as UserRow[])
      setTotal((resp as any).total || (resp as any).count || 0)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { setMounted(true); }, [])
  useEffect(() => { load() }, [page, limit])

  const filtered = users // server-side filtered

  const onChangeRole = async (u: UserRow, role: string) => {
    try {
      await apiClient.adminUpdateUser(u.user_id, { role })
      message.success(`Role updated: ${u.user_id} → ${role}`)
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    }
  }

  const onApprove = async (u: UserRow) => {
    try {
      await apiClient.adminApproveUser(u.user_id)
      message.success(`User approved: ${u.user_id}`)
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    }
  }

  const onSuspend = async (u: UserRow) => {
    try {
      await apiClient.adminSuspendUser(u.user_id)
      message.success(`User suspended: ${u.user_id}`)
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    }
  }

  // 修复2FA切换逻辑
  const onToggle2FA = async (u: UserRow) => {
    try {
      if (u.two_fa) {
        // 禁用2FA - 直接调用API
        await apiClient.adminDisable2FA(u.user_id)
        message.success(`2FA has been disabled for ${u.user_id}`)
        load() // 重新加载用户列表
      } else {
        // 启用2FA - 管理员直接启用，用户首次登录时会引导设置
        await apiClient.adminEnable2FA(u.user_id)
        message.success(`2FA has been enabled for ${u.user_id}. User will be prompted to complete setup on next login.`)
        load() // 重新加载用户列表
      }
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    }
  }


  // 使用权限系统替代硬编码的角色检查
  const { permissions } = usePermissions()
  const isAdmin = mounted && permissions?.canManageUsers

  if (!mounted) {
    return null
  }
  if (!isAdmin) {
    return <div className="p-6">403 Forbidden: Admins only.</div>
  }

  // Define table columns
  const columns: ColumnsType<UserRow> = [
    {
      title: 'Username',
      dataIndex: 'user_id',
      key: 'user_id',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: 'Email',
      dataIndex: 'email',
      key: 'email',
      render: (text) => text || '-'
    },
    {
      title: 'Role',
      dataIndex: 'role',
      key: 'role',
      render: (role, record) => (
        <Select
          value={role}
          onChange={(value) => onChangeRole(record, value)}
          style={{ width: 160 }}
        >
          <Option value="viewer">viewer</Option>
          <Option value="administrator">administrator</Option>
        </Select>
      )
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status) => {
        const color = status === 'active' ? 'green' : status === 'pending' ? 'orange' : 'red'
        return <Tag color={color}>{status}</Tag>
      }
    },
    {
      title: '2FA',
      dataIndex: 'two_fa',
      key: 'two_fa',
      render: (twoFA, record) => (
        <Button
          size="small"
          type={twoFA ? "default" : "dashed"}
          icon={<SafetyOutlined />}
          onClick={() => onToggle2FA(record)}
        >
          {twoFA ? 'Disable' : 'Enable'}
        </Button>
      )
    },
    {
      title: 'Last Login',
      dataIndex: 'last_login',
      key: 'last_login',
      render: (date) => date ? new Date(date).toLocaleString() : '-'
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          {record.status !== 'active' && (
            <Tooltip title="Approve user">
              <Button
                size="small"
                type="primary"
                icon={<CheckOutlined />}
                onClick={() => onApprove(record)}
              >
                Approve
              </Button>
            </Tooltip>
          )}
          {record.status !== 'suspended' && (
            <Popconfirm
              title="Suspend user?"
              description="Are you sure you want to suspend this user?"
              onConfirm={() => onSuspend(record)}
              okText="Yes"
              cancelText="No"
            >
              <Tooltip title="Suspend user">
                <Button
                  size="small"
                  danger
                  icon={<StopOutlined />}
                >
                  Suspend
                </Button>
              </Tooltip>
            </Popconfirm>
          )}
          <EditRoleButton user={record} onSaved={load} />
          <ResetPasswordButton user={record} onDone={(pwd) => {
            setCred({ username: record.user_id, password: pwd })
            setCredOpen(true)
          }} />
        </Space>
      )
    }
  ]

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <Title level={2}>User Management</Title>
        <Space>
          <Input.Search
            placeholder="Filter by username/email"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            onSearch={() => { setPage(1); load() }}
            style={{ width: 250 }}
          />
          <Select
            value={status}
            onChange={(value) => { setStatus(value); setPage(1) }}
            style={{ width: 140 }}
          >
            <Option value="all">All Statuses</Option>
            <Option value="active">Active</Option>
            <Option value="pending">Pending</Option>
            <Option value="suspended">Suspended</Option>
          </Select>
          <Button onClick={() => { setPage(1); load() }} loading={loading}>
            Search
          </Button>
        </Space>
      </div>

      <CreateUserModal onCreated={(u, pwd) => {
        message.success(`User created: ${u}`)
        setCred({ username: u, password: pwd })
        setCredOpen(true)
        load()
      }} />

      <CredentialsModal open={credOpen} onOpenChange={setCredOpen} creds={cred} />

      <Table
        columns={columns}
        dataSource={filtered}
        rowKey="user_id"
        loading={loading}
        pagination={{
          current: page,
          pageSize: limit,
          total: total,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) => `${range[0]}-${range[1]} of ${total} users`,
          onChange: (newPage, newPageSize) => {
            setPage(newPage)
            if (newPageSize !== limit) {
              setLimit(newPageSize)
            }
          }
        }}
      />
    </div>
  )
}

function EditRoleButton({ user, onSaved }: { user: UserRow; onSaved: () => void }) {
  const [open, setOpen] = useState(false)
  const [role, setRole] = useState(user.role)
  const [perms, setPerms] = useState<string[]>([])
  const [quotaD, setQuotaD] = useState<string>('')
  const [quotaM, setQuotaM] = useState<string>('')
  const [status, setStatus] = useState<string>(user.status)
  const [busy, setBusy] = useState(false)

  const togglePerm = (p: string) => setPerms(prev => prev.includes(p) ? prev.filter(x => x!==p) : [...prev, p])

  const save = async () => {
    setBusy(true)
    try {
      const payload: any = { role, status }
      if (perms.length) payload.permissions = perms
      if (quotaD) payload.quota_daily = parseInt(quotaD, 10)
      if (quotaM) payload.quota_monthly = parseInt(quotaM, 10)
      await apiClient.adminSetUserRole(user.user_id, payload)
      message.success(`Role updated for ${user.user_id}. User may need to re-login to see changes.`)
      setOpen(false)
      onSaved()
    } catch (err: any) {
      message.error(`Save failed: ${err?.message || String(err)}`)
    } finally {
      setBusy(false)
    }
  }

  const handleOpen = async () => {
    setOpen(true)
    try {
      const details = await apiClient.adminGetUser(user.user_id)
      setRole(details?.role || user.role)
      setStatus(details?.status || user.status)
      setPerms(details?.permissions || [])
      setQuotaD((details?.quota_daily ?? '') === '' ? '' : String(details?.quota_daily))
      setQuotaM((details?.quota_monthly ?? '') === '' ? '' : String(details?.quota_monthly))
    } catch (e: any) {
      const { title, description } = mapApiErrorToMessage(e)
      message.error(`${title}: ${description}`)
    }
  }

  return (
    <>
      <Tooltip title="Edit role & permissions">
        <Button size="small" icon={<EditOutlined />} onClick={handleOpen}>
          Edit
        </Button>
      </Tooltip>
      
      <Modal
        title="Edit Role & Permissions"
        open={open}
        onCancel={() => setOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setOpen(false)} disabled={busy}>
            Cancel
          </Button>,
          <Button key="save" type="primary" onClick={save} loading={busy}>
            Save
          </Button>
        ]}
      >
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <Text className="block mb-2">Role</Text>
            <Select value={role} onChange={setRole} style={{ width: '100%' }}>
              <Option value="viewer">viewer</Option>
              <Option value="administrator">administrator</Option>
            </Select>
          </div>
          <div>
            <Text className="block mb-2">Status</Text>
            <Select value={status} onChange={setStatus} style={{ width: '100%' }}>
              <Option value="active">active</Option>
              <Option value="pending">pending</Option>
              <Option value="suspended">suspended</Option>
            </Select>
          </div>
          <div className="sm:col-span-2">
            <Text className="block mb-2">Permissions</Text>
            <Checkbox.Group
              value={perms}
              onChange={(checkedValues) => setPerms(checkedValues as string[])}
            >
              <Space wrap>
                <Checkbox value="read">Read</Checkbox>
                <Checkbox value="download">Download</Checkbox>
                <Checkbox value="upload">Upload</Checkbox>
                <Checkbox value="admin">Admin</Checkbox>
              </Space>
            </Checkbox.Group>
          </div>
          <div>
            <Text className="block mb-2">Daily quota (-1 unlimited)</Text>
            <InputNumber
              value={quotaD ? parseInt(quotaD) : undefined}
              onChange={(value) => setQuotaD(value ? String(value) : '')}
              placeholder="-1"
              style={{ width: '100%' }}
            />
          </div>
          <div>
            <Text className="block mb-2">Monthly quota (-1 unlimited)</Text>
            <InputNumber
              value={quotaM ? parseInt(quotaM) : undefined}
              onChange={(value) => setQuotaM(value ? String(value) : '')}
              placeholder="-1"
              style={{ width: '100%' }}
            />
          </div>
        </div>
      </Modal>
    </>
  )
}

function CreateUserModal({ onCreated }: { onCreated: (username: string, password: string) => void }) {
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [role, setRole] = useState("viewer")
  const [mustReset, setMustReset] = useState(true)
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  const createUser = async () => {
    if (!username) {
      message.error('Username required')
      return
    }
    setBusy(true)
    try {
      const resp = await apiClient.adminCreateUser({ username, email, role, must_reset: mustReset })
      const pwd = (resp as any)?.initial_password || ''
      onCreated(username, pwd)
      setUsername("")
      setEmail("")
      setRole("viewer")
      setMustReset(true)
      setOpen(false)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <Button type="primary" icon={<UserOutlined />} onClick={() => setOpen(true)}>
        Create User
      </Button>
      
      <Modal
        title="Create User"
        open={open}
        onCancel={() => setOpen(false)}
        footer={[
          <Button key="cancel" onClick={() => setOpen(false)} disabled={busy}>
            Cancel
          </Button>,
          <Button key="create" type="primary" onClick={createUser} loading={busy}>
            Create
          </Button>
        ]}
      >
        <div className="space-y-4">
          <Text>Generate a one-time password and optionally force reset.</Text>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <Input 
              placeholder="Username" 
              value={username} 
              onChange={e => setUsername(e.target.value)} 
            />
            <Input 
              placeholder="Email (optional)" 
              value={email} 
              onChange={e => setEmail(e.target.value)} 
            />
            <div>
              <Text className="block mb-2">Role</Text>
              <Select value={role} onChange={setRole} style={{ width: '100%' }}>
                <Option value="viewer">viewer</Option>
                <Option value="administrator">administrator</Option>
              </Select>
            </div>
            <div className="flex items-center">
              <Checkbox 
                checked={mustReset} 
                onChange={e => setMustReset(e.target.checked)}
              >
                Force password reset
              </Checkbox>
            </div>
          </div>
        </div>
      </Modal>
    </>
  )
}

function ResetPasswordButton({ user, onDone }: { user: UserRow; onDone: (password: string) => void }) {
  const [busy, setBusy] = useState(false)

  const onReset = async () => {
    setBusy(true)
    try {
      const data = await apiClient.adminResetPassword(user.user_id)
      const pwd = data?.temporary_password || ''
      onDone(pwd)
      message.success(`Password reset for ${user.user_id}`)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      message.error(`${title}: ${description}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Popconfirm
      title={`Reset password for ${user.user_id}?`}
      description="This generates a new temporary password and forces reset on next login."
      onConfirm={onReset}
      okText="Reset Password"
      cancelText="Cancel"
      okButtonProps={{ danger: true, loading: busy }}
    >
      <Tooltip title="Reset password">
        <Button size="small" icon={<KeyOutlined />}>
          Reset Password
        </Button>
      </Tooltip>
    </Popconfirm>
  )
}

function CredentialsModal({ open, onOpenChange, creds }: { open: boolean; onOpenChange: (v: boolean) => void; creds: { username?: string; password?: string } | null }) {
  const username = creds?.username || ''
  const password = creds?.password || ''

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password)
      message.success('Password copied to clipboard')
    } catch {
      message.error('Failed to copy password')
    }
  }

  const download = () => {
    const ts = new Date().toISOString().replace(/[:.]/g, '-')
    const name = `credentials-${username}-${ts}.txt`
    const content = `Username: ${username}\nTemporary Password: ${password}\nIssued At: ${new Date().toISOString()}\n`;
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
    message.success('Credentials downloaded')
  }

  return (
    <Modal
      title="Temporary Credentials"
      open={open}
      onCancel={() => onOpenChange(false)}
      footer={[
        <Button key="close" onClick={() => onOpenChange(false)}>
          Close
        </Button>
      ]}
    >
      <div className="space-y-4">
        <Text type="secondary">Copy or download the password now. It won't be shown again.</Text>
        <div className="space-y-3">
          <div>
            <Text className="block mb-1">Username</Text>
            <Input readOnly value={username} />
          </div>
          <div>
            <Text className="block mb-1">Temporary Password</Text>
            <Space.Compact style={{ width: '100%' }}>
              <Input readOnly value={password} />
              <Button icon={<CopyOutlined />} onClick={copy}>
                Copy
              </Button>
              <Button icon={<DownloadOutlined />} onClick={download}>
                Download
              </Button>
            </Space.Compact>
          </div>
          <Text type="secondary" className="text-xs">
            Ask the user to login and change the password immediately.
          </Text>
        </div>
      </div>
    </Modal>
  )
}
