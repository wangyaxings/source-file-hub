"use client"

import React, { useEffect, useMemo, useState } from 'react'
import { apiClient } from "@/lib/api"
import { mapApiErrorToMessage } from "@/lib/errors"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { useToast } from "@/lib/use-toast"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter, DialogDescription } from "@/components/ui/dialog"
import { usePermissions } from "@/lib/permissions"
import { UserPlus, Search, Filter, ChevronUp, ChevronDown, Check, X, Edit, Key, Shield } from "lucide-react"

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
  const { toast } = useToast()


  const load = async () => {
    setLoading(true)
    try {
      const resp = await apiClient.adminListUsers({ q: filter.trim(), status: status === 'all' ? undefined : status, page, limit })
      setUsers((resp as any).users as UserRow[])
      setTotal((resp as any).total || (resp as any).count || 0)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
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
      toast({ title: 'Role updated', description: `${u.user_id} → ${role}` })
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
    }
  }

  const onApprove = async (u: UserRow) => {
    try {
      await apiClient.adminApproveUser(u.user_id)
      toast({ title: 'User approved', description: u.user_id })
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
    }
  }

  const onSuspend = async (u: UserRow) => {
    try {
      await apiClient.adminSuspendUser(u.user_id)
      toast({ title: 'User suspended', description: u.user_id })
      load()
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
    }
  }

  // 修复2FA切换逻辑
  const onToggle2FA = async (u: UserRow) => {
    try {
      if (u.two_fa) {
        // 禁用2FA - 直接调用API
        await apiClient.adminDisable2FA(u.user_id)
        toast({ title: '2FA disabled', description: `2FA has been disabled for ${u.user_id}` })
        load() // 重新加载用户列表
      } else {
        // 启用2FA - 管理员直接启用，用户首次登录时会引导设置
        await apiClient.adminEnable2FA(u.user_id)
        toast({ 
          title: '2FA enabled', 
          description: `2FA has been enabled for ${u.user_id}. User will be prompted to complete setup on next login.` 
        })
        load() // 重新加载用户列表
      }
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
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

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">User Management</h1>
      </div>

      <CredentialsModal open={credOpen} onOpenChange={setCredOpen} creds={cred} />

      {/* 筛选和搜索工具栏 */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            <Input 
              placeholder="Search users..." 
              value={filter} 
              onChange={(e) => setFilter(e.target.value)} 
              className="w-64 h-9" 
            />
            <Button 
              variant="outline" 
              size="sm" 
              className="h-9 px-3" 
              onClick={() => { setPage(1); load() }} 
              disabled={loading}
              title="Search"
            >
              <Search className="h-4 w-4" />
            </Button>
          </div>
          <Select value={status} onValueChange={(v) => { setStatus(v); setPage(1) }}>
            <SelectTrigger className="w-32 h-9" title="Filter by status">
              <Filter className="h-4 w-4 mr-2" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="pending">Pending</SelectItem>
              <SelectItem value="suspended">Suspended</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <CreateUserModal onCreated={(u, pwd) => {
          toast({ title: 'User created', description: u })
          setCred({ username: u, password: pwd })
          setCredOpen(true)
          load()
        }} />
      </div>

      <div className="border rounded-md">
        <table className="w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-3 w-1/6">Username</th>
              <th className="text-left p-3 w-1/6">Email</th>
              <th className="text-left p-3 w-1/8">Role</th>
              <th className="text-left p-3 w-1/8">Status</th>
              <th className="text-left p-3 w-1/8">2FA</th>
              <th className="text-left p-3 w-1/6">Last Login</th>
              <th className="text-left p-3 w-1/6">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(u => (
              <tr key={u.user_id} className="border-t hover:bg-muted/50">
                <td className="p-3 font-medium truncate">{u.user_id}</td>
                <td className="p-3 truncate">{u.email || '-'}</td>
                <td className="p-3">
                  <Select defaultValue={u.role} onValueChange={(v) => onChangeRole(u, v)}>
                    <SelectTrigger className="w-24 h-7 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">viewer</SelectItem>
                      <SelectItem value="administrator">admin</SelectItem>
                    </SelectContent>
                  </Select>
                </td>
                <td className="p-3">
                  <span className={`px-2 py-0.5 rounded text-xs ${u.status==='active'?'bg-green-100 text-green-700':u.status==='pending'?'bg-yellow-100 text-yellow-700':'bg-red-100 text-red-700'}`}>{u.status}</span>
                </td>
                <td className="p-3">
                  <Button size="sm" variant={u.two_fa ? 'secondary' : 'outline'} onClick={() => onToggle2FA(u)} className="h-7 px-2">
                    <Shield className={`h-3 w-3 ${u.two_fa ? 'text-green-600' : ''}`} />
                  </Button>
                </td>
                <td className="p-3 text-xs truncate">{u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</td>
                <td className="p-3">
                  <div className="flex gap-1">
                    {u.status !== 'active' && (
                      <Button size="sm" onClick={() => onApprove(u)} className="h-7 px-2" title="Approve">
                        <Check className="h-3 w-3" />
                      </Button>
                    )}
                    {u.status !== 'suspended' && (
                      <Button size="sm" variant="destructive" onClick={() => onSuspend(u)} className="h-7 px-2" title="Suspend">
                        <X className="h-3 w-3" />
                      </Button>
                    )}
                    <EditRoleButton user={u} onSaved={load} />
                    <ResetPasswordButton user={u} onDone={(pwd) => {
                      setCred({ username: u.user_id, password: pwd })
                      setCredOpen(true)
                    }} />
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td className="p-4 text-center text-muted-foreground" colSpan={7}>No users</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between py-2">
        <div className="text-sm text-muted-foreground">Page {page}, total {total}</div>
        <div className="flex items-center gap-2">
          <Select value={String(limit)} onValueChange={(v) => { setLimit(parseInt(v || '20', 10)); setPage(1) }}>
            <SelectTrigger className="w-[100px]"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="10">10 / page</SelectItem>
              <SelectItem value="20">20 / page</SelectItem>
              <SelectItem value="50">50 / page</SelectItem>
            </SelectContent>
          </Select>
          <div className="flex gap-2">
            <Button variant="outline" disabled={page<=1} onClick={() => setPage(p => Math.max(1, p-1))}>Prev</Button>
            <Button variant="outline" disabled={(page*limit)>=total} onClick={() => setPage(p => p+1)}>Next</Button>
          </div>
        </div>
      </div>

    </div>
  )
}

function EditRoleButton({ user, onSaved }: { user: UserRow; onSaved: () => void }) {
  const { toast } = useToast()
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
      toast({
        title: 'Saved',
        description: `Role updated for ${user.user_id}. User may need to re-login to see changes.`,
        duration: 5000
      })
      setOpen(false)
      onSaved()
    } catch (err: any) {
      toast({ title: 'Save failed', description: err?.message || String(err), variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={async (v) => {
      setOpen(v)
      if (v) {
        try {
          const details = await apiClient.adminGetUser(user.user_id)
          setRole(details?.role || user.role)
          setStatus(details?.status || user.status)
          setPerms(details?.permissions || [])
          setQuotaD((details?.quota_daily ?? '') === '' ? '' : String(details?.quota_daily))
          setQuotaM((details?.quota_monthly ?? '') === '' ? '' : String(details?.quota_monthly))
        } catch (e:any) {
          const { title, description } = mapApiErrorToMessage(e)
          toast({ title, description, variant: 'destructive' })
        }
      }
    }}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" className="h-7 px-2" title="Edit Role">
          <Edit className="h-3 w-3" />
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Role & Permissions</DialogTitle>
          <DialogDescription>Adjust role, permissions and quotas</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <div className="text-xs mb-1 text-muted-foreground">Role</div>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">viewer</SelectItem>
                <SelectItem value="administrator">administrator</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <div className="text-xs mb-1 text-muted-foreground">Status</div>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="active">active</SelectItem>
                <SelectItem value="pending">pending</SelectItem>
                <SelectItem value="suspended">suspended</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="sm:col-span-2">
            <div className="text-xs mb-1 text-muted-foreground">Permissions</div>
            <div className="flex flex-wrap gap-3">
              {['read','download','upload','admin'].map(p => (
                <label key={p} className="flex items-center gap-2 text-sm">
                  <input type="checkbox" checked={perms.includes(p)} onChange={() => togglePerm(p)} />
                  {p}
                </label>
              ))}
            </div>
          </div>
          <div>
            <div className="text-xs mb-1 text-muted-foreground">Daily quota (-1 unlimited)</div>
            <Input type="number" value={quotaD} onChange={e => setQuotaD(e.target.value)} placeholder="-1" />
          </div>
          <div>
            <div className="text-xs mb-1 text-muted-foreground">Monthly quota (-1 unlimited)</div>
            <Input type="number" value={quotaM} onChange={e => setQuotaM(e.target.value)} placeholder="-1" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
          <Button onClick={save} disabled={busy}>{busy ? 'Saving...' : 'Save'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CreateUserModal({ onCreated }: { onCreated: (username: string, password: string) => void }) {
  const { toast } = useToast()
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [role, setRole] = useState("viewer")
  const [mustReset, setMustReset] = useState(true)
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)

  const createUser = async () => {
    if (!username) {
      toast({ title: 'Username required', variant: 'destructive' })
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
      toast({ title, description, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="flex items-center gap-2">
          <UserPlus className="h-4 w-4" />
          Create User
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create User</DialogTitle>
          <DialogDescription>Generate a one-time password and optionally force reset.</DialogDescription>
        </DialogHeader>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
          <Input placeholder="Email (optional)" value={email} onChange={e => setEmail(e.target.value)} />
          <div>
            <div className="text-xs mb-1 text-muted-foreground">Role</div>
            <Select value={role} onValueChange={setRole}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="viewer">viewer</SelectItem>
                <SelectItem value="administrator">administrator</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={mustReset} onChange={e => setMustReset(e.target.checked)} />
            Force password reset
          </label>
        </div>
        <DialogFooter>
          <Button variant="secondary" onClick={() => setOpen(false)} disabled={busy}>Cancel</Button>
          <Button onClick={createUser} disabled={busy}>{busy ? 'Creating...' : 'Create'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordButton({ user, onDone }: { user: UserRow; onDone: (password: string) => void }) {
  const { toast } = useToast()
  const [busy, setBusy] = useState(false)
  const [confirmOpen, setConfirmOpen] = useState(false)

  const onReset = async () => {
    setBusy(true)
    try {
      const data = await apiClient.adminResetPassword(user.user_id)
      const pwd = data?.temporary_password || ''
      onDone(pwd)
      toast({ title: 'Password reset', description: user.user_id })
      setConfirmOpen(false)
    } catch (err: any) {
      const { title, description } = mapApiErrorToMessage(err)
      toast({ title, description, variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
      <DialogTrigger asChild>
        <Button size="sm" variant="outline" className="h-7 px-2" title="Reset Password">
          <Key className="h-3 w-3" />
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset password for {user.user_id}?</DialogTitle>
          <DialogDescription>This generates a new temporary password and forces reset on next login.</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="secondary" onClick={() => setConfirmOpen(false)} disabled={busy}>Cancel</Button>
          <Button variant="destructive" onClick={onReset} disabled={busy}>{busy ? 'Resetting...' : 'Reset Password'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function CredentialsModal({ open, onOpenChange, creds }: { open: boolean; onOpenChange: (v: boolean) => void; creds: { username?: string; password?: string } | null }) {
  const username = creds?.username || ''
  const password = creds?.password || ''

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password)
    } catch {
      // ignore
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
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Temporary Credentials</DialogTitle>
          <DialogDescription>Copy or download the password now. It won’t be shown again.</DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <div className="text-sm">Username</div>
          <Input readOnly value={username} />
          <div className="text-sm">Temporary Password</div>
          <div className="flex gap-2">
            <Input readOnly value={password} />
            <Button onClick={copy} variant="outline">Copy</Button>
            <Button onClick={download}>Download</Button>
          </div>
          <div className="text-xs text-muted-foreground">Ask the user to login and change the password immediately.</div>
        </div>
        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
