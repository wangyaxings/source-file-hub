"use client"

import React, { useEffect, useMemo, useState } from 'react'
import apiClient from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { useToast } from "@/lib/use-toast"

type UserRow = {
  user_id: string
  email?: string
  role: string
  status: string
  two_fa: boolean
  last_login?: string
}

export default function UserManagement() {
  const [loading, setLoading] = useState(false)
  const [users, setUsers] = useState<UserRow[]>([])
  const [filter, setFilter] = useState('')
  const { toast } = useToast()

  const load = async () => {
    setLoading(true)
    try {
      const list = await apiClient.adminListUsers()
      setUsers(list as UserRow[])
    } catch (err: any) {
      toast({ title: 'Failed to load users', description: err?.message || String(err), variant: 'destructive' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const filtered = useMemo(() => {
    const kw = filter.trim().toLowerCase()
    if (!kw) return users
    return users.filter(u => u.user_id.toLowerCase().includes(kw) || (u.email || '').toLowerCase().includes(kw))
  }, [users, filter])

  const onChangeRole = async (u: UserRow, role: string) => {
    try {
      await apiClient.adminUpdateUser(u.user_id, { role })
      toast({ title: 'Role updated', description: `${u.user_id} → ${role}` })
      load()
    } catch (err: any) {
      toast({ title: 'Failed to update role', description: err?.message || String(err), variant: 'destructive' })
    }
  }

  const onApprove = async (u: UserRow) => {
    try {
      await apiClient.adminApproveUser(u.user_id)
      toast({ title: 'User approved', description: u.user_id })
      load()
    } catch (err: any) {
      toast({ title: 'Failed to approve', description: err?.message || String(err), variant: 'destructive' })
    }
  }

  const onSuspend = async (u: UserRow) => {
    try {
      await apiClient.adminSuspendUser(u.user_id)
      toast({ title: 'User suspended', description: u.user_id })
      load()
    } catch (err: any) {
      toast({ title: 'Failed to suspend', description: err?.message || String(err), variant: 'destructive' })
    }
  }

  const onToggle2FA = async (u: UserRow) => {
    try {
      if (u.two_fa) {
        await apiClient.adminDisable2FA(u.user_id)
      } else {
        await apiClient.adminUpdateUser(u.user_id, { twofa_enabled: true })
      }
      toast({ title: '2FA updated', description: u.user_id })
      load()
    } catch (err: any) {
      toast({ title: 'Failed to update 2FA', description: err?.message || String(err), variant: 'destructive' })
    }
  }

  const isAdmin = (() => {
    const cu = apiClient.getCurrentUser()
    return cu?.role === 'administrator' || cu?.username === 'admin'
  })()

  if (!isAdmin) {
    return <div className="p-6">403 Forbidden: Admins only.</div>
  }

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">User Management</h1>
        <div className="flex gap-2 items-center">
          <Input placeholder="Filter by username/email" value={filter} onChange={(e) => setFilter(e.target.value)} className="w-64" />
          <Button variant="secondary" onClick={load} disabled={loading}>{loading ? 'Loading...' : 'Refresh'}</Button>
        </div>
      </div>

      <CreateUserPanel onCreated={() => load()} />

      <div className="overflow-x-auto border rounded-md">
        <table className="min-w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-2">Username</th>
              <th className="text-left p-2">Email</th>
              <th className="text-left p-2">Role</th>
              <th className="text-left p-2">Status</th>
              <th className="text-left p-2">2FA</th>
              <th className="text-left p-2">Last Login</th>
              <th className="text-left p-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(u => (
              <tr key={u.user_id} className="border-t">
                <td className="p-2 font-medium">{u.user_id}</td>
                <td className="p-2">{u.email || '-'}</td>
                <td className="p-2">
                  <Select defaultValue={u.role} onValueChange={(v) => onChangeRole(u, v)}>
                    <SelectTrigger className="w-[160px]"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">viewer</SelectItem>
                      <SelectItem value="administrator">administrator</SelectItem>
                    </SelectContent>
                  </Select>
                </td>
                <td className="p-2">
                  <span className={`px-2 py-0.5 rounded text-xs ${u.status==='active'?'bg-green-100 text-green-700':u.status==='pending'?'bg-yellow-100 text-yellow-700':'bg-red-100 text-red-700'}`}>{u.status}</span>
                </td>
                <td className="p-2">
                  <Button size="sm" variant={u.two_fa ? 'secondary' : 'outline'} onClick={() => onToggle2FA(u)}>
                    {u.two_fa ? 'Disable 2FA' : 'Enable 2FA'}
                  </Button>
                </td>
                <td className="p-2">{u.last_login ? new Date(u.last_login).toLocaleString() : '-'}</td>
                <td className="p-2 flex gap-2">
                  {u.status !== 'active' && (
                    <Button size="sm" onClick={() => onApprove(u)}>Approve</Button>
                  )}
                  {u.status !== 'suspended' && (
                    <Button size="sm" variant="destructive" onClick={() => onSuspend(u)}>Suspend</Button>
                  )}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td className="p-4 text-center text-muted-foreground" colSpan={7}>No users</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function CreateUserPanel({ onCreated }: { onCreated: () => void }) {
  const { toast } = useToast()
  const [username, setUsername] = useState("")
  const [email, setEmail] = useState("")
  const [role, setRole] = useState("viewer")
  const [mustReset, setMustReset] = useState(true)
  const [busy, setBusy] = useState(false)

  const createUser = async () => {
    if (!username) {
      toast({ title: 'Username required', variant: 'destructive' })
      return
    }
    setBusy(true)
    try {
      const resp = await apiClient.adminCreateUser({ username, email, role, must_reset: mustReset })
      const pwd = (resp as any)?.initial_password || '(hidden)'
      toast({ title: 'User created', description: `Initial password: ${pwd}` })
      setUsername("")
      setEmail("")
      setRole("viewer")
      setMustReset(true)
      onCreated()
    } catch (err: any) {
      toast({ title: 'Create failed', description: err?.message || String(err), variant: 'destructive' })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border rounded-md p-4 space-y-3">
      <div className="font-medium">Create User</div>
      <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
        <Input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
        <Input placeholder="Email (optional)" value={email} onChange={e => setEmail(e.target.value)} />
        <Select value={role} onValueChange={setRole}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="viewer">viewer</SelectItem>
            <SelectItem value="administrator">administrator</SelectItem>
          </SelectContent>
        </Select>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={mustReset} onChange={e => setMustReset(e.target.checked)} />
          Force password reset
        </label>
        <Button onClick={createUser} disabled={busy}>{busy ? 'Creating...' : 'Create'}</Button>
      </div>
      <div className="text-xs text-muted-foreground">After creation, an initial password will be generated and shown once. Ask the user to login and change password immediately.</div>
    </div>
  )
}
