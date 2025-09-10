"use client"

import React, { useEffect, useState } from 'react'
import { apiClient } from '@/lib/api'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

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
      const resp = await fetch(`/api/v1/web/admin/audit-logs?${qs.toString()}`, { headers: { 'Accept': 'application/json' } })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      setItems(data?.data?.items || [])
      setTotal(data?.data?.total || 0)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => { load() }, [page, limit])

  if (!mounted) return null

  return (
    <div className="space-y-4">
      <div className="flex gap-2 items-center flex-wrap">
        <Input placeholder="Actor" value={actor} onChange={e => setActor(e.target.value)} className="w-48" />
        <Input placeholder="Target user" value={target} onChange={e => setTarget(e.target.value)} className="w-48" />
        <Input placeholder="Action" value={action} onChange={e => setAction(e.target.value)} className="w-48" />
        <Button variant="secondary" onClick={() => { setPage(1); load() }} disabled={loading}>{loading ? 'Loading...' : 'Search'}</Button>
      </div>
      <div className="overflow-x-auto border rounded-md">
        <table className="min-w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-2">Time</th>
              <th className="text-left p-2">Actor</th>
              <th className="text-left p-2">Target</th>
              <th className="text-left p-2">Action</th>
              <th className="text-left p-2">Details</th>
            </tr>
          </thead>
          <tbody>
            {items.map((it, idx) => (
              <tr key={idx} className="border-t">
                <td className="p-2">{it.createdAt || it.created_at || ''}</td>
                <td className="p-2">{it.actor}</td>
                <td className="p-2">{it.targetUser || it.target_user}</td>
                <td className="p-2">{it.action}</td>
                <td className="p-2"><code className="text-xs break-words">{it.details}</code></td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td className="p-4 text-center text-muted-foreground" colSpan={5}>No records</td></tr>
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

