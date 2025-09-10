"use client"

import React, { useMemo, useState, useEffect } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { APIKeyManagement } from "@/components/admin/api-key-management"
import UserManagement from "@/components/admin/user-management"
import { AuditLogsPanel } from "@/components/admin/audit-logs-panel"
import { Shield, KeyRound, Users, ListChecks } from "lucide-react"

export function AdminPanel({ initialTab }: { initialTab?: 'keys'|'users'|'audit' }) {
  // 修改这一行的 grid 类名
  const tabsClass = useMemo(() => "grid w-full grid-cols-3", [])
  const [subTab, setSubTab] = useState<'keys'|'users'|'audit'>(initialTab || 'keys')

  useEffect(() => {
    if (initialTab) setSubTab(initialTab)
  }, [initialTab])

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2 text-xl font-semibold">
        <Shield className="h-5 w-5" />
        Admin Panel
      </div>
      <Tabs value={subTab} onValueChange={(v:any)=>setSubTab(v)} className="space-y-4">
        {/* 确保三个tab在同一行显示，样式一致 */}
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="keys" className="flex items-center gap-2">
            <KeyRound className="h-4 w-4" />
            API Keys
          </TabsTrigger>
          <TabsTrigger value="users" className="flex items-center gap-2">
            <Users className="h-4 w-4" />
            Users
          </TabsTrigger>
          <TabsTrigger value="audit" className="flex items-center gap-2">
            <ListChecks className="h-4 w-4" />
            Audit Logs
          </TabsTrigger>
        </TabsList>
        <TabsContent value="keys" className="space-y-4">
          <APIKeyManagement />
        </TabsContent>
        <TabsContent value="users" className="space-y-4">
          <UserManagement />
        </TabsContent>
        <TabsContent value="audit" className="space-y-4">
          <AuditLogsPanel />
        </TabsContent>
      </Tabs>
    </div>
  )
}
