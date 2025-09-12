'use client'

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { apiClient } from "@/lib/api"
import { formatFileSize, formatDate } from "@/lib/utils"
import { useToast } from "@/lib/use-toast"
import { usePermissions } from "@/lib/permissions"
import {
  Trash2,
  RefreshCw,
  RotateCcw,
  AlertTriangle,
  FileText,
  Clock,
  User,
  Loader2,
  X
} from "lucide-react"

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
  const { toast } = useToast()
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
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to load recycle bin'
      })
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
      toast({
        title: "Success",
        description: 'File restored successfully'
      })
      loadRecycleBin() // Refresh the list
    } catch (error) {
      console.error('Restore failed:', error)
      toast({
        variant: "destructive",
        title: "Restore Failed",
        description: error instanceof Error ? error.message : 'Restore failed'
      })
    } finally {
      setRestoringFile(null)
      setRestoreDialog({ isOpen: false, item: null })
    }
  }

  const handleClearRecycleBin = async () => {
    setIsClearing(true)
    try {
      await apiClient.clearRecycleBin()
      toast({
        title: "Success",
        description: 'Recycle bin cleared successfully'
      })
      loadRecycleBin()
    } catch (error) {
      console.error('Clear failed:', error)
      toast({
        variant: "destructive",
        title: "Clear Failed",
        description: error instanceof Error ? error.message : 'Failed to clear recycle bin'
      })
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
        <CardContent className="flex items-center justify-center py-12">
          <div className="flex items-center gap-2 text-gray-500">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading recycle bin...
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Trash2 className="h-5 w-5" />
                Recycle Bin
              </CardTitle>
              <CardDescription>
                Manage deleted files. Files are automatically purged after 90 days.
              </CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Button variant="outline" size="sm" onClick={loadRecycleBin}>
                <RefreshCw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
              {permissions?.canAccessRecycle && items.length > 0 && (
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => setShowClearDialog(true)}
                >
                  <Trash2 className="h-4 w-4 mr-2" />
                  Clear All
                </Button>
              )}
            </div>
          </div>
        </CardHeader>
      </Card>

      {/* Items List */}
      <Card>
        <CardContent className="pt-6">
          {items.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <Trash2 className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>Recycle bin is empty</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b text-left text-sm text-gray-500">
                    <th className="pb-4 font-medium w-1/4">File Name</th>
                    <th className="pb-4 font-medium w-20">Size</th>
                    <th className="pb-4 font-medium w-24">Deleted By</th>
                    <th className="pb-4 font-medium w-32">Deleted At</th>
                    <th className="pb-4 font-medium w-24">Days Left</th>
                    <th className="pb-4 font-medium w-32">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id} className="border-b last:border-0 hover:bg-gray-50">
                      <td className="py-4">
                        <div className="flex items-center gap-3">
                          <div className="flex-shrink-0">
                            <FileText className="h-5 w-5 text-gray-400" />
                          </div>
                          <div>
                            <div className="font-medium text-gray-900">
                              {item.originalName}
                            </div>
                            {item.description && (
                              <div className="text-sm text-gray-500 mt-1">{item.description}</div>
                            )}
                            {!item.fileExists && (
                              <div className="text-sm text-red-500 mt-1 flex items-center gap-1">
                                <AlertTriangle className="h-3 w-3" />
                                Physical file missing
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="py-4 text-sm text-gray-600">
                        {formatFileSize(item.size)}
                      </td>
                      <td className="py-4 text-sm text-gray-600">
                        <div className="flex items-center gap-2">
                          <User className="h-3 w-3" />
                          <span>{item.deletedBy || "unknown"}</span>
                        </div>
                      </td>
                      <td className="py-4 text-sm text-gray-600">
                        <div className="flex items-center gap-2">
                          <Clock className="h-3 w-3" />
                          <span>{formatDate(item.deletedAt)}</span>
                        </div>
                      </td>
                      <td className="py-4 text-sm">
                        <span className={`px-2 py-1 rounded-full text-xs ${
                          item.daysUntilPurge <= 7
                            ? 'bg-red-100 text-red-800'
                            : item.daysUntilPurge <= 30
                            ? 'bg-yellow-100 text-yellow-800'
                            : 'bg-green-100 text-green-800'
                        }`}>
                          {item.daysUntilPurge <= 0 ? 'Expired' : `${item.daysUntilPurge} days`}
                        </span>
                      </td>
                      <td className="py-4">
                        <div className="flex items-center gap-2">
                          {permissions?.canAccessRecycle && (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleRestore(item)}
                              disabled={restoringFile === item.id}
                              title="Restore File"
                            >
                              {restoringFile === item.id ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <RotateCcw className="h-4 w-4" />
                              )}
                            </Button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Clear All Confirmation Dialog */}
      {permissions?.canAccessRecycle && (
      <Dialog open={showClearDialog} onOpenChange={setShowClearDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-red-600">
              <AlertTriangle className="h-5 w-5" />
              Clear Recycle Bin
            </DialogTitle>
            <DialogDescription>
              This will permanently delete all {items.length} files in the recycle bin.
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowClearDialog(false)}
              disabled={isClearing}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleClearRecycleBin}
              disabled={isClearing}
            >
              {isClearing ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Clearing...
                </>
              ) : (
                <>
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear All
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      )}

      {/* Restore Confirmation Dialog */}
      {permissions?.canAccessRecycle && (
      <Dialog open={restoreDialog.isOpen} onOpenChange={(open) => setRestoreDialog({ isOpen: open, item: null })}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-green-600">
              <RotateCcw className="h-5 w-5" />
              Confirm Restore
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to restore "<strong>{restoreDialog.item?.originalName}</strong>"?
              The file will be moved back to the active files list.
            </DialogDescription>
          </DialogHeader>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRestoreDialog({ isOpen: false, item: null })}
            >
              Cancel
            </Button>
            <Button
              variant="default"
              onClick={confirmRestore}
              className="bg-green-600 hover:bg-green-700"
            >
              <RotateCcw className="mr-2 h-4 w-4" />
              Restore File
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      )}
    </div>
  )
}
