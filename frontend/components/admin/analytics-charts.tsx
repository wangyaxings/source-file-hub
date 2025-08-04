'use client'

import { useState, useEffect, useMemo } from "react"
import ReactECharts from 'echarts-for-react'
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useToast } from "@/lib/use-toast"
import {
  RefreshCw,
  Download,
  Calendar,
  TrendingUp,
  Activity,
  Clock,
  PieChart,
  BarChart3,
  Users,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Loader2
} from "lucide-react"

interface AnalyticsData {
  timeRange: {
    start: string
    end: string
  }
  overview: {
    totalRequests: number
    totalApiKeys: number
    activeUsers: number
    avgResponseTime: number
    successRate: number
    errorRate: number
  }
  trends: {
    date: string
    requests: number
    successCount: number
    errorCount: number
    avgResponseTime: number
  }[]
  apiKeyUsage: {
    apiKeyId: string
    apiKeyName: string
    userId: string
    requests: number
    successRate: number
    lastUsed: string
  }[]
  operationTypes: {
    operation: string
    count: number
    percentage: number
  }[]
  hourlyDistribution: {
    hour: number
    requests: number
  }[]
  errorTypes: {
    statusCode: number
    message: string
    count: number
  }[]
}

interface AnalyticsChartsProps {
  usageLogs: any[]
  apiKeys: any[]
}

export function AnalyticsCharts({ usageLogs, apiKeys }: AnalyticsChartsProps) {
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(false)
  const [timeRange, setTimeRange] = useState('7d')
  const [selectedApiKey, setSelectedApiKey] = useState<string>('all')
  const [selectedUser, setSelectedUser] = useState<string>('all')
  const [customDateStart, setCustomDateStart] = useState('')
  const [customDateEnd, setCustomDateEnd] = useState('')
  const [analyticsData, setAnalyticsData] = useState<AnalyticsData | null>(null)
  const [isMounted, setIsMounted] = useState(false)

  // Ensure component only renders on client side
  useEffect(() => {
    setIsMounted(true)
  }, [])

  // Fetch analytics data from backend
  const fetchAnalyticsData = async () => {
    setIsLoading(true)
    try {
      const params = new URLSearchParams({
        timeRange,
        apiKey: selectedApiKey,
        user: selectedUser
      })

      if (timeRange === 'custom') {
        if (customDateStart) params.append('startDate', customDateStart)
        if (customDateEnd) params.append('endDate', customDateEnd)
      }

      const response = await fetch(`/api/v1/web/admin/analytics/data?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        }
      })

      if (!response.ok) throw new Error('Failed to fetch analytics data')

      const result = await response.json()
      setAnalyticsData(result.data)
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Error",
        description: error instanceof Error ? error.message : 'Failed to load analytics data'
      })
      // Fallback to local processing
      setAnalyticsData(processLocalAnalyticsData())
    } finally {
      setIsLoading(false)
    }
  }

  // Fallback: Process data locally (simplified version)
  const processLocalAnalyticsData = (): AnalyticsData => {
    let filtered = [...usageLogs]
    const now = new Date()
    let startDate = new Date()

    // Apply time range filter
    switch (timeRange) {
      case '1d':
        startDate.setDate(now.getDate() - 1)
        break
      case '7d':
        startDate.setDate(now.getDate() - 7)
        break
      case '30d':
        startDate.setDate(now.getDate() - 30)
        break
      case 'custom':
        if (customDateStart) startDate = new Date(customDateStart)
        break
    }

    if (timeRange !== 'custom' || customDateStart) {
      filtered = filtered.filter(log => new Date(log.requestTime) >= startDate)
    }

    if (timeRange === 'custom' && customDateEnd) {
      const endDate = new Date(customDateEnd)
      filtered = filtered.filter(log => new Date(log.requestTime) <= endDate)
    }

    // Apply filters
    if (selectedApiKey !== 'all') {
      filtered = filtered.filter(log => log.apiKeyId === selectedApiKey)
    }

    if (selectedUser !== 'all') {
      filtered = filtered.filter(log => log.userId === selectedUser)
    }

    const totalRequests = filtered.length
    const successCount = filtered.filter(log => log.statusCode >= 200 && log.statusCode < 300).length
    const errorCount = totalRequests - successCount
    const avgResponseTime = totalRequests > 0
      ? filtered.reduce((sum, log) => sum + log.responseTimeMs, 0) / totalRequests
      : 0

    return {
      timeRange: {
        start: customDateStart || new Date(Date.now() - getDaysInMs(timeRange)).toISOString(),
        end: customDateEnd || new Date().toISOString()
      },
      overview: {
        totalRequests,
        totalApiKeys: new Set(filtered.map(log => log.apiKeyId)).size,
        activeUsers: new Set(filtered.map(log => log.userId)).size,
        avgResponseTime,
        successRate: totalRequests > 0 ? (successCount / totalRequests) * 100 : 0,
        errorRate: totalRequests > 0 ? (errorCount / totalRequests) * 100 : 0
      },
      trends: [],
      apiKeyUsage: [],
      operationTypes: [],
      hourlyDistribution: Array(24).fill(0).map((_, hour) => ({ hour, requests: 0 })),
      errorTypes: []
    }
  }

  // Fetch data when filters change
  useEffect(() => {
    fetchAnalyticsData()
  }, [timeRange, selectedApiKey, selectedUser, customDateStart, customDateEnd])

  // Initial load
  useEffect(() => {
    fetchAnalyticsData()
  }, [])

  const handleExportData = async () => {
    try {
      const params = new URLSearchParams({
        timeRange,
        apiKey: selectedApiKey,
        user: selectedUser,
        format: 'json'
      })

      if (timeRange === 'custom') {
        if (customDateStart) params.append('startDate', customDateStart)
        if (customDateEnd) params.append('endDate', customDateEnd)
      }

      const response = await fetch(`/api/v1/web/admin/analytics/export?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        }
      })

      if (!response.ok) throw new Error('Failed to export analytics data')

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `api-analytics-${new Date().toISOString().split('T')[0]}.json`
      link.click()
      URL.revokeObjectURL(url)

      toast({
        title: "Export Successful",
        description: "Analytics data has been exported successfully"
      })
    } catch (error) {
      toast({
        variant: "destructive",
        title: "Export Failed",
        description: error instanceof Error ? error.message : 'Failed to export data'
      })
    }
  }

  // Prevent SSR issues by not rendering until mounted
  if (!isMounted) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
              <span className="ml-2 text-gray-600">Initializing analytics...</span>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Show loading or no data states
  if (isLoading) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center justify-center h-64">
              <Loader2 className="h-8 w-8 animate-spin text-blue-600" />
              <span className="ml-2 text-gray-600">Loading analytics data...</span>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!analyticsData) {
    return (
      <div className="space-y-6">
        <Card>
          <CardContent className="p-6">
            <div className="text-center py-8 text-gray-500">
              <BarChart3 className="h-12 w-12 mx-auto mb-4 text-gray-300" />
              <p>No analytics data available</p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  // 请求趋势图表配置
  const trendChartOption = {
    title: {
      text: 'API Usage Trends',
      textStyle: { fontSize: 16, fontWeight: 'normal' }
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross' }
    },
    legend: {
      data: ['Total Requests', 'Success', 'Errors', 'Avg Response Time (ms)']
    },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: analyticsData?.trends?.map(t => t.date) || []
    },
    yAxis: [
      {
        type: 'value',
        name: 'Requests',
        position: 'left'
      },
      {
        type: 'value',
        name: 'Response Time (ms)',
        position: 'right'
      }
    ],
    series: [
      {
        name: 'Total Requests',
        type: 'line',
        data: analyticsData?.trends?.map(t => t.requests) || [],
        smooth: true,
        itemStyle: { color: '#3b82f6' }
      },
      {
        name: 'Success',
        type: 'line',
        data: analyticsData?.trends?.map(t => t.successCount) || [],
        smooth: true,
        itemStyle: { color: '#10b981' }
      },
      {
        name: 'Errors',
        type: 'line',
        data: analyticsData?.trends?.map(t => t.errorCount) || [],
        smooth: true,
        itemStyle: { color: '#ef4444' }
      },
      {
        name: 'Avg Response Time (ms)',
        type: 'line',
        yAxisIndex: 1,
        data: analyticsData?.trends?.map(t => Math.round(t.avgResponseTime)) || [],
        smooth: true,
        itemStyle: { color: '#8b5cf6' }
      }
    ]
  }

  // API Key使用量图表配置
  const apiKeyUsageChartOption = {
    title: {
      text: 'API Key Usage Distribution',
      textStyle: { fontSize: 16, fontWeight: 'normal' }
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: analyticsData?.apiKeyUsage?.slice(0, 10).map(item => item.apiKeyName) || [],
      axisLabel: {
        rotate: 45,
        formatter: (value: string) => value.length > 12 ? value.substring(0, 12) + '...' : value
      }
    },
    yAxis: { type: 'value', name: 'Requests' },
    series: [
      {
        name: 'Requests',
        type: 'bar',
        data: analyticsData?.apiKeyUsage?.slice(0, 10).map(item => item.requests) || [],
        itemStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: '#3b82f6' },
              { offset: 1, color: '#1e40af' }
            ]
          }
        }
      }
    ]
  }

  // 操作类型分布饼图配置
  const operationPieChartOption = {
    title: {
      text: 'Operation Types Distribution',
      textStyle: { fontSize: 16, fontWeight: 'normal' }
    },
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)'
    },
    legend: {
      orient: 'vertical',
      left: 'left'
    },
    series: [
      {
        name: 'Operations',
        type: 'pie',
        radius: '50%',
        data: analyticsData?.operationTypes?.slice(0, 8).map(item => ({
          value: item.count,
          name: item.operation
        })) || [],
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        }
      }
    ]
  }

  // 小时分布热力图配置
  const hourlyHeatmapOption = {
    title: {
      text: 'Hourly Request Distribution',
      textStyle: { fontSize: 16, fontWeight: 'normal' }
    },
    tooltip: {
      position: 'top',
      formatter: (params: any) => `${params.data[0]}:00 - ${params.data[1]} requests`
    },
    grid: { height: '50%', top: '10%' },
    xAxis: {
      type: 'category',
      data: Array.from({ length: 24 }, (_, i) => `${i}:00`),
      splitArea: { show: true }
    },
    yAxis: {
      type: 'category',
      data: ['Requests'],
      splitArea: { show: true }
    },
    visualMap: {
      min: 0,
      max: Math.max(...(analyticsData?.hourlyDistribution?.map(h => h.requests) || [0])),
      calculable: true,
      orient: 'horizontal',
      left: 'center',
      bottom: '15%',
      inRange: {
        color: ['#f0f9ff', '#3b82f6']
      }
    },
    series: [
      {
        name: 'Requests',
        type: 'heatmap',
        data: analyticsData?.hourlyDistribution?.map((hour, index) => [index, 0, hour.requests]) || [],
        label: {
          show: true
        },
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        }
      }
    ]
  }

  return (
    <div className="space-y-6">
      {/* 筛选控制栏 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Analytics Dashboard
          </CardTitle>
          <CardDescription>
            Comprehensive API usage analytics and insights
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-4 items-end">
            <div className="flex-1 min-w-[200px]">
              <Label htmlFor="timeRange">Time Range</Label>
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger>
                  <SelectValue placeholder="Select time range" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1d">Last 24 Hours</SelectItem>
                  <SelectItem value="7d">Last 7 Days</SelectItem>
                  <SelectItem value="30d">Last 30 Days</SelectItem>
                  <SelectItem value="custom">Custom Range</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {timeRange === 'custom' && (
              <>
                <div className="flex-1 min-w-[150px]">
                  <Label htmlFor="startDate">Start Date</Label>
                  <Input
                    id="startDate"
                    type="datetime-local"
                    value={customDateStart}
                    onChange={(e) => setCustomDateStart(e.target.value)}
                  />
                </div>
                <div className="flex-1 min-w-[150px]">
                  <Label htmlFor="endDate">End Date</Label>
                  <Input
                    id="endDate"
                    type="datetime-local"
                    value={customDateEnd}
                    onChange={(e) => setCustomDateEnd(e.target.value)}
                  />
                </div>
              </>
            )}

            <div className="flex-1 min-w-[200px]">
              <Label htmlFor="apiKey">API Key</Label>
              <Select value={selectedApiKey} onValueChange={setSelectedApiKey}>
                <SelectTrigger>
                  <SelectValue placeholder="All API Keys" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All API Keys</SelectItem>
                  {apiKeys.map(key => (
                    <SelectItem key={key.id} value={key.id}>
                      {key.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex-1 min-w-[200px]">
              <Label htmlFor="user">User</Label>
              <Select value={selectedUser} onValueChange={setSelectedUser}>
                <SelectTrigger>
                  <SelectValue placeholder="All Users" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Users</SelectItem>
                  {Array.from(new Set(usageLogs.map(log => log.userId))).map(userId => (
                    <SelectItem key={userId} value={userId}>
                      {userId}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <Button variant="outline" onClick={handleExportData}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 概览指标卡片 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <Activity className="h-8 w-8 text-blue-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Total Requests</p>
                <p className="text-2xl font-bold text-gray-900">
                  {analyticsData?.overview?.totalRequests?.toLocaleString() || '0'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <Users className="h-8 w-8 text-green-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Active Users</p>
                <p className="text-2xl font-bold text-gray-900">
                  {analyticsData?.overview?.activeUsers || '0'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <CheckCircle2 className="h-8 w-8 text-emerald-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Success Rate</p>
                <p className="text-2xl font-bold text-gray-900">
                  {analyticsData?.overview?.successRate?.toFixed(1) || '0.0'}%
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <XCircle className="h-8 w-8 text-red-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Error Rate</p>
                <p className="text-2xl font-bold text-gray-900">
                  {analyticsData?.overview?.errorRate?.toFixed(1) || '0.0'}%
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <Clock className="h-8 w-8 text-purple-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">Avg Response</p>
                <p className="text-2xl font-bold text-gray-900">
                  {Math.round(analyticsData?.overview?.avgResponseTime || 0)}ms
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-6">
            <div className="flex items-center">
              <TrendingUp className="h-8 w-8 text-orange-600" />
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-600">API Keys</p>
                <p className="text-2xl font-bold text-gray-900">
                  {analyticsData?.overview?.totalApiKeys || '0'}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 图表展示区域 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 请求趋势图 */}
        <Card className="lg:col-span-2">
          <CardContent className="p-6">
            <ReactECharts
              option={trendChartOption}
              style={{ height: '400px' }}
              opts={{ renderer: 'canvas' }}
            />
          </CardContent>
        </Card>

        {/* API Key使用量 */}
        <Card>
          <CardContent className="p-6">
            <ReactECharts
              option={apiKeyUsageChartOption}
              style={{ height: '350px' }}
              opts={{ renderer: 'canvas' }}
            />
          </CardContent>
        </Card>

        {/* 操作类型分布 */}
        <Card>
          <CardContent className="p-6">
            <ReactECharts
              option={operationPieChartOption}
              style={{ height: '350px' }}
              opts={{ renderer: 'canvas' }}
            />
          </CardContent>
        </Card>

        {/* 小时分布热力图 */}
        <Card className="lg:col-span-2">
          <CardContent className="p-6">
            <ReactECharts
              option={hourlyHeatmapOption}
              style={{ height: '300px' }}
              opts={{ renderer: 'canvas' }}
            />
          </CardContent>
        </Card>
      </div>

      {/* 详细数据表格 */}
      {analyticsData?.errorTypes && analyticsData.errorTypes.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-600" />
              Error Analysis
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left p-2">Status Code</th>
                    <th className="text-left p-2">Message</th>
                    <th className="text-left p-2">Count</th>
                    <th className="text-left p-2">Percentage</th>
                  </tr>
                </thead>
                <tbody>
                  {analyticsData.errorTypes.map((error, index) => (
                    <tr key={index} className="border-b">
                      <td className="p-2 font-mono">{error.statusCode}</td>
                      <td className="p-2">{error.message}</td>
                      <td className="p-2">{error.count}</td>
                      <td className="p-2">
                        {((error.count / analyticsData.overview.totalRequests) * 100).toFixed(2)}%
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// 辅助函数
function getDaysInMs(timeRange: string): number {
  switch (timeRange) {
    case '1d': return 24 * 60 * 60 * 1000
    case '7d': return 7 * 24 * 60 * 60 * 1000
    case '30d': return 30 * 24 * 60 * 60 * 1000
    default: return 7 * 24 * 60 * 60 * 1000
  }
}

function getStatusMessage(statusCode: number): string {
  const messages: { [key: number]: string } = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable'
  }
  return messages[statusCode] || 'Unknown Error'
}