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
  Loader2,
  Key
} from "lucide-react"

// 颜色辅助函数
function adjustColorBrightness(color: string, amount: number): string {
  const usePound = color[0] === "#"
  const col = usePound ? color.slice(1) : color
  const num = parseInt(col, 16)
  let r = (num >> 16) + amount
  let g = (num >> 8 & 0x00FF) + amount
  let b = (num & 0x0000FF) + amount
  r = r > 255 ? 255 : r < 0 ? 0 : r
  g = g > 255 ? 255 : g < 0 ? 0 : g
  b = b > 255 ? 255 : b < 0 ? 0 : b
  return (usePound ? "#" : "") + (r << 16 | g << 8 | b).toString(16).padStart(6, '0')
}

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
    apiKeyName: string
    requests: number
    lastUsed: string
  }[]
  operationTypes: {
    operation: string
    count: number
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
        ...(selectedApiKey !== 'all' && { apiKey: selectedApiKey }),
        ...(selectedUser !== 'all' && { user: selectedUser })
      })

      if (timeRange === 'custom') {
        if (customDateStart) params.append('startDate', customDateStart)
        if (customDateEnd) params.append('endDate', customDateEnd)
      }

      const response = await fetch(`/api/v1/web/admin/analytics/data?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const data = await response.json()
        setAnalyticsData(data.data)
      } else {
        throw new Error(`HTTP ${response.status}`)
      }
    } catch (error) {
      toast({
        title: "Failed to fetch analytics data",
        description: error instanceof Error ? error.message : 'Unknown error occurred',
        variant: "destructive"
      })
      // Fallback to local processing
      setAnalyticsData(processLocalAnalyticsData())
    } finally {
      setIsLoading(false)
    }
  }

  // Process local analytics data as fallback
  const processLocalAnalyticsData = (): AnalyticsData => {
    if (!usageLogs || usageLogs.length === 0) {
      return {
        timeRange: { start: new Date().toISOString(), end: new Date().toISOString() },
        overview: { totalRequests: 0, totalApiKeys: 0, activeUsers: 0, avgResponseTime: 0, successRate: 0, errorRate: 0 },
        trends: [], apiKeyUsage: [], operationTypes: [], hourlyDistribution: [], errorTypes: []
      }
    }

    const now = new Date()
    const cutoffTime = new Date(now.getTime() - getDaysInMs(timeRange))

    let filteredLogs = usageLogs.filter(log => {
      const logDate = new Date(log.timestamp)
      let includeByTime = true

      if (timeRange !== 'custom' || customDateStart) {
        includeByTime = logDate >= cutoffTime
      }

      if (timeRange === 'custom' && customDateEnd) {
        const endDate = new Date(customDateEnd)
        includeByTime = includeByTime && logDate <= endDate
      }

      if (selectedApiKey !== 'all') {
        includeByTime = includeByTime && log.apiKeyId === selectedApiKey
      }

      if (selectedUser !== 'all') {
        includeByTime = includeByTime && log.userId === selectedUser
      }

      return includeByTime
    })

    const totalRequests = filteredLogs.length
    const successCount = filteredLogs.filter(log => log.statusCode >= 200 && log.statusCode < 400).length
    const errorCount = totalRequests - successCount
    const avgResponseTime = totalRequests > 0 ? filteredLogs.reduce((sum, log) => sum + (log.responseTime || 0), 0) / totalRequests : 0

    return {
      timeRange: {
        start: cutoffTime.toISOString(),
        end: now.toISOString()
      },
      overview: {
        totalRequests,
        totalApiKeys: apiKeys.length,
        activeUsers: Array.from(new Set(filteredLogs.map(log => log.userId))).length,
        avgResponseTime,
        successRate: totalRequests > 0 ? (successCount / totalRequests) * 100 : 100,
        errorRate: totalRequests > 0 ? (errorCount / totalRequests) * 100 : 0
      },
      trends: [],
      apiKeyUsage: [],
      operationTypes: [],
      hourlyDistribution: [],
      errorTypes: []
    }
  }

  // Auto-fetch data when component mounts and filters change
  useEffect(() => {
    if (isMounted) {
      fetchAnalyticsData()
    }
  }, [isMounted, timeRange, selectedApiKey, selectedUser, customDateStart, customDateEnd])

  // Process filter options
  const uniqueApiKeys = useMemo(() => {
    return Array.from(new Set(usageLogs.map(log => log.apiKeyId))).filter(Boolean)
  }, [usageLogs])

  const uniqueUsers = useMemo(() => {
    return Array.from(new Set(usageLogs.map(log => log.userId))).filter(Boolean)
  }, [usageLogs])

  const handleExportData = async () => {
    try {
      const params = new URLSearchParams({
        timeRange,
        ...(selectedApiKey !== 'all' && { apiKey: selectedApiKey }),
        ...(selectedUser !== 'all' && { user: selectedUser })
      })

      if (timeRange === 'custom') {
        if (customDateStart) params.append('startDate', customDateStart)
        if (customDateEnd) params.append('endDate', customDateEnd)
      }

      const response = await fetch(`/api/v1/web/admin/analytics/export?${params}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        }
      })

      if (response.ok) {
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `analytics-${timeRange}-${new Date().toISOString().split('T')[0]}.json`
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)

        toast({
          title: "Export successful",
          description: "Analytics data has been exported"
        })
      }
    } catch (error) {
      toast({
        title: "Export failed",
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

  // 高级主题配置
  const chartTheme = {
    color: ['#3b82f6', '#10b981', '#f59e0b', '#8b5cf6', '#06b6d4', '#ef4444'],
    backgroundColor: 'transparent',
    textStyle: {
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#0f172a'
    },
    title: {
      textStyle: {
        color: '#0f172a',
        fontWeight: 600,
        fontSize: 16
      }
    },
    legend: {
      textStyle: {
        color: '#64748b',
        fontSize: 12
      }
    },
    grid: {
      borderColor: '#e2e8f0'
    }
  }

  // 请求趋势图表配置 - 多轴线图
  const trendChartOption = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross' },
      backgroundColor: 'rgba(255, 255, 255, 0.95)',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 12 }
    },
    legend: {
      data: ['Total Requests', 'Successful', 'Errors', 'Avg Response Time (ms)'],
      bottom: 0,
      textStyle: { fontSize: 12 }
    },
    grid: { left: '3%', right: '4%', bottom: '15%', containLabel: true },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: analyticsData?.trends?.map(t => t.date) || [],
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisLabel: { color: '#64748b', fontSize: 12 }
    },
    yAxis: [
      {
        type: 'value',
        name: 'Requests',
        position: 'left',
        axisLine: { lineStyle: { color: '#e2e8f0' } },
        axisLabel: { color: '#64748b', fontSize: 12 },
        splitLine: { lineStyle: { color: '#f1f5f9', type: 'dashed' } }
      },
      {
        type: 'value',
        name: 'Response Time (ms)',
        position: 'right',
        axisLine: { lineStyle: { color: '#e2e8f0' } },
        axisLabel: { color: '#64748b', fontSize: 12 }
      }
    ],
    series: [
      {
        name: 'Total Requests',
        type: 'line',
        yAxisIndex: 0,
        data: analyticsData?.trends?.map(t => t.requests) || [],
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: { width: 3 },
        areaStyle: { opacity: 0.1 }
      },
      {
        name: 'Successful',
        type: 'line',
        yAxisIndex: 0,
        data: analyticsData?.trends?.map(t => t.successCount) || [],
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: { width: 3 }
      },
      {
        name: 'Errors',
        type: 'line',
        yAxisIndex: 0,
        data: analyticsData?.trends?.map(t => t.errorCount) || [],
        smooth: true,
        symbol: 'circle',
        symbolSize: 6,
        lineStyle: { width: 3 }
      },
      {
        name: 'Avg Response Time (ms)',
        type: 'line',
        yAxisIndex: 1,
        data: analyticsData?.trends?.map(t => Math.round(t.avgResponseTime)) || [],
        smooth: true,
        symbol: 'diamond',
        symbolSize: 6,
        lineStyle: { width: 2, type: 'dashed' }
      }
    ]
  }

  // API Key使用量图表配置 - 水平条形图
  const apiKeyUsageChartOption = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'shadow' },
      backgroundColor: 'rgba(255, 255, 255, 0.95)',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 12 }
    },
    grid: { left: '15%', right: '10%', bottom: '10%', top: '10%', containLabel: true },
    xAxis: {
      type: 'value',
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisLabel: { color: '#64748b', fontSize: 12 },
      splitLine: { lineStyle: { color: '#f1f5f9', type: 'dashed' } }
    },
    yAxis: {
      type: 'category',
      data: analyticsData?.apiKeyUsage?.slice(0, 10).map(item =>
        item.apiKeyName.length > 15 ? item.apiKeyName.substring(0, 15) + '...' : item.apiKeyName
      ) || [],
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisLabel: { color: '#64748b', fontSize: 12 }
    },
    series: [{
      name: 'Requests',
      type: 'bar',
      data: analyticsData?.apiKeyUsage?.slice(0, 10).map(item => item.requests) || [],
      itemStyle: {
        borderRadius: [0, 6, 6, 0],
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 1,
          y2: 0,
          colorStops: [
            { offset: 0, color: '#3b82f6' },
            { offset: 1, color: '#06b6d4' }
          ]
        }
      },
      emphasis: {
        itemStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 1,
            y2: 0,
            colorStops: [
              { offset: 0, color: '#2563eb' },
              { offset: 1, color: '#0891b2' }
            ]
          }
        }
      },
      barWidth: '60%'
    }]
  }

  // 操作类型分布饼图配置 - 环形图
  const operationPieChartOption = {
    tooltip: {
      trigger: 'item',
      formatter: '{a} <br/>{b}: {c} ({d}%)',
      backgroundColor: 'rgba(255, 255, 255, 0.95)',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 12 }
    },
    legend: {
      bottom: 0,
      textStyle: { fontSize: 12 }
    },
    series: [{
      name: 'Operations',
      type: 'pie',
      radius: ['40%', '70%'],
      center: ['50%', '45%'],
      avoidLabelOverlap: false,
      label: { show: false, position: 'center' },
      emphasis: {
        label: { show: true, fontSize: 14, fontWeight: 'bold' },
        itemStyle: {
          shadowBlur: 10,
          shadowOffsetX: 0,
          shadowColor: 'rgba(0, 0, 0, 0.5)'
        }
      },
      labelLine: { show: false },
      data: analyticsData?.operationTypes?.slice(0, 8).map((item, index) => ({
        value: item.count,
        name: item.operation,
        itemStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 1,
            y2: 1,
            colorStops: [
              { offset: 0, color: chartTheme.color[index % chartTheme.color.length] },
              { offset: 1, color: adjustColorBrightness(chartTheme.color[index % chartTheme.color.length], -20) }
            ]
          }
        }
      })) || []
    }]
  }

  // 小时分布面积图配置
  const hourlyDistributionChartOption = {
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'cross' },
      backgroundColor: 'rgba(255, 255, 255, 0.95)',
      borderColor: '#e2e8f0',
      textStyle: { color: '#0f172a', fontSize: 12 }
    },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: analyticsData?.hourlyDistribution?.map(h => `${h.hour.toString().padStart(2, '0')}:00`) ||
            Array.from({ length: 24 }, (_, i) => `${i.toString().padStart(2, '0')}:00`),
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisLabel: { color: '#64748b', fontSize: 12 }
    },
    yAxis: {
      type: 'value',
      name: 'Requests',
      axisLine: { lineStyle: { color: '#e2e8f0' } },
      axisLabel: { color: '#64748b', fontSize: 12 },
      splitLine: { lineStyle: { color: '#f1f5f9', type: 'dashed' } }
    },
    series: [{
      name: 'Requests',
      type: 'line',
      data: analyticsData?.hourlyDistribution?.map(h => h.requests) ||
            Array.from({ length: 24 }, () => 0),
      smooth: true,
      symbol: 'circle',
      symbolSize: 8,
      lineStyle: { width: 3, color: '#3b82f6' },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0,
          y: 0,
          x2: 0,
          y2: 1,
          colorStops: [
            { offset: 0, color: 'rgba(59, 130, 246, 0.3)' },
            { offset: 1, color: 'rgba(59, 130, 246, 0.05)' }
          ]
        }
      },
      emphasis: {
        focus: 'series',
        itemStyle: {
          shadowBlur: 10,
          shadowColor: 'rgba(59, 130, 246, 0.5)'
        }
      }
    }]
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 dark:from-slate-900 dark:to-slate-800">
      <div className="space-y-8 p-6">
        {/* Controls Section */}
        <div className="flex flex-col gap-6">
          <div className="flex justify-end items-center flex-wrap gap-4">
            <div className="flex items-center gap-2 flex-wrap">
              <Select value={timeRange} onValueChange={setTimeRange}>
                <SelectTrigger className="w-20 h-8 bg-white border-gray-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="24h">24h</SelectItem>
                  <SelectItem value="7d">7d</SelectItem>
                  <SelectItem value="30d">30d</SelectItem>
                  <SelectItem value="custom">Custom</SelectItem>
                </SelectContent>
              </Select>

              <Select value={selectedApiKey} onValueChange={setSelectedApiKey}>
                <SelectTrigger className="w-24 h-8 bg-white border-gray-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Keys</SelectItem>
                  {uniqueApiKeys.map(key => (
                    <SelectItem key={key} value={key}>{key.substring(0, 8)}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={selectedUser} onValueChange={setSelectedUser}>
                <SelectTrigger className="w-24 h-8 bg-white border-gray-200">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Users</SelectItem>
                  {uniqueUsers.map(user => (
                    <SelectItem key={user} value={user}>{user}</SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Button onClick={handleExportData} size="sm" variant="outline" className="h-8 px-3">
                Export
              </Button>
            </div>
          </div>

          {timeRange === 'custom' && (
            <div className="flex gap-4 p-4 bg-white rounded-xl border border-gray-200 shadow-sm">
              <div className="flex flex-col gap-2">
                <Label className="text-sm font-medium text-gray-700">Start Date</Label>
                <Input
                  type="datetime-local"
                  value={customDateStart}
                  onChange={(e) => setCustomDateStart(e.target.value)}
                  className="w-48 border-gray-200 focus:border-blue-400"
                />
              </div>
              <div className="flex flex-col gap-2">
                <Label className="text-sm font-medium text-gray-700">End Date</Label>
                <Input
                  type="datetime-local"
                  value={customDateEnd}
                  onChange={(e) => setCustomDateEnd(e.target.value)}
                  className="w-48 border-gray-200 focus:border-blue-400"
                />
              </div>
            </div>
          )}
        </div>

        {/* 概览指标卡片 */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Total Requests</p>
              <p className="text-xl font-bold text-gray-900">
                {analyticsData?.overview?.totalRequests?.toLocaleString() || '0'}
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Active Users</p>
              <p className="text-xl font-bold text-gray-900">
                {analyticsData?.overview?.activeUsers || '0'}
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Success Rate</p>
              <p className="text-xl font-bold text-gray-900">
                {analyticsData?.overview?.successRate?.toFixed(1) || '0.0'}%
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Error Rate</p>
              <p className="text-xl font-bold text-gray-900">
                {analyticsData?.overview?.errorRate?.toFixed(1) || '0.0'}%
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">Avg Response</p>
              <p className="text-xl font-bold text-gray-900">
                {Math.round(analyticsData?.overview?.avgResponseTime || 0)}ms
              </p>
            </CardContent>
          </Card>

          <Card className="bg-white border shadow-sm hover:shadow-md transition-shadow">
            <CardContent className="p-4 text-center">
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-2">API Keys</p>
              <p className="text-xl font-bold text-gray-900">
                {analyticsData?.overview?.totalApiKeys || '0'}
              </p>
            </CardContent>
          </Card>
        </div>

        {/* 主要趋势图表 */}
        <Card className="bg-white border shadow-sm">
          <CardHeader className="pb-4">
            <CardTitle className="text-lg font-semibold text-gray-900">API Usage Trends</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ReactECharts
              option={trendChartOption}
              style={{ height: '350px' }}
              theme={chartTheme}
            />
          </CardContent>
        </Card>

        {/* 次要图表行 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* API Key使用分布 */}
          <Card className="bg-white border shadow-sm">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg font-semibold text-gray-900">API Key Usage</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <ReactECharts
                option={apiKeyUsageChartOption}
                style={{ height: '300px' }}
                theme={chartTheme}
              />
            </CardContent>
          </Card>

          {/* 操作类型分布 */}
          <Card className="bg-white border shadow-sm">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg font-semibold text-gray-900">Operation Types</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <ReactECharts
                option={operationPieChartOption}
                style={{ height: '300px' }}
                theme={chartTheme}
              />
            </CardContent>
          </Card>
        </div>

        {/* 小时分布图表 */}
        <Card className="bg-white border shadow-sm">
          <CardHeader className="pb-4">
            <CardTitle className="text-lg font-semibold text-gray-900">Hourly Distribution</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ReactECharts
              option={hourlyDistributionChartOption}
              style={{ height: '280px' }}
              theme={chartTheme}
            />
          </CardContent>
        </Card>

        {/* 错误分析表格 */}
        {analyticsData?.errorTypes && analyticsData.errorTypes.length > 0 && (
          <Card className="bg-white border shadow-sm">
            <CardHeader className="pb-4">
              <CardTitle className="text-lg font-semibold text-gray-900">Error Analysis</CardTitle>
            </CardHeader>
            <CardContent className="pt-0">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-200">
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Status Code</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Message</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Count</th>
                      <th className="text-left py-3 px-4 font-medium text-gray-700">Percentage</th>
                    </tr>
                  </thead>
                  <tbody>
                    {analyticsData.errorTypes.map((error, index) => (
                      <tr key={index} className="border-b border-gray-100 hover:bg-gray-50 transition-colors">
                        <td className="py-3 px-4">
                          <span className="bg-red-100 text-red-800 text-xs font-medium px-2.5 py-0.5 rounded-full font-mono">
                            {error.statusCode}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-900">{error.message}</td>
                        <td className="py-3 px-4 font-medium text-gray-900">{error.count}</td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-gray-200 rounded-full h-2">
                              <div
                                className="bg-red-600 h-2 rounded-full"
                                style={{
                                  width: `${((error.count / analyticsData.overview.totalRequests) * 100).toFixed(1)}%`
                                }}
                              ></div>
                            </div>
                            <span className="text-sm font-medium text-gray-700">
                              {((error.count / analyticsData.overview.totalRequests) * 100).toFixed(2)}%
                            </span>
                          </div>
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