import http from './http'

export interface DashboardMetric {
  key: string
  label: string
  value: number
  unit?: string
  trend?: number
  status: 'primary' | 'success' | 'warning' | 'danger'
}

export interface PipelineStageMetric {
  stage: 'dataplane' | 'detection' | 'semantic' | 'featureloop'
  label: string
  qps: number
  p95Ms: number
  blocked: number
  errorRate: number
  enabled: boolean
}

export interface AttackTrendPoint {
  time: string
  requests: number
  blocked: number
}

export interface RecentSecurityEvent {
  id: string
  time: string
  sourceIp: string
  path: string
  type: string
  action: 'allow' | 'block' | 'observe'
  stage: string
}

export interface SystemStatus {
  service: string
  version: string
  uptime: string
  mode: string
  health: 'ok' | 'degraded' | 'down'
}

export interface DashboardOverview {
  status: SystemStatus
  metrics: DashboardMetric[]
  pipeline: PipelineStageMetric[]
  attackTrend: AttackTrendPoint[]
  recentEvents: RecentSecurityEvent[]
}

export async function fetchDashboardOverview(): Promise<DashboardOverview> {
  const { data } = await http.get<DashboardOverview>('/dashboard/overview')
  return data
}
