import http from './http'

export interface SystemSettings {
  serverHost: string
  serverPort: number
  mode: string
  failOpen: boolean
  maxBodySize: number
  enableSemantic: boolean
  enableXdp: boolean
  databaseDriver: string
  rulesDirectory: string
  loggingLevel: string
  runtimeStatus: RuntimeStatus
}

export interface RuntimeStatus {
  status: ComponentStatus
  checkedAt: string
  uptime: string
  listener: ListenerHealth
  database: BasicHealth
  runtime: RuntimeHealth
  ruleEngine: RuleEngineHealth
  logQueue: LogQueueHealth
}

export type ComponentStatus = 'ok' | 'degraded' | 'unavailable' | 'error' | string

export interface BasicHealth {
  status: ComponentStatus
  message?: string
}

export interface ListenerHealth extends BasicHealth {
  activePorts: number[]
  activeCount: number
  configuredSites: number
}

export interface RuntimeHealth extends BasicHealth {
  siteCount: number
  enabledSiteCount: number
  hostCount: number
  loadedAt?: string
}

export interface RuleEngineHealth extends BasicHealth {
  ruleCount: number
  enabledRuleCount: number
}

export interface LogQueueHealth extends BasicHealth {
  queuedAccess: number
  queuedAttack: number
  droppedAccess: number
}

export async function fetchSystemSettings(): Promise<SystemSettings> {
  const { data } = await http.get<SystemSettings>('/settings')
  return data
}
