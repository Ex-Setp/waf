import http from './http'

export type SiteStatus = 'enabled' | 'disabled'
export type TlsMode = 'off' | 'auto' | 'custom'
export type PolicyMode = 'loose' | 'standard' | 'strict'
export type ListenerProtocol = 'http' | 'https'
export type ListenerStatus = 'listening' | 'error' | 'not-mapped' | 'disabled'

export interface ProtectedSite {
  id: string
  name: string
  domains: string[]
  upstream: string
  listenPort: number
  status: SiteStatus
  tlsMode: TlsMode
  certificateId: string
  certificateName?: string
  wafEnabled: boolean
  ccProtection: boolean
  semanticProtection: boolean
  policyMode: PolicyMode
  blockScoreThreshold: number
  listenStatus?: ListenerStatus
  listenProtocol?: ListenerProtocol
  listenReason?: string
  qps?: number | null
  blockedToday?: number | null
  updatedAt: string
}

export interface SiteSummary {
  total: number
  enabled: number
  protectedDomains: number
  blockedToday: number
}

export interface SiteListResponse {
  summary: SiteSummary
  sites: ProtectedSite[]
}

export interface SiteFormModel {
  name: string
  domains: string[]
  upstream: string
  listenPort: number
  status: SiteStatus
  tlsMode: TlsMode
  certificateId: string
  certificateName?: string
  wafEnabled: boolean
  ccProtection: boolean
  semanticProtection: boolean
  policyMode: PolicyMode
  blockScoreThreshold: number
}

export interface SiteRuntimeStatus {
  siteId: string
  siteName: string
  listenPort: number
  protocol: ListenerProtocol
  status: ListenerStatus
  domains: string[]
  tlsCertId?: string
  tlsError?: string
  bindError?: string
  dockerPublished: boolean
  lastReloadAt: string
}

export interface ListenerSummary {
  listening: number
  error: number
  notMapped: number
  disabled: number
}

export interface ListenerListResponse {
  summary: ListenerSummary
  listeners: SiteRuntimeStatus[]
}

export async function fetchSites(): Promise<SiteListResponse> {
  const { data } = await http.get<SiteListResponse>('/sites')
  return data
}

export async function fetchSiteRuntimeStatus(id: string): Promise<SiteRuntimeStatus> {
  const { data } = await http.get<SiteRuntimeStatus>(`/sites/${id}/runtime-status`)
  return data
}

export async function fetchSystemListeners(): Promise<ListenerListResponse> {
  const { data } = await http.get<ListenerListResponse>('/system/listeners')
  return data
}

export async function createSite(payload: SiteFormModel): Promise<ProtectedSite> {
  const { data } = await http.post<ProtectedSite>('/sites', payload)
  return data
}

export async function updateSite(id: string, payload: SiteFormModel): Promise<ProtectedSite> {
  const { data } = await http.put<ProtectedSite>(`/sites/${id}`, payload)
  return data
}

export async function deleteSite(id: string): Promise<void> {
  await http.delete(`/sites/${id}`)
}
