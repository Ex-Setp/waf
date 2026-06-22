import http from './http'

export type SiteStatus = 'enabled' | 'disabled'
export type TlsMode = 'off' | 'auto' | 'custom'
export type PolicyMode = 'loose' | 'standard' | 'strict'

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

export async function fetchSites(): Promise<SiteListResponse> {
  const { data } = await http.get<SiteListResponse>('/sites')
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
