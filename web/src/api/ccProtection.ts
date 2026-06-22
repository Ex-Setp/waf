import http from './http'

export type CcAction = 'block' | 'captcha' | 'observe' | 'temp-block' | 'long-block' | string

export interface CcPolicy {
  id: string
  siteId: string
  name: string
  scope: string
  threshold: number
  windowSeconds: number
  action: CcAction
  priority: number
  enabled: boolean
  hitsToday: number
}

export interface CcPolicyPayload {
  siteId: string
  name: string
  scope: string
  threshold: number
  windowSeconds: number
  action: CcAction
  priority: number
  enabled: boolean
}

export interface CcBlockEntry {
  key: string
  sourceIp: string
  policyId?: string
  policyName?: string
  scope?: string
  action: CcAction
  count: number
  blockUntil: string
}

export interface CcBlockResponse {
  blocks: CcBlockEntry[]
  total: number
}

export interface CcStats {
  qps: number
  blockedToday: number
  challengedToday: number
  activePolicies: number
}

export interface CcProtectionResponse {
  stats: CcStats
  policies: CcPolicy[]
}

export async function fetchCcProtection(): Promise<CcProtectionResponse> {
  const { data } = await http.get<CcProtectionResponse>('/cc-protection')
  return data
}

export async function createCcPolicy(payload: CcPolicyPayload): Promise<CcPolicy> {
  const { data } = await http.post<CcPolicy>('/cc-protection', payload)
  return data
}

export async function updateCcPolicy(id: string, payload: CcPolicyPayload): Promise<CcPolicy> {
  const { data } = await http.put<CcPolicy>(`/cc-protection/${id}`, payload)
  return data
}

export async function deleteCcPolicy(id: string): Promise<void> {
  await http.delete(`/cc-protection/${id}`)
}

export async function fetchCcBlocks(): Promise<CcBlockResponse> {
  const { data } = await http.get<CcBlockResponse>('/protection/cc-blocks')
  return data
}

export async function unblockCcKey(key: string): Promise<void> {
  await http.delete(`/protection/cc-blocks/${encodeURIComponent(key)}`)
}

export async function unblockCcIp(sourceIp: string): Promise<void> {
  await http.delete(`/protection/cc-blocks/${encodeURIComponent(`ip/${sourceIp}`)}`)
}
