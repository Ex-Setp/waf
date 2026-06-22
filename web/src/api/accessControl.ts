import http from './http'

export type AccessListType = 'ip_blacklist' | 'ip_whitelist' | 'url_whitelist' | 'ua_blacklist' | 'method_block'
export type AccessRuleStatus = 'enabled' | 'disabled'

export interface AccessRule {
  id: string
  type: AccessListType
  value: string
  description?: string
  status: AccessRuleStatus
  hits: number
  updatedAt?: string
}

export interface AccessRulePayload {
  type: AccessListType
  value: string
  description?: string
  status: AccessRuleStatus
}

export interface AccessControlResponse {
  rules: AccessRule[]
  total: number
}

export async function fetchAccessRules(): Promise<AccessControlResponse> {
  const { data } = await http.get<AccessControlResponse>('/access-rules')
  return data
}

export async function createAccessRule(payload: AccessRulePayload): Promise<AccessRule> {
  const { data } = await http.post<AccessRule>('/access-rules', payload)
  return data
}

export async function updateAccessRule(id: string, payload: AccessRulePayload): Promise<AccessRule> {
  const { data } = await http.put<AccessRule>(`/access-rules/${id}`, payload)
  return data
}

export async function deleteAccessRule(id: string): Promise<void> {
  await http.delete(`/access-rules/${id}`)
}
