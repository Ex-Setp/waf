import http from './http'

export type SemanticFingerprintStatus = 'observing' | 'active' | 'rollback'
export type SemanticFingerprintAction = 'log' | 'deny' | 'pass'

export interface SemanticFingerprint {
  id: string
  hash: string
  language: 'sql' | 'javascript' | 'unknown'
  skeleton: string
  nodeTypes: string[]
  samplePayload: string
  action: SemanticFingerprintAction
  status: SemanticFingerprintStatus
  ruleId: number
  generatedRule: string
  hits: number
  falsePositiveRate: number
  source: string
  xdpSyncStatus: string
  lastSeenAt: string
  updatedAt: string
}

export interface FingerprintResponse {
  fingerprints: SemanticFingerprint[]
  total: number
}

export async function fetchFingerprints(): Promise<FingerprintResponse> {
  const { data } = await http.get<FingerprintResponse>('/semantic-fingerprints')
  return data
}

export async function updateFingerprintStatus(id: string, action: 'observe' | 'activate' | 'rollback' | 'promote-rule'): Promise<SemanticFingerprint> {
  const { data } = await http.post<SemanticFingerprint>(`/semantic-fingerprints/${id}/${action}`)
  return data
}
