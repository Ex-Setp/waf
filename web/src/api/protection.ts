import http from './http'
import type { PolicyMode } from './sites'

export interface ApiListResponse<T> {
  items?: T[]
  data?: T[]
  rules?: T[]
  policies?: T[]
  whitelists?: T[]
  fingerprints?: T[]
  events?: T[]
  trend?: T[]
  total?: number
  runtimeVersion?: string
  hotReload?: boolean
}

export interface SiteProtectionPolicy {
  siteId: number | string
  siteName?: string
  mode?: PolicyMode
  enabledRuleGroups?: string[]
  ruleGroups?: string[]
  crsParanoiaLevel?: number
  inboundThreshold?: number
  outboundThreshold?: number
  defaultAction?: string
  runtimeVersion?: string
  publishedAt?: string | number
  updatedAt?: string | number
}

export interface SitePolicyAuditEntry {
  id: number | string
  time?: string | number
  siteId?: number | string
  siteName?: string
  version?: string
  action?: string
  detail?: string
}

export interface ProtectionRuleSet {
  id?: number | string
  name: string
  source?: string
  version?: string
  enabled?: boolean
  ruleCount?: number
  updatedAt?: string | number
}

export interface CRSStatus {
  enabled?: boolean
  loaded?: boolean
  rulesDir?: string
  ruleCount?: number
  fileCount?: number
  version?: string
  paranoiaLevel?: number
  inboundThreshold?: number
  outboundThreshold?: number
  lastReloadAt?: string
  lastError?: string
}

export interface SecurityCoverageOutcome {
  id: string
  category?: string
  decision?: string
  score?: number
  ruleIds?: number[]
  rules?: string[]
}

export interface SecurityCoverageSummary {
  generatedAt?: string
  ruleFileCount?: number
  ruleCount?: number
  attackTotal?: number
  attackBlocked?: number
  attackBlockRate?: number
  benignTotal?: number
  benignFalsePositives?: number
  benignFalseRate?: number
  missedAttacks?: SecurityCoverageOutcome[]
  falsePositives?: SecurityCoverageOutcome[]
  attackBlockRateTarget?: number
  falsePositiveLimit?: number
}

export interface ProtectionRuleUpdateEvaluation {
  attackBlockRate?: number
  benignFalsePositiveRate?: number
  attackBlockRateDelta?: number
  benignFalsePositiveRateDelta?: number
  benignFalsePositives?: number
  benignFalsePositivesDelta?: number
}

export interface ProtectionRuleUpdateDiff {
  newRules?: number
  removedRules?: number
  modifiedRules?: number
  added?: number
  removed?: number
  modified?: number
}

export interface ProtectionRuleUpdateSource {
  id?: number | string
  name: string
  type: string
  url?: string
  mode?: string
  enabled?: boolean
  expectedHash?: string
  currentVersion?: string
  currentHash?: string
  lastStatus?: string
  lastError?: string
  lastSuccessAt?: string | number
  updatedAt?: string | number
}

export interface ProtectionRuleUpdateSourcePayload {
  name: string
  type: string
  url?: string
  mode: string
  enabled?: boolean
  expectedHash?: string
}

export interface ProtectionRuleUpdateResult {
  id?: number | string
  updateId?: number | string
  version?: string
  status?: string
  published?: boolean
  mode?: string
  packageVersion?: string
  packageHash?: string
  evaluation?: ProtectionRuleUpdateEvaluation
  diff?: ProtectionRuleUpdateDiff
  newRules?: ProtectionRule[] | number
  removedRules?: ProtectionRule[] | number
  modifiedRules?: ProtectionRule[] | number
  blockedReason?: string
  errorMessage?: string
  emergency?: boolean
  emergencyCve?: string
  runtimeVersion?: string
  hotReload?: boolean
  observeOnly?: boolean
  grayMode?: boolean
  createdAt?: string | number
  publishedAt?: string | number
}

export interface ProtectionRuleUpdateLog extends ProtectionRuleUpdateResult {
  time?: string | number
}

export interface ProtectionRuleUpdateSummary {
  currentVersion?: string
  currentHash?: string
  currentRuleCount?: number
  currentStatus?: string
  lastPublishedAt?: string | number
  lastBlockedReason?: string
  lastFailureReason?: string
  latest?: ProtectionRuleUpdateResult
  sources?: ProtectionRuleUpdateSource[]
  logs?: ProtectionRuleUpdateLog[]
  runtimeVersion?: string
  hotReload?: boolean
}

export interface ProtectionRuleUpdatePackagePayload {
  type?: string
  version?: string
  hash?: string
  mode?: string
  rules?: ProtectionRulePayload[]
}

export interface ProtectionRuleUpdatePublishPayload {
  expectedHash?: string
  observeOnly?: boolean
  grayMode?: boolean
  package?: ProtectionRuleUpdatePackagePayload
}

export interface ProtectionRuleUpdateRollbackPayload {
  updateId?: number | string
  version?: string
}

export interface ProtectionRuleUpdateEmergencyPayload {
  cve?: string
  version?: string
  observeOnly?: boolean
  rule: ProtectionRulePayload
}

export interface ProtectionRule {
  id: number | string
  ruleId?: string | number
  name?: string
  description?: string
  category?: string
  variable?: string
  operator?: string
  pattern?: string
  severity?: string
  score?: number
  action?: string
  enabled?: boolean
  source?: string
  hits?: number
  runtimeVersion?: string
  hotReload?: boolean
  groupId?: number | string
  siteId?: number | string
  updatedAt?: string | number
}

export interface ProtectionRulePayload {
  ruleId: number
  name: string
  description?: string
  category: string
  variable: string
  operator: string
  pattern: string
  severity: string
  score: number
  action: string
  source: string
  enabled: boolean
}

export interface ProtectionRuleValidationError {
  field?: string
  line?: number
  message: string
}

export interface ProtectionRuleValidationResult {
  valid?: boolean
  errors?: ProtectionRuleValidationError[]
  runtimeVersion?: string
  hotReload?: boolean
}

export interface ProtectionRuleWriteResult {
  rule?: ProtectionRule
  runtimeVersion?: string
  hotReload?: boolean
}

export interface ProtectionRuleImportResult {
  rules?: ProtectionRule[]
  total?: number
  valid?: boolean
  errors?: ProtectionRuleValidationError[]
  runtimeVersion?: string
  hotReload?: boolean
}

export interface ProtectionRuleRollbackResult {
  rules?: ProtectionRule[]
  total?: number
  rolledBackTo?: string
  runtimeVersion?: string
  hotReload?: boolean
}

export interface ProtectionWhitelist {
  id: number | string
  siteId?: number | string
  type?: string
  pattern?: string
  reason?: string
  scope?: string
  ruleId?: string | number
  variable?: string
  enabled?: boolean
  expiresAt?: string | number
  createdFrom?: string
  updatedAt?: string | number
}

export interface ProtectionWhitelistPayload {
  siteId?: number | string
  type: string
  value: string
  description?: string
  scope?: string
  ruleId?: string | number
  variable?: string
  expiresAt?: string | number
  status?: string
}

export interface RequestParserDecodeStep {
  stage: string
  before: string
  after: string
  pass: number
}

export interface RequestParserParseError {
  source: string
  message: string
  fatal?: boolean
}

export interface RequestParserField {
  name: string
  source: string
  variable: string
  rawValue: string
  normalizedValue: string
  contentType?: string
  filename?: string
  decodeSteps?: RequestParserDecodeStep[]
  parseErrors?: RequestParserParseError[]
}

export interface RequestParserPreview {
  method?: string
  rawUri?: string
  normalizedUri?: string
  normalizedURI?: string
  path?: string
  normalizedPath?: string
  contentType?: string
  fields?: RequestParserField[]
  decodeSteps?: RequestParserDecodeStep[]
  parseErrors?: RequestParserParseError[]
  bodyTooLarge?: boolean
  failOpen?: boolean
  inspectionAllowed?: boolean
  normalizedQuery?: string
  headers?: Record<string, string>
  cookies?: Record<string, string>
  bodyText?: string
  jsonFields?: unknown[]
  multipartFields?: unknown[]
  matchedVariables?: unknown[]
}

export interface CCBotPolicy {
  id: number | string
  siteId?: number | string
  name?: string
  enabled?: boolean
  scope?: string
  windowSeconds?: number
  threshold?: number
  action?: string
  priority?: number
  hitsToday?: number
}

export interface CCBotEvent {
  id: number | string
  time?: string
  siteName?: string
  sourceIp?: string
  policyName?: string
  scope?: string
  action?: string
  count?: number
  threshold?: number
}

export interface SemanticFingerprintSummary {
  id: number | string
  hash?: string
  language?: string
  skeleton?: string
  action?: string
  status?: string
  ruleId?: number | string
  hits?: number
  falsePositiveRate?: number
  source?: string
  updatedAt?: string | number
}

export interface TrafficOverview {
  totalRequests?: number
  blockedRequests?: number
  observedRequests?: number
  captchaRequests?: number
  blockRate?: number
  qps?: number
}

export interface TrafficPoint {
  time?: string
  requests?: number
  blocked?: number
}

export interface TrafficRankItem {
  name?: string
  key?: string
  value?: number
  count?: number
}

export interface AttackEventSummary {
  id: number | string
  time?: string
  siteName?: string
  sourceIp?: string
  path?: string
  attackType?: string
  severity?: string
  action?: string
  ruleId?: string
}

function normalizeArrayResponse<T>(payload: T[] | ApiListResponse<T> | Record<string, unknown> | null | undefined, keys: string[] = []): { items: T[]; total: number } {
  if (Array.isArray(payload)) {
    return { items: payload, total: payload.length }
  }
  if (!payload || typeof payload !== 'object') {
    return { items: [], total: 0 }
  }
  for (const key of keys) {
    const value = (payload as Record<string, unknown>)[key]
    if (Array.isArray(value)) {
      return { items: value as T[], total: Number((payload as ApiListResponse<T>).total ?? value.length) }
    }
  }
  for (const key of ['items', 'data', 'rules', 'policies', 'whitelists', 'fingerprints', 'events', 'logs']) {
    const value = (payload as Record<string, unknown>)[key]
    if (Array.isArray(value)) {
      return { items: value as T[], total: Number((payload as ApiListResponse<T>).total ?? value.length) }
    }
  }
  return { items: [], total: Number((payload as ApiListResponse<T>).total ?? 0) }
}

export async function fetchSiteProtectionPolicies(): Promise<{ items: SiteProtectionPolicy[]; total: number }> {
  const { data } = await http.get<SiteProtectionPolicy[] | ApiListResponse<SiteProtectionPolicy>>('/protection/site-policies')
  return normalizeArrayResponse(data, ['policies'])
}

export async function saveSiteProtectionPolicyDraft(siteId: number | string, payload: Partial<SiteProtectionPolicy>): Promise<SiteProtectionPolicy> {
  const { data } = await http.put<SiteProtectionPolicy>(`/protection/site-policies/${siteId}`, payload)
  return data
}

export async function publishSiteProtectionPolicy(siteId: number | string): Promise<SiteProtectionPolicy> {
  const { data } = await http.post<SiteProtectionPolicy>(`/protection/site-policies/${siteId}/publish`)
  return data
}

export async function rollbackSiteProtectionPolicy(siteId: number | string, version: string): Promise<SiteProtectionPolicy> {
  const { data } = await http.post<SiteProtectionPolicy>(`/protection/site-policies/${siteId}/rollback`, null, { params: { version } })
  return data
}

export async function fetchSitePolicyVersions(siteId: number | string): Promise<{ items: SiteProtectionPolicy[]; total: number }> {
  const { data } = await http.get<SiteProtectionPolicy[] | ApiListResponse<SiteProtectionPolicy>>(`/protection/site-policies/${siteId}/versions`)
  return normalizeArrayResponse(data, ['versions'])
}

export async function fetchSitePolicyAudit(siteId: number | string): Promise<{ items: SitePolicyAuditEntry[]; total: number }> {
  const { data } = await http.get<SitePolicyAuditEntry[] | ApiListResponse<SitePolicyAuditEntry>>(`/protection/site-policies/${siteId}/audit`)
  return normalizeArrayResponse(data, ['events'])
}

export async function fetchProtectionRuleSets(): Promise<{ items: ProtectionRuleSet[]; total: number }> {
  const { data } = await http.get<ProtectionRuleSet[] | ApiListResponse<ProtectionRuleSet>>('/protection/rule-sets')
  return normalizeArrayResponse(data, ['ruleSets', 'sets'])
}

export async function fetchCRSStatus(): Promise<CRSStatus> {
  const { data } = await http.get<CRSStatus>('/protection/crs/status')
  return data
}

export async function reloadCRS(): Promise<CRSStatus> {
  const { data } = await http.post<CRSStatus>('/protection/crs/reload')
  return data
}

export async function fetchSecurityCoverage(): Promise<SecurityCoverageSummary> {
  const { data } = await http.get<SecurityCoverageSummary>('/protection/security-coverage')
  return data
}

export async function fetchProtectionRuleUpdates(): Promise<ProtectionRuleUpdateSummary> {
  const { data } = await http.get<ProtectionRuleUpdateSummary>('/protection/rule-updates')
  return data
}

export async function saveProtectionRuleUpdateSource(payload: ProtectionRuleUpdateSourcePayload): Promise<ProtectionRuleUpdateSource> {
  const { data } = await http.post<ProtectionRuleUpdateSource>('/protection/rule-updates/sources', payload)
  return data
}

export async function publishProtectionRuleUpdate(payload: ProtectionRuleUpdatePublishPayload): Promise<ProtectionRuleUpdateResult> {
  const { data } = await http.post<ProtectionRuleUpdateResult>('/protection/rule-updates/publish', payload)
  return data
}

export async function rollbackProtectionRuleUpdate(payload?: ProtectionRuleUpdateRollbackPayload): Promise<ProtectionRuleUpdateResult> {
  const { data } = await http.post<ProtectionRuleUpdateResult>('/protection/rule-updates/rollback', payload ?? {})
  return data
}

export async function createEmergencyProtectionRuleUpdate(payload: ProtectionRuleUpdateEmergencyPayload): Promise<ProtectionRuleUpdateResult> {
  const { data } = await http.post<ProtectionRuleUpdateResult>('/protection/rule-updates/emergency', payload)
  return data
}

export async function fetchProtectionRules(): Promise<{ items: ProtectionRule[]; total: number; runtimeVersion?: string; hotReload?: boolean }> {
  const { data } = await http.get<ProtectionRule[] | ApiListResponse<ProtectionRule>>('/protection/rules')
  const normalized = normalizeArrayResponse(data, ['rules'])
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    const out: { items: ProtectionRule[]; total: number; runtimeVersion?: string; hotReload?: boolean } = { ...normalized }
    const runtimeVersion = (data as ApiListResponse<ProtectionRule>).runtimeVersion
    const hotReload = (data as ApiListResponse<ProtectionRule>).hotReload
    if (runtimeVersion !== undefined) out.runtimeVersion = runtimeVersion
    if (hotReload !== undefined) out.hotReload = hotReload
    return out
  }
  return normalized
}

export async function createProtectionRule(payload: ProtectionRulePayload): Promise<ProtectionRule> {
  const { data } = await http.post<ProtectionRule | ProtectionRuleWriteResult>('/protection/rules', payload)
  return (data as ProtectionRuleWriteResult).rule ?? (data as ProtectionRule)
}

export async function updateProtectionRule(id: number | string, payload: ProtectionRulePayload): Promise<ProtectionRule> {
  const { data } = await http.put<ProtectionRule | ProtectionRuleWriteResult>(`/protection/rules/${id}`, payload)
  return (data as ProtectionRuleWriteResult).rule ?? (data as ProtectionRule)
}

export async function deleteProtectionRule(id: number | string): Promise<void> {
  await http.delete(`/protection/rules/${id}`)
}

export async function setProtectionRuleEnabled(id: number | string, enabled: boolean): Promise<ProtectionRule> {
  const { data } = await http.post<ProtectionRule | ProtectionRuleWriteResult>(`/protection/rules/${id}/${enabled ? 'enable' : 'disable'}`)
  return (data as ProtectionRuleWriteResult).rule ?? (data as ProtectionRule)
}

export async function validateProtectionRules(payload: ProtectionRulePayload[]): Promise<ProtectionRuleValidationResult> {
  const { data } = await http.post<ProtectionRuleValidationResult>('/protection/rules/validate', payload)
  return data
}

export async function testProtectionRule(payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  const { data } = await http.post<Record<string, unknown>>('/protection/rules/test', payload)
  return data
}

export async function importProtectionRules(payload: ProtectionRulePayload[]): Promise<ProtectionRuleImportResult> {
  const { data } = await http.post<ProtectionRuleImportResult>('/protection/rules/import', payload)
  return data
}

export async function exportProtectionRules(): Promise<ProtectionRule[]> {
  const { data } = await http.get<ProtectionRule[] | ApiListResponse<ProtectionRule>>('/protection/rules/export')
  return normalizeArrayResponse(data, ['rules']).items
}

export async function rollbackProtectionRules(): Promise<ProtectionRuleRollbackResult> {
  const { data } = await http.post<ProtectionRuleRollbackResult>('/protection/rules/rollback')
  return data
}

export async function fetchProtectionWhitelists(params?: Record<string, unknown>): Promise<{ items: ProtectionWhitelist[]; total: number }> {
  const { data } = await http.get<ProtectionWhitelist[] | ApiListResponse<ProtectionWhitelist>>('/protection/whitelists', { params })
  return normalizeArrayResponse(data, ['whitelists'])
}

export async function createProtectionWhitelist(payload: ProtectionWhitelistPayload): Promise<ProtectionWhitelist> {
  const { data } = await http.post<ProtectionWhitelist>('/protection/whitelists', payload)
  return data
}

export async function updateProtectionWhitelist(id: number | string, payload: ProtectionWhitelistPayload): Promise<ProtectionWhitelist> {
  const { data } = await http.put<ProtectionWhitelist>(`/protection/whitelists/${id}`, payload)
  return data
}

export async function deleteProtectionWhitelist(id: number | string): Promise<void> {
  await http.delete(`/protection/whitelists/${id}`)
}

export async function previewRequestParser(rawRequest: string): Promise<RequestParserPreview> {
  const { data } = await http.post<RequestParserPreview>('/protection/request-parser/preview', { rawRequest })
  return data
}

export async function fetchCCBotPolicies(): Promise<{ items: CCBotPolicy[]; total: number }> {
  const { data } = await http.get<CCBotPolicy[] | ApiListResponse<CCBotPolicy>>('/protection/cc-policies')
  return normalizeArrayResponse(data, ['policies'])
}

export async function fetchCCBotEvents(): Promise<{ items: CCBotEvent[]; total: number }> {
  const { data } = await http.get<CCBotEvent[] | ApiListResponse<CCBotEvent>>('/protection/cc-events')
  return normalizeArrayResponse(data, ['events'])
}

export async function fetchProtectionSemanticFingerprints(): Promise<{ items: SemanticFingerprintSummary[]; total: number }> {
  const { data } = await http.get<SemanticFingerprintSummary[] | ApiListResponse<SemanticFingerprintSummary>>('/protection/semantic-fingerprints')
  return normalizeArrayResponse(data, ['fingerprints'])
}

export async function fetchTrafficOverview(params?: Record<string, unknown>): Promise<TrafficOverview> {
  const { data } = await http.get<TrafficOverview>('/protection/traffic/overview', { params })
  return data
}

export async function fetchTrafficTrend(params?: Record<string, unknown>): Promise<{ items: TrafficPoint[]; total: number }> {
  const { data } = await http.get<TrafficPoint[] | ApiListResponse<TrafficPoint>>('/protection/traffic/trend', { params })
  return normalizeArrayResponse(data, ['trend', 'points'])
}

export async function fetchTrafficTopIP(params?: Record<string, unknown>): Promise<{ items: TrafficRankItem[]; total: number }> {
  const { data } = await http.get<TrafficRankItem[] | ApiListResponse<TrafficRankItem>>('/protection/traffic/top-ip', { params })
  return normalizeArrayResponse(data, ['items', 'topIp', 'topIPs'])
}

export async function fetchTrafficTopPath(params?: Record<string, unknown>): Promise<{ items: TrafficRankItem[]; total: number }> {
  const { data } = await http.get<TrafficRankItem[] | ApiListResponse<TrafficRankItem>>('/protection/traffic/top-path', { params })
  return normalizeArrayResponse(data, ['items', 'topPath', 'topPaths'])
}

export async function fetchTrafficStatusCodes(params?: Record<string, unknown>): Promise<{ items: TrafficRankItem[]; total: number }> {
  const { data } = await http.get<TrafficRankItem[] | ApiListResponse<TrafficRankItem>>('/protection/traffic/status-codes', { params })
  return normalizeArrayResponse(data, ['items', 'statusCodes'])
}

export async function fetchTrafficSites(params?: Record<string, unknown>): Promise<{ items: TrafficRankItem[]; total: number }> {
  const { data } = await http.get<TrafficRankItem[] | ApiListResponse<TrafficRankItem>>('/protection/traffic/sites', { params })
  return normalizeArrayResponse(data, ['items', 'sites'])
}

export async function fetchProtectionAttackEvents(params?: Record<string, unknown>): Promise<{ items: AttackEventSummary[]; total: number }> {
  const { data } = await http.get<AttackEventSummary[] | ApiListResponse<AttackEventSummary>>('/protection/attack-events', { params })
  return normalizeArrayResponse(data, ['events', 'logs'])
}
