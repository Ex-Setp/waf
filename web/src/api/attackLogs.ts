import http from './http'

export type AttackAction = 'allow' | 'block' | 'observe' | 'captcha'
export type AttackSeverity = 'low' | 'medium' | 'high' | 'critical' | ''

export interface AttackLogQuery {
  keyword?: string
  startTime?: string
  endTime?: string
  site?: string
  siteName?: string
  attackType?: string
  action?: AttackAction | ''
  sourceIp?: string
  ip?: string
  path?: string
  severity?: AttackSeverity
  stage?: string
  page: number
  pageSize: number
}

export interface AttackLogEntry {
  id: string
  time: string
  siteName: string
  sourceIp: string
  method: string
  path: string
  attackType: string
  severity: AttackSeverity
  action: AttackAction
  finalAction?: AttackAction | string
  stage: string
  ruleId: string
  ruleMessage?: string
  score?: number
  scoreBreakdown?: string
  explanationJson?: string
  operatorSuggestion?: string
  statusCode: number
  latencyMs: number
  payloadSnippet: string
}

export interface RequestParserLoggedField {
  variable?: string
  source?: string
  rawValue?: string
  normalizedValue?: string
  decodeSteps?: string[]
}

export interface RequestParserLoggedExplanation {
  matchedVariable?: string
  normalizedPath?: string
  fields?: RequestParserLoggedField[]
  parseErrors?: string[]
}

export interface RequestParserLoggedSnippet {
  rawRequest?: string
  normalizedRequest?: RequestParserLoggedExplanation
}

export interface ScoreBreakdownRule {
  id: string
  group: string
  score: number
}

export interface ScoreBreakdown {
  totalScore: number
  threshold: number
  rules: ScoreBreakdownRule[]
}

export interface SitePolicyExplanation {
  siteId?: number
  siteName?: string
  policyMode?: string
  blockScoreThreshold?: number
  runtimeVersion?: string
  ruleGroups?: string[]
}

export interface MatchedRuleExplanation {
  id?: number
  source?: string
  group?: string
  severity?: string
  score?: number
  action?: string
  message?: string
  evidence?: string[]
}

export interface RequestVariableExplanation {
  variable?: string
  source?: string
  rawValue?: string
  normalizedValue?: string
  decodeSteps?: string[]
}

export interface NormalizationStepExplanation {
  variable?: string
  steps?: string[]
}

export interface DecisionExplanation {
  status?: string
  reason?: string
}

export interface AttackExplanation {
  sitePolicy?: SitePolicyExplanation
  matchedRules?: MatchedRuleExplanation[]
  scoreBreakdown?: ScoreBreakdown
  requestVariables?: RequestVariableExplanation[]
  normalizationSteps?: NormalizationStepExplanation[]
  whitelistDecision?: DecisionExplanation
  ccBotDecision?: DecisionExplanation
  semanticDecision?: DecisionExplanation
  finalAction?: string
  reason?: string
}

export interface OperatorSuggestion {
  type: string
  title: string
  target: string
  reason: string
  action: string
}

export interface AttackLogSummary {
  total: number
  blocked: number
  observed: number
  critical: number
}

export interface AttackLogResponse {
  summary: AttackLogSummary
  logs: AttackLogEntry[]
  total: number
}

export async function fetchAttackLogs(query: AttackLogQuery): Promise<AttackLogResponse> {
  const { data } = await http.get<AttackLogResponse>('/attack-logs', { params: query })
  return data
}

export async function exportAttackLogs(query: AttackLogQuery): Promise<Blob> {
  const { data } = await http.get<Blob>('/attack-logs/export', {
    params: query,
    responseType: 'blob',
  })
  return data
}


export interface WhitelistSuggestion {
  type: string
  value: string
  description: string
  scope?: string
  ruleId?: string
  variable?: string
  siteId?: string
  path?: string
  expiresAt?: string
}

export interface WhitelistSuggestionResponse {
  suggestions: WhitelistSuggestion[]
}

export interface AccessRuleResponse {
  id: string
  type: string
  value: string
  status: string
  hits?: number
  description?: string
}

export interface WhitelistValidationResponse {
  attackLogId: string
  ruleId: string
  beforeDecision: string
  afterDecision: string
  equivalentStatus: string
  reason: string
}

export async function fetchWhitelistSuggestions(id: string): Promise<WhitelistSuggestionResponse> {
  const { data } = await http.get<WhitelistSuggestionResponse>(`/attack-logs/${id}/whitelist-suggestions`)
  return data
}

export async function applyWhitelistSuggestion(id: string, suggestion: WhitelistSuggestion): Promise<AccessRuleResponse> {
  const { data } = await http.post<AccessRuleResponse>(`/attack-logs/${id}/whitelist`, {
    type: suggestion.type,
    value: suggestion.value,
    description: suggestion.description,
    scope: suggestion.scope,
    ruleId: suggestion.ruleId,
    variable: suggestion.variable,
    siteId: suggestion.siteId,
    expiresAt: suggestion.expiresAt,
    status: 'enabled',
  })
  return data
}

export async function validateWhitelistSuggestion(id: string): Promise<WhitelistValidationResponse> {
  const { data } = await http.post<WhitelistValidationResponse>(`/attack-logs/${id}/whitelist-validate`)
  return data
}
