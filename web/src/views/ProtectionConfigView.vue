<script setup lang="ts">
import { Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import {
  createEmergencyProtectionRuleUpdate,
  createProtectionRule,
  createProtectionWhitelist,
  deleteProtectionRule,
  deleteProtectionWhitelist,
  exportProtectionRules,
  fetchCRSStatus,
  fetchCCBotEvents,
  fetchCCBotPolicies,
  fetchProtectionAttackEvents,
  fetchProtectionRules,
  fetchProtectionRuleSets,
  fetchProtectionRuleUpdates,
  fetchSecurityCoverage,
  fetchProtectionSemanticFingerprints,
  fetchProtectionWhitelists,
  importProtectionRules,
  fetchSitePolicyAudit,
  fetchSitePolicyVersions,
  fetchSiteProtectionPolicies,
  fetchTrafficOverview,
  fetchTrafficSites,
  fetchTrafficStatusCodes,
  fetchTrafficTopIP,
  fetchTrafficTopPath,
  fetchTrafficTrend,
  publishProtectionRuleUpdate,
  previewRequestParser,
  publishSiteProtectionPolicy,
  reloadCRS,
  rollbackProtectionRuleUpdate,
  rollbackProtectionRules,
  rollbackSiteProtectionPolicy,
  setProtectionRuleEnabled,
  validateProtectionRules,
  updateProtectionRule,
  updateProtectionWhitelist,
  type AttackEventSummary,
  type CCBotEvent,
  type CCBotPolicy,
  type CRSStatus,
  type ProtectionRule,
  type ProtectionRulePayload,
  type ProtectionRuleSet,
  type ProtectionRuleUpdateResult,
  type ProtectionRuleUpdateSummary,
  type ProtectionRuleValidationError,
  type ProtectionWhitelist,
  type ProtectionWhitelistPayload,
  type RequestParserField,
  type RequestParserPreview,
  type SecurityCoverageSummary,
  type SemanticFingerprintSummary,
  type SitePolicyAuditEntry,
  type SiteProtectionPolicy,
  type TrafficOverview,
  type TrafficPoint,
  type TrafficRankItem,
} from '@/api/protection'

type PanelKey = 'policy' | 'rules' | 'whitelist' | 'parser' | 'ccbot' | 'fingerprints' | 'traffic'

interface PanelState<T> {
  loading: boolean
  error: string
  items: T[]
  total: number
}

function makeState<T>(): PanelState<T> {
  return reactive({ loading: false, error: '', items: [], total: 0 }) as PanelState<T>
}

const router = useRouter()
const activeTab = ref<PanelKey>('policy')
const siteId = ref<string>('')
const timeRange = ref<[Date, Date] | [number, number] | ''>('')
const trafficAction = ref<string>('')
const trafficRuleGroup = ref<string>('')
const trafficAttackType = ref<string>('')
const parserRawRequest = ref('GET /?q=%253Cscript%253Ealert(1)%253C/script%253E HTTP/1.1\nHost: test.local\nUser-Agent: curl/8.0\n\n')
const parserResult = ref<RequestParserPreview | null>(null)
const parserLoading = ref(false)
const parserError = ref('')
const detailTitle = ref('')
const detailPayload = ref<unknown>(null)
const policyOperatingId = ref<number | string | null>(null)
const policyVersionState = reactive<{ loading: boolean; error: string; siteId: number | string | null; items: SiteProtectionPolicy[]; audit: SitePolicyAuditEntry[] }>({ loading: false, error: '', siteId: null, items: [], audit: [] })
const ruleDialogVisible = ref(false)
const ruleImportInput = ref<HTMLInputElement | null>(null)
const whitelistDialogVisible = ref(false)
const whitelistSaving = ref(false)
const whitelistError = ref('')
const editingWhitelistId = ref<number | string | null>(null)
const whitelistForm = reactive<ProtectionWhitelistPayload>({
  siteId: '',
  type: 'url_whitelist',
  value: '',
  description: '',
  scope: 'site',
  ruleId: '',
  variable: '',
  expiresAt: '',
  status: 'enabled',
})
const ruleSaving = ref(false)
const ruleImporting = ref(false)
const ruleRollingBack = ref(false)
const ruleError = ref('')
const ruleRuntimeVersion = ref('')
const ruleHotReload = ref(false)
const ruleUpdateSummary = reactive<{ loading: boolean; operating: boolean; error: string; data: ProtectionRuleUpdateSummary | null }>({ loading: false, operating: false, error: '', data: null })
const ruleUpdateResult = ref<ProtectionRuleUpdateResult | null>(null)
const ruleUpdateRollbackForm = reactive<{ updateId: string; version: string }>({ updateId: '', version: '' })
const ruleUpdatePublishForm = reactive({
  expectedHash: '',
  observeOnly: false,
  grayMode: false,
  packageType: '',
  packageVersion: '',
  packageHash: '',
  packageMode: '',
  packageRules: '',
})
const emergencyUpdateForm = reactive({
  cve: '',
  version: '',
  observeOnly: true,
  ruleId: 0,
  name: '',
  description: '',
  category: 'emergency',
  variable: 'REQUEST_URI',
  operator: '@contains',
  pattern: '',
  severity: 'critical',
  score: 10,
  action: 'deny',
  source: 'emergency',
  enabled: true,
})
const editingRuleId = ref<number | string | null>(null)
const ruleForm = reactive<ProtectionRulePayload>({
  ruleId: 0,
  name: '',
  description: '',
  category: 'custom',
  variable: 'ARGS',
  operator: '@contains',
  pattern: '',
  severity: 'medium',
  score: 5,
  action: 'deny',
  source: 'custom',
  enabled: true,
})

const policies = makeState<SiteProtectionPolicy>()
const ruleSets = makeState<ProtectionRuleSet>()
const rules = makeState<ProtectionRule>()
const crsStatus = reactive<{ loading: boolean; reloading: boolean; error: string; data: CRSStatus }>({ loading: false, reloading: false, error: '', data: {} })
const securityCoverage = reactive<{ loading: boolean; error: string; data: SecurityCoverageSummary }>({ loading: false, error: '', data: {} })
const whitelists = makeState<ProtectionWhitelist>()
const ccPolicies = makeState<CCBotPolicy>()
const ccEvents = makeState<CCBotEvent>()
const fingerprints = makeState<SemanticFingerprintSummary>()
const trafficTrend = makeState<TrafficPoint>()
const trafficTopIp = makeState<TrafficRankItem>()
const trafficTopPath = makeState<TrafficRankItem>()
const trafficStatusCodes = makeState<TrafficRankItem>()
const trafficSites = makeState<TrafficRankItem>()
const attackEvents = makeState<AttackEventSummary>()
const trafficOverview = reactive<{ loading: boolean; error: string; data: TrafficOverview }>({ loading: false, error: '', data: {} })

const tabs: Array<{ key: PanelKey; label: string; desc: string }> = [
  { key: 'policy', label: '站点策略', desc: '防护模式、阈值、规则组、发布状态' },
  { key: 'rules', label: '规则管理 / CRS', desc: 'CRS、自定义规则、规则组和热更新承接位' },
  { key: 'whitelist', label: '误报白名单', desc: 'URL、参数、IP、规则例外和攻击事件加白' },
  { key: 'parser', label: '请求解析', desc: 'raw/normalized、字段树、decode steps' },
  { key: 'ccbot', label: 'CC / Bot', desc: '多维限速、captcha、临时/长期封禁' },
  { key: 'fingerprints', label: '语义指纹', desc: '观察、启用、回滚、升级规则入口' },
  { key: 'traffic', label: '访问统计 / 解释', desc: '真实日志聚合、攻击事件解释入口' },
]

const queryParams = computed(() => {
  const params: Record<string, string | number> = {}
  if (siteId.value) params.siteId = siteId.value
  if (trafficAction.value) params.action = trafficAction.value
  if (trafficRuleGroup.value) params.ruleGroup = trafficRuleGroup.value
  if (trafficAttackType.value) params.attackType = trafficAttackType.value
  if (Array.isArray(timeRange.value)) {
    const [start, end] = timeRange.value
    params.startTime = start instanceof Date ? start.getTime() : start
    params.endTime = end instanceof Date ? end.getTime() : end
  }
  return params
})

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  return '真实 API 加载失败'
}

async function loadState<T>(state: PanelState<T>, loader: () => Promise<{ items: T[]; total: number }>): Promise<void> {
  state.loading = true
  state.error = ''
  try {
    const data = await loader()
    state.items = data.items
    state.total = data.total
  } catch (error) {
    state.items = []
    state.total = 0
    state.error = errorMessage(error)
  } finally {
    state.loading = false
  }
}

async function loadPolicies(): Promise<void> {
  await loadState(policies, fetchSiteProtectionPolicies)
}

async function loadRules(): Promise<void> {
  const loadedRulesPromise = fetchProtectionRules()
  await Promise.all([
    loadCRSStatus(),
    loadSecurityCoverage(),
    loadRuleUpdates(),
    loadState(ruleSets, fetchProtectionRuleSets),
    loadState(rules, () => loadedRulesPromise),
  ])
  const loadedRules = await loadedRulesPromise
  ruleRuntimeVersion.value = String((loadedRules as { items: ProtectionRule[]; total: number; runtimeVersion?: string }).runtimeVersion || '')
  ruleHotReload.value = rules.items.some((item) => item.hotReload === true)
}

async function loadRuleUpdates(): Promise<void> {
  ruleUpdateSummary.loading = true
  ruleUpdateSummary.error = ''
  try {
    ruleUpdateSummary.data = await fetchProtectionRuleUpdates()
  } catch (error) {
    ruleUpdateSummary.data = null
    ruleUpdateSummary.error = errorMessage(error)
  } finally {
    ruleUpdateSummary.loading = false
  }
}

async function loadCRSStatus(): Promise<void> {
  crsStatus.loading = true
  crsStatus.error = ''
  try {
    crsStatus.data = await fetchCRSStatus()
  } catch (error) {
    crsStatus.data = {}
    crsStatus.error = errorMessage(error)
  } finally {
    crsStatus.loading = false
  }
}

async function loadSecurityCoverage(): Promise<void> {
  securityCoverage.loading = true
  securityCoverage.error = ''
  try {
    securityCoverage.data = await fetchSecurityCoverage()
  } catch (error) {
    securityCoverage.data = {}
    securityCoverage.error = errorMessage(error)
  } finally {
    securityCoverage.loading = false
  }
}

async function reloadCRSRules(): Promise<void> {
  crsStatus.reloading = true
  crsStatus.error = ''
  try {
    crsStatus.data = await reloadCRS()
    await loadState(ruleSets, fetchProtectionRuleSets)
  } catch (error) {
    crsStatus.error = errorMessage(error)
  } finally {
    crsStatus.reloading = false
  }
}

async function loadWhitelist(): Promise<void> {
  await loadState(whitelists, () => fetchProtectionWhitelists(siteId.value ? { siteId: siteId.value } : undefined))
}

async function loadCCBot(): Promise<void> {
  await Promise.all([
    loadState(ccPolicies, fetchCCBotPolicies),
    loadState(ccEvents, fetchCCBotEvents),
  ])
}

async function loadFingerprints(): Promise<void> {
  await loadState(fingerprints, fetchProtectionSemanticFingerprints)
}

function goToCCProtection(): void {
  void router.push({ name: 'ccProtection' })
}

function goToParserPreview(): void {
  activeTab.value = 'parser'
  void runParserPreview()
}

async function loadTraffic(): Promise<void> {
  trafficOverview.loading = true
  trafficOverview.error = ''
  try {
    trafficOverview.data = await fetchTrafficOverview(queryParams.value)
  } catch (error) {
    trafficOverview.data = {}
    trafficOverview.error = errorMessage(error)
  } finally {
    trafficOverview.loading = false
  }
  await Promise.all([
    loadState(trafficTrend, () => fetchTrafficTrend(queryParams.value)),
    loadState(trafficTopIp, () => fetchTrafficTopIP(queryParams.value)),
    loadState(trafficTopPath, () => fetchTrafficTopPath(queryParams.value)),
    loadState(trafficStatusCodes, () => fetchTrafficStatusCodes(queryParams.value)),
    loadState(trafficSites, () => fetchTrafficSites(queryParams.value)),
    loadState(attackEvents, () => fetchProtectionAttackEvents(queryParams.value)),
  ])
}

async function runParserPreview(): Promise<void> {
  parserLoading.value = true
  parserError.value = ''
  parserResult.value = null
  try {
    parserResult.value = await previewRequestParser(parserRawRequest.value)
  } catch (error) {
    parserError.value = errorMessage(error)
  } finally {
    parserLoading.value = false
  }
}

async function refreshCurrent(): Promise<void> {
  if (activeTab.value === 'policy') await loadPolicies()
  if (activeTab.value === 'rules') await loadRules()
  if (activeTab.value === 'whitelist') await loadWhitelist()
  if (activeTab.value === 'ccbot') await loadCCBot()
  if (activeTab.value === 'fingerprints') await loadFingerprints()
  if (activeTab.value === 'traffic') await loadTraffic()
}

async function refreshAll(): Promise<void> {
  await Promise.all([loadPolicies(), loadRules(), loadWhitelist(), loadCCBot(), loadFingerprints(), loadTraffic()])
}

function openDetail(title: string, payload: unknown): void {
  detailTitle.value = title
  detailPayload.value = payload
}

async function publishPolicy(row: SiteProtectionPolicy): Promise<void> {
  policyOperatingId.value = row.siteId
  policies.error = ''
  try {
    await publishSiteProtectionPolicy(row.siteId)
    await loadPolicies()
  } catch (error) {
    policies.error = errorMessage(error)
  } finally {
    policyOperatingId.value = null
  }
}

async function showPolicyVersions(row: SiteProtectionPolicy): Promise<void> {
  policyVersionState.loading = true
  policyVersionState.error = ''
  policyVersionState.siteId = row.siteId
  policyVersionState.items = []
  policyVersionState.audit = []
  try {
    const [versions, audit] = await Promise.all([fetchSitePolicyVersions(row.siteId), fetchSitePolicyAudit(row.siteId)])
    policyVersionState.items = versions.items
    policyVersionState.audit = audit.items
    openDetail(`站点策略版本 / 审计：${row.siteName || row.siteId}`, { current: row, versions: policyVersionState.items, audit: policyVersionState.audit })
  } catch (error) {
    policyVersionState.error = errorMessage(error)
    policies.error = policyVersionState.error
  } finally {
    policyVersionState.loading = false
  }
}

async function rollbackPolicy(row: SiteProtectionPolicy): Promise<void> {
  if (!row.runtimeVersion) {
    policies.error = '缺少可回滚版本号'
    return
  }
  policyOperatingId.value = row.siteId
  policies.error = ''
  try {
    await rollbackSiteProtectionPolicy(row.siteId, row.runtimeVersion)
    await loadPolicies()
    if (policyVersionState.siteId === row.siteId) await showPolicyVersions(row)
  } catch (error) {
    policies.error = errorMessage(error)
  } finally {
    policyOperatingId.value = null
  }
}

function resetRuleForm(): void {
  editingRuleId.value = null
  Object.assign(ruleForm, { ruleId: Date.now() % 1000000000, name: '', description: '', category: 'custom', variable: 'ARGS', operator: '@contains', pattern: '', severity: 'medium', score: 5, action: 'deny', source: 'custom', enabled: true })
  ruleError.value = ''
}

function openCreateRule(): void {
  resetRuleForm()
  ruleDialogVisible.value = true
}

function openEditRule(rule: ProtectionRule): void {
  const rawId = String(rule.id || '')
  if (rawId.startsWith('runtime-')) {
    openDetail('运行时规则详情（CRS/system 规则请先克隆为 custom 后修改）', rule)
    return
  }
  editingRuleId.value = rule.id
  Object.assign(ruleForm, {
    ruleId: Number(rule.ruleId || 0),
    name: rule.name || '',
    description: rule.description || '',
    category: rule.category || 'custom',
    variable: rule.variable || 'ARGS',
    operator: rule.operator || '@contains',
    pattern: rule.pattern || '',
    severity: rule.severity || 'medium',
    score: Number(rule.score || 5),
    action: rule.action || 'deny',
    source: rule.source || 'custom',
    enabled: rule.enabled !== false,
  })
  ruleError.value = ''
  ruleDialogVisible.value = true
}

async function saveRule(): Promise<void> {
  ruleSaving.value = true
  ruleError.value = ''
  try {
    if (editingRuleId.value) await updateProtectionRule(editingRuleId.value, { ...ruleForm })
    else await createProtectionRule({ ...ruleForm })
    ruleDialogVisible.value = false
    await loadRules()
  } catch (error) {
    ruleError.value = errorMessage(error)
  } finally {
    ruleSaving.value = false
  }
}

function formatRuleValidationErrors(errors: ProtectionRuleValidationError[] | undefined): string {
  if (!errors?.length) return '规则校验失败'
  return errors.map((item) => [item.line ? `line ${item.line}` : '', item.field || '', item.message].filter(Boolean).join(' ')).join('; ')
}

async function validateRuleForm(): Promise<void> {
  try {
    const result = await validateProtectionRules([{ ...ruleForm }])
    ruleError.value = result.valid ? '' : formatRuleValidationErrors(result.errors)
  } catch (error) {
    ruleError.value = errorMessage(error)
  }
}

async function importRuleFile(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  ruleImporting.value = true
  try {
    const content = await file.text()
    const payload = JSON.parse(content) as ProtectionRulePayload[]
    const result = await importProtectionRules(payload)
    ruleError.value = result.valid ? '' : formatRuleValidationErrors(result.errors)
    await loadRules()
  } catch (error) {
    ruleError.value = errorMessage(error)
  } finally {
    input.value = ''
    ruleImporting.value = false
  }
}

async function exportRulesJson(): Promise<void> {
  const data = await exportProtectionRules()
  openDetail('规则导出 JSON', data)
}

async function rollbackRules(): Promise<void> {
  ruleRollingBack.value = true
  try {
    await rollbackProtectionRules()
    await loadRules()
  } catch (error) {
    ruleError.value = errorMessage(error)
  } finally {
    ruleRollingBack.value = false
  }
}

function parseRulePayloadList(raw: string): ProtectionRulePayload[] | undefined {
  const text = raw.trim()
  if (!text) return undefined
  const parsed = JSON.parse(text) as unknown
  if (!Array.isArray(parsed)) {
    throw new Error('package.rules 必须是 JSON 数组')
  }
  return parsed as ProtectionRulePayload[]
}

function buildPublishRuleUpdatePayload(): {
  expectedHash?: string
  observeOnly?: boolean
  grayMode?: boolean
  package?: {
    type?: string
    version?: string
    hash?: string
    mode?: string
    rules?: ProtectionRulePayload[]
  }
} {
  const payload: {
    expectedHash?: string
    observeOnly?: boolean
    grayMode?: boolean
    package?: {
      type?: string
      version?: string
      hash?: string
      mode?: string
      rules?: ProtectionRulePayload[]
    }
  } = {}
  if (ruleUpdatePublishForm.expectedHash.trim()) payload.expectedHash = ruleUpdatePublishForm.expectedHash.trim()
  if (ruleUpdatePublishForm.observeOnly) payload.observeOnly = true
  if (ruleUpdatePublishForm.grayMode) payload.grayMode = true

  const pkgRules = parseRulePayloadList(ruleUpdatePublishForm.packageRules)
  const hasPackage =
    ruleUpdatePublishForm.packageType.trim() ||
    ruleUpdatePublishForm.packageVersion.trim() ||
    ruleUpdatePublishForm.packageHash.trim() ||
    ruleUpdatePublishForm.packageMode.trim() ||
    pkgRules?.length
  if (hasPackage) {
    payload.package = {}
    if (ruleUpdatePublishForm.packageType.trim()) payload.package.type = ruleUpdatePublishForm.packageType.trim()
    if (ruleUpdatePublishForm.packageVersion.trim()) payload.package.version = ruleUpdatePublishForm.packageVersion.trim()
    if (ruleUpdatePublishForm.packageHash.trim()) payload.package.hash = ruleUpdatePublishForm.packageHash.trim()
    if (ruleUpdatePublishForm.packageMode.trim()) payload.package.mode = ruleUpdatePublishForm.packageMode.trim()
    if (pkgRules?.length) payload.package.rules = pkgRules
  }
  return payload
}

async function submitRuleUpdatePublish(): Promise<void> {
  ruleUpdateSummary.operating = true
  ruleUpdateSummary.error = ''
  try {
    ruleUpdateResult.value = await publishProtectionRuleUpdate(buildPublishRuleUpdatePayload())
    ElMessage.success('规则更新请求已提交')
    await loadRules()
  } catch (error) {
    ruleUpdateSummary.error = errorMessage(error)
  } finally {
    ruleUpdateSummary.operating = false
  }
}

async function submitRuleUpdateRollback(): Promise<void> {
  ruleUpdateSummary.operating = true
  ruleUpdateSummary.error = ''
  try {
    const payload: { updateId?: string; version?: string } = {}
    if (ruleUpdateRollbackForm.updateId.trim()) payload.updateId = ruleUpdateRollbackForm.updateId.trim()
    if (ruleUpdateRollbackForm.version.trim()) payload.version = ruleUpdateRollbackForm.version.trim()
    ruleUpdateResult.value = await rollbackProtectionRuleUpdate(Object.keys(payload).length ? payload : undefined)
    ElMessage.success('规则版本已回滚')
    await loadRules()
  } catch (error) {
    ruleUpdateSummary.error = errorMessage(error)
  } finally {
    ruleUpdateSummary.operating = false
  }
}

async function submitEmergencyRuleUpdate(): Promise<void> {
  ruleUpdateSummary.operating = true
  ruleUpdateSummary.error = ''
  try {
    const rulePayload: ProtectionRulePayload = {
      ruleId: Number(emergencyUpdateForm.ruleId),
      name: emergencyUpdateForm.name.trim(),
      category: emergencyUpdateForm.category.trim() || 'emergency',
      variable: emergencyUpdateForm.variable.trim(),
      operator: emergencyUpdateForm.operator.trim(),
      pattern: emergencyUpdateForm.pattern,
      severity: emergencyUpdateForm.severity.trim(),
      score: Number(emergencyUpdateForm.score),
      action: emergencyUpdateForm.action.trim(),
      source: emergencyUpdateForm.source.trim() || 'emergency',
      enabled: emergencyUpdateForm.enabled,
    }
    if (emergencyUpdateForm.description.trim()) {
      rulePayload.description = emergencyUpdateForm.description.trim()
    }
    const emergencyPayload: {
      cve?: string
      version?: string
      observeOnly: boolean
      rule: ProtectionRulePayload
    } = {
      observeOnly: emergencyUpdateForm.observeOnly,
      rule: rulePayload,
    }
    if (emergencyUpdateForm.cve.trim()) emergencyPayload.cve = emergencyUpdateForm.cve.trim()
    if (emergencyUpdateForm.version.trim()) emergencyPayload.version = emergencyUpdateForm.version.trim()
    ruleUpdateResult.value = await createEmergencyProtectionRuleUpdate(emergencyPayload)
    ElMessage.success('紧急规则已提交')
    await loadRules()
  } catch (error) {
    ruleUpdateSummary.error = errorMessage(error)
  } finally {
    ruleUpdateSummary.operating = false
  }
}

function openRuleImport(): void {
  ruleImportInput.value?.click()
}

async function toggleRule(rule: ProtectionRule): Promise<void> {
  const rawId = String(rule.id || '')
  if (rawId.startsWith('runtime-')) {
    openDetail('运行时规则详情（需持久化规则才能从控制台启停）', rule)
    return
  }
  await setProtectionRuleEnabled(rule.id, rule.enabled === false)
  await loadRules()
}

async function removeRule(rule: ProtectionRule): Promise<void> {
  const rawId = String(rule.id || '')
  if (rawId.startsWith('runtime-')) {
    openDetail('运行时规则详情（CRS/system 文件规则不能在此删除）', rule)
    return
  }
  await deleteProtectionRule(rule.id)
  await loadRules()
}

function resetWhitelistForm(): void {
  editingWhitelistId.value = null
  Object.assign(whitelistForm, { siteId: siteId.value || '', type: 'url_whitelist', value: '', description: '', scope: 'site', ruleId: '', variable: '', expiresAt: '', status: 'enabled' })
  whitelistError.value = ''
}

function openCreateWhitelist(): void {
  resetWhitelistForm()
  whitelistDialogVisible.value = true
}

function openEditWhitelist(row: ProtectionWhitelist): void {
  editingWhitelistId.value = row.id
  Object.assign(whitelistForm, {
    siteId: row.siteId || '',
    type: row.type || 'url_whitelist',
    value: row.pattern || '',
    description: row.reason || '',
    scope: row.scope || 'site',
    ruleId: row.ruleId || '',
    variable: row.variable || '',
    expiresAt: row.expiresAt || '',
    status: row.enabled === false ? 'disabled' : 'enabled',
  })
  whitelistError.value = ''
  whitelistDialogVisible.value = true
}

async function saveWhitelist(): Promise<void> {
  whitelistSaving.value = true
  whitelistError.value = ''
  try {
    if (editingWhitelistId.value) await updateProtectionWhitelist(editingWhitelistId.value, { ...whitelistForm })
    else await createProtectionWhitelist({ ...whitelistForm })
    whitelistDialogVisible.value = false
    await loadWhitelist()
  } catch (error) {
    whitelistError.value = errorMessage(error)
  } finally {
    whitelistSaving.value = false
  }
}

async function toggleWhitelist(row: ProtectionWhitelist): Promise<void> {
  const payload: ProtectionWhitelistPayload = {
    type: row.type || 'url_whitelist',
    value: row.pattern || '',
    description: row.reason || '',
    scope: row.scope || 'site',
    status: row.enabled === false ? 'enabled' : 'disabled',
  }
  if (row.siteId !== undefined && row.siteId !== '') payload.siteId = row.siteId
  if (row.ruleId !== undefined && row.ruleId !== '') payload.ruleId = row.ruleId
  if (row.variable !== undefined && row.variable !== '') payload.variable = row.variable
  if (row.expiresAt !== undefined && row.expiresAt !== '') payload.expiresAt = row.expiresAt
  await updateProtectionWhitelist(row.id, payload)
  await loadWhitelist()
}

async function removeWhitelist(row: ProtectionWhitelist): Promise<void> {
  await deleteProtectionWhitelist(row.id)
  await loadWhitelist()
}

function parserFieldsBySource(source: string): RequestParserField[] {
  return parserResult.value?.fields?.filter((field) => field.source === source) ?? []
}

function fieldDecodeText(field: RequestParserField): string {
  const steps = field.decodeSteps ?? []
  if (steps.length === 0) return '无解码步骤'
  return steps.map((step) => `${step.pass}:${step.stage}`).join(' → ')
}

function parserErrorText(error: { source?: string; message?: string; fatal?: boolean }): string {
  return `${error.fatal ? '[fatal] ' : ''}${error.source || 'parse'}: ${error.message || ''}`
}

function formatJson(payload: unknown): string {
  return JSON.stringify(payload, null, 2)
}

function formatDate(value?: string | number): string {
  if (!value) return '-'
  if (typeof value === 'number') return new Date(value).toLocaleString()
  return value
}

function statusTag(enabled?: boolean): 'success' | 'info' {
  return enabled === false ? 'info' : 'success'
}

function displayNumber(value?: number): string {
  return typeof value === 'number' ? String(value) : '0'
}

function percent(value?: number): string {
  return typeof value === 'number' ? `${(value * 100).toFixed(2)}%` : '--'
}

function signedPercent(value?: number): string {
  if (typeof value !== 'number') return '--'
  return `${value >= 0 ? '+' : ''}${(value * 100).toFixed(2)}%`
}

function displayCount(value?: number): string {
  return typeof value === 'number' ? String(value) : '--'
}

function gateTagType(passed?: boolean): 'success' | 'danger' | 'info' {
  if (passed === true) return 'success'
  if (passed === false) return 'danger'
  return 'info'
}

function gateMetricClass(passed?: boolean): 'is-success' | 'is-danger' | 'is-primary' {
  if (passed === true) return 'is-success'
  if (passed === false) return 'is-danger'
  return 'is-primary'
}

function updateStatusTag(status?: string): 'success' | 'warning' | 'danger' | 'info' {
  const normalized = String(status || '').toLowerCase()
  if (['published', 'success', 'ready', 'active'].includes(normalized)) return 'success'
  if (['blocked', 'failed', 'error'].includes(normalized)) return 'danger'
  if (['pending', 'publishing', 'gray', 'observe'].includes(normalized)) return 'warning'
  return 'info'
}

function updateDiffCount(value: number | ProtectionRule[] | undefined): string {
  if (typeof value === 'number') return String(value)
  if (Array.isArray(value)) return String(value.length)
  return '--'
}

function rankLabel(row: TrafficRankItem): string {
  return String(row.name || row.key || '')
}

function drilldownTraffic(kind: 'ip' | 'path' | 'site' | 'status', row: TrafficRankItem): void {
  const value = rankLabel(row)
  openDetail('访问统计下钻', {
    kind,
    value,
    count: row.value ?? row.count ?? 0,
    accessLogsEndpoint: `/api/access-logs?${kind === 'ip' ? 'sourceIp' : kind}=${encodeURIComponent(value)}`,
    attackEventsEndpoint: `/api/protection/attack-events?${kind === 'ip' ? 'sourceIp' : kind}=${encodeURIComponent(value)}`,
  })
}

onMounted(() => {
  void refreshAll()
})
</script>

<template>
  <section class="page-stack protection-config-page">
    <div class="sl-card protection-header-card">
      <div class="sl-card-head">
        <div>
          <span class="sl-card-title">防护配置</span>
          <p class="page-hint">统一承接站点策略、规则/CRS、误报白名单、请求解析、CC/Bot、语义指纹、访问统计与攻击解释。所有数据均来自真实 API；失败时展示错误，不回退假数据。</p>
        </div>
        <div class="protection-actions">
          <el-input v-model="siteId" clearable placeholder="siteId" style="width: 120px" />
          <el-select v-model="trafficAction" clearable placeholder="动作" style="width: 130px"><el-option label="allow" value="allow" /><el-option label="block" value="block" /><el-option label="observe" value="observe" /><el-option label="captcha" value="captcha" /><el-option label="temp-block" value="temp-block" /></el-select>
          <el-input v-model="trafficRuleGroup" clearable placeholder="规则组/阶段" style="width: 140px" />
          <el-input v-model="trafficAttackType" clearable placeholder="攻击类型" style="width: 130px" />
          <el-date-picker v-model="timeRange" type="datetimerange" start-placeholder="开始时间" end-placeholder="结束时间" value-format="x" />
          <el-button :icon="Search" @click="loadTraffic">筛选统计</el-button>
          <el-button :icon="Refresh" @click="refreshAll">刷新真实数据</el-button>
        </div>
      </div>
      <div class="protection-tab-grid">
        <button v-for="tab in tabs" :key="tab.key" class="protection-tab-card" :class="{ 'is-active': activeTab === tab.key }" @click="activeTab = tab.key; refreshCurrent()">
          <strong>{{ tab.label }}</strong>
          <span>{{ tab.desc }}</span>
        </button>
      </div>
    </div>

    <div v-show="activeTab === 'policy'" class="sl-card protection-panel" v-loading="policies.loading">
      <div class="sl-card-head">
        <span class="sl-card-title">站点策略</span>
        <el-button :icon="Refresh" @click="loadPolicies">刷新</el-button>
      </div>
      <el-alert v-if="policies.error" type="error" :title="policies.error" show-icon :closable="false" />
      <el-table v-else :data="policies.items" empty-text="暂无真实站点策略；请先通过后端 /api/protection/site-policies 接入策略数据">
        <el-table-column prop="siteName" label="站点" min-width="140">
          <template #default="{ row }: { row: SiteProtectionPolicy }">{{ row.siteName || row.siteId }}</template>
        </el-table-column>
        <el-table-column prop="mode" label="防护模式" width="110" />
        <el-table-column label="规则组" min-width="220">
          <template #default="{ row }: { row: SiteProtectionPolicy }">
            <div class="tag-list compact"><el-tag v-for="group in row.enabledRuleGroups || row.ruleGroups || []" :key="group" type="primary">{{ group }}</el-tag></div>
          </template>
        </el-table-column>
        <el-table-column prop="crsParanoiaLevel" label="CRS PL" width="90" />
        <el-table-column prop="inboundThreshold" label="入站阈值" width="100" />
        <el-table-column prop="defaultAction" label="默认动作" width="110" />
        <el-table-column prop="runtimeVersion" label="运行版本" min-width="130" />
        <el-table-column label="发布时间" width="170"><template #default="{ row }: { row: SiteProtectionPolicy }">{{ formatDate(row.publishedAt) }}</template></el-table-column>
        <el-table-column label="更新时间" width="170"><template #default="{ row }: { row: SiteProtectionPolicy }">{{ formatDate(row.updatedAt || row.publishedAt) }}</template></el-table-column>
        <el-table-column label="操作" width="250">
          <template #default="{ row }: { row: SiteProtectionPolicy }">
            <el-button link type="primary" @click="openDetail('站点策略详情', row)">详情</el-button>
            <el-button link type="success" :loading="policyOperatingId === row.siteId" @click="publishPolicy(row)">发布</el-button>
            <el-button link type="primary" :loading="policyVersionState.loading && policyVersionState.siteId === row.siteId" @click="showPolicyVersions(row)">版本</el-button>
            <el-button link type="warning" :disabled="!row.runtimeVersion" :loading="policyOperatingId === row.siteId" @click="rollbackPolicy(row)">回滚当前</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div v-show="activeTab === 'rules'" class="page-stack">
      <div class="sl-card protection-panel" v-loading="ruleUpdateSummary.loading">
        <div class="sl-card-head">
          <span class="sl-card-title">规则 / 情报更新</span>
          <div class="protection-actions">
            <span class="page-hint">运行版本 {{ ruleUpdateSummary.data?.runtimeVersion || '--' }} / 热更新 {{ ruleUpdateSummary.data?.hotReload ? 'ok' : 'off' }}</span>
            <el-button :icon="Refresh" @click="loadRuleUpdates">刷新</el-button>
          </div>
        </div>
        <el-alert v-if="ruleUpdateSummary.error" type="error" :title="ruleUpdateSummary.error" show-icon :closable="false" />
        <template v-else-if="ruleUpdateSummary.data">
          <div class="dashboard-metric-grid">
            <el-card class="metric-card"><div class="metric-card__label">当前版本</div><div class="metric-card__value is-primary">{{ ruleUpdateSummary.data.currentVersion || '--' }}</div><div class="metric-card__trend">Hash {{ ruleUpdateSummary.data.currentHash || '--' }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">状态 / 规则数</div><div class="metric-card__value" :class="updateStatusTag(ruleUpdateSummary.data.currentStatus) === 'danger' ? 'is-danger' : 'is-success'">{{ ruleUpdateSummary.data.currentStatus || '--' }}</div><div class="metric-card__trend">规则 {{ displayCount(ruleUpdateSummary.data.currentRuleCount) }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">最近发布</div><div class="metric-card__value is-success">{{ formatDate(ruleUpdateSummary.data.lastPublishedAt) }}</div><div class="metric-card__trend">包版本 {{ ruleUpdateSummary.data.latest?.packageVersion || '--' }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">最新差异</div><div class="metric-card__value is-warning">{{ displayCount(ruleUpdateSummary.data.latest?.diff?.newRules ?? ruleUpdateSummary.data.latest?.diff?.added) }}/{{ displayCount(ruleUpdateSummary.data.latest?.diff?.removedRules ?? ruleUpdateSummary.data.latest?.diff?.removed) }}/{{ displayCount(ruleUpdateSummary.data.latest?.diff?.modifiedRules ?? ruleUpdateSummary.data.latest?.diff?.modified) }}</div><div class="metric-card__trend">新增 / 删除 / 修改</div></el-card>
          </div>
          <el-alert v-if="ruleUpdateSummary.data.lastBlockedReason || ruleUpdateSummary.data.lastFailureReason" type="warning" :closable="false" show-icon>
            <template #title>{{ ruleUpdateSummary.data.lastBlockedReason || ruleUpdateSummary.data.lastFailureReason }}</template>
          </el-alert>
          <div class="traffic-grid">
            <div class="sl-card protection-panel">
              <div class="sl-card-head"><span class="sl-card-title">评估与来源</span><el-button link type="primary" @click="openDetail('规则更新摘要', ruleUpdateSummary.data)">详情</el-button></div>
              <div class="compact-info-grid">
                <div class="compact-info-item"><span>攻击拦截率</span><strong>{{ percent(ruleUpdateSummary.data.latest?.evaluation?.attackBlockRate) }}</strong><small>Δ {{ signedPercent(ruleUpdateSummary.data.latest?.evaluation?.attackBlockRateDelta) }}</small></div>
                <div class="compact-info-item"><span>良性误报率</span><strong>{{ percent(ruleUpdateSummary.data.latest?.evaluation?.benignFalsePositiveRate) }}</strong><small>Δ {{ signedPercent(ruleUpdateSummary.data.latest?.evaluation?.benignFalsePositiveRateDelta) }}</small></div>
                <div class="compact-info-item"><span>最新状态</span><strong><el-tag size="small" :type="updateStatusTag(ruleUpdateSummary.data.latest?.status)">{{ ruleUpdateSummary.data.latest?.status || '--' }}</el-tag></strong><small>{{ ruleUpdateSummary.data.latest?.mode || '--' }}</small></div>
                <div class="compact-info-item"><span>紧急规则</span><strong>{{ ruleUpdateSummary.data.latest?.emergency ? '是' : '否' }}</strong><small>{{ ruleUpdateSummary.data.latest?.emergencyCve || '--' }}</small></div>
              </div>
              <el-empty v-if="!(ruleUpdateSummary.data.sources?.length)" description="暂无更新来源数据" />
              <el-table v-else :data="ruleUpdateSummary.data.sources || []" size="small" empty-text="暂无更新来源数据">
                <el-table-column prop="name" label="来源" min-width="140" />
                <el-table-column prop="type" label="类型" width="100" />
                <el-table-column prop="currentVersion" label="当前版本" width="130" />
                <el-table-column prop="currentHash" label="当前 Hash" min-width="160" show-overflow-tooltip />
                <el-table-column prop="lastStatus" label="最近状态" width="100" />
                <el-table-column prop="lastError" label="最近错误" min-width="180" show-overflow-tooltip />
                <el-table-column label="最近成功" width="170">
                  <template #default="{ row }: { row: { lastSuccessAt?: string | number } }">{{ formatDate(row.lastSuccessAt) }}</template>
                </el-table-column>
              </el-table>
            </div>
            <div class="sl-card protection-panel">
              <div class="sl-card-head"><span class="sl-card-title">最近更新日志</span><span class="page-hint">新增 {{ updateDiffCount(ruleUpdateSummary.data.latest?.newRules) }} / 删除 {{ updateDiffCount(ruleUpdateSummary.data.latest?.removedRules) }} / 修改 {{ updateDiffCount(ruleUpdateSummary.data.latest?.modifiedRules) }}</span></div>
              <el-empty v-if="!(ruleUpdateSummary.data.logs?.length)" description="暂无规则更新日志" />
              <el-table v-else :data="ruleUpdateSummary.data.logs || []" size="small" empty-text="暂无规则更新日志">
                <el-table-column label="时间" width="170"><template #default="{ row }: { row: ProtectionRuleUpdateResult & { time?: string | number } }">{{ formatDate(row.time || row.publishedAt || row.createdAt) }}</template></el-table-column>
                <el-table-column prop="status" label="状态" width="100"><template #default="{ row }: { row: ProtectionRuleUpdateResult }"><el-tag size="small" :type="updateStatusTag(row.status)">{{ row.status || '--' }}</el-tag></template></el-table-column>
                <el-table-column prop="packageVersion" label="包版本" width="130" />
                <el-table-column prop="packageHash" label="Hash" min-width="150" show-overflow-tooltip />
                <el-table-column label="原因" min-width="180" show-overflow-tooltip><template #default="{ row }: { row: ProtectionRuleUpdateResult }">{{ row.blockedReason || row.errorMessage || '--' }}</template></el-table-column>
              </el-table>
            </div>
          </div>
          <div class="traffic-grid">
            <div class="sl-card protection-panel">
              <div class="sl-card-head"><span class="sl-card-title">回滚</span><span class="page-hint">留空则按后端默认策略回滚</span></div>
              <el-form label-width="86px" size="small" class="rule-form compact-form">
                <el-form-item label="updateId"><el-input v-model="ruleUpdateRollbackForm.updateId" clearable placeholder="可选" /></el-form-item>
                <el-form-item label="version"><el-input v-model="ruleUpdateRollbackForm.version" clearable placeholder="可选" /></el-form-item>
                <el-form-item><el-button type="warning" :loading="ruleUpdateSummary.operating" @click="submitRuleUpdateRollback">执行回滚</el-button></el-form-item>
              </el-form>
            </div>
            <div class="sl-card protection-panel">
              <div class="sl-card-head"><span class="sl-card-title">手动更新</span><span class="page-hint">支持 expectedHash / observeOnly / grayMode / package</span></div>
              <el-form label-width="98px" size="small" class="rule-form compact-form">
                <el-form-item label="expectedHash"><el-input v-model="ruleUpdatePublishForm.expectedHash" clearable placeholder="可选" /></el-form-item>
                <el-form-item label="发布选项"><div class="rule-inline"><el-switch v-model="ruleUpdatePublishForm.observeOnly" active-text="仅观察" /><el-switch v-model="ruleUpdatePublishForm.grayMode" active-text="灰度" /></div></el-form-item>
                <el-form-item label="package.type"><el-input v-model="ruleUpdatePublishForm.packageType" clearable placeholder="intel/manual/crs" /></el-form-item>
                <el-form-item label="package.version"><el-input v-model="ruleUpdatePublishForm.packageVersion" clearable /></el-form-item>
                <el-form-item label="package.hash"><el-input v-model="ruleUpdatePublishForm.packageHash" clearable /></el-form-item>
                <el-form-item label="package.mode"><el-input v-model="ruleUpdatePublishForm.packageMode" clearable placeholder="observe/gray/enforce" /></el-form-item>
                <el-form-item label="package.rules"><el-input v-model="ruleUpdatePublishForm.packageRules" type="textarea" :rows="4" placeholder='可选 JSON 数组，例如 [{"ruleId":155001,"name":"temp","category":"custom","variable":"ARGS","operator":"@contains","pattern":"x","severity":"high","score":8,"action":"deny","source":"manual","enabled":true}]' /></el-form-item>
                <el-form-item><el-button type="primary" :loading="ruleUpdateSummary.operating" @click="submitRuleUpdatePublish">发布更新</el-button></el-form-item>
              </el-form>
            </div>
          </div>
          <div class="sl-card protection-panel">
            <div class="sl-card-head"><span class="sl-card-title">紧急 CVE 临时规则</span><span class="page-hint">{{ ruleUpdateSummary.data.latest?.emergencyCve ? `最近紧急标记 ${ruleUpdateSummary.data.latest?.emergencyCve}` : '未发现最近紧急标记' }}</span></div>
            <el-form label-width="90px" size="small" class="rule-form compact-form">
              <div class="compact-form-grid">
                <el-form-item label="CVE"><el-input v-model="emergencyUpdateForm.cve" clearable placeholder="CVE-2026-xxxx" /></el-form-item>
                <el-form-item label="版本"><el-input v-model="emergencyUpdateForm.version" clearable placeholder="可选" /></el-form-item>
                <el-form-item label="Rule ID"><el-input-number v-model="emergencyUpdateForm.ruleId" :min="1" :step="1" /></el-form-item>
                <el-form-item label="名称"><el-input v-model="emergencyUpdateForm.name" placeholder="Emergency CVE block" /></el-form-item>
                <el-form-item label="变量"><el-input v-model="emergencyUpdateForm.variable" /></el-form-item>
                <el-form-item label="操作符"><el-input v-model="emergencyUpdateForm.operator" /></el-form-item>
                <el-form-item label="Pattern"><el-input v-model="emergencyUpdateForm.pattern" /></el-form-item>
                <el-form-item label="动作"><el-select v-model="emergencyUpdateForm.action"><el-option label="deny" value="deny" /><el-option label="log" value="log" /><el-option label="pass" value="pass" /></el-select></el-form-item>
                <el-form-item label="观察"><el-switch v-model="emergencyUpdateForm.observeOnly" active-text="仅观察" /></el-form-item>
              </div>
              <el-form-item label="描述"><el-input v-model="emergencyUpdateForm.description" type="textarea" :rows="2" /></el-form-item>
              <el-form-item><el-button type="danger" :loading="ruleUpdateSummary.operating" @click="submitEmergencyRuleUpdate">下发紧急规则</el-button></el-form-item>
            </el-form>
          </div>
          <el-alert v-if="ruleUpdateResult" type="success" :closable="false" show-icon>
            <template #title>{{ `结果: ${ruleUpdateResult.status || '--'} / 发布 ${ruleUpdateResult.published ? 'yes' : 'no'} / 版本 ${ruleUpdateResult.packageVersion || ruleUpdateResult.version || '--'}` }}</template>
            <template #default>{{ ruleUpdateResult.blockedReason || ruleUpdateResult.errorMessage || `Diff ${updateDiffCount(ruleUpdateResult.newRules)} / ${updateDiffCount(ruleUpdateResult.removedRules)} / ${updateDiffCount(ruleUpdateResult.modifiedRules)}` }}</template>
          </el-alert>
        </template>
        <el-empty v-else description="未获取到规则更新摘要" />
      </div>

      <div class="sl-card protection-panel" v-loading="crsStatus.loading">
        <div class="sl-card-head">
          <span class="sl-card-title">OWASP CRS / Coraza 状态</span>
          <div class="protection-actions"><el-button :icon="Refresh" :loading="crsStatus.reloading" @click="reloadCRSRules">重载 CRS</el-button></div>
        </div>
        <el-alert v-if="crsStatus.error" type="error" :title="crsStatus.error" show-icon :closable="false" />
        <div v-else class="dashboard-metric-grid">
          <el-card class="metric-card"><div class="metric-card__label">状态</div><div class="metric-card__value is-primary">{{ crsStatus.data.enabled ? (crsStatus.data.loaded ? '已加载' : '未加载') : '未启用' }}</div><div class="metric-card__trend">{{ crsStatus.data.rulesDir || 'rules/crs' }}</div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">规则 / 文件</div><div class="metric-card__value is-success">{{ crsStatus.data.ruleCount ?? 0 }}</div><div class="metric-card__trend">文件 {{ crsStatus.data.fileCount ?? 0 }}</div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">PL / 阈值</div><div class="metric-card__value is-warning">PL{{ crsStatus.data.paranoiaLevel ?? 1 }}</div><div class="metric-card__trend">入站 {{ crsStatus.data.inboundThreshold ?? 5 }} / 出站 {{ crsStatus.data.outboundThreshold ?? 5 }}</div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">版本 / 最近重载</div><div class="metric-card__value is-primary">{{ crsStatus.data.version || '--' }}</div><div class="metric-card__trend">{{ formatDate(crsStatus.data.lastReloadAt) }}</div></el-card>
        </div>
      </div>
      <div class="sl-card protection-panel" v-loading="securityCoverage.loading">
        <div class="sl-card-head">
          <span class="sl-card-title">安全覆盖率</span>
          <div class="protection-actions">
            <el-tag size="small" :type="gateTagType(securityCoverage.data.gatePassed)">
              {{ securityCoverage.data.gatePassed === false ? '门禁失败' : '门禁通过' }}
            </el-tag>
            <span class="page-hint">来自 /api/protection/security-coverage</span>
          </div>
        </div>
        <el-alert v-if="securityCoverage.error" type="error" :title="securityCoverage.error" show-icon :closable="false" />
        <el-alert
          v-else-if="securityCoverage.data.gatePassed === false"
          type="warning"
          :title="securityCoverage.data.gateFailures?.[0] || '安全覆盖率门禁失败'"
          :description="(securityCoverage.data.gateFailures || []).slice(1).join('；')"
          show-icon
          :closable="false"
        />
        <div v-else class="dashboard-metric-grid">
          <el-card class="metric-card"><div class="metric-card__label">攻击拦截率</div><div class="metric-card__value" :class="gateMetricClass(securityCoverage.data.gatePassed)">{{ percent(securityCoverage.data.attackBlockRate) }}</div><div class="metric-card__trend">{{ securityCoverage.data.attackBlocked ?? 0 }}/{{ securityCoverage.data.attackTotal ?? 0 }}，目标 {{ percent(securityCoverage.data.attackBlockRateTarget) }}<span v-if="securityCoverage.data.hasBaseline">，Δ {{ signedPercent(securityCoverage.data.attackBlockRateDelta) }}</span></div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">误报样本</div><div class="metric-card__value" :class="(securityCoverage.data.benignFalsePositives ?? 0) > (securityCoverage.data.falsePositiveLimit ?? 3) || (securityCoverage.data.benignFalseDelta ?? 0) > (securityCoverage.data.maxFalsePositiveRise ?? 0) ? 'is-danger' : 'is-success'">{{ securityCoverage.data.benignFalsePositives ?? 0 }}</div><div class="metric-card__trend">良性 {{ securityCoverage.data.benignTotal ?? 0 }}，上限 {{ securityCoverage.data.falsePositiveLimit ?? 3 }}<span v-if="securityCoverage.data.hasBaseline">，Δ {{ securityCoverage.data.benignFalseDelta ?? 0 }}</span></div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">规则版本 / 数量</div><div class="metric-card__value is-primary">{{ securityCoverage.data.ruleVersion || '--' }}</div><div class="metric-card__trend">{{ securityCoverage.data.ruleCount ?? 0 }} 条 / 文件 {{ securityCoverage.data.ruleFileCount ?? 0 }}</div></el-card>
          <el-card class="metric-card"><div class="metric-card__label">漏拦 / 误报</div><div class="metric-card__value is-warning">{{ securityCoverage.data.missedAttacks?.length ?? 0 }} / {{ securityCoverage.data.falsePositives?.length ?? 0 }}</div><div class="metric-card__trend">{{ securityCoverage.data.falsePositives?.[0]?.id || securityCoverage.data.missedAttacks?.[0]?.id || '无高频样本' }}</div></el-card>
        </div>
        <div v-if="!securityCoverage.error" class="compact-info-grid">
          <div class="compact-info-item"><span>报告时间</span><strong>{{ securityCoverage.data.generatedAt || '--' }}</strong><small>规则版本 {{ securityCoverage.data.ruleVersion || '--' }}</small></div>
          <div class="compact-info-item"><span>Baseline</span><strong>{{ securityCoverage.data.hasBaseline ? (securityCoverage.data.baselineGeneratedAt || '--') : '未提供' }}</strong><small v-if="securityCoverage.data.hasBaseline">版本 {{ securityCoverage.data.baselineRuleVersion || '--' }}</small><small v-else>docs/security-coverage-baseline.json</small></div>
          <div class="compact-info-item"><span>Top missed</span><strong>{{ securityCoverage.data.missedAttacks?.[0]?.id || '--' }}</strong><small>{{ securityCoverage.data.missedAttacks?.[0]?.category || '无漏拦样本' }}</small></div>
          <div class="compact-info-item"><span>Top false positive</span><strong>{{ securityCoverage.data.falsePositives?.[0]?.id || '--' }}</strong><small>{{ securityCoverage.data.falsePositives?.[0]?.category || '无误报样本' }}</small></div>
        </div>
      </div>
      <div class="sl-card protection-panel" v-loading="ruleSets.loading">
        <div class="sl-card-head"><span class="sl-card-title">CRS / 规则集概览</span><el-button :icon="Refresh" @click="loadRules">刷新</el-button></div>
        <el-alert v-if="ruleSets.error" type="error" :title="ruleSets.error" show-icon :closable="false" />
        <el-table v-else :data="ruleSets.items" empty-text="暂无真实规则集；不展示 OWASP CRS 假数量">
          <el-table-column prop="name" label="规则集" min-width="180" />
          <el-table-column prop="source" label="来源" width="120" />
          <el-table-column prop="version" label="版本" width="130" />
          <el-table-column prop="ruleCount" label="规则数" width="100" />
          <el-table-column label="状态" width="100"><template #default="{ row }: { row: ProtectionRuleSet }"><el-tag :type="statusTag(row.enabled)">{{ row.enabled === false ? '禁用' : '启用' }}</el-tag></template></el-table-column>
          <el-table-column label="更新时间" width="170"><template #default="{ row }: { row: ProtectionRuleSet }">{{ formatDate(row.updatedAt) }}</template></el-table-column>
        </el-table>
      </div>
      <div class="sl-card protection-panel" v-loading="rules.loading">
        <div class="sl-card-head"><span class="sl-card-title">规则列表</span><div class="protection-actions"><span class="page-hint">运行版本 {{ ruleRuntimeVersion || '--' }} / 热更新 {{ ruleHotReload ? 'ok' : 'off' }}</span><el-button @click="exportRulesJson">导出 JSON</el-button><el-button :loading="ruleImporting" @click="openRuleImport">导入 JSON</el-button><el-button type="warning" :loading="ruleRollingBack" @click="rollbackRules">回滚上次发布</el-button><el-button type="primary" @click="openCreateRule">新增自定义规则</el-button><input ref="ruleImportInput" type="file" accept="application/json" style="display:none" @change="importRuleFile" /></div></div>
        <el-alert v-if="rules.error" type="error" :title="rules.error" show-icon :closable="false" />
        <el-table v-else :data="rules.items" empty-text="暂无真实规则；新增 custom 规则后会热更新到检测运行时">
          <el-table-column prop="ruleId" label="规则 ID" width="130" />
          <el-table-column prop="name" label="名称" min-width="180" />
          <el-table-column prop="category" label="类别" width="120" />
          <el-table-column prop="severity" label="等级" width="100" />
          <el-table-column prop="score" label="分数" width="80" />
          <el-table-column prop="action" label="动作" width="100" />
          <el-table-column prop="source" label="来源" width="110" />
          <el-table-column prop="hits" label="命中" width="90" />
          <el-table-column prop="runtimeVersion" label="运行版本" min-width="150" />
          <el-table-column label="热更新" width="90"><template #default="{ row }: { row: ProtectionRule }">{{ row.hotReload ? 'yes' : 'no' }}</template></el-table-column>
          <el-table-column label="状态" width="100"><template #default="{ row }: { row: ProtectionRule }"><el-tag :type="statusTag(row.enabled)">{{ row.enabled === false ? '禁用' : '启用' }}</el-tag></template></el-table-column>
          <el-table-column label="操作" width="230"><template #default="{ row }: { row: ProtectionRule }"><el-button link type="primary" @click="openDetail('规则详情', row)">详情</el-button><el-button link type="primary" @click="openEditRule(row)">编辑</el-button><el-button link :type="row.enabled === false ? 'success' : 'warning'" @click="toggleRule(row)">{{ row.enabled === false ? '启用' : '禁用' }}</el-button><el-button link type="danger" @click="removeRule(row)">删除</el-button></template></el-table-column>
        </el-table>
      </div>
    </div>

    <div v-show="activeTab === 'whitelist'" class="sl-card protection-panel" v-loading="whitelists.loading">
      <div class="sl-card-head">
        <span class="sl-card-title">误报白名单 / CRS Rule Exclusion</span>
        <div class="protection-actions"><el-button type="primary" @click="openCreateWhitelist">新增白名单/例外</el-button><el-button :icon="Refresh" @click="loadWhitelist">刷新</el-button></div>
      </div>
      <el-alert v-if="whitelists.error" type="error" :title="whitelists.error" show-icon :closable="false" />
      <el-table v-else :data="whitelists.items" empty-text="暂无真实白名单；可从攻击事件一键加白或在此新增">
        <el-table-column prop="siteId" label="站点" width="90" />
        <el-table-column prop="type" label="类型" width="150" />
        <el-table-column prop="scope" label="作用域" width="100" />
        <el-table-column prop="pattern" label="匹配范围" min-width="200" />
        <el-table-column prop="ruleId" label="规则" width="110" />
        <el-table-column prop="variable" label="变量" width="120" />
        <el-table-column prop="reason" label="原因" min-width="180" />
        <el-table-column prop="createdFrom" label="来源" width="130" />
        <el-table-column label="状态" width="100"><template #default="{ row }: { row: ProtectionWhitelist }"><el-tag :type="statusTag(row.enabled)">{{ row.enabled === false ? '禁用' : '启用' }}</el-tag></template></el-table-column>
        <el-table-column label="过期时间" width="170"><template #default="{ row }: { row: ProtectionWhitelist }">{{ formatDate(row.expiresAt) }}</template></el-table-column>
        <el-table-column label="操作" width="230"><template #default="{ row }: { row: ProtectionWhitelist }"><el-button link type="primary" @click="openDetail('白名单详情', row)">详情</el-button><el-button link type="primary" @click="openEditWhitelist(row)">编辑</el-button><el-button link :type="row.enabled === false ? 'success' : 'warning'" @click="toggleWhitelist(row)">{{ row.enabled === false ? '启用' : '禁用' }}</el-button><el-button link type="danger" @click="removeWhitelist(row)">删除</el-button></template></el-table-column>
      </el-table>
    </div>

    <div v-show="activeTab === 'parser'" class="sl-card protection-panel">
      <div class="sl-card-head"><span class="sl-card-title">请求解析预览</span><el-button type="primary" :icon="Search" :loading="parserLoading" @click="runParserPreview">调用真实解析 API</el-button></div>
      <div class="parser-layout">
        <el-input v-model="parserRawRequest" type="textarea" :rows="12" placeholder="粘贴 raw HTTP request" />
        <div class="parser-result">
          <el-alert v-if="parserError" type="error" :title="parserError" show-icon :closable="false" />
          <el-empty v-else-if="!parserResult" description="尚未调用 /api/protection/request-parser/preview；不会展示伪造解析结果" />
          <div v-if="parserResult" class="parser-summary-grid">
            <el-card class="metric-card"><div class="metric-card__label">方法 / URI</div><div class="metric-card__value is-primary">{{ parserResult.method || '--' }}</div><div class="metric-card__trend">{{ parserResult.normalizedUri || parserResult.normalizedURI || parserResult.rawUri || '--' }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">规范化路径</div><div class="metric-card__value is-success">{{ parserResult.normalizedPath || '--' }}</div><div class="metric-card__trend">Content-Type {{ parserResult.contentType || '--' }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">字段 / 解码</div><div class="metric-card__value is-warning">{{ parserResult.fields?.length ?? 0 }}</div><div class="metric-card__trend">decode steps {{ parserResult.decodeSteps?.length ?? 0 }}</div></el-card>
            <el-card class="metric-card"><div class="metric-card__label">检查策略</div><div class="metric-card__value" :class="parserResult.inspectionAllowed === false ? 'is-danger' : 'is-success'">{{ parserResult.inspectionAllowed === false ? '拒绝检查' : '允许检查' }}</div><div class="metric-card__trend">fail-open {{ parserResult.failOpen ? 'on' : 'off' }} / too-large {{ parserResult.bodyTooLarge ? 'yes' : 'no' }}</div></el-card>
          </div>
          <el-alert v-if="parserResult?.parseErrors?.length" type="warning" :closable="false" show-icon>
            <template #title>{{ parserResult.parseErrors.map(parserErrorText).join('；') }}</template>
          </el-alert>
          <el-tabs v-if="parserResult" class="parser-tabs" type="border-card">
            <el-tab-pane label="字段树">
              <el-table :data="parserResult.fields || []" size="small" empty-text="未解析到字段">
                <el-table-column prop="source" label="来源" width="105" />
                <el-table-column prop="variable" label="检测变量" min-width="150" />
                <el-table-column prop="rawValue" label="Raw" min-width="180" show-overflow-tooltip />
                <el-table-column prop="normalizedValue" label="Normalized" min-width="220" show-overflow-tooltip />
                <el-table-column label="Decode Steps" min-width="210"><template #default="{ row }: { row: RequestParserField }">{{ fieldDecodeText(row) }}</template></el-table-column>
              </el-table>
            </el-tab-pane>
            <el-tab-pane label="Query/Form"><pre class="request-code">{{ formatJson([...parserFieldsBySource('query'), ...parserFieldsBySource('form')]) }}</pre></el-tab-pane>
            <el-tab-pane label="JSON"><pre class="request-code">{{ formatJson(parserFieldsBySource('json')) }}</pre></el-tab-pane>
            <el-tab-pane label="Multipart"><pre class="request-code">{{ formatJson(parserFieldsBySource('multipart')) }}</pre></el-tab-pane>
            <el-tab-pane label="原始 JSON"><pre class="request-code">{{ formatJson(parserResult) }}</pre></el-tab-pane>
          </el-tabs>
          <pre v-else class="request-code">{{ formatJson(parserResult) }}</pre>
        </div>
      </div>
    </div>

    <div v-show="activeTab === 'ccbot'" class="page-stack">
      <div class="sl-card protection-panel" v-loading="ccPolicies.loading">
        <div class="sl-card-head"><span class="sl-card-title">CC / Bot 策略</span><el-button :icon="Refresh" @click="loadCCBot">刷新</el-button></div>
        <el-alert v-if="ccPolicies.error" type="error" :title="ccPolicies.error" show-icon :closable="false" />
        <el-table v-else :data="ccPolicies.items" empty-text="暂无真实 CC/Bot 策略">
          <template #empty>
            <el-empty description="暂无 CC/Bot 策略">
              <div class="table-subtext">新库会自动生成禁用模板；如仍为空，可到 CC 防护页新增限速、验证码、封禁策略。</div>
              <el-button type="primary" @click="goToCCProtection">去新增 / 启用策略</el-button>
            </el-empty>
          </template>
          <el-table-column prop="name" label="策略名称" min-width="160" />
          <el-table-column prop="scope" label="统计维度" width="150" />
          <el-table-column prop="windowSeconds" label="窗口(s)" width="90" />
          <el-table-column prop="threshold" label="阈值" width="80" />
          <el-table-column prop="action" label="动作链" min-width="160" />
          <el-table-column label="命中" width="90"><template #default="{ row }: { row: CCBotPolicy }">{{ row.hitsToday ?? '--' }}</template></el-table-column>
          <el-table-column label="状态" width="100"><template #default="{ row }: { row: CCBotPolicy }"><el-tag :type="statusTag(row.enabled)">{{ row.enabled === false ? '禁用' : '启用' }}</el-tag></template></el-table-column>
        </el-table>
      </div>
      <div class="sl-card protection-panel" v-loading="ccEvents.loading">
        <div class="sl-card-head"><span class="sl-card-title">最近 CC/Bot 命中</span><span class="page-hint">来自 /api/protection/cc-events</span></div>
        <el-alert v-if="ccEvents.error" type="error" :title="ccEvents.error" show-icon :closable="false" />
        <el-table v-else :data="ccEvents.items" empty-text="暂无真实 CC/Bot 命中事件">
          <el-table-column prop="time" label="时间" width="170" />
          <el-table-column prop="siteName" label="站点" min-width="120" />
          <el-table-column prop="sourceIp" label="源 IP" width="140" />
          <el-table-column prop="policyName" label="策略" min-width="150" />
          <el-table-column prop="scope" label="维度" width="120" />
          <el-table-column prop="action" label="处置" width="100" />
          <el-table-column label="计数/阈值" width="110"><template #default="{ row }: { row: CCBotEvent }">{{ row.count ?? 0 }}/{{ row.threshold ?? 0 }}</template></el-table-column>
        </el-table>
      </div>
    </div>

    <div v-show="activeTab === 'fingerprints'" class="sl-card protection-panel" v-loading="fingerprints.loading">
      <div class="sl-card-head"><span class="sl-card-title">语义指纹</span><el-button :icon="Refresh" @click="loadFingerprints">刷新</el-button></div>
      <el-alert v-if="fingerprints.error" type="error" :title="fingerprints.error" show-icon :closable="false" />
      <el-table v-else :data="fingerprints.items" empty-text="暂无真实语义指纹；API 失败不回退假数据">
        <template #empty>
          <el-empty description="暂无语义指纹">
            <div class="table-subtext">语义指纹不是手工模板；开启站点语义防护后，带 SQL/JS 等可解析攻击载荷的真实请求命中语义检测，系统才会自动学习生成。</div>
            <el-button @click="goToParserPreview">用请求解析示例查看可学习载荷</el-button>
          </el-empty>
        </template>
        <el-table-column prop="hash" label="Hash" min-width="180" />
        <el-table-column prop="language" label="语言" width="110" />
        <el-table-column prop="skeleton" label="攻击骨架" min-width="220" />
        <el-table-column prop="action" label="动作" width="100" />
        <el-table-column prop="status" label="状态" width="120" />
        <el-table-column prop="hits" label="命中" width="80" />
        <el-table-column prop="source" label="来源" width="130" />
        <el-table-column label="操作" width="100"><template #default="{ row }: { row: SemanticFingerprintSummary }"><el-button link type="primary" @click="openDetail('语义指纹详情', row)">详情</el-button></template></el-table-column>
      </el-table>
    </div>

    <div v-show="activeTab === 'traffic'" class="page-stack">
      <div class="dashboard-metric-grid" v-loading="trafficOverview.loading">
        <el-card class="metric-card"><div class="metric-card__label">总请求</div><div class="metric-card__value is-primary">{{ displayNumber(trafficOverview.data.totalRequests) }}</div></el-card>
        <el-card class="metric-card"><div class="metric-card__label">拦截</div><div class="metric-card__value is-danger">{{ displayNumber(trafficOverview.data.blockedRequests) }}</div></el-card>
        <el-card class="metric-card"><div class="metric-card__label">观察 / 验证</div><div class="metric-card__value is-warning">{{ displayNumber((trafficOverview.data.observedRequests ?? 0) + (trafficOverview.data.captchaRequests ?? 0)) }}</div></el-card>
        <el-card class="metric-card"><div class="metric-card__label">拦截率 / QPS</div><div class="metric-card__value is-success">{{ trafficOverview.data.blockRate ?? 0 }}%</div><div class="metric-card__trend">QPS {{ trafficOverview.data.qps ?? 0 }}</div></el-card>
      </div>
      <el-alert v-if="trafficOverview.error" type="error" :title="trafficOverview.error" show-icon :closable="false" />
      <div class="traffic-grid">
        <div class="sl-card protection-panel" v-loading="trafficTopIp.loading">
          <div class="sl-card-head"><span class="sl-card-title">Top IP</span></div>
          <el-alert v-if="trafficTopIp.error" type="error" :title="trafficTopIp.error" show-icon :closable="false" />
          <el-table v-else :data="trafficTopIp.items" empty-text="暂无真实 Top IP 数据"><el-table-column label="IP"><template #default="{ row }: { row: TrafficRankItem }">{{ rankLabel(row) }}</template></el-table-column><el-table-column label="次数" width="100"><template #default="{ row }: { row: TrafficRankItem }">{{ row.value ?? row.count ?? 0 }}</template></el-table-column><el-table-column label="下钻" width="90"><template #default="{ row }: { row: TrafficRankItem }"><el-button link type="primary" @click="drilldownTraffic('ip', row)">详情</el-button></template></el-table-column></el-table>
        </div>
        <div class="sl-card protection-panel" v-loading="trafficTopPath.loading">
          <div class="sl-card-head"><span class="sl-card-title">Top Path</span></div>
          <el-alert v-if="trafficTopPath.error" type="error" :title="trafficTopPath.error" show-icon :closable="false" />
          <el-table v-else :data="trafficTopPath.items" empty-text="暂无真实 Top Path 数据"><el-table-column label="Path"><template #default="{ row }: { row: TrafficRankItem }">{{ rankLabel(row) }}</template></el-table-column><el-table-column label="次数" width="100"><template #default="{ row }: { row: TrafficRankItem }">{{ row.value ?? row.count ?? 0 }}</template></el-table-column><el-table-column label="下钻" width="90"><template #default="{ row }: { row: TrafficRankItem }"><el-button link type="primary" @click="drilldownTraffic('path', row)">详情</el-button></template></el-table-column></el-table>
        </div>
        <div class="sl-card protection-panel" v-loading="trafficStatusCodes.loading">
          <div class="sl-card-head"><span class="sl-card-title">状态码分布</span></div>
          <el-alert v-if="trafficStatusCodes.error" type="error" :title="trafficStatusCodes.error" show-icon :closable="false" />
          <el-table v-else :data="trafficStatusCodes.items" empty-text="暂无真实状态码数据"><el-table-column label="状态码"><template #default="{ row }: { row: TrafficRankItem }">{{ rankLabel(row) }}</template></el-table-column><el-table-column label="次数" width="100"><template #default="{ row }: { row: TrafficRankItem }">{{ row.value ?? row.count ?? 0 }}</template></el-table-column><el-table-column label="下钻" width="90"><template #default="{ row }: { row: TrafficRankItem }"><el-button link type="primary" @click="drilldownTraffic('status', row)">详情</el-button></template></el-table-column></el-table>
        </div>
        <div class="sl-card protection-panel" v-loading="trafficSites.loading">
          <div class="sl-card-head"><span class="sl-card-title">站点分布</span></div>
          <el-alert v-if="trafficSites.error" type="error" :title="trafficSites.error" show-icon :closable="false" />
          <el-table v-else :data="trafficSites.items" empty-text="暂无真实站点统计"><el-table-column label="站点"><template #default="{ row }: { row: TrafficRankItem }">{{ rankLabel(row) }}</template></el-table-column><el-table-column label="次数" width="100"><template #default="{ row }: { row: TrafficRankItem }">{{ row.value ?? row.count ?? 0 }}</template></el-table-column><el-table-column label="下钻" width="90"><template #default="{ row }: { row: TrafficRankItem }"><el-button link type="primary" @click="drilldownTraffic('site', row)">详情</el-button></template></el-table-column></el-table>
        </div>
      </div>
      <div class="sl-card protection-panel" v-loading="attackEvents.loading || trafficTrend.loading">
        <div class="sl-card-head"><span class="sl-card-title">攻击事件解释入口</span><span class="page-hint">趋势点 {{ trafficTrend.total }}，事件 {{ attackEvents.total }}</span></div>
        <el-alert v-if="attackEvents.error || trafficTrend.error" type="error" :title="attackEvents.error || trafficTrend.error" show-icon :closable="false" />
        <el-table v-else :data="attackEvents.items" empty-text="暂无真实攻击事件">
          <el-table-column prop="time" label="时间" width="170" />
          <el-table-column prop="siteName" label="站点" min-width="120" />
          <el-table-column prop="sourceIp" label="源 IP" width="140" />
          <el-table-column prop="path" label="路径" min-width="180" />
          <el-table-column prop="attackType" label="类型" width="120" />
          <el-table-column prop="action" label="动作" width="90" />
          <el-table-column prop="ruleId" label="规则" width="120" />
          <el-table-column label="操作" width="100"><template #default="{ row }: { row: AttackEventSummary }"><el-button link type="primary" @click="openDetail('攻击事件详情', row)">详情</el-button></template></el-table-column>
        </el-table>
      </div>
    </div>

    <el-dialog v-model="ruleDialogVisible" :title="editingRuleId ? '编辑防护规则' : '新增自定义防护规则'" width="680px">
      <el-alert v-if="ruleError" type="error" :title="ruleError" show-icon :closable="false" />
      <el-form label-width="110px" class="rule-form">
        <el-form-item label="规则 ID"><el-input-number v-model="ruleForm.ruleId" :min="1" :step="1" /></el-form-item>
        <el-form-item label="名称"><el-input v-model="ruleForm.name" placeholder="SQLi probe" /></el-form-item>
        <el-form-item label="类别"><el-input v-model="ruleForm.category" placeholder="sqli / xss / custom" /></el-form-item>
        <el-form-item label="变量"><el-select v-model="ruleForm.variable"><el-option label="ARGS" value="ARGS" /><el-option label="REQUEST_URI" value="REQUEST_URI" /><el-option label="REQUEST_HEADERS" value="REQUEST_HEADERS" /><el-option label="REQUEST_METHOD" value="REQUEST_METHOD" /><el-option label="BODY/default" value="BODY" /></el-select></el-form-item>
        <el-form-item label="操作符"><el-select v-model="ruleForm.operator"><el-option label="@contains" value="@contains" /><el-option label="@streq" value="@streq" /><el-option label="@rx" value="@rx" /></el-select></el-form-item>
        <el-form-item label="匹配内容"><el-input v-model="ruleForm.pattern" placeholder="union select" /></el-form-item>
        <el-form-item label="处置"><el-select v-model="ruleForm.action"><el-option label="deny" value="deny" /><el-option label="log" value="log" /><el-option label="pass" value="pass" /></el-select></el-form-item>
        <el-form-item label="等级 / 分数"><div class="rule-inline"><el-select v-model="ruleForm.severity"><el-option label="critical" value="critical" /><el-option label="high" value="high" /><el-option label="medium" value="medium" /><el-option label="low" value="low" /><el-option label="info" value="info" /></el-select><el-input-number v-model="ruleForm.score" :min="1" :max="100" /></div></el-form-item>
        <el-form-item label="来源"><el-select v-model="ruleForm.source"><el-option label="custom" value="custom" /><el-option label="semantic" value="semantic" /><el-option label="system" value="system" /><el-option label="crs" value="crs" /></el-select></el-form-item>
        <el-form-item label="状态"><el-switch v-model="ruleForm.enabled" active-text="启用" inactive-text="禁用" /></el-form-item>
        <el-form-item label="描述"><el-input v-model="ruleForm.description" type="textarea" :rows="2" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="validateRuleForm">校验</el-button><el-button @click="ruleDialogVisible = false">取消</el-button><el-button type="primary" :loading="ruleSaving" @click="saveRule">保存并热更新</el-button></template>
    </el-dialog>

    <el-dialog v-model="whitelistDialogVisible" :title="editingWhitelistId ? '编辑白名单/例外' : '新增白名单/例外'" width="680px">
      <el-alert v-if="whitelistError" type="error" :title="whitelistError" show-icon :closable="false" />
      <el-form label-width="110px" class="rule-form">
        <el-form-item label="站点 ID"><el-input v-model="whitelistForm.siteId" placeholder="空或 0 表示全局" /></el-form-item>
        <el-form-item label="类型"><el-select v-model="whitelistForm.type"><el-option label="URL 白名单" value="url_whitelist" /><el-option label="参数白名单" value="param_whitelist" /><el-option label="IP 白名单" value="ip_whitelist" /><el-option label="CIDR 白名单" value="cidr_whitelist" /><el-option label="Header 白名单" value="header_whitelist" /><el-option label="Cookie 白名单" value="cookie_whitelist" /><el-option label="CRS Rule Exclusion" value="rule_disable" /></el-select></el-form-item>
        <el-form-item label="作用域"><el-select v-model="whitelistForm.scope"><el-option label="global" value="global" /><el-option label="site" value="site" /><el-option label="path" value="path" /><el-option label="ruleId" value="ruleid" /><el-option label="variable" value="variable" /></el-select></el-form-item>
        <el-form-item label="匹配值"><el-input v-model="whitelistForm.value" placeholder="/callback 或 token=abc 或 203.0.113.0/24 或 942100" /></el-form-item>
        <el-form-item label="规则 ID"><el-input v-model="whitelistForm.ruleId" placeholder="rule_disable 可填写 CRS ruleId" /></el-form-item>
        <el-form-item label="变量"><el-input v-model="whitelistForm.variable" placeholder="ARGS:q / REQUEST_HEADERS:User-Agent" /></el-form-item>
        <el-form-item label="过期时间"><el-date-picker v-model="whitelistForm.expiresAt" type="datetime" value-format="YYYY-MM-DD HH:mm:ss" placeholder="可选" /></el-form-item>
        <el-form-item label="状态"><el-select v-model="whitelistForm.status"><el-option label="启用" value="enabled" /><el-option label="禁用" value="disabled" /></el-select></el-form-item>
        <el-form-item label="原因"><el-input v-model="whitelistForm.description" type="textarea" :rows="2" placeholder="误报原因 / 变更单号" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="whitelistDialogVisible = false">取消</el-button><el-button type="primary" :loading="whitelistSaving" @click="saveWhitelist">保存并热更新</el-button></template>
    </el-dialog>

    <el-drawer v-model="detailPayload" :title="detailTitle" size="46%">
      <pre v-if="detailPayload" class="request-code">{{ formatJson(detailPayload) }}</pre>
    </el-drawer>
  </section>
</template>
