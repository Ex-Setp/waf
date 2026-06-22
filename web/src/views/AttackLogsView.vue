<script setup lang="ts">
import { Download, Link, Refresh, Search } from '@element-plus/icons-vue'
import { ElMessage } from 'element-plus'
import { computed, onMounted, reactive, ref } from 'vue'

import { applyWhitelistSuggestion, fetchWhitelistSuggestions, type WhitelistSuggestion } from '@/api/attackLogs'
import type { AttackAction, AttackExplanation, AttackLogEntry, AttackSeverity, OperatorSuggestion, RequestParserLoggedExplanation, RequestParserLoggedSnippet, ScoreBreakdown } from '@/api/attackLogs'
import { useAttackLogsStore } from '@/stores/attackLogs'

interface AttackLogFilters {
  timeRange: [string, string] | []
  site: string
  attackType: string
  action: AttackAction | ''
  sourceIp: string
  path: string
  severity: AttackSeverity
  stage: string
  keyword: string
}

const attackLogsStore = useAttackLogsStore()
const detailVisible = ref(false)
const currentLog = ref<AttackLogEntry | null>(null)
const whitelistLoading = ref(false)
const whitelistSuggestions = ref<WhitelistSuggestion[]>([])
const filters = reactive<AttackLogFilters>({
  timeRange: [],
  site: '',
  attackType: '',
  action: '',
  sourceIp: '',
  path: '',
  severity: '',
  stage: '',
  keyword: '',
})

const requestHeaders = computed(() => [])
const requestParams = computed(() => [])
const currentScoreBreakdown = computed(() => parseScoreBreakdown(currentLog.value?.scoreBreakdown))
const currentParserExplanation = computed(() => parseParserExplanation(currentLog.value?.payloadSnippet))
const currentExplanation = computed(() => parseExplanation(currentLog.value?.explanationJson))
const currentOperatorSuggestions = computed(() => parseOperatorSuggestions(currentLog.value?.operatorSuggestion))

onMounted(() => {
  void attackLogsStore.loadLogs()
})

function applyFilters(): void {
  const [startTime, endTime] = filters.timeRange
  attackLogsStore.setFilters({
    keyword: filters.keyword.trim(),
    startTime: startTime ?? '',
    endTime: endTime ?? '',
    site: filters.site.trim(),
    siteName: filters.site.trim(),
    attackType: filters.attackType.trim(),
    action: filters.action,
    sourceIp: filters.sourceIp.trim(),
    ip: filters.sourceIp.trim(),
    path: filters.path.trim(),
    severity: filters.severity,
    stage: filters.stage.trim(),
  })
  void attackLogsStore.loadLogs()
}

function resetFilters(): void {
  filters.timeRange = []
  filters.site = ''
  filters.attackType = ''
  filters.action = ''
  filters.sourceIp = ''
  filters.path = ''
  filters.severity = ''
  filters.stage = ''
  filters.keyword = ''
  attackLogsStore.resetFilters()
  void attackLogsStore.loadLogs()
}

function handlePageChange(page: number): void {
  attackLogsStore.setPage(page)
  void attackLogsStore.loadLogs()
}

function handlePageSizeChange(pageSize: number): void {
  attackLogsStore.setPageSize(pageSize)
  void attackLogsStore.loadLogs()
}

async function openDetail(row: AttackLogEntry): Promise<void> {
  currentLog.value = row
  detailVisible.value = true
  whitelistSuggestions.value = []
  whitelistLoading.value = true
  try {
    const data = await fetchWhitelistSuggestions(row.id)
    whitelistSuggestions.value = data.suggestions ?? []
  } catch {
    whitelistSuggestions.value = []
  } finally {
    whitelistLoading.value = false
  }
}

async function handleApplyWhitelist(suggestion: WhitelistSuggestion): Promise<void> {
  if (!currentLog.value) return
  whitelistLoading.value = true
  try {
    await applyWhitelistSuggestion(currentLog.value.id, suggestion)
    ElMessage.success('已生成白名单/例外规则，并写入审计日志')
    const data = await fetchWhitelistSuggestions(currentLog.value.id)
    whitelistSuggestions.value = data.suggestions ?? []
  } catch (error) {
    ElMessage.error(error instanceof Error ? error.message : '生成白名单失败')
  } finally {
    whitelistLoading.value = false
  }
}

async function handleExport(): Promise<void> {
  try {
    const blob = await attackLogsStore.exportLogs()
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `aegis-waf-attack-logs-${Date.now()}.csv`
    link.click()
    URL.revokeObjectURL(url)
    ElMessage.success('攻击事件已导出')
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '导出失败')
  }
}

function actionType(action: AttackAction): 'success' | 'danger' | 'warning' {
  return action === 'allow' ? 'success' : action === 'block' ? 'danger' : 'warning'
}

function actionText(action: AttackAction | string): string {
  const map: Record<string, string> = { allow: '放行', block: '已拦截', observe: '观察', captcha: '人机验证' }
  return map[action] ?? (action || '--')
}

function parseScoreBreakdown(value?: string): ScoreBreakdown | null {
  if (!value) return null
  try {
    const parsed = JSON.parse(value) as Partial<ScoreBreakdown>
    if (!parsed || typeof parsed !== 'object') return null
    return {
      totalScore: Number(parsed.totalScore ?? 0),
      threshold: Number(parsed.threshold ?? 0),
      rules: Array.isArray(parsed.rules)
        ? parsed.rules.map((rule) => ({
            id: String(rule?.id ?? ''),
            group: String(rule?.group ?? ''),
            score: Number(rule?.score ?? 0),
          }))
        : [],
    }
  } catch {
    return null
  }
}

function parseParserExplanation(value?: string): RequestParserLoggedExplanation | null {
  if (!value) return null
  try {
    const parsed = JSON.parse(value) as RequestParserLoggedSnippet
    return parsed.normalizedRequest ?? null
  } catch {
    return null
  }
}

function parseExplanation(value?: string): AttackExplanation | null {
  if (!value) return null
  try {
    const parsed = JSON.parse(value) as AttackExplanation
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

function parseOperatorSuggestions(value?: string): OperatorSuggestion[] {
  if (!value) return []
  try {
    const parsed = JSON.parse(value) as OperatorSuggestion[]
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function suggestionRoute(action: string): string {
  const map: Record<string, string> = {
    create_whitelist: '/protection-config?tab=whitelist',
    open_site_policy: '/protection-config?tab=site-policy',
    open_rule_group: '/protection-config?tab=rules',
    open_cc_bot: '/cc-protection',
    open_semantic_fingerprint: '/fingerprints',
  }
  return map[action] ?? '/protection-config'
}

function formatDecodeSteps(steps?: string[]): string {
  return steps && steps.length > 0 ? steps.join(' → ') : '无解码步骤'
}

function severityType(severity: AttackSeverity): 'info' | 'warning' | 'danger' {
  return severity === 'low' ? 'info' : severity === 'medium' ? 'warning' : 'danger'
}

function severityText(severity: AttackSeverity): string {
  const map: Record<string, string> = { low: '低危', medium: '中危', high: '高危', critical: '严重' }
  return map[severity] ?? '--'
}

function ruleTypeText(type: string): string {
  const map: Record<string, string> = {
    ip_whitelist: 'IP 白名单',
    url_whitelist: 'URL 白名单',
    param_whitelist: '参数白名单',
    rule_disable: '禁用规则',
  }
  return map[type] ?? type
}

function display(value: string | number | undefined | null): string | number {
  if (value === undefined || value === null || value === '') return '--'
  return value
}
</script>

<template>
  <section class="page-stack attack-logs-page" v-loading="attackLogsStore.loading">
    <el-alert
      v-if="attackLogsStore.error"
      type="error"
      :closable="false"
      show-icon
      :title="attackLogsStore.error"
    />

    <div class="sl-stat-grid attack-stat-grid">
      <div class="sl-stat-card is-two">
        <div class="sl-stat-item">
          <div class="sl-stat-label"><span class="sl-stat-icon">Σ</span>事件总数</div>
          <div class="sl-stat-value">{{ attackLogsStore.summary.total }}</div>
        </div>
        <div class="sl-stat-item">
          <div class="sl-stat-label"><span class="sl-stat-icon is-danger">!</span>已拦截</div>
          <div class="sl-stat-value is-danger">{{ attackLogsStore.summary.blocked }}</div>
        </div>
      </div>
      <div class="sl-stat-card is-two">
        <div class="sl-stat-item">
          <div class="sl-stat-label"><span class="sl-stat-icon is-warn">◎</span>观察</div>
          <div class="sl-stat-value is-warning">{{ attackLogsStore.summary.observed }}</div>
        </div>
        <div class="sl-stat-item">
          <div class="sl-stat-label"><span class="sl-stat-icon is-danger">H</span>严重</div>
          <div class="sl-stat-value is-danger">{{ attackLogsStore.summary.critical }}</div>
        </div>
      </div>
    </div>

    <div class="sl-card attack-filter-card">
      <div class="sl-card-head">
        <span class="sl-card-title">攻击事件</span>
        <div class="attack-actions">
          <el-button :icon="Refresh" @click="attackLogsStore.loadLogs()">刷新</el-button>
          <el-button :icon="Download" :loading="attackLogsStore.exporting" @click="handleExport">导出</el-button>
        </div>
      </div>
      <el-form class="filter-form attack-filter-form" inline>
        <el-form-item label="时间">
          <el-date-picker
            v-model="filters.timeRange"
            type="datetimerange"
            value-format="YYYY-MM-DD HH:mm:ss"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            style="width: 330px"
          />
        </el-form-item>
        <el-form-item label="站点">
          <el-input v-model="filters.site" clearable placeholder="站点名称" style="width: 150px" @keyup.enter="applyFilters" />
        </el-form-item>
        <el-form-item label="攻击类型">
          <el-input v-model="filters.attackType" clearable placeholder="SQL / XSS" style="width: 150px" @keyup.enter="applyFilters" />
        </el-form-item>
        <el-form-item label="动作">
          <el-select v-model="filters.action" clearable placeholder="全部" style="width: 116px">
            <el-option label="放行" value="allow" />
            <el-option label="已拦截" value="block" />
            <el-option label="观察" value="observe" />
            <el-option label="人机验证" value="captcha" />
          </el-select>
        </el-form-item>
        <el-form-item label="攻击 IP">
          <el-input v-model="filters.sourceIp" clearable placeholder="来源 IP" style="width: 150px" @keyup.enter="applyFilters" />
        </el-form-item>
        <el-form-item label="路径">
          <el-input v-model="filters.path" clearable placeholder="请求路径" style="width: 180px" @keyup.enter="applyFilters" />
        </el-form-item>
        <el-form-item label="风险">
          <el-select v-model="filters.severity" clearable placeholder="全部" style="width: 116px">
            <el-option label="低危" value="low" />
            <el-option label="中危" value="medium" />
            <el-option label="高危" value="high" />
            <el-option label="严重" value="critical" />
          </el-select>
        </el-form-item>
        <el-form-item label="阶段">
          <el-input v-model="filters.stage" clearable placeholder="检测阶段" style="width: 130px" @keyup.enter="applyFilters" />
        </el-form-item>
        <el-form-item label="关键字">
          <el-input
            v-model="filters.keyword"
            clearable
            placeholder="IP / 路径 / 规则 / 类型"
            :prefix-icon="Search"
            style="width: 220px"
            @keyup.enter="applyFilters"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="applyFilters">查询</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </el-form-item>
      </el-form>

      <el-table :data="attackLogsStore.logs" empty-text="暂无真实攻击事件">
        <el-table-column prop="time" label="时间" width="168" />
        <el-table-column prop="siteName" label="防护应用" width="150">
          <template #default="{ row }: { row: AttackLogEntry }">{{ display(row.siteName) }}</template>
        </el-table-column>
        <el-table-column prop="sourceIp" label="攻击 IP" width="145">
          <template #default="{ row }: { row: AttackLogEntry }"><code>{{ display(row.sourceIp) }}</code></template>
        </el-table-column>
        <el-table-column label="请求路径" min-width="260" show-overflow-tooltip>
          <template #default="{ row }: { row: AttackLogEntry }">
            <el-tag size="small" type="info">{{ display(row.method) }}</el-tag>
            <span class="request-path">{{ display(row.path) }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="attackType" label="攻击类型" width="145">
          <template #default="{ row }: { row: AttackLogEntry }"><el-tag type="warning">{{ display(row.attackType) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="风险" width="92">
          <template #default="{ row }: { row: AttackLogEntry }"><el-tag :type="severityType(row.severity)">{{ severityText(row.severity) }}</el-tag></template>
        </el-table-column>
        <el-table-column label="动作" width="104">
          <template #default="{ row }: { row: AttackLogEntry }"><el-tag :type="actionType(row.action)">{{ actionText(row.action) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="ruleId" label="规则 ID" width="120">
          <template #default="{ row }: { row: AttackLogEntry }">{{ display(row.ruleId) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="92" fixed="right">
          <template #default="{ row }: { row: AttackLogEntry }"><el-button link type="primary" @click="openDetail(row)">详情</el-button></template>
        </el-table-column>
      </el-table>
      <div class="table-pagination">
        <el-pagination
          background
          layout="total, sizes, prev, pager, next"
          :current-page="attackLogsStore.query.page"
          :page-size="attackLogsStore.query.pageSize"
          :page-sizes="[10, 20, 50]"
          :total="attackLogsStore.total"
          @current-change="handlePageChange"
          @size-change="handlePageSizeChange"
        />
      </div>
    </div>

    <el-drawer v-model="detailVisible" size="820px" title="攻击事件详情" destroy-on-close>
      <div v-if="currentLog" class="attack-detail-panel">
        <div class="attack-summary">
          <div class="deny-stamp">{{ actionText(currentLog.action) }}</div>
          <div>
            <el-tag type="warning">{{ display(currentLog.attackType) }}</el-tag>
            <span class="attack-url">{{ display(currentLog.method) }} {{ display(currentLog.path) }}</span>
          </div>
          <dl class="attack-fields">
            <dt>攻击 IP</dt><dd>{{ display(currentLog.sourceIp) }}</dd>
            <dt>防护应用</dt><dd>{{ display(currentLog.siteName) }}</dd>
            <dt>攻击载荷</dt><dd><code class="payload-snippet">{{ display(currentLog.payloadSnippet) }}</code></dd>
            <dt>检测模块</dt><dd>{{ display(currentLog.stage) }}</dd>
            <dt>规则 ID</dt><dd>{{ display(currentLog.ruleId) }}</dd>
            <dt>规则说明</dt><dd>{{ display(currentLog.ruleMessage) }}</dd>
            <dt>风险分数</dt><dd>{{ display(currentLog.score) }}</dd>
            <dt>最终动作</dt><dd>{{ actionText(currentLog.finalAction || currentLog.action) }}</dd>
            <dt>异常总分</dt><dd>{{ display(currentScoreBreakdown?.totalScore) }}</dd>
            <dt>异常阈值</dt><dd>{{ display(currentScoreBreakdown?.threshold) }}</dd>
            <dt>响应状态</dt><dd>{{ display(currentLog.statusCode) }}</dd>
            <dt>处理耗时</dt><dd>{{ display(currentLog.latencyMs) }} ms</dd>
            <dt>时间</dt><dd>{{ display(currentLog.time) }}</dd>
            <dt>事件 ID</dt><dd>{{ display(currentLog.id) }}</dd>
          </dl>
          <div class="score-rule-list">
            <div class="score-rule-title">异常评分规则</div>
            <el-empty v-if="!currentScoreBreakdown || currentScoreBreakdown.rules.length === 0" description="暂无异常评分明细" />
            <div v-else class="score-rule-items">
              <div v-for="rule in currentScoreBreakdown.rules" :key="`${rule.group}:${rule.id}`" class="score-rule-item">
                <span>{{ display(rule.group) }}</span>
                <code>{{ display(rule.id) }}</code>
                <strong>{{ display(rule.score) }}</strong>
              </div>
            </div>
          </div>
        </div>
        <div class="request-box">
          <div class="request-tabs"><span class="active">请求头</span><span>请求参数</span><el-tag>真实日志字段</el-tag></div>
          <div class="detail-empty" v-if="requestHeaders.length === 0">后端当前未提供请求头字段：--</div>
          <div class="detail-empty" v-if="requestParams.length === 0">后端当前未提供请求参数字段：--</div>
          <pre class="request-code">{{ display(currentLog.payloadSnippet) }}</pre>
        </div>
        <div class="request-box">
          <div class="request-tabs"><span class="active">请求解析解释</span><el-tag>normalizedRequest</el-tag></div>
          <el-empty v-if="!currentParserExplanation" description="该事件暂无规范化解释字段" />
          <div v-else class="parser-log-panel">
            <dl class="attack-fields">
              <dt>Matched Variable</dt><dd><code>{{ display(currentParserExplanation.matchedVariable) }}</code></dd>
              <dt>Normalized Path</dt><dd>{{ display(currentParserExplanation.normalizedPath) }}</dd>
            </dl>
            <el-alert v-if="currentParserExplanation.parseErrors?.length" type="warning" :closable="false" :title="currentParserExplanation.parseErrors.join('；')" />
            <el-table :data="currentParserExplanation.fields || []" size="small" empty-text="暂无字段解释">
              <el-table-column prop="source" label="来源" width="105" />
              <el-table-column prop="variable" label="变量" min-width="140" />
              <el-table-column prop="rawValue" label="Raw" min-width="160" show-overflow-tooltip />
              <el-table-column prop="normalizedValue" label="Normalized" min-width="190" show-overflow-tooltip />
              <el-table-column label="Decode Steps" min-width="190"><template #default="{ row }">{{ formatDecodeSteps(row.decodeSteps) }}</template></el-table-column>
            </el-table>
          </div>
        </div>

        <div class="request-box">
          <div class="request-tabs"><span class="active">命中时间线 / 决策解释</span><el-tag type="success">explanation JSON</el-tag></div>
          <el-empty v-if="!currentExplanation" description="该事件暂无 explanation JSON" />
          <div v-else class="explanation-panel">
            <dl class="attack-fields">
              <dt>站点策略</dt><dd>{{ display(String(currentExplanation.sitePolicy?.policyMode ?? '--')) }}</dd>
              <dt>规则组</dt><dd>{{ display(Array.isArray(currentExplanation.sitePolicy?.ruleGroups) ? currentExplanation.sitePolicy?.ruleGroups.join(', ') : '--') }}</dd>
              <dt>白名单决策</dt><dd>{{ display(String(currentExplanation.whitelistDecision?.status ?? '--')) }}</dd>
              <dt>CC/Bot 决策</dt><dd>{{ display(String(currentExplanation.ccBotDecision?.status ?? '--')) }}</dd>
              <dt>语义决策</dt><dd>{{ display(String(currentExplanation.semanticDecision?.status ?? '--')) }}</dd>
              <dt>最终动作</dt><dd>{{ actionText(currentExplanation.finalAction || currentLog.finalAction || currentLog.action) }}</dd>
            </dl>
            <el-timeline>
              <el-timeline-item timestamp="site-policy">{{ currentExplanation.sitePolicy?.siteName || currentLog.siteName || 'global' }}</el-timeline-item>
              <el-timeline-item v-for="rule in currentExplanation.matchedRules || []" :key="`${rule.source}:${rule.id}`" timestamp="matched-rule">
                {{ display(String(rule.group ?? '--')) }} / {{ display(String(rule.source ?? '--')) }} / score {{ display(Number(rule.score ?? 0)) }}
              </el-timeline-item>
              <el-timeline-item timestamp="final-action">{{ actionText(currentExplanation.finalAction || currentLog.finalAction || currentLog.action) }}</el-timeline-item>
            </el-timeline>
          </div>
        </div>
        <div class="request-box">
          <div class="request-tabs"><span class="active">运营建议</span><el-tag type="warning">operatorSuggestion</el-tag></div>
          <el-empty v-if="currentOperatorSuggestions.length === 0" description="暂无运营建议" />
          <div v-else class="whitelist-suggestion-list">
            <div v-for="item in currentOperatorSuggestions" :key="`${item.type}:${item.target}:${item.action}`" class="whitelist-suggestion-item">
              <div>
                <strong>{{ item.title }}</strong>
                <code>{{ item.target }}</code>
                <p>{{ item.reason }}</p>
              </div>
              <el-button :icon="Link" size="small" tag="a" :href="suggestionRoute(item.action)">跳转处理</el-button>
            </div>
          </div>
        </div>
        <div class="request-box">
          <div class="request-tabs"><span class="active">生成白名单/例外</span><el-tag type="success">真实规则</el-tag></div>
          <el-skeleton v-if="whitelistLoading" :rows="3" animated />
          <el-empty v-else-if="whitelistSuggestions.length === 0" description="暂无可生成的白名单建议" />
          <div v-else class="whitelist-suggestion-list">
            <div v-for="item in whitelistSuggestions" :key="`${item.type}:${item.value}`" class="whitelist-suggestion-item">
              <div>
                <strong>{{ ruleTypeText(item.type) }}</strong>
                <code>{{ item.value }}</code>
                <p>{{ item.description }}</p>
              </div>
              <el-button type="primary" size="small" @click="handleApplyWhitelist(item)">生成规则</el-button>
            </div>
          </div>
        </div>
      </div>
    </el-drawer>
  </section>
</template>

<style scoped>
.score-rule-list { margin-top: 16px; }
.score-rule-title { margin-bottom: 8px; color: var(--el-text-color-secondary); font-size: 12px; }
.score-rule-items { display: grid; gap: 8px; }
.score-rule-item { display: grid; grid-template-columns: 1fr 1fr auto; align-items: center; gap: 10px; padding: 8px 10px; border: 1px solid var(--el-border-color-light); border-radius: 6px; }
.score-rule-item code { color: var(--el-color-primary); }
.whitelist-suggestion-list { display: grid; gap: 10px; }
.whitelist-suggestion-item { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 12px; border: 1px solid var(--el-border-color-light); border-radius: 8px; background: rgba(255,255,255,0.03); }
.whitelist-suggestion-item code { display: inline-block; margin-left: 8px; color: var(--el-color-primary); }
.whitelist-suggestion-item p { margin: 6px 0 0; color: var(--el-text-color-secondary); font-size: 12px; }
.explanation-panel { display: grid; gap: 12px; }
</style>
