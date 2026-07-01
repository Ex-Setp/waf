<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'
import { computed, onMounted } from 'vue'

import type { DashboardMetric, PipelineStageMetric, RecentSecurityEvent, SystemStatus } from '@/api/dashboard'
import { useDashboardStore } from '@/stores/dashboard'

const dashboard = useDashboardStore()

const loadedAtText = computed(() => (dashboard.loadedAt ? dashboard.loadedAt.toLocaleTimeString() : '--'))
const maxTrendValue = computed(() =>
  Math.max(1, ...dashboard.attackTrend.map((item) => item.requests), ...dashboard.attackTrend.map((item) => item.blocked)),
)

onMounted(() => {
  void dashboard.loadOverview()
})

function metricType(status: DashboardMetric['status']): 'success' | 'warning' | 'danger' | 'primary' {
  return status
}

function healthType(health?: SystemStatus['health']): 'success' | 'warning' | 'danger' | 'info' {
  if (health === 'ok') return 'success'
  if (health === 'degraded') return 'warning'
  if (health === 'down') return 'danger'
  return 'info'
}

function healthText(health?: SystemStatus['health']): string {
  const map: Record<SystemStatus['health'], string> = {
    ok: '正常',
    degraded: '降级',
    down: '异常',
  }
  return health ? map[health] : '--'
}

function stageType(enabled: boolean): 'success' | 'info' {
  return enabled ? 'success' : 'info'
}

function actionType(action: RecentSecurityEvent['action']): 'success' | 'danger' | 'warning' {
  return action === 'allow' ? 'success' : action === 'block' ? 'danger' : 'warning'
}

function actionText(action: RecentSecurityEvent['action']): string {
  const map: Record<RecentSecurityEvent['action'], string> = {
    allow: '放行',
    block: '拦截',
    observe: '观察',
  }
  return map[action]
}

function eventTypeTagType(type?: string): 'danger' | 'warning' | 'info' {
  const normalized = String(type ?? '').toLowerCase()
  if (normalized.startsWith('semantic-')) return 'danger'
  if (normalized.includes('sql') || normalized.includes('xss')) return 'warning'
  if (normalized.includes('rce') || normalized.includes('ssrf')) return 'danger'
  return 'info'
}

function formatMetric(metric: DashboardMetric): string {
  return `${metric.value.toLocaleString()}${metric.unit ?? ''}`
}

function trendText(metric: DashboardMetric): string {
  if (metric.trend == null) return '暂无趋势'
  const prefix = metric.trend >= 0 ? '+' : ''
  return `${prefix}${metric.trend}%`
}

function barHeight(value: number): string {
  return `${Math.max(8, Math.round((value / maxTrendValue.value) * 118))}px`
}

function formatNumber(value: number): string {
  return value.toLocaleString()
}

function display(value?: string | number | null): string {
  if (value == null || value === '') return '--'
  return String(value)
}
</script>

<template>
  <section class="page-stack dashboard-console" v-loading="dashboard.loading">
    <div class="sl-card dashboard-status-card">
      <div class="dashboard-status-main">
        <div>
          <div class="sl-card-title">总览</div>
          <div class="table-subtext">基于真实 /api/dashboard/overview 返回数据展示，不使用前端 mock 排行。</div>
        </div>
        <div class="status-card__actions">
          <el-tag :type="healthType(dashboard.status?.health)" effect="light">{{ healthText(dashboard.status?.health) }}</el-tag>
          <span class="dashboard-updated">更新：{{ loadedAtText }}</span>
          <el-button :icon="Refresh" :loading="dashboard.loading" @click="dashboard.loadOverview()">刷新</el-button>
        </div>
      </div>
      <div class="dashboard-status-meta">
        <span>服务：{{ display(dashboard.status?.service) }}</span>
        <span>版本：{{ display(dashboard.status?.version) }}</span>
        <span>模式：{{ display(dashboard.status?.mode) }}</span>
        <span>运行：{{ display(dashboard.status?.uptime) }}</span>
      </div>
    </div>

    <el-alert
      v-if="dashboard.error"
      type="error"
      :closable="false"
      show-icon
      title="总览接口不可用"
      :description="`${dashboard.error}。当前页面不使用前端 Mock 数据，请接入 /api/dashboard/overview 后重试。`"
    />

    <div class="dashboard-metric-grid">
      <el-card v-for="metric in dashboard.metrics" :key="metric.key" class="metric-card">
        <div class="metric-card__label">{{ metric.label }}</div>
        <div class="metric-card__value" :class="`is-${metric.status}`">{{ formatMetric(metric) }}</div>
        <div class="metric-card__trend">
          <el-tag size="small" :type="metricType(metric.status)">{{ trendText(metric) }}</el-tag>
        </div>
      </el-card>
    </div>

    <div class="dashboard-grid-two">
      <div class="sl-card dashboard-panel">
        <div class="sl-card-head">
          <span class="sl-card-title">检测流水线</span>
          <span class="table-subtext">QPS / P95 / 拦截 / 错误率</span>
        </div>
        <el-table :data="dashboard.pipeline" empty-text="暂无真实流水线数据">
          <el-table-column prop="label" label="阶段" min-width="170" />
          <el-table-column label="状态" width="90">
            <template #default="{ row }: { row: PipelineStageMetric }">
              <el-tag :type="stageType(row.enabled)">{{ row.enabled ? '启用' : '停用' }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="QPS" width="90" align="right">
            <template #default="{ row }: { row: PipelineStageMetric }">{{ formatNumber(row.qps) }}</template>
          </el-table-column>
          <el-table-column label="P95" width="92" align="right">
            <template #default="{ row }: { row: PipelineStageMetric }">{{ row.p95Ms }} ms</template>
          </el-table-column>
          <el-table-column label="拦截" width="92" align="right">
            <template #default="{ row }: { row: PipelineStageMetric }">{{ formatNumber(row.blocked) }}</template>
          </el-table-column>
          <el-table-column label="错误率" width="92" align="right">
            <template #default="{ row }: { row: PipelineStageMetric }">{{ row.errorRate }}%</template>
          </el-table-column>
        </el-table>
      </div>

      <div class="sl-card dashboard-panel">
        <div class="sl-card-head">
          <span class="sl-card-title">今日趋势</span>
          <span class="table-subtext">请求 / 拦截</span>
        </div>
        <div v-if="dashboard.attackTrend.length > 0" class="dashboard-bars">
          <div v-for="point in dashboard.attackTrend" :key="point.time" class="dashboard-bar-group">
            <div class="dashboard-bar-pair">
              <span class="dashboard-bar is-request" :style="{ height: barHeight(point.requests) }"></span>
              <span class="dashboard-bar is-blocked" :style="{ height: barHeight(point.blocked) }"></span>
            </div>
            <span class="dashboard-bar-label">{{ point.time }}</span>
          </div>
        </div>
        <el-empty v-else description="暂无真实趋势数据" />
      </div>
    </div>

    <div class="sl-card dashboard-panel">
      <div class="sl-card-head">
        <span class="sl-card-title">最近安全事件</span>
        <span class="table-subtext">仅展示后端返回事件</span>
      </div>
      <el-table :data="dashboard.recentEvents" empty-text="暂无真实安全事件">
        <el-table-column prop="time" label="时间" width="150" />
        <el-table-column prop="sourceIp" label="来源 IP" width="150">
          <template #default="{ row }: { row: RecentSecurityEvent }"><code>{{ display(row.sourceIp) }}</code></template>
        </el-table-column>
        <el-table-column prop="path" label="路径" min-width="240" show-overflow-tooltip />
        <el-table-column prop="type" label="类型" width="170">
          <template #default="{ row }: { row: RecentSecurityEvent }">
            <el-tag :type="eventTypeTagType(row.type)" effect="plain">{{ display(row.type) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="动作" width="100">
          <template #default="{ row }: { row: RecentSecurityEvent }">
            <el-tag :type="actionType(row.action)">{{ actionText(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="stage" label="阶段" width="130" />
      </el-table>
    </div>
  </section>
</template>
