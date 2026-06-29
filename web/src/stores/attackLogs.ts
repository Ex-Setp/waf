import { defineStore } from 'pinia'
import { ref } from 'vue'

import {
  exportAttackLogs,
  fetchAttackLogs,
  type AttackAction,
  type AttackLogEntry,
  type AttackLogQuery,
  type AttackLogSummary,
  type AttackSeverity,
} from '@/api/attackLogs'

const emptySummary: AttackLogSummary = {
  total: 0,
  blocked: 0,
  observed: 0,
  critical: 0,
}

const defaultQuery: AttackLogQuery = {
  keyword: '',
  startTime: '',
  endTime: '',
  site: '',
  siteName: '',
  attackType: '',
  action: '',
  sourceIp: '',
  ip: '',
  path: '',
  severity: '',
  stage: '',
  page: 1,
  pageSize: 10,
}

export type AttackLogFilters = Partial<Omit<AttackLogQuery, 'page' | 'pageSize'>> & {
  action?: AttackAction | ''
  severity?: AttackSeverity
}

export const useAttackLogsStore = defineStore('attackLogs', () => {
  const logs = ref<AttackLogEntry[]>([])
  const summary = ref<AttackLogSummary>({ ...emptySummary })
  const loading = ref(false)
  const exporting = ref(false)
  const error = ref('')
  const total = ref(0)
  const query = ref<AttackLogQuery>({ ...defaultQuery })

  async function loadLogs(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetchAttackLogs(query.value)
      logs.value = data.logs ?? []
      summary.value = data.summary ?? { ...emptySummary }
      total.value = data.total ?? logs.value.length
    } catch (err) {
      logs.value = []
      summary.value = { ...emptySummary }
      total.value = 0
      error.value = err instanceof Error ? err.message : '攻击事件加载失败'
    } finally {
      loading.value = false
    }
  }

  function setFilters(filters: AttackLogFilters): void {
    query.value = {
      ...query.value,
      ...filters,
      page: 1,
    }
  }

  function resetFilters(): void {
    query.value = {
      ...defaultQuery,
      pageSize: query.value.pageSize,
    }
  }

  function setPage(page: number): void {
    query.value.page = page
  }

  function setPageSize(pageSize: number): void {
    query.value.pageSize = pageSize
    query.value.page = 1
  }

  async function exportLogs(): Promise<Blob> {
    exporting.value = true
    try {
      return await exportAttackLogs(query.value)
    } finally {
      exporting.value = false
    }
  }

  return {
    error,
    exportLogs,
    exporting,
    loadLogs,
    loading,
    logs,
    query,
    resetFilters,
    setFilters,
    setPage,
    setPageSize,
    summary,
    total,
  }
})
