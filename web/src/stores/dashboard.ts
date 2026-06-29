import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import { fetchDashboardOverview, type DashboardOverview } from '@/api/dashboard'

export const useDashboardStore = defineStore('dashboard', () => {
  const overview = ref<DashboardOverview | null>(null)
  const loading = ref(false)
  const loadedAt = ref<Date | null>(null)
  const error = ref('')

  const metrics = computed(() => overview.value?.metrics ?? [])
  const pipeline = computed(() => overview.value?.pipeline ?? [])
  const attackTrend = computed(() => overview.value?.attackTrend ?? [])
  const recentEvents = computed(() => overview.value?.recentEvents ?? [])
  const status = computed(() => overview.value?.status ?? null)

  async function loadOverview(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      overview.value = await fetchDashboardOverview()
      loadedAt.value = new Date()
    } catch (err) {
      overview.value = null
      loadedAt.value = null
      error.value = err instanceof Error ? err.message : '总览数据加载失败'
    } finally {
      loading.value = false
    }
  }

  return {
    attackTrend,
    error,
    loadedAt,
    loading,
    loadOverview,
    metrics,
    overview,
    pipeline,
    recentEvents,
    status,
  }
})
