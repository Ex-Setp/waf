import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import {
  createSite,
  deleteSite as deleteSiteApi,
  fetchSites,
  fetchSiteRuntimeStatus,
  fetchSystemListeners,
  updateSite,
  type ListenerListResponse,
  type ProtectedSite,
  type SiteFormModel,
  type SiteRuntimeStatus,
  type SiteSummary,
} from '@/api/sites'

const emptySummary: SiteSummary = {
  total: 0,
  enabled: 0,
  protectedDomains: 0,
  blockedToday: 0,
}

function cloneSummary(summary: SiteSummary): SiteSummary {
  return {
    total: summary.total,
    enabled: summary.enabled,
    protectedDomains: summary.protectedDomains,
    blockedToday: summary.blockedToday,
  }
}

function toSiteFormModel(site: ProtectedSite): SiteFormModel {
  return {
    name: site.name,
    domains: [...site.domains],
    upstream: site.upstream,
    listenPort: site.listenPort,
    status: site.status,
    tlsMode: site.tlsMode,
    certificateId: site.certificateId ?? '',
    wafEnabled: site.wafEnabled,
    ccProtection: site.ccProtection,
    semanticProtection: site.semanticProtection,
    policyMode: site.policyMode,
    blockScoreThreshold: site.blockScoreThreshold,
  }
}

export const useSitesStore = defineStore('sites', () => {
  const sites = ref<ProtectedSite[]>([])
  const summary = ref<SiteSummary>(cloneSummary(emptySummary))
  const listeners = ref<SiteRuntimeStatus[]>([])
  const listenerSummary = ref<ListenerListResponse['summary']>({ listening: 0, error: 0, notMapped: 0, disabled: 0 })
  const listenerLoading = ref(false)
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')

  const enabledSites = computed(() => sites.value.filter((site) => site.status === 'enabled'))

  async function loadSites(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetchSites()
      sites.value = data.sites
      summary.value = data.summary
    } catch (err) {
      sites.value = []
      summary.value = cloneSummary(emptySummary)
      error.value = err instanceof Error ? err.message : '站点列表加载失败'
      throw err
    } finally {
      loading.value = false
    }
  }

  async function loadListeners(): Promise<void> {
    listenerLoading.value = true
    try {
      const data = await fetchSystemListeners()
      listeners.value = data.listeners
      listenerSummary.value = data.summary
    } catch {
      listeners.value = []
      listenerSummary.value = { listening: 0, error: 0, notMapped: 0, disabled: 0 }
    } finally {
      listenerLoading.value = false
    }
  }

  async function loadSiteRuntimeStatus(id: string): Promise<SiteRuntimeStatus | null> {
    try {
      return await fetchSiteRuntimeStatus(id)
    } catch {
      return null
    }
  }

  async function refreshAll(): Promise<void> {
    await Promise.all([loadSites(), loadListeners()])
  }

  async function saveSite(payload: SiteFormModel, id?: string): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      let saved: ProtectedSite
      if (id) {
        saved = await updateSite(id, payload)
      } else {
        saved = await createSite(payload)
      }
      const index = sites.value.findIndex((site) => site.id === saved.id)
      if (index >= 0) {
        sites.value.splice(index, 1, saved)
      } else {
        sites.value.push(saved)
      }
      await refreshAll()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '站点保存失败'
      throw err
    } finally {
      saving.value = false
    }
  }

  async function toggleSite(site: ProtectedSite): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      const payload = toSiteFormModel(site)
      payload.status = site.status === 'enabled' ? 'disabled' : 'enabled'
      await updateSite(site.id, payload)
      await refreshAll()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '站点状态更新失败'
      throw err
    } finally {
      saving.value = false
    }
  }

  async function deleteSite(id: string): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      await deleteSiteApi(id)
      await refreshAll()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '站点删除失败'
      throw err
    } finally {
      saving.value = false
    }
  }

  return {
    deleteSite,
    enabledSites,
    error,
    listeners,
    listenerLoading,
    listenerSummary,
    loadListeners,
    loadSiteRuntimeStatus,
    loadSites,
    loading,
    refreshAll,
    saveSite,
    saving,
    sites,
    summary,
    toggleSite,
  }
})
