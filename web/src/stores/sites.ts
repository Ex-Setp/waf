import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

import {
  createSite,
  deleteSite as deleteSiteApi,
  fetchSites,
  updateSite,
  type ProtectedSite,
  type SiteFormModel,
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

  async function saveSite(payload: SiteFormModel, id?: string): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      if (id) {
        await updateSite(id, payload)
      } else {
        await createSite(payload)
      }
      await loadSites()
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
      await loadSites()
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
      await loadSites()
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
    loadSites,
    loading,
    saveSite,
    saving,
    sites,
    summary,
    toggleSite,
  }
})
