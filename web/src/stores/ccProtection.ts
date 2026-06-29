import { defineStore } from 'pinia'
import { ref } from 'vue'

import { createCcPolicy, deleteCcPolicy, fetchCcBlocks, fetchCcProtection, unblockCcIp, unblockCcKey, updateCcPolicy, type CcBlockEntry, type CcPolicy, type CcPolicyPayload, type CcStats } from '@/api/ccProtection'

const emptyStats: CcStats = { qps: 0, blockedToday: 0, challengedToday: 0, activePolicies: 0 }

export const useCcProtectionStore = defineStore('ccProtection', () => {
  const stats = ref<CcStats>({ ...emptyStats })
  const policies = ref<CcPolicy[]>([])
  const blocks = ref<CcBlockEntry[]>([])
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetchCcProtection()
      const blockData = await fetchCcBlocks()
      stats.value = data.stats ?? { ...emptyStats }
      policies.value = data.policies ?? []
      blocks.value = blockData.blocks ?? []
    } catch (err) {
      stats.value = { ...emptyStats }
      policies.value = []
      blocks.value = []
      error.value = err instanceof Error ? err.message : 'CC 防护策略加载失败'
    } finally {
      loading.value = false
    }
  }

  async function savePolicy(payload: CcPolicyPayload, id?: string): Promise<void> {
    saving.value = true
    try {
      if (id) await updateCcPolicy(id, payload)
      else await createCcPolicy(payload)
      await load()
    } finally {
      saving.value = false
    }
  }

  async function removePolicy(id: string): Promise<void> {
    saving.value = true
    try {
      await deleteCcPolicy(id)
      await load()
    } finally {
      saving.value = false
    }
  }

  async function unblockKey(key: string): Promise<void> {
    saving.value = true
    try {
      await unblockCcKey(key)
      await load()
    } finally {
      saving.value = false
    }
  }

  async function unblockIp(sourceIp: string): Promise<void> {
    saving.value = true
    try {
      await unblockCcIp(sourceIp)
      await load()
    } finally {
      saving.value = false
    }
  }

  return { stats, policies, blocks, loading, saving, error, load, savePolicy, removePolicy, unblockKey, unblockIp }
})
