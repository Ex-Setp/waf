import { defineStore } from 'pinia'
import { ref } from 'vue'

import { createAccessRule, deleteAccessRule, fetchAccessRules, updateAccessRule, type AccessRule, type AccessRulePayload } from '@/api/accessControl'

export const useAccessControlStore = defineStore('accessControl', () => {
  const rules = ref<AccessRule[]>([])
  const total = ref(0)
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')

  async function loadRules(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetchAccessRules()
      rules.value = data.rules ?? []
      total.value = data.total ?? rules.value.length
    } catch (err) {
      rules.value = []
      total.value = 0
      error.value = err instanceof Error ? err.message : '访问控制规则加载失败'
    } finally {
      loading.value = false
    }
  }

  async function saveRule(payload: AccessRulePayload, id?: string): Promise<void> {
    saving.value = true
    try {
      if (id) await updateAccessRule(id, payload)
      else await createAccessRule(payload)
      await loadRules()
    } finally {
      saving.value = false
    }
  }

  async function removeRule(id: string): Promise<void> {
    saving.value = true
    try {
      await deleteAccessRule(id)
      await loadRules()
    } finally {
      saving.value = false
    }
  }

  return { rules, total, loading, saving, error, loadRules, saveRule, removeRule }
})
