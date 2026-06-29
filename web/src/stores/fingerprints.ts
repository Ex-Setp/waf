import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  fetchFingerprints,
  updateFingerprintStatus,
  type SemanticFingerprint,
} from '@/api/fingerprints'

export const useFingerprintsStore = defineStore('fingerprints', () => {
  const fingerprints = ref<SemanticFingerprint[]>([])
  const total = ref(0)
  const loading = ref(false)
  const actionLoading = ref<string>('')

  async function load(): Promise<void> {
    loading.value = true
    try {
      const data = await fetchFingerprints()
      fingerprints.value = data.fingerprints
      total.value = data.total
    } finally {
      loading.value = false
    }
  }

  async function applyAction(id: string, action: 'observe' | 'activate' | 'rollback' | 'promote-rule'): Promise<void> {
    actionLoading.value = `${id}:${action}`
    try {
      const updated = await updateFingerprintStatus(id, action)
      const index = fingerprints.value.findIndex(item => item.id === id)
      if (index >= 0) {
        fingerprints.value[index] = updated
      } else {
        fingerprints.value.unshift(updated)
        total.value += 1
      }
    } finally {
      actionLoading.value = ''
    }
  }

  return { fingerprints, total, loading, actionLoading, load, applyAction }
})
