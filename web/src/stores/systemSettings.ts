import { defineStore } from 'pinia'
import { ref } from 'vue'
import { fetchSystemSettings, type SystemSettings } from '@/api/systemSettings'
export const useSystemSettingsStore = defineStore('systemSettings', () => {
  const settings = ref<SystemSettings | null>(null)
  const loading = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      settings.value = await fetchSystemSettings()
    } catch (err) {
      error.value = err instanceof Error ? err.message : 'load settings failed'
      settings.value = null
    } finally {
      loading.value = false
    }
  }

  return { settings, loading, error, load }
})
