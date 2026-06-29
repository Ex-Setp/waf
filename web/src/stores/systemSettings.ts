import { defineStore } from 'pinia'
import { ref } from 'vue'
import { fetchSystemSettings, type SystemSettings } from '@/api/systemSettings'
export const useSystemSettingsStore = defineStore('systemSettings', () => {
  const settings = ref<SystemSettings | null>(null); const loading = ref(false)
  async function load(): Promise<void> { loading.value = true; try { settings.value = await fetchSystemSettings() } finally { loading.value = false } }
  return { settings, loading, load }
})
