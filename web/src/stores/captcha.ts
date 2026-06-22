import { defineStore } from 'pinia'
import { ref } from 'vue'

import { fetchCaptchaSettings, updateCaptchaSettings, type CaptchaSettings } from '@/api/captcha'

export const useCaptchaStore = defineStore('captcha', () => {
  const settings = ref<CaptchaSettings | null>(null)
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      settings.value = await fetchCaptchaSettings()
    } catch (err) {
      settings.value = null
      error.value = err instanceof Error ? err.message : '人机验证配置加载失败'
    } finally {
      loading.value = false
    }
  }

  async function save(payload: CaptchaSettings): Promise<void> {
    saving.value = true
    try {
      settings.value = await updateCaptchaSettings(payload)
    } finally {
      saving.value = false
    }
  }

  return { settings, loading, saving, error, load, save }
})
