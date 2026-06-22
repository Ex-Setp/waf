import { defineStore } from 'pinia'
import { ref } from 'vue'

import {
  createCertificate,
  deleteCertificate as deleteCertificateApi,
  fetchCertificates,
  type CertificateItem,
  type CertificatePayload,
} from '@/api/certificates'

export const useCertificatesStore = defineStore('certificates', () => {
  const certificates = ref<CertificateItem[]>([])
  const total = ref(0)
  const loading = ref(false)
  const saving = ref(false)
  const error = ref('')

  async function load(): Promise<void> {
    loading.value = true
    error.value = ''
    try {
      const data = await fetchCertificates()
      certificates.value = data.certificates
      total.value = data.total
    } catch (err) {
      certificates.value = []
      total.value = 0
      error.value = err instanceof Error ? err.message : '证书列表加载失败'
      throw err
    } finally {
      loading.value = false
    }
  }

  async function save(payload: CertificatePayload): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      await createCertificate(payload)
      await load()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '证书保存失败'
      throw err
    } finally {
      saving.value = false
    }
  }

  async function remove(id: string): Promise<void> {
    saving.value = true
    error.value = ''
    try {
      await deleteCertificateApi(id)
      await load()
    } catch (err) {
      error.value = err instanceof Error ? err.message : '证书删除失败'
      throw err
    } finally {
      saving.value = false
    }
  }

  return { certificates, error, load, loading, remove, save, saving, total }
})
