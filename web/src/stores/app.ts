import { defineStore } from 'pinia'
import { computed, ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  const sidebarCollapsed = ref(false)
  const serviceName = ref('Aegis-WAF')

  const layoutClass = computed(() => (sidebarCollapsed.value ? 'is-collapsed' : ''))

  function toggleSidebar(): void {
    sidebarCollapsed.value = !sidebarCollapsed.value
  }

  return {
    layoutClass,
    serviceName,
    sidebarCollapsed,
    toggleSidebar,
  }
})
