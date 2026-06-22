import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

import AccessControlView from '@/views/AccessControlView.vue'
import AttackLogsView from '@/views/AttackLogsView.vue'
import CaptchaView from '@/views/CaptchaView.vue'
import CertificatesView from '@/views/CertificatesView.vue'
import CcProtectionView from '@/views/CcProtectionView.vue'
import ConsoleLayout from '@/layouts/ConsoleLayout.vue'
import DashboardView from '@/views/DashboardView.vue'
import ProtectionConfigView from '@/views/ProtectionConfigView.vue'
import SitesView from '@/views/SitesView.vue'
import SystemSettingsView from '@/views/SystemSettingsView.vue'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: ConsoleLayout,
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'dashboard',
        component: DashboardView,
        meta: { title: '总览' },
      },
      {
        path: 'sites',
        name: 'sites',
        component: SitesView,
        meta: { title: '防护应用' },
      },
      {
        path: 'attack-logs',
        name: 'attackLogs',
        component: AttackLogsView,
        meta: { title: '攻击事件' },
      },
      {
        path: 'access-control',
        name: 'accessControl',
        component: AccessControlView,
        meta: { title: '黑白名单' },
      },
      {
        path: 'cc-protection',
        name: 'ccProtection',
        component: CcProtectionView,
        meta: { title: 'CC 防护' },
      },
      {
        path: 'captcha',
        name: 'captcha',
        component: CaptchaView,
        meta: { title: '人机验证' },
      },
      {
        path: 'protection-config',
        name: 'protectionConfig',
        component: ProtectionConfigView,
        meta: { title: '防护配置' },
      },
      {
        path: 'certificates',
        name: 'certificates',
        component: CertificatesView,
        meta: { title: '证书' },
      },
      {
        path: 'settings',
        name: 'settings',
        component: SystemSettingsView,
        meta: { title: '系统设置' },
      },
    ],
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

export default router
