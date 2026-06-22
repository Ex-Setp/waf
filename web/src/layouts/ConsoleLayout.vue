<script setup lang="ts">
import {
  Bell,
  Connection,
  DataAnalysis,
  Document,
  HomeFilled,
  Lock,
  OfficeBuilding,
  Setting,
  SwitchButton,
  Tickets,
  Tools,
} from '@element-plus/icons-vue'
import { computed } from 'vue'
import { useRoute } from 'vue-router'

import { useAppStore } from '@/stores/app'

interface NavItem {
  path: string
  title: string
  icon: typeof DataAnalysis
}

const appStore = useAppStore()
const route = useRoute()

const navItems: NavItem[] = [
  { path: '/dashboard', title: '总览', icon: DataAnalysis },
  { path: '/sites', title: '防护应用', icon: OfficeBuilding },
  { path: '/attack-logs', title: '攻击事件', icon: Document },
  { path: '/access-control', title: '黑白名单', icon: Tickets },
  { path: '/cc-protection', title: 'CC 防护', icon: Tools },
  { path: '/captcha', title: '人机验证', icon: Connection },
  { path: '/protection-config', title: '防护配置', icon: Lock },
  { path: '/certificates', title: '证书', icon: Lock },
  { path: '/settings', title: '系统设置', icon: Setting },
]

const activeMenu = computed(() => route.path)
const pageTitle = computed(() => {
  const title = route.meta.title
  return typeof title === 'string' ? title : '总览'
})
</script>

<template>
  <el-container class="console-layout safeline-shell" :class="appStore.layoutClass">
    <el-aside class="console-sidebar" width="220px">
      <div class="brand">
        <div class="brand__mark" aria-label="Aegis-WAF 标志">
          <svg viewBox="0 0 48 48" role="img">
            <path d="M24 4 40 10v12c0 10.8-6.4 18.8-16 22C14.4 40.8 8 32.8 8 22V10L24 4Z" />
            <path d="M24 13 15 33h6l2-5h8l2 5h6L30 13h-6Zm1.2 10 1.8-4.8L28.8 23h-3.6Z" />
          </svg>
        </div>
        <div class="brand__copy">
          <strong>{{ appStore.serviceName }}</strong>
          <span>Console</span>
        </div>
      </div>

      <el-menu router class="sidebar-menu" :default-active="activeMenu">
        <el-menu-item v-for="item in navItems" :key="item.path" :index="item.path">
          <el-icon><component :is="item.icon" /></el-icon>
          <template #title>{{ item.title }}</template>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <div class="version-pill">T110</div>
        <a href="#"><el-icon><HomeFilled /></el-icon> 官网入口</a>
        <a href="#"><el-icon><Document /></el-icon> 使用文档</a>
      </div>
    </el-aside>

    <el-container class="console-body">
      <el-header class="console-header">
        <div>
          <div class="page-title">{{ pageTitle }}</div>
          <div class="page-subtitle">Aegis-WAF 控制台信息架构已对齐 SafeLine 风格导航</div>
        </div>
        <div class="header-right">
          <el-button class="community-button"><el-icon><Bell /></el-icon> 社区版</el-button>
          <el-button class="round-icon-button" :icon="Setting" circle />
          <el-button class="round-icon-button" :icon="SwitchButton" circle />
        </div>
      </el-header>

      <el-main class="console-main">
        <RouterView />
      </el-main>
    </el-container>
  </el-container>
</template>
