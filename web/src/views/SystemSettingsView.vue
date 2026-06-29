<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'
import { onMounted } from 'vue'
import { useSystemSettingsStore } from '@/stores/systemSettings'
const store = useSystemSettingsStore()
onMounted(() => { void store.load() })
</script>
<template><section class="page-stack" v-loading="store.loading">
  <div class="sl-card"><div class="sl-card-head"><span class="sl-card-title">系统配置</span><el-button :icon="Refresh" @click="store.load">刷新</el-button></div><el-descriptions :column="2" border><el-descriptions-item label="监听地址">{{ store.settings?.serverHost }}:{{ store.settings?.serverPort }}</el-descriptions-item><el-descriptions-item label="运行模式">{{ store.settings?.mode }}</el-descriptions-item><el-descriptions-item label="Fail Open"><el-tag :type="store.settings?.failOpen ? 'success' : 'danger'">{{ store.settings?.failOpen ? '开启' : '关闭' }}</el-tag></el-descriptions-item><el-descriptions-item label="请求体上限">{{ store.settings?.maxBodySize }} bytes</el-descriptions-item><el-descriptions-item label="语义分析"><el-tag :type="store.settings?.enableSemantic ? 'success' : 'info'">{{ store.settings?.enableSemantic ? '启用' : '停用' }}</el-tag></el-descriptions-item><el-descriptions-item label="XDP"><el-tag :type="store.settings?.enableXdp ? 'success' : 'info'">{{ store.settings?.enableXdp ? '启用' : '停用' }}</el-tag></el-descriptions-item><el-descriptions-item label="数据库">{{ store.settings?.databaseDriver }}</el-descriptions-item><el-descriptions-item label="规则目录">{{ store.settings?.rulesDirectory }}</el-descriptions-item><el-descriptions-item label="日志级别">{{ store.settings?.loggingLevel }}</el-descriptions-item></el-descriptions></div>
</section></template>
