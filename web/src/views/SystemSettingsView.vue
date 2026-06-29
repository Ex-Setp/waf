<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'
import { computed, onMounted } from 'vue'
import { useSystemSettingsStore } from '@/stores/systemSettings'
import type { BasicHealth, ComponentStatus } from '@/api/systemSettings'

const store = useSystemSettingsStore()

onMounted(() => {
  void store.load()
})

const runtimeStatus = computed(() => store.settings?.runtimeStatus ?? null)

function tagType(status?: ComponentStatus): 'success' | 'warning' | 'danger' | 'info' {
  if (status === 'ok') return 'success'
  if (status === 'degraded') return 'warning'
  if (status === 'error') return 'danger'
  return 'info'
}

function statusText(status?: ComponentStatus): string {
  if (status === 'ok') return 'OK'
  if (status === 'degraded') return 'Degraded'
  if (status === 'error') return 'Error'
  if (status === 'unavailable') return 'Unavailable'
  return status || '--'
}

function message(health?: BasicHealth): string {
  return health?.message || '--'
}
</script>

<template>
  <section class="page-stack" v-loading="store.loading">
    <el-alert v-if="store.error" type="error" :closable="false" :title="store.error" />

    <div class="sl-card">
      <div class="sl-card-head">
        <span class="sl-card-title">System runtime status</span>
        <div class="status-card__actions">
          <el-tag :type="tagType(runtimeStatus?.status)">{{ statusText(runtimeStatus?.status) }}</el-tag>
          <el-button :icon="Refresh" @click="store.load">Refresh</el-button>
        </div>
      </div>

      <el-descriptions v-if="runtimeStatus" :column="3" border>
        <el-descriptions-item label="Checked">{{ runtimeStatus.checkedAt }}</el-descriptions-item>
        <el-descriptions-item label="Uptime">{{ runtimeStatus.uptime }}</el-descriptions-item>
        <el-descriptions-item label="Mode">{{ store.settings?.mode }}</el-descriptions-item>
      </el-descriptions>
    </div>

    <div class="sl-card" v-if="runtimeStatus">
      <div class="sl-card-head"><span class="sl-card-title">Live components</span></div>
      <el-table :data="[
        {
          name: 'Listener',
          status: runtimeStatus.listener.status,
          detail: `${runtimeStatus.listener.activeCount} active ports / ${runtimeStatus.listener.configuredSites} enabled sites`,
          message: message(runtimeStatus.listener),
        },
        {
          name: 'Database',
          status: runtimeStatus.database.status,
          detail: store.settings?.databaseDriver || '--',
          message: message(runtimeStatus.database),
        },
        {
          name: 'Runtime',
          status: runtimeStatus.runtime.status,
          detail: `${runtimeStatus.runtime.siteCount} sites, ${runtimeStatus.runtime.hostCount} hosts`,
          message: message(runtimeStatus.runtime),
        },
        {
          name: 'Rule engine',
          status: runtimeStatus.ruleEngine.status,
          detail: `${runtimeStatus.ruleEngine.enabledRuleCount} enabled / ${runtimeStatus.ruleEngine.ruleCount} total`,
          message: message(runtimeStatus.ruleEngine),
        },
        {
          name: 'Log queue',
          status: runtimeStatus.logQueue.status,
          detail: `${runtimeStatus.logQueue.queuedAccess} access, ${runtimeStatus.logQueue.queuedAttack} attack queued`,
          message: runtimeStatus.logQueue.droppedAccess > 0 ? `${runtimeStatus.logQueue.droppedAccess} dropped` : message(runtimeStatus.logQueue),
        },
      ]" row-key="name">
        <el-table-column prop="name" label="Component" min-width="150" />
        <el-table-column label="Status" width="140">
          <template #default="{ row }: { row: { status: ComponentStatus } }">
            <el-tag :type="tagType(row.status)">{{ statusText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="detail" label="Runtime detail" min-width="220" />
        <el-table-column prop="message" label="Message" min-width="220" />
      </el-table>
    </div>

    <div class="sl-card" v-if="store.settings">
      <div class="sl-card-head"><span class="sl-card-title">Runtime configuration</span></div>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="Listen address">{{ store.settings.serverHost }}:{{ store.settings.serverPort }}</el-descriptions-item>
        <el-descriptions-item label="Max body size">{{ store.settings.maxBodySize }} bytes</el-descriptions-item>
        <el-descriptions-item label="Fail open">
          <el-tag :type="store.settings.failOpen ? 'success' : 'danger'">{{ store.settings.failOpen ? 'Enabled' : 'Disabled' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Semantic engine">
          <el-tag :type="store.settings.enableSemantic ? 'success' : 'info'">{{ store.settings.enableSemantic ? 'Enabled' : 'Disabled' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="XDP">
          <el-tag :type="store.settings.enableXdp ? 'success' : 'info'">{{ store.settings.enableXdp ? 'Enabled' : 'Disabled' }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="Rules directory">{{ store.settings.rulesDirectory }}</el-descriptions-item>
        <el-descriptions-item label="Logging level">{{ store.settings.loggingLevel }}</el-descriptions-item>
      </el-descriptions>
    </div>
  </section>
</template>
