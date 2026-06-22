<script setup lang="ts">
import { Refresh } from '@element-plus/icons-vue'
import { onMounted, ref } from 'vue'
import type { SemanticFingerprint } from '@/api/fingerprints'
import { useFingerprintsStore } from '@/stores/fingerprints'

const store = useFingerprintsStore()
const current = ref<SemanticFingerprint | null>(null)

onMounted(() => { void store.load() })

function statusType(status: SemanticFingerprint['status']): 'success' | 'warning' | 'danger' {
  return status === 'active' ? 'success' : status === 'observing' ? 'warning' : 'danger'
}
function statusText(status: SemanticFingerprint['status']): string {
  return { active: '已启用拦截', observing: '观察中', rollback: '已回滚' }[status]
}
function actionText(action: SemanticFingerprint['action']): string {
  return { deny: '拦截', log: '观察', pass: '放行' }[action]
}
function shortHash(hash: string): string {
  return hash.length > 18 ? `${hash.slice(0, 18)}...` : hash
}
function busy(row: SemanticFingerprint, action: string): boolean {
  return store.actionLoading === `${row.id}:${action}`
}
</script>

<template>
  <section class="page-stack" v-loading="store.loading">
    <div class="sl-card">
      <div class="sl-card-head">
        <div>
          <span class="sl-card-title">{{ store.total }} 条语义指纹</span>
          <p class="page-hint">真实语义检测链路生成攻击骨架，稳定观察后可启用临时拦截，或升级为规则管理中的 semantic 来源规则；回滚会删除规则并从 XDP 同步层删除。</p>
        </div>
        <el-button :icon="Refresh" @click="store.load">刷新</el-button>
      </div>
      <el-table :data="store.fingerprints" row-key="id">
        <el-table-column prop="hash" label="Hash" min-width="190">
          <template #default="{ row }: { row: SemanticFingerprint }"><code class="payload-snippet">{{ shortHash(row.hash) }}</code></template>
        </el-table-column>
        <el-table-column prop="language" label="语言" width="110" />
        <el-table-column label="攻击骨架" min-width="240">
          <template #default="{ row }: { row: SemanticFingerprint }">
            <code class="payload-snippet">{{ row.skeleton || '-' }}</code>
          </template>
        </el-table-column>
        <el-table-column label="动作" width="90">
          <template #default="{ row }: { row: SemanticFingerprint }">{{ actionText(row.action) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="130">
          <template #default="{ row }: { row: SemanticFingerprint }"><el-tag :type="statusType(row.status)">{{ statusText(row.status) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="hits" label="命中" width="90" />
        <el-table-column prop="ruleId" label="规则 ID" width="110" />
        <el-table-column prop="xdpSyncStatus" label="XDP 同步" width="150" />
        <el-table-column prop="updatedAt" label="更新时间" width="170" />
        <el-table-column label="操作" width="330" fixed="right">
          <template #default="{ row }: { row: SemanticFingerprint }">
            <el-button link type="primary" @click="current = row">详情</el-button>
            <el-button link type="warning" :loading="busy(row, 'observe')" @click="store.applyAction(row.id, 'observe')">观察</el-button>
            <el-button link type="danger" :loading="busy(row, 'activate')" @click="store.applyAction(row.id, 'activate')">启用拦截</el-button>
            <el-button link type="success" :loading="busy(row, 'promote-rule')" @click="store.applyAction(row.id, 'promote-rule')">升级规则</el-button>
            <el-button link type="info" :loading="busy(row, 'rollback')" @click="store.applyAction(row.id, 'rollback')">回滚</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-drawer v-model="current" title="语义指纹详情" size="48%">
      <template v-if="current">
        <el-descriptions :column="1" border>
          <el-descriptions-item label="Hash"><code>{{ current.hash }}</code></el-descriptions-item>
          <el-descriptions-item label="来源">{{ current.source || '-' }}</el-descriptions-item>
          <el-descriptions-item label="最近命中">{{ current.lastSeenAt || '-' }}</el-descriptions-item>
          <el-descriptions-item label="样本 Payload"><code class="payload-snippet">{{ current.samplePayload || '-' }}</code></el-descriptions-item>
          <el-descriptions-item label="节点类型">{{ current.nodeTypes.join(' -> ') || '-' }}</el-descriptions-item>
          <el-descriptions-item label="生成规则"><pre class="rule-block">{{ current.generatedRule || '观察期尚未生成拦截规则' }}</pre></el-descriptions-item>
        </el-descriptions>
      </template>
    </el-drawer>
  </section>
</template>
