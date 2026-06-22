<script setup lang="ts">
import { Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, reactive, ref } from 'vue'

import type { CcAction, CcBlockEntry, CcPolicy, CcPolicyPayload } from '@/api/ccProtection'
import { useCcProtectionStore } from '@/stores/ccProtection'

const store = useCcProtectionStore()
const dialogVisible = ref(false)
const editingPolicy = ref<CcPolicy | null>(null)
const form = reactive<CcPolicyPayload>({ siteId: '', name: '', scope: '*', threshold: 60, windowSeconds: 60, action: 'block', priority: 100, enabled: true })
const totalHits = computed(() => store.policies.reduce((sum, policy) => sum + (policy.hitsToday ?? 0), 0))

onMounted(() => { void store.load() })

function resetForm(): void {
  editingPolicy.value = null
  form.siteId = ''
  form.name = ''
  form.scope = '*'
  form.threshold = 60
  form.windowSeconds = 60
  form.action = 'block'
  form.priority = 100
  form.enabled = true
}
function openCreate(): void { resetForm(); dialogVisible.value = true }
function openEdit(row: CcPolicy): void {
  editingPolicy.value = row
  form.siteId = row.siteId ?? ''
  form.name = row.name
  form.scope = row.scope
  form.threshold = row.threshold
  form.windowSeconds = row.windowSeconds
  form.action = row.action
  form.priority = row.priority ?? 100
  form.enabled = row.enabled
  dialogVisible.value = true
}
async function submitForm(): Promise<void> {
  if (!form.name.trim() || !form.scope.trim()) { ElMessage.warning('请填写策略名称和保护范围'); return }
  await store.savePolicy({ ...form, siteId: form.siteId.trim(), name: form.name.trim(), scope: form.scope.trim() }, editingPolicy.value?.id)
  ElMessage.success(editingPolicy.value ? 'CC 策略已更新' : 'CC 策略已创建')
  dialogVisible.value = false
}
async function removePolicy(row: CcPolicy): Promise<void> {
  await ElMessageBox.confirm(`确认删除 CC 策略「${row.name}」？删除后将立即刷新内存策略。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  await store.removePolicy(row.id)
  ElMessage.success('CC 策略已删除')
}
async function togglePolicy(row: CcPolicy, enabled: boolean): Promise<void> {
  await store.savePolicy({ siteId: row.siteId || '', name: row.name, scope: row.scope, threshold: row.threshold, windowSeconds: row.windowSeconds, action: row.action, priority: row.priority ?? 100, enabled }, row.id)
  ElMessage.success(enabled ? '策略已启用' : '策略已停用')
}
async function unblockKey(row: CcBlockEntry): Promise<void> {
  await ElMessageBox.confirm(`确认解除封禁 key「${row.key}」？`, '解除封禁', { type: 'warning', confirmButtonText: '解除', cancelButtonText: '取消' })
  await store.unblockKey(row.key)
  ElMessage.success('封禁已解除')
}
async function unblockIp(row: CcBlockEntry): Promise<void> {
  await ElMessageBox.confirm(`确认解除 IP「${row.sourceIp}」的全部 CC 封禁？`, '解除 IP 封禁', { type: 'warning', confirmButtonText: '解除', cancelButtonText: '取消' })
  await store.unblockIp(row.sourceIp)
  ElMessage.success('IP 封禁已解除')
}
function actionText(action: CcAction): string { return { block: '阻断', captcha: '人机验证', observe: '观察', 'temp-block': '临时封禁', 'long-block': '长期封禁' }[action] ?? action }
function actionTag(action: CcAction): 'danger' | 'warning' | 'info' | 'success' { return action.includes('long-block') || action.includes('temp-block') || action === 'block' ? 'danger' : action.includes('captcha') ? 'warning' : action.includes('observe') ? 'info' : 'success' }
</script>

<template>
  <section class="page-stack" v-loading="store.loading || store.saving">
    <div class="sl-stat-grid policy-stat-grid">
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">Q</span>实时 QPS</div><div class="sl-stat-value">{{ store.stats.qps ?? 0 }}</div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-danger">拦</span>今日阻断</div><div class="sl-stat-value">{{ store.stats.blockedToday ?? 0 }}</div></div></div>
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-warn">验</span>今日验证</div><div class="sl-stat-value">{{ store.stats.challengedToday ?? 0 }}</div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">策</span>启用策略</div><div class="sl-stat-value">{{ store.stats.activePolicies ?? 0 }}</div></div></div>
      <div class="sl-stat-card"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-danger">中</span>策略命中</div><div class="sl-stat-value">{{ totalHits }}</div></div></div>
    </div>

    <el-alert v-if="store.error" type="warning" :closable="false" show-icon title="CC 防护接口不可用" :description="`${store.error}。当前页面不使用前端 Mock 数据。`" />

    <div class="sl-card policy-board">
      <div class="sl-card-head">
        <div><span class="sl-card-title">CC / Bot 防护策略</span><div class="table-subtext">新增、编辑、删除、启停均调用真实 /api/cc-protection，并刷新运行时策略快照；支持 site/path/ua/404/login-failure 与动作链。</div></div>
        <div class="status-card__actions"><el-button :icon="Refresh" @click="store.load">刷新</el-button><el-button type="primary" :icon="Plus" @click="openCreate">新增策略</el-button></div>
      </div>

      <el-table :data="store.policies" empty-text="暂无 CC 策略">
        <el-table-column prop="name" label="策略名称" min-width="160" />
        <el-table-column label="站点" width="100"><template #default="{ row }: { row: CcPolicy }">{{ row.siteId || '全局' }}</template></el-table-column>
        <el-table-column label="统计维度 / 范围" min-width="180"><template #default="{ row }: { row: CcPolicy }"><span class="payload-snippet">{{ row.scope || '--' }}</span></template></el-table-column>
        <el-table-column label="阈值 / 窗口" width="150"><template #default="{ row }: { row: CcPolicy }">{{ row.threshold }} 次 / {{ row.windowSeconds }}s</template></el-table-column>
        <el-table-column label="优先级" width="90"><template #default="{ row }: { row: CcPolicy }">{{ row.priority ?? 100 }}</template></el-table-column>
        <el-table-column label="动作 / 动作链" min-width="190"><template #default="{ row }: { row: CcPolicy }"><el-tag :type="actionTag(row.action)">{{ actionText(row.action) }}</el-tag></template></el-table-column>
        <el-table-column prop="hitsToday" label="命中数" width="110" />
        <el-table-column label="状态" width="120"><template #default="{ row }: { row: CcPolicy }"><el-switch :model-value="row.enabled" active-text="启用" inactive-text="停用" inline-prompt @change="(value: boolean | string | number) => togglePolicy(row, Boolean(value))" /></template></el-table-column>
        <el-table-column label="操作" width="150" fixed="right"><template #default="{ row }: { row: CcPolicy }"><el-button link type="primary" @click="openEdit(row)">编辑</el-button><el-button link type="danger" @click="removePolicy(row)">删除</el-button></template></el-table-column>
      </el-table>
    </div>

    <div class="sl-card policy-board">
      <div class="sl-card-head">
        <div><span class="sl-card-title">当前封禁列表</span><div class="table-subtext">来自真实 CC limiter active block 状态，可按 key 或 IP 解除封禁；无封禁时展示空态。</div></div>
        <div class="status-card__actions"><el-button :icon="Refresh" @click="store.load">刷新</el-button></div>
      </div>

      <el-table :data="store.blocks" empty-text="暂无 active CC 封禁">
        <el-table-column prop="sourceIp" label="来源 IP" width="150" />
        <el-table-column label="封禁 key" min-width="260"><template #default="{ row }: { row: CcBlockEntry }"><span class="payload-snippet">{{ row.key }}</span></template></el-table-column>
        <el-table-column label="策略 / 范围" min-width="180"><template #default="{ row }: { row: CcBlockEntry }">{{ row.policyName || row.policyId || '--' }}<div class="table-subtext">{{ row.scope || '--' }}</div></template></el-table-column>
        <el-table-column label="动作" width="110"><template #default="{ row }: { row: CcBlockEntry }"><el-tag :type="actionTag(row.action)">{{ actionText(row.action) }}</el-tag></template></el-table-column>
        <el-table-column prop="count" label="计数" width="90" />
        <el-table-column prop="blockUntil" label="封禁至" width="190" />
        <el-table-column label="操作" width="190" fixed="right"><template #default="{ row }: { row: CcBlockEntry }"><el-button link type="primary" @click="unblockKey(row)">解除 key</el-button><el-button link type="danger" @click="unblockIp(row)">解除 IP</el-button></template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialogVisible" :title="editingPolicy ? '编辑 CC 策略' : '新增 CC 策略'" width="560px" @closed="resetForm">
      <el-form label-width="96px">
        <el-form-item label="站点 ID"><el-input v-model="form.siteId" placeholder="留空表示全局策略" /></el-form-item>
        <el-form-item label="策略名称"><el-input v-model="form.name" placeholder="例如：登录接口限速" /></el-form-item>
        <el-form-item label="统计维度"><el-input v-model="form.scope" placeholder="site、path、ua、404、login-failure:/login、/api/*" /><div class="table-subtext">site=IP+站点；path=IP+路径；ua=IP+UA；404/登录失败会在上游响应后计数。</div></el-form-item>
        <el-form-item label="阈值"><el-input-number v-model="form.threshold" :min="1" :max="100000" /> <span class="table-subtext form-inline-hint">次</span></el-form-item>
        <el-form-item label="窗口"><el-input-number v-model="form.windowSeconds" :min="1" :max="86400" /> <span class="table-subtext form-inline-hint">秒</span></el-form-item>
        <el-form-item label="优先级"><el-input-number v-model="form.priority" :min="1" :max="10000" /> <span class="table-subtext form-inline-hint">数字越小越先匹配</span></el-form-item>
        <el-form-item label="动作链"><el-input v-model="form.action" placeholder="observe>captcha>temp-block>long-block" /><div class="table-subtext">兼容单动作 block/captcha/observe/temp-block/long-block；动作链用 &gt;、, 或 | 分隔。</div></el-form-item>
        <el-form-item label="状态"><el-switch v-model="form.enabled" active-text="启用" inactive-text="停用" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialogVisible = false">取消</el-button><el-button type="primary" :loading="store.saving" @click="submitForm">保存</el-button></template>
    </el-dialog>
  </section>
</template>
