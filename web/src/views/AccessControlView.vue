<script setup lang="ts">
import { Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, reactive, ref } from 'vue'

import type { AccessListType, AccessRule, AccessRulePayload } from '@/api/accessControl'
import { useAccessControlStore } from '@/stores/accessControl'

const store = useAccessControlStore()
const dialogVisible = ref(false)
const editingRule = ref<AccessRule | null>(null)
const form = reactive<AccessRulePayload>({ type: 'ip_blacklist', value: '', description: '', status: 'enabled' })

const ruleTypeOptions: Array<{ value: AccessListType; label: string; note: string }> = [
  { value: 'ip_blacklist', label: 'IP 黑名单', note: '命中后直接阻断' },
  { value: 'ip_whitelist', label: 'IP 白名单', note: '可信来源跳过重检测' },
  { value: 'url_whitelist', label: 'URL 白名单', note: '健康检查/静态资源放行' },
  { value: 'ua_blacklist', label: 'UA 策略', note: '按 User-Agent 特征阻断' },
  { value: 'method_block', label: '方法策略', note: '限制 HTTP 方法' },
]
const enabledCount = computed(() => store.rules.filter((rule) => rule.status === 'enabled').length)
const hitCount = computed(() => store.rules.reduce((sum, rule) => sum + (rule.hits ?? 0), 0))

onMounted(() => { void store.loadRules() })

function resetForm(): void {
  editingRule.value = null
  form.type = 'ip_blacklist'
  form.value = ''
  form.description = ''
  form.status = 'enabled'
}
function openCreate(): void { resetForm(); dialogVisible.value = true }
function openEdit(row: AccessRule): void {
  editingRule.value = row
  form.type = row.type
  form.value = row.value
  form.description = row.description ?? ''
  form.status = row.status
  dialogVisible.value = true
}
async function submitForm(): Promise<void> {
  if (!form.value.trim()) { ElMessage.warning('请填写匹配内容'); return }
  await store.saveRule({ ...form, value: form.value.trim(), description: form.description?.trim() || '' }, editingRule.value?.id)
  ElMessage.success(editingRule.value ? '规则已更新' : '规则已创建')
  dialogVisible.value = false
}
async function removeRule(row: AccessRule): Promise<void> {
  await ElMessageBox.confirm(`确认删除访问控制规则「${row.value}」？删除后策略立即从内存快照移除。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  await store.removeRule(row.id)
  ElMessage.success('规则已删除')
}
async function toggleRule(row: AccessRule, enabled: boolean): Promise<void> {
  await store.saveRule({ type: row.type, value: row.value, description: row.description ?? '', status: enabled ? 'enabled' : 'disabled' }, row.id)
  ElMessage.success(enabled ? '规则已启用' : '规则已停用')
}
function typeMeta(type: AccessListType): { text: string; tag: 'danger' | 'success' | 'warning' | 'info' } {
  const map: Record<AccessListType, { text: string; tag: 'danger' | 'success' | 'warning' | 'info' }> = {
    ip_blacklist: { text: 'IP 黑名单', tag: 'danger' },
    ip_whitelist: { text: 'IP 白名单', tag: 'success' },
    url_whitelist: { text: 'URL 白名单', tag: 'success' },
    ua_blacklist: { text: 'UA 策略', tag: 'warning' },
    method_block: { text: '方法策略', tag: 'warning' },
  }
  return map[type] ?? { text: type, tag: 'info' }
}
</script>

<template>
  <section class="page-stack" v-loading="store.loading || store.saving">
    <div class="sl-stat-grid policy-stat-grid">
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">策</span>规则总数</div><div class="sl-stat-value">{{ store.total }}</div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">启</span>启用规则</div><div class="sl-stat-value">{{ enabledCount }}</div></div></div>
      <div class="sl-stat-card"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-danger">中</span>累计命中</div><div class="sl-stat-value">{{ hitCount }}</div></div></div>
      <div class="sl-stat-card"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-warn">写</span>策略变更</div><div class="sl-stat-value compact-status"><el-tag type="success">实时生效</el-tag></div></div></div>
    </div>

    <el-alert v-if="store.error" type="warning" :closable="false" show-icon title="访问控制接口不可用" :description="`${store.error}。当前页面不使用前端 Mock 数据。`" />

    <div class="sl-card policy-board">
      <div class="sl-card-head">
        <div><span class="sl-card-title">黑白名单 / 访问控制</span><div class="table-subtext">支持 IP、URL、UA、方法类策略；新增、编辑、删除后调用真实 /api/access-rules 并刷新内存策略。</div></div>
        <div class="status-card__actions"><el-button :icon="Refresh" @click="store.loadRules">刷新</el-button><el-button type="primary" :icon="Plus" @click="openCreate">新增规则</el-button></div>
      </div>

      <div class="policy-type-strip"><div v-for="item in ruleTypeOptions" :key="item.value" class="policy-type-card"><strong>{{ item.label }}</strong><span>{{ item.note }}</span></div></div>

      <el-table :data="store.rules" empty-text="暂无访问控制规则">
        <el-table-column label="策略类型" width="140"><template #default="{ row }: { row: AccessRule }"><el-tag :type="typeMeta(row.type).tag">{{ typeMeta(row.type).text }}</el-tag></template></el-table-column>
        <el-table-column prop="value" label="匹配内容" min-width="220"><template #default="{ row }: { row: AccessRule }"><span class="payload-snippet">{{ row.value || '--' }}</span></template></el-table-column>
        <el-table-column prop="description" label="说明" min-width="180"><template #default="{ row }: { row: AccessRule }">{{ row.description || '--' }}</template></el-table-column>
        <el-table-column label="状态" width="120"><template #default="{ row }: { row: AccessRule }"><el-switch :model-value="row.status === 'enabled'" active-text="启用" inactive-text="停用" inline-prompt @change="(value: boolean | string | number) => toggleRule(row, Boolean(value))" /></template></el-table-column>
        <el-table-column prop="hits" label="命中数" width="100" />
        <el-table-column label="更新时间" width="170"><template #default="{ row }: { row: AccessRule }">{{ row.updatedAt || '--' }}</template></el-table-column>
        <el-table-column label="操作" width="150" fixed="right"><template #default="{ row }: { row: AccessRule }"><el-button link type="primary" @click="openEdit(row)">编辑</el-button><el-button link type="danger" @click="removeRule(row)">删除</el-button></template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialogVisible" :title="editingRule ? '编辑访问控制规则' : '新增访问控制规则'" width="520px" @closed="resetForm">
      <el-form label-width="96px">
        <el-form-item label="策略类型"><el-select v-model="form.type"><el-option v-for="item in ruleTypeOptions" :key="item.value" :label="item.label" :value="item.value" /></el-select></el-form-item>
        <el-form-item label="匹配内容"><el-input v-model="form.value" placeholder="IP/CIDR、URL 路径、User-Agent 或 HTTP 方法" /></el-form-item>
        <el-form-item label="说明"><el-input v-model="form.description" type="textarea" :rows="3" /></el-form-item>
        <el-form-item label="状态"><el-radio-group v-model="form.status"><el-radio-button value="enabled">启用</el-radio-button><el-radio-button value="disabled">停用</el-radio-button></el-radio-group></el-form-item>
      </el-form>
      <template #footer><el-button @click="dialogVisible = false">取消</el-button><el-button type="primary" :loading="store.saving" @click="submitForm">保存</el-button></template>
    </el-dialog>
  </section>
</template>
