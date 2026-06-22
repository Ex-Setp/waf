<script setup lang="ts">
import { Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, reactive, ref, watch } from 'vue'

import type { CaptchaMethod, CaptchaSettings, CaptchaTrigger } from '@/api/captcha'
import { useCaptchaStore } from '@/stores/captcha'

const store = useCaptchaStore()
const localSettings = ref<CaptchaSettings | null>(null)
const triggerDialogVisible = ref(false)
const editingTriggerIndex = ref<number | null>(null)
const triggerForm = reactive<CaptchaTrigger>({ id: '', name: '', condition: '', method: 'button', enabled: true })

const triggerCount = computed(() => localSettings.value?.triggers?.length ?? 0)
const enabledTriggerCount = computed(() => localSettings.value?.triggers?.filter((trigger) => trigger.enabled).length ?? 0)

watch(() => store.settings, (settings) => {
  localSettings.value = settings ? JSON.parse(JSON.stringify(settings)) as CaptchaSettings : null
}, { immediate: true })
onMounted(() => { void store.load() })

function ensureSettings(): CaptchaSettings {
  if (!localSettings.value) localSettings.value = { imageCaptcha: true, sliderCaptcha: true, ttlSeconds: 300, maxAttempts: 5, triggers: [] }
  return localSettings.value
}
async function saveSettings(): Promise<void> {
  const payload = ensureSettings()
  await store.save(payload)
  ElMessage.success('人机验证配置已保存')
}
function resetTriggerForm(): void {
  editingTriggerIndex.value = null
  triggerForm.id = ''
  triggerForm.name = ''
  triggerForm.condition = ''
  triggerForm.method = 'button'
  triggerForm.enabled = true
  delete triggerForm.passRate
  delete triggerForm.challengesToday
}
function openCreateTrigger(): void { ensureSettings(); resetTriggerForm(); triggerDialogVisible.value = true }
function openEditTrigger(row: CaptchaTrigger, index: number): void {
  editingTriggerIndex.value = index
  triggerForm.id = row.id
  triggerForm.name = row.name
  triggerForm.condition = row.condition
  triggerForm.method = row.method
  triggerForm.enabled = row.enabled
  if (row.passRate === undefined) delete triggerForm.passRate
  else triggerForm.passRate = row.passRate
  if (row.challengesToday === undefined) delete triggerForm.challengesToday
  else triggerForm.challengesToday = row.challengesToday
  triggerDialogVisible.value = true
}
function submitTrigger(): void {
  const settings = ensureSettings()
  if (!triggerForm.name.trim()) { ElMessage.warning('请填写触发条件名称'); return }
  const next: CaptchaTrigger = {
    id: triggerForm.id || `trigger-${Date.now()}`,
    name: triggerForm.name.trim(),
    condition: triggerForm.condition.trim(),
    method: triggerForm.method,
    enabled: triggerForm.enabled,
  }
  if (triggerForm.passRate !== undefined) next.passRate = triggerForm.passRate
  if (triggerForm.challengesToday !== undefined) next.challengesToday = triggerForm.challengesToday
  if (editingTriggerIndex.value === null) settings.triggers.push(next)
  else settings.triggers.splice(editingTriggerIndex.value, 1, next)
  triggerDialogVisible.value = false
}
async function removeTrigger(row: CaptchaTrigger, index: number): Promise<void> {
  await ElMessageBox.confirm(`确认删除触发条件「${row.name}」？需要点击保存配置后提交到后端。`, '删除确认', { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' })
  ensureSettings().triggers.splice(index, 1)
}
function methodText(method: CaptchaMethod): string { return { image: '图形验证码', slider: '滑块验证', button: '按钮确认' }[method] ?? method }
</script>

<template>
  <section class="page-stack" v-loading="store.loading || store.saving">
    <div class="sl-stat-grid policy-stat-grid">
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">图</span>图形验证码</div><div class="sl-stat-value compact-status"><el-tag :type="localSettings?.imageCaptcha ? 'success' : 'info'">{{ localSettings?.imageCaptcha ? '启用' : '停用' }}</el-tag></div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">滑</span>滑块验证</div><div class="sl-stat-value compact-status"><el-tag :type="localSettings?.sliderCaptcha ? 'success' : 'info'">{{ localSettings?.sliderCaptcha ? '启用' : '停用' }}</el-tag></div></div></div>
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon is-warn">T</span>Token 有效期</div><div class="sl-stat-value">{{ localSettings?.ttlSeconds ?? 0 }}s</div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">试</span>最大尝试</div><div class="sl-stat-value">{{ localSettings?.maxAttempts ?? 0 }}</div></div></div>
      <div class="sl-stat-card is-two"><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">触</span>触发条件</div><div class="sl-stat-value">{{ triggerCount }}</div></div><div class="sl-stat-item"><div class="sl-stat-label"><span class="sl-stat-icon">启</span>启用条件</div><div class="sl-stat-value">{{ enabledTriggerCount }}</div></div></div>
    </div>

    <el-alert v-if="store.error" type="warning" :closable="false" show-icon title="人机验证接口不可用" :description="`${store.error}。当前页面不使用前端 Mock 数据。`" />

    <div class="sl-card policy-board">
      <div class="sl-card-head">
        <div><span class="sl-card-title">人机验证配置</span><div class="table-subtext">配置开关、触发条件、Token 有效期、验证方式通过真实 PUT /api/captcha 保存。</div></div>
        <div class="status-card__actions"><el-button :icon="Refresh" @click="store.load">刷新</el-button><el-button type="primary" :loading="store.saving" @click="saveSettings">保存配置</el-button></div>
      </div>

      <el-form v-if="localSettings" label-width="120px" class="captcha-config-form">
        <el-form-item label="验证码方式"><el-checkbox v-model="localSettings.imageCaptcha">图形验证码</el-checkbox><el-checkbox v-model="localSettings.sliderCaptcha">滑块验证</el-checkbox></el-form-item>
        <el-form-item label="Token 有效期"><el-input-number v-model="localSettings.ttlSeconds" :min="30" :max="86400" /> <span class="table-subtext form-inline-hint">秒</span></el-form-item>
        <el-form-item label="最大尝试次数"><el-input-number v-model="localSettings.maxAttempts" :min="1" :max="20" /></el-form-item>
      </el-form>
      <el-empty v-else description="人机验证配置未加载" />
    </div>

    <div class="sl-card policy-board">
      <div class="sl-card-head"><div><span class="sl-card-title">触发条件</span><div class="table-subtext">留空触发条件表示全局验证；新增/编辑后点击保存配置提交到后端。</div></div><el-button :icon="Plus" @click="openCreateTrigger">新增条件</el-button></div>
      <el-table :data="localSettings?.triggers ?? []" empty-text="暂无人机验证触发条件">
        <el-table-column prop="name" label="名称" min-width="140" />
        <el-table-column prop="condition" label="触发条件" min-width="260" />
        <el-table-column label="验证方式" width="130"><template #default="{ row }: { row: CaptchaTrigger }">{{ methodText(row.method) }}</template></el-table-column>
        <el-table-column label="通过率" width="110"><template #default="{ row }: { row: CaptchaTrigger }">{{ row.passRate ?? '--' }}</template></el-table-column>
        <el-table-column label="今日挑战" width="120"><template #default="{ row }: { row: CaptchaTrigger }">{{ row.challengesToday ?? '--' }}</template></el-table-column>
        <el-table-column label="状态" width="100"><template #default="{ row }: { row: CaptchaTrigger }"><el-tag :type="row.enabled ? 'success' : 'info'">{{ row.enabled ? '启用' : '停用' }}</el-tag></template></el-table-column>
        <el-table-column label="操作" width="150" fixed="right"><template #default="{ row, $index }: { row: CaptchaTrigger; $index: number }"><el-button link type="primary" @click="openEditTrigger(row, $index)">编辑</el-button><el-button link type="danger" @click="removeTrigger(row, $index)">删除</el-button></template></el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="triggerDialogVisible" :title="editingTriggerIndex === null ? '新增触发条件' : '编辑触发条件'" width="560px" @closed="resetTriggerForm">
      <el-form label-width="96px">
        <el-form-item label="名称"><el-input v-model="triggerForm.name" placeholder="例如：CC 策略挑战" /></el-form-item>
        <el-form-item label="触发条件"><el-input v-model="triggerForm.condition" placeholder="留空 = 全局验证；例如：cc_action == captcha" /></el-form-item>
        <el-form-item label="验证方式"><el-radio-group v-model="triggerForm.method"><el-radio-button value="button">按钮确认</el-radio-button><el-radio-button value="image">图形验证码</el-radio-button><el-radio-button value="slider">滑块验证</el-radio-button></el-radio-group></el-form-item>
        <el-form-item label="状态"><el-switch v-model="triggerForm.enabled" active-text="启用" inactive-text="停用" /></el-form-item>
      </el-form>
      <template #footer><el-button @click="triggerDialogVisible = false">取消</el-button><el-button type="primary" @click="submitTrigger">确定</el-button></template>
    </el-dialog>
  </section>
</template>
