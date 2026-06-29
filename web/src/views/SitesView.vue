<script setup lang="ts">
import { Delete, Edit, Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, reactive, ref, watch } from 'vue'

import type { PolicyMode, ProtectedSite, SiteFormModel } from '@/api/sites'
import { useCertificatesStore } from '@/stores/certificates'
import { useSitesStore } from '@/stores/sites'

const sitesStore = useSitesStore()
const certificatesStore = useCertificatesStore()
const selectedSiteRuntime = ref('')
const dialogVisible = ref(false)
const editingSiteId = ref<string>()
const domainInput = ref('')

const form = reactive<SiteFormModel>({
  name: '',
  domains: [],
  upstream: '',
  listenPort: 443,
  status: 'enabled',
  tlsMode: 'off',
  certificateId: '',
  wafEnabled: true,
  ccProtection: true,
  semanticProtection: true,
  policyMode: 'standard',
  blockScoreThreshold: 7,
})

const dialogTitle = computed(() => (editingSiteId.value ? '编辑站点' : '新增站点'))

onMounted(() => {
  void retryLoad()
  void certificatesStore.load()
})

watch(
  () => sitesStore.sites,
  async (sites) => {
    const first = sites[0]
    if (!first) {
      selectedSiteRuntime.value = ''
      return
    }
    const runtime = await sitesStore.loadSiteRuntimeStatus(first.id)
    if (runtime) {
      selectedSiteRuntime.value = `${runtime.siteId}:${runtime.status}:${runtime.protocol}`
    }
  },
  { immediate: true },
)

function resetForm(): void {
  editingSiteId.value = undefined
  form.name = ''
  form.domains = []
  form.upstream = ''
  form.listenPort = 443
  form.status = 'enabled'
  form.tlsMode = 'off'
  form.certificateId = ''
  form.wafEnabled = true
  form.ccProtection = true
  form.semanticProtection = true
  form.policyMode = 'standard'
  form.blockScoreThreshold = 7
  domainInput.value = ''
}

function openCreateDialog(): void {
  resetForm()
  dialogVisible.value = true
}

function openEditDialog(site: ProtectedSite): void {
  editingSiteId.value = site.id
  form.name = site.name
  form.domains = [...site.domains]
  form.upstream = site.upstream
  form.listenPort = site.listenPort
  form.status = site.status
  form.tlsMode = site.tlsMode
  form.certificateId = site.certificateId ?? ''
  form.wafEnabled = site.wafEnabled
  form.ccProtection = site.ccProtection
  form.semanticProtection = site.semanticProtection
  form.policyMode = site.policyMode
  form.blockScoreThreshold = site.blockScoreThreshold
  domainInput.value = ''
  dialogVisible.value = true
}

function addDomain(): void {
  const value = domainInput.value.trim()
  if (!value) return
  if (!form.domains.includes(value)) {
    form.domains.push(value)
  }
  domainInput.value = ''
}

function removeDomain(domain: string): void {
  form.domains = form.domains.filter((item) => item !== domain)
}

function formatMetric(value?: number | null): string {
  if (value == null) {
    return '--'
  }
  return String(value)
}

function formatDomains(domains: string[]): string {
  return domains.length > 0 ? domains.join(' / ') : '--'
}

function protectionStatusText(site: ProtectedSite): string {
  return site.status === 'enabled' && site.wafEnabled ? '已开启' : '已关闭'
}

function policyModeText(mode: PolicyMode): string {
  const map: Record<PolicyMode, string> = { observe: '观察', loose: '宽松', standard: '标准', strict: '严格', custom: '自定义' }
  return map[mode]
}

function policyModeType(mode: PolicyMode): 'info' | 'success' | 'danger' | 'warning' {
  if (mode === 'observe' || mode === 'loose') return 'info'
  if (mode === 'strict') return 'danger'
  if (mode === 'custom') return 'warning'
  return 'success'
}

function listenerStatusText(status?: string): string {
  const map: Record<string, string> = {
    listening: '监听中',
    error: '监听错误',
    'not-mapped': '未映射',
    disabled: '未监听',
  }
  return map[status ?? 'disabled'] ?? '未监听'
}

function listenerStatusType(status?: string): 'success' | 'warning' | 'danger' | 'info' {
  if (status === 'listening') return 'success'
  if (status === 'error') return 'danger'
  if (status === 'not-mapped') return 'warning'
  return 'info'
}

function listenerProtocolText(site: ProtectedSite): string {
  return site.listenProtocol === 'https' ? 'HTTPS' : 'HTTP'
}

function listenerProtocolType(protocol?: string): 'success' | 'info' {
  return protocol === 'https' ? 'success' : 'info'
}

function certificateStatusText(site: ProtectedSite): string {
  if (site.tlsMode === 'custom') {
    return site.certificateName ? `自定义：${site.certificateName}` : '自定义证书未绑定'
  }
  if (site.tlsMode === 'auto') {
    return '自动证书待接入'
  }
  return '未启用'
}

async function retryLoad(): Promise<void> {
  try {
    await sitesStore.loadSites()
  } catch {
    ElMessage.error('站点列表加载失败')
  }
}

async function submitSite(): Promise<void> {
  if (!form.name.trim() || form.domains.length === 0 || !form.upstream.trim()) {
    ElMessage.warning('请填写站点名称、域名和上游地址')
    return
  }

  try {
    await sitesStore.saveSite(
      {
        ...form,
        domains: [...form.domains],
      },
      editingSiteId.value,
    )
    ElMessage.success(editingSiteId.value ? '站点已更新' : '站点已创建')
    dialogVisible.value = false
  } catch {
    ElMessage.error(sitesStore.error || '站点保存失败')
  }
}

async function handleToggle(site: ProtectedSite): Promise<void> {
  try {
    await sitesStore.toggleSite(site)
    ElMessage.success(site.status === 'enabled' ? '站点已关闭防护' : '站点已开启防护')
  } catch {
    ElMessage.error(sitesStore.error || '站点状态更新失败')
  }
}

async function handleDelete(site: ProtectedSite): Promise<void> {
  try {
    await ElMessageBox.confirm(`确认删除站点“${site.name}”吗？`, '删除站点', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
    await sitesStore.deleteSite(site.id)
    ElMessage.success('站点已删除')
  } catch (err) {
    if (err !== 'cancel') {
      ElMessage.error(sitesStore.error || '站点删除失败')
    }
  }
}
</script>

<template>
  <div class="page-shell">
    <div class="page-header">
      <div>
        <h2>防护站点</h2>
        <p>管理受保护站点、域名、上游和站点级防护状态。</p>
      </div>
      <div class="page-actions">
        <el-button :icon="Refresh" @click="retryLoad">刷新</el-button>
        <el-button type="primary" :icon="Plus" @click="openCreateDialog">新增站点</el-button>
      </div>
    </div>

    <el-alert v-if="sitesStore.error" :title="sitesStore.error" type="error" show-icon class="sl-alert" />

    <el-card class="sl-stat-card" shadow="never">
      <div class="sl-stat-grid">
        <div class="sl-stat-item"><span>站点总数</span><strong>{{ sitesStore.summary.total }}</strong></div>
        <div class="sl-stat-item"><span>启用站点</span><strong>{{ sitesStore.summary.enabled }}</strong></div>
        <div class="sl-stat-item"><span>受保护域名</span><strong>{{ sitesStore.summary.protectedDomains }}</strong></div>
        <div class="sl-stat-item"><span>今日拦截</span><strong>{{ sitesStore.summary.blockedToday }}</strong></div>
      </div>
    </el-card>

    <el-card class="sl-stat-card" shadow="never">
      <template #header>系统监听器</template>
      <div class="sl-stat-grid">
        <div class="sl-stat-item"><span>监听中</span><strong>{{ sitesStore.listenerSummary.listening }}</strong></div>
        <div class="sl-stat-item"><span>监听错误</span><strong>{{ sitesStore.listenerSummary.error }}</strong></div>
        <div class="sl-stat-item"><span>未映射</span><strong>{{ sitesStore.listenerSummary.notMapped }}</strong></div>
        <div class="sl-stat-item"><span>未监听</span><strong>{{ sitesStore.listenerSummary.disabled }}</strong></div>
      </div>
    </el-card>

    <el-card class="sl-table-card" shadow="never">
      <el-table v-loading="sitesStore.loading" :data="sitesStore.sites" class="sl-website-table">
        <el-table-column prop="name" label="站点名称" min-width="160" />
        <el-table-column label="域名" min-width="220">
          <template #default="{ row }: { row: ProtectedSite }">
            {{ formatDomains(row.domains) }}
          </template>
        </el-table-column>
        <el-table-column prop="upstream" label="上游" min-width="220" />
        <el-table-column label="监听状态" width="180">
          <template #default="{ row }: { row: ProtectedSite }">
            <el-space wrap size="small">
              <el-tag :type="listenerStatusType(row.listenStatus)">{{ listenerStatusText(row.listenStatus) }}</el-tag>
              <el-tag :type="listenerProtocolType(row.listenProtocol)">{{ listenerProtocolText(row) }}</el-tag>
            </el-space>
          </template>
        </el-table-column>
        <el-table-column label="防护模式" width="110">
          <template #default="{ row }: { row: ProtectedSite }">
            <el-tag :type="policyModeType(row.policyMode)">{{ policyModeText(row.policyMode) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="防护状态" width="120">
          <template #default="{ row }: { row: ProtectedSite }">
            <el-tag :type="row.status === 'enabled' && row.wafEnabled ? 'success' : 'info'">
              {{ protectionStatusText(row) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="证书状态" width="130">
          <template #default="{ row }: { row: ProtectedSite }">
            {{ certificateStatusText(row) }}
          </template>
        </el-table-column>
        <el-table-column label="今日请求" width="110" align="right">
          <template #default="{ row }: { row: ProtectedSite }">
            {{ formatMetric(row.qps) }}
          </template>
        </el-table-column>
        <el-table-column label="今日拦截" width="110" align="right">
          <template #default="{ row }: { row: ProtectedSite }">
            {{ formatMetric(row.blockedToday) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="240" fixed="right">
          <template #default="{ row }: { row: ProtectedSite }">
            <div style="display: flex; gap: 8px">
              <el-button link type="primary" :icon="Edit" @click="openEditDialog(row)">编辑</el-button>
              <el-button link type="primary" @click="handleToggle(row)">
                {{ row.status === 'enabled' ? '关闭防护' : '开启防护' }}
              </el-button>
              <el-button link type="danger" :icon="Delete" @click="handleDelete(row)">删除</el-button>
            </div>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="640px" @closed="resetForm">
      <el-form label-width="100px">
        <el-form-item label="站点名称" required>
          <el-input v-model="form.name" placeholder="例如：主站业务" />
        </el-form-item>
        <el-form-item label="域名" required>
          <div style="display: flex; gap: 8px; width: 100%">
            <el-input v-model="domainInput" placeholder="例如：www.example.com" @keyup.enter="addDomain" />
            <el-button @click="addDomain">添加</el-button>
          </div>
          <div style="display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px">
            <el-tag v-for="domain in form.domains" :key="domain" closable @close="removeDomain(domain)">{{ domain }}</el-tag>
          </div>
        </el-form-item>
        <el-form-item label="上游地址" required>
          <el-input v-model="form.upstream" placeholder="http://127.0.0.1:8081" />
        </el-form-item>
        <el-form-item label="监听端口">
          <el-input-number v-model="form.listenPort" :min="1" :max="65535" />
        </el-form-item>
        <el-form-item label="TLS模式">
          <el-select v-model="form.tlsMode" style="width: 100%">
            <el-option label="关闭" value="off" />
            <el-option label="自动证书" value="auto" />
            <el-option label="自定义证书" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="证书">
          <el-select v-model="form.certificateId" clearable filterable style="width: 100%" placeholder="选择证书">
            <el-option v-for="cert in certificatesStore.certificates" :key="cert.id" :label="cert.name" :value="cert.id" />
          </el-select>
        </el-form-item>
        <el-form-item label="Policy mode">
          <el-select v-model="form.policyMode" style="width: 100%">
            <el-option label="Observe" value="observe" />
            <el-option label="Loose" value="loose" />
            <el-option label="Standard" value="standard" />
            <el-option label="Strict" value="strict" />
            <el-option label="Custom" value="custom" />
          </el-select>
        </el-form-item>
        <el-form-item label="Block score">
          <el-input-number v-model="form.blockScoreThreshold" :min="1" :max="100" :disabled="form.policyMode !== 'custom'" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="sitesStore.saving" @click="submitSite">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>
