<script setup lang="ts">
import { Delete, Edit, Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onMounted, reactive, ref } from 'vue'

import type { PolicyMode, ProtectedSite, SiteFormModel } from '@/api/sites'
import { useCertificatesStore } from '@/stores/certificates'
import { useSitesStore } from '@/stores/sites'

const sitesStore = useSitesStore()
const certificatesStore = useCertificatesStore()
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
  if (!value || form.domains.includes(value)) {
    return
  }
  form.domains = [...form.domains, value]
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
  const map: Record<PolicyMode, string> = { loose: '宽松', standard: '标准', strict: '严格' }
  return map[mode]
}

function policyModeType(mode: PolicyMode): 'info' | 'success' | 'danger' {
  if (mode === 'loose') return 'info'
  if (mode === 'strict') return 'danger'
  return 'success'
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
    await ElMessageBox.confirm(`确认删除站点「${site.name}」吗？`, '删除站点', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
    await sitesStore.deleteSite(site.id)
    ElMessage.success('站点已删除')
  } catch (err) {
    if (err === 'cancel') {
      return
    }
    ElMessage.error(sitesStore.error || '站点删除失败')
  }
}
</script>

<template>
  <section class="page-stack sites-page">
    <div class="sl-card">
      <div class="sl-card-head">
        <span class="sl-card-title">站点管理</span>
        <div class="status-card__actions">
          <el-button :icon="Refresh" :loading="sitesStore.loading" @click="retryLoad">刷新</el-button>
          <el-button type="primary" :icon="Plus" @click="openCreateDialog">新增站点</el-button>
        </div>
      </div>

      <el-alert
        v-if="sitesStore.error"
        :closable="false"
        show-icon
        type="error"
        :title="sitesStore.error"
        style="margin-bottom: 16px"
      >
        <template #default>
          <el-button link type="primary" @click="retryLoad">重试</el-button>
        </template>
      </el-alert>

      <el-empty v-if="!sitesStore.loading && sitesStore.sites.length === 0" description="暂无站点数据" />

      <el-table v-else v-loading="sitesStore.loading" :data="sitesStore.sites" class="sl-website-table">
        <el-table-column prop="name" label="站点名称" min-width="160" />
        <el-table-column label="域名" min-width="220">
          <template #default="{ row }: { row: ProtectedSite }">
            {{ formatDomains(row.domains) }}
          </template>
        </el-table-column>
        <el-table-column prop="upstream" label="上游" min-width="220" />
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
    </div>

    <el-dialog v-model="dialogVisible" :title="dialogTitle" width="640px" @closed="resetForm">
      <el-form label-width="100px">
        <el-form-item label="站点名称" required>
          <el-input v-model="form.name" placeholder="例如：主站业务" />
        </el-form-item>
        <el-form-item label="域名" required>
          <div class="domain-editor">
            <el-input v-model="domainInput" placeholder="example.com 或 *.example.com" @keyup.enter="addDomain">
              <template #append>
                <el-button @click="addDomain">添加</el-button>
              </template>
            </el-input>
            <div class="tag-list domain-tags">
              <el-tag v-for="domain in form.domains" :key="domain" closable @close="removeDomain(domain)">
                {{ domain }}
              </el-tag>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="上游地址" required>
          <el-input v-model="form.upstream" placeholder="http://10.0.0.12:8080" />
        </el-form-item>
        <el-form-item label="监听端口">
          <el-input-number v-model="form.listenPort" :min="1" :max="65535" />
        </el-form-item>
        <el-form-item label="TLS 模式">
          <el-radio-group v-model="form.tlsMode">
            <el-radio-button label="off">关闭</el-radio-button>
            <el-radio-button label="custom">自定义证书</el-radio-button>
            <el-radio-button label="auto">自动证书</el-radio-button>
          </el-radio-group>
          <div class="form-help">当前已支持自定义证书上传与站点绑定；自动证书/ACME 仍待接入。</div>
        </el-form-item>
        <el-form-item v-if="form.tlsMode === 'custom'" label="绑定证书">
          <el-select v-model="form.certificateId" placeholder="选择已上传证书" clearable filterable style="width: 100%">
            <el-option
              v-for="cert in certificatesStore.certificates"
              :key="cert.id"
              :label="cert.name"
              :value="cert.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="防护模式">
          <el-radio-group v-model="form.policyMode">
            <el-radio-button label="loose">宽松</el-radio-button>
            <el-radio-button label="standard">标准</el-radio-button>
            <el-radio-button label="strict">严格</el-radio-button>
          </el-radio-group>
          <div class="form-help">宽松默认观察，标准拦截高危，严格对后台/API 启用更强检测和 CC。</div>
        </el-form-item>
        <el-form-item label="防护开关">
          <el-switch
            v-model="form.wafEnabled"
            inline-prompt
            active-text="开启"
            inactive-text="关闭"
            @change="form.status = form.wafEnabled ? 'enabled' : 'disabled'"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="sitesStore.saving" @click="submitSite">保存</el-button>
      </template>
    </el-dialog>
  </section>
</template>
