<script setup lang="ts">
import { Delete, Plus, Refresh } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { onMounted, reactive, ref } from 'vue'

import type { CertificateItem, CertificatePayload } from '@/api/certificates'
import { useCertificatesStore } from '@/stores/certificates'

const store = useCertificatesStore()
const dialogVisible = ref(false)
const domainInput = ref('')
const certFileInput = ref<HTMLInputElement | null>(null)
const keyFileInput = ref<HTMLInputElement | null>(null)
const certFileName = ref('')
const keyFileName = ref('')
const form = reactive<CertificatePayload>({ name: '', domains: [], certPem: '', keyPem: '' })

onMounted(() => {
  void store.load()
})

function resetForm(): void {
  form.name = ''
  form.domains = []
  form.certPem = ''
  form.keyPem = ''
  domainInput.value = ''
  certFileName.value = ''
  keyFileName.value = ''
  if (certFileInput.value) certFileInput.value.value = ''
  if (keyFileInput.value) keyFileInput.value.value = ''
}

function openCreate(): void {
  resetForm()
  dialogVisible.value = true
}

function addDomain(): void {
  const value = domainInput.value.trim()
  if (!value || form.domains.includes(value)) return
  form.domains = [...form.domains, value]
  domainInput.value = ''
}

function removeDomain(domain: string): void {
  form.domains = form.domains.filter((item) => item !== domain)
}

function readTextFile(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result ?? ''))
    reader.onerror = () => reject(reader.error ?? new Error('文件读取失败'))
    reader.readAsText(file)
  })
}

async function loadPemFile(event: Event, target: 'cert' | 'key'): Promise<void> {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (!file) return
  try {
    const text = await readTextFile(file)
    if (target === 'cert') {
      form.certPem = text.trim()
      certFileName.value = file.name
      if (!form.name.trim()) form.name = file.name.replace(/\.(pem|crt|cer)$/i, '')
    } else {
      form.keyPem = text.trim()
      keyFileName.value = file.name
    }
    ElMessage.success(`已读取文件：${file.name}`)
  } catch (err) {
    ElMessage.error(err instanceof Error ? err.message : '文件读取失败')
  }
}

function chooseCertFile(): void { certFileInput.value?.click() }
function chooseKeyFile(): void { keyFileInput.value?.click() }

async function submitForm(): Promise<void> {
  if (!form.name.trim() || !form.certPem.trim()) {
    ElMessage.warning('请填写证书名称和证书 PEM')
    return
  }
  await store.save({ ...form, name: form.name.trim(), domains: [...form.domains] })
  ElMessage.success('证书已上传')
  dialogVisible.value = false
}

async function removeCertificate(row: CertificateItem): Promise<void> {
  await ElMessageBox.confirm(`确认删除证书「${row.name}」？已绑定站点可能需要重新选择证书。`, '删除证书', {
    type: 'warning',
    confirmButtonText: '删除',
    cancelButtonText: '取消',
  })
  await store.remove(row.id)
  ElMessage.success('证书已删除')
}

function formatDomains(domains: string[]): string {
  return domains.length > 0 ? domains.join(' / ') : '--'
}
</script>

<template>
  <section class="page-stack" v-loading="store.loading || store.saving">
    <el-alert
      type="info"
      show-icon
      :closable="false"
      title="当前已接入：证书上传/列表/删除、站点绑定、自定义证书 HTTPS 监听、按域名 SNI 选择证书；ACME 自动签发已接入后端配置，需开启 server.tls.acme 并接受 TOS 后用于 tlsMode=auto 站点。"
    />

    <el-alert
      v-if="store.error"
      type="warning"
      :closable="false"
      show-icon
      title="证书接口不可用"
      :description="store.error"
    />

    <div class="sl-card">
      <div class="sl-card-head">
        <div>
          <span class="sl-card-title">证书管理</span>
          <div class="table-subtext">证书数据来自真实 /api/certificates，不展示伪造列表。</div>
        </div>
        <div class="status-card__actions">
          <el-button :icon="Refresh" @click="store.load">刷新</el-button>
          <el-button type="primary" :icon="Plus" @click="openCreate">上传证书</el-button>
        </div>
      </div>

      <el-table :data="store.certificates" empty-text="暂无证书">
        <el-table-column prop="name" label="证书名称" min-width="180" />
        <el-table-column label="域名" min-width="260">
          <template #default="{ row }: { row: CertificateItem }">{{ formatDomains(row.domains) }}</template>
        </el-table-column>
        <el-table-column label="私钥" width="100">
          <template #default="{ row }: { row: CertificateItem }">
            <el-tag :type="row.hasPrivateKey ? 'success' : 'warning'">{{ row.hasPrivateKey ? '已保存' : '未上传' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="updatedAt" label="更新时间" width="180" />
        <el-table-column label="操作" width="120" fixed="right">
          <template #default="{ row }: { row: CertificateItem }">
            <el-button link type="danger" :icon="Delete" @click="removeCertificate(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dialogVisible" title="上传证书" width="720px" @closed="resetForm">
      <el-form label-width="96px">
        <el-form-item label="证书名称" required><el-input v-model="form.name" placeholder="例如：example.com 证书" /></el-form-item>
        <el-form-item label="域名">
          <div class="domain-editor">
            <el-input v-model="domainInput" placeholder="example.com 或 *.example.com" @keyup.enter="addDomain">
              <template #append><el-button @click="addDomain">添加</el-button></template>
            </el-input>
            <div class="tag-list domain-tags">
              <el-tag v-for="domain in form.domains" :key="domain" closable @close="removeDomain(domain)">{{ domain }}</el-tag>
            </div>
          </div>
        </el-form-item>
        <el-form-item label="证书 PEM" required>
          <div class="pem-upload-block">
            <div class="pem-upload-actions">
              <el-button @click="chooseCertFile">选择证书文件</el-button>
              <span class="table-subtext">{{ certFileName || '支持 .pem / .crt / .cer，也可直接粘贴 PEM 内容' }}</span>
            </div>
            <input ref="certFileInput" class="hidden-file-input" type="file" accept=".pem,.crt,.cer,text/plain" @change="(event) => loadPemFile(event, 'cert')" />
            <el-input v-model="form.certPem" type="textarea" :rows="7" placeholder="-----BEGIN CERTIFICATE-----" />
          </div>
        </el-form-item>
        <el-form-item label="私钥 PEM">
          <div class="pem-upload-block">
            <div class="pem-upload-actions">
              <el-button @click="chooseKeyFile">选择私钥文件</el-button>
              <span class="table-subtext">{{ keyFileName || '支持 .pem / .key，也可直接粘贴 PEM 内容' }}</span>
            </div>
            <input ref="keyFileInput" class="hidden-file-input" type="file" accept=".pem,.key,text/plain" @change="(event) => loadPemFile(event, 'key')" />
            <el-input v-model="form.keyPem" type="textarea" :rows="7" placeholder="-----BEGIN PRIVATE KEY-----" />
          </div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="store.saving" @click="submitForm">保存</el-button>
      </template>
    </el-dialog>
  </section>
</template>

<style scoped>
.pem-upload-block {
  display: grid;
  gap: 8px;
  width: 100%;
}

.pem-upload-actions {
  align-items: center;
  display: flex;
  gap: 10px;
}

.hidden-file-input {
  display: none;
}
</style>
