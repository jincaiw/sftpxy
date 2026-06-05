<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><SettingsOutline /></n-icon>
        </div>
        <span>系统设置</span>
      </div>
    </div>

    <n-spin :show="loading">
      <div class="page-grid-2">
        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><ServerOutline /></n-icon>
              服务配置
            </span>
          </template>
          <n-form label-placement="left" label-width="120">
            <n-form-item label="SSH/SFTP">
              <n-switch v-model:value="config.ssh.enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
              <span class="port-hint">端口: {{ config.ssh.listen_port || 30082 }}</span>
            </n-form-item>
            <n-form-item label="FTP/FTPS">
              <n-switch v-model:value="config.ftp.enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
              <span class="port-hint">端口: {{ config.ftp.listen_port || 30086 }}</span>
            </n-form-item>
            <n-form-item label="WebDAV">
              <n-switch v-model:value="config.webdav.enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
              <span class="port-hint">端口: {{ config.webdav.listen_port || 30084 }}</span>
            </n-form-item>
            <n-form-item label="WebAdmin">
              <n-switch v-model:value="config.httpd.enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
              <span class="port-hint">端口: {{ config.httpd.listen_port || 30088 }}</span>
            </n-form-item>
            <n-form-item label="WebClient">
              <n-switch v-model:value="config.httpd.web_client_enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
              <span class="port-hint">端口: {{ config.httpd.client_listen_port || 30080 }}</span>
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingService" @click="saveSection('service')">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><GlobeOutline /></n-icon>
              显示设置
            </span>
          </template>
          <n-form label-placement="left" label-width="120">
            <n-form-item label="时区">
              <n-select
                v-model:value="currentTimezone"
                :options="timezoneOptions"
                filterable
                placeholder="选择时区"
                @update:value="handleTimezoneChange"
              />
            </n-form-item>
            <n-form-item label="当前时间">
              <span class="time-preview">{{ currentTimePreview }}</span>
            </n-form-item>
          </n-form>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><CloudDownloadOutline /></n-icon>
              存储配置
            </span>
          </template>
          <div class="page-info-grid">
            <div class="page-info-item">
              <span class="page-info-label">存储驱动</span>
              <span class="page-info-value">{{ config.data_provider.driver || 'sqlite' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">数据库状态</span>
              <span class="page-info-value">{{ health?.status || '--' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">SSL 模式</span>
              <span class="page-info-value">{{ config.data_provider.ssl_mode || '--' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">最大连接数</span>
              <span class="page-info-value">{{ config.data_provider.max_open_conns || '--' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">自动迁移</span>
              <span class="page-info-value">{{ config.data_provider.auto_migrate ? '已启用' : '未启用' }}</span>
            </div>
          </div>
        </n-card>
      </div>
    </n-spin>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-text depth="3" style="font-size: 13px">
        配置修改将在保存后即时生效。部分配置（如端口变更）可能需要重启服务才能完全生效。
      </n-text>
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, reactive } from 'vue'
import { useMessage } from 'naive-ui'
import { SettingsOutline, ServerOutline, ShieldOutline, GlobeOutline, CloudDownloadOutline } from '@vicons/ionicons5'
import { apiClient } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { getTimezone, setTimezone, getCommonTimezones } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const loading = ref(false)
const savingService = ref(false)
const savingSecurity = ref(false)
const health = ref<any>(null)

const currentTimezone = ref(getTimezone())
const timezoneOptions = getCommonTimezones()
const currentTimePreview = ref('')

const updateTimePreview = () => {
  try {
    currentTimePreview.value = new Date().toLocaleString('zh-CN', {
      timeZone: currentTimezone.value,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false
    })
  } catch {
    currentTimePreview.value = '--'
  }
}

const handleTimezoneChange = (tz: string) => {
  currentTimezone.value = tz
  setTimezone(tz)
  updateTimePreview()
  message.success('时区已更新')
}

const config = reactive({
  ssh: { enabled: false, listen_port: 30082 },
  ftp: { enabled: false, listen_port: 30086 },
  webdav: { enabled: false, listen_port: 30084 },
  httpd: { enabled: false, listen_port: 30088, client_listen_port: 30080, web_client_enabled: true },
  mfa: { enabled: false, force_for_admins: false, force_for_users: false },
  data_provider: { driver: 'sqlite', ssl_mode: '', max_open_conns: 0, auto_migrate: false }
})

const fetchSettings = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    const [configData, healthData] = await Promise.all([
      token ? apiClient.getConfig(token) : Promise.resolve(null),
      apiClient.getHealth()
    ])
    health.value = healthData
    if (configData) {
      if (configData.ssh) Object.assign(config.ssh, configData.ssh)
      if (configData.ftp) Object.assign(config.ftp, configData.ftp)
      if (configData.webdav) Object.assign(config.webdav, configData.webdav)
      if (configData.httpd) Object.assign(config.httpd, configData.httpd)
      if (configData.mfa) Object.assign(config.mfa, configData.mfa)
      if (configData.data_provider) Object.assign(config.data_provider, configData.data_provider)
    }
  } catch (error: any) {
    message.error('获取系统配置失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const saveSection = async (section: string) => {
  const token = authStore.adminToken
  if (!token) return

  const savingRef = section === 'service' ? savingService : savingSecurity
  savingRef.value = true
  try {
    let partial: any = {}
    if (section === 'service') {
      partial = {
        ssh: { enabled: config.ssh.enabled, listen_port: config.ssh.listen_port },
        ftp: { enabled: config.ftp.enabled, listen_port: config.ftp.listen_port },
        webdav: { enabled: config.webdav.enabled, listen_port: config.webdav.listen_port },
        httpd: { enabled: config.httpd.enabled, listen_port: config.httpd.listen_port, web_client_enabled: config.httpd.web_client_enabled, client_listen_port: config.httpd.client_listen_port }
      }
    }
    await apiClient.updateConfig(token, partial)
    message.success('配置已保存')
  } catch (error: any) {
    message.error('保存配置失败: ' + error.message)
  } finally {
    savingRef.value = false
  }
}

let previewTimer: number | null = null

onMounted(() => {
  fetchSettings()
  updateTimePreview()
  previewTimer = window.setInterval(updateTimePreview, 1000)
})

onUnmounted(() => {
  if (previewTimer) clearInterval(previewTimer)
})
</script>

<style scoped>
.port-hint {
  margin-left: 12px;
  color: var(--n-text-color-disabled);
  font-size: 13px;
}

.time-preview {
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  font-size: 14px;
  color: var(--n-text-color);
}
</style>
