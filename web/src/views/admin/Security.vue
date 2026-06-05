<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><LockClosedOutline /></n-icon>
        </div>
        <span>安全策略</span>
      </div>
    </div>

    <n-spin :show="loading">
      <div class="page-grid-2">
        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><ShieldOutline /></n-icon>
              MFA 认证
            </span>
          </template>
          <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '120'">
            <n-form-item label="启用 MFA">
              <n-switch v-model:value="mfa.enabled">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
            </n-form-item>
            <n-form-item label="TOTP Issuer">
              <n-input v-model:value="mfa.issuer" placeholder="SFTPxy" />
            </n-form-item>
            <n-form-item label="强制管理员 MFA">
              <n-switch v-model:value="mfa.force_for_admins">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
            </n-form-item>
            <n-form-item label="强制用户 MFA">
              <n-switch v-model:value="mfa.force_for_users">
                <template #checked>已启用</template>
                <template #unchecked>已禁用</template>
              </n-switch>
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingMfa" @click="saveMfa">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><KeyOutline /></n-icon>
              密码策略
            </span>
          </template>
          <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '120'">
            <n-form-item label="最小长度">
              <n-input-number v-model:value="passwordPolicy.min_length" :min="6" :max="128" style="width: 100%" />
            </n-form-item>
            <n-form-item label="大写字母">
              <n-switch v-model:value="passwordPolicy.require_uppercase" />
            </n-form-item>
            <n-form-item label="小写字母">
              <n-switch v-model:value="passwordPolicy.require_lowercase" />
            </n-form-item>
            <n-form-item label="数字">
              <n-switch v-model:value="passwordPolicy.require_digit" />
            </n-form-item>
            <n-form-item label="特殊字符">
              <n-switch v-model:value="passwordPolicy.require_special" />
            </n-form-item>
            <n-form-item label="禁止用户名">
              <n-switch v-model:value="passwordPolicy.disallow_username" />
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingPassword" @click="savePasswordPolicy">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><FilterOutline /></n-icon>
              IP 过滤
            </span>
          </template>
          <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '120'">
            <n-form-item label="允许列表">
              <n-input
                v-model:value="ipFilter.allow_list"
                type="textarea"
                placeholder="每行一个 IP 或 CIDR"
                :autosize="{ minRows: 3, maxRows: 8 }"
              />
            </n-form-item>
            <n-form-item label="拒绝列表">
              <n-input
                v-model:value="ipFilter.deny_list"
                type="textarea"
                placeholder="每行一个 IP 或 CIDR"
                :autosize="{ minRows: 3, maxRows: 8 }"
              />
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingIpFilter" @click="saveIpFilter">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><BugOutline /></n-icon>
              防暴力破解
            </span>
          </template>
          <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '120'">
            <n-form-item label="最大失败次数">
              <n-input-number v-model:value="defender.max_failures" :min="1" :max="100" style="width: 100%" />
            </n-form-item>
            <n-form-item label="封禁时长(分钟)">
              <n-input-number v-model:value="defender.ban_duration" :min="1" :max="1440" style="width: 100%" />
            </n-form-item>
            <n-form-item label="观察窗口(分钟)">
              <n-input-number v-model:value="defender.observation_window" :min="1" :max="60" style="width: 100%" />
            </n-form-item>
            <n-form-item label="白名单">
              <n-input
                v-model:value="defender.whitelist"
                type="textarea"
                placeholder="每行一个 IP 或 CIDR"
                :autosize="{ minRows: 2, maxRows: 6 }"
              />
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingDefender" @click="saveDefender">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><GlobeOutline /></n-icon>
              Geo-IP 设置
            </span>
          </template>
          <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '120'">
            <n-form-item label="启用 Geo-IP">
              <n-switch v-model:value="geoIp.enabled" />
            </n-form-item>
            <n-form-item label="数据库路径">
              <n-input v-model:value="geoIp.database_path" placeholder="/var/lib/geoip/GeoLite2-Country.mmdb" />
            </n-form-item>
            <n-form-item label="允许的国家">
              <n-input
                v-model:value="geoIp.allowed_countries"
                type="textarea"
                placeholder="每行一个国家代码，如 CN, US, JP"
                :autosize="{ minRows: 2, maxRows: 6 }"
              />
            </n-form-item>
            <n-form-item label="拒绝的国家">
              <n-input
                v-model:value="geoIp.denied_countries"
                type="textarea"
                placeholder="每行一个国家代码"
                :autosize="{ minRows: 2, maxRows: 6 }"
              />
            </n-form-item>
          </n-form>
          <template #action>
            <n-space justify="end">
              <n-button type="primary" :loading="savingGeoIp" @click="saveGeoIp">保存</n-button>
            </n-space>
          </template>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><CloseCircleOutline /></n-icon>
              已封禁 IP
            </span>
          </template>
          <n-data-table
            :columns="blockedColumns"
            :data="blockedIPs"
            :loading="loadingBlocked"
            size="small"
            :scroll-x="600"
            :max-height="300"
          />
        </n-card>
      </div>
    </n-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, h, onMounted, onUnmounted } from 'vue'
import { useMessage, NButton, NTag } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { RefreshOutline, LockClosedOutline, ShieldOutline, KeyOutline, FilterOutline, BugOutline, GlobeOutline, CloseCircleOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { BlockedIP } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const loading = ref(false)
const savingMfa = ref(false)
const savingIpFilter = ref(false)
const savingDefender = ref(false)
const savingPassword = ref(false)
const savingGeoIp = ref(false)
const loadingBlocked = ref(false)
const blockedIPs = ref<BlockedIP[]>([])

const mfa = reactive({
  enabled: false,
  issuer: 'SFTPxy',
  force_for_admins: false,
  force_for_users: false
})

const ipFilter = reactive({
  allow_list: '',
  deny_list: ''
})

const defender = reactive({
  max_failures: 5,
  ban_duration: 30,
  observation_window: 10,
  whitelist: ''
})

const passwordPolicy = reactive({
  min_length: 8,
  require_uppercase: false,
  require_lowercase: false,
  require_digit: false,
  require_special: false,
  disallow_username: true
})

const geoIp = reactive({
  enabled: false,
  database_path: '',
  allowed_countries: '',
  denied_countries: ''
})

const blockedColumns: DataTableColumns<BlockedIP> = [
  { title: 'IP 地址', key: 'ip', width: 130 },
  { title: '协议', key: 'protocol', width: 60 },
  { title: '原因', key: 'reason', ellipsis: { tooltip: true } },
  { title: '封禁时间', key: 'blocked_at', width: 150, render: (row) => formatTime(row.blocked_at) },
  {
    title: '状态',
    key: 'is_active',
    width: 70,
    render: (row) => h(
      NTag,
      { size: 'small', type: row.is_active ? 'error' : 'default' },
      { default: () => row.is_active ? '封禁' : '过期' }
    )
  },
  {
    title: '操作',
    key: 'actions',
    width: 60,
    render: (row) => h(
      NButton,
      { size: 'tiny', type: 'warning', onClick: () => handleUnblock(row) },
      { default: () => '解封' }
    )
  }
]

const fetchConfig = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const config = await apiClient.getConfig(token)
      const mfaConfig = config.mfa || {}
      if (mfaConfig) {
        mfa.enabled = !!mfaConfig.enabled
        mfa.issuer = mfaConfig.issuer || 'SFTPxy'
        mfa.force_for_admins = !!mfaConfig.force_for_admins
        mfa.force_for_users = !!mfaConfig.force_for_users
      }
      const auth = config.auth || {}
      if (auth.password_policy) {
        passwordPolicy.min_length = auth.password_policy.min_length || 8
        passwordPolicy.require_uppercase = !!auth.password_policy.require_uppercase
        passwordPolicy.require_lowercase = !!auth.password_policy.require_lowercase
        passwordPolicy.require_digit = !!auth.password_policy.require_digit
        passwordPolicy.require_special = !!auth.password_policy.require_special
        passwordPolicy.disallow_username = auth.password_policy.disallow_username !== false
      }
      if (auth.geoip) {
        geoIp.enabled = !!auth.geoip.enabled
        geoIp.database_path = auth.geoip.database_path || ''
        geoIp.allowed_countries = (auth.geoip.allowed_countries || []).join('\n')
        geoIp.denied_countries = (auth.geoip.denied_countries || []).join('\n')
      }
      if (auth.ip_filter) {
        ipFilter.allow_list = (auth.ip_filter.allow_list || []).join('\n')
        ipFilter.deny_list = (auth.ip_filter.deny_list || []).join('\n')
      }
      if (config.defender) {
        defender.max_failures = config.defender.max_failures || 5
        defender.ban_duration = config.defender.ban_duration || 30
        defender.observation_window = config.defender.observation_window || 10
        defender.whitelist = (config.defender.whitelist || []).join('\n')
      }
    }
  } catch (error: any) {
    message.error('获取安全配置失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const fetchBlockedIPs = async () => {
  loadingBlocked.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      blockedIPs.value = (await apiClient.listBlockedIPs(token)).items
    }
  } catch (error: any) {
    message.error('获取封禁 IP 列表失败: ' + error.message)
  } finally {
    loadingBlocked.value = false
  }
}

const handleUnblock = async (item: BlockedIP) => {
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.unblockIP(token, item.ip)
      message.success(`IP ${item.ip} 已解封`)
      await fetchBlockedIPs()
    }
  } catch (error: any) {
    message.error('解封失败: ' + error.message)
  }
}

const splitLines = (text: string): string[] =>
  text.split('\n').map((l) => l.trim()).filter(Boolean)

const saveMfa = async () => {
  savingMfa.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.updateConfig(token, { mfa: { ...mfa } })
      message.success('MFA 设置已保存')
    }
  } catch (error: any) {
    message.error('保存 MFA 设置失败: ' + error.message)
  } finally {
    savingMfa.value = false
  }
}

const saveIpFilter = async () => {
  savingIpFilter.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.updateConfig(token, {
        auth: { ip_filter: { allow_list: splitLines(ipFilter.allow_list), deny_list: splitLines(ipFilter.deny_list) } }
      })
      message.success('IP 过滤设置已保存')
    }
  } catch (error: any) {
    message.error('保存 IP 过滤设置失败: ' + error.message)
  } finally {
    savingIpFilter.value = false
  }
}

const saveDefender = async () => {
  savingDefender.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.updateConfig(token, {
        defender: {
          max_failures: defender.max_failures,
          ban_duration: defender.ban_duration,
          observation_window: defender.observation_window,
          whitelist: splitLines(defender.whitelist)
        }
      })
      message.success('防暴力破解设置已保存')
    }
  } catch (error: any) {
    message.error('保存防暴力破解设置失败: ' + error.message)
  } finally {
    savingDefender.value = false
  }
}

const savePasswordPolicy = async () => {
  savingPassword.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.updateConfig(token, { auth: { password_policy: { ...passwordPolicy } } })
      message.success('密码策略已保存')
    }
  } catch (error: any) {
    message.error('保存密码策略失败: ' + error.message)
  } finally {
    savingPassword.value = false
  }
}

const saveGeoIp = async () => {
  savingGeoIp.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.updateConfig(token, {
        auth: {
          geoip: {
            enabled: geoIp.enabled,
            database_path: geoIp.database_path,
            allowed_countries: splitLines(geoIp.allowed_countries),
            denied_countries: splitLines(geoIp.denied_countries)
          }
        }
      })
      message.success('Geo-IP 设置已保存')
    }
  } catch (error: any) {
    message.error('保存 Geo-IP 设置失败: ' + error.message)
  } finally {
    savingGeoIp.value = false
  }
}

onMounted(async () => {
  await fetchConfig()
  await fetchBlockedIPs()
})
</script>
