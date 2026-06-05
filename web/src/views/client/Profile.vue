<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><PersonOutline /></n-icon>
        </div>
        <span>个人资料</span>
      </div>
    </div>

    <div class="page-grid-2">
      <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-profile-basic">
        <template #header>
          <span class="page-section-title">
            <n-icon><PersonOutline /></n-icon>
            基本信息
          </span>
        </template>
        <n-spin :show="loading">
          <div class="page-info-grid">
            <div class="page-info-item">
              <span class="page-info-label">用户名</span>
              <span class="page-info-value">{{ profile?.username || authStore.clientUser?.username || '--' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">状态</span>
              <n-tag :type="profile?.status === 'active' ? 'success' : 'warning'">
                {{ profile?.status || authStore.clientUser?.status || '--' }}
              </n-tag>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">主目录</span>
              <span class="page-info-value">{{ profile?.home_directory || '--' }}</span>
            </div>
            <div class="page-info-item">
              <span class="page-info-label">创建时间</span>
              <span class="page-info-value">{{ formatTime(profile?.created_at) }}</span>
            </div>
          </div>
        </n-spin>
      </n-card>

      <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-profile-quota">
        <template #header>
          <span class="page-section-title">
            <n-icon><CloudOutline /></n-icon>
            存储配额
          </span>
        </template>
        <n-spin :show="quotaLoading">
          <template v-if="quota">
            <n-space vertical :size="12">
              <div>
                <div style="margin-bottom: 4px; font-size: 13px; color: var(--n-text-color-2)">
                  存储空间：{{ formatBytes(quota.bytes_used) }} / {{ quota.bytes_total > 0 ? formatBytes(quota.bytes_total) : '无限制' }}
                </div>
                <n-progress
                  type="line"
                  :percentage="quota.bytes_total > 0 ? Math.round(quota.bytes_used / quota.bytes_total * 100) : 0"
                  :indicator-placement="'inside'"
                  :status="quota.bytes_total > 0 && quota.bytes_used / quota.bytes_total > 0.9 ? 'error' : 'info'"
                />
              </div>
              <div>
                <div style="margin-bottom: 4px; font-size: 13px; color: var(--n-text-color-2)">
                  文件数量：{{ quota.files_used }} / {{ quota.files_total > 0 ? quota.files_total : '无限制' }}
                </div>
                <n-progress
                  type="line"
                  :percentage="quota.files_total > 0 ? Math.round(quota.files_used / quota.files_total * 100) : 0"
                  :indicator-placement="'inside'"
                  :status="quota.files_total > 0 && quota.files_used / quota.files_total > 0.9 ? 'error' : 'info'"
                />
              </div>
            </n-space>
          </template>
          <n-empty v-else description="暂无配额信息" />
        </n-spin>
      </n-card>

      <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-profile-keys">
        <template #header>
          <span class="page-section-title">
            <n-icon><KeyOutline /></n-icon>
            SSH 公钥
          </span>
        </template>
        <template #header-extra>
          <n-button size="small" type="primary" data-testid="client-add-key-btn" @click="showAddKeyModal = true">
            添加公钥
          </n-button>
        </template>
        <n-data-table :columns="keyColumns" :data="publicKeys" size="small" :loading="keysLoading" />
      </n-card>

      <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-profile-mfa">
        <template #header>
          <span class="page-section-title">
            <n-icon><ShieldCheckmarkOutline /></n-icon>
            两步验证 (MFA)
          </span>
        </template>
        <template v-if="profile?.mfa_enabled">
          <n-space vertical align="center" :size="12">
            <n-tag type="success" size="large">MFA 已启用</n-tag>
            <n-button type="error" data-testid="client-mfa-disable-btn" @click="showDisableMfaModal = true">
              禁用 MFA
            </n-button>
          </n-space>
        </template>
        <template v-else>
          <n-space vertical align="center" :size="12">
            <n-tag type="warning" size="large">MFA 未启用</n-tag>
            <n-button type="primary" :loading="mfaSetupLoading" data-testid="client-mfa-enable-btn" @click="handleSetupMFA">
              启用 MFA
            </n-button>
          </n-space>
        </template>

        <n-modal
          v-model:show="showMfaSetupModal"
          preset="card"
          title="设置两步验证"
          style="width: 480px"
        >
          <n-spin :show="mfaVerifying">
            <n-space vertical :size="16">
              <div v-if="mfaSetupData" style="text-align: center">
                <img :src="mfaSetupData.qr_url" alt="QR Code" style="max-width: 200px; margin: 0 auto" />
                <div style="margin-top: 8px; font-size: 13px; color: var(--n-text-color-2)">
                  手动输入密钥：<code style="user-select: all">{{ mfaSetupData.secret }}</code>
                </div>
              </div>
              <n-form-item label="验证码">
                <n-input
                  v-model:value="mfaVerifyCode"
                  placeholder="请输入 TOTP 验证码"
                  maxlength="6"
                  :input-props="{ 'data-testid': 'client-mfa-verify-code' }"
                  @keyup.enter="handleVerifyMFA"
                />
              </n-form-item>
            </n-space>
          </n-spin>
          <template #footer>
            <n-space justify="end">
              <n-button @click="showMfaSetupModal = false">取消</n-button>
              <n-button type="primary" :loading="mfaVerifying" :disabled="!mfaVerifyCode" data-testid="client-mfa-verify-btn" @click="handleVerifyMFA">
                验证并启用
              </n-button>
            </n-space>
          </template>
        </n-modal>

        <n-modal
          v-model:show="showMfaRecoveryModal"
          preset="card"
          title="恢复码"
          style="width: 480px"
        >
          <n-alert type="warning" style="margin-bottom: 12px">
            请妥善保存以下恢复码，丢失后将无法恢复账户访问。
          </n-alert>
          <n-input
            type="textarea"
            :value="mfaRecoveryCodes.join('\n')"
            readonly
            :rows="6"
          />
          <template #footer>
            <n-space justify="end">
              <n-button @click="handleCopyRecoveryCodes">复制恢复码</n-button>
              <n-button type="primary" @click="showMfaRecoveryModal = false">我已保存</n-button>
            </n-space>
          </template>
        </n-modal>
      </n-card>

      <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-password-card">
        <template #header>
          <span class="page-section-title">
            <n-icon><LockClosedOutline /></n-icon>
            修改密码
          </span>
        </template>
        <n-form
          ref="passwordFormRef"
          :model="passwordForm"
          :rules="passwordRules"
          label-placement="left"
          label-width="80"
          data-testid="client-password-form"
        >
          <n-form-item label="当前密码" path="currentPassword">
            <n-input
              v-model:value="passwordForm.currentPassword"
              type="password"
              show-password-on="click"
              placeholder="请输入当前密码"
              :input-props="{ 'data-testid': 'client-password-current' }"
            />
          </n-form-item>
          <n-form-item label="新密码" path="newPassword">
            <n-input
              v-model:value="passwordForm.newPassword"
              type="password"
              show-password-on="click"
              placeholder="请输入新密码"
              :input-props="{ 'data-testid': 'client-password-new' }"
            />
          </n-form-item>
          <n-form-item label="确认密码" path="confirmPassword">
            <n-input
              v-model:value="passwordForm.confirmPassword"
              type="password"
              show-password-on="click"
              placeholder="请再次输入新密码"
              :input-props="{ 'data-testid': 'client-password-confirm' }"
            />
          </n-form-item>
        </n-form>
        <template #footer>
          <n-space justify="end">
            <n-button type="primary" :loading="passwordChanging" data-testid="client-password-submit" @click="handlePasswordChange">
              修改密码
            </n-button>
          </n-space>
        </template>
      </n-card>
    </div>

    <n-modal
      v-model:show="showAddKeyModal"
      preset="card"
      title="添加 SSH 公钥"
      style="width: 480px"
    >
      <n-form-item label="名称">
        <n-input
          v-model:value="addKeyForm.label"
          placeholder="可选，为此公钥设置名称"
          :input-props="{ 'data-testid': 'client-add-key-label' }"
        />
      </n-form-item>
      <n-form-item label="公钥内容">
        <n-input
          v-model:value="addKeyForm.publicKey"
          type="textarea"
          placeholder="粘贴 SSH 公钥内容（以 ssh-rsa / ssh-ed25519 等开头）"
          :rows="5"
          :input-props="{ 'data-testid': 'client-add-key-content' }"
        />
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="client-add-key-cancel" @click="showAddKeyModal = false">取消</n-button>
          <n-button type="primary" :loading="addKeyLoading" :disabled="!addKeyForm.publicKey" data-testid="client-add-key-submit" @click="handleAddKey">
            添加
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal
      v-model:show="showDisableMfaModal"
      preset="card"
      title="禁用 MFA"
      style="width: 400px"
    >
      <n-form-item label="当前密码">
        <n-input
          v-model:value="disableMfaPassword"
          type="password"
          show-password-on="click"
          placeholder="请输入当前密码以确认"
          :input-props="{ 'data-testid': 'client-mfa-disable-password' }"
        />
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showDisableMfaModal = false">取消</n-button>
          <n-button type="error" :loading="disableMfaLoading" :disabled="!disableMfaPassword" data-testid="client-mfa-disable-confirm" @click="handleDisableMFA">
            确认禁用
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteKeyConfirm"
      title="确认删除"
      :content="`确定要删除公钥「${deletingKey?.label || deletingKey?.fingerprint || ''}」吗？`"
      @confirm="handleDeleteKey"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, h } from 'vue'
import { useMessage, NButton, NIcon, NSpace } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { TrashOutline, PersonOutline, LockClosedOutline, KeyOutline, ShieldCheckmarkOutline, CloudOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { apiClient } from '@/api/client'
import type { ClientProfile, PublicKeyItem, QuotaInfo, MFASetupResponse } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const loading = ref(false)
const passwordChanging = ref(false)
const passwordFormRef = ref<FormInst | null>(null)
const profile = ref<ClientProfile | null>(null)

const publicKeys = ref<PublicKeyItem[]>([])
const keysLoading = ref(false)
const showAddKeyModal = ref(false)
const addKeyLoading = ref(false)
const addKeyForm = reactive({
  label: '',
  publicKey: ''
})
const showDeleteKeyConfirm = ref(false)
const deletingKey = ref<PublicKeyItem | null>(null)

const quota = ref<QuotaInfo | null>(null)
const quotaLoading = ref(false)

const mfaSetupLoading = ref(false)
const showMfaSetupModal = ref(false)
const mfaSetupData = ref<MFASetupResponse | null>(null)
const mfaVerifyCode = ref('')
const mfaVerifying = ref(false)
const showMfaRecoveryModal = ref(false)
const mfaRecoveryCodes = ref<string[]>([])
const showDisableMfaModal = ref(false)
const disableMfaPassword = ref('')
const disableMfaLoading = ref(false)

const passwordForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: ''
})

const passwordRules = {
  currentPassword: { required: true, message: '请输入当前密码', trigger: 'blur' },
  newPassword: { required: true, message: '请输入新密码', trigger: 'blur', min: 6 },
  confirmPassword: {
    required: true,
    message: '请再次输入新密码',
    trigger: 'blur',
    validator: (_rule: unknown, value: string) => {
      if (value !== passwordForm.newPassword) {
        return new Error('两次输入的密码不一致')
      }
      return true
    }
  }
}

const keyColumns: DataTableColumns<PublicKeyItem> = [
  { title: '名称', key: 'label' },
  { title: '指纹', key: 'fingerprint', ellipsis: { tooltip: true }, render: (row) => row.fingerprint || 'N/A' },
  { title: '添加时间', key: 'created_at', width: 180, render: (row) => formatTime(row.created_at) },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    render: (row) => h(
      NButton,
      {
        size: 'small',
        type: 'error',
        quaternary: true,
        'data-testid': `client-delete-key-${row.id}`,
        onClick: () => handleDeleteKeyClick(row)
      },
      {
        icon: () => h(NIcon, null, { default: () => h(TrashOutline) })
      }
    )
  }
]

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

const fetchProfile = async () => {
  const token = authStore.clientToken
  if (!token) return

  loading.value = true
  try {
    profile.value = await apiClient.getClientProfile(token)
    authStore.clientUser = {
      ...authStore.clientUser,
      id: profile.value.id,
      username: profile.value.username,
      status: profile.value.status
    }
    fetchPublicKeys()
  } catch (error: any) {
    message.error('获取个人资料失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const fetchPublicKeys = () => {
  publicKeys.value = (Array.isArray(profile.value?.public_keys) ? profile.value.public_keys : []) as PublicKeyItem[]
}

const handleAddKey = async () => {
  const token = authStore.clientToken
  if (!token || !addKeyForm.publicKey) return

  addKeyLoading.value = true
  try {
    await apiClient.addPublicKey(token, {
      public_key: addKeyForm.publicKey,
      label: addKeyForm.label || undefined
    })
    message.success('公钥添加成功')
    showAddKeyModal.value = false
    addKeyForm.label = ''
    addKeyForm.publicKey = ''
    await fetchProfile()
  } catch (error: any) {
    message.error('添加公钥失败: ' + error.message)
  } finally {
    addKeyLoading.value = false
  }
}

const handleDeleteKeyClick = (row: PublicKeyItem) => {
  deletingKey.value = row
  showDeleteKeyConfirm.value = true
}

const handleDeleteKey = async () => {
  const token = authStore.clientToken
  if (!token || !deletingKey.value) return

  try {
    await apiClient.removePublicKey(token, deletingKey.value.id)
    message.success('公钥已删除')
    await fetchProfile()
  } catch (error: any) {
    message.error('删除公钥失败: ' + error.message)
  }
}

const fetchQuota = async () => {
  const token = authStore.clientToken
  if (!token) return

  quotaLoading.value = true
  try {
    quota.value = await apiClient.getOwnQuota(token)
  } catch (error: any) {
    message.error('获取配额信息失败: ' + error.message)
  } finally {
    quotaLoading.value = false
  }
}

const handleSetupMFA = async () => {
  const token = authStore.clientToken
  if (!token) return

  mfaSetupLoading.value = true
  try {
    mfaSetupData.value = await apiClient.setupMFA(token)
    mfaVerifyCode.value = ''
    showMfaSetupModal.value = true
  } catch (error: any) {
    message.error('MFA 设置失败: ' + error.message)
  } finally {
    mfaSetupLoading.value = false
  }
}

const handleVerifyMFA = async () => {
  const token = authStore.clientToken
  if (!token || !mfaVerifyCode.value) return

  mfaVerifying.value = true
  try {
    const result = await apiClient.verifyMFA(token, mfaVerifyCode.value)
    showMfaSetupModal.value = false
    mfaRecoveryCodes.value = result.recovery_codes || []
    showMfaRecoveryModal.value = true
    message.success('MFA 启用成功')
    await fetchProfile()
  } catch (error: any) {
    message.error('验证失败: ' + error.message)
  } finally {
    mfaVerifying.value = false
  }
}

const handleDisableMFA = async () => {
  const token = authStore.clientToken
  if (!token || !disableMfaPassword.value) return

  disableMfaLoading.value = true
  try {
    await apiClient.disableMFA(token, disableMfaPassword.value)
    message.success('MFA 已禁用')
    showDisableMfaModal.value = false
    disableMfaPassword.value = ''
    await fetchProfile()
  } catch (error: any) {
    message.error('禁用 MFA 失败: ' + error.message)
  } finally {
    disableMfaLoading.value = false
  }
}

const handleCopyRecoveryCodes = async () => {
  try {
    await navigator.clipboard.writeText(mfaRecoveryCodes.value.join('\n'))
    message.success('恢复码已复制')
  } catch (_error) {
    message.info('复制失败，请手动复制')
  }
}

const handlePasswordChange = async () => {
  if (!passwordFormRef.value) return

  const token = authStore.clientToken
  if (!token) return

  passwordChanging.value = true
  try {
    await passwordFormRef.value.validate()
    await apiClient.changeClientPassword(token, passwordForm.currentPassword, passwordForm.newPassword)
    message.success('密码修改成功，请使用新密码重新登录')
    passwordForm.currentPassword = ''
    passwordForm.newPassword = ''
    passwordForm.confirmPassword = ''
  } catch (error: any) {
    message.error('密码修改失败: ' + error.message)
  } finally {
    passwordChanging.value = false
  }
}

onMounted(() => {
  fetchProfile()
  fetchQuota()
})
</script>
