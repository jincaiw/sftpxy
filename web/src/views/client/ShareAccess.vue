<template>
  <div class="auth-page">
    <div class="share-center">
      <n-card class="auth-card share-card" :bordered="false" v-if="!loading && !error">
        <div class="share-brand">
          <div class="share-brand__icon">
            <n-icon :size="28">
              <DocumentTextOutline v-if="shareInfo?.share_type === 'download'" />
              <CloudUploadOutline v-else-if="shareInfo?.share_type === 'upload'" />
              <SwapHorizontalOutline v-else />
            </n-icon>
          </div>
          <span class="share-brand__name">SFTPxy</span>
        </div>
        <h1 class="share-heading">
          {{ shareInfo?.share_type === 'upload' ? '文件上传' : '文件下载' }}
        </h1>
        <p class="share-desc">通过分享链接安全传输文件</p>

        <div class="password-section" v-if="needPassword && !shareInfo">
          <n-input
            v-model:value="password"
            type="password"
            show-password-on="click"
            placeholder="请输入分享密码"
            @keyup.enter="accessWithPassword"
          />
          <n-button type="primary" block @click="accessWithPassword" :loading="accessing">
            验证密码
          </n-button>
        </div>

        <div class="share-body" v-if="shareInfo">
          <div class="share-info-grid">
            <div class="share-info-item share-info-item--full">
              <span class="share-info-label">文件路径</span>
              <span class="share-info-value share-info-path">{{ shareInfo.path }}</span>
            </div>
            <div class="share-info-item" v-if="shareInfo.share_type === 'download'">
              <span class="share-info-label">已下载</span>
              <span class="share-info-value">{{ shareInfo.download_count || 0 }} 次</span>
            </div>
            <div class="share-info-item" v-if="shareInfo.share_type === 'upload'">
              <span class="share-info-label">已上传</span>
              <span class="share-info-value">{{ shareInfo.upload_count || 0 }} 次</span>
            </div>
            <div class="share-info-item" v-if="shareInfo.max_downloads">
              <span class="share-info-label">最大下载次数</span>
              <span class="share-info-value">{{ shareInfo.max_downloads }}</span>
            </div>
            <div class="share-info-item" v-if="shareInfo.max_uploads">
              <span class="share-info-label">最大上传次数</span>
              <span class="share-info-value">{{ shareInfo.max_uploads }}</span>
            </div>
            <div class="share-info-item" v-if="shareInfo.expires_at">
              <span class="share-info-label">过期时间</span>
              <span class="share-info-value">{{ formatTime(shareInfo.expires_at) }}</span>
            </div>
            <div class="share-info-item">
              <span class="share-info-label">分享者</span>
              <span class="share-info-value">{{ shareInfo.username }}</span>
            </div>
          </div>

          <div class="share-actions" v-if="shareInfo && !needPassword">
            <n-button
              v-if="shareInfo.share_type === 'download' || shareInfo.share_type === 'both'"
              type="primary"
              size="large"
              block
              @click="handleDownload"
              :loading="downloading"
            >
              <template #icon><n-icon><CloudDownloadOutline /></n-icon></template>
              下载文件
            </n-button>
            <n-button
              v-if="shareInfo.share_type === 'upload' || shareInfo.share_type === 'both'"
              type="primary"
              size="large"
              block
              ghost
              @click="showUploadModal = true"
            >
              <template #icon><n-icon><CloudUploadOutline /></n-icon></template>
              上传文件
            </n-button>
          </div>
        </div>
      </n-card>

      <n-card class="auth-card share-card share-card--error" :bordered="false" v-if="error">
        <div class="share-brand">
          <div class="share-brand__icon share-brand__icon--error">
            <n-icon :size="28"><CloseCircleOutline /></n-icon>
          </div>
          <span class="share-brand__name">SFTPxy</span>
        </div>
        <h1 class="share-heading">无法访问</h1>
        <p class="share-desc share-desc--error">{{ error }}</p>
      </n-card>

      <n-card class="auth-card share-card share-card--loading" :bordered="false" v-if="loading">
        <div class="share-brand">
          <n-spin size="large" />
        </div>
        <h1 class="share-heading" style="margin-top: 16px">正在加载分享信息...</h1>
      </n-card>
    </div>

    <n-modal v-model:show="showUploadModal" preset="card" title="上传文件" style="max-width: 500px">
      <n-upload
        :action="uploadUrl"
        :headers="uploadHeaders"
        :data="uploadData"
        multiple
        @finish="handleUploadFinish"
        @error="handleUploadError"
      >
        <n-upload-dragger>
          <div style="padding: 20px">
            <n-icon :size="40" style="color: var(--app-text-tertiary)"><CloudUploadOutline /></n-icon>
            <p style="margin-top: 8px; color: var(--app-text-tertiary)">点击或拖拽文件到此区域上传</p>
          </div>
        </n-upload-dragger>
      </n-upload>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useMessage } from 'naive-ui'
import {
  DocumentTextOutline,
  CloudUploadOutline,
  CloudDownloadOutline,
  SwapHorizontalOutline,
  CloseCircleOutline
} from '@vicons/ionicons5'
import { apiClient } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const route = useRoute()
const message = useMessage()

const shareToken = computed(() => route.params.token as string)
const loading = ref(true)
const accessing = ref(false)
const downloading = ref(false)
const error = ref('')
const password = ref('')
const needPassword = ref(false)
const showUploadModal = ref(false)
const shareInfo = ref<any>(null)

const uploadUrl = computed(() => `/api/v1/shares/upload/${shareToken.value}`)
const uploadHeaders = computed(() => ({}))
const uploadData = computed(() => ({}))

const fetchShareInfo = async () => {
  loading.value = true
  error.value = ''
  try {
    const data = await apiClient.accessShare(shareToken.value)
    shareInfo.value = data
  } catch (err: any) {
    const msg = err?.message || '获取分享信息失败'
    if (msg.includes('password') || msg.includes('密码')) {
      needPassword.value = true
    } else {
      error.value = msg
    }
  } finally {
    loading.value = false
  }
}

const accessWithPassword = async () => {
  if (!password.value) return
  accessing.value = true
  try {
    const data = await apiClient.accessShare(shareToken.value, password.value)
    shareInfo.value = data
    needPassword.value = false
  } catch (err: any) {
    message.error(err?.message || '密码验证失败')
  } finally {
    accessing.value = false
  }
}

const handleDownload = async () => {
  downloading.value = true
  try {
    const params = new URLSearchParams()
    if (password.value) params.set('password', password.value)
    const baseUrl = window.location.origin
    window.open(`${baseUrl}/api/v1/shares/download/${shareToken.value}?${params.toString()}`, '_blank')
  } finally {
    downloading.value = false
  }
}

const handleUploadFinish = () => {
  message.success('上传成功')
  showUploadModal.value = false
  fetchShareInfo()
}

const handleUploadError = () => {
  message.error('上传失败')
}

onMounted(fetchShareInfo)
</script>

<style scoped>
.share-center {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 460px;
}

.share-card {
  animation: card-in 0.5s cubic-bezier(0.16, 1, 0.3, 1);
}

.share-card :deep(.n-card__content) {
  padding: 44px 40px !important;
}

.share-brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
}

.share-brand__icon {
  width: 64px;
  height: 64px;
  display: grid;
  place-items: center;
  border-radius: 20px;
  color: #eff6ff;
  background: linear-gradient(135deg, var(--app-accent) 0%, #06b6d4 100%);
  box-shadow: 0 14px 32px rgba(37, 99, 235, 0.25);
}

.share-brand__icon--error {
  background: linear-gradient(135deg, #ef4444 0%, #f97316 100%);
  box-shadow: 0 14px 32px rgba(239, 68, 68, 0.25);
}

.share-brand__name {
  font-size: 20px;
  font-weight: 800;
  color: var(--app-text-primary);
  letter-spacing: 0.04em;
}

.share-heading {
  margin: 16px 0 0;
  text-align: center;
  font-size: 24px;
  font-weight: 700;
  color: var(--app-text-primary);
  line-height: 1.3;
}

.share-desc {
  margin: 8px 0 0;
  text-align: center;
  font-size: 14px;
  color: var(--app-text-secondary);
  line-height: 1.6;
}

.share-desc--error {
  color: #ef4444;
}

.share-body {
  margin-top: 32px;
}

.share-info-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 24px;
}

.share-info-item {
  padding: 12px 14px;
  border-radius: 14px;
  background: var(--app-bg-muted);
  border: 1px solid var(--app-border);
}

.share-info-item--full {
  grid-column: 1 / -1;
}

.share-info-label {
  display: block;
  font-size: 12px;
  color: var(--app-text-tertiary);
  margin-bottom: 4px;
  font-weight: 500;
}

.share-info-value {
  display: block;
  font-size: 14px;
  font-weight: 600;
  color: var(--app-text-primary);
  word-break: break-all;
}

.share-info-path {
  font-family: 'SF Mono', 'Monaco', 'Menlo', monospace;
  font-size: 13px;
}

.password-section {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-bottom: 16px;
}

.share-actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.share-card--loading .share-brand {
  padding: 16px 0;
}

@keyframes card-in {
  from {
    opacity: 0;
    transform: translateY(16px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@media (max-width: 480px) {
  .share-card :deep(.n-card__content) {
    padding: 32px 24px !important;
  }

  .share-brand__icon {
    width: 56px;
    height: 56px;
    border-radius: 18px;
  }

  .share-heading {
    font-size: 22px;
  }
}
</style>
