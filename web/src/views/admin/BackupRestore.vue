<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><CloudDownloadOutline /></n-icon>
        </div>
        <span>备份恢复</span>
      </div>
    </div>

    <div class="page-grid-2">
      <n-card class="data-table-card" :bordered="false" size="small">
        <template #header>
          <span class="page-section-title">
            <n-icon><DownloadOutline /></n-icon>
            导出备份
          </span>
        </template>
        <n-space vertical>
          <span class="page-hint">将系统配置和用户数据导出为 JSON 文件，用于备份和迁移。</span>
          <n-button type="primary" :loading="exporting" @click="handleExport">
            <template #icon><n-icon><DownloadOutline /></n-icon></template>
            导出备份
          </n-button>
        </n-space>
      </n-card>

      <n-card class="data-table-card" :bordered="false" size="small">
        <template #header>
          <span class="page-section-title">
            <n-icon><CloudUploadOutline /></n-icon>
            导入恢复
          </span>
        </template>
        <n-space vertical>
          <span class="page-hint">从 JSON 备份文件恢复系统配置和用户数据。</span>
          <n-upload
            :max="1"
            accept=".json"
            :default-upload="false"
            @change="handleFileChange"
          >
            <n-button>
              <template #icon><n-icon><CloudUploadOutline /></n-icon></template>
              选择备份文件
            </n-button>
          </n-upload>
          <n-form-item label="冲突策略" label-placement="left" style="margin-top: 8px">
            <n-select
              v-model:value="conflictStrategy"
              :options="conflictOptions"
              style="width: 200px"
            />
          </n-form-item>
          <n-alert v-if="selectedFile" type="info" :show-icon="false">
            已选择文件: {{ selectedFile.name }} ({{ formatSize(selectedFile.size) }})
          </n-alert>
          <n-button
            type="warning"
            :loading="importing"
            :disabled="!selectedFile"
            @click="handleImport"
          >
            <template #icon><n-icon><CloudUploadOutline /></n-icon></template>
            导入恢复
          </n-button>
        </n-space>
      </n-card>
    </div>

    <ConfirmDialog
      v-model:show="showImportConfirm"
      title="确认导入"
      content="导入操作将覆盖现有数据，确定要继续吗？"
      @confirm="doImport"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import type { UploadFileInfo } from 'naive-ui'
import { DownloadOutline, CloudUploadOutline, CloudDownloadOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'

const message = useMessage()
const authStore = useAuthStore()

const exporting = ref(false)
const importing = ref(false)
const selectedFile = ref<File | null>(null)
const conflictStrategy = ref('skip')
const showImportConfirm = ref(false)

const conflictOptions = [
  { label: '跳过已存在', value: 'skip' },
  { label: '覆盖已存在', value: 'overwrite' }
]

const formatSize = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

const handleExport = async () => {
  exporting.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const blob = await apiClient.exportBackup(token)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sftpxy-backup-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      message.success('备份已导出')
    }
  } catch (error: any) {
    message.error('导出备份失败: ' + error.message)
  } finally {
    exporting.value = false
  }
}

const handleFileChange = (data: { file: UploadFileInfo }) => {
  if (data.file?.file) {
    selectedFile.value = data.file.file
  } else {
    selectedFile.value = null
  }
}

const handleImport = () => {
  showImportConfirm.value = true
}

const doImport = async () => {
  if (!selectedFile.value) return
  importing.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const text = await selectedFile.value.text()
      const data = JSON.parse(text)
      await apiClient.importRestore(token, data, conflictStrategy.value)
      message.success('数据已恢复')
      selectedFile.value = null
    }
  } catch (error: any) {
    if (error instanceof SyntaxError) {
      message.error('备份文件 JSON 格式错误')
    } else {
      message.error('导入恢复失败: ' + error.message)
    }
  } finally {
    importing.value = false
  }
}
</script>
