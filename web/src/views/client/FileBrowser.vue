<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><FolderOpenOutline /></n-icon>
        </div>
        <span>文件管理</span>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-files-card">
      <template #header>
        <div class="file-header">
          <n-space align="center">
            <n-breadcrumb>
              <n-breadcrumb-item @click="navigateTo('/')">根目录</n-breadcrumb-item>
              <n-breadcrumb-item
                v-for="(part, index) in pathParts"
                :key="index"
                @click="navigateTo(partsPath[index])"
              >
                {{ part }}
              </n-breadcrumb-item>
            </n-breadcrumb>
            <n-space style="margin-left: auto">
              <n-button
                v-if="checkedRowKeys.length > 0"
                size="small"
                type="primary"
                data-testid="client-batch-download-button"
                :loading="batchDownloading"
                @click="handleBatchDownload"
              >
                <template #icon><n-icon><DownloadOutline /></n-icon></template>
                批量下载 ({{ checkedRowKeys.length }})
              </n-button>
              <n-button size="small" data-testid="client-upload-button" :loading="uploading" :disabled="uploading" @click="handleUpload">
                <template #icon><n-icon><CloudUploadOutline /></n-icon></template>
                上传
              </n-button>
              <n-button size="small" data-testid="client-create-folder-open" @click="showCreateFolder = true">
                <template #icon><n-icon><FolderOpenOutline /></n-icon></template>
                新建文件夹
              </n-button>
              <n-button size="small" data-testid="client-files-refresh" @click="refreshFiles" :loading="loading">
                <template #icon><n-icon><RefreshOutline /></n-icon></template>
                刷新
              </n-button>
            </n-space>
          </n-space>
        </div>
      </template>

      <n-data-table
        :columns="columns"
        :data="files"
        :loading="loading"
        :pagination="false"
        :row-key="(row: FileItem) => row.name"
        v-model:checked-row-keys="checkedRowKeys"
        size="small"
      />
    </n-card>

    <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-shares-card">
      <template #header>
        <n-space justify="space-between" align="center">
          <span>分享链接</span>
          <n-button size="small" data-testid="client-shares-refresh" @click="fetchShares" :loading="shareLoading">
            刷新分享
          </n-button>
        </n-space>
      </template>

      <n-data-table
        :columns="shareColumns"
        :data="shares"
        :loading="shareLoading"
        :pagination="false"
        size="small"
      />
    </n-card>

    <n-modal
      v-model:show="showCreateFolder"
      preset="card"
      title="新建文件夹"
      style="width: 400px"
    >
      <n-form-item label="文件夹名称">
        <n-input v-model:value="newFolderName" placeholder="请输入文件夹名称" :input-props="{ 'data-testid': 'client-create-folder-name' }" />
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="client-create-folder-cancel" @click="showCreateFolder = false">取消</n-button>
          <n-button type="primary" :loading="creating" data-testid="client-create-folder-submit" @click="handleCreateFolder">
            创建
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal
      v-model:show="showRenameModal"
      preset="card"
      title="重命名"
      style="width: 400px"
    >
      <n-form-item label="新名称">
        <n-input v-model:value="newName" placeholder="请输入新名称" :input-props="{ 'data-testid': 'client-rename-name' }" />
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="client-rename-cancel" @click="showRenameModal = false">取消</n-button>
          <n-button type="primary" :loading="renaming" data-testid="client-rename-submit" @click="handleRename">
            重命名
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除 ${deletingFile?.name} 吗？此操作不可撤销。`"
      @confirm="handleDelete"
    />

    <n-modal
      v-model:show="showShareModal"
      preset="card"
      title="创建分享链接"
      style="width: 480px"
    >
      <n-form-item label="分享路径">
        <n-input :value="shareForm.path" disabled :input-props="{ 'data-testid': 'client-share-path' }" />
      </n-form-item>
      <n-form-item label="分享类型">
        <n-select
          v-model:value="shareForm.shareType"
          data-testid="client-share-type"
          :options="shareTypeOptions"
        />
      </n-form-item>
      <n-form-item label="访问密码">
        <n-input
          v-model:value="shareForm.password"
          type="password"
          show-password-on="click"
          placeholder="可选，留空则无需密码"
          :input-props="{ 'data-testid': 'client-share-password' }"
        />
      </n-form-item>
      <n-form-item label="过期时间">
        <n-date-picker
          v-model:value="shareForm.expiresAt"
          type="datetime"
          clearable
          style="width: 100%"
          data-testid="client-share-expires"
        />
      </n-form-item>
      <n-form-item label="下载次数">
        <n-input-number
          v-model:value="shareForm.maxDownloads"
          :min="0"
          :disabled="shareForm.shareType === 'upload'"
          style="width: 100%"
          data-testid="client-share-max-downloads"
        />
      </n-form-item>
      <n-form-item label="上传次数">
        <n-input-number
          v-model:value="shareForm.maxUploads"
          :min="0"
          :disabled="shareForm.shareType === 'download'"
          style="width: 100%"
          data-testid="client-share-max-uploads"
        />
      </n-form-item>
      <n-form-item label="IP 白名单">
        <n-input
          v-model:value="shareForm.ipRestrictions"
          type="textarea"
          placeholder="每行一个 IP，可选"
          :rows="3"
          :input-props="{ 'data-testid': 'client-share-ip-restrictions' }"
        />
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="client-share-cancel" @click="showShareModal = false">取消</n-button>
          <n-button type="primary" :loading="shareCreating" data-testid="client-share-submit" @click="handleCreateShare">
            创建分享
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal
      v-model:show="showShareResult"
      preset="card"
      title="分享创建成功"
      style="width: 480px"
    >
      <n-form-item label="分享链接">
        <n-input :value="shareResultUrl" readonly>
          <template #suffix>
            <n-button text @click="copyShareResultUrl">
              <template #icon><n-icon><CopyOutline /></n-icon></template>
            </n-button>
          </template>
        </n-input>
      </n-form-item>
      <n-form-item label="访问令牌">
        <n-input :value="shareResultToken" readonly>
          <template #suffix>
            <n-button text @click="copyShareResultToken">
              <template #icon><n-icon><CopyOutline /></n-icon></template>
            </n-button>
          </template>
        </n-input>
      </n-form-item>
      <template #footer>
        <n-space justify="end">
          <n-button type="primary" @click="showShareResult = false">确定</n-button>
        </n-space>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, h, computed, onMounted, reactive } from 'vue'
import { useMessage, NIcon, NButton, NDropdown, NTag, NSpace } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import {
  FolderOpenOutline,
  DocumentOutline,
  RefreshOutline,
  CloudUploadOutline,
  CreateOutline,
  TrashOutline,
  DownloadOutline,
  EllipsisVerticalOutline,
  FolderOutline,
  ShareSocialOutline,
  CopyOutline,
  LinkOutline
} from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { FileItem, ShareItem } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const files = ref<FileItem[]>([])
const loading = ref(false)
const currentPath = ref('/')
const checkedRowKeys = ref<string[]>([])
const batchDownloading = ref(false)
const showCreateFolder = ref(false)
const showRenameModal = ref(false)
const showDeleteConfirm = ref(false)
const newFolderName = ref('')
const newName = ref('')
const creating = ref(false)
const renaming = ref(false)
const uploading = ref(false)
const shares = ref<ShareItem[]>([])
const shareLoading = ref(false)
const showShareModal = ref(false)
const shareCreating = ref(false)

const renamingFile = ref<FileItem | null>(null)
const deletingFile = ref<FileItem | null>(null)
const sharingFile = ref<FileItem | null>(null)

const shareForm = reactive({
  path: '',
  shareType: 'download' as 'download' | 'upload' | 'both',
  password: '',
  expiresAt: null as number | null,
  maxDownloads: 0 as number | null,
  maxUploads: 0 as number | null,
  ipRestrictions: ''
})

const shareTypeOptions = [
  { label: '下载分享', value: 'download' },
  { label: '上传分享', value: 'upload' },
  { label: '下载+上传', value: 'both' }
]

const showShareResult = ref(false)
const shareResultUrl = ref('')
const shareResultToken = ref('')

const pathParts = computed(() => {
  if (currentPath.value === '/') return []
  return currentPath.value.split('/').filter(Boolean)
})

const partsPath = computed(() => {
  const parts: string[] = []
  pathParts.value.forEach((_, i) => {
    parts.push('/' + pathParts.value.slice(0, i + 1).join('/'))
  })
  return parts
})

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

const columns: DataTableColumns<FileItem> = [
  {
    type: 'selection'
  },
  {
    title: '名称',
    key: 'name',
    render: (row) => h('div', { style: 'display: flex; align-items: center; gap: 8px; cursor: pointer', onClick: () => row.is_dir ? navigateToRow(row) : null }, [
      h(NIcon, { size: 20, color: row.is_dir ? '#f0a020' : '#2080f0' }, { default: () => h(row.is_dir ? FolderOutline : DocumentOutline) }),
      h('span', row.name)
    ])
  },
  {
    title: '大小',
    key: 'size',
    width: 100,
    render: (row) => row.is_dir ? '--' : formatBytes(row.size)
  },
  {
    title: '修改时间',
    key: 'mod_time',
    width: 180,
    render: (row) => formatTime(row.mod_time)
  },
  {
    title: '权限',
    key: 'mode',
    width: 100
  },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    render: (row) => {
      const options = [
        { label: '重命名', key: 'rename' },
        { label: '下载', key: 'download' },
        { label: '分享', key: 'share' },
        { label: '删除', key: 'delete' }
      ]
      return h(
        NDropdown,
        {
          options,
          'data-testid': `client-file-actions-${row.name}`,
          onSelect: (key: string) => handleAction(key, row)
        },
        {
          default: () => h(
            NButton,
            { size: 'small', quaternary: true, 'data-testid': `client-file-actions-trigger-${row.name}` },
            { icon: () => h(NIcon, null, { default: () => h(EllipsisVerticalOutline) }) }
          )
        }
      )
    }
  }
]

const shareColumns: DataTableColumns<ShareItem> = [
  {
    title: '路径',
    key: 'path'
  },
  {
    title: '类型',
    key: 'share_type',
    width: 100,
    render: (row) => {
      const typeMap: Record<string, { type: 'info' | 'success' | 'warning', label: string }> = {
        download: { type: 'info', label: '下载' },
        upload: { type: 'success', label: '上传' },
        both: { type: 'warning', label: '下载+上传' }
      }
      const info = typeMap[row.share_type] || typeMap.download
      return h(NTag, { type: info.type, size: 'small' }, { default: () => info.label })
    }
  },
  {
    title: '状态',
    key: 'is_active',
    width: 100,
    render: (row) => h(
      NTag,
      { type: row.is_active ? 'success' : 'warning', size: 'small' },
      { default: () => row.is_active ? '有效' : '已撤销' }
    )
  },
  {
    title: '次数',
    key: 'usage',
    width: 120,
    render: (row) => {
      if (row.share_type === 'both') {
        return `下载 ${row.download_count}/${row.max_downloads || '∞'}  上传 ${row.upload_count}/${row.max_uploads || '∞'}`
      }
      return row.share_type === 'download'
        ? `${row.download_count}/${row.max_downloads || '∞'}`
        : `${row.upload_count}/${row.max_uploads || '∞'}`
    }
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 180,
    render: (row) => formatTime(row.created_at)
  },
  {
    title: '操作',
    key: 'actions',
    width: 180,
    render: (row) => h(
      NSpace,
      { size: 4 },
      {
        default: () => [
          h(
            NButton,
            {
              size: 'tiny',
              secondary: true,
              'data-testid': `client-share-copy-${row.id}`,
              onClick: () => handleCopyShare(row)
            },
            {
              icon: () => h(NIcon, null, { default: () => h(CopyOutline) }),
              default: () => '复制链接'
            }
          ),
          h(
            NButton,
            {
              size: 'tiny',
              tertiary: true,
              'data-testid': `client-share-verify-${row.id}`,
              onClick: () => handleAccessShare(row)
            },
            {
              icon: () => h(NIcon, null, { default: () => h(LinkOutline) }),
              default: () => '验证'
            }
          ),
          h(
            NButton,
            {
              size: 'tiny',
              type: 'error',
              secondary: true,
              'data-testid': `client-share-revoke-${row.id}`,
              disabled: !row.is_active,
              onClick: () => handleRevokeShare(row)
            },
            '撤销'
          )
        ]
      }
    )
  }
]

const navigateTo = (path: string) => {
  currentPath.value = path
  fetchFiles()
}

const navigateToRow = (row: FileItem) => {
  if (row.is_dir) {
    const newPath = currentPath.value === '/'
      ? '/' + row.name
      : currentPath.value + '/' + row.name
    navigateTo(newPath)
  }
}

const fetchFiles = async () => {
  loading.value = true
  checkedRowKeys.value = []
  try {
    const token = authStore.clientToken
    if (token) {
      files.value = await apiClient.listFiles(token, currentPath.value)
    }
  } catch (error: any) {
    message.error('获取文件列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleUpload = () => {
  const input = document.createElement('input')
  input.type = 'file'
  input.multiple = true
  input.onchange = async (e) => {
    const files = (e.target as HTMLInputElement).files
    if (!files || files.length === 0) return
    uploading.value = true
    const msg = message.create('正在上传...', { type: 'loading', duration: 0 })
    try {
      const token = authStore.clientToken
      if (token) {
        for (const file of Array.from(files)) {
          await apiClient.uploadFile(token, currentPath.value, file)
        }
        message.success(`成功上传 ${files.length} 个文件`)
        await fetchFiles()
      }
    } catch (err: any) {
      message.error('上传失败: ' + err.message)
    } finally {
      msg.destroy()
      uploading.value = false
    }
  }
  input.click()
}

const handleCreateFolder = async () => {
  if (!newFolderName.value) {
    message.warning('请输入文件夹名称')
    return
  }
  creating.value = true
  try {
    const token = authStore.clientToken
    if (token) {
      const folderPath = currentPath.value === '/'
        ? '/' + newFolderName.value
        : currentPath.value + '/' + newFolderName.value
      await apiClient.createFolder(token, folderPath)
      message.success('文件夹创建成功')
      showCreateFolder.value = false
      newFolderName.value = ''
      await fetchFiles()
    }
  } catch (error: any) {
    message.error('创建文件夹失败: ' + error.message)
  } finally {
    creating.value = false
  }
}

const handleAction = (action: string, row: FileItem) => {
  switch (action) {
    case 'download':
      handleDownload(row)
      break
    case 'rename':
      handleRenameClick(row)
      break
    case 'share':
      handleShareClick(row)
      break
    case 'delete':
      handleDeleteClick(row)
      break
  }
}

const handleDownload = async (row: FileItem) => {
  try {
    const token = authStore.clientToken
    const filePath = currentPath.value === '/'
      ? '/' + row.name
      : currentPath.value + '/' + row.name
    if (token) {
      if (row.is_dir) {
        const msg = message.create('正在打包下载文件夹...', { type: 'loading', duration: 0 })
        try {
          const blob = await apiClient.downloadZip(token, [filePath])
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = row.name + '.zip'
          a.click()
          URL.revokeObjectURL(url)
          message.success('文件夹下载成功')
        } finally {
          msg.destroy()
        }
      } else {
        const blob = await apiClient.downloadFile(token, filePath)
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = row.name
        a.click()
        URL.revokeObjectURL(url)
      }
    }
  } catch (error: any) {
    message.error('下载失败: ' + error.message)
  }
}

const handleBatchDownload = async () => {
  if (checkedRowKeys.value.length === 0) return
  const token = authStore.clientToken
  if (!token) return

  const paths = checkedRowKeys.value.map(name => {
    return currentPath.value === '/'
      ? '/' + name
      : currentPath.value + '/' + name
  })

  batchDownloading.value = true
  const msg = message.create('正在打包下载...', { type: 'loading', duration: 0 })
  try {
    const blob = await apiClient.downloadZip(token, paths)
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `download_${new Date().toISOString().replace(/[:.]/g, '').slice(0, 15)}.zip`
    a.click()
    URL.revokeObjectURL(url)
    message.success(`成功下载 ${checkedRowKeys.value.length} 个项目`)
    checkedRowKeys.value = []
  } catch (error: any) {
    message.error('批量下载失败: ' + error.message)
  } finally {
    msg.destroy()
    batchDownloading.value = false
  }
}

const handleRenameClick = (row: FileItem) => {
  renamingFile.value = row
  newName.value = row.name
  showRenameModal.value = true
}

const handleRename = async () => {
  if (!newName.value || !renamingFile.value) return
  renaming.value = true
  try {
    const token = authStore.clientToken
    if (token) {
      const oldPath = currentPath.value === '/'
        ? '/' + renamingFile.value.name
        : currentPath.value + '/' + renamingFile.value.name
      const newPath = currentPath.value === '/'
        ? '/' + newName.value
        : currentPath.value + '/' + newName.value
      await apiClient.renameFile(token, oldPath, newPath)
      message.success('重命名成功')
      showRenameModal.value = false
      renamingFile.value = null
      newName.value = ''
      await fetchFiles()
    }
  } catch (error: any) {
    message.error('重命名失败: ' + error.message)
  } finally {
    renaming.value = false
  }
}

const handleDeleteClick = (row: FileItem) => {
  deletingFile.value = row
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingFile.value) return
  try {
    const token = authStore.clientToken
    if (token) {
      const filePath = currentPath.value === '/'
        ? '/' + deletingFile.value.name
        : currentPath.value + '/' + deletingFile.value.name
      await apiClient.deleteFile(token, filePath)
      message.success('删除成功')
      await fetchFiles()
    }
  } catch (error: any) {
    message.error('删除失败: ' + error.message)
  }
}

const resolveCurrentItemPath = (row: FileItem) => {
  return currentPath.value === '/'
    ? '/' + row.name
    : currentPath.value + '/' + row.name
}

const handleShareClick = (row: FileItem) => {
  sharingFile.value = row
  shareForm.path = resolveCurrentItemPath(row)
  shareForm.shareType = row.is_dir ? 'upload' : 'download'
  shareForm.password = ''
  shareForm.expiresAt = null
  shareForm.maxDownloads = 0
  shareForm.maxUploads = 0
  shareForm.ipRestrictions = ''
  showShareModal.value = true
}

const fetchShares = async () => {
  const token = authStore.clientToken
  if (!token) return

  shareLoading.value = true
  try {
    const response = await apiClient.listShares(token)
    shares.value = response.items
  } catch (error: any) {
    message.error('获取分享列表失败: ' + error.message)
  } finally {
    shareLoading.value = false
  }
}

const handleCreateShare = async () => {
  const token = authStore.clientToken
  if (!token || !shareForm.path) return

  shareCreating.value = true
  try {
    const ipRestrictions = shareForm.ipRestrictions
      .split('\n')
      .map((item) => item.trim())
      .filter(Boolean)

    const expiresAt = shareForm.expiresAt
      ? new Date(shareForm.expiresAt).toISOString()
      : undefined

    const created = await apiClient.createShare(token, {
      path: shareForm.path,
      share_type: shareForm.shareType,
      password: shareForm.password || undefined,
      expires_at: expiresAt,
      max_downloads: shareForm.shareType !== 'upload' ? (shareForm.maxDownloads || undefined) : undefined,
      max_uploads: shareForm.shareType !== 'download' ? (shareForm.maxUploads || undefined) : undefined,
      ip_restrictions: ipRestrictions.length > 0 ? ipRestrictions : undefined
    })
    shares.value = [created, ...shares.value]
    showShareModal.value = false

    shareResultUrl.value = buildShareUrl(created)
    shareResultToken.value = created.token
    showShareResult.value = true

    message.success('分享链接创建成功')
  } catch (error: any) {
    message.error('创建分享失败: ' + error.message)
  } finally {
    shareCreating.value = false
  }
}

const buildShareUrl = (row: ShareItem) => `${window.location.origin}/client/share/${row.token}`

const copyShareResultUrl = async () => {
  try {
    await navigator.clipboard.writeText(shareResultUrl.value)
    message.success('链接已复制')
  } catch (_error) {
    message.info(`分享链接：${shareResultUrl.value}`)
  }
}

const copyShareResultToken = async () => {
  try {
    await navigator.clipboard.writeText(shareResultToken.value)
    message.success('令牌已复制')
  } catch (_error) {
    message.info(`访问令牌：${shareResultToken.value}`)
  }
}

const handleCopyShare = async (row: ShareItem) => {
  const url = buildShareUrl(row)
  try {
    await navigator.clipboard.writeText(url)
    message.success('分享链接已复制')
  } catch (_error) {
    message.info(`分享链接：${url}`)
  }
}

const handleAccessShare = async (row: ShareItem) => {
  try {
    const result = await apiClient.accessShare(row.token)
    message.success(`分享验证成功：${result.path}`)
    await fetchShares()
  } catch (error: any) {
    message.error('分享验证失败: ' + error.message)
  }
}

const handleRevokeShare = async (row: ShareItem) => {
  const token = authStore.clientToken
  if (!token) return

  try {
    await apiClient.revokeShare(token, row.id)
    message.success('分享已撤销')
    await fetchShares()
  } catch (error: any) {
    message.error('撤销分享失败: ' + error.message)
  }
}

const refreshFiles = () => {
  fetchFiles()
}

onMounted(() => {
  fetchFiles()
  fetchShares()
})
</script>

<style scoped>
.file-header {
  width: 100%;
}
</style>
