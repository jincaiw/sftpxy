<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><ShareSocialOutline /></n-icon>
        </div>
        <span>分享管理</span>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <template #header>
        <span class="page-section-title">筛选</span>
      </template>
      <div class="filter-section">
        <div class="filter-bar">
          <n-input
            v-model:value="filterOwner"
            placeholder="搜索所有者"
            style="min-width: 150px"
            @keyup.enter="fetchShares"
          />
          <n-select
            v-model:value="filterStatus"
            :options="statusFilterOptions"
            style="min-width: 130px"
            @update:value="fetchShares"
          />
          <n-button @click="fetchShares" :loading="loading" class="filter-search-btn">
            <template #icon><n-icon><SearchOutline /></n-icon></template>
            搜索
          </n-button>
        </div>
      </div>
      <n-data-table
        :columns="columns"
        :data="shares"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="850"
      />
    </n-card>

    <n-modal
      v-model:show="showDetailModal"
      preset="card"
      title="分享详情"
      style="max-width: 560px; width: 90vw"
    >
      <n-descriptions v-if="detailShare" :column="1" bordered>
        <n-descriptions-item label="Token">{{ detailShare.token }}</n-descriptions-item>
        <n-descriptions-item label="所有者">{{ detailShare.username }}</n-descriptions-item>
        <n-descriptions-item label="路径">{{ detailShare.path }}</n-descriptions-item>
        <n-descriptions-item label="类型">{{ detailShare.share_type === 'download' ? '下载' : detailShare.share_type === 'upload' ? '上传' : '下载+上传' }}</n-descriptions-item>
        <n-descriptions-item label="下载次数">{{ detailShare.download_count }}</n-descriptions-item>
        <n-descriptions-item label="上传次数">{{ detailShare.upload_count }}</n-descriptions-item>
        <n-descriptions-item label="最大下载">{{ detailShare.max_downloads || '无限制' }}</n-descriptions-item>
        <n-descriptions-item label="最大上传">{{ detailShare.max_uploads || '无限制' }}</n-descriptions-item>
        <n-descriptions-item label="IP 限制">{{ detailShare.ip_restrictions || '无' }}</n-descriptions-item>
        <n-descriptions-item label="过期时间">{{ formatTime(detailShare.expires_at) || '永不过期' }}</n-descriptions-item>
        <n-descriptions-item label="状态">{{ detailShare.is_active ? '活跃' : '已撤销' }}</n-descriptions-item>
        <n-descriptions-item label="创建时间">{{ formatTime(detailShare.created_at) }}</n-descriptions-item>
      </n-descriptions>
    </n-modal>

    <ConfirmDialog
      v-model:show="showRevokeConfirm"
      title="确认撤销"
      :content="`确定要撤销此分享吗？撤销后该分享链接将无法使用。`"
      @confirm="handleRevoke"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, h, onMounted, reactive } from 'vue'
import { useMessage, NTag, NButton, NIcon } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { SearchOutline, EyeOutline, TrashOutline, ShareSocialOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { ShareItem } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const shares = ref<ShareItem[]>([])
const loading = ref(false)
const filterOwner = ref('')
const filterStatus = ref('')
const showDetailModal = ref(false)
const showRevokeConfirm = ref(false)
const detailShare = ref<ShareItem | null>(null)
const revokingShare = ref<ShareItem | null>(null)

const statusFilterOptions = [
  { label: '全部状态', value: '' },
  { label: '活跃', value: 'active' },
  { label: '已撤销', value: 'revoked' },
  { label: '已过期', value: 'expired' }
]

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const getShareStatus = (share: ShareItem): string => {
  if (!share.is_active) return 'revoked'
  if (share.expires_at && new Date(share.expires_at) < new Date()) return 'expired'
  return 'active'
}

const statusTagMap: Record<string, { type: 'success' | 'error' | 'warning'; label: string }> = {
  active: { type: 'success', label: '活跃' },
  revoked: { type: 'error', label: '已撤销' },
  expired: { type: 'warning', label: '已过期' }
}

const columns: DataTableColumns<ShareItem> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '所有者', key: 'username', width: 120 },
  { title: '路径', key: 'path', ellipsis: { tooltip: true } },
  {
    title: '类型',
    key: 'share_type',
    width: 80,
    render: (row) => h(
      NTag,
      { size: 'small', type: row.share_type === 'download' ? 'info' : 'warning' },
      { default: () => row.share_type === 'download' ? '下载' : row.share_type === 'upload' ? '上传' : '下载+上传' }
    )
  },
  {
    title: '状态',
    key: 'status',
    width: 90,
    render: (row) => {
      const status = getShareStatus(row)
      const config = statusTagMap[status] || { type: 'default' as const, label: status }
      return h(NTag, { size: 'small', type: config.type }, { default: () => config.label })
    }
  },
  {
    title: '过期时间',
    key: 'expires_at',
    width: 170,
    render: (row) => formatTime(row.expires_at) || '永不过期'
  },
  {
    title: '下载',
    key: 'download_count',
    width: 70,
    render: (row) => `${row.download_count}`
  },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: (row) => h('div', { style: 'display: flex; gap: 8px' }, [
      h(
        NButton,
        { size: 'small', onClick: () => handleViewDetail(row) },
        { default: () => '详情', icon: () => h(NIcon, null, { default: () => h(EyeOutline) }) }
      ),
      getShareStatus(row) === 'active'
        ? h(
            NButton,
            { size: 'small', type: 'error', onClick: () => handleRevokeClick(row) },
            { default: () => '撤销', icon: () => h(NIcon, null, { default: () => h(TrashOutline) }) }
          )
        : null
    ].filter(Boolean))
  }
]

const fetchShares = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const result = await apiClient.adminListShares(token, { owner: filterOwner.value || undefined })
      let items = result.items || []
      if (filterStatus.value) {
        items = items.filter(s => getShareStatus(s) === filterStatus.value)
      }
      shares.value = items
    }
  } catch (error: any) {
    message.error('获取分享列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleViewDetail = (share: ShareItem) => {
  detailShare.value = share
  showDetailModal.value = true
}

const handleRevokeClick = (share: ShareItem) => {
  revokingShare.value = share
  showRevokeConfirm.value = true
}

const handleRevoke = async () => {
  if (!revokingShare.value) return
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.adminDeleteShare(token, revokingShare.value.id)
      message.success('分享已撤销')
      showRevokeConfirm.value = false
      revokingShare.value = null
      await fetchShares()
    }
  } catch (error: any) {
    message.error('撤销分享失败: ' + error.message)
  }
}

onMounted(fetchShares)
</script>

<style scoped>
.filter-section {
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--n-border-color, rgba(239, 239, 245, 0.5));
}
.filter-bar {
  display: flex;
  flex-wrap: nowrap;
  align-items: center;
  gap: 12px;
}
.filter-search-btn {
  margin-left: auto;
}
</style>
