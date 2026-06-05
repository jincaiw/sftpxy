<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><DocumentTextOutline /></n-icon>
        </div>
        <span>审计日志</span>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <template #header>
        <span class="page-section-title">筛选</span>
      </template>
      <div class="filter-section">
        <div class="filter-bar">
          <n-select
            v-model:value="filterProtocol"
            :options="[
              { label: '全部协议', value: '' },
              { label: 'SSH', value: 'ssh' },
              { label: 'FTP', value: 'ftp' },
              { label: 'WebDAV', value: 'webdav' },
              { label: 'HTTP', value: 'http' }
            ]"
            style="min-width: 120px"
            @update:value="() => { pagination.page = 1; fetchLogs() }"
          />
          <n-select
            v-model:value="filterAction"
            :options="[
              { label: '全部操作', value: '' },
              { label: '登录', value: 'login' },
              { label: '登出', value: 'logout' },
              { label: '上传', value: 'upload' },
              { label: '下载', value: 'download' },
              { label: '删除', value: 'delete' },
              { label: '重命名', value: 'rename' }
            ]"
            style="min-width: 120px"
            @update:value="() => { pagination.page = 1; fetchLogs() }"
          />
          <n-input
            v-model:value="filterUsername"
            placeholder="搜索用户名"
            style="min-width: 150px"
            @keyup.enter="fetchLogs"
          />
          <n-button @click="fetchLogs" :loading="loading" class="filter-search-btn">
            <template #icon><n-icon><SearchOutline /></n-icon></template>
            搜索
          </n-button>
        </div>
      </div>
      <n-data-table
        :columns="columns"
        :data="logs"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="900"
        remote
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, h, reactive, onMounted } from 'vue'
import { useMessage, NTag } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { SearchOutline, DocumentTextOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { AuditLog } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const logs = ref<AuditLog[]>([])
const loading = ref(false)
const total = ref(0)
const filterProtocol = ref('')
const filterAction = ref('')
const filterUsername = ref('')

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100],
  itemCount: 0,
  remote: true
})

const statusColorMap: Record<string, 'success' | 'error' | 'warning'> = {
  'success': 'success',
  'failed': 'error',
  'denied': 'warning'
}

const columns: DataTableColumns<AuditLog> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '时间', key: 'timestamp', width: 180, render: (row) => formatTime(row.timestamp) },
  { title: '用户名', key: 'username', width: 120 },
  {
    title: '协议',
    key: 'protocol',
    width: 80,
    render: (row) => h(
      NTag,
      { size: 'small', type: 'info' },
      { default: () => row.protocol?.toUpperCase() }
    )
  },
  { title: '操作', key: 'action', width: 100 },
  { title: '远程地址', key: 'remote_addr', width: 140 },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row) => h(
      NTag,
      { size: 'small', type: statusColorMap[row.status] || 'default' },
      { default: () => row.status }
    )
  },
  { title: '详情', key: 'details' }
]

const fetchLogs = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const result = await apiClient.getLogs(token, {
        page: pagination.page,
        limit: pagination.pageSize,
        protocol: filterProtocol.value || undefined,
        action: filterAction.value || undefined,
        username: filterUsername.value || undefined
      })
      logs.value = result.items || []
      total.value = result.total || 0
      pagination.itemCount = total.value
    }
  } catch (error: any) {
    message.error('获取日志失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handlePageChange = (page: number) => {
  pagination.page = page
  fetchLogs()
}

const handlePageSizeChange = (pageSize: number) => {
  pagination.pageSize = pageSize
  pagination.page = 1
  fetchLogs()
}

onMounted(fetchLogs)
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
