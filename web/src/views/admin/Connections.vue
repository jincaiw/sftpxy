<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><LinkOutline /></n-icon>
        </div>
        <span>活动连接</span>
      </div>
      <div class="page-actions">
        <n-button @click="fetchConnections" :loading="loading">
          <template #icon><n-icon><RefreshOutline /></n-icon></template>
          刷新
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="connections"
        :loading="loading"
        :scroll-x="800"
      />
    </n-card>

    <ConfirmDialog
      v-model:show="showDisconnectConfirm"
      title="确认断开连接"
      :content="`确定要断开用户 ${disconnectingConnection?.username} 的连接吗？`"
      @confirm="handleDisconnect"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, h, onMounted, onUnmounted } from 'vue'
import { useMessage, NTag, NButton, NIcon } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { RefreshOutline, CloseOutline, LinkOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { Connection } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const connections = ref<Connection[]>([])
const loading = ref(false)
const showDisconnectConfirm = ref(false)
const disconnectingConnection = ref<Connection | null>(null)

let refreshTimer: number | null = null

const protocolTypeMap: Record<string, 'success' | 'warning' | 'info' | 'error'> = {
  'ssh': 'success',
  'sftp': 'success',
  'ftp': 'warning',
  'ftps': 'warning',
  'webdav': 'info',
  'http': 'info'
}

const columns: DataTableColumns<Connection> = [
  { title: '连接ID', key: 'id', width: 120 },
  { title: '用户名', key: 'username' },
  {
    title: '协议',
    key: 'protocol',
    render: (row) => h(
      NTag,
      { type: protocolTypeMap[row.protocol?.toLowerCase()] || 'default', size: 'small' },
      { default: () => row.protocol?.toUpperCase() }
    )
  },
  { title: '远程地址', key: 'remote_addr' },
  { title: '连接时间', key: 'connected_at', width: 180, render: (row) => formatTime(row.connected_at) },
  {
    title: '上传',
    key: 'bytes_sent',
    width: 100,
    render: (row) => formatBytes(row.bytes_sent)
  },
  {
    title: '下载',
    key: 'bytes_recv',
    width: 100,
    render: (row) => formatBytes(row.bytes_recv)
  },
  {
    title: '操作',
    key: 'actions',
    width: 80,
    render: (row) => h(
      NButton,
      {
        size: 'small',
        type: 'error',
        onClick: () => handleDisconnectClick(row)
      },
      {
        default: () => '断开',
        icon: () => h(NIcon, null, { default: () => h(CloseOutline) })
      }
    )
  }
]

const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

const fetchConnections = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      connections.value = await apiClient.getConnections(token)
    }
  } catch (error: any) {
    message.error('获取连接列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleDisconnectClick = (conn: Connection) => {
  disconnectingConnection.value = conn
  showDisconnectConfirm.value = true
}

const handleDisconnect = async () => {
  if (!disconnectingConnection.value) return
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.disconnectConnection(token, disconnectingConnection.value.id)
      message.success('连接已断开')
      await fetchConnections()
    }
  } catch (error: any) {
    message.error('断开连接失败: ' + error.message)
  }
}

onMounted(() => {
  fetchConnections()
  refreshTimer = window.setInterval(fetchConnections, 30000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>
