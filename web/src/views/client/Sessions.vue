<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><TimeOutline /></n-icon>
        </div>
        <span>活动会话</span>
      </div>
      <div class="page-actions">
        <n-button data-testid="client-sessions-refresh" :loading="loading" @click="fetchSessions">
          <template #icon><n-icon><RefreshOutline /></n-icon></template>
          刷新
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small" data-testid="client-sessions-card">

      <n-data-table
        :columns="columns"
        :data="sessions"
        :loading="loading"
        :pagination="false"
        size="small"
      />

      <n-empty v-if="!loading && sessions.length === 0" description="暂无活动会话" style="margin-top: 24px" />
    </n-card>
  </div>
</template>

<script setup lang="ts">
import { ref, h, onMounted } from 'vue'
import { useMessage, NButton, NTag, NIcon } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { TimeOutline, RefreshOutline } from '@vicons/ionicons5'
import { apiClient } from '@/api/client'
import type { SessionItem } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const sessions = ref<SessionItem[]>([])
const loading = ref(false)

const protocolTagType = (protocol: string): 'info' | 'success' | 'warning' => {
  const map: Record<string, 'info' | 'success' | 'warning'> = {
    sftp: 'info',
    ssh: 'success',
    ftp: 'warning',
    webdav: 'info',
    http: 'success'
  }
  return map[protocol.toLowerCase()] || 'info'
}

const columns: DataTableColumns<SessionItem> = [
  {
    title: '协议',
    key: 'protocol',
    width: 120,
    render: (row) => h(
      NTag,
      { type: protocolTagType(row.protocol), size: 'small' },
      { default: () => row.protocol.toUpperCase() }
    )
  },
  {
    title: '客户端 IP',
    key: 'client_ip',
    width: 180
  },
  {
    title: '连接时间',
    key: 'started_at',
    width: 200,
    render: (row) => formatTime(row.started_at)
  },
  {
    title: '操作',
    key: 'actions',
    width: 100,
    render: (row) => h(
      NButton,
      {
        size: 'small',
        type: 'error',
        secondary: true,
        'data-testid': `client-session-disconnect-${row.id}`,
        onClick: () => handleDisconnect(row)
      },
      '断开'
    )
  }
]

const fetchSessions = async () => {
  const token = authStore.clientToken
  if (!token) return

  loading.value = true
  try {
    sessions.value = await apiClient.getOwnSessions(token)
  } catch (error: any) {
    message.error('获取会话列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleDisconnect = async (row: SessionItem) => {
  const token = authStore.clientToken
  if (!token) return

  try {
    await apiClient.disconnectOwnSession(token, row.id)
    message.success('会话已断开')
    await fetchSessions()
  } catch (error: any) {
    message.error('断开会话失败: ' + error.message)
  }
}

onMounted(fetchSessions)
</script>
