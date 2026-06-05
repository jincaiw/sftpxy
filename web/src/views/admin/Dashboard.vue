<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><PulseOutline /></n-icon>
        </div>
        <span>服务仪表盘</span>
      </div>
      <div class="page-actions">
        <n-button quaternary circle @click="fetchStatus" :loading="refreshing">
          <template #icon>
            <n-icon :size="18"><RefreshOutline /></n-icon>
          </template>
        </n-button>
      </div>
    </div>

    <div class="page-stat-grid">
      <div class="page-stat-card">
        <div class="page-stat-icon" :class="healthStatus === 'healthy' ? 'page-stat-icon--green' : 'page-stat-icon--red'">
          <n-icon :size="22"><PulseOutline /></n-icon>
        </div>
        <div class="page-stat-content">
          <div class="page-stat-label">服务状态</div>
          <div class="page-stat-value">
            <span class="status-dot" :class="healthStatus === 'healthy' ? 'dot-green pulse' : 'dot-red'" />
            {{ healthStatus === 'healthy' ? 'Running' : 'Stopped' }}
          </div>
          <div class="page-stat-sub">{{ status?.uptime ? formatUptime(status.uptime) : '--' }}</div>
        </div>
      </div>

      <div class="page-stat-card">
        <div class="page-stat-icon page-stat-icon--blue">
          <n-icon :size="22"><LinkOutline /></n-icon>
        </div>
        <div class="page-stat-content">
          <div class="page-stat-label">活动连接</div>
          <div class="page-stat-value">{{ connectionCount }}</div>
          <div class="page-stat-sub">
            <template v-if="protocolBreakdown.length">
              <span v-for="(item, idx) in protocolBreakdown" :key="item.name">
                {{ item.name }}: {{ item.count }}<template v-if="idx < protocolBreakdown.length - 1"> | </template>
              </span>
            </template>
            <template v-else>暂无连接</template>
          </div>
        </div>
      </div>

      <div class="page-stat-card">
        <div class="page-stat-icon" :class="memoryIconClass">
          <n-icon :size="22"><HardwareChipOutline /></n-icon>
        </div>
        <div class="page-stat-content">
          <div class="page-stat-label">内存使用</div>
          <div class="memory-bar-wrap">
            <div class="memory-bar-rail">
              <div
                class="memory-bar-fill"
                :style="{ width: memoryPercent + '%', backgroundColor: memoryColor }"
              />
            </div>
            <span class="memory-percent">{{ memoryPercent }}%</span>
          </div>
          <div class="page-stat-sub">{{ formatBytes(status?.memory?.alloc_mb || 0) }} / {{ formatBytes(status?.memory?.sys_mb || 0) }}</div>
        </div>
      </div>
    </div>

    <div class="bottom-section">
      <n-card class="page-card" :bordered="false">
        <template #header>
          <span class="page-section-title">
            <n-icon><ServerOutline /></n-icon>
            协议状态
          </span>
        </template>
        <div class="protocol-cards">
          <div
            v-for="p in protocolList"
            :key="p.name"
            class="protocol-mini-card"
            :class="{ active: p.enabled }"
          >
            <div class="protocol-icon-wrap">
              <n-icon :size="18">
                <TerminalOutline v-if="p.key === 'ssh'" />
                <CloudUploadOutline v-else-if="p.key === 'ftp'" />
                <GlobeOutline v-else-if="p.key === 'webdav'" />
                <ShieldOutline v-else-if="p.key === 'webadmin'" />
                <PersonOutline v-else-if="p.key === 'webclient'" />
                <ServerOutline v-else />
              </n-icon>
            </div>
            <div class="protocol-info">
              <span class="protocol-name">{{ p.name }}</span>
              <span class="protocol-conn">{{ p.count }} 连接</span>
            </div>
            <span class="status-dot small" :class="p.enabled ? 'dot-green pulse' : 'dot-gray'" />
          </div>
        </div>
      </n-card>

      <n-card class="page-card" :bordered="false">
        <template #header>
          <span class="page-section-title">
            <n-icon><InformationCircleOutline /></n-icon>
            系统信息
          </span>
        </template>
        <div class="page-info-grid">
          <div class="page-info-item">
            <span class="page-info-label">版本</span>
            <span class="page-info-value">{{ status?.version ? `SFTPxy ${status.version}` : '--' }}</span>
          </div>
          <div class="page-info-item">
            <span class="page-info-label">Go</span>
            <span class="page-info-value">{{ status?.runtime?.go_version || '--' }}</span>
          </div>
          <div class="page-info-item">
            <span class="page-info-label">系统</span>
            <span class="page-info-value">{{ status?.runtime ? `${status.runtime.os}/${status.runtime.arch}` : '--' }}</span>
          </div>
          <div class="page-info-item">
            <span class="page-info-label">CPU</span>
            <span class="page-info-value">{{ status?.runtime?.num_cpu ? `${status.runtime.num_cpu} 核` : '--' }}</span>
          </div>
          <div class="page-info-item">
            <span class="page-info-label">Goroutines</span>
            <span class="page-info-value">{{ status?.runtime?.num_goroutine || '--' }}</span>
          </div>
          <div class="page-info-item">
            <span class="page-info-label">GC</span>
            <span class="page-info-value">{{ status?.memory?.num_gc ?? '--' }} 次</span>
          </div>
        </div>
      </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useMessage } from 'naive-ui'
import { apiClient } from '@/api/client'
import type { SystemStatus, Connection } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import {
  RefreshOutline,
  PulseOutline,
  LinkOutline,
  HardwareChipOutline,
  TerminalOutline,
  CloudUploadOutline,
  GlobeOutline,
  ServerOutline,
  ShieldOutline,
  PersonOutline,
  InformationCircleOutline
} from '@vicons/ionicons5'

const message = useMessage()
const authStore = useAuthStore()
const status = ref<SystemStatus | null>(null)
const healthStatus = ref<string>('')
const connections = ref<Connection[]>([])
const refreshing = ref(false)

let refreshTimer: number | null = null

const connectionCount = computed(() => connections.value.length)

const protocolBreakdown = computed(() => {
  const map: Record<string, number> = {}
  for (const c of connections.value) {
    const name = c.protocol?.toUpperCase() || 'Unknown'
    map[name] = (map[name] || 0) + 1
  }
  return Object.entries(map).map(([name, count]) => ({ name, count }))
})

const protocolList = computed(() => {
  const protocols = status.value?.protocols
  const countMap: Record<string, number> = {}
  for (const c of connections.value) {
    const p = c.protocol?.toLowerCase() || ''
    countMap[p] = (countMap[p] || 0) + 1
  }
  const httpCount = countMap['http'] || 0
  return [
    { name: 'SSH/SFTP', enabled: protocols?.ssh_enabled ?? false, key: 'ssh', count: countMap['ssh'] || 0 },
    { name: 'FTP/FTPS', enabled: protocols?.ftp_enabled ?? false, key: 'ftp', count: countMap['ftp'] || 0 },
    { name: 'WebDAV', enabled: protocols?.webdav_enabled ?? false, key: 'webdav', count: countMap['webdav'] || 0 },
    { name: 'WebAdmin', enabled: protocols?.webadmin_enabled ?? false, key: 'webadmin', count: httpCount },
    { name: 'WebClient', enabled: protocols?.webclient_enabled ?? false, key: 'webclient', count: '—' }
  ]
})

const memoryPercent = computed(() => {
  const alloc = status.value?.memory?.alloc_mb || 0
  const sys = status.value?.memory?.sys_mb || 1
  return Math.round((alloc / sys) * 100)
})

const memoryColor = computed(() => {
  const p = memoryPercent.value
  if (p >= 90) return '#d03050'
  if (p >= 70) return '#f0a020'
  return '#18a058'
})

const memoryIconClass = computed(() => {
  const p = memoryPercent.value
  if (p >= 90) return 'page-stat-icon--red'
  if (p >= 70) return 'page-stat-icon--orange'
  return 'page-stat-icon--green'
})

const formatBytes = (mb: number) => `${mb.toFixed(2)} MB`

const formatUptime = (uptime: string) => {
  return uptime.replace(/(\d+h)?(\d+m)?(\d+)\.\d+s/, '$1$2$3s').replace(/(\d+)s/, '$1秒').replace(/(\d+)m/g, '$1分').replace(/(\d+)h/g, '$1时')
}

const fetchStatus = async () => {
  refreshing.value = true
  try {
    const requests: Promise<any>[] = [
      apiClient.getSystemStatus(),
      apiClient.getHealth()
    ]
    if (authStore.adminToken) {
      requests.push(apiClient.getConnections(authStore.adminToken))
    }
    const results = await Promise.allSettled(requests)
    if (results[0].status === 'fulfilled') {
      status.value = results[0].value
    }
    if (results[1].status === 'fulfilled') {
      healthStatus.value = results[1].value.status
    }
    if (results.length > 2 && results[2].status === 'fulfilled') {
      connections.value = Array.isArray(results[2].value) ? results[2].value : []
    } else {
      connections.value = []
    }
    const failed = results.filter(r => r.status === 'rejected')
    if (failed.length > 0 && failed.length === results.length) {
      message.error('获取系统状态失败: ' + (failed[0] as PromiseRejectedResult).reason?.message)
    }
  } catch (error: any) {
    message.error('获取系统状态失败: ' + error.message)
  } finally {
    refreshing.value = false
  }
}

onMounted(() => {
  fetchStatus()
  refreshTimer = window.setInterval(fetchStatus, 30000)
})

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.bottom-section {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.protocol-cards {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 12px;
}

.protocol-mini-card {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-radius: var(--app-radius-md);
  background: var(--app-bg-muted);
  border: 1px solid var(--app-border);
  transition: all 0.2s ease;
}

.protocol-mini-card.active {
  background: linear-gradient(135deg, rgba(34, 197, 94, 0.08), rgba(34, 197, 94, 0.02));
  border-color: rgba(34, 197, 94, 0.2);
}

.protocol-mini-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(15, 23, 42, 0.08);
}

.protocol-icon-wrap {
  width: 36px;
  height: 36px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--app-bg-strong);
  color: var(--app-text-secondary);
  flex-shrink: 0;
}

.protocol-mini-card.active .protocol-icon-wrap {
  color: #22c55e;
  background: rgba(34, 197, 94, 0.12);
}

.protocol-info {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.protocol-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--app-text-primary);
}

.protocol-conn {
  font-size: 13px;
  color: var(--app-text-tertiary);
}

.status-dot {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
  vertical-align: middle;
  margin-right: 6px;
}

.status-dot.small {
  width: 8px;
  height: 8px;
}

.dot-green {
  background-color: #18a058;
  box-shadow: 0 0 6px rgba(24, 160, 88, 0.4);
}

.dot-red {
  background-color: #d03050;
  box-shadow: 0 0 6px rgba(208, 48, 80, 0.4);
}

.dot-gray {
  background-color: #c2c2c2;
}

.pulse {
  animation: pulse-glow 2s ease-in-out infinite;
}

@keyframes pulse-glow {
  0%, 100% {
    box-shadow: 0 0 4px rgba(24, 160, 88, 0.3);
  }
  50% {
    box-shadow: 0 0 10px rgba(24, 160, 88, 0.6);
  }
}

.dot-red.pulse {
  animation: pulse-glow-red 2s ease-in-out infinite;
}

@keyframes pulse-glow-red {
  0%, 100% {
    box-shadow: 0 0 4px rgba(208, 48, 80, 0.3);
  }
  50% {
    box-shadow: 0 0 10px rgba(208, 48, 80, 0.6);
  }
}

.memory-bar-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 8px 0;
}

.memory-bar-rail {
  flex: 1;
  height: 10px;
  background-color: var(--app-bg-muted);
  border-radius: 5px;
  overflow: hidden;
}

.memory-bar-fill {
  height: 100%;
  border-radius: 5px;
  transition: width 0.6s ease, background-color 0.3s ease;
}

.memory-percent {
  font-size: 14px;
  font-weight: 600;
  color: var(--app-text-primary);
  min-width: 40px;
  text-align: right;
}

.page-section-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--app-text-primary);
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0;
}

@media (max-width: 1024px) {
  .bottom-section {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .protocol-cards {
    grid-template-columns: 1fr;
  }
}
</style>
