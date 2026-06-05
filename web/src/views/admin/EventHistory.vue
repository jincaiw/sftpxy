<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><TimeOutline /></n-icon>
        </div>
        <span>事件执行历史</span>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <template #header>
        <span class="page-section-title">筛选</span>
      </template>
      <div class="filter-section">
        <div class="filter-bar">
          <n-select
            v-model:value="filterRule"
            :options="ruleFilterOptions"
            style="min-width: 160px"
            clearable
            placeholder="筛选规则"
            @update:value="debouncedFetchHistory"
          />
          <n-select
            v-model:value="filterStatus"
            :options="statusFilterOptions"
            style="min-width: 130px"
            @update:value="debouncedFetchHistory"
          />
          <n-date-picker
            v-model:value="dateRange"
            type="datetimerange"
            clearable
            @update:value="debouncedFetchHistory"
          />
          <n-button @click="fetchHistory" :loading="loading" class="filter-search-btn">
            <template #icon><n-icon><SearchOutline /></n-icon></template>
            搜索
          </n-button>
        </div>
      </div>
      <n-data-table
        :columns="columns"
        :data="historyItems"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="850"
      />
    </n-card>

    <n-modal
      v-model:show="showErrorModal"
      preset="card"
      title="错误详情"
      style="max-width: 560px; width: 90vw"
    >
      <n-code :code="errorDetail" language="text" word-wrap />
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, h, onMounted, reactive, computed } from 'vue'
import { useMessage, NTag, NButton, NIcon } from 'naive-ui'
import type { DataTableColumns } from 'naive-ui'
import { SearchOutline, TimeOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { EventHistoryItem, EventRule } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const historyItems = ref<EventHistoryItem[]>([])
const eventRules = ref<EventRule[]>([])
const loading = ref(false)
const filterRule = ref<number | null>(null)
const filterStatus = ref('')
const dateRange = ref<[number, number] | null>(null)
const showErrorModal = ref(false)
const errorDetail = ref('')
let debounceTimer: ReturnType<typeof setTimeout> | null = null

const debouncedFetchHistory = () => {
  if (debounceTimer) clearTimeout(debounceTimer)
  debounceTimer = setTimeout(() => fetchHistory(), 300)
}

const statusFilterOptions = [
  { label: '全部状态', value: '' },
  { label: '成功', value: 'success' },
  { label: '失败', value: 'failed' }
]

const ruleFilterOptions = computed(() =>
  eventRules.value.map((r) => ({ label: r.name, value: r.id }))
)

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50, 100]
})

const columns: DataTableColumns<EventHistoryItem> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '规则名称', key: 'rule_name', width: 150 },
  {
    title: '动作类型',
    key: 'action_type',
    width: 120,
    render: (row) => h(NTag, { size: 'small', type: 'info' }, { default: () => row.action_type })
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
    render: (row) => h(
      NTag,
      { size: 'small', type: row.status === 'success' ? 'success' : 'error' },
      { default: () => row.status === 'success' ? '成功' : '失败' }
    )
  },
  { title: '开始时间', key: 'started_at', width: 180, render: (row) => formatTime(row.started_at) },
  {
    title: '耗时',
    key: 'duration_ms',
    width: 100,
    render: (row) => `${row.duration_ms}ms`
  },
  {
    title: '错误',
    key: 'error',
    render: (row) => row.error
      ? h(
          NButton,
          { size: 'small', type: 'error', onClick: () => handleViewError(row) },
          { default: () => '查看' }
        )
      : h('span', { style: 'color: var(--n-text-color-disabled)' }, '无')
  }
]

const fetchRules = async () => {
  try {
    const token = authStore.adminToken
    if (token) {
      eventRules.value = (await apiClient.listEventRules(token)).items
    }
  } catch (_error) {
    // silently fail - rule filter is optional
  }
}

const fetchHistory = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const params: Record<string, any> = {}
      if (filterRule.value) params.rule_id = filterRule.value
      if (filterStatus.value) params.status = filterStatus.value
      if (dateRange.value) {
        params.from = new Date(dateRange.value[0]).toISOString()
        params.to = new Date(dateRange.value[1]).toISOString()
      }
      historyItems.value = (await apiClient.listEventHistory(token, params)).items
    }
  } catch (error: any) {
    message.error('获取事件历史失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleViewError = (item: EventHistoryItem) => {
  errorDetail.value = item.error || '无错误信息'
  showErrorModal.value = true
}

onMounted(async () => {
  await fetchRules()
  await fetchHistory()
})
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
