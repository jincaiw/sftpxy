<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><FlashOutline /></n-icon>
        </div>
        <span>事件规则管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建规则
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="rules"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="800"
      />
    </n-card>

    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="editingRule ? '编辑事件规则' : '新建事件规则'"
      style="max-width: 640px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="formRules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '100'"
      >
        <n-form-item label="规则名称" path="name">
          <n-input v-model:value="formValue.name" />
        </n-form-item>
        <n-form-item label="触发类型" path="trigger_type">
          <n-select
            v-model:value="formValue.trigger_type"
            :options="triggerTypeOptions"
            clearable
          />
        </n-form-item>
        <n-form-item v-if="formValue.trigger_type === 'schedule'" label="Cron 表达式" path="schedule">
          <n-input-group>
            <n-select
              v-model:value="formValue.schedule"
              :options="cronPresetOptions"
              placeholder="选择预设"
              clearable
              style="width: 180px"
            />
            <n-input v-model:value="formValue.schedule" placeholder="0 2 * * *" style="flex: 1" />
          </n-input-group>
        </n-form-item>
        <n-form-item label="条件">
          <div style="width: 100%">
            <div v-for="(cond, index) in formConditions" :key="index" style="display: flex; gap: 8px; margin-bottom: 8px; align-items: center;">
              <n-select v-model:value="cond.field" :options="conditionFieldOptions" placeholder="字段" clearable style="min-width: 120px" />
              <n-select v-model:value="cond.operator" :options="conditionOperatorOptions" placeholder="运算符" clearable style="min-width: 110px" />
              <n-input v-model:value="cond.valueText" placeholder="值" style="flex: 1" />
              <n-button quaternary circle @click="removeCondition(index)">
                <template #icon><n-icon><CloseOutline /></n-icon></template>
              </n-button>
            </div>
            <n-button dashed block @click="addCondition">
              <template #icon><n-icon><AddOutline /></n-icon></template>
              添加条件
            </n-button>
          </div>
        </n-form-item>
        <n-form-item label="动作">
          <div style="width: 100%">
            <n-card v-for="(action, index) in formActions" :key="index" size="small" style="margin-bottom: 8px" :bordered="true">
              <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 8px;">
                <n-select v-model:value="action.type" :options="actionTypeOptions" placeholder="动作类型" clearable style="min-width: 160px" />
                <n-button quaternary circle @click="removeAction(index)">
                  <template #icon><n-icon><CloseOutline /></n-icon></template>
                </n-button>
              </div>
              <div v-if="action.type === 'http' || action.type === 'external_callback'">
                <n-input v-model:value="action.configUrl" placeholder="URL" style="margin-bottom: 4px" />
                <n-select v-model:value="action.configMethod" :options="httpMethodOptions" placeholder="HTTP方法" clearable style="width: 120px; margin-bottom: 4px" />
              </div>
              <div v-else-if="action.type === 'command' || action.type === 'custom_script'">
                <n-input v-model:value="action.configCommand" placeholder="命令" />
              </div>
              <div v-else-if="action.type === 'email'">
                <n-input v-model:value="action.configTo" placeholder="收件人邮箱" style="margin-bottom: 4px" />
                <n-input v-model:value="action.configSubject" placeholder="邮件主题" />
              </div>
              <div v-else-if="action.type === 'file_delete'">
                <n-input v-model:value="action.configPath" placeholder="要删除的文件路径" />
              </div>
              <div v-else-if="action.type === 'file_move' || action.type === 'file_copy'">
                <n-input v-model:value="action.configSource" placeholder="源路径" style="margin-bottom: 4px" />
                <n-input v-model:value="action.configDest" placeholder="目标路径" />
              </div>
              <div v-else-if="action.type === 'data_retention'">
                <n-input v-model:value="action.configDirectory" placeholder="扫描目录路径" style="margin-bottom: 4px" />
                <n-input-number v-model:value="action.configDays" placeholder="保留天数" :min="1" style="width: 100%" />
              </div>
              <div v-else-if="action.type === 'batch_delete'">
                <n-input v-model:value="action.configDirectory" placeholder="扫描目录路径，如 /data/temp" style="margin-bottom: 4px" />
                <n-input-number v-model:value="action.configMaxAgeDays" placeholder="文件最大保留天数" :min="1" style="width: 100%; margin-bottom: 4px" />
                <n-space :size="12" style="margin-bottom: 4px">
                  <n-switch v-model:value="action.configRecursive">
                    <template #checked>是</template>
                    <template #unchecked>否</template>
                  </n-switch>
                  <n-switch v-model:value="action.configDeleteEmptyDirs">
                    <template #checked>是</template>
                    <template #unchecked>否</template>
                  </n-switch>
                </n-space>
                <n-input-number v-model:value="action.configMaxDeletes" placeholder="单次最大删除数 (默认1000)" :min="1" style="width: 100%" />
              </div>
              <div v-else-if="action.type === 'quota_scan'">
                <n-input v-model:value="action.configUsername" placeholder="要扫描配额的用户名" />
              </div>
            </n-card>
            <n-button dashed block @click="addAction">
              <template #icon><n-icon><AddOutline /></n-icon></template>
              添加动作
            </n-button>
          </div>
        </n-form-item>
        <n-form-item label="启用">
          <n-switch v-model:value="formValue.is_active" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" @click="handleSubmit">
            {{ editingRule ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除事件规则 ${deletingRule?.name} 吗？`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, h, onMounted, onUnmounted } from 'vue'
import { useMessage, useDialog, NTag, NButton, NIcon, NSwitch } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, CloseOutline, FlashOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { EventRule } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const dialog = useDialog()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const rules = ref<EventRule[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const showDeleteConfirm = ref(false)
const editingRule = ref<EventRule | null>(null)
const deletingRule = ref<EventRule | null>(null)
const formRef = ref<FormInst | null>(null)

const triggerTypeOptions = [
  { label: '文件上传', value: 'upload' },
  { label: '文件下载', value: 'download' },
  { label: '文件删除', value: 'delete' },
  { label: '文件重命名', value: 'rename' },
  { label: '用户登录', value: 'login' },
  { label: '用户登出', value: 'logout' },
  { label: '连接建立', value: 'connect' },
  { label: '连接断开', value: 'disconnect' },
  { label: '定时调度', value: 'schedule' }
]

const formValue = reactive({
  name: '',
  trigger_type: null as string | null,
  is_active: true,
  schedule: ''
})

const conditionFieldOptions = [
  { label: '协议', value: 'protocol' },
  { label: '路径', value: 'path' },
  { label: '文件扩展名', value: 'file_ext' },
  { label: '文件大小', value: 'file_size' },
  { label: '用户名', value: 'username' },
  { label: 'IP地址', value: 'ip_address' },
  { label: '结果', value: 'result' },
  { label: '扫描目录', value: 'directory' },
  { label: '文件年龄(天)', value: 'file_age' }
]

const conditionOperatorOptions = [
  { label: '等于', value: 'eq' },
  { label: '不等于', value: 'ne' },
  { label: '包含', value: 'contains' },
  { label: '开头是', value: 'starts_with' },
  { label: '结尾是', value: 'ends_with' },
  { label: '大于', value: 'gt' },
  { label: '小于', value: 'lt' },
  { label: '大于等于', value: 'gte' },
  { label: '小于等于', value: 'lte' },
  { label: '在列表中', value: 'in' },
  { label: '正则匹配', value: 'regex' }
]

interface FormCondition {
  field: string | null
  operator: string | null
  valueText: string
}

const formConditions = ref<FormCondition[]>([])

const addCondition = () => {
  formConditions.value.push({ field: null, operator: null, valueText: '' })
}

const removeCondition = (index: number) => {
  formConditions.value.splice(index, 1)
}

const actionTypeOptions = [
  { label: 'HTTP 请求', value: 'http' },
  { label: '执行命令', value: 'command' },
  { label: '发送邮件', value: 'email' },
  { label: '删除文件', value: 'file_delete' },
  { label: '移动文件', value: 'file_move' },
  { label: '复制文件', value: 'file_copy' },
  { label: '数据保留', value: 'data_retention' },
  { label: '批量删除', value: 'batch_delete' },
  { label: '配额扫描', value: 'quota_scan' },
  { label: '外部回调', value: 'external_callback' },
  { label: '自定义脚本', value: 'custom_script' }
]

const httpMethodOptions = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'PUT', value: 'PUT' },
  { label: 'PATCH', value: 'PATCH' }
]

const cronPresetOptions = [
  { label: '每小时', value: '0 * * * *' },
  { label: '每天凌晨2点', value: '0 2 * * *' },
  { label: '每天凌晨3点', value: '0 3 * * *' },
  { label: '每周一凌晨2点', value: '0 2 * * 1' },
  { label: '每月1日凌晨2点', value: '0 2 1 * *' },
  { label: '每5分钟', value: '*/5 * * * *' }
]

interface FormAction {
  type: string | null
  configUrl: string
  configMethod: string
  configCommand: string
  configTo: string
  configSubject: string
  configPath: string
  configSource: string
  configDest: string
  configDays: number | null
  configDirectory: string
  configMaxAgeDays: number | null
  configRecursive: boolean
  configDeleteEmptyDirs: boolean
  configMaxDeletes: number | null
  configUsername: string
}

const formActions = ref<FormAction[]>([])

const addAction = () => {
  formActions.value.push({ type: null, configUrl: '', configMethod: 'POST', configCommand: '', configTo: '', configSubject: '', configPath: '', configSource: '', configDest: '', configDays: null, configDirectory: '', configMaxAgeDays: null, configRecursive: true, configDeleteEmptyDirs: false, configMaxDeletes: null, configUsername: '' })
}

const removeAction = (index: number) => {
  formActions.value.splice(index, 1)
}

const formRules = {
  name: { required: true, message: '请输入规则名称', trigger: 'blur' },
  trigger_type: { required: true, message: '请选择触发类型', trigger: 'change' }
}

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const resetForm = () => {
  formValue.name = ''
  formValue.trigger_type = null
  formValue.is_active = true
  formValue.schedule = ''
  formConditions.value = []
  formActions.value = []
  editingRule.value = null
}

const columns: DataTableColumns<EventRule> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name' },
  {
    title: '触发类型',
    key: 'trigger_type',
    render: (row) => h(
      NTag,
      { size: 'small', type: 'info' },
      { default: () => triggerTypeOptions.find((t) => t.value === row.trigger_type)?.label || row.trigger_type }
    )
  },
  {
    title: '条件',
    key: 'conditions',
    render: (row) => {
      const conds = row.conditions || []
      if (conds.length === 0) return h('span', { style: 'color: #999' }, '无条件')
      return h('div', { style: 'display: flex; flex-wrap: wrap; gap: 4px' },
        conds.map((c: any) => h(NTag, { size: 'small', type: 'info' }, {
          default: () => `${conditionFieldOptions.find(f => f.value === c.field)?.label || c.field} ${conditionOperatorOptions.find(o => o.value === c.operator)?.label || c.operator} ${c.value}`
        }))
      )
    }
  },
  {
    title: '动作',
    key: 'rule_actions',
    render: (row) => {
      const acts = row.actions || []
      if (acts.length === 0) return h('span', { style: 'color: #999' }, '无动作')
      return h('div', { style: 'display: flex; flex-wrap: wrap; gap: 4px' },
        acts.map((a: any) => h(NTag, { size: 'small', type: 'success' }, {
          default: () => actionTypeOptions.find(t => t.value === a.type)?.label || a.type
        }))
      )
    }
  },
  {
    title: '状态',
    key: 'is_active',
    width: 100,
    render: (row) => h(NSwitch, {
      value: row.is_active,
      onUpdateValue: (val: boolean) => handleToggle(row, val)
    })
  },
  { title: '创建时间', key: 'created_at', width: 170, render: (row) => formatTime(row.created_at) },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: (row) => h('div', { style: 'display: flex; gap: 8px' }, [
      h(
        NButton,
        { size: 'small', onClick: () => handleEdit(row) },
        { default: () => '编辑', icon: () => h(NIcon, null, { default: () => h(CreateOutline) }) }
      ),
      h(
        NButton,
        { size: 'small', type: 'error', onClick: () => handleDeleteClick(row) },
        { default: () => '删除', icon: () => h(NIcon, null, { default: () => h(TrashOutline) }) }
      )
    ])
  }
]

const fetchRules = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      rules.value = (await apiClient.listEventRules(token)).items
    }
  } catch (error: any) {
    message.error('获取事件规则列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showModal.value = true
}

const handleEdit = (rule: EventRule) => {
  editingRule.value = rule
  formValue.name = rule.name
  formValue.trigger_type = rule.trigger_type
  formValue.is_active = rule.is_active
  formValue.schedule = (rule as any).schedule || ''
  formConditions.value = (rule.conditions || []).map((c: any) => ({
    field: c.field || null,
    operator: c.operator || null,
    valueText: String(c.value ?? '')
  }))
  formActions.value = (rule.actions || []).map((a: any) => ({
    type: a.type || null,
    configUrl: a.config?.url || '',
    configMethod: a.config?.method || 'POST',
    configCommand: a.config?.command || '',
    configTo: a.config?.to || '',
    configSubject: a.config?.subject || '',
    configPath: a.config?.path || '',
    configSource: a.config?.source || '',
    configDest: a.config?.destination || '',
    configDays: a.config?.max_age_seconds ? Math.round(a.config.max_age_seconds / 86400) : (a.config?.days || null),
    configDirectory: a.config?.directory || '',
    configMaxAgeDays: a.config?.max_age_days || a.config?.days || null,
    configRecursive: a.config?.recursive !== undefined ? a.config.recursive : true,
    configDeleteEmptyDirs: a.config?.delete_empty_dirs || false,
    configMaxDeletes: a.config?.max_deletes || null,
    configUsername: a.config?.username || ''
  }))
  showModal.value = true
}

const handleDeleteClick = (rule: EventRule) => {
  deletingRule.value = rule
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingRule.value) return
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.deleteEventRule(token, deletingRule.value.id)
      message.success('事件规则已删除')
      showDeleteConfirm.value = false
      deletingRule.value = null
      await fetchRules()
    }
  } catch (error: any) {
    message.error('删除事件规则失败: ' + error.message)
  }
}

const handleToggle = (rule: EventRule, is_active: boolean) => {
  dialog.warning({
    title: '确认操作',
    content: `确定要${rule.is_active ? '禁用' : '启用'}规则 "${rule.name}" 吗？`,
    positiveText: '确定',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        const token = authStore.adminToken
        if (token) {
          await apiClient.updateEventRule(token, rule.id, { is_active })
          message.success(is_active ? '规则已启用' : '规则已禁用')
          await fetchRules()
        }
      } catch (error: any) {
        message.error('更新规则状态失败: ' + error.message)
      }
    }
  })
}

const handleSubmit = async () => {
  if (!formRef.value) return
  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (token) {
      const conditions = formConditions.value
        .filter(c => c.field && c.operator)
        .map((c, i) => ({
          field: c.field!,
          operator: c.operator!,
          value: c.valueText
        }))
      const actions = formActions.value
        .filter(a => a.type)
        .map((a, i) => {
          const config: Record<string, any> = {}
          const actionType = a.type!
          if (actionType === 'http' || actionType === 'external_callback') {
            if (a.configUrl) config.url = a.configUrl
            if (a.configMethod) config.method = a.configMethod
          } else if (actionType === 'command' || actionType === 'custom_script') {
            if (a.configCommand) config.command = a.configCommand
          } else if (actionType === 'email') {
            if (a.configTo) config.to = a.configTo
            if (a.configSubject) config.subject = a.configSubject
          } else if (actionType === 'file_delete') {
            if (a.configPath) config.path = a.configPath
          } else if (actionType === 'file_move' || actionType === 'file_copy') {
            if (a.configSource) config.source = a.configSource
            if (a.configDest) config.destination = a.configDest
          } else if (actionType === 'data_retention') {
            if (a.configDirectory) config.directory = a.configDirectory
            if (a.configDays) config.max_age_seconds = a.configDays * 86400
          } else if (actionType === 'batch_delete') {
            if (a.configDirectory) config.directory = a.configDirectory
            if (a.configMaxAgeDays) config.max_age_days = a.configMaxAgeDays
            config.recursive = a.configRecursive
            config.delete_empty_dirs = a.configDeleteEmptyDirs
            if (a.configMaxDeletes) config.max_deletes = a.configMaxDeletes
          } else if (actionType === 'quota_scan') {
            if (a.configUsername) config.username = a.configUsername
          }
          return { type: actionType, config, order_index: i }
        })
      const payload: Partial<EventRule> = {
        name: formValue.name.trim(),
        trigger_type: formValue.trigger_type || '',
        conditions,
        actions,
        is_active: formValue.is_active,
        schedule: formValue.trigger_type === 'schedule' ? formValue.schedule : ''
      } as any
      if (editingRule.value) {
        await apiClient.updateEventRule(token, editingRule.value.id, payload)
        message.success('事件规则已更新')
      } else {
        await apiClient.createEventRule(token, payload)
        message.success('事件规则已创建')
      }
      showModal.value = false
      resetForm()
      await fetchRules()
    }
  } catch (error: any) {
    message.error('保存事件规则失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}

onMounted(fetchRules)
</script>
