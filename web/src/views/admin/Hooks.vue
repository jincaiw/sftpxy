<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><GitBranchOutline /></n-icon>
        </div>
        <span>Hooks 配置</span>
      </div>
    </div>

    <n-spin :show="loading">
      <div class="page-grid-1">
        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><ShieldCheckmarkOutline /></n-icon>
              Auth Hook
            </span>
          </template>
          <n-form ref="authFormRef" :model="formModel" :rules="formRules" label-placement="left" label-width="120">
            <n-form-item label="类型">
              <n-select
                v-model:value="authHook.type"
                :options="hookTypeOptions"
              />
            </n-form-item>
            <n-form-item v-if="authHook.type === 'http'" label="Endpoint" path="authHookEndpoint">
              <n-input v-model:value="authHook.endpoint" placeholder="https://example.com/auth" />
            </n-form-item>
            <n-form-item v-if="authHook.type === 'command'" label="命令" path="authHookCommand">
              <n-input v-model:value="authHook.command" placeholder="/usr/local/bin/auth-hook" />
            </n-form-item>
            <n-form-item label="超时(秒)">
              <n-input-number v-model:value="authHook.timeout" :min="1" :max="300" style="width: 100%" />
            </n-form-item>
            <n-form-item label="缓存 TTL(秒)">
              <n-input-number v-model:value="authHook.cache_ttl" :min="0" :max="3600" style="width: 100%" />
            </n-form-item>
          </n-form>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><PersonOutline /></n-icon>
              Dynamic User Hook
            </span>
          </template>
          <n-form ref="dynamicUserFormRef" :model="formModel" :rules="formRules" label-placement="left" label-width="120">
            <n-form-item label="类型">
              <n-select
                v-model:value="dynamicUserHook.type"
                :options="hookTypeOptions"
              />
            </n-form-item>
            <n-form-item v-if="dynamicUserHook.type === 'http'" label="Endpoint" path="dynamicUserHookEndpoint">
              <n-input v-model:value="dynamicUserHook.endpoint" placeholder="https://example.com/dynamic-user" />
            </n-form-item>
            <n-form-item v-if="dynamicUserHook.type === 'command'" label="命令" path="dynamicUserHookCommand">
              <n-input v-model:value="dynamicUserHook.command" placeholder="/usr/local/bin/dynamic-user-hook" />
            </n-form-item>
          </n-form>
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><FileTrayOutline /></n-icon>
              File Event Hooks
            </span>
          </template>
          <template #header-extra>
            <n-button size="small" @click="addFileEventHook">
              <template #icon><n-icon><AddOutline /></n-icon></template>
              添加
            </n-button>
          </template>
          <div v-for="(hook, index) in fileEventHooks" :key="index" class="hook-item">
            <n-space align="center" :wrap="true" :size="12">
              <n-form-item label="事件类型" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-select
                  v-model:value="hook.event_type"
                  :options="fileEventOptions"
                  style="width: 140px"
                />
              </n-form-item>
              <n-form-item label="Hook 类型" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-select
                  v-model:value="hook.type"
                  :options="hookTypeOptions"
                  style="width: 120px"
                />
              </n-form-item>
              <n-form-item v-if="hook.type === 'http'" label="Endpoint" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-input v-model:value="hook.endpoint" style="width: 280px" />
              </n-form-item>
              <n-form-item v-if="hook.type === 'command'" label="命令" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-input v-model:value="hook.command" style="width: 280px" />
              </n-form-item>
              <n-form-item :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-button size="small" type="error" @click="removeFileEventHook(index)">
                  <template #icon><n-icon><TrashOutline /></n-icon></template>
                </n-button>
              </n-form-item>
            </n-space>
          </div>
          <n-empty v-if="!fileEventHooks.length" description="暂无文件事件 Hook" />
        </n-card>

        <n-card class="data-table-card" :bordered="false" size="small">
          <template #header>
            <span class="page-section-title">
              <n-icon><WifiOutline /></n-icon>
              Connection Hooks
            </span>
          </template>
          <template #header-extra>
            <n-button size="small" @click="addConnectionHook">
              <template #icon><n-icon><AddOutline /></n-icon></template>
              添加
            </n-button>
          </template>
          <div v-for="(hook, index) in connectionHooks" :key="index" class="hook-item">
            <n-space align="center" :wrap="true" :size="12">
              <n-form-item label="事件类型" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-select
                  v-model:value="hook.event_type"
                  :options="connectionEventOptions"
                  style="width: 140px"
                />
              </n-form-item>
              <n-form-item label="Hook 类型" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-select
                  v-model:value="hook.type"
                  :options="hookTypeOptions"
                  style="width: 120px"
                />
              </n-form-item>
              <n-form-item v-if="hook.type === 'http'" label="Endpoint" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-input v-model:value="hook.endpoint" style="width: 280px" />
              </n-form-item>
              <n-form-item v-if="hook.type === 'command'" label="命令" :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-input v-model:value="hook.command" style="width: 280px" />
              </n-form-item>
              <n-form-item :show-feedback="false" :style="{ marginBottom: 0 }">
                <n-button size="small" type="error" @click="removeConnectionHook(index)">
                  <template #icon><n-icon><TrashOutline /></n-icon></template>
                </n-button>
              </n-form-item>
            </n-space>
          </div>
          <n-empty v-if="!connectionHooks.length" description="暂无连接事件 Hook" />
        </n-card>
      </div>
    </n-spin>

    <div class="page-actions">
      <n-button type="primary" :loading="saving" @click="handleSave">
        保存配置
      </n-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { useMessage } from 'naive-ui'
import type { FormInst, FormRules } from 'naive-ui'
import { AddOutline, TrashOutline, GitBranchOutline, ShieldCheckmarkOutline, PersonOutline, FileTrayOutline, WifiOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'

const message = useMessage()
const authStore = useAuthStore()
const formRef = ref<FormInst | null>(null)
const authFormRef = ref<FormInst | null>(null)
const dynamicUserFormRef = ref<FormInst | null>(null)

const loading = ref(false)
const saving = ref(false)

const hookTypeOptions = [
  { label: 'HTTP', value: 'http' },
  { label: '命令', value: 'command' }
]

const fileEventOptions = [
  { label: '上传', value: 'upload' },
  { label: '下载', value: 'download' },
  { label: '删除', value: 'delete' },
  { label: '重命名', value: 'rename' },
  { label: '创建目录', value: 'mkdir' }
]

const connectionEventOptions = [
  { label: '连接建立', value: 'connect' },
  { label: '连接断开', value: 'disconnect' },
  { label: '登录', value: 'login' },
  { label: '登出', value: 'logout' }
]

interface HookEntry {
  event_type: string
  type: string
  endpoint: string
  command: string
}

const authHook = reactive({
  type: 'http',
  endpoint: '',
  command: '',
  timeout: 30,
  cache_ttl: 0
})

const dynamicUserHook = reactive({
  type: 'http',
  endpoint: '',
  command: ''
})

const fileEventHooks = ref<HookEntry[]>([])
const connectionHooks = ref<HookEntry[]>([])

const formModel = computed(() => ({
  authHookEndpoint: authHook.endpoint,
  authHookCommand: authHook.command,
  dynamicUserHookEndpoint: dynamicUserHook.endpoint,
  dynamicUserHookCommand: dynamicUserHook.command
}))

const formRules: FormRules = {
  authHookEndpoint: [
    {
      required: false,
      trigger: 'blur',
      validator: () => {
        if (authHook.type === 'http' && authHook.endpoint && !authHook.endpoint.startsWith('http')) {
          return new Error('请输入有效的 HTTP URL')
        }
        return true
      }
    }
  ],
  authHookCommand: [
    {
      required: false,
      trigger: 'blur',
      validator: () => {
        if (authHook.type === 'command' && authHook.command && !authHook.command.startsWith('/')) {
          return new Error('请输入有效的命令路径')
        }
        return true
      }
    }
  ],
  dynamicUserHookEndpoint: [
    {
      required: false,
      trigger: 'blur',
      validator: () => {
        if (dynamicUserHook.type === 'http' && dynamicUserHook.endpoint && !dynamicUserHook.endpoint.startsWith('http')) {
          return new Error('请输入有效的 HTTP URL')
        }
        return true
      }
    }
  ],
  dynamicUserHookCommand: [
    {
      required: false,
      trigger: 'blur',
      validator: () => {
        if (dynamicUserHook.type === 'command' && dynamicUserHook.command && !dynamicUserHook.command.startsWith('/')) {
          return new Error('请输入有效的命令路径')
        }
        return true
      }
    }
  ]
}

const addFileEventHook = () => {
  fileEventHooks.value.push({ event_type: 'upload', type: 'http', endpoint: '', command: '' })
}

const removeFileEventHook = (index: number) => {
  fileEventHooks.value.splice(index, 1)
}

const addConnectionHook = () => {
  connectionHooks.value.push({ event_type: 'connect', type: 'http', endpoint: '', command: '' })
}

const removeConnectionHook = (index: number) => {
  connectionHooks.value.splice(index, 1)
}

const fetchConfig = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const config = await apiClient.getConfig(token)
      const hooks = config.hooks || {}
      if (hooks.auth) {
        authHook.type = hooks.auth.type || 'http'
        authHook.endpoint = hooks.auth.endpoint || ''
        authHook.command = hooks.auth.command || ''
        authHook.timeout = hooks.auth.timeout || 30
        authHook.cache_ttl = hooks.auth.cache_ttl || 0
      }
      if (hooks.dynamic_user) {
        dynamicUserHook.type = hooks.dynamic_user.type || 'http'
        dynamicUserHook.endpoint = hooks.dynamic_user.endpoint || ''
        dynamicUserHook.command = hooks.dynamic_user.command || ''
      }
      fileEventHooks.value = (hooks.file_events || []).map((h: any) => ({
        event_type: h.event_type || 'upload',
        type: h.type || 'http',
        endpoint: h.endpoint || '',
        command: h.command || ''
      }))
      connectionHooks.value = (hooks.connection_events || []).map((h: any) => ({
        event_type: h.event_type || 'connect',
        type: h.type || 'http',
        endpoint: h.endpoint || '',
        command: h.command || ''
      }))
    }
  } catch (error: any) {
    message.error('获取 Hook 配置失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleSave = async () => {
  try {
    await Promise.all([
      authFormRef.value?.validate(),
      dynamicUserFormRef.value?.validate()
    ])
  } catch {
    return
  }

  for (let i = 0; i < fileEventHooks.value.length; i++) {
    const hook = fileEventHooks.value[i]
    if (!hook.event_type) {
      message.error(`文件事件 Hook ${i + 1}: 请选择事件类型`)
      return
    }
    if (hook.type === 'http' && !hook.endpoint) {
      message.error(`文件事件 Hook ${i + 1}: 请输入端点 URL`)
      return
    }
    if (hook.type === 'command' && !hook.command) {
      message.error(`文件事件 Hook ${i + 1}: 请输入命令路径`)
      return
    }
  }

  for (let i = 0; i < connectionHooks.value.length; i++) {
    const hook = connectionHooks.value[i]
    if (!hook.event_type) {
      message.error(`连接事件 Hook ${i + 1}: 请选择事件类型`)
      return
    }
    if (hook.type === 'http' && !hook.endpoint) {
      message.error(`连接事件 Hook ${i + 1}: 请输入端点 URL`)
      return
    }
    if (hook.type === 'command' && !hook.command) {
      message.error(`连接事件 Hook ${i + 1}: 请输入命令路径`)
      return
    }
  }

  saving.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      const hooksConfig: Record<string, any> = {
        auth: {
          type: authHook.type,
          endpoint: authHook.type === 'http' ? authHook.endpoint : undefined,
          command: authHook.type === 'command' ? authHook.command : undefined,
          timeout: authHook.timeout,
          cache_ttl: authHook.cache_ttl
        },
        dynamic_user: {
          type: dynamicUserHook.type,
          endpoint: dynamicUserHook.type === 'http' ? dynamicUserHook.endpoint : undefined,
          command: dynamicUserHook.type === 'command' ? dynamicUserHook.command : undefined
        },
        file_events: fileEventHooks.value.map((h) => ({
          event_type: h.event_type,
          type: h.type,
          endpoint: h.type === 'http' ? h.endpoint : undefined,
          command: h.type === 'command' ? h.command : undefined
        })),
        connection_events: connectionHooks.value.map((h) => ({
          event_type: h.event_type,
          type: h.type,
          endpoint: h.type === 'http' ? h.endpoint : undefined,
          command: h.type === 'command' ? h.command : undefined
        }))
      }
      await apiClient.updateConfig(token, { hooks: hooksConfig })
      message.success('Hook 配置已保存')
    }
  } catch (error: any) {
    message.error('保存 Hook 配置失败: ' + error.message)
  } finally {
    saving.value = false
  }
}

onMounted(fetchConfig)
</script>
