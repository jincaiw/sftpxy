<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><KeyOutline /></n-icon>
        </div>
        <span>角色管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" data-testid="admin-roles-create" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建角色
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="roles"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="900"
      />
    </n-card>

    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="editingRole ? '编辑角色' : '新建角色'"
      style="max-width: 640px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="rules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '92'"
        data-testid="admin-role-form"
      >
        <n-form-item label="名称" path="name">
          <n-input
            v-model:value="formValue.name"
            :input-props="{ 'data-testid': 'admin-role-name' }"
          />
        </n-form-item>
        <n-form-item label="描述" path="description">
          <n-input
            v-model:value="formValue.description"
            type="textarea"
            :autosize="{ minRows: 2, maxRows: 4 }"
            :input-props="{ 'data-testid': 'admin-role-description' }"
          />
        </n-form-item>
        <n-form-item label="权限">
          <div class="permission-groups">
            <div v-for="group in permissionGroups" :key="group.label" class="permission-group">
              <div class="permission-group__header">
                <span class="permission-group__label">{{ group.label }}</span>
                <n-button text size="tiny" @click="toggleGroup(group)">
                  {{ isGroupAllSelected(group) ? '取消全选' : '全选' }}
                </n-button>
              </div>
              <n-checkbox-group v-model:value="formValue.permissions">
                <n-space item-style="display: flex; flex-wrap: wrap; gap: 4px;">
                  <n-checkbox
                    v-for="perm in group.permissions"
                    :key="perm.value"
                    :value="perm.value"
                    :label="perm.label"
                  />
                </n-space>
              </n-checkbox-group>
            </div>
          </div>
        </n-form-item>
        <n-form-item label="范围 JSON" path="scopeText">
          <n-input
            v-model:value="formValue.scopeText"
            type="textarea"
            placeholder='例如：{"tenant":"default"}'
            :autosize="{ minRows: 4, maxRows: 8 }"
            :input-props="{ 'data-testid': 'admin-role-scope' }"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="admin-role-cancel" @click="showModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" data-testid="admin-role-submit" @click="handleSubmit">
            {{ editingRole ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除角色 ${deletingRole?.name} 吗？`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { h, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useMessage, NButton, NIcon, NTag, NSpace } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, KeyOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { apiClient } from '@/api/client'
import type { RoleItem } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const permissionGroups = [
  {
    label: '用户管理',
    permissions: [
      { label: '查看用户', value: 'users:read' },
      { label: '管理用户', value: 'users:write' }
    ]
  },
  {
    label: '管理员管理',
    permissions: [
      { label: '查看管理员', value: 'admins:read' },
      { label: '管理管理员', value: 'admins:write' }
    ]
  },
  {
    label: '角色管理',
    permissions: [
      { label: '查看角色', value: 'roles:read' },
      { label: '管理角色', value: 'roles:write' }
    ]
  },
  {
    label: '用户组管理',
    permissions: [
      { label: '查看用户组', value: 'groups:read' },
      { label: '管理用户组', value: 'groups:write' }
    ]
  },
  {
    label: '连接管理',
    permissions: [
      { label: '查看连接', value: 'connections:read' },
      { label: '管理连接', value: 'connections:write' }
    ]
  },
  {
    label: '审计日志',
    permissions: [
      { label: '查看日志', value: 'logs:read' }
    ]
  },
  {
    label: '事件管理',
    permissions: [
      { label: '查看事件', value: 'events:read' },
      { label: '管理事件', value: 'events:write' }
    ]
  },
  {
    label: '虚拟目录',
    permissions: [
      { label: '查看目录', value: 'folders:read' },
      { label: '管理目录', value: 'folders:write' }
    ]
  },
  {
    label: '超级权限',
    permissions: [
      { label: '全部权限', value: '*' }
    ]
  }
]

const roles = ref<RoleItem[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const showDeleteConfirm = ref(false)
const editingRole = ref<RoleItem | null>(null)
const deletingRole = ref<RoleItem | null>(null)
const formRef = ref<FormInst | null>(null)

const formValue = reactive({
  name: '',
  description: '',
  permissions: [] as string[],
  scopeText: '{}'
})

const rules = {
  name: { required: true, message: '请输入角色名称', trigger: 'blur' }
}

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const isGroupAllSelected = (group: typeof permissionGroups[number]) => {
  return group.permissions.every((p) => formValue.permissions.includes(p.value))
}

const toggleGroup = (group: typeof permissionGroups[number]) => {
  const groupValues = group.permissions.map((p) => p.value)
  if (isGroupAllSelected(group)) {
    formValue.permissions = formValue.permissions.filter((v) => !groupValues.includes(v))
  } else {
    const newPerms = new Set(formValue.permissions)
    groupValues.forEach((v) => newPerms.add(v))
    formValue.permissions = [...newPerms]
  }
}

const resetForm = () => {
  formValue.name = ''
  formValue.description = ''
  formValue.permissions = []
  formValue.scopeText = '{}'
  editingRole.value = null
}

const formatScope = (scope?: Record<string, unknown>) => JSON.stringify(scope || {}, null, 2)

const columns: DataTableColumns<RoleItem> = [
  { title: 'ID', key: 'id', width: 64 },
  { title: '名称', key: 'name' },
  { title: '描述', key: 'description' },
  {
    title: '权限',
    key: 'permissions',
    render: (row) =>
      row.permissions?.length
        ? h(
            NSpace,
            { size: [6, 6], wrap: true },
            {
              default: () =>
                row.permissions.map((permission) =>
                  h(
                    NTag,
                    { size: 'small', type: 'info', round: true },
                    { default: () => permission }
                  )
                )
            }
          )
        : h(
            NTag,
            { size: 'small', round: true },
            { default: () => '未配置' }
          )
  },
  {
    title: '范围',
    key: 'scope',
    width: 220,
    render: (row) =>
      h(
        'code',
        {
          style: 'display: block; white-space: pre-wrap; font-size: 12px; color: var(--app-text-secondary);'
        },
        formatScope(row.scope)
      )
  },
  { title: '创建时间', key: 'created_at', width: 180, render: (row) => formatTime(row.created_at) },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    render: (row) =>
      h('div', { style: 'display: flex; gap: 8px' }, [
        h(
          NButton,
          {
            size: 'small',
            'data-testid': `admin-role-edit-${row.id}`,
            onClick: () => handleEdit(row)
          },
          {
            default: () => '编辑',
            icon: () => h(NIcon, null, { default: () => h(CreateOutline) })
          }
        ),
        h(
          NButton,
          {
            size: 'small',
            type: 'error',
            'data-testid': `admin-role-delete-${row.id}`,
            onClick: () => handleDeleteClick(row)
          },
          {
            default: () => '删除',
            icon: () => h(NIcon, null, { default: () => h(TrashOutline) })
          }
        )
      ])
  }
]

const fetchRoles = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (!token) return
    roles.value = await apiClient.getRoles(token)
  } catch (error: any) {
    message.error('获取角色列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showModal.value = true
}

const handleEdit = (role: RoleItem) => {
  editingRole.value = role
  formValue.name = role.name
  formValue.description = role.description || ''
  formValue.permissions = [...(role.permissions || [])]
  formValue.scopeText = formatScope(role.scope)
  showModal.value = true
}

const handleDeleteClick = (role: RoleItem) => {
  deletingRole.value = role
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingRole.value) return
  try {
    const token = authStore.adminToken
    if (!token) return
    await apiClient.deleteRole(token, deletingRole.value.id)
    message.success('角色已删除')
    showDeleteConfirm.value = false
    deletingRole.value = null
    await fetchRoles()
  } catch (error: any) {
    message.error('删除角色失败: ' + error.message)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return

  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (!token) return

    let scope: Record<string, unknown> = {}
    const scopeText = formValue.scopeText.trim()
    if (scopeText) {
      const parsed = JSON.parse(scopeText)
      if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
        throw new Error('范围 JSON 必须是对象')
      }
      scope = parsed as Record<string, unknown>
    }

    const payload = {
      name: formValue.name.trim(),
      description: formValue.description.trim(),
      permissions: formValue.permissions,
      scope
    }

    if (editingRole.value) {
      await apiClient.updateRole(token, editingRole.value.id, payload)
      message.success('角色已更新')
    } else {
      await apiClient.createRole(token, payload)
      message.success('角色已创建')
    }

    showModal.value = false
    resetForm()
    await fetchRoles()
  } catch (error: any) {
    message.error('保存角色失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}

onMounted(fetchRoles)
</script>

<style scoped>
.permission-groups {
  display: flex;
  flex-direction: column;
  gap: 12px;
  width: 100%;
}

.permission-group {
  padding: 10px 12px;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-bg-muted);
}

.permission-group__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.permission-group__label {
  font-weight: 600;
  font-size: 13px;
  color: var(--app-text-primary);
}
</style>
