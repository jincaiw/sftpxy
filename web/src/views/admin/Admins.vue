<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><ShieldOutline /></n-icon>
        </div>
        <span>管理员管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" data-testid="admin-admins-create" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建管理员
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="admins"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="1100"
      />
    </n-card>

    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="editingAdmin ? '编辑管理员' : '新建管理员'"
      style="max-width: 560px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="rules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '90'"
        data-testid="admin-admin-form"
      >
        <n-form-item label="用户名" path="username">
          <n-input
            v-model:value="formValue.username"
            :disabled="!!editingAdmin"
            :input-props="{ 'data-testid': 'admin-admin-username' }"
          />
        </n-form-item>
        <n-form-item label="角色" path="role_id">
          <n-select
            v-model:value="formValue.role_id"
            clearable
            placeholder="选择角色"
            :options="roleOptions"
            data-testid="admin-admin-role"
          />
        </n-form-item>
        <n-form-item label="权限" path="permissionsText">
          <n-input
            v-model:value="formValue.permissionsText"
            type="textarea"
            placeholder="留空表示使用超级管理员默认权限；可填写如 users:read, groups:write"
            :autosize="{ minRows: 3, maxRows: 6 }"
            :input-props="{ 'data-testid': 'admin-admin-permissions' }"
          />
        </n-form-item>
        <n-form-item label="状态" path="status">
          <n-select
            v-model:value="formValue.status"
            :options="statusOptions"
            data-testid="admin-admin-status"
          />
        </n-form-item>
        <n-form-item :label="editingAdmin ? '新密码' : '密码'" path="password">
          <n-input
            v-model:value="formValue.password"
            type="password"
            show-password-on="click"
            placeholder="编辑时留空表示不修改"
            :input-props="{ 'data-testid': 'admin-admin-password' }"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="admin-admin-cancel" @click="showModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" data-testid="admin-admin-submit" @click="handleSubmit">
            {{ editingAdmin ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除管理员 ${deletingAdmin?.username} 吗？此操作不可撤销。`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, h, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useMessage, NButton, NIcon, NTag, NSpace } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, ShieldOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { apiClient } from '@/api/client'
import type { AdminAccount, RoleItem } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const admins = ref<AdminAccount[]>([])
const roles = ref<RoleItem[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const showDeleteConfirm = ref(false)
const editingAdmin = ref<AdminAccount | null>(null)
const deletingAdmin = ref<AdminAccount | null>(null)
const formRef = ref<FormInst | null>(null)

const formValue = reactive<{
  username: string
  status: string
  role_id: number | null
  permissionsText: string
  password: string
}>({
  username: '',
  status: 'active',
  role_id: null,
  permissionsText: '',
  password: ''
})

const rules = computed(() => ({
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  password: editingAdmin.value
    ? { required: false, trigger: 'blur' }
    : { required: true, message: '请输入密码', trigger: 'blur' }
}))

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const statusOptions = [
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
]

const roleOptions = computed(() =>
  roles.value.map((role) => ({
    label: role.name,
    value: role.id
  }))
)

const roleNameMap = computed(() =>
  roles.value.reduce<Record<number, string>>((acc, role) => {
    acc[role.id] = role.name
    return acc
  }, {})
)

const resetForm = () => {
  formValue.username = ''
  formValue.status = 'active'
  formValue.role_id = null
  formValue.permissionsText = ''
  formValue.password = ''
  editingAdmin.value = null
}

const parsePermissions = (value: string) =>
  value
    .split(/[\n,\s]+/)
    .map((item) => item.trim())
    .filter(Boolean)

const columns: DataTableColumns<AdminAccount> = [
  { title: 'ID', key: 'id', width: 64 },
  { title: '用户名', key: 'username' },
  {
    title: '角色',
    key: 'role_id',
    render: (row) =>
      row.role_id
        ? h(
            NTag,
            { type: 'info', round: true },
            { default: () => roleNameMap.value[row.role_id as number] || `角色 #${row.role_id}` }
          )
        : h(
            NTag,
            { type: 'default', round: true },
            { default: () => '未分配' }
          )
  },
  {
    title: '权限',
    key: 'permissions',
    width: 220,
    render: (row) =>
      row.permissions?.length
        ? h(
            NSpace,
            { size: [6, 6], wrap: true },
            {
              default: () =>
                row.permissions!.map((permission) =>
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
            { type: 'success', round: true },
            { default: () => '全权限' }
          )
  },
  {
    title: '状态',
    key: 'status',
    render: (row) =>
      h(
        NTag,
        { type: row.status === 'active' ? 'success' : 'warning', round: true },
        { default: () => (row.status === 'active' ? '启用' : '禁用') }
      )
  },
  { title: '创建时间', key: 'created_at', width: 180, render: (row) => formatTime(row.created_at) },
  { title: '最后登录', key: 'last_login', width: 180, render: (row) => formatTime(row.last_login) },
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
            'data-testid': `admin-admin-edit-${row.username}`,
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
            'data-testid': `admin-admin-delete-${row.username}`,
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
  const token = authStore.adminToken
  if (!token) return
  roles.value = await apiClient.getRoles(token)
}

const fetchAdmins = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (!token) return
    admins.value = await apiClient.getAdmins(token)
  } catch (error: any) {
    message.error('获取管理员列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showModal.value = true
}

const handleEdit = (admin: AdminAccount) => {
  editingAdmin.value = admin
  formValue.username = admin.username
  formValue.status = admin.status
  formValue.role_id = admin.role_id ?? null
  formValue.permissionsText = admin.permissions?.join(', ') || ''
  formValue.password = ''
  showModal.value = true
}

const handleDeleteClick = (admin: AdminAccount) => {
  deletingAdmin.value = admin
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingAdmin.value) return
  try {
    const token = authStore.adminToken
    if (!token) return
    await apiClient.deleteAdmin(token, deletingAdmin.value.id)
    message.success('管理员已删除')
    showDeleteConfirm.value = false
    deletingAdmin.value = null
    await fetchAdmins()
  } catch (error: any) {
    message.error('删除管理员失败: ' + error.message)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return

  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (!token) return

    const payload: Record<string, any> = {
      username: formValue.username.trim(),
      status: formValue.status,
      role_id: formValue.role_id,
    }
    const perms = parsePermissions(formValue.permissionsText)
    if (perms.length > 0) {
      payload.permissions = perms
    }
    if (formValue.password) {
      payload.password = formValue.password
    }

    if (editingAdmin.value) {
      await apiClient.updateAdmin(token, editingAdmin.value.id, payload)
      message.success('管理员已更新')
    } else {
      if (!formValue.password) {
        message.error('请输入密码')
        submitLoading.value = false
        return
      }
      await apiClient.createAdmin(token, payload as { username: string; status: string; role_id: number | null; password: string })
      message.success('管理员已创建')
    }

    showModal.value = false
    resetForm()
    await fetchAdmins()
  } catch (error: any) {
    message.error('保存管理员失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}

onMounted(async () => {
  try {
    await fetchRoles()
  } catch (error: any) {
    message.error('获取角色列表失败: ' + error.message)
  }
  await fetchAdmins()
})
</script>
