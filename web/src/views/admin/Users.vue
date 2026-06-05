<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><PeopleOutline /></n-icon>
        </div>
        <span>用户管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" data-testid="admin-users-create" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建用户
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="users"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="1300"
      />
    </n-card>

    <n-modal
      v-model:show="showCreateModal"
      preset="card"
      :title="editingUser ? '编辑用户' : '新建用户'"
      style="max-width: 500px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="rules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '80'"
        data-testid="admin-user-form"
      >
        <n-form-item label="用户名" path="username">
          <n-input v-model:value="formValue.username" :disabled="!!editingUser" :input-props="{ 'data-testid': 'admin-user-username' }" />
        </n-form-item>
        <n-form-item label="邮箱" path="email">
          <n-input v-model:value="formValue.email" :input-props="{ 'data-testid': 'admin-user-email' }" />
        </n-form-item>
        <n-form-item label="主目录" path="home_directory">
          <n-input v-model:value="formValue.home_directory" :input-props="{ 'data-testid': 'admin-user-home-directory' }" />
        </n-form-item>
        <n-form-item label="用户组" path="group_ids">
          <n-select
            v-model:value="formValue.group_ids"
            multiple
            clearable
            filterable
            placeholder="选择用户组"
            :options="groupOptions"
            data-testid="admin-user-groups"
          />
        </n-form-item>
        <n-form-item label="角色" path="role_ids">
          <n-select
            v-model:value="formValue.role_ids"
            multiple
            clearable
            filterable
            placeholder="选择角色"
            :options="roleOptions"
            data-testid="admin-user-roles"
          />
        </n-form-item>
        <n-form-item label="状态" path="status">
          <n-select
            v-model:value="formValue.status"
            data-testid="admin-user-status"
            :options="[
              { label: '启用', value: 'active' },
              { label: '禁用', value: 'disabled' }
            ]"
          />
        </n-form-item>
        <n-form-item v-if="!editingUser" label="密码" path="password">
          <n-input v-model:value="formValue.password" type="password" show-password-on="click" :input-props="{ 'data-testid': 'admin-user-password' }" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="admin-user-cancel" @click="showCreateModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" data-testid="admin-user-submit" @click="handleSubmit">
            {{ editingUser ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <n-modal
      v-model:show="showPasswordModal"
      preset="card"
      title="修改用户密码"
      style="max-width: 420px; width: 90vw"
    >
      <n-form :label-placement="isMobile ? 'top' : 'left'" :label-width="isMobile ? 'auto' : '80'">
        <n-form-item label="用户">
          <n-input :value="passwordUser?.username" disabled />
        </n-form-item>
        <n-form-item label="新密码">
          <n-input v-model:value="newPassword" type="password" show-password-on="click" placeholder="请输入新密码" />
        </n-form-item>
        <n-form-item label="确认密码">
          <n-input v-model:value="confirmPassword" type="password" show-password-on="click" placeholder="请再次输入新密码" />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showPasswordModal = false">取消</n-button>
          <n-button type="primary" @click="submitPasswordChange">确认修改</n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除用户 ${deletingUser?.username} 吗？此操作不可撤销。`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, h, onMounted, onUnmounted, computed } from 'vue'
import { useMessage, NTag, NButton, NIcon, NSpace } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, PeopleOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { User, GroupItem, RoleItem } from '@/api/client'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const users = ref<User[]>([])
const groups = ref<GroupItem[]>([])
const roles = ref<RoleItem[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showCreateModal = ref(false)
const showDeleteConfirm = ref(false)
const showPasswordModal = ref(false)
const passwordUser = ref<User | null>(null)
const newPassword = ref('')
const confirmPassword = ref('')
const editingUser = ref<User | null>(null)
const deletingUser = ref<User | null>(null)
const formRef = ref<FormInst | null>(null)

const formValue = reactive({
  username: '',
  email: '',
  home_directory: '/home',
  group_ids: [] as number[],
  role_ids: [] as number[],
  status: 'active',
  password: ''
})

const rules = {
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  password: { required: true, message: '请输入密码', trigger: 'blur' },
  email: {
    trigger: 'blur',
    validator: (_rule: any, value: string) => {
      if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
        return new Error('请输入有效的邮箱地址')
      }
      return true
    }
  }
}

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const groupOptions = computed(() =>
  groups.value.map((group) => ({
    label: group.name,
    value: group.id
  }))
)

const roleOptions = computed(() =>
  roles.value.map((role) => ({
    label: role.name,
    value: role.id
  }))
)

const groupNameMap = computed(() =>
  groups.value.reduce<Record<number, string>>((acc, group) => {
    acc[group.id] = group.name
    return acc
  }, {})
)

const roleNameMap = computed(() =>
  roles.value.reduce<Record<number, string>>((acc, role) => {
    acc[role.id] = role.name
    return acc
  }, {})
)

const renderRelationTags = (ids: number[] | undefined, labelMap: Record<number, string>, emptyLabel: string) => {
  if (!ids?.length) {
    return h(
      NTag,
      { size: 'small', round: true },
      { default: () => emptyLabel }
    )
  }
  return h(
    NSpace,
    { size: [6, 6], wrap: true },
    {
      default: () =>
        ids.map((id) =>
          h(
            NTag,
            { size: 'small', type: 'info', round: true },
            { default: () => labelMap[id] || `#${id}` }
          )
        )
    }
  )
}

const resetForm = () => {
  Object.assign(formValue, {
    username: '',
    email: '',
    home_directory: '/home',
    group_ids: [],
    role_ids: [],
    status: 'active',
    password: ''
  })
  editingUser.value = null
}

const columns: DataTableColumns<User> = [
  { title: 'ID', key: 'id', width: 60, align: 'center' },
  { title: '用户名', key: 'username', width: 120 },
  { title: '邮箱', key: 'email', width: 160, ellipsis: { tooltip: true } },
  { title: '主目录', key: 'home_directory', ellipsis: { tooltip: true } },
  {
    title: '用户组',
    key: 'group_ids',
    width: 160,
    render: (row) => renderRelationTags(row.group_ids, groupNameMap.value, '未分组')
  },
  {
    title: '角色',
    key: 'role_ids',
    width: 160,
    render: (row) => renderRelationTags(row.role_ids, roleNameMap.value, '未分配')
  },
  {
    title: '状态',
    key: 'status',
    width: 80,
    align: 'center',
    render: (row) => h(
      NTag,
      { type: row.status === 'active' ? 'success' : 'error', size: 'small' },
      { default: () => row.status === 'active' ? '启用' : '禁用' }
    )
  },
  { title: '创建时间', key: 'created_at', width: 170, render: (row) => formatTime(row.created_at) },
  { title: '最后登录', key: 'last_login', width: 170, render: (row) => formatTime(row.last_login) },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    align: 'center',
    render: (row) => h('div', { class: 'page-table-actions' }, [
      h(
        NButton,
        { size: 'small', 'data-testid': `admin-user-edit-${row.username}`, onClick: () => handleEdit(row) },
        { default: () => '编辑', icon: () => h(NIcon, null, { default: () => h(CreateOutline) }) }
      ),
      h(
        NButton,
        { size: 'small', type: 'warning', onClick: () => handleChangePassword(row) },
        { default: () => '改密' }
      ),
      h(
        NButton,
        { size: 'small', type: 'error', 'data-testid': `admin-user-delete-${row.username}`, onClick: () => handleDeleteClick(row) },
        { default: () => '删除', icon: () => h(NIcon, null, { default: () => h(TrashOutline) }) }
      )
    ])
  }
]
const fetchReferenceData = async () => {
  const token = authStore.adminToken
  if (!token) return
  const [groupItems, roleItems] = await Promise.all([
    apiClient.getGroups(token),
    apiClient.getRoles(token)
  ])
  groups.value = groupItems
  roles.value = roleItems
}


const fetchUsers = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      users.value = await apiClient.getUsers(token)
    }
  } catch (error: any) {
    message.error('获取用户列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showCreateModal.value = true
}

const handleEdit = (user: User) => {
  editingUser.value = user
  formValue.username = user.username
  formValue.email = user.email || ''
  formValue.home_directory = user.home_directory
  formValue.group_ids = [...(user.group_ids || [])]
  formValue.role_ids = [...(user.role_ids || [])]
  formValue.status = user.status
  formValue.password = ''
  showCreateModal.value = true
}

const handleDeleteClick = (user: User) => {
  deletingUser.value = user
  showDeleteConfirm.value = true
}

const handleChangePassword = (user: User) => {
  passwordUser.value = user
  newPassword.value = ''
  confirmPassword.value = ''
  showPasswordModal.value = true
}

const submitPasswordChange = async () => {
  if (!newPassword.value || newPassword.value.length < 6) {
    message.error('密码长度至少6位')
    return
  }
  if (newPassword.value !== confirmPassword.value) {
    message.error('两次输入的密码不一致')
    return
  }
  try {
    const token = authStore.adminToken
    if (token && passwordUser.value) {
      await apiClient.updateUser(token, passwordUser.value.id, { password: newPassword.value } as any)
      message.success(`用户 ${passwordUser.value.username} 密码已修改`)
      showPasswordModal.value = false
    }
  } catch (error: any) {
    message.error('密码修改失败: ' + error.message)
  }
}

const handleDelete = async () => {
  if (!deletingUser.value) return
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.deleteUser(token, deletingUser.value.id)
      message.success('用户已删除')
      await fetchUsers()
    }
  } catch (error: any) {
    message.error('删除失败: ' + error.message)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return

  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (token) {
      if (editingUser.value) {
        const { password, ...updateData } = formValue
        const payload = password ? { ...formValue } : updateData
        await apiClient.updateUser(token, editingUser.value.id, payload)
        message.success('用户已更新')
      } else {
        await apiClient.createUser(token, formValue)
        message.success('用户已创建')
      }
      showCreateModal.value = false
      resetForm()
      await fetchUsers()
    }
  } catch (error: any) {
    const errMsg = error.message || ''
    if (errMsg.includes('UNIQUE constraint failed') || errMsg.includes('duplicate') || errMsg.includes('Failed to create user') || errMsg.includes('already exists')) {
      message.error(editingUser.value ? '更新用户失败：用户名可能已存在' : '创建用户失败：用户名已存在，请使用其他用户名')
    } else if (errMsg.includes('home directory')) {
      message.error('创建用户失败：无法创建用户主目录')
    } else {
      message.error('操作失败: ' + errMsg)
    }
  } finally {
    submitLoading.value = false
  }
}

onMounted(async () => {
  try {
    await fetchReferenceData()
  } catch (error: any) {
    message.error('获取组或角色失败: ' + error.message)
  }
  await fetchUsers()
})
</script>
