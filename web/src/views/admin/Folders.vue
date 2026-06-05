<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><FolderOutline /></n-icon>
        </div>
        <span>虚拟目录管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建目录
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="folders"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="700"
      />
    </n-card>

    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="editingFolder ? '编辑虚拟目录' : '新建虚拟目录'"
      style="max-width: 560px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="rules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '100'"
      >
        <n-form-item label="名称" path="name">
          <n-input v-model:value="formValue.name" />
        </n-form-item>
        <n-form-item label="映射路径" path="mapped_path">
          <n-input v-model:value="formValue.mapped_path" placeholder="/data/files" />
        </n-form-item>
        <n-form-item label="文件系统" path="filesystem_type">
          <n-select
            v-model:value="formValue.filesystem_type"
            :options="filesystemOptions"
          />
        </n-form-item>
        <n-form-item label="关联用户">
          <n-select
            v-model:value="formValue.user_ids"
            multiple
            clearable
            filterable
            placeholder="选择用户"
            :options="userOptions"
          />
        </n-form-item>
        <n-form-item label="关联用户组">
          <n-select
            v-model:value="formValue.group_ids"
            multiple
            clearable
            filterable
            placeholder="选择用户组"
            :options="groupOptions"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button @click="showModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" @click="handleSubmit">
            {{ editingFolder ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除虚拟目录 ${deletingFolder?.name} 吗？此操作不可撤销。`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, h, onMounted, onUnmounted, computed } from 'vue'
import { useMessage, NTag, NButton, NIcon } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, FolderOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useAuthStore } from '@/stores/auth'
import { apiClient } from '@/api/client'
import type { VirtualFolder, User, GroupItem } from '@/api/client'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const folders = ref<VirtualFolder[]>([])
const users = ref<User[]>([])
const groups = ref<GroupItem[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const showDeleteConfirm = ref(false)
const editingFolder = ref<VirtualFolder | null>(null)
const deletingFolder = ref<VirtualFolder | null>(null)
const formRef = ref<FormInst | null>(null)

const filesystemOptions = [
  { label: '本地文件系统', value: 'local' },
  { label: '加密文件系统', value: 'encrypted' },
  { label: '远程SFTP', value: 'remotesftp' },
  { label: 'HTTP文件系统', value: 'httpfs' }
]

const filesystemLabelMap: Record<string, string> = {
  local: '本地文件系统',
  encrypted: '加密文件系统',
  remotesftp: '远程SFTP',
  httpfs: 'HTTP文件系统'
}

const formValue = reactive({
  name: '',
  mapped_path: '',
  filesystem_type: 'local' as 'local' | 'encrypted' | 'remotesftp' | 'httpfs',
  user_ids: [] as number[],
  group_ids: [] as number[]
})

const rules = {
  name: { required: true, message: '请输入目录名称', trigger: 'blur' },
  mapped_path: { required: true, message: '请输入映射路径', trigger: 'blur' },
  filesystem_type: { required: true, message: '请选择文件系统类型', trigger: 'change' }
}

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const userOptions = computed(() =>
  users.value.map((u) => ({ label: u.username, value: u.id }))
)

const groupOptions = computed(() =>
  groups.value.map((g) => ({ label: g.name, value: g.id }))
)

const resetForm = () => {
  formValue.name = ''
  formValue.mapped_path = ''
  formValue.filesystem_type = 'local'
  formValue.user_ids = []
  formValue.group_ids = []
  editingFolder.value = null
}

const columns: DataTableColumns<VirtualFolder> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '名称', key: 'name' },
  { title: '映射路径', key: 'mapped_path' },
  {
    title: '文件系统',
    key: 'filesystem_type',
    render: (row) => h(
      NTag,
      { size: 'small', type: 'info' },
      { default: () => filesystemLabelMap[row.filesystem_type] || row.filesystem_type }
    )
  },
  {
    title: '共享',
    key: 'is_shared',
    width: 80,
    render: (row) => h(NTag, { size: 'small', type: row.is_shared ? 'success' : 'default' }, { default: () => row.is_shared ? '是' : '否' })
  },
  {
    title: '所有者ID',
    key: 'owner_user_id',
    width: 90
  },
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

const fetchReferenceData = async () => {
  const token = authStore.adminToken
  if (!token) return
  const [userItems, groupItems] = await Promise.all([
    apiClient.getUsers(token),
    apiClient.getGroups(token)
  ])
  users.value = userItems
  groups.value = groupItems
}

const fetchFolders = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (token) {
      folders.value = await apiClient.listVirtualFolders(token)
    }
  } catch (error: any) {
    message.error('获取虚拟目录列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showModal.value = true
}

const handleEdit = (folder: VirtualFolder) => {
  editingFolder.value = folder
  formValue.name = folder.name
  formValue.mapped_path = folder.mapped_path
  formValue.filesystem_type = folder.filesystem_type
  formValue.user_ids = (folder as any).user_ids || []
  formValue.group_ids = (folder as any).group_ids || []
  showModal.value = true
}

const handleDeleteClick = (folder: VirtualFolder) => {
  deletingFolder.value = folder
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingFolder.value) return
  try {
    const token = authStore.adminToken
    if (token) {
      await apiClient.deleteVirtualFolder(token, deletingFolder.value.id)
      message.success('虚拟目录已删除')
      showDeleteConfirm.value = false
      deletingFolder.value = null
      await fetchFolders()
    }
  } catch (error: any) {
    message.error('删除虚拟目录失败: ' + error.message)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return
  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (token) {
      const payload: Partial<VirtualFolder> = {
        name: formValue.name.trim(),
        mapped_path: formValue.mapped_path.trim(),
        filesystem_type: formValue.filesystem_type
      }
      if (editingFolder.value) {
        await apiClient.updateVirtualFolder(token, editingFolder.value.id, payload)
        const folderId = editingFolder.value.id
        const oldUserIds: number[] = (editingFolder.value as any).user_ids || []
        const oldGroupIds: number[] = (editingFolder.value as any).group_ids || []
        const newUserIds = formValue.user_ids
        const newGroupIds = formValue.group_ids
        for (const userId of oldUserIds.filter(id => !newUserIds.includes(id))) {
          await apiClient.removeUserFromFolder(token, folderId, userId)
        }
        for (const userId of newUserIds.filter(id => !oldUserIds.includes(id))) {
          await apiClient.addUserToFolder(token, folderId, userId)
        }
        for (const groupId of oldGroupIds.filter(id => !newGroupIds.includes(id))) {
          await apiClient.removeGroupFromFolder(token, folderId, groupId)
        }
        for (const groupId of newGroupIds.filter(id => !oldGroupIds.includes(id))) {
          await apiClient.addGroupToFolder(token, folderId, groupId)
        }
        message.success('虚拟目录已更新')
      } else {
        const created = await apiClient.createVirtualFolder(token, payload)
        const folderId = created.id
        for (const userId of formValue.user_ids) {
          await apiClient.addUserToFolder(token, folderId, userId)
        }
        for (const groupId of formValue.group_ids) {
          await apiClient.addGroupToFolder(token, folderId, groupId)
        }
        message.success('虚拟目录已创建')
      }
      showModal.value = false
      resetForm()
      await fetchFolders()
    }
  } catch (error: any) {
    message.error('保存虚拟目录失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}

onMounted(async () => {
  try {
    await fetchReferenceData()
  } catch (error: any) {
    message.error('获取关联数据失败: ' + error.message)
  }
  await fetchFolders()
})
</script>
