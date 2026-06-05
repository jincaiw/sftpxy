<template>
  <div class="page-container">
    <div class="page-header">
      <div class="page-title">
        <div class="page-title__icon">
          <n-icon :size="20"><PeopleOutline /></n-icon>
        </div>
        <span>用户组管理</span>
      </div>
      <div class="page-actions">
        <n-button type="primary" data-testid="admin-groups-create" @click="handleCreateClick">
          <template #icon><n-icon><AddOutline /></n-icon></template>
          新建用户组
        </n-button>
      </div>
    </div>

    <n-card class="data-table-card" :bordered="false" size="small">
      <n-data-table
        :columns="columns"
        :data="groups"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="800"
      />
    </n-card>

    <n-modal
      v-model:show="showModal"
      preset="card"
      :title="editingGroup ? '编辑用户组' : '新建用户组'"
      style="max-width: 520px; width: 90vw"
    >
      <n-form
        ref="formRef"
        :model="formValue"
        :rules="rules"
        :label-placement="isMobile ? 'top' : 'left'"
        :label-width="isMobile ? 'auto' : '80'"
        data-testid="admin-group-form"
      >
        <n-form-item label="名称" path="name">
          <n-input
            v-model:value="formValue.name"
            :input-props="{ 'data-testid': 'admin-group-name' }"
          />
        </n-form-item>
        <n-form-item label="描述" path="description">
          <n-input
            v-model:value="formValue.description"
            type="textarea"
            :autosize="{ minRows: 3, maxRows: 5 }"
            :input-props="{ 'data-testid': 'admin-group-description' }"
          />
        </n-form-item>
      </n-form>
      <template #footer>
        <n-space justify="end">
          <n-button data-testid="admin-group-cancel" @click="showModal = false">取消</n-button>
          <n-button type="primary" :loading="submitLoading" data-testid="admin-group-submit" @click="handleSubmit">
            {{ editingGroup ? '保存' : '创建' }}
          </n-button>
        </n-space>
      </template>
    </n-modal>

    <ConfirmDialog
      v-model:show="showDeleteConfirm"
      title="确认删除"
      :content="`确定要删除用户组 ${deletingGroup?.name} 吗？`"
      @confirm="handleDelete"
    />
  </div>
</template>

<script setup lang="ts">
import { h, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useMessage, NButton, NIcon } from 'naive-ui'
import type { DataTableColumns, FormInst } from 'naive-ui'
import { AddOutline, CreateOutline, TrashOutline, PeopleOutline } from '@vicons/ionicons5'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { apiClient } from '@/api/client'
import type { GroupItem } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import { formatTime } from '@/utils/timezone'

const message = useMessage()
const authStore = useAuthStore()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const groups = ref<GroupItem[]>([])
const loading = ref(false)
const submitLoading = ref(false)
const showModal = ref(false)
const showDeleteConfirm = ref(false)
const editingGroup = ref<GroupItem | null>(null)
const deletingGroup = ref<GroupItem | null>(null)
const formRef = ref<FormInst | null>(null)

const formValue = reactive({
  name: '',
  description: ''
})

const rules = {
  name: { required: true, message: '请输入用户组名称', trigger: 'blur' }
}

const pagination = reactive({
  page: 1,
  pageSize: 20,
  showSizePicker: true,
  pageSizes: [10, 20, 50]
})

const resetForm = () => {
  formValue.name = ''
  formValue.description = ''
  editingGroup.value = null
}

const columns: DataTableColumns<GroupItem> = [
  { title: 'ID', key: 'id', width: 64 },
  { title: '名称', key: 'name' },
  { title: '描述', key: 'description' },
  { title: '创建时间', key: 'created_at', width: 180, render: (row) => formatTime(row.created_at) },
  { title: '更新时间', key: 'updated_at', width: 180, render: (row) => formatTime(row.updated_at) },
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
            'data-testid': `admin-group-edit-${row.id}`,
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
            'data-testid': `admin-group-delete-${row.id}`,
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

const fetchGroups = async () => {
  loading.value = true
  try {
    const token = authStore.adminToken
    if (!token) return
    groups.value = await apiClient.getGroups(token)
  } catch (error: any) {
    message.error('获取用户组列表失败: ' + error.message)
  } finally {
    loading.value = false
  }
}

const handleCreateClick = () => {
  resetForm()
  showModal.value = true
}

const handleEdit = (group: GroupItem) => {
  editingGroup.value = group
  formValue.name = group.name
  formValue.description = group.description || ''
  showModal.value = true
}

const handleDeleteClick = (group: GroupItem) => {
  deletingGroup.value = group
  showDeleteConfirm.value = true
}

const handleDelete = async () => {
  if (!deletingGroup.value) return
  try {
    const token = authStore.adminToken
    if (!token) return
    await apiClient.deleteGroup(token, deletingGroup.value.id)
    message.success('用户组已删除')
    showDeleteConfirm.value = false
    deletingGroup.value = null
    await fetchGroups()
  } catch (error: any) {
    message.error('删除用户组失败: ' + error.message)
  }
}

const handleSubmit = async () => {
  if (!formRef.value) return

  submitLoading.value = true
  try {
    await formRef.value.validate()
    const token = authStore.adminToken
    if (!token) return

    const payload = {
      name: formValue.name.trim(),
      description: formValue.description.trim()
    }

    if (editingGroup.value) {
      await apiClient.updateGroup(token, editingGroup.value.id, payload)
      message.success('用户组已更新')
    } else {
      await apiClient.createGroup(token, payload)
      message.success('用户组已创建')
    }

    showModal.value = false
    resetForm()
    await fetchGroups()
  } catch (error: any) {
    message.error('保存用户组失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}

onMounted(fetchGroups)
</script>
