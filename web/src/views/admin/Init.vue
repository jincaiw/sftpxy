<template>
  <div class="init-page">
    <div class="init-container">
      <div class="init-brand">
        <n-icon size="48" color="#2080f0">
          <CloudOutline />
        </n-icon>
        <h1>SFTPxy</h1>
        <p>初始化管理员账户</p>
      </div>

      <n-card :bordered="false" style="max-width: 420px; width: 90vw">
        <n-form
          ref="formRef"
          :model="formValue"
          :rules="rules"
          :label-placement="isMobile ? 'top' : 'left'"
          :label-width="isMobile ? 'auto' : '100'"
        >
          <n-form-item label="用户名" path="username">
            <n-input
              v-model:value="formValue.username"
              placeholder="admin"
              @keyup.enter="handleSubmit"
            />
          </n-form-item>
          <n-form-item label="密码" path="password">
            <n-input
              v-model:value="formValue.password"
              type="password"
              show-password-on="click"
              placeholder="请输入密码"
              @keyup.enter="handleSubmit"
            />
          </n-form-item>
          <n-form-item label="确认密码" path="confirmPassword">
            <n-input
              v-model:value="formValue.confirmPassword"
              type="password"
              show-password-on="click"
              placeholder="请再次输入密码"
              @keyup.enter="handleSubmit"
            />
          </n-form-item>
          <n-form-item label="密码强度">
            <n-progress
              :percentage="passwordStrength.percentage"
              :color="passwordStrength.color"
              :indicator-text-color="passwordStrength.color"
              :height="8"
              :border-radius="4"
            />
            <span style="margin-left: 8px; font-size: 12px; color: var(--n-text-color-3)">
              {{ passwordStrength.label }}
            </span>
          </n-form-item>
        </n-form>
        <n-button
          type="primary"
          block
          :loading="submitLoading"
          @click="handleSubmit"
        >
          创建管理员
        </n-button>
      </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useMessage } from 'naive-ui'
import type { FormInst, FormRules } from 'naive-ui'
import { CloudOutline } from '@vicons/ionicons5'
import { apiClient } from '@/api/client'

const router = useRouter()
const message = useMessage()

const isMobile = ref(false)
const checkMobile = () => { isMobile.value = window.matchMedia('(max-width: 768px)').matches }
onMounted(() => { checkMobile(); window.addEventListener('resize', checkMobile) })
onUnmounted(() => { window.removeEventListener('resize', checkMobile) })

const submitLoading = ref(false)
const formRef = ref<FormInst | null>(null)

const formValue = reactive({
  username: '',
  password: '',
  confirmPassword: ''
})

const validateConfirmPassword = (_rule: any, value: string) => {
  if (value !== formValue.password) {
    return new Error('两次输入的密码不一致')
  }
  return true
}

const rules: FormRules = {
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  password: { required: true, message: '请输入密码', trigger: 'blur' },
  confirmPassword: [
    { required: true, message: '请再次输入密码', trigger: 'blur' },
    { validator: validateConfirmPassword, trigger: 'blur' }
  ]
}

const passwordStrength = computed(() => {
  const pwd = formValue.password
  if (!pwd) return { percentage: 0, color: '#d03050', label: '' }
  let score = 0
  if (pwd.length >= 8) score++
  if (pwd.length >= 12) score++
  if (/[a-z]/.test(pwd)) score++
  if (/[A-Z]/.test(pwd)) score++
  if (/\d/.test(pwd)) score++
  if (/[^a-zA-Z0-9]/.test(pwd)) score++
  if (score <= 2) return { percentage: 33, color: '#d03050', label: '弱' }
  if (score <= 4) return { percentage: 66, color: '#f0a020', label: '中' }
  return { percentage: 100, color: '#18a058', label: '强' }
})

const handleSubmit = async () => {
  if (!formRef.value) return
  submitLoading.value = true
  try {
    await formRef.value.validate()
    await apiClient.initAdmin({
      username: formValue.username.trim(),
      password: formValue.password
    })
    message.success('管理员账户创建成功，请登录')
    router.push('/admin/login')
  } catch (error: any) {
    message.error('创建管理员失败: ' + error.message)
  } finally {
    submitLoading.value = false
  }
}
</script>

<style scoped>
.init-page {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: var(--n-body-color);
}

.init-container {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 24px;
}

.init-brand {
  text-align: center;
}

.init-brand h1 {
  margin: 8px 0 4px;
  font-size: 28px;
  font-weight: 600;
}

.init-brand p {
  color: var(--n-text-color-3);
  font-size: 14px;
}
</style>
