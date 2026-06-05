<template>
  <div class="auth-page">
    <div class="login-center">
      <n-card class="auth-card login-card" :bordered="false">
        <div class="login-brand">
          <div class="login-brand__icon">
            <n-icon size="30"><CloudOutline /></n-icon>
          </div>
          <span class="login-brand__name">SFTPxy</span>
        </div>
        <h1 class="login-heading">管理员登录</h1>
        <p class="login-desc">登录管理控制台，管理用户与系统配置</p>
        <n-form
          ref="formRef"
          class="login-form"
          :model="formValue"
          :rules="rules"
          label-placement="left"
          label-width="0"
          require-mark-placement="right-hanging"
          size="large"
          data-testid="admin-login-form"
        >
          <n-form-item path="username">
            <n-input
              v-model:value="formValue.username"
              placeholder="用户名"
              :input-props="{ autocomplete: 'username', 'data-testid': 'admin-login-username' }"
            >
              <template #prefix>
                <n-icon><PersonOutline /></n-icon>
              </template>
            </n-input>
          </n-form-item>
          <n-form-item path="password">
            <n-input
              v-model:value="formValue.password"
              type="password"
              placeholder="密码"
              show-password-on="click"
              :input-props="{ autocomplete: 'current-password', 'data-testid': 'admin-login-password' }"
              @keyup.enter="handleLogin"
            >
              <template #prefix>
                <n-icon><LockClosedOutline /></n-icon>
              </template>
            </n-input>
          </n-form-item>
          <n-button
            type="primary"
            size="large"
            block
            :loading="authStore.loading"
            data-testid="admin-login-submit"
            @click="handleLogin"
          >
            登录
          </n-button>
          <div class="login-divider"><span>或</span></div>
          <n-button
            size="large"
            block
            class="login-oidc"
            @click="handleOIDCLogin"
          >
            使用 OIDC 登录
          </n-button>
        </n-form>
      </n-card>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useMessage } from 'naive-ui'
import type { FormInst } from 'naive-ui'
import { CloudOutline, PersonOutline, LockClosedOutline } from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const message = useMessage()
const authStore = useAuthStore()
const formRef = ref<FormInst | null>(null)

const formValue = reactive({
  username: '',
  password: ''
})

const rules = {
  username: { required: true, message: '请输入用户名', trigger: 'blur' },
  password: { required: true, message: '请输入密码', trigger: 'blur' }
}

const handleLogin = async () => {
  if (!formRef.value) return

  try {
    await formRef.value.validate()
    await authStore.adminLogin(formValue.username, formValue.password)
    message.success('登录成功')
    const redirect = (route.query.redirect as string) || '/admin/dashboard'
    router.push(redirect)
  } catch (error: any) {
    message.error(error.message || '登录失败，请检查用户名和密码')
  }
}

const handleOIDCLogin = () => {
  const redirect = authStore.getOIDCLoginUrl('admin', '/admin/login')
  window.location.href = redirect
}

onMounted(() => {
  const token = route.query.token as string | undefined
  const role = route.query.role as 'admin' | 'user' | undefined
  const username = route.query.username as string | undefined
  if (token && role === 'admin') {
    authStore.completeOIDCLogin('admin', token, username)
    const redirect = (route.query.redirect as string) || '/admin/dashboard'
    router.replace(redirect)
  }
})
</script>

<style scoped>
.login-center {
  position: relative;
  z-index: 1;
  width: 100%;
  max-width: 420px;
}

.login-card {
  animation: card-in 0.5s cubic-bezier(0.16, 1, 0.3, 1);
}

.login-card :deep(.n-card__content) {
  padding: 44px 40px !important;
}

.login-brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
  margin-bottom: 4px;
}

.login-brand__icon {
  width: 64px;
  height: 64px;
  display: grid;
  place-items: center;
  border-radius: 20px;
  color: #eff6ff;
  background: linear-gradient(135deg, var(--app-accent) 0%, #06b6d4 100%);
  box-shadow: 0 14px 32px rgba(37, 99, 235, 0.25);
}

.login-brand__name {
  font-size: 20px;
  font-weight: 800;
  color: var(--app-text-primary);
  letter-spacing: 0.04em;
}

.login-heading {
  margin: 16px 0 0;
  text-align: center;
  font-size: 24px;
  font-weight: 700;
  color: var(--app-text-primary);
  line-height: 1.3;
}

.login-desc {
  margin: 8px 0 0;
  text-align: center;
  font-size: 14px;
  color: var(--app-text-secondary);
  line-height: 1.6;
}

.login-form {
  margin-top: 32px;
}

.login-form :deep(.n-form-item) {
  margin-bottom: 20px;
}

.login-divider {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 20px 0;
  color: var(--app-text-tertiary);
  font-size: 13px;
}

.login-divider::before,
.login-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: var(--app-border);
}

.login-oidc {
  font-weight: 500;
}

@keyframes card-in {
  from {
    opacity: 0;
    transform: translateY(16px) scale(0.98);
  }
  to {
    opacity: 1;
    transform: translateY(0) scale(1);
  }
}

@media (max-width: 480px) {
  .login-card :deep(.n-card__content) {
    padding: 32px 24px !important;
  }

  .login-brand__icon {
    width: 56px;
    height: 56px;
    border-radius: 18px;
  }

  .login-heading {
    font-size: 22px;
  }
}
</style>
