import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { apiClient } from '@/api/client'
import type { LoginResponse, UserInfo } from '@/api/client'

export const useAuthStore = defineStore('auth', () => {
  const adminToken = ref<string | null>(localStorage.getItem('sftpxy-token-admin'))
  const clientToken = ref<string | null>(localStorage.getItem('sftpxy-token-client'))
  const adminUser = ref<UserInfo | null>(null)
  const clientUser = ref<UserInfo | null>(null)
  const loading = ref(false)

  const isAdminLoggedIn = computed(() => !!adminToken.value)
  const isClientLoggedIn = computed(() => !!clientToken.value)

  const setAdminToken = (token: string, user?: UserInfo) => {
    adminToken.value = token
    localStorage.setItem('sftpxy-token-admin', token)
    if (user) adminUser.value = user
  }

  const setClientToken = (token: string, user?: UserInfo) => {
    clientToken.value = token
    localStorage.setItem('sftpxy-token-client', token)
    if (user) clientUser.value = user
  }

  const adminLogin = async (username: string, password: string): Promise<LoginResponse> => {
    loading.value = true
    try {
      const response = await apiClient.adminLogin(username, password)
      setAdminToken(response.token, response.user)
      return response
    } finally {
      loading.value = false
    }
  }

  const clientLogin = async (username: string, password: string, mfaCode?: string): Promise<LoginResponse> => {
    loading.value = true
    try {
      const response = await apiClient.userLogin(username, password, mfaCode)
      setClientToken(response.token, response.user)
      return response
    } finally {
      loading.value = false
    }
  }

  const adminLogout = () => {
    adminToken.value = null
    adminUser.value = null
    localStorage.removeItem('sftpxy-token-admin')
  }

  const clientLogout = () => {
    clientToken.value = null
    clientUser.value = null
    localStorage.removeItem('sftpxy-token-client')
  }

  const init = () => {
    const storedAdminToken = localStorage.getItem('sftpxy-token-admin')
    const storedClientToken = localStorage.getItem('sftpxy-token-client')
    if (storedAdminToken) adminToken.value = storedAdminToken
    if (storedClientToken) clientToken.value = storedClientToken
  }

  const completeOIDCLogin = (role: 'admin' | 'user', token: string, username?: string) => {
    const user: UserInfo | undefined = username
      ? {
          id: 0,
          username,
          role,
          status: 'active'
        }
      : undefined

    if (role === 'admin') {
      setAdminToken(token, user)
      return
    }
    setClientToken(token, user)
  }

  const getOIDCLoginUrl = (role: 'admin' | 'user', returnTo: string) => {
    return apiClient.getOIDCLoginUrl(role, returnTo)
  }

  return {
    adminToken,
    clientToken,
    adminUser,
    clientUser,
    loading,
    isAdminLoggedIn,
    isClientLoggedIn,
    setAdminToken,
    setClientToken,
    adminLogin,
    clientLogin,
    adminLogout,
    clientLogout,
    init,
    completeOIDCLogin,
    getOIDCLoginUrl
  }
})
