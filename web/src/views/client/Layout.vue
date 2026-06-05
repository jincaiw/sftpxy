<template>
  <n-layout class="app-shell client-layout" has-sider>
    <template v-if="isMobile">
      <n-drawer v-model:show="drawerVisible" :width="220" placement="left">
        <n-drawer-content :native-scrollbar="false" body-content-style="padding: 0;">
          <div class="app-shell__brand">
            <div class="app-shell__brand-icon">
              <n-icon size="24">
                <CloudOutline />
              </n-icon>
            </div>
            <div class="app-shell__brand-copy">
              <span class="app-shell__brand-title">SFTPxy</span>
              <span class="app-shell__brand-subtitle">WebClient 文件访问</span>
            </div>
          </div>
          <n-menu
            :options="menuOptions"
            :value="currentRoute"
            @update:value="handleMenuSelect"
          />
        </n-drawer-content>
      </n-drawer>
    </template>
    <template v-else>
      <n-layout-sider
        class="app-shell__sider"
        bordered
        collapse-mode="width"
        :collapsed-width="64"
        :width="220"
        :collapsed="collapsed"
        show-trigger
        @collapse="collapsed = true"
        @expand="collapsed = false"
      >
        <div class="app-shell__brand">
          <div class="app-shell__brand-icon">
            <n-icon size="24">
              <CloudOutline />
            </n-icon>
          </div>
          <div v-show="!collapsed" class="app-shell__brand-copy">
            <span class="app-shell__brand-title">SFTPxy</span>
            <span class="app-shell__brand-subtitle">WebClient 文件访问</span>
          </div>
        </div>
        <n-menu
          :collapsed="collapsed"
          :collapsed-width="64"
          :collapsed-icon-size="22"
          :options="menuOptions"
          :value="currentRoute"
          @update:value="handleMenuSelect"
        />
      </n-layout-sider>
    </template>
    <n-layout>
      <n-layout-header bordered class="app-shell__header">
        <div class="app-shell__header-main">
          <span class="app-shell__eyebrow">WebClient</span>
          <div class="app-shell__title-row">
            <n-button v-if="isMobile" quaternary circle class="hamburger-btn" @click="drawerVisible = true">
              <template #icon>
                <n-icon><MenuOutline /></n-icon>
              </template>
            </n-button>
            <span class="app-shell__title">{{ pageTitle }}</span>
            <n-breadcrumb class="app-shell__breadcrumb">
              <n-breadcrumb-item v-for="item in breadcrumbItems" :key="item">
                {{ item }}
              </n-breadcrumb-item>
            </n-breadcrumb>
          </div>
        </div>
        <div class="app-shell__header-actions">
          <n-button quaternary circle class="theme-toggle-btn" @click="toggleTheme">
            <template #icon>
              <n-icon>
                <SunnyOutline v-if="isDark" />
                <MoonOutline v-else />
              </n-icon>
            </template>
          </n-button>
          <n-dropdown :options="userOptions" trigger="click" @select="handleDropdownSelect">
            <n-button quaternary class="user-menu-btn" data-testid="client-user-menu">
              <template #icon>
                <n-icon><PersonOutline /></n-icon>
              </template>
              {{ authStore.clientUser?.username || '用户' }}
            </n-button>
          </n-dropdown>
        </div>
      </n-layout-header>
      <n-layout-content class="app-shell__content">
        <div class="app-shell__content-inner">
          <router-view />
        </div>
      </n-layout-content>
    </n-layout>
  </n-layout>
</template>

<script setup lang="ts">
import { ref, computed, h, onMounted, onUnmounted, inject, type Ref } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useDialog, useMessage } from 'naive-ui'
import type { MenuOption, DropdownOption } from 'naive-ui'
import {
  CloudOutline,
  FolderOpenOutline,
  PersonOutline,
  SunnyOutline,
  MoonOutline,
  LogOutOutline,
  DesktopOutline,
  MenuOutline
} from '@vicons/ionicons5'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const dialog = useDialog()
const message = useMessage()
const authStore = useAuthStore()

const collapsed = ref(false)
const isDark = inject<Ref<boolean>>('isDark', ref(false))
const isMobile = ref(false)
const drawerVisible = ref(false)

const checkMobile = () => {
  isMobile.value = window.matchMedia('(max-width: 768px)').matches
}

onMounted(() => {
  checkMobile()
  window.addEventListener('resize', checkMobile)
})

onUnmounted(() => {
  window.removeEventListener('resize', checkMobile)
})

const currentRoute = computed(() => {
  const name = route.name as string
  if (name?.startsWith('Client')) return name
  return 'ClientFiles'
})

const breadcrumbItems = computed(() => {
  const title = (route.meta.title as string) || '文件管理'
  return ['文件管理', title]
})

const pageTitle = computed(() => (route.meta.title as string) || '文件管理')

const renderIcon = (icon: any) => () => h(icon, { size: 20 })

const menuOptions: MenuOption[] = [
  {
    label: '文件管理',
    key: 'ClientFiles',
    icon: renderIcon(FolderOpenOutline)
  },
  {
    label: '个人资料',
    key: 'ClientProfile',
    icon: renderIcon(PersonOutline)
  },
  {
    label: '活动会话',
    key: 'ClientSessions',
    icon: renderIcon(DesktopOutline)
  }
]

const userOptions: DropdownOption[] = [
  {
    label: '退出登录',
    key: 'logout',
    icon: renderIcon(LogOutOutline)
  }
]

const handleMenuSelect = (key: string) => {
  router.push({ name: key })
  if (isMobile.value) {
    drawerVisible.value = false
  }
}

const toggleTheme = () => {
  isDark.value = !isDark.value
}

const handleDropdownSelect = (key: string) => {
  if (key === 'logout') {
    dialog.warning({
      title: '确认退出',
      content: '确定要退出登录吗？',
      positiveText: '退出',
      negativeText: '取消',
      onPositiveClick: () => {
        authStore.clientLogout()
        message.success('已退出登录')
        router.push('/client/login')
      }
    })
  }
}
</script>
