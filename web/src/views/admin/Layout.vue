<template>
  <n-layout class="app-shell admin-layout" has-sider>
    <template v-if="isMobile">
      <n-drawer v-model:show="drawerVisible" :width="240" placement="left">
        <n-drawer-content :native-scrollbar="false" body-content-style="padding: 0;">
          <div class="app-shell__brand">
            <div class="app-shell__brand-icon">
              <n-icon size="24">
                <CloudOutline />
              </n-icon>
            </div>
            <div class="app-shell__brand-copy">
              <span class="app-shell__brand-title">SFTPxy</span>
              <span class="app-shell__brand-subtitle">WebAdmin 管理后台</span>
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
        :width="240"
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
            <span class="app-shell__brand-subtitle">WebAdmin 管理后台</span>
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
          <span class="app-shell__eyebrow">WebAdmin</span>
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
            <n-button quaternary class="user-menu-btn" data-testid="admin-user-menu">
              <template #icon>
                <n-icon><PersonOutline /></n-icon>
              </template>
              {{ authStore.adminUser?.username || '管理员' }}
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
  HomeOutline,
  PersonOutline,
  PeopleOutline,
  LinkOutline,
  DocumentTextOutline,
  SettingsOutline,
  ShieldOutline,
  SunnyOutline,
  MoonOutline,
  LogOutOutline,
  FolderOutline,
  ShareSocialOutline,
  FlashOutline,
  TimeOutline,
  GitBranchOutline,
  LockClosedOutline,
  CloudDownloadOutline,
  MenuOutline,
  GridOutline,
  KeyOutline,
  ServerOutline,
  PulseOutline
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
  if (name?.startsWith('Admin')) return name
  return 'AdminDashboard'
})

const breadcrumbItems = computed(() => {
  const title = (route.meta.title as string) || '仪表盘'
  return ['管理后台', title]
})

const pageTitle = computed(() => (route.meta.title as string) || '仪表盘')

const renderIcon = (icon: any) => () => h(icon, { size: 20 })

const menuOptions: MenuOption[] = [
  {
    label: '概览',
    key: 'overview',
    icon: renderIcon(GridOutline),
    children: [
      { label: '仪表盘', key: 'AdminDashboard', icon: renderIcon(HomeOutline) }
    ]
  },
  {
    label: '用户与权限',
    key: 'user-perm',
    icon: renderIcon(KeyOutline),
    children: [
      { label: '管理员管理', key: 'AdminAdmins', icon: renderIcon(PersonOutline) },
      { label: '用户管理', key: 'AdminUsers', icon: renderIcon(PeopleOutline) },
      { label: '用户组管理', key: 'AdminGroups', icon: renderIcon(PeopleOutline) },
      { label: '角色管理', key: 'AdminRoles', icon: renderIcon(ShieldOutline) }
    ]
  },
  {
    label: '存储与分享',
    key: 'storage',
    icon: renderIcon(ServerOutline),
    children: [
      { label: '虚拟目录', key: 'AdminFolders', icon: renderIcon(FolderOutline) },
      { label: '分享管理', key: 'AdminShares', icon: renderIcon(ShareSocialOutline) }
    ]
  },
  {
    label: '监控与日志',
    key: 'monitor',
    icon: renderIcon(PulseOutline),
    children: [
      { label: '活动连接', key: 'AdminConnections', icon: renderIcon(LinkOutline) },
      { label: '审计日志', key: 'AdminLogs', icon: renderIcon(DocumentTextOutline) }
    ]
  },
  {
    label: '自动化',
    key: 'automation',
    icon: renderIcon(FlashOutline),
    children: [
      { label: '事件规则', key: 'AdminEventRules', icon: renderIcon(FlashOutline) },
      { label: '事件历史', key: 'AdminEventHistory', icon: renderIcon(TimeOutline) },
      { label: 'Hooks 配置', key: 'AdminHooks', icon: renderIcon(GitBranchOutline) }
    ]
  },
  {
    label: '系统',
    key: 'system',
    icon: renderIcon(SettingsOutline),
    children: [
      { label: '安全策略', key: 'AdminSecurity', icon: renderIcon(LockClosedOutline) },
      { label: '系统设置', key: 'AdminSettings', icon: renderIcon(SettingsOutline) },
      { label: '备份恢复', key: 'AdminBackupRestore', icon: renderIcon(CloudDownloadOutline) }
    ]
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
        authStore.adminLogout()
        message.success('已退出登录')
        router.push('/admin/login')
      }
    })
  }
}
</script>
