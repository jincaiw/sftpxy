import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'

const routes: RouteRecordRaw[] = [
  {
    path: '/',
    redirect: '/client'
  },
  // Admin routes
  {
    path: '/admin/login',
    name: 'AdminLogin',
    component: () => import('@/views/admin/Login.vue'),
    meta: { requiresAuth: false, role: 'admin' }
  },
  {
    path: '/admin/init',
    name: 'AdminInit',
    component: () => import('@/views/admin/Init.vue'),
    meta: { requiresAuth: false, role: 'admin' }
  },
  {
    path: '/admin',
    component: () => import('@/views/admin/Layout.vue'),
    meta: { requiresAuth: true, role: 'admin' },
    children: [
      {
        path: '',
        redirect: '/admin/dashboard'
      },
      {
        path: 'dashboard',
        name: 'AdminDashboard',
        component: () => import('@/views/admin/Dashboard.vue'),
        meta: { title: '仪表盘' }
      },
      {
        path: 'users',
        name: 'AdminUsers',
        component: () => import('@/views/admin/Users.vue'),
        meta: { title: '用户管理' }
      },
      {
        path: 'admins',
        name: 'AdminAdmins',
        component: () => import('@/views/admin/Admins.vue'),
        meta: { title: '管理员管理' }
      },
      {
        path: 'groups',
        name: 'AdminGroups',
        component: () => import('@/views/admin/Groups.vue'),
        meta: { title: '用户组管理' }
      },
      {
        path: 'roles',
        name: 'AdminRoles',
        component: () => import('@/views/admin/Roles.vue'),
        meta: { title: '角色管理' }
      },
      {
        path: 'connections',
        name: 'AdminConnections',
        component: () => import('@/views/admin/Connections.vue'),
        meta: { title: '活动连接' }
      },
      {
        path: 'logs',
        name: 'AdminLogs',
        component: () => import('@/views/admin/Logs.vue'),
        meta: { title: '审计日志' }
      },
      {
        path: 'settings',
        name: 'AdminSettings',
        component: () => import('@/views/admin/Settings.vue'),
        meta: { title: '系统设置' }
      },
      {
        path: 'folders',
        name: 'AdminFolders',
        component: () => import('@/views/admin/Folders.vue'),
        meta: { title: '虚拟目录' }
      },
      {
        path: 'shares',
        name: 'AdminShares',
        component: () => import('@/views/admin/Shares.vue'),
        meta: { title: '分享管理' }
      },
      {
        path: 'event-rules',
        name: 'AdminEventRules',
        component: () => import('@/views/admin/EventRules.vue'),
        meta: { title: '事件规则' }
      },
      {
        path: 'event-history',
        name: 'AdminEventHistory',
        component: () => import('@/views/admin/EventHistory.vue'),
        meta: { title: '事件历史' }
      },
      {
        path: 'hooks',
        name: 'AdminHooks',
        component: () => import('@/views/admin/Hooks.vue'),
        meta: { title: 'Hooks 配置' }
      },
      {
        path: 'security',
        name: 'AdminSecurity',
        component: () => import('@/views/admin/Security.vue'),
        meta: { title: '安全策略' }
      },
      {
        path: 'backup',
        name: 'AdminBackupRestore',
        component: () => import('@/views/admin/BackupRestore.vue'),
        meta: { title: '备份恢复' }
      }
    ]
  },
  // Client routes
  {
    path: '/client/login',
    name: 'ClientLogin',
    component: () => import('@/views/client/Login.vue'),
    meta: { requiresAuth: false, role: 'client' }
  },
  {
    path: '/client/share/:token',
    name: 'ShareAccess',
    component: () => import('@/views/client/ShareAccess.vue'),
    meta: { requiresAuth: false }
  },
  {
    path: '/client',
    component: () => import('@/views/client/Layout.vue'),
    meta: { requiresAuth: true, role: 'client' },
    children: [
      {
        path: '',
        redirect: '/client/files'
      },
      {
        path: 'files',
        name: 'ClientFiles',
        component: () => import('@/views/client/FileBrowser.vue'),
        meta: { title: '文件管理' }
      },
      {
        path: 'profile',
        name: 'ClientProfile',
        component: () => import('@/views/client/Profile.vue'),
        meta: { title: '个人资料' }
      },
      {
        path: 'sessions',
        name: 'ClientSessions',
        component: () => import('@/views/client/Sessions.vue'),
        meta: { title: '活动会话' }
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(),
  routes
})

// Navigation guard
router.beforeEach((to, from, next) => {
  const role = to.matched.find(r => r.meta.role)?.meta.role as string
  const requiresAuth = to.matched.some(r => r.meta.requiresAuth !== false)

  if (requiresAuth && role) {
    const token = localStorage.getItem(`sftpxy-token-${role}`)
    if (!token) {
      next({ path: `/${role}/login`, query: { redirect: to.fullPath } })
      return
    }
  }

  if (to.path.endsWith('/login')) {
    const loginRole = to.meta.role as string
    if (loginRole) {
      const token = localStorage.getItem(`sftpxy-token-${loginRole}`)
      if (token) {
        next(`/${loginRole}`)
        return
      }
    }
  }

  next()
})

export default router
