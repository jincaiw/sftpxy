<template>
  <n-config-provider :theme="theme" :locale="zhCN" :date-locale="dateZhCN">
    <n-message-provider>
      <n-dialog-provider>
        <router-view />
      </n-dialog-provider>
    </n-message-provider>
  </n-config-provider>
</template>

<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount, watch, provide } from 'vue'
import { darkTheme, zhCN, dateZhCN } from 'naive-ui'
import type { GlobalTheme } from 'naive-ui'

const storedTheme = localStorage.getItem('sftpxy-theme')
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
const isDark = ref(storedTheme ? storedTheme === 'dark' : prefersDark)

provide('isDark', isDark)

const theme = ref<GlobalTheme | null>(isDark.value ? darkTheme : null)
const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
const handleSystemThemeChange = (event: MediaQueryListEvent) => {
  if (!localStorage.getItem('sftpxy-theme')) {
    isDark.value = event.matches
  }
}

const syncTheme = (dark: boolean) => {
  theme.value = dark ? darkTheme : null
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
}

watch(isDark, (val) => {
  syncTheme(val)
  localStorage.setItem('sftpxy-theme', val ? 'dark' : 'light')
}, { immediate: true })

onMounted(() => {
  mediaQuery.addEventListener('change', handleSystemThemeChange)
})

onBeforeUnmount(() => {
  mediaQuery.removeEventListener('change', handleSystemThemeChange)
})
</script>
