import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { NaiveUiResolver } from 'unplugin-vue-components/resolvers'
import { resolve } from 'path'

export default defineConfig({
  plugins: [
    vue(),
    Components({
      resolvers: [NaiveUiResolver()]
    })
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src')
    }
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          vue: ['vue', 'vue-router', 'pinia'],
          naiveui: ['naive-ui']
        }
      }
    }
  },
  server: {
    port: 30090,
    proxy: {
      '/api': {
        target: 'http://localhost:30088',
        changeOrigin: true
      },
      '/health': {
        target: 'http://localhost:30088',
        changeOrigin: true
      },
      '/status': {
        target: 'http://localhost:30088',
        changeOrigin: true
      }
    }
  }
})
