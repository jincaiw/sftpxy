import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

const webDir = process.cwd()
const repoRoot = path.resolve(webDir, '..')
const testDir = path.join(webDir, 'tests/e2e')

export default defineConfig({
  testDir,
  testMatch: ['*.spec.ts'],
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: {
    timeout: 10_000
  },
  reporter: [['list'], ['html', { open: 'never', outputFolder: path.join(testDir, 'playwright-report') }]],
  use: {
    baseURL: 'http://127.0.0.1:30088',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure'
  },
  webServer: {
    command: 'bash tests/e2e/start-e2e.sh',
    cwd: repoRoot,
    url: 'http://127.0.0.1:30088/health',
    timeout: 120_000,
    reuseExistingServer: false
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome']
      }
    }
  ]
})
