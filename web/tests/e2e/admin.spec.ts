import { expect, test } from '@playwright/test'
import { waitForSeededLogin } from './helpers'

test('WebAdmin 主流程可用', async ({ page, request }) => {
  await waitForSeededLogin(request, 'admin', 'admin', 'admin-pass')

  await page.goto('/admin/login')

  await page.getByTestId('admin-login-username').fill('admin')
  await page.getByTestId('admin-login-password').fill('admin-pass')
  await page.getByTestId('admin-login-submit').click()

  await expect(page).toHaveURL(/\/admin\/dashboard$/)
  await expect(page.getByTestId('admin-user-menu')).toBeVisible()

  await page.goto('/admin/users')
  await expect(page.getByTestId('admin-users-create')).toBeVisible()

  await page.getByTestId('admin-users-create').click()
  await page.getByTestId('admin-user-username').fill('e2e-created-user')
  await page.getByTestId('admin-user-email').fill('e2e-created-user@example.com')
  await page.getByTestId('admin-user-home-directory').fill('/home')
  await page.getByTestId('admin-user-password').fill('e2e-created-user-pass')
  await page.getByTestId('admin-user-submit').click()

  await expect(page.getByTestId('admin-user-edit-e2e-created-user')).toBeVisible()
  await expect(page.getByRole('cell', { name: 'e2e-created-user@example.com', exact: true })).toBeVisible()

  await page.getByTestId('admin-user-edit-e2e-created-user').click()
  await page.getByTestId('admin-user-email').fill('e2e-created-user+updated@example.com')
  await page.getByTestId('admin-user-status').click()
  await page.getByText('禁用', { exact: true }).click()
  await page.getByTestId('admin-user-submit').click()

  await expect(page.getByRole('cell', { name: 'e2e-created-user+updated@example.com', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: '禁用', exact: true })).toBeVisible()

  await page.goto('/admin/logs')
  await expect(page.getByRole('button', { name: '搜索' })).toBeVisible()
  await expect(page.getByText('admin').first()).toBeVisible()

  await page.getByTestId('admin-user-menu').click()
  await page.getByText('退出登录', { exact: true }).click()
  await page.getByRole('button', { name: '退出' }).click()

  await expect(page).toHaveURL(/\/admin\/login$/)
})
