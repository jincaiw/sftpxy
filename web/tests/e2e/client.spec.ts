// @ts-nocheck
import path from 'node:path'

import { expect, test } from '@playwright/test'
import { clientBaseURL, waitForSeededLogin } from './helpers'

test('WebClient 主流程可用', async ({ page, request }) => {
  await waitForSeededLogin(request, 'user', 'testuser', 'testuser-pass')

  await page.goto(`${clientBaseURL}/client/login`)

  await page.getByTestId('client-login-username').fill('testuser')
  await page.getByTestId('client-login-password').fill('testuser-pass')
  await page.getByTestId('client-login-submit').click()

  await expect(page).toHaveURL(/\/client\/files$/)
  await expect(page.getByText('existing.txt')).toBeVisible()

  const uploadFile = path.resolve(process.cwd(), 'tests/e2e/fixtures/upload-e2e.txt')
  const fileChooserPromise = page.waitForEvent('filechooser')
  await page.getByTestId('client-upload-button').click()
  const fileChooser = await fileChooserPromise
  await fileChooser.setFiles(uploadFile)
  await expect(page.getByTestId('client-files-card').getByText('upload-e2e.txt')).toBeVisible()

  await page.getByTestId('client-create-folder-open').click()
  await page.getByTestId('client-create-folder-name').fill('e2e-folder')
  await page.getByTestId('client-create-folder-submit').click()
  await expect(page.getByText('e2e-folder')).toBeVisible()

  await page.getByTestId('client-file-actions-trigger-existing.txt').click()
  await page.getByText('分享', { exact: true }).click()
  await expect(page.getByText('创建分享链接')).toBeVisible()
  await page.getByTestId('client-share-submit').click()
  await expect(page.getByText('/existing.txt')).toBeVisible()

  await page.goto(`${clientBaseURL}/client/profile`)
  await expect(page.getByTestId('client-profile-basic')).toContainText('testuser')

  await page.getByTestId('client-password-current').fill('testuser-pass')
  await page.getByTestId('client-password-new').fill('testuser-pass-2')
  await page.getByTestId('client-password-confirm').fill('testuser-pass-2')
  await page.getByTestId('client-password-submit').click()
  await expect(page.getByText('密码修改成功，请使用新密码重新登录')).toBeVisible()

  await page.getByTestId('client-password-current').fill('testuser-pass-2')
  await page.getByTestId('client-password-new').fill('testuser-pass')
  await page.getByTestId('client-password-confirm').fill('testuser-pass')
  await page.getByTestId('client-password-submit').click()
  await expect(page.getByText('密码修改成功，请使用新密码重新登录')).toBeVisible()

  await page.getByTestId('client-user-menu').click()
  await page.getByText('退出登录', { exact: true }).click()
  await page.getByRole('button', { name: '退出' }).click()

  await expect(page).toHaveURL(/\/client\/login$/)
})
