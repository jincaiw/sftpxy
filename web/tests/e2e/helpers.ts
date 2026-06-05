import { expect, type APIRequestContext } from '@playwright/test'

const adminBaseURL = 'http://127.0.0.1:30088'
export const clientBaseURL = 'http://127.0.0.1:30080'

export async function waitForSeededLogin(
  request: APIRequestContext,
  role: 'admin' | 'user',
  username: string,
  password: string
) {
  const baseURL = role === 'admin' ? adminBaseURL : clientBaseURL
  const endpoint = role === 'admin' ? '/api/v1/auth/admin/login' : '/api/v1/auth/user/login'

  await expect
    .poll(
      async () => {
        const response = await request.post(`${baseURL}${endpoint}`, {
          data: { username, password }
        })
        return response.status()
      },
      {
        timeout: 30_000,
        intervals: [250, 500, 1_000]
      }
    )
    .toBe(200)
}
