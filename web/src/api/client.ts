// API response types
export interface LoginResponse {
  token: string
  token_type?: string
  user?: UserInfo
  message?: string
}

export interface UserInfo {
  id: number
  username: string
  email?: string
  role?: string
  status?: string
}

export interface SystemStatus {
  service: string
  version: string
  uptime: string
  runtime: {
    go_version: string
    os: string
    arch: string
    num_goroutine: number
    num_cpu: number
  }
  memory: {
    alloc_mb: number
    total_alloc_mb: number
    sys_mb: number
    num_gc: number
    heap_objects: number
  }
  protocols: {
    ssh_enabled: boolean
    ftp_enabled: boolean
    webdav_enabled: boolean
    webadmin_enabled: boolean
    webclient_enabled: boolean
  }
  timestamp: string
}

export interface HealthStatus {
  status: string
  timestamp: string
  uptime: string
  version: string
}

export interface User {
  id: number
  username: string
  email?: string
  home_directory: string
  group_ids?: number[]
  role_ids?: number[]
  status: string
  created_at: string
  last_login?: string
}

export interface AdminAccount {
  id: number
  username: string
  status: string
  permissions?: string[]
  role_id?: number | null
  created_at: string
  last_login?: string
}

export interface GroupItem {
  id: number
  name: string
  description?: string
  created_at?: string
  updated_at?: string
}

export interface RoleItem {
  id: number
  name: string
  description?: string
  permissions: string[]
  scope?: Record<string, any>
  created_at?: string
}

export interface Connection {
  id: string
  username: string
  protocol: string
  remote_addr: string
  connected_at: string
  bytes_sent: number
  bytes_recv: number
  principal?: 'user' | 'admin'
}

export interface AuditLog {
  id: number
  timestamp: string
  username: string
  action: string
  protocol: string
  remote_addr: string
  details?: string
  status: string
}

export interface FileItem {
  name: string
  size: number
  mod_time: string
  is_dir: boolean
  mode: string
  path: string
}

export interface ProfileQuota {
  configured: boolean
  raw?: Record<string, any> | string
}

export interface ProfilePublicKey {
  id: number
  label: string
  created_at: string
}

export interface ClientProfile {
  id: number
  username: string
  status: string
  home_directory: string
  mfa_enabled: boolean
  quota: ProfileQuota
  public_keys: ProfilePublicKey[]
  created_at: string
  updated_at: string
}

export interface ShareItem {
  id: number
  token: string
  user_id: number
  username: string
  share_type: 'download' | 'upload' | 'both'
  path: string
  expires_at?: string
  max_downloads: number
  max_uploads: number
  download_count: number
  upload_count: number
  ip_restrictions?: string
  is_active: boolean
  created_at: string
}

export interface ShareListResponse {
  items: ShareItem[]
  total: number
}

export interface VirtualFolder {
  id: number
  name: string
  mapped_path: string
  filesystem_type: 'local' | 'encrypted' | 'remotesftp' | 'httpfs'
  is_shared: boolean
  owner_user_id: number
  filesystem_config: Record<string, any>
  created_at: string
  updated_at?: string
}

export interface EventRule {
  id: number
  name: string
  trigger_type: string
  conditions: Record<string, any>
  actions: Record<string, any>[]
  is_active: boolean
  schedule?: string
  created_at: string
  updated_at?: string
}

export interface EventHistoryItem {
  id: number
  rule_id: number
  rule_name: string
  action_type: string
  status: 'success' | 'failed'
  started_at: string
  duration_ms: number
  error?: string
}

export interface AppConfig {
  [key: string]: any
}

export interface BlockedIP {
  id: number
  ip: string
  protocol: string
  reason: string
  blocked_at: string
  is_active: boolean
  expires_at?: string
}

export interface CreateShareRequest {
  path: string
  share_type: 'download' | 'upload' | 'both'
  password?: string
  expires_at?: string
  max_downloads?: number
  max_uploads?: number
  ip_restrictions?: string[]
}

export interface AddPublicKeyRequest {
  public_key: string
  label?: string
}

export interface PublicKeyItem {
  id: number
  fingerprint: string
  label: string
  created_at: string
}

export interface MFASetupResponse {
  secret: string
  qr_url: string
  recovery_codes?: string[]
}

export interface MFAVerifyResponse {
  message: string
  recovery_codes: string[]
}

export interface QuotaInfo {
  bytes_used: number
  bytes_total: number
  files_used: number
  files_total: number
}

export interface SessionItem {
  id: string
  protocol: string
  client_ip: string
  started_at: string
}

export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}

// API Client
class ApiClient {
  private baseUrl: string

  constructor(baseUrl?: string) {
    this.baseUrl = baseUrl || ''
  }

  private detectRoleFromPath(path: string): string | null {
    if (path.startsWith('/api/v1/auth/admin/') || path.startsWith('/api/v1/admin')) return 'admin'
    if (path.startsWith('/api/v1/auth/user/') || path.startsWith('/api/v1/profile') || path.startsWith('/api/v1/files') || path.startsWith('/api/v1/shares') || path.startsWith('/api/v1/user/')) return 'client'
    if (path.startsWith('/api/v1/users') || path.startsWith('/api/v1/admins') || path.startsWith('/api/v1/groups') || path.startsWith('/api/v1/roles') || path.startsWith('/api/v1/connections') || path.startsWith('/api/v1/logs') || path.startsWith('/api/v1/config') || path.startsWith('/api/v1/defender') || path.startsWith('/api/v1/backup') || path.startsWith('/api/v1/restore') || path.startsWith('/api/v1/folders') || path.startsWith('/api/v1/events')) return 'admin'
    return null
  }

  private async request<T>(
    method: string,
    path: string,
    data?: any,
    token?: string | null
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`
    const headers: Record<string, string> = {
      'Content-Type': 'application/json'
    }
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    const response = await fetch(url, {
      method,
      headers,
      body: data ? JSON.stringify(data) : undefined
    })

    if (!response.ok) {
      if (response.status === 401) {
        const role = this.detectRoleFromPath(path)
        if (role) {
          localStorage.removeItem(`sftpxy-token-${role}`)
          if (!path.startsWith('/api/v1/auth/')) {
            window.location.href = `/${role === 'admin' ? 'admin' : 'client'}/login`
          }
        }
      }
      const error = await response.json().catch(() => ({ message: response.statusText }))
      throw new Error(error.message || `HTTP ${response.status}`)
    }

    const text = await response.text()
    if (!text || text.trim() === '') {
      return undefined as T
    }

    const result = JSON.parse(text)
    return result as T
  }

  // Auth endpoints
  async adminLogin(username: string, password: string): Promise<LoginResponse> {
    return this.request('POST', '/api/v1/auth/admin/login', { username, password })
  }

  async userLogin(username: string, password: string, mfaCode?: string): Promise<LoginResponse> {
    return this.request('POST', '/api/v1/auth/user/login', { username, password, mfa_code: mfaCode })
  }

  getOIDCLoginUrl(role: 'admin' | 'user', returnTo: string): string {
    const query = new URLSearchParams({
      role,
      return_to: returnTo
    })
    return `${this.baseUrl}/api/v1/auth/oidc/start?${query.toString()}`
  }

  // System endpoints
  async getSystemStatus(): Promise<SystemStatus> {
    return this.request('GET', '/status')
  }

  async getHealth(): Promise<HealthStatus> {
    return this.request('GET', '/health')
  }

  // Admin endpoints (require admin token)
  async getUsers(token: string): Promise<User[]> {
    const result = await this.request<User[] | null>('GET', '/api/v1/users', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async getAdmins(token: string): Promise<AdminAccount[]> {
    const result = await this.request<AdminAccount[] | null>('GET', '/api/v1/admins', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async createAdmin(token: string, admin: Partial<AdminAccount> & { password: string }): Promise<AdminAccount> {
    return this.request('POST', '/api/v1/admins', admin, token)
  }

  async updateAdmin(token: string, id: number, admin: Partial<AdminAccount> & { password?: string }): Promise<{ message: string }> {
    return this.request('PUT', `/api/v1/admins/${id}`, admin, token)
  }

  async deleteAdmin(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/admins/${id}`, undefined, token)
  }

  async getGroups(token: string): Promise<GroupItem[]> {
    const result = await this.request<GroupItem[] | null>('GET', '/api/v1/groups', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async createGroup(token: string, group: Partial<GroupItem>): Promise<GroupItem> {
    return this.request('POST', '/api/v1/groups', group, token)
  }

  async updateGroup(token: string, id: number, group: Partial<GroupItem>): Promise<{ message: string }> {
    return this.request('PUT', `/api/v1/groups/${id}`, group, token)
  }

  async deleteGroup(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/groups/${id}`, undefined, token)
  }

  async getRoles(token: string): Promise<RoleItem[]> {
    const result = await this.request<RoleItem[] | null>('GET', '/api/v1/roles', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async createRole(token: string, role: Partial<RoleItem>): Promise<RoleItem> {
    return this.request('POST', '/api/v1/roles', role, token)
  }

  async updateRole(token: string, id: number, role: Partial<RoleItem>): Promise<{ message: string }> {
    return this.request('PUT', `/api/v1/roles/${id}`, role, token)
  }

  async deleteRole(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/roles/${id}`, undefined, token)
  }

  async createUser(token: string, user: Partial<User>): Promise<User> {
    return this.request('POST', '/api/v1/users', user, token)
  }

  async updateUser(token: string, id: number, user: Partial<User>): Promise<User> {
    return this.request('PUT', `/api/v1/users/${id}`, user, token)
  }

  async deleteUser(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/users/${id}`, undefined, token)
  }

  async getConnections(token: string): Promise<Connection[]> {
    const result = await this.request<Connection[] | null>('GET', '/api/v1/connections', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async disconnectConnection(token: string, id: string): Promise<void> {
    return this.request('DELETE', `/api/v1/connections/${id}`, undefined, token)
  }

  async getLogs(token: string, params?: {
    page?: number
    limit?: number
    protocol?: string
    action?: string
    username?: string
  }): Promise<{ items: AuditLog[]; total: number }> {
    const query = new URLSearchParams()
    if (params?.page) query.set('page', String(params.page))
    if (params?.limit) query.set('limit', String(params.limit))
    if (params?.protocol) query.set('protocol', params.protocol)
    if (params?.action) query.set('action', params.action)
    if (params?.username) query.set('username', params.username)

    const queryString = query.toString()
    const result = await this.request<{ items: AuditLog[]; total: number } | null>('GET', `/api/v1/logs${queryString ? '?' + queryString : ''}`, undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async getClientProfile(token: string): Promise<ClientProfile> {
    const result = await this.request<ClientProfile | null>('GET', '/api/v1/profile', undefined, token)
    return result || { id: 0, username: '', status: '', home_directory: '', mfa_enabled: false, quota: { configured: false }, public_keys: [], created_at: '', updated_at: '' }
  }

  async changeClientPassword(token: string, currentPassword: string, newPassword: string): Promise<{ message: string }> {
    return this.request('POST', '/api/v1/profile/password', {
      current_password: currentPassword,
      new_password: newPassword
    }, token)
  }

  // File operations (require client token)
  async listFiles(token: string, path: string): Promise<FileItem[]> {
    const result = await this.request<FileItem[] | null>('GET', `/api/v1/files${path ? '?path=' + encodeURIComponent(path) : ''}`, undefined, token)
    return Array.isArray(result) ? result : []
  }

  async downloadFile(token: string, path: string): Promise<Blob> {
    const url = `${this.baseUrl}/api/v1/files/download?path=${encodeURIComponent(path)}`
    const headers: Record<string, string> = {}
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    const response = await fetch(url, { headers })
    if (!response.ok) throw new Error('Download failed')
    return response.blob()
  }

  async downloadZip(token: string, paths: string[]): Promise<Blob> {
    const url = `${this.baseUrl}/api/v1/files/download/zip`
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ paths })
    })
    if (!response.ok) throw new Error('Download zip failed')
    return response.blob()
  }

  async uploadFile(token: string, path: string, file: File): Promise<void> {
    const url = `${this.baseUrl}/api/v1/files/upload?path=${encodeURIComponent(path)}`
    const formData = new FormData()
    formData.append('file', file)
    const headers: Record<string, string> = {}
    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: formData
    })
    if (!response.ok) throw new Error('Upload failed')
  }

  async deleteFile(token: string, path: string): Promise<void> {
    return this.request('DELETE', `/api/v1/files?path=${encodeURIComponent(path)}`, undefined, token)
  }

  async renameFile(token: string, oldPath: string, newPath: string): Promise<void> {
    return this.request('PUT', '/api/v1/files/rename', { old_path: oldPath, new_path: newPath }, token)
  }

  async createFolder(token: string, path: string): Promise<void> {
    return this.request('POST', '/api/v1/files/folder', { path }, token)
  }

  async listShares(token: string): Promise<ShareListResponse> {
    const result = await this.request<ShareListResponse | null>('GET', '/api/v1/shares', undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async createShare(token: string, payload: CreateShareRequest): Promise<ShareItem> {
    return this.request('POST', '/api/v1/shares', payload, token)
  }

  async revokeShare(token: string, shareId: number): Promise<{ message: string }> {
    return this.request('POST', `/api/v1/shares/${shareId}/revoke`, undefined, token)
  }

  async accessShare(shareToken: string, password?: string, authToken?: string): Promise<ShareItem> {
    return this.request('POST', `/api/v1/shares/access/${shareToken}`, password ? { password } : {}, authToken)
  }

  async listVirtualFolders(token: string): Promise<VirtualFolder[]> {
    const result = await this.request<VirtualFolder[] | null>('GET', '/api/v1/folders', undefined, token)
    return Array.isArray(result) ? result : []
  }

  async createVirtualFolder(token: string, folder: Partial<VirtualFolder>): Promise<VirtualFolder> {
    return this.request('POST', '/api/v1/folders', folder, token)
  }

  async updateVirtualFolder(token: string, id: number, folder: Partial<VirtualFolder>): Promise<{ message: string }> {
    return this.request('PUT', `/api/v1/folders/${id}`, folder, token)
  }

  async deleteVirtualFolder(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/folders/${id}`, undefined, token)
  }

  async listAllShares(token: string, params?: {
    owner?: string
    status?: string
  }): Promise<ShareListResponse> {
    const query = new URLSearchParams()
    if (params?.owner) query.set('owner', params.owner)
    if (params?.status) query.set('status', params.status)
    const queryString = query.toString()
    const result = await this.request<ShareListResponse | null>('GET', `/api/v1/shares${queryString ? '?' + queryString : ''}`, undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async listEventRules(token: string): Promise<{items: EventRule[], total: number}> {
    const result = await this.request<{items: EventRule[], total: number} | null>('GET', '/api/v1/events/rules', undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async createEventRule(token: string, rule: Partial<EventRule>): Promise<EventRule> {
    return this.request('POST', '/api/v1/events/rules', rule, token)
  }

  async updateEventRule(token: string, id: number, rule: Partial<EventRule>): Promise<{ message: string }> {
    return this.request('PUT', `/api/v1/events/rules/${id}`, rule, token)
  }

  async deleteEventRule(token: string, id: number): Promise<void> {
    return this.request('DELETE', `/api/v1/events/rules/${id}`, undefined, token)
  }

  async listEventHistory(token: string, params?: {
    rule_id?: number
    status?: string
    from?: string
    to?: string
  }): Promise<{items: EventHistoryItem[], total: number}> {
    const query = new URLSearchParams()
    if (params?.rule_id) query.set('rule_id', String(params.rule_id))
    if (params?.status) query.set('status', params.status)
    if (params?.from) query.set('from', params.from)
    if (params?.to) query.set('to', params.to)
    const queryString = query.toString()
    const result = await this.request<{items: EventHistoryItem[], total: number} | null>('GET', `/api/v1/events/history${queryString ? '?' + queryString : ''}`, undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async getConfig(token: string): Promise<AppConfig> {
    return this.request('GET', '/api/v1/config', undefined, token)
  }

  async updateConfig(token: string, config: Partial<AppConfig>): Promise<{ message: string }> {
    return this.request('PUT', '/api/v1/config', config, token)
  }

  async listBlockedIPs(token: string): Promise<{items: BlockedIP[], total: number}> {
    const result = await this.request<{items: BlockedIP[], total: number} | null>('GET', '/api/v1/defender/blocked', undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async unblockIP(token: string, ip: string): Promise<void> {
    return this.request('DELETE', `/api/v1/defender/blocked/${encodeURIComponent(ip)}`, undefined, token)
  }

  async exportBackup(token: string): Promise<Blob> {
    const url = `${this.baseUrl}/api/v1/backup`
    const headers: Record<string, string> = {}
    if (token) headers['Authorization'] = `Bearer ${token}`
    const response = await fetch(url, { headers })
    if (!response.ok) throw new Error('导出备份失败')
    return response.blob()
  }

  async importRestore(token: string, data: any, strategy: string = 'skip'): Promise<{ message: string }> {
    return this.request('POST', '/api/v1/restore', { ...data, conflict_strategy: strategy }, token)
  }

  async initAdmin(admin: { username: string; password: string }): Promise<AdminAccount> {
    return this.request('POST', '/api/v1/auth/admin/init', admin)
  }

  async addPublicKey(token: string, data: AddPublicKeyRequest): Promise<PublicKeyItem> {
    return this.request('POST', '/api/v1/user/public-keys', data, token)
  }

  async removePublicKey(token: string, keyID: number): Promise<{ message: string }> {
    return this.request('DELETE', `/api/v1/user/public-keys/${keyID}`, undefined, token)
  }

  async setupMFA(token: string): Promise<MFASetupResponse> {
    return this.request('POST', '/api/v1/user/mfa/setup', undefined, token)
  }

  async verifyMFA(token: string, code: string): Promise<MFAVerifyResponse> {
    return this.request('POST', '/api/v1/user/mfa/verify', { code }, token)
  }

  async disableMFA(token: string, password: string): Promise<{ message: string }> {
    return this.request('DELETE', '/api/v1/user/mfa', { password }, token)
  }

  async getOwnQuota(token: string): Promise<QuotaInfo> {
    const result = await this.request<QuotaInfo | null>('GET', '/api/v1/user/quota', undefined, token)
    return result || { bytes_used: 0, bytes_total: 0, files_used: 0, files_total: 0 }
  }

  async getOwnSessions(token: string): Promise<SessionItem[]> {
    const result = await this.request<SessionItem[] | {items: SessionItem[], total: number} | null>('GET', '/api/v1/user/sessions', undefined, token)
    if (Array.isArray(result)) return result
    if (result && Array.isArray((result as any).items)) return (result as any).items
    return []
  }

  async disconnectOwnSession(token: string, sessionId: string): Promise<void> {
    return this.request('DELETE', `/api/v1/user/sessions/${sessionId}`, undefined, token)
  }

  async adminListShares(token: string, params?: { owner?: string; status?: string }): Promise<{items: ShareItem[], total: number}> {
    const query = new URLSearchParams()
    if (params?.owner) query.set('owner', params.owner)
    if (params?.status) query.set('status', params.status)
    const queryString = query.toString()
    const result = await this.request<{items: ShareItem[], total: number} | null>('GET', `/api/v1/admin/shares${queryString ? '?' + queryString : ''}`, undefined, token)
    return { items: Array.isArray(result?.items) ? result.items : [], total: result?.total || 0 }
  }

  async adminDeleteShare(token: string, shareId: number): Promise<{message: string}> {
    return this.request('DELETE', `/api/v1/admin/shares/${shareId}`, undefined, token)
  }

  async addUserToFolder(token: string, folderId: number, userId: number): Promise<{message: string}> {
    return this.request('POST', `/api/v1/folders/${folderId}/users`, { user_id: userId }, token)
  }

  async removeUserFromFolder(token: string, folderId: number, userId: number): Promise<{message: string}> {
    return this.request('DELETE', `/api/v1/folders/${folderId}/users/${userId}`, undefined, token)
  }

  async addGroupToFolder(token: string, folderId: number, groupId: number): Promise<{message: string}> {
    return this.request('POST', `/api/v1/folders/${folderId}/groups`, { group_id: groupId }, token)
  }

  async removeGroupFromFolder(token: string, folderId: number, groupId: number): Promise<{message: string}> {
    return this.request('DELETE', `/api/v1/folders/${folderId}/groups/${groupId}`, undefined, token)
  }
}

export const apiClient = new ApiClient()
