# SFTPxy 生产配置说明

## 总体原则

当前生产配置基线是：

- 单机 Linux + systemd
- SQLite 本地持久化
- 服务内 TLS
- 密码 + SSH 公钥认证
- 可选 JWT / API Key / OIDC / LDAP 外部认证集成

## 必改项

以下配置必须在生产中明确设置：

- `ssh.host_keys`
- `httpd.tls_cert_file`
- `httpd.tls_key_file`
- `httpd.session_secret`
- `httpd.cors_origins`
- `data_provider.connection_string`
- `kms.key_path`

安装脚本生成的默认配置已经会填入：

- 持久化 SSH host key 路径
- TLS 证书路径
- 随机 `session_secret`
- 显式 `cors_origins`

## SSH / SFTP / SCP

建议：

- 启用 `password_auth` 与 `public_key_auth`
- 生产只使用持久化 `host_keys`
- 保留 `scp_enabled: true` 以覆盖 SCP 用户

关键项：

```yaml
ssh:
  enabled: true
  listen_port: 30082
  host_keys:
    - /var/lib/sftpxy/keys/ssh_host_ed25519_key
  password_auth: true
  public_key_auth: true
```

## HTTP / WebAdmin / WebClient / REST

建议：

- 使用同一套 TLS 证书
- 不允许通配 CORS
- `static_path` 和 `template_path` 指向安装后的 `web/dist`
- 为 `JWT` 单独设置签名密钥，避免与示例配置共用占位值
- 外部认证仅在具备稳定 IdP/LDAP 与回调域名时启用

关键项：

```yaml
httpd:
  enabled: true
  listen_port: 30088
  client_listen_port: 30080
  tls_cert_file: /etc/sftpxy/certs/sftpxy.crt
  tls_key_file: /etc/sftpxy/certs/sftpxy.key
  static_path: /usr/local/share/sftpxy/web/dist
  template_path: /usr/local/share/sftpxy/web/dist
  session_secret: "<replace-with-random-secret>"
  cors_origins:
    - https://files.example.com
  jwt:
    enabled: true
    secret: "<replace-with-random-jwt-secret>"
    issuer: sftpxy
    audience: sftpxy-api
    expiry_seconds: 3600
```

- `listen_port`（30088）：WebAdmin 管理后台 + REST API
- `client_listen_port`（30080）：WebClient 客户端独立端口，仅暴露文件浏览、分享访问等用户功能，与管理端口隔离

### API Key

适用于自动化系统、内部运维脚本和只需访问管理 API 的集成方。

建议：

- 每个集成使用独立 `api_key`
- 使用长随机值
- 仅按需赋予 `role` 和 `scopes`

示例：

```yaml
httpd:
  api_keys:
    - key: "<replace-with-long-random-key>"
      subject: "automation-admin"
      role: "admin"
      scopes:
        - "admin"
      enabled: true
```

请求方式：

- 请求头 `X-API-Key: <key>`
- 或 `Authorization: ApiKey <key>`

### OIDC

适用于浏览器单点登录场景。

建议：

- 使用 HTTPS 回调地址
- 只允许明确的用户或管理员登录流
- 启用 `auto_create_users` 前先约束 `role_field` 与映射规则

关键项：

```yaml
httpd:
  oidc:
    enabled: true
    provider_name: corp-sso
    client_id: "<client-id>"
    client_secret: "<client-secret>"
    auth_url: "https://id.example.com/oauth2/authorize"
    token_url: "https://id.example.com/oauth2/token"
    user_info_url: "https://id.example.com/oauth2/userinfo"
    redirect_url: "https://files.example.com/api/v1/auth/oidc/callback"
    scopes: ["openid", "profile", "email"]
    username_field: "preferred_username"
    email_field: "email"
    role_field: "role"
    role_mappings:
      admin: "admin"
      user: "user"
    allow_admin: false
    allow_user: true
    auto_create_users: true
    user_home_base_dir: "/var/lib/sftpxy/oidc-users"
```

### LDAP / AD

适用于目录服务统一认证场景。

建议：

- 使用 `ldaps://` 或受控 TLS
- 尽量使用只读服务账号搜索用户，再用用户 DN 二次 bind 验证密码
- 将自动建用户目录限制到专用路径

关键项：

```yaml
httpd:
  ldap:
    enabled: true
    url: "ldaps://ldap.example.com:636"
    bind_dn: "cn=readonly,dc=example,dc=com"
    bind_password: "<bind-password>"
    base_dn: "dc=example,dc=com"
    user_filter: "(&(objectClass=person)(uid=%s))"
    username_attribute: "uid"
    allow_user: true
    auto_create_users: true
    user_home_base_dir: "/var/lib/sftpxy/ldap-users"
```

## FTP / FTPS

建议：

- 生产启用时统一采用 `Explicit TLS`
- 强制控制信道和数据通道 TLS
- 配置清晰的被动端口范围
- NAT 场景设置 `nat_external_address`

关键项：

```yaml
ftp:
  enabled: true
  listen_port: 30086
  explicit_tls: true
  tls_cert_file: /etc/sftpxy/certs/sftpxy.crt
  tls_key_file: /etc/sftpxy/certs/sftpxy.key
  force_control_tls: true
  force_data_tls: true
  passive_port_start: 30100
  passive_port_end: 30199
  nat_external_address: 203.0.113.10
```

同时放通：

- 控制端口：`30086`
- 被动端口范围：`30100-30199`

## WebDAV

建议：

- 使用 TLS
- `base_path` 明确设置为 `/` 或固定前缀
- 不启用客户端证书认证

关键项：

```yaml
webdav:
  enabled: true
  listen_port: 30084
  base_path: /
  tls_cert_file: /etc/sftpxy/certs/sftpxy.crt
  tls_key_file: /etc/sftpxy/certs/sftpxy.key
  client_cert: false
```

## SQLite

当前单机生产默认使用：

```yaml
data_provider:
  driver: sqlite
  connection_string: /var/lib/sftpxy/sftpxy.db
  auto_migrate: true
```

说明：

- 程序会以 `WAL` 模式打开 SQLite
- 适合当前单机生产交付
- 不适用于多实例共享数据库文件

## 远程 SFTP 存储

当前生产基线要求必须配置远程主机校验，不再接受无校验连接。

建议在文件系统配置中显式提供：

- `host_key`：远程 SSH 公钥
- 或 `host_key`：`SHA256:...` 指纹

未配置时，生产校验和运行都应视为不安全配置。
