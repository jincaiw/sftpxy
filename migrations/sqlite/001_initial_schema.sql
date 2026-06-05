-- +goose Up
-- Create admins table
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    permissions TEXT,
    role_id INTEGER REFERENCES roles(id),
    mfa_secret TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    filters TEXT,
    last_login_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    password_hash TEXT,
    home_dir TEXT NOT NULL,
    filesystem TEXT,
    permissions TEXT,
    filters TEXT,
    quotas TEXT,
    bandwidth_limits TEXT,
    transfer_limits TEXT,
    max_sessions INTEGER DEFAULT 10,
    allowed_protocols TEXT,
    denied_protocols TEXT,
    ip_filters TEXT,
    mfa_secret TEXT,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    expiration_date DATETIME,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create groups table
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    settings TEXT,
    user_settings TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    permissions TEXT,
    scope TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create user_groups junction table
CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Create admin_roles junction table
CREATE TABLE IF NOT EXISTS admin_roles (
    admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (admin_id, role_id)
);

-- Create user_roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Create public_keys table
CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label TEXT,
    public_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create virtual_folders table
CREATE TABLE IF NOT EXISTS virtual_folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    mapped_path TEXT NOT NULL,
    filesystem_type TEXT NOT NULL,
    filesystem_config TEXT,
    owner_user_id INTEGER REFERENCES users(id),
    is_shared BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create user_virtual_folders junction table
CREATE TABLE IF NOT EXISTS user_virtual_folders (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id INTEGER NOT NULL REFERENCES virtual_folders(id) ON DELETE CASCADE,
    virtual_path TEXT NOT NULL,
    permissions TEXT,
    quota TEXT,
    PRIMARY KEY (user_id, folder_id)
);

-- Create shares table
CREATE TABLE IF NOT EXISTS shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_type TEXT NOT NULL, -- download or upload
    path TEXT NOT NULL,
    password_hash TEXT,
    expires_at DATETIME,
    max_downloads INTEGER,
    max_uploads INTEGER,
    download_count INTEGER DEFAULT 0,
    upload_count INTEGER DEFAULT 0,
    ip_restrictions TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create event_rules table
CREATE TABLE IF NOT EXISTS event_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL,
    trigger_config TEXT,
    conditions TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    schedule TEXT, -- cron expression for scheduled events
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create event_actions table
CREATE TABLE IF NOT EXISTS event_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES event_rules(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL, -- http, command, email, file_operation
    action_config TEXT NOT NULL,
    order_index INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create event_history table
CREATE TABLE IF NOT EXISTS event_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL REFERENCES event_rules(id),
    action_id INTEGER NOT NULL REFERENCES event_actions(id),
    event_type TEXT NOT NULL,
    payload TEXT,
    result TEXT NOT NULL, -- success, failure
    error_message TEXT,
    executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL, -- user, admin, system
    actor_name TEXT,
    target_type TEXT,
    target_id TEXT,
    protocol TEXT,
    client_ip TEXT,
    result TEXT NOT NULL, -- success, failure
    error_message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create transfer_logs table
CREATE TABLE IF NOT EXISTS transfer_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation TEXT NOT NULL, -- upload, download
    username TEXT NOT NULL,
    protocol TEXT NOT NULL,
    connection_id TEXT,
    local_address TEXT,
    remote_address TEXT,
    file_path TEXT NOT NULL,
    file_size INTEGER,
    bytes_transferred INTEGER,
    start_time DATETIME,
    end_time DATETIME,
    duration_ms INTEGER,
    status TEXT NOT NULL, -- success, failure
    error TEXT,
    ftp_mode TEXT, -- active, passive (FTP only)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create command_logs table
CREATE TABLE IF NOT EXISTS command_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    command TEXT NOT NULL, -- rename, rmdir, mkdir, etc.
    username TEXT NOT NULL,
    protocol TEXT NOT NULL,
    path TEXT,
    new_path TEXT,
    result TEXT NOT NULL, -- success, failure
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create http_logs table
CREATE TABLE IF NOT EXISTS http_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    username TEXT,
    client_ip TEXT,
    user_agent TEXT,
    response_time_ms INTEGER,
    request_size INTEGER,
    response_size INTEGER,
    auth_method TEXT, -- jwt, api_key
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create defender_blocklist table
CREATE TABLE IF NOT EXISTS defender_blocklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    protocol TEXT,
    reason TEXT,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    client_ip TEXT,
    connected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create indexes for common queries
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_admins_username ON admins(username);
CREATE INDEX idx_public_keys_user_id ON public_keys(user_id);
CREATE INDEX idx_virtual_folders_owner ON virtual_folders(owner_user_id);
CREATE INDEX idx_shares_token ON shares(token);
CREATE INDEX idx_shares_user_id ON shares(user_id);
CREATE INDEX idx_event_rules_trigger ON event_rules(trigger_type);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_transfer_logs_username ON transfer_logs(username);
CREATE INDEX idx_transfer_logs_created_at ON transfer_logs(created_at);
CREATE INDEX idx_http_logs_created_at ON http_logs(created_at);
CREATE INDEX idx_defender_blocklist_ip ON defender_blocklist(ip);
CREATE INDEX idx_defender_blocklist_active ON defender_blocklist(is_active);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_active ON sessions(is_active);

-- +goose Down
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS defender_blocklist;
DROP TABLE IF EXISTS http_logs;
DROP TABLE IF EXISTS command_logs;
DROP TABLE IF EXISTS transfer_logs;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS event_history;
DROP TABLE IF EXISTS event_actions;
DROP TABLE IF EXISTS event_rules;
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS user_virtual_folders;
DROP TABLE IF EXISTS virtual_folders;
DROP TABLE IF EXISTS public_keys;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS admin_roles;
DROP TABLE IF EXISTS user_groups;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS admins;
