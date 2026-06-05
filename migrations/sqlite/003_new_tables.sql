-- +goose Up
CREATE TABLE IF NOT EXISTS group_virtual_folders (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    folder_id INTEGER NOT NULL REFERENCES virtual_folders(id) ON DELETE CASCADE,
    virtual_path TEXT NOT NULL,
    permissions TEXT,
    PRIMARY KEY (group_id, folder_id)
);

CREATE TABLE IF NOT EXISTS data_retention_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    scope TEXT NOT NULL DEFAULT 'global',
    scope_id INTEGER,
    retention_days INTEGER NOT NULL,
    action TEXT NOT NULL DEFAULT 'delete',
    action_config TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_group_virtual_folders_group ON group_virtual_folders(group_id);
CREATE INDEX idx_group_virtual_folders_folder ON group_virtual_folders(folder_id);
CREATE INDEX idx_data_retention_policies_scope ON data_retention_policies(scope, scope_id);
CREATE INDEX idx_data_retention_policies_active ON data_retention_policies(is_active);

-- +goose Down
DROP TABLE IF EXISTS data_retention_policies;
DROP TABLE IF EXISTS group_virtual_folders;
