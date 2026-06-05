-- +goose Up
CREATE TABLE IF NOT EXISTS group_virtual_folders (
    group_id INT NOT NULL,
    folder_id INT NOT NULL,
    virtual_path TEXT NOT NULL,
    permissions JSON,
    PRIMARY KEY (group_id, folder_id),
    FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES virtual_folders(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS data_retention_policies (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(50) NOT NULL DEFAULT 'global',
    scope_id INT,
    retention_days INT NOT NULL,
    action VARCHAR(50) NOT NULL DEFAULT 'delete',
    action_config JSON,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_scope (scope, scope_id),
    INDEX idx_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_group_virtual_folders_group ON group_virtual_folders(group_id);
CREATE INDEX idx_group_virtual_folders_folder ON group_virtual_folders(folder_id);

-- +goose Down
DROP TABLE IF EXISTS data_retention_policies;
DROP TABLE IF EXISTS group_virtual_folders;
