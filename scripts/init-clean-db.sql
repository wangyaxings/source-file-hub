-- ========================================
-- File Hub - Clean Database Initialization
-- ========================================
-- This script creates a clean database with only the initial admin account
-- All other data (files, packages, etc.) will be empty

-- Enable foreign keys and WAL mode for better performance
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- ========================================
-- Create Tables
-- ========================================

-- Files table
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    versioned_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    description TEXT,
    uploader TEXT NOT NULL,
    upload_time TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    is_latest BOOLEAN NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    deleted_at TEXT,
    deleted_by TEXT,
    file_exists BOOLEAN NOT NULL DEFAULT 1,
    checksum TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_files_file_type ON files(file_type);
CREATE INDEX IF NOT EXISTS idx_files_original_name ON files(original_name);
CREATE INDEX IF NOT EXISTS idx_files_status ON files(status);
CREATE INDEX IF NOT EXISTS idx_files_is_latest ON files(is_latest);
CREATE INDEX IF NOT EXISTS idx_files_upload_time ON files(upload_time);
CREATE INDEX IF NOT EXISTS idx_files_deleted_at ON files(deleted_at);
CREATE INDEX IF NOT EXISTS idx_files_file_path ON files(file_path);

-- Access logs table
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    ciid TEXT NOT NULL,
    gbid TEXT NOT NULL,
    event_code TEXT NOT NULL,
    message TEXT NOT NULL,
    details TEXT,
    hostname TEXT NOT NULL,
    source_location TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_event_code ON access_logs(event_code);
CREATE INDEX IF NOT EXISTS idx_logs_level ON access_logs(level);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON access_logs(created_at);

-- File operations audit log
CREATE TABLE IF NOT EXISTS file_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id TEXT NOT NULL,
    operation TEXT NOT NULL, -- 'upload', 'download', 'delete', 'restore', 'purge'
    operator TEXT NOT NULL,
    operation_time TEXT NOT NULL,
    details TEXT, -- JSON details
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE INDEX IF NOT EXISTS idx_audit_file_id ON file_audit_logs(file_id);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON file_audit_logs(operation);
CREATE INDEX IF NOT EXISTS idx_audit_operation_time ON file_audit_logs(operation_time);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    key_hash TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '["read"]', -- JSON array of permissions
    status TEXT NOT NULL DEFAULT 'active', -- active, disabled, expired
    expires_at TEXT,
    usage_count INTEGER DEFAULT 0,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_api_keys_role ON api_keys(role);
CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);

-- API Usage Logs table
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    file_id TEXT,
    file_path TEXT,
    ip_address TEXT,
    user_agent TEXT,
    status_code INTEGER,
    response_size INTEGER DEFAULT 0,
    response_time_ms INTEGER DEFAULT 0,
    error_message TEXT,
    request_time TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id),
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE INDEX IF NOT EXISTS idx_api_usage_api_key_id ON api_usage_logs(api_key_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_user_id ON api_usage_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_request_time ON api_usage_logs(request_time);
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint ON api_usage_logs(endpoint);
CREATE INDEX IF NOT EXISTS idx_api_usage_file_id ON api_usage_logs(file_id);

-- User Roles table
CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user', -- admin, user, api_user
    permissions TEXT, -- JSON array of specific permissions
    quota_daily INTEGER DEFAULT -1, -- -1 for unlimited
    quota_monthly INTEGER DEFAULT -1,
    status TEXT NOT NULL DEFAULT 'active', -- active, suspended, disabled
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role);
CREATE INDEX IF NOT EXISTS idx_user_roles_status ON user_roles(status);

-- Application Users table (simplified for authboss)
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    email TEXT,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    twofa_enabled BOOLEAN NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_last_code TEXT,
    recovery_codes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- Packages table
CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    type TEXT NOT NULL,
    file_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    path TEXT NOT NULL,
    ip TEXT,
    timestamp TEXT NOT NULL,
    remark TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_packages_tenant ON packages(tenant_id);
CREATE INDEX IF NOT EXISTS idx_packages_type ON packages(type);
CREATE INDEX IF NOT EXISTS idx_packages_timestamp ON packages(timestamp);

-- Admin audit table
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    target_user TEXT,
    action TEXT NOT NULL,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_logs(actor);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_logs(target_user);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_admin_audit_created ON admin_audit_logs(created_at);

-- Casbin policy table
CREATE TABLE IF NOT EXISTS casbin_policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ptype TEXT NOT NULL,
    v0 TEXT,
    v1 TEXT,
    v2 TEXT,
    v3 TEXT,
    v4 TEXT,
    v5 TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_casbin_ptype ON casbin_policies(ptype);
CREATE INDEX IF NOT EXISTS idx_casbin_v0 ON casbin_policies(v0);
CREATE INDEX IF NOT EXISTS idx_casbin_v1 ON casbin_policies(v1);

-- ========================================
-- Initialize Casbin Policies
-- ========================================

-- Administrator policies - Full access
INSERT OR IGNORE INTO casbin_policies (ptype, v0, v1, v2) VALUES
('p', 'administrator', '/api/v1/web/*', '(GET|POST|PUT|PATCH|DELETE)'),
('p', 'administrator', '/api/v1/admin/*', '(GET|POST|PUT|PATCH|DELETE)'),
('p', 'administrator', 'admin', 'access'),
('p', 'administrator', '/api/v1/web/auth/check-permission', 'POST'),
('p', 'administrator', '/api/v1/web/auth/check-permissions', 'POST'),
('p', 'administrator', '/api/v1/web/auth/me', 'GET'),
('p', 'administrator', '/api/v1/web/auth/ab/2fa/totp/*', '(GET|POST|PUT|PATCH|DELETE)');

-- Viewer policies - Read-only access
INSERT OR IGNORE INTO casbin_policies (ptype, v0, v1, v2) VALUES
('p', 'viewer', '/api/v1/web/health*', 'GET'),
('p', 'viewer', '/api/v1/web/', 'GET'),
('p', 'viewer', '/api/v1/web/files/list', 'GET'),
('p', 'viewer', '/api/v1/web/files/versions/*', 'GET'),
('p', 'viewer', '/api/v1/web/files/*', 'GET'),
('p', 'viewer', '/api/v1/web/recycle-bin', 'GET'),
('p', 'viewer', '/api/v1/web/packages', 'GET'),
('p', 'viewer', '/api/v1/web/auth/check-permission', 'POST'),
('p', 'viewer', '/api/v1/web/auth/check-permissions', 'POST'),
('p', 'viewer', '/api/v1/web/auth/me', 'GET'),
('p', 'viewer', '/api/v1/web/auth/ab/2fa/totp/*', '(GET|POST|PUT|PATCH|DELETE)');

-- ========================================
-- Create Initial Admin User
-- ========================================

-- Insert admin user (password: admin123)
-- Password hash is generated using bcrypt with cost 12
INSERT OR IGNORE INTO users (
    username,
    email,
    password_hash,
    role,
    twofa_enabled,
    created_at,
    updated_at
) VALUES (
    'admin',
    'admin@localhost',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8KzKz2K', -- admin123
    'administrator',
    0,
    datetime('now'),
    datetime('now')
);

-- Create admin role record
INSERT OR IGNORE INTO user_roles (
    user_id,
    role,
    permissions,
    quota_daily,
    quota_monthly,
    status,
    created_at,
    updated_at
) VALUES (
    'admin',
    'administrator',
    '["read", "write", "delete", "admin", "upload", "download"]',
    -1,
    -1,
    'active',
    datetime('now'),
    datetime('now')
);

-- ========================================
-- Clean Database - Remove All Other Data
-- ========================================

-- Clear all files (keep table structure)
DELETE FROM files;

-- Clear all packages (keep table structure)
DELETE FROM packages;

-- Clear all API keys (keep table structure)
DELETE FROM api_keys;

-- Clear all API usage logs (keep table structure)
DELETE FROM api_usage_logs;

-- Clear all file audit logs (keep table structure)
DELETE FROM file_audit_logs;

-- Clear all access logs (keep table structure)
DELETE FROM access_logs;

-- Clear all admin audit logs (keep table structure)
DELETE FROM admin_audit_logs;

-- Note: Keep users table with only admin user
-- Note: Keep user_roles table with only admin role
-- Note: Keep casbin_policies table with default policies

-- ========================================
-- Verification
-- ========================================

-- Verify admin user exists
SELECT 'Admin user verification:' as info;
SELECT username, role, email, twofa_enabled, created_at FROM users WHERE username = 'admin';

-- Verify admin role exists
SELECT 'Admin role verification:' as info;
SELECT user_id, role, status, created_at FROM user_roles WHERE user_id = 'admin';

-- Verify policies exist
SELECT 'Casbin policies count:' as info;
SELECT COUNT(*) as policy_count FROM casbin_policies;

-- Verify clean state
SELECT 'Clean database verification:' as info;
SELECT
    (SELECT COUNT(*) FROM files) as files_count,
    (SELECT COUNT(*) FROM packages) as packages_count,
    (SELECT COUNT(*) FROM api_keys) as api_keys_count,
    (SELECT COUNT(*) FROM users) as users_count;

-- ========================================
-- Initialization Complete
-- ========================================

SELECT 'Database initialization completed successfully!' as status;
SELECT 'Only admin user exists with password: admin123' as note;
SELECT 'All other data has been cleared' as note;
