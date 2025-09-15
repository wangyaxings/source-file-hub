package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
	"strings"

	_ "modernc.org/sqlite"
)

// Database manager struct
type Database struct {
	db *sql.DB
}

// FileStatus represents the status of a file
type FileStatus string

const (
	FileStatusActive  FileStatus = "active"  // Active file
	FileStatusDeleted FileStatus = "deleted" // In recycle bin
	FileStatusPurged  FileStatus = "purged"  // Permanently deleted
)

// FileRecord represents a file record in the database
type FileRecord struct {
	ID            string     `json:"id"`
	OriginalName  string     `json:"originalName"`
	VersionedName string     `json:"versionedName"`
	FileType      string     `json:"fileType"`
	FilePath      string     `json:"filePath"`
	Size          int64      `json:"size"`
	Description   string     `json:"description"`
	Uploader      string     `json:"uploader"`
	UploadTime    time.Time  `json:"uploadTime"`
	Version       int        `json:"version"`
	IsLatest      bool       `json:"isLatest"`
	Status        FileStatus `json:"status"`
	DeletedAt     *time.Time `json:"deletedAt,omitempty"`
	DeletedBy     string     `json:"deletedBy,omitempty"`
	FileExists    bool       `json:"fileExists"`         // Whether physical file exists
	Checksum      string     `json:"checksum,omitempty"` // SHA256 checksum
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
}

// RecycleBinItem represents an item in the recycle bin
type RecycleBinItem struct {
	FileRecord
	DaysUntilPurge int `json:"daysUntilPurge"`
}

// APIKey represents an API key record
type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	KeyHash     string     `json:"-"`             // Never expose the hash
	Key         string     `json:"key,omitempty"` // Only returned on creation
	Role        string     `json:"role"`
	Permissions []string   `json:"permissions"`
	Status      string     `json:"status"` // active, disabled, expired
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	UsageCount  int64      `json:"usageCount"`
	LastUsedAt  *time.Time `json:"lastUsedAt,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// APIUsageLog represents an API usage log entry
type APIUsageLog struct {
	ID             int64     `json:"id"`
	APIKeyID       string    `json:"apiKeyId"`
	UserID         string    `json:"userId"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	FileID         string    `json:"fileId,omitempty"`
	FilePath       string    `json:"filePath,omitempty"`
	IPAddress      string    `json:"ipAddress"`
	UserAgent      string    `json:"userAgent,omitempty"`
	StatusCode     int       `json:"statusCode"`
	ResponseSize   int64     `json:"responseSize"`
	ResponseTimeMs int64     `json:"responseTimeMs"`
	ErrorMessage   string    `json:"errorMessage,omitempty"`
	RequestTime    time.Time `json:"requestTime"`
	CreatedAt      time.Time `json:"createdAt"`
}

// UserRole represents user role and permissions
type UserRole struct {
	ID           int64     `json:"id"`
	UserID       string    `json:"userId"`
	Role         string    `json:"role"` // admin, user, api_user
	Permissions  []string  `json:"permissions,omitempty"`
	QuotaDaily   int64     `json:"quotaDaily"`   // -1 for unlimited
	QuotaMonthly int64     `json:"quotaMonthly"` // -1 for unlimited
	Status       string    `json:"status"`       // active, suspended, disabled
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// AppUser represents an application user record (simplified for authboss)
type AppUser struct {
	Username      string     `json:"username"`
	Email         string     `json:"email,omitempty"`
	PasswordHash  string     `json:"-"`
	Role          string     `json:"role"` // viewer, administrator
	TwoFAEnabled  bool       `json:"twoFAEnabled"`
	TOTPSecret    string     `json:"-"`
	TOTPLastCode  string     `json:"-"`
	RecoveryCodes string     `json:"-"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	LastLoginAt   *time.Time `json:"lastLoginAt,omitempty"`
	// Note: MustReset removed - authboss handles password reset flow
}

var defaultDB *Database

// InitDatabase initializes the database connection and creates tables
func InitDatabase(dbPath string) error {
	// Create directory if not exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// Enable foreign keys and WAL mode for better performance
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return fmt.Errorf("failed to enable foreign keys: %v", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return fmt.Errorf("failed to enable WAL mode: %v", err)
	}

	defaultDB = &Database{db: db}

	// Perform lightweight schema migration for api_keys: user_id -> role
	if err := defaultDB.migrateAPIKeysRoleColumn(); err != nil {
		return fmt.Errorf("failed to migrate api_keys schema: %v", err)
	}

	if err := defaultDB.createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}

	// Initialize policies
	if err := defaultDB.initializeCasbinPolicies(); err != nil {
		return fmt.Errorf("failed to initialize casbin policies: %v", err)
	}

	// Casbin policy section
	if err := defaultDB.updateCasbinPolicies(); err != nil {
		return fmt.Errorf("failed to update casbin policies: %v", err)
	}

	return nil
}

// migrateAPIKeysRoleColumn ensures api_keys table has 'role' column instead of legacy 'user_id'
func (d *Database) migrateAPIKeysRoleColumn() error {
	// Check if api_keys table exists
	var c int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='api_keys'").Scan(&c); err != nil {
		return err
	}
	if c == 0 {
		// Table doesn't exist yet; nothing to migrate
		return nil
	}

	// Check if 'role' column exists
	var roleCol int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name='role'").Scan(&roleCol); err != nil {
		return err
	}
	if roleCol > 0 {
		// Already migrated
		return nil
	}

	// Legacy table detected: perform migration user_id -> role
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	steps := []string{
		// Rename old table
		"ALTER TABLE api_keys RENAME TO api_keys_old",
		// Create new table with 'role' column
		`CREATE TABLE api_keys (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            key_hash TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            permissions TEXT NOT NULL DEFAULT '["read"]',
            status TEXT NOT NULL DEFAULT 'active',
            expires_at TEXT,
            usage_count INTEGER DEFAULT 0,
            last_used_at TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )`,
		// Copy data mapping user_id -> role
		`INSERT INTO api_keys (id, name, description, key_hash, role, permissions, status, expires_at, usage_count, last_used_at, created_at, updated_at)
         SELECT id, name, description, key_hash, user_id AS role, permissions, status, expires_at, usage_count, last_used_at, created_at, updated_at FROM api_keys_old`,
		// Drop old table
		"DROP TABLE api_keys_old",
		// Recreate indexes
		"CREATE INDEX IF NOT EXISTS idx_api_keys_role ON api_keys(role)",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)",
		"CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash)",
	}

	for _, stmt := range steps {
		if _, err = tx.Exec(stmt); err != nil {
			return fmt.Errorf("migration step failed: %v", err)
		}
	}

	if err = tx.Commit(); err != nil {
		return err
	}
	return nil
}

// GetDatabase returns the default database instance
func GetDatabase() *Database {
	return defaultDB
}

// GetDB returns the underlying sql.DB instance
func (d *Database) GetDB() *sql.DB {
	return d.db
}

// createTables creates all necessary database tables
func (d *Database) createTables() error {
	// Files table
	createFilesTable := `
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
	`

	// Access logs table (enhanced)
	createLogsTable := `
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
	`

	// File operations audit log
	createAuditTable := `
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
	`

	// API Keys table
	createAPIKeysTable := `
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
    `

	// API Usage Logs table
	createAPIUsageTable := `
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
	`

	// User Roles table (enhance user management)
	createUserRolesTable := `
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
    `

	// Application Users table (simplified for authboss)
	createUsersTable := `
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
    `

	// Execute all table creation statements
	createPackagesTable := `
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
	`

	// Admin audit table
	createAdminAuditTable := `
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
    `

	// Casbin policy section
	createCasbinTable := `
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
	`

	tables := []string{createFilesTable, createLogsTable, createAuditTable, createAPIKeysTable, createAPIUsageTable, createUserRolesTable, createUsersTable, createPackagesTable, createAdminAuditTable, createCasbinTable}
	for _, table := range tables {
		if _, err := d.db.Exec(table); err != nil {
			return fmt.Errorf("failed to create table: %v", err)
		}
	}

	return nil
}

// Casbin policy section
func (d *Database) initializeCasbinPolicies() error {
	// Check if policy rows exist
	var c int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM casbin_policies").Scan(&c); err != nil {
		return err
	}

	// Initialize policies
	if c > 0 {
		return nil
	}

	// Initialize policies
	policies := []struct {
		ptype string
		v0    string
		v1    string
		v2    string
	}{
		// 缁狅紕鎮婇崨妯绘綀閿?- 鐎瑰苯鍙忕拋鍧楁６
		{"p", "administrator", "/api/v1/web/*", "(GET|POST|PUT|PATCH|DELETE)"},
		{"p", "administrator", "/api/v1/admin/*", "(GET|POST|PUT|PATCH|DELETE)"},
		{"p", "administrator", "admin", "access"}, // Admin access permission

		// 閺屻儳婀呴懓鍛綀閿?- 閸欘亣顕扮拋鍧楁６
		{"p", "viewer", "/api/v1/web/health*", "GET"},
		{"p", "viewer", "/api/v1/web/", "GET"},
		{"p", "viewer", "/api/v1/web/files/list", "GET"},
		{"p", "viewer", "/api/v1/web/files/versions/*", "GET"},
		{"p", "viewer", "/api/v1/web/files/*", "GET"},
		{"p", "viewer", "/api/v1/web/recycle-bin", "GET"},
		{"p", "viewer", "/api/v1/web/packages", "GET"},

		// 閺夊啴妾哄Λ鈧弻顧嘝I - 閹碘偓閺堝顓荤拠浣烘暏閹寸兘鍏橀崣顖欎簰娴ｈ法鏁?		{"p", "administrator", "/api/v1/web/auth/check-permission", "POST"},
		{"p", "administrator", "/api/v1/web/auth/check-permissions", "POST"},
		{"p", "viewer", "/api/v1/web/auth/check-permission", "POST"},
		{"p", "viewer", "/api/v1/web/auth/check-permissions", "POST"},

		// 閻劍鍩涙穱鈩冧紖API - 閹碘偓閺堝顓荤拠浣烘暏閹寸兘鍏橀崣顖欎簰閼惧嘲褰囬懛顏勭箒閻ㄥ嫪淇婇敓?		{"p", "administrator", "/api/v1/web/auth/me", "GET"},
		{"p", "viewer", "/api/v1/web/auth/me", "GET"},

		// TOTP 2FA API - 閹碘偓閺堝顓荤拠浣烘暏閹寸兘鍏橀崣顖欎簰缁狅紕鎮婇懛顏勭箒閿?FA
		{"p", "administrator", "/api/v1/web/auth/ab/2fa/totp/*", "(GET|POST|PUT|PATCH|DELETE)"},
		{"p", "viewer", "/api/v1/web/auth/ab/2fa/totp/*", "(GET|POST|PUT|PATCH|DELETE)"},
	}

	stmt, err := d.db.Prepare("INSERT INTO casbin_policies (ptype, v0, v1, v2) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, policy := range policies {
		if _, err := stmt.Exec(policy.ptype, policy.v0, policy.v1, policy.v2); err != nil {
			return err
		}
	}

	return nil
}

// Casbin policy section
func (d *Database) updateCasbinPolicies() error {
	// Check if admin access policy already exists
	var c int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM casbin_policies WHERE v0 = 'administrator' AND v1 = 'admin' AND v2 = 'access'").Scan(&c); err != nil {
		return err
	}

	// If admin access policy exists, skip update
	if c > 0 {
		return nil
	}

	// Add missing policies
	missingPolicies := []struct {
		ptype string
		v0    string
		v1    string
		v2    string
	}{
		{"p", "administrator", "/api/v1/web/auth/me", "GET"},
		{"p", "viewer", "/api/v1/web/auth/me", "GET"},
		{"p", "administrator", "/api/v1/web/auth/ab/2fa/totp/*", "(GET|POST|PUT|PATCH|DELETE)"},
		{"p", "viewer", "/api/v1/web/auth/ab/2fa/totp/*", "(GET|POST|PUT|PATCH|DELETE)"},
		{"p", "administrator", "admin", "access"}, // Admin access permission
	}

	stmt, err := d.db.Prepare("INSERT INTO casbin_policies (ptype, v0, v1, v2) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, policy := range missingPolicies {
		if _, err := stmt.Exec(policy.ptype, policy.v0, policy.v1, policy.v2); err != nil {
			return err
		}
	}

	return nil
}

// InsertFileRecord inserts a new file record
func (d *Database) InsertFileRecord(record *FileRecord) error {
	record.CreatedAt = time.Now()
	record.UpdatedAt = time.Now()
	record.Status = FileStatusActive
	record.FileExists = true

	// Start a transaction to ensure atomicity
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// If this is the latest version, mark all previous versions as not latest
	if record.IsLatest {
		updateQuery := `
		UPDATE files
		SET is_latest = 0, updated_at = ?
		WHERE file_type = ? AND original_name = ? AND status = 'active'
		`
		_, err = tx.Exec(updateQuery,
			record.UpdatedAt.Format(time.RFC3339),
			record.FileType,
			record.OriginalName,
		)
		if err != nil {
			return fmt.Errorf("failed to update previous versions: %v", err)
		}
	}

	// Insert the new record
	insertQuery := `
	INSERT INTO files (
		id, original_name, versioned_name, file_type, file_path, size,
		description, uploader, upload_time, version, is_latest, status,
		file_exists, checksum, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = tx.Exec(insertQuery,
		record.ID, record.OriginalName, record.VersionedName, record.FileType,
		record.FilePath, record.Size, record.Description, record.Uploader,
		record.UploadTime.Format(time.RFC3339), record.Version, record.IsLatest,
		record.Status, record.FileExists, record.Checksum,
		record.CreatedAt.Format(time.RFC3339), record.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to insert file record: %v", err)
	}

	// Commit the transaction
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	// Log the upload operation
	if err := d.LogFileOperation(record.ID, "upload", record.Uploader, map[string]interface{}{
		"file_type": record.FileType,
		"size":      record.Size,
		"version":   record.Version,
	}); err != nil {
		// Log the error but don't fail the operation
		fmt.Printf("Warning: failed to log file operation: %v\n", err)
	}

	return nil
}

// GetFilesByType returns files by type
func (d *Database) GetFilesByType(fileType string, includeDeleted bool) ([]FileRecord, error) {
	query := `
	SELECT id, original_name, versioned_name, file_type, file_path, size,
		   description, uploader, upload_time, version, is_latest, status,
		   deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
	FROM files
	WHERE file_type = ?
	`

	if !includeDeleted {
		query += " AND status = 'active'"
	}

	query += " ORDER BY upload_time DESC"

	rows, err := d.db.Query(query, fileType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return d.scanFileRecords(rows)
}

// GetAllFiles returns all files
func (d *Database) GetAllFiles(includeDeleted bool) ([]FileRecord, error) {
	query := `
	SELECT id, original_name, versioned_name, file_type, file_path, size,
		   description, uploader, upload_time, version, is_latest, status,
		   deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
	FROM files
	`

	if !includeDeleted {
		query += " WHERE status = 'active'"
	}

	query += " ORDER BY upload_time DESC"

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return d.scanFileRecords(rows)
}

// GetFileVersions returns all versions of a file
func (d *Database) GetFileVersions(fileType, originalName string) ([]FileRecord, error) {
	query := `
	SELECT id, original_name, versioned_name, file_type, file_path, size,
		   description, uploader, upload_time, version, is_latest, status,
		   deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
	FROM files
	WHERE file_type = ? AND original_name = ? AND status = 'active'
	ORDER BY version DESC
	`

	rows, err := d.db.Query(query, fileType, originalName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return d.scanFileRecords(rows)
}

// SoftDeleteFile moves a file to recycle bin
func (d *Database) SoftDeleteFile(fileID, deletedBy string) error {
	now := time.Now()
	query := `
	UPDATE files
	SET status = 'deleted', deleted_at = ?, deleted_by = ?, updated_at = ?
	WHERE id = ? AND status = 'active'
	`

	result, err := d.db.Exec(query, now.Format(time.RFC3339), deletedBy, now.Format(time.RFC3339), fileID)
	if err != nil {
		return fmt.Errorf("failed to soft delete file: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found or already deleted")
	}

	// Log the delete operation
	if err := d.LogFileOperation(fileID, "delete", deletedBy, map[string]interface{}{
		"deleted_at": now.Format(time.RFC3339),
	}); err != nil {
		// Log the error but don't fail the operation
		fmt.Printf("Warning: failed to log file operation: %v\n", err)
	}

	return nil
}

// RestoreFile restores a file from recycle bin
func (d *Database) RestoreFile(fileID, restoredBy string) error {
	now := time.Now()
	query := `
	UPDATE files
	SET status = 'active', deleted_at = NULL, deleted_by = NULL, updated_at = ?
	WHERE id = ? AND status = 'deleted'
	`

	result, err := d.db.Exec(query, now.Format(time.RFC3339), fileID)
	if err != nil {
		return fmt.Errorf("failed to restore file: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found in recycle bin")
	}

	// Log the restore operation
	if err := d.LogFileOperation(fileID, "restore", restoredBy, map[string]interface{}{
		"restored_at": now.Format(time.RFC3339),
	}); err != nil {
		// Log the error but don't fail the operation
		fmt.Printf("Warning: failed to log file operation: %v\n", err)
	}

	return nil
}

// GetRecycleBinItems returns all items in recycle bin
func (d *Database) GetRecycleBinItems() ([]RecycleBinItem, error) {
	query := `
	SELECT id, original_name, versioned_name, file_type, file_path, size,
		   description, uploader, upload_time, version, is_latest, status,
		   deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
	FROM files
	WHERE status = 'deleted'
	ORDER BY deleted_at DESC
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []RecycleBinItem
	for rows.Next() {
		var record FileRecord
		var uploadTimeStr, createdAtStr, updatedAtStr string
		var deletedAtStr sql.NullString

		err := rows.Scan(
			&record.ID, &record.OriginalName, &record.VersionedName,
			&record.FileType, &record.FilePath, &record.Size,
			&record.Description, &record.Uploader, &uploadTimeStr,
			&record.Version, &record.IsLatest, &record.Status,
			&deletedAtStr, &record.DeletedBy, &record.FileExists,
			&record.Checksum, &createdAtStr, &updatedAtStr,
		)

		if err != nil {
			log.Printf("Error scanning recycle bin record: %v", err)
			continue
		}

		// Parse time strings
		if uploadTime, parseErr := time.Parse(time.RFC3339, uploadTimeStr); parseErr == nil {
			record.UploadTime = uploadTime
		}
		if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			record.CreatedAt = createdAt
		}
		if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
			record.UpdatedAt = updatedAt
		}

		// Parse deleted_at time and calculate days until purge
		var daysUntilPurge int = 90 // Default 90 days
		if deletedAtStr.Valid {
			if deletedAt, parseErr := time.Parse(time.RFC3339, deletedAtStr.String); parseErr == nil {
				record.DeletedAt = &deletedAt
				daysSinceDeleted := int(time.Since(deletedAt).Hours() / 24)
				daysUntilPurge = 90 - daysSinceDeleted
				if daysUntilPurge < 0 {
					daysUntilPurge = 0
				}
			}
		}

		items = append(items, RecycleBinItem{
			FileRecord:     record,
			DaysUntilPurge: daysUntilPurge,
		})
	}

	return items, nil
}

// PermanentlyDeleteFile permanently deletes a file (marks as purged)
func (d *Database) PermanentlyDeleteFile(fileID, purgedBy string) error {
	now := time.Now()
	query := `
	UPDATE files
	SET status = 'purged', updated_at = ?
	WHERE id = ? AND status = 'deleted'
	`

	result, err := d.db.Exec(query, now.Format(time.RFC3339), fileID)
	if err != nil {
		return fmt.Errorf("failed to permanently delete file: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("file not found in recycle bin")
	}

	// Log the purge operation
	if err := d.LogFileOperation(fileID, "purge", purgedBy, map[string]interface{}{
		"purged_at": now.Format(time.RFC3339),
	}); err != nil {
		// Log the error but don't fail the operation
		fmt.Printf("Warning: failed to log file operation: %v\n", err)
	}

	return nil
}

// AutoCleanupRecycleBin automatically purges files older than 90 days
func (d *Database) AutoCleanupRecycleBin() error {
	cutoffTime := time.Now().AddDate(0, 0, -90) // 90 days ago

	query := `
	UPDATE files
	SET status = 'purged', updated_at = ?
	WHERE status = 'deleted' AND deleted_at < ?
	`

	result, err := d.db.Exec(query, time.Now().Format(time.RFC3339), cutoffTime.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to auto cleanup recycle bin: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %v", err)
	}

	log.Printf("Auto cleanup: purged %d files from recycle bin", rowsAffected)
	return nil
}

// CheckFileExists updates the file_exists flag based on physical file existence
func (d *Database) CheckFileExists(fileID string) error {
	// First get the file record
	query := `SELECT file_path FROM files WHERE id = ?`
	var filePath string
	err := d.db.QueryRow(query, fileID).Scan(&filePath)
	if err != nil {
		return fmt.Errorf("file record not found: %v", err)
	}

	// Check if physical file exists
	fileExists := true
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fileExists = false
	}

	// Update the file_exists flag
	updateQuery := `UPDATE files SET file_exists = ?, updated_at = ? WHERE id = ?`
	_, err = d.db.Exec(updateQuery, fileExists, time.Now().Format(time.RFC3339), fileID)
	if err != nil {
		return fmt.Errorf("failed to update file_exists flag: %v", err)
	}

	return nil
}

// LogFileOperation logs file operations to audit table
func (d *Database) LogFileOperation(fileID, operation, operator string, details map[string]interface{}) error {
	detailsJSON, _ := json.Marshal(details)

	query := `
	INSERT INTO file_audit_logs (file_id, operation, operator, operation_time, details)
	VALUES (?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query, fileID, operation, operator, time.Now().Format(time.RFC3339), string(detailsJSON))
	if err != nil {
		log.Printf("Failed to log file operation: %v", err)
		return err
	}

	return nil
}

// scanFileRecords helper function to scan file records from rows
func (d *Database) scanFileRecords(rows *sql.Rows) ([]FileRecord, error) {
	var records []FileRecord

	for rows.Next() {
		var record FileRecord
		var uploadTimeStr, createdAtStr, updatedAtStr string
		var deletedAtStr, deletedBy sql.NullString

		err := rows.Scan(
			&record.ID, &record.OriginalName, &record.VersionedName,
			&record.FileType, &record.FilePath, &record.Size,
			&record.Description, &record.Uploader, &uploadTimeStr,
			&record.Version, &record.IsLatest, &record.Status,
			&deletedAtStr, &deletedBy, &record.FileExists,
			&record.Checksum, &createdAtStr, &updatedAtStr,
		)

		if err != nil {
			log.Printf("Error scanning file record: %v", err)
			continue
		}

		// Parse time fields
		if uploadTime, err := time.Parse(time.RFC3339, uploadTimeStr); err == nil {
			record.UploadTime = uploadTime
		}
		if createdAt, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			record.CreatedAt = createdAt
		}
		if updatedAt, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			record.UpdatedAt = updatedAt
		}
		if deletedAtStr.Valid {
			if deletedAt, err := time.Parse(time.RFC3339, deletedAtStr.String); err == nil {
				record.DeletedAt = &deletedAt
			}
		}
		if deletedBy.Valid {
			record.DeletedBy = deletedBy.String
		}

		records = append(records, record)
	}

	return records, nil
}

// GetFileRecordByID returns a file record by ID
func (d *Database) GetFileRecordByID(id string) (*FileRecord, error) {
    if id == "" {
        return nil, fmt.Errorf("file id is required")
    }
    query := `
    SELECT id, original_name, versioned_name, file_type, file_path, size,
           description, uploader, upload_time, version, is_latest, status,
           deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
    FROM files WHERE id = ?
    `
    row := d.db.QueryRow(query, id)
    var rec FileRecord
    var uploadTimeStr, createdAtStr, updatedAtStr string
    var deletedAt sql.NullString
    if err := row.Scan(&rec.ID, &rec.OriginalName, &rec.VersionedName, &rec.FileType, &rec.FilePath, &rec.Size,
        &rec.Description, &rec.Uploader, &uploadTimeStr, &rec.Version, &rec.IsLatest, &rec.Status,
        &deletedAt, &rec.DeletedBy, &rec.FileExists, &rec.Checksum, &createdAtStr, &updatedAtStr); err != nil {
        return nil, err
    }
    if t, err := time.Parse(time.RFC3339, uploadTimeStr); err == nil { rec.UploadTime = t }
    if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil { rec.CreatedAt = t }
    if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil { rec.UpdatedAt = t }
    if deletedAt.Valid {
        if t, err := time.Parse(time.RFC3339, deletedAt.String); err == nil { rec.DeletedAt = &t }
    }
    return &rec, nil
}

// ListFilesWithPagination returns active files with pagination and total count
func (d *Database) ListFilesWithPagination(offset, limit int) ([]FileRecord, int, error) {
    if limit <= 0 {
        limit = 50
    }
    if offset < 0 {
        offset = 0
    }
    countQ := `SELECT COUNT(*) FROM files WHERE status = 'active'`
    var total int
    if err := d.db.QueryRow(countQ).Scan(&total); err != nil {
        return nil, 0, fmt.Errorf("count files failed: %v", err)
    }

    query := `
    SELECT id, original_name, versioned_name, file_type, file_path, size,
           description, uploader, upload_time, version, is_latest, status,
           deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
    FROM files
    WHERE status = 'active'
    ORDER BY upload_time DESC
    LIMIT ? OFFSET ?
    `
    rows, err := d.db.Query(query, limit, offset)
    if err != nil {
        return nil, 0, err
    }
    defer rows.Close()
    recs, err := d.scanFileRecords(rows)
    if err != nil {
        return nil, 0, err
    }
    return recs, total, nil
}

// ListFilesWithPaginationByType returns active files of a specific type with pagination and total count
func (d *Database) ListFilesWithPaginationByType(fileType string, offset, limit int) ([]FileRecord, int, error) {
    if limit <= 0 { limit = 50 }
    if offset < 0 { offset = 0 }
    countQ := `SELECT COUNT(*) FROM files WHERE status = 'active' AND file_type = ?`
    var total int
    if err := d.db.QueryRow(countQ, fileType).Scan(&total); err != nil {
        return nil, 0, fmt.Errorf("count files failed: %v", err)
    }
    query := `
    SELECT id, original_name, versioned_name, file_type, file_path, size,
           description, uploader, upload_time, version, is_latest, status,
           deleted_at, deleted_by, file_exists, checksum, created_at, updated_at
    FROM files
    WHERE status = 'active' AND file_type = ?
    ORDER BY upload_time DESC
    LIMIT ? OFFSET ?
    `
    rows, err := d.db.Query(query, fileType, limit, offset)
    if err != nil { return nil, 0, err }
    defer rows.Close()
    recs, err := d.scanFileRecords(rows)
    if err != nil { return nil, 0, err }
    return recs, total, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// =============================================================================
// Package Management Functions
// =============================================================================

// InsertPackageRecord inserts a new package record
func (d *Database) InsertPackageRecord(p *PackageRecord) error {
	p.CreatedAt = time.Now()
	p.UpdatedAt = time.Now()
	if p.Timestamp.IsZero() {
		p.Timestamp = time.Now()
	}
	query := `
    INSERT INTO packages (id, tenant_id, type, file_name, size, path, ip, timestamp, remark, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `
	_, err := d.db.Exec(query,
		p.ID, p.TenantID, p.Type, p.FileName, p.Size, p.Path, p.IP,
		p.Timestamp.Format(time.RFC3339), p.Remark,
		p.CreatedAt.Format(time.RFC3339), p.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

// ListPackages lists packages with optional filters and pagination
func (d *Database) ListPackages(tenant, ptype, search string, page, limit int) ([]PackageRecord, int, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	offset := (page - 1) * limit

	base := "SELECT id, tenant_id, type, file_name, size, path, ip, timestamp, remark, created_at, updated_at FROM packages WHERE 1=1"
	countQ := "SELECT COUNT(1) FROM packages WHERE 1=1"
	args := []interface{}{}

	if tenant != "" {
		base += " AND tenant_id = ?"
		countQ += " AND tenant_id = ?"
		args = append(args, tenant)
	}
	if ptype != "" {
		base += " AND type = ?"
		countQ += " AND type = ?"
		args = append(args, ptype)
	}
	if search != "" {
		like := "%" + search + "%"
		base += " AND (file_name LIKE ? OR path LIKE ? OR remark LIKE ?)"
		countQ += " AND (file_name LIKE ? OR path LIKE ? OR remark LIKE ?)"
		args = append(args, like, like, like)
	}
	base += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"

	// Count first
	var total int
	if err := d.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Append pagination params
	argsWithPage := append(append([]interface{}{}, args...), limit, offset)
	rows, err := d.db.Query(base, argsWithPage...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var list []PackageRecord
	for rows.Next() {
		var r PackageRecord
		var ts, ca, ua string
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Type, &r.FileName, &r.Size, &r.Path, &r.IP, &ts, &r.Remark, &ca, &ua); err != nil {
			log.Printf("scan package: %v", err)
			continue
		}
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			r.Timestamp = t
		}
		if t, err := time.Parse(time.RFC3339, ca); err == nil {
			r.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, ua); err == nil {
			r.UpdatedAt = t
		}
		list = append(list, r)
	}
	return list, total, nil
}

// UpdatePackageRemark updates remark for a package
func (d *Database) UpdatePackageRemark(id, remark string) error {
	now := time.Now().Format(time.RFC3339)
	_, err := d.db.Exec("UPDATE packages SET remark = ?, updated_at = ? WHERE id = ?", remark, now, id)
	return err
}

// =============================================================================
// API Key Management Functions
// =============================================================================

// CreateAPIKey creates a new API key
func (d *Database) CreateAPIKey(apiKey *APIKey) error {
	apiKey.CreatedAt = time.Now()
	apiKey.UpdatedAt = time.Now()

	permissionsJSON, _ := json.Marshal(apiKey.Permissions)

	query := `
    INSERT INTO api_keys (
        id, name, description, key_hash, role, permissions, status,
        expires_at, usage_count, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

	var expiresAtStr sql.NullString
	if apiKey.ExpiresAt != nil {
		expiresAtStr = sql.NullString{String: apiKey.ExpiresAt.Format(time.RFC3339), Valid: true}
	}

	_, err := d.db.Exec(query,
		apiKey.ID, apiKey.Name, apiKey.Description, apiKey.KeyHash, apiKey.Role,
		string(permissionsJSON), apiKey.Status, expiresAtStr, apiKey.UsageCount,
		apiKey.CreatedAt.Format(time.RFC3339), apiKey.UpdatedAt.Format(time.RFC3339),
	)

	return err
}

// GetAPIKeyByID retrieves an API key by its ID
func (d *Database) GetAPIKeyByID(keyID string) (*APIKey, error) {
	query := `
    SELECT id, name, description, key_hash, role, permissions, status,
           expires_at, usage_count, last_used_at, created_at, updated_at
    FROM api_keys
    WHERE id = ?
    `

	var apiKey APIKey
	var permissionsJSON string
	var expiresAtStr, lastUsedAtStr sql.NullString
	var createdAtStr, updatedAtStr string

	err := d.db.QueryRow(query, keyID).Scan(
		&apiKey.ID, &apiKey.Name, &apiKey.Description, &apiKey.KeyHash,
		&apiKey.Role, &permissionsJSON, &apiKey.Status,
		&expiresAtStr, &apiKey.UsageCount, &lastUsedAtStr,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		return nil, err
	}

	// Parse JSON permissions
	if err := json.Unmarshal([]byte(permissionsJSON), &apiKey.Permissions); err != nil {
		// Log the error but continue with empty permissions
		fmt.Printf("Warning: failed to parse permissions JSON: %v\n", err)
		apiKey.Permissions = []string{}
	}

	// Parse time strings
	if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
		apiKey.CreatedAt = createdAt
	}
	if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
		apiKey.UpdatedAt = updatedAt
	}
	if expiresAtStr.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr.String); parseErr == nil {
			apiKey.ExpiresAt = &expiresAt
		}
	}
	if lastUsedAtStr.Valid {
		if lastUsedAt, parseErr := time.Parse(time.RFC3339, lastUsedAtStr.String); parseErr == nil {
			apiKey.LastUsedAt = &lastUsedAt
		}
	}

	return &apiKey, nil
}

// GetAPIKeyByHash retrieves an API key by its hash
func (d *Database) GetAPIKeyByHash(keyHash string) (*APIKey, error) {
	query := `
    SELECT id, name, description, key_hash, role, permissions, status,
           expires_at, usage_count, last_used_at, created_at, updated_at
    FROM api_keys
    WHERE key_hash = ? AND status = 'active'
    `

	var apiKey APIKey
	var permissionsJSON string
	var expiresAtStr, lastUsedAtStr sql.NullString
	var createdAtStr, updatedAtStr string

	err := d.db.QueryRow(query, keyHash).Scan(
		&apiKey.ID, &apiKey.Name, &apiKey.Description, &apiKey.KeyHash,
		&apiKey.Role, &permissionsJSON, &apiKey.Status,
		&expiresAtStr, &apiKey.UsageCount, &lastUsedAtStr,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		return nil, err
	}

	// Parse JSON permissions
	if err := json.Unmarshal([]byte(permissionsJSON), &apiKey.Permissions); err != nil {
		// Log the error but continue with empty permissions
		fmt.Printf("Warning: failed to parse permissions JSON: %v\n", err)
		apiKey.Permissions = []string{}
	}

	// Parse time strings
	if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
		apiKey.CreatedAt = createdAt
	}
	if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
		apiKey.UpdatedAt = updatedAt
	}
	if expiresAtStr.Valid {
		if expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr.String); parseErr == nil {
			apiKey.ExpiresAt = &expiresAt
		}
	}
	if lastUsedAtStr.Valid {
		if lastUsedAt, parseErr := time.Parse(time.RFC3339, lastUsedAtStr.String); parseErr == nil {
			apiKey.LastUsedAt = &lastUsedAt
		}
	}

	return &apiKey, nil
}

// GetAPIKeysByUserID retrieves all API keys for a user
func (d *Database) GetAPIKeysByRole(role string) ([]APIKey, error) {
	query := `
    SELECT id, name, description, role, permissions, status,
           expires_at, usage_count, last_used_at, created_at, updated_at
    FROM api_keys
    WHERE role = ?
    ORDER BY created_at DESC
    `

	rows, err := d.db.Query(query, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apiKeys []APIKey
	for rows.Next() {
		var apiKey APIKey
		var permissionsJSON string
		var expiresAtStr, lastUsedAtStr sql.NullString
		var createdAtStr, updatedAtStr string

		err := rows.Scan(
			&apiKey.ID, &apiKey.Name, &apiKey.Description, &apiKey.Role,
			&permissionsJSON, &apiKey.Status, &expiresAtStr, &apiKey.UsageCount,
			&lastUsedAtStr, &createdAtStr, &updatedAtStr,
		)

		if err != nil {
			log.Printf("Error scanning API key record: %v", err)
			continue
		}

		// Parse JSON permissions
		if err := json.Unmarshal([]byte(permissionsJSON), &apiKey.Permissions); err != nil {
			log.Printf("Warning: failed to parse permissions JSON: %v", err)
			apiKey.Permissions = []string{}
		}

		// Parse time strings
		if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			apiKey.CreatedAt = createdAt
		}
		if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
			apiKey.UpdatedAt = updatedAt
		}
		if expiresAtStr.Valid {
			if expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr.String); parseErr == nil {
				apiKey.ExpiresAt = &expiresAt
			}
		}
		if lastUsedAtStr.Valid {
			if lastUsedAt, parseErr := time.Parse(time.RFC3339, lastUsedAtStr.String); parseErr == nil {
				apiKey.LastUsedAt = &lastUsedAt
			}
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

// GetAllAPIKeys retrieves all API keys
func (d *Database) GetAllAPIKeys() ([]APIKey, error) {
	query := `
    SELECT id, name, description, role, permissions, status,
           expires_at, usage_count, last_used_at, created_at, updated_at
    FROM api_keys
    ORDER BY created_at DESC
    `

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apiKeys []APIKey
	for rows.Next() {
		var apiKey APIKey
		var permissionsJSON string
		var expiresAtStr, lastUsedAtStr sql.NullString
		var createdAtStr, updatedAtStr string

		err := rows.Scan(
			&apiKey.ID, &apiKey.Name, &apiKey.Description, &apiKey.Role,
			&permissionsJSON, &apiKey.Status, &expiresAtStr, &apiKey.UsageCount,
			&lastUsedAtStr, &createdAtStr, &updatedAtStr,
		)

		if err != nil {
			log.Printf("Error scanning API key record: %v", err)
			continue
		}

		// Parse JSON permissions
		if err := json.Unmarshal([]byte(permissionsJSON), &apiKey.Permissions); err != nil {
			log.Printf("Warning: failed to parse permissions JSON: %v", err)
			apiKey.Permissions = []string{}
		}

		// Parse time strings
		if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			apiKey.CreatedAt = createdAt
		}
		if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
			apiKey.UpdatedAt = updatedAt
		}
		if expiresAtStr.Valid {
			if expiresAt, parseErr := time.Parse(time.RFC3339, expiresAtStr.String); parseErr == nil {
				apiKey.ExpiresAt = &expiresAt
			}
		}
		if lastUsedAtStr.Valid {
			if lastUsedAt, parseErr := time.Parse(time.RFC3339, lastUsedAtStr.String); parseErr == nil {
				apiKey.LastUsedAt = &lastUsedAt
			}
		}

		apiKeys = append(apiKeys, apiKey)
	}

	return apiKeys, nil
}

// UpdateAPIKeyUsage updates the usage count and last used time for an API key
func (d *Database) UpdateAPIKeyUsage(keyID string) error {
	query := `
	UPDATE api_keys
	SET usage_count = usage_count + 1, last_used_at = ?, updated_at = ?
	WHERE id = ?
	`

	now := time.Now()
	_, err := d.db.Exec(query, now.Format(time.RFC3339), now.Format(time.RFC3339), keyID)
	return err
}

// UpdateAPIKeyStatus updates the status of an API key
func (d *Database) UpdateAPIKeyStatus(keyID, status string) error {
	query := `
	UPDATE api_keys
	SET status = ?, updated_at = ?
	WHERE id = ?
	`

	now := time.Now()
	_, err := d.db.Exec(query, status, now.Format(time.RFC3339), keyID)
	return err
}

// DeleteAPIKey deletes an API key
func (d *Database) DeleteAPIKey(keyID string) error {
	query := `DELETE FROM api_keys WHERE id = ?`
	_, err := d.db.Exec(query, keyID)
	return err
}

// UpdateAPIKeyFields updates selective fields of an API key
func (d *Database) UpdateAPIKeyFields(id string, name *string, description *string, permissions *[]string, expiresAt *time.Time, clearExpiry bool) error {
    if id == "" { return fmt.Errorf("api key id required") }
    sets := []string{}
    args := []interface{}{}
    if name != nil {
        sets = append(sets, "name = ?")
        args = append(args, *name)
    }
    if description != nil {
        sets = append(sets, "description = ?")
        args = append(args, *description)
    }
    if permissions != nil {
        permJSON, _ := json.Marshal(*permissions)
        sets = append(sets, "permissions = ?")
        args = append(args, string(permJSON))
    }
    if clearExpiry {
        sets = append(sets, "expires_at = NULL")
    } else if expiresAt != nil {
        sets = append(sets, "expires_at = ?")
        args = append(args, expiresAt.Format(time.RFC3339))
    }
    if len(sets) == 0 {
        return nil
    }
    sets = append(sets, "updated_at = ?")
    args = append(args, time.Now().Format(time.RFC3339))
    // where clause id
    args = append(args, id)
    query := fmt.Sprintf("UPDATE api_keys SET %s WHERE id = ?", strings.Join(sets, ", "))
    _, err := d.db.Exec(query, args...)
    return err
}

// LogAPIUsage logs an API usage entry
func (d *Database) LogAPIUsage(log *APIUsageLog) error {
	query := `
	INSERT INTO api_usage_logs (
		api_key_id, user_id, endpoint, method, file_id, file_path,
		ip_address, user_agent, status_code, response_size, response_time_ms,
		error_message, request_time
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		log.APIKeyID, log.UserID, log.Endpoint, log.Method, log.FileID, log.FilePath,
		log.IPAddress, log.UserAgent, log.StatusCode, log.ResponseSize, log.ResponseTimeMs,
		log.ErrorMessage, log.RequestTime.Format(time.RFC3339),
	)

	return err
}

// GetAPIUsageLogs retrieves API usage logs with filters
func (d *Database) GetAPIUsageLogs(userID, fileID string, limit, offset int) ([]APIUsageLog, error) {
	query := `
	SELECT id, api_key_id, user_id, endpoint, method, file_id, file_path,
		   ip_address, user_agent, status_code, response_size, response_time_ms,
		   error_message, request_time, created_at
	FROM api_usage_logs
	WHERE 1=1
	`
	args := []interface{}{}

	if userID != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}

	if fileID != "" {
		query += " AND file_id = ?"
		args = append(args, fileID)
	}

	query += " ORDER BY request_time DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []APIUsageLog
	for rows.Next() {
		var logEntry APIUsageLog
		var requestTimeStr, createdAtStr string
		var fileID, filePath, userAgent, errorMessage sql.NullString

		err := rows.Scan(
			&logEntry.ID, &logEntry.APIKeyID, &logEntry.UserID, &logEntry.Endpoint,
			&logEntry.Method, &fileID, &filePath, &logEntry.IPAddress, &userAgent,
			&logEntry.StatusCode, &logEntry.ResponseSize, &logEntry.ResponseTimeMs,
			&errorMessage, &requestTimeStr, &createdAtStr,
		)

		if err != nil {
			log.Printf("Error scanning API usage log: %v", err)
			continue
		}

		// Handle nullable fields
		if fileID.Valid {
			logEntry.FileID = fileID.String
		}
		if filePath.Valid {
			logEntry.FilePath = filePath.String
		}
		if userAgent.Valid {
			logEntry.UserAgent = userAgent.String
		}
		if errorMessage.Valid {
			logEntry.ErrorMessage = errorMessage.String
		}

		// Parse time strings
		if requestTime, parseErr := time.Parse(time.RFC3339, requestTimeStr); parseErr == nil {
			logEntry.RequestTime = requestTime
		}
		if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
			logEntry.CreatedAt = createdAt
		}

		logs = append(logs, logEntry)
	}

	return logs, nil
}

// =============================================================================
// User Role Management Functions
// =============================================================================

// CreateOrUpdateUserRole creates or updates a user role
func (d *Database) CreateOrUpdateUserRole(userRole *UserRole) error {
	userRole.UpdatedAt = time.Now()
	if userRole.CreatedAt.IsZero() {
		userRole.CreatedAt = userRole.UpdatedAt
	}

	permissionsJSON, _ := json.Marshal(userRole.Permissions)

	query := `
	INSERT OR REPLACE INTO user_roles (
		user_id, role, permissions, quota_daily, quota_monthly, status, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		userRole.UserID, userRole.Role, string(permissionsJSON),
		userRole.QuotaDaily, userRole.QuotaMonthly, userRole.Status,
		userRole.CreatedAt.Format(time.RFC3339), userRole.UpdatedAt.Format(time.RFC3339),
	)

	return err
}

// GetUserRole retrieves a user's role and permissions
func (d *Database) GetUserRole(userID string) (*UserRole, error) {
	query := `
	SELECT id, user_id, role, permissions, quota_daily, quota_monthly, status, created_at, updated_at
	FROM user_roles
	WHERE user_id = ?
	`

	var userRole UserRole
	var permissionsJSON sql.NullString
	var createdAtStr, updatedAtStr string

	err := d.db.QueryRow(query, userID).Scan(
		&userRole.ID, &userRole.UserID, &userRole.Role, &permissionsJSON,
		&userRole.QuotaDaily, &userRole.QuotaMonthly, &userRole.Status,
		&createdAtStr, &updatedAtStr,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return default role if not found
			return &UserRole{
				UserID:       userID,
				Role:         "user",
				Permissions:  []string{"read"},
				QuotaDaily:   -1,
				QuotaMonthly: -1,
				Status:       "active",
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}, nil
		}
		return nil, err
	}

	// Parse JSON permissions
	if permissionsJSON.Valid {
		if err := json.Unmarshal([]byte(permissionsJSON.String), &userRole.Permissions); err != nil {
			log.Printf("Warning: failed to parse user role permissions JSON: %v", err)
			userRole.Permissions = []string{"read"} // default permissions
		}
	}

	// Parse time strings
	if createdAt, parseErr := time.Parse(time.RFC3339, createdAtStr); parseErr == nil {
		userRole.CreatedAt = createdAt
	}
	if updatedAt, parseErr := time.Parse(time.RFC3339, updatedAtStr); parseErr == nil {
		userRole.UpdatedAt = updatedAt
	}

	return &userRole, nil
}

// =============================================================================
// User Management Functions (users table)
// =============================================================================

// CreateUser inserts a new application user. Caller must provide a hashed password.
func (d *Database) CreateUser(u *AppUser) error {
	if u == nil || u.Username == "" || u.PasswordHash == "" {
		return fmt.Errorf("invalid user payload")
	}
	if u.Role == "" {
		u.Role = "viewer"
	}
	now := time.Now()
	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}
	u.UpdatedAt = now

	_, err := d.db.Exec(`
        INSERT INTO users (username, email, password_hash, role, twofa_enabled, totp_secret, totp_last_code, recovery_codes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
		u.Username,
		u.Email,
		u.PasswordHash,
		u.Role,
		u.TwoFAEnabled,
		u.TOTPSecret,
		u.TOTPLastCode,
		u.RecoveryCodes,
		u.CreatedAt.Format(time.RFC3339),
		u.UpdatedAt.Format(time.RFC3339),
	)
	return err
}

// GetUser retrieves a user by username.
func (d *Database) GetUser(username string) (*AppUser, error) {
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}
	row := d.db.QueryRow(`
        SELECT username, email, password_hash, role, twofa_enabled, totp_secret, totp_last_code, recovery_codes, created_at, updated_at, last_login_at
        FROM users WHERE username = ?
    `, username)

	var u AppUser
	var createdAtStr, updatedAtStr string
	var lastLogin sql.NullString
	if err := row.Scan(&u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.TwoFAEnabled, &u.TOTPSecret, &u.TOTPLastCode, &u.RecoveryCodes, &createdAtStr, &updatedAtStr, &lastLogin); err != nil {
		return nil, err
	}
	if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
		u.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
		u.UpdatedAt = t
	}
	if lastLogin.Valid {
		if t, err := time.Parse(time.RFC3339, lastLogin.String); err == nil {
			u.LastLoginAt = &t
		}
	}
	return &u, nil
}

// UpdateUser updates mutable fields for a user (email, role, twofa flags, totp_secret, timestamps)
func (d *Database) UpdateUser(u *AppUser) error {
	if u == nil || u.Username == "" {
		return fmt.Errorf("invalid user payload")
	}
	u.UpdatedAt = time.Now()
	_, err := d.db.Exec(`
        UPDATE users SET email = ?, role = ?, twofa_enabled = ?, totp_secret = ?, totp_last_code = ?, recovery_codes = ?, updated_at = ?
        WHERE username = ?
    `,
		u.Email,
		u.Role,
		u.TwoFAEnabled,
		u.TOTPSecret,
		u.TOTPLastCode,
		u.RecoveryCodes,
		u.UpdatedAt.Format(time.RFC3339),
		u.Username,
	)
	return err
}

// UpdateUserPassword updates a user's password hash
func (d *Database) UpdateUserPassword(username, passwordHash string) error {
	if username == "" || passwordHash == "" {
		return fmt.Errorf("username and password hash required")
	}
	_, err := d.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`, passwordHash, time.Now().Format(time.RFC3339), username)
	return err
}

// SetUser2FA sets 2FA status and optionally TOTP secret
func (d *Database) SetUser2FA(username string, enabled bool, secret string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	_, err := d.db.Exec(`
        UPDATE users SET twofa_enabled = ?, totp_secret = ?, updated_at = ? WHERE username = ?
    `, enabled, secret, time.Now().Format(time.RFC3339), username)
	return err
}

// SetUserLastLogin updates the last_login_at timestamp
func (d *Database) SetUserLastLogin(username string, when time.Time) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	_, err := d.db.Exec(`UPDATE users SET last_login_at = ?, updated_at = ? WHERE username = ?`, when.Format(time.RFC3339), time.Now().Format(time.RFC3339), username)
	return err
}

// Note: SetUserMustReset function removed - authboss handles password reset flow

// ListUsers returns all users from users table
func (d *Database) ListUsers() ([]AppUser, error) {
	rows, err := d.db.Query(`
        SELECT username, email, password_hash, role, twofa_enabled, totp_secret, created_at, updated_at, last_login_at
        FROM users ORDER BY username ASC
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []AppUser
	for rows.Next() {
		var u AppUser
		var createdAtStr, updatedAtStr string
		var lastLogin sql.NullString
		if err := rows.Scan(&u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.TwoFAEnabled, &u.TOTPSecret, &createdAtStr, &updatedAtStr, &lastLogin); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			u.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtStr); err == nil {
			u.UpdatedAt = t
		}
		if lastLogin.Valid {
			if t, err := time.Parse(time.RFC3339, lastLogin.String); err == nil {
				u.LastLoginAt = &t
			}
		}
		users = append(users, u)
	}
	return users, nil
}

// PackageRecord represents an uploaded package (assets/others)
type PackageRecord struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenantId"`
	Type      string    `json:"type"` // assets or others
	FileName  string    `json:"fileName"`
	Size      int64     `json:"size"`
	Path      string    `json:"path"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
	Remark    string    `json:"remark"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// LogAdminAction appends an admin audit log entry
func (d *Database) LogAdminAction(actor, targetUser, action string, details map[string]interface{}) error {
	var detailsJSON []byte
	var err error
	if details != nil {
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			detailsJSON = []byte("{}")
		}
	} else {
		detailsJSON = []byte("{}")
	}
	_, err = d.db.Exec(`
        INSERT INTO admin_audit_logs (actor, target_user, action, details, created_at)
        VALUES (?, ?, ?, ?, ?)
    `,
		actor,
		targetUser,
		action,
		string(detailsJSON),
		time.Now().Format(time.RFC3339),
	)
	return err
}

// AdminAuditLog represents admin operation audit entries
type AdminAuditLog struct {
	ID         int64     `json:"id"`
	Actor      string    `json:"actor"`
	TargetUser string    `json:"targetUser"`
	Action     string    `json:"action"`
	Details    string    `json:"details"`
	CreatedAt  time.Time `json:"createdAt"`
}

// GetAdminAuditLogs returns audit logs by filters with pagination and total count
func (d *Database) GetAdminAuditLogs(actor, target, action, since, until string, page, limit int) ([]AdminAuditLog, int, error) {
	where := "WHERE 1=1"
	args := []interface{}{}
	if actor != "" {
		where += " AND actor = ?"
		args = append(args, actor)
	}
	if target != "" {
		where += " AND target_user = ?"
		args = append(args, target)
	}
	if action != "" {
		where += " AND action = ?"
		args = append(args, action)
	}
	if since != "" {
		where += " AND created_at >= ?"
		args = append(args, since)
	}
	if until != "" {
		where += " AND created_at <= ?"
		args = append(args, until)
	}

	// Total count
	var total int
	row := d.db.QueryRow("SELECT COUNT(1) FROM admin_audit_logs "+where, args...)
	if err := row.Scan(&total); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * limit
	query := "SELECT id, actor, target_user, action, details, created_at FROM admin_audit_logs " + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args2 := append([]interface{}{}, args...)
	args2 = append(args2, limit, offset)

	rows, err := d.db.Query(query, args2...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var items []AdminAuditLog
	for rows.Next() {
		var it AdminAuditLog
		var createdAtStr string
		if err := rows.Scan(&it.ID, &it.Actor, &it.TargetUser, &it.Action, &it.Details, &createdAtStr); err != nil {
			continue
		}
		if t, err := time.Parse(time.RFC3339, createdAtStr); err == nil {
			it.CreatedAt = t
		}
		items = append(items, it)
	}
	return items, total, nil
}







