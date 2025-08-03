package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database manager struct
type Database struct {
	db *sql.DB
}

// FileStatus represents the status of a file
type FileStatus string

const (
	FileStatusActive   FileStatus = "active"   // Active file
	FileStatusDeleted  FileStatus = "deleted"  // In recycle bin
	FileStatusPurged   FileStatus = "purged"   // Permanently deleted
)

// FileRecord represents a file record in the database
type FileRecord struct {
	ID          string     `json:"id"`
	OriginalName string    `json:"originalName"`
	VersionedName string   `json:"versionedName"`
	FileType    string     `json:"fileType"`
	FilePath    string     `json:"filePath"`
	Size        int64      `json:"size"`
	Description string     `json:"description"`
	Uploader    string     `json:"uploader"`
	UploadTime  time.Time  `json:"uploadTime"`
	Version     int        `json:"version"`
	IsLatest    bool       `json:"isLatest"`
	Status      FileStatus `json:"status"`
	DeletedAt   *time.Time `json:"deletedAt,omitempty"`
	DeletedBy   string     `json:"deletedBy,omitempty"`
	FileExists  bool       `json:"fileExists"` // Whether physical file exists
	Checksum    string     `json:"checksum,omitempty"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

// RecycleBinItem represents an item in the recycle bin
type RecycleBinItem struct {
	FileRecord
	DaysUntilPurge int `json:"daysUntilPurge"`
}

var defaultDB *Database

// InitDatabase initializes the database connection and creates tables
func InitDatabase(dbPath string) error {
	// Create directory if not exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %v", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
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

	if err := defaultDB.createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %v", err)
	}

	return nil
}

// GetDatabase returns the default database instance
func GetDatabase() *Database {
	return defaultDB
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

	// Execute all table creation statements
	tables := []string{createFilesTable, createLogsTable, createAuditTable}
	for _, table := range tables {
		if _, err := d.db.Exec(table); err != nil {
			return fmt.Errorf("failed to create table: %v", err)
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

	query := `
	INSERT INTO files (
		id, original_name, versioned_name, file_type, file_path, size,
		description, uploader, upload_time, version, is_latest, status,
		file_exists, checksum, created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.Exec(query,
		record.ID, record.OriginalName, record.VersionedName, record.FileType,
		record.FilePath, record.Size, record.Description, record.Uploader,
		record.UploadTime.Format(time.RFC3339), record.Version, record.IsLatest,
		record.Status, record.FileExists, record.Checksum,
		record.CreatedAt.Format(time.RFC3339), record.UpdatedAt.Format(time.RFC3339),
	)

	if err != nil {
		return fmt.Errorf("failed to insert file record: %v", err)
	}

	// Log the upload operation
	d.LogFileOperation(record.ID, "upload", record.Uploader, map[string]interface{}{
		"file_type": record.FileType,
		"size":      record.Size,
		"version":   record.Version,
	})

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
	d.LogFileOperation(fileID, "delete", deletedBy, map[string]interface{}{
		"deleted_at": now.Format(time.RFC3339),
	})

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
	d.LogFileOperation(fileID, "restore", restoredBy, map[string]interface{}{
		"restored_at": now.Format(time.RFC3339),
	})

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
	d.LogFileOperation(fileID, "purge", purgedBy, map[string]interface{}{
		"purged_at": now.Format(time.RFC3339),
	})

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

// GetDB returns the underlying sql.DB instance
func (d *Database) GetDB() *sql.DB {
	return d.db
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}