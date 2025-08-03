package migration

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"secure-file-hub/internal/database"
)

// FileMetadata represents the old JSON metadata structure
type FileMetadata struct {
	ID           string    `json:"id"`
	OriginalName string    `json:"originalName"`
	FileType     string    `json:"fileType"`
	Description  string    `json:"description"`
	Uploader     string    `json:"uploader"`
	UploadTime   time.Time `json:"uploadTime"`
	Version      int       `json:"version"`
	VersionedName string   `json:"versionedName"`
}

// MigrateFromJSON migrates file metadata from JSON file to database
func MigrateFromJSON(metadataFile string) error {
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	log.Println("Starting migration from JSON metadata to database...")

	// Load existing JSON metadata if exists
	var oldMetadata map[string]FileMetadata
	if _, err := os.Stat(metadataFile); err == nil {
		data, err := os.ReadFile(metadataFile)
		if err != nil {
			log.Printf("Warning: Failed to read metadata file: %v", err)
		} else {
			if err := json.Unmarshal(data, &oldMetadata); err != nil {
				log.Printf("Warning: Failed to parse metadata file: %v", err)
			} else {
				log.Printf("Found %d files in existing metadata", len(oldMetadata))
			}
		}
	}

	// Migrate existing metadata to database
	migratedCount := 0
	if oldMetadata != nil {
		for relativePath, metadata := range oldMetadata {
			fullPath := filepath.Join("downloads", relativePath)

			// Check if file actually exists
			fileExists := true
			var fileSize int64
			var checksum string

			if stat, err := os.Stat(fullPath); err == nil {
				fileSize = stat.Size()
				// Calculate checksum for existing files
				if hash, err := calculateChecksum(fullPath); err == nil {
					checksum = hash
				}
			} else {
				fileExists = false
				log.Printf("Warning: File referenced in metadata not found: %s", fullPath)
			}

			// Determine if this is the latest version
			isLatest := metadata.Version == 0 || strings.Contains(relativePath, metadata.OriginalName)

			record := &database.FileRecord{
				ID:           metadata.ID,
				OriginalName: metadata.OriginalName,
				VersionedName: metadata.VersionedName,
				FileType:     metadata.FileType,
				FilePath:     fullPath,
				Size:         fileSize,
				Description:  metadata.Description,
				Uploader:     metadata.Uploader,
				UploadTime:   metadata.UploadTime,
				Version:      metadata.Version,
				IsLatest:     isLatest,
				FileExists:   fileExists,
				Checksum:     checksum,
			}

			if err := db.InsertFileRecord(record); err != nil {
				log.Printf("Warning: Failed to migrate file record %s: %v", metadata.ID, err)
			} else {
				migratedCount++
			}
		}
	}

	// Scan for files not in metadata and add them
	discoveredCount := 0
	types := []string{"config", "certificate", "docs"}
	for _, fileType := range types {
		baseDir := filepath.Join("downloads", fileType+"s")

		if _, err := os.Stat(baseDir); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Skip files already migrated
			alreadyMigrated := false
			if oldMetadata != nil {
				relPath, _ := filepath.Rel("downloads", path)
				if _, exists := oldMetadata[relPath]; exists {
					return nil
				}
			}

			if !alreadyMigrated && isValidFileExtension(info.Name()) {
				if record := createRecordFromFile(path, fileType, info); record != nil {
					if err := db.InsertFileRecord(record); err != nil {
						log.Printf("Warning: Failed to add discovered file %s: %v", path, err)
					} else {
						discoveredCount++
					}
				}
			}
			return nil
		})
	}

	log.Printf("Migration completed: %d files migrated from metadata, %d files discovered", migratedCount, discoveredCount)

	// Backup the old metadata file
	if oldMetadata != nil {
		backupFile := metadataFile + ".backup." + time.Now().Format("20060102_150405")
		if err := os.Rename(metadataFile, backupFile); err != nil {
			log.Printf("Warning: Failed to backup metadata file: %v", err)
		} else {
			log.Printf("Old metadata backed up to: %s", backupFile)
		}
	}

	return nil
}

// createRecordFromFile creates a database record from a discovered file
func createRecordFromFile(filePath, fileType string, info os.FileInfo) *database.FileRecord {
	// Generate ID
	id := generateFileID()

	// Calculate checksum
	checksum, err := calculateChecksum(filePath)
	if err != nil {
		log.Printf("Warning: Failed to calculate checksum for %s: %v", filePath, err)
	}

	fileName := info.Name()
	var originalName string
	var version int

	// Try to parse version from filename
	if strings.Contains(fileName, "_v") {
		parts := strings.Split(fileName, "_v")
		if len(parts) >= 2 {
			originalName = parts[0] + filepath.Ext(fileName)
			versionStr := strings.TrimSuffix(parts[1], filepath.Ext(fileName))
			if v, parseErr := strconv.Atoi(versionStr); parseErr == nil {
				version = v
			} else {
				version = 1
			}
		} else {
			originalName = fileName
			version = 1
		}
	} else {
		originalName = fileName
		version = 1
	}

	return &database.FileRecord{
		ID:           id,
		OriginalName: originalName,
		VersionedName: fileName,
		FileType:     fileType,
		FilePath:     filePath,
		Size:         info.Size(),
		Description:  "Discovered during migration",
		Uploader:     "system_migration",
		UploadTime:   info.ModTime(),
		Version:      version,
		IsLatest:     true, // Assume discovered files are latest
		FileExists:   true,
		Checksum:     checksum,
	}
}

// calculateChecksum calculates MD5 checksum of a file
func calculateChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// generateFileID generates a unique file ID
func generateFileID() string {
	return fmt.Sprintf("file_%d_%d", time.Now().UnixNano(), os.Getpid())
}

// isValidFileExtension checks if file extension is valid
func isValidFileExtension(filename string) bool {
	validExtensions := map[string]bool{
		".json": true, ".crt": true, ".key": true, ".pem": true,
		".txt": true, ".log": true, ".yaml": true, ".yml": true,
		".conf": true, ".config": true, ".cfg": true,
	}

	ext := strings.ToLower(filepath.Ext(filename))
	return validExtensions[ext]
}