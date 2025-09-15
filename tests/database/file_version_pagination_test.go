package database

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"secure-file-hub/internal/database"
	"secure-file-hub/tests/helpers"
)

func TestGetFileVersionsWithPagination(t *testing.T) {
	// Setup test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	if err := database.InitDatabase(dbPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	db := database.GetDatabase()

	// Create test file records with multiple versions
	fileType := "document"
	originalName := "test-doc.pdf"
	uploader := "testuser"

	// Insert 5 versions of the same file
	for i := 1; i <= 5; i++ {
		versionedName := fmt.Sprintf("test-doc_v%d.pdf", i)
		record := &database.FileRecord{
			ID:            helpers.GenerateRandomID(16),
			OriginalName:  originalName,
			VersionedName: versionedName,
			FileType:      fileType,
			FilePath:      filepath.Join(tempDir, "files", versionedName),
			Size:          int64(1000 * i), // Different sizes
			Description:   "Test document version",
			Uploader:      uploader,
			UploadTime:    time.Now().Add(-time.Duration(5-i) * time.Hour), // Older versions first
			Version:       i,
			IsLatest:      i == 5, // Only the last version is latest
		}

		if err := db.InsertFileRecord(record); err != nil {
			t.Fatalf("Failed to insert file record %d: %v", i, err)
		}
	}

	tests := []struct {
		name           string
		fileType       string
		originalName   string
		offset         int
		limit          int
		expectedCount  int
		expectedTotal  int
		expectedFirst  int // Expected version number of first result
	}{
		{
			name:          "First page with limit 2",
			fileType:      fileType,
			originalName:  originalName,
			offset:        0,
			limit:         2,
			expectedCount: 2,
			expectedTotal: 5,
			expectedFirst: 5, // Latest version first (DESC order)
		},
		{
			name:          "Second page with limit 2",
			fileType:      fileType,
			originalName:  originalName,
			offset:        2,
			limit:         2,
			expectedCount: 2,
			expectedTotal: 5,
			expectedFirst: 3,
		},
		{
			name:          "Last page with limit 2",
			fileType:      fileType,
			originalName:  originalName,
			offset:        4,
			limit:         2,
			expectedCount: 1,
			expectedTotal: 5,
			expectedFirst: 1,
		},
		{
			name:          "All versions with large limit",
			fileType:      fileType,
			originalName:  originalName,
			offset:        0,
			limit:         10,
			expectedCount: 5,
			expectedTotal: 5,
			expectedFirst: 5,
		},
		{
			name:          "Default limit when 0",
			fileType:      fileType,
			originalName:  originalName,
			offset:        0,
			limit:         0,
			expectedCount: 5,
			expectedTotal: 5,
			expectedFirst: 5,
		},
		{
			name:          "Negative offset handled",
			fileType:      fileType,
			originalName:  originalName,
			offset:        -1,
			limit:         2,
			expectedCount: 2,
			expectedTotal: 5,
			expectedFirst: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, total, err := db.GetFileVersionsWithPagination(tt.fileType, tt.originalName, tt.offset, tt.limit)
			if err != nil {
				t.Fatalf("GetFileVersionsWithPagination failed: %v", err)
			}

			if len(records) != tt.expectedCount {
				t.Errorf("Expected %d records, got %d", tt.expectedCount, len(records))
			}

			if total != tt.expectedTotal {
				t.Errorf("Expected total %d, got %d", tt.expectedTotal, total)
			}

			if len(records) > 0 && records[0].Version != tt.expectedFirst {
				t.Errorf("Expected first record version %d, got %d", tt.expectedFirst, records[0].Version)
			}

			// Verify all records are for the correct file
			for _, record := range records {
				if record.FileType != tt.fileType {
					t.Errorf("Expected file type %s, got %s", tt.fileType, record.FileType)
				}
				if record.OriginalName != tt.originalName {
					t.Errorf("Expected original name %s, got %s", tt.originalName, record.OriginalName)
				}
				if record.Status != database.FileStatusActive {
					t.Errorf("Expected status active, got %s", record.Status)
				}
			}
		})
	}
}

func TestGetFileVersionsByIDWithPagination(t *testing.T) {
	// Setup test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	if err := database.InitDatabase(dbPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	db := database.GetDatabase()

	// Create test file records with multiple versions
	fileType := "image"
	originalName := "photo.jpg"
	uploader := "photographer"
	var fileIDs []string

	// Insert 3 versions of the same file
	for i := 1; i <= 3; i++ {
		fileID := helpers.GenerateRandomID(16)
		fileIDs = append(fileIDs, fileID)
		versionedName := fmt.Sprintf("photo_v%d.jpg", i)
		
		record := &database.FileRecord{
			ID:            fileID,
			OriginalName:  originalName,
			VersionedName: versionedName,
			FileType:      fileType,
			FilePath:      filepath.Join(tempDir, "files", versionedName),
			Size:          int64(2000 * i),
			Description:   "Test photo version",
			Uploader:      uploader,
			UploadTime:    time.Now().Add(-time.Duration(3-i) * time.Hour),
			Version:       i,
			IsLatest:      i == 3,
		}

		if err := db.InsertFileRecord(record); err != nil {
			t.Fatalf("Failed to insert file record %d: %v", i, err)
		}
	}

	tests := []struct {
		name           string
		fileID         string
		offset         int
		limit          int
		expectedCount  int
		expectedTotal  int
		shouldError    bool
	}{
		{
			name:          "Get versions by first file ID",
			fileID:        fileIDs[0],
			offset:        0,
			limit:         2,
			expectedCount: 2,
			expectedTotal: 3,
			shouldError:   false,
		},
		{
			name:          "Get versions by latest file ID",
			fileID:        fileIDs[2],
			offset:        0,
			limit:         10,
			expectedCount: 3,
			expectedTotal: 3,
			shouldError:   false,
		},
		{
			name:          "Get versions with pagination",
			fileID:        fileIDs[1],
			offset:        1,
			limit:         1,
			expectedCount: 1,
			expectedTotal: 3,
			shouldError:   false,
		},
		{
			name:        "Non-existent file ID",
			fileID:      "non-existent-id",
			offset:      0,
			limit:       10,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, total, err := db.GetFileVersionsByIDWithPagination(tt.fileID, tt.offset, tt.limit)
			
			if tt.shouldError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("GetFileVersionsByIDWithPagination failed: %v", err)
			}

			if len(records) != tt.expectedCount {
				t.Errorf("Expected %d records, got %d", tt.expectedCount, len(records))
			}

			if total != tt.expectedTotal {
				t.Errorf("Expected total %d, got %d", tt.expectedTotal, total)
			}

			// Verify all records are for the same file (same original name and type)
			for _, record := range records {
				if record.FileType != fileType {
					t.Errorf("Expected file type %s, got %s", fileType, record.FileType)
				}
				if record.OriginalName != originalName {
					t.Errorf("Expected original name %s, got %s", originalName, record.OriginalName)
				}
			}
		})
	}
}

func TestGetFileVersionsWithPaginationNonExistentFile(t *testing.T) {
	// Setup test database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	
	if err := database.InitDatabase(dbPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	db := database.GetDatabase()

	// Test with non-existent file
	records, total, err := db.GetFileVersionsWithPagination("nonexistent", "file.txt", 0, 10)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(records) != 0 {
		t.Errorf("Expected 0 records for non-existent file, got %d", len(records))
	}

	if total != 0 {
		t.Errorf("Expected total 0 for non-existent file, got %d", total)
	}
}
