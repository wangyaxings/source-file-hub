package database

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"secure-file-hub/internal/database"
	"secure-file-hub/tests/helpers"
)

func testInitDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "unit.db")
	if err := database.InitDatabase(dbPath); err != nil {
		t.Fatalf("InitDatabase failed: %v", err)
	}
	if database.GetDatabase() != nil {
		t.Cleanup(func() { _ = database.GetDatabase().Close() })
	}
	return dbPath
}

func TestUserRole_CreateGet(t *testing.T) {
	testInitDB(t)
	d := database.GetDatabase()
	if d == nil {
		t.Fatal("db nil")
	}

	// Default fallback when missing
	def, err := d.GetUserRole("alice")
	if err != nil {
		t.Fatalf("GetUserRole default: %v", err)
	}
	if def.Role == "" || def.UserID != "alice" {
		t.Fatalf("unexpected default: %+v", def)
	}

	// Create/Update and read back
	ur := &database.UserRole{UserID: "alice", Role: "viewer", Status: "active"}
	if err := d.CreateOrUpdateUserRole(ur); err != nil {
		t.Fatalf("CreateOrUpdateUserRole: %v", err)
	}
	got, err := d.GetUserRole("alice")
	if err != nil {
		t.Fatalf("GetUserRole: %v", err)
	}
	if got.Role != "viewer" || got.Status != "active" {
		t.Fatalf("mismatch: %+v", got)
	}
}

func TestUser_UpdatePassword(t *testing.T) {
	testInitDB(t)
	d := database.GetDatabase()
	if d == nil {
		t.Fatal("db nil")
	}
	if err := d.CreateUser(&database.AppUser{Username: "alice", PasswordHash: "h", Role: "viewer"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := d.UpdateUserPassword("alice", "newhash"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	u, err := d.GetUser("alice")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if u.PasswordHash != "newhash" {
		t.Fatalf("hash mismatch: %q", u.PasswordHash)
	}
}

// TestUser_CreateAndGet tests user creation and retrieval
func TestUser_CreateAndGet(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config // Use config to ensure proper setup

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Test user creation
	user := &database.AppUser{
		Username:     "testuser",
		Email:        "test@example.com",
		PasswordHash: "hashed_password",
		Role:         "viewer",
		TwoFAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Test user retrieval
	retrievedUser, err := db.GetUser("testuser")
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if retrievedUser.Username != user.Username {
		t.Errorf("Expected username %s, got %s", user.Username, retrievedUser.Username)
	}

	if retrievedUser.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, retrievedUser.Email)
	}

	if retrievedUser.Role != user.Role {
		t.Errorf("Expected role %s, got %s", user.Role, retrievedUser.Role)
	}
}

// TestUser_Update tests user update functionality
func TestUser_Update(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create initial user
	user := &database.AppUser{
		Username:     "updateuser",
		Email:        "old@example.com",
		PasswordHash: "old_hash",
		Role:         "viewer",
		TwoFAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Update user
	user.Email = "new@example.com"
	user.Role = "admin"
	user.TwoFAEnabled = true

	if err := db.UpdateUser(user); err != nil {
		t.Fatalf("Failed to update user: %v", err)
	}

	// Verify update
	updatedUser, err := db.GetUser("updateuser")
	if err != nil {
		t.Fatalf("Failed to get updated user: %v", err)
	}

	if updatedUser.Email != "new@example.com" {
		t.Errorf("Expected email new@example.com, got %s", updatedUser.Email)
	}

	if updatedUser.Role != "admin" {
		t.Errorf("Expected role admin, got %s", updatedUser.Role)
	}

	if !updatedUser.TwoFAEnabled {
		t.Error("Expected TwoFA to be enabled")
	}
}

// TestUserRole_CreateAndGet tests user role creation and retrieval
func TestUserRole_CreateAndGet(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Test role creation
	role := &database.UserRole{
		UserID:       "testuser",
		Role:         "admin",
		Permissions:  []string{"read", "write", "delete"},
		QuotaDaily:   1000,
		QuotaMonthly: 30000,
		Status:       "active",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.CreateOrUpdateUserRole(role); err != nil {
		t.Fatalf("Failed to create user role: %v", err)
	}

	// Test role retrieval
	retrievedRole, err := db.GetUserRole("testuser")
	if err != nil {
		t.Fatalf("Failed to get user role: %v", err)
	}

	if retrievedRole.UserID != role.UserID {
		t.Errorf("Expected user ID %s, got %s", role.UserID, retrievedRole.UserID)
	}

	if retrievedRole.Role != role.Role {
		t.Errorf("Expected role %s, got %s", role.Role, retrievedRole.Role)
	}

	if retrievedRole.Status != role.Status {
		t.Errorf("Expected status %s, got %s", role.Status, retrievedRole.Status)
	}
}

// TestFileRecord_CreateAndGet tests file record creation and retrieval
func TestFileRecord_CreateAndGet(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Test file record creation
	fileRecord := &database.FileRecord{
		ID:            "test_file_123",
		OriginalName:  "test.txt",
		VersionedName: "test_v1.txt",
		FileType:      ".txt",
		FilePath:      "downloads/test_v1.txt",
		Size:          1024,
		Description:   "Test file",
		Uploader:      "testuser",
		UploadTime:    time.Now(),
		Version:       1,
		IsLatest:      true,
		Status:        database.FileStatusActive,
		FileExists:    true,
		Checksum:      "abc123",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.InsertFileRecord(fileRecord); err != nil {
		t.Fatalf("Failed to create file record: %v", err)
	}

	// Test file record retrieval by checking if it exists
	err := db.CheckFileExists("test_file_123")
	if err != nil {
		t.Fatalf("Failed to check file existence: %v", err)
	}
}

// TestFileRecord_ListByUploader tests listing files by uploader
func TestFileRecord_ListByUploader(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create multiple file records
	uploader := "testuser"
	for i := 1; i <= 3; i++ {
		fileRecord := &database.FileRecord{
			ID:            helpers.GenerateRandomID(16),
			OriginalName:  fmt.Sprintf("test%d.txt", i),
			VersionedName: fmt.Sprintf("test%d_v1.txt", i),
			FileType:      ".txt",
			FilePath:      fmt.Sprintf("downloads/test%d_v1.txt", i),
			Size:          1024,
			Description:   fmt.Sprintf("Test file %d", i),
			Uploader:      uploader,
			UploadTime:    time.Now(),
			Version:       1,
			IsLatest:      true,
			Status:        database.FileStatusActive,
			FileExists:    true,
			Checksum:      fmt.Sprintf("checksum%d", i),
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if err := db.InsertFileRecord(fileRecord); err != nil {
			t.Fatalf("Failed to create file record %d: %v", i, err)
		}
	}

	// List all files and verify they exist
	files, err := db.GetAllFiles(false)
	if err != nil {
		t.Fatalf("Failed to get all files: %v", err)
	}

	if len(files) < 3 {
		t.Errorf("Expected at least 3 files, got %d", len(files))
	}

	// Verify uploader matches
	uploaderCount := 0
	for _, file := range files {
		if file.Uploader == uploader {
			uploaderCount++
		}
	}

	if uploaderCount < 3 {
		t.Errorf("Expected at least 3 files from uploader %s, got %d", uploader, uploaderCount)
	}
}

// TestAPIKey_CreateAndGet tests API key creation and retrieval
func TestAPIKey_CreateAndGet(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Test API key creation
	apiKey := &database.APIKey{
		ID:          "test_api_key_123",
		Name:        "Test API Key",
		KeyHash:     "hashed_key_value",
		Role:        "api_user",
		Permissions: []string{"read", "write"},
		Status:      "active",
		ExpiresAt:   &[]time.Time{time.Now().Add(24 * time.Hour)}[0],
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.CreateAPIKey(apiKey); err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Test API key retrieval by hash
	retrievedKey, err := db.GetAPIKeyByHash("hashed_key_value")
	if err != nil {
		t.Fatalf("Failed to get API key: %v", err)
	}

	if retrievedKey.ID != apiKey.ID {
		t.Errorf("Expected ID %s, got %s", apiKey.ID, retrievedKey.ID)
	}

	if retrievedKey.Name != apiKey.Name {
		t.Errorf("Expected name %s, got %s", apiKey.Name, retrievedKey.Name)
	}

	if retrievedKey.Role != apiKey.Role {
		t.Errorf("Expected role %s, got %s", apiKey.Role, retrievedKey.Role)
	}
}

// TestAPIKey_ListByRole tests listing API keys by role
func TestAPIKey_ListByRole(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create multiple API keys for the same role
	role := "api_user"
	for i := 1; i <= 3; i++ {
		apiKey := &database.APIKey{
			ID:          helpers.GenerateRandomID(16),
			Name:        fmt.Sprintf("Test API Key %d", i),
			KeyHash:     fmt.Sprintf("hashed_key_%d", i),
			Role:        role,
			Permissions: []string{"read"},
			Status:      "active",
			ExpiresAt:   &[]time.Time{time.Now().Add(24 * time.Hour)}[0],
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}

		if err := db.CreateAPIKey(apiKey); err != nil {
			t.Fatalf("Failed to create API key %d: %v", i, err)
		}
	}

	// List API keys by role
	keys, err := db.GetAPIKeysByRole(role)
	if err != nil {
		t.Fatalf("Failed to get API keys by role: %v", err)
	}

	if len(keys) < 3 {
		t.Errorf("Expected at least 3 API keys, got %d", len(keys))
	}

	for _, key := range keys {
		if key.Role != role {
			t.Errorf("Expected role %s, got %s", role, key.Role)
		}
	}
}

// TestAPIKey_Deactivate tests API key deactivation
func TestAPIKey_Deactivate(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create API key
	apiKey := &database.APIKey{
		ID:          "deactivate_test_key",
		Name:        "Deactivate Test Key",
		KeyHash:     "hashed_key_value",
		Role:        "api_user",
		Permissions: []string{"read"},
		Status:      "active",
		ExpiresAt:   &[]time.Time{time.Now().Add(24 * time.Hour)}[0],
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.CreateAPIKey(apiKey); err != nil {
		t.Fatalf("Failed to create API key: %v", err)
	}

	// Deactivate API key using the available UpdateAPIKeyStatus method
	if err := db.UpdateAPIKeyStatus("deactivate_test_key", "disabled"); err != nil {
		t.Fatalf("Failed to deactivate API key: %v", err)
	}

	// Verify deactivation by getting the key by hash
	// Note: GetAPIKeyByHash only returns active keys, so we expect an error for disabled keys
	_, getErr := db.GetAPIKeyByHash("hashed_key_value")
	if getErr == nil {
		t.Error("Expected error when getting disabled API key, but got none")
	}
	
	// This is expected behavior - disabled keys should not be returned by GetAPIKeyByHash
	t.Logf("Successfully verified that disabled API key is not returned: %v", getErr)
}
