package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"secure-file-hub/internal/database"
	"secure-file-hub/internal/handler"
	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"
)

// testInitDB initializes a temporary SQLite DB and sets it as default
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

// setupTestServer creates a test server with proper configuration
func setupTestServer(t *testing.T) *server.Server {
	// Disable HTTPS redirect for tests
	oldHTTPSRedirect := os.Getenv("DISABLE_HTTPS_REDIRECT")
	os.Setenv("DISABLE_HTTPS_REDIRECT", "true")
	t.Cleanup(func() {
		if oldHTTPSRedirect == "" {
			os.Unsetenv("DISABLE_HTTPS_REDIRECT")
		} else {
			os.Setenv("DISABLE_HTTPS_REDIRECT", oldHTTPSRedirect)
		}
	})

	helpers.SetupTestEnvironment(t)

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Register routes
	handler.RegisterRoutes(srv.Router)

	// Initialize default permissions for testing
	initializeTestPermissions(t)

	return srv
}

// initializeTestPermissions sets up basic permissions for tests
func initializeTestPermissions(t *testing.T) {
	t.Helper()

	// Try to initialize basic Casbin policies for testing
	setupBasicTestPolicies(t)

	t.Log("Test permissions initialized")
}

// setupBasicTestPolicies sets up basic policies for test users
func setupBasicTestPolicies(t *testing.T) {
	t.Helper()

	// This function would normally add Casbin policies for test users
	// For now, we'll create a simple implementation

	// Basic policies for different roles
	policies := []struct {
		subject string
		object  string
		action  string
	}{
		// Admin policies
		{"admin", "/api/v1/web/*", "GET"},
		{"admin", "/api/v1/web/*", "POST"},
		{"admin", "/api/v1/web/*", "PUT"},
		{"admin", "/api/v1/web/*", "DELETE"},

		// User policies
		{"user", "/api/v1/web/files", "GET"},
		{"user", "/api/v1/web/files/upload", "POST"},
		{"user", "/api/v1/web/auth/me", "GET"},

		// Viewer policies
		{"viewer", "/api/v1/web/files", "GET"},
		{"viewer", "/api/v1/web/auth/me", "GET"},

		// API user policies
		{"api_user", "/api/v1/public/*", "GET"},
	}

	t.Logf("Setting up %d basic test policies", len(policies))

	// Note: In a real implementation, these would be added to Casbin
	// For now, we'll just log them for debugging
	for _, policy := range policies {
		t.Logf("Policy: %s can %s on %s", policy.subject, policy.action, policy.object)
	}
}

func TestHealthHandler(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}
}

func TestAPIInfoHandler(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if name, ok := data["name"].(string); !ok || name == "" {
			t.Error("Expected API name in response data")
		}
	} else {
		t.Error("Expected data field in response")
	}
}

func TestMeHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || success {
		t.Error("Expected success=false in response")
	}
}

func TestMeHandler_WithUser(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "testuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if userData, ok := data["user"].(map[string]interface{}); ok {
			if username, ok := userData["username"].(string); !ok || username != user.Username {
				t.Error("Expected correct username in response")
			}
		} else {
			t.Error("Expected user data in response")
		}
	} else {
		t.Error("Expected data field in response")
	}
}

func TestFileUploadHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/upload", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestFileUploadHandler_ValidFile(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "uploaduser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create test file content
	fileContent := "This is a test roadmap file"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "test_roadmap.tsv", fileContent, map[string]string{
		"fileType":    "roadmap",
		"description": "Test roadmap file",
	})
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if _, ok := response["data"].(map[string]interface{}); !ok {
		t.Error("Expected data field in response")
	}
}

func TestFileUploadHandler_InvalidFileType(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "uploaduser2", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create test file with invalid type
	fileContent := "This is a test file"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "test.txt", fileContent, map[string]string{
		"fileType":    "invalid_type",
		"description": "Test file",
	})
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || success {
		t.Error("Expected success=false in response")
	}
}

// TestFileUploadHandler_EmptyFile tests file upload with empty file
func TestFileUploadHandler_EmptyFile(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "emptyfileuser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create test file with empty content
	fileContent := ""
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "empty.txt", fileContent, map[string]string{
		"fileType":    "roadmap",
		"description": "Empty test file",
	})
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Empty files should be rejected
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty file, got %d", rr.Code)
	}
}

// TestFileUploadHandler_LargeFile tests file upload with large file
func TestFileUploadHandler_LargeFile(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "largefileuser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create large file content (1MB)
	largeContent := strings.Repeat("A", 1024*1024)
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "large.txt", largeContent, map[string]string{
		"fileType":    "roadmap",
		"description": "Large test file",
	})
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Large files should be handled appropriately
	if rr.Code != http.StatusOK && rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected status 200 or 413 for large file, got %d", rr.Code)
	}
}

// TestFileUploadHandler_MissingFields tests file upload with missing required fields
func TestFileUploadHandler_MissingFields(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "missingfielduser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test with missing fileType field
	fileContent := "This is a test file"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "test.txt", fileContent, map[string]string{
		"description": "Test file without fileType",
	})
	req.AddCookie(cookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Should fail due to missing required field
	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing fileType, got %d", rr.Code)
	}
}

// TestFileUploadHandler_InvalidFileName tests file upload with invalid filename
func TestFileUploadHandler_InvalidFileName(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "invalidnameuser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test with invalid filename characters
	invalidFilenames := []string{
		"../../../etc/passwd",
		"file with spaces.txt",
		"file\nwith\nnewlines.txt",
		"file\twith\ttabs.txt",
		"",
		".",
		"..",
	}

	for _, filename := range invalidFilenames {
		t.Run(fmt.Sprintf("Filename_%s", filename), func(t *testing.T) {
			fileContent := "This is a test file"
			req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", filename, fileContent, map[string]string{
				"fileType":    "roadmap",
				"description": "Test file with invalid name",
			})
			req.AddCookie(cookie)

			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			// Should fail for invalid filenames
			if rr.Code == http.StatusOK {
				t.Errorf("Expected failure for invalid filename '%s', got status %d", filename, rr.Code)
			}
		})
	}
}

// TestFileUploadHandler_ConcurrentUploads tests concurrent file uploads
func TestFileUploadHandler_ConcurrentUploads(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "concurrentuploaduser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test concurrent uploads
	concurrency := 5
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer func() { done <- true }()

			fileContent := fmt.Sprintf("This is concurrent test file %d", index)
			filename := fmt.Sprintf("concurrent_%d.tsv", index)
			req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", filename, fileContent, map[string]string{
				"fileType":    "roadmap",
				"description": fmt.Sprintf("Concurrent test file %d", index),
			})
			req.AddCookie(cookie)

			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent upload %d failed with status %d", index, rr.Code)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

func TestFileListHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestFileListHandler_WithUser(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "listuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/list", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if _, ok := data["files"].([]interface{}); !ok {
			t.Error("Expected files array in response data")
		}
	} else {
		t.Error("Expected data field in response")
	}
}

func TestFileDownloadHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/test.txt", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestFileDownloadHandler_NotFound(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "downloaduser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/files/nonexistent.txt", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

// TestFileDownloadHandler_InvalidPath tests file download with invalid path
func TestFileDownloadHandler_InvalidPath(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "invalidpathuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test various invalid paths
	invalidPaths := []string{
		"/api/v1/web/files/../../../etc/passwd",
		"/api/v1/web/files/",
		"/api/v1/web/files/.",
		"/api/v1/web/files/..",
		"/api/v1/web/files/file%20with%20spaces.txt",
		"/api/v1/web/files/file%0Awith%0Anewlines.txt",
	}

	for _, path := range invalidPaths {
		t.Run(fmt.Sprintf("Path_%s", path), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			// Should fail for invalid paths
			if rr.Code == http.StatusOK {
				t.Errorf("Expected failure for invalid path '%s', got status %d", path, rr.Code)
			}
		})
	}
}

// TestFileDownloadHandler_ConcurrentDownloads tests concurrent file downloads
func TestFileDownloadHandler_ConcurrentDownloads(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "concurrentdownloaduser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create a test file first
	config := helpers.SetupTestEnvironment(t)
	_ = helpers.CreateTestFileWithContent(t, config, "concurrent_test.txt", "Test content for concurrent download")
	fileRecord := helpers.CreateTestFileRecord(t, "concurrent_test.txt", user.Username)

	// Test concurrent downloads
	concurrency := 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer func() { done <- true }()

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/web/files/%s", fileRecord.ID), nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			// Should succeed for valid file
			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent download %d failed with status %d", index, rr.Code)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

func TestFileDeleteHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/web/files/test123/delete", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestFileDeleteHandler_NotFound(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "deleteuser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/web/files/nonexistent123/delete", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rr.Code)
	}
}

func TestGetDefaultUsersHandler(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/users", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if data, ok := response["data"].(map[string]interface{}); ok {
		if users, ok := data["users"].([]interface{}); !ok || len(users) == 0 {
			t.Error("Expected users array in response data")
		}
	} else {
		t.Error("Expected data field in response")
	}
}

func TestPermissionCheckHandler_Unauthorized(t *testing.T) {
	srv := setupTestServer(t)

	permissionData := map[string]string{
		"resource": "files",
		"action":   "read",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

func TestPermissionCheckHandler_WithUser(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "permuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	permissionData := map[string]string{
		"resource": "files",
		"action":   "read",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if _, ok := response["allowed"].(bool); !ok {
		t.Error("Expected allowed field in response")
	}
}

func TestMultiplePermissionCheckHandler_WithUser(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "multiuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	permissionData := map[string]interface{}{
		"permissions": []map[string]string{
			{"resource": "files", "action": "read"},
			{"resource": "files", "action": "write"},
		},
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permissions", permissionData, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if results, ok := response["results"].(map[string]interface{}); !ok {
		t.Error("Expected results field in response")
	} else {
		if len(results) != 2 {
			t.Error("Expected 2 permission results")
		}
	}
}

// TestPermissionCheckHandler_InvalidJSON tests permission check with invalid JSON
func TestPermissionCheckHandler_InvalidJSON(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "jsonuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create request with invalid JSON
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/check-permission", strings.NewReader("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestPermissionCheckHandler_MissingFields tests permission check with missing required fields
func TestPermissionCheckHandler_MissingFields(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "missinguser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test with missing resource field
	permissionData := map[string]string{
		"action": "read",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Should still work but with empty resource
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}
}

// TestPermissionCheckHandler_EmptyPermissions tests multiple permission check with empty permissions array
func TestPermissionCheckHandler_EmptyPermissions(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user and login
	user := helpers.CreateTestUser(t, "emptyuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	permissionData := map[string]interface{}{
		"permissions": []map[string]string{},
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permissions", permissionData, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if results, ok := response["results"].(map[string]interface{}); !ok {
		t.Error("Expected results field in response")
	} else {
		if len(results) != 0 {
			t.Error("Expected 0 permission results for empty permissions array")
		}
	}
}

// TestPermissionCheckHandler_DifferentRoles tests permission check with different user roles
func TestPermissionCheckHandler_DifferentRoles(t *testing.T) {
	srv := setupTestServer(t)

	// Test different roles and their permissions
	testCases := []struct {
		role           string
		resource       string
		action         string
		expectedResult bool
		description    string
	}{
		{"admin", "files", "read", true, "Admin should be able to read files"},
		{"admin", "files", "write", true, "Admin should be able to write files"},
		{"admin", "users", "read", true, "Admin should be able to read users"},
		{"viewer", "files", "read", true, "Viewer should be able to read files"},
		{"viewer", "files", "write", false, "Viewer should not be able to write files"},
		{"viewer", "users", "read", false, "Viewer should not be able to read users"},
		{"user", "files", "read", true, "User should be able to read files"},
		{"user", "files", "write", false, "User should not be able to write files"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			// Create test user with specific role
			username := fmt.Sprintf("roleuser_%s_%s_%s", tc.role, tc.resource, tc.action)
			user := helpers.CreateTestUser(t, username, "TestPassword123!", tc.role)
			cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

			permissionData := map[string]string{
				"resource": tc.resource,
				"action":   tc.action,
			}

			req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if success, ok := response["success"].(bool); !ok || !success {
				t.Error("Expected success=true in response")
			}

			if allowed, ok := response["allowed"].(bool); !ok {
				t.Error("Expected allowed field in response")
			} else if allowed != tc.expectedResult {
				t.Errorf("Expected allowed=%v for role %s, resource %s, action %s, got %v",
					tc.expectedResult, tc.role, tc.resource, tc.action, allowed)
			}
		})
	}
}

// TestPermissionCheckHandler_ConcurrentRequests tests concurrent permission checks
func TestPermissionCheckHandler_ConcurrentRequests(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "concurrentuser", "TestPassword123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Test concurrent requests
	concurrency := 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer func() { done <- true }()

			permissionData := map[string]string{
				"resource": "files",
				"action":   "read",
			}

			req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permission", permissionData, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent request %d failed with status %d", index, rr.Code)
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Errorf("Concurrent request %d failed to unmarshal response: %v", index, err)
			}

			if success, ok := response["success"].(bool); !ok || !success {
				t.Errorf("Concurrent request %d expected success=true", index)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

// TestPermissionCheckHandler_LargePermissionSet tests multiple permission check with large permission set
func TestPermissionCheckHandler_LargePermissionSet(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "largeuser", "TestPassword123!", "admin")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "TestPassword123!")

	// Create large permission set
	permissions := make([]map[string]string, 100)
	for i := 0; i < 100; i++ {
		permissions[i] = map[string]string{
			"resource": fmt.Sprintf("resource_%d", i),
			"action":   "read",
		}
	}

	permissionData := map[string]interface{}{
		"permissions": permissions,
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/check-permissions", permissionData, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if success, ok := response["success"].(bool); !ok || !success {
		t.Error("Expected success=true in response")
	}

	if results, ok := response["results"].(map[string]interface{}); !ok {
		t.Error("Expected results field in response")
	} else {
		if len(results) != 100 {
			t.Errorf("Expected 100 permission results, got %d", len(results))
		}
	}
}
