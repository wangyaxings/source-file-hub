package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	return srv
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
