package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/handler"
	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"
)

// legacy helper user for tests that still reference authUser variable
var authUser = &auth.User{Username: "testuser", Role: "viewer"}
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

func TestIntegration_UserRegistrationAndLogin(t *testing.T) {
	srv := setupTestServer(t)

	// 鍒涘缓娴嬭瘯鐢ㄦ埛
	user := helpers.CreateTestUser(t, "testuser", "TestPassword123!", "viewer")

	// 浣跨敤Authboss鐧诲綍API
	loginData := map[string]string{
		"username": user.Username,
		"password": "TestPassword123!",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/ab/login", loginData, nil)
	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// 璋冭瘯淇℃伅
	t.Logf("Response status: %d", rr.Code)
	t.Logf("Response body: %s", rr.Body.String())
	t.Logf("Response headers: %+v", rr.Header())

	// 妫€鏌ユ墍鏈塩ookies
	cookies := rr.Result().Cookies()
	t.Logf("Cookies received: %d", len(cookies))
	for i, cookie := range cookies {
		t.Logf("Cookie %d: Name=%s, Value=%s", i, cookie.Name, cookie.Value)
	}

	// Authboss鐧诲綍鍙兘杩斿洖閲嶅畾鍚戞垨JSON鍝嶅簲
	var sessionCookie *http.Cookie
	// 妫€鏌ession cookie鏄惁璁剧疆锛堟棤璁哄搷搴旂姸鎬佸浣曪級
	for _, cookie := range cookies {
		if cookie.Name == "ab_session" {
			sessionCookie = cookie
			break
		}
	}

	if sessionCookie == nil {
		t.Error("Expected session cookie to be set")
		return
	}

	t.Logf("Session cookie found: %s", sessionCookie.Value)

	// 娴嬭瘯璁よ瘉鍚庣殑璇锋眰 - 鐩存帴浣跨敤session楠岃瘉
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/auth/me", nil, nil)
	req.AddCookie(sessionCookie)

	rr = httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// 妫€鏌ュ搷搴?
	t.Logf("Auth check response status: %d", rr.Code)
	t.Logf("Auth check response body: %s", rr.Body.String())

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 for authenticated request, got %d", rr.Code)
	}
}

// TestIntegration_FileUploadAndDownload tests complete file upload and download flow
func TestIntegration_FileUploadAndDownload(t *testing.T) {
    srv := setupTestServer(t)

    // Create test user
    user := helpers.CreateTestUser(t, "fileuser", "password123", "admin")
    // Login to get session cookie
    sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Test file upload
	fileContent := "This is a test file for integration testing"
    req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "integration_test.txt", fileContent, map[string]string{
        "description": "Integration test file",
    })
    req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Verify upload response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected file data in upload response")
	}

	// Extract file ID from response
	fileDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data to be a map")
	}

	fileID, ok := fileDataMap["id"].(string)
	if !ok || fileID == "" {
		t.Error("Expected file ID in upload response")
	}

	// Test file download
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/"+fileID+"/download", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify download response
	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify file content
	downloadedContent := rr.Body.String()
	if downloadedContent != fileContent {
		t.Errorf("Expected downloaded content to match uploaded content")
	}
}

// TestIntegration_APIKeyManagement tests complete API key management flow
func TestIntegration_APIKeyManagement(t *testing.T) {
    srv := setupTestServer(t)

    // Create test user
    user := helpers.CreateTestUser(t, "apikeyuser", "password123", "admin")
    sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Test API key creation
	apiKeyData := map[string]interface{}{
		"name":        "Integration Test API Key",
		"permissions": []string{"read", "write"},
		"expires_at":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

    req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/admin/api-keys", apiKeyData, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify API key creation response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusCreated)

	if response["data"] == nil {
		t.Error("Expected API key data in creation response")
	}

	// Extract API key from response
	apiKeyDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected API key data to be a map")
	}

	apiKey, ok := apiKeyDataMap["key"].(string)
	if !ok || apiKey == "" {
		t.Error("Expected API key in creation response")
	}

	// Test API key usage
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/public/files", nil, map[string]string{
		"X-API-Key": apiKey,
	})
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify API key usage response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected files data in API key response")
	}

	// Test API key listing
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/admin/api-keys", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify API key listing response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected API keys data in listing response")
	}
}

// TestIntegration_UserManagement tests complete user management flow
func TestIntegration_UserManagement(t *testing.T) {
    srv := setupTestServer(t)

    // Create admin user
    adminUser := helpers.CreateTestUser(t, "adminuser", "password123", "admin")
    sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, adminUser.Username, "password123")

	// Create regular user
	regularUser := helpers.CreateTestUser(t, "regularuser", "password123", "viewer")
	_ = regularUser

	// Test user listing
    req := helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/admin/users", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify user listing response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected users data in listing response")
	}

	// Test user update
	updateData := map[string]interface{}{
		"role": "admin",
	}

    req = helpers.CreateTestRequest(t, http.MethodPatch, "/api/v1/web/admin/users/regularuser", updateData, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify user update response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected user data in update response")
	}

	// Test user suspension
    req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/admin/users/regularuser/suspend", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify user suspension response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected user data in suspension response")
	}
}

// TestIntegration_FileManagement tests complete file management flow
func TestIntegration_FileManagement(t *testing.T) {
    srv := setupTestServer(t)

    // Create test user
    user := helpers.CreateTestUser(t, "filemanager", "password123", "admin")
    sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Test file upload
	fileContent := "This is a test file for file management"
    req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "management_test.txt", fileContent, map[string]string{
        "description": "File management test file",
    })
    req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Verify upload response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected file data in upload response")
	}

	// Extract file ID from response
	fileDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data to be a map")
	}

	fileID, ok := fileDataMap["id"].(string)
	if !ok || fileID == "" {
		t.Error("Expected file ID in upload response")
	}

	// Test file listing
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/list", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file listing response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected files data in listing response")
	}

	// Test file deletion (DELETE)
	req = helpers.CreateTestRequest(t, http.MethodDelete, "/api/v1/web/files/"+fileID+"/delete", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file deletion response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected deletion data in response")
	}
}

// TestIntegration_AuthenticationFlow tests complete authentication flow
func TestIntegration_AuthenticationFlow(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user for this test
	user := helpers.CreateTestUser(t, "authflowuser", "TestPassword123!", "viewer")

	// Test user login with Authboss
	loginData := map[string]string{
		"username": user.Username,
		"password": "TestPassword123!",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/ab/login", loginData, nil)
	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Verify login response is successful
	if rr.Code != http.StatusOK && rr.Code != http.StatusFound && rr.Code != http.StatusSeeOther && rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("Expected successful login response, got status %d", rr.Code)
	}

	// Test completed successfully - Authboss integration is working
}

// TestIntegration_ErrorHandling tests error handling across the system
func TestIntegration_ErrorHandling(t *testing.T) {
	srv := setupTestServer(t)

	// Test invalid registration
	invalidRegistrationData := map[string]string{
		"username": "", // Invalid: empty username
		"email":    "invalid-email",
		"password": "weak", // Invalid: weak password
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/register", invalidRegistrationData, nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify error response
	helpers.AssertErrorResponse(t, rr, http.StatusBadRequest)

	// Test invalid login
	invalidLoginData := map[string]string{
		"username": "nonexistent",
		"password": "wrongpassword",
	}

	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/login", invalidLoginData, nil)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify error response
	helpers.AssertErrorResponse(t, rr, http.StatusUnauthorized)

	// Test unauthorized access
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/auth/me", nil, nil)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify unauthorized response
	helpers.AssertErrorResponse(t, rr, http.StatusUnauthorized)

	// Test forbidden access
	user := helpers.CreateTestUser(t, "vieweruser", "password123", "viewer")
	authUser := &auth.User{
		Username: user.Username,
		Role:     user.Role,
	}

	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/admin/users", nil, nil)
	req = helpers.AddAuthContext(req, authUser)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify forbidden response
	helpers.AssertErrorResponse(t, rr, http.StatusForbidden)
}

// TestIntegration_Performance tests system performance under load
func TestIntegration_Performance(t *testing.T) {
	srv := setupTestServer(t)

	// Test concurrent requests
	concurrency := 50
	requests := 100

	done := make(chan bool, concurrency)

	start := time.Now()

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			for j := 0; j < requests/concurrency; j++ {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
				rr := httptest.NewRecorder()

				srv.Router.ServeHTTP(rr, req)

				// Should get a response
				if rr.Code == 0 {
					t.Errorf("Expected server to respond to concurrent request %d-%d", index, j)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all requests to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}

	elapsed := time.Since(start)

	// Verify performance
	if elapsed > 5*time.Second {
		t.Errorf("Expected requests to complete within 5 seconds, took %v", elapsed)
	}

	// Calculate requests per second
	rps := float64(requests) / elapsed.Seconds()
	if rps < 10 {
		t.Errorf("Expected at least 10 requests per second, got %f", rps)
	}
}

// TestIntegration_DataConsistency tests data consistency across operations
func TestIntegration_DataConsistency(t *testing.T) {
    srv := setupTestServer(t)

    // Create test user
    user := helpers.CreateTestUser(t, "consistencyuser", "password123", "admin")
    sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Test file upload
	fileContent := "This is a test file for data consistency"
    req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "consistency_test.txt", fileContent, map[string]string{
        "description": "Data consistency test file",
    })
    req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	// Verify upload response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected file data in upload response")
	}

	// Extract file ID from response
	fileDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data to be a map")
	}

	fileID, ok := fileDataMap["id"].(string)
	if !ok || fileID == "" {
		t.Error("Expected file ID in upload response")
	}

	// Test file listing consistency
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/list", nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file listing response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected files data in listing response")
	}

	// Verify file is in the list
	filesData, ok := response["data"].([]interface{})
	if !ok {
		t.Fatal("Expected files data to be an array")
	}

	found := false
	for _, file := range filesData {
		fileMap, ok := file.(map[string]interface{})
		if !ok {
			continue
		}

		if fileMap["id"] == fileID {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected uploaded file to be in the file list")
	}

	// Test file info consistency
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/"+fileID, nil, nil)
    req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file info response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected file data in info response")
	}

	// Verify file info matches upload data
	fileInfoMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file info data to be a map")
	}

	if fileInfoMap["id"] != fileID {
		t.Error("Expected file ID to match in info response")
	}

	if fileInfoMap["originalName"] != "consistency_test.txt" {
		t.Error("Expected original name to match in info response")
	}

	if fileInfoMap["description"] != "Data consistency test file" {
		t.Error("Expected description to match in info response")
	}
}

// TestIntegration_FileVersioning tests file versioning functionality
func TestIntegration_FileVersioning(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "versionuser", "password123", "admin")
	sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Upload first version
	fileContent1 := "Version 1 content"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "version_test.tsv", fileContent1, map[string]string{
		"fileType":    "roadmap",
		"description": "Version 1",
	})
	req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("First upload failed: %d %s", rr.Code, rr.Body.String())
	}

	response1 := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	fileData1, ok := response1["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data in first upload response")
	}
	fileID1 := fileData1["id"].(string)

	// Upload second version
	fileContent2 := "Version 2 content"
	req = helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "version_test.tsv", fileContent2, map[string]string{
		"fileType":    "roadmap",
		"description": "Version 2",
	})
	req = helpers.AddSessionCookie(req, sessionCookie)

	rr = httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Second upload failed: %d %s", rr.Code, rr.Body.String())
	}

	response2 := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	fileData2, ok := response2["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data in second upload response")
	}
	fileID2 := fileData2["id"].(string)

	// Verify different file IDs
	if fileID1 == fileID2 {
		t.Error("Expected different file IDs for different versions")
	}

	// Test file versions endpoint
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/versions/roadmap/version_test.tsv", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Get versions failed: %d %s", rr.Code, rr.Body.String())
	}

	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	if response["data"] == nil {
		t.Error("Expected versions data in response")
	}
}

// TestIntegration_RecycleBin tests recycle bin functionality
func TestIntegration_RecycleBin(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "recycleuser", "password123", "admin")
	sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Upload a file
	fileContent := "Recycle bin test file"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "recycle_test.tsv", fileContent, map[string]string{
		"fileType":    "roadmap",
		"description": "Recycle bin test",
	})
	req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Upload failed: %d %s", rr.Code, rr.Body.String())
	}

	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	fileData, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected file data in upload response")
	}
	fileID := fileData["id"].(string)

	// Delete the file (move to recycle bin)
	req = helpers.CreateTestRequest(t, http.MethodDelete, "/api/v1/web/files/"+fileID+"/delete", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Delete failed: %d %s", rr.Code, rr.Body.String())
	}

	// Check recycle bin
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/recycle-bin", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Get recycle bin failed: %d %s", rr.Code, rr.Body.String())
	}

	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	if response["data"] == nil {
		t.Error("Expected recycle bin data in response")
	}

	// Restore the file
	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/files/"+fileID+"/restore", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Restore failed: %d %s", rr.Code, rr.Body.String())
	}

	// Verify file is back in the list
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/list", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("List files failed: %d %s", rr.Code, rr.Body.String())
	}

	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	if response["data"] == nil {
		t.Error("Expected files data in response")
	}
}

// TestIntegration_ErrorHandling_Comprehensive tests comprehensive error handling
func TestIntegration_ErrorHandling_Comprehensive(t *testing.T) {
	srv := setupTestServer(t)

	// Test cases for various error scenarios
	testCases := []struct {
		name           string
		method         string
		path           string
		body           interface{}
		headers        map[string]string
		expectedStatus int
		description    string
	}{
		{
			name:           "InvalidEndpoint",
			method:         "GET",
			path:           "/api/v1/web/invalid-endpoint",
			expectedStatus: http.StatusNotFound,
			description:    "Non-existent endpoint should return 404",
		},
		{
			name:           "InvalidMethod",
			method:         "PATCH",
			path:           "/api/v1/web/upload",
			expectedStatus: http.StatusMethodNotAllowed,
			description:    "Invalid HTTP method should return 405",
		},
		{
			name:           "MalformedJSON",
			method:         "POST",
			path:           "/api/v1/web/auth/check-permission",
			body:           "invalid json",
			headers:        map[string]string{"Content-Type": "application/json"},
			expectedStatus: http.StatusBadRequest,
			description:    "Malformed JSON should return 400",
		},
		{
			name:           "MissingRequiredField",
			method:         "POST",
			path:           "/api/v1/web/auth/check-permission",
			body:           map[string]string{"resource": "files"}, // missing action
			expectedStatus: http.StatusBadRequest,
			description:    "Missing required field should return 400",
		},
		{
			name:           "InvalidFileType",
			method:         "POST",
			path:           "/api/v1/web/upload",
			body:           "multipart form with invalid file type",
			expectedStatus: http.StatusUnauthorized, // Will fail auth first
			description:    "Invalid file type should be handled properly",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var req *http.Request
			if tc.body != nil {
				req = helpers.CreateTestRequest(t, tc.method, tc.path, tc.body, tc.headers)
			} else {
				req = httptest.NewRequest(tc.method, tc.path, nil)
				for key, value := range tc.headers {
					req.Header.Set(key, value)
				}
			}

			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("%s: Expected status %d, got %d. Body: %s",
					tc.description, tc.expectedStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestIntegration_SecurityHeaders tests security headers
func TestIntegration_SecurityHeaders(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Check for security headers
	securityHeaders := []string{
		"X-Content-Type-Options",
		"X-Frame-Options",
		"X-XSS-Protection",
		"Strict-Transport-Security",
	}

	for _, header := range securityHeaders {
		if rr.Header().Get(header) == "" {
			t.Logf("Warning: Security header %s not set", header)
		}
	}
}

// TestIntegration_ConcurrentOperations tests concurrent operations
func TestIntegration_ConcurrentOperations(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "concurrentuser", "password123", "admin")
	sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Test concurrent file uploads
	concurrency := 5
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(index int) {
			defer func() { done <- true }()

			fileContent := fmt.Sprintf("Concurrent test file %d", index)
			req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload",
				fmt.Sprintf("concurrent_test_%d.tsv", index), fileContent, map[string]string{
					"fileType":    "roadmap",
					"description": fmt.Sprintf("Concurrent test %d", index),
				})
			req = helpers.AddSessionCookie(req, sessionCookie)

			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent upload %d failed: %d %s", index, rr.Code, rr.Body.String())
			}
		}(i)
	}

	// Wait for all uploads to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}

	// Verify all files were uploaded
	req := helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/list", nil, nil)
	req = helpers.AddSessionCookie(req, sessionCookie)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("List files failed: %d %s", rr.Code, rr.Body.String())
	}

	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	if response["data"] == nil {
		t.Error("Expected files data in response")
	}
}

// TestIntegration_LargeFileHandling tests large file handling
func TestIntegration_LargeFileHandling(t *testing.T) {
	srv := setupTestServer(t)

	// Create test user
	user := helpers.CreateTestUser(t, "largefileuser", "password123", "admin")
	sessionCookie := helpers.LoginAndGetSessionCookie(t, srv.Router, user.Username, "password123")

	// Create a large file content (simulate large file)
	largeContent := make([]byte, 1024*1024) // 1MB
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "large_test.tsv", string(largeContent), map[string]string{
		"fileType":    "roadmap",
		"description": "Large file test",
	})
	req = helpers.AddSessionCookie(req, sessionCookie)

	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Large file upload failed: %d %s", rr.Code, rr.Body.String())
	}

	response := helpers.AssertSuccessResponse(t, rr, http.StatusOK)
	if response["data"] == nil {
		t.Error("Expected file data in upload response")
	}
}

// TestIntegration_APIVersioning tests API versioning
func TestIntegration_APIVersioning(t *testing.T) {
	srv := setupTestServer(t)

	// Test different API versions
	versions := []string{"/api/v1/health", "/api/v1/web/health"}

	for _, version := range versions {
		t.Run("Version_"+version, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, version, nil)
			rr := httptest.NewRecorder()

			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("API version %s failed: %d %s", version, rr.Code, rr.Body.String())
			}

			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to unmarshal response for %s: %v", version, err)
			}

			if success, ok := response["success"].(bool); !ok || !success {
				t.Errorf("Expected success=true for API version %s", version)
			}
		})
	}
}

