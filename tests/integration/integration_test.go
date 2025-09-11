package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"
)

// TestIntegration_UserRegistrationAndLogin tests complete user registration and login flow
func TestIntegration_UserRegistrationAndLogin(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Test user registration
	registrationData := map[string]string{
		"username": "integrationuser",
		"email":    "integration@example.com",
		"password": "IntegrationPassword123!",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/register", registrationData, nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify registration response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusCreated)

	if response["data"] == nil {
		t.Error("Expected user data in registration response")
	}

	// Test user login
	loginData := map[string]string{
		"username": "integrationuser",
		"password": "IntegrationPassword123!",
	}

	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/login", loginData, nil)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify login response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected login data in response")
	}

	// Extract token from response
	loginDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected login data to be a map")
	}

	token, ok := loginDataMap["token"].(string)
	if !ok || token == "" {
		t.Error("Expected token in login response")
	}

	// Test authenticated request
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + token,
	})
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify authenticated response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected user data in authenticated response")
	}
}

// TestIntegration_FileUploadAndDownload tests complete file upload and download flow
func TestIntegration_FileUploadAndDownload(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Create test user
	user := helpers.CreateTestUser(t, "fileuser", "password123", "admin")
	authUser := &auth.User{
		Username: user.Username,
		Role:     user.Role,
	}

	// Test file upload
	fileContent := "This is a test file for integration testing"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "integration_test.txt", fileContent, map[string]string{
		"description": "Integration test file",
	})
	req = helpers.AddAuthContext(req, authUser)

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
	req = helpers.AddAuthContext(req, authUser)
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
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Create test user
	user := helpers.CreateTestUser(t, "apikeyuser", "password123", "admin")
	authUser := &auth.User{
		Username: user.Username,
		Role:     user.Role,
	}

	// Test API key creation
	apiKeyData := map[string]interface{}{
		"name":        "Integration Test API Key",
		"permissions": []string{"read", "write"},
		"expires_at":  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/admin/api-keys", apiKeyData, nil)
	req = helpers.AddAuthContext(req, authUser)
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
	req = helpers.AddAuthContext(req, authUser)
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
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Create admin user
	adminUser := helpers.CreateTestUser(t, "adminuser", "password123", "admin")
	authAdmin := &auth.User{
		Username: adminUser.Username,
		Role:     adminUser.Role,
	}

	// Create regular user
	regularUser := helpers.CreateTestUser(t, "regularuser", "password123", "viewer")
	_ = regularUser

	// Test user listing
	req := helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/admin/users", nil, nil)
	req = helpers.AddAuthContext(req, authAdmin)
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
	req = helpers.AddAuthContext(req, authAdmin)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify user update response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected user data in update response")
	}

	// Test user suspension
	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/admin/users/regularuser/suspend", nil, nil)
	req = helpers.AddAuthContext(req, authAdmin)
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
	helpers.SetupTestEnvironment(t)

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Create test user
	user := helpers.CreateTestUser(t, "filemanager", "password123", "admin")
	authUser := &auth.User{
		Username: user.Username,
		Role:     user.Role,
	}

	// Test file upload
	fileContent := "This is a test file for file management"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "management_test.txt", fileContent, map[string]string{
		"description": "File management test file",
	})
	req = helpers.AddAuthContext(req, authUser)

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
	req = helpers.AddAuthContext(req, authUser)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file listing response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected files data in listing response")
	}

	// Test file info
	req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/files/"+fileID, nil, nil)
	req = helpers.AddAuthContext(req, authUser)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify file info response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected file data in info response")
	}

	// Test file deletion
	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/files/"+fileID+"/delete", nil, nil)
	req = helpers.AddAuthContext(req, authUser)
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
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Test user registration
	registrationData := map[string]string{
		"username": "authuser",
		"email":    "auth@example.com",
		"password": "AuthPassword123!",
	}

	req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/register", registrationData, nil)
	rr := httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify registration response
	response := helpers.AssertSuccessResponse(t, rr, http.StatusCreated)

	if response["data"] == nil {
		t.Error("Expected user data in registration response")
	}

	// Test user login
	loginData := map[string]string{
		"username": "authuser",
		"password": "AuthPassword123!",
	}

	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/login", loginData, nil)
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify login response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected login data in response")
	}

	// Extract token from response
	loginDataMap, ok := response["data"].(map[string]interface{})
	if !ok {
		t.Fatal("Expected login data to be a map")
	}

	token, ok := loginDataMap["token"].(string)
	if !ok || token == "" {
		t.Error("Expected token in login response")
	}

	// Test password change
	changePasswordData := map[string]string{
		"old_password": "AuthPassword123!",
		"new_password": "NewAuthPassword123!",
	}

	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/change-password", changePasswordData, map[string]string{
		"Authorization": "Bearer " + token,
	})
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify password change response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected password change data in response")
	}

	// Test logout
	req = helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/logout", nil, map[string]string{
		"Authorization": "Bearer " + token,
	})
	rr = httptest.NewRecorder()

	srv.Router.ServeHTTP(rr, req)

	// Verify logout response
	response = helpers.AssertSuccessResponse(t, rr, http.StatusOK)

	if response["data"] == nil {
		t.Error("Expected logout data in response")
	}
}

// TestIntegration_ErrorHandling tests error handling across the system
func TestIntegration_ErrorHandling(t *testing.T) {
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

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
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

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
	config := helpers.SetupTestEnvironment(t)
	_ = config

	// Create server
	srv := server.New()
	if srv == nil {
		t.Fatal("Failed to create server")
	}

	// Create test user
	user := helpers.CreateTestUser(t, "consistencyuser", "password123", "admin")
	authUser := &auth.User{
		Username: user.Username,
		Role:     user.Role,
	}

	// Test file upload
	fileContent := "This is a test file for data consistency"
	req := helpers.CreateMultipartRequest(t, "/api/v1/web/upload", "consistency_test.txt", fileContent, map[string]string{
		"description": "Data consistency test file",
	})
	req = helpers.AddAuthContext(req, authUser)

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
	req = helpers.AddAuthContext(req, authUser)
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
	req = helpers.AddAuthContext(req, authUser)
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
