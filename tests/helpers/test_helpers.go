package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	mathrand "math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"

	"golang.org/x/crypto/bcrypt"
)

// TestConfig holds test configuration
type TestConfig struct {
	TempDir    string
	DBPath     string
	UploadDir  string
	ConfigPath string
}

// SetupTestEnvironment creates a complete test environment
func SetupTestEnvironment(t *testing.T) *TestConfig {
	t.Helper()

	config := &TestConfig{
		TempDir: t.TempDir(),
	}

	config.DBPath = filepath.Join(config.TempDir, "test.db")
	config.UploadDir = filepath.Join(config.TempDir, "downloads")
	config.ConfigPath = filepath.Join(config.TempDir, "config.json")

	// Create upload directory
	if err := os.MkdirAll(config.UploadDir, 0755); err != nil {
		t.Fatalf("Failed to create upload directory: %v", err)
	}

	// Initialize database
	if err := database.InitDatabase(config.DBPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	// Cleanup function
	t.Cleanup(func() {
		if db := database.GetDatabase(); db != nil {
			_ = db.Close()
		}
	})

	return config
}

// CreateTestUser creates a test user with given parameters
func CreateTestUser(t *testing.T, username, password, role string) *database.AppUser {
	t.Helper()

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	user := &database.AppUser{
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         role,
		TwoFAEnabled: false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return user
}

// CreateTestAPIKey creates a test API key
func CreateTestAPIKey(t *testing.T, userID, name string, permissions []string) *database.APIKey {
	t.Helper()

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	keyID := GenerateRandomID(16)
	keyValue := GenerateRandomID(32)

	hashedKey, err := bcrypt.GenerateFromPassword([]byte(keyValue), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Failed to hash API key: %v", err)
	}

	apiKey := &database.APIKey{
		ID:          keyID,
		Name:        name,
		KeyHash:     string(hashedKey),
		Role:        "api_user",
		Permissions: permissions,
		Status:      "active",
		ExpiresAt:   &[]time.Time{time.Now().Add(24 * time.Hour)}[0],
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := db.CreateAPIKey(apiKey); err != nil {
		t.Fatalf("Failed to create test API key: %v", err)
	}

	// Return the API key with the original value for testing
	apiKey.Key = keyValue
	return apiKey
}

// CreateTestFile creates a test file in the upload directory
func CreateTestFile(t *testing.T, config *TestConfig, filename, content string) string {
	t.Helper()

	filePath := filepath.Join(config.UploadDir, filename)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	return filePath
}

// CreateTestFileRecord creates a test file record in the database
func CreateTestFileRecord(t *testing.T, originalName, uploader string) *database.FileRecord {
	t.Helper()

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	fileID := GenerateRandomID(16)
	versionedName := fmt.Sprintf("%s_v1", originalName)

	record := &database.FileRecord{
		ID:            fileID,
		OriginalName:  originalName,
		VersionedName: versionedName,
		FileType:      filepath.Ext(originalName),
		FilePath:      filepath.Join("downloads", versionedName),
		Size:          1024,
		Description:   "Test file",
		Uploader:      uploader,
		UploadTime:    time.Now(),
		Version:       1,
		IsLatest:      true,
		Status:        database.FileStatusActive,
		FileExists:    true,
		Checksum:      "test_checksum",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := db.InsertFileRecord(record); err != nil {
		t.Fatalf("Failed to create test file record: %v", err)
	}

	return record
}

// GenerateRandomID generates a random ID of specified length
func GenerateRandomID(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

// CreateTestRequest creates an HTTP request with optional body and headers
func CreateTestRequest(t *testing.T, method, url string, body interface{}, headers map[string]string) *http.Request {
	t.Helper()

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req := httptest.NewRequest(method, url, reqBody)

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return req
}

// CreateMultipartRequest creates a multipart form request for file uploads
func CreateMultipartRequest(t *testing.T, url string, filename, content string, fields map[string]string) *http.Request {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file
	fileWriter, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	fileWriter.Write([]byte(content))

	// Add additional fields
	for key, value := range fields {
		fieldWriter, err := writer.CreateFormField(key)
		if err != nil {
			t.Fatalf("Failed to create form field: %v", err)
		}
		fieldWriter.Write([]byte(value))
	}

	writer.Close()

	req := httptest.NewRequest("POST", url, &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	return req
}

// AddAuthContext adds authentication context to a request
func AddAuthContext(req *http.Request, user *auth.User) *http.Request {
	ctx := context.WithValue(req.Context(), "user", user)
	return req.WithContext(ctx)
}

// AddAPIKeyContext adds API key context to a request
func AddAPIKeyContext(req *http.Request, apiKey *database.APIKey) *http.Request {
	ctx := context.WithValue(req.Context(), "api_key", apiKey)
	return req.WithContext(ctx)
}

// AssertJSONResponse asserts that the response is valid JSON with expected structure
func AssertJSONResponse(t *testing.T, rr *httptest.ResponseRecorder, expectedStatus int) map[string]interface{} {
	t.Helper()

	if rr.Code != expectedStatus {
		t.Fatalf("Expected status %d, got %d. Body: %s", expectedStatus, rr.Code, rr.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to unmarshal JSON response: %v. Body: %s", err, rr.Body.String())
	}

	return response
}

// AssertErrorResponse asserts that the response contains an error
func AssertErrorResponse(t *testing.T, rr *httptest.ResponseRecorder, expectedStatus int) {
	t.Helper()

	response := AssertJSONResponse(t, rr, expectedStatus)

	if success, ok := response["success"].(bool); ok && success {
		t.Fatalf("Expected error response, but got success=true")
	}

	if _, ok := response["error"]; !ok {
		t.Fatalf("Expected error field in response")
	}
}

// AssertSuccessResponse asserts that the response is successful
func AssertSuccessResponse(t *testing.T, rr *httptest.ResponseRecorder, expectedStatus int) map[string]interface{} {
	t.Helper()

	response := AssertJSONResponse(t, rr, expectedStatus)

	if success, ok := response["success"].(bool); !ok || !success {
		t.Fatalf("Expected success response, but got success=%v", success)
	}

	return response
}

// CleanupTestFiles removes test files
func CleanupTestFiles(t *testing.T, filePaths ...string) {
	t.Helper()

	for _, filePath := range filePaths {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			t.Logf("Failed to remove test file %s: %v", filePath, err)
		}
	}
}

// WaitForCondition waits for a condition to be true with timeout
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Condition not met within timeout: %s", message)
}

// LoginAndGetSessionCookie logs in via Authboss and returns the session cookie
func LoginAndGetSessionCookie(t *testing.T, router http.Handler, username, password string) *http.Cookie {
    t.Helper()
    loginData := map[string]string{"username": username, "password": password}
    body, _ := json.Marshal(loginData)
    req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/login", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK && rr.Code != http.StatusFound && rr.Code != http.StatusTemporaryRedirect {
        t.Fatalf("Login failed: status=%d body=%s", rr.Code, rr.Body.String())
    }
    for _, c := range rr.Result().Cookies() {
        if c.Name == "ab_session" && c.Value != "" {
            return c
        }
    }
    t.Fatalf("No ab_session cookie returned on login; status=%d body=%s", rr.Code, rr.Body.String())
    return nil
}

// AddSessionCookie adds an Authboss session cookie to a request
func AddSessionCookie(req *http.Request, cookie *http.Cookie) *http.Request {
    req.AddCookie(cookie)
    return req
}
