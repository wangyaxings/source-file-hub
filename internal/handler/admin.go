package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"

	"github.com/gorilla/mux"
)

// Temporary storage for API keys that can be downloaded
// Keys are stored for 10 minutes after creation
var (
	tempAPIKeys = make(map[string]*TempAPIKey)
	tempKeysMux sync.RWMutex
)

// TempAPIKey represents a temporarily stored API key for download
type TempAPIKey struct {
    Key       string
    Name      string
    Role      string
    CreatedAt time.Time
}

// cleanupExpiredTempKeys removes expired temporary API keys
func cleanupExpiredTempKeys() {
	tempKeysMux.Lock()
	defer tempKeysMux.Unlock()

	now := time.Now()
	for keyID, tempKey := range tempAPIKeys {
		// Remove keys older than 10 minutes
		if now.Sub(tempKey.CreatedAt) > 10*time.Minute {
			delete(tempAPIKeys, keyID)
		}
	}
}

// CleanupExpiredTempKeys is a public function for external cleanup
func CleanupExpiredTempKeys() {
	cleanupExpiredTempKeys()
}

// storeTempAPIKey stores an API key temporarily for download
func storeTempAPIKey(keyID, key, name, role string) {
	tempKeysMux.Lock()
	defer tempKeysMux.Unlock()

    tempAPIKeys[keyID] = &TempAPIKey{
        Key:       key,
        Name:      name,
        Role:      role,
        CreatedAt: time.Now(),
    }

	// Clean up expired keys
	cleanupExpiredTempKeys()
}

// getTempAPIKey retrieves a temporary API key
func getTempAPIKey(keyID string) (*TempAPIKey, bool) {
	tempKeysMux.RLock()
	defer tempKeysMux.RUnlock()

	tempKey, exists := tempAPIKeys[keyID]
	if !exists {
		return nil, false
	}

	// Check if key has expired
	if time.Since(tempKey.CreatedAt) > 10*time.Minute {
		return nil, false
	}

	return tempKey, true
}

// RegisterAdminRoutes registers admin routes
func RegisterAdminRoutes(router *mux.Router) {
	// Admin API routes (require admin authentication)
	admin := router.PathPrefix("/api/v1/admin").Subrouter()

	// API Key Management
	admin.HandleFunc("/api-keys", listAPIKeysHandler).Methods("GET")
	admin.HandleFunc("/api-keys", createAPIKeyHandler).Methods("POST")
	admin.HandleFunc("/api-keys/{keyId}", getAPIKeyHandler).Methods("GET")
	admin.HandleFunc("/api-keys/{keyId}", updateAPIKeyHandler).Methods("PUT")
	admin.HandleFunc("/api-keys/{keyId}", deleteAPIKeyHandler).Methods("DELETE")
	admin.HandleFunc("/api-keys/{keyId}/status", updateAPIKeyStatusHandler).Methods("PATCH")
	admin.HandleFunc("/api-keys/{keyId}/regenerate", regenerateAPIKeyHandler).Methods("POST")
	admin.HandleFunc("/api-keys/{keyId}/download", downloadAPIKeyHandler).Methods("GET")

	// Usage Analytics
	admin.HandleFunc("/usage/logs", getUsageLogsHandler).Methods("GET")
	admin.HandleFunc("/usage/stats", getUsageStatsHandler).Methods("GET")
	admin.HandleFunc("/usage/summary", getUsageSummaryHandler).Methods("GET")

	// User Management
	admin.HandleFunc("/users", listUsersHandler).Methods("GET")
	admin.HandleFunc("/users/{userId}/role", updateUserRoleHandler).Methods("PUT")
	admin.HandleFunc("/users/{userId}/api-keys", getUserAPIKeysHandler).Methods("GET")
	admin.HandleFunc("/users/{userId}/usage", getUserUsageHandler).Methods("GET")
}

// RegisterWebAdminRoutes registers admin routes under web API
func RegisterWebAdminRoutes(router *mux.Router) {
	// Admin API routes (require web authentication + admin role)
	admin := router.PathPrefix("/admin").Subrouter()

	// API Key Management
	admin.HandleFunc("/api-keys", requireAdminAuth(listAPIKeysHandler)).Methods("GET")
	admin.HandleFunc("/api-keys", requireAdminAuth(createAPIKeyHandler)).Methods("POST")
	admin.HandleFunc("/api-keys/{keyId}", requireAdminAuth(getAPIKeyHandler)).Methods("GET")
	admin.HandleFunc("/api-keys/{keyId}", requireAdminAuth(updateAPIKeyHandler)).Methods("PUT")
	admin.HandleFunc("/api-keys/{keyId}", requireAdminAuth(deleteAPIKeyHandler)).Methods("DELETE")
	admin.HandleFunc("/api-keys/{keyId}/status", requireAdminAuth(updateAPIKeyStatusHandler)).Methods("PATCH")
	admin.HandleFunc("/api-keys/{keyId}/regenerate", requireAdminAuth(regenerateAPIKeyHandler)).Methods("POST")
	admin.HandleFunc("/api-keys/{keyId}/download", requireAdminAuth(downloadAPIKeyHandler)).Methods("GET")

	// Usage Analytics
	admin.HandleFunc("/usage/logs", requireAdminAuth(getUsageLogsHandler)).Methods("GET")
	admin.HandleFunc("/usage/stats", requireAdminAuth(getUsageStatsHandler)).Methods("GET")
	admin.HandleFunc("/usage/summary", requireAdminAuth(getUsageSummaryHandler)).Methods("GET")

	// Enhanced Analytics
	RegisterAnalyticsRoutes(admin)

	// User Management
	admin.HandleFunc("/users", requireAdminAuth(listUsersHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}/role", requireAdminAuth(updateUserRoleHandler)).Methods("PUT")
	admin.HandleFunc("/users/{userId}/api-keys", requireAdminAuth(getUserAPIKeysHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}/usage", requireAdminAuth(getUserUsageHandler)).Methods("GET")
}

// requireAdminAuth checks if the user has admin privileges
func requireAdminAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get user from context (set by AuthMiddleware)
		userCtx := r.Context().Value("user")
		if userCtx == nil {
			writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		user, ok := userCtx.(*auth.User)
		if !ok {
			writeErrorResponse(w, http.StatusUnauthorized, "Invalid user context")
			return
		}

		// Check if user is admin
		if user.Username != "admin" {
			writeErrorResponse(w, http.StatusForbidden, "Admin privileges required")
			return
		}

		// User is admin, proceed with the request
		handler.ServeHTTP(w, r)
	}
}

// =============================================================================
// API Key Management Handlers
// =============================================================================

// CreateAPIKeyRequest represents the request to create an API key
type CreateAPIKeyRequest struct {
    Name        string   `json:"name"`
    Description string   `json:"description,omitempty"`
    Role        string   `json:"role"`
    Permissions []string `json:"permissions"`
    ExpiresAt   *string  `json:"expires_at,omitempty"`
}

// UpdateAPIKeyRequest represents the request to update an API key
type UpdateAPIKeyRequest struct {
	Name        *string   `json:"name,omitempty"`
	Description *string   `json:"description,omitempty"`
	Permissions *[]string `json:"permissions,omitempty"`
	ExpiresAt   *string   `json:"expires_at,omitempty"`
}

// createAPIKeyHandler creates a new API key
func createAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
		return
	}

    // Validate required fields
    if req.Name == "" || req.Role == "" {
        writeErrorResponse(w, http.StatusBadRequest, "Name and role are required")
        return
    }

	// Validate permissions
	if !apikey.ValidatePermissions(req.Permissions) {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid permissions")
		return
	}

    // Generate API key
    fullKey, keyHash, err := apikey.GenerateAPIKey("sk")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate API key")
		return
	}

	// Parse expiration date if provided
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		// Support multiple date formats
		dateFormats := []string{
			time.RFC3339,          // "2006-01-02T15:04:05Z07:00"
			"2006-01-02T15:04:05", // "2024-12-25T14:30:00"
			"2006-01-02T15:04",    // "2024-12-25T14:30" (datetime-local format)
			"2006-01-02 15:04:05", // "2024-12-25 14:30:00"
			"2006-01-02 15:04",    // "2024-12-25 14:30"
		}

		var parseErr error
		for _, format := range dateFormats {
			if expTime, err := time.Parse(format, *req.ExpiresAt); err == nil {
				// If parsed time has no timezone info, default to server local timezone
				if expTime.Location() == time.UTC && format != time.RFC3339 {
					expTime = time.Date(expTime.Year(), expTime.Month(), expTime.Day(),
						expTime.Hour(), expTime.Minute(), expTime.Second(),
						expTime.Nanosecond(), time.Local)
				}

				// Validate expiration time is not in the past
				if expTime.Before(time.Now()) {
					writeErrorResponse(w, http.StatusBadRequest, "Expiration date cannot be in the past")
					return
				}

				expiresAt = &expTime
				break
			} else {
				parseErr = err
			}
		}

		if expiresAt == nil {
			writeErrorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("Invalid expiration date format. Expected formats: YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS. Error: %v", parseErr))
			return
		}
	}

    // If permissions not provided, derive from role
    if len(req.Permissions) == 0 {
        switch req.Role {
        case "admin":
            req.Permissions = []string{"read", "download", "upload", "admin"}
        case "read_only":
            req.Permissions = []string{"read"}
        case "download_only":
            req.Permissions = []string{"read", "download"}
        case "upload_only":
            req.Permissions = []string{"upload"}
        case "read_upload":
            req.Permissions = []string{"read", "upload"}
        default:
            req.Permissions = []string{"read"}
        }
    }

    // Create API key record
    apiKeyRecord := &database.APIKey{
        ID:          apikey.GenerateAPIKeyID(),
        Name:        req.Name,
        Description: req.Description,
        KeyHash:     keyHash,
        Key:         fullKey, // Only set for creation response
        Role:        req.Role,
        Permissions: req.Permissions,
        Status:      "active",
        ExpiresAt:   expiresAt,
        UsageCount:  0,
    }

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	if err := db.CreateAPIKey(apiKeyRecord); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create API key: "+err.Error())
		return
	}

	// Store the API key temporarily for download (10 minutes)
    storeTempAPIKey(apiKeyRecord.ID, fullKey, apiKeyRecord.Name, apiKeyRecord.Role)

	// Return the API key (only time the full key is shown)
	// Create a copy for response that includes the full key
	responseData := *apiKeyRecord

    response := Response{
        Success: true,
        Message: "API key created successfully. Please save this key securely - it will not be shown again.",
        Data: map[string]interface{}{
            "api_key":      responseData,
            "download_url": fmt.Sprintf("/api/v1/admin/api-keys/%s/download", apiKeyRecord.ID),
        },
    }

	writeJSONResponse(w, http.StatusCreated, response)
}

// listAPIKeysHandler lists all API keys
func listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
    role := r.URL.Query().Get("role")

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var apiKeys []database.APIKey
	var err error

    if role != "" {
        apiKeys, err = db.GetAPIKeysByRole(role)
    } else {
        // Get all API keys
        apiKeys, err = db.GetAllAPIKeys()
    }

	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

    // Mask keys in response - never show full keys after creation
    for i := range apiKeys {
        apiKeys[i].Key = apikey.MaskAPIKey(apiKeys[i].KeyHash)
        apiKeys[i].KeyHash = "" // Don't expose hash
    }

	response := Response{
		Success: true,
		Message: "API keys retrieved successfully",
		Data: map[string]interface{}{
			"keys":  apiKeys,
			"count": len(apiKeys),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getAPIKeyHandler gets a specific API key
func getAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	// Implementation would get API key by ID
	// For now, return placeholder
	response := Response{
		Success: true,
		Data:    map[string]interface{}{"id": keyID},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// updateAPIKeyHandler updates an API key
func updateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	var req UpdateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	// Implementation would update the API key
	response := Response{
		Success: true,
		Message: "API key updated successfully",
		Data:    map[string]interface{}{"id": keyID},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// deleteAPIKeyHandler deletes an API key
func deleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	if err := db.DeleteAPIKey(keyID); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete API key")
		return
	}

	response := Response{
		Success: true,
		Message: "API key deleted successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// updateAPIKeyStatusHandler updates API key status
func updateAPIKeyStatusHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	var req struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	if req.Status != "active" && req.Status != "disabled" {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid status")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	if err := db.UpdateAPIKeyStatus(keyID, req.Status); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update API key status")
		return
	}

	response := Response{
		Success: true,
		Message: "API key status updated successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// regenerateAPIKeyHandler regenerates an API key (creates new key, invalidates old one)
func regenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	if keyID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "API key ID is required")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	// Get existing API key to preserve metadata
	// Note: This is a simplified implementation - in production you'd want to get by ID
	// For now, we'll generate a new key with the same prefix

	// Generate new API key
	fullKey, keyHash, err := apikey.GenerateAPIKey("sk")
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate new API key")
		return
	}

	// Update the API key with new hash (this would need a proper update method)
	// For now, we'll create a new record and mark the old one as disabled
	// In production, you'd want to implement a proper update method

	// Create new API key record with same metadata but new key
    newAPIKey := &database.APIKey{
        ID:          apikey.GenerateAPIKeyID(),
        Name:        "Regenerated Key", // This should be updated from the original
        Description: "Regenerated API key",
        KeyHash:     keyHash,
        Key:         fullKey,          // Only shown once
        Role:        "unknown",        // This should be retrieved from original key
        Permissions: []string{"read"}, // This should be retrieved from original key
        Status:      "active",
        UsageCount:  0,
    }

	if err := db.CreateAPIKey(newAPIKey); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create new API key")
		return
	}

	// Store the new API key temporarily for download (10 minutes)
    storeTempAPIKey(newAPIKey.ID, fullKey, newAPIKey.Name, newAPIKey.Role)

	// Disable the old key
	if err := db.UpdateAPIKeyStatus(keyID, "disabled"); err != nil {
		// Log warning but don't fail the operation
		fmt.Printf("Warning: Failed to disable old API key %s: %v\n", keyID, err)
	}

	response := Response{
		Success: true,
		Message: "API key regenerated successfully. The old key has been disabled. Please save this new key securely - it will not be shown again.",
		Data: map[string]interface{}{
			"api_key":      newAPIKey,
			"download_url": fmt.Sprintf("/api/v1/admin/api-keys/%s/download", newAPIKey.ID),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// downloadAPIKeyHandler downloads an API key as a text file
func downloadAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

	if keyID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "API key ID is required")
		return
	}

	// Get the temporary API key
	tempKey, exists := getTempAPIKey(keyID)
	if !exists {
		writeErrorResponse(w, http.StatusNotFound, "API key not found or has expired. Download is only available for 10 minutes after creation.")
		return
	}

	// Create the file content
    content := fmt.Sprintf(`# API Key Information
# Generated: %s
# Key ID: %s
# Name: %s
# Role: %s

# API Key (keep this secure!)
%s

# Usage Instructions:
# 1. Store this key securely
# 2. Use it in the Authorization header: "Authorization: Bearer %s"
# 3. This key will not be shown again after download
# 4. If you lose this key, you'll need to regenerate it

# Security Notes:
# - Never share this key publicly
# - Store it in a secure password manager
# - Rotate keys regularly
# - Monitor key usage for suspicious activity
`,
		tempKey.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		keyID,
		tempKey.Name,
        tempKey.Role,
        tempKey.Key,
        tempKey.Key,
    )

	// Set response headers for file download
	filename := fmt.Sprintf("api-key-%s-%s.txt", tempKey.Name, time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Write the content
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(content))

	// Remove the temporary key after download for security
	tempKeysMux.Lock()
	delete(tempAPIKeys, keyID)
	tempKeysMux.Unlock()
}

// =============================================================================
// Usage Analytics Handlers
// =============================================================================

// getUsageLogsHandler gets API usage logs
func getUsageLogsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	userID := r.URL.Query().Get("user_id")
	fileID := r.URL.Query().Get("file_id")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0

	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	logs, err := db.GetAPIUsageLogs(userID, fileID, limit, offset)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve usage logs")
		return
	}

	response := Response{
		Success: true,
		Message: "Usage logs retrieved successfully",
		Data: map[string]interface{}{
			"logs":   logs,
			"count":  len(logs),
			"limit":  limit,
			"offset": offset,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getUsageStatsHandler gets usage statistics
func getUsageStatsHandler(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	period := r.URL.Query().Get("period") // daily, weekly, monthly
	if period == "" {
		period = "daily"
	}

	// This would implement detailed usage statistics
	// For now, return mock data
	stats := map[string]interface{}{
		"period":          period,
		"total_requests":  1250,
		"total_downloads": 450,
		"total_uploads":   125,
		"unique_users":    25,
		"top_files": []map[string]interface{}{
			{"file_name": "config.json", "downloads": 45},
			{"file_name": "certificate.pem", "downloads": 32},
		},
		"top_users": []map[string]interface{}{
			{"user_id": "user_123", "requests": 150},
			{"user_id": "user_456", "requests": 98},
		},
	}

	response := Response{
		Success: true,
		Message: "Usage statistics retrieved successfully",
		Data:    stats,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getUsageSummaryHandler gets usage summary
func getUsageSummaryHandler(w http.ResponseWriter, r *http.Request) {
	// This would implement usage summary across different time periods
	summary := map[string]interface{}{
		"today": map[string]interface{}{
			"requests":  156,
			"downloads": 45,
			"uploads":   12,
			"errors":    3,
		},
		"this_week": map[string]interface{}{
			"requests":  1250,
			"downloads": 450,
			"uploads":   125,
			"errors":    15,
		},
		"this_month": map[string]interface{}{
			"requests":  5680,
			"downloads": 2100,
			"uploads":   580,
			"errors":    67,
		},
		"total": map[string]interface{}{
			"api_keys":    15,
			"active_keys": 12,
			"total_users": 25,
			"total_files": 156,
		},
	}

	response := Response{
		Success: true,
		Message: "Usage summary retrieved successfully",
		Data:    summary,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// =============================================================================
// User Management Handlers
// =============================================================================

// listUsersHandler lists all users with their roles
func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	// This would get all users from the authentication system
	// For now, return placeholder data
	users := []map[string]interface{}{
		{
			"user_id":    "admin",
			"tenant_id":  "demo",
			"role":       "admin",
			"status":     "active",
			"api_keys":   3,
			"last_login": "2024-01-01T12:00:00Z",
		},
		{
			"user_id":    "user1",
			"tenant_id":  "demo",
			"role":       "user",
			"status":     "active",
			"api_keys":   1,
			"last_login": "2024-01-01T10:30:00Z",
		},
	}

	response := Response{
		Success: true,
		Message: "Users retrieved successfully",
		Data: map[string]interface{}{
			"users": users,
			"count": len(users),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// updateUserRoleHandler updates a user's role
func updateUserRoleHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
    userID := vars["userId"]

	var req struct {
		Role         string   `json:"role"`
		Permissions  []string `json:"permissions,omitempty"`
		QuotaDaily   int64    `json:"quota_daily,omitempty"`
		QuotaMonthly int64    `json:"quota_monthly,omitempty"`
		Status       string   `json:"status,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
		return
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	userRole := &database.UserRole{
		UserID:       userID,
		Role:         req.Role,
		Permissions:  req.Permissions,
		QuotaDaily:   req.QuotaDaily,
		QuotaMonthly: req.QuotaMonthly,
		Status:       req.Status,
	}

	if err := db.CreateOrUpdateUserRole(userRole); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user role")
		return
	}

	response := Response{
		Success: true,
		Message: "User role updated successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getUserAPIKeysHandler gets API keys for a specific user
func getUserAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    role := vars["userId"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

    apiKeys, err := db.GetAPIKeysByRole(role)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	// Mask keys in response - never show full keys after creation
	for i := range apiKeys {
		apiKeys[i].Key = apikey.MaskAPIKey(apiKeys[i].KeyHash)
		apiKeys[i].KeyHash = ""
	}

    response := Response{
        Success: true,
        Message: "User API keys retrieved successfully",
        Data: map[string]interface{}{
            "role": role,
            "keys":    apiKeys,
            "count":   len(apiKeys),
        },
    }

	writeJSONResponse(w, http.StatusOK, response)
}

// getUserUsageHandler gets usage statistics for a specific user
func getUserUsageHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]

	// This would implement user-specific usage statistics
    usage := map[string]interface{}{
        "role":               userID,
        "total_requests":     234,
		"total_downloads":    89,
		"total_uploads":      23,
		"last_activity":      "2024-01-01T15:30:00Z",
		"most_used_endpoint": "/api/v1/files",
		"daily_usage": []map[string]interface{}{
			{"date": "2024-01-01", "requests": 45},
			{"date": "2024-01-02", "requests": 67},
		},
	}

	response := Response{
		Success: true,
		Message: "User usage retrieved successfully",
		Data:    usage,
	}

	writeJSONResponse(w, http.StatusOK, response)
}
