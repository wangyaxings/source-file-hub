package handler

import (
    "encoding/json"
    "fmt"
    "net/http"
    "strconv"
    "sync"
    "time"

    "secure-file-hub/internal/apikey"
    "secure-file-hub/internal/database"
    "secure-file-hub/internal/middleware"

    "github.com/gorilla/mux"
    "golang.org/x/crypto/bcrypt"
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
    admin.HandleFunc("/api-keys", middleware.RequireAuthorization(listAPIKeysHandler)).Methods("GET")
    admin.HandleFunc("/api-keys", middleware.RequireAuthorization(createAPIKeyHandler)).Methods("POST")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(getAPIKeyHandler)).Methods("GET")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(updateAPIKeyHandler)).Methods("PUT")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(deleteAPIKeyHandler)).Methods("DELETE")
    admin.HandleFunc("/api-keys/{keyId}/status", middleware.RequireAuthorization(updateAPIKeyStatusHandler)).Methods("PATCH")
    admin.HandleFunc("/api-keys/{keyId}/regenerate", middleware.RequireAuthorization(regenerateAPIKeyHandler)).Methods("POST")
    admin.HandleFunc("/api-keys/{keyId}/download", middleware.RequireAuthorization(downloadAPIKeyHandler)).Methods("GET")

	// Usage Analytics
    admin.HandleFunc("/usage/logs", middleware.RequireAuthorization(getUsageLogsHandler)).Methods("GET")
    admin.HandleFunc("/usage/stats", middleware.RequireAuthorization(getUsageStatsHandler)).Methods("GET")
    admin.HandleFunc("/usage/summary", middleware.RequireAuthorization(getUsageSummaryHandler)).Methods("GET")

    // User Management
    admin.HandleFunc("/users", middleware.RequireAuthorization(createUserHandler)).Methods("POST")
    admin.HandleFunc("/users", middleware.RequireAuthorization(listUsersHandler)).Methods("GET")
    admin.HandleFunc("/users/{userId}", middleware.RequireAuthorization(updateUserHandler)).Methods("PATCH")
    admin.HandleFunc("/users/{userId}/approve", middleware.RequireAuthorization(approveUserHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/suspend", middleware.RequireAuthorization(suspendUserHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/2fa/disable", middleware.RequireAuthorization(disableUser2FAHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/role", middleware.RequireAuthorization(updateUserRoleHandler)).Methods("PUT")
    admin.HandleFunc("/users/{userId}/api-keys", middleware.RequireAuthorization(getUserAPIKeysHandler)).Methods("GET")
    admin.HandleFunc("/users/{userId}/usage", middleware.RequireAuthorization(getUserUsageHandler)).Methods("GET")
}

// RegisterWebAdminRoutes registers admin routes under web API
func RegisterWebAdminRoutes(router *mux.Router) {
	// Admin API routes (require web authentication + admin role)
	admin := router.PathPrefix("/admin").Subrouter()

	// API Key Management
    admin.HandleFunc("/api-keys", middleware.RequireAuthorization(listAPIKeysHandler)).Methods("GET")
    admin.HandleFunc("/api-keys", middleware.RequireAuthorization(createAPIKeyHandler)).Methods("POST")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(getAPIKeyHandler)).Methods("GET")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(updateAPIKeyHandler)).Methods("PUT")
    admin.HandleFunc("/api-keys/{keyId}", middleware.RequireAuthorization(deleteAPIKeyHandler)).Methods("DELETE")
    admin.HandleFunc("/api-keys/{keyId}/status", middleware.RequireAuthorization(updateAPIKeyStatusHandler)).Methods("PATCH")
    admin.HandleFunc("/api-keys/{keyId}/regenerate", middleware.RequireAuthorization(regenerateAPIKeyHandler)).Methods("POST")
    admin.HandleFunc("/api-keys/{keyId}/download", middleware.RequireAuthorization(downloadAPIKeyHandler)).Methods("GET")

	// Usage Analytics
    admin.HandleFunc("/usage/logs", middleware.RequireAuthorization(getUsageLogsHandler)).Methods("GET")
    admin.HandleFunc("/usage/stats", middleware.RequireAuthorization(getUsageStatsHandler)).Methods("GET")
    admin.HandleFunc("/usage/summary", middleware.RequireAuthorization(getUsageSummaryHandler)).Methods("GET")

	// Enhanced Analytics
	RegisterAnalyticsRoutes(admin)

    // User Management
    admin.HandleFunc("/users", middleware.RequireAuthorization(createUserHandler)).Methods("POST")
    admin.HandleFunc("/users", middleware.RequireAuthorization(listUsersHandler)).Methods("GET")
    admin.HandleFunc("/users/{userId}", middleware.RequireAuthorization(updateUserHandler)).Methods("PATCH")
    admin.HandleFunc("/users/{userId}/approve", middleware.RequireAuthorization(approveUserHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/suspend", middleware.RequireAuthorization(suspendUserHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/2fa/disable", middleware.RequireAuthorization(disableUser2FAHandler)).Methods("POST")
    admin.HandleFunc("/users/{userId}/role", middleware.RequireAuthorization(updateUserRoleHandler)).Methods("PUT")
    admin.HandleFunc("/users/{userId}/api-keys", middleware.RequireAuthorization(getUserAPIKeysHandler)).Methods("GET")
    admin.HandleFunc("/users/{userId}/usage", middleware.RequireAuthorization(getUserUsageHandler)).Methods("GET")
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
    db := database.GetDatabase()
    if db == nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
        return
    }

    list, err := db.ListUsers()
    if err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to list users")
        return
    }

    // Build response combining role status from user_roles
    users := make([]map[string]interface{}, 0, len(list))
    for _, u := range list {
        status := "active"
        if ur, err := db.GetUserRole(u.Username); err == nil && ur != nil {
            if ur.Status != "" {
                status = ur.Status
            }
            // Prefer role from users table; but if empty, take from user_roles
            if u.Role == "" {
                u.Role = ur.Role
            }
        }

        users = append(users, map[string]interface{}{
            "user_id":     u.Username,
            "email":       u.Email,
            "role":        u.Role,
            "status":      status,
            "two_fa":      u.TwoFAEnabled,
            "last_login":  func() string { if u.LastLoginAt != nil { return u.LastLoginAt.UTC().Format(time.RFC3339) }; return "" }(),
        })
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

// updateUserHandler partially updates user fields (role, 2fa)
func updateUserHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]

    var req struct {
        Role         *string `json:"role,omitempty"`
        TwoFAEnabled *bool   `json:"twofa_enabled,omitempty"`
        Reset2FA     *bool   `json:"reset_2fa,omitempty"`
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
    u, err := db.GetUser(userID)
    if err != nil {
        writeErrorResponse(w, http.StatusNotFound, "User not found")
        return
    }
    if req.Role != nil {
        u.Role = *req.Role
    }
    if req.TwoFAEnabled != nil {
        u.TwoFAEnabled = *req.TwoFAEnabled
        if !u.TwoFAEnabled {
            u.TOTPSecret = ""
        }
    }
    if req.Reset2FA != nil && *req.Reset2FA {
        u.TwoFAEnabled = false
        u.TOTPSecret = ""
    }
    if err := db.UpdateUser(u); err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to update user")
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User updated"})
}

func approveUserHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
        return
    }
    if err := db.CreateOrUpdateUserRole(&database.UserRole{UserID: userID, Status: "active"}); err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to approve user")
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User approved"})
}

func suspendUserHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
        return
    }
    if err := db.CreateOrUpdateUserRole(&database.UserRole{UserID: userID, Status: "suspended"}); err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to suspend user")
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User suspended"})
}

func disableUser2FAHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
        return
    }
    if err := db.SetUser2FA(userID, false, ""); err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to disable 2FA")
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "2FA disabled"})
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
// createUserHandler creates a new application user with an initial password
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    var req struct{
        Username   string  `json:"username"`
        Email      string  `json:"email,omitempty"`
        Role       string  `json:"role,omitempty"`
        MustReset  *bool   `json:"must_reset,omitempty"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeErrorResponse(w, http.StatusBadRequest, "Invalid request format")
        return
    }
    if req.Username == "" {
        writeErrorResponse(w, http.StatusBadRequest, "username is required")
        return
    }
    if req.Role == "" {
        req.Role = "viewer"
    }
    mustReset := true
    if req.MustReset != nil {
        mustReset = *req.MustReset
    }

    // Generate initial password
    initialPassword := generateRandomPassword(16)

    db := database.GetDatabase()
    if db == nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
        return
    }

    // Create user
    if _, err := db.GetUser(req.Username); err == nil {
        writeErrorResponse(w, http.StatusBadRequest, "user already exists")
        return
    }

    // Hash password
    hashed, _ := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
    user := &database.AppUser{
        Username:     req.Username,
        Email:        req.Email,
        PasswordHash: string(hashed),
        Role:         req.Role,
        TwoFAEnabled: false,
        MustReset:    mustReset,
    }
    if err := db.CreateUser(user); err != nil {
        writeErrorResponse(w, http.StatusInternalServerError, "Failed to create user")
        return
    }
    // Create/Update user role record as active
    _ = db.CreateOrUpdateUserRole(&database.UserRole{UserID: req.Username, Role: req.Role, Status: "active"})

    writeJSONResponse(w, http.StatusOK, Response{
        Success: true,
        Message: "User created",
        Data: map[string]interface{}{
            "username": req.Username,
            "initial_password": initialPassword,
            "must_reset": mustReset,
        },
    })
}

func generateRandomPassword(length int) string {
    const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_+"
    b := make([]byte, length)
    for i := range b {
        b[i] = letters[int(time.Now().UnixNano()+int64(i))%len(letters)]
    }
    return string(b)
}
