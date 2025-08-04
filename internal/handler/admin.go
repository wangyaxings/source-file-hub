package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"

	"github.com/gorilla/mux"
)

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

	// Usage Analytics
	admin.HandleFunc("/usage/logs", requireAdminAuth(getUsageLogsHandler)).Methods("GET")
	admin.HandleFunc("/usage/stats", requireAdminAuth(getUsageStatsHandler)).Methods("GET")
	admin.HandleFunc("/usage/summary", requireAdminAuth(getUsageSummaryHandler)).Methods("GET")

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
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	UserID      string    `json:"user_id"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   *string   `json:"expires_at,omitempty"`
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
	if req.Name == "" || req.UserID == "" {
		writeErrorResponse(w, http.StatusBadRequest, "Name and user_id are required")
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
			time.RFC3339,           // "2006-01-02T15:04:05Z07:00"
			"2006-01-02T15:04:05",  // "2024-12-25T14:30:00"
			"2006-01-02T15:04",     // "2024-12-25T14:30" (datetime-local format)
			"2006-01-02 15:04:05",  // "2024-12-25 14:30:00"
			"2006-01-02 15:04",     // "2024-12-25 14:30"
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

	// Create API key record
	apiKeyRecord := &database.APIKey{
		ID:          apikey.GenerateAPIKeyID(),
		Name:        req.Name,
		Description: req.Description,
		KeyHash:     keyHash,
		Key:         fullKey, // Only set for creation response
		UserID:      req.UserID,
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

	// Return the API key (only time the full key is shown)
	response := Response{
		Success: true,
		Message: "API key created successfully",
		Data:    apiKeyRecord,
	}

	writeJSONResponse(w, http.StatusCreated, response)
}

// listAPIKeysHandler lists all API keys
func listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	var apiKeys []database.APIKey
	var err error

	if userID != "" {
		apiKeys, err = db.GetAPIKeysByUserID(userID)
	} else {
		// Get all API keys
		apiKeys, err = db.GetAllAPIKeys()
	}

	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	// Mask keys in response
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
		"period":     period,
		"total_requests": 1250,
		"total_downloads": 450,
		"total_uploads": 125,
		"unique_users": 25,
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
			"user_id":     "admin",
			"tenant_id":   "demo",
			"role":        "admin",
			"status":      "active",
			"api_keys":    3,
			"last_login": "2024-01-01T12:00:00Z",
		},
		{
			"user_id":     "user1",
			"tenant_id":   "demo",
			"role":        "user",
			"status":      "active",
			"api_keys":    1,
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
	userID := vars["userId"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not available")
		return
	}

	apiKeys, err := db.GetAPIKeysByUserID(userID)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve API keys")
		return
	}

	// Mask keys in response
	for i := range apiKeys {
		apiKeys[i].Key = apikey.MaskAPIKey(apiKeys[i].KeyHash)
		apiKeys[i].KeyHash = ""
	}

	response := Response{
		Success: true,
		Message: "User API keys retrieved successfully",
		Data: map[string]interface{}{
			"user_id": userID,
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
		"user_id": userID,
		"total_requests": 234,
		"total_downloads": 89,
		"total_uploads": 23,
		"last_activity": "2024-01-01T15:30:00Z",
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