package handler

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

    "secure-file-hub/internal/apikey"
    "secure-file-hub/internal/auth"
    "secure-file-hub/internal/authz"
    "secure-file-hub/internal/database"
    "secure-file-hub/internal/application/usecases"
    repo "secure-file-hub/internal/infrastructure/repository/sqlite"
    "secure-file-hub/internal/presentation/http/validation"
	"secure-file-hub/internal/middleware"
	"secure-file-hub/internal/logger"

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
	admin.HandleFunc("/users/{userId}/2fa/enable", middleware.RequireAuthorization(enableUser2FAHandler)).Methods("POST")
	admin.HandleFunc("/users/{userId}/reset-password", middleware.RequireAuthorization(resetUserPasswordHandler)).Methods("POST")
	admin.HandleFunc("/users/{userId}/role", middleware.RequireAuthorization(updateUserRoleHandler)).Methods("PUT")
	admin.HandleFunc("/users/{userId}/api-keys", middleware.RequireAuthorization(getUserAPIKeysHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}/usage", middleware.RequireAuthorization(getUserUsageHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}", middleware.RequireAuthorization(getUserDetailsHandler)).Methods("GET")
	admin.HandleFunc("/audit-logs", middleware.RequireAuthorization(getAdminAuditLogsHandler)).Methods("GET")
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
	admin.HandleFunc("/users/{userId}/2fa/enable", middleware.RequireAuthorization(enableUser2FAHandler)).Methods("POST")
	admin.HandleFunc("/users/{userId}/reset-password", middleware.RequireAuthorization(resetUserPasswordHandler)).Methods("POST")
	admin.HandleFunc("/users/{userId}/role", middleware.RequireAuthorization(updateUserRoleHandler)).Methods("PUT")
	admin.HandleFunc("/users/{userId}/api-keys", middleware.RequireAuthorization(getUserAPIKeysHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}/usage", middleware.RequireAuthorization(getUserUsageHandler)).Methods("GET")
	admin.HandleFunc("/users/{userId}", middleware.RequireAuthorization(getUserDetailsHandler)).Methods("GET")
	admin.HandleFunc("/audit-logs", middleware.RequireAuthorization(getAdminAuditLogsHandler)).Methods("GET")
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
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        return
    }

    // Validate required fields
    if req.Name == "" || req.Role == "" {
        missing := map[string]interface{}{}
        if req.Name == "" { missing["name"] = "required" }
        if req.Role == "" { missing["role"] = "required" }
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Missing required fields", map[string]interface{}{"fields": missing})
        return
    }

    // Validate permissions
    if !apikey.ValidatePermissions(req.Permissions) {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_PERMISSION", "Invalid permissions", map[string]interface{}{"field": "permissions", "allowed": apikey.GetValidPermissions()})
        return
    }

    // Prepare expiration
    
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
                    writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Expiration date cannot be in the past", map[string]interface{}{"field": "expires_at"})
                    return
                }

				expiresAt = &expTime
				break
			} else {
				parseErr = err
			}
		}

        if expiresAt == nil {
            writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR",
                "Invalid expiration date format. Expected formats: YYYY-MM-DDTHH:MM or YYYY-MM-DDTHH:MM:SS.", map[string]interface{}{"field": "expires_at"})
            _ = parseErr
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

    // Use usecase to generate and persist API key
    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    created, err := uc.Create(req.Name, req.Description, req.Role, req.Permissions, expiresAt)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create API key: "+err.Error())
        if l := logger.GetLogger(); l != nil {
            rid := r.Context().Value(middleware.RequestIDKey)
            actor := getActor(r)
            l.ErrorCtx(logger.EventError, "create_api_key_failed", map[string]interface{}{"name": req.Name, "role": req.Role}, "INTERNAL_ERROR", rid, actor)
        }
        return
    }

	// Create Casbin policies for the API key (鏁版嵁搴撻€傞厤鍣ㄨ嚜鍔ㄦ寔涔呭寲)
    if err := authz.CreateAPIKeyPolicies(created.ID, req.Permissions); err != nil {
        // If Casbin policy creation fails, clean up the database record
        if db := database.GetDatabase(); db != nil { _ = db.DeleteAPIKey(created.ID) }
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create API key policies: "+err.Error())
        if l := logger.GetLogger(); l != nil {
            rid := r.Context().Value(middleware.RequestIDKey)
            actor := getActor(r)
            l.ErrorCtx(logger.EventError, "create_api_key_policies_failed", map[string]interface{}{"api_key_id": created.ID}, "INTERNAL_ERROR", rid, actor)
        }
        return
    }

    // Store the API key temporarily for download (10 minutes)
    storeTempAPIKey(created.ID, created.Key, created.Name, created.Role)

    // Return the API key (only time the full key is shown)
    // Create a copy for response that includes the full key
    responseData := database.APIKey{
        ID:          created.ID,
        Name:        created.Name,
        Description: created.Description,
        Key:         created.Key,
        Role:        created.Role,
        Permissions: created.Permissions,
        Status:      created.Status,
        ExpiresAt:   created.ExpiresAt,
        UsageCount:  created.UsageCount,
        LastUsedAt:  created.LastUsedAt,
        CreatedAt:   created.CreatedAt,
        UpdatedAt:   created.UpdatedAt,
    }

	response := Response{
		Success: true,
		Message: "API key created successfully. Please save this key securely - it will not be shown again.",
		Data: map[string]interface{}{
            "api_key":      responseData,
            "download_url": fmt.Sprintf("/api/v1/admin/api-keys/%s/download", responseData.ID),
		},
	}

    writeJSONResponse(w, http.StatusCreated, response)
    if l := logger.GetLogger(); l != nil {
        rid := r.Context().Value(middleware.RequestIDKey)
        actor := getActor(r)
        l.InfoCtx(logger.EventAPIRequest, "api_key_created", map[string]interface{}{"api_key_id": created.ID, "role": created.Role}, "", rid, actor)
    }
}

// listAPIKeysHandler lists all API keys
func listAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
    role := r.URL.Query().Get("role")

    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    items, err := uc.List(role)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve API keys")
        return
    }
    // Map domain entity to database.APIKey for backward-compatible response
    apiKeys := make([]database.APIKey, 0, len(items))
    for _, k := range items {
        apiKeys = append(apiKeys, database.APIKey{
            ID:          k.ID,
            Name:        k.Name,
            Description: k.Description,
            Key:         k.Key, // masked in repo for listings
            Role:        k.Role,
            Permissions: k.Permissions,
            Status:      k.Status,
            ExpiresAt:   k.ExpiresAt,
            UsageCount:  k.UsageCount,
            LastUsedAt:  k.LastUsedAt,
            CreatedAt:   k.CreatedAt,
            UpdatedAt:   k.UpdatedAt,
        })
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
    if l := logger.GetLogger(); l != nil {
        rid := r.Context().Value(middleware.RequestIDKey)
        l.InfoCtx(logger.EventAPIRequest, "list_api_keys_success", map[string]interface{}{"count": len(apiKeys)}, "", rid, getActor(r))
    }
}

// getAPIKeyHandler gets a specific API key
func getAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    keyID := vars["keyId"]
    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    k, err := uc.GetByID(keyID)
    if err != nil || k == nil {
        writeErrorWithCode(w, http.StatusNotFound, "API_KEY_NOT_FOUND", "API key not found")
        return
    }
    response := Response{
        Success: true,
        Message: "API key retrieved successfully",
        Data: map[string]interface{}{
            "api_key": map[string]interface{}{
                "id": k.ID, "name": k.Name, "description": k.Description, "key": k.Key, "role": k.Role,
                "permissions": k.Permissions, "status": k.Status, "expiresAt": k.ExpiresAt,
                "usageCount": k.UsageCount, "lastUsedAt": k.LastUsedAt, "createdAt": k.CreatedAt, "updatedAt": k.UpdatedAt,
            },
        },
    }
    writeJSONResponse(w, http.StatusOK, response)
}

// updateAPIKeyHandler updates an API key
func updateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    keyID := vars["keyId"]

	var req UpdateAPIKeyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        return
    }

    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    // Get current API key to verify it exists
    _, err := uc.GetByID(keyID)
    if err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "API_KEY_NOT_FOUND", "API key not found")
        return
    }

    // Build patch and update through usecase (handles policies if permissions changed)
    var expiresAt *time.Time
    if req.ExpiresAt != nil && *req.ExpiresAt != "" {
        formats := []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04"}
        var parseErr error
        for _, f := range formats {
            if t, err := time.Parse(f, *req.ExpiresAt); err == nil {
                if t.Location() == time.UTC && f != time.RFC3339 { t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.Local) }
                expiresAt = &t
                break
            } else { parseErr = err }
        }
        if expiresAt == nil {
            writeErrorWithCode(w, http.StatusBadRequest, "INVALID_EXPIRES_AT", "Invalid expiration date format")
            _ = parseErr
            return
        }
    }
    patch := usecases.APIKeyUpdatePatch{
        Name:        req.Name,
        Description: req.Description,
        Permissions: req.Permissions,
        ExpiresAt:   expiresAt,
    }
    if _, err := uc.Update(keyID, patch); err != nil {
        if strings.Contains(err.Error(), "invalid permissions") {
            writeErrorWithCode(w, http.StatusBadRequest, "INVALID_PERMISSION", "Invalid permissions")
            return
        }
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update API key")
        return
    }
    // Return updated object
    if updated, err := uc.GetByID(keyID); err == nil && updated != nil {
        apiKey := map[string]interface{}{
            "id": updated.ID,
            "name": updated.Name,
            "description": updated.Description,
            "key": updated.Key,
            "role": updated.Role,
            "permissions": updated.Permissions,
            "status": updated.Status,
            "expiresAt": updated.ExpiresAt,
            "usageCount": updated.UsageCount,
            "lastUsedAt": updated.LastUsedAt,
            "createdAt": updated.CreatedAt,
            "updatedAt": updated.UpdatedAt,
        }
        writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "API key updated successfully", Data: map[string]interface{}{"api_key": apiKey}})
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "API key updated successfully", Data: map[string]interface{}{"id": keyID}})
}

// deleteAPIKeyHandler deletes an API key
func deleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    keyID := vars["keyId"]

    // Remove all Casbin policies for this API key first (鏁版嵁搴撻€傞厤鍣ㄨ嚜鍔ㄦ寔涔呭寲)
    if err := authz.RemoveAllAPIKeyPolicies(keyID); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to remove API key policies: "+err.Error())
        return
    }

    // Then delete from database
    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    if err := uc.Delete(keyID); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete API key")
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
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "update_api_key_status_invalid_request", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

    if req.Status != "active" && req.Status != "disabled" {
        writeErrorWithCode(w, http.StatusBadRequest, "INVALID_STATUS", "Invalid status")
        return
    }

    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    if err := uc.UpdateStatus(keyID, req.Status); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update API key status")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "update_api_key_status_failed", map[string]interface{}{"api_key_id": keyID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// If disabling the API key, remove all Casbin policies (鏁版嵁搴撻€傞厤鍣ㄨ嚜鍔ㄦ寔涔呭寲)
	if req.Status == "disabled" {
		if err := authz.RemoveAllAPIKeyPolicies(keyID); err != nil {
			// Log the error but don't fail the request since the database update succeeded
			fmt.Printf("Warning: Failed to remove Casbin policies for disabled API key %s: %v\n", keyID, err)
		}
	}

    response := Response{
        Success: true,
        Message: "API key status updated successfully",
    }

    writeJSONResponse(w, http.StatusOK, response)
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "update_api_key_status_success", map[string]interface{}{"api_key_id": keyID, "status": req.Status}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// regenerateAPIKeyHandler regenerates an API key (creates new key, invalidates old one)
func regenerateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    keyID := vars["keyId"]

    if keyID == "" {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "API key ID is required", map[string]interface{}{"field": "keyId"})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "regenerate_api_key_missing_id", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

    uc := usecases.NewAPIKeyUseCase(repo.NewAPIKeyRepo())
    // Load old key
    oldKey, err := uc.GetByID(keyID)
    if err != nil || oldKey == nil {
        writeErrorWithCode(w, http.StatusNotFound, "API_KEY_NOT_FOUND", "API key not found")
        return
    }
    // Create new key with same metadata
    created, err := uc.Create(oldKey.Name, "Regenerated API key", oldKey.Role, oldKey.Permissions, oldKey.ExpiresAt)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create new API key")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "regenerate_api_key_create_failed", map[string]interface{}{"api_key_id": keyID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
    // Store the new API key temporarily for download (10 minutes)
    storeTempAPIKey(created.ID, created.Key, created.Name, created.Role)
    // Disable the old key
    if err := uc.UpdateStatus(keyID, "disabled"); err != nil {
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "regenerate_api_key_disable_old_failed", map[string]interface{}{"api_key_id": keyID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
    }
    // Update Casbin policies
    if err := authz.RemoveAllAPIKeyPolicies(keyID); err != nil {
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "regenerate_api_key_remove_policies_failed", map[string]interface{}{"api_key_id": keyID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
    }
    if err := authz.CreateAPIKeyPolicies(created.ID, created.Permissions); err != nil {
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "regenerate_api_key_create_policies_failed", map[string]interface{}{"api_key_id": created.ID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
    }
    response := Response{
        Success: true,
        Message: "API key regenerated successfully. The old key has been disabled. Please save this new key securely - it will not be shown again.",
        Data: map[string]interface{}{
            "api_key":      database.APIKey{ID: created.ID, Name: created.Name, Description: created.Description, Key: created.Key, Role: created.Role, Permissions: created.Permissions, Status: created.Status, ExpiresAt: created.ExpiresAt, UsageCount: created.UsageCount, LastUsedAt: created.LastUsedAt, CreatedAt: created.CreatedAt, UpdatedAt: created.UpdatedAt},
            "download_url": fmt.Sprintf("/api/v1/admin/api-keys/%s/download", created.ID),
        },
    }
    writeJSONResponse(w, http.StatusOK, response)
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "regenerate_api_key_success", map[string]interface{}{"new_api_key_id": created.ID, "old_api_key_id": keyID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// downloadAPIKeyHandler downloads an API key as a text file
func downloadAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["keyId"]

    if keyID == "" {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "API key ID is required", map[string]interface{}{"field": "keyId"})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "download_api_key_missing_id", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Get the temporary API key
	tempKey, exists := getTempAPIKey(keyID)
    if !exists {
        writeErrorWithCodeDetails(w, http.StatusNotFound, "API_KEY_NOT_FOUND", "API key not found or has expired. Download is only available for 10 minutes after creation.", map[string]interface{}{"reason": "expired_or_not_found"})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "download_api_key_expired_or_not_found", map[string]interface{}{"api_key_id": keyID}, "API_KEY_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "download_api_key_success", map[string]interface{}{"api_key_id": keyID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

    logs, err := db.GetAPIUsageLogs(userID, fileID, limit, offset)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve usage logs")
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

	// Query params
	q := r.URL.Query().Get("q")
	statusFilter := r.URL.Query().Get("status") // active|suspended|pending
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page <= 0 {
		page = 1
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}

    list, err := db.ListUsers()
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list users")
        return
    }

	// Build response combining role status from user_roles
	rows := make([]map[string]interface{}, 0, len(list))
	lowerQ := strings.ToLower(strings.TrimSpace(q))
	for _, u := range list {
		status := "active"
		if ur, err := db.GetUserRole(u.Username); err == nil && ur != nil {
			if ur.Status != "" {
				status = ur.Status
			}
			if u.Role == "" {
				u.Role = ur.Role
			}
		}
		// Filter by status
		if statusFilter != "" && status != statusFilter {
			continue
		}
		// Filter by keyword
		if lowerQ != "" {
			if !strings.Contains(strings.ToLower(u.Username), lowerQ) && !strings.Contains(strings.ToLower(u.Email), lowerQ) {
				continue
			}
		}
		rows = append(rows, map[string]interface{}{
			"user_id": u.Username,
			"email":   u.Email,
			"role":    u.Role,
			"status":  status,
			"two_fa":  u.TwoFAEnabled,
			"last_login": func() string {
				if u.LastLoginAt != nil {
					return u.LastLoginAt.UTC().Format(time.RFC3339)
				}
				return ""
			}(),
		})
	}

	total := len(rows)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	paged := rows[start:end]

	response := Response{
		Success: true,
		Message: "Users retrieved successfully",
		Data: map[string]interface{}{
			"users": paged,
			"count": len(paged),
			"total": total,
			"page":  page,
			"limit": limit,
		},
	}

    writeJSONResponse(w, http.StatusOK, response)
    if l := logger.GetLogger(); l != nil {
        rid := r.Context().Value(middleware.RequestIDKey)
        l.InfoCtx(logger.EventAPIRequest, "list_users_success", map[string]interface{}{"count": len(paged), "total": total, "page": page, "limit": limit}, "", rid, getActor(r))
    }
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
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        return
    }
    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }
    u, err := db.GetUser(userID)
    if err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        return
    }
    // Validate role if provided
    if req.Role != nil {
        if !validation.ValidateUserRole(*req.Role) {
            writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid role",
                map[string]interface{}{"field": "role", "allowed": []string{"viewer", "administrator"}})
            return
        }
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update user")
        return
    }
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User updated"})
}

func approveUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }
    if err := db.CreateOrUpdateUserRole(&database.UserRole{UserID: userID, Status: "active"}); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to approve user")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "approve_user_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
	// Audit
	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "approve_user", nil)
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User approved"})
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "user_approved", map[string]interface{}{"user_id": userID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

func suspendUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
	db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }
    if err := db.CreateOrUpdateUserRole(&database.UserRole{UserID: userID, Status: "suspended"}); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to suspend user")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "suspend_user_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "suspend_user", nil)
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "User suspended"})
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "user_suspended", map[string]interface{}{"user_id": userID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

func disableUser2FAHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }
    // Ensure user exists
    if _, err := db.GetUser(userID); err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "disable_2fa_user_not_found", map[string]interface{}{"user_id": userID}, "USER_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
    if err := db.SetUser2FA(userID, false, ""); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable 2FA")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "disable_2fa_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "disable_2fa", nil)
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "2FA disabled"})
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "user_2fa_disabled", map[string]interface{}{"user_id": userID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// enableUser2FAHandler enables 2FA for a user (admin can force enable)
func enableUser2FAHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
	db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

	// Get user to check current status
	user, err := db.GetUser(userID)
    if err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "enable_2fa_user_not_found", map[string]interface{}{"user_id": userID}, "USER_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// If user already has 2FA enabled and has a secret, just return success
	if user.TwoFAEnabled && user.TOTPSecret != "" {
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "2FA already enabled"})
		return
	}

	// Enable 2FA but don't set a secret - user will need to complete setup on first login
    if err := db.SetUser2FA(userID, true, ""); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to enable 2FA")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "enable_2fa_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Log admin action
	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "enable_2fa", nil)

    writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "2FA enabled. User will be prompted to complete setup on next login."})
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "user_2fa_enabled", map[string]interface{}{"user_id": userID}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
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
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        return
    }

    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

    // Validation: user must exist
    if _, err := db.GetUser(userID); err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        return
    }
    // Validation: role
    if req.Role != "" && !validation.ValidateUserRole(req.Role) {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid role",
            map[string]interface{}{"field": "role", "allowed": []string{"viewer", "administrator"}})
        return
    }
    // Validation: permissions
    if req.Permissions != nil && !apikey.ValidatePermissions(req.Permissions) {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_PERMISSION", "Invalid permissions",
            map[string]interface{}{"field": "permissions", "allowed": apikey.GetValidPermissions()})
        return
    }
    // Validation: quotas (allow -1 or >=0)
    if req.QuotaDaily < -1 || req.QuotaMonthly < -1 {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid quota values",
            map[string]interface{}{"quota_daily": "must be -1 or >= 0", "quota_monthly": "must be -1 or >= 0"})
        return
    }
    // Validation: status
    if !validation.ValidateUserStatus(req.Status) {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid status",
            map[string]interface{}{"field": "status", "allowed": []string{"active", "suspended", "disabled", "pending"}})
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
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update user role")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "update_user_role_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
	// Keep users table role in sync
	if u, err := db.GetUser(userID); err == nil && u != nil {
		u.Role = userRole.Role
		_ = db.UpdateUser(u)
	}
	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "update_role", map[string]interface{}{
		"role":          userRole.Role,
		"permissions":   userRole.Permissions,
		"quota_daily":   userRole.QuotaDaily,
		"quota_monthly": userRole.QuotaMonthly,
		"status":        userRole.Status,
	})

	response := Response{
		Success: true,
		Message: "User role updated successfully",
	}

    writeJSONResponse(w, http.StatusOK, response)
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "user_role_updated", map[string]interface{}{"user_id": userID, "role": userRole.Role}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// getUserAPIKeysHandler gets API keys for a specific user
func getUserAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	role := vars["userId"]

    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

    apiKeys, err := db.GetAPIKeysByRole(role)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve API keys")
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
			"role":  role,
			"keys":  apiKeys,
			"count": len(apiKeys),
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
	var req struct {
		Username string `json:"username"`
		Email    string `json:"email,omitempty"`
		Role     string `json:"role,omitempty"`
		// Note: MustReset removed - authboss handles password reset flow
	}
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request format")
        return
    }
    if req.Username == "" {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "username is required", map[string]interface{}{"field": "username"})
        return
    }
	if req.Role == "" {
		req.Role = "viewer"
	}
	// Note: MustReset logic removed - authboss handles password reset flow

	// Generate initial password
	initialPassword := generateRandomPassword(16)

    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }

	// Create user
    if _, err := db.GetUser(req.Username); err == nil {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "user already exists", map[string]interface{}{"field": "username"})
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
		// Note: MustReset removed - authboss handles password reset flow
	}
    if err := db.CreateUser(user); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create user")
        return
    }
	// Create/Update user role record as active
	_ = db.CreateOrUpdateUserRole(&database.UserRole{UserID: req.Username, Role: req.Role, Status: "active"})
	// Audit
	actor := getActor(r)
	_ = db.LogAdminAction(actor, req.Username, "create_user", map[string]interface{}{
		"role": req.Role,
		// Note: must_reset removed - authboss handles password reset flow
	})

	writeJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Message: "User created",
		Data: map[string]interface{}{
			"username":         req.Username,
			"initial_password": initialPassword,
		},
	})
}

func generateRandomPassword(length int) string {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()_+"
	if length < 12 {
		length = 12
	}
	b := make([]byte, length)
	max := big.NewInt(int64(len(letters)))
	for i := 0; i < length; i++ {
		n, err := crand.Int(crand.Reader, max)
		if err != nil {
			// fallback to time-based if crypto fails (rare)
			b[i] = letters[int(time.Now().UnixNano()+int64(i))%len(letters)]
			continue
		}
		b[i] = letters[n.Int64()]
	}
	return string(b)
}

// getUserDetailsHandler returns a user's role/permissions/quotas/status for editing
func getUserDetailsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        return
    }
    u, err := db.GetUser(userID)
    if err != nil || u == nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        return
    }
	ur, _ := db.GetUserRole(userID)
	payload := map[string]interface{}{
		"user_id": u.Username,
		"email":   u.Email,
		"role":    u.Role,
		"two_fa":  u.TwoFAEnabled,
		"last_login": func() string {
			if u.LastLoginAt != nil {
				return u.LastLoginAt.UTC().Format(time.RFC3339)
			}
			return ""
		}(),
		"status": func() string {
			if ur != nil && ur.Status != "" {
				return ur.Status
			}
			return "active"
		}(),
		"permissions": func() []string {
			if ur != nil {
				return ur.Permissions
			}
			return []string{}
		}(),
		"quota_daily": func() int64 {
			if ur != nil {
				return ur.QuotaDaily
			}
			return -1
		}(),
		"quota_monthly": func() int64 {
			if ur != nil {
				return ur.QuotaMonthly
			}
			return -1
		}(),
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: payload})
}

// getAdminAuditLogsHandler lists admin audit logs with filters
func getAdminAuditLogsHandler(w http.ResponseWriter, r *http.Request) {
    db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "get_admin_audit_logs_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
	q := r.URL.Query()
	actor := q.Get("actor")
	target := q.Get("target")
	action := q.Get("action")
	since := q.Get("since")
	until := q.Get("until")
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if page <= 0 {
		page = 1
	}
	if limit <= 0 || limit > 200 {
		limit = 20
	}

    logs, total, err := db.GetAdminAuditLogs(actor, target, action, since, until, page, limit)
    if err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get audit logs")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "get_admin_audit_logs_failed", map[string]interface{}{"actor": actor}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }
    writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
        "items": logs,
        "count": len(logs),
        "total": total,
        "page":  page,
        "limit": limit,
    }})
    if l := logger.GetLogger(); l != nil { l.InfoCtx(logger.EventAPIRequest, "get_admin_audit_logs_success", map[string]interface{}{"count": len(logs), "total": total, "page": page, "limit": limit}, "", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
}

// resetUserPasswordHandler regenerates a user's password and forces reset on next login
func resetUserPasswordHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["userId"]
    if userID == "" {
        writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "userId is required", map[string]interface{}{"field": "userId"})
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "reset_password_missing_userId", nil, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	db := database.GetDatabase()
    if db == nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not available")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "reset_password_db_unavailable", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Ensure user exists
    if _, err := db.GetUser(userID); err != nil {
        writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
        if l := logger.GetLogger(); l != nil { l.WarnCtx(logger.EventError, "reset_password_user_not_found", map[string]interface{}{"user_id": userID}, "USER_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Generate new password and update hash
	newPassword := generateRandomPassword(16)
	hashed, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
    if err := db.UpdateUserPassword(userID, string(hashed)); err != nil {
        writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update password")
        if l := logger.GetLogger(); l != nil { l.ErrorCtx(logger.EventError, "reset_password_update_failed", map[string]interface{}{"user_id": userID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r)) }
        return
    }

	// Note: Password reset flow is now handled by authboss
	// No need to force password reset flag

	actor := getActor(r)
	_ = db.LogAdminAction(actor, userID, "reset_password", nil)

	writeJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Message: "Password reset. Provide the temporary password to the user.",
		Data: map[string]interface{}{
			"username":           userID,
			"temporary_password": newPassword,
		},
	})
}

// getActor extracts username from request context
func getActor(r *http.Request) string {
	if u := r.Context().Value("user"); u != nil {
		if au, ok := u.(*auth.User); ok && au != nil {
			return au.Username
		}
	}
	return "unknown"
}


