package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
	"secure-file-hub/internal/database"
	cfgpkg "secure-file-hub/internal/infrastructure/config"
	"secure-file-hub/internal/middleware"

	di "secure-file-hub/internal/infrastructure/di"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

var appContainer *di.Container

const maxUploadBytes = 128 << 20

type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details"`
}

// File-related utility functions moved to file_handlers.go

func RegisterRoutes(router *mux.Router) {

	router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")
	router.HandleFunc("/api/v1/healthz", healthCheckHandler).Methods("GET")

	webAPI := router.PathPrefix("/api/v1/web").Subrouter()

	webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
	webAPI.HandleFunc("/auth/users", handleGetDefaultUsers).Methods("GET")

	webAPI.HandleFunc("/auth/check-permission", middleware.RequireAuthorization(checkPermissionHandler)).Methods("POST")
	webAPI.HandleFunc("/auth/check-permissions", middleware.RequireAuthorization(checkMultiplePermissionsHandler)).Methods("POST")

	webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
	webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	webFileMgmtRouter := webAPI.PathPrefix("").Subrouter()
	webFileMgmtRouter.Use(middleware.APILoggingMiddleware)
	webFileMgmtRouter.HandleFunc("/upload", middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/list", middleware.RequireAuthorization(listFilesHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/versions/{type}/{filename}", middleware.RequireAuthorization(getFileVersionsHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/{id}/delete", middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
	webFileMgmtRouter.HandleFunc("/files/{id}/restore", middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/{id}/purge", middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")

	webAPI.HandleFunc("/versions/{type}/versions.json", middleware.RequireAuthorization(handleGetVersionsList)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/manifest", middleware.RequireAuthorization(handleGetVersionManifest)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/tags", middleware.RequireAuthorization(handleUpdateVersionTags)).Methods("PUT")

	webAPI.HandleFunc("/recycle-bin", middleware.RequireAuthorization(getRecycleBinHandler)).Methods("GET")
	webAPI.HandleFunc("/recycle-bin/clear", middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")

	webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
	webFilesRouter.Use(middleware.APILoggingMiddleware) // Add API logging for file downloads
	webFilesRouter.Use(middleware.Authorize())
	webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	webPackagesRouter := webAPI.PathPrefix("/packages").Subrouter()
	webPackagesRouter.Use(middleware.APILoggingMiddleware)
	webPackagesRouter.HandleFunc("", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiListPackagesHandler(w, r)
	})).Methods("GET")
	webPackagesRouter.HandleFunc("/{id}/remark", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUpdatePackageRemarkHandler(w, r)
	})).Methods("PATCH")

	webAPI.HandleFunc("/packages/upload/assets-zip", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUploadAssetsZipHandler(w, r)
	})).Methods("POST")
	webAPI.HandleFunc("/packages/upload/others-zip", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUploadOthersZipHandler(w, r)
	})).Methods("POST")

	RegisterWebAdminRoutes(webAPI)
	RegisterAPIRoutes(router)

	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// File handler functions moved to file_handlers.go
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	handleFileDownload(w, r)
}

func apiInfoHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://localhost:8443/api/v1"

	// Prefer unified version from configs/app.yaml
	appCfg := cfgpkg.Load()
	appVersion := appCfg.Application.Version
	if appVersion == "" {
		appVersion = "v1.0.0"
	}
	buildTime := os.Getenv("BUILD_TIME")
	gitCommit := os.Getenv("GIT_COMMIT")
	gitTag := os.Getenv("GIT_TAG") // Add git tag support

	response := Response{
		Success: true,
		Message: "FileServer REST API Information",
		Data: map[string]interface{}{
			"name":              "FileServer REST API",
			"version":           appVersion,
			"description":       "A secure file server with user authentication and SSL support",
			"base_url":          baseURL,
			"documentation_url": baseURL + "/docs",
			"build": map[string]interface{}{
				"time":   buildTime,
				"commit": gitCommit,
				"tag":    gitTag,
			},
			"endpoints": map[string]interface{}{
				"api_info":     baseURL,
				"health_check": baseURL + "/health",
				"authentication": map[string]interface{}{
					"login":         baseURL + "/web/auth/ab/login",
					"logout":        baseURL + "/web/auth/ab/logout",
					"current_user":  baseURL + "/web/auth/me",
					"default_users": baseURL + "/web/auth/users",
					"note":          "Web authentication uses Authboss session-based auth",
				},
				"file_downloads": map[string]interface{}{
					"unified_download": baseURL + "/files/{path}",
					"examples": []string{
						baseURL + "/files/configs/config.json",
						baseURL + "/files/certificates/server.crt",
						baseURL + "/files/certificates/server.key",
						baseURL + "/files/certificates/cert_info.json",
						baseURL + "/files/docs/api_guide.txt",
					},
				},
				"logs": map[string]interface{}{
					"access_logs": baseURL + "/logs/access",
					"system_logs": baseURL + "/logs/system",
				},
			},
			"authentication_required": []string{
				"/files/*",
				"/logs/*",
			},
			"features": []string{
				"Authboss Session Authentication",
				"Casbin Authorization",
				"API Key Authentication for Public API",
				"Multi-tenant Support",
				"HTTPS Only",
				"Path Traversal Protection",
				"Structured Logging",
				"SQLite Log Storage",
				"2FA Support via TOTP",
			},
			"supported_file_types": []string{
				"application/json",
				"application/x-x509-ca-cert",
				"application/pkcs8",
				"text/plain",
				"application/octet-stream",
			},
			"rate_limits": map[string]interface{}{
				"requests_per_minute": 100,
				"burst_limit":         10,
			},
			"server_info": map[string]interface{}{
				"timestamp":      time.Now().UTC().Format(time.RFC3339),
				"uptime":         "runtime dependent",
				"ssl_enabled":    true,
				"golang_version": "go1.19+",
			},
			"upload_limits": map[string]interface{}{
				"max_upload_bytes": maxUploadBytes,
			},
		},
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSONResponse(w, http.StatusOK, response)
}

func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "Service is running",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func healthAPIKeyCheckHandler(w http.ResponseWriter, r *http.Request) {
	apiKey := r.URL.Query().Get("api_key")
	if apiKey == "" {

		response := Response{
			Success: false,
			Message: "Service is healthy, but no API key provided",
			Data: map[string]interface{}{
				"healthy":       true,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	if !apikey.ValidateAPIKeyFormat(apiKey) {
		response := Response{
			Success: false,
			Message: "Service is healthy, but API key format is invalid",
			Data: map[string]interface{}{
				"healthy":       true,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	db := database.GetDatabase()
	if db == nil {
		response := Response{
			Success: false,
			Message: "Service is unhealthy - database not available",
			Data: map[string]interface{}{
				"healthy":       false,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusServiceUnavailable, response)
		return
	}

	keyHash := apikey.HashAPIKey(apiKey)
	apiKeyRecord, err := db.GetAPIKeyByHash(keyHash)
	if err != nil {
		response := Response{
			Success: false,
			Message: "Service is healthy, but API key is invalid",
			Data: map[string]interface{}{
				"healthy":       true,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	if apiKeyRecord.Status != "active" {
		response := Response{
			Success: false,
			Message: "Service is healthy, but API key is disabled",
			Data: map[string]interface{}{
				"healthy":       true,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	if apiKeyRecord.ExpiresAt != nil && apiKeyRecord.ExpiresAt.Before(time.Now()) {
		response := Response{
			Success: false,
			Message: "Service is healthy, but API key has expired",
			Data: map[string]interface{}{
				"healthy":       true,
				"api_key_valid": false,
				"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
			},
		}
		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	response := Response{
		Success: true,
		Message: "Service is healthy and API key is valid",
		Data: map[string]interface{}{
			"healthy":       true,
			"api_key_valid": true,
			"timestamp":     fmt.Sprintf("%d", time.Now().Unix()),
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
}

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

func writeErrorWithCode(w http.ResponseWriter, status int, code, message string) {

	details := make(map[string]interface{})
	if rid := w.Header().Get("X-Request-ID"); rid != "" {
		details["request_id"] = rid
	}
	response := Response{
		Success: false,
		Error:   message,
		Code:    code,
		Details: details,
	}
	writeJSONResponse(w, status, response)
}

func writeErrorWithCodeDetails(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	// Only add request_id from header if it doesn't already exist in details
	if rid := w.Header().Get("X-Request-ID"); rid != "" {
		if _, ok := details["request_id"]; !ok {
			details["request_id"] = rid
		}
	}
	response := Response{
		Success: false,
		Error:   message,
		Code:    code,
		Details: details,
	}
	writeJSONResponse(w, status, response)
}

// Authentication handler functions moved to auth_handlers.go
func meHandler(w http.ResponseWriter, r *http.Request) {
	handleMe(w, r)
}

// Authentication handler functions moved to auth_handlers.go
func loadUserFromDatabase(username string) (*auth.User, error) {
	return loadUserFromDatabaseImpl(username)
}

func checkUserStatus(username string) error {
	return checkUserStatusImpl(username)
}

// Authentication handlers moved to auth_handlers.go

// Access logs handler moved to admin_handlers.go

type FileUploadRequest struct {
	FileType    string `form:"fileType" json:"fileType"`
	Description string `form:"description" json:"description"`
}

type FileInfo struct {
	ID           string    `json:"id"`
	FileName     string    `json:"fileName"`
	OriginalName string    `json:"originalName"`
	FileType     string    `json:"fileType"`
	Size         int64     `json:"size"`
	Description  string    `json:"description"`
	UploadTime   time.Time `json:"uploadTime"`
	Version      int       `json:"version"`
	IsLatest     bool      `json:"isLatest"`
	Uploader     string    `json:"uploader"`
	Path         string    `json:"path"`
	VersionID    string    `json:"versionId,omitempty"`
	Checksum     string    `json:"checksum,omitempty"`
}

// File handler functions moved to file_handlers.go
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	handleFileUpload(w, r)
}

// File handler functions moved to file_handlers.go
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	handleListFiles(w, r)
}

// File handler functions moved to file_handlers.go
func getFileVersionsHandler(w http.ResponseWriter, r *http.Request) {
	handleGetFileVersions(w, r)
}

// File handler functions moved to file_handlers.go
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	handleDeleteFile(w, r)
}

// File handler functions moved to file_handlers.go
func restoreFileHandler(w http.ResponseWriter, r *http.Request) {
	handleRestoreFile(w, r)
}

// File handler functions moved to file_handlers.go
func purgeFileHandler(w http.ResponseWriter, r *http.Request) {
	handlePurgeFile(w, r)
}

// Recycle bin handler functions moved to recycle_handlers.go
func getRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	handleGetRecycleBin(w, r)
}

// Recycle bin handler functions moved to recycle_handlers.go
func clearRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	handleClearRecycleBin(w, r)
}

func generateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 12 // Minimum secure length
	}

	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	allChars := lowercase + uppercase + digits + special

	password := make([]byte, length)

	sets := []string{lowercase, uppercase, digits, special}
	for i, set := range sets {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = set[charIndex.Int64()]
	}

	for i := len(sets); i < length; i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = allChars[charIndex.Int64()]
	}

	for i := len(password) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("failed to shuffle password: %v", err)
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password), nil
}

// Version handlers moved to version_handlers.go

func SetContainer(container *di.Container) {
	appContainer = container
}

func RegisterWebAdminRoutes(router *mux.Router) {

	admin := router.PathPrefix("/admin").Subrouter()
	admin.Use(middleware.RequireAdminAuth)

	admin.HandleFunc("/api-keys", adminListAPIKeysHandler).Methods("GET")
	admin.HandleFunc("/api-keys", adminCreateAPIKeyHandler).Methods("POST")
	admin.HandleFunc("/api-keys/{id}", adminUpdateAPIKeyHandler).Methods("PUT")
	admin.HandleFunc("/api-keys/{id}", adminDeleteAPIKeyHandler).Methods("DELETE")
	admin.HandleFunc("/api-keys/{id}/status", adminUpdateAPIKeyStatusHandler).Methods("PATCH")

	admin.HandleFunc("/usage/logs", adminUsageLogsHandler).Methods("GET")

	admin.HandleFunc("/analytics", adminAnalyticsHandler).Methods("GET")
	admin.HandleFunc("/analytics/data", adminAnalyticsHandler).Methods("GET")

	admin.HandleFunc("/users", adminListUsersHandler).Methods("GET")
	admin.HandleFunc("/users/{id}", adminGetUserHandler).Methods("GET")
	admin.HandleFunc("/users", adminCreateUserHandler).Methods("POST")
	admin.HandleFunc("/users/{id}", adminPatchUserHandler).Methods("PATCH")
	admin.HandleFunc("/users/{id}/approve", adminApproveUserHandler).Methods("POST")
	admin.HandleFunc("/users/{id}/suspend", adminSuspendUserHandler).Methods("POST")
	admin.HandleFunc("/users/{id}/2fa/enable", adminEnable2FAHandler).Methods("POST")
	admin.HandleFunc("/users/{id}/2fa/disable", adminDisable2FAHandler).Methods("POST")
	admin.HandleFunc("/users/{id}/reset-password", adminResetPasswordHandler).Methods("POST")

	log.Printf("Admin routes registered")
}

func adminListAPIKeysHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	keys, err := db.GetAllAPIKeys()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"keys":  keys,
		"count": len(keys),
	}})
}

func adminCreateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
		ExpiresAt   string   `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}
	if req.Name == "" || req.Role == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "name and role are required")
		return
	}
	if !apikey.ValidatePermissions(req.Permissions) {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid permissions")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	existingKeys, err := db.GetAllAPIKeys()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check existing API keys")
		return
	}
	for _, key := range existingKeys {
		if key.Name == req.Name {
			writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "API key name already exists")
			return
		}
	}

	fullKey, keyHash, err := apikey.GenerateAPIKey("sk")
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate API key")
		return
	}

	var expiresAtPtr *time.Time
	if strings.TrimSpace(req.ExpiresAt) != "" {
		if t, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil {
			expiresAtPtr = &t
		}
	}

	rec := &database.APIKey{
		ID:          apikey.GenerateAPIKeyID(),
		Name:        req.Name,
		Description: req.Description,
		KeyHash:     keyHash,
		Role:        req.Role,
		Permissions: req.Permissions,
		Status:      "active",
		ExpiresAt:   expiresAtPtr,
		UsageCount:  0,
	}
	if err := db.CreateAPIKey(rec); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save API key")
		return
	}

	_ = authz.CreateAPIKeyPolicies(rec.ID, rec.Permissions)

	rec.Key = fullKey
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"api_key":      rec,
		"download_url": "",
	}})
}

func adminUpdateAPIKeyStatusHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || id == "" || req.Status == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id and status required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	if err := db.UpdateAPIKeyStatus(id, req.Status); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "status updated"})
}

func adminUpdateAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	var req struct {
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Permissions *[]string `json:"permissions"`
		ExpiresAt   *string   `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	var expiresAt *time.Time
	clearExpiry := false
	if req.ExpiresAt != nil {
		if strings.TrimSpace(*req.ExpiresAt) == "" {
			clearExpiry = true
		} else if t, err := time.Parse(time.RFC3339, *req.ExpiresAt); err == nil {
			expiresAt = &t
		}
	}

	if req.Permissions != nil {
		if !apikey.ValidatePermissions(*req.Permissions) {
			writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid permissions")
			return
		}
	}

	if req.Name != nil {
		existingKeys, err := db.GetAllAPIKeys()
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check existing API keys")
			return
		}
		for _, key := range existingKeys {
			if key.ID != id && key.Name == *req.Name {
				writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "API key name already exists")
				return
			}
		}
	}

	if err := db.UpdateAPIKeyFields(id, req.Name, req.Description, req.Permissions, expiresAt, clearExpiry); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if req.Permissions != nil {
		_ = authz.RemoveAllAPIKeyPolicies(id)
		_ = authz.CreateAPIKeyPolicies(id, *req.Permissions)
	}

	rec, err := db.GetAPIKeyByID(id)
	if err != nil {
		writeJSONResponse(w, http.StatusOK, Response{Success: true})
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"api_key": rec}})
}

func adminDeleteAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	_ = authz.RemoveAllAPIKeyPolicies(id)
	if err := db.DeleteAPIKey(id); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "deleted"})
}

func adminUsageLogsHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}

	filters := database.APIUsageLogFilters{
		UserID:   q.Get("userId"),
		FileID:   q.Get("fileId"),
		APIKey:   q.Get("apiKey"),
		Method:   q.Get("method"),
		Endpoint: q.Get("endpoint"),
		TimeFrom: q.Get("timeFrom"),
		TimeTo:   q.Get("timeTo"),
	}

	if filters.APIKey != "" || filters.Method != "" || filters.Endpoint != "" || filters.TimeFrom != "" || filters.TimeTo != "" || filters.UserID != "" || filters.FileID != "" {
		logs, err := db.GetAPIUsageLogsFiltered(filters, limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		totalCount, err := db.GetAPIUsageLogsCountFiltered(filters)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	} else {

		logs, err := db.GetAPIUsageLogs("", "", limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		totalCount, err := db.GetAPIUsageLogsCount("", "")
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	}
}

func adminAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	q := r.URL.Query()

	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)
	end := now

	if s := strings.TrimSpace(firstNonEmpty(q.Get("start"), q.Get("startDate"))); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			start = t
		}
	}
	if e := strings.TrimSpace(firstNonEmpty(q.Get("end"), q.Get("endDate"))); e != "" {
		if t, err := time.Parse(time.RFC3339, e); err == nil {
			end = t
		}
	}

	if tr := strings.TrimSpace(q.Get("timeRange")); tr != "" {
		switch strings.ToLower(tr) {
		case "24h":
			start = now.Add(-24 * time.Hour)
		case "7d":
			start = now.Add(-7 * 24 * time.Hour)
		case "30d":
			start = now.Add(-30 * 24 * time.Hour)
		}
	}

	apiKeyFilter := strings.TrimSpace(firstNonEmpty(q.Get("api_key_id"), q.Get("apiKey")))
	userFilter := strings.TrimSpace(firstNonEmpty(q.Get("user_id"), q.Get("user")))
	data, err := db.GetAnalyticsData(database.AnalyticsTimeRange{Start: start, End: end}, apiKeyFilter, userFilter)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func adminGetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		return
	}

	user, err := db.GetUser(userID)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "USER_NOT_FOUND", "User not found")
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get user: "+err.Error())
		}
		return
	}

	userRole, err := db.GetUserRole(userID)
	if err != nil {

		userRole = &database.UserRole{
			UserID: userID,
			Role:   "viewer",
			Status: "active",
		}
	}

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"id":            user.Username,
			"username":      user.Username,
			"email":         user.Email,
			"role":          userRole.Role,
			"status":        userRole.Status,
			"twofa_enabled": user.TwoFAEnabled,
			"last_login":    user.LastLoginAt,
			"created_at":    user.CreatedAt,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

func adminListUsersHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	users, err := db.ListUsers()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	q := strings.TrimSpace(r.URL.Query().Get("q"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}

	type row struct {
		UserID    string `json:"user_id"`
		Email     string `json:"email,omitempty"`
		Role      string `json:"role"`
		Status    string `json:"status"`
		TwoFA     bool   `json:"two_fa"`
		LastLogin string `json:"last_login,omitempty"`
	}

	list := make([]row, 0, len(users))
	for _, u := range users {
		ur, _ := db.GetUserRole(u.Username)
		r := row{UserID: u.Username, Email: u.Email, Role: u.Role, Status: "active", TwoFA: u.TwoFAEnabled}
		if ur != nil && ur.Status != "" {
			r.Status = ur.Status
		}
		if u.LastLoginAt != nil {
			r.LastLogin = u.LastLoginAt.Format(time.RFC3339)
		}
		if q != "" && !(strings.Contains(strings.ToLower(r.UserID), strings.ToLower(q)) || strings.Contains(strings.ToLower(r.Email), strings.ToLower(q))) {
			continue
		}
		if statusFilter != "" && statusFilter != "all" && r.Status != statusFilter {
			continue
		}
		list = append(list, r)
	}
	total := len(list)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	paged := list[start:end]

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"users": paged,
		"count": total,
		"total": total,
		"page":  page,
		"limit": limit,
	}})
}

func adminCreateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username  string `json:"username"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		MustReset bool   `json:"must_reset"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "username required")
		return
	}
	if req.Role == "" {
		req.Role = "viewer"
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	if _, err := db.GetUser(req.Username); err == nil {
		writeErrorWithCode(w, http.StatusBadRequest, "CONFLICT", "user already exists")
		return
	}

	tmp, _ := apikey.GenerateRandomString(16)

	hashed, _ := bcrypt.GenerateFromPassword([]byte(tmp), bcrypt.DefaultCost)
	if err := db.CreateUser(&database.AppUser{Username: req.Username, Email: req.Email, PasswordHash: string(hashed), Role: req.Role}); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	_ = db.CreateOrUpdateUserRole(&database.UserRole{UserID: req.Username, Role: req.Role, Status: "pending", QuotaDaily: -1, QuotaMonthly: -1})
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"initial_password": tmp,
	}})
}

func adminApproveUserHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	ur, _ := db.GetUserRole(username)
	if ur == nil {
		ur = &database.UserRole{UserID: username, Role: "viewer"}
	}
	ur.Status = "active"
	if err := db.CreateOrUpdateUserRole(ur); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func adminSuspendUserHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	ur, _ := db.GetUserRole(username)
	if ur == nil {
		ur = &database.UserRole{UserID: username, Role: "viewer"}
	}
	ur.Status = "suspended"
	if err := db.CreateOrUpdateUserRole(ur); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func adminEnable2FAHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	if err := db.SetUser2FA(username, true, ""); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func adminDisable2FAHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	if err := db.SetUser2FA(username, false, ""); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

func adminResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	if username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	tmp, _ := apikey.GenerateRandomString(16)
	if err := auth.SetPassword(username, tmp); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"username": username, "temporary_password": tmp}})
}

func adminPatchUserHandler(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["id"]
	if username == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	var req struct {
		Role         *string `json:"role"`
		TwoFAEnabled *bool   `json:"twofa_enabled"`
		Reset2FA     *bool   `json:"reset_2fa"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	if req.Role != nil {
		appUser, err := db.GetUser(username)
		if err == nil {
			appUser.Role = *req.Role
			_ = db.UpdateUser(appUser)
		}
		ur, _ := db.GetUserRole(username)
		if ur == nil {
			ur = &database.UserRole{UserID: username}
		}
		ur.Role = *req.Role
		_ = db.CreateOrUpdateUserRole(ur)
	}
	if req.TwoFAEnabled != nil {
		_ = db.SetUser2FA(username, *req.TwoFAEnabled, "")
	}
	if req.Reset2FA != nil && *req.Reset2FA {
		_ = db.SetUser2FA(username, false, "")
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true})
}

// Authentication handler functions moved to auth_handlers.go
func checkPermissionHandler(w http.ResponseWriter, r *http.Request) {
	handleCheckPermission(w, r)
}

func checkMultiplePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	handleCheckMultiplePermissions(w, r)
}

// Package handler functions moved to package_handlers.go
func apiListPackagesHandler(w http.ResponseWriter, r *http.Request) {
	handleListPackages(w, r)
}

func apiUpdatePackageRemarkHandler(w http.ResponseWriter, r *http.Request) {
	handleUpdatePackageRemark(w, r)
}

func RegisterAPIRoutes(router *mux.Router) {

	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	apiRouter.HandleFunc("/health", healthCheckHandler).Methods("GET")
	apiRouter.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	apiRouter.HandleFunc("/status-check", healthAPIKeyCheckHandler).Methods("GET")

	publicAPI := apiRouter.PathPrefix("/public").Subrouter()

	publicAPI.Handle("/files/upload", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(uploadFileHandler)))).Methods("POST")
	publicAPI.Handle("/files", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(listFilesHandler)))).Methods("GET")
	publicAPI.Handle("/files/{id}/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiDownloadFileByIDHandler)))).Methods("GET")
	publicAPI.Handle("/files/{id}", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(deleteFileHandler)))).Methods("DELETE")
	publicAPI.Handle("/files/{id}/restore", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(restoreFileHandler)))).Methods("POST")

	publicAPI.Handle("/versions/{type}/latest", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetLatestVersionInfoHandler)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetLatestVersionInfoHandler)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiDownloadLatestByTypeHandler)))).Methods("GET")

	log.Printf("Registering version status route for roadmap and recommendation")
	publicAPI.Handle("/versions/{type}/status", middleware.APILoggingMiddleware(http.HandlerFunc(apiGetVersionTypeStatusHandler))).Methods("GET")

	publicAPI.Handle("/versions/{type}/{ver}/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetVersionInfoHandler)))).Methods("GET")

	publicAPI.Handle("/packages", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiListPackagesHandler)))).Methods("GET")
	publicAPI.Handle("/packages/{id}/remark", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUpdatePackageRemarkHandler)))).Methods("PATCH")

	publicAPI.Handle("/upload/assets-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUploadAssetsZipHandler)))).Methods("POST")
	publicAPI.Handle("/upload/others-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUploadOthersZipHandler)))).Methods("POST")

	log.Printf("Public API routes registered with API key authentication")
}

func apiDownloadFileByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if strings.TrimSpace(id) == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	rec, err := db.GetFileRecordByID(id)
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found", map[string]interface{}{
			"file_id": id,
			"message": "The requested file could not be found in the database.",
		})
		return
	}
	if rec.Status == database.FileStatusPurged || !rec.FileExists {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "FILE_NOT_AVAILABLE", "File not available", map[string]interface{}{
			"file_id": id,
			"status":  rec.Status,
			"message": "The file is not available for download. It may have been deleted or purged.",
		})
		return
	}

	fullPath := rec.FilePath
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "FILE_CONTENT_MISSING", "File content missing", map[string]interface{}{
			"file_id":   id,
			"file_path": fullPath,
			"message":   "The file record exists but the physical file is missing from storage.",
		})
		return
	}
	f, err := os.Open(fullPath)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot open file")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot stat file")
		return
	}
	name := filepath.Base(rec.FilePath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	w.Header().Set("Content-Type", getContentType(name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("download by id failed: %v", err)
		return
	}
}

func apiGetLatestVersionInfoHandler(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	items, err := db.GetFilesByType(t, false)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	var latest *database.FileRecord
	for i := range items {
		if items[i].IsLatest && items[i].Status == database.FileStatusActive {
			latest = &items[i]
			break
		}
	}
	if latest == nil && len(items) > 0 {

		for i := range items {
			if items[i].Status != database.FileStatusActive {
				continue
			}
			if latest == nil || items[i].Version > latest.Version {
				latest = &items[i]
			}
		}
	}
	if latest == nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "NO_LATEST_VERSION", "No latest version available for this type", map[string]interface{}{
			"type":    t,
			"message": "There are currently no files available for this version type. This may be because no files have been uploaded yet, or all files are in an inactive state.",
		})
		return
	}
	info := convertToFileInfo(*latest)
	if info.VersionID == "" {

		info.VersionID = filepath.Base(filepath.Dir(latest.FilePath))
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"latest": info}})
}

func apiGetVersionInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	t := strings.ToLower(vars["type"])
	ver := vars["ver"]
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}
	if strings.TrimSpace(ver) == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "version identifier required", map[string]interface{}{"field": "ver"})
		return
	}

	if strings.EqualFold(ver, "latest") {
		apiGetLatestVersionInfoHandler(w, r)
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	items, err := db.GetFilesByType(t, false)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	var target *database.FileRecord
	for i := range items {
		if items[i].Status != database.FileStatusActive {
			continue
		}

		vid := filepath.Base(filepath.Dir(items[i].FilePath))
		if vid == ver {
			target = &items[i]
			break
		}
	}
	if target == nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "VERSION_NOT_FOUND", "Specified version not found", map[string]interface{}{
			"type":    t,
			"version": ver,
			"message": "The requested version does not exist for this file type. Please check the version identifier or use 'latest' to get the most recent version.",
		})
		return
	}
	info := convertToFileInfo(*target)
	info.VersionID = ver
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"version": info}})
}

func apiGetVersionTypeStatusHandler(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	items, err := db.GetFilesByType(t, false)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	var latest *database.FileRecord
	hasActive := false
	for i := range items {
		if items[i].IsLatest && items[i].Status == database.FileStatusActive {
			latest = &items[i]
			break
		}
	}
	if latest == nil && len(items) > 0 {
		for i := range items {
			if items[i].Status == database.FileStatusActive {
				hasActive = true
				if latest == nil || items[i].Version > latest.Version {
					latest = &items[i]
				}
			}
		}
	}
	var status string
	var message string
	if latest != nil {
		status = "available"
		message = "Latest version is available for download"
	} else if hasActive {
		status = "available"
		message = "Active versions exist but none is marked as latest"
	} else if len(items) > 0 {
		status = "inactive"
		message = "All versions are in inactive state"
	} else {
		status = "empty"
		message = "No files uploaded for this type"
	}

	writeJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"type":           t,
			"status":         status,
			"message":        message,
			"total_versions": len(items),
			"active_versions": len(func() []database.FileRecord {
				var active []database.FileRecord
				for _, item := range items {
					if item.Status == database.FileStatusActive {
						active = append(active, item)
					}
				}
				return active
			}()),
			"has_latest": latest != nil,
		},
	})
}

func apiDownloadLatestByTypeHandler(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	items, err := db.GetFilesByType(t, false)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	var latest *database.FileRecord
	for i := range items {
		if items[i].IsLatest && items[i].Status == database.FileStatusActive {
			latest = &items[i]
			break
		}
	}
	if latest == nil && len(items) > 0 {
		for i := range items {
			if items[i].Status != database.FileStatusActive {
				continue
			}
			if latest == nil || items[i].Version > latest.Version {
				latest = &items[i]
			}
		}
	}
	if latest == nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "NO_LATEST_VERSION", "No latest version available for this type", map[string]interface{}{
			"type":    t,
			"message": "There are currently no files available for this version type. This may be because no files have been uploaded yet, or all files are in an inactive state.",
		})
		return
	}

	f, err := os.Open(latest.FilePath)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot open file")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot stat file")
		return
	}
	name := filepath.Base(latest.FilePath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	w.Header().Set("Content-Type", getContentType(name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = io.Copy(w, f)
}

func apiUploadAssetsZipHandler(w http.ResponseWriter, r *http.Request) {
	apiUploadZipHandler(w, r, "assets")
}

func apiUploadOthersZipHandler(w http.ResponseWriter, r *http.Request) {
	apiUploadZipHandler(w, r, "others")
}

func apiUploadZipHandler(w http.ResponseWriter, r *http.Request, kind string) {
	if kind != "assets" && kind != "others" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid kind")
		return
	}

	if err := r.ParseMultipartForm(128 << 20); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to parse form", map[string]interface{}{"field": "form", "error": err.Error()})
		return
	}

	tenant := strings.TrimSpace(r.FormValue("tenant_id"))
	if tenant == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "tenant_id is required", map[string]interface{}{"field": "tenant_id"})
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Missing file", map[string]interface{}{"field": "file"})
		return
	}
	defer file.Close()
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".zip") {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "Only .zip is allowed", map[string]interface{}{"filename": header.Filename})
		return
	}
	originalName := header.Filename

	ext := filepath.Ext(originalName)
	baseName := strings.TrimSuffix(originalName, ext)
	timestamp := time.Now().Format("20060102T150405Z")
	uniqueName := fmt.Sprintf("%s_%s%s", baseName, timestamp, ext)

	baseDir := filepath.Join("downloads", "packages", tenant, kind)
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create directory")
		return
	}
	targetPath := filepath.Join(baseDir, uniqueName)
	out, err := os.Create(targetPath)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create file")
		return
	}
	defer out.Close()
	n, err := io.Copy(out, file)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save file")
		return
	}

	db := database.GetDatabase()
	if db != nil {
		rec := &database.PackageRecord{
			ID:        fmt.Sprintf("pkg_%d", time.Now().UnixNano()),
			TenantID:  tenant,
			Type:      kind,
			FileName:  uniqueName,
			Size:      n,
			Path:      targetPath,
			IP:        middleware.GetClientIP(r),
			Timestamp: time.Now().UTC(),
			Remark:    fmt.Sprintf("uploaded via public API (original: %s)", originalName),
		}
		if err := db.InsertPackageRecord(rec); err != nil {
			log.Printf("Warning: Failed to save package record to database: %v", err)

		}
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Upload successful", Data: map[string]interface{}{"file": uniqueName, "original_file": originalName, "size": n, "tenant": tenant, "type": kind}})
}

func CleanupExpiredTempKeys() {

	log.Printf("CleanupExpiredTempKeys: placeholder implementation - no expired keys to clean")
}

// Test helper functions to allow testing of unexported functions
func WriteErrorWithCodeForTest(w http.ResponseWriter, status int, code, message string) {
	writeErrorWithCode(w, status, code, message)
}

func WriteErrorWithCodeDetailsForTest(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	writeErrorWithCodeDetails(w, status, code, message, details)
}

func WriteErrorResponseForTest(w http.ResponseWriter, status int, message string) {
	// Map status codes to error codes for legacy compatibility
	var code string
	switch status {
	case http.StatusBadRequest:
		code = "VALIDATION_ERROR"
	case http.StatusUnauthorized:
		code = "UNAUTHORIZED"
	case http.StatusNotFound:
		code = "NOT_FOUND"
	default:
		code = "INTERNAL_ERROR"
	}

	writeErrorWithCode(w, status, code, message)
}
