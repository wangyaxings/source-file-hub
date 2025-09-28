package handler

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/database"
	cfgpkg "secure-file-hub/internal/infrastructure/config"
	"secure-file-hub/internal/middleware"

	"github.com/gorilla/mux"
)

// API handler functions
func handleAPIInfo(w http.ResponseWriter, r *http.Request) {
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

func handleHealthCheck(w http.ResponseWriter, r *http.Request) {
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

func handleHealthAPIKeyCheck(w http.ResponseWriter, r *http.Request) {
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

func handleAPIDownloadFileByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if strings.TrimSpace(id) == "" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "id required")
		return
	}
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", databaseNotAvailable)
		return
	}
	rec, err := db.GetFileRecordByID(id)
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "FILE_NOT_FOUND", fileNotFound, map[string]interface{}{
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
	w.Header().Set(cacheControl, "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if _, err := io.Copy(w, f); err != nil {
		log.Printf("download by id failed: %v", err)
		return
	}
}

// findLatestVersion finds the latest version for a given file type
func findLatestVersion(fileType string) (*database.FileRecord, error) {
	items, err := getFilesByTypeFromDatabase(fileType)
	if err != nil {
		return nil, err
	}

	if len(items) == 0 {
		return nil, fmt.Errorf("no files found for type %s", fileType)
	}

	latest := findLatestVersionFromItems(items)
	if latest == nil {
		return nil, fmt.Errorf("no active versions available for type %s", fileType)
	}

	return latest, nil
}

func getFilesByTypeFromDatabase(fileType string) ([]database.FileRecord, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not available")
	}

	items, err := db.GetFilesByType(fileType, false)
	if err != nil {
		return nil, fmt.Errorf("failed to get files: %v", err)
	}

	return items, nil
}

func findLatestVersionFromItems(items []database.FileRecord) *database.FileRecord {
	// First, try to find the latest marked version
	for i := range items {
		if items[i].IsLatest && items[i].Status == database.FileStatusActive {
			return &items[i]
		}
	}

	// If no latest marked version, find the highest version among active items
	var latest *database.FileRecord
	for i := range items {
		if items[i].Status != database.FileStatusActive {
			continue
		}
		if latest == nil || items[i].Version > latest.Version {
			latest = &items[i]
		}
	}

	return latest
}

// getFilesByType retrieves files by type from database
func getFilesByType(fileType string) ([]database.FileRecord, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not available")
	}

	return db.GetFilesByType(fileType, false)
}

// determineVersionStatus determines the status of versions for a file type
func determineVersionStatus(items []database.FileRecord) (string, string, *database.FileRecord) {
	latest := findLatestVersionFromItems(items)
	status, message := determineStatusAndMessage(latest, items)

	return status, message, latest
}

func determineStatusAndMessage(latest *database.FileRecord, items []database.FileRecord) (string, string) {
	if latest != nil {
		return "available", "Latest version is available for download"
	}

	hasActive := hasActiveVersions(items)
	if hasActive {
		return "available", "Active versions exist but none is marked as latest"
	}

	if len(items) > 0 {
		return "inactive", "All versions are in inactive state"
	}

	return "empty", "No files uploaded for this type"
}

func hasActiveVersions(items []database.FileRecord) bool {
	for _, item := range items {
		if item.Status == database.FileStatusActive {
			return true
		}
	}
	return false
}

// countActiveVersions counts the number of active versions
func countActiveVersions(items []database.FileRecord) int {
	count := 0
	for _, item := range items {
		if item.Status == database.FileStatusActive {
			count++
		}
	}
	return count
}

// serveFileDownload serves a file for download
func serveFileDownload(w http.ResponseWriter, r *http.Request, record *database.FileRecord) {
	f, err := os.Open(record.FilePath)
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

	name := filepath.Base(record.FilePath)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", name))
	w.Header().Set("Content-Type", getContentType(name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fi.Size()))
	w.Header().Set(cacheControl, "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = io.Copy(w, f)
}

// handleAPIGetLatestVersionInfo handles requests for latest version info
const (
	allowedFileTypes = "roadmap or recommendation"
	noLatestVersion  = "No latest version available for this type"
	cacheControl     = "Cache-Control"
)

func handleAPIGetLatestVersionInfo(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be "+allowedFileTypes, map[string]interface{}{"field": "type"})
		return
	}

	latest, err := findLatestVersion(t)
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "NO_LATEST_VERSION", noLatestVersion, map[string]interface{}{
			"type":    t,
			"message": err.Error(),
		})
		return
	}

	info := convertToFileInfo(*latest)
	if info.VersionID == "" {
		info.VersionID = filepath.Base(filepath.Dir(latest.FilePath))
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"latest": info}})
}

func handleAPIGetVersionInfo(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	t := strings.ToLower(vars["type"])
	ver := vars["ver"]

	if err := validateVersionInfoRequest(t, ver); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error(), map[string]interface{}{"field": "type"})
		return
	}

	if strings.EqualFold(ver, "latest") {
		handleLatestVersionRequest(w, t)
		return
	}

	handleSpecificVersionRequest(w, t, ver)
}

func validateVersionInfoRequest(fileType, version string) error {
	if fileType != "roadmap" && fileType != "recommendation" {
		return fmt.Errorf("type must be 'roadmap' or 'recommendation'")
	}
	if strings.TrimSpace(version) == "" {
		return fmt.Errorf("version identifier required")
	}
	return nil
}

func handleLatestVersionRequest(w http.ResponseWriter, fileType string) {
	latest, err := findLatestVersion(fileType)
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "NO_LATEST_VERSION", "No latest version available for this type", map[string]interface{}{
			"type":    fileType,
			"message": err.Error(),
		})
		return
	}

	info := convertToFileInfo(*latest)
	if info.VersionID == "" {
		info.VersionID = filepath.Base(filepath.Dir(latest.FilePath))
	}
	info.VersionID = "latest" // Override with "latest"
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"version": info}})
}

func handleSpecificVersionRequest(w http.ResponseWriter, fileType, version string) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", databaseNotAvailable)
		return
	}

	items, err := db.GetFilesByType(fileType, false)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	target := findVersionInItems(items, version)
	if target == nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "VERSION_NOT_FOUND", versionNotFound, map[string]interface{}{
			"type":    fileType,
			"version": version,
			"message": "The requested version does not exist for this file type. Please check the version identifier or use 'latest' to get the most recent version.",
		})
		return
	}

	info := convertToFileInfo(*target)
	info.VersionID = version
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"version": info}})
}

func findVersionInItems(items []database.FileRecord, version string) *database.FileRecord {
	for i := range items {
		if items[i].Status != database.FileStatusActive {
			continue
		}

		vid := filepath.Base(filepath.Dir(items[i].FilePath))
		if vid == version {
			return &items[i]
		}
	}
	return nil
}

func handleAPIGetVersionTypeStatus(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}

	items, err := getFilesByType(t)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", databaseNotAvailable)
		return
	}

	status, message, latest := determineVersionStatus(items)
	activeCount := countActiveVersions(items)

	writeJSONResponse(w, http.StatusOK, Response{
		Success: true,
		Data: map[string]interface{}{
			"type":            t,
			"status":          status,
			"message":         message,
			"total_versions":  len(items),
			"active_versions": activeCount,
			"has_latest":      latest != nil,
		},
	})
}

func handleAPIDownloadLatestByType(w http.ResponseWriter, r *http.Request) {
	t := strings.ToLower(mux.Vars(r)["type"])
	if t != "roadmap" && t != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type"})
		return
	}

	latest, err := findLatestVersion(t)
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusNotFound, "NO_LATEST_VERSION", "No latest version available for this type", map[string]interface{}{
			"type":    t,
			"message": err.Error(),
		})
		return
	}

	serveFileDownload(w, r, latest)
}

func handleAPIUploadZip(w http.ResponseWriter, r *http.Request, kind string) {
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

func handleAPIUploadAssetsZip(w http.ResponseWriter, r *http.Request) {
	handleAPIUploadZip(w, r, "assets")
}

func handleAPIUploadOthersZip(w http.ResponseWriter, r *http.Request) {
	handleAPIUploadZip(w, r, "others")
}

// RegisterAPIRoutes registers all API routes
func RegisterAPIRoutes(router *mux.Router) {
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	apiRouter.HandleFunc("/health", handleHealthCheck).Methods("GET")
	apiRouter.HandleFunc("/healthz", handleHealthCheck).Methods("GET")

	apiRouter.HandleFunc("/status-check", handleHealthAPIKeyCheck).Methods("GET")

	publicAPI := apiRouter.PathPrefix("/public").Subrouter()

	publicAPI.Handle("/files/upload", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleFileUpload)))).Methods("POST")
	publicAPI.Handle("/files", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleListFiles)))).Methods("GET")
	publicAPI.Handle("/files/{id}/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIDownloadFileByID)))).Methods("GET")
	publicAPI.Handle("/files/{id}", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleDeleteFile)))).Methods("DELETE")
	publicAPI.Handle("/files/{id}/restore", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleRestoreFile)))).Methods("POST")

	publicAPI.Handle("/versions/{type}/latest", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIGetLatestVersionInfo)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIGetLatestVersionInfo)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIDownloadLatestByType)))).Methods("GET")

	log.Printf("Registering version status route for roadmap and recommendation")
	publicAPI.Handle("/versions/{type}/status", middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIGetVersionTypeStatus))).Methods("GET")

	publicAPI.Handle("/versions/{type}/{ver}/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIGetVersionInfo)))).Methods("GET")

	publicAPI.Handle("/packages", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleListPackages)))).Methods("GET")
	publicAPI.Handle("/packages/{id}/remark", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleUpdatePackageRemark)))).Methods("PATCH")

	publicAPI.Handle("/upload/assets-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIUploadAssetsZip)))).Methods("POST")
	publicAPI.Handle("/upload/others-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(handleAPIUploadOthersZip)))).Methods("POST")

	log.Printf("Public API routes registered with API key authentication")
}
