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

func handleAPIGetLatestVersionInfo(w http.ResponseWriter, r *http.Request) {
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

func handleAPIGetVersionInfo(w http.ResponseWriter, r *http.Request) {
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
		handleAPIGetLatestVersionInfo(w, r)
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

func handleAPIGetVersionTypeStatus(w http.ResponseWriter, r *http.Request) {
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

func handleAPIDownloadLatestByType(w http.ResponseWriter, r *http.Request) {
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
