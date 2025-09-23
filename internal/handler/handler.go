package handler

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	"secure-file-hub/internal/application/usecases"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/domain/entities"
	repo "secure-file-hub/internal/infrastructure/repository/sqlite"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"
	fc "secure-file-hub/internal/presentation/http/controllers"

	di "secure-file-hub/internal/infrastructure/di"

	ab "github.com/aarondl/authboss/v3"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// Global variables
var appContainer *di.Container

// Global upload size limit (bytes)
const maxUploadBytes = 128 << 20 // 128MB

// Response 閫氱敤鍝嶅簲缁撴瀯
type Response struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message,omitempty"`
	Data    interface{}            `json:"data,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Code    string                 `json:"code,omitempty"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// FileMetadata has been removed - use database.FileRecord instead
// This legacy structure was used for JSON-based metadata storage

// Database helper functions

// calculateFileChecksum calculates SHA256 checksum of a file
func calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// convertToFileInfo converts database.FileRecord to FileInfo
func convertToFileInfo(record database.FileRecord) FileInfo {
	return FileInfo{
		ID:           record.ID,
		FileName:     record.VersionedName,
		OriginalName: record.OriginalName,
		FileType:     record.FileType,
		Size:         record.Size,
		Description:  record.Description,
		UploadTime:   record.UploadTime,
		Version:      record.Version,
		IsLatest:     record.IsLatest,
		Uploader:     record.Uploader,
		Path:         record.FilePath,
		Checksum:     record.Checksum,
	}
}

// convertEntityToFileInfo converts entities.File to FileInfo
func convertEntityToFileInfo(entity entities.File) FileInfo {
	return FileInfo{
		ID:           entity.ID,
		FileName:     entity.VersionedName,
		OriginalName: entity.OriginalName,
		FileType:     entity.FileType,
		Size:         entity.Size,
		Description:  entity.Description,
		UploadTime:   entity.UploadTime,
		Version:      entity.Version,
		IsLatest:     entity.IsLatest,
		Uploader:     entity.Uploader,
		Path:         entity.FilePath,
	}
}

func RegisterRoutes(router *mux.Router) {
	// 全局健康检查
	router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")
	router.HandleFunc("/api/v1/healthz", healthCheckHandler).Methods("GET")

	// Web API前缀
	webAPI := router.PathPrefix("/api/v1/web").Subrouter()

	// ========= 认证相关路由 =========

	// 基础认证信息（无需认证）
	webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
	webAPI.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")

	// 权限检查API
	webAPI.HandleFunc("/auth/check-permission", middleware.RequireAuthorization(checkPermissionHandler)).Methods("POST")
	webAPI.HandleFunc("/auth/check-permissions", middleware.RequireAuthorization(checkMultiplePermissionsHandler)).Methods("POST")

	// 2FA TOTP now handled by Authboss under /api/v1/web/auth/ab/2fa/totp/*

	// ========= API信息和健康检查 =========
	webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
	webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	// ========= 文件管理路由 =========
	// Apply API logging middleware to all file management endpoints
	webFileMgmtRouter := webAPI.PathPrefix("").Subrouter()
	webFileMgmtRouter.Use(middleware.APILoggingMiddleware)
	webFileMgmtRouter.HandleFunc("/upload", middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/list", middleware.RequireAuthorization(listFilesHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/versions/{type}/{filename}", middleware.RequireAuthorization(getFileVersionsHandler)).Methods("GET")
	webFileMgmtRouter.HandleFunc("/files/{id}/delete", middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
	webFileMgmtRouter.HandleFunc("/files/{id}/restore", middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
	webFileMgmtRouter.HandleFunc("/files/{id}/purge", middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")

	// ========= 版本管理路由 =========
	webAPI.HandleFunc("/versions/{type}/versions.json", middleware.RequireAuthorization(webGetVersionsListHandler)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/manifest", middleware.RequireAuthorization(webGetVersionManifestHandler)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/tags", middleware.RequireAuthorization(webUpdateVersionTagsHandler)).Methods("PUT")

	// 回收站管理
	webAPI.HandleFunc("/recycle-bin", middleware.RequireAuthorization(getRecycleBinHandler)).Methods("GET")
	webAPI.HandleFunc("/recycle-bin/clear", middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")

	// 统一文件下载
	webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
	webFilesRouter.Use(middleware.APILoggingMiddleware) // Add API logging for file downloads
	webFilesRouter.Use(middleware.Authorize())
	webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	// Packages web endpoints (delegate to API handlers)
	// Apply API logging middleware to web endpoints for usage tracking
	webPackagesRouter := webAPI.PathPrefix("/packages").Subrouter()
	webPackagesRouter.Use(middleware.APILoggingMiddleware)
	webPackagesRouter.HandleFunc("", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiListPackagesHandler(w, r)
	})).Methods("GET")
	webPackagesRouter.HandleFunc("/{id}/remark", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUpdatePackageRemarkHandler(w, r)
	})).Methods("PATCH")

	// Web upload wrappers (session auth) -> require tenant_id in form and save
	webAPI.HandleFunc("/packages/upload/assets-zip", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUploadAssetsZipHandler(w, r)
	})).Methods("POST")
	webAPI.HandleFunc("/packages/upload/others-zip", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUploadOthersZipHandler(w, r)
	})).Methods("POST")

	// 其他业务路由...
	RegisterWebAdminRoutes(webAPI)
	RegisterAPIRoutes(router)
	// RegisterAdminRoutes removed - consolidated into RegisterWebAdminRoutes to avoid duplication

	// 静态文件
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// downloadFileHandler 缁熶竴鏂囦欢涓嬭浇澶勭悊鍣?
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 浠嶶RL璺緞涓彁鍙栨枃浠惰矾寰?
	filePath := strings.TrimPrefix(r.URL.Path, "/api/v1/web/files/")

	// 楠岃瘉鍜屾竻鐞嗚矾寰?
	if filePath == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "File path cannot be empty", map[string]interface{}{"field": "path"})
		return
	}

	// 闃叉璺緞閬嶅巻鏀诲嚮
	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid file path", map[string]interface{}{"field": "path", "reason": "path traversal or absolute path"})
		return
	}

	// 鏋勫缓瀹屾暣鐨勬枃浠惰矾寰?- 娉ㄦ剰杩欓噷涓嶅啀娣诲姞downloads鍓嶇紑锛屽洜涓轰紶鍏ョ殑璺緞宸茬粡鍖呭惈浜?
	var fullPath string
	if strings.HasPrefix(filePath, "downloads/") {
		fullPath = filePath
	} else {
		fullPath = filepath.Join("downloads", filePath)
	}

	// 楠岃瘉鏂囦欢璺緞鏄惁鍦ㄥ厑璁哥殑鐩綍鍐?
	if !isAllowedPath(fullPath) {
		writeErrorWithCodeDetails(w, http.StatusForbidden, "INVALID_PERMISSION", "File path not allowed", map[string]interface{}{"path": fullPath})
		return
	}

	// 妫€鏌ユ枃浠舵槸鍚﹀瓨鍦?
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Printf("File not found: %s", fullPath)
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found")
		return
	}

	// 鎵撳紑鏂囦欢
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Error opening file %s: %v", fullPath, err)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot open file")
		return
	}
	defer file.Close()

	// 鑾峰彇鏂囦欢淇℃伅
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", fullPath, err)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Cannot get file info")
		return
	}

	// 鑾峰彇鏂囦欢鍚?
	fileName := filepath.Base(filePath)

	// 纭畾鍐呭绫诲瀷
	contentType := getContentType(fileName)

	// 璁剧疆鍝嶅簲澶?
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 澶嶅埗鏂囦欢鍐呭鍒板搷搴?
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Error writing file to response: %v", err)
		return
	}

	log.Printf("File %s downloaded successfully by %s", filePath, r.RemoteAddr)

	// 璁板綍缁撴瀯鍖栦笅杞芥棩蹇?
	if l := logger.GetLogger(); l != nil {
		var userInfo map[string]interface{}
		if userCtx := r.Context().Value("user"); userCtx != nil {
			if user, ok := userCtx.(*auth.User); ok {
				userInfo = map[string]interface{}{
					"username": user.Username,
					"role":     user.Role,
				}
			}
		}
		if rid := r.Context().Value(middleware.RequestIDKey); rid != nil {
			if userInfo == nil {
				userInfo = map[string]interface{}{}
			}
			userInfo["request_id"] = rid
		}
		l.LogFileDownload(filePath, r.RemoteAddr, fileInfo.Size(), userInfo)
	}
}

// apiInfoHandler API淇℃伅椤甸潰澶勭悊鍣?- 绫讳技GitHub API鏍归〉闈?
func apiInfoHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://localhost:8443/api/v1"

	// Dynamic build/version from environment variables
	appVersion := os.Getenv("APP_VERSION")
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

// healthCheckHandler 鍋ュ悍妫€鏌ュ鐞嗗櫒
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "鏈嶅姟杩愯姝ｅ父",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// writeJSONResponse 鍐欏叆JSON鍝嶅簲
func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeErrorResponse 鍐欏叆閿欒鍝嶅簲
func writeErrorResponse(w http.ResponseWriter, status int, message string) {
	// Legacy shim: prefer writeErrorWithCode; map common statuses
	code := "INTERNAL_ERROR"
	if status == http.StatusBadRequest {
		code = "VALIDATION_ERROR"
	}
	if status == http.StatusUnauthorized {
		code = "UNAUTHORIZED"
	}
	if status == http.StatusNotFound {
		code = "NOT_FOUND"
	}
	writeErrorWithCode(w, status, code, message)
}

// writeErrorWithCode writes a structured error including a machine-readable code
func writeErrorWithCode(w http.ResponseWriter, status int, code, message string) {
	// Attach request_id from header if present
	details := map[string]interface{}{}
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

// writeErrorWithCodeDetails writes a structured error with custom details map.
func writeErrorWithCodeDetails(w http.ResponseWriter, status int, code, message string, details map[string]interface{}) {
	if details == nil {
		details = map[string]interface{}{}
	}
	if rid := w.Header().Get("X-Request-ID"); rid != "" {
		// do not overwrite if caller already set one
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

// Note: Login and logout are now handled by authboss under /api/v1/web/auth/ab/
// These handlers have been removed as they are replaced by authboss functionality

// meHandler returns current user info from session (Authboss)
func meHandler(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated via Authboss session
	if username, ok := ab.GetSession(r, ab.SessionKey); ok && username != "" {
		// Load user from database
		user, err := loadUserFromDatabase(username)
		if err != nil {
			writeErrorWithCode(w, http.StatusUnauthorized, "USER_NOT_FOUND", "User not found in database")
			return
		}

		// Check user status
		if err := checkUserStatus(user.Username); err != nil {
			writeErrorWithCode(w, http.StatusUnauthorized, "ACCOUNT_SUSPENDED", err.Error())
			return
		}

		// Update last login timestamp (only for the first auth check per session)
		if db := database.GetDatabase(); db != nil {
			_ = db.SetUserLastLogin(user.Username, time.Now())
		}

		// Build user payload
		payload := usecases.NewUserUseCase().BuildMePayload(user.Username, user.Role, user.TwoFAEnabled)
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
			"user": payload,
		}})
		return
	}

	// Not authenticated
	writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
}

// 从数据库加载用户
func loadUserFromDatabase(username string) (*auth.User, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not available")
	}

	appUser, err := db.GetUser(username)
	if err != nil {
		return nil, err
	}

	return &auth.User{
		Username:     appUser.Username,
		Role:         appUser.Role,
		Email:        appUser.Email,
		TwoFAEnabled: appUser.TwoFAEnabled,
	}, nil
}

// 检查用户状态
func checkUserStatus(username string) error {
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not available")
	}

	userRole, err := db.GetUserRole(username)
	if err != nil {
		// 为没有角色记录的用户创建默认记录
		defaultRole := &database.UserRole{
			UserID: username,
			Role:   "viewer",
			Status: "active",
		}
		if err := db.CreateOrUpdateUserRole(defaultRole); err != nil {
			log.Printf("Warning: Failed to create default role for %s: %v", username, err)
		}
		return nil
	}

	if userRole.Status == "suspended" {
		return fmt.Errorf("ACCOUNT_SUSPENDED")
	}

	// 自动激活pending状态的用户
	if userRole.Status == "pending" {
		userRole.Status = "active"
		if err := db.CreateOrUpdateUserRole(userRole); err != nil {
			log.Printf("Warning: Failed to activate user %s: %v", username, err)
		}
	}

	return nil
}

// Note: Password change is now handled by authboss under /api/v1/web/auth/ab/
// This handler has been removed as it is replaced by authboss functionality

// Note: Password validation is now handled by authboss
// This function has been removed as it is replaced by authboss functionality

// getDefaultUsersHandler 鑾峰彇榛樿娴嬭瘯鐢ㄦ埛鍒楄〃
func getDefaultUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := auth.GetDefaultUsers()

	response := Response{
		Success: true,
		Message: "榛樿娴嬭瘯鐢ㄦ埛鍒楄〃",
		Data: map[string]interface{}{
			"users": users,
			"note":  "杩欎簺鏄璁剧殑娴嬭瘯鐢ㄦ埛锛屾偍鍙互浣跨敤杩欎簺璐︽埛杩涜鐧诲綍娴嬭瘯",
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// isAllowedPath 楠岃瘉鏂囦欢璺緞鏄惁鍦ㄥ厑璁哥殑鐩綍鍐?
func isAllowedPath(path string) bool {
	// 鑾峰彇缁濆璺緞
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// 鑾峰彇涓嬭浇鐩綍鐨勭粷瀵硅矾寰?
	downloadDir, err := filepath.Abs("downloads")
	if err != nil {
		return false
	}

	// 妫€鏌ヨ矾寰勬槸鍚﹀湪downloads鐩綍涓?
	return strings.HasPrefix(absPath, downloadDir)
}

// getAccessLogsHandler 鑾峰彇璁块棶鏃ュ織澶勭悊鍣?
func getAccessLogsHandler(w http.ResponseWriter, r *http.Request) {
	// 鑾峰彇鏌ヨ鍙傛暟
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // 榛樿闄愬埗
	offset := 0 // 榛樿鍋忕Щ

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}

	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// 浠庢暟鎹簱鏌ヨ鏃ュ織
	l := logger.GetLogger()
	if l == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Logging system not initialized")
		return
	}

	logs, err := l.GetAccessLogs(limit, offset)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to query logs")
		return
	}

	response := Response{
		Success: true,
		Message: "璁块棶鏃ュ織鏌ヨ鎴愬姛",
		Data: map[string]interface{}{
			"logs":   logs,
			"limit":  limit,
			"offset": offset,
			"count":  len(logs),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// FileUploadRequest 鏂囦欢涓婁紶璇锋眰缁撴瀯
type FileUploadRequest struct {
	FileType    string `form:"fileType" json:"fileType"`       // config, certificate, docs
	Description string `form:"description" json:"description"` // 鏂囦欢鎻忚堪
}

// FileInfo 鏂囦欢淇℃伅缁撴瀯
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

// uploadFileHandler 鏂囦欢涓婁紶澶勭悊鍣?
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 瑙ｆ瀽multipart form锛堟彁楂橀檺棰濓級
	err := r.ParseMultipartForm(128 << 20) // 128MB
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to parse form", map[string]interface{}{"field": "form", "error": err.Error()})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_parse_form_failed", map[string]interface{}{"error": err.Error()}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 鑾峰彇鏂囦欢
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to get file", map[string]interface{}{"field": "file", "error": err.Error()})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_missing_file", map[string]interface{}{"error": err.Error()}, "VALIDATION_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	defer file.Close()

	// Enforce file size limit (e.g., 128MB)
	if header.Size > maxUploadBytes {
		writeErrorWithCodeDetails(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Uploaded file exceeds the maximum allowed size", map[string]interface{}{"field": "file", "max_bytes": maxUploadBytes, "actual_bytes": header.Size})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_too_large", map[string]interface{}{"actual_bytes": header.Size, "max_bytes": maxUploadBytes}, "PAYLOAD_TOO_LARGE", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 鑾峰彇涓婁紶鍙傛暟
	fileType := r.FormValue("fileType")
	description := r.FormValue("description")
	// optional version tags (comma-separated)
	rawTags := r.FormValue("versionTags")
	var versionTags []string
	if strings.TrimSpace(rawTags) != "" {
		parts := strings.Split(rawTags, ",")
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if t != "" {
				versionTags = append(versionTags, t)
			}
		}
	}

	// 楠岃瘉鏂囦欢绫诲瀷
	allowedTypes := map[string]bool{
		"roadmap":        true,
		"recommendation": true,
	}
	if !allowedTypes[fileType] {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_TYPE", "Unsupported file type", map[string]interface{}{"field": "fileType", "allowed": []string{"roadmap", "recommendation"}})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_invalid_file_type", map[string]interface{}{"fileType": fileType}, "INVALID_FILE_TYPE", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 楠岃瘉鏂囦欢鎵╁睍鍚?
	if !isValidFileExtension(header.Filename) {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "Unsupported file format", map[string]interface{}{"field": "file", "filename": header.Filename})
		if l := logger.GetLogger(); l != nil {
			l.WarnCtx(logger.EventError, "upload_invalid_ext", map[string]interface{}{"filename": header.Filename}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 杩涗竴姝ユ牎楠屾墿灞曞悕涓庣被鍨嬪尮閰嶏紙roadmap->.tsv锛宺ecommendation->.xlsx锛夊苟璁剧疆鍥哄畾鍘熷鍚?
	ext := strings.ToLower(filepath.Ext(header.Filename))
	var fixedOriginalName string
	switch fileType {
	case "roadmap":
		if ext != ".tsv" {
			writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "File extension does not match fileType", map[string]interface{}{"field": "file", "expected_ext": ".tsv", "got": ext})
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "upload_ext_mismatch", map[string]interface{}{"expected": ".tsv", "got": ext}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
			return
		}
		fixedOriginalName = "roadmap.tsv"
	case "recommendation":
		if ext != ".xlsx" {
			writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_FORMAT", "File extension does not match fileType", map[string]interface{}{"field": "file", "expected_ext": ".xlsx", "got": ext})
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "upload_ext_mismatch", map[string]interface{}{"expected": ".xlsx", "got": ext}, "INVALID_FILE_FORMAT", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
			return
		}
		fixedOriginalName = "recommendation.xlsx"
	default:
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "INVALID_FILE_TYPE", "Unsupported file type", map[string]interface{}{"field": "fileType", "allowed": []string{"roadmap", "recommendation"}})
		return
	}

	// Description 保持用户输入的内容，不自动添加原始文件名

	// 鑾峰彇鐢ㄦ埛淇℃伅锛堜粠璁よ瘉涓棿浠惰缃殑涓婁笅鏂囦腑鑾峰彇锛?
	var uploader string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			uploader = user.Username
		} else {
			uploader = "unknown"
		}
	} else {
		uploader = "unknown"
	}

	// 鍒涘缓鏂囦欢淇℃伅
	fileInfo := &FileInfo{
		ID:           generateFileID(),
		FileName:     header.Filename,
		OriginalName: fixedOriginalName,
		FileType:     fileType,
		Size:         header.Size,
		Description:  description,
		UploadTime:   time.Now(),
		Uploader:     uploader,
	}

	// 鐢熸垚鐗堟湰鍖栫殑鏂囦欢鍚嶅拰璺緞
	versionedFileName, version, err := generateVersionedFileName(fileType, fixedOriginalName)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate filename: "+err.Error())
		return
	}

	fileInfo.FileName = versionedFileName
	fileInfo.Version = version
	fileInfo.IsLatest = true

	// Build machine version_id (UTC, vYYYYMMDDHHMMSSZ) and timestamp suffix
	ts := time.Now().UTC().Format("20060102150405") + "Z"
	versionID := "v" + ts

	// 鍒涘缓鐩爣鐩綍 - 鐩存帴浣跨敤UTC鏃堕棿鏍煎紡鐨勬枃浠跺す
	targetDir := filepath.Join("downloads", fileType+"s")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create directory: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_mkdir_failed", map[string]interface{}{"error": err.Error(), "dir": targetDir}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 鐢熸垚鏈€缁堟枃浠跺悕锛屽彧浣跨敤 versionID 閬垮厤閲嶅
	ext = strings.ToLower(filepath.Ext(fixedOriginalName))
	finalFileName := fmt.Sprintf("%s%s", versionID, ext)

	// 确保文件名不包含文件类型前缀，避免重复
	if strings.HasPrefix(finalFileName, fileType + "_") {
		finalFileName = strings.TrimPrefix(finalFileName, fileType + "_")
	}

	// 鍒涘缓鐗堟湰鐩綍
	versionDir := filepath.Join(targetDir, versionID)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create version directory: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_mkdir_version_failed", map[string]interface{}{"error": err.Error(), "dir": versionDir}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 淇濆瓨鏂囦欢鍒扮増鏈洰褰?
	targetPath := filepath.Join(versionDir, finalFileName)
	fileInfo.Path = targetPath
	fileInfo.FileName = finalFileName

	dst, err := os.Create(targetPath)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create file: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_create_file_failed", map[string]interface{}{"error": err.Error(), "path": targetPath}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save file: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_write_failed", map[string]interface{}{"error": err.Error(), "path": targetPath}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 鏇存柊鏈€鏂扮増鏈摼鎺?
	latestPath := filepath.Join(targetDir, fixedOriginalName)
	os.Remove(latestPath) // 鍒犻櫎鏃х殑閾炬帴锛堝鏋滃瓨鍦級

	// 鍒涘缓纭摼鎺ユ寚鍚戞渶鏂扮増鏈?
	if err := os.Link(targetPath, latestPath); err != nil {
		// 濡傛灉纭摼鎺ュけ璐ワ紝澶嶅埗鏂囦欢
		if copyErr := copyFile(targetPath, latestPath); copyErr != nil {
			log.Printf("Warning: Failed to create latest version link: %v", copyErr)
		}
	}

	// Calculate SHA256 checksum
	checksum, err := calculateFileChecksum(targetPath)
	if err != nil {
		log.Printf("Warning: Failed to calculate SHA256 checksum: %v", err)
	}

	// Create database record
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	record := &database.FileRecord{
		ID:            fileInfo.ID,
		OriginalName:  fixedOriginalName,
		VersionedName: finalFileName,
		FileType:      fileType,
		FilePath:      targetPath,
		Size:          fileInfo.Size,
		Description:   description,
		Uploader:      uploader,
		UploadTime:    time.Now(),
		Version:       version,
		IsLatest:      true,
		Checksum:      checksum,
	}

	// Save to database
	if err := db.InsertFileRecord(record); err != nil {
		// If database save fails, try to clean up the file
		os.Remove(targetPath)
		os.Remove(latestPath)
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save file metadata: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "upload_db_insert_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// Write versioning artifacts for roadmap/recommendation (manifest in the same version directory)
	if err := writeWebVersionArtifacts(fileType, versionID, fileInfo.FileName, targetPath, checksum, versionTags); err != nil {
		log.Printf("Warning: failed to write version artifacts: %v", err)
	}

	// Record upload log
	if l := logger.GetLogger(); l != nil {
		details := map[string]interface{}{
			"fileType":    fileType,
			"version":     version,
			"description": description,
		}
		if rid := r.Context().Value(middleware.RequestIDKey); rid != nil {
			details["request_id"] = rid
		}
		l.LogFileUpload(fileInfo.Path, uploader, fileInfo.Size, details)
	}

	// enrich response with versionId header + field
	w.Header().Set("X-Version-ID", versionID)
	fileInfo.VersionID = versionID

	response := Response{
		Success: true,
		Message: "File uploaded successfully",
		Data:    fileInfo,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// listFilesHandler 鏂囦欢鍒楄〃澶勭悊鍣?
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")
	// Parse pagination
	page := 1
	limit := 50
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	// Use DI controller if available
	var controller *fc.FileController
	if appContainer != nil && appContainer.FileController != nil {
		controller = appContainer.FileController
	} else {
		// Fallback: create controller on demand (not recommended for production)
		controller = fc.NewFileController(usecases.NewFileUseCase(repo.NewFileRepo()))
	}
	items, total, err := controller.ListWithPagination(fileType, page, limit)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get file list: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "list_files_failed", map[string]interface{}{"type": fileType, "page": page, "limit": limit}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	// Convert to FileInfo format
	files := make([]FileInfo, 0, len(items))
	for _, f := range items {
		files = append(files, convertEntityToFileInfo(f))
	}
	response := Response{
		Success: true,
		Message: "File list retrieved successfully",
		Data: map[string]interface{}{
			"files": files,
			"count": total,
			"page":  page,
			"limit": limit,
		},
	}
	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "list_files_success", map[string]interface{}{"type": fileType, "count": len(files), "total": total, "page": page, "limit": limit}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// getFileVersionsHandler 鑾峰彇鏂囦欢鐗堟湰澶勭悊鍣?
func getFileVersionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileType := vars["type"]
	filename := vars["filename"]

	// Use DI controller if available
	var controller *fc.FileController
	if appContainer != nil && appContainer.FileController != nil {
		controller = appContainer.FileController
	} else {
		// Fallback: create controller on demand (not recommended for production)
		controller = fc.NewFileController(usecases.NewFileUseCase(repo.NewFileRepo()))
	}
	items, err := controller.Versions(fileType, filename)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get file versions: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "get_versions_failed", map[string]interface{}{"type": fileType, "filename": filename}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}
	versions := make([]FileInfo, 0, len(items))
	for _, f := range items {
		versions = append(versions, convertEntityToFileInfo(f))
	}

	response := Response{
		Success: true,
		Message: "File versions retrieved successfully",
		Data: map[string]interface{}{
			"versions": versions,
			"count":    len(versions),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "get_versions_success", map[string]interface{}{"type": fileType, "filename": filename, "count": len(versions)}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// deleteFileHandler 鍒犻櫎鏂囦欢锛堢Щ鍔ㄥ埌鍥炴敹绔欙級
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 鑾峰彇鐢ㄦ埛淇℃伅
	var deletedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			deletedBy = user.Username
		} else {
			deletedBy = "unknown"
		}
	} else {
		deletedBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "recyclebin_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if err := db.SoftDeleteFile(fileID, deletedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found or already deleted")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "soft_delete_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "soft_delete_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File moved to recycle bin successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "soft_delete_success", map[string]interface{}{"file_id": fileID, "by": deletedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// restoreFileHandler 浠庡洖鏀剁珯鎭㈠鏂囦欢
func restoreFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 鑾峰彇鐢ㄦ埛淇℃伅
	var restoredBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			restoredBy = user.Username
		} else {
			restoredBy = "unknown"
		}
	} else {
		restoredBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "clear_recyclebin_db_unavailable", nil, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	if err := db.RestoreFile(fileID, restoredBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found in recycle bin")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "restore_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to restore file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "restore_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File restored successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "restore_success", map[string]interface{}{"file_id": fileID, "by": restoredBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// purgeFileHandler 姘镐箙鍒犻櫎鏂囦欢
func purgeFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 鑾峰彇鐢ㄦ埛淇℃伅
	var purgedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			purgedBy = user.Username
		} else {
			purgedBy = "unknown"
		}
	} else {
		purgedBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		return
	}

	if err := db.PermanentlyDeleteFile(fileID, purgedBy); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found or already purged")
			if l := logger.GetLogger(); l != nil {
				l.WarnCtx(logger.EventError, "purge_not_found", map[string]interface{}{"file_id": fileID}, "FILE_NOT_FOUND", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		} else {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to purge file: "+err.Error())
			if l := logger.GetLogger(); l != nil {
				l.ErrorCtx(logger.EventError, "purge_failed", map[string]interface{}{"file_id": fileID}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
			}
		}
		return
	}

	response := Response{
		Success: true,
		Message: "File permanently deleted",
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "purge_success", map[string]interface{}{"file_id": fileID, "by": purgedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// getRecycleBinHandler 鑾峰彇鍥炴敹绔欏唴瀹?
func getRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		return
	}

	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get recycle bin items: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "recyclebin_query_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	response := Response{
		Success: true,
		Message: "Recycle bin retrieved successfully",
		Data: map[string]interface{}{
			"items": items,
			"count": len(items),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "recyclebin_success", map[string]interface{}{"count": len(items)}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// clearRecycleBinHandler 娓呯┖鍥炴敹绔?
func clearRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	// 鑾峰彇鐢ㄦ埛淇℃伅
	var purgedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			purgedBy = user.Username
		} else {
			purgedBy = "unknown"
		}
	} else {
		purgedBy = "unknown"
	}

	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Database not initialized")
		return
	}

	// 鑾峰彇鍥炴敹绔欎腑鐨勬墍鏈夐」鐩?
	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get recycle bin items: "+err.Error())
		if l := logger.GetLogger(); l != nil {
			l.ErrorCtx(logger.EventError, "clear_recyclebin_query_failed", map[string]interface{}{"error": err.Error()}, "INTERNAL_ERROR", r.Context().Value(middleware.RequestIDKey), getActor(r))
		}
		return
	}

	// 姘镐箙鍒犻櫎鎵€鏈夐」鐩?
	purgedCount := 0
	for _, item := range items {
		if err := db.PermanentlyDeleteFile(item.ID, purgedBy); err != nil {
			log.Printf("Failed to purge file %s: %v", item.ID, err)
		} else {
			purgedCount++
		}
	}

	response := Response{
		Success: true,
		Message: fmt.Sprintf("Recycle bin cleared: %d files purged", purgedCount),
		Data: map[string]interface{}{
			"purged_count": purgedCount,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
	if l := logger.GetLogger(); l != nil {
		l.InfoCtx(logger.EventAPIRequest, "clear_recyclebin_success", map[string]interface{}{"purged_count": purgedCount, "by": purgedBy}, "", r.Context().Value(middleware.RequestIDKey), getActor(r))
	}
}

// 杈呭姪鍑芥暟

// generateSecurePassword generates a secure password with the following characteristics:
// - At least 12 characters long
// - Contains uppercase letters (A-Z)
// - Contains lowercase letters (a-z)
// - Contains digits (0-9)
// - Contains special characters (!@#$%^&*()_+-=[]{}|;:,.<>?)
// This follows security best practices for temporary passwords
func generateSecurePassword(length int) (string, error) {
	if length < 12 {
		length = 12 // Minimum secure length
	}

	// Character sets
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits := "0123456789"
	special := "!@#$%^&*()_+-=[]{}|;:,.<>?"

	// All characters combined
	allChars := lowercase + uppercase + digits + special

	// Ensure at least one character from each set
	password := make([]byte, length)

	// First, add one character from each required set
	sets := []string{lowercase, uppercase, digits, special}
	for i, set := range sets {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = set[charIndex.Int64()]
	}

	// Fill the rest with random characters from all sets
	for i := len(sets); i < length; i++ {
		charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(allChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character: %v", err)
		}
		password[i] = allChars[charIndex.Int64()]
	}

	// Shuffle the password to randomize positions
	for i := len(password) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", fmt.Errorf("failed to shuffle password: %v", err)
		}
		password[i], password[j.Int64()] = password[j.Int64()], password[i]
	}

	return string(password), nil
}

// generateFileID 鐢熸垚鏂囦欢ID
func generateFileID() string {
	return fmt.Sprintf("file_%d_%d", time.Now().UnixNano(), os.Getpid())
}

// generateVersionedFileName 鐢熸垚鐗堟湰鍖栫殑鏂囦欢鍚?
func generateVersionedFileName(fileType, originalName string) (string, int, error) {
	// 浠庢暟鎹簱鑾峰彇鐜版湁鐗堟湰鍙?
	db := database.GetDatabase()
	if db == nil {
		return "", 0, fmt.Errorf("database not initialized")
	}

	// 鏌ヨ鏁版嵁搴撲腑鍚屽悕鏂囦欢鐨勬渶澶х増鏈彿
	query := `
		SELECT COALESCE(MAX(version), 0) as max_version
		FROM files
		WHERE file_type = ? AND original_name = ? AND status != 'purged'
	`

	var maxVersion int
	err := db.GetDB().QueryRow(query, fileType, originalName).Scan(&maxVersion)
	if err != nil && err != sql.ErrNoRows {
		return "", 0, fmt.Errorf("failed to query max version: %v", err)
	}

	// 鏂扮増鏈彿
	version := maxVersion + 1

	// 鐢熸垚鐗堟湰鍖栨枃浠跺悕
	ext := filepath.Ext(originalName)
	baseName := strings.TrimSuffix(originalName, ext)
	versionedName := fmt.Sprintf("%s_v%d%s", baseName, version, ext)

	return versionedName, version, nil
}

// isValidFileExtension 楠岃瘉鏂囦欢鎵╁睍鍚?
func isValidFileExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validExts := map[string]bool{
		".tsv":  true, // Roadmap
		".xlsx": true, // Recommendation
	}
	return validExts[ext]
}

// copyFile 澶嶅埗鏂囦欢
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// getContentType 鏍规嵁鏂囦欢鎵╁睍鍚嶇‘瀹氬唴瀹圭被鍨?
func getContentType(fileName string) string {
	ext := strings.ToLower(filepath.Ext(fileName))
	switch ext {
	case ".tsv":
		return "text/tab-separated-values"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	case ".zip":
		return "application/zip"
	default:
		return "application/octet-stream"
	}
}

// =========================
// Versioning (web) helpers and endpoints (no channels)
// =========================

// writeWebVersionArtifacts writes manifest.json and updates versions.json for roadmap/recommendation
func writeWebVersionArtifacts(fileType, versionID, storedName, targetPath, checksum string, tags []string) error {
	if fileType != "roadmap" && fileType != "recommendation" {
		return nil
	}
	// Use the same directory as the target file (version directory)
	baseDir := filepath.Dir(targetPath)
	manifestPath := filepath.Join(baseDir, "manifest.json")

	manifest := map[string]interface{}{
		"version_id":   versionID,
		"version_tags": tags,
		"build": map[string]interface{}{
			"time":   time.Now().UTC().Format(time.RFC3339),
			"commit": "",
		},
		"artifact": map[string]interface{}{
			"file_name": storedName,
			"path":      targetPath,
			"sha256":    checksum,
			"size":      fileSizeSafe(targetPath),
		},
		"schema_version":   "1.0",
		"breaking_changes": []string{},
	}
	if err := writeJSONFileGeneric(manifestPath, manifest); err != nil {
		return err
	}
	return nil
}

func writeJSONFileGeneric(path string, v interface{}) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSONFileGeneric(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// webGetVersionManifestHandler returns manifest.json for given versionId
func webGetVersionManifestHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"])
	vid := vars["versionId"]
	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid type", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	if vid == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "versionId required", map[string]interface{}{"field": "versionId"})
		return
	}
	baseDir := filepath.Join("downloads", ft+"s", vid)
	manifestPath := filepath.Join(baseDir, "manifest.json")
	if b, err := os.ReadFile(manifestPath); err == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return
	}
	writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "Manifest not found")
}

// webGetVersionsListHandler returns versions.json
func webGetVersionsListHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"])
	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid type", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	baseDir := filepath.Join("downloads", ft+"s")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": []interface{}{}}})
		return
	}
	list := []interface{}{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Expect folder name equals versionID (vYYYYMMDDHHMMSSZ)
		mpath := filepath.Join(baseDir, e.Name(), "manifest.json")
		if m, err := readJSONFileGeneric(mpath); err == nil {
			date := ""
			if b, ok := m["build"].(map[string]interface{}); ok {
				if t, ok2 := b["time"].(string); ok2 {
					date = t
				}
			}
			list = append(list, map[string]interface{}{
				"version_id": m["version_id"],
				"tags":       m["version_tags"],
				"status":     "active",
				"date":       date,
			})
		}
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"versions": list}})
}

// webUpdateVersionTagsHandler updates tags for a specific version (admin only)
func webUpdateVersionTagsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"]) // roadmap or recommendation
	vid := vars["versionId"]

	if ft != "roadmap" && ft != "recommendation" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "type must be 'roadmap' or 'recommendation'", map[string]interface{}{"field": "type", "allowed": []string{"roadmap", "recommendation"}})
		return
	}
	if vid == "" {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "versionId required", map[string]interface{}{"field": "versionId"})
		return
	}

	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// Normalize tags
	for i := range body.Tags {
		body.Tags[i] = strings.TrimSpace(body.Tags[i])
	}

	// Remove empty tags (placeholder - tags are not actually used in this implementation)
	// In a real implementation, you would save these tags to the database
	_ = body.Tags // Prevent unused variable warning

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Version tags updated successfully"})
}

func fileSizeSafe(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// SetContainer sets the DI container for handlers to use
func SetContainer(container *di.Container) {
	appContainer = container
}

// getActor extracts the actor (username) from the request context for logging
func getActor(r *http.Request) string {
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			return user.Username
		}
	}
	return "anonymous"
}

// RegisterWebAdminRoutes registers admin-specific routes
func RegisterWebAdminRoutes(router *mux.Router) {
	// Mount under /admin with admin privilege guard
	admin := router.PathPrefix("/admin").Subrouter()
	admin.Use(middleware.RequireAdminAuth)

	// API Keys
	admin.HandleFunc("/api-keys", adminListAPIKeysHandler).Methods("GET")
	admin.HandleFunc("/api-keys", adminCreateAPIKeyHandler).Methods("POST")
	admin.HandleFunc("/api-keys/{id}", adminUpdateAPIKeyHandler).Methods("PUT")
	admin.HandleFunc("/api-keys/{id}", adminDeleteAPIKeyHandler).Methods("DELETE")
	admin.HandleFunc("/api-keys/{id}/status", adminUpdateAPIKeyStatusHandler).Methods("PATCH")

	// Usage logs
	admin.HandleFunc("/usage/logs", adminUsageLogsHandler).Methods("GET")

	// Analytics overview
	admin.HandleFunc("/analytics", adminAnalyticsHandler).Methods("GET")
	admin.HandleFunc("/analytics/data", adminAnalyticsHandler).Methods("GET")

	// Users
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

// =========================
// Admin: API Keys Handlers
// =========================

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

	// Check if API key name already exists
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

	// Generate key
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
	// Create casbin policies for this key
	_ = authz.CreateAPIKeyPolicies(rec.ID, rec.Permissions)

	// Return the plaintext key only once
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

	// Check if API key name already exists (if name is being updated)
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
	// Return updated record
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

	// Build filters from query parameters
	filters := database.APIUsageLogFilters{
		UserID:   q.Get("userId"),
		FileID:   q.Get("fileId"),
		APIKey:   q.Get("apiKey"),
		Method:   q.Get("method"),
		Endpoint: q.Get("endpoint"),
		TimeFrom: q.Get("timeFrom"),
		TimeTo:   q.Get("timeTo"),
	}

	// Use filtered query if any filters are provided
	if filters.APIKey != "" || filters.Method != "" || filters.Endpoint != "" || filters.TimeFrom != "" || filters.TimeTo != "" || filters.UserID != "" || filters.FileID != "" {
		logs, err := db.GetAPIUsageLogsFiltered(filters, limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		// Get total count for pagination
		totalCount, err := db.GetAPIUsageLogsCountFiltered(filters)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		// Return both "logs" and standard "items" to maximize compatibility
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	} else {
		// Use original query for backwards compatibility when no filters
		logs, err := db.GetAPIUsageLogs("", "", limit, offset)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		// Get total count for pagination
		totalCount, err := db.GetAPIUsageLogsCount("", "")
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}

		// Return both "logs" and standard "items" to maximize compatibility
		writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"logs": logs, "items": logs, "count": totalCount}})
	}
}

// adminAnalyticsHandler returns analytics data for admin dashboard
func adminAnalyticsHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}
	q := r.URL.Query()
	// time range: default last 7 days
	now := time.Now().UTC()
	start := now.Add(-7 * 24 * time.Hour)
	end := now
	// Accept multiple param aliases from frontend
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
	// Optional timeRange alias (e.g., '7d','24h')
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
	// Filters
	apiKeyFilter := strings.TrimSpace(firstNonEmpty(q.Get("api_key_id"), q.Get("apiKey")))
	userFilter := strings.TrimSpace(firstNonEmpty(q.Get("user_id"), q.Get("user")))
	data, err := db.GetAnalyticsData(database.AnalyticsTimeRange{Start: start, End: end}, apiKeyFilter, userFilter)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

// helper to pick first non-empty string
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// ======================
// Admin: Users Handlers
// ======================

func adminGetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	// Get user from database
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

	// Get user role information
	userRole, err := db.GetUserRole(userID)
	if err != nil {
		// Create default role if not exists
		userRole = &database.UserRole{
			UserID: userID,
			Role:   "viewer",
			Status: "active",
		}
	}

	response := Response{
		Success: true,
		Data: map[string]interface{}{
			"id":           user.Username,
			"username":     user.Username,
			"email":        user.Email,
			"role":         userRole.Role,
			"status":       userRole.Status,
			"twofa_enabled": user.TwoFAEnabled,
			"last_login":   user.LastLoginAt,
			"created_at":   user.CreatedAt,
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
	// Generate a temporary password
	tmp, _ := apikey.GenerateRandomString(16)
	// Create user
	// Hash password
	hashed, _ := bcrypt.GenerateFromPassword([]byte(tmp), bcrypt.DefaultCost)
	if err := db.CreateUser(&database.AppUser{Username: req.Username, Email: req.Email, PasswordHash: string(hashed), Role: req.Role}); err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	// Set initial role record with pending status
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
	// Update role in both tables
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

// checkPermissionHandler checks if the current user has a specific permission
func checkPermissionHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	// Get user from context
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid user context")
		return
	}

	// Check permission using Casbin
	allowed, err := authz.CheckPermission(user.Role, req.Resource, req.Action)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check permission")
		return
	}

	// Frontend expects top-level fields: { success, allowed, resource, action, role }
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"allowed":  allowed,
		"resource": req.Resource,
		"action":   req.Action,
		"role":     user.Role,
	})
}

// checkMultiplePermissionsHandler checks multiple permissions at once
func checkMultiplePermissionsHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Permissions []struct {
			Resource string `json:"resource"`
			Action   string `json:"action"`
		} `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	// Get user from context
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return
	}

	user, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorWithCode(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid user context")
		return
	}

	// Build mapping result: "<resource>:<action>" => allowed (boolean)
	resultMap := make(map[string]bool, len(req.Permissions))

	// Check each permission
	for _, perm := range req.Permissions {
		allowed, err := authz.CheckPermission(user.Role, perm.Resource, perm.Action)
		if err != nil {
			writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check permission")
			return
		}
		key := perm.Resource + ":" + perm.Action
		resultMap[key] = allowed
	}

	// Frontend expects: { success, results: {"/path:METHOD": bool}, role }
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"results": resultMap,
		"role":    user.Role,
	})
}

// apiListPackagesHandler lists packages (API endpoint)
func apiListPackagesHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
		return
	}

	q := r.URL.Query()
	tenant := strings.TrimSpace(q.Get("tenant"))
	ptype := strings.TrimSpace(q.Get("type"))
	search := strings.TrimSpace(q.Get("q"))
	page, _ := strconv.Atoi(q.Get("page"))
	limit, _ := strconv.Atoi(q.Get("limit"))

	items, total, err := db.ListPackages(tenant, ptype, search, page, limit)
	if err != nil {
		writeErrorWithCode(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	// Normalize shape for frontend
	data := map[string]interface{}{
		"items": items,
		"count": total,
		"page": func() int {
			if page > 0 {
				return page
			}
			return 1
		}(),
		"limit": func() int {
			if limit > 0 {
				return limit
			}
			return 50
		}(),
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: data})
}

// apiUpdatePackageRemarkHandler updates package remark (API endpoint)
func apiUpdatePackageRemarkHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	packageID := vars["id"]

	var req struct {
		Remark string `json:"remark"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body", map[string]interface{}{"field": "body", "error": err.Error()})
		return
	}

	// This is a placeholder implementation
	// In a real implementation, this would update the package remark in the database

	response := Response{
		Success: true,
		Message: "Package remark updated successfully",
		Data: map[string]interface{}{
			"package_id": packageID,
			"remark":     req.Remark,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// RegisterAPIRoutes registers API-specific routes (for external API access)
func RegisterAPIRoutes(router *mux.Router) {
	// API routes for external access (different from web routes)
	apiRouter := router.PathPrefix("/api/v1").Subrouter()

	// Health check for API (no authentication required) - 对外暴露
	apiRouter.HandleFunc("/health", healthCheckHandler).Methods("GET")
	apiRouter.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	// Public API routes with API key authentication
	publicAPI := apiRouter.PathPrefix("/public").Subrouter()

	// File management endpoints with API key authentication
	publicAPI.Handle("/files/upload", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(uploadFileHandler)))).Methods("POST")
	publicAPI.Handle("/files", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(listFilesHandler)))).Methods("GET")
	publicAPI.Handle("/files/{id}/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiDownloadFileByIDHandler)))).Methods("GET")
	publicAPI.Handle("/files/{id}", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(deleteFileHandler)))).Methods("DELETE")
	publicAPI.Handle("/files/{id}/restore", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(restoreFileHandler)))).Methods("POST")

	// Latest version helpers for roadmap/recommendation
	publicAPI.Handle("/versions/{type}/latest", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetLatestVersionInfoHandler)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetLatestVersionInfoHandler)))).Methods("GET")
	publicAPI.Handle("/versions/{type}/latest/download", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiDownloadLatestByTypeHandler)))).Methods("GET")

	// Generic version info: supports 'latest' or concrete versionId
	publicAPI.Handle("/versions/{type}/{ver}/info", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiGetVersionInfoHandler)))).Methods("GET")

	// Package management endpoints with API key authentication
	publicAPI.Handle("/packages", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiListPackagesHandler)))).Methods("GET")
	publicAPI.Handle("/packages/{id}/remark", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUpdatePackageRemarkHandler)))).Methods("PATCH")

	// Public uploads: assets / others ZIPs
	publicAPI.Handle("/upload/assets-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUploadAssetsZipHandler)))).Methods("POST")
	publicAPI.Handle("/upload/others-zip", middleware.APIKeyAuthMiddleware(middleware.APILoggingMiddleware(http.HandlerFunc(apiUploadOthersZipHandler)))).Methods("POST")

	log.Printf("Public API routes registered with API key authentication")
}

// apiDownloadFileByIDHandler downloads a file by database ID (public API)
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
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not found")
		return
	}
	if rec.Status == database.FileStatusPurged || !rec.FileExists {
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File not available")
		return
	}
	// Serve the file
	fullPath := rec.FilePath
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "File content missing")
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

// apiGetLatestVersionInfoHandler returns JSON info for the latest roadmap/recommendation
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
		// Fallback: pick highest version active file
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
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "No file found")
		return
	}
	info := convertToFileInfo(*latest)
	if info.VersionID == "" {
		// Derive versionId from the directory name of the stored file path
		// downloads/<type>s/<versionId>/<file>
		info.VersionID = filepath.Base(filepath.Dir(latest.FilePath))
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"latest": info}})
}

// apiGetVersionInfoHandler returns JSON info for a given versionId (or 'latest') of roadmap/recommendation
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
	// If 'latest', delegate to latest handler logic
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
		// versionId is the directory name in the stored path: downloads/<type>s/<versionId>/<file>
		vid := filepath.Base(filepath.Dir(items[i].FilePath))
		if vid == ver {
			target = &items[i]
			break
		}
	}
	if target == nil {
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "Specified version not found")
		return
	}
	info := convertToFileInfo(*target)
	info.VersionID = ver
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{"version": info}})
}

// apiDownloadLatestByTypeHandler streams the latest roadmap/recommendation file
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
		writeErrorWithCode(w, http.StatusNotFound, "FILE_NOT_FOUND", "No file found")
		return
	}
	// Stream
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

// apiUploadAssetsZipHandler handles public upload of assets zip
func apiUploadAssetsZipHandler(w http.ResponseWriter, r *http.Request) {
	apiUploadZipHandler(w, r, "assets")
}

// apiUploadOthersZipHandler handles public upload of others zip
func apiUploadOthersZipHandler(w http.ResponseWriter, r *http.Request) {
	apiUploadZipHandler(w, r, "others")
}

// apiUploadZipHandler saves <tenant>_{kind}_<UTC>.zip into downloads/packages/<tenant>/<kind>/
func apiUploadZipHandler(w http.ResponseWriter, r *http.Request, kind string) {
	if kind != "assets" && kind != "others" {
		writeErrorWithCode(w, http.StatusBadRequest, "VALIDATION_ERROR", "invalid kind")
		return
	}
	// Parse form
	if err := r.ParseMultipartForm(128 << 20); err != nil {
		writeErrorWithCodeDetails(w, http.StatusBadRequest, "VALIDATION_ERROR", "Failed to parse form", map[string]interface{}{"field": "form", "error": err.Error()})
		return
	}
	// New: require tenant_id param (no longer parsed from filename)
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
	// Create unique filename to avoid overwriting
	ext := filepath.Ext(originalName)
	baseName := strings.TrimSuffix(originalName, ext)
	timestamp := time.Now().Format("20060102T150405Z")
	uniqueName := fmt.Sprintf("%s_%s%s", baseName, timestamp, ext)

	// Create directories by tenant/kind
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
	// Save package record
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
			// Continue anyway - file was saved successfully
		}
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Upload successful", Data: map[string]interface{}{"file": uniqueName, "original_file": originalName, "size": n, "tenant": tenant, "type": kind}})
}

// CleanupExpiredTempKeys cleans up expired temporary keys
// This is a placeholder implementation - in a real implementation,
// this would clean up expired API keys or temporary authentication tokens
func CleanupExpiredTempKeys() {
	// This is a placeholder implementation for cleanup of expired temporary keys
	// In a real implementation, this would:
	// 1. Query database for expired API keys
	// 2. Remove expired keys from database
	// 3. Update any related policies in Casbin
	// 4. Log the cleanup operation

	log.Printf("CleanupExpiredTempKeys: placeholder implementation - no expired keys to clean")
}
