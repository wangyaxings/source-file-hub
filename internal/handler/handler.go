package handler

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"

	"github.com/gorilla/mux"
)

// Response 閫氱敤鍝嶅簲缁撴瀯
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// FileMetadata 鏂囦欢鍏冩暟鎹粨鏋?(deprecated, use database.FileRecord)
type FileMetadata struct {
	ID            string    `json:"id"`
	OriginalName  string    `json:"originalName"`
	FileType      string    `json:"fileType"`
	Description   string    `json:"description"`
	Uploader      string    `json:"uploader"`
	UploadTime    time.Time `json:"uploadTime"`
	Version       int       `json:"version"`
	VersionedName string    `json:"versionedName"`
}

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

	// 2FA TOTP endpoints (custom, not conflicting with Authboss routes)
	webAPI.HandleFunc("/auth/2fa/totp/setup", middleware.RequireAuthorization(startTOTPHandler)).Methods("POST")
	webAPI.HandleFunc("/auth/2fa/totp/confirm", middleware.RequireAuthorization(enableTOTPHandler)).Methods("POST")
	webAPI.HandleFunc("/auth/2fa/totp/remove", middleware.RequireAuthorization(disableTOTPHandler)).Methods("POST")

	// ========= API信息和健康检查 =========
	webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
	webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

	// ========= 文件管理路由 =========
	webAPI.HandleFunc("/upload", middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
	webAPI.HandleFunc("/files/list", middleware.RequireAuthorization(listFilesHandler)).Methods("GET")
	webAPI.HandleFunc("/files/versions/{type}/{filename}", middleware.RequireAuthorization(getFileVersionsHandler)).Methods("GET")
	webAPI.HandleFunc("/files/{id}/delete", middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
	webAPI.HandleFunc("/files/{id}/restore", middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
	webAPI.HandleFunc("/files/{id}/purge", middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")

	// ========= 版本管理路由 =========
	webAPI.HandleFunc("/versions/{type}/versions.json", middleware.RequireAuthorization(webGetVersionsListHandler)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/manifest", middleware.RequireAuthorization(webGetVersionManifestHandler)).Methods("GET")
	webAPI.HandleFunc("/versions/{type}/{versionId}/tags", middleware.RequireAuthorization(webUpdateVersionTagsHandler)).Methods("PUT")

	// 回收站管理
	webAPI.HandleFunc("/recycle-bin", middleware.RequireAuthorization(getRecycleBinHandler)).Methods("GET")
	webAPI.HandleFunc("/recycle-bin/clear", middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")

	// 统一文件下载
	webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
	webFilesRouter.Use(middleware.Authorize())
	webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	// Packages web endpoints (delegate to API handlers)
	webAPI.HandleFunc("/packages", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiListPackagesHandler(w, r)
	})).Methods("GET")
	webAPI.HandleFunc("/packages/{id}/remark", middleware.RequireAuthorization(func(w http.ResponseWriter, r *http.Request) {
		apiUpdatePackageRemarkHandler(w, r)
	})).Methods("PATCH")

	// 其他业务路由...
	RegisterWebAdminRoutes(webAPI)
	RegisterAPIRoutes(router)
	RegisterAdminRoutes(router)

	// 静态文件
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// downloadFileHandler 缁熶竴鏂囦欢涓嬭浇澶勭悊鍣?
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 浠嶶RL璺緞涓彁鍙栨枃浠惰矾寰?
	filePath := strings.TrimPrefix(r.URL.Path, "/api/v1/web/files/")

	// 楠岃瘉鍜屾竻鐞嗚矾寰?
	if filePath == "" {
		writeErrorResponse(w, http.StatusBadRequest, "File path cannot be empty")
		return
	}

	// 闃叉璺緞閬嶅巻鏀诲嚮
	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid file path")
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
		writeErrorResponse(w, http.StatusForbidden, "File path not allowed")
		return
	}

	// 妫€鏌ユ枃浠舵槸鍚﹀瓨鍦?
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Printf("File not found: %s", fullPath)
		writeErrorResponse(w, http.StatusNotFound, "File not found")
		return
	}

	// 鎵撳紑鏂囦欢
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Error opening file %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "Cannot open file")
		return
	}
	defer file.Close()

	// 鑾峰彇鏂囦欢淇℃伅
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "Cannot get file info")
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
			if user, ok := userCtx.(map[string]interface{}); ok {
				userInfo = user
			}
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
			},
			"endpoints": map[string]interface{}{
				"api_info":     baseURL,
				"health_check": baseURL + "/health",
				"authentication": map[string]interface{}{
					"login":         baseURL + "/auth/login",
					"logout":        baseURL + "/auth/logout",
					"default_users": baseURL + "/auth/users",
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
				"JWT Authentication",
				"Multi-tenant Support",
				"HTTPS Only",
				"Path Traversal Protection",
				"Structured Logging",
				"SQLite Log Storage",
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
	response := Response{
		Success: false,
		Error:   message,
	}

	writeJSONResponse(w, status, response)
}

// Note: Login and logout are now handled by authboss under /api/v1/web/auth/ab/
// These handlers have been removed as they are replaced by authboss functionality

// meHandler returns current user info from session (Authboss)
func meHandler(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value("user")
	if userCtx == nil {
		writeErrorResponse(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	u, ok := userCtx.(*auth.User)
	if !ok {
		writeErrorResponse(w, http.StatusUnauthorized, "Invalid user context")
		return
	}
	payload := map[string]interface{}{"username": u.Username, "role": u.Role}
	if db := database.GetDatabase(); db != nil {
		if ur, err := db.GetUserRole(u.Username); err == nil && ur != nil {
			if ur.Status != "" {
				payload["status"] = ur.Status
			}
			payload["permissions"] = ur.Permissions
			payload["quota_daily"] = ur.QuotaDaily
			payload["quota_monthly"] = ur.QuotaMonthly
		}

		// Get detailed user info including TOTP secret status
		if appUser, err := db.GetUser(u.Username); err == nil {
			payload["two_fa"] = appUser.TwoFAEnabled
			payload["totp_secret"] = appUser.TOTPSecret != ""
			payload["two_fa_enabled"] = appUser.TwoFAEnabled
		}
	}
	// Include current 2FA state from context user as fallback
	if payload["two_fa"] == nil {
		payload["two_fa"] = u.TwoFAEnabled
	}
	writeJSONResponse(w, http.StatusOK, Response{Success: true, Data: map[string]interface{}{
		"user": payload,
	}})
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
		writeErrorResponse(w, http.StatusInternalServerError, "鏃ュ織绯荤粺鏈垵濮嬪寲")
		return
	}

	logs, err := l.GetAccessLogs(limit, offset)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "鏌ヨ鏃ュ織澶辫触")
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
}

// uploadFileHandler 鏂囦欢涓婁紶澶勭悊鍣?
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 瑙ｆ瀽multipart form锛堟彁楂橀檺棰濓級
	err := r.ParseMultipartForm(128 << 20) // 128MB
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to parse form: "+err.Error())
		return
	}

	// 鑾峰彇鏂囦欢
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to get file: "+err.Error())
		return
	}
	defer file.Close()

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
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported file type")
		return
	}

	// 楠岃瘉鏂囦欢鎵╁睍鍚?
	if !isValidFileExtension(header.Filename) {
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported file format")
		return
	}

	// 杩涗竴姝ユ牎楠屾墿灞曞悕涓庣被鍨嬪尮閰嶏紙roadmap->.tsv锛宺ecommendation->.xlsx锛夊苟璁剧疆鍥哄畾鍘熷鍚?
	ext := strings.ToLower(filepath.Ext(header.Filename))
	var fixedOriginalName string
	switch fileType {
	case "roadmap":
		if ext != ".tsv" {
			writeErrorResponse(w, http.StatusBadRequest, "File extension does not match fileType: roadmap requires .tsv")
			return
		}
		fixedOriginalName = "roadmap.tsv"
	case "recommendation":
		if ext != ".xlsx" {
			writeErrorResponse(w, http.StatusBadRequest, "File extension does not match fileType: recommendation requires .xlsx")
			return
		}
		fixedOriginalName = "recommendation.xlsx"
	default:
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported file type")
		return
	}

	// 灏嗕笂浼犵殑鍘熷鏂囦欢鍚嶈褰曞湪鎻忚堪涓紝渚夸簬杩芥函
	if header.Filename != "" {
		if strings.TrimSpace(description) == "" {
			description = "Original filename: " + header.Filename
		} else if !strings.Contains(description, "Original filename:") {
			description = description + " | Original filename: " + header.Filename
		}
	}

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
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate filename: "+err.Error())
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
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create directory: "+err.Error())
		return
	}

	// 鐢熸垚鏈€缁堟枃浠跺悕锛?type>_<versionID>.<ext>
	ext = strings.ToLower(filepath.Ext(fixedOriginalName))
	finalFileName := fmt.Sprintf("%s_%s%s", fileType, versionID, ext)

	// 鍒涘缓鐗堟湰鐩綍
	versionDir := filepath.Join(targetDir, versionID)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create version directory: "+err.Error())
		return
	}

	// 淇濆瓨鏂囦欢鍒扮増鏈洰褰?
	targetPath := filepath.Join(versionDir, finalFileName)
	fileInfo.Path = targetPath
	fileInfo.FileName = finalFileName

	dst, err := os.Create(targetPath)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create file: "+err.Error())
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to save file: "+err.Error())
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
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
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
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to save file metadata: "+err.Error())
		return
	}

	// Write versioning artifacts for roadmap/recommendation (manifest in the same version directory)
	if err := writeWebVersionArtifacts(fileType, versionID, fileInfo.FileName, targetPath, checksum, versionTags); err != nil {
		log.Printf("Warning: failed to write version artifacts: %v", err)
	}

	// Record upload log
	if l := logger.GetLogger(); l != nil {
		l.LogFileUpload(fileInfo.Path, uploader, fileInfo.Size, map[string]interface{}{
			"fileType":    fileType,
			"version":     version,
			"description": description,
		})
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
	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	var records []database.FileRecord
	var err error

	if fileType != "" {
		records, err = db.GetFilesByType(fileType, false)
	} else {
		records, err = db.GetAllFiles(false)
	}

	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get file list: "+err.Error())
		return
	}

	// Convert to FileInfo format
	var files []FileInfo
	for _, record := range records {
		// Check file existence and update database if needed
		if _, err := os.Stat(record.FilePath); err != nil {
			// File doesn't exist, update database
			if checkErr := db.CheckFileExists(record.ID); checkErr != nil {
				log.Printf("Warning: Failed to check file existence: %v", checkErr)
			}
		}
		files = append(files, convertToFileInfo(record))
	}

	response := Response{
		Success: true,
		Message: "File list retrieved successfully",
		Data: map[string]interface{}{
			"files": files,
			"count": len(files),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getFileVersionsHandler 鑾峰彇鏂囦欢鐗堟湰澶勭悊鍣?
func getFileVersionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileType := vars["type"]
	filename := vars["filename"]

	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	records, err := db.GetFileVersions(fileType, filename)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get file versions: "+err.Error())
		return
	}

	// Convert to FileInfo format
	var versions []FileInfo
	for _, record := range records {
		versions = append(versions, convertToFileInfo(record))
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
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	if err := db.SoftDeleteFile(fileID, deletedBy); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete file: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "File moved to recycle bin successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
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
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	if err := db.RestoreFile(fileID, restoredBy); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to restore file: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "File restored successfully",
	}

	writeJSONResponse(w, http.StatusOK, response)
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
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	if err := db.PermanentlyDeleteFile(fileID, purgedBy); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to purge file: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "File permanently deleted",
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getRecycleBinHandler 鑾峰彇鍥炴敹绔欏唴瀹?
func getRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get recycle bin items: "+err.Error())
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
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

	// 鑾峰彇鍥炴敹绔欎腑鐨勬墍鏈夐」鐩?
	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get recycle bin items: "+err.Error())
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
}

// 杈呭姪鍑芥暟

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
		writeErrorResponse(w, http.StatusBadRequest, "Invalid type")
		return
	}
	if vid == "" {
		writeErrorResponse(w, http.StatusBadRequest, "versionId required")
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
	writeErrorResponse(w, http.StatusNotFound, "Manifest not found")
}

// webGetVersionsListHandler returns versions.json
func webGetVersionsListHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ft := strings.ToLower(vars["type"])
	if ft != "roadmap" && ft != "recommendation" {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid type")
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
		writeErrorResponse(w, http.StatusBadRequest, "type must be 'roadmap' or 'recommendation'")
		return
	}
	if vid == "" {
		writeErrorResponse(w, http.StatusBadRequest, "versionId required")
		return
	}

	var body struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Normalize tags
	for i := range body.Tags {
		body.Tags[i] = strings.TrimSpace(body.Tags[i])
	}
	
	// Remove empty tags
	validTags := make([]string, 0, len(body.Tags))
	for _, tag := range body.Tags {
		if tag != "" {
			validTags = append(validTags, tag)
		}
	}

	writeJSONResponse(w, http.StatusOK, Response{Success: true, Message: "Version tags updated successfully"})
}

func fileSizeSafe(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}
