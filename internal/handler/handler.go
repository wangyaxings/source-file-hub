package handler

import (
	"crypto/md5"
	"database/sql"
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

	"github.com/gorilla/mux"
)

// Response 通用响应结构
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// FileMetadata 文件元数据结构 (deprecated, use database.FileRecord)
type FileMetadata struct {
	ID           string    `json:"id"`
	OriginalName string    `json:"originalName"`
	FileType     string    `json:"fileType"`
	Description  string    `json:"description"`
	Uploader     string    `json:"uploader"`
	UploadTime   time.Time `json:"uploadTime"`
	Version      int       `json:"version"`
	VersionedName string   `json:"versionedName"`
}

// Database helper functions

// calculateFileChecksum calculates MD5 checksum of a file
func calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// convertToFileInfo converts database.FileRecord to FileInfo
func convertToFileInfo(record database.FileRecord) FileInfo {
	return FileInfo{
		ID:          record.ID,
		FileName:    record.VersionedName,
		OriginalName: record.OriginalName,
		FileType:    record.FileType,
		Size:        record.Size,
		Description: record.Description,
		UploadTime:  record.UploadTime,
		Version:     record.Version,
		IsLatest:    record.IsLatest,
		Uploader:    record.Uploader,
		Path:        record.FilePath,
	}
}

// RegisterRoutes 注册所有路由
func RegisterRoutes(router *mux.Router) {
	// 添加全局健康检查路由（不需要认证，便于系统监控）
	router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")

	// Web API版本前缀 (原有的Web界面API)
	webAPI := router.PathPrefix("/api/v1/web").Subrouter()

	// 认证相关路由（无需认证）
	webAPI.HandleFunc("/auth/login", loginHandler).Methods("POST")
	webAPI.HandleFunc("/auth/logout", logoutHandler).Methods("POST")
	webAPI.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")

	// Web API根信息页面（无需认证）
	webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
	webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")

	// 健康检查路由（无需认证）
	webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")

	// 文件管理路由（需要Web认证）
	webAPI.HandleFunc("/upload", uploadFileHandler).Methods("POST")
	webAPI.HandleFunc("/files/list", listFilesHandler).Methods("GET")
	webAPI.HandleFunc("/files/versions/{type}/{filename}", getFileVersionsHandler).Methods("GET")
	webAPI.HandleFunc("/files/{id}/delete", deleteFileHandler).Methods("DELETE")
	webAPI.HandleFunc("/files/{id}/restore", restoreFileHandler).Methods("POST")
	webAPI.HandleFunc("/files/{id}/purge", purgeFileHandler).Methods("DELETE")

	// 回收站管理
	webAPI.HandleFunc("/recycle-bin", getRecycleBinHandler).Methods("GET")
	webAPI.HandleFunc("/recycle-bin/clear", clearRecycleBinHandler).Methods("DELETE")

	// 统一文件下载路由（需要Web认证）
	webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
	webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	// 日志查询路由（需要Web认证）
	webAPI.HandleFunc("/logs/access", getAccessLogsHandler).Methods("GET")

	// Packages (assets/others) web endpoints delegating to public handlers
	webAPI.HandleFunc("/packages/upload/assets-zip", func(w http.ResponseWriter, r *http.Request) {
		apiUploadAssetsZipHandler(w, r)
	}).Methods("POST")
	webAPI.HandleFunc("/packages/upload/others-zip", func(w http.ResponseWriter, r *http.Request) {
		apiUploadOthersZipHandler(w, r)
	}).Methods("POST")
	webAPI.HandleFunc("/packages", func(w http.ResponseWriter, r *http.Request) {
		apiListPackagesHandler(w, r)
	}).Methods("GET")
	webAPI.HandleFunc("/packages/{id}/remark", func(w http.ResponseWriter, r *http.Request) {
		apiUpdatePackageRemarkHandler(w, r)
	}).Methods("PATCH")

	// Admin web routes removed per requirements

		// =============================================================================
	// Public API Routes (require API key authentication) - 注册在更具体的路径
	// =============================================================================
	RegisterAPIRoutes(router)

	// =============================================================================
	// Admin API Routes (require admin authentication)
	// =============================================================================
	RegisterAdminRoutes(router)

	// =============================================================================
	// Static Files
	// =============================================================================

	// 静态文件服务路由
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// downloadFileHandler 统一文件下载处理器
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 从URL路径中提取文件路径
	filePath := strings.TrimPrefix(r.URL.Path, "/api/v1/web/files/")

	// 验证和清理路径
	if filePath == "" {
		writeErrorResponse(w, http.StatusBadRequest, "File path cannot be empty")
		return
	}

	// 防止路径遍历攻击
	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		writeErrorResponse(w, http.StatusBadRequest, "Invalid file path")
		return
	}

	// 构建完整的文件路径 - 注意这里不再添加downloads前缀，因为传入的路径已经包含了
	var fullPath string
	if strings.HasPrefix(filePath, "downloads/") {
		fullPath = filePath
	} else {
		fullPath = filepath.Join("downloads", filePath)
	}

	// 验证文件路径是否在允许的目录内
	if !isAllowedPath(fullPath) {
		writeErrorResponse(w, http.StatusForbidden, "File path not allowed")
		return
	}

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Printf("File not found: %s", fullPath)
		writeErrorResponse(w, http.StatusNotFound, "File not found")
		return
	}

	// 打开文件
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Error opening file %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "Cannot open file")
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "Cannot get file info")
		return
	}

	// 获取文件名
	fileName := filepath.Base(filePath)

	// 确定内容类型
	contentType := getContentType(fileName)

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 复制文件内容到响应
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Error writing file to response: %v", err)
		return
	}

	log.Printf("File %s downloaded successfully by %s", filePath, r.RemoteAddr)

	// 记录结构化下载日志
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

// apiInfoHandler API信息页面处理器 - 类似GitHub API根页面
func apiInfoHandler(w http.ResponseWriter, r *http.Request) {
	baseURL := "https://localhost:8443/api/v1"

	response := Response{
		Success: true,
		Message: "FileServer REST API Information",
		Data: map[string]interface{}{
			"name":        "FileServer REST API",
			"version":     "v1.0.0",
			"description": "A secure file server with user authentication and SSL support",
			"base_url":    baseURL,
			"documentation_url": baseURL + "/docs",
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
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"uptime":    "runtime dependent",
				"ssl_enabled": true,
				"golang_version": "go1.19+",
			},
		},
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSONResponse(w, http.StatusOK, response)
}

// healthCheckHandler 健康检查处理器
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := Response{
		Success: true,
		Message: "服务运行正常",
		Data: map[string]interface{}{
			"status":    "healthy",
			"timestamp": fmt.Sprintf("%d", time.Now().Unix()),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// writeJSONResponse 写入JSON响应
func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// writeErrorResponse 写入错误响应
func writeErrorResponse(w http.ResponseWriter, status int, message string) {
	response := Response{
		Success: false,
		Error:   message,
	}

	writeJSONResponse(w, status, response)
}

// loginHandler 用户登录处理器
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginReq auth.LoginRequest

	// 解析请求体
	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "请求格式错误")
		return
	}

	// 用户认证
	loginResp, err := auth.Authenticate(&loginReq)
	if err != nil {
		log.Printf("Login failed for user %s@%s: %v", loginReq.Username, loginReq.TenantID, err)

		// 记录登录失败日志
		if l := logger.GetLogger(); l != nil {
			l.LogUserLogin(loginReq.TenantID, loginReq.Username, r.RemoteAddr, false)
		}

		writeErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}

	log.Printf("User %s@%s logged in successfully", loginReq.Username, loginReq.TenantID)

	// 记录用户登录日志
	if l := logger.GetLogger(); l != nil {
		l.LogUserLogin(loginReq.TenantID, loginReq.Username, r.RemoteAddr, true)
	}

	// 返回登录成功响应
	response := Response{
		Success: true,
		Message: "登录成功",
		Data:    loginResp,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// logoutHandler 用户登出处理器
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// 获取Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		writeErrorResponse(w, http.StatusBadRequest, "缺少Authorization header")
		return
	}

	// 提取token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		writeErrorResponse(w, http.StatusBadRequest, "Authorization header格式错误")
		return
	}

	token := parts[1]

	// 执行登出
	if err := auth.Logout(token); err != nil {
		writeErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	log.Printf("User logged out successfully")

	response := Response{
		Success: true,
		Message: "登出成功",
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getDefaultUsersHandler 获取默认测试用户列表
func getDefaultUsersHandler(w http.ResponseWriter, r *http.Request) {
	users := auth.GetDefaultUsers()

	response := Response{
		Success: true,
		Message: "默认测试用户列表",
		Data: map[string]interface{}{
			"users": users,
			"note":  "这些是预设的测试用户，您可以使用这些账户进行登录测试",
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// isAllowedPath 验证文件路径是否在允许的目录内
func isAllowedPath(path string) bool {
	// 获取绝对路径
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}

	// 获取下载目录的绝对路径
	downloadDir, err := filepath.Abs("downloads")
	if err != nil {
		return false
	}

	// 检查路径是否在downloads目录下
	return strings.HasPrefix(absPath, downloadDir)
}

// getAccessLogsHandler 获取访问日志处理器
func getAccessLogsHandler(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // 默认限制
	offset := 0 // 默认偏移

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

	// 从数据库查询日志
	l := logger.GetLogger()
	if l == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "日志系统未初始化")
		return
	}

	logs, err := l.GetAccessLogs(limit, offset)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "查询日志失败")
		return
	}

	response := Response{
		Success: true,
		Message: "访问日志查询成功",
		Data: map[string]interface{}{
			"logs":   logs,
			"limit":  limit,
			"offset": offset,
			"count":  len(logs),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}



// FileUploadRequest 文件上传请求结构
type FileUploadRequest struct {
	FileType    string `form:"fileType" json:"fileType"`       // config, certificate, docs
	Description string `form:"description" json:"description"` // 文件描述
}

// FileInfo 文件信息结构
type FileInfo struct {
	ID          string    `json:"id"`
	FileName    string    `json:"fileName"`
	OriginalName string   `json:"originalName"`
	FileType    string    `json:"fileType"`
	Size        int64     `json:"size"`
	Description string    `json:"description"`
	UploadTime  time.Time `json:"uploadTime"`
	Version     int       `json:"version"`
	IsLatest    bool      `json:"isLatest"`
	Uploader    string    `json:"uploader"`
	Path        string    `json:"path"`
}

// uploadFileHandler 文件上传处理器
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
    // 解析multipart form（提高限额）
    err := r.ParseMultipartForm(128 << 20) // 128MB
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to parse form: "+err.Error())
		return
	}

	// 获取文件
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "Failed to get file: "+err.Error())
		return
	}
	defer file.Close()

	// 获取上传参数
	fileType := r.FormValue("fileType")
	description := r.FormValue("description")

	// 验证文件类型
	allowedTypes := map[string]bool{
		"roadmap":        true,
		"recommendation": true,
	}
	if !allowedTypes[fileType] {
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported file type")
		return
	}

    // 验证文件扩展名
    if !isValidFileExtension(header.Filename) {
		writeErrorResponse(w, http.StatusBadRequest, "Unsupported file format")
		return
	}

    // 进一步校验扩展名与类型匹配（roadmap->.tsv，recommendation->.xlsx）并设置固定原始名
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

    // 将上传的原始文件名记录在描述中，便于追溯
    if header.Filename != "" {
        if strings.TrimSpace(description) == "" {
            description = "Original filename: " + header.Filename
        } else if !strings.Contains(description, "Original filename:") {
            description = description + " | Original filename: " + header.Filename
        }
    }

	// 获取用户信息（从认证中间件设置的上下文中获取）
	var uploader string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			uploader = user.Username + "@" + user.TenantID
		} else {
			uploader = "unknown"
		}
	} else {
		uploader = "unknown"
	}

	// 创建文件信息
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

	// 生成版本化的文件名和路径
    versionedFileName, version, err := generateVersionedFileName(fileType, fixedOriginalName)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate filename: "+err.Error())
		return
	}

	fileInfo.FileName = versionedFileName
	fileInfo.Version = version
	fileInfo.IsLatest = true

	// 创建目标目录
	targetDir := filepath.Join("downloads", fileType+"s")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to create directory: "+err.Error())
		return
	}

	// 保存文件
	targetPath := filepath.Join(targetDir, versionedFileName)
	fileInfo.Path = targetPath

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

	// 更新最新版本链接
    latestPath := filepath.Join(targetDir, fixedOriginalName)
	os.Remove(latestPath) // 删除旧的链接（如果存在）

	// 创建硬链接指向最新版本
	if err := os.Link(targetPath, latestPath); err != nil {
		// 如果硬链接失败，复制文件
		if copyErr := copyFile(targetPath, latestPath); copyErr != nil {
			log.Printf("Warning: Failed to create latest version link: %v", copyErr)
		}
	}

	// Calculate checksum
	checksum, err := calculateFileChecksum(targetPath)
	if err != nil {
		log.Printf("Warning: Failed to calculate checksum: %v", err)
	}

	// Create database record
	db := database.GetDatabase()
	if db == nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Database not initialized")
		return
	}

    record := &database.FileRecord{
		ID:           fileInfo.ID,
		OriginalName: fixedOriginalName,
		VersionedName: versionedFileName,
		FileType:     fileType,
		FilePath:     targetPath,
		Size:         fileInfo.Size,
		Description:  description,
		Uploader:     uploader,
		UploadTime:   time.Now(),
		Version:      version,
		IsLatest:     true,
		Checksum:     checksum,
	}

	// Save to database
	if err := db.InsertFileRecord(record); err != nil {
		// If database save fails, try to clean up the file
		os.Remove(targetPath)
		os.Remove(latestPath)
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to save file metadata: "+err.Error())
		return
	}

	// Record upload log
	if l := logger.GetLogger(); l != nil {
		l.LogFileUpload(fileInfo.Path, uploader, fileInfo.Size, map[string]interface{}{
			"fileType":    fileType,
			"version":     version,
			"description": description,
		})
	}

	response := Response{
		Success: true,
		Message: "File uploaded successfully",
		Data:    fileInfo,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// listFilesHandler 文件列表处理器
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

// getFileVersionsHandler 获取文件版本处理器
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

// deleteFileHandler 删除文件（移动到回收站）
func deleteFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 获取用户信息
	var deletedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			deletedBy = user.Username + "@" + user.TenantID
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

// restoreFileHandler 从回收站恢复文件
func restoreFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 获取用户信息
	var restoredBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			restoredBy = user.Username + "@" + user.TenantID
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

// purgeFileHandler 永久删除文件
func purgeFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileID := vars["id"]

	// 获取用户信息
	var purgedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			purgedBy = user.Username + "@" + user.TenantID
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

// getRecycleBinHandler 获取回收站内容
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

// clearRecycleBinHandler 清空回收站
func clearRecycleBinHandler(w http.ResponseWriter, r *http.Request) {
	// 获取用户信息
	var purgedBy string
	if userCtx := r.Context().Value("user"); userCtx != nil {
		if user, ok := userCtx.(*auth.User); ok {
			purgedBy = user.Username + "@" + user.TenantID
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

	// 获取回收站中的所有项目
	items, err := db.GetRecycleBinItems()
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "Failed to get recycle bin items: "+err.Error())
		return
	}

	// 永久删除所有项目
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

// 辅助函数

// generateFileID 生成文件ID
func generateFileID() string {
	return fmt.Sprintf("file_%d_%d", time.Now().UnixNano(), os.Getpid())
}

// generateVersionedFileName 生成版本化的文件名
func generateVersionedFileName(fileType, originalName string) (string, int, error) {
	// 从数据库获取现有版本号
	db := database.GetDatabase()
	if db == nil {
		return "", 0, fmt.Errorf("database not initialized")
	}

	// 查询数据库中同名文件的最大版本号
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

	// 新版本号
	version := maxVersion + 1

	// 生成版本化文件名
	ext := filepath.Ext(originalName)
	baseName := strings.TrimSuffix(originalName, ext)
	versionedName := fmt.Sprintf("%s_v%d%s", baseName, version, ext)

	return versionedName, version, nil
}

// isValidFileExtension 验证文件扩展名
func isValidFileExtension(filename string) bool {
    ext := strings.ToLower(filepath.Ext(filename))
    validExts := map[string]bool{
        ".tsv":  true, // Roadmap
        ".xlsx": true, // Recommendation
    }
    return validExts[ext]
}

// copyFile 复制文件
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



// getContentType 根据文件扩展名确定内容类型
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
