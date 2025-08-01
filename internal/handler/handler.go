package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"secure-file-hub/internal/auth"
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

// FileMetadata 文件元数据结构
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

// 全局文件元数据存储
var (
	fileMetadataStore = make(map[string]FileMetadata) // key: 文件路径
	metadataMutex     sync.RWMutex
	metadataFile      = "downloads/metadata.json"
)

// 元数据管理函数

// initMetadata 初始化元数据存储
func initMetadata() {
	loadMetadata()
	// 如果元数据为空，尝试迁移现有文件
	if len(fileMetadataStore) == 0 {
		migrateExistingFiles()
	}
}

// migrateExistingFiles 迁移现有文件到元数据系统
func migrateExistingFiles() {
	log.Println("Migrating existing files to metadata system...")

	types := []string{"config", "certificate", "docs"}
	for _, fileType := range types {
		baseDir := filepath.Join("downloads", fileType+"s")

		if _, err := os.Stat(baseDir); os.IsNotExist(err) {
			continue
		}

		filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !isValidFileExtension(info.Name()) {
				return nil
			}

			relPath, _ := filepath.Rel("downloads", path)
			fileName := info.Name()

			// 跳过已经有元数据的文件
			if _, exists := getFileMetadata(relPath); exists {
				return nil
			}

			// 判断是否为版本化文件
			var originalName string
			var version int
			if strings.Contains(fileName, "_v") {
				// 提取原始文件名和版本号
				parts := strings.Split(fileName, "_v")
				if len(parts) >= 2 {
					originalName = parts[0] + filepath.Ext(fileName)
					// 简单提取版本号
					versionStr := strings.TrimSuffix(parts[1], filepath.Ext(fileName))
					if v, parseErr := strconv.Atoi(versionStr); parseErr == nil {
						version = v
					} else {
						version = 1
					}
				} else {
					originalName = fileName
					version = 1
				}
			} else {
				originalName = fileName
				version = 0 // 最新版本标记
			}

			// 创建迁移的元数据
			metadata := FileMetadata{
				ID:           generateFileID(),
				OriginalName: originalName,
				FileType:     fileType,
				Description:  "历史文件（系统迁移）",
				Uploader:     "system",
				UploadTime:   info.ModTime(),
				Version:      version,
				VersionedName: fileName,
			}

			// 保存元数据
			metadataMutex.Lock()
			fileMetadataStore[relPath] = metadata
			metadataMutex.Unlock()

			log.Printf("Migrated file: %s (version %d)", relPath, version)
			return nil
		})
	}

	// 保存迁移后的元数据
	saveMetadata()
	log.Println("File migration completed")
}

// loadMetadata 从文件加载元数据
func loadMetadata() {
	metadataMutex.Lock()
	defer metadataMutex.Unlock()

	if _, err := os.Stat(metadataFile); os.IsNotExist(err) {
		// 元数据文件不存在，创建空存储
		fileMetadataStore = make(map[string]FileMetadata)
		return
	}

	data, err := os.ReadFile(metadataFile)
	if err != nil {
		log.Printf("Warning: Failed to read metadata file: %v", err)
		fileMetadataStore = make(map[string]FileMetadata)
		return
	}

	if err := json.Unmarshal(data, &fileMetadataStore); err != nil {
		log.Printf("Warning: Failed to parse metadata file: %v", err)
		fileMetadataStore = make(map[string]FileMetadata)
		return
	}
}

// saveMetadata 保存元数据到文件（调用时应已持有锁）
func saveMetadataLocked() {
	data, err := json.MarshalIndent(fileMetadataStore, "", "  ")
	if err != nil {
		log.Printf("Error marshaling metadata: %v", err)
		return
	}

	// 确保目录存在
	os.MkdirAll(filepath.Dir(metadataFile), 0755)

	if err := os.WriteFile(metadataFile, data, 0644); err != nil {
		log.Printf("Error saving metadata: %v", err)
	}
}

// saveMetadata 保存元数据到文件（安全版本，会获取锁）
func saveMetadata() {
	metadataMutex.RLock()
	defer metadataMutex.RUnlock()
	saveMetadataLocked()
}

// addFileMetadata 添加文件元数据
func addFileMetadata(path string, metadata FileMetadata) {
	metadataMutex.Lock()
	fileMetadataStore[path] = metadata
	saveMetadataLocked() // 直接调用不需要锁的版本
	metadataMutex.Unlock()
}

// getFileMetadata 获取文件元数据
func getFileMetadata(path string) (FileMetadata, bool) {
	metadataMutex.RLock()
	defer metadataMutex.RUnlock()
	metadata, exists := fileMetadataStore[path]
	return metadata, exists
}

// updateLatestVersion 更新最新版本的元数据
func updateLatestVersion(fileType, originalName string, newMetadata FileMetadata) {
	metadataMutex.Lock()
	defer metadataMutex.Unlock()

	// 找到同名文件的所有版本，更新最新版本的链接文件元数据
	latestPath := filepath.Join(fileType+"s", originalName)
	fileMetadataStore[latestPath] = FileMetadata{
		ID:           newMetadata.ID,
		OriginalName: newMetadata.OriginalName,
		FileType:     newMetadata.FileType,
		Description:  newMetadata.Description,
		Uploader:     newMetadata.Uploader,
		UploadTime:   newMetadata.UploadTime,
		Version:      newMetadata.Version,
		VersionedName: newMetadata.VersionedName,
	}

	saveMetadataLocked() // 使用不需要锁的版本
}

// RegisterRoutes 注册所有路由
func RegisterRoutes(router *mux.Router) {
	// 初始化元数据存储
	initMetadata()
	// API版本前缀
	api := router.PathPrefix("/api/v1").Subrouter()

	// 认证相关路由（无需认证）
	api.HandleFunc("/auth/login", loginHandler).Methods("POST")
	api.HandleFunc("/auth/logout", logoutHandler).Methods("POST")
	api.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")

	// API根信息页面（无需认证）
	api.HandleFunc("", apiInfoHandler).Methods("GET")
	api.HandleFunc("/", apiInfoHandler).Methods("GET")

	// 健康检查路由（无需认证）
	api.HandleFunc("/health", healthCheckHandler).Methods("GET")

	// 文件上传路由（需要认证）
	api.HandleFunc("/upload", uploadFileHandler).Methods("POST")
	api.HandleFunc("/files/list", listFilesHandler).Methods("GET")
	api.HandleFunc("/files/versions/{type}/{filename}", getFileVersionsHandler).Methods("GET")

	// 统一文件下载路由（需要认证）
	filesRouter := api.PathPrefix("/files").Subrouter()
	filesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

	// 日志查询路由（需要认证）
	api.HandleFunc("/logs/access", getAccessLogsHandler).Methods("GET")
	api.HandleFunc("/logs/system", getSystemLogsHandler).Methods("GET")

	// 静态文件服务路由（可选）
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// downloadFileHandler 统一文件下载处理器
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	// 从URL路径中提取文件路径
	filePath := strings.TrimPrefix(r.URL.Path, "/api/v1/files/")

	// 验证和清理路径
	if filePath == "" {
		writeErrorResponse(w, http.StatusBadRequest, "文件路径不能为空")
		return
	}

	// 防止路径遍历攻击
	if strings.Contains(filePath, "..") || strings.HasPrefix(filePath, "/") {
		writeErrorResponse(w, http.StatusBadRequest, "无效的文件路径")
		return
	}

	// 构建完整的文件路径
	fullPath := filepath.Join("downloads", filePath)

	// 验证文件路径是否在允许的目录内
	if !isAllowedPath(fullPath) {
		writeErrorResponse(w, http.StatusForbidden, "文件路径不在允许的目录内")
		return
	}

	// 检查文件是否存在
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		log.Printf("File not found: %s", fullPath)
		writeErrorResponse(w, http.StatusNotFound, "文件未找到")
		return
	}

	// 打开文件
	file, err := os.Open(fullPath)
	if err != nil {
		log.Printf("Error opening file %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法打开文件")
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", fullPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法获取文件信息")
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

// getSystemLogsHandler 获取系统日志处理器
func getSystemLogsHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: 从SQLite数据库查询系统日志
	response := Response{
		Success: true,
		Message: "系统日志查询功能即将推出",
		Data: map[string]interface{}{
			"note": "此功能正在开发中，将从SQLite数据库查询结构化日志",
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
	// 解析multipart form
	err := r.ParseMultipartForm(32 << 20) // 32MB
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "解析表单失败: "+err.Error())
		return
	}

	// 获取文件
	file, header, err := r.FormFile("file")
	if err != nil {
		writeErrorResponse(w, http.StatusBadRequest, "获取文件失败: "+err.Error())
		return
	}
	defer file.Close()

	// 获取上传参数
	fileType := r.FormValue("fileType")
	description := r.FormValue("description")

	// 验证文件类型
	allowedTypes := map[string]bool{
		"config":      true,
		"certificate": true,
		"docs":        true,
	}
	if !allowedTypes[fileType] {
		writeErrorResponse(w, http.StatusBadRequest, "不支持的文件类型")
		return
	}

	// 验证文件扩展名
	if !isValidFileExtension(header.Filename) {
		writeErrorResponse(w, http.StatusBadRequest, "不支持的文件格式")
		return
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
		OriginalName: header.Filename,
		FileType:     fileType,
		Size:         header.Size,
		Description:  description,
		UploadTime:   time.Now(),
		Uploader:     uploader,
	}

	// 生成版本化的文件名和路径
	versionedFileName, version, err := generateVersionedFileName(fileType, header.Filename)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "生成文件名失败: "+err.Error())
		return
	}

	fileInfo.FileName = versionedFileName
	fileInfo.Version = version
	fileInfo.IsLatest = true

	// 创建目标目录
	targetDir := filepath.Join("downloads", fileType+"s")
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "创建目录失败: "+err.Error())
		return
	}

	// 保存文件
	targetPath := filepath.Join(targetDir, versionedFileName)
	fileInfo.Path = targetPath

	dst, err := os.Create(targetPath)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "创建文件失败: "+err.Error())
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "保存文件失败: "+err.Error())
		return
	}

	// 更新最新版本链接
	latestPath := filepath.Join(targetDir, header.Filename)
	os.Remove(latestPath) // 删除旧的链接（如果存在）

	// 创建硬链接指向最新版本
	if err := os.Link(targetPath, latestPath); err != nil {
		// 如果硬链接失败，复制文件
		if copyErr := copyFile(targetPath, latestPath); copyErr != nil {
			log.Printf("Warning: Failed to create latest version link: %v", copyErr)
		}
	}

	// 保存文件元数据
	metadata := FileMetadata{
		ID:           fileInfo.ID,
		OriginalName: header.Filename,
		FileType:     fileType,
		Description:  description,
		Uploader:     uploader,
		UploadTime:   time.Now(),
		Version:      version,
		VersionedName: versionedFileName,
	}

	// 保存版本化文件的元数据
	versionedPath := filepath.Join(fileType+"s", versionedFileName)
	addFileMetadata(versionedPath, metadata)

	// 更新最新版本的元数据
	updateLatestVersion(fileType, header.Filename, metadata)

	// 记录上传日志
	if l := logger.GetLogger(); l != nil {
		l.LogFileUpload(fileInfo.Path, uploader, fileInfo.Size, map[string]interface{}{
			"fileType":    fileType,
			"version":     version,
			"description": description,
		})
	}

	response := Response{
		Success: true,
		Message: "文件上传成功",
		Data:    fileInfo,
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// listFilesHandler 文件列表处理器
func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	fileType := r.URL.Query().Get("type")

	var files []FileInfo
	var err error

	if fileType != "" {
		files, err = getFilesByType(fileType)
	} else {
		files, err = getAllFiles()
	}

	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "获取文件列表失败: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "获取文件列表成功",
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

	versions, err := getFileVersions(fileType, filename)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "获取文件版本失败: "+err.Error())
		return
	}

	response := Response{
		Success: true,
		Message: "获取文件版本成功",
		Data: map[string]interface{}{
			"versions": versions,
			"count":    len(versions),
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// 辅助函数

// generateFileID 生成文件ID
func generateFileID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// generateVersionedFileName 生成版本化的文件名
func generateVersionedFileName(fileType, originalName string) (string, int, error) {
	baseDir := filepath.Join("downloads", fileType+"s")

	// 获取现有版本号
	version := 1
	pattern := fmt.Sprintf("%s_v*%s", strings.TrimSuffix(originalName, filepath.Ext(originalName)), filepath.Ext(originalName))

	if files, err := filepath.Glob(filepath.Join(baseDir, pattern)); err == nil {
		version = len(files) + 1
	}

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
		".json": true,
		".crt":  true,
		".key":  true,
		".pem":  true,
		".txt":  true,
		".log":  true,
		".zip":  true,
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

// getFilesByType 根据类型获取文件列表
func getFilesByType(fileType string) ([]FileInfo, error) {
	var files []FileInfo
	metadataMutex.RLock()
	defer metadataMutex.RUnlock()

	// 从元数据中找到指定类型的文件，只显示最新版本（非版本化的文件名）
	for path, metadata := range fileMetadataStore {
		if metadata.FileType == fileType && !strings.Contains(filepath.Base(path), "_v") {
			// 这是最新版本的文件
			fullPath := filepath.Join("downloads", path)

			// 检查文件是否存在
			if info, err := os.Stat(fullPath); err == nil {
				fileInfo := FileInfo{
					ID:           metadata.ID,
					FileName:     filepath.Base(path),
					OriginalName: metadata.OriginalName,
					FileType:     metadata.FileType,
					Size:         info.Size(),
					Description:  metadata.Description,
					UploadTime:   metadata.UploadTime,
					Version:      metadata.Version,
					IsLatest:     true,
					Uploader:     metadata.Uploader,
					Path:         path,
				}
				files = append(files, fileInfo)
			}
		}
	}

	// 按上传时间倒序排序
	sort.Slice(files, func(i, j int) bool {
		return files[i].UploadTime.After(files[j].UploadTime)
	})

	return files, nil
}

// getAllFiles 获取所有文件
func getAllFiles() ([]FileInfo, error) {
	var allFiles []FileInfo

	types := []string{"config", "certificate", "docs"}
	for _, fileType := range types {
		files, err := getFilesByType(fileType)
		if err != nil {
			return nil, err
		}
		allFiles = append(allFiles, files...)
	}

	return allFiles, nil
}

// getFileVersions 获取文件版本列表
func getFileVersions(fileType, filename string) ([]FileInfo, error) {
	var versions []FileInfo
	metadataMutex.RLock()
	defer metadataMutex.RUnlock()

	// 从元数据中找到指定文件的所有版本
	for path, metadata := range fileMetadataStore {
		if metadata.FileType == fileType && metadata.OriginalName == filename {
			fullPath := filepath.Join("downloads", path)

			// 检查文件是否存在
			if info, err := os.Stat(fullPath); err == nil {
				// 判断是否为最新版本（非版本化文件名）
				isLatest := !strings.Contains(filepath.Base(path), "_v")

				fileInfo := FileInfo{
					ID:           metadata.ID,
					FileName:     filepath.Base(path),
					OriginalName: metadata.OriginalName,
					FileType:     metadata.FileType,
					Size:         info.Size(),
					Description:  metadata.Description,
					UploadTime:   metadata.UploadTime,
					Version:      metadata.Version,
					IsLatest:     isLatest,
					Uploader:     metadata.Uploader,
					Path:         path,
				}
				versions = append(versions, fileInfo)
			}
		}
	}

	// 按版本号倒序排序（最新版本在前）
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version > versions[j].Version
	})

	return versions, nil
}

// getContentType 根据文件扩展名确定内容类型
func getContentType(fileName string) string {
	ext := filepath.Ext(fileName)
	switch ext {
	case ".json":
		return "application/json"
	case ".crt", ".pem":
		return "application/x-x509-ca-cert"
	case ".key":
		return "application/pkcs8"
	case ".txt":
		return "text/plain"
	case ".log":
		return "text/plain"
	default:
		return "application/octet-stream"
	}
}