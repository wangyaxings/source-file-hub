package handler

import (
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

// RegisterRoutes 注册所有路由
func RegisterRoutes(router *mux.Router) {
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