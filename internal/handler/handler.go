package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"fileserver/internal/auth"
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
	
	// 健康检查路由（无需认证）
	api.HandleFunc("/health", healthCheckHandler).Methods("GET")
	
	// 需要认证的路由
	api.HandleFunc("/config/download", downloadConfigHandler).Methods("GET")
	
	// 静态文件服务路由（可选）
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}

// downloadConfigHandler 下载配置文件处理器
func downloadConfigHandler(w http.ResponseWriter, r *http.Request) {
	configPath := "configs/config.json"

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Config file not found: %s", configPath)
		writeErrorResponse(w, http.StatusNotFound, "配置文件未找到")
		return
	}

	// 打开文件
	file, err := os.Open(configPath)
	if err != nil {
		log.Printf("Error opening config file: %v", err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法打开配置文件")
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info: %v", err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法获取文件信息")
		return
	}

	// 设置响应头
	w.Header().Set("Content-Disposition", "attachment; filename=\"config.json\"")
	w.Header().Set("Content-Type", "application/json")
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

	log.Printf("Config file downloaded successfully by %s", r.RemoteAddr)
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
		writeErrorResponse(w, http.StatusUnauthorized, err.Error())
		return
	}
	
	log.Printf("User %s@%s logged in successfully", loginReq.Username, loginReq.TenantID)
	
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