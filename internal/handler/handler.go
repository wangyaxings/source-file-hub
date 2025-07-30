package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
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

	// 证书相关路由（RESTful API）
	certificatesRouter := api.PathPrefix("/certificates").Subrouter()
	certificatesRouter.HandleFunc("", listCertificatesHandler).Methods("GET")
	certificatesRouter.HandleFunc("/{cert_name}", getCertificateHandler).Methods("GET")
	certificatesRouter.HandleFunc("/{cert_name}/info", getCertificateInfoHandler).Methods("GET")

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

// listCertificatesHandler 列出所有可用的证书（RESTful API）
func listCertificatesHandler(w http.ResponseWriter, r *http.Request) {
	certDir := "certs"

	// 检查证书目录是否存在
	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		writeErrorResponse(w, http.StatusNotFound, "证书目录不存在")
		return
	}

	// 读取证书目录
	files, err := os.ReadDir(certDir)
	if err != nil {
		log.Printf("Error reading certificates directory: %v", err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法读取证书目录")
		return
	}

	// 构建证书列表
	certificates := []map[string]interface{}{}

	for _, file := range files {
		if !file.IsDir() {
			fileName := file.Name()
			fileExt := filepath.Ext(fileName)

			cert := map[string]interface{}{
				"name": fileName,
				"type": getCertificateType(fileExt),
				"download_url": fmt.Sprintf("/api/v1/certificates/%s", fileName),
			}

			// 如果是证书文件，添加信息链接
			if fileExt == ".crt" || fileExt == ".pem" {
				cert["info_url"] = fmt.Sprintf("/api/v1/certificates/%s/info", fileName)
			}

			certificates = append(certificates, cert)
		}
	}

	response := Response{
		Success: true,
		Message: "证书列表获取成功",
		Data: map[string]interface{}{
			"total_count": len(certificates),
			"certificates": certificates,
			"directory": certDir,
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getCertificateHandler 下载指定的证书文件（RESTful API）
func getCertificateHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certName := vars["cert_name"]

	if certName == "" {
		writeErrorResponse(w, http.StatusBadRequest, "证书名称不能为空")
		return
	}

	// 验证文件名，防止路径遍历攻击
	if strings.Contains(certName, "..") || strings.Contains(certName, "/") || strings.Contains(certName, "\\") {
		writeErrorResponse(w, http.StatusBadRequest, "无效的证书名称")
		return
	}

	certPath := filepath.Join("certs", certName)

	// 检查文件是否存在
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		writeErrorResponse(w, http.StatusNotFound, "证书文件不存在")
		return
	}

	// 打开文件
	file, err := os.Open(certPath)
	if err != nil {
		log.Printf("Error opening certificate file %s: %v", certPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法打开证书文件")
		return
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		log.Printf("Error getting file info for %s: %v", certPath, err)
		writeErrorResponse(w, http.StatusInternalServerError, "无法获取文件信息")
		return
	}

	// 确定内容类型
	contentType := getCertificateContentType(filepath.Ext(certName))

	// 设置响应头
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", certName))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileInfo.Size()))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// 复制文件内容到响应
	_, err = io.Copy(w, file)
	if err != nil {
		log.Printf("Error writing certificate file to response: %v", err)
		return
	}

	log.Printf("Certificate %s downloaded successfully by %s", certName, r.RemoteAddr)
}

// getCertificateInfoHandler 获取证书信息（RESTful API）
func getCertificateInfoHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	certName := vars["cert_name"]

	if certName == "" {
		writeErrorResponse(w, http.StatusBadRequest, "证书名称不能为空")
		return
	}

	// 验证文件名
	if strings.Contains(certName, "..") || strings.Contains(certName, "/") || strings.Contains(certName, "\\") {
		writeErrorResponse(w, http.StatusBadRequest, "无效的证书名称")
		return
	}

	// 检查是否为证书文件
	ext := filepath.Ext(certName)
	if ext != ".crt" && ext != ".pem" {
		writeErrorResponse(w, http.StatusBadRequest, "只能查看证书文件(.crt, .pem)的信息")
		return
	}

	// 先检查对应的info文件是否存在
	infoPath := filepath.Join("certs", "cert_info.json")
	if _, err := os.Stat(infoPath); err == nil {
		// 读取JSON格式的证书信息
		infoFile, err := os.Open(infoPath)
		if err != nil {
			log.Printf("Error opening certificate info file: %v", err)
			writeErrorResponse(w, http.StatusInternalServerError, "无法读取证书信息")
			return
		}
		defer infoFile.Close()

		var certInfo map[string]interface{}
		if err := json.NewDecoder(infoFile).Decode(&certInfo); err != nil {
			log.Printf("Error decoding certificate info: %v", err)
			writeErrorResponse(w, http.StatusInternalServerError, "证书信息格式错误")
			return
		}

		response := Response{
			Success: true,
			Message: "证书信息获取成功",
			Data: map[string]interface{}{
				"certificate_name": certName,
				"certificate_info": certInfo,
			},
		}

		writeJSONResponse(w, http.StatusOK, response)
		return
	}

	// 如果没有info文件，返回基本信息
	certPath := filepath.Join("certs", certName)
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		writeErrorResponse(w, http.StatusNotFound, "证书文件不存在")
		return
	}

	fileInfo, err := os.Stat(certPath)
	if err != nil {
		writeErrorResponse(w, http.StatusInternalServerError, "无法获取文件信息")
		return
	}

	basicInfo := map[string]interface{}{
		"name": certName,
		"size": fileInfo.Size(),
		"modified_time": fileInfo.ModTime().Format(time.RFC3339),
		"type": getCertificateType(ext),
	}

	response := Response{
		Success: true,
		Message: "证书基本信息获取成功",
		Data: map[string]interface{}{
			"certificate_name": certName,
			"basic_info": basicInfo,
			"note": "详细的证书信息需要cert_info.json文件",
		},
	}

	writeJSONResponse(w, http.StatusOK, response)
}

// getCertificateType 根据文件扩展名确定证书类型
func getCertificateType(ext string) string {
	switch ext {
	case ".crt":
		return "X.509 Certificate"
	case ".key":
		return "Private Key"
	case ".pem":
		return "PEM Certificate"
	case ".json":
		return "Certificate Information"
	default:
		return "Unknown"
	}
}

// getCertificateContentType 根据文件扩展名确定内容类型
func getCertificateContentType(ext string) string {
	switch ext {
	case ".crt", ".pem":
		return "application/x-x509-ca-cert"
	case ".key":
		return "application/pkcs8"
	case ".json":
		return "application/json"
	default:
		return "application/octet-stream"
	}
}