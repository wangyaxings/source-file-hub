package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

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
	
	// 配置文件下载路由
	api.HandleFunc("/config/download", downloadConfigHandler).Methods("GET")
	
	// 健康检查路由
	api.HandleFunc("/health", healthCheckHandler).Methods("GET")
	
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