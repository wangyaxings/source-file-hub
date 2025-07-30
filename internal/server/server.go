package server

import (
	"log"
	"net/http"
	"time"

	"fileserver/internal/middleware"
	"github.com/gorilla/mux"
)

// Server 代表HTTP服务器
type Server struct {
	Router *mux.Router
}

// New 创建新的服务器实例
func New() *Server {
	router := mux.NewRouter()
	
	// 添加中间件（顺序很重要）
	router.Use(loggingMiddleware)
	router.Use(corsMiddleware)
	router.Use(middleware.AuthMiddleware) // 认证中间件
	
	return &Server{
		Router: router,
	}
}

// loggingMiddleware 日志中间件
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
	})
}

// corsMiddleware CORS中间件
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}