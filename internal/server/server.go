package server

import (
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
	router.Use(middleware.LoggingMiddleware) // 结构化日志记录
	router.Use(middleware.CorsMiddleware)    // CORS处理
	router.Use(middleware.AuthMiddleware)    // 身份认证

	return &Server{
		Router: router,
	}
}

