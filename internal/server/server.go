package server

import (
	"secure-file-hub/internal/middleware"

	"github.com/gorilla/mux"
)

// Server represents the HTTP server with configured middleware
type Server struct {
	Router *mux.Router
}

// New creates a new server instance and attaches middlewares
func New() *Server {
	router := mux.NewRouter()

	// Order matters: HTTPS redirect, CORS (preflight), Logging, then Auth
	router.Use(middleware.HTTPSRedirectMiddleware)
	router.Use(middleware.CorsMiddleware)
	router.Use(middleware.LoggingMiddleware)
	router.Use(middleware.AuthMiddleware)

	return &Server{
		Router: router,
	}
}
