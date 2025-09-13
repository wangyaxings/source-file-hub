package server

import (
	"log"
	"net/http"
	"secure-file-hub/internal/auth"
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

	// Initialize Authboss and mount routes under /api/v1/web/auth/ab to avoid collisions
    if ab, err := auth.InitAuthboss(); err == nil && ab != nil {
        // Mount Authboss router with proper path stripping BEFORE other middleware
        router.PathPrefix("/api/v1/web/auth/ab").Handler(
            http.StripPrefix("/api/v1/web/auth/ab", ab.Config.Core.Router),
        )
        router.Use(func(next http.Handler) http.Handler { return ab.LoadClientStateMiddleware(next) })
        log.Printf("Authboss initialized and mounted at /api/v1/web/auth/ab")
    } else {
        log.Printf("Warning: Failed to initialize Authboss: %v", err)
    }

    // Our auth middleware now relies on Authboss session
    router.Use(middleware.AuthMiddleware)

    // Provide JSON shim for Authboss TOTP endpoints (setup/confirm)
    router.Use(middleware.TOTPJSONShimMiddleware)

    // Add 2FA setup middleware to check if user needs to complete 2FA setup
    router.Use(middleware.TwoFASetupMiddleware)

    // Add 2FA verification middleware to check if user needs to complete 2FA verification
    router.Use(middleware.TwoFAVerificationMiddleware)

	return &Server{
		Router: router,
	}
}
