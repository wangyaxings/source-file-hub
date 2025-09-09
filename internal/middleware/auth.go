package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"secure-file-hub/internal/auth"
)

// AuthMiddleware handles authentication and exposes public routes
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Always allow CORS preflight
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// Public endpoints: health, login, default users, public API, and static files
		if path == "/api/v1/health" || path == "/api/v1/healthz" ||
			path == "/api/v1/web/health" || path == "/api/v1/web/healthz" ||
			strings.HasPrefix(path, "/static/") ||
			strings.Contains(path, "/auth/login") ||
			strings.Contains(path, "/auth/users") ||
			strings.Contains(path, "/api/v1/public") {
			next.ServeHTTP(w, r)
			return
		}

		// Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeUnauthorizedResponse(w, "Missing Authorization header")
			return
		}

		// Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeUnauthorizedResponse(w, "Invalid Authorization header format, should be: Bearer <token>")
			return
		}
		token := parts[1]

		// Validate token
		user, err := auth.ValidateToken(token)
		if err != nil {
			writeUnauthorizedResponse(w, err.Error())
			return
		}

		// Attach user to context
		ctx := context.WithValue(r.Context(), "user", user)
		r = r.WithContext(ctx)

		// Helpful debug headers
		w.Header().Set("X-User-Username", user.Username)

		next.ServeHTTP(w, r)
	})
}

// writeUnauthorizedResponse writes an unauthorized response payload
func writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    "UNAUTHORIZED",
	})
}

// writeHealthResponse responds with a structured health payload suitable for Operation Center
// Note: health response is produced by handler; middleware only bypasses auth.
