package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
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

		// Public endpoints: health, default users, public API, static files, and authboss endpoints
		if path == "/api/v1/health" || path == "/api/v1/healthz" ||
			path == "/api/v1/web/health" || path == "/api/v1/web/healthz" ||
			strings.HasPrefix(path, "/static/") ||
			// Allow Authboss endpoints under /auth/ab/* without session
			strings.HasPrefix(path, "/api/v1/web/auth/ab/") ||
			// Allow default users endpoint (for frontend login page)
			strings.Contains(path, "/auth/users") ||
			strings.Contains(path, "/api/v1/public") {
			next.ServeHTTP(w, r)
			return
		}

		// Use Authboss session instead of Authorization header
		if pid, ok := ab.GetSession(r, ab.SessionKey); ok && pid != "" {
			// Load user from DB
			var user *auth.User
			if db := database.GetDatabase(); db != nil {
				if au, err := db.GetUser(pid); err == nil && au != nil {
					// Check user status
					userRole, roleErr := db.GetUserRole(pid)
					if roleErr != nil {
						log.Printf("Warning: Failed to get user role for %s: %v", pid, roleErr)
					} else if userRole != nil {
						log.Printf("User %s has role status: %s", pid, userRole.Status)
						if userRole.Status == "suspended" {
							writeUnauthorizedResponse(w, "ACCOUNT_SUSPENDED")
							return
						}
						// Allow pending users to access basic functionality
						// They will be restricted by authorization middleware based on their role
					}

					user = &auth.User{Username: au.Username, Role: au.Role, Email: au.Email, TwoFAEnabled: au.TwoFAEnabled}
					// Note: Password reset is now handled by authboss
					// No need to check MustReset flag here
				} else {
					log.Printf("Warning: Failed to get user %s from database: %v", pid, err)
				}
			}
			if user == nil {
				log.Printf("Warning: User %s not found in database", pid)
				writeUnauthorizedResponse(w, "User not found")
				return
			}
			ctx := context.WithValue(r.Context(), "user", user)
			r = r.WithContext(ctx)
			w.Header().Set("X-User-Username", user.Username)
			next.ServeHTTP(w, r)
			return
		}

		writeUnauthorizedResponse(w, "Authentication required")
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
