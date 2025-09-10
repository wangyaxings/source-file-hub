package middleware

import (
    "context"
    "encoding/json"
    "net/http"
    "strings"

    ab "github.com/aarondl/authboss/v3"
    "secure-file-hub/internal/auth"
    "secure-file-hub/internal/database"
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
            strings.HasPrefix(path, "/api/v1/web/auth/") ||
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
                    user = &auth.User{Username: au.Username, Role: au.Role, Email: au.Email, TwoFAEnabled: au.TwoFAEnabled}
                    // Enforce must reset password if flagged
                    if au.MustReset {
                        // Allow change-password and auth endpoints
                        if !(strings.HasPrefix(path, "/api/v1/web/auth/change-password") || strings.HasPrefix(path, "/api/v1/web/auth")) {
                            writeUnauthorizedResponse(w, "PASSWORD_RESET_REQUIRED")
                            return
                        }
                    }
                }
            }
            if user == nil {
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
        return

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
