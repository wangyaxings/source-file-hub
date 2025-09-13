package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
)

// TwoFASetupMiddleware checks if user needs to complete 2FA setup
func TwoFASetupMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip 2FA setup check for certain endpoints
		if strings.HasPrefix(path, "/api/v1/web/auth/ab/") ||
			strings.Contains(path, "/auth/2fa/") ||
			strings.Contains(path, "/auth/me") ||
			strings.Contains(path, "/health") ||
			strings.Contains(path, "/static/") ||
			strings.Contains(path, "/admin/") ||
			strings.Contains(path, "2fa/totp") {
			next.ServeHTTP(w, r)
			return
		}

		// Check if user is authenticated via authboss session
		if pid, ok := ab.GetSession(r, ab.SessionKey); ok && pid != "" {
			// Check if user needs 2FA setup
			if db := database.GetDatabase(); db != nil {
				if appUser, err := db.GetUser(pid); err == nil && appUser != nil {
					// If user has 2FA enabled but no TOTP secret, they need to complete setup
					if appUser.TwoFAEnabled && appUser.TOTPSecret == "" {
						write2FASetupRequiredResponse(w)
						return
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// write2FASetupRequiredResponse writes a response indicating 2FA setup is required
func write2FASetupRequiredResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "2fa setup required",
		"code":    "2FA_SETUP_REQUIRED",
		"message": "Your account has 2FA enabled. Please complete the setup first.",
	})
}
