package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
)

// TwoFAVerificationMiddleware checks if user needs to complete 2FA verification
func TwoFAVerificationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Skip 2FA verification check for certain endpoints
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
			// Check if user needs 2FA verification
			if db := database.GetDatabase(); db != nil {
				if appUser, err := db.GetUser(pid); err == nil && appUser != nil {
					// If user has 2FA enabled and has TOTP secret, they need verification
					if appUser.TwoFAEnabled && appUser.TOTPSecret != "" {
						// Check if 2FA verification is completed in this session
						if !is2FAVerified(r) {
							write2FAVerificationRequiredResponse(w)
							return
						}
					}
				}
			}
		}

		next.ServeHTTP(w, r)
	})
}

// is2FAVerified checks if 2FA verification is completed in the current session
func is2FAVerified(r *http.Request) bool {
	// Check if 2FA verification flag is set in session
	if verified, ok := ab.GetSession(r, "2fa_verified"); ok {
		return verified == "true"
	}
	// Also check Authboss TOTP verification status
	if verified, ok := ab.GetSession(r, ab.Session2FA); ok {
		return verified == "totp"
	}
	return false
}

// write2FAVerificationRequiredResponse writes a response indicating 2FA verification is required
func write2FAVerificationRequiredResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "2fa verification required",
		"code":    "2FA_VERIFICATION_REQUIRED",
		"message": "Please enter your 2FA verification code to continue.",
	})
}