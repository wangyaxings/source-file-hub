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
		if shouldSkip2FACheck(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		if requires2FAVerification(r) {
			write2FAVerificationRequiredResponse(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func shouldSkip2FACheck(path string) bool {
	skipPaths := []string{
		"/api/v1/web/auth/ab/",
		"/auth/2fa/",
		"/auth/me",
		"/health",
		"/static/",
		"/admin/",
		"2fa/totp",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) || strings.Contains(path, skipPath) {
			return true
		}
	}
	return false
}

func requires2FAVerification(r *http.Request) bool {
	pid, ok := ab.GetSession(r, ab.SessionKey)
	if !ok || pid == "" {
		return false
	}

	user, err := getUserFromDatabase(pid)
	if err != nil || user == nil {
		return false
	}

	return userNeeds2FAVerification(user, r)
}

func getUserFromDatabase(pid string) (*database.AppUser, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, nil
	}
	return db.GetUser(pid)
}

func userNeeds2FAVerification(user *database.AppUser, r *http.Request) bool {
	if !user.TwoFAEnabled || user.TOTPSecret == "" {
		return false
	}
	return !is2FAVerified(r)
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
