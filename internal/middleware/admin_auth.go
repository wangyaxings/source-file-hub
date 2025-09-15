package middleware

import (
	"encoding/json"
	"net/http"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
)

// RequireAdminAuth middleware ensures the authenticated user has admin privileges
func RequireAdminAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get user from context (set by AuthMiddleware)
		userCtx := r.Context().Value("user")
		if userCtx == nil {
			writeAdminAuthError(w, "UNAUTHORIZED", "Authentication required")
			return
		}

		user, ok := userCtx.(*auth.User)
		if !ok {
			writeAdminAuthError(w, "UNAUTHORIZED", "Invalid user context")
			return
		}

		// Check if user has admin role using Casbin
		allowed, err := authz.CheckPermission(user.Role, "admin", "access")
		if err != nil {
			writeAdminAuthError(w, "AUTHORIZATION_ERROR", "Failed to check admin permissions")
			return
		}

		if !allowed {
			writeAdminAuthError(w, "INSUFFICIENT_PRIVILEGES", "Admin privileges required")
			return
		}

		// User is authenticated and has admin privileges
		next.ServeHTTP(w, r)
	})
}

// RequireAdminAuthorization function removed to avoid conflict with existing RequireAuthorization in authorize.go
// The RequireAdminAuth middleware above provides the necessary admin authorization functionality

// writeAdminAuthError writes a structured admin authorization error response
func writeAdminAuthError(w http.ResponseWriter, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")

	statusCode := http.StatusUnauthorized
	if errorType == "INSUFFICIENT_PRIVILEGES" {
		statusCode = http.StatusForbidden
	} else if errorType == "AUTHORIZATION_ERROR" {
		statusCode = http.StatusInternalServerError
	}

	w.WriteHeader(statusCode)

	response := map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    errorType,
		"message": getAdminErrorMessage(errorType),
	}

	json.NewEncoder(w).Encode(response)
}

// getAdminErrorMessage returns user-friendly error messages for admin authorization errors
func getAdminErrorMessage(errorType string) string {
	messages := map[string]string{
		"UNAUTHORIZED":            "Please log in to access admin features",
		"INSUFFICIENT_PRIVILEGES": "This action requires administrator privileges",
		"AUTHORIZATION_ERROR":     "Permission check failed",
	}

	if msg, exists := messages[errorType]; exists {
		return msg
	}
	return "Authorization failed"
}
