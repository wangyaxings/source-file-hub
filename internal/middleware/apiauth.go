package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"secure-file-hub/internal/apikey"
	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/authz"
	"secure-file-hub/internal/database"
)

// APIAuthContext key for storing API authentication info in request context
type APIAuthContext struct {
	APIKey        *database.APIKey
	Role          string
	KeyID         string
	HasPermission func(permission string) bool
}

const APIAuthContextKey = "api_auth"

// APIKeyAuthMiddleware validates API key authentication using Casbin
func APIKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from Authorization header or X-API-Key header
		var apiKeyValue string
		authHeader := r.Header.Get("Authorization")
		xApiKey := r.Header.Get("X-API-Key")
		
		if authHeader != "" {
			// Parse Bearer token or API key directly
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKeyValue = strings.TrimPrefix(authHeader, "Bearer ")
			} else if strings.HasPrefix(authHeader, "ApiKey ") {
				apiKeyValue = strings.TrimPrefix(authHeader, "ApiKey ")
			} else {
				// Try direct API key
				apiKeyValue = authHeader
			}
		} else if xApiKey != "" {
			apiKeyValue = xApiKey
		} else {
			writeAPIErrorResponse(w, http.StatusUnauthorized, "MISSING_API_KEY", "API key is required")
			return
		}


		// Validate API key format
		if !apikey.ValidateAPIKeyFormat(apiKeyValue) {
			writeAPIErrorResponse(w, http.StatusUnauthorized, "INVALID_API_KEY_FORMAT", "Invalid API key format")
			return
		}

		// Get database instance
		db := database.GetDatabase()
		if db == nil {
			writeAPIErrorResponse(w, http.StatusInternalServerError, "DATABASE_ERROR", "Database not available")
			return
		}

		// Hash the API key for lookup
		keyHash := apikey.HashAPIKey(apiKeyValue)

		// Retrieve API key from database
		apiKeyRecord, err := db.GetAPIKeyByHash(keyHash)
		if err != nil {
			writeAPIErrorResponse(w, http.StatusUnauthorized, "INVALID_API_KEY", "Invalid or expired API key")
			return
		}

		// Check if API key is active
		if apiKeyRecord.Status != "active" {
			writeAPIErrorResponse(w, http.StatusUnauthorized, "API_KEY_DISABLED", "API key is disabled")
			return
		}

		// Check if API key is expired
		if apiKeyRecord.ExpiresAt != nil && apiKeyRecord.ExpiresAt.Before(time.Now()) {
			writeAPIErrorResponse(w, http.StatusUnauthorized, "API_KEY_EXPIRED", "API key has expired")
			return
		}

    // Use Casbin to check permission for this specific request
    allowed, err := authz.CheckAPIKeyPermission(apiKeyRecord.ID, r.URL.Path, r.Method)
    if err != nil || !allowed {
        if err != nil {
            log.Printf("Warning: Casbin permission check failed: %v", err)
        }
        // Fallback: infer required permission by method and path
        required := inferRequiredPermission(r.Method, r.URL.Path)
        if !apikey.HasPermission(apiKeyRecord.Permissions, required) {
            writeAPIErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "API key does not have required permission: "+required)
            return
        }
    }

		// Create permission checker function (for backward compatibility)
		hasPermission := func(permission string) bool {
			// For backward compatibility, still check the old permission system
			return apikey.HasPermission(apiKeyRecord.Permissions, permission)
		}

		// Update API key usage (async)
		go func() {
			if err := db.UpdateAPIKeyUsage(apiKeyRecord.ID); err != nil {
				log.Printf("Warning: Failed to update API key usage: %v", err)
			}
		}()

		// Create auth context
		authContext := &APIAuthContext{
			APIKey:        apiKeyRecord,
			Role:          apiKeyRecord.Role,
			KeyID:         apiKeyRecord.ID,
			HasPermission: hasPermission,
		}

		// Add auth context to request
		ctx := context.WithValue(r.Context(), APIAuthContextKey, authContext)
		r = r.WithContext(ctx)

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// RequirePermission middleware checks if the authenticated user/API key has the required permission
func RequirePermission(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check API key context first
			if apiAuthCtx := GetAPIAuthContext(r); apiAuthCtx != nil {
				if !apiAuthCtx.HasPermission(permission) {
					writeAPIErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "API key does not have required permission: "+permission)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			
			// Check user context
			userCtx := r.Context().Value("user")
			if userCtx == nil {
				writeAPIErrorResponse(w, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication required")
				return
			}
			
			user, ok := userCtx.(*auth.User)
			if !ok {
				writeAPIErrorResponse(w, http.StatusUnauthorized, "INVALID_USER_CONTEXT", "Invalid user context")
				return
			}
			
			// Use Casbin to check permission
			e := authz.GetEnforcer()
			if e == nil {
				writeAPIErrorResponse(w, http.StatusInternalServerError, "AUTHORIZATION_ERROR", "Authorization system not available")
				return
			}
			
			allowed, err := e.Enforce(user.Role, r.URL.Path, permission)
			if err != nil || !allowed {
				writeAPIErrorResponse(w, http.StatusForbidden, "INSUFFICIENT_PERMISSIONS", "User does not have required permission: "+permission)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// GetAPIAuthContext retrieves API auth context from request
func GetAPIAuthContext(r *http.Request) *APIAuthContext {
    if ctx := r.Context().Value(APIAuthContextKey); ctx != nil {
        if authCtx, ok := ctx.(*APIAuthContext); ok {
            return authCtx
        }
    }
    return nil
}

// inferRequiredPermission provides a conservative fallback mapping from HTTP method/path to permission
func inferRequiredPermission(method, path string) string {
    m := strings.ToUpper(method)
    switch m {
    case http.MethodGet:
        // Treat explicit downloads as download permission
        if strings.Contains(path, "/download") || strings.HasPrefix(path, "/api/v1/public/files/") && !strings.HasSuffix(path, "/files") {
            return "download"
        }
        return "read"
    case http.MethodDelete:
        return "delete"
    default: // POST, PUT, PATCH
        return "upload"
    }
}

// APILoggingMiddleware logs API requests
func APILoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response recorder to capture status code and size
		recorder := &ResponseRecorder{
			ResponseWriter: w,
			StatusCode:     http.StatusOK,
			Size:           0,
		}

		// Process request
		next.ServeHTTP(recorder, r)

		// Log the API usage
		go func() {
			authCtx := GetAPIAuthContext(r)
			if authCtx != nil {
				db := database.GetDatabase()
				if db != nil {
					logEntry := &database.APIUsageLog{
						APIKeyID:       authCtx.KeyID,
						UserID:         authCtx.Role,
						Endpoint:       r.URL.Path,
						Method:         r.Method,
						IPAddress:      GetClientIP(r),
						UserAgent:      r.Header.Get("User-Agent"),
						StatusCode:     recorder.StatusCode,
						ResponseSize:   recorder.Size,
						ResponseTimeMs: time.Since(start).Milliseconds(),
						RequestTime:    start,
					}

					// Extract file ID from request if applicable
					if fileID := r.URL.Query().Get("file_id"); fileID != "" {
						logEntry.FileID = fileID
					}
					if filePath := r.URL.Query().Get("file_path"); filePath != "" {
						logEntry.FilePath = filePath
					}

					if err := db.LogAPIUsage(logEntry); err != nil {
						log.Printf("Warning: Failed to log API usage: %v", err)
					}
				}
			}
		}()
	})
}

// ResponseRecorder captures response data for logging
type ResponseRecorder struct {
	http.ResponseWriter
	StatusCode int
	Size       int64
}

func (r *ResponseRecorder) WriteHeader(statusCode int) {
	r.StatusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *ResponseRecorder) Write(data []byte) (int, error) {
	size, err := r.ResponseWriter.Write(data)
	r.Size += int64(size)
	return size, err
}

// GetClientIP extracts client IP from request
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take first IP from comma-separated list
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	if idx := strings.LastIndex(r.RemoteAddr, ":"); idx != -1 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// writeAPIErrorResponse writes a JSON error response
func writeAPIErrorResponse(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
		},
		"success": false,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Warning: Failed to encode error response: %v", err)
	}
}
