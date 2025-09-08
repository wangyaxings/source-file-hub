package middleware

import (
    "context"
    "encoding/json"
    "net/http"
    "strings"
    "time"
    "os"

    "secure-file-hub/internal/auth"
    "secure-file-hub/internal/database"
)

// AuthMiddleware handles authentication and exposes public routes
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Health endpoint (public, structured for Operation Center)
        if strings.Contains(r.URL.Path, "/health") {
            writeHealthResponse(w)
            return
        }

        // Public routes
        if strings.Contains(r.URL.Path, "/auth/login") ||
           strings.Contains(r.URL.Path, "/auth/users") ||
           strings.Contains(r.URL.Path, "/api/v1/public") {
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
        w.Header().Set("X-User-TenantID", user.TenantID)
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
func writeHealthResponse(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/json")

    dbOK := true
    storageOK := true
    issues := []string{}

    if db := database.GetDatabase(); db == nil {
        dbOK = false
        issues = append(issues, "database not initialized")
    } else if err := db.GetDB().Ping(); err != nil {
        dbOK = false
        issues = append(issues, "database ping failed")
    }
    if _, err := os.Stat("downloads"); err != nil {
        storageOK = false
        issues = append(issues, "storage path not available")
    }

    healthy := dbOK && storageOK
    status := "ok"
    if !healthy { status = "error" }

    resp := map[string]interface{}{
        "success":  healthy,
        "message":  map[bool]string{true: "Service is healthy", false: "Service is unhealthy"}[healthy],
        "error":    func() string { if healthy || len(issues)==0 { return "" }; return strings.Join(issues, "; ") }(),
        "data": map[string]interface{}{
            "service":   "Operation File Server",
            "status":    status,
            "connected": healthy,
            "time":      time.Now().UTC().Format(time.RFC3339),
        },
    }

    code := http.StatusOK
    if !healthy { code = http.StatusServiceUnavailable }
    w.WriteHeader(code)
    _ = json.NewEncoder(w).Encode(resp)
}

