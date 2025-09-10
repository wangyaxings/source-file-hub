package middleware

import (
    "net/http"
    "strings"

    "secure-file-hub/internal/auth"
    "secure-file-hub/internal/authz"
)

// Authorize returns a middleware that enforces RBAC with Casbin based on user role, path and method
func Authorize() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Allow preflight
            if r.Method == http.MethodOptions {
                next.ServeHTTP(w, r)
                return
            }

            // Public endpoints shortcut (same logic as AuthMiddleware)
            path := r.URL.Path
            if strings.Contains(path, "/auth/login") || strings.Contains(path, "/auth/register") {
                next.ServeHTTP(w, r)
                return
            }

            // Require authenticated user from context
            userCtx := r.Context().Value("user")
            if userCtx == nil {
                http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
                return
            }
            user, ok := userCtx.(*auth.User)
            if !ok {
                http.Error(w, "UNAUTHORIZED", http.StatusUnauthorized)
                return
            }

            sub := user.Role
            if sub == "" {
                sub = "viewer"
            }
            obj := r.URL.Path
            act := r.Method

            e := authz.GetEnforcer()
            if e == nil {
                // Fail-closed to be safe
                http.Error(w, "FORBIDDEN", http.StatusForbidden)
                return
            }
            ok2, err := e.Enforce(sub, obj, act)
            if err != nil || !ok2 {
                http.Error(w, "FORBIDDEN", http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// RequireAuthorization is a helper to wrap a HandlerFunc with Authorize middleware for route registration convenience
func RequireAuthorization(next http.HandlerFunc) http.HandlerFunc {
    middleware := Authorize()
    return func(w http.ResponseWriter, r *http.Request) {
        middleware(http.HandlerFunc(next)).ServeHTTP(w, r)
    }
}

