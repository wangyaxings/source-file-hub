package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"secure-file-hub/internal/auth"
)

// AuthMiddleware 认证中间件
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						// 跳过不需要认证的接口
		if strings.Contains(r.URL.Path, "/auth/login") ||
		   strings.Contains(r.URL.Path, "/health") ||
		   strings.Contains(r.URL.Path, "/auth/users") { // 获取默认用户列表
			next.ServeHTTP(w, r)
			return
		}

		// 获取Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeUnauthorizedResponse(w, "缺少Authorization header")
			return
		}

		// 检查Bearer token格式
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeUnauthorizedResponse(w, "Authorization header格式错误，应为: Bearer <token>")
			return
		}

		token := parts[1]

		// 验证token
		user, err := auth.ValidateToken(token)
		if err != nil {
			writeUnauthorizedResponse(w, err.Error())
			return
		}

		// 将用户信息添加到请求上下文中
		ctx := context.WithValue(r.Context(), "user", user)
		r = r.WithContext(ctx)

		// 在响应头中添加用户信息（方便调试）
		w.Header().Set("X-User-TenantID", user.TenantID)
		w.Header().Set("X-User-Username", user.Username)

		// 继续处理请求
		next.ServeHTTP(w, r)
	})
}

// writeUnauthorizedResponse 写入未授权响应
func writeUnauthorizedResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"success": false,
		"error":   message,
		"code":    "UNAUTHORIZED",
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		// If we can't encode the response, just log the error
		// We've already set the status code, so the client will get something
		_ = err // Suppress unused variable warning
	}
}