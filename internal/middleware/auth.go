package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"

	ab "github.com/aarondl/authboss/v3"
)

// AuthMiddleware 统一使用Authboss session认证
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// CORS预检请求直接放行
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// 公开端点：无需认证
		if isPublicEndpoint(path) {
			next.ServeHTTP(w, r)
			return
		}

		// 检查测试环境中的用户上下文
		if userCtx := r.Context().Value("user"); userCtx != nil {
			if user, ok := userCtx.(*auth.User); ok {
				// 检查用户状态
				if err := checkUserStatus(user.Username); err != nil {
					writeUnauthorizedResponse(w, err.Error())
					return
				}
				next.ServeHTTP(w, r)
				return
			}
		}

		// 使用Authboss session验证
		if username, ok := ab.GetSession(r, ab.SessionKey); ok && username != "" {
			user, err := loadUserFromDatabase(username)
			if err != nil {
				log.Printf("Failed to load user %s: %v", username, err)
				writeUnauthorizedResponse(w, "USER_NOT_FOUND")
				return
			}

			// 检查用户状态
			if err := checkUserStatus(user.Username); err != nil {
				writeUnauthorizedResponse(w, err.Error())
				return
			}

			// 将用户信息添加到请求上下文
			ctx := context.WithValue(r.Context(), "user", user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
			return
		}

		// 未认证请求
		writeUnauthorizedResponse(w, "AUTHENTICATION_REQUIRED")
	})
}

// 检查是否为公开端点
func isPublicEndpoint(path string) bool {
	// 精确匹配的公开路径
	publicPaths := []string{
		"/api/v1/health", "/api/v1/healthz",
		"/api/v1/web/health", "/api/v1/web/healthz",
		"/api/v1/web/auth/users", // 默认用户列表
		"/api/v1/web/auth/me",    // 用户信息端点 - 需要特殊处理
	}

	for _, publicPath := range publicPaths {
		if path == publicPath {
			return true
		}
	}

	// Authboss认证相关路径
	if strings.HasPrefix(path, "/api/v1/web/auth/ab/") {
		return true
	}

	// 静态文件
	if strings.HasPrefix(path, "/static/") {
		return true
	}

	return false
}

// 从数据库加载用户
func loadUserFromDatabase(username string) (*auth.User, error) {
	db := database.GetDatabase()
	if db == nil {
		return nil, fmt.Errorf("database not available")
	}

	appUser, err := db.GetUser(username)
	if err != nil {
		return nil, err
	}

	return &auth.User{
		Username:     appUser.Username,
		Role:         appUser.Role,
		Email:        appUser.Email,
		TwoFAEnabled: appUser.TwoFAEnabled,
	}, nil
}

// 检查用户状态
func checkUserStatus(username string) error {
	db := database.GetDatabase()
	if db == nil {
		return fmt.Errorf("database not available")
	}

	userRole, err := db.GetUserRole(username)
	if err != nil {
		// 为没有角色记录的用户创建默认记录
		defaultRole := &database.UserRole{
			UserID: username,
			Role:   "viewer",
			Status: "active",
		}
		if err := db.CreateOrUpdateUserRole(defaultRole); err != nil {
			log.Printf("Warning: Failed to create default role for %s: %v", username, err)
		}
		return nil
	}

	if userRole.Status == "suspended" {
		return fmt.Errorf("ACCOUNT_SUSPENDED")
	}

	// 自动激活pending状态的用户
	if userRole.Status == "pending" {
		userRole.Status = "active"
		if err := db.CreateOrUpdateUserRole(userRole); err != nil {
			log.Printf("Warning: Failed to activate user %s: %v", username, err)
		}
	}

	return nil
}

// 写入未授权响应
func writeUnauthorizedResponse(w http.ResponseWriter, errorType string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)

	response := map[string]interface{}{
		"success": false,
		"error":   errorType,
		"message": getErrorMessage(errorType),
	}

	json.NewEncoder(w).Encode(response)
}

// 获取错误信息
func getErrorMessage(errorType string) string {
	messages := map[string]string{
		"AUTHENTICATION_REQUIRED": "Authentication required",
		"USER_NOT_FOUND":          "User not found",
		"ACCOUNT_SUSPENDED":       "Account suspended",
	}

	if msg, exists := messages[errorType]; exists {
		return msg
	}
	return "Authentication failed"
}
