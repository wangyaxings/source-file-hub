package middleware

import (
	"net/http"
	"strings"
	"time"

	"fileserver/internal/logger"
)

// LoggingMiddleware 结构化日志记录中间件
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// 创建响应包装器来捕获状态码
		wrapper := &responseWrapper{
			ResponseWriter: w,
			statusCode:     200, // 默认状态码
		}

		// 获取用户信息（如果已认证）
		var userInfo map[string]interface{}
		if userCtx := r.Context().Value("user"); userCtx != nil {
			if user, ok := userCtx.(map[string]interface{}); ok {
				userInfo = user
			}
		}

		// 记录请求日志
		l := logger.GetLogger()
		if l != nil {
			l.LogAPIRequest(
				r.Method,
				r.URL.Path,
				r.UserAgent(),
				getClientIP(r),
				userInfo,
			)
		}

		// 处理请求
		next.ServeHTTP(wrapper, r)

		// 计算响应时间
		duration := time.Since(start)

		// 记录响应日志
		if l != nil {
			l.LogAPIResponse(
				r.Method,
				r.URL.Path,
				wrapper.statusCode,
				duration,
				userInfo,
			)
		}
	})
}

// responseWrapper 响应包装器用于捕获状态码
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// getClientIP 获取客户端真实IP
func getClientIP(r *http.Request) string {
	// 尝试从X-Forwarded-For头获取
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For可能包含多个IP，取第一个
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// 尝试从X-Real-IP头获取
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// 使用RemoteAddr
	ip := r.RemoteAddr
	if colonIndex := strings.LastIndex(ip, ":"); colonIndex != -1 {
		ip = ip[:colonIndex]
	}

	return ip
}