package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"secure-file-hub/internal/logger"
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

		// 获取请求ID
		requestID := r.Context().Value(RequestIDKey)

		// 获取用户信息（如果已认证）
		var userInfo map[string]interface{}
		var actor string
		if userCtx := r.Context().Value("user"); userCtx != nil {
			if user, ok := userCtx.(map[string]interface{}); ok {
				userInfo = user
				if username, exists := user["username"]; exists {
					if usernameStr, ok := username.(string); ok {
						actor = usernameStr
					}
				}
			}
		}

		// 记录请求日志 - 使用增强的上下文日志方法
		l := logger.GetLogger()
		if l != nil {
			details := map[string]interface{}{
				"method":      r.Method,
				"path":        r.URL.Path,
				"user_agent":  r.UserAgent(),
				"remote_addr": getClientIP(r),
			}
			if userInfo != nil {
				details["user"] = userInfo
			}
			
			l.InfoCtx(
				logger.EventAPIRequest,
				fmt.Sprintf("API request: %s %s", r.Method, r.URL.Path),
				details,
				"API_REQUEST", // code
				requestID,     // request_id
				actor,         // actor
			)
		}

		// 处理请求
		next.ServeHTTP(wrapper, r)

		// 计算响应时间
		duration := time.Since(start)

		// 记录响应日志 - 使用增强的上下文日志方法
		if l != nil {
			details := map[string]interface{}{
				"method":        r.Method,
				"path":          r.URL.Path,
				"status_code":   wrapper.statusCode,
				"response_time": duration.Milliseconds(),
			}
			if userInfo != nil {
				details["user"] = userInfo
			}

			level := logger.LogLevelINFO
			eventCode := logger.EventAPIResponse
			code := "API_RESPONSE"
			
			if wrapper.statusCode >= 400 {
				level = logger.LogLevelWARN
				code = "API_RESPONSE_ERROR"
			}
			if wrapper.statusCode >= 500 {
				level = logger.LogLevelERROR
				code = "API_RESPONSE_SERVER_ERROR"
			}

			message := fmt.Sprintf("API response: %s %s [%d] (%dms)", r.Method, r.URL.Path, wrapper.statusCode, duration.Milliseconds())
			
			// Use appropriate log level method with context
			switch level {
			case logger.LogLevelWARN:
				l.WarnCtx(eventCode, message, details, code, requestID, actor)
			case logger.LogLevelERROR:
				l.ErrorCtx(eventCode, message, details, code, requestID, actor)
			default:
				l.InfoCtx(eventCode, message, details, code, requestID, actor)
			}
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