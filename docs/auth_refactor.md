# 认证系统迁移实施方案

## 📋 实施策略：渐进式迁移到Authboss

基于当前系统状态，采用**渐进式迁移**策略，逐步清理混合认证问题，最终统一到Authboss认证系统。

## 🎯 第一阶段：立即修复

### 1. 修复前端API客户端混乱

#### 修改文件：`frontend/lib/api.ts`

**当前问题代码：**
```typescript
// 混合的认证处理
// Note: No longer using Authorization header - authboss handles authentication via session cookies
setUser(user: UserInfo) {
  this.currentUser = user
  if (typeof window !== 'undefined') {
    localStorage.setItem('currentUser', JSON.stringify(user))
  }
}

// 同时处理Token和Session
async login(data: LoginRequest): Promise<LoginResponse> {
  // 使用Authboss但还有Token相关逻辑
}
```

**修复后代码：**
```typescript
class ApiClient {
  private baseUrl = '/api/v1/web'
  private currentUser: UserInfo | null = null

  constructor() {
    // 只保留用户信息，不再存储token
    this.currentUser = typeof window !== 'undefined'
      ? JSON.parse(localStorage.getItem('currentUser') || 'null')
      : null
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseUrl}${endpoint}`

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...((options.headers as Record<string, string>) || {})
    }

    const config: RequestInit = {
      ...options,
      headers,
      credentials: 'include', // 始终包含session cookie
    }

    try {
      const response = await fetch(url, config)

      if (!response.ok) {
        if (response.status === 401) {
          const wasAuthenticated = this.isAuthenticated()
          if (wasAuthenticated) {
            this.logout()
            throw new Error('Session expired, please log in again')
          }
          throw new Error('Authentication required')
        }

        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || errorData.message || `HTTP ${response.status}`)
      }

      const data = await response.json()
      
      // 统一处理成功响应
      if (data.success !== undefined) {
        return data
      }
      
      // Authboss响应格式兼容
      if (data.status === 'success') {
        return { success: true, data }
      }

      return { success: true, data }
    } catch (error) {
      console.error(`Request failed for ${url}:`, error)
      throw error
    }
  }

  // 统一使用Authboss登录
  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await fetch(`${this.baseUrl}/auth/ab/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(data),
      credentials: 'include',
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      const errorMessage = errorData.error || errorData.message || 'Login failed'
      
      // 处理2FA相关错误
      if (errorMessage.includes('otp') || errorMessage.includes('2fa')) {
        throw new Error(`2FA_REQUIRED: ${errorMessage}`)
      }
      
      throw new Error(errorMessage)
    }

    const result = await response.json()
    
    // Authboss成功响应处理
    if (result.status === 'success') {
      // 获取用户信息
      const meResponse = await this.request<{ user: UserInfo }>('/auth/me')
      if (meResponse.success && meResponse.data) {
        this.setUser((meResponse.data as any).user)
      }
      return { status: 'success', location: result.location }
    }

    throw new Error('Login failed')
  }

  async logoutUser(): Promise<void> {
    try {
      await fetch(`${this.baseUrl}/auth/ab/logout`, { 
        method: 'POST', 
        headers: { 'Accept': 'application/json' }, 
        credentials: 'include'
      })
    } finally {
      this.logout()
    }
  }

  setUser(user: UserInfo) {
    this.currentUser = user
    if (typeof window !== 'undefined') {
      localStorage.setItem('currentUser', JSON.stringify(user))
    }
  }

  getCurrentUser(): UserInfo | null {
    return this.currentUser
  }

  logout() {
    this.currentUser = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('currentUser')
    }
  }

  isAuthenticated(): boolean {
    return this.currentUser !== null
  }

  // 2FA功能统一使用自定义endpoints（暂时保持）
  async startTOTP(): Promise<{ secret: string; otpauth_url: string }> {
    const resp = await this.request<{ secret: string; otpauth_url: string }>('/auth/2fa/totp/start', { method: 'POST' })
    return resp.data as any
  }

  async enableTOTP(code: string): Promise<void> {
    await this.request('/auth/2fa/totp/enable', { 
      method: 'POST', 
      body: JSON.stringify({ code }) 
    })
    
    // 重新获取用户信息以更新2FA状态
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) {
      this.setUser((me.data as any).user)
    }
  }

  async disableTOTP(): Promise<void> {
    await this.request('/auth/2fa/disable', { method: 'POST' })
    
    // 重新获取用户信息以更新2FA状态
    const me = await this.request<{ user: UserInfo }>('/auth/me')
    if (me.success && me.data) {
      this.setUser((me.data as any).user)
    }
  }

  // 其他业务方法保持不变...
}
```

### 2. 清理中间件混乱

#### 修改文件：`internal/middleware/auth.go`

**当前问题：**
```go
// 混合了Authboss session和Token验证逻辑
func AuthMiddleware(next http.Handler) http.Handler {
    // 使用Authboss session，但还有Token相关注释和逻辑
}
```

**修复后代码：**
```go
package middleware

import (
    "context"
    "encoding/json"
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
    publicPaths := []string{
        "/api/v1/health", "/api/v1/healthz",
        "/api/v1/web/health", "/api/v1/web/healthz",
        "/api/v1/web/auth/users", // 默认用户列表
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
        "USER_NOT_FOUND":         "User not found",
        "ACCOUNT_SUSPENDED":      "Account suspended",
    }
    
    if msg, exists := messages[errorType]; exists {
        return msg
    }
    return "Authentication failed"
}
```

### 3. 修复路由注册混乱

#### 修改文件：`internal/handler/handler.go`

**当前问题：**
```go
// 2FA endpoints 分散在多个地方
webAPI.HandleFunc("/auth/2fa/totp/start", middleware.RequireAuthorization(startTOTPHandler))
// 同时Authboss也有2FA: /auth/ab/2fa/totp/*
```

**修复后代码：**
```go
func RegisterRoutes(router *mux.Router) {
    // 全局健康检查
    router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")
    router.HandleFunc("/api/v1/healthz", healthCheckHandler).Methods("GET")

    // Web API前缀
    webAPI := router.PathPrefix("/api/v1/web").Subrouter()

    // ========= 认证相关路由 =========
    
    // 基础认证信息（无需认证）
    webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
    webAPI.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")
    
    // 自定义2FA endpoints（暂时保留，需要认证）
    // 注意：这些将在第二阶段迁移到Authboss
    webAPI.HandleFunc("/auth/2fa/totp/start", middleware.RequireAuthorization(startTOTPHandler)).Methods("POST")
    webAPI.HandleFunc("/auth/2fa/totp/enable", middleware.RequireAuthorization(enableTOTPHandler)).Methods("POST")
    webAPI.HandleFunc("/auth/2fa/disable", middleware.RequireAuthorization(disableTOTPHandler)).Methods("POST")
    
    // ========= API信息和健康检查 =========
    webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
    webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
    webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
    webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

    // ========= 文件管理路由 =========
    webAPI.HandleFunc("/upload", middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
    webAPI.HandleFunc("/files/list", listFilesHandler).Methods("GET")
    webAPI.HandleFunc("/files/versions/{type}/{filename}", getFileVersionsHandler).Methods("GET")
    webAPI.HandleFunc("/files/{id}/delete", middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
    webAPI.HandleFunc("/files/{id}/restore", middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
    webAPI.HandleFunc("/files/{id}/purge", middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")

    // 回收站管理
    webAPI.HandleFunc("/recycle-bin", getRecycleBinHandler).Methods("GET")
    webAPI.HandleFunc("/recycle-bin/clear", middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")

    // 统一文件下载
    webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
    webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")

    // 其他业务路由...
    RegisterWebAdminRoutes(webAPI)
    RegisterAPIRoutes(router)
    RegisterAdminRoutes(router)
    
    // 静态文件
    router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
}
```

### 4. 修复前端登录组件

#### 修改文件：`frontend/components/auth/login-form.tsx`

**当前问题：**
```typescript
// 错误的API路径提示
<code className="px-1">/api/v1/web/auth/2fa/totp/validate</code>
<code className="px-1">/api/v1/web/auth/2fa/totp/setup</code>
```

**修复后代码：**
```typescript
// 改进的登录流程处理
const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault()
  setIsLoading(true)
  setError("")

  try {
    const result = await apiClient.login(formData)
    
    if (result.status === 'success') {
      onLogin()
    }
  } catch (error: any) {
    const errorMessage = error?.message || 'Login failed'
    
    // 处理2FA相关错误
    if (errorMessage.includes('2FA_REQUIRED')) {
      setLoginStep('2fa')
      setError("Please enter your 2FA verification code")
    } else if (errorMessage.includes('2fa setup required')) {
      setShow2FASetup(true)
      setError("Please complete 2FA setup")
    } else {
      setError(errorMessage)
    }
  } finally {
    setIsLoading(false)
  }
}

// 修复API路径提示
{showOtpInfo && (
  <div className="text-xs text-muted-foreground bg-muted/30 p-3 rounded">
    If your account has 2FA enabled, you will be prompted for verification code.
    <br />
    <small>
      After login, you can manage 2FA settings in your profile.
    </small>
  </div>
)}
```

## 🎯 第二阶段：功能统一

### 1. 清理自定义认证系统

#### 修改文件：`internal/auth/user.go`

**移除Token相关功能：**
```go
// 删除这些全局变量和函数
// var tokenStore = map[string]*TokenInfo{}
// func Authenticate(req *LoginRequest) (*LoginResponse, error)
// func ValidateToken(token string) (*User, error) 
// func Logout(token string) error
// func generateToken() string

// 保留并改进这些功能
func StartTOTPSetup(username, issuer string) (secret string, otpauthURL string, err error) {
    // 现有逻辑保持不变
}

func EnableTOTP(username, code string) error {
    // 现有逻辑保持不变
}

func DisableTOTP(username string) error {
    // 现有逻辑保持不变
}

// 保留用户管理功能
func InitDefaultUsers() {
    // 现有逻辑保持不变
}

func GetDefaultUsers() []map[string]interface{} {
    // 现有逻辑保持不变
}
```

### 2. 更新测试代码

#### 修改文件：`tests/integration/integration_test.go`

**使用Authboss API进行测试：**
```go
func TestIntegration_UserRegistrationAndLogin(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()

    // 使用Authboss登录API
    loginData := map[string]string{
        "username": "testuser",
        "password": "TestPassword123!",
    }

    req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/ab/login", loginData, nil)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    // 验证Authboss响应格式
    if rr.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d", rr.Code)
    }

    // 检查session cookie是否设置
    cookies := rr.Result().Cookies()
    var sessionCookie *http.Cookie
    for _, cookie := range cookies {
        if cookie.Name == "ab_session" {
            sessionCookie = cookie
            break
        }
    }
    
    if sessionCookie == nil {
        t.Error("Expected session cookie to be set")
    }

    // 测试认证后的请求
    req = helpers.CreateTestRequest(t, http.MethodGet, "/api/v1/web/auth/me", nil, nil)
    req.AddCookie(sessionCookie)
    
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    
    helpers.AssertSuccessResponse(t, rr, http.StatusOK)
}
```

### 3. 文档更新

#### 修改文件：`docs/auth.md`

**更新认证流程文档：**
```markdown
# Authentication & Authorization

## 统一认证架构

系统使用Authboss作为主要认证框架，提供session-based认证。

### 认证流程

1. **登录**: `POST /api/v1/web/auth/ab/login`
2. **会话验证**: 通过session cookie自动验证
3. **用户信息**: `GET /api/v1/web/auth/me`
4. **登出**: `POST /api/v1/web/auth/ab/logout`

### 2FA功能

- **设置**: `POST /api/v1/web/auth/2fa/totp/start`
- **启用**: `POST /api/v1/web/auth/2fa/totp/enable`
- **禁用**: `POST /api/v1/web/auth/2fa/disable`

注意：2FA功能将在后续版本中迁移到Authboss统一管理。

### 前端集成

```typescript
// 登录
await apiClient.login({ username, password })

// 检查认证状态
const user = apiClient.getCurrentUser()

// 登出
await apiClient.logoutUser()
```

### 安全特性

- Session-based认证，安全性更高
- HttpOnly cookies，防止XSS攻击
- Secure flag，强制HTTPS传输
- SameSite=Lax，防止CSRF攻击
```

## 🎯 第三阶段：完全迁移（3周内）

### 1. 迁移2FA到Authboss

#### 目标：将自定义2FA完全迁移到Authboss TOTP模块

```go
// 配置Authboss TOTP
func InitAuthboss() (*ab.Authboss, error) {
    // ... 现有配置 ...
    
    // 启用TOTP模块
    a.Config.Modules.TOTP2FAIssuer = "Secure File Hub"
    
    // 初始化TOTP
    if err := a.Init(); err != nil {
        return nil, err
    }
    
    // 设置TOTP模块
    t := &totp2fa.TOTP{Authboss: a}
    if err := t.Setup(); err != nil {
        return nil, err
    }
    
    return a, nil
}
```

### 2. 移除自定义2FA endpoints

```go
// 删除这些路由
// webAPI.HandleFunc("/auth/2fa/totp/start", ...)
// webAPI.HandleFunc("/auth/2fa/totp/enable", ...)
// webAPI.HandleFunc("/auth/2fa/disable", ...)

// 使用Authboss TOTP路由：/api/v1/web/auth/ab/2fa/totp/*
```

### 3. 更新前端2FA调用

```typescript
// 使用Authboss TOTP API
async startTOTP(): Promise<{ secret: string; otpauth_url: string }> {
    const resp = await this.request('/auth/ab/2fa/totp/setup', { method: 'POST' })
    return resp.data
}

async enableTOTP(code: string): Promise<void> {
    await this.request('/auth/ab/2fa/totp/confirm', { 
        method: 'POST', 
        body: JSON.stringify({ code }) 
    })
}
```

## 📊 迁移验证清单

### 功能验证
- [ ] 用户可以正常登录/登出
- [ ] Session cookie正确设置和验证
- [ ] 2FA设置和验证正常工作
- [ ] 权限控制正确执行
- [ ] 文件上传/下载正常

### 安全验证
- [ ] 未认证用户无法访问受保护资源
- [ ] Session过期后自动要求重新认证
- [ ] 2FA验证码正确验证
- [ ] HTTPS强制执行
- [ ] Cookie安全标志正确设置

### 性能验证
- [ ] 认证性能无明显下降
- [ ] 内存使用正常（移除内存tokenStore）
- [ ] 并发用户访问正常

### 兼容性验证
- [ ] 现有用户可以正常迁移
- [ ] API接口向后兼容
- [ ] 前端应用正常工作

## 🚀 迁移完成后的收益

1. **架构简化**：统一认证系统，减少维护复杂度
2. **安全性提升**：使用成熟的Authboss框架
3. **功能完整**：获得完整的认证功能生态
4. **开发效率**：专注业务逻辑而非认证基础设施
5. **社区支持**：享受Authboss社区的支持和更新

通过这个渐进式迁移方案，可以在不影响现有功能的情况下，逐步解决混合认证架构问题，最终建立一个统一、安全、易维护的认证系统。