# 认证系统迁移到Authboss - 完整分析与修复方案

## 🚨 当前认证系统混乱状况分析

### 1. 混合认证架构问题

#### 问题概述
当前系统存在**双重认证机制**，导致代码复杂性高、维护困难、潜在安全风险：

- **Legacy JWT Token系统**：使用内存tokenStore + JWT token
- **Authboss Session系统**：使用数据库 + session cookies
- **两套系统并存**：造成路由冲突、中间件混乱、前端API不一致

### 2. 具体混乱位置及影响范围

#### 2.1 前端API客户端混乱 (`frontend/lib/api.ts`)
**问题代码标识：**
```typescript
// 混合的认证处理 - 同时处理Token和Session
// Note: No longer using Authorization header - authboss handles authentication via session cookies
setUser(user: UserInfo) {
  this.currentUser = user
  if (typeof window !== 'undefined') {
    localStorage.setItem('currentUser', JSON.stringify(user))  // 存储用户但不存储token
  }
}

// 登录方法混乱：声称使用Authboss但仍有Token逻辑痕迹
async login(data: LoginRequest): Promise<LoginResponse>
```

**影响范围：**
- 前端认证状态管理不一致
- API调用可能失败或行为不可预测
- 用户体验不一致

#### 2.2 中间件认证逻辑混乱 (`internal/middleware/auth.go`)
**问题代码标识：**
```go
// AuthMiddleware 混合了Authboss session和残留的Token验证逻辑
func AuthMiddleware(next http.Handler) http.Handler {
    // 使用Authboss session，但代码中还有Token相关注释和判断
    // 既检查session又保留了token相关的处理路径
}
```

**影响范围：**
- 认证逻辑不确定性
- 性能问题（双重检查）
- 安全漏洞风险

#### 2.3 路由注册冲突 (`internal/handler/handler.go`)
**问题代码标识：**
```go
// 2FA endpoints在多个地方重复定义
webAPI.HandleFunc("/auth/2fa/totp/start", middleware.RequireAuthorization(startTOTPHandler))
webAPI.HandleFunc("/auth/2fa/totp/enable", middleware.RequireAuthorization(enableTOTPHandler))
webAPI.HandleFunc("/auth/2fa/disable", middleware.RequireAuthorization(disableTOTPHandler))

// 同时Authboss也提供: /api/v1/web/auth/ab/2fa/totp/*
// 造成功能重复和路由冲突
```

**影响范围：**
- 2FA功能可能冲突或不一致
- 路由优先级问题
- 代码维护复杂度高

#### 2.4 用户认证逻辑残留 (`internal/auth/user.go`)
**问题代码标识：**
```go
// 保留了大量已弃用的Token相关函数和变量
var tokenStore = map[string]*TokenInfo{}  // 已弃用但仍存在
// LoginResponse removed - login now handled by Authboss
// TokenInfo and tokenStore removed - authentication now handled by Authboss
// Authenticate removed - authentication now handled by Authboss
```

**影响范围：**
- 死代码占用内存和存储
- 代码混乱，影响新开发者理解
- 潜在的安全风险

#### 2.5 测试代码过时 (`tests/helpers/test_config.go`)
**问题代码标识：**
```go
Auth: struct {
    JWTSecret    string `json:"jwt_secret"`      // 已不使用JWT
    TokenExpiry  int    `json:"token_expiry"`    // 已不使用Token
    TwoFAEnabled bool   `json:"twofa_enabled"`
}{
    JWTSecret:    "test_jwt_secret_key",  // 无效配置
    TokenExpiry:  3600,                  // 无效配置
}
```

**影响范围：**
- 测试可能失败或给出错误结果
- CI/CD流水线不可靠
- 开发效率降低

#### 2.6 API文档不一致 (`docs/api-guide.md` vs `docs/auth.md`)
**问题表现：**
- `docs/api-guide.md` 描述JWT Token认证
- `docs/auth.md` 描述Authboss Session认证  
- 开发者和用户困惑，不知道使用哪套API

## 🎯 完整迁移方案

### 阶段一：立即修复（1周内完成）

#### 1.1 修复前端API客户端

**文件：`frontend/lib/api.ts`**

```typescript
class ApiClient {
  private baseUrl = '/api/v1/web'
  private currentUser: UserInfo | null = null

  constructor() {
    // 只保留用户信息，完全移除token存储
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
            this.clearUser()
            window.location.href = '/login'
          }
          throw new Error('Authentication required')
        }
        throw new Error(`HTTP ${response.status}`)
      }

      const data = await response.json()
      
      // 统一响应格式处理
      if (data.success !== undefined) {
        return data
      }
      
      // Authboss格式兼容
      if (data.status === 'success') {
        return { success: true, data }
      }

      return { success: true, data }
    } catch (error) {
      console.error(`API request failed: ${endpoint}`, error)
      throw error
    }
  }

  // 完全使用Authboss登录API
  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await this.request<any>('/auth/ab/login', {
      method: 'POST',
      body: JSON.stringify(data)
    })

    // Authboss成功响应处理
    if (response.data?.status === 'success') {
      // 获取用户信息
      const userResponse = await this.request<{ user: UserInfo }>('/auth/me')
      if (userResponse.success) {
        this.setUser(userResponse.data.user)
        return { 
          success: true, 
          user: userResponse.data.user,
          redirect: response.data.location 
        }
      }
    }

    throw new Error('Login failed')
  }

  // 完全使用Authboss登出API
  async logoutUser(): Promise<void> {
    try {
      await this.request('/auth/ab/logout', { method: 'POST' })
    } finally {
      this.clearUser()
    }
  }

  // 移除所有token相关方法，只保留用户信息管理
  setUser(user: UserInfo) {
    this.currentUser = user
    if (typeof window !== 'undefined') {
      localStorage.setItem('currentUser', JSON.stringify(user))
    }
  }

  clearUser() {
    this.currentUser = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem('currentUser')
    }
  }

  getCurrentUser(): UserInfo | null {
    return this.currentUser
  }

  isAuthenticated(): boolean {
    return this.currentUser !== null
  }
}
```

#### 1.2 清理中间件认证逻辑

**文件：`internal/middleware/auth.go`**

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

// AuthMiddleware 完全使用Authboss session认证
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        path := r.URL.Path

        // CORS预检请求直接放行
        if r.Method == http.MethodOptions {
            next.ServeHTTP(w, r)
            return
        }

        // 公开端点检查
        if isPublicEndpoint(path) {
            next.ServeHTTP(w, r)
            return
        }

        // 使用Authboss session验证 - 这是唯一的认证方式
        username, sessionExists := ab.GetSession(r, ab.SessionKey)

        if sessionExists && username != "" {
            // 从数据库加载完整用户信息
            user, err := loadUserFromDatabase(username)
            if err != nil {
                log.Printf("Failed to load user %s: %v", username, err)
                writeUnauthorizedResponse(w, "USER_NOT_FOUND")
                return
            }

            // 检查用户状态（suspended用户拒绝访问）
            if err := checkUserStatus(user.Username); err != nil {
                log.Printf("User %s access denied: %v", username, err)
                writeUnauthorizedResponse(w, err.Error())
                return
            }

            // 将认证用户信息添加到请求上下文
            ctx := context.WithValue(r.Context(), "user", user)
            next.ServeHTTP(w, r.WithContext(ctx))
            return
        }

        // 未认证请求
        writeUnauthorizedResponse(w, "AUTHENTICATION_REQUIRED")
    })
}

// isPublicEndpoint 检查是否为公开端点
func isPublicEndpoint(path string) bool {
    publicPaths := []string{
        "/api/v1/health", "/api/v1/healthz",
        "/api/v1/web/health", "/api/v1/web/healthz",
        "/api/v1/web", "/api/v1/web/", // API信息端点
        "/api/v1/web/auth/users", // 默认用户列表（演示用）
    }

    // 精确匹配公开路径
    for _, publicPath := range publicPaths {
        if path == publicPath {
            return true
        }
    }

    // Authboss认证端点都是公开的
    if strings.HasPrefix(path, "/api/v1/web/auth/ab/") {
        return true
    }

    // 静态文件公开
    if strings.HasPrefix(path, "/static/") {
        return true
    }

    return false
}

// loadUserFromDatabase 从数据库加载用户信息
func loadUserFromDatabase(username string) (*auth.User, error) {
    db := database.GetDatabase()
    if db == nil {
        return nil, fmt.Errorf("database not available")
    }

    appUser, err := db.GetUser(username)
    if err != nil {
        return nil, fmt.Errorf("user not found: %v", err)
    }

    return &auth.User{
        Username:     appUser.Username,
        Role:         appUser.Role,
        Email:        appUser.Email,
        TwoFAEnabled: appUser.TwoFAEnabled,
    }, nil
}

// checkUserStatus 检查用户状态
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
            Status: "active", // 默认激活
        }
        if createErr := db.CreateOrUpdateUserRole(defaultRole); createErr != nil {
            return fmt.Errorf("failed to create default role: %v", createErr)
        }
        return nil // 新创建的用户可以访问
    }

    // 检查用户状态
    switch userRole.Status {
    case "suspended":
        return fmt.Errorf("USER_SUSPENDED")
    case "pending":
        return fmt.Errorf("USER_PENDING_APPROVAL")
    case "active":
        return nil
    default:
        return fmt.Errorf("INVALID_USER_STATUS")
    }
}

// writeUnauthorizedResponse 写入未授权响应
func writeUnauthorizedResponse(w http.ResponseWriter, reason string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusUnauthorized)
    
    response := map[string]interface{}{
        "success": false,
        "error":   "Authentication required",
        "code":    reason,
    }
    
    json.NewEncoder(w).Encode(response)
}
```

#### 1.3 清理路由注册冲突

**文件：`internal/handler/routes.go`** (新建)

```go
package handler

import (
    "github.com/gorilla/mux"
    "secure-file-hub/internal/middleware"
)

// RegisterRoutes 统一路由注册，避免冲突
func RegisterRoutes(router *mux.Router) {
    // ========= 全局健康检查 =========
    router.HandleFunc("/api/v1/health", healthCheckHandler).Methods("GET")
    router.HandleFunc("/api/v1/healthz", healthCheckHandler).Methods("GET")

    // ========= Web API子路由 =========
    webAPI := router.PathPrefix("/api/v1/web").Subrouter()

    // API信息
    webAPI.HandleFunc("", apiInfoHandler).Methods("GET")
    webAPI.HandleFunc("/", apiInfoHandler).Methods("GET")
    webAPI.HandleFunc("/health", healthCheckHandler).Methods("GET")
    webAPI.HandleFunc("/healthz", healthCheckHandler).Methods("GET")

    // 认证相关路由
    registerAuthRoutes(webAPI)
    
    // 文件管理路由
    registerFileRoutes(webAPI)
    
    // 管理员路由
    registerAdminRoutes(webAPI)
    
    // 静态文件路由
    router.PathPrefix("/static/").Handler(
        http.StripPrefix("/static/", http.FileServer(http.Dir("./static/")))
    )
}

// registerAuthRoutes 注册认证相关路由
func registerAuthRoutes(webAPI *mux.Router) {
    // 用户信息（需要认证）
    webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
    
    // 演示用户列表（无需认证）
    webAPI.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")
    
    // 密码修改（需要认证）
    webAPI.HandleFunc("/auth/change-password", 
        middleware.RequireAuthorization(changePasswordHandler)).Methods("POST")
    
    // 自定义2FA endpoints（暂时保留，后续迁移）
    // TODO: 第二阶段迁移到Authboss TOTP
    webAPI.HandleFunc("/auth/2fa/totp/start", 
        middleware.RequireAuthorization(startTOTPHandler)).Methods("POST")
    webAPI.HandleFunc("/auth/2fa/totp/enable", 
        middleware.RequireAuthorization(enableTOTPHandler)).Methods("POST")
    webAPI.HandleFunc("/auth/2fa/disable", 
        middleware.RequireAuthorization(disableTOTPHandler)).Methods("POST")
        
    // 注意：Authboss路由由server初始化时挂载到 /api/v1/web/auth/ab/*
}

// registerFileRoutes 注册文件管理路由
func registerFileRoutes(webAPI *mux.Router) {
    // 文件上传
    webAPI.HandleFunc("/upload", 
        middleware.RequireAuthorization(uploadFileHandler)).Methods("POST")
    
    // 文件列表
    webAPI.HandleFunc("/files/list", listFilesHandler).Methods("GET")
    
    // 文件版本
    webAPI.HandleFunc("/files/versions/{type}/{filename}", 
        getFileVersionsHandler).Methods("GET")
    
    // 文件操作
    webAPI.HandleFunc("/files/{id}/delete", 
        middleware.RequireAuthorization(deleteFileHandler)).Methods("DELETE")
    webAPI.HandleFunc("/files/{id}/restore", 
        middleware.RequireAuthorization(restoreFileHandler)).Methods("POST")
    webAPI.HandleFunc("/files/{id}/purge", 
        middleware.RequireAuthorization(purgeFileHandler)).Methods("DELETE")
    
    // 回收站
    webAPI.HandleFunc("/recycle-bin", getRecycleBinHandler).Methods("GET")
    webAPI.HandleFunc("/recycle-bin/clear", 
        middleware.RequireAuthorization(clearRecycleBinHandler)).Methods("DELETE")
    
    // 文件下载（统一处理）
    webFilesRouter := webAPI.PathPrefix("/files").Subrouter()
    webFilesRouter.PathPrefix("/").HandlerFunc(downloadFileHandler).Methods("GET")
}

// registerAdminRoutes 注册管理员路由
func registerAdminRoutes(webAPI *mux.Router) {
    // 用户管理
    webAPI.HandleFunc("/admin/users", 
        middleware.RequireAuthorization(getUsersHandler)).Methods("GET")
    webAPI.HandleFunc("/admin/users/{username}", 
        middleware.RequireAuthorization(updateUserHandler)).Methods("PATCH")
    webAPI.HandleFunc("/admin/users/{username}/approve", 
        middleware.RequireAuthorization(approveUserHandler)).Methods("POST")
    webAPI.HandleFunc("/admin/users/{username}/suspend", 
        middleware.RequireAuthorization(suspendUserHandler)).Methods("POST")
    
    // 其他管理功能...
}
```

### 阶段二：深度清理（2周内完成）

#### 2.1 移除Legacy认证代码

**文件：`internal/auth/user.go`** (清理版)

```go
package auth

import (
    "errors"
    "fmt"

    "secure-file-hub/internal/database"

    "golang.org/x/crypto/bcrypt"
)

// User 应用用户结构
type User struct {
    Username     string `json:"username"`
    Password     string `json:"-"` // 永远不暴露密码哈希
    Role         string `json:"role"`
    Email        string `json:"email,omitempty"`
    TwoFAEnabled bool   `json:"two_fa_enabled"`
}

// LoginRequest 登录请求结构（用于前端类型定义）
type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
    OTP      string `json:"otp,omitempty"`
}

// UserInfo 返回给客户端的用户信息
type UserInfo struct {
    Username string `json:"username"`
    Role     string `json:"role"`
    Email    string `json:"email,omitempty"`
    TwoFA    bool   `json:"two_fa"`
}

// 密码处理函数
func hashPassword(password string) string {
    bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes)
}

func checkPassword(hashedPassword, password string) bool {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

// SetPassword 设置用户密码（管理员功能）
func SetPassword(username, newPassword string) error {
    if username == "" || newPassword == "" {
        return errors.New("username and password are required")
    }
    
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    
    return db.UpdateUserPassword(username, hashPassword(newPassword))
}

// AddUser 添加新用户（管理员功能）
func AddUser(username, password, email string) error {
    if username == "" || password == "" {
        return errors.New("username and password are required")
    }
    
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    
    // 检查用户是否已存在
    if _, err := db.GetUser(username); err == nil {
        return errors.New("user already exists")
    }
    
    // 创建用户
    user := &database.AppUser{
        Username:     username,
        Email:        email,
        PasswordHash: hashPassword(password),
        Role:         "viewer", // 默认角色
    }
    
    if err := db.CreateUser(user); err != nil {
        return fmt.Errorf("failed to create user: %v", err)
    }
    
    // 创建用户角色记录
    userRole := &database.UserRole{
        UserID: username,
        Role:   "viewer",
        Status: "pending", // 需要管理员批准
    }
    
    return db.CreateOrUpdateUserRole(userRole)
}

// GetDefaultUsers 返回演示用户（开发/测试用）
func GetDefaultUsers() []map[string]string {
    return []map[string]string{
        {
            "username": "admin", 
            "password": "admin123", 
            "role": "administrator", 
            "desc": "Administrator account",
        },
        {
            "username": "user1", 
            "password": "password123", 
            "role": "viewer", 
            "desc": "Viewer account",
        },
        {
            "username": "test", 
            "password": "test123", 
            "role": "viewer", 
            "desc": "Test account",
        },
    }
}

// 注意：所有登录、认证、token相关功能已完全移除
// 这些功能现在由Authboss处理
```

#### 2.2 更新测试配置

**文件：`tests/helpers/test_config.go`** (清理版)

```go
package helpers

import (
    "encoding/json"
    "os"
    "path/filepath"
    "testing"
)

// TestConfigData 测试配置结构
type TestConfigData struct {
    Server struct {
        Port     int    `json:"port"`
        Host     string `json:"host"`
        CertFile string `json:"cert_file"`
        KeyFile  string `json:"key_file"`
    } `json:"server"`
    
    Database struct {
        Path string `json:"path"`
    } `json:"database"`
    
    Upload struct {
        MaxFileSize  int64    `json:"max_file_size"`
        AllowedTypes []string `json:"allowed_types"`
    } `json:"upload"`
    
    Session struct {
        AuthKey string `json:"auth_key"`
        EncKey  string `json:"enc_key"`
    } `json:"session"` // 替换Auth配置
    
    Logging struct {
        Level  string `json:"level"`
        Format string `json:"format"`
    } `json:"logging"`
}

// CreateTestConfig 创建测试配置
func CreateTestConfig(t *testing.T, configPath string) *TestConfigData {
    t.Helper()

    config := &TestConfigData{
        Server: struct {
            Port     int    `json:"port"`
            Host     string `json:"host"`
            CertFile string `json:"cert_file"`
            KeyFile  string `json:"key_file"`
        }{
            Port:     8443,
            Host:     "localhost",
            CertFile: "certs/server.crt",
            KeyFile:  "certs/server.key",
        },
        
        Database: struct {
            Path string `json:"path"`
        }{
            Path: "data/test.db",
        },
        
        Upload: struct {
            MaxFileSize  int64    `json:"max_file_size"`
            AllowedTypes []string `json:"allowed_types"`
        }{
            MaxFileSize:  100 * 1024 * 1024, // 100MB
            AllowedTypes: []string{".txt", ".pdf", ".doc", ".docx", ".xlsx", ".tsv", ".zip"},
        },
        
        Session: struct {
            AuthKey string `json:"auth_key"`
            EncKey  string `json:"enc_key"`
        }{
            AuthKey: "test-auth-key-32-chars-long!!!", // Authboss session密钥
            EncKey:  "test-enc-key-32-chars-long!!!",  // Authboss加密密钥
        },
        
        Logging: struct {
            Level  string `json:"level"`
            Format string `json:"format"`
        }{
            Level:  "debug",
            Format: "json",
        },
    }

    // 创建目录
    dir := filepath.Dir(configPath)
    if err := os.MkdirAll(dir, 0755); err != nil {
        t.Fatalf("Failed to create config directory: %v", err)
    }

    // 写入配置文件
    configJSON, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        t.Fatalf("Failed to marshal config: %v", err)
    }

    if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
        t.Fatalf("Failed to write config file: %v", err)
    }

    return config
}
```

#### 2.3 更新集成测试

**文件：`tests/integration/auth_test.go`** (新建)

```go
package integration

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"

    "secure-file-hub/internal/server"
    "secure-file-hub/tests/helpers"
)

func TestAuthbossLogin_Success(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()

    // 测试Authboss登录API
    loginData := map[string]string{
        "username": "admin",
        "password": "admin123",
    }
    
    loginJSON, _ := json.Marshal(loginData)
    req := httptest.NewRequest(
        http.MethodPost, 
        "/api/v1/web/auth/ab/login",
        strings.NewReader(string(loginJSON)),
    )
    req.Header.Set("Content-Type", "application/json")

    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    // 验证响应
    if rr.Code != http.StatusOK {
        t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
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
        t.Error("Expected session cookie 'ab_session' to be set")
    }

    // 验证cookie属性
    if !sessionCookie.HttpOnly {
        t.Error("Session cookie should be HttpOnly")
    }
    
    if !sessionCookie.Secure {
        t.Error("Session cookie should be Secure")
    }

    // 测试认证后的/auth/me端点
    req = httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
    req.AddCookie(sessionCookie)
    
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    
    if rr.Code != http.StatusOK {
        t.Errorf("Expected /auth/me to return 200, got %d", rr.Code)
    }

    // 解析用户信息响应
    var meResponse struct {
        Success bool `json:"success"`
        Data    struct {
            User struct {
                Username string `json:"username"`
                Role     string `json:"role"`
            } `json:"user"`
        } `json:"data"`
    }
    
    if err := json.Unmarshal(rr.Body.Bytes(), &meResponse); err != nil {
        t.Errorf("Failed to parse /auth/me response: %v", err)
    }
    
    if !meResponse.Success {
        t.Error("Expected success response from /auth/me")
    }
    
    if meResponse.Data.User.Username != "admin" {
        t.Errorf("Expected username 'admin', got '%s'", meResponse.Data.User.Username)
    }
}

func TestAuthbossLogin_InvalidCredentials(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()

    loginData := map[string]string{
        "username": "admin",
        "password": "wrongpassword",
    }
    
    loginJSON, _ := json.Marshal(loginData)
    req := httptest.NewRequest(
        http.MethodPost, 
        "/api/v1/web/auth/ab/login",
        strings.NewReader(string(loginJSON)),
    )
    req.Header.Set("Content-Type", "application/json")

    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    // Authboss应该返回400或401
    if rr.Code != http.StatusBadRequest && rr.Code != http.StatusUnauthorized {
        t.Errorf("Expected 400 or 401 for invalid credentials, got %d", rr.Code)
    }

    // 确保没有设置session cookie
    cookies := rr.Result().Cookies()
    for _, cookie := range cookies {
        if cookie.Name == "ab_session" && cookie.Value != "" {
            t.Error("Session cookie should not be set for failed login")
        }
    }
}

func TestAuthMiddleware_RequiresAuthentication(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()

    // 测试受保护的端点需要认证
    protectedEndpoints := []string{
        "/api/v1/web/upload",
        "/api/v1/web/files/123/delete",
        "/api/v1/web/admin/users",
    }

    for _, endpoint := range protectedEndpoints {
        req := httptest.NewRequest(http.MethodGet, endpoint, nil)
        rr := httptest.NewRecorder()
        srv.Router.ServeHTTP(rr, req)

        if rr.Code != http.StatusUnauthorized {
            t.Errorf("Expected 401 for protected endpoint %s, got %d", endpoint, rr.Code)
        }
    }
}

func TestAuthbossLogout(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()

    // 先登录获取session
    loginData := map[string]string{
        "username": "admin",
        "password": "admin123",
    }
    
    loginJSON, _ := json.Marshal(loginData)
    req := httptest.NewRequest(
        http.MethodPost, 
        "/api/v1/web/auth/ab/login",
        strings.NewReader(string(loginJSON)),
    )
    req.Header.Set("Content-Type", "application/json")

    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("Login failed with status %d", rr.Code)
    }

    // 获取session cookie
    var sessionCookie *http.Cookie
    for _, cookie := range rr.Result().Cookies() {
        if cookie.Name == "ab_session" {
            sessionCookie = cookie
            break
        }
    }

    if sessionCookie == nil {
        t.Fatal("No session cookie received from login")
    }

    // 执行登出
    req = httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/logout", nil)
    req.AddCookie(sessionCookie)
    
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
        t.Errorf("Expected 200 or 302 for logout, got %d", rr.Code)
    }

    // 验证登出后无法访问受保护资源
    req = httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
    req.AddCookie(sessionCookie) // 使用旧的session cookie
    
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    if rr.Code != http.StatusUnauthorized {
        t.Errorf("Expected 401 after logout, got %d", rr.Code)
    }
}
```

### 阶段三：完全迁移2FA（3周内完成）

#### 3.1 迁移2FA到Authboss TOTP

**目标：将自定义2FA完全迁移到Authboss TOTP模块**

**文件：`internal/auth/authboss.go`** (增强版)

```go
package auth

import (
    "context"
    "fmt"
    "net/http"

    "github.com/aarondl/authboss/v3"
    "github.com/aarondl/authboss/v3/modules/totp2fa"
    "github.com/gorilla/sessions"
    
    "secure-file-hub/internal/database"
)

// InitAuthboss 初始化Authboss，包含完整2FA支持
func InitAuthboss() (*authboss.Authboss, error) {
    ab := authboss.New()

    // 数据库存储
    store := &AuthbossStore{}
    ab.Config.Storage.Server = store
    ab.Config.Storage.SessionState = &SessionStore{}
    ab.Config.Storage.CookieState = &CookieStore{}

    // 核心配置
    ab.Config.Paths.Mount = "/api/v1/web/auth/ab"
    ab.Config.Paths.RootURL = "https://localhost:8443"
    ab.Config.Paths.AuthLoginOK = "/api/v1/web/auth/me"
    ab.Config.Paths.AuthLogoutOK = "/"

    // 启用模块
    ab.Config.Modules.Auth = true
    ab.Config.Modules.Logout = true
    ab.Config.Modules.TOTP2FA = true // 启用TOTP 2FA

    // TOTP配置
    ab.Config.Modules.TOTP2FAIssuer = "Secure File Hub"

    // 邮件配置（如需要）
    // ab.Config.Mail.From = "noreply@yourapp.com"

    // 初始化
    if err := ab.Init(); err != nil {
        return nil, fmt.Errorf("failed to initialize authboss: %v", err)
    }

    return ab, nil
}
```

#### 3.2 移除自定义2FA endpoints

**文件：`internal/handler/routes.go`** (更新版)

```go
// registerAuthRoutes 注册认证相关路由
func registerAuthRoutes(webAPI *mux.Router) {
    // 用户信息（需要认证）
    webAPI.HandleFunc("/auth/me", meHandler).Methods("GET")
    
    // 演示用户列表（无需认证）
    webAPI.HandleFunc("/auth/users", getDefaultUsersHandler).Methods("GET")
    
    // 密码修改（需要认证）
    webAPI.HandleFunc("/auth/change-password", 
        middleware.RequireAuthorization(changePasswordHandler)).Methods("POST")
    
    // 注意：自定义2FA endpoints已完全移除
    // 所有2FA功能现在通过Authboss TOTP处理：
    // - Setup TOTP: POST /api/v1/web/auth/ab/2fa/totp/setup
    // - Confirm TOTP: POST /api/v1/web/auth/ab/2fa/totp/confirm
    // - Validate TOTP: POST /api/v1/web/auth/ab/2fa/totp/validate
    // - Remove TOTP: POST /api/v1/web/auth/ab/2fa/totp/remove
}
```

#### 3.3 更新前端2FA调用

**文件：`frontend/lib/api.ts`** (2FA部分)

```typescript
// 2FA管理方法 - 使用Authboss TOTP API
class ApiClient {
    // ... 其他方法 ...

    // 开始TOTP设置
    async startTOTP(): Promise<{ secret: string; otpauth_url: string }> {
        const response = await this.request<{
            secret: string;
            otpauth_url: string;
        }>('/auth/ab/2fa/totp/setup', { method: 'POST' });
        
        return response.data;
    }

    // 确认TOTP设置
    async confirmTOTP(code: string): Promise<void> {
        await this.request('/auth/ab/2fa/totp/confirm', {
            method: 'POST',
            body: JSON.stringify({ 
                code: code,
                recovery_codes: true // 请求恢复码
            })
        });
    }

    // 移除TOTP
    async removeTOTP(): Promise<void> {
        await this.request('/auth/ab/2fa/totp/remove', {
            method: 'POST'
        });
    }

    // 验证TOTP（登录时使用）
    async validateTOTP(code: string): Promise<void> {
        await this.request('/auth/ab/2fa/totp/validate', {
            method: 'POST',
            body: JSON.stringify({ code })
        });
    }

    // 获取2FA状态
    async get2FAStatus(): Promise<{ enabled: boolean; backup_codes?: string[] }> {
        const response = await this.request<{
            enabled: boolean;
            backup_codes?: string[];
        }>('/auth/me');
        
        return {
            enabled: response.data.user.two_fa || false,
            backup_codes: response.data.backup_codes
        };
    }
}
```

### 阶段四：文档更新与验证

#### 4.1 统一API文档

**文件：`docs/api_guide_unified.md`** (新建)

```markdown
# Secure File Hub API Guide

## 概述

Secure File Hub 提供基于Authboss的安全认证系统，使用session-based认证替代JWT tokens。

## 认证系统

### 基础认证流程

1. **用户登录**：`POST /api/v1/web/auth/ab/login`
2. **获取用户信息**：`GET /api/v1/web/auth/me`  
3. **用户登出**：`POST /api/v1/web/auth/ab/logout`

### 登录API

```http
POST /api/v1/web/auth/ab/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123",
  "code": "123456"  // 可选：2FA验证码
}
```

**成功响应：**
```json
{
  "status": "success",
  "location": "/api/v1/web/auth/me"
}
```

同时设置session cookie：`ab_session=xxx; HttpOnly; Secure; SameSite=Lax`

### 用户信息API

```http
GET /api/v1/web/auth/me
Cookie: ab_session=xxx
```

**响应：**
```json
{
  "success": true,
  "data": {
    "user": {
      "username": "admin",
      "role": "administrator",
      "email": "admin@example.com",
      "two_fa": true
    },
    "permissions": ["read", "write", "admin"],
    "quotas": {
      "storage_used": 1048576,
      "storage_limit": 10485760
    }
  }
}
```

### 登出API

```http
POST /api/v1/web/auth/ab/logout
Cookie: ab_session=xxx
```

## 双因素认证 (2FA)

### TOTP设置流程

1. **开始设置**：
```http
POST /api/v1/web/auth/ab/2fa/totp/setup
Cookie: ab_session=xxx
```

响应包含secret和二维码URL：
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "otpauth_url": "otpauth://totp/SecureFileHub:admin?secret=JBSWY3DPEHPK3PXP&issuer=SecureFileHub"
}
```

2. **确认设置**：
```http
POST /api/v1/web/auth/ab/2fa/totp/confirm
Cookie: ab_session=xxx
Content-Type: application/json

{
  "code": "123456",
  "recovery_codes": true
}
```

3. **移除TOTP**：
```http
POST /api/v1/web/auth/ab/2fa/totp/remove
Cookie: ab_session=xxx
```

### 启用2FA后的登录

当用户启用2FA后，登录时需要提供TOTP验证码：

```http
POST /api/v1/web/auth/ab/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123",
  "code": "123456"  // TOTP验证码
}
```

## 文件管理API

### 文件上传

```http
POST /api/v1/web/upload
Cookie: ab_session=xxx
Content-Type: multipart/form-data

file=@document.pdf&description=Important document
```

### 文件下载

```http
GET /api/v1/web/files/documents/document.pdf
Cookie: ab_session=xxx
```

### 文件列表

```http
GET /api/v1/web/files/list?page=1&limit=20
Cookie: ab_session=xxx
```

## 错误处理

### 认证错误

- `401 Unauthorized`：未登录或session已过期
- `403 Forbidden`：权限不足
- `400 Bad Request`：登录参数错误或2FA验证失败

示例错误响应：
```json
{
  "success": false,
  "error": "Authentication required",
  "code": "AUTHENTICATION_REQUIRED"
}
```

### 2FA相关错误

```json
{
  "success": false,
  "error": "Invalid TOTP code",
  "code": "TOTP_INVALID"
}
```

## 安全特性

- **Session-based认证**：更安全的服务端session管理
- **HttpOnly cookies**：防止XSS攻击窃取session
- **Secure flag**：强制HTTPS传输
- **SameSite=Lax**：防止CSRF攻击
- **TOTP 2FA**：基于时间的一次性密码增强安全性
- **用户状态管理**：pending/active/suspended状态控制

## 迁移指南

### 从JWT Token迁移

如果你之前使用JWT token认证：

1. **移除Authorization header**：不再需要`Authorization: Bearer xxx`
2. **启用credentials**：fetch请求设置`credentials: 'include'`
3. **更新登录端点**：使用`/api/v1/web/auth/ab/login`
4. **处理session过期**：监听401响应，重定向到登录页

### 前端代码示例

```javascript
// 旧方式（JWT）
const response = await fetch('/api/v1/files/list', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// 新方式（Session）
const response = await fetch('/api/v1/web/files/list', {
  credentials: 'include'  // 自动包含session cookie
});
```

## 开发与测试

### 演示用户

系统提供以下演示账户：

```http
GET /api/v1/web/auth/users
```

返回：
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "username": "admin",
        "password": "admin123",
        "role": "administrator",
        "desc": "Administrator account"
      },
      {
        "username": "user1", 
        "password": "password123",
        "role": "viewer",
        "desc": "Viewer account"
      }
    ]
  }
}
```

### 健康检查

```http
GET /api/v1/health
```

无需认证，返回服务状态。
```

## 📊 迁移验证清单

### 功能验证
- [ ] 用户可以使用Authboss API正常登录/登出
- [ ] Session cookie正确设置并包含安全标志
- [ ] `/auth/me` 端点正确返回用户信息
- [ ] 2FA设置和验证通过Authboss TOTP正常工作
- [ ] 权限控制和用户状态检查正确执行
- [ ] 文件上传/下载功能正常
- [ ] 前端应用完全迁移到session认证

### 安全验证
- [ ] 未认证用户无法访问受保护资源
- [ ] Session过期后自动要求重新认证
- [ ] 2FA验证码通过Authboss正确验证
- [ ] HTTPS强制执行
- [ ] Cookie安全标志(HttpOnly、Secure、SameSite)正确设置
- [ ] 用户状态(suspended/pending)正确阻止访问

### 性能验证
- [ ] 认证性能无明显下降
- [ ] 内存使用正常（已移除内存tokenStore）
- [ ] 并发用户访问正常
- [ ] 数据库连接池正常工作

### 代码质量验证
- [ ] 所有Legacy JWT/Token相关代码已移除
- [ ] 自定义2FA代码已移除，使用Authboss TOTP
- [ ] 路由注册清晰，无冲突
- [ ] 中间件逻辑简洁，只处理Authboss session
- [ ] 测试用例覆盖新的认证流程
- [ ] 文档更新完整且准确

### 兼容性验证
- [ ] 现有用户可以正常登录（密码哈希兼容）
- [ ] API接口响应格式保持一致
- [ ] 前端应用无需额外配置即可工作
- [ ] 数据库schema兼容现有数据

## 📈 迁移时间表

| 阶段 | 时间 | 主要任务 | 关键交付物 |
|------|------|----------|------------|
| **阶段一** | 第1周 | 立即修复混乱 | 前端API统一、中间件清理、路由整理 |
| **阶段二** | 第2-3周 | 深度清理 | 移除Legacy代码、更新测试、集成测试 |
| **阶段三** | 第4-5周 | 完全迁移2FA | Authboss TOTP集成、移除自定义2FA |
| **阶段四** | 第6周 | 文档和验证 | 统一文档、全面测试、性能验证 |

## 🚀 迁移完成后的收益

### 1. 架构简化
- **统一认证系统**：只有Authboss session认证
- **代码减少**：移除数千行Legacy认证代码
- **维护简化**：专注业务逻辑而非认证基础设施

### 2. 安全性提升  
- **成熟框架**：使用经过实战检验的Authboss框架
- **安全默认**：自动处理session安全、CSRF保护等
- **2FA标准化**：使用标准TOTP协议

### 3. 开发效率
- **功能完整**：获得完整的认证功能生态
- **社区支持**：享受Authboss社区的支持和更新
- **扩展性强**：可轻松添加邮箱验证、密码重置等功能

### 4. 用户体验
- **会话持久**：用户登录状态更稳定
- **安全感知**：用户能感受到更专业的安全处理
- **功能丰富**：标准的2FA体验

### 5. 运维优势
- **监控简化**：统一的认证日志和监控点
- **故障排查**：清晰的认证流程，易于调试
- **扩展部署**：session存储可轻松扩展到Redis等

## ⚠️ 风险控制

### 迁移风险
- **数据丢失风险**：LOW - 只修改认证逻辑，不涉及业务数据
- **服务中断风险**：MEDIUM - 通过灰度发布和回滚计划控制
- **兼容性风险**：LOW - API接口保持兼容，前端逐步迁移

### 回滚计划
1. **代码回滚**：Git版本控制，可快速回滚到任意版本
2. **配置回滚**：保留Legacy配置文件，支持快速切换
3. **数据一致性**：用户数据结构保持不变，无需数据迁移

## 📝 总结

通过这个**渐进式迁移方案**，可以：

1. **立即解决**当前认证系统的混乱问题
2. **逐步清理**Legacy代码，降低技术债务  
3. **统一认证架构**，使用成熟的Authboss框架
4. **提升系统安全性**和开发效率
5. **为未来功能扩展**打下坚实基础

整个迁移过程风险可控，收益明显，建议按计划执行。