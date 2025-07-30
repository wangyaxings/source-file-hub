package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User 用户结构体
type User struct {
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Password string `json:"-"` // 不在JSON中显示密码
}

// LoginRequest 登录请求结构体
type LoginRequest struct {
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应结构体
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"` // token过期时间（秒）
	User      UserInfo `json:"user"`
}

// UserInfo 用户信息（不包含密码）
type UserInfo struct {
	TenantID string `json:"tenant_id"`
	Username string `json:"username"`
}

// 内存中的用户存储（生产环境应使用数据库）
var userStore = map[string]*User{
	"admin:demo@admin": {
		TenantID: "demo",
		Username: "admin",
		Password: hashPassword("admin123"), // 默认密码
	},
	"user1:demo@user1": {
		TenantID: "demo",
		Username: "user1",
		Password: hashPassword("password123"),
	},
	"test:tenant1@test": {
		TenantID: "tenant1",
		Username: "test",
		Password: hashPassword("test123"),
	},
}

// 活跃的token存储（简单实现，生产环境建议使用Redis）
var tokenStore = map[string]*TokenInfo{}

// TokenInfo token信息
type TokenInfo struct {
	User      *User     `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

// hashPassword 对密码进行哈希处理
func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

// checkPassword 验证密码
func checkPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// generateToken 生成简单的token（生产环境建议使用JWT）
func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based token if random generation fails
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// getUserKey 获取用户存储的key
func getUserKey(tenantID, username string) string {
	return fmt.Sprintf("%s:%s@%s", username, tenantID, username)
}

// Authenticate 用户认证
func Authenticate(req *LoginRequest) (*LoginResponse, error) {
	if req.TenantID == "" || req.Username == "" || req.Password == "" {
		return nil, errors.New("租户ID、用户名和密码不能为空")
	}

	// 查找用户
	userKey := getUserKey(req.TenantID, req.Username)
	user, exists := userStore[userKey]
	if !exists {
		return nil, errors.New("用户不存在")
	}

	// 验证密码
	if !checkPassword(user.Password, req.Password) {
		return nil, errors.New("密码错误")
	}

	// 生成token
	token := generateToken()
	expiresAt := time.Now().Add(24 * time.Hour) // token有效期24小时

	// 存储token
	tokenStore[token] = &TokenInfo{
		User:      user,
		ExpiresAt: expiresAt,
	}

	// 返回登录响应
	return &LoginResponse{
		Token:     token,
		ExpiresIn: 24 * 60 * 60, // 24小时，以秒为单位
		User: UserInfo{
			TenantID: user.TenantID,
			Username: user.Username,
		},
	}, nil
}

// ValidateToken 验证token
func ValidateToken(token string) (*User, error) {
	if token == "" {
		return nil, errors.New("token不能为空")
	}

	// 查找token
	tokenInfo, exists := tokenStore[token]
	if !exists {
		return nil, errors.New("无效的token")
	}

	// 检查token是否过期
	if time.Now().After(tokenInfo.ExpiresAt) {
		// 删除过期的token
		delete(tokenStore, token)
		return nil, errors.New("token已过期")
	}

	return tokenInfo.User, nil
}

// Logout 登出
func Logout(token string) error {
	if token == "" {
		return errors.New("token不能为空")
	}

	// 删除token
	delete(tokenStore, token)
	return nil
}

// AddUser 添加用户（管理功能）
func AddUser(tenantID, username, password string) error {
	if tenantID == "" || username == "" || password == "" {
		return errors.New("租户ID、用户名和密码不能为空")
	}

	userKey := getUserKey(tenantID, username)
	if _, exists := userStore[userKey]; exists {
		return errors.New("用户已存在")
	}

	userStore[userKey] = &User{
		TenantID: tenantID,
		Username: username,
		Password: hashPassword(password),
	}

	return nil
}

// GetDefaultUsers 获取默认测试用户信息
func GetDefaultUsers() []map[string]string {
	return []map[string]string{
		{
			"tenant_id": "demo",
			"username":  "admin",
			"password":  "admin123",
			"desc":      "管理员账户",
		},
		{
			"tenant_id": "demo",
			"username":  "user1",
			"password":  "password123",
			"desc":      "普通用户账户",
		},
		{
			"tenant_id": "tenant1",
			"username":  "test",
			"password":  "test123",
			"desc":      "测试账户",
		},
	}
}