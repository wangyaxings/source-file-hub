package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"secure-file-hub/internal/database"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// User represents an application user
type User struct {
    Username     string `json:"username"`
    Password     string `json:"-"` // hashed password, never expose
    Role         string `json:"role"`
    Email        string `json:"email,omitempty"`
    TwoFAEnabled bool   `json:"two_fa_enabled"`
}

// LoginRequest represents a login payload
type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
    OTP      string `json:"otp,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string   `json:"token"`
	ExpiresIn int64    `json:"expires_in"` // seconds
	User      UserInfo `json:"user"`
}

// UserInfo is user information returned to clients
type UserInfo struct {
    Username string `json:"username"`
    Role     string `json:"role"`
}

// In-memory user store (for demo; production should use DB)
// Deprecated in-memory store retained for fallback during transition
var userStore = map[string]*User{}

// Active token store (simple in-memory; consider Redis for production)
var tokenStore = map[string]*TokenInfo{}

// TokenInfo represents token metadata
type TokenInfo struct {
	User      *User     `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
}

func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func checkPassword(hashedPassword, password string) bool {
    return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

// SetPassword sets a user's password without old password verification (admin/seed use)
func SetPassword(username, newPassword string) error {
    if username == "" || newPassword == "" {
        return errors.New("username and new password are required")
    }
    // Update DB users table
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    return db.UpdateUserPassword(username, hashPassword(newPassword))
}

// ChangePassword changes a user's password after verifying the old password
func ChangePassword(username, oldPassword, newPassword string) error {
    if username == "" || oldPassword == "" || newPassword == "" {
        return errors.New("username, old password and new password are required")
    }
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    appUser, err := db.GetUser(username)
    if err != nil {
        return errors.New("user not found")
    }
    if !checkPassword(appUser.PasswordHash, oldPassword) {
        return errors.New("old password is incorrect")
    }
    return db.UpdateUserPassword(username, hashPassword(newPassword))
}

// SeedAdmin ensures an administrator account exists with the given password
func SeedAdmin(password string) {
    if password == "" {
        password = "admin123"
    }
    db := database.GetDatabase()
    if db == nil {
        return
    }
    // Create admin if not exists
    if _, err := db.GetUser("admin"); err != nil {
        _ = db.CreateUser(&database.AppUser{
            Username:     "admin",
            Email:        "",
            PasswordHash: hashPassword(password),
            Role:         "administrator",
            TwoFAEnabled: false,
        })
    } else {
        _ = db.UpdateUserPassword("admin", hashPassword(password))
    }

    // Seed demo users for quick start (viewer role)
    if _, err := db.GetUser("user1"); err != nil {
        _ = db.CreateUser(&database.AppUser{
            Username:     "user1",
            PasswordHash: hashPassword("password123"),
            Role:         "viewer",
        })
    }
    if _, err := db.GetUser("test"); err != nil {
        _ = db.CreateUser(&database.AppUser{
            Username:     "test",
            PasswordHash: hashPassword("test123"),
            Role:         "viewer",
        })
    }
}

// generateToken creates a random token (fallback to timestamp if random fails)
func generateToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// getUserKey computes the key for the in-memory store
func getUserKey(username string) string {
    return username
}

// Authenticate validates credentials and returns a token
func Authenticate(req *LoginRequest) (*LoginResponse, error) {
    if req.Username == "" || req.Password == "" {
        return nil, errors.New("username and password are required")
    }

    db := database.GetDatabase()
    if db == nil {
        return nil, errors.New("database not available")
    }

    // 1. 验证用户凭据
    appUser, err := db.GetUser(req.Username)
    if err != nil {
        return nil, errors.New("user not found")
    }
    if !checkPassword(appUser.PasswordHash, req.Password) {
        return nil, errors.New("invalid password")
    }

    // 2. 检查用户状态 - 关键修复点
    userRole, err := db.GetUserRole(appUser.Username)
    if err != nil {
        // 如果没有 user_role 记录，为新用户创建默认记录
        defaultRole := &database.UserRole{
            UserID:  appUser.Username,
            Role:    appUser.Role, // 使用 users 表中的角色
            Status:  "active",     // 默认设为 active，而不是 pending
        }

        if err := db.CreateOrUpdateUserRole(defaultRole); err != nil {
            log.Printf("Warning: Failed to create default user role for %s: %v", appUser.Username, err)
        }
        userRole = defaultRole
    }

    // 3. 检查用户状态
    if userRole.Status == "suspended" {
        return nil, errors.New("account suspended")
    }

    // 对于 pending 状态的用户，如果是管理员创建的用户，自动激活
    if userRole.Status == "pending" {
        // 自动将管理员创建的用户状态改为 active
        userRole.Status = "active"
        if err := db.CreateOrUpdateUserRole(userRole); err != nil {
            log.Printf("Warning: Failed to activate user %s: %v", appUser.Username, err)
        }
    }

    // 4. 处理 2FA 验证
    if appUser.TwoFAEnabled {
        if req.OTP == "" {
            return nil, errors.New("otp code required")
        }
        if ok := totp.Validate(req.OTP, appUser.TOTPSecret); !ok {
            return nil, errors.New("invalid otp code")
        }
    }

    // 5. 更新最后登录时间
    _ = db.SetUserLastLogin(appUser.Username, time.Now())

    // 6. 生成token
    token := generateToken()
    expiresAt := time.Now().Add(24 * time.Hour)

    // Build runtime user for context
    runtimeUser := &User{
        Username:     appUser.Username,
        Password:     appUser.PasswordHash,
        Role:         appUser.Role,
        Email:        appUser.Email,
        TwoFAEnabled: appUser.TwoFAEnabled,
    }
    tokenStore[token] = &TokenInfo{User: runtimeUser, ExpiresAt: expiresAt}

    return &LoginResponse{
        Token:     token,
        ExpiresIn: 24 * 60 * 60,
        User:      UserInfo{Username: appUser.Username, Role: appUser.Role},
    }, nil
}

// ValidateToken validates and returns the associated user
func ValidateToken(token string) (*User, error) {
	if token == "" {
		return nil, errors.New("token is required")
	}

	tokenInfo, exists := tokenStore[token]
	if !exists {
		return nil, errors.New("invalid token")
	}

	if time.Now().After(tokenInfo.ExpiresAt) {
		delete(tokenStore, token)
		return nil, errors.New("token expired")
	}

	return tokenInfo.User, nil
}

// Logout deletes a token from the store
func Logout(token string) error {
	if token == "" {
		return errors.New("token is required")
	}
	delete(tokenStore, token)
	return nil
}

// AddUser adds a new user (admin functionality)
func AddUser(username, password string) error {
    if username == "" || password == "" {
        return errors.New("username and password are required")
    }
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    if _, err := db.GetUser(username); err == nil {
        return errors.New("user already exists")
    }
    return db.CreateUser(&database.AppUser{
        Username:     username,
        PasswordHash: hashPassword(password),
        Role:         "viewer",
    })
}

// GetDefaultUsers returns demo users for quick start/testing
func GetDefaultUsers() []map[string]string {
    return []map[string]string{
        {"username": "admin", "password": "admin123", "role": "administrator", "desc": "Administrator account"},
        {"username": "user1", "password": "password123", "role": "viewer", "desc": "Viewer account"},
        {"username": "test", "password": "test123", "role": "viewer", "desc": "Viewer account"},
    }
}

// Register creates a new end-user with viewer role by default
func Register(username, password, email string) error {
    if username == "" || password == "" {
        return errors.New("username and password are required")
    }
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    if _, err := db.GetUser(username); err == nil {
        return errors.New("user already exists")
    }
    if err := db.CreateUser(&database.AppUser{
        Username:     username,
        Email:        email,
        PasswordHash: hashPassword(password),
        Role:         "viewer",
    }); err != nil {
        return err
    }
    // Put a default role record with pending status for approval flow
    _ = db.CreateOrUpdateUserRole(&database.UserRole{
        UserID:       username,
        Role:         "viewer",
        Permissions:  []string{"read"},
        QuotaDaily:   -1,
        QuotaMonthly: -1,
        Status:       "pending",
    })
    return nil
}

// StartTOTPSetup generates a new TOTP secret and returns the provisioning URL
func StartTOTPSetup(username, issuer string) (secret string, otpauthURL string, err error) {
    if username == "" {
        return "", "", errors.New("username is required")
    }
    if issuer == "" {
        issuer = "Secure File Hub"
    }
    key, err := totp.Generate(totp.GenerateOpts{
        Issuer:      issuer,
        AccountName: username,
        Period:      30,
        Digits:      otp.DigitsSix,
        Algorithm:   otp.AlgorithmSHA1,
    })
    if err != nil {
        return "", "", err
    }
    db := database.GetDatabase()
    if db == nil {
        return "", "", errors.New("database not available")
    }
    if err := db.SetUser2FA(username, false, key.Secret()); err != nil {
        return "", "", err
    }
    return key.Secret(), key.URL(), nil
}

// EnableTOTP verifies the provided code and enables 2FA
func EnableTOTP(username, code string) error {
    if username == "" || code == "" {
        return errors.New("username and code are required")
    }
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    u, err := db.GetUser(username)
    if err != nil {
        return errors.New("user not found")
    }
    if u.TOTPSecret == "" {
        return errors.New("2fa not initialized")
    }
    if !totp.Validate(code, u.TOTPSecret) {
        return errors.New("invalid otp code")
    }
    return db.SetUser2FA(username, true, u.TOTPSecret)
}

// DisableTOTP disables 2FA for the user
func DisableTOTP(username string) error {
    if username == "" {
        return errors.New("username is required")
    }
    db := database.GetDatabase()
    if db == nil {
        return errors.New("database not available")
    }
    return db.SetUser2FA(username, false, "")
}
