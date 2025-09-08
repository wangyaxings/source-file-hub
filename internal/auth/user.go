package auth

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "golang.org/x/crypto/bcrypt"
)

// User represents an application user
type User struct {
    TenantID string `json:"tenant_id"`
    Username string `json:"username"`
    Password string `json:"-"` // do not expose password in JSON
}

// LoginRequest represents a login payload
type LoginRequest struct {
    TenantID string `json:"tenant_id"`
    Username string `json:"username"`
    Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
    Token     string   `json:"token"`
    ExpiresIn int64    `json:"expires_in"` // seconds
    User      UserInfo `json:"user"`
}

// UserInfo is user information returned to clients
type UserInfo struct {
    TenantID string `json:"tenant_id"`
    Username string `json:"username"`
}

// In-memory user store (for demo; production should use DB)
var userStore = map[string]*User{
    "admin:demo@admin":  { TenantID: "demo",    Username: "admin", Password: hashPassword("admin123") },
    "user1:demo@user1":  { TenantID: "demo",    Username: "user1", Password: hashPassword("password123") },
    "test:tenant1@test": { TenantID: "tenant1", Username: "test",  Password: hashPassword("test123") },
}

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

// generateToken creates a random token (fallback to timestamp if random fails)
func generateToken() string {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
    }
    return hex.EncodeToString(bytes)
}

// getUserKey computes the key for the in-memory store
func getUserKey(tenantID, username string) string {
    return fmt.Sprintf("%s:%s@%s", username, tenantID, username)
}

// Authenticate validates credentials and returns a token
func Authenticate(req *LoginRequest) (*LoginResponse, error) {
    if req.TenantID == "" || req.Username == "" || req.Password == "" {
        return nil, errors.New("tenant_id, username and password are required")
    }

    userKey := getUserKey(req.TenantID, req.Username)
    user, exists := userStore[userKey]
    if !exists {
        return nil, errors.New("user not found")
    }

    if !checkPassword(user.Password, req.Password) {
        return nil, errors.New("invalid password")
    }

    token := generateToken()
    expiresAt := time.Now().Add(24 * time.Hour)

    tokenStore[token] = &TokenInfo{ User: user, ExpiresAt: expiresAt }

    return &LoginResponse{
        Token:     token,
        ExpiresIn: 24 * 60 * 60,
        User:      UserInfo{ TenantID: user.TenantID, Username: user.Username },
    }, nil
}

// ValidateToken validates and returns the associated user
func ValidateToken(token string) (*User, error) {
    if token == "" { return nil, errors.New("token is required") }

    tokenInfo, exists := tokenStore[token]
    if !exists { return nil, errors.New("invalid token") }

    if time.Now().After(tokenInfo.ExpiresAt) {
        delete(tokenStore, token)
        return nil, errors.New("token expired")
    }

    return tokenInfo.User, nil
}

// Logout deletes a token from the store
func Logout(token string) error {
    if token == "" { return errors.New("token is required") }
    delete(tokenStore, token)
    return nil
}

// AddUser adds a new user (admin functionality)
func AddUser(tenantID, username, password string) error {
    if tenantID == "" || username == "" || password == "" {
        return errors.New("tenant_id, username and password are required")
    }
    key := getUserKey(tenantID, username)
    if _, exists := userStore[key]; exists { return errors.New("user already exists") }
    userStore[key] = &User{ TenantID: tenantID, Username: username, Password: hashPassword(password) }
    return nil
}

// GetDefaultUsers returns demo users for quick start/testing
func GetDefaultUsers() []map[string]string {
    return []map[string]string{
        {"tenant_id": "demo",    "username": "admin", "password": "admin123",  "desc": "Administrator account"},
        {"tenant_id": "demo",    "username": "user1", "password": "password123","desc": "Regular user account"},
        {"tenant_id": "tenant1", "username": "test",  "password": "test123",   "desc": "Test account"},
    }
}

