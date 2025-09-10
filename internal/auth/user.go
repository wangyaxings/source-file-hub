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
    Username string `json:"username"`
    Password string `json:"-"` // do not expose password in JSON
    Role     string `json:"role"`
}

// LoginRequest represents a login payload
type LoginRequest struct {
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
    Username string `json:"username"`
    Role     string `json:"role"`
}

// In-memory user store (for demo; production should use DB)
var userStore = map[string]*User{
    "admin": {Username: "admin", Password: hashPassword("admin123"), Role: "administrator"},
    "user1": {Username: "user1", Password: hashPassword("password123"), Role: "viewer"},
    "test":  {Username: "test", Password: hashPassword("test123"), Role: "viewer"},
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

// SetPassword sets a user's password without old password verification (admin/seed use)
func SetPassword(username, newPassword string) error {
    if username == "" || newPassword == "" {
        return errors.New("username and new password are required")
    }
    key := getUserKey(username)
    user, ok := userStore[key]
    if !ok {
        // create if not exists
        user = &User{Username: username, Role: "viewer"}
        userStore[key] = user
    }
    user.Password = hashPassword(newPassword)
    return nil
}

// ChangePassword changes a user's password after verifying the old password
func ChangePassword(username, oldPassword, newPassword string) error {
    if username == "" || oldPassword == "" || newPassword == "" {
        return errors.New("username, old password and new password are required")
    }
    key := getUserKey(username)
    user, ok := userStore[key]
    if !ok {
        return errors.New("user not found")
    }
    if !checkPassword(user.Password, oldPassword) {
        return errors.New("old password is incorrect")
    }
    user.Password = hashPassword(newPassword)
    return nil
}

// SeedAdmin ensures an administrator account exists with the given password
func SeedAdmin(password string) {
    if password == "" {
        password = "admin123"
    }
    key := getUserKey("admin")
    if _, ok := userStore[key]; !ok {
        userStore[key] = &User{Username: "admin", Role: "administrator"}
    }
    _ = SetPassword("admin", password)
    userStore[key].Role = "administrator"
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

	userKey := getUserKey(req.Username)
	user, exists := userStore[userKey]
	if !exists {
		return nil, errors.New("user not found")
	}

	if !checkPassword(user.Password, req.Password) {
		return nil, errors.New("invalid password")
	}

	token := generateToken()
	expiresAt := time.Now().Add(24 * time.Hour)

	tokenStore[token] = &TokenInfo{User: user, ExpiresAt: expiresAt}

    return &LoginResponse{
        Token:     token,
        ExpiresIn: 24 * 60 * 60,
        User:      UserInfo{Username: user.Username, Role: user.Role},
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
	key := getUserKey(username)
	if _, exists := userStore[key]; exists {
		return errors.New("user already exists")
	}
	userStore[key] = &User{Username: username, Password: hashPassword(password)}
	return nil
}

// GetDefaultUsers returns demo users for quick start/testing
func GetDefaultUsers() []map[string]string {
    return []map[string]string{
        {"username": "admin", "password": "admin123", "role": "administrator", "desc": "Administrator account"},
        {"username": "user1", "password": "password123", "role": "viewer", "desc": "Viewer account"},
        {"username": "test", "password": "test123", "role": "viewer", "desc": "Viewer account"},
    }
}
