package auth

import (
    "errors"
    "secure-file-hub/internal/database"
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

// LoginResponse removed - login now handled by Authboss

// UserInfo is user information returned to clients
type UserInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// In-memory user store (for demo; production should use DB)
// Deprecated in-memory store retained for fallback during transition
var userStore = map[string]*User{}

// Authentication now handled by Authboss session system

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

// Token generation now handled by Authboss

// getUserKey computes the key for the in-memory store
func getUserKey(username string) string {
	return username
}

// Authenticate removed - authentication now handled by Authboss

// Token validation and logout now handled by Authboss

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

// 2FA TOTP functions removed. Authboss manages TOTP setup/verification/removal.
