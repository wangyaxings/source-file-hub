package auth

import (
	"errors"
	"log"

	"secure-file-hub/internal/database"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the system (simplified for authboss integration)
type User struct {
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	Role         string   `json:"role"`
	TwoFAEnabled bool     `json:"twoFAEnabled"`
	Permissions  []string `json:"permissions,omitempty"`
}

// DefaultUser represents a default test user
type DefaultUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// hashPassword is a utility function for password hashing (used by authboss store)
func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

// SeedAdmin ensures an administrator account exists with the given password
// This is still needed for initial setup
func SeedAdmin(password string) {
	if password == "" {
		password = "admin123"
	}
	
	db := database.GetDatabase()
	if db == nil {
		log.Printf("Warning: Database not available for seeding admin user")
		return
	}

	// Check if admin user exists
	if _, err := db.GetUser("admin"); err != nil {
		// Create admin user
		adminUser := &database.AppUser{
			Username:     "admin",
			Email:        "admin@example.com",
			PasswordHash: hashPassword(password),
			Role:         "administrator",
		}
		if createErr := db.CreateUser(adminUser); createErr != nil {
			log.Printf("Warning: Failed to create admin user: %v", createErr)
		} else {
			log.Printf("Admin user created with username: admin")
		}
	} else {
		// Update password for existing admin
		_ = db.UpdateUserPassword("admin", hashPassword(password))
	}

	// Create test viewer user
	if _, err := db.GetUser("viewer"); err != nil {
		viewerUser := &database.AppUser{
			Username:     "viewer",
			Email:        "viewer@example.com", 
			PasswordHash: hashPassword("password123"),
			Role:         "viewer",
		}
		_ = db.CreateUser(viewerUser)
	}

	// Create test user with 2FA
	if _, err := db.GetUser("testuser"); err != nil {
		testUser := &database.AppUser{
			Username:     "testuser",
			Email:        "testuser@example.com",
			PasswordHash: hashPassword("test123"),
			Role:         "viewer",
			TwoFAEnabled: true,
		}
		_ = db.CreateUser(testUser)
	}
}

// GetDefaultUsers returns the list of default test users
func GetDefaultUsers() []DefaultUser {
	return []DefaultUser{
		{Username: "admin", Password: "admin123", Role: "administrator"},
		{Username: "viewer", Password: "password123", Role: "viewer"},
		{Username: "testuser", Password: "test123", Role: "viewer"},
	}
}

// TOTP functions for 2FA support (still needed for user self-service)

// StartTOTPSetup generates a new TOTP secret for the user
func StartTOTPSetup(username, issuer string) (string, string, error) {
	if username == "" || issuer == "" {
		return "", "", errors.New("username and issuer are required")
	}

	db := database.GetDatabase()
	if db == nil {
		return "", "", errors.New("database not available")
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return "", "", err
	}

	// Store the secret temporarily (user needs to verify before enabling)
	user, err := db.GetUser(username)
	if err != nil {
		return "", "", errors.New("user not found")
	}

	user.TOTPSecret = key.Secret()
	if err := db.UpdateUser(user); err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

// EnableTOTP verifies the TOTP code and enables 2FA for the user
func EnableTOTP(username, code string) error {
	if username == "" || code == "" {
		return errors.New("username and code are required")
	}

	db := database.GetDatabase()
	if db == nil {
		return errors.New("database not available")
	}

	user, err := db.GetUser(username)
	if err != nil {
		return errors.New("user not found")
	}

	if user.TOTPSecret == "" {
		return errors.New("TOTP not set up for this user")
	}

	// Verify the code
	if !totp.Validate(code, user.TOTPSecret) {
		return errors.New("invalid TOTP code")
	}

	// Enable 2FA
	user.TwoFAEnabled = true
	user.TOTPLastCode = code
	return db.UpdateUser(user)
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

	user, err := db.GetUser(username)
	if err != nil {
		return errors.New("user not found")
	}

	// Disable 2FA
	user.TwoFAEnabled = false
	user.TOTPSecret = ""
	user.TOTPLastCode = ""
	return db.UpdateUser(user)
}

// VerifyTOTP verifies a TOTP code for the user
func VerifyTOTP(username, code string) bool {
	if username == "" || code == "" {
		return false
	}

	db := database.GetDatabase()
	if db == nil {
		return false
	}

	user, err := db.GetUser(username)
	if err != nil || !user.TwoFAEnabled || user.TOTPSecret == "" {
		return false
	}

	// Prevent code reuse
	if user.TOTPLastCode == code {
		return false
	}

	if totp.Validate(code, user.TOTPSecret) {
		// Update last used code
		user.TOTPLastCode = code
		_ = db.UpdateUser(user)
		return true
	}

	return false
}