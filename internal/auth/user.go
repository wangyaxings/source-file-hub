package auth

import (
	"errors"
	"log"
	"os"
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

// UserInfo is user information returned to clients
type UserInfo struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

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
// This replaces any static user storage with database-backed persistent user management
func SeedAdmin(password string) {
	if password == "" {
		password = "admin123"
	}
	db := database.GetDatabase()
	if db == nil {
		log.Printf("Warning: Database not available for user seeding")
		return
	}

	// Create admin if not exists (always ensure admin exists)
	if _, err := db.GetUser("admin"); err != nil {
		if createErr := db.CreateUser(&database.AppUser{
			Username:     "admin",
			Email:        "admin@localhost",
			PasswordHash: hashPassword(password),
			Role:         "administrator",
			TwoFAEnabled: false,
		}); createErr != nil {
			log.Printf("Error creating admin user: %v", createErr)
			return
		}
		log.Printf("Created admin user with password: %s", password)

		// Create admin role record
		_ = db.CreateOrUpdateUserRole(&database.UserRole{
			UserID:       "admin",
			Role:         "administrator",
			Permissions:  []string{"read", "write", "delete", "admin", "upload", "download"},
			QuotaDaily:   -1,
			QuotaMonthly: -1,
			Status:       "active",
		})
	} else {
		// Update password if admin already exists
		if updateErr := db.UpdateUserPassword("admin", hashPassword(password)); updateErr != nil {
			log.Printf("Warning: Failed to update admin password: %v", updateErr)
		}
	}

	// Seed demo users for development/testing only
	// In production, users should be created through registration or admin interface
	if isDevelopmentMode() {
		seedDemoUsers(db)
	}
}

// seedDemoUsers creates demo users for development/testing purposes
func seedDemoUsers(db *database.Database) {
	demoUsers := []struct {
		username, password, email string
	}{
		{"user1", "password123", "user1@localhost"},
		{"test", "test123", "test@localhost"},
	}

	for _, user := range demoUsers {
		if _, err := db.GetUser(user.username); err != nil {
			if createErr := db.CreateUser(&database.AppUser{
				Username:     user.username,
				Email:        user.email,
				PasswordHash: hashPassword(user.password),
				Role:         "viewer",
				TwoFAEnabled: false,
			}); createErr != nil {
				log.Printf("Warning: Failed to create demo user %s: %v", user.username, createErr)
				continue
			}

			// Create user role record
			_ = db.CreateOrUpdateUserRole(&database.UserRole{
				UserID:       user.username,
				Role:         "viewer",
				Permissions:  []string{"read", "download"},
				QuotaDaily:   -1,
				QuotaMonthly: -1,
				Status:       "active",
			})

			log.Printf("Created demo user: %s", user.username)
		}
	}
}

// isDevelopmentMode checks if we're running in development mode
func isDevelopmentMode() bool {
	// Check environment variables or other indicators
	return os.Getenv("ENVIRONMENT") != "production" && os.Getenv("ENV") != "production"
}

// AddUser has been removed - use Register() for new users or admin interface for user management
// This function was redundant with Register() and not properly used in the codebase

// GetDefaultUsers returns demo users for quick start/testing
// Note: This function is deprecated and should only be used for development/testing
// In production, users should be created through proper registration or admin interface
func GetDefaultUsers() []map[string]string {
	db := database.GetDatabase()
	if db == nil {
		// Fallback to static list if database unavailable (development only)
		return []map[string]string{
			{"username": "admin", "password": "admin123", "role": "administrator", "desc": "Administrator account"},
			{"username": "user1", "password": "password123", "role": "viewer", "desc": "Viewer account"},
			{"username": "test", "password": "test123", "role": "viewer", "desc": "Viewer account"},
		}
	}

	// Return users from database
	users := []map[string]string{}

	// Get admin user
	if adminUser, err := db.GetUser("admin"); err == nil {
		users = append(users, map[string]string{
			"username": adminUser.Username,
			"password": "***", // Never expose actual passwords
			"role":     adminUser.Role,
			"desc":     "Administrator account",
		})
	}

	// Get demo users
	for _, username := range []string{"user1", "test"} {
		if user, err := db.GetUser(username); err == nil {
			users = append(users, map[string]string{
				"username": user.Username,
				"password": "***", // Never expose actual passwords
				"role":     user.Role,
				"desc":     "Demo viewer account",
			})
		}
	}

	// If no users found in database, return empty list
	if len(users) == 0 {
		return []map[string]string{
			{"username": "admin", "password": "admin123", "role": "administrator", "desc": "Default admin (create via database)"},
		}
	}

	return users
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
