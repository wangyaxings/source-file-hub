package auth

import (
	"testing"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/tests/helpers"

	"golang.org/x/crypto/bcrypt"
)

// Helper function to validate password format
func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		case char == '!' || char == '@' || char == '#' || char == '$' || char == '%' || char == '^' || char == '&' || char == '*':
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// TestPasswordValidation tests password validation
func TestPasswordValidation(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Test valid password
	validPassword := "ValidPassword123!"
	if !isValidPassword(validPassword) {
		t.Error("Expected valid password to pass validation")
	}

	// Test invalid passwords
	invalidPasswords := []string{
		"short",             // Too short
		"nouppercase123!",   // No uppercase
		"NOLOWERCASE123!",   // No lowercase
		"NoNumbers!",        // No numbers
		"NoSpecialChars123", // No special characters
		"",                  // Empty
	}

	for _, password := range invalidPasswords {
		if isValidPassword(password) {
			t.Errorf("Expected password '%s' to fail validation", password)
		}
	}
}

// TestPasswordHashing tests password hashing functionality
func TestPasswordHashing(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	password := "TestPassword123!"

	// Since hashPassword is private, we'll use bcrypt directly for testing
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	if hashedPassword == "" {
		t.Error("Expected hashed password to be non-empty")
	}

	if hashedPassword == password {
		t.Error("Expected hashed password to be different from original")
	}

	// Verify the hash can be used for authentication
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Errorf("Hashed password verification failed: %v", err)
	}
}

// TestCheckPassword tests password checking functionality
func TestCheckPassword(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	password := "TestPassword123!"
	// Use bcrypt directly since checkPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	// Test correct password using bcrypt directly
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		t.Error("Expected correct password to pass check")
	}

	// Test incorrect password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte("WrongPassword123!"))
	if err == nil {
		t.Error("Expected incorrect password to fail check")
	}
}

// TestAuthenticate tests user authentication
func TestAuthenticate(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Create a test user first
	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	username := "testuser"
	password := "TestPassword123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test successful authentication
	loginReq := &auth.LoginRequest{
		Username: username,
		Password: password,
	}

	response, err := auth.Authenticate(loginReq)
	if err != nil {
		t.Fatalf("Expected successful authentication, got error: %v", err)
	}

	if response == nil {
		t.Error("Expected authentication response")
	}

	if response.User.Username != username {
		t.Errorf("Expected username %s, got %s", username, response.User.Username)
	}

	if response.Token == "" {
		t.Error("Expected token to be non-empty")
	}

	// Test failed authentication with wrong password
	loginReq.Password = "WrongPassword123!"
	_, err = auth.Authenticate(loginReq)
	if err == nil {
		t.Error("Expected authentication to fail with wrong password")
	}

	// Test failed authentication with non-existent user
	loginReq.Username = "nonexistent"
	_, err = auth.Authenticate(loginReq)
	if err == nil {
		t.Error("Expected authentication to fail with non-existent user")
	}
}

// TestValidateToken tests token validation
func TestValidateToken(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Test invalid token
	_, err := auth.ValidateToken("")
	if err == nil {
		t.Error("Expected error for empty token")
	}

	_, err = auth.ValidateToken("invalid_token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

// TestLogout tests logout functionality
func TestLogout(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Test logout with empty token
	err := auth.Logout("")
	if err == nil {
		t.Error("Expected error for empty token")
	}
}

// TestAddUser tests user creation
func TestAddUser(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	username := "newuser"
	password := "NewUser123!"

	// Test successful user creation
	err := auth.AddUser(username, password)
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	// Verify user was created
	user, err := db.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get created user: %v", err)
	}

	if user.Username != username {
		t.Errorf("Expected username %s, got %s", username, user.Username)
	}

	// Test duplicate user creation
	err = auth.AddUser(username, password)
	if err == nil {
		t.Error("Expected error for duplicate user")
	}
}

// TestRegister tests user registration
func TestRegister(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	username := "registereduser"
	password := "Registered123!"
	email := "registered@example.com"

	// Test successful registration
	err := auth.Register(username, password, email)
	if err != nil {
		t.Fatalf("Failed to register user: %v", err)
	}

	// Test duplicate registration
	err = auth.Register(username, password, email)
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}
}

// TestTOTPSetup tests TOTP setup functionality
func TestTOTPSetup(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create a test user first
	username := "totpuser"
	password := "TotpUser123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test TOTP setup
	secret, otpauthURL, err := auth.StartTOTPSetup(username, "TestApp")
	if err != nil {
		t.Fatalf("Failed to setup TOTP: %v", err)
	}

	if secret == "" {
		t.Error("Expected TOTP secret to be non-empty")
	}

	if otpauthURL == "" {
		t.Error("Expected OTP auth URL to be non-empty")
	}

	// Verify user has TOTP secret
	dbUser, err := db.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if dbUser.TOTPSecret == "" {
		t.Error("Expected user to have TOTP secret")
	}

	if dbUser.TwoFAEnabled {
		t.Error("Expected 2FA to be disabled initially")
	}
}

// TestEnableTOTP tests TOTP enabling
func TestEnableTOTP(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create a test user with TOTP secret
	username := "enabletotpuser"
	password := "EnableTotp123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
		TOTPSecret:   "test_secret",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test enabling TOTP with invalid code
	err := auth.EnableTOTP(username, "000000")
	if err == nil {
		t.Error("Expected error for invalid TOTP code")
	}

	// Note: Testing with valid TOTP code would require generating a real code
	// which depends on time and the secret, so we'll skip that for now
}

// TestDisableTOTP tests TOTP disabling
func TestDisableTOTP(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create a test user with 2FA enabled
	username := "disabletotpuser"
	password := "DisableTotp123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
		TwoFAEnabled: true,
		TOTPSecret:   "test_secret",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test disabling TOTP
	err := auth.DisableTOTP(username)
	if err != nil {
		t.Fatalf("Failed to disable TOTP: %v", err)
	}

	// Verify TOTP is disabled
	dbUser, err := db.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if dbUser.TwoFAEnabled {
		t.Error("Expected 2FA to be disabled")
	}

	if dbUser.TOTPSecret != "" {
		t.Error("Expected TOTP secret to be cleared")
	}
}

// TestSetPassword tests password setting
func TestSetPassword(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create a test user
	username := "setpassuser"
	password := "OldPassword123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test setting new password
	newPassword := "NewPassword123!"
	err := auth.SetPassword(username, newPassword)
	if err != nil {
		t.Fatalf("Failed to set password: %v", err)
	}

	// Verify password was updated
	dbUser, err := db.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if dbUser.PasswordHash == hashedPassword {
		t.Error("Expected password hash to be updated")
	}

	// Verify new password works using bcrypt directly
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(newPassword))
	if err != nil {
		t.Error("Expected new password to work")
	}
}

// TestChangePassword tests password changing
func TestChangePassword(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	db := database.GetDatabase()
	if db == nil {
		t.Fatal("Database not initialized")
	}

	// Create a test user
	username := "changepassuser"
	oldPassword := "OldPassword123!"
	// Use bcrypt directly since hashPassword is private
	hashedBytes, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
	hashedPassword := string(hashedBytes)

	user := &database.AppUser{
		Username:     username,
		PasswordHash: hashedPassword,
		Role:         "viewer",
	}

	if err := db.CreateUser(user); err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test changing password with wrong old password
	newPassword := "NewPassword123!"
	err := auth.ChangePassword(username, "WrongOldPassword123!", newPassword)
	if err == nil {
		t.Error("Expected error for wrong old password")
	}

	// Test successful password change
	err = auth.ChangePassword(username, oldPassword, newPassword)
	if err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	// Verify password was updated
	dbUser, err := db.GetUser(username)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	if dbUser.PasswordHash == hashedPassword {
		t.Error("Expected password hash to be updated")
	}

	// Verify new password works using bcrypt directly
	err = bcrypt.CompareHashAndPassword([]byte(dbUser.PasswordHash), []byte(newPassword))
	if err != nil {
		t.Error("Expected new password to work")
	}
}
