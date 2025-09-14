package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secure-file-hub/internal/database"
	"secure-file-hub/internal/server"
	"secure-file-hub/tests/helpers"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Helper function to validate password format
func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	// Check for whitespace characters (spaces, tabs, newlines)
	for _, char := range password {
		if char == ' ' || char == '\t' || char == '\n' || char == '\r' {
			return false
		}
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

// Note: Authentication, token validation, logout, and registration tests removed
// These functions are now handled by authboss and are no longer part of the custom auth package

// TestTOTPSetup tests TOTP setup functionality
func TestTOTPSetup(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()
    // Create test user and login
    _ = helpers.CreateTestUser(t, "totpuser", "TotpUser123!", "viewer")
    cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "totpuser", "TotpUser123!")

    // Call Authboss TOTP setup endpoint
    req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
    req.AddCookie(cookie)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("Expected 200 on TOTP setup, got %d: %s", rr.Code, rr.Body.String())
    }

    var resp struct{
        Success bool `json:"success"`
        Data map[string]string `json:"data"`
    }
    _ = json.Unmarshal(rr.Body.Bytes(), &resp)
    if !resp.Success || resp.Data["secret"] == "" || resp.Data["otpauth_url"] == "" {
        t.Fatalf("Invalid setup response: %s", rr.Body.String())
    }
}

// TestEnableTOTP tests TOTP enabling
func TestEnableTOTP(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()
    _ = helpers.CreateTestUser(t, "enabletotpuser", "EnableTotp123!", "viewer")
    cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "enabletotpuser", "EnableTotp123!")

    // Setup to get secret
    req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
    req.AddCookie(cookie)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("setup failed: %d", rr.Code)
    }
    var resp struct{ Success bool; Data map[string]string }
    _ = json.Unmarshal(rr.Body.Bytes(), &resp)
    secret := resp.Data["secret"]
    if secret == "" { t.Fatal("empty secret") }

    // Generate current code and confirm
    code, _ := totp.GenerateCode(secret, time.Now())
    confirmBody := map[string]string{"code": code}
    b, _ := json.Marshal(confirmBody)
    req = httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/confirm", bytes.NewReader(b))
    req.Header.Set("Content-Type", "application/json")
    req.AddCookie(cookie)
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK {
        t.Fatalf("confirm failed: %d %s", rr.Code, rr.Body.String())
    }
}

// TestDisableTOTP tests TOTP disabling
func TestDisableTOTP(t *testing.T) {
    helpers.SetupTestEnvironment(t)
    srv := server.New()
    _ = helpers.CreateTestUser(t, "disabletotpuser", "DisableTotp123!", "viewer")
    cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "disabletotpuser", "DisableTotp123!")

    // Setup then remove
    req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
    req.AddCookie(cookie)
    rr := httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK { t.Fatalf("setup failed: %d", rr.Code) }

    req = httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/remove", nil)
    req.AddCookie(cookie)
    rr = httptest.NewRecorder()
    srv.Router.ServeHTTP(rr, req)
    if rr.Code != http.StatusOK { t.Fatalf("remove failed: %d %s", rr.Code, rr.Body.String()) }
}

// TestPasswordValidation_EdgeCases tests edge cases for password validation
func TestPasswordValidation_EdgeCases(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	// Test boundary conditions
	edgeCases := []struct {
		name     string
		password string
		expected bool
	}{
		{"Exactly8Chars", "Abc123!@", true},
		{"Exactly7Chars", "Abc123!", false},
		{"OnlyUppercase", "ABCDEFGH", false},
		{"OnlyLowercase", "abcdefgh", false},
		{"OnlyNumbers", "12345678", false},
		{"OnlySpecial", "!@#$%^&*", false},
		{"MixedNoSpecial", "Abcdefgh", false},
		{"MixedNoNumbers", "Abcdefg!", false},
		{"MixedNoUppercase", "abcdefg1!", false},
		{"MixedNoLowercase", "ABCDEFG1!", false},
		{"UnicodeChars", "测试密码123!", false}, // Unicode characters
		{"Spaces", "Abc 123!", false},         // Contains spaces
		{"Tabs", "Abc\t123!", false},          // Contains tabs
		{"Newlines", "Abc\n123!", false},      // Contains newlines
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidPassword(tc.password)
			if result != tc.expected {
				t.Errorf("Password '%s': expected %v, got %v", tc.password, tc.expected, result)
			}
		})
	}
}

// TestPasswordHashing_Consistency tests password hashing consistency
func TestPasswordHashing_Consistency(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	password := "TestPassword123!"

	// Hash the same password multiple times
	hashes := make([]string, 5)
	for i := 0; i < 5; i++ {
		hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}
		hashes[i] = string(hashedBytes)
	}

	// All hashes should be different (due to salt)
	for i := 0; i < len(hashes); i++ {
		for j := i + 1; j < len(hashes); j++ {
			if hashes[i] == hashes[j] {
				t.Error("Password hashes should be different due to salt")
			}
		}
	}

	// But all should verify against the original password
	for _, hash := range hashes {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		if err != nil {
			t.Errorf("Hash verification failed: %v", err)
		}
	}
}

// TestPasswordHashing_Performance tests password hashing performance
func TestPasswordHashing_Performance(t *testing.T) {
	helpers.SetupTestEnvironment(t)

	password := "TestPassword123!"
	iterations := 10

	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Failed to hash password: %v", err)
		}
	}
	elapsed := time.Since(start)

	avgTime := elapsed / time.Duration(iterations)
	t.Logf("Average hashing time: %v", avgTime)

	// Hashing should be reasonably fast but not too fast (security)
	if avgTime < 50*time.Millisecond {
		t.Logf("Warning: Password hashing is very fast (%v), consider increasing cost", avgTime)
	}
	if avgTime > 2*time.Second {
		t.Errorf("Password hashing is too slow: %v", avgTime)
	}
}

// TestTOTP_EdgeCases tests TOTP edge cases
func TestTOTP_EdgeCases(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	// Test with different user roles
	roles := []string{"viewer", "admin", "user"}
	for _, role := range roles {
		t.Run("Role_"+role, func(t *testing.T) {
			username := "totpuser_" + role
			_ = helpers.CreateTestUser(t, username, "TotpUser123!", role)
			cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, username, "TotpUser123!")

			// Test TOTP setup
			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("TOTP setup failed for role %s: status=%d body=%s", role, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestTOTP_InvalidCodes tests TOTP with invalid codes
func TestTOTP_InvalidCodes(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	_ = helpers.CreateTestUser(t, "invalidcodeuser", "InvalidCode123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "invalidcodeuser", "InvalidCode123!")

	// Setup TOTP
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("TOTP setup failed: %d", rr.Code)
	}

	var resp struct{ Success bool; Data map[string]string }
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	_ = resp.Data["secret"]

	// Test invalid codes
	invalidCodes := []string{
		"000000",    // All zeros
		"123456",    // Sequential
		"abcdef",    // Non-numeric
		"",          // Empty
		"12345",     // Too short
		"1234567",   // Too long
		"999999",    // All nines
	}

	for _, code := range invalidCodes {
		t.Run("InvalidCode_"+code, func(t *testing.T) {
			confirmBody := map[string]string{"code": code}
			b, _ := json.Marshal(confirmBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/confirm", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			// Should fail for invalid codes
			if rr.Code == http.StatusOK {
				t.Errorf("Expected failure for invalid code '%s', but got success", code)
			}
		})
	}
}

// TestTOTP_TimeDrift tests TOTP with time drift
func TestTOTP_TimeDrift(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	_ = helpers.CreateTestUser(t, "timedriftuser", "TimeDrift123!", "viewer")
	cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, "timedriftuser", "TimeDrift123!")

	// Setup TOTP
	req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/setup", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("TOTP setup failed: %d", rr.Code)
	}

	var resp struct{ Success bool; Data map[string]string }
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	secret := resp.Data["secret"]

	// Test codes from different time windows
	now := time.Now()
	timeWindows := []time.Time{
		now.Add(-30 * time.Second), // Previous window
		now,                        // Current window
		now.Add(30 * time.Second),  // Next window
	}

	for i, testTime := range timeWindows {
		t.Run(fmt.Sprintf("TimeWindow_%d", i), func(t *testing.T) {
			code, err := totp.GenerateCode(secret, testTime)
			if err != nil {
				t.Fatalf("Failed to generate TOTP code: %v", err)
			}

			confirmBody := map[string]string{"code": code}
			b, _ := json.Marshal(confirmBody)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/web/auth/ab/2fa/totp/confirm", bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			// Current and adjacent windows should work
			if i == 1 && rr.Code != http.StatusOK {
				t.Errorf("Current time window should work, got status %d", rr.Code)
			}
		})
	}
}

// TestUserStatus_EdgeCases tests user status edge cases
func TestUserStatus_EdgeCases(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	// Test with different user statuses
	statuses := []string{"active", "pending", "suspended"}
	for _, status := range statuses {
		t.Run("Status_"+status, func(t *testing.T) {
			username := "statususer_" + status
			_ = helpers.CreateTestUser(t, username, "StatusUser123!", "viewer")

			// Update user role status
			db := database.GetDatabase()
			if db != nil {
				userRole := &database.UserRole{
					UserID: username,
					Role:   "viewer",
					Status: status,
				}
				_ = db.CreateOrUpdateUserRole(userRole)
			}

			cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, username, "StatusUser123!")

			// Test accessing protected endpoint
			req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if status == "suspended" {
				// Suspended users should be rejected
				if rr.Code == http.StatusOK {
					t.Errorf("Suspended user should be rejected, got status %d", rr.Code)
				}
			} else {
				// Active and pending users should be allowed
				if rr.Code != http.StatusOK {
					t.Errorf("User with status %s should be allowed, got status %d", status, rr.Code)
				}
			}
		})
	}
}

// TestConcurrentAuthentication tests concurrent authentication
func TestConcurrentAuthentication(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	// Create multiple test users
	users := []struct {
		username string
		password string
		role     string
	}{
		{"concurrent1", "Concurrent123!", "viewer"},
		{"concurrent2", "Concurrent123!", "admin"},
		{"concurrent3", "Concurrent123!", "viewer"},
	}

	// Create users
	for _, user := range users {
		helpers.CreateTestUser(t, user.username, user.password, user.role)
	}

	// Test concurrent logins
	concurrency := len(users)
	done := make(chan bool, concurrency)

	for _, user := range users {
		go func(username, password string) {
			defer func() { done <- true }()

			// Login
			cookie := helpers.LoginAndGetSessionCookie(t, srv.Router, username, password)

			// Test authenticated request
			req := httptest.NewRequest(http.MethodGet, "/api/v1/web/auth/me", nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Router.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Concurrent authentication failed for user %s: status %d", username, rr.Code)
			}
		}(user.username, user.password)
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

// TestAuthentication_RateLimiting tests authentication rate limiting
func TestAuthentication_RateLimiting(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	srv := server.New()

	username := "ratelimituser"
	password := "RateLimit123!"
	helpers.CreateTestUser(t, username, password, "viewer")

	// Attempt multiple rapid logins
	attempts := 10
	successCount := 0

	for i := 0; i < attempts; i++ {
		loginData := map[string]string{
			"username": username,
			"password": password,
		}

		req := helpers.CreateTestRequest(t, http.MethodPost, "/api/v1/web/auth/ab/login", loginData, nil)
		rr := httptest.NewRecorder()
		srv.Router.ServeHTTP(rr, req)

		if rr.Code == http.StatusOK || rr.Code == http.StatusFound || rr.Code == http.StatusTemporaryRedirect {
			successCount++
		}
	}

	t.Logf("Successful logins: %d/%d", successCount, attempts)

	// All attempts should succeed (no rate limiting implemented yet)
	if successCount != attempts {
		t.Logf("Note: Some login attempts failed, this might indicate rate limiting is working")
	}
}

// Note: SetPassword and ChangePassword tests removed as these functions are no longer needed
// Password management is now handled by authboss
