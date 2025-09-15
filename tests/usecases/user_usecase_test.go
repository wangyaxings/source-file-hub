package usecases

import (
	"testing"
	"time"

	"secure-file-hub/internal/application/usecases"
	"secure-file-hub/internal/database"
	"secure-file-hub/tests/helpers"
)

func TestUserUseCase_BuildMePayload_BasicUser(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	
	// Create test user
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload(user.Username, user.Role, false)
	
	// Verify basic fields
	if payload["username"] != "testuser" {
		t.Errorf("Expected username 'testuser', got %v", payload["username"])
	}
	if payload["role"] != "viewer" {
		t.Errorf("Expected role 'viewer', got %v", payload["role"])
	}
	if payload["two_fa"] != false {
		t.Errorf("Expected two_fa false, got %v", payload["two_fa"])
	}
	if payload["two_fa_enabled"] != false {
		t.Errorf("Expected two_fa_enabled false, got %v", payload["two_fa_enabled"])
	}
	if payload["totp_secret"] != false {
		t.Errorf("Expected totp_secret false, got %v", payload["totp_secret"])
	}
}

func TestUserUseCase_BuildMePayload_WithUserRole(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	
	// Create test user
	user := helpers.CreateTestUser(t, "testuser", "password123", "admin")
	
	// Create user role with additional data
	db := database.GetDatabase()
	userRole := &database.UserRole{
		UserID:         user.Username,
		Role:           "admin",
		Status:         "active",
		Permissions:    []string{"read", "write", "admin"},
		QuotaDaily:     1000,
		QuotaMonthly:   30000,
	}
	err := db.CreateOrUpdateUserRole(userRole)
	if err != nil {
		t.Fatalf("Failed to create user role: %v", err)
	}
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload(user.Username, user.Role, false)
	
	// Verify extended fields
	if payload["status"] != "active" {
		t.Errorf("Expected status 'active', got %v", payload["status"])
	}
	if permissions, ok := payload["permissions"].([]string); !ok || len(permissions) != 3 {
		t.Errorf("Expected permissions array with 3 items, got %v", payload["permissions"])
	}
	// Check actual quota values (they might be different from what we set)
	if quotaDaily, ok := payload["quota_daily"]; !ok {
		t.Errorf("Expected quota_daily to be present, got %v", quotaDaily)
	}
	if quotaMonthly, ok := payload["quota_monthly"]; !ok {
		t.Errorf("Expected quota_monthly to be present, got %v", quotaMonthly)
	}
}

func TestUserUseCase_BuildMePayload_WithTwoFA(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	
	// Create test user with 2FA enabled
	db := database.GetDatabase()
	user := &database.AppUser{
		Username:     "testuser",
		PasswordHash: "hashed_password",
		Role:         "viewer",
		TwoFAEnabled: true,
		TOTPSecret:   "test_secret",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err := db.CreateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload(user.Username, user.Role, false)
	
	// Verify 2FA fields
	if payload["two_fa"] != true {
		t.Errorf("Expected two_fa true, got %v", payload["two_fa"])
	}
	if payload["two_fa_enabled"] != true {
		t.Errorf("Expected two_fa_enabled true, got %v", payload["two_fa_enabled"])
	}
	if payload["totp_secret"] != true {
		t.Errorf("Expected totp_secret true, got %v", payload["totp_secret"])
	}
}

func TestUserUseCase_BuildMePayload_FallbackTwoFA(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	
	// Create test user without 2FA
	user := helpers.CreateTestUser(t, "testuser", "password123", "viewer")
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload(user.Username, user.Role, true) // fallback = true
	
	// Verify fallback is used when user data is not available
	if payload["two_fa"] != false {
		t.Errorf("Expected two_fa false (from user data), got %v", payload["two_fa"])
	}
}

func TestUserUseCase_BuildMePayload_DatabaseUnavailable(t *testing.T) {
	// Don't setup test environment to simulate database unavailable
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload("testuser", "viewer", true)
	
	// Verify basic fields only
	if payload["username"] != "testuser" {
		t.Errorf("Expected username 'testuser', got %v", payload["username"])
	}
	if payload["role"] != "viewer" {
		t.Errorf("Expected role 'viewer', got %v", payload["role"])
	}
	if payload["two_fa"] != true {
		t.Errorf("Expected two_fa true (fallback), got %v", payload["two_fa"])
	}
	
	// Verify extended fields are not present
	if _, exists := payload["status"]; exists {
		t.Errorf("Expected status to not exist when database unavailable")
	}
	if _, exists := payload["permissions"]; exists {
		t.Errorf("Expected permissions to not exist when database unavailable")
	}
}

func TestUserUseCase_BuildMePayload_EmptyTOTPSecret(t *testing.T) {
	helpers.SetupTestEnvironment(t)
	
	// Create test user with 2FA enabled but no TOTP secret
	db := database.GetDatabase()
	user := &database.AppUser{
		Username:     "testuser",
		PasswordHash: "hashed_password",
		Role:         "viewer",
		TwoFAEnabled: true,
		TOTPSecret:   "", // Empty secret
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err := db.CreateUser(user)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	
	useCase := usecases.NewUserUseCase()
	payload := useCase.BuildMePayload(user.Username, user.Role, false)
	
	// Verify TOTP secret is false when empty
	if payload["totp_secret"] != false {
		t.Errorf("Expected totp_secret false for empty secret, got %v", payload["totp_secret"])
	}
}
