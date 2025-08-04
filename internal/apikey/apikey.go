package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// GenerateAPIKey generates a new API key with the specified prefix
func GenerateAPIKey(prefix string) (string, string, error) {
	// Generate 32 random bytes
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Convert to hex string
	keyPart := hex.EncodeToString(bytes)

	// Create the full key with prefix
	fullKey := fmt.Sprintf("%s_%s", prefix, keyPart)

	// Generate hash for storage
	hash := sha256.Sum256([]byte(fullKey))
	keyHash := hex.EncodeToString(hash[:])

	return fullKey, keyHash, nil
}

// ValidateAPIKeyFormat validates the format of an API key
func ValidateAPIKeyFormat(key string) bool {
	parts := strings.Split(key, "_")
	if len(parts) != 2 {
		return false
	}

	prefix := parts[0]
	keyPart := parts[1]

	// Check prefix (should be 2-10 alphanumeric characters)
	if len(prefix) < 2 || len(prefix) > 10 {
		return false
	}

	// Check key part (should be 64 hex characters)
	if len(keyPart) != 64 {
		return false
	}

	// Validate hex characters
	for _, char := range keyPart {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return false
		}
	}

	return true
}

// HashAPIKey generates a hash for an API key
func HashAPIKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
}

// GenerateAPIKeyID generates a unique ID for an API key
func GenerateAPIKeyID() string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("ak_%d", timestamp)
}

// ExtractPrefixFromKey extracts the prefix from an API key
func ExtractPrefixFromKey(key string) string {
	parts := strings.Split(key, "_")
	if len(parts) >= 2 {
		return parts[0]
	}
	return ""
}

// MaskAPIKey masks an API key for display purposes
func MaskAPIKey(key string) string {
	if len(key) < 12 {
		return "****"
	}

	// Show first 8 characters and last 4 characters
	return key[:8] + "..." + key[len(key)-4:]
}

// ValidatePermissions validates API key permissions
func ValidatePermissions(permissions []string) bool {
	validPermissions := map[string]bool{
		"read":     true,
		"download": true,
		"upload":   true,
		"delete":   true,
		"admin":    true,
	}

	for _, perm := range permissions {
		if !validPermissions[perm] {
			return false
		}
	}

	return true
}

// HasPermission checks if a set of permissions includes a specific permission
func HasPermission(permissions []string, required string) bool {
	// Admin permission grants all permissions
	for _, perm := range permissions {
		if perm == "admin" || perm == required {
			return true
		}
	}
	return false
}