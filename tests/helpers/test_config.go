package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigData represents the test configuration structure
type TestConfigData struct {
	Server struct {
		Port     int    `json:"port"`
		Host     string `json:"host"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"server"`
	Database struct {
		Path string `json:"path"`
	} `json:"database"`
	Upload struct {
		MaxFileSize  int64    `json:"max_file_size"`
		AllowedTypes []string `json:"allowed_types"`
	} `json:"upload"`
    Auth struct {
        TwoFAEnabled bool `json:"twofa_enabled"`
    } `json:"auth"`
	Logging struct {
		Level  string `json:"level"`
		Format string `json:"format"`
	} `json:"logging"`
}

// CreateTestConfig creates a test configuration file
func CreateTestConfig(t *testing.T, configPath string) *TestConfigData {
	t.Helper()

	config := &TestConfigData{
		Server: struct {
			Port     int    `json:"port"`
			Host     string `json:"host"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		}{
			Port:     8443,
			Host:     "localhost",
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
		Database: struct {
			Path string `json:"path"`
		}{
			Path: "data/test.db",
		},
		Upload: struct {
			MaxFileSize  int64    `json:"max_file_size"`
			AllowedTypes []string `json:"allowed_types"`
		}{
			MaxFileSize:  100 * 1024 * 1024, // 100MB
			AllowedTypes: []string{".txt", ".pdf", ".doc", ".docx", ".xlsx", ".tsv", ".zip"},
		},
        Auth: struct {
            TwoFAEnabled bool `json:"twofa_enabled"`
        }{
            TwoFAEnabled: true,
        },
		Logging: struct {
			Level  string `json:"level"`
			Format string `json:"format"`
		}{
			Level:  "debug",
			Format: "json",
		},
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("Failed to create config directory: %v", err)
	}

	// Write config file
	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
		t.Fatalf("Failed to write config file: %v", err)
	}

	return config
}

// LoadTestConfig loads a test configuration from file
func LoadTestConfig(t *testing.T, configPath string) *TestConfigData {
	t.Helper()

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read config file: %v", err)
	}

	var config TestConfigData
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	return &config
}

// DefaultTestConfig returns a default test configuration
func DefaultTestConfig() *TestConfigData {
	return &TestConfigData{
		Server: struct {
			Port     int    `json:"port"`
			Host     string `json:"host"`
			CertFile string `json:"cert_file"`
			KeyFile  string `json:"key_file"`
		}{
			Port:     8443,
			Host:     "localhost",
			CertFile: "certs/server.crt",
			KeyFile:  "certs/server.key",
		},
		Database: struct {
			Path string `json:"path"`
		}{
			Path: "data/test.db",
		},
		Upload: struct {
			MaxFileSize  int64    `json:"max_file_size"`
			AllowedTypes []string `json:"allowed_types"`
		}{
			MaxFileSize:  100 * 1024 * 1024, // 100MB
			AllowedTypes: []string{".txt", ".pdf", ".doc", ".docx", ".xlsx", ".tsv", ".zip"},
		},
        Auth: struct {
            TwoFAEnabled bool `json:"twofa_enabled"`
        }{
            TwoFAEnabled: true,
        },
		Logging: struct {
			Level  string `json:"level"`
			Format string `json:"format"`
		}{
			Level:  "debug",
			Format: "json",
		},
	}
}
