package helpers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigData represents the test configuration structure
type TestConfigData struct {
	Test struct {
		Database struct {
			Path              string `json:"path"`
			Driver            string `json:"driver"`
			MaxConnections    int    `json:"max_connections"`
			ConnectionTimeout int    `json:"connection_timeout"`
		} `json:"database"`
		Server struct {
			Port         int    `json:"port"`
			Host         string `json:"host"`
			CertFile     string `json:"cert_file"`
			KeyFile      string `json:"key_file"`
			ReadTimeout  int    `json:"read_timeout"`
			WriteTimeout int    `json:"write_timeout"`
			IdleTimeout  int    `json:"idle_timeout"`
		} `json:"server"`
		Upload struct {
			MaxFileSize  int64    `json:"max_file_size"`
			AllowedTypes []string `json:"allowed_types"`
			UploadDir    string   `json:"upload_dir"`
			TempDir      string   `json:"temp_dir"`
			ChunkSize    int      `json:"chunk_size"`
		} `json:"upload"`
		Auth struct {
			TwoFAEnabled              bool `json:"twofa_enabled"`
			PasswordMinLength         int  `json:"password_min_length"`
			PasswordRequireUppercase  bool `json:"password_require_uppercase"`
			PasswordRequireLowercase  bool `json:"password_require_lowercase"`
			PasswordRequireNumbers    bool `json:"password_require_numbers"`
			PasswordRequireSpecial    bool `json:"password_require_special"`
			SessionTimeout            int  `json:"session_timeout"`
			MaxLoginAttempts          int  `json:"max_login_attempts"`
			LockoutDuration           int  `json:"lockout_duration"`
		} `json:"auth"`
		Logging struct {
			Level      string `json:"level"`
			Format     string `json:"format"`
			Output     string `json:"output"`
			MaxSize    int64  `json:"max_size"`
			MaxBackups int    `json:"max_backups"`
			MaxAge     int    `json:"max_age"`
		} `json:"logging"`
		API struct {
			RateLimit struct {
				Enabled           bool `json:"enabled"`
				RequestsPerMinute int  `json:"requests_per_minute"`
				BurstLimit        int  `json:"burst_limit"`
			} `json:"rate_limit"`
			CORS struct {
				Enabled        bool     `json:"enabled"`
				AllowedOrigins []string `json:"allowed_origins"`
				AllowedMethods []string `json:"allowed_methods"`
				AllowedHeaders []string `json:"allowed_headers"`
				MaxAge         int      `json:"max_age"`
			} `json:"cors"`
			Timeout         int   `json:"timeout"`
			MaxRequestSize  int64 `json:"max_request_size"`
		} `json:"api"`
		Security struct {
			HTTPSRedirect    bool     `json:"https_redirect"`
			SecurityHeaders  bool     `json:"security_headers"`
			RequestTimeout   int      `json:"request_timeout"`
			MaxRequestSize   int64    `json:"max_request_size"`
			TrustedProxies   []string `json:"trusted_proxies"`
		} `json:"security"`
		Performance struct {
			ConcurrentRequests      int   `json:"concurrent_requests"`
			MemoryLimit             int64 `json:"memory_limit"`
			CPULimit                int   `json:"cpu_limit"`
			ResponseTimeThreshold   int   `json:"response_time_threshold"`
		} `json:"performance"`
	} `json:"test"`
	TestUsers []struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	} `json:"test_users"`
	TestFiles []struct {
		Name        string `json:"name"`
		Content     string `json:"content"`
		Type        string `json:"type"`
		Size        int64  `json:"size"`
		Description string `json:"description"`
	} `json:"test_files"`
	TestAPIKeys []struct {
		Name        string `json:"name"`
		Key         string `json:"key"`
		Permissions []string `json:"permissions"`
		ExpiresAt   string `json:"expires_at"`
	} `json:"test_api_keys"`
	TestScenarios struct {
		UserRegistration struct {
			ValidUsers   []map[string]interface{} `json:"valid_users"`
			InvalidUsers []map[string]interface{} `json:"invalid_users"`
		} `json:"user_registration"`
		FileUpload struct {
			ValidFiles   []map[string]interface{} `json:"valid_files"`
			InvalidFiles []map[string]interface{} `json:"invalid_files"`
		} `json:"file_upload"`
		APIAuthentication struct {
			ValidKeys   []map[string]interface{} `json:"valid_keys"`
			InvalidKeys []map[string]interface{} `json:"invalid_keys"`
		} `json:"api_authentication"`
	} `json:"test_scenarios"`
	PerformanceTargets struct {
		ConcurrentUsers    int `json:"concurrent_users"`
		ResponseTimeMs     int `json:"response_time_ms"`
		ThroughputRPS      int `json:"throughput_rps"`
		MemoryUsageMB      int `json:"memory_usage_mb"`
		CPUUsagePercent    int `json:"cpu_usage_percent"`
		ErrorRatePercent   int `json:"error_rate_percent"`
	} `json:"performance_targets"`
	CoverageTargets struct {
		OverallPercent     int `json:"overall_percent"`
		UnitTestPercent    int `json:"unit_test_percent"`
		IntegrationPercent int `json:"integration_percent"`
		CriticalPathPercent int `json:"critical_path_percent"`
	} `json:"coverage_targets"`
}

// CreateTestConfig creates a test configuration file
func CreateTestConfig(t *testing.T, configPath string) *TestConfigData {
	t.Helper()

	config := &TestConfigData{
		Test: struct {
			Database struct {
				Path              string `json:"path"`
				Driver            string `json:"driver"`
				MaxConnections    int    `json:"max_connections"`
				ConnectionTimeout int    `json:"connection_timeout"`
			} `json:"database"`
			Server struct {
				Port         int    `json:"port"`
				Host         string `json:"host"`
				CertFile     string `json:"cert_file"`
				KeyFile      string `json:"key_file"`
				ReadTimeout  int    `json:"read_timeout"`
				WriteTimeout int    `json:"write_timeout"`
				IdleTimeout  int    `json:"idle_timeout"`
			} `json:"server"`
			Upload struct {
				MaxFileSize  int64    `json:"max_file_size"`
				AllowedTypes []string `json:"allowed_types"`
				UploadDir    string   `json:"upload_dir"`
				TempDir      string   `json:"temp_dir"`
				ChunkSize    int      `json:"chunk_size"`
			} `json:"upload"`
			Auth struct {
				TwoFAEnabled              bool `json:"twofa_enabled"`
				PasswordMinLength         int  `json:"password_min_length"`
				PasswordRequireUppercase  bool `json:"password_require_uppercase"`
				PasswordRequireLowercase  bool `json:"password_require_lowercase"`
				PasswordRequireNumbers    bool `json:"password_require_numbers"`
				PasswordRequireSpecial    bool `json:"password_require_special"`
				SessionTimeout            int  `json:"session_timeout"`
				MaxLoginAttempts          int  `json:"max_login_attempts"`
				LockoutDuration           int  `json:"lockout_duration"`
			} `json:"auth"`
			Logging struct {
				Level      string `json:"level"`
				Format     string `json:"format"`
				Output     string `json:"output"`
				MaxSize    int64  `json:"max_size"`
				MaxBackups int    `json:"max_backups"`
				MaxAge     int    `json:"max_age"`
			} `json:"logging"`
			API struct {
				RateLimit struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				} `json:"rate_limit"`
				CORS struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				} `json:"cors"`
				Timeout         int   `json:"timeout"`
				MaxRequestSize  int64 `json:"max_request_size"`
			} `json:"api"`
			Security struct {
				HTTPSRedirect    bool     `json:"https_redirect"`
				SecurityHeaders  bool     `json:"security_headers"`
				RequestTimeout   int      `json:"request_timeout"`
				MaxRequestSize   int64    `json:"max_request_size"`
				TrustedProxies   []string `json:"trusted_proxies"`
			} `json:"security"`
			Performance struct {
				ConcurrentRequests      int   `json:"concurrent_requests"`
				MemoryLimit             int64 `json:"memory_limit"`
				CPULimit                int   `json:"cpu_limit"`
				ResponseTimeThreshold   int   `json:"response_time_threshold"`
			} `json:"performance"`
		}{
			Database: struct {
				Path              string `json:"path"`
				Driver            string `json:"driver"`
				MaxConnections    int    `json:"max_connections"`
				ConnectionTimeout int    `json:"connection_timeout"`
			}{
				Path:              "data/test.db",
				Driver:            "sqlite3",
				MaxConnections:    10,
				ConnectionTimeout: 30,
			},
			Server: struct {
				Port         int    `json:"port"`
				Host         string `json:"host"`
				CertFile     string `json:"cert_file"`
				KeyFile      string `json:"key_file"`
				ReadTimeout  int    `json:"read_timeout"`
				WriteTimeout int    `json:"write_timeout"`
				IdleTimeout  int    `json:"idle_timeout"`
			}{
				Port:         8443,
				Host:         "localhost",
				CertFile:     "certs/test_server.crt",
				KeyFile:      "certs/test_server.key",
				ReadTimeout:  30,
				WriteTimeout: 30,
				IdleTimeout:  120,
			},
			Upload: struct {
				MaxFileSize  int64    `json:"max_file_size"`
				AllowedTypes []string `json:"allowed_types"`
				UploadDir    string   `json:"upload_dir"`
				TempDir      string   `json:"temp_dir"`
				ChunkSize    int      `json:"chunk_size"`
			}{
				MaxFileSize:  10 * 1024 * 1024, // 10MB
				AllowedTypes: []string{".txt", ".pdf", ".doc", ".docx", ".xlsx", ".tsv", ".zip"},
				UploadDir:    "downloads/test",
				TempDir:      "temp/test",
				ChunkSize:    8192,
			},
			Auth: struct {
				TwoFAEnabled              bool `json:"twofa_enabled"`
				PasswordMinLength         int  `json:"password_min_length"`
				PasswordRequireUppercase  bool `json:"password_require_uppercase"`
				PasswordRequireLowercase  bool `json:"password_require_lowercase"`
				PasswordRequireNumbers    bool `json:"password_require_numbers"`
				PasswordRequireSpecial    bool `json:"password_require_special"`
				SessionTimeout            int  `json:"session_timeout"`
				MaxLoginAttempts          int  `json:"max_login_attempts"`
				LockoutDuration           int  `json:"lockout_duration"`
			}{
				TwoFAEnabled:              true,
				PasswordMinLength:         8,
				PasswordRequireUppercase:  true,
				PasswordRequireLowercase:  true,
				PasswordRequireNumbers:    true,
				PasswordRequireSpecial:    true,
				SessionTimeout:            3600,
				MaxLoginAttempts:          5,
				LockoutDuration:           900,
			},
			Logging: struct {
				Level      string `json:"level"`
				Format     string `json:"format"`
				Output     string `json:"output"`
				MaxSize    int64  `json:"max_size"`
				MaxBackups int    `json:"max_backups"`
				MaxAge     int    `json:"max_age"`
			}{
				Level:      "debug",
				Format:     "json",
				Output:     "test.log",
				MaxSize:    10 * 1024 * 1024, // 10MB
				MaxBackups: 3,
				MaxAge:     7,
			},
			API: struct {
				RateLimit struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				} `json:"rate_limit"`
				CORS struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				} `json:"cors"`
				Timeout         int   `json:"timeout"`
				MaxRequestSize  int64 `json:"max_request_size"`
			}{
				RateLimit: struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				}{
					Enabled:           true,
					RequestsPerMinute: 100,
					BurstLimit:        10,
				},
				CORS: struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				}{
					Enabled:        true,
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
					AllowedHeaders: []string{"*"},
					MaxAge:         86400,
				},
				Timeout:        30,
				MaxRequestSize: 10 * 1024 * 1024, // 10MB
			},
			Security: struct {
				HTTPSRedirect    bool     `json:"https_redirect"`
				SecurityHeaders  bool     `json:"security_headers"`
				RequestTimeout   int      `json:"request_timeout"`
				MaxRequestSize   int64    `json:"max_request_size"`
				TrustedProxies   []string `json:"trusted_proxies"`
			}{
				HTTPSRedirect:   false,
				SecurityHeaders: true,
				RequestTimeout:  30,
				MaxRequestSize:  10 * 1024 * 1024, // 10MB
				TrustedProxies:  []string{"127.0.0.1", "::1"},
			},
			Performance: struct {
				ConcurrentRequests      int   `json:"concurrent_requests"`
				MemoryLimit             int64 `json:"memory_limit"`
				CPULimit                int   `json:"cpu_limit"`
				ResponseTimeThreshold   int   `json:"response_time_threshold"`
			}{
				ConcurrentRequests:    100,
				MemoryLimit:           512 * 1024 * 1024, // 512MB
				CPULimit:              80,
				ResponseTimeThreshold: 1000,
			},
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
		Test: struct {
			Database struct {
				Path              string `json:"path"`
				Driver            string `json:"driver"`
				MaxConnections    int    `json:"max_connections"`
				ConnectionTimeout int    `json:"connection_timeout"`
			} `json:"database"`
			Server struct {
				Port         int    `json:"port"`
				Host         string `json:"host"`
				CertFile     string `json:"cert_file"`
				KeyFile      string `json:"key_file"`
				ReadTimeout  int    `json:"read_timeout"`
				WriteTimeout int    `json:"write_timeout"`
				IdleTimeout  int    `json:"idle_timeout"`
			} `json:"server"`
			Upload struct {
				MaxFileSize  int64    `json:"max_file_size"`
				AllowedTypes []string `json:"allowed_types"`
				UploadDir    string   `json:"upload_dir"`
				TempDir      string   `json:"temp_dir"`
				ChunkSize    int      `json:"chunk_size"`
			} `json:"upload"`
			Auth struct {
				TwoFAEnabled              bool `json:"twofa_enabled"`
				PasswordMinLength         int  `json:"password_min_length"`
				PasswordRequireUppercase  bool `json:"password_require_uppercase"`
				PasswordRequireLowercase  bool `json:"password_require_lowercase"`
				PasswordRequireNumbers    bool `json:"password_require_numbers"`
				PasswordRequireSpecial    bool `json:"password_require_special"`
				SessionTimeout            int  `json:"session_timeout"`
				MaxLoginAttempts          int  `json:"max_login_attempts"`
				LockoutDuration           int  `json:"lockout_duration"`
			} `json:"auth"`
			Logging struct {
				Level      string `json:"level"`
				Format     string `json:"format"`
				Output     string `json:"output"`
				MaxSize    int64  `json:"max_size"`
				MaxBackups int    `json:"max_backups"`
				MaxAge     int    `json:"max_age"`
			} `json:"logging"`
			API struct {
				RateLimit struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				} `json:"rate_limit"`
				CORS struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				} `json:"cors"`
				Timeout         int   `json:"timeout"`
				MaxRequestSize  int64 `json:"max_request_size"`
			} `json:"api"`
			Security struct {
				HTTPSRedirect    bool     `json:"https_redirect"`
				SecurityHeaders  bool     `json:"security_headers"`
				RequestTimeout   int      `json:"request_timeout"`
				MaxRequestSize   int64    `json:"max_request_size"`
				TrustedProxies   []string `json:"trusted_proxies"`
			} `json:"security"`
			Performance struct {
				ConcurrentRequests      int   `json:"concurrent_requests"`
				MemoryLimit             int64 `json:"memory_limit"`
				CPULimit                int   `json:"cpu_limit"`
				ResponseTimeThreshold   int   `json:"response_time_threshold"`
			} `json:"performance"`
		}{
			Database: struct {
				Path              string `json:"path"`
				Driver            string `json:"driver"`
				MaxConnections    int    `json:"max_connections"`
				ConnectionTimeout int    `json:"connection_timeout"`
			}{
				Path:              "data/test.db",
				Driver:            "sqlite3",
				MaxConnections:    10,
				ConnectionTimeout: 30,
			},
			Server: struct {
				Port         int    `json:"port"`
				Host         string `json:"host"`
				CertFile     string `json:"cert_file"`
				KeyFile      string `json:"key_file"`
				ReadTimeout  int    `json:"read_timeout"`
				WriteTimeout int    `json:"write_timeout"`
				IdleTimeout  int    `json:"idle_timeout"`
			}{
				Port:         8443,
				Host:         "localhost",
				CertFile:     "certs/test_server.crt",
				KeyFile:      "certs/test_server.key",
				ReadTimeout:  30,
				WriteTimeout: 30,
				IdleTimeout:  120,
			},
			Upload: struct {
				MaxFileSize  int64    `json:"max_file_size"`
				AllowedTypes []string `json:"allowed_types"`
				UploadDir    string   `json:"upload_dir"`
				TempDir      string   `json:"temp_dir"`
				ChunkSize    int      `json:"chunk_size"`
			}{
				MaxFileSize:  10 * 1024 * 1024, // 10MB
				AllowedTypes: []string{".txt", ".pdf", ".doc", ".docx", ".xlsx", ".tsv", ".zip"},
				UploadDir:    "downloads/test",
				TempDir:      "temp/test",
				ChunkSize:    8192,
			},
			Auth: struct {
				TwoFAEnabled              bool `json:"twofa_enabled"`
				PasswordMinLength         int  `json:"password_min_length"`
				PasswordRequireUppercase  bool `json:"password_require_uppercase"`
				PasswordRequireLowercase  bool `json:"password_require_lowercase"`
				PasswordRequireNumbers    bool `json:"password_require_numbers"`
				PasswordRequireSpecial    bool `json:"password_require_special"`
				SessionTimeout            int  `json:"session_timeout"`
				MaxLoginAttempts          int  `json:"max_login_attempts"`
				LockoutDuration           int  `json:"lockout_duration"`
			}{
				TwoFAEnabled:              true,
				PasswordMinLength:         8,
				PasswordRequireUppercase:  true,
				PasswordRequireLowercase:  true,
				PasswordRequireNumbers:    true,
				PasswordRequireSpecial:    true,
				SessionTimeout:            3600,
				MaxLoginAttempts:          5,
				LockoutDuration:           900,
			},
			Logging: struct {
				Level      string `json:"level"`
				Format     string `json:"format"`
				Output     string `json:"output"`
				MaxSize    int64  `json:"max_size"`
				MaxBackups int    `json:"max_backups"`
				MaxAge     int    `json:"max_age"`
			}{
				Level:      "debug",
				Format:     "json",
				Output:     "test.log",
				MaxSize:    10 * 1024 * 1024, // 10MB
				MaxBackups: 3,
				MaxAge:     7,
			},
			API: struct {
				RateLimit struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				} `json:"rate_limit"`
				CORS struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				} `json:"cors"`
				Timeout         int   `json:"timeout"`
				MaxRequestSize  int64 `json:"max_request_size"`
			}{
				RateLimit: struct {
					Enabled           bool `json:"enabled"`
					RequestsPerMinute int  `json:"requests_per_minute"`
					BurstLimit        int  `json:"burst_limit"`
				}{
					Enabled:           true,
					RequestsPerMinute: 100,
					BurstLimit:        10,
				},
				CORS: struct {
					Enabled        bool     `json:"enabled"`
					AllowedOrigins []string `json:"allowed_origins"`
					AllowedMethods []string `json:"allowed_methods"`
					AllowedHeaders []string `json:"allowed_headers"`
					MaxAge         int      `json:"max_age"`
				}{
					Enabled:        true,
					AllowedOrigins: []string{"*"},
					AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
					AllowedHeaders: []string{"*"},
					MaxAge:         86400,
				},
				Timeout:        30,
				MaxRequestSize: 10 * 1024 * 1024, // 10MB
			},
			Security: struct {
				HTTPSRedirect    bool     `json:"https_redirect"`
				SecurityHeaders  bool     `json:"security_headers"`
				RequestTimeout   int      `json:"request_timeout"`
				MaxRequestSize   int64    `json:"max_request_size"`
				TrustedProxies   []string `json:"trusted_proxies"`
			}{
				HTTPSRedirect:   false,
				SecurityHeaders: true,
				RequestTimeout:  30,
				MaxRequestSize:  10 * 1024 * 1024, // 10MB
				TrustedProxies:  []string{"127.0.0.1", "::1"},
			},
			Performance: struct {
				ConcurrentRequests      int   `json:"concurrent_requests"`
				MemoryLimit             int64 `json:"memory_limit"`
				CPULimit                int   `json:"cpu_limit"`
				ResponseTimeThreshold   int   `json:"response_time_threshold"`
			}{
				ConcurrentRequests:    100,
				MemoryLimit:           512 * 1024 * 1024, // 512MB
				CPULimit:              80,
				ResponseTimeThreshold: 1000,
			},
		},
	}
}
