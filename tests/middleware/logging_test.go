package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"secure-file-hub/internal/auth"
	"secure-file-hub/internal/database"
	"secure-file-hub/internal/logger"
	"secure-file-hub/internal/middleware"
	"secure-file-hub/tests/helpers"
)

func TestLoggingMiddleware_WithRequestID(t *testing.T) {
	// Setup test environment
	config := helpers.SetupTestEnvironment(t)
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	// Initialize database and logger
	if err := database.InitDatabase(config.DBPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	db := database.GetDatabase()
	if err := logger.InitLogger(db.GetDB()); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	// Create a test handler that returns 200 OK
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Create middleware chain: RequestID -> Logging -> TestHandler
	handler := middleware.RequestIDMiddleware(
		middleware.LoggingMiddleware(testHandler),
	)

	tests := []struct {
		name           string
		method         string
		path           string
		userContext    *auth.User
		expectedStatus int
		hasRequestID   bool
		customReqID    string
	}{
		{
			name:           "GET request with auto-generated request ID",
			method:         "GET",
			path:           "/api/v1/files",
			expectedStatus: 200,
			hasRequestID:   true,
		},
		{
			name:           "POST request with custom request ID",
			method:         "POST",
			path:           "/api/v1/upload",
			expectedStatus: 200,
			hasRequestID:   true,
			customReqID:    "custom-req-123",
		},
		{
			name:           "Request with authenticated user",
			method:         "GET",
			path:           "/api/v1/me",
			userContext:    &auth.User{Username: "testuser", Role: "viewer"},
			expectedStatus: 200,
			hasRequestID:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(tt.method, tt.path, nil)
			
			// Add custom request ID if specified
			if tt.customReqID != "" {
				req.Header.Set("X-Request-ID", tt.customReqID)
			}

			// Add user context if specified
			if tt.userContext != nil {
				ctx := context.WithValue(req.Context(), "user", tt.userContext)
				req = req.WithContext(ctx)
			}

			// Create response recorder
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Verify response status
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Verify request ID header is set
			if tt.hasRequestID {
				reqID := rr.Header().Get("X-Request-ID")
				if reqID == "" {
					t.Error("Expected X-Request-ID header to be set")
				}

				// If custom request ID was provided, verify it matches
				if tt.customReqID != "" && reqID != tt.customReqID {
					t.Errorf("Expected request ID %s, got %s", tt.customReqID, reqID)
				}
			}

			// Give some time for async logging to complete
			time.Sleep(100 * time.Millisecond)

			// Verify logs were created in database
			l := logger.GetLogger()
			if l != nil {
				logs, err := l.GetAccessLogs(10, 0)
				if err != nil {
					t.Fatalf("Failed to get access logs: %v", err)
				}

				// Should have at least 2 logs (request and response)
				if len(logs) < 2 {
					t.Errorf("Expected at least 2 log entries, got %d", len(logs))
				}

				// Verify request log contains request_id
				requestLog := logs[1] // Most recent is first, so request log is second
				if requestLog.EventCode != logger.EventAPIRequest {
					t.Errorf("Expected request log event code %s, got %s", logger.EventAPIRequest, requestLog.EventCode)
				}

				// Check if request_id is in details
				if requestLog.Details != nil {
					if _, hasReqID := requestLog.Details["request_id"]; !hasReqID {
						t.Error("Expected request_id in log details")
					}

					// Verify custom request ID if provided
					if tt.customReqID != "" {
						if reqID, ok := requestLog.Details["request_id"].(string); ok {
							if reqID != tt.customReqID {
								t.Errorf("Expected request_id %s in log, got %s", tt.customReqID, reqID)
							}
						}
					}

					// Check for actor if user was authenticated
					if tt.userContext != nil {
						if actor, hasActor := requestLog.Details["actor"]; !hasActor {
							t.Error("Expected actor in log details for authenticated request")
						} else if actorStr, ok := actor.(string); ok {
							if actorStr != tt.userContext.Username {
								t.Errorf("Expected actor %s, got %s", tt.userContext.Username, actorStr)
							}
						}
					}
				}

				// Verify response log contains request_id
				responseLog := logs[0] // Most recent log
				if responseLog.EventCode != logger.EventAPIResponse {
					t.Errorf("Expected response log event code %s, got %s", logger.EventAPIResponse, responseLog.EventCode)
				}

				if responseLog.Details != nil {
					if _, hasReqID := responseLog.Details["request_id"]; !hasReqID {
						t.Error("Expected request_id in response log details")
					}
				}
			}
		})
	}
}

func TestLoggingMiddleware_ErrorStatusCodes(t *testing.T) {
	// Setup test environment
	config := helpers.SetupTestEnvironment(t)
	defer func() {
		if db := database.GetDatabase(); db != nil {
			db.Close()
		}
	}()

	// Initialize database and logger
	if err := database.InitDatabase(config.DBPath); err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	db := database.GetDatabase()
	if err := logger.InitLogger(db.GetDB()); err != nil {
		t.Fatalf("Failed to initialize logger: %v", err)
	}

	tests := []struct {
		name           string
		statusCode     int
		expectedLevel  logger.LogLevel
		expectedCode   string
	}{
		{
			name:          "Success response",
			statusCode:    200,
			expectedLevel: logger.LogLevelINFO,
			expectedCode:  "API_RESPONSE",
		},
		{
			name:          "Client error response",
			statusCode:    400,
			expectedLevel: logger.LogLevelWARN,
			expectedCode:  "API_RESPONSE_ERROR",
		},
		{
			name:          "Not found response",
			statusCode:    404,
			expectedLevel: logger.LogLevelWARN,
			expectedCode:  "API_RESPONSE_ERROR",
		},
		{
			name:          "Server error response",
			statusCode:    500,
			expectedLevel: logger.LogLevelERROR,
			expectedCode:  "API_RESPONSE_SERVER_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that returns the specified status code
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte("Response"))
			})

			// Create middleware chain
			handler := middleware.RequestIDMiddleware(
				middleware.LoggingMiddleware(testHandler),
			)

			// Create request
			req := httptest.NewRequest("GET", "/api/test", nil)
			rr := httptest.NewRecorder()

			// Execute request
			handler.ServeHTTP(rr, req)

			// Verify response status
			if rr.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, rr.Code)
			}

			// Give some time for async logging
			time.Sleep(100 * time.Millisecond)

			// Verify log level and code
			l := logger.GetLogger()
			if l != nil {
				logs, err := l.GetAccessLogs(10, 0)
				if err != nil {
					t.Fatalf("Failed to get access logs: %v", err)
				}

				if len(logs) < 1 {
					t.Fatal("Expected at least 1 log entry")
				}

				// Check the response log (most recent)
				responseLog := logs[0]
				if responseLog.Level != tt.expectedLevel {
					t.Errorf("Expected log level %s, got %s", tt.expectedLevel, responseLog.Level)
				}

				// Check the code in details
				if responseLog.Details != nil {
					if code, hasCode := responseLog.Details["code"]; hasCode {
						if codeStr, ok := code.(string); ok {
							if codeStr != tt.expectedCode {
								t.Errorf("Expected code %s, got %s", tt.expectedCode, codeStr)
							}
						}
					} else {
						t.Error("Expected code in log details")
					}
				}
			}
		})
	}
}
