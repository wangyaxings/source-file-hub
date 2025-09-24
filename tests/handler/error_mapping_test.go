package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secure-file-hub/internal/handler"
)

// TestWriteErrorWithCode tests the basic error writing functionality
func TestWriteErrorWithCode(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		code           string
		message        string
		requestID      string
		expectedStatus int
		expectedCode   string
		expectedError  string
	}{
		{
			name:           "Basic error without request ID",
			status:         http.StatusBadRequest,
			code:           "VALIDATION_ERROR",
			message:        "Invalid input",
			requestID:      "",
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "VALIDATION_ERROR",
			expectedError:  "Invalid input",
		},
		{
			name:           "Error with request ID",
			status:         http.StatusNotFound,
			code:           "NOT_FOUND",
			message:        "Resource not found",
			requestID:      "req-123",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NOT_FOUND",
			expectedError:  "Resource not found",
		},
		{
			name:           "Internal server error",
			status:         http.StatusInternalServerError,
			code:           "INTERNAL_ERROR",
			message:        "Something went wrong",
			requestID:      "req-456",
			expectedStatus: http.StatusInternalServerError,
			expectedCode:   "INTERNAL_ERROR",
			expectedError:  "Something went wrong",
		},
		{
			name:           "Unauthorized error",
			status:         http.StatusUnauthorized,
			code:           "UNAUTHORIZED",
			message:        "Authentication required",
			requestID:      "",
			expectedStatus: http.StatusUnauthorized,
			expectedCode:   "UNAUTHORIZED",
			expectedError:  "Authentication required",
		},
		{
			name:           "Forbidden error",
			status:         http.StatusForbidden,
			code:           "FORBIDDEN",
			message:        "Access denied",
			requestID:      "req-789",
			expectedStatus: http.StatusForbidden,
			expectedCode:   "FORBIDDEN",
			expectedError:  "Access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that uses writeErrorWithCode
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set request ID header if provided
				if tt.requestID != "" {
					w.Header().Set("X-Request-ID", tt.requestID)
				}
				// Use reflection to call the unexported function
				handler.WriteErrorWithCodeForTest(w, tt.status, tt.code, tt.message)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			testHandler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Check content type
			if contentType := rr.Header().Get("Content-Type"); contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			// Parse response body
			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse JSON response: %v", err)
			}

			// Check response structure
			if success, ok := response["success"].(bool); !ok || success {
				t.Errorf("Expected success to be false, got %v", response["success"])
			}

			if code, ok := response["code"].(string); !ok || code != tt.expectedCode {
				t.Errorf("Expected code %s, got %v", tt.expectedCode, response["code"])
			}

			if errorMsg, ok := response["error"].(string); !ok || errorMsg != tt.expectedError {
				t.Errorf("Expected error %s, got %v", tt.expectedError, response["error"])
			}

			// Check details
			details, ok := response["details"].(map[string]interface{})
			if !ok {
				t.Errorf("Expected details to be a map, got %T", response["details"])
			} else {
				if tt.requestID != "" {
					if requestID, exists := details["request_id"]; !exists || requestID != tt.requestID {
						t.Errorf("Expected request_id %s in details, got %v", tt.requestID, requestID)
					}
				} else {
					if _, exists := details["request_id"]; exists {
						t.Errorf("Expected no request_id in details when not provided")
					}
				}
			}
		})
	}
}

// TestWriteErrorWithCodeDetails tests error writing with custom details
func TestWriteErrorWithCodeDetails(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		code           string
		message        string
		details        map[string]interface{}
		requestID      string
		expectedStatus int
		expectedCode   string
		expectedError  string
	}{
		{
			name:    "Error with custom details",
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "Invalid field",
			details: map[string]interface{}{
				"field":  "username",
				"reason": "too short",
			},
			requestID:      "req-123",
			expectedStatus: http.StatusBadRequest,
			expectedCode:   "VALIDATION_ERROR",
			expectedError:  "Invalid field",
		},
		{
			name:           "Error with nil details",
			status:         http.StatusNotFound,
			code:           "NOT_FOUND",
			message:        "User not found",
			details:        nil,
			requestID:      "req-456",
			expectedStatus: http.StatusNotFound,
			expectedCode:   "NOT_FOUND",
			expectedError:  "User not found",
		},
		{
			name:    "Error with existing request_id in details",
			status:  http.StatusForbidden,
			code:    "FORBIDDEN",
			message: "Access denied",
			details: map[string]interface{}{
				"request_id": "custom-req-id",
				"resource":   "admin-panel",
			},
			requestID:      "req-789",
			expectedStatus: http.StatusForbidden,
			expectedCode:   "FORBIDDEN",
			expectedError:  "Access denied",
		},
		{
			name:    "Error with complex details",
			status:  http.StatusUnprocessableEntity,
			code:    "VALIDATION_ERROR",
			message: "Multiple validation errors",
			details: map[string]interface{}{
				"fields": map[string]interface{}{
					"email":    "invalid format",
					"password": "too weak",
				},
				"count": 2,
			},
			requestID:      "",
			expectedStatus: http.StatusUnprocessableEntity,
			expectedCode:   "VALIDATION_ERROR",
			expectedError:  "Multiple validation errors",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that uses writeErrorWithCodeDetails
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Set request ID header if provided
				if tt.requestID != "" {
					w.Header().Set("X-Request-ID", tt.requestID)
				}
				// Use reflection to call the unexported function
				handler.WriteErrorWithCodeDetailsForTest(w, tt.status, tt.code, tt.message, tt.details)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			testHandler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Parse response body
			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse JSON response: %v", err)
			}

			// Check response structure
			if success, ok := response["success"].(bool); !ok || success {
				t.Errorf("Expected success to be false, got %v", response["success"])
			}

			if code, ok := response["code"].(string); !ok || code != tt.expectedCode {
				t.Errorf("Expected code %s, got %v", tt.expectedCode, response["code"])
			}

			if errorMsg, ok := response["error"].(string); !ok || errorMsg != tt.expectedError {
				t.Errorf("Expected error %s, got %v", tt.expectedError, response["error"])
			}

			// Check details
			details, ok := response["details"].(map[string]interface{})
			if !ok {
				t.Errorf("Expected details to be a map, got %T", response["details"])
			} else {
				// Check request_id handling
				if tt.details != nil && tt.details["request_id"] != nil {
					// Should preserve existing request_id
					if requestID, exists := details["request_id"]; !exists || requestID != "custom-req-id" {
						t.Errorf("Expected custom request_id to be preserved, got %v", requestID)
					}
				} else if tt.requestID != "" {
					// Should add request_id from header
					if requestID, exists := details["request_id"]; !exists || requestID != tt.requestID {
						t.Errorf("Expected request_id %s from header, got %v", tt.requestID, requestID)
					}
				}

				// Check custom details are preserved
				if tt.details != nil {
					for key, expectedValue := range tt.details {
						if key == "request_id" {
							continue // Already checked above
						}
						if actualValue, exists := details[key]; !exists {
							t.Errorf("Expected detail key %s to exist", key)
						} else {
							// For complex nested structures, just check existence
							if key == "fields" || key == "count" {
								// These are tested by their presence
								continue
							}
							if actualValue != expectedValue {
								t.Errorf("Expected detail %s to be %v, got %v", key, expectedValue, actualValue)
							}
						}
					}
				}
			}
		})
	}
}

// TestErrorResponseMapping tests the legacy error response mapping
func TestErrorResponseMapping(t *testing.T) {
	tests := []struct {
		name           string
		status         int
		message        string
		expectedCode   string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Bad Request maps to VALIDATION_ERROR",
			status:         http.StatusBadRequest,
			message:        "Invalid input",
			expectedCode:   "VALIDATION_ERROR",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Invalid input",
		},
		{
			name:           "Unauthorized maps to UNAUTHORIZED",
			status:         http.StatusUnauthorized,
			message:        "Auth required",
			expectedCode:   "UNAUTHORIZED",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "Auth required",
		},
		{
			name:           "Not Found maps to NOT_FOUND",
			status:         http.StatusNotFound,
			message:        "Resource missing",
			expectedCode:   "NOT_FOUND",
			expectedStatus: http.StatusNotFound,
			expectedError:  "Resource missing",
		},
		{
			name:           "Other status maps to INTERNAL_ERROR",
			status:         http.StatusServiceUnavailable,
			message:        "Service down",
			expectedCode:   "INTERNAL_ERROR",
			expectedStatus: http.StatusServiceUnavailable,
			expectedError:  "Service down",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test handler that uses writeErrorResponse (legacy function)
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handler.WriteErrorResponseForTest(w, tt.status, tt.message)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			rr := httptest.NewRecorder()
			testHandler.ServeHTTP(rr, req)

			// Check status code
			if rr.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rr.Code)
			}

			// Parse response body
			var response map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse JSON response: %v", err)
			}

			// Check response structure
			if success, ok := response["success"].(bool); !ok || success {
				t.Errorf("Expected success to be false, got %v", response["success"])
			}

			if code, ok := response["code"].(string); !ok || code != tt.expectedCode {
				t.Errorf("Expected code %s, got %v", tt.expectedCode, response["code"])
			}

			if errorMsg, ok := response["error"].(string); !ok || errorMsg != tt.expectedError {
				t.Errorf("Expected error %s, got %v", tt.expectedError, response["error"])
			}
		})
	}
}
